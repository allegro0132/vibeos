use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::BTreeMap;
use std::sync::Mutex;

use vibeos_durable_format::{
    encode_object_transaction, preview_grant_transaction, preview_revoke_transaction, DerivationId,
    DurableRights, GrantFlags, GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain,
    ResourceKind, RootPolicy, SlotIdentity, SpaceId, StoreId, TransactionId,
};
use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
use vibeos_storage_device::MutationFailure;

use crate::{
    canonical_attributable_physical_bytes, root_policy_commitment, CasStoreError, FormatOptions,
    PageDevice, PageDeviceInfo, PersistentAuthorityError, PersistentAuthorityImport,
    PersistentAuthorityView, PersistentObjectHandle, PersistentSingletonUpdate,
    PrincipalQuotaLimits, QuotaError, ScrubStatus, SegmentStore, StoreLimits, StoreRuntimeContext,
    LEGACY_SYSTEM_PRINCIPAL, REFERENCE_CODEC_TYPED_V1,
};

const SEGMENTS: u64 = 16;
const OBJECT_KIND_RAW: u32 = 0x4155_5432;
const POLICY: &[u8] = b"test authority roots v1";

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    loop {
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    OutsideRange,
}

#[derive(Clone)]
struct MemoryDevice {
    pages: Arc<Mutex<BTreeMap<u64, Page>>>,
    segments: u64,
}

impl MemoryDevice {
    fn blank() -> Self {
        Self::with_segments(SEGMENTS)
    }

    fn with_segments(segments: u64) -> Self {
        Self {
            pages: Arc::new(Mutex::new(BTreeMap::new())),
            segments,
        }
    }

    fn snapshot(&self) -> BTreeMap<u64, Page> {
        self.pages.lock().unwrap().clone()
    }
}

impl PageDevice for MemoryDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = admitted_pages(self.segments).unwrap();
        PageDeviceInfo {
            device_id: [0xa7; 16],
            range_first_logical_block: 2_048,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if page >= self.info().page_count {
            return Err(TestError::OutsideRange);
        }
        output.fill(0);
        if let Some(stored) = self.pages.lock().unwrap().get(&page) {
            output.copy_from_slice(stored);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.info().page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        self.pages.lock().unwrap().insert(page, *input);
        Ok(())
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityFaultError {
    Injected,
    DriverRestarted,
    OutsideRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityEffect {
    None,
    Visible,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityFaultAction {
    Normal,
    FailNotSubmitted,
    FailAmbiguous(AuthorityEffect),
    Pending(AuthorityEffect),
}

#[derive(Clone)]
struct AuthorityFaultMedia {
    visible: BTreeMap<u64, Page>,
    durable: BTreeMap<u64, Page>,
    mutation_count: usize,
    fault: Option<(usize, AuthorityFaultAction)>,
}

#[derive(Clone)]
struct AuthorityFaultDevice {
    media: Arc<Mutex<AuthorityFaultMedia>>,
}

impl AuthorityFaultDevice {
    fn blank() -> Self {
        Self::from_durable(BTreeMap::new())
    }

    fn from_durable(durable: BTreeMap<u64, Page>) -> Self {
        Self {
            media: Arc::new(Mutex::new(AuthorityFaultMedia {
                visible: durable.clone(),
                durable,
                mutation_count: 0,
                fault: None,
            })),
        }
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.media.lock().unwrap().durable.clone()
    }

    fn mutation_count(&self) -> usize {
        self.media.lock().unwrap().mutation_count
    }

    fn reset_mutation_count(&self) {
        self.media.lock().unwrap().mutation_count = 0;
    }

    fn arm(&self, mutation_index: usize, action: AuthorityFaultAction) {
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.fault = Some((mutation_index, action));
    }

    fn power_cycle(&self) {
        let mut media = self.media.lock().unwrap();
        media.visible = media.durable.clone();
        media.mutation_count = 0;
        media.fault = None;
    }

    fn next_action(&self) -> AuthorityFaultAction {
        let mut media = self.media.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media
            .fault
            .filter(|(mutation, _)| *mutation == index)
            .map_or(AuthorityFaultAction::Normal, |(_, action)| action)
    }

    fn write_effect(&self, page: u64, bytes: Page, effect: AuthorityEffect) {
        let mut media = self.media.lock().unwrap();
        if !matches!(effect, AuthorityEffect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, AuthorityEffect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn flush_effect(&self, effect: AuthorityEffect) {
        if matches!(effect, AuthorityEffect::Durable) {
            let mut media = self.media.lock().unwrap();
            media.durable = media.visible.clone();
        }
    }
}

impl PageDevice for AuthorityFaultDevice {
    type Error = AuthorityFaultError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = admitted_pages(SEGMENTS).unwrap();
        PageDeviceInfo {
            device_id: [0xa7; 16],
            range_first_logical_block: 2_048,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if page >= self.info().page_count {
            return Err(AuthorityFaultError::OutsideRange);
        }
        output.fill(0);
        if let Some(stored) = self.media.lock().unwrap().visible.get(&page) {
            output.copy_from_slice(stored);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if page >= self.info().page_count {
            return Err(MutationFailure::not_submitted(
                AuthorityFaultError::OutsideRange,
            ));
        }
        let bytes = *input;
        match self.next_action() {
            AuthorityFaultAction::Normal => {
                self.write_effect(page, bytes, AuthorityEffect::Visible);
                Ok(())
            }
            AuthorityFaultAction::FailNotSubmitted => Err(MutationFailure::not_submitted(
                AuthorityFaultError::Injected,
            )),
            AuthorityFaultAction::FailAmbiguous(effect) => {
                self.write_effect(page, bytes, effect);
                Err(MutationFailure::ambiguous(
                    AuthorityFaultError::DriverRestarted,
                ))
            }
            AuthorityFaultAction::Pending(effect) => {
                self.write_effect(page, bytes, effect);
                pending::<Result<(), MutationFailure<AuthorityFaultError>>>().await
            }
        }
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        match self.next_action() {
            AuthorityFaultAction::Normal => {
                self.flush_effect(AuthorityEffect::Durable);
                Ok(())
            }
            AuthorityFaultAction::FailNotSubmitted => Err(MutationFailure::not_submitted(
                AuthorityFaultError::Injected,
            )),
            AuthorityFaultAction::FailAmbiguous(effect) => {
                self.flush_effect(effect);
                Err(MutationFailure::ambiguous(
                    AuthorityFaultError::DriverRestarted,
                ))
            }
            AuthorityFaultAction::Pending(effect) => {
                self.flush_effect(effect);
                pending::<Result<(), MutationFailure<AuthorityFaultError>>>().await
            }
        }
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn limits() -> StoreLimits {
    StoreLimits {
        max_catalog_entries: 64,
        max_replay_records: 4,
        recovery_memory_bytes: 2 * 1024 * 1024,
        max_compat_object_bytes: 64 * 1024,
    }
}

fn store_id() -> StoreId {
    StoreId::new(0x4155_5448_2d54_4553_5401).unwrap()
}

fn kind() -> ObjectKind {
    ObjectKind::new(OBJECT_KIND_RAW).unwrap()
}

fn format_records() -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    vec![RecordChain::new(store_id())
        .append(None, RecordBody::Format)
        .unwrap()]
}

fn append_object_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    bytes: &[u8],
) -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end: 4 })
            .unwrap(),
    );
    output.extend(
        encode_object_transaction(
            &mut chain,
            TransactionId::new(1).unwrap(),
            ObjectId::new(2).unwrap(),
            kind(),
            bytes,
        )
        .unwrap()
        .records,
    );
    output
}

fn append_next_object_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    bytes: &[u8],
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, ObjectId) {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let object = transaction.checked_add(1).unwrap();
    let exclusive_end = object.checked_add(1).unwrap();
    let object_id = ObjectId::new(object).unwrap();
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end })
            .unwrap(),
    );
    output.extend(
        encode_object_transaction(
            &mut chain,
            TransactionId::new(transaction).unwrap(),
            object_id,
            kind(),
            bytes,
        )
        .unwrap()
        .records,
    );
    (output, object_id)
}

fn root_grant() -> GrantRecord {
    GrantRecord {
        derivation_id: DerivationId::new(5).unwrap(),
        parent_id: None,
        object_id: ObjectId::new(2).unwrap(),
        target: SlotIdentity {
            space: SpaceId::new(6).unwrap(),
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind: ResourceKind::new(OBJECT_KIND_RAW).unwrap(),
        flags: GrantFlags::ROOT,
    }
}

fn append_grant_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
) -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let mut output = records.to_vec();
    let grant_transaction_id = preflight.id_high_water().max(4);
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end: 7 })
            .unwrap(),
    );
    output.extend(
        preview_grant_transaction(
            &chain,
            TransactionId::new(grant_transaction_id).unwrap(),
            root_grant(),
        )
        .unwrap()
        .0
        .records,
    );
    output
}

fn append_root_grant_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    object_id: ObjectId,
) -> (Vec<[u8; vibeos_durable_format::RECORD_SIZE]>, GrantRecord) {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let derivation = transaction.checked_add(1).unwrap();
    let space = transaction.checked_add(2).unwrap();
    let exclusive_end = transaction.checked_add(3).unwrap();
    let grant = GrantRecord {
        derivation_id: DerivationId::new(derivation).unwrap(),
        parent_id: None,
        object_id,
        target: SlotIdentity {
            space: SpaceId::new(space).unwrap(),
            slot: 0,
            generation: 0,
        },
        rights: DurableRights::READ,
        resource_kind: ResourceKind::new(OBJECT_KIND_RAW).unwrap(),
        flags: GrantFlags::ROOT,
    };
    let mut output = records.to_vec();
    output.push(
        chain
            .append(None, RecordBody::IdHighWater { exclusive_end })
            .unwrap(),
    );
    output.extend(
        preview_grant_transaction(
            &chain,
            TransactionId::new(transaction).unwrap(),
            grant.clone(),
        )
        .unwrap()
        .0
        .records,
    );
    (output, grant)
}

fn append_revoke_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    grant: &GrantRecord,
) -> Vec<[u8; vibeos_durable_format::RECORD_SIZE]> {
    let preflight = vibeos_durable_format::preflight_recovery(records, store_id()).unwrap();
    let mut chain =
        RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let transaction = preflight.id_high_water().max(1);
    let mut output = records.to_vec();
    output.push(
        chain
            .append(
                None,
                RecordBody::IdHighWater {
                    exclusive_end: transaction + 1,
                },
            )
            .unwrap(),
    );
    output.extend(
        preview_revoke_transaction(
            &chain,
            TransactionId::new(transaction).unwrap(),
            grant.derivation_id,
        )
        .unwrap()
        .0
        .records,
    );
    output
}

fn import(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    roots: &[RootPolicy],
) -> PersistentAuthorityImport {
    PersistentAuthorityImport::from_m4(records, store_id(), roots, POLICY, Vec::new()).unwrap()
}

fn find_object(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
) -> vibeos_durable_format::RecoveredObject {
    vibeos_durable_format::preflight_recovery(records, store_id())
        .unwrap()
        .committed_objects()
        .iter()
        .find(|object| object.object_id.get() == 2)
        .unwrap()
        .clone()
}

fn assert_not_persistently_resolved(
    view: &PersistentAuthorityView,
    object: &vibeos_durable_format::RecoveredObject,
) {
    assert!(view.object_for_recovered(object).is_none());
    assert!(view.objects().is_empty());
    assert_eq!(view.principal_policies()[0].committed_logical_bytes, 0);
    assert_eq!(view.principal_policies()[0].committed_physical_bytes, 0);
}

async fn read_handle(
    store: &SegmentStore<MemoryDevice>,
    handle: &PersistentObjectHandle,
) -> Vec<u8> {
    store.read_persistent_object(handle).await.unwrap()
}

const AUTHORITY_FAULT_UUID: [u8; 16] = *b"M7.7-AUTH-FAULT!";

fn authority_fault_options() -> FormatOptions {
    FormatOptions {
        store_uuid: StoreUuid::new(AUTHORITY_FAULT_UUID).unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }
}

fn assert_exact_empty_authority(
    view: &PersistentAuthorityView,
    expected: &PersistentAuthorityImport,
    case: &str,
) {
    assert_eq!(view.store_uuid(), AUTHORITY_FAULT_UUID, "{case}");
    assert_eq!(view.checkpoint_generation(), 2, "{case}");
    assert_eq!(
        view.root_policy_sha256(),
        expected.root_policy_sha256(),
        "{case}"
    );
    assert_eq!(view.record_stream(), expected.record_stream(), "{case}");
    assert_eq!(view.principal_policies(), expected.principals(), "{case}");
    assert!(view.objects().is_empty(), "{case}");
    assert_eq!(
        view.principals().len(),
        expected.principals().len(),
        "{case}"
    );
}

fn cold_recover_empty_authority_or_retry(device: AuthorityFaultDevice, case: &str) -> bool {
    device.power_cycle();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    let info =
        block_on(cold.mount()).unwrap_or_else(|error| panic!("{case}: cold mount: {error:?}"));
    let expected = import(&format_records(), &[]);
    let maintenance = cold
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap_or_else(|error| panic!("{case}: provision maintenance root: {error:?}"));
    let (view, retried) =
        match block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))) {
            Ok(view) => {
                assert_eq!(info.generation, 2, "{case}: recovered generation");
                (view, false)
            }
            Err(PersistentAuthorityError::NotInitialized) => {
                assert_eq!(info.generation, 1, "{case}: retry generation");
                let view =
                    block_on(cold.import_persistent_authority(&maintenance, expected.clone()))
                        .unwrap_or_else(|error| panic!("{case}: retry import: {error:?}"));
                (view, true)
            }
            Err(error) => panic!("{case}: unexpected cold recovery result: {error:?}"),
        };
    assert_exact_empty_authority(&view, &expected, case);
    assert_eq!(cold.info().unwrap().generation, 2, "{case}");
    assert_eq!(cold.info().unwrap().object_count, 0, "{case}");
    assert_eq!(
        block_on(cold.scrub(&maintenance))
            .unwrap_or_else(|error| panic!("{case}: scrub: {error:?}"))
            .status,
        ScrubStatus::Healthy,
        "{case}"
    );
    retried
}

#[test]
fn empty_authority_import_is_power_cut_atomic_at_every_mutation_and_cancel_point() {
    let seed_device = AuthorityFaultDevice::blank();
    let (seed_runtime, _seed_quota, _seed_maintenance) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut seed =
        SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), seed_runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    drop(seed);
    seed_device.power_cycle();
    let formatted = seed_device.durable_image();

    // First measure the exact mutation surface of a successful empty import.
    // Every subsequent case starts from this same generation-1 durable image.
    let probe_device = AuthorityFaultDevice::from_durable(formatted.clone());
    let (probe_runtime, _probe_quota, probe_maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut probe =
        SegmentStore::new_with_runtime_context(probe_device.clone(), limits(), probe_runtime);
    assert_eq!(block_on(probe.mount()).unwrap().generation, 1);
    let probe_maintenance = probe
        .provision_maintenance_root(&probe_maintenance_provisioner)
        .unwrap();
    probe_device.reset_mutation_count();
    let probe_expected = import(&format_records(), &[]);
    let probe_view =
        block_on(probe.import_persistent_authority(&probe_maintenance, probe_expected.clone()))
            .unwrap();
    assert_exact_empty_authority(&probe_view, &probe_expected, "successful probe");
    let mutation_count = probe_device.mutation_count();
    assert!(mutation_count > 0);
    drop(probe);

    let failure_actions = [
        AuthorityFaultAction::FailNotSubmitted,
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::None),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Visible),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Durable),
    ];
    let cancel_actions = [
        AuthorityFaultAction::Pending(AuthorityEffect::None),
        AuthorityFaultAction::Pending(AuthorityEffect::Visible),
        AuthorityFaultAction::Pending(AuthorityEffect::Durable),
    ];
    let mut retry_count = 0;
    let mut recovered_count = 0;

    for mutation in 0..mutation_count {
        for action in failure_actions {
            let case = alloc::format!("mutation {mutation}/{mutation_count}, fault {action:?}");
            let device = AuthorityFaultDevice::from_durable(formatted.clone());
            let (runtime, _quota, maintenance_provisioner) =
                StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
            let mut store =
                SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
            assert_eq!(block_on(store.mount()).unwrap().generation, 1, "{case}");
            let maintenance = store
                .provision_maintenance_root(&maintenance_provisioner)
                .unwrap();
            device.arm(mutation, action);
            let result = block_on(
                store.import_persistent_authority(&maintenance, import(&format_records(), &[])),
            );
            assert!(result.is_err(), "{case}: injected fault was not reached");
            drop(store);

            if cold_recover_empty_authority_or_retry(device, &case) {
                retry_count += 1;
            } else {
                recovered_count += 1;
            }
        }

        for action in cancel_actions {
            let case = alloc::format!("mutation {mutation}/{mutation_count}, cancel {action:?}");
            let device = AuthorityFaultDevice::from_durable(formatted.clone());
            let (runtime, _quota, maintenance_provisioner) =
                StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
            let mut store =
                SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
            assert_eq!(block_on(store.mount()).unwrap().generation, 1, "{case}");
            let maintenance = store
                .provision_maintenance_root(&maintenance_provisioner)
                .unwrap();
            device.arm(mutation, action);
            let mut operation = Box::pin(
                store.import_persistent_authority(&maintenance, import(&format_records(), &[])),
            );
            assert!(
                matches!(poll_once(operation.as_mut()), Poll::Pending),
                "{case}: pending mutation was not reached"
            );
            drop(operation);
            drop(store);

            if cold_recover_empty_authority_or_retry(device, &case) {
                retry_count += 1;
            } else {
                recovered_count += 1;
            }
        }
    }

    assert!(
        retry_count > 0,
        "matrix must exercise retryable generation 1"
    );
    assert!(
        recovered_count > 0,
        "matrix must exercise durable generation 2 despite an ambiguous outcome"
    );
}

#[test]
fn object_then_grant_append_is_boot_local_until_grant_checkpoint() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-AUTH-TEST!!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[])))
            .unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    assert!(store.info().unwrap().object_count == 0);

    let bytes = b"unrooted until a later grant";
    let object_records = append_object_records(&format_records(), bytes);
    let object = find_object(&object_records);
    let appended = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        import(&object_records, &[]),
        &principal,
    ))
    .unwrap();
    let expected_physical = canonical_attributable_physical_bytes(bytes.len() as u64).unwrap();
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, bytes.len() as u64);
    assert_eq!(usage.committed_physical_bytes, expected_physical);
    assert_not_persistently_resolved(appended.view(), &object);
    let transient = appended.object_for_recovered(&object).unwrap();
    assert_eq!(block_on(read_handle(&store, transient)), bytes);
    assert_eq!(
        block_on(store.read_appended_object(&appended, &object)).unwrap(),
        bytes
    );
    let object_checkpoint = appended.view().checkpoint_generation();
    assert_eq!(store.info().unwrap().object_count, 1);
    let (object_view, transient_witness) = appended.into_parts();
    assert_not_persistently_resolved(&object_view, &object);
    assert_eq!(
        block_on(store.read_transient_object(&transient_witness, &object)).unwrap(),
        bytes
    );
    drop(object_view);

    // This models a power cut between object and grant: a fresh runtime sees
    // the complete logical stream, but no object authority or persistent quota.
    let (cold_runtime, _cold_quota, _cold_maintenance) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device.clone(), limits(), cold_runtime);
    block_on(cold.mount()).unwrap();
    let recovered =
        block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_not_persistently_resolved(&recovered, &object);
    let cold_principal = recovered.principals()[0].clone();
    let cold_usage = cold.principal_quota_usage(&cold_principal).unwrap();
    assert_eq!(cold_usage.committed_logical_bytes, 0);
    assert_eq!(cold_usage.committed_physical_bytes, 0);
    assert_eq!(recovered.record_stream().len(), object_records.len() * 512);
    drop(cold);

    let grant_records = append_grant_records(&object_records);
    let grant = root_grant();
    let rooted = block_on(store.append_persistent_authority(
        &writer,
        object_checkpoint,
        import(&grant_records, &[RootPolicy { grant }]),
        &principal,
    ))
    .unwrap();
    let persistent = rooted.view().object_for_recovered(&object).unwrap();
    assert_eq!(block_on(read_handle(&store, persistent)), bytes);
    assert_eq!(rooted.view().objects().len(), 1);
    // The later grant reuses the CAS mapping committed by the object append;
    // it must not consume one new mapping per authority checkpoint.
    assert_eq!(store.info().unwrap().object_count, 1);
    assert_eq!(
        rooted.view().principal_policies()[0].committed_logical_bytes,
        bytes.len() as u64
    );
    // The source capability is intentionally still alive. Its boot-local
    // charge was transferred by exact stable ID, so persistent recovery adds
    // one charge rather than stacking a second charge on top.
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, bytes.len() as u64);
    assert_eq!(usage.committed_physical_bytes, expected_physical);
    drop(transient_witness);
    let usage_after_source_drop = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage_after_source_drop, usage);
    drop(rooted);

    let (final_runtime, _final_quota, _final_maintenance) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut final_cold = SegmentStore::new_with_runtime_context(device, limits(), final_runtime);
    block_on(final_cold.mount()).unwrap();
    let recovered =
        block_on(final_cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert!(recovered.object_for_recovered(&object).is_some());
    assert_eq!(recovered.objects().len(), 1);
    let final_principal = recovered.principals()[0].clone();
    let final_usage = final_cold.principal_quota_usage(&final_principal).unwrap();
    assert_eq!(final_usage.committed_logical_bytes, bytes.len() as u64);
    assert_eq!(final_usage.committed_physical_bytes, expected_physical);
}

#[test]
fn tombstone_reactivates_live_source_charge_until_source_drop() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-REVOKE-QTA!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[])))
            .unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let bytes = b"source survives durable tombstone";
    let physical = canonical_attributable_physical_bytes(bytes.len() as u64).unwrap();
    let object_records = append_object_records(&format_records(), bytes);
    let object_append = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        import(&object_records, &[]),
        &principal,
    ))
    .unwrap();
    let (object_view, source) = object_append.into_parts();
    let grant_records = append_grant_records(&object_records);
    let grant = root_grant();
    let granted = block_on(store.append_persistent_authority(
        &writer,
        object_view.checkpoint_generation(),
        import(
            &grant_records,
            &[RootPolicy {
                grant: grant.clone(),
            }],
        ),
        &principal,
    ))
    .unwrap();
    let after_grant = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(after_grant.committed_logical_bytes, bytes.len() as u64);
    assert_eq!(after_grant.committed_physical_bytes, physical);

    let revoke_records = append_revoke_records(&grant_records, &grant);
    let revoked = block_on(store.append_persistent_authority(
        &writer,
        granted.view().checkpoint_generation(),
        import(&revoke_records, &[]),
        &principal,
    ))
    .unwrap();
    assert!(revoked.view().objects().is_empty());
    let after_tombstone = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(after_tombstone.committed_logical_bytes, bytes.len() as u64);
    assert_eq!(after_tombstone.committed_physical_bytes, physical);
    drop(source);
    let after_source_drop = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(after_source_drop.committed_logical_bytes, 0);
    assert_eq!(after_source_drop.committed_physical_bytes, 0);
}

#[test]
fn transient_quota_releases_on_drop_and_second_put_is_rejected_before_io() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-QUOTA-TEST!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let first_bytes = b"exact transient charge";
    let physical = canonical_attributable_physical_bytes(first_bytes.len() as u64).unwrap();
    let initial_import = import(&format_records(), &[])
        .with_system_principal(
            LEGACY_SYSTEM_PRINCIPAL,
            first_bytes.len() as u64,
            physical,
            false,
        )
        .unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, initial_import)).unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let first_records = append_object_records(&format_records(), first_bytes);
    let first = block_on(
        store.append_persistent_authority(
            &writer,
            initial.checkpoint_generation(),
            import(&first_records, &[])
                .with_system_principal(
                    LEGACY_SYSTEM_PRINCIPAL,
                    first_bytes.len() as u64,
                    physical,
                    false,
                )
                .unwrap(),
            &principal,
        ),
    )
    .unwrap();
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, first_bytes.len() as u64);
    assert_eq!(usage.committed_physical_bytes, physical);

    let before = device.snapshot();
    let (second_records, _) = append_next_object_records(&first_records, b"x");
    let rejected = block_on(
        store.append_persistent_authority(
            &writer,
            first.view().checkpoint_generation(),
            import(&second_records, &[])
                .with_system_principal(
                    LEGACY_SYSTEM_PRINCIPAL,
                    first_bytes.len() as u64,
                    physical,
                    false,
                )
                .unwrap(),
            &principal,
        ),
    );
    assert!(matches!(
        rejected,
        Err(PersistentAuthorityError::Cas(CasStoreError::Quota(
            QuotaError::LogicalQuotaExceeded
        )))
    ));
    assert_eq!(
        device.snapshot(),
        before,
        "quota denial must precede media I/O"
    );

    let first_checkpoint = first.view().checkpoint_generation();
    drop(first);
    let released = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(released.committed_logical_bytes, 0);
    assert_eq!(released.committed_physical_bytes, 0);

    // The source capability is gone, so its anonymous CAS mapping carries no
    // quota credit. Grant must perform a fresh admission even though the Blob
    // payload itself can deduplicate.
    let grant_records = append_grant_records(&first_records);
    let grant = root_grant();
    let attenuated = principal
        .attenuate(PrincipalQuotaLimits {
            logical_bytes: first_bytes.len() as u64 - 1,
            physical_bytes: physical,
        })
        .unwrap();
    let before_grant = device.snapshot();
    let denied_grant = block_on(
        store.append_persistent_authority(
            &writer,
            first_checkpoint,
            import(
                &grant_records,
                &[RootPolicy {
                    grant: grant.clone(),
                }],
            )
            .with_system_principal(
                LEGACY_SYSTEM_PRINCIPAL,
                first_bytes.len() as u64,
                physical,
                false,
            )
            .unwrap(),
            &attenuated,
        ),
    );
    assert!(matches!(
        denied_grant,
        Err(PersistentAuthorityError::Cas(CasStoreError::Quota(
            QuotaError::LogicalQuotaExceeded
        )))
    ));
    assert_eq!(
        device.snapshot(),
        before_grant,
        "grant re-admission denial must precede media I/O"
    );

    let granted = block_on(
        store.append_persistent_authority(
            &writer,
            first_checkpoint,
            import(&grant_records, &[RootPolicy { grant }])
                .with_system_principal(
                    LEGACY_SYSTEM_PRINCIPAL,
                    first_bytes.len() as u64,
                    physical,
                    false,
                )
                .unwrap(),
            &principal,
        ),
    )
    .unwrap();
    assert_eq!(granted.view().objects().len(), 1);
    let readmitted = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(readmitted.committed_logical_bytes, first_bytes.len() as u64);
    assert_eq!(readmitted.committed_physical_bytes, physical);
}

#[test]
fn singleton_replacement_quota_failure_precedes_authority_media() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-SINGLE-QTA!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let transient_bytes = b"runtime quota remains live";
    let physical = canonical_attributable_physical_bytes(transient_bytes.len() as u64).unwrap();
    let initial = block_on(
        store.import_persistent_authority(
            &maintenance,
            import(&format_records(), &[])
                .with_system_principal(
                    LEGACY_SYSTEM_PRINCIPAL,
                    transient_bytes.len() as u64,
                    physical,
                    false,
                )
                .unwrap(),
        ),
    )
    .unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let object_records = append_object_records(&format_records(), transient_bytes);
    let transient = block_on(
        store.append_persistent_authority(
            &writer,
            initial.checkpoint_generation(),
            import(&object_records, &[])
                .with_system_principal(
                    LEGACY_SYSTEM_PRINCIPAL,
                    transient_bytes.len() as u64,
                    physical,
                    false,
                )
                .unwrap(),
            &principal,
        ),
    )
    .unwrap();
    let before_media = device.snapshot();
    let before_generation = store.info().unwrap().generation;
    let update = PersistentSingletonUpdate::new(
        Vec::new(),
        vec![kind()],
        POLICY.to_vec(),
        kind(),
        b"x".to_vec(),
    )
    .unwrap();

    assert!(matches!(
        block_on(store.put_persistent_singleton(
            &writer,
            transient.view().checkpoint_generation(),
            update,
        )),
        Err(PersistentAuthorityError::InvalidQuotaPolicy)
    ));
    assert_eq!(device.snapshot(), before_media);
    assert_eq!(store.info().unwrap().generation, before_generation);
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, transient_bytes.len() as u64);
    assert_eq!(usage.committed_physical_bytes, physical);
}

#[test]
fn combined_persistent_and_runtime_usage_rejects_before_authority_publication() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-MIXED-QTA!!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();

    let object_bytes = b"mixed quota item";
    let per_object_physical =
        canonical_attributable_physical_bytes(object_bytes.len() as u64).unwrap();
    let logical_limit = object_bytes.len() as u64 * 2;
    let physical_limit = per_object_physical * 2;

    // A starts as an exact persistent charge installed by the migration-only
    // import path.
    let object_a_records = append_object_records(&format_records(), object_bytes);
    let rooted_a_records = append_grant_records(&object_a_records);
    let grant_a = root_grant();
    let initial = block_on(
        store.import_persistent_authority(
            &maintenance,
            import(
                &rooted_a_records,
                &[RootPolicy {
                    grant: grant_a.clone(),
                }],
            )
            .with_system_principal(
                LEGACY_SYSTEM_PRINCIPAL,
                logical_limit,
                physical_limit,
                false,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let principal = initial.principals()[0].clone();

    // B remains boot-local. A persistent + B runtime now exactly saturates
    // both quota dimensions.
    let (object_b_records, _) = append_next_object_records(&rooted_a_records, object_bytes);
    let append_b = block_on(
        store.append_persistent_authority(
            &writer,
            initial.checkpoint_generation(),
            import(
                &object_b_records,
                &[RootPolicy {
                    grant: grant_a.clone(),
                }],
            )
            .with_system_principal(
                LEGACY_SYSTEM_PRINCIPAL,
                logical_limit,
                physical_limit,
                false,
            )
            .unwrap(),
            &principal,
        ),
    )
    .unwrap();
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, logical_limit);
    assert_eq!(usage.committed_physical_bytes, physical_limit);

    // C would become persistent, and its persistent policy totals are valid in
    // isolation (A + C). Combined with live runtime B, however, admission must
    // fail before any CAS or authority media publication.
    let (object_c_records, object_c_id) =
        append_next_object_records(&object_b_records, object_bytes);
    let (rooted_c_records, grant_c) = append_root_grant_records(&object_c_records, object_c_id);
    let before_checkpoint = append_b.view().checkpoint_generation();
    let before_generation = store.info().unwrap().generation;
    let before_media = device.snapshot();
    let rejected = block_on(
        store.append_persistent_authority(
            &writer,
            before_checkpoint,
            import(
                &rooted_c_records,
                &[RootPolicy { grant: grant_a }, RootPolicy { grant: grant_c }],
            )
            .with_system_principal(
                LEGACY_SYSTEM_PRINCIPAL,
                logical_limit,
                physical_limit,
                false,
            )
            .unwrap(),
            &principal,
        ),
    );
    assert!(matches!(
        rejected,
        Err(PersistentAuthorityError::Cas(CasStoreError::Quota(
            QuotaError::LogicalQuotaExceeded
        )))
    ));
    assert_eq!(device.snapshot(), before_media);
    assert_eq!(store.info().unwrap().generation, before_generation);
    let current =
        block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_eq!(current.checkpoint_generation(), before_checkpoint);
    assert_eq!(current.record_stream().len(), object_b_records.len() * 512);
}

#[test]
fn cold_view_requires_exact_policy_object_bindings() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-BIND-TEST!!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();

    let expected_bytes = [0x31; 37];
    let object_records = append_object_records(&format_records(), &expected_bytes);
    let rooted_records = append_grant_records(&object_records);
    let roots = [RootPolicy {
        grant: root_grant(),
    }];
    let exact = import(&rooted_records, &roots);
    let view = block_on(store.import_persistent_authority(&maintenance, exact.clone())).unwrap();
    assert!(block_on(store.verify_persistent_authority_import(&view, &exact)).is_ok());

    // Persistent authority may bind only a RAW logical object mapping. Even
    // if every stable/V2 identity and immutable Blob byte is otherwise exact,
    // a typed-reference mapping is an authority edge and must fail closed.
    assert!(matches!(
        block_on(
            store.test_build_persistent_view_with_reference_codec(&view, REFERENCE_CODEC_TYPED_V1,)
        ),
        Err(PersistentAuthorityError::Store(crate::StoreError::Corrupt))
    ));

    // Matching stable identity, kind, and length must not authenticate a
    // binding to different immutable content.
    let mut wrong_bytes = exact.clone();
    wrong_bytes.test_replace_admitted_object_bytes(2, &[0x32; 37]);
    assert!(matches!(
        block_on(store.verify_persistent_authority_import(&view, &wrong_bytes)),
        Err(PersistentAuthorityError::PolicyMismatch)
    ));

    // A view with one binding omitted from the compiled-policy import is an
    // extra authority edge and must fail closed.
    let mut omitted = exact.clone();
    omitted.test_set_object_admitted(2, false);
    assert!(matches!(
        block_on(store.verify_persistent_authority_import(&view, &omitted)),
        Err(PersistentAuthorityError::PolicyMismatch)
    ));

    // Conversely, an exact compiled-policy object without a binding in the
    // recovered view cannot be silently dropped. Add a second valid logical
    // object to the private expected set while retaining the same view.
    let (extended_records, second_object) =
        append_next_object_records(&rooted_records, b"unbound expected object");
    let mut missing = import(&extended_records, &roots);
    missing.test_set_object_admitted(second_object.get(), true);
    // Isolate the set check from the stream check so this fixture proves the
    // checker rejects the missing private binding directly.
    missing.record_stream = exact.record_stream.clone();
    assert!(matches!(
        block_on(store.verify_persistent_authority_import(&view, &missing)),
        Err(PersistentAuthorityError::PolicyMismatch)
    ));
}

#[test]
fn eight_segment_authority_append_runs_one_bounded_gc_and_recovers() {
    let device = MemoryDevice::with_segments(8);
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-GC-8SEG!!!!").unwrap(),
        cleaner_reserve_segments: 2,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[])))
            .unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let mut expected_generation = initial.checkpoint_generation();
    let mut records = format_records();
    let mut observed_gc = false;

    // Each append first publishes one anonymous CAS object and then the
    // successor authority checkpoint. Four appends cannot fit in the six
    // ordinary segments, so at least one reaches CleanerReserve and exercises
    // the single foreground-GC retry. No append retains its transient witness.
    for discriminator in 0_u8..4 {
        let bytes = vec![discriminator; 900];
        let (next_records, _) = append_next_object_records(&records, &bytes);
        let appended = block_on(store.append_persistent_authority(
            &writer,
            expected_generation,
            import(&next_records, &[]),
            &principal,
        ))
        .unwrap();
        let next_generation = appended.view().checkpoint_generation();
        observed_gc |= next_generation > expected_generation + 2;
        assert_eq!(
            appended.view().record_stream().len(),
            next_records.len() * 512
        );
        expected_generation = next_generation;
        records = next_records;
        drop(appended);
    }
    assert!(
        observed_gc,
        "the eight-segment fixture must force foreground GC"
    );
    assert!(store.info().unwrap().free_segments >= 2);
    drop(store);

    let (cold_runtime, _cold_quota, cold_maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), cold_runtime);
    block_on(cold.mount()).unwrap();
    let recovered =
        block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_eq!(recovered.checkpoint_generation(), expected_generation);
    assert_eq!(recovered.record_stream().len(), records.len() * 512);
    assert!(recovered.objects().is_empty());
    let maintenance = cold
        .provision_maintenance_root(&cold_maintenance_provisioner)
        .unwrap();
    assert_eq!(
        block_on(cold.scrub(&maintenance)).unwrap().status,
        ScrubStatus::Healthy
    );
}

#[test]
fn delayed_grants_keep_duplicate_content_stable_objects_independent() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-DUP-CONTENT").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[])))
            .unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();

    let bytes = b"same bytes, independent stable identities";
    let (object_a_records, object_a_id) = append_next_object_records(&format_records(), bytes);
    let object_a = vibeos_durable_format::preflight_recovery(&object_a_records, store_id())
        .unwrap()
        .committed_objects()[0]
        .clone();
    let append_a = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        import(&object_a_records, &[]),
        &principal,
    ))
    .unwrap();
    let mut expected_generation = append_a.view().checkpoint_generation();
    drop(append_a);

    // B has identical content but receives authority first. Canonical
    // promotion reserves A's older anonymous mapping before allocating B, so
    // the two stable identities never collapse onto one revocation domain.
    let (object_b_records, object_b_id) = append_next_object_records(&object_a_records, bytes);
    let (grant_b_records, grant_b) = append_root_grant_records(&object_b_records, object_b_id);
    let append_b = block_on(store.append_persistent_authority(
        &writer,
        expected_generation,
        import(
            &grant_b_records,
            &[RootPolicy {
                grant: grant_b.clone(),
            }],
        ),
        &principal,
    ))
    .unwrap();
    expected_generation = append_b.view().checkpoint_generation();
    assert_eq!(append_b.view().objects().len(), 1);
    assert_eq!(store.info().unwrap().object_count, 2);
    drop(append_b);

    let (grant_a_records, grant_a) = append_root_grant_records(&grant_b_records, object_a_id);
    let roots = [
        RootPolicy {
            grant: grant_a.clone(),
        },
        RootPolicy { grant: grant_b },
    ];
    let append_a_grant = block_on(store.append_persistent_authority(
        &writer,
        expected_generation,
        import(&grant_a_records, &roots),
        &principal,
    ))
    .unwrap();
    assert_eq!(append_a_grant.view().objects().len(), 2);
    // A's source authority was dropped, so grant performs fresh quota
    // admission but safely adopts A's exact anonymous RAW mapping. A and B
    // remain independent ObjectMappings while their Blob content deduplicates.
    assert_eq!(store.info().unwrap().object_count, 2);
    assert_eq!(
        block_on(read_handle(
            &store,
            append_a_grant
                .view()
                .object_for_recovered(&object_a)
                .unwrap()
        )),
        bytes
    );
    let final_generation = append_a_grant.view().checkpoint_generation();
    drop(append_a_grant);
    drop(store);

    let (cold_runtime, _cold_quota, _cold_maintenance) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), cold_runtime);
    block_on(cold.mount()).unwrap();
    let recovered =
        block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_eq!(recovered.checkpoint_generation(), final_generation);
    assert_eq!(recovered.objects().len(), 2);
}
