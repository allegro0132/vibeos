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
    FsTreeKind, PageDevice, PageDeviceInfo, PersistentAuthorityError, PersistentAuthorityImport,
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

const FAULT_FS_NAMESPACE: u128 = 0x4653_2d46_4155_4c54_2d4e_5301;

fn governed_fs_runtime() -> (
    StoreRuntimeContext,
    crate::StorageQuotaProvisioner,
    crate::StoreMaintenanceProvisioner,
) {
    StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
        &crate::fs_typed_reference_kinds(),
    )
    .unwrap()
}

fn cold_fs_generation(device: AuthorityFaultDevice, case: &str) -> u64 {
    device.power_cycle();
    let (runtime, _quota, provisioner) = governed_fs_runtime();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(cold.mount()).unwrap_or_else(|error| panic!("{case}: cold mount: {error:?}"));
    let root = block_on(cold.recover_fs_root(FAULT_FS_NAMESPACE))
        .unwrap_or_else(|error| panic!("{case}: recover root: {error:?}"))
        .unwrap_or_else(|| panic!("{case}: file-tree root disappeared"));
    let generation = root.generation();
    assert!(
        matches!(generation, 1 | 2),
        "{case}: torn generation {generation}"
    );
    let maintenance = cold.provision_maintenance_root(&provisioner).unwrap();
    assert_eq!(
        block_on(cold.scrub(&maintenance))
            .unwrap_or_else(|error| panic!("{case}: scrub: {error:?}"))
            .status,
        ScrubStatus::Healthy,
        "{case}"
    );
    generation
}

#[test]
fn file_tree_authority_root_switch_is_power_cut_atomic_at_every_mutation() {
    let seed_device = AuthorityFaultDevice::blank();
    let (runtime, _quota, provisioner) = governed_fs_runtime();
    let mut seed = SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    block_on(seed.import_persistent_authority(&maintenance, import(&format_records(), &[])))
        .unwrap();
    let inode = block_on(seed.commit_fs_cow_tree_for_maintenance(
        &maintenance,
        None,
        FsTreeKind::Inode,
        1,
        &[],
    ))
    .unwrap();
    let dirent = block_on(seed.commit_fs_cow_tree_for_maintenance(
        &maintenance,
        None,
        FsTreeKind::Dirent,
        1,
        &[],
    ))
    .unwrap();
    let root = block_on(seed.commit_fs_root_for_maintenance(
        &maintenance,
        FAULT_FS_NAMESPACE,
        1,
        2,
        1,
        &inode,
        &dirent,
    ))
    .unwrap();
    assert_eq!(
        block_on(seed.compare_exchange_fs_root_for_maintenance(
            &maintenance,
            FAULT_FS_NAMESPACE,
            0,
            &root,
        ))
        .unwrap(),
        1
    );
    drop(seed);
    seed_device.power_cycle();
    let seeded = seed_device.durable_image();

    let prepare_candidate = |device: &AuthorityFaultDevice| {
        let (runtime, _quota, provisioner) = governed_fs_runtime();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(store.mount()).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let previous = block_on(store.recover_fs_root(FAULT_FS_NAMESPACE))
            .unwrap()
            .unwrap();
        assert_eq!(previous.generation(), 1);
        let inode = block_on(store.commit_fs_cow_tree_for_maintenance(
            &maintenance,
            Some(&previous),
            FsTreeKind::Inode,
            2,
            &[],
        ))
        .unwrap();
        let dirent = block_on(store.commit_fs_cow_tree_for_maintenance(
            &maintenance,
            Some(&previous),
            FsTreeKind::Dirent,
            2,
            &[],
        ))
        .unwrap();
        let next = block_on(store.commit_fs_root_for_maintenance(
            &maintenance,
            FAULT_FS_NAMESPACE,
            2,
            2,
            1,
            &inode,
            &dirent,
        ))
        .unwrap();
        (store, maintenance, next)
    };

    let probe_device = AuthorityFaultDevice::from_durable(seeded.clone());
    let (mut probe, probe_maintenance, probe_root) = prepare_candidate(&probe_device);
    probe_device.reset_mutation_count();
    assert_eq!(
        block_on(probe.compare_exchange_fs_root_for_maintenance(
            &probe_maintenance,
            FAULT_FS_NAMESPACE,
            1,
            &probe_root,
        ))
        .unwrap(),
        2
    );
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
    let mut old = 0;
    let mut new = 0;
    for mutation in 0..mutation_count {
        for action in failure_actions {
            let case = alloc::format!("FS root mutation {mutation}/{mutation_count}, {action:?}");
            let device = AuthorityFaultDevice::from_durable(seeded.clone());
            let (mut store, maintenance, next) = prepare_candidate(&device);
            device.arm(mutation, action);
            assert!(
                block_on(store.compare_exchange_fs_root_for_maintenance(
                    &maintenance,
                    FAULT_FS_NAMESPACE,
                    1,
                    &next,
                ))
                .is_err(),
                "{case}: injected fault was not reached"
            );
            drop(store);
            match cold_fs_generation(device, &case) {
                1 => old += 1,
                2 => new += 1,
                _ => unreachable!(),
            }
        }
        for action in cancel_actions {
            let case = alloc::format!("FS root mutation {mutation}/{mutation_count}, {action:?}");
            let device = AuthorityFaultDevice::from_durable(seeded.clone());
            let (mut store, maintenance, next) = prepare_candidate(&device);
            device.arm(mutation, action);
            let mut operation = Box::pin(store.compare_exchange_fs_root_for_maintenance(
                &maintenance,
                FAULT_FS_NAMESPACE,
                1,
                &next,
            ));
            assert!(
                matches!(poll_once(operation.as_mut()), Poll::Pending),
                "{case}"
            );
            drop(operation);
            drop(store);
            match cold_fs_generation(device, &case) {
                1 => old += 1,
                2 => new += 1,
                _ => unreachable!(),
            }
        }
    }
    assert!(
        old > 0 && new > 0,
        "fault matrix must recover both old and new roots"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    OutsideRange,
}

#[derive(Clone)]
struct MemoryDevice {
    pages: Arc<Mutex<BTreeMap<u64, Page>>>,
    segments: u64,
    probes: Arc<Mutex<Vec<(u64, std::time::Instant)>>>,
}

impl MemoryDevice {
    fn blank() -> Self {
        Self::with_segments(SEGMENTS)
    }

    fn with_segments(segments: u64) -> Self {
        Self {
            pages: Arc::new(Mutex::new(BTreeMap::new())),
            segments,
            probes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn take_probes(&self) -> Vec<(u64, std::time::Instant)> {
        core::mem::take(&mut *self.probes.lock().unwrap())
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
            if page >= u64::MAX - 64 {
                self.probes
                    .lock()
                    .unwrap()
                    .push((u64::MAX - page, std::time::Instant::now()));
            }
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
    reads: usize,
    read_pages: Option<BTreeMap<u64, usize>>,
    read_trace: Option<Vec<u64>>,
    writes: usize,
    flushes: usize,
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
                reads: 0,
                read_pages: None,
                read_trace: None,
                writes: 0,
                flushes: 0,
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
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.reads = 0;
        if let Some(pages) = &mut media.read_pages { pages.clear(); }
        if let Some(trace) = &mut media.read_trace { trace.clear(); }
        media.writes = 0;
        media.flushes = 0;
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

    fn next_action(&self, flush: bool) -> AuthorityFaultAction {
        let mut media = self.media.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        if flush { media.flushes += 1; } else { media.writes += 1; }
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
        let mut media = self.media.lock().unwrap();
        media.reads += 1;
        if let Some(pages) = &mut media.read_pages { *pages.entry(page).or_default() += 1; }
        if let Some(trace) = &mut media.read_trace { trace.push(page); }
        output.fill(0);
        if let Some(stored) = media.visible.get(&page) {
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
        match self.next_action(false) {
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
        match self.next_action(true) {
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

#[test]
fn quiescent_compaction_is_atomic_at_every_mutation_and_cancel_point() {
    let seed_device = AuthorityFaultDevice::blank();
    let (runtime, _quota, provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut seed = SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    let initial = block_on(seed.import_persistent_authority(
        &maintenance, import(&format_records(), &[]))).unwrap();
    let writer = seed.derive_persistent_authority_writer(&maintenance).unwrap();
    let records = append_object_records(&format_records(), &vec![0x81; 4096]);
    let appended = block_on(seed.append_persistent_authority(&writer,
        initial.checkpoint_generation(), import(&records, &[]), &initial.principals()[0])).unwrap();
    let old_generation = appended.view().checkpoint_generation();
    drop(appended);
    drop(seed);
    seed_device.power_cycle();
    let image = seed_device.durable_image();
    let prepare = |device: AuthorityFaultDevice| {
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(store.mount()).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let writer = store.derive_persistent_authority_writer(&maintenance).unwrap();
        (store, writer)
    };
    let probe_device = AuthorityFaultDevice::from_durable(image.clone());
    let (mut probe, writer) = prepare(probe_device.clone());
    probe_device.reset_mutation_count();
    let compact = block_on(probe.compact_unpinned_persistent_authority(
        &writer, old_generation, import(&records, &[]), |r| Ok(import(r, &[]))))
        .unwrap().unwrap();
    let expected = compact.record_stream().to_vec();
    let mutations = probe_device.mutation_count();
    assert!(mutations > 0);
    let original = import(&records, &[]).record_stream().to_vec();
    let actions = [
        AuthorityFaultAction::FailNotSubmitted,
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::None),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Visible),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Durable),
        AuthorityFaultAction::Pending(AuthorityEffect::None),
        AuthorityFaultAction::Pending(AuthorityEffect::Visible),
        AuthorityFaultAction::Pending(AuthorityEffect::Durable),
    ];
    let mut old_count = 0;
    let mut new_count = 0;
    for mutation in 0..mutations {
        for action in actions {
            let case = alloc::format!("mutation {mutation}/{mutations}: {action:?}");
            let device = AuthorityFaultDevice::from_durable(image.clone());
            let (mut store, writer) = prepare(device.clone());
            device.arm(mutation, action);
            let mut operation = Box::pin(store.compact_unpinned_persistent_authority(
                &writer, old_generation, import(&records, &[]), |r| Ok(import(r, &[]))));
            if matches!(action, AuthorityFaultAction::Pending(_)) {
                assert!(matches!(poll_once(operation.as_mut()), Poll::Pending), "{case}");
            } else {
                assert!(block_on(operation.as_mut()).is_err(), "{case}");
            }
            drop(operation);
            let reopened = store.pins.try_close_empty_root_admission().unwrap()
                .unwrap_or_else(|| panic!("{case}: admission remained closed"));
            drop(reopened);
            drop(store);
            device.power_cycle();
            let (cold, _) = prepare(device);
            let view = block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY)))
                .unwrap_or_else(|error| panic!("{case}: recovery: {error:?}"));
            if view.checkpoint_generation() == old_generation {
                assert_eq!(view.record_stream(), original, "{case}");
                old_count += 1;
            } else {
                assert_eq!(view.checkpoint_generation(), old_generation + 1, "{case}");
                assert_eq!(view.record_stream(), expected, "{case}");
                new_count += 1;
            }
        }
    }
    assert!(old_count > 0 && new_count > 0);
}

#[test]
fn quiescent_compaction_preserves_live_witnesses_and_reclaims_only_after_drop() {
    for external in [false, true] {
        let device = MemoryDevice::blank();
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"M7.7-AUTH-TEST!!").unwrap(),
            cleaner_reserve_segments: 4, limits: limits(),
        })).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let initial = block_on(store.import_persistent_authority(
            &maintenance, import(&format_records(), &[]))).unwrap();
        let principal = initial.principals()[0].clone();
        let writer = store.derive_persistent_authority_writer(&maintenance).unwrap();
        let payload = vec![0x61; 4096];
        let records = if external {
            let root = vibeos_blob_format::BlobDescriptor::from_content(OBJECT_KIND_RAW, &payload)
                .unwrap().root;
            let first = append_external_object_records(&format_records(), payload.len() as u64, root).0;
            append_external_object_records(&first, payload.len() as u64, root).0
        } else { append_object_records(&format_records(), &payload) };
        let recovered = find_object(&records);
        let mut update = import(&records, &[]);
        if external {
            let preflight = vibeos_durable_format::preflight_recovery(&records, store_id()).unwrap();
            for object in preflight.committed_objects() {
                update.attach_external_payload(object.object_id.get(), payload.clone()).unwrap();
            }
        }
        let appended = block_on(store.append_persistent_authority(
            &writer, initial.checkpoint_generation(), update, &principal)).unwrap();
        let (view, witness) = appended.into_parts();
        let generation = view.checkpoint_generation();
        assert!(store.transient_witness_covers_runtime_roots(&witness));
        assert!(!store.quiescent_compaction_hint());
        let owner = store.pins.allocate_owner().unwrap();
        let unrelated = store.pins.pin_root(
            crate::pins::RootKey::new(u128::MAX, 1, OBJECT_KIND_RAW).unwrap(),
            crate::pins::RuntimeRootClass::InvocationLease, owner, crate::pins::PinAdmission::Ordinary,
        ).unwrap();
        assert!(!store.transient_witness_covers_runtime_roots(&witness));
        drop(unrelated);
        let reader = store.pins.pin_read_generation(generation, owner, crate::pins::PinAdmission::Ordinary).unwrap();
        assert!(!store.transient_witness_covers_runtime_roots(&witness));
        drop(reader);
        assert!(store.transient_witness_covers_runtime_roots(&witness));
        let (foreign_runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut foreign = SegmentStore::new_with_runtime_context(store.device.clone(), limits(), foreign_runtime);
        block_on(foreign.mount()).unwrap();
        assert!(!foreign.transient_witness_covers_runtime_roots(&witness));
        drop(foreign);

        assert!(matches!(block_on(store.compact_unpinned_persistent_authority(
            &writer, generation - 1, import(&records, &[]), |_| panic!("stale"))),
            Err(PersistentAuthorityError::GenerationMismatch)));
        assert!(block_on(store.compact_unpinned_persistent_authority(
            &writer, generation, import(&records, &[]), |_| panic!("live witness")))
            .unwrap().is_none());
        assert_eq!(block_on(store.read_transient_object(&witness, &recovered)).unwrap(), payload);
        drop(witness);
        drop(view);
        assert!(store.quiescent_compaction_hint());
        let reader = store.pins.pin_read_generation(generation, owner, crate::pins::PinAdmission::Ordinary).unwrap();
        assert!(!store.quiescent_compaction_hint());
        drop(reader);
        assert!(store.quiescent_compaction_hint());
        for wrong_stream in [false, true] {
            let result = block_on(store.compact_unpinned_persistent_authority(
                &writer, generation, import(&records, &[]), |_| {
                    if wrong_stream { Ok(import(&records, &[])) }
                    else { Err(PersistentAuthorityError::PolicyMismatch) }
                }));
            assert!(matches!(result, Err(PersistentAuthorityError::PolicyMismatch)));
            assert_eq!(store.info().unwrap().generation, generation);
            let reopened = store.pins.try_close_empty_root_admission().unwrap().unwrap();
            drop(reopened);
        }
        let compacted = block_on(store.compact_unpinned_persistent_authority(
            &writer, generation, import(&records, &[]), |compact| Ok(import(compact, &[]))))
            .unwrap().unwrap();
        let compact_records: Vec<[u8; vibeos_durable_format::RECORD_SIZE]> = compacted.record_stream()
            .chunks_exact(vibeos_durable_format::RECORD_SIZE).map(|r| r.try_into().unwrap()).collect();
        let before = vibeos_durable_format::preflight_recovery(&records, store_id()).unwrap();
        let after = vibeos_durable_format::preflight_recovery(&compact_records, store_id()).unwrap();
        assert!(after.committed_objects().is_empty());
        assert_eq!(after.id_high_water(), before.id_high_water());
        assert_eq!(compacted.checkpoint_generation(), generation + 1);
        drop(compacted);
        block_on(store.mount()).unwrap();
        let cold = block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
        assert_eq!(cold.record_stream().len(), compact_records.len() * vibeos_durable_format::RECORD_SIZE);
        assert_eq!(cold.checkpoint_generation(), generation + 1);
    }
}

#[test]
fn compacted_replace_preserves_stale_handles_and_witnesses() {
    for external in [false, true] {
        compacted_replace_preserves_handles(external);
    }
}

fn compacted_replace_preserves_handles(external: bool) {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
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

    // Granted object A, then ungranted object B.
    let bytes_a = b"granted object a";
    let external_bytes = vec![0x71; 4096];
    let bytes_b: &[u8] = if external {
        &external_bytes
    } else {
        b"boot-local object b"
    };
    let object_records = append_object_records(&format_records(), bytes_a);
    let object_a = find_object(&object_records);
    let appended = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        import(&object_records, &[]),
        &principal,
    ))
    .unwrap();
    let after_object = appended.view().checkpoint_generation();
    drop(appended);
    let grant_records = append_grant_records(&object_records);
    let grant = root_grant();
    let rooted = block_on(store.append_persistent_authority(
        &writer,
        after_object,
        import(&grant_records, &[RootPolicy {
            grant: grant.clone(),
        }]),
        &principal,
    ))
    .unwrap();
    let stale_persistent = rooted
        .view()
        .object_for_recovered(&object_a)
        .unwrap()
        .clone();
    let after_grant = rooted.view().checkpoint_generation();
    drop(rooted);
    store.set_catalog_delta_policy(crate::CatalogDeltaPolicy::Always);
    let (both_records, object_b_id) = if external {
        let descriptor = vibeos_blob_format::BlobDescriptor::from_content(OBJECT_KIND_RAW, bytes_b)
            .unwrap();
        append_external_object_records(&grant_records, bytes_b.len() as u64, descriptor.root)
    } else {
        append_next_object_records(&grant_records, bytes_b)
    };
    let object_b = vibeos_durable_format::preflight_recovery(&both_records, store_id())
        .unwrap()
        .committed_objects()
        .iter()
        .find(|object| object.object_id == object_b_id)
        .unwrap()
        .clone();
    let mut update_b = import(&both_records, &[RootPolicy { grant: grant.clone() }]);
    if external {
        update_b
            .attach_external_payload(object_b_id.get(), bytes_b.to_vec())
            .unwrap();
    }
    let appended_b = block_on(store.append_persistent_authority(
        &writer,
        after_grant,
        update_b,
        &principal,
    ))
    .unwrap();
    let (view_b, witness_b) = appended_b.into_parts();
    assert!(!store.transient_witness_covers_runtime_roots(&witness_b));
    let after_b = view_b.checkpoint_generation();
    let replay_before = store.info().unwrap().replay_count;
    assert!(replay_before > 0, "fixture must have catalog deltas to preserve");
    drop(view_b);

    // Compact (runtime policy: keep the ungranted object) and replace.
    let preflight =
        vibeos_durable_format::preflight_recovery(&both_records, store_id()).unwrap();
    let compacted = preflight.compact(false).unwrap();
    let compacted_preflight = vibeos_durable_format::preflight_recovery(&compacted, store_id())
        .unwrap();
    assert_eq!(compacted_preflight.id_high_water(), preflight.id_high_water());
    assert!(
        compacted.len() < both_records.len(),
        "redundant high-water records must fold away ({} -> {})",
        both_records.len(),
        compacted.len(),
    );
    let replaced = block_on(store.replace_persistent_authority(
        &writer,
        after_b,
        import(&compacted, &[RootPolicy { grant }]),
    ))
    .unwrap();

    assert_eq!(store.info().unwrap().replay_count, replay_before);
    // Force the checkpoint's catalog replay to be read from media before
    // resolving old live handles; the in-memory CAS can mask a missing tail.
    block_on(store.mount()).unwrap();
    assert_eq!(store.info().unwrap().replay_count, replay_before);
    // Handles minted before the replacement must still read.
    assert_eq!(block_on(read_handle(&store, &stale_persistent)), bytes_a);
    assert_eq!(
        block_on(store.read_transient_object(&witness_b, &object_b)).unwrap(),
        bytes_b
    );
    // The replacement view resolves object A persistently under its new
    // sequence numbers.
    let object_a_compacted = vibeos_durable_format::preflight_recovery(&compacted, store_id())
        .unwrap()
        .committed_objects()
        .iter()
        .find(|object| object.object_id.get() == 2)
        .unwrap()
        .clone();
    let fresh = replaced.object_for_recovered(&object_a_compacted).unwrap();
    assert_eq!(block_on(read_handle(&store, fresh)), bytes_a);
}

fn append_external_object_records(
    records: &[[u8; vibeos_durable_format::RECORD_SIZE]],
    byte_len: u64,
    merkle_root: [u8; 32],
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
    let (transaction, _) = vibeos_durable_format::preview_external_object_transaction(
        &chain,
        TransactionId::new(transaction).unwrap(),
        object_id,
        kind(),
        byte_len,
        merkle_root,
    )
    .unwrap();
    output.extend(transaction.records);
    (output, object_id)
}

#[test]
fn external_object_appends_recover_and_verify_end_to_end() {
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

    // Content larger than one page, with its content address computed
    // exactly the way the blob writer will.
    let content: Vec<u8> = (0..200_000_u32).map(|at| (at * 7 + 3) as u8).collect();
    let declared = vibeos_blob_format::BlobDescriptor::from_content(OBJECT_KIND_RAW, &content)
        .unwrap()
        .root;
    let (records, object_id) =
        append_external_object_records(&format_records(), content.len() as u64, declared);
    let recovered_external = vibeos_durable_format::preflight_recovery(&records, store_id())
        .unwrap()
        .committed_objects()
        .iter()
        .find(|object| object.object_id == object_id)
        .unwrap()
        .clone();
    assert!(recovered_external.is_external());

    // A fresh external object without its payload must fail closed. Run the
    // starved attempt on its own store so its released reservations cannot
    // interact with the happy path below.
    {
        let device = MemoryDevice::blank();
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut starved_store =
            SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(starved_store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"M7.7-AUTH-TEST!!").unwrap(),
            cleaner_reserve_segments: 4,
            limits: limits(),
        }))
        .unwrap();
        let maintenance = starved_store
            .provision_maintenance_root(&provisioner)
            .unwrap();
        let initial = block_on(
            starved_store
                .import_persistent_authority(&maintenance, import(&format_records(), &[])),
        )
        .unwrap();
        let principal = initial.principals()[0].clone();
        let writer = starved_store
            .derive_persistent_authority_writer(&maintenance)
            .unwrap();
        let starved = import(&records, &[]);
        assert!(block_on(starved_store.append_persistent_authority(
            &writer,
            initial.checkpoint_generation(),
            starved,
            &principal,
        ))
        .is_err());
    }

    // With the payload attached, the append publishes object and record
    // stream under one checkpoint, readable through the transient witness.
    let mut with_payload = import(&records, &[]);
    with_payload
        .attach_external_payload(object_id.get(), content.clone())
        .unwrap();
    let appended = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        with_payload,
        &principal,
    ))
    .unwrap();
    let usage = store.principal_quota_usage(&principal).unwrap();
    assert_eq!(usage.committed_logical_bytes, content.len() as u64);
    let (view, witness) = appended.into_parts();
    assert_eq!(
        block_on(store.read_transient_object(&witness, &recovered_external)).unwrap(),
        content
    );
    let after_append = view.checkpoint_generation();
    drop(view);

    // A wrong declared root must never publish: rebuild the same records
    // with a tampered root and a fresh store to prove the writer-side check.
    {
        let device = MemoryDevice::blank();
        let (runtime, _quota, provisioner) =
            StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut poisoned = SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(poisoned.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"M7.7-AUTH-TEST!!").unwrap(),
            cleaner_reserve_segments: 4,
            limits: limits(),
        }))
        .unwrap();
        let maintenance = poisoned.provision_maintenance_root(&provisioner).unwrap();
        let initial = block_on(
            poisoned.import_persistent_authority(&maintenance, import(&format_records(), &[])),
        )
        .unwrap();
        let principal = initial.principals()[0].clone();
        let writer = poisoned
            .derive_persistent_authority_writer(&maintenance)
            .unwrap();
        let mut tampered_root = declared;
        tampered_root[0] ^= 1;
        let (records, object_id) = append_external_object_records(
            &format_records(),
            content.len() as u64,
            tampered_root,
        );
        let mut tampered = import(&records, &[]);
        tampered
            .attach_external_payload(object_id.get(), content.clone())
            .unwrap();
        assert!(block_on(poisoned.append_persistent_authority(
            &writer,
            initial.checkpoint_generation(),
            tampered,
            &principal,
        ))
        .is_err());
    }

    // A later grant admits the external object into the durable view. Its
    // content never re-enters the stream: the binding reuses the blob the
    // fused append committed.
    let (grant_records, grant) = append_root_grant_records(&records, object_id);
    let rooted = block_on(store.append_persistent_authority(
        &writer,
        after_append,
        import(&grant_records, &[RootPolicy {
            grant: grant.clone(),
        }]),
        &principal,
    ))
    .unwrap();
    let handle = rooted
        .view()
        .object_for_recovered(&recovered_external)
        .unwrap();
    assert_eq!(block_on(read_handle(&store, handle)), content);
    let after_grant = rooted.view().checkpoint_generation();
    drop(rooted);

    // Cold boot: the granted external object resolves persistently through
    // its already-durable blob and the full import verification accepts the
    // stream without any payload.
    drop(store);
    let (cold_runtime, _cold_quota, _cold_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), cold_runtime);
    block_on(cold.mount()).unwrap();
    let recovered =
        block_on(cold.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    assert_eq!(recovered.checkpoint_generation(), after_grant);
    let verify = import(&grant_records, &[RootPolicy { grant }]);
    block_on(cold.verify_persistent_authority_import(&recovered, &verify)).unwrap();
    let handle = recovered.object_for_recovered(&recovered_external).unwrap();
    assert_eq!(block_on(read_handle(&cold, handle)), content);
}

#[test]
fn control_inline_object_then_grant_same_flow() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
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
    let content: Vec<u8> = (0..200_000_u32).map(|at| (at * 7 + 3) as u8).collect();
    let (records, object_id) = append_next_object_records(&format_records(), &content);
    let appended = block_on(store.append_persistent_authority(
        &writer,
        initial.checkpoint_generation(),
        import(&records, &[]),
        &principal,
    ))
    .unwrap();
    let after_append = appended.view().checkpoint_generation();
    let (_view, _witness) = appended.into_parts();
    let (grant_records, grant) = append_root_grant_records(&records, object_id);
    let _rooted = block_on(store.append_persistent_authority(
        &writer,
        after_append,
        import(&grant_records, &[RootPolicy { grant }]),
        &principal,
    ))
    .unwrap();
}

/// Seed one committed and switched generation-1 namespace root on a fresh
/// authority-initialized store, exactly like the compare-exchange matrix.
fn seed_fs_root_switch_fixture() -> (AuthorityFaultDevice, BTreeMap<u64, Page>) {
    let seed_device = AuthorityFaultDevice::blank();
    let (runtime, _quota, provisioner) = governed_fs_runtime();
    let mut seed = SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    block_on(seed.import_persistent_authority(&maintenance, import(&format_records(), &[])))
        .unwrap();
    block_on(seed.commit_fs_transaction_with_root_switch_for_maintenance(
        &maintenance,
        None,
        FAULT_FS_NAMESPACE,
        1,
        2,
        1,
        &[],
        &[],
        0,
    ))
    .unwrap();
    drop(seed);
    seed_device.power_cycle();
    let seeded = seed_device.durable_image();
    (seed_device, seeded)
}

#[test]
fn fused_fs_root_switch_publishes_one_checkpoint_and_cold_recovers() {
    let (device, _seeded) = seed_fs_root_switch_fixture();
    let (runtime, _quota, provisioner) = governed_fs_runtime();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.mount()).unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let previous = block_on(store.recover_fs_root(FAULT_FS_NAMESPACE))
        .unwrap()
        .unwrap();
    assert_eq!(previous.generation(), 1);

    // A stale expectation declines cleanly before any staging: the store
    // stays mounted and the durable root is untouched.
    assert!(matches!(
        block_on(store.commit_fs_transaction_with_root_switch_for_maintenance(
            &maintenance,
            Some(&previous),
            FAULT_FS_NAMESPACE,
            8,
            2,
            1,
            &[],
            &[],
            7,
        )),
        Err(crate::FsRootPublishError::Conflict)
    ));
    assert!(!store.needs_remount());

    // The complete mkdir-equivalent — tree nodes, namespace root, and the
    // persistent root switch — advances exactly one checkpoint generation.
    let before = store.info().unwrap();
    let dirent_inputs = [crate::FsNodeEntryInput {
        pending: None,
        key: b"dirent-fused",
        value: b"target-fused",
        child: None,
        data: None,
    }];
    let root = block_on(store.commit_fs_transaction_with_root_switch_for_maintenance(
        &maintenance,
        Some(&previous),
        FAULT_FS_NAMESPACE,
        2,
        2,
        1,
        &[],
        &dirent_inputs,
        1,
    ))
    .unwrap();
    let after = store.info().unwrap();
    assert_eq!(
        after.generation,
        before.generation + 1,
        "tree batch and root switch must ride one checkpoint"
    );
    assert_eq!(root.object_kind(), crate::FS_ROOT_V1_KIND);
    let switched = block_on(store.recover_fs_root(FAULT_FS_NAMESPACE))
        .unwrap()
        .unwrap();
    assert_eq!(switched.generation(), 2);
    drop(store);

    // Cold recovery selects the switched root through the fused authority
    // snapshot and resolves its trees.
    device.power_cycle();
    let (runtime, _quota, provisioner) = governed_fs_runtime();
    let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(cold.mount()).unwrap();
    let recovered = block_on(cold.recover_fs_root(FAULT_FS_NAMESPACE))
        .unwrap()
        .unwrap();
    assert_eq!(recovered.generation(), 2);
    let cold_maintenance = cold.provision_maintenance_root(&provisioner).unwrap();
    let entries = block_on(cold.read_fs_tree(&recovered, FsTreeKind::Dirent, 64)).unwrap();
    assert!(entries.iter().any(|entry| entry.key == b"dirent-fused"));
    // The switched store accepts the next fused transaction.
    block_on(cold.commit_fs_transaction_with_root_switch_for_maintenance(
        &cold_maintenance,
        Some(&recovered),
        FAULT_FS_NAMESPACE,
        3,
        2,
        1,
        &[],
        &dirent_inputs,
        2,
    ))
    .unwrap();
}

#[test]
fn fused_fs_root_switch_is_power_cut_atomic_at_every_mutation() {
    let (_seed_device, seeded) = seed_fs_root_switch_fixture();

    let dirent_inputs = [crate::FsNodeEntryInput {
        pending: None,
        key: b"dirent-atomic",
        value: b"target-atomic",
        child: None,
        data: None,
    }];
    macro_rules! run_switch {
        ($store:expr, $maintenance:expr, $previous:expr) => {
            Box::pin($store.commit_fs_transaction_with_root_switch_for_maintenance(
                $maintenance,
                Some($previous),
                FAULT_FS_NAMESPACE,
                2,
                2,
                1,
                &[],
                &dirent_inputs,
                1,
            ))
        };
    }
    let prepare = |device: &AuthorityFaultDevice| {
        let (runtime, _quota, provisioner) = governed_fs_runtime();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(store.mount()).unwrap();
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let previous = block_on(store.recover_fs_root(FAULT_FS_NAMESPACE))
            .unwrap()
            .unwrap();
        assert_eq!(previous.generation(), 1);
        (store, maintenance, previous)
    };

    let probe_device = AuthorityFaultDevice::from_durable(seeded.clone());
    let (mut probe, probe_maintenance, probe_previous) = prepare(&probe_device);
    probe_device.reset_mutation_count();
    block_on(run_switch!(&mut probe, &probe_maintenance, &probe_previous)).unwrap();
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
    let mut old = 0;
    let mut new = 0;
    for mutation in 0..mutation_count {
        for action in failure_actions {
            let case =
                alloc::format!("fused root switch mutation {mutation}/{mutation_count}, {action:?}");
            let device = AuthorityFaultDevice::from_durable(seeded.clone());
            let (mut store, maintenance, previous) = prepare(&device);
            device.arm(mutation, action);
            assert!(
                block_on(run_switch!(&mut store, &maintenance, &previous)).is_err(),
                "{case}: injected fault was not reached"
            );
            drop(store);
            match cold_fs_generation(device, &case) {
                1 => old += 1,
                2 => new += 1,
                _ => unreachable!(),
            }
        }
        for action in cancel_actions {
            let case =
                alloc::format!("fused root switch mutation {mutation}/{mutation_count}, {action:?}");
            let device = AuthorityFaultDevice::from_durable(seeded.clone());
            let (mut store, maintenance, previous) = prepare(&device);
            device.arm(mutation, action);
            let mut operation = run_switch!(&mut store, &maintenance, &previous);
            assert!(
                matches!(poll_once(operation.as_mut()), Poll::Pending),
                "{case}"
            );
            drop(operation);
            drop(store);
            match cold_fs_generation(device, &case) {
                1 => old += 1,
                2 => new += 1,
                _ => unreachable!(),
            }
        }
    }
    assert!(
        old > 0 && new > 0,
        "fault matrix must recover both old and new roots"
    );
}

/// Profiling harness: `cargo test --release -p vibeos-segment-store --lib
/// profile_object_append -- --ignored --nocapture`.
#[test]
#[ignore]
fn profile_object_append() {
    let device = MemoryDevice::with_segments(64);
    let (runtime, _quota, maintenance_provisioner) =
        StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let limits = StoreLimits {
        max_catalog_entries: 4096,
        max_replay_records: 32,
        recovery_memory_bytes: 64 * 1024 * 1024,
        max_compat_object_bytes: 64 * 1024,
    };
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits, runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"M7.7-AUTH-PROF!!").unwrap(),
        cleaner_reserve_segments: 4,
        limits,
    }))
    .unwrap();
    store.set_deferred_commit_readback(true);
    let maintenance = store
        .provision_maintenance_root(&maintenance_provisioner)
        .unwrap();
    let mut records = format_records();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, import(&records, &[]))).unwrap();
    let principal = initial.principals()[0].clone();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let mut generation = initial.checkpoint_generation();
    let total: u32 = std::env::var("VIBE_PROFILE_APPENDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40);
    for index in 0..total {
        let bytes: Vec<u8> = (0..4096_u32)
            .map(|i| (i.wrapping_mul(131).wrapping_add(index.wrapping_mul(17)) % 251) as u8)
            .collect();
        let build_started = std::time::Instant::now();
        let (next_records, _object) = append_next_object_records(&records, &bytes);
        let update = import(&next_records, &[]);
        let build = build_started.elapsed();
        device.take_probes();
        let before = device.snapshot();
        let started = std::time::Instant::now();
        let appended =
            block_on(store.append_persistent_authority(&writer, generation, update, &principal))
                .unwrap();
        let elapsed = started.elapsed();
        let after = device.snapshot();
        let written = after
            .iter()
            .filter(|(page, bytes)| before.get(page) != Some(bytes))
            .count();
        generation = appended.view().checkpoint_generation();
        records = next_records;
        if index == 1 || index == 9 || index + 1 == total {
            let probes = device.take_probes();
            let mut line = std::format!(
                "append #{:>2}: stream {} records, import-build {:.2} ms, append {:.2} ms, {written} pages written; phases:",
                index + 1,
                records.len(),
                build.as_secs_f64() * 1e3,
                elapsed.as_secs_f64() * 1e3
            );
            for pair in probes.windows(2) {
                line.push_str(&std::format!(
                    " {}->{} {:.2}",
                    pair[0].0,
                    pair[1].0,
                    pair[1].1.duration_since(pair[0].1).as_secs_f64() * 1e3
                ));
            }
            std::println!("{line}");
        }
    }
}

#[test]
fn experimental_authority_replay_uses_verified_device_snapshot() {
    let device = MemoryDevice::blank();
    let (runtime, _quota, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions { store_uuid: StoreUuid::new([7;16]).unwrap(), cleaner_reserve_segments: 4, limits: limits() })).unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[]))).unwrap();
    let state = store.mounted.as_ref().unwrap();
    let expected = crate::encode_persistent_authority_snapshot(state.persistent_authority.as_ref().unwrap()).unwrap();
    let before = device.snapshot();
    assert_eq!(block_on(crate::authority_delta::replay_device_for_test(&device, state, expected.len())).unwrap(), expected);
    assert!(block_on(crate::authority_delta::replay_device_for_test(&device, state, expected.len()-1)).is_err());
    assert_eq!(device.snapshot(), before);
    let vibeos_segment_format::PhysicalPointer::Value(pointer) = state.authority_root else { panic!("authority pointer"); };
    let page = vibeos_segment_format::segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
    device.pages.lock().unwrap().get_mut(&page).unwrap()[0] ^= 1;
    let damaged = device.snapshot();
    assert!(block_on(crate::authority_delta::replay_device_for_test(&device, state, expected.len())).is_err());
    assert_eq!(device.snapshot(), damaged);
}

#[test]
fn experimental_delta_checkpoint_cold_mount_and_gc_materialize() {
    use crate::PersistentAuthoritySnapshot;
    use vibeos_segment_format::{PhysicalPointer, segment_base_page};
    let device = MemoryDevice::blank();
    let export = |name: &str| {
        if let Some(directory) = std::env::var_os("VIBE_DELTA_IMAGE_FIXTURES") {
            use std::io::{Seek, SeekFrom, Write};
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let mut file = std::fs::File::create(directory.join(name)).unwrap();
            file.set_len(device.info().page_count * 4096).unwrap();
            for (page, bytes) in device.snapshot() {
                file.seek(SeekFrom::Start(page * 4096)).unwrap();
                file.write_all(&bytes).unwrap();
            }
        }
    };

    let (runtime, _quota, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions { store_uuid: StoreUuid::new([7;16]).unwrap(), cleaner_reserve_segments: 4, limits: limits() })).unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    block_on(store.import_persistent_authority(&maintenance, import(&format_records(), &[]))).unwrap();
    let mut chain = RecordChain::new(store_id());
    let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
    let mut old_roots = Vec::new();
    for step in 1..=3 {
        let state = store.mounted.as_ref().unwrap();
        old_roots.push(state.authority_root);
        let base = state.persistent_authority.as_ref().unwrap();
        records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: step * 32 }).unwrap());
        let next = PersistentAuthoritySnapshot::new(state.generation + 1,
            root_policy_commitment(POLICY), records.clone(), vec![], base.principals().to_vec()).unwrap();
        block_on(store.publish_experimental_delta_for_test(next)).unwrap();
        let PhysicalPointer::Value(pointer) = store.mounted.as_ref().unwrap().authority_root else { panic!("root"); };
        let page = segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
        assert_eq!(&device.snapshot()[&page][..8], b"VIBEAUL1");
    }
    old_roots.push(store.mounted.as_ref().unwrap().authority_root);
    export("delta.raw");
    for old in &old_roots {
        let damaged = MemoryDevice::blank();
        *damaged.pages.lock().unwrap() = device.snapshot();
        let PhysicalPointer::Value(old) = old else { panic!("old root"); };
        let page = segment_base_page(old.segment_no).unwrap() + u64::from(old.payload_relative_page);
        damaged.pages.lock().unwrap().get_mut(&page).unwrap()[0] ^= 1;
        let before_mount = damaged.snapshot();
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut invalid = SegmentStore::new_with_runtime_context(damaged.clone(), limits(), runtime);
        assert!(block_on(invalid.mount()).is_err(), "damaged ancestor must prevent admission");
        assert_eq!(damaged.snapshot(), before_mount, "rejected mount must not mutate media");
    }

    let expected = crate::encode_persistent_authority_snapshot(store.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap();
    // Exercise the same store instance after a successful cached mount. Every
    // old proof must be gone on remount, including shared delta ancestors.
    for old in &old_roots {
        let PhysicalPointer::Value(old) = old else { panic!("old root"); };
        let base_page = segment_base_page(old.segment_no).unwrap();
        for relative in [u64::from(old.payload_relative_page),
                         u64::from(old.descriptor_relative_page),
                         u64::from(vibeos_segment_format::SEGMENT_SEAL_BODY_PAGE)] {
            let changed = MemoryDevice::blank();
            *changed.pages.lock().unwrap() = device.snapshot();
            let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
            let mut remounted = SegmentStore::new_with_runtime_context(changed.clone(), limits(), runtime);
            block_on(remounted.mount()).unwrap();
            let page = base_page + relative;
            let original = changed.snapshot()[&page];
            changed.pages.lock().unwrap().get_mut(&page).unwrap()[0] ^= 1;
            let damaged_image = changed.snapshot();
            assert!(block_on(remounted.mount()).is_err(), "warm remount must reject changed authority media");
            assert!(remounted.mounted.is_none(), "failed remount must discard the admitted state");
            assert_eq!(changed.snapshot(), damaged_image, "rejected remount must be read-only");
            changed.pages.lock().unwrap().insert(page, original);
            block_on(remounted.mount()).unwrap();
            assert_eq!(crate::encode_persistent_authority_snapshot(remounted.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(), expected);
        }
    }
    std::println!("mount-local memo: 12 same-instance payload/descriptor/seal corruptions rejected; repaired remounts match");
    drop(store);
    let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(cold.mount()).unwrap();
    assert_eq!(crate::encode_persistent_authority_snapshot(cold.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(), expected);
    block_on(cold.collect_garbage()).unwrap();
    let state = cold.mounted.as_ref().unwrap();
    assert_eq!(state.persistent_authority.as_ref().unwrap().record_stream(), records);
    let PhysicalPointer::Value(pointer) = state.authority_root else { panic!("root"); };
    let page = segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
    assert_eq!(&device.snapshot()[&page][..8], b"VIBEAUT2");
    export("materialized.raw");
    // A materialized checkpoint must no longer read any predecessor payload.
    for old in old_roots {
        let PhysicalPointer::Value(old) = old else { panic!("old root"); };
        assert_ne!(old.segment_no, pointer.segment_no);
        let page = segment_base_page(old.segment_no).unwrap() + u64::from(old.payload_relative_page);
        if let Some(bytes) = device.pages.lock().unwrap().get_mut(&page) { bytes[0] ^= 1; }
    }
    drop(cold);
    let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut final_store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(final_store.mount()).unwrap();
    assert_eq!(final_store.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap().record_stream(), records);
}

#[test]
fn experimental_delta_publish_is_atomic_at_each_mutation_and_cancel_point() {
    exercise_experimental_delta_publish(false);
}

#[test]
fn experimental_cached_delta_publish_is_atomic_at_each_mutation_and_cancel_point() {
    exercise_experimental_delta_publish(true);
}

fn exercise_experimental_delta_publish(warm_cache: bool) {
    use crate::PersistentAuthoritySnapshot;
    fn mount(device: AuthorityFaultDevice) -> SegmentStore<AuthorityFaultDevice> {
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(store.mount()).unwrap();
        store
    }
    let seed_device = AuthorityFaultDevice::blank();
    let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut seed = SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    block_on(seed.import_persistent_authority(&maintenance, import(&format_records(), &[]))).unwrap();
    let principals = seed.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap().principals().to_vec();
    let mut chain = RecordChain::new(store_id());
    let mut records = chain.append(None, RecordBody::Format).unwrap().to_vec();
    records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: 32 }).unwrap());
    let base = PersistentAuthoritySnapshot::new(3, root_policy_commitment(POLICY), records.clone(), vec![], principals.clone()).unwrap();
    block_on(seed.publish_experimental_delta_for_test(base.clone())).unwrap();
    let warm_base = seed.experimental_authority_base.take().unwrap();
    drop(seed);
    seed_device.power_cycle();
    let initial = seed_device.durable_image();
    records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: 64 }).unwrap());
    let next = PersistentAuthoritySnapshot::new(4, root_policy_commitment(POLICY), records, vec![], principals).unwrap();
    let old_bytes = crate::encode_persistent_authority_snapshot(&base).unwrap();
    let new_bytes = crate::encode_persistent_authority_snapshot(&next).unwrap();
    let probe_device = AuthorityFaultDevice::from_durable(initial.clone());
    let mut probe = mount(probe_device.clone());
    probe_device.reset_mutation_count();
    block_on(probe.publish_experimental_delta_for_test(next.clone())).unwrap();
    let mutations = probe_device.mutation_count();
    assert!(mutations > 0);
    let vibeos_segment_format::PhysicalPointer::Value(pointer) = probe.mounted.as_ref().unwrap().authority_root else { panic!("delta root"); };
    let page = vibeos_segment_format::segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
    assert_eq!(&probe_device.durable_image()[&page][..8], b"VIBEAUL1");
    drop(probe);
    let actions = [
        AuthorityFaultAction::FailNotSubmitted,
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::None),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Visible),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Durable),
        AuthorityFaultAction::Pending(AuthorityEffect::None),
        AuthorityFaultAction::Pending(AuthorityEffect::Visible),
        AuthorityFaultAction::Pending(AuthorityEffect::Durable),
    ];
    let mut old = 0;
    let mut new = 0;
    for mutation in 0..mutations {
        for action in actions {
            let case = alloc::format!("delta mutation {mutation}/{mutations} {action:?}");
            let device = AuthorityFaultDevice::from_durable(initial.clone());
            let mut store = mount(device.clone());
            if warm_cache { store.experimental_authority_base = Some(warm_base.clone()); }
            device.arm(mutation, action);
            let mut operation = Box::pin(store.publish_experimental_delta_for_test(next.clone()));
            let outcome = poll_once(operation.as_mut());
            match action {
                AuthorityFaultAction::Pending(_) => assert!(matches!(outcome, Poll::Pending), "{case}"),
                _ => assert!(matches!(outcome, Poll::Ready(Err(_))), "{case}"),
            }
            drop(operation);
            assert!(store.experimental_authority_base.is_none(), "{case}: failed publication retained cache");
            drop(store);
            device.power_cycle();
            let before_mount = device.durable_image();
            let mut cold = mount(device.clone());
            let state = cold.mounted.as_ref().unwrap();
            let actual = crate::encode_persistent_authority_snapshot(state.persistent_authority.as_ref().unwrap()).unwrap();
            if actual == old_bytes {
                old += 1;
                assert_eq!(state.generation, 3, "{case}");
            } else {
                assert_eq!(actual, new_bytes, "{case}: neither complete old nor new snapshot");
                assert_eq!(state.generation, 4, "{case}");
                new += 1;
            }
            assert_eq!(device.mutation_count(), 0, "{case}: recovery wrote media");
            assert_eq!(device.durable_image(), before_mount, "{case}");
            if actual == old_bytes {
                block_on(cold.publish_experimental_delta_for_test(next.clone()))
                    .unwrap_or_else(|e| panic!("{case}: retry failed: {e:?}"));
            }
            drop(cold);
            device.power_cycle();
            let confirmed = mount(device.clone());
            assert_eq!(crate::encode_persistent_authority_snapshot(
                confirmed.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()
            ).unwrap(), new_bytes, "{case}: retry/confirmed checkpoint");

        }
    }
    assert!(old > 0 && new > 0, "must exercise both checkpoint outcomes");
    std::println!("delta publish warm_cache={warm_cache}: {mutations} mutation points, {} fault/cancel cases, {old} old, {new} new", mutations * actions.len());
}

#[test]
fn experimental_delta_gc_is_atomic_at_each_mutation_and_cancel_point() {
    exercise_experimental_delta_gc(false);
}

#[test]
fn experimental_delta_gc_preserves_live_object_and_grant_at_each_cut() {
    exercise_experimental_delta_gc(true);
}

// Shared only by host tests: the growth matrix uses the same live authority
// fixture and exact object/grant/quota assertions as the delta GC work.
pub(super) fn delta_growth_fixture(has_object: bool) -> (
    StoreId, &'static [u8], Vec<RootPolicy>, Vec<[u8; 512]>, Vec<u8>,
) {
    let payload: Vec<u8> = if has_object { (0..4096).map(|n| (n % 251) as u8).collect() } else { Vec::new() };
    let records = if has_object { append_grant_records(&append_object_records(&format_records(), &payload)) } else { format_records() };
    let roots = if has_object { vec![RootPolicy { grant: root_grant() }] } else { Vec::new() };
    (store_id(), POLICY, roots, records, payload)
}

pub(super) fn assert_delta_growth_object<D: PageDevice>(store: &SegmentStore<D>, payload: &[u8])
where D::Error: core::fmt::Debug {
    if payload.is_empty() { return; }
    let view = block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
    let sectors = view.record_stream().as_chunks::<512>().0;
    let graph = vibeos_durable_format::preflight_recovery(sectors, store_id()).unwrap()
        .finish(&[RootPolicy { grant: root_grant() }]).unwrap();
    assert_eq!(graph.grants.len(), 1);
    assert_eq!(graph.grants[0].grant, root_grant());
    assert_eq!(view.objects().len(), 1);
    let object = find_object(sectors);
    let handle = view.object_for_recovered(&object).unwrap();
    assert_eq!(block_on(store.read_persistent_object(handle)).unwrap(), payload);
    let usage = store.principal_quota_usage(&view.principals()[0]).unwrap();
    assert_eq!(usage.committed_logical_bytes, payload.len() as u64);
    assert_eq!(usage.committed_physical_bytes, canonical_attributable_physical_bytes(payload.len() as u64).unwrap());
}

fn exercise_experimental_delta_gc(has_object: bool) {
    use crate::PersistentAuthoritySnapshot;
    fn mount(device: AuthorityFaultDevice) -> SegmentStore<AuthorityFaultDevice> {
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
        block_on(store.mount()).unwrap();
        store
    }
    fn check_object(store: &SegmentStore<AuthorityFaultDevice>, payload: &[u8]) {
        let view = block_on(store.recover_persistent_authority(root_policy_commitment(POLICY))).unwrap();
        let sectors: Vec<_> = view.record_stream().as_chunks::<512>().0.to_vec();
        let graph = vibeos_durable_format::preflight_recovery(&sectors, store_id()).unwrap()
            .finish(&[RootPolicy { grant: root_grant() }]).unwrap();
        assert_eq!(graph.grants.len(), 1);
        assert_eq!(graph.grants[0].grant, root_grant());
        assert_eq!(view.objects().len(), 1);
        let object = find_object(&sectors);
        let handle = view.object_for_recovered(&object).unwrap();
        assert_eq!(block_on(store.read_persistent_object(handle)).unwrap(), payload);
        let usage = store.principal_quota_usage(&view.principals()[0]).unwrap();
        assert_eq!(usage.committed_logical_bytes, payload.len() as u64);
        assert_eq!(usage.committed_physical_bytes, canonical_attributable_physical_bytes(payload.len() as u64).unwrap());
    }
    let payload: Vec<u8> = (0..4096).map(|n| (n % 251) as u8).collect();
    let export = |name: &str, image: &BTreeMap<u64, Page>| {
        if has_object {
            if let Some(directory) = std::env::var_os("VIBE_DELTA_IMAGE_FIXTURES") {
                use std::io::{Seek, SeekFrom, Write};
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory).unwrap();
                let mut file = std::fs::File::create(directory.join(name)).unwrap();
                file.set_len(admitted_pages(SEGMENTS).unwrap() * 4096).unwrap();
                for (page, bytes) in image {
                    file.seek(SeekFrom::Start(page * 4096)).unwrap();
                    file.write_all(bytes).unwrap();
                }
            }
        }
    };
    let seed_device = AuthorityFaultDevice::blank();
    let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut seed = SegmentStore::new_with_runtime_context(seed_device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    let seed_records = if has_object { append_grant_records(&append_object_records(&format_records(), &payload)) } else { format_records() };
    let roots = if has_object { vec![RootPolicy { grant: root_grant() }] } else { vec![] };
    block_on(seed.import_persistent_authority(&maintenance, import(&seed_records, &roots))).unwrap();
    let preflight = vibeos_durable_format::preflight_recovery(&seed_records, store_id()).unwrap();
    let mut chain = RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap()).unwrap();
    let mut records: Vec<u8> = seed_records.iter().flatten().copied().collect();
    let mut ancestors = Vec::new();
    for step in 1..=3 {
        let state = seed.mounted.as_ref().unwrap();
        ancestors.push(state.authority_root);
        records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: step * 32 }).unwrap());
        let next = PersistentAuthoritySnapshot::new(state.generation + 1, root_policy_commitment(POLICY),
            records.clone(), state.persistent_authority.as_ref().unwrap().objects.clone(), state.persistent_authority.as_ref().unwrap().principals().to_vec()).unwrap();
        block_on(seed.publish_experimental_delta_for_test(next)).unwrap();
    }
    let state = seed.mounted.as_ref().unwrap();
    ancestors.push(state.authority_root);
    let old = crate::encode_persistent_authority_snapshot(state.persistent_authority.as_ref().unwrap()).unwrap();
    let old_generation = state.generation;
    if has_object { check_object(&seed, &payload); }
    drop(seed);
    seed_device.power_cycle();
    let initial = seed_device.durable_image();
    export("live-delta.raw", &initial);
    let probe_device = AuthorityFaultDevice::from_durable(initial.clone());
    let mut probe = mount(probe_device.clone());
    probe_device.reset_mutation_count();
    block_on(probe.collect_garbage()).unwrap();
    let mutations = probe_device.mutation_count();
    export("live-materialized.raw", &probe_device.durable_image());
    let state = probe.mounted.as_ref().unwrap();
    assert_eq!(state.generation, old_generation + 2);
    let materialized = crate::encode_persistent_authority_snapshot(state.persistent_authority.as_ref().unwrap()).unwrap();
    assert_ne!(old, materialized);
    assert_eq!(state.persistent_authority.as_ref().unwrap().record_stream(), records);
    drop(probe);
    let actions = [
        AuthorityFaultAction::FailNotSubmitted,
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::None),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Visible),
        AuthorityFaultAction::FailAmbiguous(AuthorityEffect::Durable),
        AuthorityFaultAction::Pending(AuthorityEffect::None),
        AuthorityFaultAction::Pending(AuthorityEffect::Visible),
        AuthorityFaultAction::Pending(AuthorityEffect::Durable),
    ];
    let mut outcomes = [0_usize; 3];
    for mutation in 0..mutations {
        for action in actions {
            let case = alloc::format!("delta GC mutation {mutation}/{mutations} {action:?}");
            let device = AuthorityFaultDevice::from_durable(initial.clone());
            let mut store = mount(device.clone());
            device.arm(mutation, action);
            let mut operation = Box::pin(store.collect_garbage());
            let result = poll_once(operation.as_mut());
            match action {
                AuthorityFaultAction::Pending(_) => assert!(matches!(result, Poll::Pending), "{case}"),
                _ => assert!(matches!(result, Poll::Ready(Err(_))), "{case}"),
            }
            drop(operation);
            drop(store);
            device.power_cycle();
            let durable = device.durable_image();
            let mut cold = mount(device.clone());
            let state = cold.mounted.as_ref().unwrap();
            assert!((old_generation..=old_generation + 2).contains(&state.generation), "{case}");
            outcomes[(state.generation - old_generation) as usize] += 1;
            let actual = crate::encode_persistent_authority_snapshot(state.persistent_authority.as_ref().unwrap()).unwrap();
            assert_eq!(actual, if state.generation == old_generation { &old } else { &materialized }.as_slice(), "{case}");
            if state.generation == old_generation {
                for pointer in &ancestors {
                    let vibeos_segment_format::PhysicalPointer::Value(pointer) = pointer else { panic!("ancestor"); };
                    assert_eq!(state.allocation.segment_state(pointer.segment_no), Some(crate::SegmentAllocation::Allocated), "{case}");
                }
            }
            if state.generation == old_generation + 1 {
                for pointer in &ancestors {
                    let vibeos_segment_format::PhysicalPointer::Value(pointer) = pointer else { panic!("ancestor"); };
                    assert!(matches!(state.allocation.segment_state(pointer.segment_no),
                        Some(crate::SegmentAllocation::Allocated | crate::SegmentAllocation::Retired)),
                        "{case}: ancestor reusable before barrier");
                }
            }
            assert_eq!(device.mutation_count(), 0, "{case}: recovery wrote media");
            assert_eq!(device.durable_image(), durable, "{case}");
            if has_object { check_object(&cold, &payload); }
            if state.generation < old_generation + 2 {
                block_on(cold.collect_garbage()).unwrap_or_else(|e| panic!("{case}: GC retry/resume: {e:?}"));
            }
            drop(cold);
            device.power_cycle();
            let confirmed = mount(device.clone());
            assert_eq!(confirmed.mounted.as_ref().unwrap().generation, old_generation + 2, "{case}");

            assert_eq!(crate::encode_persistent_authority_snapshot(
                confirmed.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()
            ).unwrap(), materialized, "{case}: completed GC");
            if has_object { check_object(&confirmed, &payload); }
        }
    }
    assert!(outcomes.iter().all(|&count| count > 0));
    std::println!("delta GC has_object={has_object}: {mutations} mutation points, {} cases, old/relocated/barrier: {outcomes:?}", mutations * actions.len());
}

#[test]
fn experimental_delta_publication_io_against_full_snapshot() {
    use crate::PersistentAuthoritySnapshot;
    let device = AuthorityFaultDevice::blank();
    let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut seed = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(seed.format(authority_fault_options())).unwrap();
    let maintenance = seed.provision_maintenance_root(&provisioner).unwrap();
    let mut chain = RecordChain::new(store_id());
    let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
    for n in 1..=320 {
        sectors.push(chain.append(None, RecordBody::IdHighWater { exclusive_end: n * 32 }).unwrap());
    }
    block_on(seed.import_persistent_authority(&maintenance, import(&sectors, &[]))).unwrap();
    let base = seed.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap().clone();
    let mut next_records: Vec<u8> = sectors.iter().flatten().copied().collect();
    let mut successors = Vec::new();
    for n in 1..=8 {
        next_records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: (320 + n) * 32 }).unwrap());
        successors.push(PersistentAuthoritySnapshot::new(base.checkpoint_generation() + n as u64,
            root_policy_commitment(POLICY), next_records.clone(), vec![], base.principals().to_vec()).unwrap());
    }
    drop(seed);
    device.power_cycle();
    let initial = device.durable_image();
    let expected = crate::encode_persistent_authority_snapshot(successors.last().unwrap()).unwrap();
    let mut measured = Vec::new();
    let mut cold_reads = Vec::new();
    for delta in [false, true] {
        let device = AuthorityFaultDevice::from_durable(initial.clone());
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(store.mount()).unwrap();
        device.reset_mutation_count();
        for snapshot in &successors {
            if delta {
                block_on(store.publish_experimental_delta_for_test(snapshot.clone())).unwrap();
                let state = store.mounted.as_ref().unwrap();
                let witness = store.experimental_authority_base.as_ref().unwrap();
                assert!(witness.matches(state));
                for field in 0..6 {
                    let mut changed = state.clone();
                    match field {
                        0 => changed.generation += 1,
                        1 => changed.authority_root = vibeos_segment_format::PhysicalPointer::Null,
                        2 => changed.admitted_segments += 1,
                        3 => changed.next_segment_generation += 1,
                        4 => changed.superblock.binding.store_uuid = StoreUuid::new([8;16]).unwrap(),
                        _ => {
                            let base = changed.persistent_authority.as_ref().unwrap();
                            let mut policies = base.principals().to_vec();
                            policies[0].admission_revoked = true;
                            changed.persistent_authority = Some(PersistentAuthoritySnapshot::new(
                                base.checkpoint_generation(), root_policy_commitment(POLICY),
                                base.record_stream().to_vec(), base.objects.clone(), policies,
                            ).unwrap());
                        },
                    }
                    assert!(!witness.matches(&changed), "cache accepted changed field {field}");
                }

            } else {
                block_on(store.publish_full_snapshot_for_test(snapshot.clone())).unwrap();
            }
        }
        let media = device.media.lock().unwrap();
        let io = (media.reads * 4096, media.writes * 4096, media.flushes);
        drop(media);
        std::println!("authority 321-record base, 8 appends, delta={delta}: reads={} writes={} flushes={}", io.0, io.1, io.2);
        measured.push(io);
        drop(store);
        device.power_cycle();
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        device.reset_mutation_count();
        device.media.lock().unwrap().read_pages = Some(BTreeMap::new());
        device.media.lock().unwrap().read_trace = Some(Vec::new());
        let mut cold = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
        block_on(cold.mount()).unwrap();
        let media = device.media.lock().unwrap();
        let reads = media.reads * 4096;
        let pages = media.read_pages.as_ref().unwrap();
        let mut segments = BTreeMap::<Option<u64>, (usize, usize, usize)>::new();
        for (&page, &count) in pages {
            let segment = page.checked_sub(vibeos_segment_format::ANCHOR_PAGES)
                .map(|relative| relative / vibeos_segment_format::SEGMENT_PAGES);
            let stats = segments.entry(segment).or_default();
            stats.0 += count;
            stats.1 += 1;
            stats.2 = stats.2.max(count);
        }
        assert_eq!(pages.values().sum::<usize>(), media.reads);
        let trace = media.read_trace.as_ref().unwrap();
        assert_eq!(trace.len(), media.reads);
        let mut cache_estimates = Vec::new();
        for capacity in [0, 64, 512] {
            let mut lru = Vec::new();
            let mut misses = 0;
            for &page in trace {
                if let Some(index) = lru.iter().position(|&cached| cached == page) {
                    lru.remove(index);
                } else {
                    misses += 1;
                    if capacity > 0 && lru.len() == capacity { lru.remove(0); }
                }
                if capacity > 0 { lru.push(page); }
            }
            if capacity == 0 { assert_eq!(misses, media.reads); }
            if capacity >= pages.len() { assert_eq!(misses, pages.len()); }
            cache_estimates.push((capacity, misses));
        }
        std::println!("cold read-trace LRU simulation delta={delta}: (capacity,misses)={cache_estimates:?}");
        std::println!("cold page attribution delta={delta}: total={} unique={} segments(total,unique,max_repeats)={segments:?}", media.reads, pages.len());
        assert_eq!((media.writes, media.flushes), (0, 0), "cold recovery must be read-only");
        drop(media);
        cold_reads.push(reads);
        std::println!("authority 321-record base, 8 appends, delta={delta}: cold recovery reads={reads} writes=0 flushes=0");
        assert!(cold.experimental_authority_base.is_none(), "cold mount must clear provenance cache");
        assert_eq!(crate::encode_persistent_authority_snapshot(cold.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(), expected);
        // Reserving the optional 64 KiB memo must not reduce admission. This
        // budget sits between the cached and uncached recovery upper bounds.
        let mut tight_limits = limits();
        tight_limits.recovery_memory_bytes = cold.info().unwrap().recovery_peak_bytes - 32 * 1024;
        let tight_device = AuthorityFaultDevice::from_durable(device.durable_image());
        let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
        let mut tight = SegmentStore::new_with_runtime_context(tight_device.clone(), tight_limits, runtime);
        block_on(tight.mount()).unwrap();
        assert_eq!(tight.info().unwrap().recovery_peak_bytes, tight_limits.recovery_memory_bytes,
            "expected the conservative peak of the uncached retry");
        assert_eq!(crate::encode_persistent_authority_snapshot(tight.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(), expected);
        assert_eq!(tight_device.mutation_count(), 0, "fallback mount must remain read-only");
        std::println!("cold memo delta={delta}: tight-budget uncached fallback passed at {} bytes", tight_limits.recovery_memory_bytes);
    }
    std::println!("publication plus one cold mount: full reads={} delta reads={}",
        measured[0].0 + cold_reads[0], measured[1].0 + cold_reads[1]);
    assert!(measured[1].1 < measured[0].1);
    assert_eq!(measured[0].2, measured[1].2, "must preserve flush durability boundaries");
}

#[test]
fn experimental_delta_with_multi_extent_base_cold_recovery() {
    use crate::PersistentAuthoritySnapshot;
    use std::io::{Seek, SeekFrom, Write};
    let device = MemoryDevice::blank();
    let mut budget = limits();
    budget.recovery_memory_bytes = 32 * 1024 * 1024;
    let (runtime, _, provisioner) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), budget, runtime);
    block_on(store.format(FormatOptions { store_uuid: StoreUuid::new([7;16]).unwrap(), cleaner_reserve_segments: 4, limits: budget })).unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let mut chain = RecordChain::new(store_id());
    let mut sectors = vec![chain.append(None, RecordBody::Format).unwrap()];
    for n in 1..=8192 {
        sectors.push(chain.append(None, RecordBody::IdHighWater { exclusive_end: n * 32 }).unwrap());
    }
    block_on(store.import_persistent_authority(&maintenance, import(&sectors, &[]))).unwrap();
    let base = store.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap().clone();
    let encoded = crate::encode_persistent_authority_snapshot(&base).unwrap();
    assert!(encoded.len() > vibeos_segment_format::SEGMENT_PAGES as usize * 4096);
    let export = |name: &str| {
        if let Some(directory) = std::env::var_os("VIBE_DELTA_IMAGE_FIXTURES") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let mut file = std::fs::File::create(directory.join(name)).unwrap();
            file.set_len(device.info().page_count * 4096).unwrap();
            for (page, bytes) in device.snapshot() {
                file.seek(SeekFrom::Start(page * 4096)).unwrap();
                file.write_all(&bytes).unwrap();
            }
        }
    };
    export("multi-base.raw");
    let mut records = base.record_stream().to_vec();
    records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: 8193 * 32 }).unwrap());
    let next = PersistentAuthoritySnapshot::new(base.checkpoint_generation() + 1,
        root_policy_commitment(POLICY), records, vec![], base.principals().to_vec()).unwrap();
    block_on(store.publish_experimental_delta_for_test(next.clone())).unwrap();
    export("multi-delta.raw");
    drop(store);
    let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut cold = SegmentStore::new_with_runtime_context(device.clone(), budget, runtime);
    block_on(cold.mount()).unwrap();
    assert_eq!(crate::encode_persistent_authority_snapshot(cold.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(),
        crate::encode_persistent_authority_snapshot(&next).unwrap());
    let mut records = next.record_stream().to_vec();
    for n in 8194..=16385 {
        records.extend_from_slice(&chain.append(None, RecordBody::IdHighWater { exclusive_end: n * 32 }).unwrap());
    }
    let large = PersistentAuthoritySnapshot::new(next.checkpoint_generation() + 1,
        root_policy_commitment(POLICY), records, vec![], next.principals().to_vec()).unwrap();
    block_on(cold.publish_experimental_delta_for_test(large.clone())).unwrap();
    let vibeos_segment_format::PhysicalPointer::Value(pointer) = cold.mounted.as_ref().unwrap().authority_root else { panic!("root"); };
    let page = vibeos_segment_format::segment_base_page(pointer.segment_no).unwrap() + u64::from(pointer.payload_relative_page);
    assert_eq!(&device.snapshot()[&page][..8], b"VIBEAUL1", "must exercise a delta, not full fallback");
    export("multi-large-delta.raw");
    drop(cold);
    let (runtime, _, _) = StoreRuntimeContext::governed_with_maintenance_provisioner().unwrap();
    let mut recovered = SegmentStore::new_with_runtime_context(device.clone(), budget, runtime);
    block_on(recovered.mount()).unwrap();
    assert_eq!(crate::encode_persistent_authority_snapshot(recovered.mounted.as_ref().unwrap().persistent_authority.as_ref().unwrap()).unwrap(),
        crate::encode_persistent_authority_snapshot(&large).unwrap());
}
