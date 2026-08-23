//! C7.4 crash-safety evidence for one complete Component publication.
//!
//! The 512-byte records below are the frozen *logical* durable-format codec
//! only.  The production mutation exercised by this test is exclusively the
//! Storage V2 persistent-authority append; this file deliberately calls no M4
//! block-device append or resume API.

use core::future::{pending, Future};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use vibeos_durable_format::{
    encode_object_transaction, preflight_recovery, preview_grant_transaction, DerivationId,
    DurableRights, GrantFlags, GrantRecord, ObjectId, ObjectKind, RecordBody, RecordChain,
    ResourceKind, RootPolicy, SlotIdentity, SpaceId, StoreId, TransactionId, RECORD_SIZE,
};
use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
use vibeos_segment_store::{
    root_policy_commitment, FormatOptions, PageDevice, PageDeviceInfo, PersistentAuthorityError,
    PersistentAuthorityImport, SegmentStore, StoreLimits, StoreRuntimeContext,
    LEGACY_SYSTEM_PRINCIPAL,
};
use vibeos_storage_device::MutationFailure;

const SEGMENTS: u64 = 32;
const STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;
const COMPONENT_SPACE_RAW: u128 = 0x5649_4245_4f53_2d43_4f4d_504f_4e45_4e54;
const EVIDENCE_KIND_RAW: u32 = 0x434d_4531;
const ARTIFACT_KIND_RAW: u32 = 0x434d_5031;
const STORED_OBJECT_KIND_RAW: u32 = 0x5354_4f52;
const MAX_C71_ARTIFACT_BYTES: usize = 1_442_144;
const POLICY_V2: &[u8] = b"vibeos.storage-v2.external-policy.v2\0persistent-space=0x5053,slot=0,generation=0,rights=rgx,kind=0x43535043\0program-space=0x50524f47,slot=0,generation=0,rights=r,kind=0x50524731\0component-space=0x564942454f532d434f4d504f4e454e54,slot=0,generation=0,rights=r,kind=0x434d5031\0component-evidence=exact-root-relative,kind=0x434d4531,len=112,inline=1,ungranted=1\0sealed-singleton-optional=0x53534801";

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

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    Injected,
    DriverRestarted,
    OutsideRange,
}

impl core::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum MutationKind {
    Write,
    Flush,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    None,
    Visible,
    Durable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultAction {
    Normal,
    FailNotSubmitted,
    FailAmbiguous(Effect),
    Pending(Effect),
}

/// The original matrix exercises the `PageDevice` one-page fallback at every
/// physical mutation. `CachedBatch` additionally mirrors the production
/// `CapabilityPageDevice` shape: one `write_pages` request is one ambiguous
/// mutation, and its write-through read cache is invalidated before the request
/// can reach media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceMode {
    PageFallback,
    CachedBatch,
}

const FAULT_ACTIONS: [FaultAction; 7] = [
    FaultAction::FailNotSubmitted,
    FaultAction::FailAmbiguous(Effect::None),
    FaultAction::FailAmbiguous(Effect::Visible),
    FaultAction::FailAmbiguous(Effect::Durable),
    FaultAction::Pending(Effect::None),
    FaultAction::Pending(Effect::Visible),
    FaultAction::Pending(Effect::Durable),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultPlan {
    mutation_index: usize,
    action: FaultAction,
}

#[derive(Clone)]
struct FaultMedia {
    page_count: u64,
    durable: BTreeMap<u64, Page>,
    visible: BTreeMap<u64, Page>,
    cache: BTreeMap<u64, Page>,
    mode: DeviceMode,
    mutation_count: usize,
    batch_write_count: usize,
    trace: Vec<MutationKind>,
    fault: Option<FaultPlan>,
}

#[derive(Clone)]
struct FaultDevice {
    media: Arc<Mutex<FaultMedia>>,
}

impl FaultDevice {
    fn from_durable(image: BTreeMap<u64, Page>) -> Self {
        Self::from_durable_with_mode(image, DeviceMode::PageFallback)
    }

    fn from_durable_cached_batch(image: BTreeMap<u64, Page>) -> Self {
        Self::from_durable_with_mode(image, DeviceMode::CachedBatch)
    }

    fn from_durable_with_mode(image: BTreeMap<u64, Page>, mode: DeviceMode) -> Self {
        Self {
            media: Arc::new(Mutex::new(FaultMedia {
                page_count: admitted_pages(SEGMENTS).unwrap(),
                visible: image.clone(),
                durable: image,
                cache: BTreeMap::new(),
                mode,
                mutation_count: 0,
                batch_write_count: 0,
                trace: Vec::new(),
                fault: None,
            })),
        }
    }

    fn arm(&self, mutation_index: usize, action: FaultAction) {
        let mut media = self.media.lock().unwrap();
        media.mutation_count = 0;
        media.trace.clear();
        media.fault = Some(FaultPlan {
            mutation_index,
            action,
        });
    }

    fn mutation_count(&self) -> usize {
        self.media.lock().unwrap().mutation_count
    }

    fn batch_write_count(&self) -> usize {
        self.media.lock().unwrap().batch_write_count
    }

    fn cached_range(&self, first_page: u64, page_count: usize) -> bool {
        let media = self.media.lock().unwrap();
        (first_page..first_page.saturating_add(page_count as u64))
            .all(|page| media.cache.contains_key(&page))
    }

    fn trace(&self) -> Vec<MutationKind> {
        self.media.lock().unwrap().trace.clone()
    }

    fn durable_image(&self) -> BTreeMap<u64, Page> {
        self.media.lock().unwrap().durable.clone()
    }

    fn next_action(&self, kind: MutationKind) -> FaultAction {
        let mut media = self.media.lock().unwrap();
        let index = media.mutation_count;
        media.mutation_count += 1;
        media.trace.push(kind);
        media
            .fault
            .filter(|plan| plan.mutation_index == index)
            .map_or(FaultAction::Normal, |plan| plan.action)
    }

    fn write_effect(&self, page: u64, bytes: Page, effect: Effect) {
        let mut media = self.media.lock().unwrap();
        if !matches!(effect, Effect::None) {
            media.visible.insert(page, bytes);
        }
        if matches!(effect, Effect::Durable) {
            media.durable.insert(page, bytes);
        }
    }

    fn write_pages_effect(&self, first_page: u64, input: &[Page], effect: Effect) {
        let mut media = self.media.lock().unwrap();
        for (offset, bytes) in input.iter().enumerate() {
            let page = first_page + offset as u64;
            if !matches!(effect, Effect::None) {
                media.visible.insert(page, *bytes);
            }
            if matches!(effect, Effect::Durable) {
                media.durable.insert(page, *bytes);
            }
        }
    }

    fn invalidate_cache(&self, first_page: u64, page_count: usize) {
        let mut media = self.media.lock().unwrap();
        for page in first_page..first_page.saturating_add(page_count as u64) {
            media.cache.remove(&page);
        }
    }

    fn cache_pages(&self, first_page: u64, input: &[Page]) {
        let mut media = self.media.lock().unwrap();
        if media.mode != DeviceMode::CachedBatch {
            return;
        }
        for (offset, bytes) in input.iter().enumerate() {
            media.cache.insert(first_page + offset as u64, *bytes);
        }
    }

    fn flush_effect(&self, effect: Effect) {
        if matches!(effect, Effect::Durable) {
            let mut media = self.media.lock().unwrap();
            media.durable = media.visible.clone();
        }
    }
}

impl PageDevice for FaultDevice {
    type Error = TestError;

    fn info(&self) -> PageDeviceInfo {
        let page_count = self.media.lock().unwrap().page_count;
        PageDeviceInfo {
            device_id: [0xc7; 16],
            range_first_logical_block: 2048,
            logical_block_count: page_count * 8,
            logical_block_size: 512,
            page_count,
        }
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        let mut media = self.media.lock().unwrap();
        if page >= media.page_count {
            return Err(TestError::OutsideRange);
        }
        if media.mode == DeviceMode::CachedBatch {
            if let Some(stored) = media.cache.get(&page) {
                output.copy_from_slice(stored);
                return Ok(());
            }
        }
        output.fill(0);
        if let Some(stored) = media.visible.get(&page) {
            output.copy_from_slice(stored);
        }
        if media.mode == DeviceMode::CachedBatch {
            media.cache.insert(page, *output);
        }
        Ok(())
    }

    async fn write_page(
        &self,
        page: u64,
        input: &Page,
    ) -> Result<(), MutationFailure<Self::Error>> {
        if self.media.lock().unwrap().mode == DeviceMode::CachedBatch {
            self.invalidate_cache(page, 1);
        }
        if page >= self.media.lock().unwrap().page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        let bytes = *input;
        match self.next_action(MutationKind::Write) {
            FaultAction::Normal => {
                self.write_effect(page, bytes, Effect::Visible);
                self.cache_pages(page, core::slice::from_ref(&bytes));
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.write_effect(page, bytes, effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.write_effect(page, bytes, effect);
                pending::<Result<(), MutationFailure<TestError>>>().await
            }
        }
    }

    async fn read_pages(&self, first_page: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        if output.is_empty() {
            return Ok(());
        }
        if self.media.lock().unwrap().mode == DeviceMode::PageFallback {
            for (offset, page) in output.iter_mut().enumerate() {
                self.read_page(first_page + offset as u64, page).await?;
            }
            return Ok(());
        }

        let mut media = self.media.lock().unwrap();
        let end = first_page
            .checked_add(output.len() as u64)
            .ok_or(TestError::OutsideRange)?;
        if end > media.page_count {
            return Err(TestError::OutsideRange);
        }
        let all_cached = output.iter_mut().enumerate().all(|(offset, page)| {
            media
                .cache
                .get(&(first_page + offset as u64))
                .is_some_and(|stored| {
                    page.copy_from_slice(stored);
                    true
                })
        });
        if all_cached {
            return Ok(());
        }
        for (offset, page) in output.iter_mut().enumerate() {
            let page_number = first_page + offset as u64;
            page.fill(0);
            if let Some(stored) = media.visible.get(&page_number) {
                page.copy_from_slice(stored);
            }
        }
        for (offset, page) in output.iter().enumerate() {
            media.cache.insert(first_page + offset as u64, *page);
        }
        Ok(())
    }

    async fn write_pages(
        &self,
        first_page: u64,
        input: &[Page],
    ) -> Result<(), MutationFailure<Self::Error>> {
        if input.is_empty() {
            return Ok(());
        }
        if self.media.lock().unwrap().mode == DeviceMode::PageFallback {
            for (offset, page) in input.iter().enumerate() {
                self.write_page(first_page + offset as u64, page).await?;
            }
            return Ok(());
        }

        // Match production ordering: discard every affected cache entry before
        // validating/submitting the batch, and repopulate only after the whole
        // request returns an unambiguous success.
        self.invalidate_cache(first_page, input.len());
        let end = first_page
            .checked_add(input.len() as u64)
            .ok_or_else(|| MutationFailure::not_submitted(TestError::OutsideRange))?;
        if end > self.media.lock().unwrap().page_count {
            return Err(MutationFailure::not_submitted(TestError::OutsideRange));
        }
        self.media.lock().unwrap().batch_write_count += 1;
        match self.next_action(MutationKind::Write) {
            FaultAction::Normal => {
                self.write_pages_effect(first_page, input, Effect::Visible);
                self.cache_pages(first_page, input);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.write_pages_effect(first_page, input, effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.write_pages_effect(first_page, input, effect);
                pending::<Result<(), MutationFailure<TestError>>>().await
            }
        }
    }

    async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
        match self.next_action(MutationKind::Flush) {
            FaultAction::Normal => {
                self.flush_effect(Effect::Durable);
                Ok(())
            }
            FaultAction::FailNotSubmitted => {
                Err(MutationFailure::not_submitted(TestError::Injected))
            }
            FaultAction::FailAmbiguous(effect) => {
                self.flush_effect(effect);
                Err(MutationFailure::ambiguous(TestError::DriverRestarted))
            }
            FaultAction::Pending(effect) => {
                self.flush_effect(effect);
                pending::<Result<(), MutationFailure<TestError>>>().await
            }
        }
    }
}

fn limits() -> StoreLimits {
    StoreLimits {
        recovery_memory_bytes: 128 * 1024 * 1024,
        ..StoreLimits::default()
    }
}

fn store_id() -> StoreId {
    StoreId::new(STORE_ID_RAW).unwrap()
}

fn component_space() -> SpaceId {
    SpaceId::new(COMPONENT_SPACE_RAW).unwrap()
}

fn format_records() -> Vec<[u8; RECORD_SIZE]> {
    vec![RecordChain::new(store_id())
        .append(None, RecordBody::Format)
        .unwrap()]
}

fn evidence_bytes() -> [u8; 112] {
    let mut bytes = [0_u8; 112];
    bytes[..8].copy_from_slice(b"VIBESIG\0");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&112_u16.to_le_bytes());
    bytes[12..14].copy_from_slice(&1_u16.to_le_bytes());
    bytes[16..48].fill(0x31);
    bytes[48..].fill(0xa7);
    bytes
}

fn artifact_bytes(size: usize) -> Vec<u8> {
    // The SegmentStore boundary receives an already-admitted opaque artifact;
    // semantic Component validation is independently covered above this
    // layer. Deterministic non-compressible bytes force the exact inline
    // length through the physical CAS and authority checkpoint paths.
    (0..size)
        .map(|index| (index.wrapping_mul(197).wrapping_add(0x11)) as u8)
        .collect()
}

#[derive(Clone)]
struct BundleFixture {
    predecessor: Vec<[u8; RECORD_SIZE]>,
    successor: Vec<[u8; RECORD_SIZE]>,
    root: GrantRecord,
    evidence: vibeos_durable_format::RecoveredObject,
    artifact: vibeos_durable_format::RecoveredObject,
}

impl BundleFixture {
    fn new(artifact_size: usize) -> Self {
        let predecessor = format_records();
        let preflight = preflight_recovery(&predecessor, store_id()).unwrap();
        let mut chain =
            RecordChain::from_checkpoint(store_id(), preflight.chain_checkpoint().unwrap())
                .unwrap();
        let base = preflight.id_high_water().max(1);
        let evidence_transaction = TransactionId::new(base).unwrap();
        let evidence_object = ObjectId::new(base + 1).unwrap();
        let artifact_transaction = TransactionId::new(base + 2).unwrap();
        let artifact_object = ObjectId::new(base + 3).unwrap();
        let root_transaction = TransactionId::new(base + 4).unwrap();
        let root_derivation = DerivationId::new(base + 5).unwrap();
        let mut successor = predecessor.clone();
        successor.push(
            chain
                .append(
                    None,
                    RecordBody::IdHighWater {
                        // Internal protocol IDs remain the exact contiguous
                        // base+0..base+5 range. The same sole reservation must
                        // additionally cover the fixed Component SpaceId,
                        // without moving `base` up into that policy identity.
                        exclusive_end: (base + 6).max(COMPONENT_SPACE_RAW + 1),
                    },
                )
                .unwrap(),
        );
        successor.extend(
            encode_object_transaction(
                &mut chain,
                evidence_transaction,
                evidence_object,
                ObjectKind::new(EVIDENCE_KIND_RAW).unwrap(),
                &evidence_bytes(),
            )
            .unwrap()
            .records,
        );
        successor.extend(
            encode_object_transaction(
                &mut chain,
                artifact_transaction,
                artifact_object,
                ObjectKind::new(ARTIFACT_KIND_RAW).unwrap(),
                &artifact_bytes(artifact_size),
            )
            .unwrap()
            .records,
        );
        let root = GrantRecord {
            derivation_id: root_derivation,
            parent_id: None,
            object_id: artifact_object,
            target: SlotIdentity {
                space: component_space(),
                slot: 0,
                generation: 0,
            },
            rights: DurableRights::READ,
            resource_kind: ResourceKind::new(STORED_OBJECT_KIND_RAW).unwrap(),
            flags: GrantFlags::ROOT,
        };
        successor.extend(
            preview_grant_transaction(&chain, root_transaction, root.clone())
                .unwrap()
                .0
                .records,
        );
        let recovered = preflight_recovery(&successor, store_id()).unwrap();
        let evidence = recovered
            .committed_objects()
            .iter()
            .find(|object| object.object_id == evidence_object)
            .unwrap()
            .clone();
        let artifact = recovered
            .committed_objects()
            .iter()
            .find(|object| object.object_id == artifact_object)
            .unwrap()
            .clone();
        assert_eq!(evidence.transaction_id, evidence_transaction);
        assert_eq!(artifact.transaction_id, artifact_transaction);
        assert_eq!(root_transaction.get() + 1, root_derivation.get());
        assert_eq!(COMPONENT_SPACE_RAW + 1, recovered.id_high_water());
        Self {
            predecessor,
            successor,
            root,
            evidence,
            artifact,
        }
    }

    fn predecessor_bytes(&self) -> Vec<u8> {
        self.predecessor.iter().flatten().copied().collect()
    }

    fn successor_bytes(&self) -> Vec<u8> {
        self.successor.iter().flatten().copied().collect()
    }

    fn predecessor_import(&self) -> PersistentAuthorityImport {
        PersistentAuthorityImport::from_m4(
            &self.predecessor,
            store_id(),
            &[],
            POLICY_V2,
            Vec::new(),
        )
        .unwrap()
        .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, u64::MAX, u64::MAX, false)
        .unwrap()
    }

    fn successor_import(&self) -> PersistentAuthorityImport {
        let preflight = preflight_recovery(&self.successor, store_id()).unwrap();
        PersistentAuthorityImport::from_m4_with_exact_inline_attachments_preflighted(
            &self.successor,
            store_id(),
            &[RootPolicy {
                grant: self.root.clone(),
            }],
            &[],
            core::slice::from_ref(&self.evidence),
            POLICY_V2,
            Vec::new(),
            preflight,
        )
        .unwrap()
        .with_system_principal(LEGACY_SYSTEM_PRINCIPAL, u64::MAX, u64::MAX, false)
        .unwrap()
    }
}

fn prepared_image(fixture: &BundleFixture) -> BTreeMap<u64, Page> {
    let device = FaultDevice::from_durable(BTreeMap::new());
    let (runtime, _quota, provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    block_on(store.format(FormatOptions {
        store_uuid: StoreUuid::new(*b"C74-PHYS-MATRIX!").unwrap(),
        cleaner_reserve_segments: 4,
        limits: limits(),
    }))
    .unwrap();
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let initial =
        block_on(store.import_persistent_authority(&maintenance, fixture.predecessor_import()))
            .unwrap();
    assert_eq!(initial.record_stream(), fixture.predecessor_bytes());
    assert_eq!(
        initial.root_policy_sha256(),
        root_policy_commitment(POLICY_V2)
    );
    drop(store);
    device.durable_image()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicalState {
    Predecessor,
    Successor,
}

fn cold_state(image: BTreeMap<u64, Page>, fixture: &BundleFixture) -> LogicalState {
    let device = FaultDevice::from_durable(image);
    let (runtime, _quota, _provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.mount()).unwrap();
    let view =
        block_on(store.recover_persistent_authority(root_policy_commitment(POLICY_V2))).unwrap();
    assert_eq!(view.root_policy_sha256(), root_policy_commitment(POLICY_V2));
    if view.record_stream() == fixture.predecessor_bytes() {
        assert!(view.objects().is_empty());
        return LogicalState::Predecessor;
    }
    assert_eq!(view.record_stream(), fixture.successor_bytes());
    // The exact evidence record remains authenticated by the logical stream,
    // but checkpoint-only retention must never create a CAS binding or a
    // resolver handle for it.
    assert_eq!(view.objects().len(), 1);
    assert!(view.object_for_recovered(&fixture.evidence).is_none());
    let artifact = view.object_for_recovered(&fixture.artifact).unwrap();
    assert_eq!(artifact.object_kind(), ARTIFACT_KIND_RAW);
    assert_eq!(artifact.exact_len(), fixture.artifact.byte_len());
    assert_eq!(
        block_on(store.read_persistent_object(artifact)).unwrap(),
        fixture.artifact.bytes
    );
    LogicalState::Successor
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallOutcome {
    Completed,
    AlreadyComplete,
    Failed,
    Pending,
}

fn drive_converging_install(device: &FaultDevice, fixture: &BundleFixture) -> InstallOutcome {
    let (runtime, _quota, provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime);
    if block_on(store.mount()).is_err() {
        return InstallOutcome::Failed;
    }
    let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
    let writer = store
        .derive_persistent_authority_writer(&maintenance)
        .unwrap();
    let view = match block_on(store.recover_persistent_authority(root_policy_commitment(POLICY_V2)))
    {
        Ok(view) => view,
        Err(_) => return InstallOutcome::Failed,
    };
    if view.record_stream() == fixture.successor_bytes() {
        return InstallOutcome::AlreadyComplete;
    }
    if view.record_stream() != fixture.predecessor_bytes() {
        return InstallOutcome::Failed;
    }
    let principal = view.principals()[0].clone();
    let mut append = Box::pin(store.append_persistent_authority(
        &writer,
        view.checkpoint_generation(),
        fixture.successor_import(),
        &principal,
    ));
    match poll_once(append.as_mut()) {
        Poll::Ready(Ok(result)) => {
            assert_eq!(result.view().record_stream(), fixture.successor_bytes());
            assert_eq!(result.view().objects().len(), 1);
            assert!(result.object_for_recovered(&fixture.evidence).is_none());
            assert!(result.object_for_recovered(&fixture.artifact).is_some());
            InstallOutcome::Completed
        }
        Poll::Ready(Err(_)) => InstallOutcome::Failed,
        Poll::Pending => InstallOutcome::Pending,
    }
}

fn run_fault_case(
    initial_image: &BTreeMap<u64, Page>,
    fixture: &BundleFixture,
    boundary: usize,
    action: FaultAction,
) {
    run_fault_case_with_mode(
        initial_image,
        fixture,
        boundary,
        action,
        DeviceMode::PageFallback,
    );
}

fn run_fault_case_with_mode(
    initial_image: &BTreeMap<u64, Page>,
    fixture: &BundleFixture,
    boundary: usize,
    action: FaultAction,
    mode: DeviceMode,
) {
    let device = FaultDevice::from_durable_with_mode(initial_image.clone(), mode);
    device.arm(boundary, action);
    let outcome = drive_converging_install(&device, fixture);
    assert!(
        matches!(outcome, InstallOutcome::Failed | InstallOutcome::Pending),
        "fault {action:?} at boundary {boundary} unexpectedly completed"
    );
    assert_eq!(
        device.mutation_count(),
        boundary + 1,
        "fault {action:?} did not fire at boundary {boundary}"
    );

    // Power loss is modelled by constructing a fresh device from only the
    // durable image. The logical authority must be one complete checkpoint.
    let crashed_image = device.durable_image();
    let recovered = cold_state(crashed_image.clone(), fixture);

    // The installer retries from a fresh cold recovery. A predecessor performs
    // exactly one new V2 append; a successor is an exact no-op with zero media
    // mutations. Both converge to the same complete successor.
    let retry = FaultDevice::from_durable_with_mode(crashed_image, mode);
    let retried = drive_converging_install(&retry, fixture);
    match recovered {
        LogicalState::Predecessor => {
            assert_eq!(retried, InstallOutcome::Completed);
            assert!(retry.mutation_count() > 0);
        }
        LogicalState::Successor => {
            assert_eq!(retried, InstallOutcome::AlreadyComplete);
            assert_eq!(retry.mutation_count(), 0);
        }
    }
    assert_eq!(
        cold_state(retry.durable_image(), fixture),
        LogicalState::Successor
    );
}

fn baseline(initial_image: &BTreeMap<u64, Page>, fixture: &BundleFixture) -> Vec<MutationKind> {
    baseline_with_mode(initial_image, fixture, DeviceMode::PageFallback)
}

fn baseline_with_mode(
    initial_image: &BTreeMap<u64, Page>,
    fixture: &BundleFixture,
    mode: DeviceMode,
) -> Vec<MutationKind> {
    let device = FaultDevice::from_durable_with_mode(initial_image.clone(), mode);
    assert_eq!(
        drive_converging_install(&device, fixture),
        InstallOutcome::Completed
    );
    if mode == DeviceMode::CachedBatch {
        assert!(device.batch_write_count() > 0);
    }
    let trace = device.trace();
    assert!(trace.contains(&MutationKind::Write));
    assert!(trace.contains(&MutationKind::Flush));
    assert_eq!(
        cold_state(device.durable_image(), fixture),
        LogicalState::Successor
    );
    trace
}

#[test]
fn logical_512_byte_prefix_model_never_publishes_a_partial_bundle() {
    let fixture = BundleFixture::new(352);
    for record_index in 0..fixture.successor.len() {
        for cut in 0..=RECORD_SIZE {
            let mut image = fixture.successor[..record_index].to_vec();
            if cut != 0 {
                let mut torn = [0_u8; RECORD_SIZE];
                torn[..cut].copy_from_slice(&fixture.successor[record_index][..cut]);
                image.push(torn);
            }
            let complete_records = record_index + usize::from(cut == RECORD_SIZE);
            if complete_records == 0 {
                assert!(preflight_recovery(&image, store_id()).is_err());
                continue;
            }
            let recovered = preflight_recovery(&image, store_id()).unwrap();
            assert_eq!(recovered.last_sequence() as usize, complete_records);
            let component_roots = recovered
                .committed_grants()
                .iter()
                .filter(|grant| grant.grant.target.space == component_space())
                .count();
            let fully_committed = complete_records == fixture.successor.len();
            assert_eq!(component_roots, usize::from(fully_committed));
        }
    }
}

#[test]
fn small_bundle_exhaustive_storage_v2_fault_matrix_recovers_only_two_states() {
    let fixture = BundleFixture::new(352);
    let initial_image = prepared_image(&fixture);
    let trace = baseline(&initial_image, &fixture);
    for boundary in 0..trace.len() {
        for action in FAULT_ACTIONS {
            run_fault_case(&initial_image, &fixture, boundary, action);
        }
    }
}

#[test]
fn cached_batch_write_pages_fault_matrix_recovers_only_two_states() {
    let fixture = BundleFixture::new(352);
    let initial_image = prepared_image(&fixture);
    let trace = baseline_with_mode(&initial_image, &fixture, DeviceMode::CachedBatch);
    for boundary in 0..trace.len() {
        for action in FAULT_ACTIONS {
            run_fault_case_with_mode(
                &initial_image,
                &fixture,
                boundary,
                action,
                DeviceMode::CachedBatch,
            );
        }
    }
}

#[test]
fn cached_batch_write_pages_discards_stale_range_before_every_uncertain_return() {
    let first_page = 7;
    let old: [Page; 3] = [[0x11; 4096], [0x22; 4096], [0x33; 4096]];
    let new: [Page; 3] = [[0xa1; 4096], [0xb2; 4096], [0xc3; 4096]];
    let initial: BTreeMap<_, _> = old
        .iter()
        .enumerate()
        .map(|(offset, page)| (first_page + offset as u64, *page))
        .collect();

    for action in FAULT_ACTIONS {
        let device = FaultDevice::from_durable_cached_batch(initial.clone());
        let mut primed = [[0_u8; 4096]; 3];
        block_on(device.read_pages(first_page, &mut primed)).unwrap();
        assert_eq!(primed, old);
        assert!(device.cached_range(first_page, old.len()));

        device.arm(0, action);
        let mut write = Box::pin(device.write_pages(first_page, &new));
        match (action, poll_once(write.as_mut())) {
            (FaultAction::Pending(_), Poll::Pending) => {}
            (
                FaultAction::FailNotSubmitted | FaultAction::FailAmbiguous(_),
                Poll::Ready(Err(_)),
            ) => {}
            (action, result) => panic!("unexpected batch result for {action:?}: {result:?}"),
        }
        drop(write);

        // A failed or cancelled request must never leave the old cached pages
        // able to masquerade as physical postflight evidence. Effect::Visible
        // and Effect::Durable are then observed from the backing device; None
        // observes the old media bytes, but in every case only after a miss.
        assert!(!device.cached_range(first_page, old.len()));
        let mut observed = [[0_u8; 4096]; 3];
        block_on(device.read_pages(first_page, &mut observed)).unwrap();
        let changed = matches!(
            action,
            FaultAction::FailAmbiguous(Effect::Visible | Effect::Durable)
                | FaultAction::Pending(Effect::Visible | Effect::Durable)
        );
        assert_eq!(observed, if changed { new } else { old });
    }
}

#[test]
fn on_media_policy_selects_one_exact_recognized_profile() {
    let fixture = BundleFixture::new(352);
    let image = prepared_image(&fixture);
    let device = FaultDevice::from_durable(image);
    let (runtime, _quota, _provisioner) =
        StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .unwrap();
    let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime);
    block_on(store.mount()).unwrap();
    let observed = root_policy_commitment(POLICY_V2);
    let unrelated = [0x5a; 32];

    let view =
        block_on(store.recover_persistent_authority_recognized(&[unrelated, observed])).unwrap();
    assert_eq!(view.root_policy_sha256(), observed);
    for recognized in [&[][..], &[unrelated][..], &[observed, observed][..]] {
        assert!(matches!(
            block_on(store.recover_persistent_authority_recognized(recognized)),
            Err(PersistentAuthorityError::PolicyMismatch)
        ));
    }
}

fn max_artifact_boundaries(trace: &[MutationKind]) -> BTreeSet<usize> {
    let mut selected = BTreeSet::new();
    selected.insert(0);
    selected.insert(trace.len() - 1);
    for (index, pair) in trace.windows(2).enumerate() {
        if pair[0] != pair[1] {
            selected.insert(index);
            selected.insert(index + 1);
        }
    }
    // Cover the whole long write train without turning this large-object test
    // into thousands of multi-MiB cold mounts. The exhaustive small matrix
    // above covers every mutation boundary; this selection adds every phase
    // transition plus 33 evenly distributed large-object boundaries.
    let stride = trace.len().div_ceil(33).max(1);
    selected.extend((0..trace.len()).step_by(stride));
    for kind in [MutationKind::Write, MutationKind::Flush] {
        let positions: Vec<_> = trace
            .iter()
            .enumerate()
            .filter_map(|(index, candidate)| (*candidate == kind).then_some(index))
            .collect();
        for percentile in [0, 1, 2, 3, 4] {
            selected.insert(positions[percentile * (positions.len() - 1) / 4]);
        }
    }
    selected
}

#[test]
fn c71_max_inline_artifact_storage_v2_fault_effect_matrix_converges() {
    let fixture = BundleFixture::new(MAX_C71_ARTIFACT_BYTES);
    assert_eq!(fixture.artifact.bytes.len(), MAX_C71_ARTIFACT_BYTES);
    assert!(!fixture.artifact.is_external());
    let initial_image = prepared_image(&fixture);
    let trace = baseline(&initial_image, &fixture);
    let boundaries = max_artifact_boundaries(&trace);
    assert!(boundaries.len() >= 12);
    for boundary in boundaries {
        for action in FAULT_ACTIONS {
            run_fault_case(&initial_image, &fixture, boundary, action);
        }
    }
}
