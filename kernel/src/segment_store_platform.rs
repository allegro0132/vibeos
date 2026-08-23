//! Capability-scoped kernel adapters for Storage V2.
//!
//! The admitted block backends expose 512-byte logical blocks while the
//! on-media Storage V2 ABI is page based. This module is the sole translation
//! boundary: QEMU issues each 4 KiB page (and bounded consecutive page batch)
//! as a contiguous capability-checked request against one pinned incarnation;
//! Milk-V retains the compatible one-block PIO fallback.

extern crate alloc;

use core::any::Any;
use core::cell::UnsafeCell;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use core::task::{Context, Poll};

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;

use vibeos_core::cap::{Cap, InvocationLease, Resource, Rights};
use vibeos_core::heap::OwnerId;
#[cfg(feature = "file-tree")]
use vibeos_file_store::{FileError, FileTreeBackend, FileTreeFuture, FileTreeRoot, FsTransaction};
use vibeos_segment_format::{PAGE_SIZE, Page, StoreUuid};
use vibeos_segment_store::{
    ColdScrubEvidence, FormatOptions, FormatProbe, GrowablePageDevice, LegacyFormatProbe,
    MigrationControl, MigrationController, MigrationError, MigrationState, MigrationTransition,
    PageDevice, PageDeviceInfo, PersistentAuthorityAppendResult, PersistentAuthorityError,
    PersistentAuthorityImport, PersistentAuthorityTransientObjects, PersistentAuthorityView,
    PersistentObjectHandle, ScrubStatus, SegmentStore, StoragePrincipal, StorageQuotaProvisioner,
    StorageV2FormatProbe, StoreLimits, StoreMaintenance, StoreMaintenanceProvisioner,
    StoreRuntimeContext,
};
use vibeos_storage_device::{
    BlockRangeCapability, BlockRangeProvisioner, DeviceSession, MutationCertainty, MutationFailure,
    MutationResult,
};

use crate::block_device::{self, BlockDevice, BlockError};
use crate::world::Space;
use crate::{exec, heap, sync::SpinLock};

const LOGICAL_BLOCK_SIZE: usize = 512;
const BLOCKS_PER_PAGE: u64 = (PAGE_SIZE / LOGICAL_BLOCK_SIZE) as u64;

/// Largest page run one block-device request may carry, derived from the
/// selected board backend's maximum transfer size.
#[cfg(feature = "qemu-virt")]
const MAX_PAGES_PER_REQUEST: usize =
    crate::virtio::BLOCK_MAX_TRANSFER_SIZE as usize / vibeos_segment_format::PAGE_SIZE;
#[cfg(feature = "milkv-duo")]
const MAX_PAGES_PER_REQUEST: usize = crate::sdhci_blk::MAX_TRANSFER_BLOCKS as usize
    * LOGICAL_BLOCK_SIZE
    / vibeos_segment_format::PAGE_SIZE;
const STORAGE_V2_FOREGROUND_FREE_SEGMENTS: u64 = 10;
/// Extra segments requested beyond the floor whenever foreground growth
/// runs, so one growth transaction serves many subsequent commits.
const STORAGE_V2_GROWTH_HYSTERESIS_SEGMENTS: u64 = 22;

/// Scale the fixed foreground floor and hysteresis to the device: they were
/// tuned on large bench devices, and on a small store (the Milk-V 64 MiB
/// slice is sixteen 4 MiB segments) a 10-segment floor is structurally
/// unreachable once a handful of segments hold live data — growth exhausts
/// immediately and every subsequent commit pays up to eight full GC mark
/// walks of the live object graph. An eighth of the device (clamped to the
/// tuned values) keeps foreground collection an emergency, not a tax.
fn scaled_free_floor(total_segments: u64) -> u64 {
    (total_segments / 8).clamp(2, STORAGE_V2_FOREGROUND_FREE_SEGMENTS)
}

fn scaled_growth_hysteresis(total_segments: u64) -> u64 {
    (total_segments / 4).clamp(2, STORAGE_V2_GROWTH_HYSTERESIS_SEGMENTS)
}
pub(crate) const STORAGE_V2_GROWTH_GRANULE_BLOCKS: u64 =
    vibeos_segment_format::SEGMENT_PAGES * BLOCKS_PER_PAGE;
const M4_STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;

/// Poll one storage future with supervisor allocation provenance. `SegmentStore`
/// retains recovered tables across calls, so those allocations must never
/// belong to a raw-reclaimable caller arena.
struct SystemPoll<F> {
    future: F,
}

impl<F: Future> Future for SystemPoll<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        // Safety: pinning `SystemPoll` pins its `future` field, and the field is
        // never moved before this wrapper is dropped.
        let result =
            unsafe { Pin::new_unchecked(&mut self.get_unchecked_mut().future) }.poll(context);
        system.restore();
        result
    }
}

fn poll_as_system<F: Future>(future: F) -> SystemPoll<F> {
    SystemPoll { future }
}

/// Allocate a deliberately large, one-shot control future in the trusted
/// system domain. Migration composes bounded mount, scrub, import, and
/// body/seal state machines; keeping that aggregate future inline in the shell
/// executor frame would consume the physical hart stack even though none of
/// its media buffers are recursively live.
fn system_arc<T>(value: T) -> Arc<T> {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let value = Arc::new(value);
    system.restore();
    value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageIoError {
    AuthorityRevoked,
    OperationBusy,
    InvalidRange,
    Block(BlockError),
}

impl fmt::Display for PageIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityRevoked => formatter.write_str("Storage V2 block authority revoked"),
            Self::OperationBusy => formatter.write_str("Storage V2 page device is already active"),
            Self::InvalidRange => formatter.write_str("Storage V2 page is outside its range"),
            Self::Block(error) => write!(formatter, "Storage V2 block I/O failed: {error}"),
        }
    }
}

/// An exact page-oriented view of one private block-range capability.
///
/// The CSpace and handle are retained rather than a long-lived invocation
/// lease. Revocation is rechecked before every page I/O. A private operation
/// epoch additionally pins one device session across every page and flush in a
/// high-level store/control transaction; each page keeps one fresh lease across
/// its eight sequential block requests.
#[derive(Clone)]
pub(crate) struct CapabilityPageDevice {
    backend: Arc<Space>,
    block: Cap,
    info: Arc<SpinLock<PageDeviceInfo>>,
    initial_block_count: u64,
    provisioned_block_count: u64,
    active: Arc<SpinLock<Option<ActivePageSession>>>,
    page_cache: Arc<PageCache>,
}

/// Recover by the policy identity already committed on media. A v2-enabled
/// build recognizes the exact legacy-v1 and Component-v2 commitments as two
/// disjoint profiles; unknown or duplicate commitments fail closed. This does
/// not upgrade v1, and the Component installer separately requires exact v2.
async fn recover_recognized_persistent_authority(
    store: &SegmentStore<CapabilityPageDevice>,
    requested_policy_sha256: [u8; 32],
) -> Result<PersistentAuthorityView, PersistentAuthorityError<PageIoError>> {
    #[cfg(feature = "component-durable-publication")]
    if requested_policy_sha256
        == crate::durable_cspace::storage_v2_component_external_policy_sha256()
    {
        let recognized = [
            crate::durable_cspace::storage_v2_legacy_external_policy_sha256(),
            crate::durable_cspace::storage_v2_component_external_policy_sha256(),
        ];
        return store
            .recover_persistent_authority_recognized(&recognized)
            .await;
    }
    store
        .recover_persistent_authority(requested_policy_sha256)
        .await
}

/// Bounded write-through LRU cache over this device's pages, shared by every
/// clone of the device handle. The storage stack re-reads its hot B+tree and
/// manifest pages on every traversal — measured at tens of megabytes of
/// repeat reads per small mutation — which a RAM-backed QEMU disk absorbs
/// but a 25 MHz PIO microSD cannot. All runtime I/O flows through this one
/// device, so hits are coherent: writes update or drop the affected entries,
/// and an ambiguous write failure drops them as well.
const PAGE_CACHE_CAPACITY: usize = 512;

struct PageCacheEntry {
    data: alloc::boxed::Box<Page>,
    tick: u64,
}

struct PageCache {
    state: SpinLock<PageCacheState>,
}

struct PageCacheState {
    entries: alloc::collections::BTreeMap<u64, PageCacheEntry>,
    tick: u64,
}

/// Bounded page-cache effectiveness telemetry: a one-line hit-rate report
/// every 8192 page reads.
fn page_cache_account(pages: u64, hits: u64) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static PAGES: AtomicU64 = AtomicU64::new(0);
    static HITS: AtomicU64 = AtomicU64::new(0);
    static LAST_REPORT: AtomicU64 = AtomicU64::new(0);
    HITS.fetch_add(hits, Ordering::Relaxed);
    let total = PAGES.fetch_add(pages, Ordering::Relaxed) + pages;
    let last = LAST_REPORT.load(Ordering::Relaxed);
    if total.saturating_sub(last) >= 8192
        && LAST_REPORT
            .compare_exchange(last, total, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        crate::uart::_print(format_args!(
            "  pgcache: {} of {} page reads served from cache\n",
            HITS.load(Ordering::Relaxed),
            total,
        ));
    }
}

impl PageCache {
    fn new() -> Self {
        Self {
            state: SpinLock::new_recoverable(PageCacheState {
                entries: alloc::collections::BTreeMap::new(),
                tick: 0,
            }),
        }
    }

    /// Copy a cached page into `output`, refreshing its recency.
    fn get(&self, page: u64, output: &mut Page) -> bool {
        let mut state = self.state.lock();
        state.tick += 1;
        let tick = state.tick;
        match state.entries.get_mut(&page) {
            Some(entry) => {
                entry.tick = tick;
                output.copy_from_slice(&entry.data[..]);
                true
            }
            None => false,
        }
    }

    fn insert(&self, page: u64, data: &Page) {
        let boxed = alloc::boxed::Box::new(*data);
        let mut state = self.state.lock();
        state.tick += 1;
        let tick = state.tick;
        if let Some(entry) = state.entries.get_mut(&page) {
            entry.data.copy_from_slice(data);
            entry.tick = tick;
            return;
        }
        if state.entries.len() >= PAGE_CACHE_CAPACITY {
            if let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.tick)
                .map(|(page, _)| *page)
            {
                state.entries.remove(&oldest);
            }
        }
        state
            .entries
            .insert(page, PageCacheEntry { data: boxed, tick });
    }

    fn invalidate(&self, first_page: u64, page_count: usize) {
        let mut state = self.state.lock();
        for page in first_page..first_page.saturating_add(page_count as u64) {
            state.entries.remove(&page);
        }
    }

    /// Drop every write-through observation before a cold media proof. A
    /// successful device write may have populated this cache before its flush
    /// or checkpoint publication later failed, so cached bytes are never
    /// admissible evidence for physical postflight or ambiguous recovery.
    fn clear(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.tick = 0;
    }
}

#[derive(Clone, Copy)]
struct ActivePageSession {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    session: DeviceSession,
    submitted: bool,
}

struct PageDeviceOperation {
    device: CapabilityPageDevice,
    claim: ActivePageSession,
    armed: bool,
}

impl PageDeviceOperation {
    fn finish(mut self) {
        assert!(self.device.clear_operation(self.claim));
        self.armed = false;
    }
}

impl Drop for PageDeviceOperation {
    fn drop(&mut self) {
        if self.armed {
            assert!(self.device.clear_operation(self.claim));
        }
    }
}

impl CapabilityPageDevice {
    /// Full provisioned capacity of this device in pages, independent of how
    /// much has been admitted so far — the denominator for scaling the
    /// foreground free-segment policy to the actual media size.
    pub(crate) fn provisioned_page_count(&self) -> u64 {
        self.provisioned_block_count / BLOCKS_PER_PAGE
    }

    pub(crate) fn new(
        backend: Arc<Space>,
        block: Cap,
        expected_first_block: u64,
        expected_block_count: u64,
    ) -> Result<Self, PageIoError> {
        if expected_block_count == 0 || !expected_block_count.is_multiple_of(BLOCKS_PER_PAGE) {
            return Err(PageIoError::InvalidRange);
        }
        let lease = backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(block, Rights::READ)
            .map_err(|_| PageIoError::AuthorityRevoked)?;
        let range = lease.with(BlockDevice::range);
        if range.first_block() != expected_first_block
            || range.block_count() != expected_block_count
        {
            return Err(PageIoError::InvalidRange);
        }
        Ok(Self {
            backend,
            block,
            info: system_arc(SpinLock::new(PageDeviceInfo {
                device_id: range.device_id().get().to_le_bytes(),
                range_first_logical_block: range.first_block(),
                logical_block_count: range.block_count(),
                logical_block_size: LOGICAL_BLOCK_SIZE as u32,
                page_count: range.block_count() / BLOCKS_PER_PAGE,
            })),
            initial_block_count: range.block_count(),
            provisioned_block_count: range.block_count(),
            active: system_arc(SpinLock::new_recoverable(None)),
            page_cache: system_arc(PageCache::new()),
        })
    }

    pub(crate) fn new_preprovisioned(
        backend: Arc<Space>,
        block: Cap,
        expected_first_block: u64,
        initial_block_count: u64,
    ) -> Result<Self, PageIoError> {
        if initial_block_count == 0 || !initial_block_count.is_multiple_of(BLOCKS_PER_PAGE) {
            return Err(PageIoError::InvalidRange);
        }
        let lease = backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(block, Rights::READ)
            .map_err(|_| PageIoError::AuthorityRevoked)?;
        let range = lease.with(BlockDevice::range);
        if range.first_block() != expected_first_block
            || range.block_count() < initial_block_count
            || !range.block_count().is_multiple_of(BLOCKS_PER_PAGE)
        {
            return Err(PageIoError::InvalidRange);
        }
        Ok(Self {
            backend,
            block,
            info: system_arc(SpinLock::new(PageDeviceInfo {
                device_id: range.device_id().get().to_le_bytes(),
                range_first_logical_block: range.first_block(),
                logical_block_count: initial_block_count,
                logical_block_size: LOGICAL_BLOCK_SIZE as u32,
                page_count: initial_block_count / BLOCKS_PER_PAGE,
            })),
            initial_block_count,
            provisioned_block_count: range.block_count(),
            active: system_arc(SpinLock::new_recoverable(None)),
            page_cache: system_arc(PageCache::new()),
        })
    }

    fn begin_operation(
        &self,
        task: exec::TaskId,
        domain: heap::AllocationDomain,
        token: u64,
    ) -> Result<PageDeviceOperation, PageIoError> {
        let lease = self.lease(Rights::READ)?;
        let session = block_device::range_info_with(&lease)
            .map_err(PageIoError::Block)?
            .session();
        let claim = ActivePageSession {
            task,
            domain,
            token,
            session,
            submitted: false,
        };
        let mut active = self.active.lock();
        if active.is_some() {
            return Err(PageIoError::OperationBusy);
        }
        *active = Some(claim);
        Ok(PageDeviceOperation {
            device: self.clone(),
            claim,
            armed: true,
        })
    }

    fn begin_current_operation(&self) -> Result<PageDeviceOperation, PageIoError> {
        let task = exec::current_task_id().ok_or(PageIoError::AuthorityRevoked)?;
        let domain = heap::current_domain();
        let token = NEXT_PAGE_OPERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("page-device operation token space exhausted");
        self.begin_operation(task, domain, token)
    }

    fn clear_operation(&self, expected: ActivePageSession) -> bool {
        let mut active = self.active.lock();
        if active.is_some_and(|claim| {
            claim.task == expected.task
                && claim.domain == expected.domain
                && claim.token == expected.token
        }) {
            *active = None;
            true
        } else {
            false
        }
    }

    fn expected_session(&self) -> Result<DeviceSession, PageIoError> {
        self.active
            .lock()
            .as_ref()
            .map(|claim| claim.session)
            .ok_or(PageIoError::AuthorityRevoked)
    }

    fn require_session(&self, observed: DeviceSession) -> Result<(), PageIoError> {
        if observed == self.expected_session()? {
            Ok(())
        } else {
            Err(PageIoError::Block(BlockError::DriverRestarted))
        }
    }

    fn mutation_submitted(&self) -> bool {
        self.active
            .lock()
            .as_ref()
            .is_some_and(|claim| claim.submitted)
    }

    fn mark_mutation_submitted(&self) {
        self.active
            .lock()
            .as_mut()
            .expect("page I/O requires an active operation epoch")
            .submitted = true;
    }

    fn clear_submitted_mutation(&self) {
        self.active
            .lock()
            .as_mut()
            .expect("page I/O requires an active operation epoch")
            .submitted = false;
    }

    fn compose_mutation_failure(
        &self,
        failure: MutationFailure<PageIoError>,
    ) -> MutationFailure<PageIoError> {
        if self.mutation_submitted() || failure.certainty() == MutationCertainty::Ambiguous {
            failure.force_ambiguous()
        } else {
            failure
        }
    }

    unsafe fn recover_faulted_operation(&self, task: exec::TaskId, domain: heap::AllocationDomain) {
        let task_key =
            crate::sync::TaskRecoveryKey::new(task.0).expect("executor TaskId zero is reserved");
        // Safety: the executor permanently detached this exact task.
        let _ = unsafe { self.active.recover_after_task_fault(domain, task_key) };
        let mut active = self.active.lock();
        if active.is_some_and(|claim| claim.task == task && claim.domain == domain) {
            *active = None;
        }
    }

    fn lease(&self, need: Rights) -> Result<InvocationLease<BlockDevice>, PageIoError> {
        self.backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(self.block, need)
            .map_err(|_| PageIoError::AuthorityRevoked)
    }

    fn first_sector(&self, page: u64) -> Result<u64, PageIoError> {
        if page >= self.info.lock().page_count {
            return Err(PageIoError::InvalidRange);
        }
        page.checked_mul(BLOCKS_PER_PAGE)
            .ok_or(PageIoError::InvalidRange)
    }

    fn page_range_first_sector(
        &self,
        first_page: u64,
        page_count: usize,
    ) -> Result<u64, PageIoError> {
        let page_count = u64::try_from(page_count).map_err(|_| PageIoError::InvalidRange)?;
        let end = first_page
            .checked_add(page_count)
            .ok_or(PageIoError::InvalidRange)?;
        if page_count == 0 || end > self.info.lock().page_count {
            return Err(PageIoError::InvalidRange);
        }
        first_page
            .checked_mul(BLOCKS_PER_PAGE)
            .ok_or(PageIoError::InvalidRange)
    }

    fn expose_preprovisioned_range(&self) {
        self.expose_block_count(self.provisioned_block_count);
    }

    fn expose_block_count(&self, block_count: u64) {
        let mut info = self.info.lock();
        info.logical_block_count = block_count;
        info.page_count = block_count / BLOCKS_PER_PAGE;
    }

    fn restrict_to_initial_range(&self) {
        let mut info = self.info.lock();
        info.logical_block_count = self.initial_block_count;
        info.page_count = self.initial_block_count / BLOCKS_PER_PAGE;
    }

    fn growth_capability_bounded(
        &self,
        durable_block_count: u64,
        maximum_additional_blocks: u64,
    ) -> Result<Option<BlockRangeCapability>, PageIoError> {
        if durable_block_count > self.provisioned_block_count {
            return Err(PageIoError::InvalidRange);
        }
        let additional =
            (self.provisioned_block_count - durable_block_count).min(maximum_additional_blocks);
        if additional == 0 {
            return Ok(None);
        }
        let lease = self.lease(Rights::READ)?;
        let session = block_device::range_info_with(&lease)
            .map_err(PageIoError::Block)?
            .session();
        let range = lease.with(BlockDevice::range);
        // SAFETY: the trusted storage service owns the sole CSpace grant for
        // this preprovisioned range and derives only its exact adjacent suffix.
        let provisioner = unsafe {
            BlockRangeProvisioner::new(session, range.first_block(), range.block_count())
        }
        .map_err(|_| PageIoError::InvalidRange)?;
        provisioner
            .derive(durable_block_count, additional)
            .map(Some)
            .map_err(|_| PageIoError::InvalidRange)
    }
}

static NEXT_PAGE_OPERATION: AtomicU64 = AtomicU64::new(1);
static INSTALLED_CONTROL_DEVICE: SpinLock<Option<CapabilityPageDevice>> = SpinLock::new(None);

pub(crate) use vibeos_segment_store::{
    MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK as MIGRATION_CONTROL_FIRST_BLOCK,
    MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT as MIGRATION_CONTROL_BLOCK_COUNT,
    V2_DEFAULT_FIRST_LOGICAL_BLOCK as STORAGE_V2_FIRST_BLOCK,
    V2_DEFAULT_LOGICAL_BLOCK_COUNT as STORAGE_V2_BLOCK_COUNT,
};

/// The two non-overlapping page devices owned by the trusted migration
/// coordinator. Neither handle is installed into init or a client CSpace.
pub(crate) struct StorageV2Devices {
    backend: Arc<Space>,
    legacy_writer: Cap,
    legacy_reader: Cap,
    legacy_write_frozen: Arc<AtomicBool>,
    legacy_store: SpinLock<Option<Weak<vibeos_object_store::StoreService>>>,
    migration_operations: MigrationOperationGate,
    pub(crate) migration_control: CapabilityPageDevice,
    pub(crate) runtime: Arc<StorageV2Runtime>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MigrationOperationKind {
    Migrate,
    MigrateUntilStaged,
    Rollback,
    CloseRollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveMigrationOperation {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    kind: MigrationOperationKind,
}

/// One recoverable claim spanning source scan, cold scrub, and selector
/// publication. The page-device epoch serializes individual controller I/O;
/// this wider gate prevents two valid high-level transitions from racing in
/// the validation gap between their initial selector read and final write.
#[derive(Clone)]
struct MigrationOperationGate {
    active: Arc<SpinLock<Option<ActiveMigrationOperation>>>,
}

struct MigrationOperation {
    gate: MigrationOperationGate,
    claim: ActiveMigrationOperation,
    armed: bool,
}

impl MigrationOperationGate {
    fn new() -> Self {
        Self {
            active: system_arc(SpinLock::new_recoverable(None)),
        }
    }

    fn begin_current(
        &self,
        kind: MigrationOperationKind,
    ) -> Result<MigrationOperation, MigrationRunError> {
        let task =
            exec::current_task_id().ok_or(MigrationRunError::V2(V2RuntimeError::OutsideTask))?;
        self.begin(task, heap::current_domain(), kind)
    }

    fn begin(
        &self,
        task: exec::TaskId,
        domain: heap::AllocationDomain,
        kind: MigrationOperationKind,
    ) -> Result<MigrationOperation, MigrationRunError> {
        let token = NEXT_MIGRATION_OPERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("Storage V2 migration operation token space exhausted");
        let claim = ActiveMigrationOperation {
            task,
            domain,
            token,
            kind,
        };
        let mut active = self.active.lock();
        if active.is_some() {
            return Err(MigrationRunError::Busy);
        }
        *active = Some(claim);
        Ok(MigrationOperation {
            gate: self.clone(),
            claim,
            armed: true,
        })
    }

    fn clear(&self, expected: ActiveMigrationOperation) -> bool {
        let mut active = self.active.lock();
        if *active == Some(expected) {
            *active = None;
            true
        } else {
            false
        }
    }

    /// Release only the exact claim owned by a synchronously stopped task.
    ///
    /// # Safety
    ///
    /// The caller must prove `task` is terminal and cannot resume or drop its
    /// abandoned guard, including cross-hart Release/Acquire quiescence.
    unsafe fn recover_faulted(&self, task: exec::TaskId, domain: heap::AllocationDomain) {
        let task_key =
            crate::sync::TaskRecoveryKey::new(task.0).expect("executor TaskId zero is reserved");
        // Safety: inherited from this method's terminal-task contract.
        let _ = unsafe { self.active.recover_after_task_fault(domain, task_key) };
        let mut active = self.active.lock();
        if active.is_some_and(|claim| claim.task == task && claim.domain == domain) {
            *active = None;
        }
    }
}

impl Drop for MigrationOperation {
    fn drop(&mut self) {
        if self.armed {
            assert!(self.gate.clear(self.claim));
            self.armed = false;
        }
    }
}

static NEXT_MIGRATION_OPERATION: AtomicU64 = AtomicU64::new(1);
static INSTALLED_MIGRATION_OPERATIONS: SpinLock<Option<MigrationOperationGate>> =
    SpinLock::new(None);

/// The only capability which authorizes an explicit M4-to-V2 cutover. The
/// embedded weak reference cannot keep a retired coordinator alive or mint a
/// `StoreMaintenance` token; it only selects the exact sealed runtime whose
/// private provisioner performs the operation.
pub(crate) struct StorageMigrationAuthority {
    devices: Weak<StorageV2Devices>,
}

impl StorageMigrationAuthority {
    pub(crate) fn new(devices: &Arc<StorageV2Devices>) -> Arc<Self> {
        system_arc(Self {
            devices: Arc::downgrade(devices),
        })
    }

    fn authorizes(&self, expected: &Arc<StorageV2Devices>) -> bool {
        self.devices
            .upgrade()
            .is_some_and(|devices| Arc::ptr_eq(&devices, expected))
    }
}

impl Resource for StorageMigrationAuthority {
    fn kind(&self) -> &'static str {
        "storage-v2-migration"
    }

    fn describe(&self) -> String {
        String::from("explicit Storage V2 migration authority")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootStoreSelection {
    Blank,
    LegacyM4,
    StorageV2,
    FailClosed,
}

impl BootStoreSelection {
    const fn encode(self) -> u8 {
        match self {
            Self::Blank => 1,
            Self::LegacyM4 => 2,
            Self::StorageV2 => 3,
            Self::FailClosed => 4,
        }
    }

    fn decode(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Blank),
            2 => Some(Self::LegacyM4),
            3 => Some(Self::StorageV2),
            4 => Some(Self::FailClosed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootProbeError {
    Device(PageIoError),
    MigrationControl,
    LegacyCorrupt,
    StorageV2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum V2RuntimeError {
    Busy,
    OutsideTask,
    Unformatted,
    AuthorityMissing,
    JournalChanged,
    ObjectUnavailable,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationRunError {
    Busy,
    Unauthorized,
    SourceAbsent,
    SourceCorrupt,
    SourceChanged,
    V2(V2RuntimeError),
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MigrationReport {
    pub state: MigrationState,
    pub generation: u64,
    pub checkpoint_generation: u64,
    pub object_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageTransitionRecovery {
    Published(MigrationControl),
    NotCommitted,
    FailClosed,
}

pub(crate) type StorageV2MigrationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MigrationReport, MigrationRunError>> + Send + 'a>>;

enum LegacySnapshot {
    Absent,
    Valid(Vec<[u8; LOGICAL_BLOCK_SIZE]>),
}

const STORAGE_V2_UUID: [u8; 16] = *b"VIBEOS-STOR-V2!!";

/// Runtime store limits for the Storage V2 device. The recovery budget must
/// match the format-time policy: large objects ride the M4 record stream
/// inside the authority snapshot, and mount/growth transition accounting
/// holds predecessor and successor state simultaneously.
fn storage_v2_store_limits() -> StoreLimits {
    StoreLimits {
        // Recovery and collection account two mounted states side by side;
        // each carries the full logical record stream, so the budget bounds
        // the cumulative object bytes a store instance can carry (~a quarter
        // of this value) rather than a single object's size.
        recovery_memory_bytes: 64 * 1024 * 1024,
        ..StoreLimits::default()
    }
}

fn storage_v2_format_options() -> FormatOptions {
    FormatOptions {
        store_uuid: StoreUuid::new(STORAGE_V2_UUID).expect("fixed Storage V2 UUID is non-zero"),
        cleaner_reserve_segments: 2,
        // Large objects ride the M4 record stream inside the authority
        // snapshot; the default 2 MiB recovery ceiling cannot remount a store
        // holding a ~1 MiB object. Raise the bounded accounting budget without
        // changing any on-media geometry.
        limits: storage_v2_store_limits(),
    }
}

fn prepare_native_empty_authority() -> Result<(PersistentAuthorityImport, Vec<u8>), V2RuntimeError>
{
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let prepared = crate::durable_cspace::storage_v2_empty_import()
        .map(|import| {
            let expected = import.record_stream().to_vec();
            (import, expected)
        })
        .map_err(|_| V2RuntimeError::Corrupt);
    system.restore();
    prepared
}

#[derive(Clone, Copy)]
struct ActiveV2Operation {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
}

struct StableSegmentStore(UnsafeCell<SegmentStore<CapabilityPageDevice>>);

#[cfg(feature = "file-tree")]
struct KernelFileTreeBackend {
    runtime: Arc<StorageV2Runtime>,
}

#[cfg(feature = "file-tree")]
fn map_file_runtime_error(error: V2RuntimeError) -> FileError {
    match error {
        V2RuntimeError::Busy | V2RuntimeError::JournalChanged => FileError::Busy,
        V2RuntimeError::OutsideTask
        | V2RuntimeError::Unformatted
        | V2RuntimeError::AuthorityMissing
        | V2RuntimeError::ObjectUnavailable
        | V2RuntimeError::Corrupt => FileError::ServiceUnavailable,
    }
}

#[cfg(feature = "file-tree")]
impl FileTreeBackend for KernelFileTreeBackend {
    fn stage_chunk<'a>(
        &'a self,
        previous: Option<vibeos_segment_store::FsPersistentData>,
        bytes: Vec<u8>,
    ) -> FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
        Box::pin(async move {
            self.runtime.ensure_boot_proof().await?;
            let maintenance = self
                .runtime
                .maintenance
                .lock()
                .clone()
                .ok_or(FileError::ServiceUnavailable)?;
            let mut operation = self.runtime.begin().map_err(map_file_runtime_error)?;
            let result = poll_as_system(operation.store().commit_fs_data_chunk_for_maintenance(
                &maintenance,
                previous.as_ref(),
                &bytes,
            ))
            .await
            .map_err(|_| FileError::ServiceUnavailable);
            operation.finish();
            result
        })
    }

    fn stage_chunks<'a>(
        &'a self,
        previous: Option<vibeos_segment_store::FsPersistentData>,
        chunks: Vec<Vec<u8>>,
    ) -> FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
        Box::pin(async move {
            if chunks.is_empty() || chunks.iter().any(|bytes| bytes.is_empty()) {
                // The batched path admits only whole non-empty chunks; the
                // zero-length stream head keeps its dedicated commit.
                let mut tail = previous;
                for bytes in chunks {
                    tail = Some(self.stage_chunk(tail, bytes).await?);
                }
                return tail.ok_or(FileError::ServiceUnavailable);
            }
            let maintenance = self
                .runtime
                .maintenance
                .lock()
                .clone()
                .ok_or(FileError::ServiceUnavailable)?;
            // One batch consumes a segment per chunk plus its metadata
            // segment inside a single transaction, and the following
            // tree/root commit burns several more; replenish to that
            // appetite, not to the per-append floor.
            let needed = (chunks.len() as u64).saturating_add(12);
            let mut attempt = 0;
            loop {
                self.runtime
                    .ensure_foreground_capacity_for(needed)
                    .await
                    .map_err(map_file_runtime_error)?;
                let mut operation = self.runtime.begin().map_err(map_file_runtime_error)?;
                let result =
                    poll_as_system(operation.store().stage_fs_data_chunks_for_maintenance(
                        &maintenance,
                        previous.as_ref(),
                        &chunks,
                    ))
                    .await;
                let declined_clean = result.is_err() && !operation.store().needs_remount();
                if result.is_err() && !declined_clean {
                    // A failed staged batch leaves the store poisoned; only a
                    // new cold proof may re-establish the durable checkpoint.
                    self.runtime.invalidate_recovery_cache();
                }
                operation.finish();
                match result {
                    Ok(tail) => return Ok(tail),
                    Err(error) => {
                        #[cfg(feature = "storage-bench")]
                        crate::println!(
                            "  bench-detail fs-stage error (clean={declined_clean}): {error:?}"
                        );
                        let _ = &error;
                        if declined_clean && attempt == 0 {
                            // The batch was declined before staging anything;
                            // reclaim dead segments and retry once.
                            if let Ok(mut operation) = self.runtime.begin() {
                                let _ = poll_as_system(operation.store().collect_garbage()).await;
                                if let Ok(view) = poll_as_system(
                                    recover_recognized_persistent_authority(
                                        operation.store(),
                                        crate::durable_cspace::storage_v2_external_policy_sha256(),
                                    ),
                                )
                                .await
                                {
                                    self.runtime.publish_authority(view);
                                }
                                operation.finish();
                            }
                            attempt += 1;
                            continue;
                        }
                        return Err(FileError::ServiceUnavailable);
                    }
                }
            }
        })
    }

    fn read_chunk<'a>(
        &'a self,
        data: vibeos_segment_store::FsPersistentData,
        index: u64,
    ) -> FileTreeFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move {
            let mut operation = self.runtime.begin().map_err(map_file_runtime_error)?;
            let result = poll_as_system(operation.store().read_fs_data_chunk(&data, index))
                .await
                .map_err(|_| FileError::ServiceUnavailable);
            operation.finish();
            result
        })
    }

    fn commit<'a>(&'a self, transaction: FsTransaction) -> FileTreeFuture<'a, u64> {
        Box::pin(async move {
            self.runtime.ensure_boot_proof().await?;
            let maintenance = self
                .runtime
                .maintenance
                .lock()
                .clone()
                .ok_or(FileError::ServiceUnavailable)?;
            // The fused transaction stages every new node in one batch;
            // prefer growth to a foreground collection for its appetite. The
            // appetite is capped by the device-scaled policy: on a small
            // store a fixed 12-segment demand is structurally unreachable
            // and turns every commit into a full foreground collection.
            self.runtime
                .ensure_foreground_capacity_for_scaled(12)
                .await
                .map_err(map_file_runtime_error)?;
            let mut operation = self.runtime.begin().map_err(map_file_runtime_error)?;
            let result = poll_as_system(
                transaction.commit_persistent_for_maintenance(operation.store(), &maintenance),
            )
            .await;
            if result.is_err() && operation.store().needs_remount() {
                // A failed staged batch leaves the store poisoned; only a
                // new cold proof may re-establish the durable checkpoint.
                self.runtime.invalidate_recovery_cache();
            }
            let result = result.map_err(|error| match error {
                ref detail
                    if {
                        crate::uart::_print(format_args!("  fs-commit error: {detail:?}\n"));
                        false
                    } =>
                {
                    unreachable!()
                }
                vibeos_file_store::PersistentCommitError::File(error) => error,
                vibeos_file_store::PersistentCommitError::Publish(
                    vibeos_segment_store::FsRootPublishError::Conflict,
                ) => FileError::Conflict,
                _ => FileError::ServiceUnavailable,
            });
            operation.finish();
            result
        })
    }
}

// Safety: access is serialized by `StorageV2Runtime::active`. Fault cleanup
// releases only the exact detached task's claim before another task may enter.
unsafe impl Sync for StableSegmentStore {}

pub(crate) struct StorageV2Runtime {
    store: StableSegmentStore,
    device: CapabilityPageDevice,
    context: StoreRuntimeContext,
    active: SpinLock<Option<ActiveV2Operation>>,
    maintenance: SpinLock<Option<StoreMaintenance>>,
    authority: SpinLock<Option<Arc<PersistentAuthorityView>>>,
    hot_reads: HotReadCache,
    authority_boot_proved: AtomicBool,
    last_info: SpinLock<Option<vibeos_segment_store::StoreInfo>>,
    boot_selection: AtomicU8,
    needs_rebuild: AtomicBool,
    /// Logical-record count at the last steady-state compaction attempt, so
    /// the append path re-evaluates compaction only after meaningful growth.
    compact_watermark: AtomicU64,
    /// Validated replay of the published logical stream (fix: appends
    /// re-decoded the whole journal per put). Keyed by chain checkpoint and
    /// record count; any mismatch falls back to a full replay.
    preflight_cache: SpinLock<Option<crate::durable_cspace::StorageV2PreflightCache>>,
    maintenance_provisioner: StoreMaintenanceProvisioner,
    _quota_provisioner: StorageQuotaProvisioner,
}

/// Below this many logical records the authority stream is not worth
/// rewriting: migration fixtures and small stores never trigger compaction.
const STORAGE_V2_COMPACT_MIN_RECORDS: usize = 2048;

const STORAGE_V2_HOT_READ_CACHE_BYTES: usize = 256 * 1024;
// Object-store tokens retain the encoded Merkle envelope, so a 64 KiB user
// blob is slightly larger than 64 KiB at this layer.
const STORAGE_V2_HOT_READ_MAX_OBJECT_BYTES: usize = 72 * 1024;
const STORAGE_V2_HOT_READ_CACHE_ENTRIES: usize = 64;

struct HotReadCacheState {
    bytes: usize,
    entries: Vec<Arc<[u8]>>,
}

struct HotReadCache {
    state: SpinLock<HotReadCacheState>,
}

impl HotReadCache {
    fn new() -> Self {
        Self {
            state: SpinLock::new_recoverable(HotReadCacheState {
                bytes: 0,
                entries: Vec::new(),
            }),
        }
    }

    fn insert(&self, bytes: &[u8]) -> Option<Weak<[u8]>> {
        if bytes.len() > STORAGE_V2_HOT_READ_MAX_OBJECT_BYTES {
            return None;
        }
        let value: Arc<[u8]> = Arc::from(bytes);
        let mut state = self.state.lock();
        while state.entries.len() >= STORAGE_V2_HOT_READ_CACHE_ENTRIES
            || state.bytes.saturating_add(value.len()) > STORAGE_V2_HOT_READ_CACHE_BYTES
        {
            if state.entries.is_empty() {
                return None;
            }
            let evicted = state.entries.remove(0);
            state.bytes = state.bytes.saturating_sub(evicted.len());
        }
        state.bytes += value.len();
        let weak = Arc::downgrade(&value);
        state.entries.push(value);
        Some(weak)
    }

    fn clear(&self) {
        let mut state = self.state.lock();
        state.entries.clear();
        state.bytes = 0;
    }
}

static NEXT_V2_OPERATION: AtomicU64 = AtomicU64::new(1);
static INSTALLED_V2_RUNTIME: SpinLock<Option<Arc<StorageV2Runtime>>> = SpinLock::new(None);

struct V2Operation {
    runtime: Arc<StorageV2Runtime>,
    claim: ActiveV2Operation,
    page_operation: Option<PageDeviceOperation>,
    armed: bool,
}

impl V2Operation {
    fn store(&mut self) -> &mut SegmentStore<CapabilityPageDevice> {
        // Safety: this exact operation owns the sole active claim, and the
        // returned borrow cannot escape the operation future.
        unsafe { &mut *self.runtime.store.0.get() }
    }

    fn finish(mut self) {
        self.page_operation
            .take()
            .expect("active V2 operation owns a page-device epoch")
            .finish();
        assert!(self.runtime.clear(self.claim));
        self.armed = false;
    }
}

impl Drop for V2Operation {
    fn drop(&mut self) {
        if self.armed {
            self.page_operation
                .take()
                .expect("active V2 operation owns a page-device epoch")
                .finish();
            // A cancelled/short-circuited operation may have crossed an
            // on-media mutation boundary.  Never retain boot proof or object
            // handles across that ambiguity; the next explicit probe must
            // rebuild the store and prove media again.
            self.runtime.invalidate_recovery_cache();
            assert!(self.runtime.clear(self.claim));
        }
    }
}

impl StorageV2Runtime {
    fn new(device: CapabilityPageDevice) -> Arc<Self> {
        let typed_kinds: &[u32] = if cfg!(feature = "file-tree") {
            &vibeos_segment_store::fs_typed_reference_kinds()
        } else {
            &[]
        };
        let (context, quota, maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                typed_kinds,
            )
            .expect("fixed Storage V2 governed runtime policy is valid");
        let mut store = SegmentStore::new_with_runtime_context(
            device.clone(),
            storage_v2_store_limits(),
            context.clone(),
        );
        // Deferred commit read-back: every read path Merkle-verifies content
        // and boot performs a full cold scrub, so a damaged device write is
        // detected at first use instead of at the commit that produced it.
        // This trades that detection window for not re-reading and re-hashing
        // every just-written page on the foreground commit path.
        store.set_deferred_commit_readback(true);
        let runtime = Arc::new(Self {
            store: StableSegmentStore(UnsafeCell::new(store)),
            device,
            context,
            active: SpinLock::new_recoverable(None),
            maintenance: SpinLock::new_recoverable(None),
            authority: SpinLock::new_recoverable(None),
            hot_reads: HotReadCache::new(),
            authority_boot_proved: AtomicBool::new(false),
            last_info: SpinLock::new_recoverable(None),
            boot_selection: AtomicU8::new(0),
            needs_rebuild: AtomicBool::new(false),
            compact_watermark: AtomicU64::new(0),
            preflight_cache: SpinLock::new_recoverable(None),
            maintenance_provisioner: maintenance,
            _quota_provisioner: quota,
        });
        let mut installed = INSTALLED_V2_RUNTIME.lock();
        assert!(
            installed.is_none(),
            "only one Storage V2 runtime may be installed"
        );
        *installed = Some(runtime.clone());
        runtime
    }

    fn begin(self: &Arc<Self>) -> Result<V2Operation, V2RuntimeError> {
        let task = exec::current_task_id().ok_or(V2RuntimeError::OutsideTask)?;
        let domain = heap::current_domain();
        let token = NEXT_V2_OPERATION
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("Storage V2 operation token space exhausted");
        let claim = ActiveV2Operation {
            task,
            domain,
            token,
        };
        let mut active = self.active.lock();
        if active.is_some() {
            return Err(V2RuntimeError::Busy);
        }
        *active = Some(claim);
        drop(active);
        let page_operation = match self.device.begin_operation(task, domain, token) {
            Ok(operation) => operation,
            Err(error) => {
                assert!(self.clear(claim));
                return Err(match error {
                    PageIoError::OperationBusy => V2RuntimeError::Busy,
                    _ => V2RuntimeError::Corrupt,
                });
            }
        };
        if self.needs_rebuild.swap(false, Ordering::AcqRel) {
            let mut system = heap::enter_owner(OwnerId::SYSTEM);
            // Safety: this exact claim excludes every other access and fault
            // cleanup marked the previous task permanently detached.
            unsafe {
                *self.store.0.get() = SegmentStore::new_with_runtime_context(
                    self.device.clone(),
                    storage_v2_store_limits(),
                    self.context.clone(),
                );
            }
            system.restore();
            *self.authority.lock() = None;
            *self.last_info.lock() = None;
        }
        Ok(V2Operation {
            runtime: self.clone(),
            claim,
            page_operation: Some(page_operation),
            armed: true,
        })
    }

    fn clear(&self, expected: ActiveV2Operation) -> bool {
        let mut active = self.active.lock();
        if active.is_some_and(|claim| {
            claim.task == expected.task
                && claim.domain == expected.domain
                && claim.token == expected.token
        }) {
            *active = None;
            true
        } else {
            false
        }
    }

    /// Return a previously verified object only while no media operation can
    /// advance or invalidate the authority generation. Holding `active` for
    /// the check and copy gives the cache path the same publication ordering
    /// as a normal store operation without opening a page-device epoch.
    fn read_hot_bytes(
        &self,
        cached: &Weak<[u8]>,
        expected_generation: u64,
    ) -> Result<Option<Vec<u8>>, vibeos_object_store::StoreError> {
        let Some(bytes) = cached.upgrade() else {
            return Ok(None);
        };
        let active = self.active.lock();
        if active.is_some() {
            return Err(vibeos_object_store::StoreError::Busy);
        }
        let selection = BootStoreSelection::decode(self.boot_selection.load(Ordering::Acquire));
        let proved = self.authority_boot_proved.load(Ordering::Acquire);
        let authority = self.authority.lock();
        let current = authority.as_ref().is_some_and(|view| {
            view.checkpoint_generation() == expected_generation
                && cache_metadata_matches_boot_proof(
                    selection,
                    proved,
                    view.root_policy_sha256(),
                    view.store_uuid(),
                )
        });
        if !current {
            // A stale cache entry proves nothing about the object itself: a
            // later append or collection advanced the published generation
            // without touching this content. Decline the cache and let the
            // caller resolve through the durable path, which re-validates
            // the object's stable identity against the current view and
            // fails closed only if the object is genuinely unresolvable.
            return Ok(None);
        }
        let output = bytes.as_ref().to_vec();
        drop(authority);
        drop(active);
        Ok(Some(output))
    }

    fn install_maintenance_if_missing(
        &self,
        operation: &mut V2Operation,
    ) -> Result<(), V2RuntimeError> {
        if self.maintenance.lock().is_none() {
            let root = operation
                .store()
                .provision_maintenance_root(&self.maintenance_provisioner)
                .map_err(|_| V2RuntimeError::Corrupt)?;
            *self.maintenance.lock() = Some(root);
        }
        Ok(())
    }

    fn publish_authority(&self, view: PersistentAuthorityView) -> Arc<PersistentAuthorityView> {
        let view = system_arc(view);
        *self.authority.lock() = Some(view.clone());
        view
    }

    /// Revoke facade provenance when an exclusive operation cannot be
    /// acquired. This path may race the operation which made `begin` return
    /// `Busy`, so it deliberately performs no page-cache, authority-view, or
    /// rebuild mutation. Ordinary operations never set the proof bit back to
    /// true; only a complete physical recovery can mint fresh provenance.
    fn revoke_boot_proof_without_epoch(&self) {
        self.authority_boot_proved.store(false, Ordering::Release);
    }

    fn clear_recovery_cache(&self) {
        // Callers which start a cold proof hold the exclusive V2/page-device
        // operation before entering here and invoke this before `mount`.
        // Ambiguous append failures also clear while retaining that same
        // operation claim. This guarantees the next proof reads device media,
        // not a write-through page which may never have become durable.
        self.device.page_cache.clear();
        self.authority_boot_proved.store(false, Ordering::Release);
        *self.authority.lock() = None;
        *self.last_info.lock() = None;
        self.hot_reads.clear();
    }

    /// Invalidate every proof derived from the current in-memory store after
    /// a cold recovery attempt has observed an incomplete or corrupt state.
    /// A later operation must rebuild the store object and prove media again;
    /// it must never append through a capability cached by an earlier boot
    /// proof after that proof has failed.
    fn invalidate_recovery_cache(&self) {
        self.clear_recovery_cache();
        *self.preflight_cache.lock() = None;
        self.needs_rebuild.store(true, Ordering::Release);
    }

    pub(crate) fn authority_view(&self) -> Option<Arc<PersistentAuthorityView>> {
        self.authority.lock().clone()
    }

    fn boot_proved_authority(&self) -> Option<Arc<PersistentAuthorityView>> {
        let view = self.authority_view()?;
        cache_metadata_matches_boot_proof(
            BootStoreSelection::decode(self.boot_selection.load(Ordering::Acquire)),
            self.authority_boot_proved.load(Ordering::Acquire),
            view.root_policy_sha256(),
            view.store_uuid(),
        )
        .then_some(view)
    }

    /// Format only the explicitly provisioned V2 slice. M4 and control are
    /// disjoint capabilities and cannot be addressed by this store object.
    /// A prior crash is resumable only when every observed anchor byte is an
    /// exact prefix of the deterministic formatter write sequence.
    pub(crate) async fn ensure_formatted_for_migration(
        self: &Arc<Self>,
    ) -> Result<vibeos_segment_store::StoreInfo, V2RuntimeError> {
        self.device.restrict_to_initial_range();
        let mut operation = self.begin()?;
        let mounted = poll_as_system(operation.store().mount()).await;
        let result = match mounted {
            Ok(info) => Ok(info),
            Err(vibeos_segment_store::StoreError::Unformatted) => poll_as_system(
                operation
                    .store()
                    .format_or_resume_canonical(storage_v2_format_options()),
            )
            .await
            .map_err(|_| V2RuntimeError::Corrupt),
            Err(_) => Err(V2RuntimeError::Corrupt),
        };
        if result.is_ok() {
            self.install_maintenance_if_missing(&mut operation)?;
        }
        if let Ok(info) = result.as_ref() {
            *self.last_info.lock() = Some(*info);
        }
        operation.finish();
        result
    }

    /// Admit only a fresh canonical format (or an exact formatter crash
    /// prefix) before native empty-authority installation. A mountable foreign
    /// UUID or previously used authority-less V2 store is not recoverable.
    pub(crate) async fn ensure_native_initial_format(
        self: &Arc<Self>,
    ) -> Result<vibeos_segment_store::StoreInfo, V2RuntimeError> {
        self.device.restrict_to_initial_range();
        let mut operation = self.begin()?;
        let options = storage_v2_format_options();
        let mounted = poll_as_system(operation.store().mount()).await;
        let result = match mounted {
            Ok(info)
                if operation
                    .store()
                    .is_canonical_initial_format(options)
                    .map_err(|_| V2RuntimeError::Corrupt)? =>
            {
                Ok(info)
            }
            Ok(_) => Err(V2RuntimeError::Corrupt),
            Err(vibeos_segment_store::StoreError::Unformatted) => {
                poll_as_system(operation.store().format_or_resume_canonical(options))
                    .await
                    .map_err(|_| V2RuntimeError::Corrupt)
            }
            Err(_) => Err(V2RuntimeError::Corrupt),
        };
        if result.is_ok() {
            self.install_maintenance_if_missing(&mut operation)?;
        }
        if let Ok(info) = result.as_ref() {
            *self.last_info.lock() = Some(*info);
        }
        operation.finish();
        result
    }

    /// Install the canonical no-root authority for a native blank V2 store.
    /// Construction and its exact readback witness are allocated to SYSTEM,
    /// then the existing persistent-authority transaction supplies all media
    /// ordering and crash semantics.
    pub(crate) async fn install_native_empty_authority(
        self: &Arc<Self>,
    ) -> Result<Arc<PersistentAuthorityView>, V2RuntimeError> {
        let (import, expected) = prepare_native_empty_authority()?;
        self.install_persistent_authority(import, &expected).await
    }

    /// Import the exact externally admitted M4 closure. Replaying after a
    /// crash is idempotent when the canonical record stream already matches;
    /// a still-M4-authoritative newer stream replaces the old V2 snapshot in
    /// one new checkpoint.
    pub(crate) async fn install_persistent_authority(
        self: &Arc<Self>,
        import: PersistentAuthorityImport,
        expected_record_stream: &[u8],
    ) -> Result<Arc<PersistentAuthorityView>, V2RuntimeError> {
        let expected_policy = import.root_policy_sha256();
        let mut operation = self.begin()?;
        let result = poll_as_system(async {
            let store = operation.store();
            match store.recover_persistent_authority(expected_policy).await {
                Ok(view) if view.record_stream() == expected_record_stream => Ok(view),
                Ok(view) => {
                    let writer = store.derive_persistent_authority_writer(
                        self.maintenance
                            .lock()
                            .as_ref()
                            .ok_or(PersistentAuthorityError::Unauthorized)?,
                    )?;
                    store
                        .replace_persistent_authority(&writer, view.checkpoint_generation(), import)
                        .await
                }
                Err(PersistentAuthorityError::NotInitialized) => {
                    let maintenance = self
                        .maintenance
                        .lock()
                        .clone()
                        .ok_or(PersistentAuthorityError::Unauthorized)?;
                    store
                        .import_persistent_authority(&maintenance, import)
                        .await
                }
                Err(error) => Err(error),
            }
        })
        .await
        .map_err(|_| V2RuntimeError::Corrupt)?;
        operation.finish();
        if result.record_stream() != expected_record_stream {
            return Err(V2RuntimeError::Corrupt);
        }
        Ok(self.publish_authority(result))
    }

    /// Append a strict logical-journal successor while preserving transient
    /// object handles from this exact append. Those handles deliberately do
    /// not enter the durable authority view until a later grant names them.
    async fn append_persistent_authority(
        self: &Arc<Self>,
        expected_generation: u64,
        import: PersistentAuthorityImport,
        principal: StoragePrincipal,
    ) -> Result<PersistentAuthorityAppendResult, V2RuntimeError> {
        let mut operation = self.begin()?;
        let result = self
            .append_persistent_authority_in_operation(
                &mut operation,
                expected_generation,
                import,
                principal,
            )
            .await;
        operation.finish();
        result
    }

    /// Append while the caller retains the exact V2/page-device epoch. The
    /// policy-bound C7.4 facade uses this together with capacity preparation so
    /// no intervening operation can replace the checked authority policy before
    /// the durable snapshot write.
    async fn append_persistent_authority_in_operation(
        self: &Arc<Self>,
        operation: &mut V2Operation,
        expected_generation: u64,
        import: PersistentAuthorityImport,
        principal: StoragePrincipal,
    ) -> Result<PersistentAuthorityAppendResult, V2RuntimeError> {
        let maintenance = self
            .maintenance
            .lock()
            .clone()
            .ok_or(V2RuntimeError::Corrupt)?;
        let result = poll_as_system(async {
            let store = operation.store();
            let writer = store
                .derive_persistent_authority_writer(&maintenance)
                .map_err(|_| V2RuntimeError::Corrupt)?;
            store
                .append_persistent_authority(&writer, expected_generation, import, &principal)
                .await
                .map_err(|error| match error {
                    PersistentAuthorityError::GenerationMismatch => V2RuntimeError::JournalChanged,
                    _error => {
                        #[cfg(feature = "storage-bench")]
                        crate::println!("  bench-detail authority append error: {_error:?}");
                        V2RuntimeError::Corrupt
                    }
                })
        })
        .await;
        if result
            .as_ref()
            .is_err_and(|error| append_error_requires_cold_recovery(*error))
        {
            // Every non-stale-check append failure may have crossed an
            // on-media mutation boundary. Revoke the predecessor proof while
            // this operation still owns the runtime claim; only a new boot
            // probe may establish which atomic checkpoint became durable.
            self.invalidate_recovery_cache();
        }
        result
    }

    /// Cold-mount, reconstruct opaque authority handles under the frozen
    /// external policy, and run the complete anonymous scrub before producing
    /// selector evidence.
    pub(crate) async fn cold_recover_and_scrub(
        self: &Arc<Self>,
        expected_policy_sha256: [u8; 32],
    ) -> Result<(Arc<PersistentAuthorityView>, ColdScrubEvidence), V2RuntimeError> {
        // The preprovisioned parent range is not allocatable merely because it
        // is addressable. Mount still enforces the checkpoint's admitted
        // segment count; exposing the parent here lets a previously grown
        // checkpoint be read after reboot without widening durable policy.
        self.device.expose_preprovisioned_range();
        let mut operation = self.begin()?;
        // Once a new cold proof starts, no caller may consume the preceding
        // boot's cached view. Success publishes a replacement before releasing
        // this exact operation claim; failure forces a full runtime rebuild.
        self.clear_recovery_cache();
        // Keep every fallible proof step inside a local result so that all
        // early failures first release the exact operation epoch and then
        // atomically invalidate the previously published runtime cache.
        let recovered = async {
            let info =
                poll_as_system(operation.store().mount())
                    .await
                    .map_err(|error| match error {
                        vibeos_segment_store::StoreError::Unformatted => {
                            V2RuntimeError::Unformatted
                        }
                        other => {
                            crate::uart::_print(format_args!("  cold mount failed: {other:?}\n"));
                            V2RuntimeError::Corrupt
                        }
                    })?;
            self.install_maintenance_if_missing(&mut operation)?;
            let maintenance = self
                .maintenance
                .lock()
                .clone()
                .ok_or(V2RuntimeError::Corrupt)?;
            let durable_blocks = vibeos_segment_format::admitted_pages(info.admitted_segments)
                .ok()
                .and_then(|pages| pages.checked_mul(BLOCKS_PER_PAGE))
                .ok_or(V2RuntimeError::Corrupt)?;
            // Full preprovisioned addressability is needed only to discover a
            // previously grown checkpoint. Once mount has fixed the durable
            // boundary, narrow the live device view before deriving the exact
            // adjacent suffix admitted by this growth transaction.
            self.device.expose_block_count(durable_blocks);
            // No growth here: a cold proof must leave the checkpoint exactly
            // where recovery found it. The migration contract binds a staged
            // or native activation to the precise current checkpoint, and a
            // boot-time growth transaction silently advanced past it,
            // failing every powered-off selector verification. Foreground
            // writers replenish capacity themselves (with hysteresis) on
            // their first commit instead.
            *self.last_info.lock() = Some(info);
            let view = poll_as_system(recover_recognized_persistent_authority(
                operation.store(),
                expected_policy_sha256,
            ))
            .await
            .map_err(|error| match error {
                PersistentAuthorityError::NotInitialized => V2RuntimeError::AuthorityMissing,
                other => {
                    crate::uart::_print(format_args!(
                        "  cold authority recovery failed: {other:?}\n"
                    ));
                    V2RuntimeError::Corrupt
                }
            })?;
            // The stored digest commits to policy bytes but does not prove
            // either that this stream satisfies the policy or that its private
            // bindings name those exact logical bytes. Rebuild the import
            // under the same fixed-CSpace and saved-program policy used by
            // live M4 recovery, then prove every complete object identity.
            let import = crate::durable_cspace::storage_v2_recovery_import_for_policy(
                view.record_stream(),
                view.root_policy_sha256(),
            )
            .map_err(|_| V2RuntimeError::Corrupt)?;
            poll_as_system(
                operation
                    .store()
                    .verify_persistent_authority_import(&view, &import),
            )
            .await
            .map_err(|_| V2RuntimeError::Corrupt)?;
            // Boot-boundary compaction: no runtime capabilities exist yet, so
            // ungranted boot-local objects — which cold recovery deliberately
            // refuses to resolve — may be shed together with dead grant
            // closures. The import-owned compactor retains only any exact
            // policy attachment already proved from the same preflight (C7.4
            // operator evidence), never a generic orphan or kind lookup. A
            // replacement is re-validated under the compiled policy and
            // re-verified exactly like the recovered view; any failure past
            // the replacement attempt fails the cold proof.
            let view = {
                let record_count = view.record_stream().len() / LOGICAL_BLOCK_SIZE;
                let compacted = if record_count >= STORAGE_V2_COMPACT_MIN_RECORDS {
                    decode_authority_records(view.record_stream())
                        .ok()
                        .and_then(|records| {
                            crate::durable_cspace::storage_v2_compact_records_for_policy(
                                &records,
                                true,
                                view.root_policy_sha256(),
                            )
                            .ok()
                            .flatten()
                        })
                } else {
                    None
                };
                match compacted {
                    None => view,
                    Some(compacted) => {
                        let import =
                            crate::durable_cspace::storage_v2_compaction_import_for_policy(
                                &compacted,
                                view.root_policy_sha256(),
                            )
                            .map_err(|_| V2RuntimeError::Corrupt)?;
                        let writer = operation
                            .store()
                            .derive_persistent_authority_writer(&maintenance)
                            .map_err(|_| V2RuntimeError::Corrupt)?;
                        let generation = view.checkpoint_generation();
                        drop(view);
                        let replaced = poll_as_system(
                            operation
                                .store()
                                .replace_persistent_authority(&writer, generation, import),
                        )
                        .await
                        .map_err(|_| V2RuntimeError::Corrupt)?;
                        let verify = crate::durable_cspace::storage_v2_recovery_import_for_policy(
                            replaced.record_stream(),
                            replaced.root_policy_sha256(),
                        )
                        .map_err(|_| V2RuntimeError::Corrupt)?;
                        poll_as_system(
                            operation
                                .store()
                                .verify_persistent_authority_import(&replaced, &verify),
                        )
                        .await
                        .map_err(|_| V2RuntimeError::Corrupt)?;
                        replaced
                    }
                }
            };
            let scrub = poll_as_system(operation.store().scrub(&maintenance))
                .await
                .map_err(|_| V2RuntimeError::Corrupt)?;
            // A crash may durably publish anonymous CAS extents/checkpoints
            // before the atomic authority snapshot which would bind them.
            // Scrub may therefore be newer than authority, never older.
            if scrub.status != ScrubStatus::Healthy
                || scrub.checkpoint_generation < view.checkpoint_generation()
                || !crate::durable_cspace::storage_v2_recovery_policy_is_recognized(
                    view.root_policy_sha256(),
                )
            {
                return Err(V2RuntimeError::Corrupt);
            }
            let evidence = ColdScrubEvidence {
                device_id: self.device.info().device_id,
                v2_first_logical_block: STORAGE_V2_FIRST_BLOCK,
                v2_logical_block_count: STORAGE_V2_BLOCK_COUNT,
                store_uuid: StoreUuid::new(view.store_uuid())
                    .map_err(|_| V2RuntimeError::Corrupt)?,
                checkpoint_generation: view.checkpoint_generation(),
                authority_sha256: view.snapshot_sha256(),
                complete: true,
            };
            Ok((view, evidence))
        }
        .await;
        match recovered {
            Ok((view, evidence)) => {
                let view = self.publish_authority(view);
                self.authority_boot_proved.store(true, Ordering::Release);
                operation.finish();
                Ok((view, evidence))
            }
            Err(error) => {
                // Invalidate while this operation still excludes every other
                // hart. Releasing the claim first would permit a waiter to
                // observe and append through the stale cached authority.
                self.invalidate_recovery_cache();
                operation.finish();
                Err(error)
            }
        }
    }

    /// Re-mount physical media and independently rebuild the persistent
    /// authority view for a publication postflight. Unlike ordinary facade
    /// recovery, this never reuses the boot-proved in-memory view and never
    /// performs boot-only compaction. Success replaces the runtime cache only
    /// after exact external-policy binding verification and a complete scrub.
    async fn readback_persistent_authority_from_media(
        self: &Arc<Self>,
        expected_policy_sha256: [u8; 32],
    ) -> Result<Arc<PersistentAuthorityView>, V2RuntimeError> {
        self.device.expose_preprovisioned_range();
        let mut operation = self.begin()?;
        self.clear_recovery_cache();
        let recovered = async {
            let info =
                poll_as_system(operation.store().mount())
                    .await
                    .map_err(|error| match error {
                        vibeos_segment_store::StoreError::Unformatted => {
                            V2RuntimeError::Unformatted
                        }
                        _ => V2RuntimeError::Corrupt,
                    })?;
            self.install_maintenance_if_missing(&mut operation)?;
            let maintenance = self
                .maintenance
                .lock()
                .clone()
                .ok_or(V2RuntimeError::Corrupt)?;
            let durable_blocks = vibeos_segment_format::admitted_pages(info.admitted_segments)
                .ok()
                .and_then(|pages| pages.checked_mul(BLOCKS_PER_PAGE))
                .ok_or(V2RuntimeError::Corrupt)?;
            self.device.expose_block_count(durable_blocks);
            *self.last_info.lock() = Some(info);

            let view = poll_as_system(recover_recognized_persistent_authority(
                operation.store(),
                expected_policy_sha256,
            ))
            .await
            .map_err(|error| match error {
                PersistentAuthorityError::NotInitialized => V2RuntimeError::AuthorityMissing,
                _ => V2RuntimeError::Corrupt,
            })?;
            let import = crate::durable_cspace::storage_v2_recovery_import_for_policy(
                view.record_stream(),
                view.root_policy_sha256(),
            )
            .map_err(|_| V2RuntimeError::Corrupt)?;
            poll_as_system(
                operation
                    .store()
                    .verify_persistent_authority_import(&view, &import),
            )
            .await
            .map_err(|_| V2RuntimeError::Corrupt)?;
            let scrub = poll_as_system(operation.store().scrub(&maintenance))
                .await
                .map_err(|_| V2RuntimeError::Corrupt)?;
            if scrub.status != ScrubStatus::Healthy
                || scrub.checkpoint_generation < view.checkpoint_generation()
                || !crate::durable_cspace::storage_v2_recovery_policy_is_recognized(
                    view.root_policy_sha256(),
                )
                || view.store_uuid() != STORAGE_V2_UUID
                || BootStoreSelection::decode(self.boot_selection.load(Ordering::Acquire))
                    != Some(BootStoreSelection::StorageV2)
            {
                return Err(V2RuntimeError::Corrupt);
            }
            Ok(view)
        }
        .await;
        match recovered {
            Ok(view) => {
                let view = self.publish_authority(view);
                self.authority_boot_proved.store(true, Ordering::Release);
                operation.finish();
                Ok(view)
            }
            Err(error) => {
                self.invalidate_recovery_cache();
                operation.finish();
                Err(error)
            }
        }
    }

    pub(crate) async fn read_persistent_object(
        self: &Arc<Self>,
        object: &PersistentObjectHandle,
    ) -> Result<Vec<u8>, V2RuntimeError> {
        let mut operation = self.begin()?;
        let bytes = poll_as_system(operation.store().read_persistent_object(object))
            .await
            .map_err(map_persistent_read_error)?;
        operation.finish();
        Ok(bytes)
    }

    /// Grow the store toward the foreground free-segment floor while the
    /// device still has growth capability. Both the file-tree and the object
    /// append paths call this before mutating, which keeps capacity relief on
    /// the growth path instead of a blocking foreground collection.
    async fn ensure_foreground_capacity(self: &Arc<Self>) -> Result<(), V2RuntimeError> {
        // Zero lets the device-scaled floor decide; batched callers pass
        // their real per-transaction appetite instead.
        self.ensure_foreground_capacity_for(0).await
    }

    /// Like [`StorageV2Runtime::ensure_foreground_capacity_for`], but the
    /// requested appetite is clamped to what the device's scaled policy can
    /// actually sustain, so a demand tuned on large devices cannot force a
    /// collection on every commit of a small store.
    async fn ensure_foreground_capacity_for_scaled(
        self: &Arc<Self>,
        required_free: u64,
    ) -> Result<(), V2RuntimeError> {
        let total_segments =
            (self.device.provisioned_page_count() / vibeos_segment_format::SEGMENT_PAGES).max(1);
        let sustainable = scaled_free_floor(total_segments)
            .saturating_add(scaled_growth_hysteresis(total_segments));
        self.ensure_foreground_capacity_for(required_free.min(sustainable))
            .await
    }

    /// Like [`StorageV2Runtime::ensure_foreground_capacity`], but replenishing
    /// to at least `required_free` segments. Batched staging consumes several
    /// segments inside one transaction, so its caller must raise the floor to
    /// the batch's appetite instead of relying on the per-append default.
    async fn ensure_foreground_capacity_for(
        self: &Arc<Self>,
        required_free: u64,
    ) -> Result<(), V2RuntimeError> {
        let mut operation = self.begin()?;
        let result = self
            .ensure_foreground_capacity_for_operation(&mut operation, required_free)
            .await;
        operation.finish();
        result
    }

    /// Replenish capacity while retaining a caller-owned exclusive mutation
    /// epoch. This is the only capacity path used by policy-bound authority
    /// append, so the policy observation made before entry cannot race a
    /// maintenance replacement on another task or hart.
    async fn ensure_foreground_capacity_for_operation(
        self: &Arc<Self>,
        operation: &mut V2Operation,
        required_free: u64,
    ) -> Result<(), V2RuntimeError> {
        let total_segments =
            (self.device.provisioned_page_count() / vibeos_segment_format::SEGMENT_PAGES).max(1);
        let scaled_floor = scaled_free_floor(total_segments);
        let hysteresis = scaled_growth_hysteresis(total_segments);
        let floor = scaled_floor.max(required_free);
        let info = operation
            .store()
            .info()
            .map_err(|_| V2RuntimeError::Corrupt)?;
        if info.free_segments >= floor {
            return Ok(());
        }
        let durable_blocks = vibeos_segment_format::admitted_pages(info.admitted_segments)
            .ok()
            .and_then(|pages| pages.checked_mul(BLOCKS_PER_PAGE))
            .ok_or(V2RuntimeError::Corrupt)?;
        // Grow with hysteresis: replenishing exactly to the floor makes the
        // very next commit dip below it again, turning every append into a
        // growth checkpoint. Overshooting amortizes one growth transaction
        // across many commits.
        let growth_blocks = floor
            .saturating_add(hysteresis)
            .saturating_sub(info.free_segments)
            .checked_mul(STORAGE_V2_GROWTH_GRANULE_BLOCKS)
            .ok_or(V2RuntimeError::Corrupt)?;
        let additional = self
            .device
            .growth_capability_bounded(durable_blocks, growth_blocks)
            .map_err(|_| V2RuntimeError::Corrupt)?;
        #[cfg(feature = "storage-bench")]
        crate::println!(
            "  bench-detail capacity free={} floor={} growth_blocks={} additional={:?}",
            info.free_segments,
            floor,
            growth_blocks,
            additional.is_some()
        );
        if let Some(additional) = additional {
            let maintenance = self
                .maintenance
                .lock()
                .clone()
                .ok_or(V2RuntimeError::Corrupt)?;
            poll_as_system(operation.store().grow(&maintenance, additional))
                .await
                .map_err(|_| V2RuntimeError::Corrupt)?;
        } else {
            // Growth is exhausted: reclaim dead space now, while enough free
            // segments remain for the collector's relocation targets. Each
            // round's source budget bounds its pause, and a retired segment
            // only rejoins the free set two checkpoint generations later, so
            // one round cannot observe its own relief — iterate bounded
            // rounds until the requested floor is met or reclaim stalls.
            // Reclaim past the floor with the same hysteresis as growth:
            // every mark walk costs one pass over the live object graph, so
            // stopping at the floor makes the very next batch dip below it
            // and charges a full walk per handful of freed segments.
            // Overshooting amortizes one walk across many commits.
            let reclaim_target = floor.saturating_add(hysteresis);
            let mut collected = false;
            let mut last_free = info.free_segments;
            let mut stalled = 0_u32;
            for _ in 0..8 {
                #[cfg(all(feature = "storage-bench", feature = "qemu-virt"))]
                let io_before = crate::virtio_blk::telemetry();
                let _telemetry = match poll_as_system(operation.store().collect_garbage()).await {
                    Ok(telemetry) => telemetry,
                    Err(_error) => {
                        #[cfg(feature = "storage-bench")]
                        crate::println!("  bench-detail gc error: {_error:?}");
                        break;
                    }
                };
                collected = true;
                let Ok(current) = operation.store().info() else {
                    break;
                };
                #[cfg(feature = "storage-bench")]
                crate::println!(
                    "  bench-detail gc-round free={} floor={}",
                    current.free_segments,
                    floor
                );
                #[cfg(all(feature = "storage-bench", feature = "qemu-virt"))]
                {
                    let io = crate::virtio_blk::telemetry().saturating_sub(io_before);
                    crate::println!(
                        "  bench-detail gc-io reads={} read_mib={} writes={} live_obj={} live_blob={} copied={} reclaimed_seg={} pause_ms={}",
                        io.read_requests,
                        io.read_bytes / (1024 * 1024),
                        io.write_requests,
                        _telemetry.live_object_count,
                        _telemetry.live_blob_count,
                        _telemetry.copied_bytes,
                        _telemetry.reclaimed_segments,
                        _telemetry.foreground_pause_ns / 1_000_000
                    );
                }
                if current.free_segments >= reclaim_target {
                    break;
                }
                // Past the floor the walk is pure amortization; a round that
                // stops yielding must not stall the caller, which already has
                // the capacity it asked for.
                if current.free_segments >= floor && current.free_segments <= last_free {
                    break;
                }
                if current.free_segments <= last_free {
                    stalled += 1;
                    if stalled >= 3 {
                        break;
                    }
                } else {
                    stalled = 0;
                }
                last_free = current.free_segments;
            }
            if collected {
                // Collection preserves the logical stream but advances the
                // checkpoint generation; refresh the published authority view
                // so the next append's generation witness is current.
                if let Ok(view) = poll_as_system(recover_recognized_persistent_authority(
                    operation.store(),
                    crate::durable_cspace::storage_v2_external_policy_sha256(),
                ))
                .await
                {
                    self.publish_authority(view);
                }
            }
        }
        Ok(())
    }

    /// Steady-state stream compaction. When the appended logical journal has
    /// outgrown the threshold and a rewrite would shed at least a quarter of
    /// its records, replace the persistent authority with the compacted
    /// equivalent and return the published replacement view. Handles and
    /// read tokens minted earlier this boot keep resolving: persistent and
    /// transient resolution binds stable object ids, never stream sequences.
    /// Ungranted (runtime-transient) objects are retained; only a boot
    /// boundary may shed those.
    async fn maybe_compact_authority(
        self: &Arc<Self>,
        view: &PersistentAuthorityView,
    ) -> Result<Option<Arc<PersistentAuthorityView>>, vibeos_object_store::StoreError> {
        let record_count = (view.record_stream().len() / LOGICAL_BLOCK_SIZE) as u64;
        if (record_count as usize) < STORAGE_V2_COMPACT_MIN_RECORDS {
            return Ok(None);
        }
        let watermark = self.compact_watermark.load(Ordering::Acquire);
        if watermark != 0 && record_count < watermark.saturating_add(watermark / 4) {
            return Ok(None);
        }
        self.compact_watermark
            .store(record_count, Ordering::Release);
        // Evaluation failures (nothing worth compacting, policy re-validation
        // declined) leave the appended state authoritative. Only an actual
        // replacement attempt with an unknown durable outcome fails closed.
        let Ok(records) = decode_authority_records(view.record_stream()) else {
            return Ok(None);
        };
        let compacted = match crate::durable_cspace::storage_v2_compact_records_for_policy(
            &records,
            false,
            view.root_policy_sha256(),
        ) {
            Ok(Some(compacted)) => compacted,
            _ => return Ok(None),
        };
        let Ok(import) = crate::durable_cspace::storage_v2_compaction_import_for_policy(
            &compacted,
            view.root_policy_sha256(),
        ) else {
            return Ok(None);
        };
        let mut expected = Vec::new();
        if expected
            .try_reserve_exact(compacted.len() * LOGICAL_BLOCK_SIZE)
            .is_err()
        {
            return Ok(None);
        }
        for record in &compacted {
            expected.extend_from_slice(record);
        }
        match self.install_persistent_authority(import, &expected).await {
            Ok(replacement) => {
                self.compact_watermark
                    .store(compacted.len() as u64, Ordering::Release);
                Ok(Some(replacement))
            }
            Err(_) => {
                // The replacement's durability is unknown; only a fresh cold
                // proof may re-establish which checkpoint is live.
                self.invalidate_recovery_cache();
                Err(vibeos_object_store::StoreError::Corrupt)
            }
        }
    }

    /// Re-establish the boot proof after an invalidation (for example a
    /// failed staged batch that poisoned the mounted store). The file tree
    /// stays fail-closed until a complete cold proof succeeds; without this
    /// re-proof, one recoverable capacity failure would leave every later
    /// file-tree operation returning Unavailable for the rest of the session.
    #[cfg(feature = "file-tree")]
    async fn ensure_boot_proof(self: &Arc<Self>) -> Result<(), FileError> {
        if BootStoreSelection::decode(self.boot_selection.load(Ordering::Acquire))
            != Some(BootStoreSelection::StorageV2)
        {
            return Err(FileError::ServiceUnavailable);
        }
        if self.boot_proved_authority().is_some() {
            return Ok(());
        }
        crate::uart::_print(format_args!(
            "  storage v2: re-proving the store after an invalidated boot proof
"
        ));
        self.cold_recover_and_scrub(crate::durable_cspace::storage_v2_external_policy_sha256())
            .await
            .map(|_| ())
            .map_err(|error| {
                crate::uart::_print(format_args!(
                    "  storage v2: re-proof failed: {error:?}
"
                ));
                FileError::ServiceUnavailable
            })
    }

    #[cfg(feature = "file-tree")]
    async fn recover_file_tree(
        self: &Arc<Self>,
        namespace: u128,
    ) -> Result<FileTreeRoot, FileError> {
        self.ensure_boot_proof().await?;
        self.ensure_foreground_capacity()
            .await
            .map_err(|_| FileError::ServiceUnavailable)?;
        let mut operation = self.begin().map_err(map_file_runtime_error)?;
        let recovered = poll_as_system(FileTreeRoot::recover_persistent(
            operation.store(),
            namespace,
            vibeos_file_store::MAX_TRANSACTION_EDITS,
        ))
        .await
        .map_err(|_| FileError::ServiceUnavailable);
        operation.finish();
        let mut root = recovered?.unwrap_or(FileTreeRoot::new_empty(namespace)?);
        root.attach_backend(Arc::new(KernelFileTreeBackend {
            runtime: self.clone(),
        }))?;
        Ok(root)
    }

    async fn read_transient_object(
        self: &Arc<Self>,
        witness: &PersistentAuthorityTransientObjects,
        object: &vibeos_durable_format::RecoveredObject,
    ) -> Result<Vec<u8>, V2RuntimeError> {
        let mut operation = self.begin()?;
        let bytes = poll_as_system(operation.store().read_transient_object(witness, object))
            .await
            .map_err(map_persistent_read_error)?;
        operation.finish();
        Ok(bytes)
    }

    pub(crate) fn maintenance(&self) -> Option<StoreMaintenance> {
        self.maintenance.lock().clone()
    }
}

/// Release the exact V2 operation claim abandoned by a permanently detached
/// task. On-media poison/checkpoint rules force later code through cold mount.
pub(crate) unsafe fn recover_faulted_task(task: exec::TaskId, domain: heap::AllocationDomain) {
    let migration_operations = INSTALLED_MIGRATION_OPERATIONS.lock().clone();
    if let Some(migration_operations) = migration_operations {
        // Safety: the executor detached this exact task before cleanup and
        // observed its cross-hart quiescence acknowledgement.
        unsafe { migration_operations.recover_faulted(task, domain) };
    }
    let control = INSTALLED_CONTROL_DEVICE.lock().clone();
    if let Some(control) = control {
        // Safety: the executor detached this exact task before cleanup.
        unsafe { control.recover_faulted_operation(task, domain) };
    }
    let installed = INSTALLED_V2_RUNTIME.lock();
    let Some(runtime) = installed.as_ref() else {
        return;
    };
    let task_key =
        crate::sync::TaskRecoveryKey::new(task.0).expect("executor TaskId zero is reserved");
    // Safety: the executor detached this exact task before invoking cleanup.
    // Repair every stable lock it could have abandoned before inspecting the
    // operation breadcrumb.
    let _ = unsafe { runtime.active.recover_after_task_fault(domain, task_key) };
    let _ = unsafe {
        runtime
            .maintenance
            .recover_after_task_fault(domain, task_key)
    };
    let _ = unsafe { runtime.authority.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { runtime.last_info.recover_after_task_fault(domain, task_key) };
    // Safety: the executor detached this exact task before cleanup.
    unsafe { runtime.device.recover_faulted_operation(task, domain) };
    let mut active = runtime.active.lock();
    if active.is_some_and(|claim| claim.task == task && claim.domain == domain) {
        runtime.needs_rebuild.store(true, Ordering::Release);
        *runtime.authority.lock() = None;
        *runtime.last_info.lock() = None;
        *active = None;
    }
}

impl StorageV2Devices {
    pub(crate) fn new(
        backend: Arc<Space>,
        legacy_writer: Cap,
        legacy_reader: Cap,
        migration_control: Cap,
        store: Cap,
    ) -> Result<Self, PageIoError> {
        let store_device = CapabilityPageDevice::new_preprovisioned(
            backend.clone(),
            store,
            STORAGE_V2_FIRST_BLOCK,
            STORAGE_V2_BLOCK_COUNT,
        )?;
        let control_device = CapabilityPageDevice::new(
            backend.clone(),
            migration_control,
            MIGRATION_CONTROL_FIRST_BLOCK,
            MIGRATION_CONTROL_BLOCK_COUNT,
        )?;
        let migration_operations = MigrationOperationGate::new();
        {
            let mut installed = INSTALLED_CONTROL_DEVICE.lock();
            assert!(
                installed.is_none(),
                "only one migration control device may exist"
            );
            *installed = Some(control_device.clone());
        }
        {
            let mut installed = INSTALLED_MIGRATION_OPERATIONS.lock();
            assert!(
                installed.is_none(),
                "only one Storage V2 migration-operation gate may exist"
            );
            *installed = Some(migration_operations.clone());
        }
        Ok(Self {
            backend: backend.clone(),
            legacy_writer,
            legacy_reader,
            legacy_write_frozen: system_arc(AtomicBool::new(false)),
            legacy_store: SpinLock::new(None),
            migration_operations,
            migration_control: control_device,
            runtime: StorageV2Runtime::new(store_device),
        })
    }

    pub(crate) fn selected_boot_store(&self) -> Option<BootStoreSelection> {
        BootStoreSelection::decode(self.runtime.boot_selection.load(Ordering::Acquire))
    }

    pub(crate) async fn benchmark_authority_shape(
        &self,
    ) -> Option<(usize, usize, bool, u64, u64, u32)> {
        let view = self.runtime.authority_view()?;
        let info = self.runtime.last_info.lock().as_ref().copied()?;
        let mut operation = self.runtime.begin().ok()?;
        let verified = operation.store().current_cas_payloads_verified();
        operation.finish();
        Some((
            view.objects().len(),
            view.record_stream().len() / LOGICAL_BLOCK_SIZE,
            verified,
            info.allocated_segments,
            info.free_segments,
            info.cleaner_reserved_segments,
        ))
    }

    #[cfg(feature = "file-tree")]
    pub(crate) async fn recover_file_tree_root(
        &self,
        namespace: u128,
    ) -> Result<FileTreeRoot, FileError> {
        self.runtime.recover_file_tree(namespace).await
    }

    /// Bind the sole unified facade so migration can prove no legacy journal
    /// invocation is in flight before killing the writer branch. Initialization
    /// performs this once before the executor can expose either capability.
    pub(crate) fn bind_legacy_store(&self, service: &Arc<vibeos_object_store::StoreService>) {
        let mut installed = self.legacy_store.lock();
        assert!(
            installed.is_none(),
            "legacy store facade is bound exactly once"
        );
        *installed = Some(Arc::downgrade(service));
    }

    pub(crate) fn legacy_write_gate(&self) -> Arc<AtomicBool> {
        self.legacy_write_frozen.clone()
    }

    fn legacy_store_busy(&self) -> Result<bool, MigrationRunError> {
        let service = self
            .legacy_store
            .lock()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or(MigrationRunError::Control)?;
        Ok(service.info().busy)
    }

    async fn freeze_legacy_frontend_and_quiesce(&self) -> Result<(), MigrationRunError> {
        // Release publishes the logical freeze before the active-operation
        // scan. New M4 mutations fail at the platform write boundary; an
        // operation which passed that boundary remains visible as busy until
        // its final flush and exact claim release.
        self.legacy_write_frozen.store(true, Ordering::Release);
        while self.legacy_store_busy()? {
            exec::yield_now().await;
        }
        Ok(())
    }

    fn publish_boot_store(&self, selection: BootStoreSelection) {
        if selection != BootStoreSelection::StorageV2 {
            // A cached view is usable only while the selector which was
            // published from its exact cold proof continues to select V2.
            self.runtime.clear_recovery_cache();
        }
        self.runtime
            .boot_selection
            .store(selection.encode(), Ordering::Release);
    }

    /// A selector read error is an ambiguity about which backend owns durable
    /// authority, never an ordinary operator error. Kill both legacy mutation
    /// paths before publishing the fail-closed facade state so no cached boot
    /// choice remains usable after corruption or uncertain control I/O.
    fn fail_closed_control(&self) -> MigrationRunError {
        self.legacy_write_frozen.store(true, Ordering::Release);
        let _ = self.retire_legacy_writer();
        self.publish_boot_store(BootStoreSelection::FailClosed);
        MigrationRunError::Control
    }

    fn control_or_fail_closed(
        &self,
        observed: Result<Option<MigrationControl>, MigrationError<PageIoError>>,
    ) -> Result<Option<MigrationControl>, MigrationRunError> {
        observed.map_err(|_| self.fail_closed_control())
    }

    /// Revoke only the pre-migration writer branch. The sibling read branch
    /// remains valid for the bounded compatibility release and cannot write.
    pub(crate) fn retire_legacy_writer(&self) -> bool {
        self.backend.0.lock().revoke_slot(self.legacy_writer.slot()) != 0
    }

    async fn read_legacy_sector(
        &self,
        lease: &InvocationLease<BlockDevice>,
        session: DeviceSession,
        relative_sector: u64,
    ) -> Result<[u8; 512], PageIoError> {
        let mut output = [0; 512];
        block_device::read_blocks_with_session(lease, session, relative_sector, 1, &mut output)
            .await
            .map_err(PageIoError::Block)?;
        Ok(output)
    }

    /// Recover the selector only from the dedicated control capability. A
    /// malformed record is not treated as an absent record.
    pub(crate) async fn migration_control(
        &self,
    ) -> Result<Option<MigrationControl>, MigrationError<PageIoError>> {
        let operation = self
            .migration_control
            .begin_current_operation()
            .map_err(MigrationError::Device)?;
        let result = MigrationController::new(self.migration_control.clone())?
            .recover()
            .await;
        operation.finish();
        result
    }

    pub(crate) async fn transition(
        &self,
        maintenance: &StoreMaintenance,
        current: Option<MigrationControl>,
        transition: MigrationTransition,
    ) -> Result<MigrationControl, MigrationError<PageIoError>> {
        let operation = self
            .migration_control
            .begin_current_operation()
            .map_err(MigrationError::Device)?;
        let result = MigrationController::new(self.migration_control.clone())?
            .transition(
                maintenance,
                &self.runtime.maintenance_provisioner,
                current,
                transition,
            )
            .await;
        operation.finish();
        result
    }

    pub(crate) fn select_boot_store(
        &self,
        legacy: LegacyFormatProbe,
        v2: StorageV2FormatProbe,
        control: Option<MigrationControl>,
    ) -> BootStoreSelection {
        match vibeos_segment_store::probe_storage_formats(legacy, v2, control) {
            FormatProbe::Blank => BootStoreSelection::Blank,
            FormatProbe::M4Only | FormatProbe::BothPreferM4 => BootStoreSelection::LegacyM4,
            FormatProbe::V2Only | FormatProbe::BothPreferV2 => BootStoreSelection::StorageV2,
            FormatProbe::Corrupt => BootStoreSelection::FailClosed,
        }
    }

    /// Read M4 without relying on "some non-zero bytes" as a format marker.
    /// Every non-empty sector must decode canonically, and the selected record
    /// stream must pass the complete semantic preflight.
    async fn legacy_snapshot(&self) -> Result<LegacySnapshot, BootProbeError> {
        use vibeos_durable_format::{DecodeStatus, LogRecord, StoreId};

        // One lease and one device incarnation cover the complete journal
        // scan. A driver restart therefore rejects the whole candidate rather
        // than allowing sectors from two media incarnations to be combined
        // into one apparently canonical authority stream.
        let lease = self
            .backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(self.legacy_reader, Rights::READ)
            .map_err(|_| BootProbeError::Device(PageIoError::AuthorityRevoked))?;
        let session = block_device::range_info_with(&lease)
            .map_err(PageIoError::Block)
            .map_err(BootProbeError::Device)?
            .session();
        let mut sectors = Vec::new();
        sectors
            .try_reserve_exact(vibeos_segment_store::M4_LOGICAL_BLOCK_COUNT as usize)
            .map_err(|_| BootProbeError::LegacyCorrupt)?;
        for sector in 0..vibeos_segment_store::M4_LOGICAL_BLOCK_COUNT {
            let bytes = self
                .read_legacy_sector(&lease, session, sector)
                .await
                .map_err(BootProbeError::Device)?;
            match LogRecord::decode(&bytes) {
                Ok(DecodeStatus::Valid(_)) => sectors.push(bytes),
                // The M4 crash model permanently skips an unsealed append and
                // permits a later valid record to chain around that slot.
                Ok(DecodeStatus::Empty | DecodeStatus::Torn) => {}
                Err(_) => return Err(BootProbeError::LegacyCorrupt),
            }
        }
        if sectors.is_empty() {
            return Ok(LegacySnapshot::Absent);
        }
        let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
        vibeos_durable_format::preflight_recovery(&sectors, store_id)
            .map_err(|_| BootProbeError::LegacyCorrupt)?;
        Ok(LegacySnapshot::Valid(sectors))
    }

    fn canonical_record_stream(records: &[[u8; LOGICAL_BLOCK_SIZE]]) -> Option<Vec<u8>> {
        let length = records.len().checked_mul(LOGICAL_BLOCK_SIZE)?;
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut stream = Vec::new();
        let reserved = stream.try_reserve_exact(length).is_ok();
        if reserved {
            for record in records {
                stream.extend_from_slice(record);
            }
        }
        system.restore();
        reserved.then_some(stream)
    }

    fn evidence_matches(control: MigrationControl, evidence: ColdScrubEvidence) -> bool {
        evidence.complete
            && control.store_uuid == *evidence.store_uuid.as_bytes()
            && control.device_id == evidence.device_id
            && control.v2_first_logical_block == evidence.v2_first_logical_block
            && control.v2_logical_block_count == evidence.v2_logical_block_count
            && match control.state {
                MigrationState::V2Staged => {
                    control.activation_checkpoint_generation == evidence.checkpoint_generation
                        && control.activation_authority_sha256 == evidence.authority_sha256
                }
                MigrationState::V2Active | MigrationState::RollbackClosed => {
                    evidence.checkpoint_generation > control.activation_checkpoint_generation
                        || (evidence.checkpoint_generation
                            == control.activation_checkpoint_generation
                            && control.activation_authority_sha256 == evidence.authority_sha256)
                }
                MigrationState::FrozenM4 => false,
            }
    }

    fn migration_report(
        control: MigrationControl,
        view: &PersistentAuthorityView,
    ) -> MigrationReport {
        MigrationReport {
            state: control.state,
            generation: control.generation,
            checkpoint_generation: view.checkpoint_generation(),
            object_count: u32::try_from(view.objects().len()).unwrap_or(u32::MAX),
        }
    }

    fn same_stable_control_binding(left: MigrationControl, right: MigrationControl) -> bool {
        left.device_id == right.device_id
            && left.m4_first_logical_block == right.m4_first_logical_block
            && left.m4_logical_block_count == right.m4_logical_block_count
            && left.v2_first_logical_block == right.v2_first_logical_block
            && left.v2_logical_block_count == right.v2_logical_block_count
    }

    fn stage_successor_matches(
        frozen: MigrationControl,
        staged: MigrationControl,
        evidence: ColdScrubEvidence,
    ) -> bool {
        frozen.state == MigrationState::FrozenM4
            && staged.state == MigrationState::V2Staged
            && frozen
                .generation
                .checked_add(1)
                .is_some_and(|generation| staged.generation == generation)
            && Self::same_stable_control_binding(frozen, staged)
            && frozen.store_uuid == [0; 16]
            && frozen.activation_checkpoint_generation == 0
            && frozen.activation_authority_sha256 == [0; 32]
            && Self::evidence_matches(staged, evidence)
    }

    /// Classify the durable result after a failed Stage publication. Only the
    /// exact old Frozen record and its exact evidence-bound Stage successor
    /// are recoverable. Absence, another valid state, or a read failure leaves
    /// backend authority ambiguous and therefore requires fail-closed state.
    fn classify_stage_transition_recovery(
        frozen: MigrationControl,
        evidence: ColdScrubEvidence,
        observed: Result<Option<MigrationControl>, ()>,
    ) -> StageTransitionRecovery {
        match observed {
            Ok(Some(staged)) if Self::stage_successor_matches(frozen, staged, evidence) => {
                StageTransitionRecovery::Published(staged)
            }
            Ok(Some(current)) if current == frozen => StageTransitionRecovery::NotCommitted,
            _ => StageTransitionRecovery::FailClosed,
        }
    }

    fn rollback_successor_matches(staged: MigrationControl, frozen: MigrationControl) -> bool {
        staged.state == MigrationState::V2Staged
            && frozen.state == MigrationState::FrozenM4
            && staged
                .generation
                .checked_add(1)
                .is_some_and(|generation| frozen.generation == generation)
            && Self::same_stable_control_binding(staged, frozen)
            && frozen.store_uuid == [0; 16]
            && frozen.activation_checkpoint_generation == 0
            && frozen.activation_authority_sha256 == [0; 32]
    }

    fn close_successor_matches(active: MigrationControl, closed: MigrationControl) -> bool {
        active.state == MigrationState::V2Active
            && closed.state == MigrationState::RollbackClosed
            && active
                .generation
                .checked_add(1)
                .is_some_and(|generation| closed.generation == generation)
            && Self::same_stable_control_binding(active, closed)
            && active.store_uuid == closed.store_uuid
            && active.activation_checkpoint_generation == closed.activation_checkpoint_generation
            && active.activation_authority_sha256 == closed.activation_authority_sha256
    }

    fn rollback_proofs_match(
        staged: MigrationControl,
        evidence: ColdScrubEvidence,
        v2_record_stream: &[u8],
        m4_record_stream: &[u8],
    ) -> bool {
        staged.state == MigrationState::V2Staged
            && Self::evidence_matches(staged, evidence)
            && v2_record_stream == m4_record_stream
    }

    fn native_control_matches(control: MigrationControl, evidence: ColdScrubEvidence) -> bool {
        control.state == MigrationState::RollbackClosed
            && control.generation == 1
            && Self::evidence_matches(control, evidence)
    }

    async fn initialize_native_v2(
        &self,
        recovered: Result<(Arc<PersistentAuthorityView>, ColdScrubEvidence), V2RuntimeError>,
    ) -> Result<BootStoreSelection, BootProbeError> {
        // Freeze both the logical facade gate and physical M4 writer before
        // the first native V2 mutation. No selector is published while format,
        // authority import, scrub, or control publication remains incomplete.
        self.freeze_legacy_frontend_and_quiesce()
            .await
            .map_err(|_| BootProbeError::StorageV2)?;
        let _ = self.retire_legacy_writer();

        let (view, evidence) = match recovered {
            Ok(proved) => proved,
            Err(V2RuntimeError::Unformatted | V2RuntimeError::AuthorityMissing) => {
                self.runtime
                    .ensure_native_initial_format()
                    .await
                    .map_err(|error| {
                        crate::uart::_print(format_args!(
                            "  storage v2 native format failed: {error:?}\n"
                        ));
                        BootProbeError::StorageV2
                    })?;
                self.runtime
                    .install_native_empty_authority()
                    .await
                    .map_err(|error| {
                        crate::uart::_print(format_args!(
                            "  storage v2 empty-authority install failed: {error:?}\n"
                        ));
                        BootProbeError::StorageV2
                    })?;
                self.runtime
                    .cold_recover_and_scrub(
                        crate::durable_cspace::storage_v2_external_policy_sha256(),
                    )
                    .await
                    .map_err(|error| {
                        crate::uart::_print(format_args!(
                            "  storage v2 post-format recovery failed: {error:?}\n"
                        ));
                        BootProbeError::StorageV2
                    })?
            }
            Err(error) => {
                crate::uart::_print(format_args!(
                    "  storage v2 native init rejected cold recovery: {error:?}\n"
                ));
                return Err(BootProbeError::StorageV2);
            }
        };
        let (expected_native, _) =
            prepare_native_empty_authority().map_err(|_| BootProbeError::StorageV2)?;
        if !crate::durable_cspace::is_storage_v2_native_empty_view(&view, &expected_native)
            || evidence.store_uuid.as_bytes() != &STORAGE_V2_UUID
        {
            crate::uart::_print(format_args!(
                "  storage v2 native init: empty-view/uuid proof mismatch\n"
            ));
            return Err(BootProbeError::StorageV2);
        }
        let maintenance = self
            .runtime
            .maintenance()
            .ok_or(BootProbeError::StorageV2)?;
        let closed = match self
            .transition(
                &maintenance,
                None,
                MigrationTransition::InitializeV2(evidence),
            )
            .await
        {
            Ok(closed) if Self::native_control_matches(closed, evidence) => closed,
            Ok(_) => return Err(BootProbeError::MigrationControl),
            Err(_) => match self.migration_control().await {
                Ok(Some(closed)) if Self::native_control_matches(closed, evidence) => closed,
                // No publication is a safe retry point, but this boot remains
                // fail-closed because the mutation result was ambiguous.
                Ok(None) => return Err(BootProbeError::MigrationControl),
                _ => return Err(BootProbeError::MigrationControl),
            },
        };
        debug_assert!(Self::native_control_matches(closed, evidence));
        self.publish_boot_store(BootStoreSelection::StorageV2);
        Ok(BootStoreSelection::StorageV2)
    }

    /// Boot-time probe. V2 is valid only after a cold mount, exact external
    /// authority recovery, and a healthy full scrub. A structurally formatted
    /// but not-yet-imported slice is tolerated only while no selector (or a
    /// Frozen selector) still makes M4 authoritative.
    pub(crate) async fn boot_probe(&self) -> Result<BootStoreSelection, BootProbeError> {
        let control = match self.migration_control().await {
            Ok(control) => control,
            Err(_) => {
                // An ambiguous selector must never leave a writable legacy
                // branch usable in this boot.
                let _ = self.retire_legacy_writer();
                self.publish_boot_store(BootStoreSelection::FailClosed);
                return Err(BootProbeError::MigrationControl);
            }
        };
        // Every durable migration state means the M4 compatibility window is
        // read-only, including Frozen and Staged boots which still read M4.
        if control.is_some() {
            self.legacy_write_frozen.store(true, Ordering::Release);
            let _ = self.retire_legacy_writer();
        }
        let legacy = match self.legacy_snapshot().await {
            Ok(LegacySnapshot::Absent) => LegacyFormatProbe::Absent,
            Ok(LegacySnapshot::Valid(_)) => LegacyFormatProbe::Valid,
            Err(error) => {
                // Corrupt or ambiguously read legacy media must not leave the
                // physical writer branch alive behind a merely Pending facade.
                self.legacy_write_frozen.store(true, Ordering::Release);
                let _ = self.retire_legacy_writer();
                self.publish_boot_store(BootStoreSelection::FailClosed);
                return Err(error);
            }
        };
        let policy = crate::durable_cspace::storage_v2_external_policy_sha256();
        let recovered_v2 = self.runtime.cold_recover_and_scrub(policy).await;
        if legacy == LegacyFormatProbe::Absent && control.is_none() {
            let result = self.initialize_native_v2(recovered_v2).await;
            if result.is_err() {
                let _ = self.retire_legacy_writer();
                self.publish_boot_store(BootStoreSelection::FailClosed);
            }
            return result;
        }
        let v2 = match recovered_v2 {
            Ok((_, evidence)) => StorageV2FormatProbe::Valid {
                device_id: evidence.device_id,
                v2_first_logical_block: evidence.v2_first_logical_block,
                v2_logical_block_count: evidence.v2_logical_block_count,
                store_uuid: evidence.store_uuid,
                checkpoint_generation: evidence.checkpoint_generation,
                authority_sha256: evidence.authority_sha256,
            },
            Err(V2RuntimeError::Unformatted) => StorageV2FormatProbe::Absent,
            Err(V2RuntimeError::AuthorityMissing)
                if control.is_none_or(|value| value.state == MigrationState::FrozenM4) =>
            {
                StorageV2FormatProbe::Absent
            }
            Err(_) => StorageV2FormatProbe::Corrupt,
        };
        let selected = self.select_boot_store(legacy, v2, control);
        if matches!(
            selected,
            BootStoreSelection::StorageV2 | BootStoreSelection::FailClosed
        ) {
            let _ = self.retire_legacy_writer();
        }
        self.publish_boot_store(selected);
        Ok(selected)
    }

    /// Execute the one-way, explicit cutover under a real capability lease.
    /// The empty V2 slice may be prepared first, but M4 is frozen and its
    /// writer branch is revoked before the authoritative source scan or any
    /// authority import. Frozen and Staged retries remain M4-readable only.
    pub(crate) fn migrate<'a>(
        self: &'a Arc<Self>,
        authority: &'a InvocationLease<StorageMigrationAuthority>,
    ) -> StorageV2MigrationFuture<'a> {
        Box::pin(async move {
            let _operation =
                self.begin_migration_operation(authority, MigrationOperationKind::Migrate)?;
            self.migrate_inner(authority, false).await
        })
    }

    /// Acceptance-only deterministic interruption point. It exercises the
    /// exact production path and returns after durable Stage publication,
    /// leaving the next boot M4-authoritative but read-only.
    #[cfg(feature = "legacy-shell")]
    pub(crate) fn migrate_until_staged<'a>(
        self: &'a Arc<Self>,
        authority: &'a InvocationLease<StorageMigrationAuthority>,
    ) -> StorageV2MigrationFuture<'a> {
        Box::pin(async move {
            let _operation = self
                .begin_migration_operation(authority, MigrationOperationKind::MigrateUntilStaged)?;
            self.migrate_inner(authority, true).await
        })
    }

    /// Explicitly discard a staged V2 boot preference. The immutable V2 bytes
    /// remain available for a later audited migration retry; rollback never
    /// resurrects the physical or logical M4 writer branch.
    pub(crate) fn rollback<'a>(
        self: &'a Arc<Self>,
        authority: &'a InvocationLease<StorageMigrationAuthority>,
    ) -> StorageV2MigrationFuture<'a> {
        Box::pin(async move {
            let _operation =
                self.begin_migration_operation(authority, MigrationOperationKind::Rollback)?;
            self.rollback_inner(authority).await
        })
    }

    /// Permanently close the compatibility rollback window after revalidating
    /// the active V2 checkpoint and external authority policy.
    pub(crate) fn close_rollback<'a>(
        self: &'a Arc<Self>,
        authority: &'a InvocationLease<StorageMigrationAuthority>,
    ) -> StorageV2MigrationFuture<'a> {
        Box::pin(async move {
            let _operation =
                self.begin_migration_operation(authority, MigrationOperationKind::CloseRollback)?;
            self.close_rollback_inner(authority).await
        })
    }

    fn begin_migration_operation(
        self: &Arc<Self>,
        authority: &InvocationLease<StorageMigrationAuthority>,
        kind: MigrationOperationKind,
    ) -> Result<MigrationOperation, MigrationRunError> {
        // Reject foreign authority before exposing whether an operation is in
        // flight. A valid caller receives Busy without touching boot
        // selection, legacy gates, either data range, or the selector pages.
        if !authority.authorizes(Rights::INVOKE)
            || !authority.with(|resource| resource.authorizes(self))
        {
            return Err(MigrationRunError::Unauthorized);
        }
        self.migration_operations.begin_current(kind)
    }

    async fn rollback_inner(
        self: &Arc<Self>,
        authority: &InvocationLease<StorageMigrationAuthority>,
    ) -> Result<MigrationReport, MigrationRunError> {
        if !authority.authorizes(Rights::INVOKE)
            || !authority.with(|resource| resource.authorizes(self))
        {
            return Err(MigrationRunError::Unauthorized);
        }
        let control = Box::pin(self.migration_control()).await;
        let staged = self
            .control_or_fail_closed(control)?
            .filter(|value| value.state == MigrationState::V2Staged)
            .ok_or(MigrationRunError::Control)?;

        // A staged selector already requires read-only M4, but repeat the
        // logical gate, exact active-claim drain, and physical revocation
        // before using M4 as rollback evidence. None of these are undone.
        Box::pin(self.freeze_legacy_frontend_and_quiesce()).await?;
        let _ = self.retire_legacy_writer();
        self.publish_boot_store(BootStoreSelection::LegacyM4);

        let policy = crate::durable_cspace::storage_v2_external_policy_sha256();
        let (view, evidence) = Box::pin(self.runtime.cold_recover_and_scrub(policy))
            .await
            .map_err(MigrationRunError::V2)?;
        let records = match Box::pin(self.legacy_snapshot())
            .await
            .map_err(|_| MigrationRunError::SourceCorrupt)?
        {
            LegacySnapshot::Absent => return Err(MigrationRunError::SourceAbsent),
            LegacySnapshot::Valid(records) => records,
        };
        let record_stream =
            Self::canonical_record_stream(&records).ok_or(MigrationRunError::SourceCorrupt)?;
        if !Self::evidence_matches(staged, evidence) {
            return Err(MigrationRunError::Control);
        }
        if !Self::rollback_proofs_match(staged, evidence, view.record_stream(), &record_stream) {
            return Err(MigrationRunError::SourceChanged);
        }
        let maintenance = self
            .runtime
            .maintenance()
            .ok_or(MigrationRunError::V2(V2RuntimeError::Corrupt))?;
        let frozen = match Box::pin(self.transition(
            &maintenance,
            Some(staged),
            MigrationTransition::RollBackToM4,
        ))
        .await
        {
            Ok(frozen) if Self::rollback_successor_matches(staged, frozen) => frozen,
            Ok(_) => {
                self.publish_boot_store(BootStoreSelection::FailClosed);
                return Err(MigrationRunError::Control);
            }
            Err(_) => match Box::pin(self.migration_control()).await {
                Ok(Some(frozen)) if Self::rollback_successor_matches(staged, frozen) => frozen,
                Ok(Some(current)) if current == staged => {
                    self.publish_boot_store(BootStoreSelection::LegacyM4);
                    return Err(MigrationRunError::Control);
                }
                _ => {
                    self.publish_boot_store(BootStoreSelection::FailClosed);
                    return Err(MigrationRunError::Control);
                }
            },
        };
        self.legacy_write_frozen.store(true, Ordering::Release);
        let _ = self.retire_legacy_writer();
        self.publish_boot_store(BootStoreSelection::LegacyM4);
        Ok(Self::migration_report(frozen, &view))
    }

    async fn close_rollback_inner(
        self: &Arc<Self>,
        authority: &InvocationLease<StorageMigrationAuthority>,
    ) -> Result<MigrationReport, MigrationRunError> {
        if !authority.authorizes(Rights::INVOKE)
            || !authority.with(|resource| resource.authorizes(self))
        {
            return Err(MigrationRunError::Unauthorized);
        }
        let control = Box::pin(self.migration_control()).await;
        let active = self
            .control_or_fail_closed(control)?
            .filter(|value| value.state == MigrationState::V2Active)
            .ok_or(MigrationRunError::Control)?;
        self.legacy_write_frozen.store(true, Ordering::Release);
        let _ = self.retire_legacy_writer();

        let policy = crate::durable_cspace::storage_v2_external_policy_sha256();
        let (view, evidence) = Box::pin(self.runtime.cold_recover_and_scrub(policy))
            .await
            .map_err(MigrationRunError::V2)?;
        if !Self::evidence_matches(active, evidence) {
            return Err(MigrationRunError::Control);
        }
        let maintenance = self
            .runtime
            .maintenance()
            .ok_or(MigrationRunError::V2(V2RuntimeError::Corrupt))?;
        let closed = match Box::pin(self.transition(
            &maintenance,
            Some(active),
            MigrationTransition::CloseRollback(evidence),
        ))
        .await
        {
            Ok(closed) if Self::close_successor_matches(active, closed) => closed,
            Ok(_) => {
                self.publish_boot_store(BootStoreSelection::FailClosed);
                return Err(MigrationRunError::Control);
            }
            Err(_) => match Box::pin(self.migration_control()).await {
                Ok(Some(closed)) if Self::close_successor_matches(active, closed) => closed,
                Ok(Some(current)) if current == active => {
                    self.publish_boot_store(BootStoreSelection::StorageV2);
                    return Err(MigrationRunError::Control);
                }
                _ => {
                    self.publish_boot_store(BootStoreSelection::FailClosed);
                    return Err(MigrationRunError::Control);
                }
            },
        };
        self.publish_boot_store(BootStoreSelection::StorageV2);
        Ok(Self::migration_report(closed, &view))
    }

    async fn migrate_inner(
        self: &Arc<Self>,
        authority: &InvocationLease<StorageMigrationAuthority>,
        stop_after_stage: bool,
    ) -> Result<MigrationReport, MigrationRunError> {
        if !authority.authorizes(Rights::INVOKE)
            || !authority.with(|resource| resource.authorizes(self))
        {
            return Err(MigrationRunError::Unauthorized);
        }
        let policy = crate::durable_cspace::storage_v2_external_policy_sha256();
        let observed_control = Box::pin(self.migration_control()).await;
        let control = self.control_or_fail_closed(observed_control)?;

        if control.is_some() {
            self.legacy_write_frozen.store(true, Ordering::Release);
            let _ = self.retire_legacy_writer();
        }

        if let Some(active) = control.filter(|value| value.state.prefers_v2()) {
            let (view, evidence) = Box::pin(self.runtime.cold_recover_and_scrub(policy))
                .await
                .map_err(MigrationRunError::V2)?;
            if !Self::evidence_matches(active, evidence) {
                return Err(MigrationRunError::Control);
            }
            let _ = self.retire_legacy_writer();
            self.publish_boot_store(BootStoreSelection::StorageV2);
            return Ok(Self::migration_report(active, &view));
        }

        // Resume of a fully staged snapshot never rewrites V2: re-establish the
        // exact scrub and source equality proofs, then publish Active.
        if let Some(staged) = control.filter(|value| value.state == MigrationState::V2Staged) {
            let (view, evidence) = Box::pin(self.runtime.cold_recover_and_scrub(policy))
                .await
                .map_err(MigrationRunError::V2)?;
            if !Self::evidence_matches(staged, evidence) {
                return Err(MigrationRunError::Control);
            }
            let records = match Box::pin(self.legacy_snapshot())
                .await
                .map_err(|_| MigrationRunError::SourceCorrupt)?
            {
                LegacySnapshot::Absent => return Err(MigrationRunError::SourceChanged),
                LegacySnapshot::Valid(records) => records,
            };
            let record_stream =
                Self::canonical_record_stream(&records).ok_or(MigrationRunError::SourceCorrupt)?;
            if view.record_stream() != record_stream.as_slice() {
                return Err(MigrationRunError::SourceChanged);
            }
            if stop_after_stage {
                self.publish_boot_store(BootStoreSelection::LegacyM4);
                return Ok(Self::migration_report(staged, &view));
            }
            let maintenance = self
                .runtime
                .maintenance()
                .ok_or(MigrationRunError::V2(V2RuntimeError::Corrupt))?;
            let active = match Box::pin(self.transition(
                &maintenance,
                Some(staged),
                MigrationTransition::ActivateV2(evidence),
            ))
            .await
            {
                Ok(active) => active,
                Err(_) => match Box::pin(self.migration_control()).await {
                    Ok(Some(active))
                        if active.state == MigrationState::V2Active
                            && Self::evidence_matches(active, evidence) =>
                    {
                        active
                    }
                    _ => {
                        self.publish_boot_store(BootStoreSelection::FailClosed);
                        return Err(MigrationRunError::Control);
                    }
                },
            };
            self.publish_boot_store(BootStoreSelection::StorageV2);
            return Ok(Self::migration_report(active, &view));
        }

        if control.is_some_and(|value| value.state != MigrationState::FrozenM4) {
            return Err(MigrationRunError::Control);
        }

        // Formatting is safe preparation because it touches only the disjoint
        // V2 capability. No source byte is observed or imported yet.
        Box::pin(self.runtime.ensure_formatted_for_migration())
            .await
            .map_err(MigrationRunError::V2)?;
        let maintenance = self
            .runtime
            .maintenance()
            .ok_or(MigrationRunError::V2(V2RuntimeError::Corrupt))?;

        // Publish the shared logical write gate first, then drain the unified
        // facade's exact active claim. New writes fail at the platform boundary
        // on every hart, while an operation which already passed that boundary
        // remains busy through its final durability barrier. Only then may the
        // durable selector be frozen and the physical writer branch revoked.
        Box::pin(self.freeze_legacy_frontend_and_quiesce()).await?;

        let frozen = if let Some(frozen) = control {
            frozen
        } else {
            match Box::pin(self.transition(
                &maintenance,
                None,
                MigrationTransition::FreezeM4(
                    StoreUuid::new(STORAGE_V2_UUID).expect("fixed Storage V2 UUID is non-zero"),
                ),
            ))
            .await
            {
                Ok(frozen) => frozen,
                Err(_) => match Box::pin(self.migration_control()).await {
                    Ok(Some(frozen)) if frozen.state == MigrationState::FrozenM4 => frozen,
                    Ok(None) => {
                        // No sealed selector reached media, and no source read
                        // or V2 import has occurred. This same-boot logical gate
                        // may therefore be safely reopened for an operator retry.
                        self.legacy_write_frozen.store(false, Ordering::Release);
                        return Err(MigrationRunError::Control);
                    }
                    _ => {
                        self.publish_boot_store(BootStoreSelection::FailClosed);
                        return Err(MigrationRunError::Control);
                    }
                },
            }
        };
        let _ = self.retire_legacy_writer();
        self.publish_boot_store(BootStoreSelection::LegacyM4);

        let records = match Box::pin(self.legacy_snapshot())
            .await
            .map_err(|_| MigrationRunError::SourceCorrupt)?
        {
            LegacySnapshot::Absent => return Err(MigrationRunError::SourceAbsent),
            LegacySnapshot::Valid(records) => records,
        };
        let record_stream =
            Self::canonical_record_stream(&records).ok_or(MigrationRunError::SourceCorrupt)?;

        let import = crate::durable_cspace::storage_v2_migration_import(&records)
            .map_err(|_| MigrationRunError::SourceCorrupt)?;
        let _installed = Box::pin(
            self.runtime
                .install_persistent_authority(import, &record_stream),
        )
        .await
        .map_err(MigrationRunError::V2)?;
        let (view, evidence) = Box::pin(self.runtime.cold_recover_and_scrub(policy))
            .await
            .map_err(MigrationRunError::V2)?;
        if view.record_stream() != record_stream.as_slice() {
            return Err(MigrationRunError::SourceChanged);
        }

        let staged = match Box::pin(self.transition(
            &maintenance,
            Some(frozen),
            MigrationTransition::StageV2(evidence),
        ))
        .await
        {
            Ok(staged) if Self::stage_successor_matches(frozen, staged, evidence) => staged,
            Ok(_) => return Err(self.fail_closed_control()),
            Err(_) => {
                let recovered = Box::pin(self.migration_control()).await.map_err(|_| ());
                match Self::classify_stage_transition_recovery(frozen, evidence, recovered) {
                    StageTransitionRecovery::Published(staged) => staged,
                    StageTransitionRecovery::NotCommitted => {
                        self.publish_boot_store(BootStoreSelection::LegacyM4);
                        return Err(MigrationRunError::Control);
                    }
                    StageTransitionRecovery::FailClosed => {
                        return Err(self.fail_closed_control());
                    }
                }
            }
        };
        if !Self::evidence_matches(staged, evidence) {
            return Err(MigrationRunError::Control);
        }
        if stop_after_stage {
            self.publish_boot_store(BootStoreSelection::LegacyM4);
            return Ok(Self::migration_report(staged, &view));
        }

        let active = match Box::pin(self.transition(
            &maintenance,
            Some(staged),
            MigrationTransition::ActivateV2(evidence),
        ))
        .await
        {
            Ok(active) => active,
            Err(_) => match Box::pin(self.migration_control()).await {
                Ok(Some(active))
                    if active.state == MigrationState::V2Active
                        && Self::evidence_matches(active, evidence) =>
                {
                    active
                }
                _ => {
                    self.publish_boot_store(BootStoreSelection::FailClosed);
                    return Err(MigrationRunError::Control);
                }
            },
        };
        self.publish_boot_store(BootStoreSelection::StorageV2);
        Ok(Self::migration_report(active, &view))
    }
}

#[cfg(any(test, feature = "legacy-shell"))]
mod storage_v2_transition_tests {
    use super::*;

    fn staged() -> MigrationControl {
        MigrationControl {
            state: MigrationState::V2Staged,
            generation: 2,
            device_id: [7; 16],
            m4_first_logical_block: vibeos_segment_store::M4_FIRST_LOGICAL_BLOCK,
            m4_logical_block_count: vibeos_segment_store::M4_LOGICAL_BLOCK_COUNT,
            v2_first_logical_block: STORAGE_V2_FIRST_BLOCK,
            v2_logical_block_count: STORAGE_V2_BLOCK_COUNT,
            store_uuid: STORAGE_V2_UUID,
            activation_checkpoint_generation: 11,
            activation_authority_sha256: [9; 32],
        }
    }

    fn evidence() -> ColdScrubEvidence {
        ColdScrubEvidence {
            device_id: [7; 16],
            v2_first_logical_block: STORAGE_V2_FIRST_BLOCK,
            v2_logical_block_count: STORAGE_V2_BLOCK_COUNT,
            store_uuid: StoreUuid::new(STORAGE_V2_UUID).unwrap(),
            checkpoint_generation: 11,
            authority_sha256: [9; 32],
            complete: true,
        }
    }

    #[cfg_attr(test, test)]
    pub(crate) fn hot_read_cache_has_byte_and_entry_bounds_and_clear_revokes_tokens() {
        let cache = HotReadCache::new();
        let mut page = Vec::new();
        page.resize(64 * 1024, 0x5a);
        let first = cache.insert(&page).unwrap();
        for _ in 1..=STORAGE_V2_HOT_READ_CACHE_BYTES / page.len() {
            cache.insert(&page).unwrap();
        }
        assert!(first.upgrade().is_none());
        {
            let state = cache.state.lock();
            assert_eq!(state.bytes, STORAGE_V2_HOT_READ_CACHE_BYTES);
            assert_eq!(
                state.entries.len(),
                STORAGE_V2_HOT_READ_CACHE_BYTES / page.len()
            );
        }

        cache.clear();
        let first_empty = cache.insert(&[]).unwrap();
        for _ in 1..=STORAGE_V2_HOT_READ_CACHE_ENTRIES {
            cache.insert(&[]).unwrap();
        }
        assert!(first_empty.upgrade().is_none());
        let survivor = cache.insert(&[1]).unwrap();
        cache.clear();
        assert!(survivor.upgrade().is_none());
        page.resize(STORAGE_V2_HOT_READ_MAX_OBJECT_BYTES + 1, 0);
        assert!(cache.insert(&page).is_none());
    }

    fn frozen_predecessor(staged: MigrationControl) -> MigrationControl {
        let mut frozen = MigrationControl::frozen(staged.device_id);
        frozen.generation = staged.generation - 1;
        frozen
    }

    #[cfg_attr(test, test)]
    pub(crate) fn stage_retry_accepts_only_exact_old_or_new_selector() {
        let staged = staged();
        let frozen = frozen_predecessor(staged);
        let evidence = evidence();
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(
                frozen,
                evidence,
                Ok(Some(staged)),
            ),
            StageTransitionRecovery::Published(staged)
        );
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(
                frozen,
                evidence,
                Ok(Some(frozen)),
            ),
            StageTransitionRecovery::NotCommitted
        );

        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(frozen, evidence, Err(())),
            StageTransitionRecovery::FailClosed
        );
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(frozen, evidence, Ok(None)),
            StageTransitionRecovery::FailClosed
        );

        let mut wrong_generation = staged;
        wrong_generation.generation += 1;
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(
                frozen,
                evidence,
                Ok(Some(wrong_generation)),
            ),
            StageTransitionRecovery::FailClosed
        );
        let mut wrong_binding = staged;
        wrong_binding.v2_logical_block_count -= 8;
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(
                frozen,
                evidence,
                Ok(Some(wrong_binding)),
            ),
            StageTransitionRecovery::FailClosed
        );
        let mut wrong_evidence = evidence;
        wrong_evidence.authority_sha256 = [8; 32];
        assert_eq!(
            StorageV2Devices::classify_stage_transition_recovery(
                frozen,
                wrong_evidence,
                Ok(Some(staged)),
            ),
            StageTransitionRecovery::FailClosed
        );
    }

    #[cfg_attr(test, test)]
    pub(crate) fn rollback_requires_exact_staged_evidence_and_source_stream() {
        let staged = staged();
        assert!(StorageV2Devices::rollback_proofs_match(
            staged,
            evidence(),
            b"same canonical stream",
            b"same canonical stream"
        ));
        assert!(!StorageV2Devices::rollback_proofs_match(
            staged,
            evidence(),
            b"V2 stream",
            b"M4 stream"
        ));
        let mut wrong = evidence();
        wrong.authority_sha256 = [8; 32];
        assert!(!StorageV2Devices::rollback_proofs_match(
            staged, wrong, b"same", b"same"
        ));

        let mut frozen = MigrationControl::frozen(staged.device_id);
        frozen.generation = staged.generation + 1;
        assert!(StorageV2Devices::rollback_successor_matches(staged, frozen));
        frozen.generation += 1;
        assert!(!StorageV2Devices::rollback_successor_matches(
            staged, frozen
        ));
    }

    #[cfg_attr(test, test)]
    pub(crate) fn close_preserves_activation_floor_and_accepts_newer_healthy_evidence() {
        let mut active = staged();
        active.state = MigrationState::V2Active;
        active.generation = 3;
        let mut newer = evidence();
        newer.checkpoint_generation += 1;
        newer.authority_sha256 = [10; 32];
        assert!(StorageV2Devices::evidence_matches(active, newer));

        let mut closed = active;
        closed.state = MigrationState::RollbackClosed;
        closed.generation += 1;
        assert!(StorageV2Devices::close_successor_matches(active, closed));
        closed.activation_checkpoint_generation += 1;
        assert!(!StorageV2Devices::close_successor_matches(active, closed));
    }

    #[cfg_attr(test, test)]
    pub(crate) fn boot_proved_cache_requires_exact_selector_policy_and_uuid() {
        let selection = Some(BootStoreSelection::StorageV2);
        let policy = crate::durable_cspace::storage_v2_external_policy_sha256();
        assert!(cache_metadata_matches_boot_proof(
            selection,
            true,
            policy,
            STORAGE_V2_UUID,
        ));
        assert!(!cache_metadata_matches_boot_proof(
            Some(BootStoreSelection::LegacyM4),
            true,
            policy,
            STORAGE_V2_UUID,
        ));
        assert!(!cache_metadata_matches_boot_proof(
            selection,
            false,
            policy,
            STORAGE_V2_UUID,
        ));
        assert!(!cache_metadata_matches_boot_proof(
            selection,
            true,
            [0xff; 32],
            STORAGE_V2_UUID,
        ));
        assert!(!cache_metadata_matches_boot_proof(
            selection,
            true,
            policy,
            *b"FOREIGN-V2-UUID!",
        ));
    }

    #[cfg_attr(test, test)]
    pub(crate) fn append_failures_revoke_cache_unless_proved_pre_mutation() {
        assert!(!append_error_requires_cold_recovery(
            V2RuntimeError::JournalChanged
        ));
        for error in [
            V2RuntimeError::Busy,
            V2RuntimeError::OutsideTask,
            V2RuntimeError::Unformatted,
            V2RuntimeError::AuthorityMissing,
            V2RuntimeError::ObjectUnavailable,
            V2RuntimeError::Corrupt,
        ] {
            assert!(append_error_requires_cold_recovery(error));
        }
    }

    #[cfg_attr(test, test)]
    pub(crate) fn concurrent_migration_actions_are_busy_without_changing_boot_selection() {
        let gate = MigrationOperationGate::new();
        let selection = AtomicU8::new(BootStoreSelection::LegacyM4.encode());
        let rollback = gate
            .begin(
                exec::TaskId(41),
                heap::AllocationDomain::SYSTEM,
                MigrationOperationKind::Rollback,
            )
            .unwrap();

        // `Migrate` from V2Staged is the activate operation. It cannot race a
        // rollback through their shared read/scrub/write validation gap, and
        // a same-task recursive invocation is rejected identically.
        assert!(matches!(
            gate.begin(
                exec::TaskId(42),
                heap::AllocationDomain::SYSTEM,
                MigrationOperationKind::Migrate,
            ),
            Err(MigrationRunError::Busy)
        ));
        assert!(matches!(
            gate.begin(
                exec::TaskId(41),
                heap::AllocationDomain::SYSTEM,
                MigrationOperationKind::Rollback,
            ),
            Err(MigrationRunError::Busy)
        ));
        assert_eq!(
            BootStoreSelection::decode(selection.load(Ordering::Acquire)),
            Some(BootStoreSelection::LegacyM4)
        );
        drop(rollback);

        selection.store(BootStoreSelection::StorageV2.encode(), Ordering::Release);
        let close = gate
            .begin(
                exec::TaskId(43),
                heap::AllocationDomain::SYSTEM,
                MigrationOperationKind::CloseRollback,
            )
            .unwrap();
        assert!(matches!(
            gate.begin(
                exec::TaskId(44),
                heap::AllocationDomain::SYSTEM,
                MigrationOperationKind::CloseRollback,
            ),
            Err(MigrationRunError::Busy)
        ));
        assert_eq!(
            BootStoreSelection::decode(selection.load(Ordering::Acquire)),
            Some(BootStoreSelection::StorageV2)
        );
        drop(close);
    }

    #[cfg_attr(test, test)]
    pub(crate) fn terminal_task_cleanup_releases_only_its_migration_claim() {
        let gate = MigrationOperationGate::new();
        let task = exec::TaskId(51);
        let domain = heap::AllocationDomain::SYSTEM;
        let mut abandoned = gate
            .begin(task, domain, MigrationOperationKind::MigrateUntilStaged)
            .unwrap();
        // Model a faulted future whose stack will be reclaimed without normal
        // Drop, while avoiding a real allocation leak in the boot selftest.
        abandoned.armed = false;
        drop(abandoned);

        // A sibling in the same untracked SYSTEM allocation domain cannot
        // clear the abandoned operation without the exact terminal TaskId.
        // Safety: the synthetic sibling was never scheduled and is terminal.
        unsafe { gate.recover_faulted(exec::TaskId(52), domain) };
        assert!(matches!(
            gate.begin(exec::TaskId(52), domain, MigrationOperationKind::Migrate),
            Err(MigrationRunError::Busy)
        ));

        // Safety: the synthetic task identity was never scheduled and cannot
        // resume or drop the deliberately abandoned guard.
        unsafe { gate.recover_faulted(task, domain) };
        let replacement = gate
            .begin(exec::TaskId(52), domain, MigrationOperationKind::Migrate)
            .unwrap();
        drop(replacement);
    }
}

#[cfg(feature = "legacy-shell")]
pub(crate) fn run_storage_v2_transition_selftests() {
    storage_v2_transition_tests::stage_retry_accepts_only_exact_old_or_new_selector();
    storage_v2_transition_tests::rollback_requires_exact_staged_evidence_and_source_stream();
    storage_v2_transition_tests::close_preserves_activation_floor_and_accepts_newer_healthy_evidence();
    storage_v2_transition_tests::boot_proved_cache_requires_exact_selector_policy_and_uuid();
    storage_v2_transition_tests::append_failures_revoke_cache_unless_proved_pre_mutation();
    storage_v2_transition_tests::concurrent_migration_actions_are_busy_without_changing_boot_selection();
    storage_v2_transition_tests::terminal_task_cleanup_releases_only_its_migration_claim();
    storage_v2_transition_tests::hot_read_cache_has_byte_and_entry_bounds_and_clear_revokes_tokens(
    );
}

fn map_facade_error(error: V2RuntimeError) -> vibeos_object_store::StoreError {
    match error {
        V2RuntimeError::Busy => vibeos_object_store::StoreError::Busy,
        V2RuntimeError::JournalChanged => vibeos_object_store::StoreError::JournalChanged,
        V2RuntimeError::ObjectUnavailable => vibeos_object_store::StoreError::ObjectUnavailable,
        V2RuntimeError::Unformatted | V2RuntimeError::AuthorityMissing => {
            vibeos_object_store::StoreError::Unformatted
        }
        V2RuntimeError::OutsideTask | V2RuntimeError::Corrupt => {
            vibeos_object_store::StoreError::Corrupt
        }
    }
}

fn map_persistent_read_error(error: PersistentAuthorityError<PageIoError>) -> V2RuntimeError {
    match error {
        PersistentAuthorityError::Store(vibeos_segment_store::StoreError::ObjectUnavailable) => {
            V2RuntimeError::ObjectUnavailable
        }
        _ => V2RuntimeError::Corrupt,
    }
}

fn cache_metadata_matches_boot_proof(
    selection: Option<BootStoreSelection>,
    proved: bool,
    policy_sha256: [u8; 32],
    store_uuid: [u8; 16],
) -> bool {
    selection == Some(BootStoreSelection::StorageV2)
        && proved
        && crate::durable_cspace::storage_v2_recovery_policy_is_recognized(policy_sha256)
        && store_uuid == STORAGE_V2_UUID
}

fn append_error_requires_cold_recovery(error: V2RuntimeError) -> bool {
    // GenerationMismatch is checked against the mounted authority before any
    // append mutation. Every other error is conservatively ambiguous at this
    // sealed facade boundary and must revoke the boot proof.
    error != V2RuntimeError::JournalChanged
}

fn recovered_v2_snapshot(
    view: &PersistentAuthorityView,
    hot_reads: &HotReadCache,
) -> Result<vibeos_object_store::StorageV2AuthoritySnapshot, vibeos_object_store::StoreError> {
    let authority_generation = view.checkpoint_generation();
    recovered_v2_snapshot_with(
        view.record_stream(),
        view.root_policy_sha256(),
        hot_reads,
        |object| {
            view.object_for_recovered(object)
                .map(|handle| StorageV2ReadToken::Persistent {
                    handle: handle.clone(),
                    authority_generation,
                    cached: None,
                })
        },
    )
}

fn appended_v2_snapshot(
    view: &PersistentAuthorityView,
    transient: Arc<PersistentAuthorityTransientObjects>,
    hot_reads: &HotReadCache,
) -> Result<vibeos_object_store::StorageV2AuthoritySnapshot, vibeos_object_store::StoreError> {
    let authority_generation = view.checkpoint_generation();
    recovered_v2_snapshot_with(
        view.record_stream(),
        view.root_policy_sha256(),
        hot_reads,
        |object| {
            if let Some(handle) = view.object_for_recovered(object) {
                Some(StorageV2ReadToken::Persistent {
                    handle: handle.clone(),
                    authority_generation,
                    cached: None,
                })
            } else if transient.object_for_recovered(object).is_some() {
                Some(StorageV2ReadToken::Transient {
                    witness: transient.clone(),
                    recovered: system_arc(object.clone()),
                    authority_generation,
                    cached: None,
                })
            } else {
                None
            }
        },
    )
}

#[derive(Clone)]
enum StorageV2ReadToken {
    Persistent {
        handle: PersistentObjectHandle,
        authority_generation: u64,
        cached: Option<Weak<[u8]>>,
    },
    Transient {
        witness: Arc<PersistentAuthorityTransientObjects>,
        recovered: Arc<vibeos_durable_format::RecoveredObject>,
        authority_generation: u64,
        cached: Option<Weak<[u8]>>,
    },
}

impl StorageV2ReadToken {
    fn cache_verified_bytes(
        &mut self,
        recovered: &vibeos_durable_format::RecoveredObject,
        cache: &HotReadCache,
    ) {
        if recovered.is_external() {
            // External content never rides the record stream; caching the
            // empty inline bytes would serve empty reads.
            return;
        }
        match self {
            Self::Persistent { handle, cached, .. }
                if handle.object_kind() == recovered.object_kind.get()
                    && handle.exact_len() == recovered.bytes.len() as u64 =>
            {
                *cached = cache.insert(&recovered.bytes);
            }
            Self::Transient {
                recovered: token_object,
                cached,
                ..
            } if token_object.object_id == recovered.object_id
                && token_object.object_kind == recovered.object_kind
                && token_object.bytes.len() == recovered.bytes.len() =>
            {
                *cached = cache.insert(&recovered.bytes);
            }
            _ => {}
        }
    }
}

fn decode_authority_records(
    record_stream: &[u8],
) -> Result<Vec<[u8; LOGICAL_BLOCK_SIZE]>, vibeos_object_store::StoreError> {
    let record_count = record_stream.len() / LOGICAL_BLOCK_SIZE;
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| vibeos_object_store::StoreError::InsufficientMemory)?;
    for record in record_stream.chunks_exact(LOGICAL_BLOCK_SIZE) {
        records.push(
            record
                .try_into()
                .map_err(|_| vibeos_object_store::StoreError::Corrupt)?,
        );
    }
    if records.len().checked_mul(LOGICAL_BLOCK_SIZE) != Some(record_stream.len()) {
        return Err(vibeos_object_store::StoreError::Corrupt);
    }
    Ok(records)
}

fn authority_stream_checkpoint(
    record_stream: &[u8],
) -> Result<vibeos_durable_format::ChainCheckpoint, vibeos_object_store::StoreError> {
    if record_stream.is_empty() || !record_stream.len().is_multiple_of(LOGICAL_BLOCK_SIZE) {
        return Err(vibeos_object_store::StoreError::Corrupt);
    }
    let last: &[u8; LOGICAL_BLOCK_SIZE] = record_stream
        .last_chunk()
        .ok_or(vibeos_object_store::StoreError::Corrupt)?;
    let decoded = match vibeos_durable_format::LogRecord::decode(last) {
        Ok(vibeos_durable_format::DecodeStatus::Valid(decoded)) => decoded,
        _ => return Err(vibeos_object_store::StoreError::Corrupt),
    };
    Ok(vibeos_durable_format::ChainCheckpoint {
        next_sequence: decoded
            .record
            .sequence
            .checked_add(1)
            .ok_or(vibeos_object_store::StoreError::Corrupt)?,
        previous_sequence: decoded.record.sequence,
        previous_crc32c: decoded.crc32c,
    })
}

fn recovered_v2_snapshot_with(
    record_stream: &[u8],
    external_root_policy_sha256: [u8; 32],
    hot_reads: &HotReadCache,
    resolve: impl Fn(&vibeos_durable_format::RecoveredObject) -> Option<StorageV2ReadToken>,
) -> Result<vibeos_object_store::StorageV2AuthoritySnapshot, vibeos_object_store::StoreError> {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let result = build_recovered_v2_snapshot(
        record_stream,
        external_root_policy_sha256,
        hot_reads,
        resolve,
    );
    system.restore();
    result
}

fn build_recovered_v2_snapshot(
    record_stream: &[u8],
    external_root_policy_sha256: [u8; 32],
    hot_reads: &HotReadCache,
    resolve: impl Fn(&vibeos_durable_format::RecoveredObject) -> Option<StorageV2ReadToken>,
) -> Result<vibeos_object_store::StorageV2AuthoritySnapshot, vibeos_object_store::StoreError> {
    use vibeos_durable_format::StoreId;

    let records = decode_authority_records(record_stream)?;
    let store_id = StoreId::new(M4_STORE_ID_RAW).expect("fixed M4 store ID is non-zero");
    let preflight = vibeos_durable_format::preflight_recovery(&records, store_id)
        .map_err(|_| vibeos_object_store::StoreError::Corrupt)?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(preflight.committed_objects().len())
        .map_err(|_| vibeos_object_store::StoreError::InsufficientMemory)?;
    for recovered in preflight.committed_objects() {
        if let Some(mut token) = resolve(recovered) {
            token.cache_verified_bytes(recovered, hot_reads);
            objects.push(vibeos_object_store::StorageV2RecoveredObject::new(
                recovered,
                vibeos_object_store::StorageV2ObjectToken::new(token),
            ));
        }
    }
    vibeos_object_store::StorageV2AuthoritySnapshot::new(
        records.len(),
        preflight,
        external_root_policy_sha256,
        objects,
    )
}

impl vibeos_object_store::StorageV2Backend for StorageV2Runtime {
    fn selection(&self) -> vibeos_object_store::StorageBackendSelection {
        let installed = INSTALLED_V2_RUNTIME.lock();
        if installed
            .as_ref()
            .is_none_or(|runtime| !core::ptr::eq(runtime.as_ref(), self))
        {
            return vibeos_object_store::StorageBackendSelection::FailClosed;
        }
        let selection = BootStoreSelection::decode(self.boot_selection.load(Ordering::Acquire));
        match selection {
            None => vibeos_object_store::StorageBackendSelection::Pending,
            Some(BootStoreSelection::Blank | BootStoreSelection::LegacyM4) => {
                vibeos_object_store::StorageBackendSelection::LegacyM4
            }
            Some(BootStoreSelection::StorageV2) => {
                vibeos_object_store::StorageBackendSelection::StorageV2
            }
            Some(BootStoreSelection::FailClosed) => {
                vibeos_object_store::StorageBackendSelection::FailClosed
            }
        }
    }

    fn info(&self) -> vibeos_object_store::StorageV2BackendInfo {
        let info = *self.last_info.lock();
        let view = self.authority_view();
        vibeos_object_store::StorageV2BackendInfo {
            ready: info.is_some() && view.is_some(),
            busy: self.active.lock().is_some(),
            allocated_segments: info.map_or(0, |info| info.allocated_segments as usize),
            recovered_objects: view.as_ref().map_or(0, |view| view.objects().len()),
            checkpoint_generation: view.as_ref().map_or(0, |view| view.checkpoint_generation()),
        }
    }

    fn recover_authority(
        &self,
    ) -> vibeos_object_store::StorageV2Future<'_, vibeos_object_store::StorageV2AuthoritySnapshot>
    {
        Box::pin(async move {
            let runtime = INSTALLED_V2_RUNTIME
                .lock()
                .as_ref()
                .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                .cloned()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            let view = runtime
                .boot_proved_authority()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            recovered_v2_snapshot(&view, &runtime.hot_reads)
        })
    }

    fn readback_authority(
        &self,
    ) -> vibeos_object_store::StorageV2Future<'_, vibeos_object_store::StorageV2AuthoritySnapshot>
    {
        Box::pin(async move {
            let runtime = INSTALLED_V2_RUNTIME
                .lock()
                .as_ref()
                .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                .cloned()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            // A media postflight may only begin from the same selected,
            // boot-proved authority which minted the facade provenance. The
            // digest is comparison evidence, not a component-policy claim.
            let proved = runtime
                .boot_proved_authority()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            let expected_policy_sha256 = proved.root_policy_sha256();
            drop(proved);
            let view = runtime
                .readback_persistent_authority_from_media(expected_policy_sha256)
                .await
                .map_err(map_facade_error)?;
            match recovered_v2_snapshot(&view, &runtime.hot_reads) {
                Ok(snapshot) => Ok(snapshot),
                Err(error) => {
                    runtime.invalidate_recovery_cache();
                    Err(error)
                }
            }
        })
    }

    fn append_authority<'a>(
        &'a self,
        expected: vibeos_durable_format::ChainCheckpoint,
        records: &'a [[u8; LOGICAL_BLOCK_SIZE]],
    ) -> vibeos_object_store::StorageV2Future<'a, vibeos_object_store::StorageV2AuthoritySnapshot>
    {
        self.append_authority_with_payload(expected, records, None)
    }

    fn append_authority_bound_to_policy<'a>(
        &'a self,
        expected: vibeos_durable_format::ChainCheckpoint,
        expected_external_root_policy_sha256: [u8; 32],
        records: &'a [[u8; LOGICAL_BLOCK_SIZE]],
    ) -> vibeos_object_store::StorageV2Future<'a, vibeos_object_store::StorageV2AuthoritySnapshot>
    {
        Box::pin(async move {
            let runtime = INSTALLED_V2_RUNTIME
                .lock()
                .as_ref()
                .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                .cloned()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            let mut operation = match runtime.begin() {
                Ok(operation) => operation,
                Err(error) => {
                    // Consuming the linear facade must not leave mintable
                    // predecessor proof even when the exclusive epoch cannot
                    // be acquired. A concurrently completing cold proof may
                    // establish a genuinely fresh replacement; ordinary
                    // operations cannot restore the revoked boot-proof bit.
                    // This branch owns no mutation epoch, so it must not touch
                    // the page cache or any other recovery state.
                    runtime.revoke_boot_proof_without_epoch();
                    return Err(map_facade_error(error));
                }
            };
            let result = async {
                // The caller cannot reflect a legacy or unknown digest into the
                // guard. This exact constant is independently frozen in kernel
                // policy, while object-store carries only its comparison digest.
                if expected_external_root_policy_sha256
                    != crate::durable_cspace::storage_v2_component_external_policy_sha256()
                    || BootStoreSelection::decode(runtime.boot_selection.load(Ordering::Acquire))
                        != Some(BootStoreSelection::StorageV2)
                {
                    return Err(vibeos_object_store::StoreError::Corrupt);
                }
                let predecessor = runtime
                    .boot_proved_authority()
                    .ok_or(vibeos_object_store::StoreError::Corrupt)?;
                if predecessor.root_policy_sha256() != expected_external_root_policy_sha256 {
                    return Err(vibeos_object_store::StoreError::Corrupt);
                }
                if authority_stream_checkpoint(predecessor.record_stream())? != expected {
                    return Err(vibeos_object_store::StoreError::JournalChanged);
                }
                drop(predecessor);

                // Capacity preparation and the authority append intentionally
                // retain this same ActiveV2Operation. No maintenance writer can
                // replace the policy between the comparison above and either
                // class of physical mutation.
                runtime
                    .ensure_foreground_capacity_for_operation(
                        &mut operation,
                        STORAGE_V2_FOREGROUND_FREE_SEGMENTS,
                    )
                    .await
                    .map_err(map_facade_error)?;
                let current = runtime
                    .boot_proved_authority()
                    .ok_or(vibeos_object_store::StoreError::Corrupt)?;
                if current.root_policy_sha256() != expected_external_root_policy_sha256 {
                    return Err(vibeos_object_store::StoreError::Corrupt);
                }
                if authority_stream_checkpoint(current.record_stream())? != expected {
                    return Err(vibeos_object_store::StoreError::JournalChanged);
                }

                let mut stream_records = Vec::new();
                stream_records
                    .try_reserve_exact(
                        current.record_stream().len() / LOGICAL_BLOCK_SIZE + records.len(),
                    )
                    .map_err(|_| vibeos_object_store::StoreError::InsufficientMemory)?;
                for bytes in current.record_stream().chunks_exact(LOGICAL_BLOCK_SIZE) {
                    stream_records.push(
                        bytes
                            .try_into()
                            .map_err(|_| vibeos_object_store::StoreError::Corrupt)?,
                    );
                }
                stream_records.extend_from_slice(records);
                let cached_preflight = runtime.preflight_cache.lock().take();
                let (import, preflight_cache) =
                    crate::durable_cspace::storage_v2_migration_import_incremental_for_policy(
                        &stream_records,
                        records.len(),
                        expected,
                        cached_preflight,
                        expected_external_root_policy_sha256,
                    )
                    .map_err(|_| vibeos_object_store::StoreError::Corrupt)?;
                drop(stream_records);
                let principal = current
                    .principals()
                    .first()
                    .filter(|_| current.principals().len() == 1)
                    .cloned()
                    .ok_or(vibeos_object_store::StoreError::Corrupt)?;
                let appended = runtime
                    .append_persistent_authority_in_operation(
                        &mut operation,
                        current.checkpoint_generation(),
                        import,
                        principal,
                    )
                    .await
                    .map_err(map_facade_error)?;
                let (view, transient) = appended.into_parts();
                if view.root_policy_sha256() != expected_external_root_policy_sha256 {
                    return Err(vibeos_object_store::StoreError::Corrupt);
                }
                let transient = system_arc(transient);
                let snapshot = match appended_v2_snapshot(&view, transient, &runtime.hot_reads) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        runtime.invalidate_recovery_cache();
                        return Err(error);
                    }
                };
                *runtime.preflight_cache.lock() = Some(preflight_cache);
                runtime.publish_authority(view);
                // C7.4 is one initial installation. Avoid a second, separately
                // guarded compaction write after this exact policy-bound epoch;
                // boot-boundary compaction remains available on the next cold
                // proof if the general threshold is ever reached.
                Ok(snapshot)
            }
            .await;
            if result.is_err() {
                // The sealed transition is linear across every failure, even
                // one proved before the first write. Revoke the cached boot
                // proof while this exact V2/page-device epoch is still held,
                // so another facade recovery cannot mint replacement
                // provenance without a fresh cold media proof.
                runtime.invalidate_recovery_cache();
            }
            operation.finish();
            result
        })
    }

    fn append_authority_with_payload<'a>(
        &'a self,
        expected: vibeos_durable_format::ChainCheckpoint,
        records: &'a [[u8; LOGICAL_BLOCK_SIZE]],
        external_payload: Option<(u128, &'a [u8])>,
    ) -> vibeos_object_store::StorageV2Future<'a, vibeos_object_store::StorageV2AuthoritySnapshot>
    {
        Box::pin(async move {
            let runtime = INSTALLED_V2_RUNTIME
                .lock()
                .as_ref()
                .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                .cloned()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            // Keep the cleaner off the commit path: while the device still has
            // growth capability, capacity relief happens through bounded store
            // growth instead of a blocking foreground collection inside the
            // append; once growth is exhausted, a budgeted collection runs at
            // the free-segment floor. Either transition advances the
            // checkpoint generation while preserving the logical stream, so
            // it must complete before this append captures its generation
            // witness. Failure here is not fatal by itself; a true capacity
            // condition still fails the append closed below.
            let required_free = external_payload
                .map(|(_, payload)| {
                    // An external payload consumes roughly a segment per
                    // 4 MiB plus metadata; the quota admission additionally
                    // requires that much ordinary capacity to be free before
                    // the reservation, so replenish to the whole appetite.
                    (payload.len() as u64)
                        .div_ceil(STORAGE_V2_GROWTH_GRANULE_BLOCKS * LOGICAL_BLOCK_SIZE as u64)
                        .saturating_add(8)
                })
                .unwrap_or(STORAGE_V2_FOREGROUND_FREE_SEGMENTS);
            let _ = runtime.ensure_foreground_capacity_for(required_free).await;
            let current = runtime
                .authority_view()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            #[cfg(feature = "storage-bench")]
            let phase_started = crate::sbi::time();
            let mut stream_records = Vec::new();
            stream_records
                .try_reserve_exact(
                    current.record_stream().len() / LOGICAL_BLOCK_SIZE + records.len(),
                )
                .map_err(|_| vibeos_object_store::StoreError::InsufficientMemory)?;
            for bytes in current.record_stream().chunks_exact(LOGICAL_BLOCK_SIZE) {
                stream_records.push(
                    bytes
                        .try_into()
                        .map_err(|_| vibeos_object_store::StoreError::Corrupt)?,
                );
            }
            // The published stream was fully validated when it was recovered or
            // appended; the concurrency guard only needs the chain checkpoint,
            // which one decode of the final record yields.
            let last_record = stream_records
                .last()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            let decoded = match vibeos_durable_format::LogRecord::decode(last_record) {
                Ok(vibeos_durable_format::DecodeStatus::Valid(decoded)) => decoded,
                _ => return Err(vibeos_object_store::StoreError::Corrupt),
            };
            let observed = vibeos_durable_format::ChainCheckpoint {
                next_sequence: decoded
                    .record
                    .sequence
                    .checked_add(1)
                    .ok_or(vibeos_object_store::StoreError::Corrupt)?,
                previous_sequence: decoded.record.sequence,
                previous_crc32c: decoded.crc32c,
            };
            if observed != expected {
                return Err(vibeos_object_store::StoreError::JournalChanged);
            }
            stream_records.extend_from_slice(records);
            #[cfg(feature = "storage-bench")]
            let phase_preflight = crate::sbi::time();
            let cached_preflight = self.preflight_cache.lock().take();
            let (mut import, preflight_cache) =
                crate::durable_cspace::storage_v2_migration_import_incremental_for_policy(
                    &stream_records,
                    records.len(),
                    expected,
                    cached_preflight,
                    current.root_policy_sha256(),
                )
                .map_err(|_error| {
                    #[cfg(feature = "storage-bench")]
                    crate::println!("  bench-detail migration import error: {_error:?}");
                    vibeos_object_store::StoreError::Corrupt
                })?;
            if let Some((stable_object_id, payload)) = external_payload {
                // The payload copy lives exactly as long as the installation
                // and can reach 64 MiB; charge it to the system heap beside
                // the store's own staging buffers, not the client budget.
                let mut system = heap::enter_owner(OwnerId::SYSTEM);
                let mut owned = Vec::new();
                let reserved = owned.try_reserve_exact(payload.len());
                if reserved.is_ok() {
                    owned.extend_from_slice(payload);
                }
                system.restore();
                if reserved.is_err() {
                    #[cfg(feature = "storage-bench")]
                    crate::println!("  bench-detail external payload copy oom");
                    return Err(vibeos_object_store::StoreError::InsufficientMemory);
                }
                import
                    .attach_external_payload(stable_object_id, owned)
                    .map_err(|_error| {
                        #[cfg(feature = "storage-bench")]
                        crate::println!("  bench-detail attach error: {_error:?}");
                        vibeos_object_store::StoreError::Corrupt
                    })?;
            }
            let import = import;
            #[cfg(feature = "storage-bench")]
            let phase_import = crate::sbi::time();
            // The import owns its own validated copy; release the raw stream
            // buffer before the append's peak transient allocations.
            drop(stream_records);
            let principal = current
                .principals()
                .first()
                .filter(|_| current.principals().len() == 1)
                .cloned()
                .ok_or(vibeos_object_store::StoreError::Corrupt)?;
            let appended = runtime
                .append_persistent_authority(current.checkpoint_generation(), import, principal)
                .await
                .map_err(map_facade_error)?;
            #[cfg(feature = "storage-bench")]
            let phase_append = crate::sbi::time();
            let (view, transient) = appended.into_parts();
            let transient = system_arc(transient);
            // Steady-state compaction: an oversized logical journal is
            // rewritten to its live equivalent and installed as a
            // replacement checkpoint. Token resolution binds stable object
            // ids, so the snapshot below stays valid either way; the
            // just-appended (still ungranted) objects resolve through the
            // transient witness.
            let compacted_view = runtime.maybe_compact_authority(&view).await?;
            if compacted_view.is_none() {
                // The appended stream is now the published stream; retain its
                // validated replay for the next strict extension. A compacted
                // replacement rewrites the chain, so its cache would never
                // match and is not worth holding.
                *runtime.preflight_cache.lock() = Some(preflight_cache);
            }
            let snapshot_view: &PersistentAuthorityView = match compacted_view.as_deref() {
                Some(replacement) => replacement,
                None => &view,
            };
            let snapshot = match appended_v2_snapshot(snapshot_view, transient, &runtime.hot_reads)
            {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    runtime.invalidate_recovery_cache();
                    return Err(error);
                }
            };
            if compacted_view.is_none() {
                runtime.publish_authority(view);
            }
            #[cfg(feature = "storage-bench")]
            {
                let phase_publish = crate::sbi::time();
                crate::println!(
                    "  bench-phase preflight={} import={} append={} publish={}",
                    phase_preflight.saturating_sub(phase_started),
                    phase_import.saturating_sub(phase_preflight),
                    phase_append.saturating_sub(phase_import),
                    phase_publish.saturating_sub(phase_append),
                );
            }
            Ok(snapshot)
        })
    }

    fn read_object<'a>(
        &'a self,
        object: &'a vibeos_object_store::StorageV2ObjectToken,
    ) -> vibeos_object_store::StorageV2Future<'a, Vec<u8>> {
        Box::pin(async move {
            let installed_current = {
                let installed = INSTALLED_V2_RUNTIME.lock();
                installed
                    .as_ref()
                    .is_some_and(|runtime| core::ptr::eq(runtime.as_ref(), self))
            };
            if !installed_current {
                return Err(vibeos_object_store::StoreError::Corrupt);
            }
            let token = object
                .downcast_ref::<StorageV2ReadToken>()
                .ok_or(vibeos_object_store::StoreError::ObjectUnavailable)?;
            match token {
                StorageV2ReadToken::Persistent {
                    handle,
                    authority_generation,
                    cached,
                } => {
                    if let Some(bytes) = cached.as_ref() {
                        if let Some(output) = self.read_hot_bytes(bytes, *authority_generation)? {
                            return Ok(output);
                        }
                    }
                    let runtime = INSTALLED_V2_RUNTIME
                        .lock()
                        .as_ref()
                        .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                        .cloned()
                        .ok_or(vibeos_object_store::StoreError::Corrupt)?;
                    runtime
                        .read_persistent_object(handle)
                        .await
                        .map_err(map_facade_error)
                }
                StorageV2ReadToken::Transient {
                    witness,
                    recovered,
                    authority_generation,
                    cached,
                } => {
                    if let Some(bytes) = cached.as_ref() {
                        if let Some(output) = self.read_hot_bytes(bytes, *authority_generation)? {
                            return Ok(output);
                        }
                    }
                    let runtime = INSTALLED_V2_RUNTIME
                        .lock()
                        .as_ref()
                        .filter(|runtime| core::ptr::eq(runtime.as_ref(), self))
                        .cloned()
                        .ok_or(vibeos_object_store::StoreError::Corrupt)?;
                    runtime
                        .read_transient_object(witness, recovered)
                        .await
                        .map_err(map_facade_error)
                }
            }
        })
    }
}

impl PageDevice for &CapabilityPageDevice {
    type Error = PageIoError;

    fn info(&self) -> PageDeviceInfo {
        (*self).info()
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        (*self).read_page(page, output).await
    }

    async fn write_page(&self, page: u64, input: &Page) -> MutationResult<(), Self::Error> {
        (*self).write_page(page, input).await
    }

    async fn read_pages(&self, first_page: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        (*self).read_pages(first_page, output).await
    }

    async fn write_pages(
        &self,
        first_page: u64,
        input: &[Page],
    ) -> MutationResult<(), Self::Error> {
        (*self).write_pages(first_page, input).await
    }

    async fn flush(&self) -> MutationResult<(), Self::Error> {
        (*self).flush().await
    }
}

impl PageDevice for CapabilityPageDevice {
    type Error = PageIoError;

    fn info(&self) -> PageDeviceInfo {
        *self.info.lock()
    }

    async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
        if self.page_cache.get(page, output) {
            page_cache_account(1, 1);
            return Ok(());
        }
        page_cache_account(1, 0);
        let first = self.first_sector(page)?;
        let lease = self.lease(Rights::READ)?;
        let session = block_device::range_info_with(&lease)
            .map_err(PageIoError::Block)?
            .session();
        self.require_session(session)?;
        block_device::read_blocks_with_session(
            &lease,
            session,
            first,
            BLOCKS_PER_PAGE as u32,
            output,
        )
        .await
        .map_err(PageIoError::Block)?;
        self.page_cache.insert(page, output);
        Ok(())
    }

    async fn write_page(&self, page: u64, input: &Page) -> MutationResult<(), Self::Error> {
        // Drop the stale entry before the mutation may reach media; the fresh
        // content is re-inserted only after an unambiguous success.
        self.page_cache.invalidate(page, 1);
        let first = self
            .first_sector(page)
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;
        let lease = self
            .lease(Rights::WRITE)
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;
        let session = block_device::begin_mutation(&lease)
            .map_err(|failure| self.compose_mutation_failure(failure.map(PageIoError::Block)))?;
        self.require_session(session.device_session())
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;

        let result = block_device::write_blocks_with_session(
            &lease,
            session,
            first,
            BLOCKS_PER_PAGE as u32,
            input,
            false,
        )
        .await
        .map(|_| ())
        .map_err(|failure| failure.map(PageIoError::Block));
        match result {
            Ok(()) => self.mark_mutation_submitted(),
            Err(failure) => return Err(self.compose_mutation_failure(failure)),
        }
        self.page_cache.insert(page, input);
        Ok(())
    }

    async fn read_pages(&self, first_page: u64, output: &mut [Page]) -> Result<(), Self::Error> {
        if output.is_empty() {
            return Ok(());
        }
        let all_cached = output
            .iter_mut()
            .enumerate()
            .all(|(index, page)| self.page_cache.get(first_page + index as u64, page));
        page_cache_account(
            output.len() as u64,
            if all_cached { output.len() as u64 } else { 0 },
        );
        if all_cached {
            return Ok(());
        }
        let first = self.page_range_first_sector(first_page, output.len())?;
        let lease = self.lease(Rights::READ)?;
        let session = block_device::range_info_with(&lease)
            .map_err(PageIoError::Block)?
            .session();
        self.require_session(session)?;
        for (chunk_index, chunk) in output.chunks_mut(MAX_PAGES_PER_REQUEST).enumerate() {
            let page_offset = chunk_index
                .checked_mul(MAX_PAGES_PER_REQUEST)
                .ok_or(PageIoError::InvalidRange)?;
            let block_offset = (page_offset as u64)
                .checked_mul(BLOCKS_PER_PAGE)
                .ok_or(PageIoError::InvalidRange)?;
            let block_count = u32::try_from(chunk.len())
                .ok()
                .and_then(|count| count.checked_mul(BLOCKS_PER_PAGE as u32))
                .ok_or(PageIoError::InvalidRange)?;
            block_device::read_blocks_with_session(
                &lease,
                session,
                first
                    .checked_add(block_offset)
                    .ok_or(PageIoError::InvalidRange)?,
                block_count,
                chunk.as_flattened_mut(),
            )
            .await
            .map_err(PageIoError::Block)?;
        }
        for (index, page) in output.iter().enumerate() {
            self.page_cache.insert(first_page + index as u64, page);
        }
        Ok(())
    }

    async fn write_pages(
        &self,
        first_page: u64,
        input: &[Page],
    ) -> MutationResult<(), Self::Error> {
        if input.is_empty() {
            return Ok(());
        }
        // Drop stale entries before any chunk may reach media; fresh content
        // is re-inserted only after the whole run succeeds unambiguously.
        self.page_cache.invalidate(first_page, input.len());
        let first = self
            .page_range_first_sector(first_page, input.len())
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;
        {
            let lease = self
                .lease(Rights::WRITE)
                .map_err(MutationFailure::not_submitted)
                .map_err(|failure| self.compose_mutation_failure(failure))?;
            let session = block_device::begin_mutation(&lease).map_err(|failure| {
                self.compose_mutation_failure(failure.map(PageIoError::Block))
            })?;
            self.require_session(session.device_session())
                .map_err(MutationFailure::not_submitted)
                .map_err(|failure| self.compose_mutation_failure(failure))?;
            for (chunk_index, chunk) in input.chunks(MAX_PAGES_PER_REQUEST).enumerate() {
                let page_offset = chunk_index
                    .checked_mul(MAX_PAGES_PER_REQUEST)
                    .ok_or_else(|| MutationFailure::not_submitted(PageIoError::InvalidRange))
                    .map_err(|failure| self.compose_mutation_failure(failure))?;
                let block_offset = (page_offset as u64)
                    .checked_mul(BLOCKS_PER_PAGE)
                    .ok_or_else(|| MutationFailure::not_submitted(PageIoError::InvalidRange))
                    .map_err(|failure| self.compose_mutation_failure(failure))?;
                let block_count = u32::try_from(chunk.len())
                    .ok()
                    .and_then(|count| count.checked_mul(BLOCKS_PER_PAGE as u32))
                    .ok_or_else(|| MutationFailure::not_submitted(PageIoError::InvalidRange))
                    .map_err(|failure| self.compose_mutation_failure(failure))?;
                let result = block_device::write_blocks_with_session(
                    &lease,
                    session,
                    first
                        .checked_add(block_offset)
                        .ok_or_else(|| MutationFailure::not_submitted(PageIoError::InvalidRange))
                        .map_err(|failure| self.compose_mutation_failure(failure))?,
                    block_count,
                    chunk.as_flattened(),
                    false,
                )
                .await
                .map(|_| ())
                .map_err(|failure| failure.map(PageIoError::Block));
                match result {
                    Ok(()) => self.mark_mutation_submitted(),
                    Err(failure) => return Err(self.compose_mutation_failure(failure)),
                }
            }
            for (index, page) in input.iter().enumerate() {
                self.page_cache.insert(first_page + index as u64, page);
            }
            Ok(())
        }
    }

    async fn flush(&self) -> MutationResult<(), Self::Error> {
        let lease = self
            .lease(Rights::WRITE)
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;
        let session = block_device::begin_mutation(&lease)
            .map_err(|failure| self.compose_mutation_failure(failure.map(PageIoError::Block)))?;
        self.require_session(session.device_session())
            .map_err(MutationFailure::not_submitted)
            .map_err(|failure| self.compose_mutation_failure(failure))?;
        let result = block_device::flush_with_session(&lease, session)
            .await
            .map_err(|failure| self.compose_mutation_failure(failure.map(PageIoError::Block)));
        if result.is_ok() {
            self.clear_submitted_mutation();
        }
        result
    }
}

impl GrowablePageDevice for CapabilityPageDevice {
    fn validate_growth(
        &self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<(), Self::Error> {
        let additional_blocks = additional.range().block_count();
        let expected = self
            .growth_capability_bounded(durable_logical_block_count, additional_blocks)?
            .ok_or(PageIoError::InvalidRange)?;
        if expected != additional {
            return Err(PageIoError::InvalidRange);
        }
        Ok(())
    }

    fn admit_growth(
        &mut self,
        durable_logical_block_count: u64,
        additional: BlockRangeCapability,
    ) -> Result<PageDeviceInfo, Self::Error> {
        self.validate_growth(durable_logical_block_count, additional)?;
        let enlarged = durable_logical_block_count
            .checked_add(additional.range().block_count())
            .ok_or(PageIoError::InvalidRange)?;
        if enlarged > self.provisioned_block_count {
            return Err(PageIoError::InvalidRange);
        }
        self.expose_block_count(enlarged);
        Ok(self.info())
    }
}
