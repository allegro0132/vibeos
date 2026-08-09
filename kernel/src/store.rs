//! Capability-addressed persistent object store.
//!
//! The public surface deliberately has no path or `ObjectId` lookup.  A caller
//! needs a `StoreService` capability for the operation and a `StoredObject`
//! capability for every read.  Stable IDs remain private journal details.
//!
//! The unified durable journal is bounded to sectors 64..576 so recovery work
//! cannot grow with the remainder of the block device.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};

use vibeos_core::durable::{ObjectId, StoreId, TransactionId};
use vibeos_core::store as journal;

use crate::cap::{Cap, CapError, InvocationLease, Resource, Rights};
use crate::exec::{self, TaskId};
use crate::heap::{self, AllocationDomain, OwnerId};
use crate::sync::SpinLock;
use crate::virtio_blk::{self, BlockDevice, BlockError};
use crate::world::Space;

/// The persistent journal is isolated from the block-driver acceptance sectors
/// and deliberately bounded so boot-time recovery cannot monopolize the hart.
pub const STORE_FIRST_SECTOR: u64 = 64;
pub const STORE_END_SECTOR: u64 = 576;
pub const STORE_LOG_SECTORS: usize = (STORE_END_SECTOR - STORE_FIRST_SECTOR) as usize;

/// Conservative dynamic working-set floor for decoding every record in the
/// fixed journal. The caller's already-live payload/future is outside this
/// allowance. Refuse before taking the single-writer claim when a bounded
/// component cannot supply it, rather than quota-faulting mid-operation.
pub const STORE_WORKING_HEADROOM: usize = 4 * 1024 * 1024;

/// Budget used by the current interactive client and the audited fault probe.
/// It leaves room for their own future/payload plus the recovery floor above.
pub const STORE_CLIENT_MEMORY_BUDGET: usize = 8 * 1024 * 1024;

// Stable platform trust anchor for this object journal.  VibeOS has no entropy
// source yet, so this is intentionally a fixed, documented value rather than a
// boot-local counter pretending to be globally unique.
const STORE_ID_RAW: u128 = 0x5649_4245_4f53_2d53_544f_5245_2d4d_3401;
const FIRST_ALLOCATABLE_ID: u128 = 1;

const STORED_OBJECT_RIGHTS: Rights = Rights::READ.union(Rights::GRANT).union(Rights::REVOKE);

fn store_id() -> StoreId {
    StoreId::new(STORE_ID_RAW).expect("the fixed object-store ID is non-zero")
}

/// Construct a stable content-type tag without exposing any object identity or
/// lookup mechanism. Zero remains reserved by the durable format.
pub const fn journal_object_kind(value: u32) -> Option<journal::ObjectKind> {
    journal::ObjectKind::new(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    PermissionDenied,
    Busy,
    BackendAuthority,
    Backend(BlockError),
    DeviceTooSmall,
    ReadOnly,
    FlushUnsupported,
    JournalFull,
    Unformatted,
    Corrupt,
    ObjectTooLarge,
    IdExhausted,
    PublicationTargetRestarted,
    ObjectUnavailable,
    ObjectMismatch,
    InsufficientMemory,
    OutsideTask,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(error) => write!(f, "object-store block I/O failed: {error}"),
            _ => f.write_str(match self {
                Self::PermissionDenied => "store capability lacks the required right",
                Self::Busy => "object store already has an active operation",
                Self::BackendAuthority => "object store lost its block capability",
                Self::DeviceTooSmall => "block device is too small for the object journal",
                Self::ReadOnly => "object store requires a writable block device",
                Self::FlushUnsupported => "object store requires ordered flush support",
                Self::JournalFull => "object journal is full",
                Self::Unformatted => "object journal is not formatted",
                Self::Corrupt => "object journal failed closed during recovery",
                Self::ObjectTooLarge => "object is too large for the journal format",
                Self::IdExhausted => "object-store stable ID space is exhausted",
                Self::PublicationTargetRestarted => {
                    "target CSpace restarted before the object capability was published"
                }
                Self::ObjectUnavailable => "stored object is absent from the recovered journal",
                Self::ObjectMismatch => "committed object failed read-back verification",
                Self::InsufficientMemory => {
                    "store caller lacks the bounded journal-recovery headroom"
                }
                Self::OutsideTask => "store operations require an executor task context",
                Self::Backend(_) => unreachable!(),
            }),
        }
    }
}

impl From<BlockError> for StoreError {
    fn from(error: BlockError) -> Self {
        Self::Backend(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreInfo {
    pub ready: bool,
    pub busy: bool,
    pub used_sectors: usize,
    pub recovered_objects: usize,
    pub id_high_water: u128,
    pub last_sequence: u64,
}

#[derive(Clone, Copy)]
struct RuntimeState {
    ready: bool,
    used_sectors: usize,
    recovered_objects: usize,
    id_high_water: u128,
    last_sequence: u64,
}

impl RuntimeState {
    const COLD: Self = Self {
        ready: false,
        used_sectors: 0,
        recovered_objects: 0,
        id_high_water: 0,
        last_sequence: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActiveClaim {
    task: TaskId,
    domain: AllocationDomain,
    token: u64,
}

#[derive(Clone, Copy)]
struct FaultTarget {
    task: TaskId,
    domain: AllocationDomain,
}

/// One fixed `.bss` scan buffer shared by all invocations. The active claim is
/// the exclusive-access proof. A faulted invocation is detached before its
/// claim is recovered, and the next scan overwrites every element before use.
/// Keeping this platform workspace out of the dynamic heap also means a raw
/// fault cannot strand allocator ownership or inflate component/bench peaks.
struct StableScratch(UnsafeCell<[[u8; journal::RECORD_SIZE]; STORE_LOG_SECTORS]>);

// Safety: the single active claim serializes every access. No reference into
// the array is retained across an await or published to a client.
unsafe impl Sync for StableScratch {}

impl StableScratch {
    const fn new() -> Self {
        Self(UnsafeCell::new(
            [[0u8; journal::RECORD_SIZE]; STORE_LOG_SECTORS],
        ))
    }

    fn write(&self, offset: usize, bytes: [u8; journal::RECORD_SIZE]) {
        debug_assert!(offset < STORE_LOG_SECTORS);
        // Safety: callers hold the sole active store claim and this borrow ends
        // before the next block operation can await.
        unsafe { (&mut *self.0.get())[offset] = bytes };
    }

    fn sectors(&self) -> &[[u8; journal::RECORD_SIZE]] {
        // Safety: recovery is synchronous and runs under the sole active claim;
        // scan_region has overwritten the complete vector immediately before.
        unsafe { (&*self.0.get()).as_slice() }
    }
}

static STORE_SCRATCH: StableScratch = StableScratch::new();

struct StoreInner {
    /// Dedicated backend CSpace.  It should contain only the attenuated block
    /// grant supplied at construction time.
    backend: Arc<Space>,
    block: Cap,
    active: SpinLock<Option<ActiveClaim>>,
    state: SpinLock<RuntimeState>,
}

static INSTALLED_STORE: SpinLock<Option<Arc<StoreInner>>> = SpinLock::new(None);
static NEXT_ACTIVE_TOKEN: AtomicU64 = AtomicU64::new(1);
static FAULT_REACHED: AtomicU64 = AtomicU64::new(0);

impl StoreInner {
    fn begin(self: &Arc<Self>) -> Result<StoreOperation, StoreError> {
        let domain = heap::current_domain();
        let task = exec::current_task_id().ok_or(StoreError::OutsideTask)?;
        let token = NEXT_ACTIVE_TOKEN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .expect("object-store operation token space exhausted");
        let mut active = self.active.lock();
        if active.is_some() {
            return Err(StoreError::Busy);
        }
        *active = Some(ActiveClaim {
            task,
            domain,
            token,
        });
        drop(active);
        Ok(StoreOperation {
            inner: self.clone(),
            task,
            domain,
            token,
            armed: true,
        })
    }

    fn clear(&self, task: TaskId, domain: AllocationDomain, token: u64) -> bool {
        let mut active = self.active.lock();
        if active.is_some_and(|claim| {
            claim.task == task && claim.domain == domain && claim.token == token
        }) {
            *active = None;
            true
        } else {
            false
        }
    }

    fn info(&self) -> StoreInfo {
        let state = *self.state.lock();
        StoreInfo {
            ready: state.ready,
            busy: self.active.lock().is_some(),
            used_sectors: state.used_sectors,
            recovered_objects: state.recovered_objects,
            id_high_water: state.id_high_water,
            last_sequence: state.last_sequence,
        }
    }

    fn install_recovery(&self, recovered: &journal::RecoveredStore, used_sectors: usize) {
        *self.state.lock() = RuntimeState {
            ready: true,
            used_sectors,
            recovered_objects: recovered.objects.len(),
            id_high_water: recovered.id_high_water,
            last_sequence: recovered.last_sequence,
        };
    }
}

/// Clears the single-operation claim on every ordinary return, error, or async
/// cancellation.  No journal cursor is cached, so the next operation always
/// re-scans physical media and cannot trust partially advanced in-memory state.
struct StoreOperation {
    inner: Arc<StoreInner>,
    task: TaskId,
    domain: AllocationDomain,
    token: u64,
    armed: bool,
}

impl StoreOperation {
    fn finish(mut self) {
        assert!(
            self.inner.clear(self.task, self.domain, self.token),
            "only the exact store invocation may release its active claim"
        );
        self.armed = false;
    }
}

impl Drop for StoreOperation {
    fn drop(&mut self) {
        if self.armed {
            assert!(
                self.inner.clear(self.task, self.domain, self.token),
                "a stale store guard must not clear a newer active claim"
            );
        }
    }
}

/// Authority to operate the object store.  The raw backend cap is private and
/// is resolved afresh for each individual block request.
pub struct StoreService {
    inner: Arc<StoreInner>,
}

impl StoreService {
    pub fn new(backend: Arc<Space>, block: Cap) -> Arc<Self> {
        let inner = system_allocation(|| {
            Arc::new(StoreInner {
                backend,
                block,
                active: SpinLock::new(None),
                state: SpinLock::new(RuntimeState::COLD),
            })
        });
        {
            let mut installed = INSTALLED_STORE.lock();
            assert!(
                installed.is_none(),
                "only one persistent store may own the journal"
            );
            *installed = Some(inner.clone());
        }
        system_allocation(|| Arc::new(Self { inner }))
    }

    pub fn info(&self) -> StoreInfo {
        self.inner.info()
    }
}

/// Number of audited puts that reached the deterministic pre-write panic. The
/// acceptance path samples this around every fault so an earlier quota panic
/// cannot masquerade as the intended injection.
pub fn fault_reached_count() -> u64 {
    FAULT_REACHED.load(Ordering::Acquire)
}

/// Recover the active claim abandoned by one exact task fault. The executor's
/// general fault-cleanup hook invokes this after the task is detached forever,
/// for both tracked and conservative untracked fault domains.
///
/// # Safety
///
/// `task` in `domain` must be permanently detached and unable to resume.
pub unsafe fn recover_faulted_task(task: TaskId, domain: AllocationDomain) {
    let installed = INSTALLED_STORE.lock();
    let Some(inner) = installed.as_ref() else {
        return;
    };

    // Safety: the executor has made a guard abandoned by this exact domain
    // permanently unreachable. This repairs the lock itself before inspection.
    let _ = unsafe { inner.active.recover_after_fault(domain) };
    let mut active = inner.active.lock();
    if active.is_some_and(|claim| claim.task == task && claim.domain == domain) {
        *active = None;
    }
}

impl Resource for StoreService {
    fn kind(&self) -> &'static str {
        "object-store"
    }

    fn describe(&self) -> String {
        let info = self.info();
        if !info.ready {
            return String::from("capability-addressed object store (recovery pending)");
        }
        format!(
            "capability-addressed object store [{} objects, {} journal sectors]",
            info.recovered_objects, info.used_sectors
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// An immutable object name.  Stable journal identity is intentionally private:
/// the only public way to read this object is to present a live typed cap.
pub struct StoredObject {
    store_id: StoreId,
    object_id: ObjectId,
    object_kind: journal::ObjectKind,
    byte_len: usize,
    commit_sequence: u64,
}

impl Resource for StoredObject {
    fn kind(&self) -> &'static str {
        "stored-object"
    }

    fn describe(&self) -> String {
        format!(
            "immutable stored object [kind {}, {} bytes]",
            self.object_kind.get(),
            self.byte_len
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn info_with(lease: &InvocationLease<StoreService>) -> Result<StoreInfo, StoreError> {
    if !lease.authorizes(Rights::READ) {
        return Err(StoreError::PermissionDenied);
    }
    Ok(lease.with(StoreService::info))
}

/// Append and durably commit an immutable object, re-read it through the block
/// device, and only then publish a cap into the exact target CSpace incarnation
/// which initiated the operation.
pub async fn put_with(
    lease: InvocationLease<StoreService>,
    target: Arc<Space>,
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<Cap, StoreError> {
    put_to_space(lease, target.as_ref(), object_kind, bytes, None).await
}

/// Sealed acceptance entry point. The fault target is carried inside this one
/// future rather than in global state, so an earlier error/fault/cancellation
/// cannot leave an injection armed for a different invocation.
pub(crate) async fn put_with_static_fault_before_write(
    lease: InvocationLease<StoreService>,
    target: &'static Space,
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<Cap, StoreError> {
    let target_domain = heap::current_domain();
    assert!(
        target_domain.arena.is_tracked(),
        "the injected store path requires an audited fault arena"
    );
    let target_task = exec::current_task_id().expect("the injected store path runs in a task");
    put_to_space(
        lease,
        target,
        object_kind,
        bytes,
        Some(FaultTarget {
            task: target_task,
            domain: target_domain,
        }),
    )
    .await
}

async fn put_to_space(
    lease: InvocationLease<StoreService>,
    target: &Space,
    object_kind: journal::ObjectKind,
    bytes: &[u8],
    fault_target: Option<FaultTarget>,
) -> Result<Cap, StoreError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(StoreError::PermissionDenied);
    }
    if bytes.len() > journal::MAX_OBJECT_SIZE {
        return Err(StoreError::ObjectTooLarge);
    }
    ensure_working_headroom()?;

    // Snapshot the destination before the first await.  Publication uses the
    // same-incarnation primitive after commit, so restart cannot redirect a
    // successful transaction into a fresh authority domain.
    let target_incarnation = target.0.lock().incarnation();
    let inner = lease.with(|service| service.inner.clone());
    let operation = inner.begin()?;

    let backend = backend_info(&inner)?;
    if backend.read_only {
        return Err(StoreError::ReadOnly);
    }
    if !backend.supports_flush {
        return Err(StoreError::FlushUnsupported);
    }

    let mut scan = scan_region(&inner).await?;
    let recovered = recover_scan(&scan);
    let (mut chain, old_high_water, format_record) = match recovered {
        Ok(recovered) => {
            let checkpoint = recovered
                .chain_checkpoint()
                .map_err(|_| StoreError::Corrupt)?;
            let chain = journal::RecordChain::from_checkpoint(store_id(), checkpoint)
                .map_err(|_| StoreError::Corrupt)?;
            inner.install_recovery(&recovered, scan.next_physical);
            (chain, recovered.id_high_water, None)
        }
        Err(StoreError::Unformatted) => {
            let mut chain = journal::RecordChain::new(store_id());
            let format = chain
                .append(None, journal::RecordBody::Format)
                .map_err(|_| StoreError::Corrupt)?;
            (chain, 0, Some(format))
        }
        Err(error) => return Err(error),
    };

    let first_id = old_high_water.max(FIRST_ALLOCATABLE_ID);
    let object_raw = first_id.checked_add(1).ok_or(StoreError::IdExhausted)?;
    let exclusive_end = object_raw.checked_add(1).ok_or(StoreError::IdExhausted)?;
    let transaction_id = TransactionId::new(first_id).ok_or(StoreError::IdExhausted)?;
    let object_id = ObjectId::new(object_raw).ok_or(StoreError::IdExhausted)?;

    let chunk_count = if bytes.is_empty() {
        0
    } else {
        bytes.len().div_ceil(journal::CHUNK_DATA_SIZE)
    };
    let required = (if format_record.is_some() { 1usize } else { 0 })
        .checked_add(3)
        .and_then(|count| count.checked_add(chunk_count))
        .ok_or(StoreError::JournalFull)?;
    if scan
        .next_physical
        .checked_add(required)
        .is_none_or(|end| end > STORE_LOG_SECTORS)
    {
        return Err(StoreError::JournalFull);
    }

    let high_water = chain
        .append(None, journal::RecordBody::IdHighWater { exclusive_end })
        .map_err(map_encode_error)?;
    let (transaction, _next_chain) =
        journal::preview_object_transaction(&chain, transaction_id, object_id, object_kind, bytes)
            .map_err(map_encode_error)?;
    debug_assert_eq!(
        required,
        format_record.is_some() as usize + 1 + transaction.records.len()
    );

    if let Some(target) = fault_target {
        assert_eq!(operation.task, target.task);
        assert_eq!(operation.domain, target.domain);
        FAULT_REACHED
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("store fault-injection counter exhausted");
        panic!("injected object-store fault before durable write");
    }

    // Every record is individually flushed.  This is stronger than the final
    // commit-flush minimum and keeps every acknowledged prefix independently
    // recoverable under the v1 ordered-flush media contract.
    if let Some(format) = format_record.as_ref() {
        append_record(&inner, &mut scan.next_physical, format).await?;
    }
    append_record(&inner, &mut scan.next_physical, &high_water).await?;
    for record in &transaction.records {
        append_record(&inner, &mut scan.next_physical, record).await?;
    }
    drop(transaction);

    // A successful flush is necessary but not sufficient for publication:
    // decode the actual backing sectors and require the exact committed bytes.
    let verified_scan = scan_region(&inner).await?;
    let verified = recover_scan(&verified_scan)?;
    let catalog_count = verified.objects.len();
    let committed = verified
        .objects
        .iter()
        .find(|object| object.object_id == object_id)
        .ok_or(StoreError::ObjectMismatch)?;
    if committed.object_kind != object_kind || committed.bytes.as_slice() != bytes {
        return Err(StoreError::ObjectMismatch);
    }
    let commit_sequence = committed.commit_sequence;
    let byte_len = committed.bytes.len();
    inner.install_recovery(&verified, verified_scan.next_physical);
    debug_assert!(catalog_count > 0);
    let object: Arc<StoredObject> = system_allocation(|| {
        Arc::new(StoredObject {
            store_id: verified.store_id,
            object_id,
            object_kind,
            byte_len,
            commit_sequence,
        })
    });
    let published =
        target
            .0
            .lock()
            .mint_if_incarnation(target_incarnation, object, STORED_OBJECT_RIGHTS);
    operation.finish();
    published.ok_or(StoreError::PublicationTargetRestarted)
}

/// Read a committed object by capability.  The object resource carries only
/// private journal identity; every invocation scans and validates the disk
/// again, so a same-boot cache cannot impersonate persistence.
pub async fn get_with(
    service: InvocationLease<StoreService>,
    object: InvocationLease<StoredObject>,
) -> Result<Vec<u8>, StoreError> {
    if !service.authorizes(Rights::READ) || !object.authorizes(Rights::READ) {
        return Err(StoreError::PermissionDenied);
    }
    ensure_working_headroom()?;
    let inner = service.with(|store| store.inner.clone());
    let key = object.with(|stored| {
        (
            stored.store_id,
            stored.object_id,
            stored.object_kind,
            stored.byte_len,
            stored.commit_sequence,
        )
    });
    if key.0 != store_id() {
        return Err(StoreError::ObjectUnavailable);
    }

    let operation = inner.begin()?;
    let scan = scan_region(&inner).await?;
    let mut recovered = recover_scan(&scan)?;
    let found = recovered
        .objects
        .iter()
        .position(|candidate| {
            candidate.object_id == key.1
                && candidate.object_kind == key.2
                && candidate.bytes.len() == key.3
                && candidate.commit_sequence == key.4
        })
        .ok_or(StoreError::ObjectUnavailable)?;

    inner.install_recovery(&recovered, scan.next_physical);
    let recovered_bytes = recovered.objects.swap_remove(found).bytes;
    operation.finish();
    Ok(recovered_bytes)
}

struct PhysicalScan {
    /// First physical slot after every observed non-zero sector, including a
    /// torn tail.  Such a tail is never overwritten; a retry chains around it.
    next_physical: usize,
}

async fn scan_region(inner: &StoreInner) -> Result<PhysicalScan, StoreError> {
    let info = backend_info(inner)?;
    if info.capacity_sectors < STORE_END_SECTOR {
        return Err(StoreError::DeviceTooSmall);
    }

    let mut next_physical = 0;
    for offset in 0..STORE_LOG_SECTORS {
        let sector = STORE_FIRST_SECTOR + offset as u64;
        let bytes = read_sector(inner, sector).await?;
        if bytes.iter().any(|byte| *byte != 0) {
            next_physical = offset + 1;
        }
        STORE_SCRATCH.write(offset, bytes);
    }
    Ok(PhysicalScan { next_physical })
}

fn recover_scan(_scan: &PhysicalScan) -> Result<journal::RecoveredStore, StoreError> {
    journal::recover(
        STORE_SCRATCH.sectors(),
        journal::RecoveryPolicy {
            store_id: store_id(),
        },
    )
    .map_err(|error| match error {
        journal::RecoveryError::MissingFormat => StoreError::Unformatted,
        _ => StoreError::Corrupt,
    })
}

async fn append_record(
    inner: &StoreInner,
    next_physical: &mut usize,
    record: &[u8; journal::RECORD_SIZE],
) -> Result<(), StoreError> {
    if *next_physical >= STORE_LOG_SECTORS {
        return Err(StoreError::JournalFull);
    }
    let sector = STORE_FIRST_SECTOR + *next_physical as u64;
    write_sector(inner, sector, *record).await?;
    *next_physical += 1;
    flush(inner).await
}

fn backend_info(inner: &StoreInner) -> Result<virtio_blk::BlockInfo, StoreError> {
    let lease = backend_lease(inner, Rights::READ)?;
    Ok(virtio_blk::info_with(&lease)?)
}

async fn read_sector(inner: &StoreInner, sector: u64) -> Result<[u8; 512], StoreError> {
    let lease = backend_lease(inner, Rights::READ)?;
    Ok(virtio_blk::read_with(lease, sector).await?)
}

async fn write_sector(inner: &StoreInner, sector: u64, bytes: [u8; 512]) -> Result<(), StoreError> {
    let lease = backend_lease(inner, Rights::WRITE)?;
    Ok(virtio_blk::write_with(lease, sector, bytes).await?)
}

async fn flush(inner: &StoreInner) -> Result<(), StoreError> {
    let lease = backend_lease(inner, Rights::WRITE)?;
    Ok(virtio_blk::flush_with(lease).await?)
}

fn backend_lease(
    inner: &StoreInner,
    need: Rights,
) -> Result<InvocationLease<BlockDevice>, StoreError> {
    let cspace = inner.backend.0.lock();
    cspace
        .lookup_lease::<BlockDevice>(inner.block, need)
        .map_err(map_cap_error)
}

fn map_cap_error(_error: CapError) -> StoreError {
    StoreError::BackendAuthority
}

fn map_encode_error(error: journal::EncodeError) -> StoreError {
    match error {
        journal::EncodeError::ObjectTooLarge => StoreError::ObjectTooLarge,
        journal::EncodeError::SequenceOverflow => StoreError::JournalFull,
        _ => StoreError::Corrupt,
    }
}

fn ensure_working_headroom() -> Result<(), StoreError> {
    let domain = heap::current_domain();
    let stats = crate::HEAP
        .account_stats(domain.owner)
        .ok_or(StoreError::InsufficientMemory)?;
    if stats.quota_bytes.saturating_sub(stats.live_bytes) < STORE_WORKING_HEADROOM {
        return Err(StoreError::InsufficientMemory);
    }
    Ok(())
}

/// Execute one synchronous allocation burst as SYSTEM.  The scope is restored
/// before its caller can await, so another task can never inherit this owner.
fn system_allocation<T>(operation: impl FnOnce() -> T) -> T {
    let mut scope = heap::enter_owner(OwnerId::SYSTEM);
    let value = operation();
    scope.restore();
    value
}
