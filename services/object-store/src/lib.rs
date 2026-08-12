//! Capability-addressed persistent object store.
//!
//! The public surface deliberately has no path or `ObjectId` lookup.  A caller
//! needs a `StoreService` capability for the operation and a `StoredObject`
//! capability for every read.  Stable IDs remain private journal details.
//!
//! The unified durable journal is bounded to sectors 64..576 so recovery work
//! cannot grow with the remainder of the block device.

#![no_std]

extern crate alloc;

mod codec;

pub use codec::*;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};

use crate as journal;
use vibeos_durable_format as authority;

use vibeos_blob_format::{BlobDescriptor, BlobError, BlobView, MerkleProof, LEAF_SIZE};
use vibeos_core::cap::{Cap, InvocationLease, Resource, Rights};
use vibeos_core::exec::{self, TaskId};
use vibeos_core::heap::{self, AllocationDomain, OwnerId};
use vibeos_core::sync::SpinLock;
use vibeos_storage_device::{DeviceSession, MutationFailure, MutationResult};

fn erase_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

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

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, BackendError>> + Send + 'a>>;
pub type BackendMutationFuture<'a, T> =
    Pin<Box<dyn Future<Output = MutationResult<T, BackendError>> + Send + 'a>>;

/// Classify the durability barrier that follows a successfully submitted
/// write. Even when the barrier itself is rejected before publication, the
/// composite durable-write operation can no longer claim no media effect.
pub fn barrier_after_successful_write<T, E>(barrier: MutationResult<T, E>) -> MutationResult<T, E> {
    barrier.map_err(MutationFailure::force_ambiguous)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendError {
    Offline,
    QueueFull,
    OutOfRange,
    ReadOnly,
    FlushUnsupported,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "block device is offline",
            Self::QueueFull => "block request queue is full",
            Self::OutOfRange => "sector is outside the device capacity",
            Self::ReadOnly => "block device is read-only",
            Self::FlushUnsupported => "block device does not support flush",
            Self::TimedOut => "block request timed out",
            Self::DriverCancelled => "block driver was cancelled",
            Self::DriverFault => "block driver faulted",
            Self::DriverRestarted => "block driver session restarted",
            Self::DeviceIo => "block device reported an I/O error",
            Self::Unsupported => "block device rejected the operation",
            Self::Protocol => "block device returned a malformed completion",
            Self::Quarantined => "block DMA is quarantined after an unconfirmed reset",
            Self::AuthorityRevoked => "block capability is absent or revoked",
            Self::PermissionDenied => "block capability lacks the required right",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendInfo {
    pub capacity_sectors: u64,
    pub read_only: bool,
    pub supports_flush: bool,
    /// Exact device incarnation used by every I/O in one store operation.
    pub session: DeviceSession,
}

/// Block and memory-accounting surface required by the object service.
pub trait Platform: Send + Sync {
    fn info(&self) -> Result<BackendInfo, BackendError>;
    fn read_sector(&self, session: DeviceSession, sector: u64) -> BackendFuture<'_, [u8; 512]>;
    /// Write one historical M4 sector and make it durable using one pinned
    /// device session. A failure retains whether media effect is possible.
    fn write_sector_durable(
        &self,
        session: DeviceSession,
        sector: u64,
        bytes: [u8; 512],
    ) -> BackendMutationFuture<'_, ()>;
    fn has_working_headroom(&self, required: usize) -> bool;
}

/// Exact CSpace incarnation into which a newly committed object may be
/// published. The trait intentionally offers no lookup by stable object ID.
pub trait PublicationTarget: Send + Sync {
    fn incarnation(&self) -> u64;
    fn publish(
        &self,
        expected_incarnation: u64,
        object: Arc<StoredObject>,
        rights: Rights,
    ) -> Option<Cap>;
}

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
    Backend(BackendError),
    BackendMutation(MutationFailure<BackendError>),
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
    JournalChanged,
    InsufficientMemory,
    OutsideTask,
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(error) => write!(f, "object-store block I/O failed: {error}"),
            Self::BackendMutation(failure) => write!(
                f,
                "object-store durable write failed: {} ({:?})",
                failure.error(),
                failure.certainty()
            ),
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
                Self::JournalChanged => "object journal changed before append",
                Self::InsufficientMemory => {
                    "store caller lacks the bounded journal-recovery headroom"
                }
                Self::OutsideTask => "store operations require an executor task context",
                Self::Backend(_) | Self::BackendMutation(_) => unreachable!(),
            }),
        }
    }
}

impl From<BackendError> for StoreError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

impl From<MutationFailure<BackendError>> for StoreError {
    fn from(failure: MutationFailure<BackendError>) -> Self {
        Self::BackendMutation(failure)
    }
}

/// Error boundary for the canonical Merkle-blob profile. Journal failures and
/// format/integrity failures remain distinguishable to callers and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobStoreError {
    Store(StoreError),
    Format(BlobError),
    ObjectKindMismatch,
}

impl core::fmt::Display for BlobStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "Merkle blob store failed: {error}"),
            Self::Format(error) => write!(f, "Merkle blob verification failed: {error}"),
            Self::ObjectKindMismatch => {
                f.write_str("Merkle descriptor kind does not match durable object kind")
            }
        }
    }
}

impl From<StoreError> for BlobStoreError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<BlobError> for BlobStoreError {
    fn from(error: BlobError) -> Self {
        Self::Format(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobPublication {
    pub capability: Cap,
    pub descriptor: BlobDescriptor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlob {
    pub descriptor: BlobDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBlobChunk {
    pub descriptor: BlobDescriptor,
    pub index: u32,
    pub bytes: Vec<u8>,
    pub proof: MerkleProof,
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
    platform: Arc<dyn Platform>,
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

    fn install_recovery(&self, recovered: &authority::RecoveryPreflight, used_sectors: usize) {
        let checkpoint = recovered
            .chain_checkpoint()
            .expect("a successful recovery has a usable checkpoint");
        *self.state.lock() = RuntimeState {
            ready: true,
            used_sectors,
            recovered_objects: recovered.committed_objects().len(),
            id_high_water: recovered.id_high_water(),
            last_sequence: checkpoint.previous_sequence,
        };
    }

    fn install_unformatted_recovery(&self, used_sectors: usize) {
        *self.state.lock() = RuntimeState {
            ready: true,
            used_sectors,
            recovered_objects: 0,
            id_high_water: 0,
            last_sequence: 0,
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
    pub fn new(platform: Arc<dyn Platform>) -> Arc<Self> {
        let inner = system_allocation(|| {
            Arc::new(StoreInner {
                platform,
                active: SpinLock::new_recoverable(None),
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

    /// Sealed kernel-only access to the unified object/authority journal. This
    /// is deliberately not a capability operation: only the separately
    /// constructed durable-CSpace service receives a handle, and no caller can
    /// use it as an ambient ObjectId lookup namespace.
    pub fn authority_journal(&self) -> AuthorityJournal {
        AuthorityJournal {
            inner: self.inner.clone(),
        }
    }

    /// Sealed kernel-only reader for singleton configuration records. It
    /// exposes neither object IDs nor a general namespace: callers can only
    /// select the newest immutable object carrying an already-known kind.
    pub fn sealed_config_journal(&self) -> SealedConfigJournal {
        SealedConfigJournal {
            inner: self.inner.clone(),
        }
    }
}

/// Kernel-only latest-version view used for small boot configuration objects.
/// Writes still use the ordinary audited `put_with` path.
#[derive(Clone)]
pub struct SealedConfigJournal {
    inner: Arc<StoreInner>,
}

impl SealedConfigJournal {
    pub async fn latest(
        &self,
        object_kind: journal::ObjectKind,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        ensure_working_headroom()?;
        let operation = self.inner.begin()?;
        let result = async {
            let scan = scan_region(&self.inner).await?;
            let recovered = match recover_scan(&scan) {
                Ok(recovered) => recovered,
                Err(StoreError::Unformatted) => {
                    self.inner.install_unformatted_recovery(scan.next_physical);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let newest = recovered
                .committed_objects()
                .iter()
                .filter(|object| object.object_kind == object_kind)
                .max_by_key(|object| object.commit_sequence)
                .map(|object| object.bytes.clone());
            self.inner.install_recovery(&recovered, scan.next_physical);
            for object in &mut recovered.into_objects() {
                erase_bytes(&mut object.bytes);
            }
            Ok(newest)
        }
        .await;
        operation.finish();
        result
    }
}

/// One inert view of the shared journal. Authority is still absent: callers
/// must apply external root constraints and construct typed resource witnesses
/// before installing anything into a CSpace.
pub struct AuthoritySnapshot {
    pub formatted: bool,
    pub checkpoint: ChainCheckpoint,
    pub used_sectors: usize,
    pub preflight: Option<authority::RecoveryPreflight>,
}

impl AuthoritySnapshot {
    pub fn id_high_water(&self) -> u128 {
        self.preflight
            .as_ref()
            .map(authority::RecoveryPreflight::id_high_water)
            .unwrap_or(0)
    }

    pub fn chain(&self) -> Result<authority::RecordChain, StoreError> {
        authority::RecordChain::from_checkpoint(store_id(), self.checkpoint)
            .map_err(|_| StoreError::Corrupt)
    }
}

/// Kernel-only writer for authority records in the exact object-store journal.
/// Each operation rescans media and compares the caller's checkpoint before
/// writing, so no stale preview can fork the sequence/CRC chain.
#[derive(Clone)]
pub struct AuthorityJournal {
    inner: Arc<StoreInner>,
}

impl AuthorityJournal {
    pub async fn recover(&self) -> Result<AuthoritySnapshot, StoreError> {
        ensure_working_headroom()?;
        let operation = self.inner.begin()?;
        let result = async {
            validate_writable_backend(&self.inner)?;
            let scan = scan_region(&self.inner).await?;
            let snapshot = authority_snapshot(&scan)?;
            if let Some(preflight) = snapshot.preflight.as_ref() {
                self.inner
                    .install_recovery(preflight, snapshot.used_sectors);
            } else {
                self.inner
                    .install_unformatted_recovery(snapshot.used_sectors);
            }
            Ok(snapshot)
        }
        .await;
        // Ordinary errors release explicitly; async cancellation retains the
        // StoreOperation Drop backstop, while guarded panics use the executor's
        // exact-task/domain recovery hook.
        operation.finish();
        result
    }

    /// Append an already-previewed sequence after checking that physical media
    /// still has the checkpoint against which it was encoded. Every record is
    /// written and flushed independently, preserving the v1 prefix model.
    pub async fn append(
        &self,
        expected: ChainCheckpoint,
        records: &[[u8; journal::RECORD_SIZE]],
    ) -> Result<AuthoritySnapshot, StoreError> {
        if records.is_empty() {
            return Err(StoreError::Corrupt);
        }
        ensure_working_headroom()?;
        let operation = self.inner.begin()?;
        let result = async {
            validate_writable_backend(&self.inner)?;
            let mut scan = scan_region(&self.inner).await?;
            let before = authority_snapshot(&scan)?;
            if before.checkpoint != expected {
                return Err(StoreError::JournalChanged);
            }
            if scan
                .next_physical
                .checked_add(records.len())
                .is_none_or(|end| end > STORE_LOG_SECTORS)
            {
                return Err(StoreError::JournalFull);
            }

            let final_checkpoint = validate_preview(&before, records)?;
            for record in records {
                append_record(&self.inner, &mut scan.next_physical, scan.session, record).await?;
            }

            // A flush is not accepted on faith: the complete semantic pass
            // must observe the exact chain head encoded by the preview.
            let verified_scan = scan_region(&self.inner).await?;
            let verified = authority_snapshot(&verified_scan)?;
            if verified.checkpoint != final_checkpoint {
                return Err(StoreError::ObjectMismatch);
            }
            let preflight = verified.preflight.as_ref().ok_or(StoreError::Corrupt)?;
            self.inner
                .install_recovery(preflight, verified.used_sectors);
            Ok(verified)
        }
        .await;
        // Every ordinary append error reaches this exact claim release. Async
        // cancellation uses Drop; guarded panic cleanup uses the exact task and
        // allocation domain recorded by StoreInner.
        operation.finish();
        result
    }

    /// Read one restored object through a live typed capability. The durable
    /// service gets journal access but still cannot bypass CSpace authority by
    /// naming an ObjectId directly.
    pub async fn read(&self, object: InvocationLease<StoredObject>) -> Result<Vec<u8>, StoreError> {
        if !object.authorizes(Rights::READ) {
            return Err(StoreError::PermissionDenied);
        }
        read_committed_object(self.inner.clone(), object).await
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

    let task_key =
        vibeos_core::sync::TaskRecoveryKey::new(task.0).expect("executor TaskId zero is reserved");
    // Safety: the executor installed this exact task key around its poll and
    // has now detached that task forever. A same-domain task on another hart
    // carries a different key and cannot have its guard recovered here.
    let _ = unsafe { inner.active.recover_after_task_fault(domain, task_key) };
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

impl StoredObject {
    pub fn from_recovered(object: &authority::RecoveredObject) -> Arc<Self> {
        system_allocation(|| {
            Arc::new(Self {
                store_id: store_id(),
                object_id: object.object_id,
                object_kind: object.object_kind,
                byte_len: object.bytes.len(),
                commit_sequence: object.commit_sequence,
            })
        })
    }
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
    target: Arc<dyn PublicationTarget>,
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<Cap, StoreError> {
    put_to_space(lease, target.as_ref(), object_kind, bytes, None).await
}

/// Sealed acceptance entry point. The fault target is carried inside this one
/// future rather than in global state, so an earlier error/fault/cancellation
/// cannot leave an injection armed for a different invocation.
pub async fn put_with_static_fault_before_write(
    lease: InvocationLease<StoreService>,
    target: &'static dyn PublicationTarget,
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
    target: &dyn PublicationTarget,
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
    let target_incarnation = target.incarnation();
    let inner = lease.with(|service| service.inner.clone());
    let operation = inner.begin()?;

    validate_writable_backend(&inner)?;

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
            (chain, recovered.id_high_water(), None)
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
        append_record(&inner, &mut scan.next_physical, scan.session, format).await?;
    }
    append_record(&inner, &mut scan.next_physical, scan.session, &high_water).await?;
    for record in &transaction.records {
        append_record(&inner, &mut scan.next_physical, scan.session, record).await?;
    }
    drop(transaction);

    // A successful flush is necessary but not sufficient for publication:
    // decode the actual backing sectors and require the exact committed bytes.
    let verified_scan = scan_region(&inner).await?;
    let verified = recover_scan(&verified_scan)?;
    let catalog_count = verified.committed_objects().len();
    let committed = verified
        .committed_objects()
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
            store_id: verified.store_id(),
            object_id,
            object_kind,
            byte_len,
            commit_sequence,
        })
    });
    let published = target.publish(target_incarnation, object, STORED_OBJECT_RIGHTS);
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
    let inner = service.with(|store| store.inner.clone());
    read_committed_object(inner, object).await
}

/// Encode content into the canonical Merkle-blob profile after enforcing the
/// current journal object's physical size limit. This preflight avoids a large
/// doomed allocation when the durable v1 journal cannot hold the result.
pub fn encode_blob_object(
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<Vec<u8>, BlobStoreError> {
    let encoded_len = vibeos_blob_format::encoded_len(bytes.len())?;
    if encoded_len > journal::MAX_OBJECT_SIZE {
        return Err(BlobStoreError::Store(StoreError::ObjectTooLarge));
    }
    Ok(vibeos_blob_format::encode_blob(object_kind.get(), bytes)?)
}

/// Strictly decode and verify every data and tree node in one stored Merkle
/// blob. The durable journal kind is an independent outer binding and must
/// agree with the descriptor's content kind.
pub fn verify_blob_object(
    object_kind: journal::ObjectKind,
    encoded: &[u8],
) -> Result<VerifiedBlob, BlobStoreError> {
    let blob = BlobView::decode(encoded)?;
    if blob.descriptor().object_kind != object_kind.get() {
        return Err(BlobStoreError::ObjectKindMismatch);
    }
    blob.verify_all()?;
    Ok(VerifiedBlob {
        descriptor: blob.descriptor(),
        bytes: blob.data().to_vec(),
    })
}

/// Verify one chunk and its sibling path without requiring all other data
/// chunks to be rehashed. The returned proof can be rechecked independently
/// against the returned descriptor.
pub fn verify_blob_object_chunk(
    object_kind: journal::ObjectKind,
    encoded: &[u8],
    index: u32,
) -> Result<VerifiedBlobChunk, BlobStoreError> {
    let blob = BlobView::decode(encoded)?;
    if blob.descriptor().object_kind != object_kind.get() {
        return Err(BlobStoreError::ObjectKindMismatch);
    }
    blob.verify_chunk(index)?;
    Ok(VerifiedBlobChunk {
        descriptor: blob.descriptor(),
        index,
        bytes: blob.chunk(index)?.to_vec(),
        proof: blob.proof(index)?,
    })
}

/// Commit one immutable canonical Merkle blob through the existing audited
/// object transaction, then publish the ordinary StoredObject capability. The
/// journal's exact-byte readback therefore covers the descriptor, content, and
/// complete hash tree before this function returns success.
pub async fn put_blob_with(
    lease: InvocationLease<StoreService>,
    target: Arc<dyn PublicationTarget>,
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<BlobPublication, BlobStoreError> {
    let encoded = encode_blob_object(object_kind, bytes)?;
    let descriptor = BlobView::decode(&encoded)?.descriptor();
    let capability = put_with(lease, target, object_kind, &encoded).await?;
    Ok(BlobPublication {
        capability,
        descriptor,
    })
}

/// Read a Merkle blob through both required capabilities, erase the redundant
/// encoded envelope, and return content only after complete tree validation.
pub async fn get_blob_with(
    service: InvocationLease<StoreService>,
    object: InvocationLease<StoredObject>,
) -> Result<VerifiedBlob, BlobStoreError> {
    let object_kind = object.with(|stored| stored.object_kind);
    let mut encoded = get_with(service, object).await?;
    let result = verify_blob_object(object_kind, &encoded);
    erase_bytes(&mut encoded);
    result
}

/// Read and authenticate one logical 4 KiB blob chunk. The v1 journal backend
/// still recovers the enclosing object in full; the API and proof semantics are
/// intentionally stable for a later extent-addressed backend.
pub async fn get_blob_chunk_with(
    service: InvocationLease<StoreService>,
    object: InvocationLease<StoredObject>,
    index: u32,
) -> Result<VerifiedBlobChunk, BlobStoreError> {
    let object_kind = object.with(|stored| stored.object_kind);
    let mut encoded = get_with(service, object).await?;
    let result = verify_blob_object_chunk(object_kind, &encoded, index);
    erase_bytes(&mut encoded);
    result
}

pub const fn blob_leaf_size() -> usize {
    LEAF_SIZE
}

async fn read_committed_object(
    inner: Arc<StoreInner>,
    object: InvocationLease<StoredObject>,
) -> Result<Vec<u8>, StoreError> {
    ensure_working_headroom()?;
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
    let recovered = recover_scan(&scan)?;
    let found = recovered
        .committed_objects()
        .iter()
        .position(|candidate| {
            candidate.object_id == key.1
                && candidate.object_kind == key.2
                && candidate.bytes.len() == key.3
                && candidate.commit_sequence == key.4
        })
        .ok_or(StoreError::ObjectUnavailable)?;

    inner.install_recovery(&recovered, scan.next_physical);
    let mut objects = recovered.into_objects();
    let recovered_bytes = objects.swap_remove(found).bytes;
    operation.finish();
    Ok(recovered_bytes)
}

struct PhysicalScan {
    /// First physical slot after every observed non-zero sector, including a
    /// torn tail.  Such a tail is never overwritten; a retry chains around it.
    next_physical: usize,
    session: DeviceSession,
}

async fn scan_region(inner: &StoreInner) -> Result<PhysicalScan, StoreError> {
    let info = backend_info(inner)?;
    if info.capacity_sectors < STORE_END_SECTOR {
        return Err(StoreError::DeviceTooSmall);
    }

    let mut next_physical = 0;
    for offset in 0..STORE_LOG_SECTORS {
        let sector = STORE_FIRST_SECTOR + offset as u64;
        let bytes = read_sector(inner, info.session, sector).await?;
        if bytes.iter().any(|byte| *byte != 0) {
            next_physical = offset + 1;
        }
        STORE_SCRATCH.write(offset, bytes);
    }
    Ok(PhysicalScan {
        next_physical,
        session: info.session,
    })
}

fn recover_scan(_scan: &PhysicalScan) -> Result<authority::RecoveryPreflight, StoreError> {
    authority::preflight_recovery(STORE_SCRATCH.sectors(), store_id()).map_err(map_recovery_error)
}

fn authority_snapshot(scan: &PhysicalScan) -> Result<AuthoritySnapshot, StoreError> {
    match authority::preflight_recovery(STORE_SCRATCH.sectors(), store_id()) {
        Ok(preflight) => {
            let checkpoint = preflight
                .chain_checkpoint()
                .map_err(|_| StoreError::Corrupt)?;
            Ok(AuthoritySnapshot {
                formatted: true,
                checkpoint,
                used_sectors: scan.next_physical,
                preflight: Some(preflight),
            })
        }
        Err(authority::RecoveryError::MissingFormat) => Ok(AuthoritySnapshot {
            formatted: false,
            checkpoint: ChainCheckpoint {
                next_sequence: 1,
                previous_sequence: 0,
                previous_crc32c: 0,
            },
            used_sectors: scan.next_physical,
            preflight: None,
        }),
        Err(_) => Err(StoreError::Corrupt),
    }
}

fn validate_preview(
    before: &AuthoritySnapshot,
    records: &[[u8; journal::RECORD_SIZE]],
) -> Result<ChainCheckpoint, StoreError> {
    let mut next_sequence = before.checkpoint.next_sequence;
    let mut previous_sequence = before.checkpoint.previous_sequence;
    let mut previous_crc32c = before.checkpoint.previous_crc32c;
    for (index, bytes) in records.iter().enumerate() {
        let DecodeStatus::Valid(decoded) =
            authority::LogRecord::decode(bytes).map_err(|_| StoreError::Corrupt)?
        else {
            return Err(StoreError::Corrupt);
        };
        if decoded.record.store_id != store_id()
            || decoded.record.sequence != next_sequence
            || decoded.record.previous_sequence != previous_sequence
            || decoded.record.previous_crc32c != previous_crc32c
        {
            return Err(StoreError::JournalChanged);
        }
        let is_format = matches!(decoded.record.body, RecordBody::Format);
        if (!before.formatted && index == 0) != is_format {
            return Err(StoreError::Corrupt);
        }
        if before.formatted && is_format {
            return Err(StoreError::Corrupt);
        }
        previous_sequence = decoded.record.sequence;
        previous_crc32c = decoded.crc32c;
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or(StoreError::JournalFull)?;
    }
    Ok(ChainCheckpoint {
        next_sequence,
        previous_sequence,
        previous_crc32c,
    })
}

fn map_recovery_error(error: authority::RecoveryError) -> StoreError {
    match error {
        authority::RecoveryError::MissingFormat => StoreError::Unformatted,
        _ => StoreError::Corrupt,
    }
}

async fn append_record(
    inner: &StoreInner,
    next_physical: &mut usize,
    session: DeviceSession,
    record: &[u8; journal::RECORD_SIZE],
) -> Result<(), StoreError> {
    if *next_physical >= STORE_LOG_SECTORS {
        return Err(StoreError::JournalFull);
    }
    let sector = STORE_FIRST_SECTOR + *next_physical as u64;
    write_sector_durable(inner, session, sector, *record).await?;
    *next_physical += 1;
    Ok(())
}

fn backend_info(inner: &StoreInner) -> Result<BackendInfo, StoreError> {
    Ok(inner.platform.info()?)
}

fn validate_writable_backend(inner: &StoreInner) -> Result<(), StoreError> {
    let backend = backend_info(inner)?;
    if backend.read_only {
        return Err(StoreError::ReadOnly);
    }
    if !backend.supports_flush {
        return Err(StoreError::FlushUnsupported);
    }
    Ok(())
}

async fn read_sector(
    inner: &StoreInner,
    session: DeviceSession,
    sector: u64,
) -> Result<[u8; 512], StoreError> {
    Ok(inner.platform.read_sector(session, sector).await?)
}

async fn write_sector_durable(
    inner: &StoreInner,
    session: DeviceSession,
    sector: u64,
    bytes: [u8; 512],
) -> Result<(), StoreError> {
    Ok(inner
        .platform
        .write_sector_durable(session, sector, bytes)
        .await?)
}

fn map_encode_error(error: journal::EncodeError) -> StoreError {
    match error {
        journal::EncodeError::ObjectTooLarge => StoreError::ObjectTooLarge,
        journal::EncodeError::SequenceOverflow => StoreError::JournalFull,
        _ => StoreError::Corrupt,
    }
}

fn ensure_working_headroom() -> Result<(), StoreError> {
    let installed = INSTALLED_STORE.lock();
    let Some(inner) = installed.as_ref() else {
        return Err(StoreError::BackendAuthority);
    };
    if !inner.platform.has_working_headroom(STORE_WORKING_HEADROOM) {
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
