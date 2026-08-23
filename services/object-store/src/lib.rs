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

pub use vibeos_blob_format::{encoded_len as blob_profile_encoded_len, BlobDescriptor};
use vibeos_blob_format::{BlobError, BlobView, MerkleProof, LEAF_SIZE};
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

// Frozen C7.4 durable layout. These values are deliberately private: callers
// select only development or operator installation and never supply, receive,
// or inspect a stable durable identity.
const C74_COMPONENT_SPACE_ID_RAW: u128 = 0x5649_4245_4f53_2d43_4f4d_504f_4e45_4e54;
const C74_COMPONENT_ARTIFACT_KIND_RAW: u32 = 0x434d_5031;
const C74_OPERATOR_EVIDENCE_KIND_RAW: u32 = 0x434d_4531;
const C74_STORED_OBJECT_RESOURCE_KIND_RAW: u32 = 0x5354_4f52;
const C74_PERSISTENT_SPACE_ID_RAW: u128 = 0x5053;
const C74_PERSISTENT_OBJECT_KIND_RAW: u32 = 0x4353_5043;
const C74_PROGRAM_SPACE_ID_RAW: u128 = 0x5052_4f47;
const C74_PROGRAM_OBJECT_KIND_RAW: u32 = 0x5052_4731;
const C74_OPERATOR_EVIDENCE_LEN: usize = 112;
const C74_DEVELOPMENT_ID_COUNT: u128 = 4;
const C74_OPERATOR_ID_COUNT: u128 = 6;
const C74_STORAGE_V2_EXTERNAL_POLICY_SHA256: [u8; 32] = [
    0x85, 0x6f, 0x31, 0x4c, 0xfb, 0xd8, 0x21, 0xec, 0x0f, 0x87, 0x30, 0x90, 0x39, 0x48, 0xa8, 0xc1,
    0x65, 0xbf, 0x5c, 0xe8, 0x6b, 0xf4, 0x16, 0xda, 0x2b, 0x21, 0x7b, 0xf6, 0xc3, 0x49, 0x2a, 0xa3,
];

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

/// Boot-selected persistence backend. `Pending` and `FailClosed` never fall
/// through to the legacy journal: the selector must explicitly publish M4 or
/// V2 before durable recovery can begin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageBackendSelection {
    Pending,
    LegacyM4,
    StorageV2,
    FailClosed,
}

/// Harmless aggregate information supplied by the sealed V2 runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageV2BackendInfo {
    pub ready: bool,
    pub busy: bool,
    pub allocated_segments: usize,
    pub recovered_objects: usize,
    pub checkpoint_generation: u64,
}

/// Opaque backend-owned authority. The object-store facade can carry and
/// compare this token but cannot derive a media address or stable identifier
/// from it. Only the backend which created it can downcast the sealed payload.
#[derive(Clone)]
pub struct StorageV2ObjectToken {
    inner: Arc<dyn Any + Send + Sync>,
}

impl StorageV2ObjectToken {
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self {
            inner: Arc::new(value),
        }
    }

    pub fn downcast_ref<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.inner.as_ref().downcast_ref::<T>()
    }
}

/// One exact logical-journal object bound to an opaque V2 object capability.
/// Construction is checked again against the recovered durable-format record
/// before the binding can enter an `AuthoritySnapshot`.
#[derive(Clone)]
pub struct StorageV2RecoveredObject {
    stable_object_id: ObjectId,
    object_kind: journal::ObjectKind,
    byte_len: usize,
    commit_sequence: u64,
    token: StorageV2ObjectToken,
}

impl StorageV2RecoveredObject {
    pub fn new(object: &authority::RecoveredObject, token: StorageV2ObjectToken) -> Self {
        Self {
            stable_object_id: object.object_id,
            object_kind: object.object_kind,
            byte_len: object.byte_len() as usize,
            commit_sequence: object.commit_sequence,
            token,
        }
    }

    fn matches(&self, object: &authority::RecoveredObject) -> bool {
        self.stable_object_id == object.object_id
            && self.object_kind == object.object_kind
            && self.byte_len == object.byte_len() as usize
            && self.commit_sequence == object.commit_sequence
    }
}

/// Strictly recovered authority plus the private V2 bindings for exactly the
/// objects which may be materialized as capabilities.
pub struct StorageV2AuthoritySnapshot {
    pub used_sectors: usize,
    pub preflight: authority::RecoveryPreflight,
    external_root_policy_sha256: [u8; 32],
    objects: Vec<StorageV2RecoveredObject>,
}

impl StorageV2AuthoritySnapshot {
    pub fn new(
        used_sectors: usize,
        preflight: authority::RecoveryPreflight,
        external_root_policy_sha256: [u8; 32],
        mut objects: Vec<StorageV2RecoveredObject>,
    ) -> Result<Self, StoreError> {
        objects.sort_unstable_by_key(|object| object.stable_object_id);
        if objects
            .windows(2)
            .any(|pair| pair[0].stable_object_id == pair[1].stable_object_id)
            || objects.iter().any(|binding| {
                !preflight
                    .committed_objects()
                    .iter()
                    .any(|object| binding.matches(object))
            })
        {
            return Err(StoreError::Corrupt);
        }
        Ok(Self {
            used_sectors,
            preflight,
            external_root_policy_sha256,
            objects,
        })
    }

    /// Exact commitment used by the Storage V2 persistent-authority root.
    /// This is a comparison witness only: it conveys no object identity and
    /// does not by itself prove any component installer policy profile.
    pub const fn external_root_policy_sha256(&self) -> [u8; 32] {
        self.external_root_policy_sha256
    }
}

pub type StorageV2Future<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// Kernel-sealed Storage V2 bridge. It deliberately speaks the existing
/// durable record stream and opaque object capabilities, never Blob keys,
/// ObjectIds, paths, or physical pointers.
pub trait StorageV2Backend: Send + Sync {
    fn selection(&self) -> StorageBackendSelection;
    fn info(&self) -> StorageV2BackendInfo;
    fn recover_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot>;
    /// Re-read the authoritative checkpoint and rebuild its exact object
    /// bindings from physical media. This is deliberately separate from
    /// [`Self::recover_authority`], which may consume a boot-proved cache.
    ///
    /// The default fails closed: a backend must explicitly implement an
    /// independent media readback before it can satisfy a publication
    /// postflight. Reusing the boot cache here would turn two observations of
    /// one in-memory value into false crash-consistency evidence.
    fn readback_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
        Box::pin(async { Err(StoreError::Corrupt) })
    }
    fn append_authority<'a>(
        &'a self,
        expected: ChainCheckpoint,
        records: &'a [[u8; journal::RECORD_SIZE]],
    ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot>;
    /// Append only while the backend's current physical authority remains bound
    /// to `expected_external_root_policy_sha256`. The policy comparison and
    /// every capacity/authority mutation performed for this append must share
    /// one backend-exclusive mutation epoch.
    ///
    /// The default deliberately fails closed instead of delegating to
    /// [`Self::append_authority`]: a backend which cannot make the policy check
    /// atomic with its writes cannot implement the sealed C7.4 protocol.
    fn append_authority_bound_to_policy<'a>(
        &'a self,
        _expected: ChainCheckpoint,
        _expected_external_root_policy_sha256: [u8; 32],
        _records: &'a [[u8; journal::RECORD_SIZE]],
    ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
        Box::pin(async { Err(StoreError::Corrupt) })
    }
    /// Append a successor whose new records include one external object;
    /// `external_payload` carries that object's exact content bytes so the
    /// backend can commit them in the same durable transaction. Backends
    /// without external-object support refuse the payload form.
    fn append_authority_with_payload<'a>(
        &'a self,
        expected: ChainCheckpoint,
        records: &'a [[u8; journal::RECORD_SIZE]],
        external_payload: Option<(u128, &'a [u8])>,
    ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
        match external_payload {
            None => self.append_authority(expected, records),
            Some(_) => Box::pin(async { Err(StoreError::ObjectTooLarge) }),
        }
    }
    fn read_object<'a>(&'a self, object: &'a StorageV2ObjectToken) -> StorageV2Future<'a, Vec<u8>>;
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
    v2: Option<Arc<dyn StorageV2Backend>>,
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
        Self::new_with_storage_v2(platform, None)
    }

    pub fn new_with_storage_v2(
        platform: Arc<dyn Platform>,
        v2: Option<Arc<dyn StorageV2Backend>>,
    ) -> Arc<Self> {
        let inner = system_allocation(|| {
            Arc::new(StoreInner {
                platform,
                v2,
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
        if let Some(v2) = self.inner.v2.as_ref() {
            match v2.selection() {
                StorageBackendSelection::StorageV2 => {
                    let info = v2.info();
                    return StoreInfo {
                        ready: info.ready,
                        // V2 operations are serialized twice: the facade gate
                        // spans capability publication and deterministic fault
                        // injection, while the backend gate spans mutable
                        // SegmentStore access.  Report either claim so callers
                        // cannot mistake the gap between those phases for an
                        // idle store.
                        busy: info.busy || self.inner.active.lock().is_some(),
                        used_sectors: info.allocated_segments,
                        recovered_objects: info.recovered_objects,
                        id_high_water: 0,
                        last_sequence: info.checkpoint_generation,
                    };
                }
                StorageBackendSelection::Pending | StorageBackendSelection::FailClosed => {
                    return StoreInfo {
                        ready: false,
                        ..self.inner.info()
                    };
                }
                StorageBackendSelection::LegacyM4 => {}
            }
        }
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
        if let Some(v2) = selected_v2_backend(&self.inner)? {
            let snapshot = v2.recover_authority().await?;
            let newest = snapshot
                .preflight
                .committed_objects()
                .iter()
                .filter(|object| object.object_kind == object_kind)
                .max_by_key(|object| object.commit_sequence);
            return match newest {
                Some(object) => {
                    let token = snapshot
                        .token_for(object)
                        .ok_or(StoreError::ObjectUnavailable)?;
                    v2.read_object(token).await.map(Some)
                }
                None => Ok(None),
            };
        }
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
/// may use the decoded records for migration or policy validation, but this
/// type has no operation which can confer recovered authority. Only
/// [`AuthorityJournal::recover_bound`] can consume a freshly recovered source
/// and produce a [`BoundAuthorityRecovery`].
///
/// In particular, a migration snapshot cannot be finished even when its
/// caller supplied a syntactically valid preflight:
///
/// ```compile_fail
/// use vibeos_durable_format::RootPolicy;
/// use vibeos_object_store::AuthoritySnapshot;
///
/// fn cannot_finish(snapshot: AuthoritySnapshot, roots: &[RootPolicy]) {
///     let _ = snapshot.finish_bound(roots);
/// }
/// ```
pub struct AuthoritySnapshot {
    pub formatted: bool,
    pub checkpoint: ChainCheckpoint,
    pub used_sectors: usize,
    pub preflight: Option<authority::RecoveryPreflight>,
    v2_objects: Option<Arc<Vec<StorageV2RecoveredObject>>>,
}

/// One canonical authority recovery produced by consuming the object store's
/// private preflight under an exact external root policy.
///
/// The fields are private and this type is deliberately neither `Clone` nor
/// `Debug`. A caller may inspect the recovered graph by shared borrow, but can
/// materialize a resource only when the selected full record is uniquely
/// present in this same internally-owned recovery.
///
/// ```compile_fail
/// use vibeos_object_store::BoundAuthorityRecovery;
///
/// fn require_clone<T: Clone>() {}
/// fn duplicate() {
///     require_clone::<BoundAuthorityRecovery>();
/// }
/// ```
#[must_use = "a bound authority recovery must be admitted or discarded"]
pub struct BoundAuthorityRecovery {
    recovered: authority::RecoveredStore,
    grant_history: Vec<authority::RecoveredGrant>,
    v2_objects: Option<Arc<Vec<StorageV2RecoveredObject>>>,
}

/// Move-only exact predicate for the sealed C7.4 physical postflight.
///
/// Every durable identity is supplied by the installer before physical
/// readback and remains private after construction. The object store compares
/// these complete records against its independently recovered graph; it never
/// returns the graph, a stable identifier, or a materializable object.
#[must_use = "a C7.4 postflight expectation must be physically checked or discarded"]
struct C74ExactPostflightExpectation {
    root: authority::RecoveredGrant,
    artifact: authority::RecoveredObject,
    evidence: C74ExpectedEvidence,
    expected_id_high_water: u128,
    expected_last_sequence: u64,
}

enum C74ExpectedEvidence {
    Absent {
        forbidden_kind: authority::ObjectKind,
    },
    RetainedOnly(authority::RecoveredObject),
}

impl C74ExactPostflightExpectation {
    /// Construct the exact development-image predicate. The evidence kind is
    /// an explicit negative assertion: no object of that kind may occur in the
    /// recovered logical graph.
    fn development(
        root: authority::RecoveredGrant,
        artifact: authority::RecoveredObject,
        forbidden_evidence_kind: authority::ObjectKind,
        expected_id_high_water: u128,
        expected_last_sequence: u64,
    ) -> Result<Self, StoreError> {
        let expectation = Self {
            root,
            artifact,
            evidence: C74ExpectedEvidence::Absent {
                forbidden_kind: forbidden_evidence_kind,
            },
            expected_id_high_water,
            expected_last_sequence,
        };
        validate_c74_expectation_shape(&expectation)?;
        Ok(expectation)
    }

    /// Construct the exact operator predicate. `evidence` is retained in the
    /// logical checkpoint only: postflight additionally proves that the V2
    /// binding table has no entry for its stable identity and that no
    /// committed grant ever named it, including tombstoned history.
    fn operator(
        root: authority::RecoveredGrant,
        artifact: authority::RecoveredObject,
        evidence: authority::RecoveredObject,
        expected_id_high_water: u128,
        expected_last_sequence: u64,
    ) -> Result<Self, StoreError> {
        let expectation = Self {
            root,
            artifact,
            evidence: C74ExpectedEvidence::RetainedOnly(evidence),
            expected_id_high_water,
            expected_last_sequence,
        };
        validate_c74_expectation_shape(&expectation)?;
        Ok(expectation)
    }
}

/// Opaque proof that one exact C7.4 predicate matched an independent physical
/// Storage V2 readback.
///
/// The receipt is move-only, has no accessors, and carries no resource.
#[must_use = "a C7.4 postflight receipt must be consumed by the sealed installer"]
struct C74ExactPostflightReceipt {
    _sealed: (),
}

impl BoundAuthorityRecovery {
    /// Borrow the exact canonical recovered graph retained by this provenance
    /// receipt. No mutable view or independently replaceable resolver is
    /// exposed.
    pub fn recovered(&self) -> &authority::RecoveredStore {
        &self.recovered
    }

    /// Materialize only a full record which occurs uniquely in this bound
    /// recovery under its stable object identity.
    ///
    /// `selected` is comparison evidence, not lookup authority. An adjacent
    /// record with the same ID is rejected and no other object is considered as
    /// a fallback. The returned resource is always constructed from the
    /// internally-owned canonical record.
    pub fn stored_object(
        &self,
        selected: &authority::RecoveredObject,
    ) -> Result<Arc<StoredObject>, StoreError> {
        let exact = self.exact_object(selected)?;
        stored_object_from_bindings(self.v2_objects.as_deref(), exact)
    }

    /// Report whether this exact internally recovered object ever appeared in
    /// any committed grant, including a grant later hidden from the live view
    /// by a tombstone. The selected record is comparison evidence only: it
    /// must uniquely and exactly match this bound recovery. No stable object
    /// ID, derivation ID, or historical record is returned.
    pub fn exact_object_has_grant_history(
        &self,
        selected: &authority::RecoveredObject,
    ) -> Result<bool, StoreError> {
        let exact = self.exact_object(selected)?;
        Ok(self
            .grant_history
            .iter()
            .any(|grant| grant.grant.object_id == exact.object_id))
    }

    fn exact_object(
        &self,
        selected: &authority::RecoveredObject,
    ) -> Result<&authority::RecoveredObject, StoreError> {
        let mut candidates = self
            .recovered
            .objects
            .iter()
            .filter(|candidate| candidate.object_id == selected.object_id);
        let exact = candidates.next().ok_or(StoreError::ObjectUnavailable)?;
        if candidates.next().is_some() {
            return Err(StoreError::Corrupt);
        }
        if exact != selected {
            return Err(StoreError::ObjectUnavailable);
        }
        Ok(exact)
    }
}

fn validate_c74_expectation_shape(
    expected: &C74ExactPostflightExpectation,
) -> Result<(), StoreError> {
    let root = &expected.root;
    let grant = &root.grant;
    let root_transaction = root.transaction_id.get();
    let artifact_transaction = root_transaction
        .checked_sub(2)
        .and_then(authority::TransactionId::new)
        .ok_or(StoreError::Corrupt)?;
    let artifact_object = root_transaction
        .checked_sub(1)
        .and_then(authority::ObjectId::new)
        .ok_or(StoreError::Corrupt)?;
    let root_derivation = root_transaction
        .checked_add(1)
        .and_then(authority::DerivationId::new)
        .ok_or(StoreError::Corrupt)?;
    let id_end = root_transaction.checked_add(2).ok_or(StoreError::Corrupt)?;
    let space_end = grant
        .target
        .space
        .get()
        .checked_add(1)
        .ok_or(StoreError::Corrupt)?;

    if grant.parent_id.is_some()
        || !grant.flags.is_root()
        || grant.target.slot != 0
        || grant.target.generation != 0
        || grant.object_id != artifact_object
        || grant.derivation_id != root_derivation
        || expected.artifact.object_id != artifact_object
        || expected.artifact.transaction_id != artifact_transaction
        || expected.artifact.is_external()
        || expected.artifact.byte_len() != expected.artifact.bytes.len() as u64
        || expected.artifact.prepare_sequence == 0
        || expected.artifact.prepare_sequence >= expected.artifact.commit_sequence
        || expected
            .artifact
            .commit_sequence
            .checked_add(1)
            .is_none_or(|sequence| sequence != root.prepare_sequence)
        || root
            .prepare_sequence
            .checked_add(1)
            .is_none_or(|sequence| sequence != root.commit_sequence)
        || expected.expected_id_high_water != id_end.max(space_end)
        || expected.expected_last_sequence != root.commit_sequence
    {
        return Err(StoreError::Corrupt);
    }

    match &expected.evidence {
        C74ExpectedEvidence::Absent { forbidden_kind } => {
            if *forbidden_kind == expected.artifact.object_kind {
                return Err(StoreError::Corrupt);
            }
        }
        C74ExpectedEvidence::RetainedOnly(evidence) => {
            let base = root_transaction.checked_sub(4).ok_or(StoreError::Corrupt)?;
            let evidence_transaction =
                authority::TransactionId::new(base).ok_or(StoreError::Corrupt)?;
            let evidence_object = base
                .checked_add(1)
                .and_then(authority::ObjectId::new)
                .ok_or(StoreError::Corrupt)?;
            if evidence.object_kind == expected.artifact.object_kind
                || evidence.transaction_id != evidence_transaction
                || evidence.object_id != evidence_object
                || evidence.is_external()
                || evidence.byte_len() != 112
                || evidence.bytes.len() != 112
                || evidence.prepare_sequence == 0
                || evidence
                    .prepare_sequence
                    .checked_add(2)
                    .is_none_or(|sequence| sequence != evidence.commit_sequence)
                || evidence
                    .commit_sequence
                    .checked_add(1)
                    .is_none_or(|sequence| sequence != expected.artifact.prepare_sequence)
            {
                return Err(StoreError::Corrupt);
            }
        }
    }
    Ok(())
}

fn validate_c74_exact_postflight(
    recovery: &BoundAuthorityRecovery,
    expected: &C74ExactPostflightExpectation,
) -> Result<C74ExactPostflightReceipt, StoreError> {
    validate_c74_expectation_shape(expected)?;
    let recovered = &recovery.recovered;
    if recovered.id_high_water != expected.expected_id_high_water
        || recovered.last_sequence != expected.expected_last_sequence
    {
        return Err(StoreError::Corrupt);
    }

    let component_space = expected.root.grant.target.space;
    let mut slots = recovered
        .slots
        .iter()
        .filter(|slot| slot.space == component_space);
    let slot = slots.next().ok_or(StoreError::Corrupt)?;
    if slots.next().is_some()
        || slot.slot != expected.root.grant.target.slot
        || slot.max_generation != expected.root.grant.target.generation
        || slot.live_derivation != Some(expected.root.grant.derivation_id)
    {
        return Err(StoreError::Corrupt);
    }

    let mut live_roots = recovered
        .grants
        .iter()
        .filter(|grant| grant.grant.target.space == component_space);
    if live_roots.next() != Some(&expected.root) || live_roots.next().is_some() {
        return Err(StoreError::Corrupt);
    }
    let mut complete_history = recovery
        .grant_history
        .iter()
        .filter(|grant| grant.grant.target.space == component_space);
    if complete_history.next() != Some(&expected.root) || complete_history.next().is_some() {
        return Err(StoreError::Corrupt);
    }

    let artifact = recovery.exact_object(&expected.artifact)?;
    if recovered
        .objects
        .iter()
        .filter(|object| object.object_kind == artifact.object_kind)
        .count()
        != 1
    {
        return Err(StoreError::Corrupt);
    }
    let mut artifact_history = recovery
        .grant_history
        .iter()
        .filter(|grant| grant.grant.object_id == artifact.object_id);
    if artifact_history.next() != Some(&expected.root) || artifact_history.next().is_some() {
        return Err(StoreError::Corrupt);
    }

    let bindings = recovery.v2_objects.as_deref().ok_or(StoreError::Corrupt)?;
    let artifact_bound = bindings
        .binary_search_by_key(&artifact.object_id, |binding| binding.stable_object_id)
        .ok()
        .map(|index| &bindings[index])
        .is_some_and(|binding| binding.matches(artifact));
    if !artifact_bound {
        return Err(StoreError::ObjectUnavailable);
    }

    match &expected.evidence {
        C74ExpectedEvidence::Absent { forbidden_kind } => {
            if recovered
                .objects
                .iter()
                .any(|object| object.object_kind == *forbidden_kind)
            {
                return Err(StoreError::Corrupt);
            }
        }
        C74ExpectedEvidence::RetainedOnly(expected_evidence) => {
            let evidence = recovery.exact_object(expected_evidence)?;
            if recovered
                .objects
                .iter()
                .filter(|object| object.object_kind == evidence.object_kind)
                .count()
                != 1
                || recovery
                    .grant_history
                    .iter()
                    .any(|grant| grant.grant.object_id == evidence.object_id)
                || bindings
                    .iter()
                    .any(|binding| binding.stable_object_id == evidence.object_id)
            {
                return Err(StoreError::Corrupt);
            }
        }
    }

    Ok(C74ExactPostflightReceipt { _sealed: () })
}

#[derive(Clone)]
pub struct AuthorityObjectResolver {
    v2_objects: Option<Arc<Vec<StorageV2RecoveredObject>>>,
}

impl AuthorityObjectResolver {
    pub fn stored_object(
        &self,
        object: &authority::RecoveredObject,
    ) -> Result<Arc<StoredObject>, StoreError> {
        stored_object_from_bindings(self.v2_objects.as_deref(), object)
    }
}

impl AuthoritySnapshot {
    /// Wrap a strict legacy preflight for external policy validation without
    /// granting any Storage V2 object bindings. This constructor exists for
    /// the migration coordinator, which must run the production M4 authority
    /// validator before importing any bytes into the disjoint V2 range.
    pub fn from_legacy_preflight(
        used_sectors: usize,
        preflight: authority::RecoveryPreflight,
    ) -> Result<Self, StoreError> {
        if preflight.store_id() != store_id() {
            return Err(StoreError::Corrupt);
        }
        let checkpoint = preflight
            .chain_checkpoint()
            .map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            formatted: true,
            checkpoint,
            used_sectors,
            preflight: Some(preflight),
            v2_objects: None,
        })
    }

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

    /// Construct a stored-object resource only when this exact recovered
    /// record is covered by the selected backend's authenticated binding set.
    pub fn stored_object(
        &self,
        object: &authority::RecoveredObject,
    ) -> Result<Arc<StoredObject>, StoreError> {
        stored_object_from_bindings(self.v2_objects.as_deref(), object)
    }

    pub fn object_resolver(&self) -> AuthorityObjectResolver {
        AuthorityObjectResolver {
            v2_objects: self.v2_objects.clone(),
        }
    }
}

fn root_policy_set_is_exact(
    recovered: &authority::RecoveredStore,
    roots: &[authority::RootPolicy],
) -> bool {
    let live_root_count = recovered
        .grants
        .iter()
        .filter(|grant| grant.grant.flags.is_root())
        .count();
    live_root_count == roots.len()
        && roots.iter().all(|root| {
            recovered
                .grants
                .iter()
                .filter(|grant| grant.grant.flags.is_root() && grant.grant == root.grant)
                .count()
                == 1
        })
}

fn stored_object_from_bindings(
    bindings: Option<&Vec<StorageV2RecoveredObject>>,
    object: &authority::RecoveredObject,
) -> Result<Arc<StoredObject>, StoreError> {
    match bindings {
        // An external record carries no inline bytes. Only Storage V2's exact
        // opaque token can name its payload; manufacturing a legacy object
        // name here would bind a zero-byte facade to a non-zero logical object.
        None if object.is_external() => Err(StoreError::ObjectUnavailable),
        None => Ok(StoredObject::from_recovered(object)),
        Some(bindings) => {
            let binding = bindings
                .binary_search_by_key(&object.object_id, |binding| binding.stable_object_id)
                .ok()
                .map(|index| &bindings[index])
                .filter(|binding| binding.matches(object))
                .ok_or(StoreError::ObjectUnavailable)?;
            Ok(StoredObject::from_storage_v2(object, binding.token.clone()))
        }
    }
}

impl StorageV2AuthoritySnapshot {
    fn token_for(&self, object: &authority::RecoveredObject) -> Option<&StorageV2ObjectToken> {
        self.objects
            .binary_search_by_key(&object.object_id, |binding| binding.stable_object_id)
            .ok()
            .map(|index| &self.objects[index])
            .filter(|binding| binding.matches(object))
            .map(|binding| &binding.token)
    }

    fn into_facade(self) -> Result<AuthoritySnapshot, StoreError> {
        let checkpoint = self
            .preflight
            .chain_checkpoint()
            .map_err(|_| StoreError::Corrupt)?;
        Ok(AuthoritySnapshot {
            formatted: true,
            checkpoint,
            used_sectors: self.used_sectors,
            preflight: Some(self.preflight),
            v2_objects: Some(Arc::new(self.objects)),
        })
    }
}

/// Kernel-only writer for authority records in the exact object-store journal.
/// Each operation rescans media and compares the caller's checkpoint before
/// writing, so no stale preview can fork the sequence/CRC chain.
#[derive(Clone)]
pub struct AuthorityJournal {
    inner: Arc<StoreInner>,
}

/// Linear provenance for the boot-selected and boot-proved Storage V2
/// authority journal.
///
/// The backend and current checkpoint are private, this type is deliberately
/// not `Clone`, and every operation consumes it. A failed append therefore
/// leaves the caller with no reusable predecessor handle; minting another one
/// requires a fresh boot-proved recovery. The handle exposes no backend
/// object identifier or media address.
#[must_use = "Storage V2 journal provenance is linear and must be consumed"]
struct StorageV2OnlyAuthorityJournal {
    backend: Arc<dyn StorageV2Backend>,
    checkpoint: ChainCheckpoint,
    external_root_policy_sha256: [u8; 32],
}

/// One boot-proved Storage V2 journal head and the exact snapshot which minted
/// it. The pair is deliberately opaque and move-only: callers cannot split it,
/// inspect its checkpoint/preflight, or substitute a caller-built snapshot
/// before the C7.4 installer consumes it.
///
/// ```compile_fail
/// use vibeos_object_store::{AuthoritySnapshot, StorageV2RecoveredAuthorityHead};
/// fn no_snapshot_or_checkpoint(
///     mut head: StorageV2RecoveredAuthorityHead,
///     replacement: AuthoritySnapshot,
/// ) {
///     let _ = head.snapshot();
///     let _ = head.checkpoint();
///     let _ = head.into_parts();
///     head.snapshot = replacement;
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_object_store::StorageV2RecoveredAuthorityHead;
/// fn require_clone<T: Clone>() {}
/// fn cannot_duplicate() { require_clone::<StorageV2RecoveredAuthorityHead>(); }
/// ```
#[must_use = "the sealed Storage V2 recovered head must be consumed"]
pub struct StorageV2RecoveredAuthorityHead {
    journal: StorageV2OnlyAuthorityJournal,
    snapshot: AuthoritySnapshot,
}

impl StorageV2RecoveredAuthorityHead {
    /// Exact external-policy commitment carried by the physical authority
    /// snapshot. This comparison digest contains no durable identity.
    pub const fn external_root_policy_sha256(&self) -> [u8; 32] {
        self.journal.external_root_policy_sha256
    }

    /// Commit one development artifact through the fixed private four-ID
    /// protocol, or recognize the exact already-committed successor.
    pub async fn install_c74_development(
        self,
        artifact_bytes: &[u8],
    ) -> Result<C74CommittedStorageV2Install, C74StorageV2InstallError> {
        c74_install(self, artifact_bytes, None).await
    }

    /// Commit canonical operator evidence, artifact, and root through the
    /// fixed private six-ID protocol, or recognize that exact successor.
    pub async fn install_c74_operator(
        self,
        artifact_bytes: &[u8],
        evidence_bytes: &[u8; C74_OPERATOR_EVIDENCE_LEN],
    ) -> Result<C74CommittedStorageV2Install, C74StorageV2InstallError> {
        c74_install(self, artifact_bytes, Some(evidence_bytes)).await
    }
}

/// Redacted C7.4 initial-install failures. No record, checkpoint, or durable
/// identity is carried by this error surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C74StorageV2InstallError {
    Unformatted,
    ExternalPolicyMismatch,
    ExistingComponentHistory,
    IdExhausted,
    Encode,
    Append(StoreError),
    PostflightMismatch,
}

/// Opaque acknowledged C7.4 Storage V2 successor. Its private expectation is
/// consumed only by independent physical readback; the public surface exposes
/// three root-presence booleans and no graph, object, evidence, or stable ID.
#[must_use = "the committed C7.4 successor must be physically recovered"]
pub struct C74CommittedStorageV2Install {
    journal: StorageV2OnlyAuthorityJournal,
    expectation: C74ExactPostflightExpectation,
    persistent_root_present: bool,
    program_root_present: bool,
    component_root_present: bool,
}

struct C74FixedRootPolicyUnion {
    persistent_present: bool,
    program_present: bool,
    persistent: [authority::RootConstraint; 1],
    program: [authority::RootConstraint; 1],
    component: [authority::RootConstraint; 1],
}

impl C74FixedRootPolicyUnion {
    fn new(
        persistent_present: bool,
        program_present: bool,
        component_present: bool,
    ) -> Result<Self, StoreError> {
        if !component_present {
            return Err(StoreError::Corrupt);
        }
        let fixed = |space_raw, rights, object_kind_raw| authority::RootConstraint {
            space: authority::SpaceId::new(space_raw)
                .expect("fixed C7.4 root-policy space is non-zero"),
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(rights),
            resource_kind: c74_resource_kind(),
            object_kind: authority::ObjectKind::new(object_kind_raw)
                .expect("fixed C7.4 root-policy object kind is non-zero"),
        };
        Ok(Self {
            persistent_present,
            program_present,
            persistent: [fixed(
                C74_PERSISTENT_SPACE_ID_RAW,
                authority::DurableRights::READ
                    .union(authority::DurableRights::GRANT)
                    .union(authority::DurableRights::REVOKE),
                C74_PERSISTENT_OBJECT_KIND_RAW,
            )],
            program: [fixed(
                C74_PROGRAM_SPACE_ID_RAW,
                authority::DurableRights::READ,
                C74_PROGRAM_OBJECT_KIND_RAW,
            )],
            component: [fixed(
                C74_COMPONENT_SPACE_ID_RAW,
                authority::DurableRights::READ,
                C74_COMPONENT_ARTIFACT_KIND_RAW,
            )],
        })
    }

    fn partitions(&self) -> Vec<authority::RootPolicyPartition<'_>> {
        let mut partitions = Vec::with_capacity(3);
        if self.persistent_present {
            partitions.push(authority::RootPolicyPartition {
                space: self.persistent[0].space,
                constraints: &self.persistent,
            });
        }
        if self.program_present {
            partitions.push(authority::RootPolicyPartition {
                space: self.program[0].space,
                constraints: &self.program,
            });
        }
        partitions.push(authority::RootPolicyPartition {
            space: self.component[0].space,
            constraints: &self.component,
        });
        partitions
    }
}

impl C74CommittedStorageV2Install {
    pub const fn persistent_root_present(&self) -> bool {
        self.persistent_root_present
    }

    pub const fn program_root_present(&self) -> bool {
        self.program_root_present
    }

    pub const fn component_root_present(&self) -> bool {
        self.component_root_present
    }

    /// Consume the acknowledged successor and independently re-read physical
    /// media under the private fixed complete C7.4 root-policy union. Success
    /// consumes all journal provenance and returns no identity, authority, or
    /// graph.
    ///
    /// ```compile_fail
    /// use vibeos_durable_format::RootPolicyPartition;
    /// use vibeos_object_store::C74CommittedStorageV2Install;
    /// fn cannot_supply_raw_policy(
    ///     committed: C74CommittedStorageV2Install,
    ///     partitions: &[RootPolicyPartition<'_>],
    /// ) {
    ///     let _ = committed.recover_bound(partitions);
    /// }
    /// ```
    pub async fn recover_bound(self) -> Result<(), StoreError> {
        let Self {
            journal,
            expectation,
            persistent_root_present,
            program_root_present,
            component_root_present,
        } = self;
        let union = C74FixedRootPolicyUnion::new(
            persistent_root_present,
            program_root_present,
            component_root_present,
        )?;
        let partitions = union.partitions();
        let (journal, receipt) = journal
            .recover_c74_bound_exact(&partitions, expectation)
            .await?;
        drop(receipt);
        drop(journal);
        Ok(())
    }
}

impl AuthorityJournal {
    /// Mint linear journal provenance only from the selected Storage V2
    /// backend's boot-proved authority. Non-V2 selections are rejected before
    /// invoking any backend recovery or legacy-media operation.
    pub async fn recover_storage_v2_only(
        &self,
    ) -> Result<StorageV2RecoveredAuthorityHead, StoreError> {
        let backend = storage_v2_only_backend(&self.inner)?;
        let recovered = backend.recover_authority().await?;
        let external_root_policy_sha256 = recovered.external_root_policy_sha256();
        let snapshot = recovered.into_facade()?;
        let journal = StorageV2OnlyAuthorityJournal {
            backend,
            checkpoint: snapshot.checkpoint,
            external_root_policy_sha256,
        };
        Ok(StorageV2RecoveredAuthorityHead { journal, snapshot })
    }

    /// Recover the selected durable backend and admit the complete union of
    /// independently owned root-policy partitions in one object-store-owned
    /// transition.
    ///
    /// Unlike [`Self::recover`], this method does not expose an intermediate
    /// [`AuthoritySnapshot`] which a caller could rewrite or replace. Root
    /// selection and `RecoveryPreflight::finish` run synchronously inside this
    /// method immediately after the canonical M4 scan or sealed Storage V2
    /// recovery. Omitting any partition which owns a live root, adding a
    /// foreign partition, or selecting an extra root therefore fails closed.
    pub async fn recover_bound(
        &self,
        partitions: &[authority::RootPolicyPartition<'_>],
    ) -> Result<BoundAuthorityRecovery, StoreError> {
        let snapshot = self.recover().await?;
        finish_recovered_snapshot(snapshot, partitions)
    }

    pub async fn recover(&self) -> Result<AuthoritySnapshot, StoreError> {
        if let Some(v2) = selected_v2_backend(&self.inner)? {
            return v2.recover_authority().await?.into_facade();
        }
        ensure_working_headroom()?;
        let operation = self.inner.begin()?;
        let result = async {
            // Recovery is deliberately valid after the migration controller
            // freezes the M4 writer branch.  Only append requires WRITE and a
            // flush barrier; scanning an already-published journal needs the
            // retained read capability alone.
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
        if let Some(v2) = selected_v2_backend(&self.inner)? {
            return v2.append_authority(expected, records).await?.into_facade();
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
        let v2_token = object.with(|stored| stored.v2_token.clone());
        match v2_token {
            Some(token) => {
                selected_v2_backend(&self.inner)?
                    .ok_or(StoreError::ObjectUnavailable)?
                    .read_object(&token)
                    .await
            }
            // A Staged boot reconstructs live capabilities from the frozen M4
            // authority before an explicit same-boot activation. Those exact
            // resources remain readable through the retained read-only M4
            // sibling for this rollback release; they never become an ambient
            // ObjectId lookup, and every post-activation write still selects
            // V2. A subsequent boot reconstructs the capability with a V2
            // token from VIBEAUT2.
            None => {
                gate_exact_m4_read(&self.inner)?;
                read_committed_object(self.inner.clone(), object).await
            }
        }
    }
}

async fn c74_install(
    head: StorageV2RecoveredAuthorityHead,
    artifact_bytes: &[u8],
    evidence_bytes: Option<&[u8; C74_OPERATOR_EVIDENCE_LEN]>,
) -> Result<C74CommittedStorageV2Install, C74StorageV2InstallError> {
    let StorageV2RecoveredAuthorityHead { journal, snapshot } = head;
    if journal.external_root_policy_sha256 != C74_STORAGE_V2_EXTERNAL_POLICY_SHA256 {
        return Err(C74StorageV2InstallError::ExternalPolicyMismatch);
    }
    c74_validate_sealed_snapshot(journal.checkpoint, &snapshot)?;

    let (journal, expectation, presence) =
        match c74_exact_existing(&snapshot, artifact_bytes, evidence_bytes)? {
            Some(expectation) => (journal, expectation, c74_root_presence(&snapshot)?),
            None => {
                c74_require_virgin_component_namespace(&snapshot)?;
                let records =
                    c74_encode_initial_records(&snapshot, artifact_bytes, evidence_bytes)?;
                let (journal, successor) = journal
                    .append(&records)
                    .await
                    .map_err(C74StorageV2InstallError::Append)?;
                let expectation = c74_exact_existing(&successor, artifact_bytes, evidence_bytes)?
                    .ok_or(C74StorageV2InstallError::PostflightMismatch)?;
                let presence = c74_root_presence(&successor)?;
                (journal, expectation, presence)
            }
        };
    if !presence.2 {
        return Err(C74StorageV2InstallError::PostflightMismatch);
    }
    Ok(C74CommittedStorageV2Install {
        journal,
        expectation,
        persistent_root_present: presence.0,
        program_root_present: presence.1,
        component_root_present: presence.2,
    })
}

fn c74_validate_sealed_snapshot(
    journal_checkpoint: ChainCheckpoint,
    snapshot: &AuthoritySnapshot,
) -> Result<(), C74StorageV2InstallError> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C74StorageV2InstallError::Unformatted)?;
    if !snapshot.formatted
        || journal_checkpoint != snapshot.checkpoint
        || preflight.store_id() != store_id()
        || preflight.chain_checkpoint().ok() != Some(snapshot.checkpoint)
    {
        return Err(C74StorageV2InstallError::Unformatted);
    }
    Ok(())
}

fn c74_space_id() -> authority::SpaceId {
    authority::SpaceId::new(C74_COMPONENT_SPACE_ID_RAW)
        .expect("fixed C7.4 Component space is non-zero")
}

fn c74_artifact_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C74_COMPONENT_ARTIFACT_KIND_RAW)
        .expect("fixed C7.4 artifact kind is non-zero")
}

fn c74_evidence_kind() -> authority::ObjectKind {
    authority::ObjectKind::new(C74_OPERATOR_EVIDENCE_KIND_RAW)
        .expect("fixed C7.4 evidence kind is non-zero")
}

fn c74_resource_kind() -> authority::ResourceKind {
    authority::ResourceKind::new(C74_STORED_OBJECT_RESOURCE_KIND_RAW)
        .expect("fixed C7.4 resource kind is non-zero")
}

fn c74_root_presence(
    snapshot: &AuthoritySnapshot,
) -> Result<(bool, bool, bool), C74StorageV2InstallError> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C74StorageV2InstallError::Unformatted)?;
    let live = |space_raw| {
        preflight
            .slots()
            .iter()
            .any(|slot| slot.space.get() == space_raw && slot.live_derivation.is_some())
    };
    Ok((
        live(0x5053),
        live(0x5052_4f47),
        live(C74_COMPONENT_SPACE_ID_RAW),
    ))
}

fn c74_require_virgin_component_namespace(
    snapshot: &AuthoritySnapshot,
) -> Result<(), C74StorageV2InstallError> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C74StorageV2InstallError::Unformatted)?;
    if preflight
        .slots()
        .iter()
        .any(|slot| slot.space == c74_space_id())
        || preflight
            .committed_grants()
            .iter()
            .any(|grant| grant.grant.target.space == c74_space_id())
        || preflight.committed_objects().iter().any(|object| {
            object.object_kind == c74_artifact_kind() || object.object_kind == c74_evidence_kind()
        })
    {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }
    Ok(())
}

fn c74_encode_initial_records(
    snapshot: &AuthoritySnapshot,
    artifact_bytes: &[u8],
    evidence_bytes: Option<&[u8; C74_OPERATOR_EVIDENCE_LEN]>,
) -> Result<Vec<[u8; journal::RECORD_SIZE]>, C74StorageV2InstallError> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C74StorageV2InstallError::Unformatted)?;
    let base = preflight.id_high_water().max(FIRST_ALLOCATABLE_ID);
    let id_count = if evidence_bytes.is_some() {
        C74_OPERATOR_ID_COUNT
    } else {
        C74_DEVELOPMENT_ID_COUNT
    };
    let id_end = base
        .checked_add(id_count)
        .ok_or(C74StorageV2InstallError::IdExhausted)?;
    let space_end = C74_COMPONENT_SPACE_ID_RAW
        .checked_add(1)
        .ok_or(C74StorageV2InstallError::IdExhausted)?;
    let mut chain = authority::RecordChain::from_checkpoint(store_id(), snapshot.checkpoint)
        .map_err(|_| C74StorageV2InstallError::Encode)?;
    let (high_water, next) = authority::preview_id_high_water(&chain, id_end.max(space_end))
        .map_err(|_| C74StorageV2InstallError::Encode)?;
    let mut records = high_water.records;
    chain = next;

    let artifact_offset = if let Some(evidence_bytes) = evidence_bytes {
        let evidence_transaction = c74_transaction(base)?;
        let evidence_object = c74_object(base, 1)?;
        let (evidence, next) = authority::preview_object_transaction(
            &chain,
            evidence_transaction,
            evidence_object,
            c74_evidence_kind(),
            evidence_bytes,
        )
        .map_err(|_| C74StorageV2InstallError::Encode)?;
        records.extend(evidence.records);
        chain = next;
        2
    } else {
        0
    };

    let artifact_transaction = c74_transaction(c74_offset(base, artifact_offset)?)?;
    let artifact_object = c74_object(base, artifact_offset + 1)?;
    let (artifact, next) = authority::preview_object_transaction(
        &chain,
        artifact_transaction,
        artifact_object,
        c74_artifact_kind(),
        artifact_bytes,
    )
    .map_err(|_| C74StorageV2InstallError::Encode)?;
    records.extend(artifact.records);
    chain = next;

    let root_transaction = c74_transaction(c74_offset(base, artifact_offset + 2)?)?;
    let root_derivation = c74_derivation(c74_offset(base, artifact_offset + 3)?)?;
    let root = authority::GrantRecord {
        derivation_id: root_derivation,
        parent_id: None,
        object_id: artifact_object,
        target: authority::SlotIdentity {
            space: c74_space_id(),
            slot: 0,
            generation: 0,
        },
        rights: authority::DurableRights::READ,
        resource_kind: c74_resource_kind(),
        flags: authority::GrantFlags::ROOT,
    };
    let (root, _) = authority::preview_grant_transaction(&chain, root_transaction, root)
        .map_err(|_| C74StorageV2InstallError::Encode)?;
    records.extend(root.records);
    Ok(records)
}

fn c74_exact_existing(
    snapshot: &AuthoritySnapshot,
    artifact_bytes: &[u8],
    evidence_bytes: Option<&[u8; C74_OPERATOR_EVIDENCE_LEN]>,
) -> Result<Option<C74ExactPostflightExpectation>, C74StorageV2InstallError> {
    let preflight = snapshot
        .preflight
        .as_ref()
        .ok_or(C74StorageV2InstallError::Unformatted)?;
    let has_component_history = preflight
        .slots()
        .iter()
        .any(|slot| slot.space == c74_space_id())
        || preflight
            .committed_grants()
            .iter()
            .any(|grant| grant.grant.target.space == c74_space_id())
        || preflight.committed_objects().iter().any(|object| {
            object.object_kind == c74_artifact_kind() || object.object_kind == c74_evidence_kind()
        });
    if !has_component_history {
        return Ok(None);
    }

    let mut slots = preflight
        .slots()
        .iter()
        .filter(|slot| slot.space == c74_space_id());
    let slot = slots
        .next()
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    if slots.next().is_some() || slot.slot != 0 || slot.max_generation != 0 {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }
    let mut component_grants = preflight
        .committed_grants()
        .iter()
        .filter(|grant| grant.grant.target.space == c74_space_id());
    let root = component_grants
        .next()
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    if component_grants.next().is_some()
        || slot.live_derivation != Some(root.grant.derivation_id)
        || root.grant.parent_id.is_some()
        || root.grant.flags != authority::GrantFlags::ROOT
        || root.grant.target.slot != 0
        || root.grant.target.generation != 0
        || root.grant.rights != authority::DurableRights::READ
        || root.grant.resource_kind != c74_resource_kind()
    {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }

    let root_transaction = root.transaction_id.get();
    let artifact_transaction = root_transaction
        .checked_sub(2)
        .and_then(authority::TransactionId::new)
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    let artifact_object = root_transaction
        .checked_sub(1)
        .and_then(authority::ObjectId::new)
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    let root_derivation = root_transaction
        .checked_add(1)
        .and_then(authority::DerivationId::new)
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    let expected_high_water = root_transaction
        .checked_add(2)
        .map(|end| end.max(C74_COMPONENT_SPACE_ID_RAW + 1))
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    if root.grant.object_id != artifact_object
        || root.grant.derivation_id != root_derivation
        || preflight.id_high_water() != expected_high_water
        || preflight.last_sequence() != root.commit_sequence
    {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }

    let mut artifacts = preflight
        .committed_objects()
        .iter()
        .filter(|object| object.object_kind == c74_artifact_kind());
    let artifact = artifacts
        .next()
        .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
    if artifacts.next().is_some()
        || artifact.object_id != artifact_object
        || artifact.transaction_id != artifact_transaction
        || artifact.is_external()
        || artifact.byte_len() != artifact.bytes.len() as u64
        || artifact.bytes.as_slice() != artifact_bytes
        || artifact.prepare_sequence == 0
        || artifact.prepare_sequence >= artifact.commit_sequence
        || artifact
            .commit_sequence
            .checked_add(1)
            .is_none_or(|sequence| sequence != root.prepare_sequence)
        || root
            .prepare_sequence
            .checked_add(1)
            .is_none_or(|sequence| sequence != root.commit_sequence)
    {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }
    let mut artifact_history = preflight
        .committed_grants()
        .iter()
        .filter(|grant| grant.grant.object_id == artifact.object_id);
    if artifact_history.next() != Some(root) || artifact_history.next().is_some() {
        return Err(C74StorageV2InstallError::ExistingComponentHistory);
    }

    let expectation = match evidence_bytes {
        None => {
            if preflight
                .committed_objects()
                .iter()
                .any(|object| object.object_kind == c74_evidence_kind())
            {
                return Err(C74StorageV2InstallError::ExistingComponentHistory);
            }
            C74ExactPostflightExpectation::development(
                root.clone(),
                artifact.clone(),
                c74_evidence_kind(),
                preflight.id_high_water(),
                preflight.last_sequence(),
            )
        }
        Some(evidence_bytes) => {
            let evidence_transaction = root_transaction
                .checked_sub(4)
                .and_then(authority::TransactionId::new)
                .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
            let evidence_object = root_transaction
                .checked_sub(3)
                .and_then(authority::ObjectId::new)
                .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
            let mut evidence_by_kind = preflight
                .committed_objects()
                .iter()
                .filter(|object| object.object_kind == c74_evidence_kind());
            let evidence = evidence_by_kind
                .next()
                .ok_or(C74StorageV2InstallError::ExistingComponentHistory)?;
            if evidence_by_kind.next().is_some()
                || evidence.object_id != evidence_object
                || evidence.transaction_id != evidence_transaction
                || evidence.is_external()
                || evidence.byte_len() != C74_OPERATOR_EVIDENCE_LEN as u64
                || evidence.bytes.as_slice() != evidence_bytes
                || evidence.prepare_sequence == 0
                || evidence
                    .prepare_sequence
                    .checked_add(2)
                    .is_none_or(|sequence| sequence != evidence.commit_sequence)
                || evidence
                    .commit_sequence
                    .checked_add(1)
                    .is_none_or(|sequence| sequence != artifact.prepare_sequence)
                || preflight
                    .committed_grants()
                    .iter()
                    .any(|grant| grant.grant.object_id == evidence_object)
            {
                return Err(C74StorageV2InstallError::ExistingComponentHistory);
            }
            C74ExactPostflightExpectation::operator(
                root.clone(),
                artifact.clone(),
                evidence.clone(),
                preflight.id_high_water(),
                preflight.last_sequence(),
            )
        }
    }
    .map_err(|_| C74StorageV2InstallError::ExistingComponentHistory)?;
    Ok(Some(expectation))
}

fn c74_offset(first: u128, amount: u128) -> Result<u128, C74StorageV2InstallError> {
    first
        .checked_add(amount)
        .ok_or(C74StorageV2InstallError::IdExhausted)
}

fn c74_transaction(raw: u128) -> Result<authority::TransactionId, C74StorageV2InstallError> {
    authority::TransactionId::new(raw).ok_or(C74StorageV2InstallError::IdExhausted)
}

fn c74_object(first: u128, amount: u128) -> Result<authority::ObjectId, C74StorageV2InstallError> {
    authority::ObjectId::new(c74_offset(first, amount)?)
        .ok_or(C74StorageV2InstallError::IdExhausted)
}

fn c74_derivation(raw: u128) -> Result<authority::DerivationId, C74StorageV2InstallError> {
    authority::DerivationId::new(raw).ok_or(C74StorageV2InstallError::IdExhausted)
}

impl StorageV2OnlyAuthorityJournal {
    /// Return the exact external root-policy commitment carried by the V2
    /// authority root which minted this handle. Callers must compare it to
    /// their own required profile; the journal makes no component-policy
    /// claim from Storage V2 selection alone.
    #[cfg(test)]
    const fn external_root_policy_sha256(&self) -> [u8; 32] {
        self.external_root_policy_sha256
    }

    /// Append against the exact checkpoint which minted this provenance.
    ///
    /// Success returns replacement provenance bound to the verified successor.
    /// Every error consumes the old handle, including errors whose durable
    /// effect is ambiguous, so retry requires a fresh boot/cold recovery.
    async fn append(
        self,
        records: &[[u8; journal::RECORD_SIZE]],
    ) -> Result<(Self, AuthoritySnapshot), StoreError> {
        if records.is_empty() {
            return Err(StoreError::Corrupt);
        }
        require_storage_v2_selection(self.backend.as_ref())?;
        let recovered = self
            .backend
            .append_authority_bound_to_policy(
                self.checkpoint,
                self.external_root_policy_sha256,
                records,
            )
            .await?;
        if recovered.external_root_policy_sha256() != self.external_root_policy_sha256 {
            return Err(StoreError::Corrupt);
        }
        let snapshot = recovered.into_facade()?;
        let successor = Self {
            backend: self.backend,
            checkpoint: snapshot.checkpoint,
            external_root_policy_sha256: self.external_root_policy_sha256,
        };
        Ok((successor, snapshot))
    }

    /// Independently re-read physical Storage V2 media and bind the complete
    /// recovered root-policy union. The readback must reproduce this handle's
    /// exact logical checkpoint; an intervening journal successor fails as
    /// `JournalChanged` and consumes the handle.
    #[cfg(test)]
    async fn recover_bound(
        self,
        partitions: &[authority::RootPolicyPartition<'_>],
    ) -> Result<(Self, BoundAuthorityRecovery), StoreError> {
        require_storage_v2_selection(self.backend.as_ref())?;
        let readback = self.backend.readback_authority().await?;
        if readback.external_root_policy_sha256() != self.external_root_policy_sha256 {
            return Err(StoreError::Corrupt);
        }
        let snapshot = readback.into_facade()?;
        if snapshot.checkpoint != self.checkpoint {
            return Err(StoreError::JournalChanged);
        }
        let recovered = finish_recovered_snapshot(snapshot, partitions)?;
        Ok((self, recovered))
    }

    /// Independently re-read physical Storage V2 media and check one sealed
    /// C7.4 exact predicate without returning the recovered graph or an object
    /// resource. The expectation is consumed, and success yields only an
    /// opaque receipt plus successor journal provenance.
    async fn recover_c74_bound_exact(
        self,
        partitions: &[authority::RootPolicyPartition<'_>],
        expectation: C74ExactPostflightExpectation,
    ) -> Result<(Self, C74ExactPostflightReceipt), StoreError> {
        require_storage_v2_selection(self.backend.as_ref())?;
        let readback = self.backend.readback_authority().await?;
        if readback.external_root_policy_sha256() != self.external_root_policy_sha256 {
            return Err(StoreError::Corrupt);
        }
        let snapshot = readback.into_facade()?;
        if snapshot.checkpoint != self.checkpoint {
            return Err(StoreError::JournalChanged);
        }
        let recovery = finish_recovered_snapshot(snapshot, partitions)?;
        let receipt = validate_c74_exact_postflight(&recovery, &expectation)?;
        Ok((self, receipt))
    }
}

/// Complete authority recovery only for a snapshot obtained directly inside
/// `AuthorityJournal::recover_bound`. Keeping this transition private is the
/// origin typestate boundary: public migration/inert snapshot constructors can
/// never call it, even if their caller manufactures a valid durable record
/// stream with the fixed store ID.
fn finish_recovered_snapshot(
    snapshot: AuthoritySnapshot,
    partitions: &[authority::RootPolicyPartition<'_>],
) -> Result<BoundAuthorityRecovery, StoreError> {
    let AuthoritySnapshot {
        formatted,
        checkpoint,
        used_sectors: _,
        preflight,
        v2_objects,
    } = snapshot;
    if !formatted {
        return Err(StoreError::Unformatted);
    }
    let preflight = preflight.ok_or(StoreError::Unformatted)?;
    let preflight_checkpoint = preflight
        .chain_checkpoint()
        .map_err(|_| StoreError::Corrupt)?;
    if preflight.store_id() != store_id() || preflight_checkpoint != checkpoint {
        return Err(StoreError::Corrupt);
    }

    let roots = authority::select_root_policy_union(&preflight, partitions)
        .map_err(|_| StoreError::Corrupt)?;
    let mut grant_history = Vec::new();
    grant_history
        .try_reserve_exact(preflight.committed_grants().len())
        .map_err(|_| StoreError::InsufficientMemory)?;
    grant_history.extend_from_slice(preflight.committed_grants());
    let recovered = preflight.finish(&roots).map_err(|_| StoreError::Corrupt)?;
    let recovered_checkpoint = recovered
        .chain_checkpoint()
        .map_err(|_| StoreError::Corrupt)?;
    if recovered.store_id != store_id()
        || recovered_checkpoint != checkpoint
        || !root_policy_set_is_exact(&recovered, &roots)
    {
        return Err(StoreError::Corrupt);
    }

    Ok(BoundAuthorityRecovery {
        recovered,
        grant_history,
        v2_objects,
    })
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
    clear_faulted_active_claim(&inner.active, task, domain);
}

fn clear_faulted_active_claim(
    active: &SpinLock<Option<ActiveClaim>>,
    task: TaskId,
    domain: AllocationDomain,
) -> bool {
    let mut active = active.lock();
    if active.is_some_and(|claim| claim.task == task && claim.domain == domain) {
        *active = None;
        true
    } else {
        false
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
    v2_token: Option<StorageV2ObjectToken>,
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
                v2_token: None,
            })
        })
    }

    fn from_storage_v2(
        object: &authority::RecoveredObject,
        token: StorageV2ObjectToken,
    ) -> Arc<Self> {
        system_allocation(|| {
            Arc::new(Self {
                store_id: store_id(),
                object_id: object.object_id,
                object_kind: object.object_kind,
                byte_len: object.byte_len() as usize,
                commit_sequence: object.commit_sequence,
                v2_token: Some(token),
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

    // Snapshot the destination before either backend can await. Publication
    // must never redirect a completed transaction into a restarted authority
    // domain, irrespective of which durable format is selected at boot.
    let target_incarnation = target.incarnation();
    let inner = lease.with(|service| service.inner.clone());
    if let Some(backend) = selected_v2_backend(&inner)? {
        // The logical v2 record stream admits inline objects up to the
        // journal chunk envelope; larger objects commit by reference with
        // their content in the V2 content-addressed store. The M4 backend
        // additionally enforces its physical sector capacity below.
        let external = bytes.len() > journal::MAX_OBJECT_SIZE;
        if bytes.len() as u64 > journal::MAX_EXTERNAL_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        // The V2 backend has its own exclusive mutable-store epoch, but that
        // epoch begins only at append time.  Keep the facade claim across
        // recovery, preview, the audited pre-write fault point, append, and
        // capability publication. Raw task cleanup can therefore identify and
        // release the exact abandoned operation even when the panic precedes
        // the first backend mutation.
        let operation = inner.begin()?;
        // V2 ordinary object publication must update the durable record stream
        // and its private binding table in the same checkpoint. The backend
        // owns the ID reservation and exact readback; the facade publishes
        // only the returned sealed object.
        let snapshot = backend.recover_authority().await?;
        let before = snapshot.into_facade()?;
        let old_high_water = before.id_high_water();
        let first_id = old_high_water.max(FIRST_ALLOCATABLE_ID);
        let object_raw = first_id.checked_add(1).ok_or(StoreError::IdExhausted)?;
        let exclusive_end = object_raw.checked_add(1).ok_or(StoreError::IdExhausted)?;
        let transaction_id = TransactionId::new(first_id).ok_or(StoreError::IdExhausted)?;
        let object_id = ObjectId::new(object_raw).ok_or(StoreError::IdExhausted)?;
        let mut chain = before.chain()?;
        let high_water = chain
            .append(None, journal::RecordBody::IdHighWater { exclusive_end })
            .map_err(map_encode_error)?;
        let declared_root = if external {
            // The content address is computed here, declared in the record,
            // and proved again by the backend's blob writer before anything
            // durable references it.
            Some(
                vibeos_blob_format::BlobDescriptor::from_content(object_kind.get(), bytes)
                    .map_err(|_| StoreError::ObjectTooLarge)?
                    .root,
            )
        } else {
            None
        };
        let mut records = match declared_root {
            Some(root) => {
                journal::preview_external_object_transaction(
                    &chain,
                    transaction_id,
                    object_id,
                    object_kind,
                    bytes.len() as u64,
                    root,
                )
                .map_err(map_encode_error)?
                .0
                .records
            }
            None => {
                journal::preview_object_transaction(
                    &chain,
                    transaction_id,
                    object_id,
                    object_kind,
                    bytes,
                )
                .map_err(map_encode_error)?
                .0
                .records
            }
        };
        // Reuse the transaction's record buffer instead of duplicating the
        // whole write set beside it: large objects carry thousands of
        // 512-byte chunk records and the extra copy wasted client quota.
        records
            .try_reserve_exact(1)
            .map_err(|_| StoreError::InsufficientMemory)?;
        records.insert(0, high_water);

        if let Some(target) = fault_target {
            assert_eq!(
                exec::current_task_id().expect("the injected store path runs in a task"),
                target.task
            );
            assert_eq!(heap::current_domain(), target.domain);
            FAULT_REACHED
                .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    count.checked_add(1)
                })
                .expect("store fault-injection counter exhausted");
            panic!("injected object-store fault before durable write");
        }

        let committed = backend
            .append_authority_with_payload(
                before.checkpoint,
                &records,
                declared_root.map(|_| (object_raw, bytes)),
            )
            .await?;
        let object = committed
            .preflight
            .committed_objects()
            .iter()
            .find(|candidate| {
                candidate.object_id == object_id
                    && candidate.object_kind == object_kind
                    && match declared_root {
                        Some(root) => {
                            candidate.external_root == Some(root)
                                && candidate.byte_len() == bytes.len() as u64
                        }
                        None => candidate.bytes.as_slice() == bytes,
                    }
            })
            .ok_or(StoreError::ObjectMismatch)?;
        let token = committed
            .token_for(object)
            .ok_or(StoreError::ObjectMismatch)?
            .clone();
        let resource = StoredObject::from_storage_v2(object, token);
        let published = target.publish(target_incarnation, resource, STORED_OBJECT_RIGHTS);
        operation.finish();
        return published.ok_or(StoreError::PublicationTargetRestarted);
    }
    ensure_working_headroom()?;
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
            v2_token: None,
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
    let token = object.with(|stored| stored.v2_token.clone());
    match token {
        Some(token) => {
            selected_v2_backend(&inner)?
                .ok_or(StoreError::ObjectUnavailable)?
                .read_object(&token)
                .await
        }
        // See AuthorityJournal::read: an already-held pre-activation
        // capability may read only its exact frozen M4 object until reboot.
        None => {
            gate_exact_m4_read(&inner)?;
            read_committed_object(inner, object).await
        }
    }
}

/// Encode content into the canonical Merkle-blob profile after enforcing the
/// storage envelope. The encoded image may exceed the inline journal chunk
/// budget: the V2 backend then commits it by reference through the external
/// object path, while the M4 backend still enforces its physical sector
/// capacity at publication.
pub fn encode_blob_object(
    object_kind: journal::ObjectKind,
    bytes: &[u8],
) -> Result<Vec<u8>, BlobStoreError> {
    let encoded_len = vibeos_blob_format::encoded_len(bytes.len())?;
    if encoded_len as u64 > journal::MAX_EXTERNAL_OBJECT_SIZE {
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

/// Encoded length of one canonical Merkle blob envelope for a content size.
/// Used by callers which must admit an object before allocating its envelope.
pub fn blob_encoded_len(content_len: usize) -> Result<usize, BlobError> {
    vibeos_blob_format::encoded_len(content_len)
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
    let info = validate_recovery_backend_info(backend_info(inner)?)?;

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

fn validate_recovery_backend_info(backend: BackendInfo) -> Result<BackendInfo, StoreError> {
    if backend.capacity_sectors < STORE_END_SECTOR {
        return Err(StoreError::DeviceTooSmall);
    }
    // `read_only` and `supports_flush` are mutation properties.  Requiring
    // either here would make the intentionally frozen M4 compatibility image
    // unreadable during V2Staged recovery.
    Ok(backend)
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
                v2_objects: None,
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
            v2_objects: None,
        }),
        Err(_) => Err(StoreError::Corrupt),
    }
}

fn selected_v2_backend(
    inner: &StoreInner,
) -> Result<Option<Arc<dyn StorageV2Backend>>, StoreError> {
    let Some(backend) = inner.v2.as_ref() else {
        return Ok(None);
    };
    if selection_uses_storage_v2(backend.selection())? {
        Ok(Some(backend.clone()))
    } else {
        Ok(None)
    }
}

/// Resolve only an explicitly selected Storage V2 backend. Unlike
/// `selected_v2_backend`, Legacy M4 is an error rather than a fallback. This
/// check performs no platform or backend journal I/O.
fn storage_v2_only_backend(inner: &StoreInner) -> Result<Arc<dyn StorageV2Backend>, StoreError> {
    let backend = inner.v2.as_ref().ok_or(StoreError::BackendAuthority)?;
    require_storage_v2_selection(backend.as_ref())?;
    Ok(backend.clone())
}

fn require_storage_v2_selection(backend: &dyn StorageV2Backend) -> Result<(), StoreError> {
    match backend.selection() {
        StorageBackendSelection::StorageV2 => Ok(()),
        StorageBackendSelection::LegacyM4 => Err(StoreError::BackendAuthority),
        StorageBackendSelection::Pending => Err(StoreError::Unformatted),
        StorageBackendSelection::FailClosed => Err(StoreError::Corrupt),
    }
}

fn selection_uses_storage_v2(selection: StorageBackendSelection) -> Result<bool, StoreError> {
    match selection {
        StorageBackendSelection::LegacyM4 => Ok(false),
        StorageBackendSelection::StorageV2 => Ok(true),
        StorageBackendSelection::Pending => Err(StoreError::Unformatted),
        StorageBackendSelection::FailClosed => Err(StoreError::Corrupt),
    }
}

/// Gate the retained exact-capability M4 read path through the same backend
/// selection used by ordinary V2 reads. A same-boot V2 activation may retain
/// an already-held M4 capability, but ambiguous or corrupt selection must fail
/// closed before any legacy media is read.
fn gate_exact_m4_read(inner: &StoreInner) -> Result<(), StoreError> {
    selected_v2_backend(inner)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};
    use core::task::{Context, Poll, Waker};
    use vibeos_storage_device::{DeviceId, DeviceSession};

    const TEST_OBJECT_RAW: u128 = 0x901;
    const TEST_OBJECT_TRANSACTION_RAW: u128 = 0x902;
    const TEST_DERIVATION_RAW: u128 = 0x903;
    const TEST_GRANT_TRANSACTION_RAW: u128 = 0x904;
    const TEST_SPACE_RAW: u128 = 0x905;

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("test future unexpectedly yielded"),
        }
    }

    struct NoIoPlatform {
        calls: AtomicUsize,
    }

    impl NoIoPlatform {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }
    }

    impl Platform for NoIoPlatform {
        fn info(&self) -> Result<BackendInfo, BackendError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Err(BackendError::Offline)
        }

        fn read_sector(
            &self,
            _session: DeviceSession,
            _sector: u64,
        ) -> BackendFuture<'_, [u8; 512]> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Err(BackendError::Offline) })
        }

        fn write_sector_durable(
            &self,
            _session: DeviceSession,
            _sector: u64,
            _bytes: [u8; 512],
        ) -> BackendMutationFuture<'_, ()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Err(MutationFailure::not_submitted(BackendError::Offline)) })
        }

        fn has_working_headroom(&self, _required: usize) -> bool {
            self.calls.fetch_add(1, Ordering::AcqRel);
            false
        }
    }

    struct TestStorageV2Backend {
        selection: AtomicU8,
        boot_proved: AtomicBool,
        fail_append: AtomicBool,
        policy_sha256: SpinLock<[u8; 32]>,
        recover_calls: AtomicUsize,
        readback_calls: AtomicUsize,
        append_calls: AtomicUsize,
    }

    impl TestStorageV2Backend {
        fn new(selection: StorageBackendSelection, boot_proved: bool) -> Self {
            Self {
                selection: AtomicU8::new(Self::encode_selection(selection)),
                boot_proved: AtomicBool::new(boot_proved),
                fail_append: AtomicBool::new(false),
                policy_sha256: SpinLock::new([0x5a; 32]),
                recover_calls: AtomicUsize::new(0),
                readback_calls: AtomicUsize::new(0),
                append_calls: AtomicUsize::new(0),
            }
        }

        const fn encode_selection(selection: StorageBackendSelection) -> u8 {
            match selection {
                StorageBackendSelection::Pending => 0,
                StorageBackendSelection::LegacyM4 => 1,
                StorageBackendSelection::StorageV2 => 2,
                StorageBackendSelection::FailClosed => 3,
            }
        }

        fn decode_selection(encoded: u8) -> StorageBackendSelection {
            match encoded {
                0 => StorageBackendSelection::Pending,
                1 => StorageBackendSelection::LegacyM4,
                2 => StorageBackendSelection::StorageV2,
                _ => StorageBackendSelection::FailClosed,
            }
        }

        fn set_selection(&self, selection: StorageBackendSelection) {
            self.selection
                .store(Self::encode_selection(selection), Ordering::Release);
        }

        fn fail_next_append(&self) {
            self.fail_append.store(true, Ordering::Release);
        }

        fn complete_cold_recovery(&self) {
            self.boot_proved.store(true, Ordering::Release);
        }

        fn set_policy_byte(&self, byte: u8) {
            *self.policy_sha256.lock() = [byte; 32];
        }

        fn set_policy_sha256(&self, policy_sha256: [u8; 32]) {
            *self.policy_sha256.lock() = policy_sha256;
        }

        fn snapshot(&self) -> StorageV2AuthoritySnapshot {
            let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
            let selected = &preflight.committed_objects()[0];
            let objects = alloc::vec![StorageV2RecoveredObject::new(
                selected,
                StorageV2ObjectToken::new(0xfeed_beef_u64),
            )];
            StorageV2AuthoritySnapshot::new(
                used_sectors,
                preflight,
                *self.policy_sha256.lock(),
                objects,
            )
            .unwrap()
        }
    }

    impl StorageV2Backend for TestStorageV2Backend {
        fn selection(&self) -> StorageBackendSelection {
            Self::decode_selection(self.selection.load(Ordering::Acquire))
        }

        fn info(&self) -> StorageV2BackendInfo {
            StorageV2BackendInfo::default()
        }

        fn recover_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            self.recover_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if !self.boot_proved.load(Ordering::Acquire) {
                    return Err(StoreError::Corrupt);
                }
                Ok(self.snapshot())
            })
        }

        fn readback_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            self.readback_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if !self.boot_proved.load(Ordering::Acquire) {
                    return Err(StoreError::Corrupt);
                }
                Ok(self.snapshot())
            })
        }

        fn append_authority<'a>(
            &'a self,
            expected: ChainCheckpoint,
            _records: &'a [[u8; journal::RECORD_SIZE]],
        ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
            self.append_calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if self.fail_append.swap(false, Ordering::AcqRel) {
                    self.boot_proved.store(false, Ordering::Release);
                    return Err(StoreError::Corrupt);
                }
                let snapshot = self.snapshot();
                if snapshot.preflight.chain_checkpoint().ok() != Some(expected) {
                    return Err(StoreError::JournalChanged);
                }
                Ok(snapshot)
            })
        }

        fn append_authority_bound_to_policy<'a>(
            &'a self,
            expected: ChainCheckpoint,
            expected_external_root_policy_sha256: [u8; 32],
            records: &'a [[u8; journal::RECORD_SIZE]],
        ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
            Box::pin(async move {
                if *self.policy_sha256.lock() != expected_external_root_policy_sha256 {
                    self.boot_proved.store(false, Ordering::Release);
                    return Err(StoreError::Corrupt);
                }
                let result = self.append_authority(expected, records).await;
                if result.is_err() {
                    self.boot_proved.store(false, Ordering::Release);
                }
                result
            })
        }

        fn read_object<'a>(
            &'a self,
            _object: &'a StorageV2ObjectToken,
        ) -> StorageV2Future<'a, Vec<u8>> {
            Box::pin(async { Err(StoreError::ObjectUnavailable) })
        }
    }

    /// Exercises the trait's fail-closed default. Supporting ordinary V2
    /// appends is deliberately insufficient to implement the sealed
    /// policy-bound C7.4 transition.
    struct StorageV2BackendWithoutPolicyBoundAppend {
        inner: Arc<TestStorageV2Backend>,
    }

    impl StorageV2Backend for StorageV2BackendWithoutPolicyBoundAppend {
        fn selection(&self) -> StorageBackendSelection {
            self.inner.selection()
        }

        fn info(&self) -> StorageV2BackendInfo {
            self.inner.info()
        }

        fn recover_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            self.inner.recover_authority()
        }

        fn readback_authority(&self) -> StorageV2Future<'_, StorageV2AuthoritySnapshot> {
            self.inner.readback_authority()
        }

        fn append_authority<'a>(
            &'a self,
            expected: ChainCheckpoint,
            records: &'a [[u8; journal::RECORD_SIZE]],
        ) -> StorageV2Future<'a, StorageV2AuthoritySnapshot> {
            self.inner.append_authority(expected, records)
        }

        fn read_object<'a>(
            &'a self,
            object: &'a StorageV2ObjectToken,
        ) -> StorageV2Future<'a, Vec<u8>> {
            self.inner.read_object(object)
        }
    }

    fn test_authority_journal(
        backend: Option<Arc<dyn StorageV2Backend>>,
    ) -> (AuthorityJournal, Arc<NoIoPlatform>) {
        let platform = Arc::new(NoIoPlatform::new());
        let inner = Arc::new(StoreInner {
            platform: platform.clone(),
            v2: backend,
            active: SpinLock::new_recoverable(None),
            state: SpinLock::new(RuntimeState::COLD),
        });
        (AuthorityJournal { inner }, platform)
    }

    fn test_object_kind() -> authority::ObjectKind {
        authority::ObjectKind::new(0x434d_5031).unwrap()
    }

    fn test_root_constraint() -> authority::RootConstraint {
        authority::RootConstraint {
            space: authority::SpaceId::new(TEST_SPACE_RAW).unwrap(),
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(authority::DurableRights::READ),
            resource_kind: authority::ResourceKind::new(0x5354_4f52).unwrap(),
            object_kind: test_object_kind(),
        }
    }

    fn test_root_grant() -> authority::GrantRecord {
        authority::GrantRecord {
            derivation_id: authority::DerivationId::new(TEST_DERIVATION_RAW).unwrap(),
            parent_id: None,
            object_id: authority::ObjectId::new(TEST_OBJECT_RAW).unwrap(),
            target: authority::SlotIdentity {
                space: authority::SpaceId::new(TEST_SPACE_RAW).unwrap(),
                slot: 0,
                generation: 0,
            },
            rights: authority::DurableRights::READ,
            resource_kind: authority::ResourceKind::new(0x5354_4f52).unwrap(),
            flags: authority::GrantFlags::ROOT,
        }
    }

    fn test_preflight(
        durable_store: StoreId,
        external: bool,
    ) -> (
        authority::RecoveryPreflight,
        Vec<authority::RootPolicy>,
        usize,
    ) {
        let mut chain = authority::RecordChain::new(durable_store);
        let mut records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let (high_water, next) = authority::preview_id_high_water(&chain, 0x1000).unwrap();
        records.extend(high_water.records);
        chain = next;

        let object_transaction =
            authority::TransactionId::new(TEST_OBJECT_TRANSACTION_RAW).unwrap();
        let object_id = authority::ObjectId::new(TEST_OBJECT_RAW).unwrap();
        let (object_records, next) = if external {
            let (encoded, next) = authority::preview_external_object_transaction(
                &chain,
                object_transaction,
                object_id,
                test_object_kind(),
                4096,
                [0x3c; 32],
            )
            .unwrap();
            (encoded.records, next)
        } else {
            let (encoded, next) = authority::preview_object_transaction(
                &chain,
                object_transaction,
                object_id,
                test_object_kind(),
                &[0x5a, 0xa5],
            )
            .unwrap();
            (encoded.records, next)
        };
        records.extend(object_records);
        chain = next;

        let (grant, _next) = authority::preview_grant_transaction(
            &chain,
            authority::TransactionId::new(TEST_GRANT_TRANSACTION_RAW).unwrap(),
            test_root_grant(),
        )
        .unwrap();
        records.extend(grant.records);

        let preflight = authority::preflight_recovery(&records, durable_store).unwrap();
        let roots = preflight
            .select_roots(core::slice::from_ref(&test_root_constraint()))
            .unwrap();
        (preflight, roots, records.len())
    }

    fn c74_operator_fixture(
        bind_evidence: bool,
    ) -> (
        AuthoritySnapshot,
        authority::RootConstraint,
        C74ExactPostflightExpectation,
    ) {
        const BASE: u128 = 0x880;
        let durable_store = store_id();
        let evidence_kind = authority::ObjectKind::new(0x434d_4531).unwrap();
        let artifact_kind = test_object_kind();
        let space = authority::SpaceId::new(TEST_SPACE_RAW).unwrap();
        let resource_kind = authority::ResourceKind::new(0x5354_4f52).unwrap();
        let mut chain = authority::RecordChain::new(durable_store);
        let mut records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let expected_id_high_water = (BASE + 6).max(space.get() + 1);
        let (high_water, next) =
            authority::preview_id_high_water(&chain, expected_id_high_water).unwrap();
        records.extend(high_water.records);
        chain = next;

        let (encoded, next) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(BASE).unwrap(),
            authority::ObjectId::new(BASE + 1).unwrap(),
            evidence_kind,
            &[0xa5; 112],
        )
        .unwrap();
        records.extend(encoded.records);
        chain = next;
        let (encoded, next) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(BASE + 2).unwrap(),
            authority::ObjectId::new(BASE + 3).unwrap(),
            artifact_kind,
            &[0x5a, 0xa5],
        )
        .unwrap();
        records.extend(encoded.records);
        chain = next;
        let grant = authority::GrantRecord {
            derivation_id: authority::DerivationId::new(BASE + 5).unwrap(),
            parent_id: None,
            object_id: authority::ObjectId::new(BASE + 3).unwrap(),
            target: authority::SlotIdentity {
                space,
                slot: 0,
                generation: 0,
            },
            rights: authority::DurableRights::READ,
            resource_kind,
            flags: authority::GrantFlags::ROOT,
        };
        let (encoded, _next) = authority::preview_grant_transaction(
            &chain,
            authority::TransactionId::new(BASE + 4).unwrap(),
            grant,
        )
        .unwrap();
        records.extend(encoded.records);

        let preflight = authority::preflight_recovery(&records, durable_store).unwrap();
        let expected_root = preflight.committed_grants()[0].clone();
        let evidence = preflight
            .committed_objects()
            .iter()
            .find(|object| object.object_kind == evidence_kind)
            .unwrap()
            .clone();
        let artifact = preflight
            .committed_objects()
            .iter()
            .find(|object| object.object_kind == artifact_kind)
            .unwrap()
            .clone();
        let expectation = C74ExactPostflightExpectation::operator(
            expected_root,
            artifact.clone(),
            evidence.clone(),
            preflight.id_high_water(),
            preflight.last_sequence(),
        )
        .unwrap();
        let constraint = authority::RootConstraint {
            space,
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(authority::DurableRights::READ),
            resource_kind,
            object_kind: artifact_kind,
        };
        let mut bindings = alloc::vec![StorageV2RecoveredObject::new(
            &artifact,
            StorageV2ObjectToken::new(0xc74_u64),
        )];
        if bind_evidence {
            bindings.push(StorageV2RecoveredObject::new(
                &evidence,
                StorageV2ObjectToken::new(0xbad_u64),
            ));
        }
        let snapshot =
            StorageV2AuthoritySnapshot::new(records.len(), preflight, [0x5a; 32], bindings)
                .unwrap()
                .into_facade()
                .unwrap();
        (snapshot, constraint, expectation)
    }

    fn tombstoned_grant_preflight() -> (authority::RecoveryPreflight, usize) {
        let mut chain = authority::RecordChain::new(store_id());
        let mut records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let (high_water, next) = authority::preview_id_high_water(&chain, 0x1000).unwrap();
        records.extend(high_water.records);
        chain = next;
        let (object, next) = authority::preview_object_transaction(
            &chain,
            authority::TransactionId::new(TEST_OBJECT_TRANSACTION_RAW).unwrap(),
            authority::ObjectId::new(TEST_OBJECT_RAW).unwrap(),
            test_object_kind(),
            &[0x5a, 0xa5],
        )
        .unwrap();
        records.extend(object.records);
        chain = next;
        let (grant, next) = authority::preview_grant_transaction(
            &chain,
            authority::TransactionId::new(TEST_GRANT_TRANSACTION_RAW).unwrap(),
            test_root_grant(),
        )
        .unwrap();
        records.extend(grant.records);
        chain = next;
        let (revoke, _next) = authority::preview_revoke_transaction(
            &chain,
            authority::TransactionId::new(0x906).unwrap(),
            authority::DerivationId::new(TEST_DERIVATION_RAW).unwrap(),
        )
        .unwrap();
        records.extend(revoke.records);
        (
            authority::preflight_recovery(&records, store_id()).unwrap(),
            records.len(),
        )
    }

    fn two_root_preflight() -> (
        authority::RecoveryPreflight,
        authority::RootConstraint,
        authority::RootConstraint,
        usize,
    ) {
        let durable_store = store_id();
        let first_object = authority::ObjectId::new(0x1101).unwrap();
        let second_object = authority::ObjectId::new(0x1102).unwrap();
        let first_kind = test_object_kind();
        let second_kind = authority::ObjectKind::new(first_kind.get() + 1).unwrap();
        let first_space = authority::SpaceId::new(0x1501).unwrap();
        let second_space = authority::SpaceId::new(0x1502).unwrap();
        let resource_kind = authority::ResourceKind::new(0x5354_4f52).unwrap();

        let mut chain = authority::RecordChain::new(durable_store);
        let mut records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let (high_water, next) = authority::preview_id_high_water(&chain, 0x2000).unwrap();
        records.extend(high_water.records);
        chain = next;

        for (transaction, object, kind, bytes) in [
            (
                authority::TransactionId::new(0x1201).unwrap(),
                first_object,
                first_kind,
                &[0x11][..],
            ),
            (
                authority::TransactionId::new(0x1202).unwrap(),
                second_object,
                second_kind,
                &[0x22][..],
            ),
        ] {
            let (encoded, next) =
                authority::preview_object_transaction(&chain, transaction, object, kind, bytes)
                    .unwrap();
            records.extend(encoded.records);
            chain = next;
        }

        for (transaction_raw, derivation_raw, object, space) in [
            (0x1401, 0x1301, first_object, first_space),
            (0x1402, 0x1302, second_object, second_space),
        ] {
            let grant = authority::GrantRecord {
                derivation_id: authority::DerivationId::new(derivation_raw).unwrap(),
                parent_id: None,
                object_id: object,
                target: authority::SlotIdentity {
                    space,
                    slot: 0,
                    generation: 0,
                },
                rights: authority::DurableRights::READ,
                resource_kind,
                flags: authority::GrantFlags::ROOT,
            };
            let (encoded, next) = authority::preview_grant_transaction(
                &chain,
                authority::TransactionId::new(transaction_raw).unwrap(),
                grant,
            )
            .unwrap();
            records.extend(encoded.records);
            chain = next;
        }

        let first = authority::RootConstraint {
            space: first_space,
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(authority::DurableRights::READ),
            resource_kind,
            object_kind: first_kind,
        };
        let second = authority::RootConstraint {
            space: second_space,
            first_slot: 0,
            last_slot_inclusive: 0,
            rights: authority::RootRightsConstraint::exact(authority::DurableRights::READ),
            resource_kind,
            object_kind: second_kind,
        };
        (
            authority::preflight_recovery(&records, durable_store).unwrap(),
            first,
            second,
            records.len(),
        )
    }

    fn snapshot_from_preflight(
        preflight: authority::RecoveryPreflight,
        used_sectors: usize,
        with_v2_binding: bool,
    ) -> AuthoritySnapshot {
        let checkpoint = preflight.chain_checkpoint().unwrap();
        let v2_objects = with_v2_binding.then(|| {
            let selected = &preflight.committed_objects()[0];
            Arc::new(alloc::vec![StorageV2RecoveredObject::new(
                selected,
                StorageV2ObjectToken::new(0xfeed_beef_u64),
            )])
        });
        AuthoritySnapshot {
            formatted: true,
            checkpoint,
            used_sectors,
            preflight: Some(preflight),
            v2_objects,
        }
    }

    fn c74_format_only_snapshot() -> (AuthoritySnapshot, Vec<[u8; journal::RECORD_SIZE]>) {
        let mut chain = authority::RecordChain::new(store_id());
        let records = alloc::vec![chain.append(None, authority::RecordBody::Format).unwrap()];
        let preflight = authority::preflight_recovery(&records, store_id()).unwrap();
        (
            snapshot_from_preflight(preflight, records.len(), false),
            records,
        )
    }

    fn c74_encoded_successor(
        artifact_bytes: &[u8],
        evidence_bytes: Option<&[u8; C74_OPERATOR_EVIDENCE_LEN]>,
    ) -> AuthoritySnapshot {
        let (before, mut records) = c74_format_only_snapshot();
        let appended = c74_encode_initial_records(&before, artifact_bytes, evidence_bytes).unwrap();
        records.extend(appended);
        let preflight = authority::preflight_recovery(&records, store_id()).unwrap();
        snapshot_from_preflight(preflight, records.len(), false)
    }

    /// White-box stand-in for the synchronous tail of
    /// `AuthorityJournal::recover_bound`. Production callers cannot invoke
    /// `finish_recovered_snapshot` with an inert or migration snapshot.
    fn finish_single_test_snapshot(
        snapshot: AuthoritySnapshot,
    ) -> Result<BoundAuthorityRecovery, StoreError> {
        let constraint = test_root_constraint();
        let partitions = [authority::RootPolicyPartition {
            space: constraint.space,
            constraints: core::slice::from_ref(&constraint),
        }];
        finish_recovered_snapshot(snapshot, &partitions)
    }

    #[test]
    fn recovery_backend_accepts_frozen_read_only_media() {
        let session = DeviceSession::new(DeviceId::new(1).unwrap(), 1).unwrap();
        let backend = BackendInfo {
            capacity_sectors: STORE_END_SECTOR,
            read_only: true,
            supports_flush: false,
            session,
        };
        assert_eq!(validate_recovery_backend_info(backend), Ok(backend));
    }

    #[test]
    fn recovery_backend_still_rejects_a_short_device() {
        let session = DeviceSession::new(DeviceId::new(1).unwrap(), 1).unwrap();
        let backend = BackendInfo {
            capacity_sectors: STORE_END_SECTOR - 1,
            read_only: false,
            supports_flush: true,
            session,
        };
        assert_eq!(
            validate_recovery_backend_info(backend),
            Err(StoreError::DeviceTooSmall)
        );
    }

    #[test]
    fn exact_m4_read_gate_covers_all_backend_selections() {
        assert_eq!(
            selection_uses_storage_v2(StorageBackendSelection::LegacyM4),
            Ok(false)
        );
        assert_eq!(
            selection_uses_storage_v2(StorageBackendSelection::StorageV2),
            Ok(true)
        );
        assert_eq!(
            selection_uses_storage_v2(StorageBackendSelection::Pending),
            Err(StoreError::Unformatted)
        );
        assert_eq!(
            selection_uses_storage_v2(StorageBackendSelection::FailClosed),
            Err(StoreError::Corrupt)
        );
    }

    #[test]
    fn storage_v2_only_mint_rejects_every_non_v2_selection_before_io() {
        for (selection, expected) in [
            (
                StorageBackendSelection::LegacyM4,
                StoreError::BackendAuthority,
            ),
            (StorageBackendSelection::Pending, StoreError::Unformatted),
            (StorageBackendSelection::FailClosed, StoreError::Corrupt),
        ] {
            let backend = Arc::new(TestStorageV2Backend::new(selection, true));
            let (journal, platform) = test_authority_journal(Some(backend.clone()));
            let result = poll_ready(journal.recover_storage_v2_only());
            assert_eq!(result.err(), Some(expected));
            assert_eq!(backend.recover_calls.load(Ordering::Acquire), 0);
            assert_eq!(backend.readback_calls.load(Ordering::Acquire), 0);
            assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
            assert_eq!(platform.calls(), 0);
        }

        let (journal, platform) = test_authority_journal(None);
        assert_eq!(
            poll_ready(journal.recover_storage_v2_only()).err(),
            Some(StoreError::BackendAuthority)
        );
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn storage_v2_only_mint_requires_boot_proof() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            false,
        ));
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        assert_eq!(
            poll_ready(journal.recover_storage_v2_only()).err(),
            Some(StoreError::Corrupt)
        );
        assert_eq!(backend.recover_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.readback_calls.load(Ordering::Acquire), 0);
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn c74_public_install_rejects_non_v2_policy_before_append() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();

        assert_eq!(
            poll_ready(head.install_c74_development(b"not decoded here")).err(),
            Some(C74StorageV2InstallError::ExternalPolicyMismatch)
        );
        assert_eq!(backend.recover_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
        assert_eq!(backend.readback_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn c74_object_store_commitment_matches_the_frozen_loader_digest() {
        const FROZEN_LOADER_DIGEST: [u8; 32] = [
            0x85, 0x6f, 0x31, 0x4c, 0xfb, 0xd8, 0x21, 0xec, 0x0f, 0x87, 0x30, 0x90, 0x39, 0x48,
            0xa8, 0xc1, 0x65, 0xbf, 0x5c, 0xe8, 0x6b, 0xf4, 0x16, 0xda, 0x2b, 0x21, 0x7b, 0xf6,
            0xc3, 0x49, 0x2a, 0xa3,
        ];
        assert_eq!(C74_STORAGE_V2_EXTERNAL_POLICY_SHA256, FROZEN_LOADER_DIGEST);

        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        backend.set_policy_sha256(FROZEN_LOADER_DIGEST);
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();

        // This fixture already contains the reserved artifact kind. Reaching
        // that rejection proves the object-store hard gate accepted exactly
        // the frozen V2 digest instead of reflecting a caller-selected value.
        assert_eq!(
            poll_ready(head.install_c74_development(b"artifact")).err(),
            Some(C74StorageV2InstallError::ExistingComponentHistory)
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn c74_sealed_head_rejects_an_internal_checkpoint_snapshot_mismatch() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        backend.set_policy_sha256(C74_STORAGE_V2_EXTERNAL_POLICY_SHA256);
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let mut head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        head.snapshot.checkpoint.next_sequence += 1;

        assert_eq!(
            poll_ready(head.install_c74_development(b"artifact")).err(),
            Some(C74StorageV2InstallError::Unformatted)
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn c74_private_encoder_recognizes_only_its_exact_fixed_successors() {
        let artifact = b"canonical component artifact";
        let development = c74_encoded_successor(artifact, None);
        let development_expectation = c74_exact_existing(&development, artifact, None)
            .unwrap()
            .expect("the fixed development successor must be recognized");
        validate_c74_expectation_shape(&development_expectation).unwrap();
        assert_eq!(
            development_expectation.root.grant.target.space,
            c74_space_id()
        );
        assert_eq!(development_expectation.root.grant.target.slot, 0);
        assert_eq!(development_expectation.root.grant.target.generation, 0);
        assert_eq!(
            development_expectation.root.grant.rights,
            authority::DurableRights::READ
        );
        assert_eq!(
            development_expectation.root.grant.resource_kind,
            c74_resource_kind()
        );
        assert!(matches!(
            development_expectation.evidence,
            C74ExpectedEvidence::Absent { .. }
        ));
        assert_eq!(c74_root_presence(&development), Ok((false, false, true)));
        assert_eq!(
            c74_exact_existing(&development, b"adjacent artifact", None).err(),
            Some(C74StorageV2InstallError::ExistingComponentHistory)
        );

        let evidence = [0xa7; C74_OPERATOR_EVIDENCE_LEN];
        let operator = c74_encoded_successor(artifact, Some(&evidence));
        let operator_expectation = c74_exact_existing(&operator, artifact, Some(&evidence))
            .unwrap()
            .expect("the fixed operator successor must be recognized");
        validate_c74_expectation_shape(&operator_expectation).unwrap();
        let C74ExpectedEvidence::RetainedOnly(expected_evidence) = &operator_expectation.evidence
        else {
            panic!("operator evidence predicate missing")
        };
        assert_eq!(expected_evidence.bytes.as_slice(), &evidence);
        assert!(!operator
            .preflight
            .as_ref()
            .unwrap()
            .committed_grants()
            .iter()
            .any(|grant| grant.grant.object_id == expected_evidence.object_id));

        let mut adjacent_evidence = evidence;
        adjacent_evidence[0] ^= 1;
        assert_eq!(
            c74_exact_existing(&operator, artifact, Some(&adjacent_evidence)).err(),
            Some(C74StorageV2InstallError::ExistingComponentHistory)
        );
        assert_eq!(
            c74_exact_existing(&operator, artifact, None).err(),
            Some(C74StorageV2InstallError::ExistingComponentHistory)
        );
        assert_eq!(
            c74_exact_existing(&development, artifact, Some(&evidence)).err(),
            Some(C74StorageV2InstallError::ExistingComponentHistory)
        );
    }

    #[test]
    fn c74_private_fixed_root_union_is_exact_and_fails_closed() {
        assert!(C74FixedRootPolicyUnion::new(false, false, false).is_err());

        let artifact = b"canonical component artifact";
        let component_only = c74_encoded_successor(artifact, None);
        let presence = c74_root_presence(&component_only).unwrap();
        assert_eq!(presence, (false, false, true));
        let union = C74FixedRootPolicyUnion::new(presence.0, presence.1, presence.2).unwrap();
        let partitions = union.partitions();
        assert_eq!(partitions.len(), 1);
        assert!(finish_recovered_snapshot(component_only, &partitions).is_ok());

        let missing_persistent = c74_encoded_successor(artifact, None);
        let union = C74FixedRootPolicyUnion::new(true, false, true).unwrap();
        let partitions = union.partitions();
        assert_eq!(
            finish_recovered_snapshot(missing_persistent, &partitions).err(),
            Some(StoreError::Corrupt)
        );

        let union = C74FixedRootPolicyUnion::new(true, true, true).unwrap();
        assert_eq!(union.partitions().len(), 3);
        for constraint in [&union.persistent[0], &union.program[0], &union.component[0]] {
            assert_eq!(constraint.first_slot, 0);
            assert_eq!(constraint.last_slot_inclusive, 0);
            assert_eq!(constraint.resource_kind, c74_resource_kind());
        }
        assert_eq!(union.persistent[0].space.get(), C74_PERSISTENT_SPACE_ID_RAW);
        assert_eq!(
            union.persistent[0].rights,
            authority::RootRightsConstraint::exact(
                authority::DurableRights::READ
                    .union(authority::DurableRights::GRANT)
                    .union(authority::DurableRights::REVOKE)
            )
        );
        assert_eq!(
            union.persistent[0].object_kind.get(),
            C74_PERSISTENT_OBJECT_KIND_RAW
        );
        assert_eq!(union.program[0].space.get(), C74_PROGRAM_SPACE_ID_RAW);
        assert_eq!(
            union.program[0].rights,
            authority::RootRightsConstraint::exact(authority::DurableRights::READ)
        );
        assert_eq!(
            union.program[0].object_kind.get(),
            C74_PROGRAM_OBJECT_KIND_RAW
        );
        assert_eq!(union.component[0].space.get(), C74_COMPONENT_SPACE_ID_RAW);
        assert_eq!(
            union.component[0].object_kind.get(),
            C74_COMPONENT_ARTIFACT_KIND_RAW
        );
    }

    #[test]
    fn storage_v2_only_append_and_physical_bound_recovery_are_linear() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        let StorageV2RecoveredAuthorityHead {
            journal: handle, ..
        } = head;
        assert_eq!(handle.external_root_policy_sha256(), [0x5a; 32]);

        let records = [[0xa5; journal::RECORD_SIZE]];
        let (handle, _appended) = poll_ready(handle.append(&records)).unwrap();
        let constraint = test_root_constraint();
        let partitions = [authority::RootPolicyPartition {
            space: constraint.space,
            constraints: core::slice::from_ref(&constraint),
        }];
        let (handle, bound) = poll_ready(handle.recover_bound(&partitions)).unwrap();

        assert_eq!(handle.external_root_policy_sha256(), [0x5a; 32]);
        assert_eq!(bound.recovered().objects.len(), 1);
        assert_eq!(backend.recover_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.readback_calls.load(Ordering::Acquire), 1);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn storage_v2_only_append_failure_requires_a_new_cold_proof() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        let StorageV2RecoveredAuthorityHead {
            journal: handle, ..
        } = head;
        backend.fail_next_append();

        let records = [[0x3c; journal::RECORD_SIZE]];
        assert_eq!(
            poll_ready(handle.append(&records)).err(),
            Some(StoreError::Corrupt)
        );
        // `handle` was consumed by append. The backend also revoked its boot
        // proof, so provenance cannot be minted again from the cached view.
        assert_eq!(
            poll_ready(journal.recover_storage_v2_only()).err(),
            Some(StoreError::Corrupt)
        );
        backend.complete_cold_recovery();
        assert!(poll_ready(journal.recover_storage_v2_only()).is_ok());

        assert_eq!(backend.append_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.recover_calls.load(Ordering::Acquire), 3);
        assert_eq!(backend.readback_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn storage_v2_only_rechecks_selection_and_policy_on_each_transition() {
        let backend = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        let (journal, platform) = test_authority_journal(Some(backend.clone()));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        let StorageV2RecoveredAuthorityHead {
            journal: handle, ..
        } = head;
        backend.set_selection(StorageBackendSelection::LegacyM4);
        assert_eq!(
            poll_ready(handle.append(&[[0x11; journal::RECORD_SIZE]])).err(),
            Some(StoreError::BackendAuthority)
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);

        backend.set_selection(StorageBackendSelection::StorageV2);
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        let StorageV2RecoveredAuthorityHead {
            journal: handle, ..
        } = head;
        backend.set_policy_byte(0x7b);
        assert_eq!(
            poll_ready(handle.append(&[[0x22; journal::RECORD_SIZE]])).err(),
            Some(StoreError::Corrupt)
        );
        assert_eq!(backend.append_calls.load(Ordering::Acquire), 0);
        // A policy-bound transition error consumes the cached boot proof as
        // well as the linear handle. A new head cannot be minted until an
        // explicit cold recovery re-establishes the physical authority.
        assert_eq!(
            poll_ready(journal.recover_storage_v2_only()).err(),
            Some(StoreError::Corrupt)
        );
        backend.complete_cold_recovery();
        assert!(poll_ready(journal.recover_storage_v2_only()).is_ok());
        assert_eq!(backend.recover_calls.load(Ordering::Acquire), 4);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn storage_v2_only_policy_bound_append_defaults_fail_closed() {
        let inner = Arc::new(TestStorageV2Backend::new(
            StorageBackendSelection::StorageV2,
            true,
        ));
        let backend = Arc::new(StorageV2BackendWithoutPolicyBoundAppend {
            inner: inner.clone(),
        });
        let (journal, platform) = test_authority_journal(Some(backend));
        let head = poll_ready(journal.recover_storage_v2_only()).unwrap();
        let StorageV2RecoveredAuthorityHead {
            journal: handle, ..
        } = head;

        assert_eq!(
            poll_ready(handle.append(&[[0x33; journal::RECORD_SIZE]])).err(),
            Some(StoreError::Corrupt)
        );
        assert_eq!(inner.append_calls.load(Ordering::Acquire), 0);
        assert_eq!(platform.calls(), 0);
    }

    #[test]
    fn internal_recovery_completion_materializes_exact_inline_object() {
        let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
        let snapshot = snapshot_from_preflight(preflight, used_sectors, false);
        let bound = finish_single_test_snapshot(snapshot)
            .expect("the exact roots must finish the original preflight");
        let recovered = bound.recovered();
        assert_eq!(recovered.store_id, store_id());
        assert_eq!(recovered.grants.len(), 1);
        assert_eq!(recovered.objects.len(), 1);

        let selected = &recovered.objects[0];
        let stored = bound
            .stored_object(selected)
            .expect("the internally-owned exact inline record must materialize");
        assert_eq!(stored.store_id, recovered.store_id);
        assert_eq!(stored.object_id, selected.object_id);
        assert_eq!(stored.object_kind, selected.object_kind);
        assert_eq!(stored.byte_len, selected.bytes.len());
        assert_eq!(stored.commit_sequence, selected.commit_sequence);
        assert!(stored.v2_token.is_none());
    }

    #[test]
    fn c74_exact_postflight_keeps_evidence_out_of_every_binding() {
        let (snapshot, constraint, expectation) = c74_operator_fixture(false);
        let partitions = [authority::RootPolicyPartition {
            space: constraint.space,
            constraints: core::slice::from_ref(&constraint),
        }];
        let recovery = finish_recovered_snapshot(snapshot, &partitions).unwrap();
        let receipt = validate_c74_exact_postflight(&recovery, &expectation).unwrap();
        assert_eq!(core::mem::size_of_val(&receipt), 0);
    }

    #[test]
    fn c74_exact_postflight_rejects_an_evidence_token_or_historical_grant() {
        let (snapshot, constraint, expectation) = c74_operator_fixture(true);
        let partitions = [authority::RootPolicyPartition {
            space: constraint.space,
            constraints: core::slice::from_ref(&constraint),
        }];
        let recovery = finish_recovered_snapshot(snapshot, &partitions).unwrap();
        assert_eq!(
            validate_c74_exact_postflight(&recovery, &expectation).err(),
            Some(StoreError::Corrupt)
        );

        let (snapshot, constraint, expectation) = c74_operator_fixture(false);
        let partitions = [authority::RootPolicyPartition {
            space: constraint.space,
            constraints: core::slice::from_ref(&constraint),
        }];
        let mut recovery = finish_recovered_snapshot(snapshot, &partitions).unwrap();
        let evidence_id = match &expectation.evidence {
            C74ExpectedEvidence::RetainedOnly(evidence) => evidence.object_id,
            C74ExpectedEvidence::Absent { .. } => unreachable!(),
        };
        let mut historical = expectation.root.clone();
        historical.grant.object_id = evidence_id;
        historical.grant.target.space = authority::SpaceId::new(TEST_SPACE_RAW + 1).unwrap();
        recovery.grant_history.push(historical);
        assert_eq!(
            validate_c74_exact_postflight(&recovery, &expectation).err(),
            Some(StoreError::Corrupt)
        );
    }

    #[test]
    fn bound_recovery_retains_tombstoned_grant_history_as_a_boolean_only() {
        let (preflight, used_sectors) = tombstoned_grant_preflight();
        let selected = preflight.committed_objects()[0].clone();
        let snapshot = snapshot_from_preflight(preflight, used_sectors, false);
        let bound = finish_recovered_snapshot(snapshot, &[])
            .expect("the tombstoned root leaves no live root-policy obligation");
        assert!(bound.recovered().grants.is_empty());
        assert_eq!(bound.exact_object_has_grant_history(&selected), Ok(true));

        let mut adjacent = selected;
        adjacent.bytes.push(0xff);
        adjacent.byte_len += 1;
        assert_eq!(
            bound.exact_object_has_grant_history(&adjacent),
            Err(StoreError::ObjectUnavailable)
        );
    }

    #[test]
    fn internal_recovery_completion_rejects_missing_foreign_and_foreign_store_roots() {
        let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
        let snapshot = snapshot_from_preflight(preflight, used_sectors, false);
        assert!(matches!(
            finish_recovered_snapshot(snapshot, &[]),
            Err(StoreError::Corrupt)
        ));

        let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
        let mut foreign = test_root_constraint();
        foreign.space = authority::SpaceId::new(TEST_SPACE_RAW + 1).unwrap();
        let partitions = [authority::RootPolicyPartition {
            space: foreign.space,
            constraints: core::slice::from_ref(&foreign),
        }];
        let snapshot = snapshot_from_preflight(preflight, used_sectors, false);
        assert!(matches!(
            finish_recovered_snapshot(snapshot, &partitions),
            Err(StoreError::Corrupt)
        ));

        let foreign_store = StoreId::new(STORE_ID_RAW + 1).unwrap();
        let (preflight, _roots, used_sectors) = test_preflight(foreign_store, false);
        let snapshot = snapshot_from_preflight(preflight, used_sectors, false);
        assert!(matches!(
            finish_single_test_snapshot(snapshot),
            Err(StoreError::Corrupt)
        ));
    }

    #[test]
    fn internal_recovery_requires_the_complete_multi_partition_root_union() {
        let (preflight, first, second, used_sectors) = two_root_preflight();
        let partitions = [
            authority::RootPolicyPartition {
                space: first.space,
                constraints: core::slice::from_ref(&first),
            },
            authority::RootPolicyPartition {
                space: second.space,
                constraints: core::slice::from_ref(&second),
            },
        ];
        let bound = finish_recovered_snapshot(
            snapshot_from_preflight(preflight, used_sectors, false),
            &partitions,
        )
        .expect("the complete independently owned root union must recover");
        assert_eq!(bound.recovered().grants.len(), 2);
        assert_eq!(bound.recovered().objects.len(), 2);

        let (preflight, first, _second, used_sectors) = two_root_preflight();
        let incomplete = [authority::RootPolicyPartition {
            space: first.space,
            constraints: core::slice::from_ref(&first),
        }];
        assert!(matches!(
            finish_recovered_snapshot(
                snapshot_from_preflight(preflight, used_sectors, false),
                &incomplete,
            ),
            Err(StoreError::Corrupt)
        ));
    }

    #[test]
    fn forged_recovered_clone_cannot_replace_bound_internal_provenance() {
        let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
        let bound =
            finish_single_test_snapshot(snapshot_from_preflight(preflight, used_sectors, false))
                .unwrap();
        let exact = bound.recovered().objects[0].clone();

        let mut forged = bound.recovered().clone();
        forged.objects[0].bytes[0] ^= 0xff;
        let forged_selected = &forged.objects[0];
        assert_eq!(
            bound.stored_object(forged_selected).err(),
            Some(StoreError::ObjectUnavailable)
        );
        assert_eq!(bound.recovered().objects[0], exact);
        assert!(bound.stored_object(&exact).is_ok());
    }

    #[test]
    fn bound_materialization_rejects_missing_and_adjacent_selected_records() {
        let (preflight, _roots, used_sectors) = test_preflight(store_id(), false);
        let bound =
            finish_single_test_snapshot(snapshot_from_preflight(preflight, used_sectors, false))
                .unwrap();
        let exact = bound.recovered().objects[0].clone();

        let mut missing = exact.clone();
        missing.object_id = authority::ObjectId::new(TEST_OBJECT_RAW + 1).unwrap();
        assert_eq!(
            bound.stored_object(&missing).err(),
            Some(StoreError::ObjectUnavailable)
        );

        for adjacent in [
            {
                let mut value = exact.clone();
                value.object_kind =
                    authority::ObjectKind::new(exact.object_kind.get() + 1).unwrap();
                value
            },
            {
                let mut value = exact.clone();
                value.byte_len += 1;
                value
            },
            {
                let mut value = exact.clone();
                value.commit_sequence += 1;
                value
            },
        ] {
            assert_eq!(
                bound.stored_object(&adjacent).err(),
                Some(StoreError::ObjectUnavailable)
            );
        }
    }

    #[test]
    fn legacy_external_fails_closed_while_bound_v2_token_materializes_logical_object() {
        let (preflight, _roots, used_sectors) = test_preflight(store_id(), true);
        let legacy =
            finish_single_test_snapshot(snapshot_from_preflight(preflight, used_sectors, false))
                .unwrap();
        let selected = &legacy.recovered().objects[0];
        assert_eq!(
            legacy.stored_object(selected).err(),
            Some(StoreError::ObjectUnavailable)
        );

        let (preflight, _roots, used_sectors) = test_preflight(store_id(), true);
        let v2 =
            finish_single_test_snapshot(snapshot_from_preflight(preflight, used_sectors, true))
                .unwrap();
        let selected = &v2.recovered().objects[0];
        let stored = v2
            .stored_object(selected)
            .expect("the exact bound V2 token must materialize external content");
        assert_eq!(stored.byte_len, selected.byte_len() as usize);
        assert!(stored.v2_token.is_some());
    }

    #[test]
    fn fault_cleanup_clears_only_the_exact_facade_claim() {
        let task = TaskId(41);
        let other_task = TaskId(42);
        let domain = AllocationDomain::SYSTEM;
        let active = SpinLock::new_recoverable(Some(ActiveClaim {
            task,
            domain,
            token: 7,
        }));

        assert!(!clear_faulted_active_claim(&active, other_task, domain));
        assert!(active.lock().is_some());
        assert!(clear_faulted_active_claim(&active, task, domain));
        assert!(active.lock().is_none());
        assert!(!clear_faulted_active_claim(&active, task, domain));
    }
}
