//! Fixed-capacity runtime-root and extent-map generation pins for M7.5.
//!
//! A pin is acquired only after an operation has resolved existing authority.
//! This module deliberately has no lookup by `ObjectId` (or by `BlobKey`): the
//! crate-private [`RootKey`] can only be supplied by the authority/catalog
//! integration which already performed that resolution.
//!
//! Readers use the following protocol:
//!
//! 1. resolve an authorized object and its extent-map generation;
//! 2. acquire [`ObjectReadPin`];
//! 3. re-resolve authority and the current extent-map generation;
//! 4. call [`ObjectReadPin::finish_recheck`] before issuing any media read.
//!
//! A cleaner publishes a replacement mapping and then waits for
//! [`PinRegistry::is_quiescent_through`] before recycling the old segments.  A
//! reader racing after the quiescence scan either pins the new generation or
//! fails step 4; it cannot start an old-generation read after reuse.
//!
//! Slots are statically bounded and all backing arrays are allocated as part of
//! the registry. Ordinary acquisitions preserve a configured emergency reserve
//! for authority/migration completion. Fault cleanup is owner-based and may be
//! performed only after the scheduler supplies [`FaultDomainStopped`]; there is
//! intentionally no timeout or clock-based force-release API.

#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicU64, Ordering};

const FREE: u64 = 0;
const CLAIM_BIT: u64 = 1 << 63;

const fn claim_value(owner: PinOwner) -> u64 {
    CLAIM_BIT | owner.0
}

const fn claiming_owner(value: u64) -> Option<u64> {
    if value & CLAIM_BIT != 0 {
        Some(value & !CLAIM_BIT)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinError {
    InvalidConfiguration,
    InvalidIdentity,
    InvalidGeneration,
    SlotExhausted,
    LeaseExhausted,
    OwnerExhausted,
    AllocationFailed,
    SnapshotBusy,
    RecheckFailed,
}

/// Catalog identity captured only after authority has already been resolved.
///
/// Fields and construction remain crate-private so this type cannot become an
/// ambient object-opening surface when the pin types are wired into `lib.rs`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RootKey {
    object_id: u128,
    commit_generation: u64,
    object_kind: u32,
}

impl RootKey {
    pub(crate) fn new(
        object_id: u128,
        commit_generation: u64,
        object_kind: u32,
    ) -> Result<Self, PinError> {
        if object_id == 0 || commit_generation == 0 || object_kind == 0 {
            return Err(PinError::InvalidIdentity);
        }
        Ok(Self {
            object_id,
            commit_generation,
            object_kind,
        })
    }

    pub(crate) const fn object_id(self) -> u128 {
        self.object_id
    }

    pub(crate) const fn commit_generation(self) -> u64 {
        self.commit_generation
    }

    pub(crate) const fn object_kind(self) -> u32 {
        self.object_kind
    }
}

/// Why a runtime root is currently live. The class is telemetry and auditing
/// data only; every class is equally authoritative during marking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum RuntimeRootClass {
    ObjectResource = 1,
    InvocationLease = 2,
    BlobReader = 3,
    ExplicitSnapshot = 4,
    AuthorityTransaction = 5,
    MigrationTransaction = 6,
}

impl RuntimeRootClass {
    fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::ObjectResource),
            2 => Some(Self::InvocationLease),
            3 => Some(Self::BlobReader),
            4 => Some(Self::ExplicitSnapshot),
            5 => Some(Self::AuthorityTransaction),
            6 => Some(Self::MigrationTransaction),
            _ => None,
        }
    }
}

/// Owner of a group of pins. The scheduler allocates one owner per task or
/// fault domain and keeps the value opaque outside the storage/runtime bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PinOwner(u64);

/// Proof token supplied only after a fault domain is synchronously stopped.
///
/// Constructing this after a timeout would violate the pin protocol. The
/// constructor is crate-private so the scheduler bridge, not a caller, decides
/// when task termination has been proven.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FaultDomainStopped {
    owner: PinOwner,
}

impl FaultDomainStopped {
    pub(crate) const fn after_join(owner: PinOwner) -> Self {
        Self { owner }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PinAdmission {
    /// Must leave the configured reserve untouched.
    Ordinary,
    /// May consume reserve while completing an already-committed authority or
    /// migration operation. It still cannot exceed physical slot capacity.
    CompletionCritical,
}

/// Opaque authority/accounting lifetime retained by one owner-scoped root
/// slot. Keeping it in the registry (rather than only in the guard's arena)
/// lets trusted fault cleanup release it after synchronous task termination.
pub(crate) trait RootRetention: Send + Sync {}

impl<T: Send + Sync> RootRetention for T {}

pub(crate) type RootRetentionHandle = Arc<dyn RootRetention>;

struct RootSlot {
    lease: AtomicU64,
    object_low: AtomicU64,
    object_high: AtomicU64,
    commit_generation: AtomicU64,
    object_kind: AtomicU64,
    class: AtomicU64,
    owner: AtomicU64,
    retention: UnsafeCell<Option<RootRetentionHandle>>,
}

// SAFETY: `retention` is read or changed only while `root_revision` is held in
// its odd writer state. All other fields are atomic.
unsafe impl Sync for RootSlot {}

impl RootSlot {
    fn new() -> Self {
        Self {
            lease: AtomicU64::new(FREE),
            object_low: AtomicU64::new(0),
            object_high: AtomicU64::new(0),
            commit_generation: AtomicU64::new(0),
            object_kind: AtomicU64::new(0),
            class: AtomicU64::new(0),
            owner: AtomicU64::new(0),
            retention: UnsafeCell::new(None),
        }
    }

    fn read_stable(&self) -> Option<(u64, RootKey, RuntimeRootClass)> {
        let lease = self.lease.load(Ordering::Acquire);
        if lease == FREE || claiming_owner(lease).is_some() {
            return None;
        }
        let low = self.object_low.load(Ordering::Relaxed);
        let high = self.object_high.load(Ordering::Relaxed);
        let commit_generation = self.commit_generation.load(Ordering::Relaxed);
        let object_kind = self.object_kind.load(Ordering::Relaxed);
        let class = self.class.load(Ordering::Relaxed);
        if self.lease.load(Ordering::Acquire) != lease {
            return None;
        }
        let object_id = u128::from(low) | (u128::from(high) << 64);
        let key = RootKey::new(object_id, commit_generation, object_kind as u32).ok()?;
        Some((lease, key, RuntimeRootClass::from_u64(class)?))
    }
}

struct ReaderSlot {
    lease: AtomicU64,
    extent_generation: AtomicU64,
    owner: AtomicU64,
}

/// Serializes root-slot mutation and publishes an even revision only after all
/// slot writes are visible.  An odd revision is therefore an unambiguous
/// writer-in-progress marker, not merely a change counter.
struct RootWriteGuard<'a> {
    revision: &'a AtomicU64,
    completed_revision: u64,
}

impl Drop for RootWriteGuard<'_> {
    fn drop(&mut self) {
        self.revision
            .store(self.completed_revision, Ordering::SeqCst);
    }
}

impl ReaderSlot {
    fn new() -> Self {
        Self {
            lease: AtomicU64::new(FREE),
            extent_generation: AtomicU64::new(0),
            owner: AtomicU64::new(0),
        }
    }

    fn read_stable(&self) -> Option<(u64, u64)> {
        let lease = self.lease.load(Ordering::Acquire);
        if lease == FREE || claiming_owner(lease).is_some() {
            return None;
        }
        let generation = self.extent_generation.load(Ordering::Relaxed);
        if self.lease.load(Ordering::Acquire) != lease || generation == 0 {
            return None;
        }
        Some((lease, generation))
    }
}

/// Fixed-capacity pins shared by the authority bridge, Blob readers, and the
/// cleaner. No operation grows either slot array.
pub(crate) struct PinRegistry<const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    roots: [RootSlot; ROOT_SLOTS],
    readers: [ReaderSlot; READER_SLOTS],
    reserved_roots: usize,
    reserved_readers: usize,
    next_lease: AtomicU64,
    next_owner: AtomicU64,
    root_revision: AtomicU64,
}

/// Shareable fixed-capacity registry used by long-lived handles. Cloning this
/// value clones only an `Arc`; slot arrays remain one bounded allocation.
pub(crate) type SharedPinRegistry<const ROOT_SLOTS: usize, const READER_SLOTS: usize> =
    Arc<PinRegistry<ROOT_SLOTS, READER_SLOTS>>;

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize> PinRegistry<ROOT_SLOTS, READER_SLOTS> {
    pub(crate) fn new(reserved_roots: usize, reserved_readers: usize) -> Result<Self, PinError> {
        if reserved_roots > ROOT_SLOTS || reserved_readers > READER_SLOTS {
            return Err(PinError::InvalidConfiguration);
        }
        Ok(Self {
            roots: core::array::from_fn(|_| RootSlot::new()),
            readers: core::array::from_fn(|_| ReaderSlot::new()),
            reserved_roots,
            reserved_readers,
            next_lease: AtomicU64::new(1),
            next_owner: AtomicU64::new(1),
            root_revision: AtomicU64::new(0),
        })
    }

    fn begin_root_write(&self) -> RootWriteGuard<'_> {
        loop {
            let revision = self.root_revision.load(Ordering::SeqCst);
            if revision & 1 != 0 {
                spin_loop();
                continue;
            }
            let writing_revision = revision.wrapping_add(1);
            if self
                .root_revision
                .compare_exchange(
                    revision,
                    writing_revision,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return RootWriteGuard {
                    revision: &self.root_revision,
                    completed_revision: revision.wrapping_add(2),
                };
            }
            spin_loop();
        }
    }

    pub(crate) fn allocate_owner(&self) -> Result<PinOwner, PinError> {
        next_non_reserved(&self.next_owner)
            .map(PinOwner)
            .map_err(|_| PinError::OwnerExhausted)
    }

    pub(crate) fn into_shared(self) -> SharedPinRegistry<ROOT_SLOTS, READER_SLOTS> {
        Arc::new(self)
    }

    pub(crate) fn pin_root(
        &self,
        key: RootKey,
        class: RuntimeRootClass,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<RuntimeRootPin<'_, ROOT_SLOTS, READER_SLOTS>, PinError> {
        self.pin_root_with_retention(key, class, owner, admission, None)
    }

    fn pin_root_with_retention(
        &self,
        key: RootKey,
        class: RuntimeRootClass,
        owner: PinOwner,
        admission: PinAdmission,
        mut retention: Option<RootRetentionHandle>,
    ) -> Result<RuntimeRootPin<'_, ROOT_SLOTS, READER_SLOTS>, PinError> {
        validate_owner(owner)?;
        let lease = next_non_reserved(&self.next_lease)?;
        let admitted = match admission {
            PinAdmission::Ordinary => ROOT_SLOTS.saturating_sub(self.reserved_roots),
            PinAdmission::CompletionCritical => ROOT_SLOTS,
        };
        let _write = self.begin_root_write();
        for (index, slot) in self.roots[..admitted].iter().enumerate() {
            if slot
                .lease
                .compare_exchange(
                    FREE,
                    claim_value(owner),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            slot.object_low
                .store(key.object_id as u64, Ordering::Relaxed);
            slot.object_high
                .store((key.object_id >> 64) as u64, Ordering::Relaxed);
            slot.commit_generation
                .store(key.commit_generation, Ordering::Relaxed);
            slot.object_kind
                .store(u64::from(key.object_kind), Ordering::Relaxed);
            slot.class.store(class as u64, Ordering::Relaxed);
            slot.owner.store(owner.0, Ordering::Relaxed);
            // SAFETY: `_write` exclusively serializes every retention access;
            // a Free slot has had its prior retention taken before reuse.
            unsafe {
                debug_assert!((*slot.retention.get()).is_none());
                *slot.retention.get() = retention.take();
            }
            slot.lease.store(lease, Ordering::Release);
            return Ok(RuntimeRootPin {
                registry: self,
                slot: index,
                lease,
                key,
            });
        }
        Err(PinError::SlotExhausted)
    }

    pub(crate) fn pin_read_generation(
        &self,
        extent_generation: u64,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<ReadGenerationPin<'_, ROOT_SLOTS, READER_SLOTS>, PinError> {
        if extent_generation == 0 {
            return Err(PinError::InvalidGeneration);
        }
        validate_owner(owner)?;
        let lease = next_non_reserved(&self.next_lease)?;
        let admitted = match admission {
            PinAdmission::Ordinary => READER_SLOTS.saturating_sub(self.reserved_readers),
            PinAdmission::CompletionCritical => READER_SLOTS,
        };
        for (index, slot) in self.readers[..admitted].iter().enumerate() {
            if slot
                .lease
                .compare_exchange(
                    FREE,
                    claim_value(owner),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            slot.extent_generation
                .store(extent_generation, Ordering::Relaxed);
            slot.owner.store(owner.0, Ordering::Relaxed);
            slot.lease.store(lease, Ordering::Release);
            return Ok(ReadGenerationPin {
                registry: self,
                slot: index,
                lease,
                extent_generation,
            });
        }
        Err(PinError::SlotExhausted)
    }

    /// Atomically in the protocol sense acquires both roots needed by one Blob
    /// read. If the second fixed-capacity allocation fails, the first pin is
    /// synchronously rolled back.
    pub(crate) fn pin_object_reader(
        &self,
        key: RootKey,
        extent_generation: u64,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<ObjectReadPin<'_, ROOT_SLOTS, READER_SLOTS>, PinError> {
        let root = self.pin_root(key, RuntimeRootClass::BlobReader, owner, admission)?;
        let generation = self.pin_read_generation(extent_generation, owner, admission)?;
        Ok(ObjectReadPin { root, generation })
    }

    /// Take a bounded, retryable GC-epoch snapshot of all runtime roots.
    ///
    /// The destination is preallocated to exactly the registry capacity. An
    /// odd `root_revision` means a writer is changing one or more slots. A
    /// snapshot is accepted only when the revisions before and after the scan
    /// are the same even value. A permanently busy system returns
    /// `SnapshotBusy`; the cleaner yields and retries rather than weakening the
    /// root set.
    pub(crate) fn snapshot_roots(
        &self,
        destination: &mut RuntimeRootSnapshot,
        max_attempts: usize,
    ) -> Result<(), PinError> {
        if destination.capacity < ROOT_SLOTS || max_attempts == 0 {
            return Err(PinError::InvalidConfiguration);
        }
        for _ in 0..max_attempts {
            destination.roots.clear();
            let before = self.root_revision.load(Ordering::SeqCst);
            if before & 1 != 0 {
                continue;
            }
            for slot in &self.roots {
                if let Some((_lease, key, class)) = slot.read_stable() {
                    destination.roots.push(RuntimeRoot { key, class });
                }
            }
            let after = self.root_revision.load(Ordering::SeqCst);
            if before == after && after & 1 == 0 {
                destination.revision = after;
                return Ok(());
            }
        }
        destination.roots.clear();
        Err(PinError::SnapshotBusy)
    }

    /// True only when no active reader can still dereference `generation` or
    /// any older extent map. Claimed-but-not-published slots are safe to ignore:
    /// their callers have not received a token and must recheck before I/O.
    pub(crate) fn is_quiescent_through(&self, generation: u64) -> bool {
        self.readers.iter().all(|slot| {
            slot.read_stable()
                .is_none_or(|(_lease, pinned)| pinned > generation)
        })
    }

    /// Release every pin owned by a synchronously terminated fault domain.
    /// There is deliberately no elapsed-time argument or timeout fallback.
    pub(crate) fn release_stopped_owner(&self, stopped: FaultDomainStopped) -> ReleasedPins {
        let owner = stopped.owner.0;
        let mut released = ReleasedPins::default();
        for index in 0..self.roots.len() {
            let retention = {
                let _root_write = self.begin_root_write();
                let slot = &self.roots[index];
                let lease = slot.lease.load(Ordering::Acquire);
                let claim = claiming_owner(lease);
                let owned = lease != FREE
                    && (claim == Some(owner)
                        || (claim.is_none() && slot.owner.load(Ordering::Relaxed) == owner));
                if owned
                    && slot
                        .lease
                        .compare_exchange(lease, FREE, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                {
                    released.roots += 1;
                    // SAFETY: `_root_write` exclusively serializes retention
                    // access and this exact lease has just become Free.
                    unsafe { (*slot.retention.get()).take() }
                } else {
                    None
                }
            };
            // Dropping retained object authority can release another root and
            // must therefore happen after the registry writer guard is gone.
            drop(retention);
        }
        for slot in &self.readers {
            loop {
                let lease = slot.lease.load(Ordering::Acquire);
                if lease == FREE {
                    break;
                }
                let claim = claiming_owner(lease);
                if claim.is_some_and(|claim_owner| claim_owner != owner)
                    || (claim.is_none() && slot.owner.load(Ordering::Relaxed) != owner)
                {
                    break;
                }
                if slot
                    .lease
                    .compare_exchange(lease, FREE, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    released.readers += 1;
                    break;
                }
            }
        }
        released
    }

    fn release_root(&self, index: usize, lease: u64) {
        let retention = {
            let _write = self.begin_root_write();
            let slot = &self.roots[index];
            if slot
                .lease
                .compare_exchange(lease, FREE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // SAFETY: `_write` exclusively serializes retention access.
                unsafe { (*slot.retention.get()).take() }
            } else {
                None
            }
        };
        drop(retention);
    }

    fn release_reader(&self, index: usize, lease: u64) {
        let slot = &self.readers[index];
        let _ = slot
            .lease
            .compare_exchange(lease, FREE, Ordering::AcqRel, Ordering::Acquire);
    }

    fn root_is_active(&self, index: usize, lease: u64) -> bool {
        self.roots[index].lease.load(Ordering::Acquire) == lease
    }

    fn reader_is_active(&self, index: usize, lease: u64) -> bool {
        self.readers[index].lease.load(Ordering::Acquire) == lease
    }

    pub(crate) fn pin_root_owned(
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
        key: RootKey,
        class: RuntimeRootClass,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>, PinError> {
        Self::pin_root_owned_with_retention(registry, key, class, owner, admission, None)
    }

    pub(crate) fn pin_root_owned_retained(
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
        key: RootKey,
        class: RuntimeRootClass,
        owner: PinOwner,
        admission: PinAdmission,
        retention: RootRetentionHandle,
    ) -> Result<OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>, PinError> {
        Self::pin_root_owned_with_retention(registry, key, class, owner, admission, Some(retention))
    }

    fn pin_root_owned_with_retention(
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
        key: RootKey,
        class: RuntimeRootClass,
        owner: PinOwner,
        admission: PinAdmission,
        retention: Option<RootRetentionHandle>,
    ) -> Result<OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>, PinError> {
        let borrowed = registry.pin_root_with_retention(key, class, owner, admission, retention)?;
        let slot = borrowed.slot;
        let lease = borrowed.lease;
        let key = borrowed.key;
        // Transfer the exact lease to an owned token without running Drop.
        core::mem::forget(borrowed);
        Ok(OwnedRuntimeRootPin {
            registry: Arc::clone(registry),
            slot,
            lease,
            key,
        })
    }

    pub(crate) fn pin_object_reader_owned(
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
        key: RootKey,
        extent_generation: u64,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<OwnedObjectReadPin<ROOT_SLOTS, READER_SLOTS>, PinError> {
        let root = Self::pin_root_owned(
            registry,
            key,
            RuntimeRootClass::BlobReader,
            owner,
            admission,
        )?;
        let generation =
            match Self::pin_read_generation_owned(registry, extent_generation, owner, admission) {
                Ok(pin) => pin,
                Err(error) => {
                    drop(root);
                    return Err(error);
                }
            };
        Ok(OwnedObjectReadPin { root, generation })
    }

    fn pin_read_generation_owned(
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
        extent_generation: u64,
        owner: PinOwner,
        admission: PinAdmission,
    ) -> Result<OwnedReadGenerationPin<ROOT_SLOTS, READER_SLOTS>, PinError> {
        let borrowed = registry.pin_read_generation(extent_generation, owner, admission)?;
        let slot = borrowed.slot;
        let lease = borrowed.lease;
        let extent_generation = borrowed.extent_generation;
        core::mem::forget(borrowed);
        Ok(OwnedReadGenerationPin {
            registry: Arc::clone(registry),
            slot,
            lease,
            extent_generation,
        })
    }
}

fn validate_owner(owner: PinOwner) -> Result<(), PinError> {
    if owner.0 == FREE || owner.0 & CLAIM_BIT != 0 {
        Err(PinError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn next_non_reserved(counter: &AtomicU64) -> Result<u64, PinError> {
    loop {
        let current = counter.load(Ordering::Acquire);
        if current == FREE || current >= CLAIM_BIT - 1 {
            return Err(PinError::LeaseExhausted);
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(current);
        }
    }
}

/// One live runtime root. Dropping it is the normal release path.
pub(crate) struct RuntimeRootPin<'a, const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    registry: &'a PinRegistry<ROOT_SLOTS, READER_SLOTS>,
    slot: usize,
    lease: u64,
    key: RootKey,
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    RuntimeRootPin<'_, ROOT_SLOTS, READER_SLOTS>
{
    pub(crate) const fn key(&self) -> RootKey {
        self.key
    }

    pub(crate) fn is_active(&self) -> bool {
        self.registry.root_is_active(self.slot, self.lease)
    }
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize> Drop
    for RuntimeRootPin<'_, ROOT_SLOTS, READER_SLOTS>
{
    fn drop(&mut self) {
        self.registry.release_root(self.slot, self.lease);
    }
}

/// `'static` runtime root suitable for embedding in a capability/object
/// handle. It releases the exact slot lease when the final handle is dropped.
pub(crate) struct OwnedRuntimeRootPin<const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    registry: SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
    slot: usize,
    lease: u64,
    key: RootKey,
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>
{
    pub(crate) const fn key(&self) -> RootKey {
        self.key
    }

    pub(crate) fn is_active(&self) -> bool {
        self.registry.root_is_active(self.slot, self.lease)
    }

    pub(crate) fn belongs_to(
        &self,
        registry: &SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
    ) -> bool {
        Arc::ptr_eq(&self.registry, registry)
    }
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize> Drop
    for OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>
{
    fn drop(&mut self) {
        self.registry.release_root(self.slot, self.lease);
    }
}

/// One live extent-map generation pin. It conveys no object authority.
pub(crate) struct ReadGenerationPin<'a, const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    registry: &'a PinRegistry<ROOT_SLOTS, READER_SLOTS>,
    slot: usize,
    lease: u64,
    extent_generation: u64,
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    ReadGenerationPin<'_, ROOT_SLOTS, READER_SLOTS>
{
    pub(crate) const fn extent_generation(&self) -> u64 {
        self.extent_generation
    }

    pub(crate) fn is_active(&self) -> bool {
        self.registry.reader_is_active(self.slot, self.lease)
    }
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize> Drop
    for ReadGenerationPin<'_, ROOT_SLOTS, READER_SLOTS>
{
    fn drop(&mut self) {
        self.registry.release_reader(self.slot, self.lease);
    }
}

pub(crate) struct OwnedReadGenerationPin<const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    registry: SharedPinRegistry<ROOT_SLOTS, READER_SLOTS>,
    slot: usize,
    lease: u64,
    extent_generation: u64,
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    OwnedReadGenerationPin<ROOT_SLOTS, READER_SLOTS>
{
    pub(crate) fn is_active(&self) -> bool {
        self.registry.reader_is_active(self.slot, self.lease)
    }
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize> Drop
    for OwnedReadGenerationPin<ROOT_SLOTS, READER_SLOTS>
{
    fn drop(&mut self) {
        self.registry.release_reader(self.slot, self.lease);
    }
}

/// The two pins held across a directed Blob read.
pub(crate) struct ObjectReadPin<'a, const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    root: RuntimeRootPin<'a, ROOT_SLOTS, READER_SLOTS>,
    generation: ReadGenerationPin<'a, ROOT_SLOTS, READER_SLOTS>,
}

/// Owned pin-then-recheck session for async/task boundaries. It pins both the
/// exact authorized object identity and the extent-map generation.
pub(crate) struct OwnedObjectReadPin<const ROOT_SLOTS: usize, const READER_SLOTS: usize> {
    root: OwnedRuntimeRootPin<ROOT_SLOTS, READER_SLOTS>,
    generation: OwnedReadGenerationPin<ROOT_SLOTS, READER_SLOTS>,
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    OwnedObjectReadPin<ROOT_SLOTS, READER_SLOTS>
{
    pub(crate) fn finish_recheck(
        self,
        observed_key: RootKey,
        observed_extent_generation: u64,
    ) -> Result<Self, PinError> {
        if self.root.key == observed_key
            && self.generation.extent_generation == observed_extent_generation
            && self.root.is_active()
            && self.generation.is_active()
        {
            Ok(self)
        } else {
            Err(PinError::RecheckFailed)
        }
    }

    pub(crate) const fn root_key(&self) -> RootKey {
        self.root.key
    }

    pub(crate) const fn extent_generation(&self) -> u64 {
        self.generation.extent_generation
    }
}

impl<const ROOT_SLOTS: usize, const READER_SLOTS: usize>
    ObjectReadPin<'_, ROOT_SLOTS, READER_SLOTS>
{
    /// Complete pin-then-recheck. On mismatch this consumes and drops both
    /// pins; the caller must retry resolution and must not issue old-map I/O.
    pub(crate) fn finish_recheck(
        self,
        observed_key: RootKey,
        observed_extent_generation: u64,
    ) -> Result<Self, PinError> {
        if self.root.key == observed_key
            && self.generation.extent_generation == observed_extent_generation
            && self.root.is_active()
            && self.generation.is_active()
        {
            Ok(self)
        } else {
            Err(PinError::RecheckFailed)
        }
    }

    pub(crate) const fn root_key(&self) -> RootKey {
        self.root.key
    }

    pub(crate) const fn extent_generation(&self) -> u64 {
        self.generation.extent_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeRoot {
    pub(crate) key: RootKey,
    pub(crate) class: RuntimeRootClass,
}

/// Preallocated destination for a linearizable-enough GC root snapshot.
pub(crate) struct RuntimeRootSnapshot {
    roots: Vec<RuntimeRoot>,
    revision: u64,
    capacity: usize,
}

impl RuntimeRootSnapshot {
    pub(crate) fn with_capacity(capacity: usize) -> Result<Self, PinError> {
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(capacity)
            .map_err(|_| PinError::AllocationFailed)?;
        Ok(Self {
            roots,
            revision: 0,
            capacity,
        })
    }

    pub(crate) fn roots(&self) -> &[RuntimeRoot] {
        &self.roots
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReleasedPins {
    pub(crate) roots: usize,
    pub(crate) readers: usize,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Barrier;

    fn key(id: u128) -> RootKey {
        RootKey::new(id, 7, 3).unwrap()
    }

    #[test]
    fn root_slots_exhaust_preserve_reserve_and_reuse_exact_lease() {
        let pins = PinRegistry::<3, 1>::new(1, 0).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let first = pins
            .pin_root(
                key(1),
                RuntimeRootClass::ObjectResource,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        let second = pins
            .pin_root(
                key(2),
                RuntimeRootClass::InvocationLease,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        assert!(matches!(
            pins.pin_root(
                key(3),
                RuntimeRootClass::ObjectResource,
                owner,
                PinAdmission::Ordinary
            ),
            Err(PinError::SlotExhausted)
        ));
        let critical = pins
            .pin_root(
                key(3),
                RuntimeRootClass::AuthorityTransaction,
                owner,
                PinAdmission::CompletionCritical,
            )
            .unwrap();
        assert!(matches!(
            pins.pin_root(
                key(4),
                RuntimeRootClass::MigrationTransaction,
                owner,
                PinAdmission::CompletionCritical
            ),
            Err(PinError::SlotExhausted)
        ));
        drop(first);
        let reused = pins
            .pin_root(
                key(4),
                RuntimeRootClass::ObjectResource,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        assert!(reused.is_active());
        drop((second, critical, reused));
    }

    #[test]
    fn old_reader_blocks_reuse_until_drop_and_recheck_rejects_stale_map() {
        let pins = PinRegistry::<2, 2>::new(0, 0).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let reader = pins
            .pin_object_reader(key(1), 9, owner, PinAdmission::Ordinary)
            .unwrap()
            .finish_recheck(key(1), 9)
            .unwrap();
        assert!(!pins.is_quiescent_through(9));
        assert!(pins.is_quiescent_through(8));
        drop(reader);
        assert!(pins.is_quiescent_through(9));

        let stale = pins
            .pin_object_reader(key(1), 9, owner, PinAdmission::Ordinary)
            .unwrap();
        assert!(matches!(
            stale.finish_recheck(key(1), 10),
            Err(PinError::RecheckFailed)
        ));
        assert!(pins.is_quiescent_through(9));
    }

    #[test]
    fn reader_slots_preserve_reserve_and_second_pin_failure_rolls_back_root() {
        let pins = PinRegistry::<2, 2>::new(0, 1).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let ordinary = pins
            .pin_read_generation(7, owner, PinAdmission::Ordinary)
            .unwrap();
        assert!(matches!(
            pins.pin_read_generation(8, owner, PinAdmission::Ordinary),
            Err(PinError::SlotExhausted)
        ));

        assert!(matches!(
            pins.pin_object_reader(key(1), 9, owner, PinAdmission::Ordinary),
            Err(PinError::SlotExhausted)
        ));
        let mut snapshot = RuntimeRootSnapshot::with_capacity(2).unwrap();
        pins.snapshot_roots(&mut snapshot, 2).unwrap();
        assert!(
            snapshot.roots().is_empty(),
            "failed paired-reader acquisition leaked its first root pin"
        );

        let critical = pins
            .pin_read_generation(8, owner, PinAdmission::CompletionCritical)
            .unwrap();
        assert!(matches!(
            pins.pin_read_generation(9, owner, PinAdmission::CompletionCritical),
            Err(PinError::SlotExhausted)
        ));
        drop((ordinary, critical));
        assert!(pins.is_quiescent_through(9));
    }

    #[test]
    fn runtime_snapshot_is_bounded_and_fault_reap_requires_join_token() {
        let pins = PinRegistry::<4, 2>::new(0, 0).unwrap();
        let live_owner = pins.allocate_owner().unwrap();
        let dead_owner = pins.allocate_owner().unwrap();
        let _live = pins
            .pin_root(
                key(1),
                RuntimeRootClass::ObjectResource,
                live_owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        let leaked_root = pins
            .pin_root(
                key(2),
                RuntimeRootClass::InvocationLease,
                dead_owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        let leaked_reader = pins
            .pin_read_generation(11, dead_owner, PinAdmission::Ordinary)
            .unwrap();
        core::mem::forget(leaked_root);
        core::mem::forget(leaked_reader);

        let released = pins.release_stopped_owner(FaultDomainStopped::after_join(dead_owner));
        assert_eq!(
            released,
            ReleasedPins {
                roots: 1,
                readers: 1
            }
        );
        assert!(pins.is_quiescent_through(11));

        let mut snapshot = RuntimeRootSnapshot::with_capacity(4).unwrap();
        pins.snapshot_roots(&mut snapshot, 2).unwrap();
        assert_eq!(snapshot.roots().len(), 1);
        assert_eq!(snapshot.roots()[0].key, key(1));
        assert_ne!(snapshot.revision(), 0);
    }

    #[test]
    fn snapshot_returns_busy_while_root_writer_remains_in_progress() {
        let pins = PinRegistry::<2, 1>::new(0, 0).unwrap();
        let mut snapshot = RuntimeRootSnapshot::with_capacity(2).unwrap();

        let writer = pins.begin_root_write();
        assert_eq!(pins.root_revision.load(Ordering::SeqCst) & 1, 1);
        assert!(matches!(
            pins.snapshot_roots(&mut snapshot, 8),
            Err(PinError::SnapshotBusy)
        ));
        assert!(snapshot.roots().is_empty());

        drop(writer);
        pins.snapshot_roots(&mut snapshot, 1).unwrap();
        assert!(snapshot.roots().is_empty());
        assert_eq!(snapshot.revision() & 1, 0);
    }

    #[test]
    fn snapshot_cannot_accept_empty_set_during_concurrent_root_handoff() {
        let pins = PinRegistry::<2, 1>::new(0, 0).unwrap();
        let owner = pins.allocate_owner().unwrap();
        let blocker = pins
            .pin_root(
                key(1),
                RuntimeRootClass::ObjectResource,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        let old = pins
            .pin_root(
                key(2),
                RuntimeRootClass::InvocationLease,
                owner,
                PinAdmission::Ordinary,
            )
            .unwrap();
        drop(blocker);

        let writer_entered = Arc::new(Barrier::new(2));
        let writer_may_finish = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let entered = Arc::clone(&writer_entered);
            let finish = Arc::clone(&writer_may_finish);
            let pins_ref = &pins;
            let worker = scope.spawn(move || {
                let _writer = pins_ref.begin_root_write();
                let replacement = key(3);
                let replacement_lease = next_non_reserved(&pins_ref.next_lease).unwrap();
                let replacement_slot = &pins_ref.roots[0];
                replacement_slot
                    .lease
                    .compare_exchange(
                        FREE,
                        claim_value(owner),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .unwrap();
                replacement_slot
                    .object_low
                    .store(replacement.object_id as u64, Ordering::Relaxed);
                replacement_slot
                    .object_high
                    .store((replacement.object_id >> 64) as u64, Ordering::Relaxed);
                replacement_slot
                    .commit_generation
                    .store(replacement.commit_generation, Ordering::Relaxed);
                replacement_slot
                    .object_kind
                    .store(u64::from(replacement.object_kind), Ordering::Relaxed);
                replacement_slot
                    .class
                    .store(RuntimeRootClass::ObjectResource as u64, Ordering::Relaxed);
                replacement_slot.owner.store(owner.0, Ordering::Relaxed);
                replacement_slot
                    .lease
                    .store(replacement_lease, Ordering::Release);
                pins_ref.roots[old.slot]
                    .lease
                    .compare_exchange(old.lease, FREE, Ordering::AcqRel, Ordering::Acquire)
                    .unwrap();
                core::mem::forget(old);

                let _ = entered.wait();
                let _ = finish.wait();
            });

            let _ = writer_entered.wait();
            let mut snapshot = RuntimeRootSnapshot::with_capacity(2).unwrap();
            assert!(matches!(
                pins.snapshot_roots(&mut snapshot, 8),
                Err(PinError::SnapshotBusy)
            ));
            assert!(snapshot.roots().is_empty());
            let _ = writer_may_finish.wait();
            worker.join().unwrap();
        });

        let mut snapshot = RuntimeRootSnapshot::with_capacity(2).unwrap();
        pins.snapshot_roots(&mut snapshot, 1).unwrap();
        assert_eq!(snapshot.roots().len(), 1);
        assert_eq!(snapshot.roots()[0].key, key(3));
        assert_eq!(snapshot.revision() & 1, 0);
    }

    #[test]
    fn owned_reader_crosses_borrow_scope_and_releases_on_drop() {
        let pins = PinRegistry::<2, 2>::new(0, 0).unwrap().into_shared();
        let owner = pins.allocate_owner().unwrap();
        let reader =
            PinRegistry::pin_object_reader_owned(&pins, key(9), 12, owner, PinAdmission::Ordinary)
                .unwrap()
                .finish_recheck(key(9), 12)
                .unwrap();
        drop(pins);
        assert_eq!(reader.root_key(), key(9));
        assert_eq!(reader.extent_generation(), 12);
        assert!(!reader.root.registry.is_quiescent_through(12));
        let registry = Arc::clone(&reader.root.registry);
        drop(reader);
        assert!(registry.is_quiescent_through(12));
    }
}
