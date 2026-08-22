//! Kernel heap: a tagged, quota-aware size-class allocator.
//!
//! Every allocation carries immutable provenance in a private header.  The
//! component that frees a block therefore need not be the component that
//! allocated it: accounting is always returned to the original owner.

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch;
use crate::runqueue::{HartId, MAX_HARTS};
use crate::sync::SpinLock;

const MIN_CLASS_SHIFT: usize = 4; // 16-byte minimum block
const MIN_CLASS_SIZE: usize = 1 << MIN_CLASS_SHIFT;
// Cover every representable power-of-two block whose top bit is not overflow.
// This also makes allocations above the old 64 KiB ceiling recyclable.
const NUM_CLASSES: usize = usize::BITS as usize - MIN_CLASS_SHIFT;
pub const MAX_OWNER_ACCOUNTS: usize = 64;
/// Maximum number of simultaneously live reclaimable fault domains.
///
/// The table is fixed so creating or reclaiming an arena never recursively
/// allocates allocator metadata. Slots are reused after close/reclaim.
pub const MAX_ALLOCATION_ARENAS: usize = 64;
/// Maximum number of fresh owner/arena pairs created or retired atomically.
///
/// Principal graph lifecycle code uses this bound to keep all transaction
/// preflight state on the stack. It is deliberately narrower than either
/// allocator metadata table.
pub const MAX_FRESH_ALLOCATION_DOMAIN_BATCH: usize = 16;
const HEADER_MAGIC: u64 = 0x5649_4245_4f57_4e52; // "VIBEOWNR"
const FREED_MAGIC: u64 = 0x4652_4545_4442_4c4b; // "FREEDBLK"

/// Stable allocation identity. Owner zero is reserved for kernel/runtime work.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct OwnerId(u64);

impl OwnerId {
    pub const SYSTEM: Self = Self(0);

    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for OwnerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::SYSTEM {
            f.write_str("system")
        } else {
            write!(f, "owner:{}", self.0)
        }
    }
}

/// One allocation incarnation within a stable owner account.
///
/// Arena zero is deliberately untracked: ordinary tasks retain the M3.11
/// leak-on-fault behaviour until their escape boundaries have been audited.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct ArenaId(u64);

impl ArenaId {
    pub const UNTRACKED: Self = Self(0);

    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn is_tracked(self) -> bool {
        self.0 != 0
    }
}

/// The complete ambient allocation identity installed while polling a task.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AllocationDomain {
    pub owner: OwnerId,
    pub arena: ArenaId,
}

impl AllocationDomain {
    pub const SYSTEM: Self = Self::untracked(OwnerId::SYSTEM);

    pub const fn new(owner: OwnerId, arena: ArenaId) -> Self {
        Self { owner, arena }
    }

    pub const fn untracked(owner: OwnerId) -> Self {
        Self {
            owner,
            arena: ArenaId::UNTRACKED,
        }
    }
}

static CURRENT_OWNERS: [AtomicU64; MAX_HARTS] =
    [const { AtomicU64::new(OwnerId::SYSTEM.0) }; MAX_HARTS];
static CURRENT_ARENAS: [AtomicU64; MAX_HARTS] =
    [const { AtomicU64::new(ArenaId::UNTRACKED.0) }; MAX_HARTS];

#[inline(always)]
fn allocation_context_hart_index() -> Option<usize> {
    if let Some(logical) = crate::ipi::current_logical_hart() {
        return Some(logical.index());
    }

    // Host integration tests do not all construct an SBI topology. A dense
    // physical id models the corresponding logical slot there. The target
    // must never make that assumption: SBI hart ids may be sparse or permuted.
    #[cfg(not(target_arch = "riscv64"))]
    {
        let physical = arch::current_hart_id();
        return (physical < MAX_HARTS).then_some(physical);
    }

    #[cfg(target_arch = "riscv64")]
    None
}

#[inline(always)]
fn domain_on_hart(hart: usize) -> AllocationDomain {
    AllocationDomain {
        owner: OwnerId(CURRENT_OWNERS[hart].load(Ordering::SeqCst)),
        arena: ArenaId(CURRENT_ARENAS[hart].load(Ordering::SeqCst)),
    }
}

/// Allocation owner active on the current logical hart.
///
/// Panics rather than borrowing another hart's provenance when the current
/// physical hart has no logical scheduler identity.
pub fn current_owner() -> OwnerId {
    current_domain().owner
}

/// Allocation arena active on the current logical hart.
pub fn current_arena() -> ArenaId {
    current_domain().arena
}

/// Complete allocation identity active on the current logical hart.
#[inline]
pub fn current_domain() -> AllocationDomain {
    let hart =
        allocation_context_hart_index().expect("allocation context requires a mapped logical hart");
    domain_on_hart(hart)
}

/// Enter an allocation-owner scope.
///
/// Normal Rust unwinding restores through `Drop`. A target fault uses longjmp,
/// so the executor must keep this value in its caller frame and invoke
/// [`OwnerScope::restore`] explicitly after its landing pad returns.
#[inline]
pub fn enter_owner(owner: OwnerId) -> OwnerScope {
    // Untracked allocations are never eligible for arena-wide raw reclaim.
    unsafe { enter_domain(AllocationDomain::untracked(owner)) }
}

/// Enter a complete owner/arena allocation scope.
///
/// The pair is updated with interrupts masked so an IRQ cannot observe a torn
/// identity and later restore an owner with the wrong incarnation.
///
/// # Safety
/// For a tracked domain, `arena` must be active and registered to `owner`.
/// Until this scope is restored, every allocation and executor registration
/// must obey the arena's no-escape contract and use only non-panicking cleanup;
/// otherwise a later raw fault reclaim can invalidate safe references or enter
/// arbitrary user code. Prefer [`enter_owner`] for ordinary untracked work.
#[inline]
pub unsafe fn enter_domain(domain: AllocationDomain) -> OwnerScope {
    let irq = arch::irq_save();
    let Some(hart) = allocation_context_hart_index() else {
        arch::irq_restore(irq);
        panic!("allocation owner scope requires a mapped logical hart");
    };
    let owner_slot = &CURRENT_OWNERS[hart];
    let arena_slot = &CURRENT_ARENAS[hart];
    let previous = AllocationDomain {
        owner: OwnerId(owner_slot.load(Ordering::SeqCst)),
        arena: ArenaId(arena_slot.load(Ordering::SeqCst)),
    };
    owner_slot.store(domain.owner.0, Ordering::SeqCst);
    arena_slot.store(domain.arena.0, Ordering::SeqCst);
    let acquisition_physical_hart = arch::current_hart_id();
    arch::irq_restore(irq);
    OwnerScope {
        acquisition_hart: hart,
        acquisition_physical_hart,
        owner_slot,
        arena_slot,
        previous,
        active: true,
        not_send: PhantomData,
    }
}

/// Enter an allocation scope after the executor has already resolved and
/// validated its current logical hart.
///
/// Keeping that identity in the executor frame avoids repeating the topology
/// lookup at every system/task provenance transition in one poll.
///
/// # Safety
/// The current CPU must own `hart` until the returned scope is restored. For
/// tracked domains, the public [`enter_domain`] no-escape contract also holds.
pub(crate) unsafe fn enter_domain_on_hart(domain: AllocationDomain, hart: HartId) -> OwnerScope {
    let irq = arch::irq_save();
    debug_assert_eq!(allocation_context_hart_index(), Some(hart.index()));
    let owner_slot = &CURRENT_OWNERS[hart.index()];
    let arena_slot = &CURRENT_ARENAS[hart.index()];
    let previous = AllocationDomain {
        owner: OwnerId(owner_slot.load(Ordering::SeqCst)),
        arena: ArenaId(arena_slot.load(Ordering::SeqCst)),
    };
    owner_slot.store(domain.owner.0, Ordering::SeqCst);
    arena_slot.store(domain.arena.0, Ordering::SeqCst);
    let acquisition_physical_hart = arch::current_hart_id();
    arch::irq_restore(irq);
    OwnerScope {
        acquisition_hart: hart.index(),
        acquisition_physical_hart,
        owner_slot,
        arena_slot,
        previous,
        active: true,
        not_send: PhantomData,
    }
}

/// # Safety
/// The caller must have proved that the current CPU owns `hart` for the
/// complete scope lifetime.
#[inline]
pub(crate) unsafe fn enter_owner_on_hart(owner: OwnerId, hart: HartId) -> OwnerScope {
    // Untracked SYSTEM transitions obey the same executor-validated hart
    // contract as the task-domain transition around the poll itself.
    unsafe { enter_domain_on_hart(AllocationDomain::untracked(owner), hart) }
}

/// A hart-affine allocation provenance scope.
///
/// ```compile_fail
/// use vibeos_core::heap::{enter_owner, OwnerId};
///
/// fn require_send<T: Send>(_: T) {}
/// require_send(enter_owner(OwnerId::new(7)));
/// ```
pub struct OwnerScope {
    acquisition_hart: usize,
    acquisition_physical_hart: usize,
    owner_slot: &'static AtomicU64,
    arena_slot: &'static AtomicU64,
    previous: AllocationDomain,
    active: bool,
    not_send: PhantomData<*mut ()>,
}

impl OwnerScope {
    pub const fn previous(&self) -> OwnerId {
        self.previous.owner
    }

    pub const fn previous_domain(&self) -> AllocationDomain {
        self.previous
    }

    fn restore_inner(&mut self) {
        self.owner_slot
            .store(self.previous.owner.0, Ordering::SeqCst);
        self.arena_slot
            .store(self.previous.arena.0, Ordering::SeqCst);
        self.active = false;
    }

    /// Restore after an enclosing executor boundary has already fixed this
    /// poll to the scope's hart.
    ///
    /// # Safety
    /// The caller must have independently verified the current physical hart.
    pub(crate) unsafe fn restore_on_verified_hart(&mut self) {
        if !self.active {
            return;
        }
        let irq = arch::irq_save();
        self.restore_inner();
        arch::irq_restore(irq);
    }

    /// Restore now rather than waiting for Drop. This is idempotent.
    pub fn restore(&mut self) {
        if self.active {
            let irq = arch::irq_save();
            let current_physical_hart = arch::current_hart_id();
            if current_physical_hart != self.acquisition_physical_hart {
                arch::irq_restore(irq);
                // Avoid a second panic from Drop while unwinding. The original
                // hart deliberately retains its installed provenance.
                self.active = false;
                panic!(
                    "allocation owner scope entered on logical hart {} / physical hart {} restored on physical hart {}",
                    self.acquisition_hart,
                    self.acquisition_physical_hart,
                    current_physical_hart
                );
            }
            self.restore_inner();
            arch::irq_restore(irq);
        }
    }
}

impl Drop for OwnerScope {
    fn drop(&mut self) {
        self.restore();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OwnerStats {
    pub owner: OwnerId,
    pub quota_bytes: usize,
    pub live_bytes: usize,
    pub peak_bytes: usize,
    pub live_allocations: usize,
    pub denials: u64,
}

/// Global allocator gauges used by diagnostics and reproducible benchmarks.
///
/// `live_bytes` can fall when allocations are freed, while
/// `peak_live_bytes` and `bump_used_bytes` are high-water-style gauges. Blocks
/// returned to a size-class free list reduce `live_bytes` but deliberately do
/// not rewind the bump cursor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeapSnapshot {
    pub live_bytes: usize,
    pub peak_live_bytes: usize,
    pub bump_used_bytes: usize,
    pub bump_remaining_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerError {
    SystemOwnerReserved,
    ZeroQuota,
    AlreadyRegistered,
    UnknownOwner,
    TableFull,
    OwnerIdExhausted,
    OwnerBusy {
        live_bytes: usize,
        live_allocations: usize,
    },
    ArenasActive {
        active_arenas: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArenaStats {
    pub arena: ArenaId,
    pub owner: OwnerId,
    pub live_bytes: usize,
    pub live_allocations: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReclaimStats {
    pub arena: ArenaId,
    pub owner: OwnerId,
    pub reclaimed_bytes: usize,
    pub reclaimed_allocations: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArenaError {
    UntrackedArenaReserved,
    SystemOwnerReserved,
    UnknownOwner,
    UnknownArena,
    OwnerMismatch {
        expected: OwnerId,
        actual: OwnerId,
    },
    TableFull,
    ArenaIdExhausted,
    ArenaBusy {
        live_bytes: usize,
        live_allocations: usize,
    },
    CorruptList,
}

/// Why an atomic fresh allocation-domain transaction was rejected.
///
/// No variant carries an owner or arena identity. Every returned error leaves
/// domain membership and both fresh-identity sequences unchanged. The result
/// buffer is ordinary SYSTEM heap storage in kernel use: reserving it is
/// recoverable and its failed-call drop restores live bytes, but ordinary
/// bump/peak/free-list and allocation-denial telemetry can still reflect that
/// allocation attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreshDomainBatchError {
    Empty,
    TooMany,
    ZeroQuota,
    /// The result buffer could not be reserved before lifecycle preflight.
    Allocation,
    OwnerCapacity,
    ArenaCapacity,
    OwnerIdentityExhausted,
    ArenaIdentityExhausted,
}

/// Why an atomic empty-domain retirement was rejected.
///
/// Identity-bearing inputs are intentionally collapsed into semantic error
/// classes so lifecycle diagnostics cannot disclose raw owner or arena IDs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreshDomainBatchRetireError {
    Empty,
    TooMany,
    InvalidDomain,
    DuplicateOwner,
    DuplicateArena,
    DomainUnavailable,
    DomainMismatch,
    ArenaBusy,
    OwnerBusy,
    OwnerHasOtherArena,
}

/// Allocation-free summary of one complete fresh-domain retirement.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FreshDomainBatchRetireOutcome {
    retired_count: usize,
}

impl FreshDomainBatchRetireOutcome {
    pub const fn retired_count(self) -> usize {
        self.retired_count
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AllocationFailure {
    UnknownOwner {
        owner: OwnerId,
    },
    UnknownArena {
        owner: OwnerId,
        arena: ArenaId,
    },
    ArenaOwnerMismatch {
        owner: OwnerId,
        arena: ArenaId,
        arena_owner: OwnerId,
    },
    QuotaExceeded {
        owner: OwnerId,
        requested_bytes: usize,
        live_bytes: usize,
        quota_bytes: usize,
    },
    HeapExhausted {
        owner: OwnerId,
        requested_bytes: usize,
    },
    LayoutOverflow {
        owner: OwnerId,
    },
    AccountingOverflow {
        owner: OwnerId,
        requested_bytes: usize,
    },
}

impl fmt::Display for AllocationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UnknownOwner { owner } => write!(f, "unregistered allocation owner {owner}"),
            Self::UnknownArena { owner, arena } => write!(
                f,
                "unregistered allocation arena {} for {owner}",
                arena.get()
            ),
            Self::ArenaOwnerMismatch {
                owner,
                arena,
                arena_owner,
            } => write!(
                f,
                "allocation arena {} belongs to {arena_owner}, not {owner}",
                arena.get()
            ),
            Self::QuotaExceeded {
                owner,
                requested_bytes,
                live_bytes,
                quota_bytes,
            } => write!(
                f,
                "{owner} quota exceeded: {live_bytes} live + {requested_bytes} requested > {quota_bytes} bytes"
            ),
            Self::HeapExhausted {
                owner,
                requested_bytes,
            } => write!(
                f,
                "kernel heap exhausted for {owner} requesting {requested_bytes} bytes"
            ),
            Self::LayoutOverflow { owner } => {
                write!(f, "allocation layout is too large for {owner}")
            }
            Self::AccountingOverflow {
                owner,
                requested_bytes,
            } => write!(
                f,
                "allocation accounting overflow for {owner} requesting {requested_bytes} bytes"
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct OwnerAccount {
    owner: OwnerId,
    quota_bytes: usize,
    live_bytes: usize,
    peak_bytes: usize,
    live_allocations: usize,
    denials: u64,
    active: bool,
}

impl OwnerAccount {
    const EMPTY: Self = Self {
        owner: OwnerId::SYSTEM,
        quota_bytes: 0,
        live_bytes: 0,
        peak_bytes: 0,
        live_allocations: 0,
        denials: 0,
        active: false,
    };

    const SYSTEM: Self = Self {
        owner: OwnerId::SYSTEM,
        quota_bytes: usize::MAX,
        live_bytes: 0,
        peak_bytes: 0,
        live_allocations: 0,
        denials: 0,
        active: true,
    };

    fn stats(self) -> OwnerStats {
        OwnerStats {
            owner: self.owner,
            quota_bytes: self.quota_bytes,
            live_bytes: self.live_bytes,
            peak_bytes: self.peak_bytes,
            live_allocations: self.live_allocations,
            denials: self.denials,
        }
    }
}

struct FreeNode {
    next: Option<NonNull<FreeNode>>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AllocationHeader {
    magic: u64,
    owner: OwnerId,
    arena: ArenaId,
    base: usize,
    class: usize,
    arena_prev: Option<NonNull<AllocationHeader>>,
    arena_next: Option<NonNull<AllocationHeader>>,
}

#[derive(Clone, Copy)]
struct ArenaRecord {
    arena: ArenaId,
    owner: OwnerId,
    head: Option<NonNull<AllocationHeader>>,
    live_bytes: usize,
    live_allocations: usize,
    active: bool,
}

impl ArenaRecord {
    const EMPTY: Self = Self {
        arena: ArenaId::UNTRACKED,
        owner: OwnerId::SYSTEM,
        head: None,
        live_bytes: 0,
        live_allocations: 0,
        active: false,
    };

    fn stats(self) -> ArenaStats {
        ArenaStats {
            arena: self.arena,
            owner: self.owner,
            live_bytes: self.live_bytes,
            live_allocations: self.live_allocations,
        }
    }
}

#[derive(Clone, Copy)]
struct AllocationPlan {
    class: usize,
    charge: usize,
    user_align: usize,
}

struct HeapInner {
    start: usize,
    cursor: usize,
    end: usize,
    free: [Option<NonNull<FreeNode>>; NUM_CLASSES],
    live_bytes: usize,
    peak_bytes: usize,
    owners: [OwnerAccount; MAX_OWNER_ACCOUNTS],
    arenas: [ArenaRecord; MAX_ALLOCATION_ARENAS],
    next_owner_id: u64,
    next_arena_id: u64,
    last_failures: [Option<AllocationFailure>; MAX_HARTS],
}

unsafe impl Send for HeapInner {}

pub struct Heap(SpinLock<HeapInner>);

impl Heap {
    pub const fn new() -> Self {
        let mut owners = [OwnerAccount::EMPTY; MAX_OWNER_ACCOUNTS];
        owners[0] = OwnerAccount::SYSTEM;
        Heap(SpinLock::new(HeapInner {
            start: 0,
            cursor: 0,
            end: 0,
            free: [None; NUM_CLASSES],
            live_bytes: 0,
            peak_bytes: 0,
            owners,
            arenas: [ArenaRecord::EMPTY; MAX_ALLOCATION_ARENAS],
            next_owner_id: 1,
            next_arena_id: 1,
            last_failures: [None; MAX_HARTS],
        }))
    }

    /// # Safety
    /// `start..end` must be a unique, otherwise-unused region of writable RAM.
    pub unsafe fn init(&self, start: usize, end: usize) {
        let mut h = self.0.lock();
        let start = align_up(start, MIN_CLASS_SIZE).unwrap_or(end);
        let end = end & !(MIN_CLASS_SIZE - 1);
        h.start = start.min(end);
        h.cursor = h.start;
        h.end = end;
        h.free = [None; NUM_CLASSES];
        h.live_bytes = 0;
        h.peak_bytes = 0;
        h.owners = [OwnerAccount::EMPTY; MAX_OWNER_ACCOUNTS];
        h.owners[0] = OwnerAccount::SYSTEM;
        h.arenas = [ArenaRecord::EMPTY; MAX_ALLOCATION_ARENAS];
        h.next_owner_id = 1;
        h.next_arena_id = 1;
        h.last_failures = [None; MAX_HARTS];
    }

    /// Global physical live/peak bytes and never-yet-used bump bytes.
    pub fn stats(&self) -> (usize, usize, usize) {
        let snapshot = self.snapshot();
        (
            snapshot.live_bytes,
            snapshot.peak_live_bytes,
            snapshot.bump_remaining_bytes,
        )
    }

    /// Allocation-free contention telemetry for the allocator metadata lock.
    pub fn lock_stats(&self) -> crate::sync::SpinLockStats {
        self.0.stats()
    }

    /// Read all global allocator gauges under one lock.
    pub fn snapshot(&self) -> HeapSnapshot {
        let h = self.0.lock();
        HeapSnapshot {
            live_bytes: h.live_bytes,
            peak_live_bytes: h.peak_bytes,
            bump_used_bytes: h.cursor.saturating_sub(h.start),
            bump_remaining_bytes: h.end.saturating_sub(h.cursor),
        }
    }

    /// Create one fresh owner and one fresh reclaimable arena for every quota.
    ///
    /// Returned domains preserve input order and never share an owner or an
    /// arena. Return storage is allocated before the allocator metadata lock is
    /// acquired. Under that single lock, table capacity and both identity
    /// sequences are completely preflighted before the first mutation. The
    /// final lifecycle-metadata writes are therefore one externally atomic
    /// commit. Every returned error preserves domain-slot membership, both
    /// identity cursors, and the pre-call live-byte baseline. Ordinary
    /// allocator high-water and denial telemetry can reflect the attempted
    /// result-buffer reservation.
    pub fn create_fresh_domains_batch(
        &self,
        quota_bytes: &[usize],
    ) -> Result<Vec<AllocationDomain>, FreshDomainBatchError> {
        if quota_bytes.is_empty() {
            return Err(FreshDomainBatchError::Empty);
        }
        if quota_bytes.len() > MAX_FRESH_ALLOCATION_DOMAIN_BATCH {
            return Err(FreshDomainBatchError::TooMany);
        }
        if quota_bytes.iter().any(|quota| *quota == 0) {
            return Err(FreshDomainBatchError::ZeroQuota);
        }

        // No allocation may remain after the transaction linearization point.
        let mut domains = Vec::new();
        domains
            .try_reserve_exact(quota_bytes.len())
            .map_err(|_| FreshDomainBatchError::Allocation)?;
        let mut h = self.0.lock();
        let mut owner_slots = [usize::MAX; MAX_FRESH_ALLOCATION_DOMAIN_BATCH];
        let mut owner_slot_count = 0usize;
        for (index, account) in h.owners.iter().enumerate() {
            if !account.active && owner_slot_count < quota_bytes.len() {
                owner_slots[owner_slot_count] = index;
                owner_slot_count += 1;
            }
        }
        if owner_slot_count != quota_bytes.len() {
            return Err(FreshDomainBatchError::OwnerCapacity);
        }

        let mut arena_slots = [usize::MAX; MAX_FRESH_ALLOCATION_DOMAIN_BATCH];
        let mut arena_slot_count = 0usize;
        for (index, arena) in h.arenas.iter().enumerate() {
            if !arena.active && arena_slot_count < quota_bytes.len() {
                arena_slots[arena_slot_count] = index;
                arena_slot_count += 1;
            }
        }
        if arena_slot_count != quota_bytes.len() {
            return Err(FreshDomainBatchError::ArenaCapacity);
        }

        let mut owners = [OwnerId::SYSTEM; MAX_FRESH_ALLOCATION_DOMAIN_BATCH];
        let mut next_owner_id = h.next_owner_id;
        for owner in owners.iter_mut().take(quota_bytes.len()) {
            loop {
                if next_owner_id == OwnerId::SYSTEM.0 {
                    return Err(FreshDomainBatchError::OwnerIdentityExhausted);
                }
                let candidate = OwnerId(next_owner_id);
                next_owner_id = next_owner_id.checked_add(1).unwrap_or(OwnerId::SYSTEM.0);
                if find_owner(&h, candidate).is_none() {
                    *owner = candidate;
                    break;
                }
            }
        }

        let mut arenas = [ArenaId::UNTRACKED; MAX_FRESH_ALLOCATION_DOMAIN_BATCH];
        let mut next_arena_id = h.next_arena_id;
        for arena in arenas.iter_mut().take(quota_bytes.len()) {
            loop {
                if next_arena_id == ArenaId::UNTRACKED.0 {
                    return Err(FreshDomainBatchError::ArenaIdentityExhausted);
                }
                let candidate = ArenaId(next_arena_id);
                next_arena_id = next_arena_id.checked_add(1).unwrap_or(ArenaId::UNTRACKED.0);
                if find_arena(&h, candidate).is_none() {
                    *arena = candidate;
                    break;
                }
            }
        }

        // Capacity was reserved before the lock and every identity is now
        // fixed, so these pushes cannot allocate or fail.
        for index in 0..quota_bytes.len() {
            domains.push(AllocationDomain::new(owners[index], arenas[index]));
        }

        // Linearization point: the heap lock hides the complete metadata write
        // set until all accounts, arenas, and sequence cursors are installed.
        h.next_owner_id = next_owner_id;
        h.next_arena_id = next_arena_id;
        for (index, quota) in quota_bytes.iter().copied().enumerate() {
            h.owners[owner_slots[index]] = OwnerAccount {
                owner: owners[index],
                quota_bytes: quota,
                live_bytes: 0,
                peak_bytes: 0,
                live_allocations: 0,
                denials: 0,
                active: true,
            };
            h.arenas[arena_slots[index]] = ArenaRecord {
                arena: arenas[index],
                owner: owners[index],
                head: None,
                live_bytes: 0,
                live_allocations: 0,
                active: true,
            };
        }
        Ok(domains)
    }

    /// Read-only validation for a later atomic fresh-domain retirement.
    ///
    /// Every owner and arena must be unique, exact, active, empty, and paired
    /// exclusively with each other. All inputs are preflighted under one heap
    /// lock and no allocator state is mutated. This does not reserve the
    /// domains: only a caller holding exclusive lifecycle authority may rely
    /// on the result remaining valid before the later retirement call.
    pub fn preflight_retire_empty_domains_batch(
        &self,
        domains: &[AllocationDomain],
    ) -> Result<(), FreshDomainBatchRetireError> {
        let h = self.0.lock();
        preflight_fresh_domain_batch_retirement(&h, domains).map(|_| ())
    }

    /// Atomically retire a batch created by [`Self::create_fresh_domains_batch`].
    ///
    /// This uses the exact same locked, read-only validation helper as
    /// [`Self::preflight_retire_empty_domains_batch`]. After that helper
    /// returns, no fallible operation remains before the single-lock commit.
    pub fn retire_empty_domains_batch(
        &self,
        domains: &[AllocationDomain],
    ) -> Result<FreshDomainBatchRetireOutcome, FreshDomainBatchRetireError> {
        let mut h = self.0.lock();
        let plan = preflight_fresh_domain_batch_retirement(&h, domains)?;

        // Linearization point: clearing remains invisible until the one heap
        // lock is released, and there are no fallible operations below it.
        for index in 0..domains.len() {
            h.arenas[plan.arena_slots[index]] = ArenaRecord::EMPTY;
            h.owners[plan.owner_slots[index]] = OwnerAccount::EMPTY;
        }
        Ok(FreshDomainBatchRetireOutcome {
            retired_count: domains.len(),
        })
    }

    /// Register a stable externally-chosen owner identity.
    pub fn register_owner(&self, owner: OwnerId, quota_bytes: usize) -> Result<(), OwnerError> {
        if owner == OwnerId::SYSTEM {
            return Err(OwnerError::SystemOwnerReserved);
        }
        if quota_bytes == 0 {
            return Err(OwnerError::ZeroQuota);
        }
        let mut h = self.0.lock();
        if find_owner(&h, owner).is_some() {
            return Err(OwnerError::AlreadyRegistered);
        }
        let Some(index) = h.owners.iter().position(|account| !account.active) else {
            return Err(OwnerError::TableFull);
        };
        h.owners[index] = OwnerAccount {
            owner,
            quota_bytes,
            live_bytes: 0,
            peak_bytes: 0,
            live_allocations: 0,
            denials: 0,
            active: true,
        };
        Ok(())
    }

    /// Allocate a fresh owner identity and register its quota.
    pub fn create_owner(&self, quota_bytes: usize) -> Result<OwnerId, OwnerError> {
        if quota_bytes == 0 {
            return Err(OwnerError::ZeroQuota);
        }
        let mut h = self.0.lock();
        let Some(index) = h.owners.iter().position(|account| !account.active) else {
            return Err(OwnerError::TableFull);
        };

        let mut raw = h.next_owner_id;
        loop {
            if raw == 0 {
                return Err(OwnerError::OwnerIdExhausted);
            }
            let owner = OwnerId(raw);
            if find_owner(&h, owner).is_none() {
                h.next_owner_id = raw.checked_add(1).unwrap_or(0);
                h.owners[index] = OwnerAccount {
                    owner,
                    quota_bytes,
                    live_bytes: 0,
                    peak_bytes: 0,
                    live_allocations: 0,
                    denials: 0,
                    active: true,
                };
                return Ok(owner);
            }
            raw = raw.checked_add(1).ok_or(OwnerError::OwnerIdExhausted)?;
        }
    }

    /// Release an account slot only after every allocation carrying its tag is gone.
    pub fn unregister_owner(&self, owner: OwnerId) -> Result<(), OwnerError> {
        if owner == OwnerId::SYSTEM {
            return Err(OwnerError::SystemOwnerReserved);
        }
        let mut h = self.0.lock();
        let Some(index) = find_owner(&h, owner) else {
            return Err(OwnerError::UnknownOwner);
        };
        let account = h.owners[index];
        if account.live_bytes != 0 || account.live_allocations != 0 {
            return Err(OwnerError::OwnerBusy {
                live_bytes: account.live_bytes,
                live_allocations: account.live_allocations,
            });
        }
        let active_arenas = h
            .arenas
            .iter()
            .filter(|arena| arena.active && arena.owner == owner)
            .count();
        if active_arenas != 0 {
            return Err(OwnerError::ArenasActive { active_arenas });
        }
        h.owners[index] = OwnerAccount::EMPTY;
        Ok(())
    }

    /// Create a reclaimable allocation incarnation under an existing owner.
    pub fn create_arena(&self, owner: OwnerId) -> Result<ArenaId, ArenaError> {
        if owner == OwnerId::SYSTEM {
            return Err(ArenaError::SystemOwnerReserved);
        }
        let mut h = self.0.lock();
        if find_owner(&h, owner).is_none() {
            return Err(ArenaError::UnknownOwner);
        }
        let Some(index) = h.arenas.iter().position(|arena| !arena.active) else {
            return Err(ArenaError::TableFull);
        };

        let mut raw = h.next_arena_id;
        loop {
            if raw == ArenaId::UNTRACKED.0 {
                return Err(ArenaError::ArenaIdExhausted);
            }
            let arena = ArenaId(raw);
            if find_arena(&h, arena).is_none() {
                h.next_arena_id = raw.checked_add(1).unwrap_or(0);
                h.arenas[index] = ArenaRecord {
                    arena,
                    owner,
                    head: None,
                    live_bytes: 0,
                    live_allocations: 0,
                    active: true,
                };
                return Ok(arena);
            }
            raw = raw.checked_add(1).ok_or(ArenaError::ArenaIdExhausted)?;
        }
    }

    pub fn arena_stats(&self, arena: ArenaId) -> Option<ArenaStats> {
        if !arena.is_tracked() {
            return None;
        }
        let h = self.0.lock();
        find_arena(&h, arena).map(|index| h.arenas[index].stats())
    }

    /// Close an exact allocation domain after normal Drop has returned every
    /// tracked block.
    ///
    /// Owner and arena are checked together under the allocator lock. A stale
    /// lifecycle record therefore cannot close a later arena merely because a
    /// caller performed a separate `arena_stats` preflight.
    pub fn close_empty_domain(&self, domain: AllocationDomain) -> Result<(), ArenaError> {
        if !domain.arena.is_tracked() {
            return Err(ArenaError::UntrackedArenaReserved);
        }
        let mut h = self.0.lock();
        let Some(index) = find_arena(&h, domain.arena) else {
            return Err(ArenaError::UnknownArena);
        };
        let record = h.arenas[index];
        if record.owner != domain.owner {
            return Err(ArenaError::OwnerMismatch {
                expected: domain.owner,
                actual: record.owner,
            });
        }
        if record.live_bytes != 0 || record.live_allocations != 0 || record.head.is_some() {
            return Err(ArenaError::ArenaBusy {
                live_bytes: record.live_bytes,
                live_allocations: record.live_allocations,
            });
        }
        h.arenas[index] = ArenaRecord::EMPTY;
        Ok(())
    }

    /// Raw-reclaim every allocation belonging to one exact faulted domain.
    ///
    /// Every complete size-class block is scrubbed before it enters a free
    /// list. This is required because fault recovery deliberately skips Rust
    /// `Drop`; a replacement component must never inherit secret or ordinary
    /// payload bytes abandoned by the faulted incarnation.
    ///
    /// # Safety
    /// The caller must have permanently quiesced every task in `domain`, raw
    /// deallocated their future envelopes, removed runtime registrations, and
    /// proved that no pointer or reference into an arena allocation escaped.
    /// No destructor is run here.
    pub unsafe fn reclaim_faulted_domain(
        &self,
        domain: AllocationDomain,
    ) -> Result<ReclaimStats, ArenaError> {
        if !domain.arena.is_tracked() {
            return Err(ArenaError::UntrackedArenaReserved);
        }
        let mut h = self.0.lock();
        let Some(arena_index) = find_arena(&h, domain.arena) else {
            return Err(ArenaError::UnknownArena);
        };
        let record = h.arenas[arena_index];
        if record.owner != domain.owner {
            return Err(ArenaError::OwnerMismatch {
                expected: domain.owner,
                actual: record.owner,
            });
        }
        let Some(owner_index) = find_owner(&h, record.owner) else {
            return Err(ArenaError::UnknownOwner);
        };

        // Validate the entire chain before mutating allocator state. A corrupt
        // or cyclic list is leaked intact rather than partially double-freed.
        let mut node = record.head;
        let mut previous = None;
        let mut allocations = 0usize;
        let mut bytes = 0usize;
        while let Some(header_ptr) = node {
            let header_address = header_ptr.as_ptr() as usize;
            let Some(last_header_start) = h.cursor.checked_sub(size_of::<AllocationHeader>())
            else {
                return Err(ArenaError::CorruptList);
            };
            if allocations >= record.live_allocations
                || header_address < h.start
                || header_address > last_header_start
                || header_address % align_of::<AllocationHeader>() != 0
            {
                return Err(ArenaError::CorruptList);
            }
            let header = unsafe { &*header_ptr.as_ptr() };
            if header.magic != HEADER_MAGIC
                || header.owner != record.owner
                || header.arena != domain.arena
                || header.class >= NUM_CLASSES
                || header.arena_prev != previous
            {
                return Err(ArenaError::CorruptList);
            }
            let block_bytes = class_size(header.class);
            let Some(block_end) = header.base.checked_add(block_bytes) else {
                return Err(ArenaError::CorruptList);
            };
            let Some(header_end) = header_address.checked_add(size_of::<AllocationHeader>()) else {
                return Err(ArenaError::CorruptList);
            };
            if header.base < h.start
                || header.base % MIN_CLASS_SIZE != 0
                || block_end > h.cursor
                || header_address < header.base
                || header_end > block_end
            {
                return Err(ArenaError::CorruptList);
            }
            bytes = bytes
                .checked_add(block_bytes)
                .ok_or(ArenaError::CorruptList)?;
            allocations += 1;
            previous = Some(header_ptr);
            node = header.arena_next;
        }
        if allocations != record.live_allocations || bytes != record.live_bytes {
            return Err(ArenaError::CorruptList);
        }

        let account = h.owners[owner_index];
        let Some(owner_live) = account.live_bytes.checked_sub(bytes) else {
            return Err(ArenaError::CorruptList);
        };
        let Some(owner_allocations) = account.live_allocations.checked_sub(allocations) else {
            return Err(ArenaError::CorruptList);
        };
        let Some(global_live) = h.live_bytes.checked_sub(bytes) else {
            return Err(ArenaError::CorruptList);
        };

        node = record.head;
        while let Some(header_ptr) = node {
            let header = unsafe { *header_ptr.as_ptr() };
            let next = header.arena_next;
            let base = header.base;
            let class = header.class;
            unsafe {
                zero_block_before_reuse(base, class_size(class));
                header_ptr.as_ptr().write(AllocationHeader {
                    magic: FREED_MAGIC,
                    ..header
                });
                let free = base as *mut FreeNode;
                free.write(FreeNode {
                    next: h.free[class],
                });
                h.free[class] = NonNull::new(free);
            }
            node = next;
        }

        h.owners[owner_index].live_bytes = owner_live;
        h.owners[owner_index].live_allocations = owner_allocations;
        h.live_bytes = global_live;
        h.arenas[arena_index] = ArenaRecord::EMPTY;
        Ok(ReclaimStats {
            arena: domain.arena,
            owner: record.owner,
            reclaimed_bytes: bytes,
            reclaimed_allocations: allocations,
        })
    }

    pub fn account_stats(&self, owner: OwnerId) -> Option<OwnerStats> {
        let h = self.0.lock();
        find_owner(&h, owner).map(|index| h.owners[index].stats())
    }

    /// Most recent allocation failure on this logical hart.
    ///
    /// An unmapped hart returns `None` rather than consuming a peer's reason.
    pub fn last_failure(&self) -> Option<AllocationFailure> {
        let hart = allocation_context_hart_index()?;
        self.0.lock().last_failures[hart]
    }

    /// Take this logical hart's most recent allocation failure.
    pub fn take_last_failure(&self) -> Option<AllocationFailure> {
        let hart = allocation_context_hart_index()?;
        self.0.lock().last_failures[hart].take()
    }

    /// Physical bytes charged for this layout, including allocator metadata,
    /// alignment padding, and size-class rounding.
    pub fn allocation_charge(layout: Layout) -> Option<usize> {
        allocation_plan(layout).map(|plan| plan.charge)
    }

    fn record_failure(&self, hart: usize, owner: OwnerId, failure: AllocationFailure) {
        let mut h = self.0.lock();
        if let Some(index) = find_owner(&h, owner) {
            h.owners[index].denials = h.owners[index].denials.saturating_add(1);
        }
        h.last_failures[hart] = Some(failure);
    }
}

/// Clear one allocator-owned block after all references into its arena have
/// been quiesced and before the block becomes reusable.
///
/// Volatile stores plus a compiler fence keep this security boundary from
/// being optimized away. Free-list metadata is written only after the scrub.
unsafe fn zero_block_before_reuse(base: usize, bytes: usize) {
    let pointer = base as *mut u8;
    for offset in 0..bytes {
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn find_owner(h: &HeapInner, owner: OwnerId) -> Option<usize> {
    h.owners
        .iter()
        .position(|account| account.active && account.owner == owner)
}

fn find_arena(h: &HeapInner, arena: ArenaId) -> Option<usize> {
    h.arenas
        .iter()
        .position(|record| record.active && record.arena == arena)
}

struct FreshDomainBatchRetirePlan {
    owner_slots: [usize; MAX_FRESH_ALLOCATION_DOMAIN_BATCH],
    arena_slots: [usize; MAX_FRESH_ALLOCATION_DOMAIN_BATCH],
}

fn preflight_fresh_domain_batch_retirement(
    h: &HeapInner,
    domains: &[AllocationDomain],
) -> Result<FreshDomainBatchRetirePlan, FreshDomainBatchRetireError> {
    if domains.is_empty() {
        return Err(FreshDomainBatchRetireError::Empty);
    }
    if domains.len() > MAX_FRESH_ALLOCATION_DOMAIN_BATCH {
        return Err(FreshDomainBatchRetireError::TooMany);
    }
    for (index, domain) in domains.iter().enumerate() {
        if domain.owner == OwnerId::SYSTEM || !domain.arena.is_tracked() {
            return Err(FreshDomainBatchRetireError::InvalidDomain);
        }
        if domains[index + 1..]
            .iter()
            .any(|other| other.owner == domain.owner)
        {
            return Err(FreshDomainBatchRetireError::DuplicateOwner);
        }
        if domains[index + 1..]
            .iter()
            .any(|other| other.arena == domain.arena)
        {
            return Err(FreshDomainBatchRetireError::DuplicateArena);
        }
    }

    let mut plan = FreshDomainBatchRetirePlan {
        owner_slots: [usize::MAX; MAX_FRESH_ALLOCATION_DOMAIN_BATCH],
        arena_slots: [usize::MAX; MAX_FRESH_ALLOCATION_DOMAIN_BATCH],
    };
    for (input_index, domain) in domains.iter().copied().enumerate() {
        let mut owner_index = None;
        for (index, account) in h.owners.iter().enumerate() {
            if account.active && account.owner == domain.owner {
                if owner_index.replace(index).is_some() {
                    return Err(FreshDomainBatchRetireError::DomainUnavailable);
                }
            }
        }
        let Some(owner_index) = owner_index else {
            return Err(FreshDomainBatchRetireError::DomainUnavailable);
        };

        let mut arena_index = None;
        for (index, arena) in h.arenas.iter().enumerate() {
            if arena.active && arena.arena == domain.arena {
                if arena_index.replace(index).is_some() {
                    return Err(FreshDomainBatchRetireError::DomainUnavailable);
                }
            }
        }
        let Some(arena_index) = arena_index else {
            return Err(FreshDomainBatchRetireError::DomainUnavailable);
        };

        let account = h.owners[owner_index];
        let arena = h.arenas[arena_index];
        if arena.owner != domain.owner {
            return Err(FreshDomainBatchRetireError::DomainMismatch);
        }
        if arena.live_bytes != 0 || arena.live_allocations != 0 || arena.head.is_some() {
            return Err(FreshDomainBatchRetireError::ArenaBusy);
        }
        if account.live_bytes != 0 || account.live_allocations != 0 {
            return Err(FreshDomainBatchRetireError::OwnerBusy);
        }
        if h.arenas
            .iter()
            .filter(|other| other.active && other.owner == domain.owner)
            .count()
            != 1
        {
            return Err(FreshDomainBatchRetireError::OwnerHasOtherArena);
        }
        plan.owner_slots[input_index] = owner_index;
        plan.arena_slots[input_index] = arena_index;
    }
    Ok(plan)
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align - 1)
        .map(|aligned| aligned & !(align - 1))
}

fn class_size(index: usize) -> usize {
    1usize << (index + MIN_CLASS_SHIFT)
}

fn allocation_plan(layout: Layout) -> Option<AllocationPlan> {
    let user_align = layout
        .align()
        .max(align_of::<AllocationHeader>())
        .max(MIN_CLASS_SIZE);
    let required = size_of::<AllocationHeader>()
        .checked_add(layout.size().max(1))?
        .checked_add(user_align - 1)?
        .max(MIN_CLASS_SIZE);
    let charge = required.checked_next_power_of_two()?;
    let shift = charge.trailing_zeros() as usize;
    let class = shift.checked_sub(MIN_CLASS_SHIFT)?;
    (class < NUM_CLASSES).then_some(AllocationPlan {
        class,
        charge,
        user_align,
    })
}

fn user_address(base: usize, plan: AllocationPlan, layout: Layout) -> Option<usize> {
    let after_header = base.checked_add(size_of::<AllocationHeader>())?;
    let user = align_up(after_header, plan.user_align)?;
    let user_end = user.checked_add(layout.size().max(1))?;
    let block_end = base.checked_add(plan.charge)?;
    (user_end <= block_end).then_some(user)
}

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(hart) = allocation_context_hart_index() else {
            // Allocating without a registered logical hart must not borrow
            // another hart's owner, arena, or diagnostic slot.
            return ptr::null_mut();
        };
        let domain = domain_on_hart(hart);
        let owner = domain.owner;
        let Some(plan) = allocation_plan(layout) else {
            self.record_failure(hart, owner, AllocationFailure::LayoutOverflow { owner });
            return ptr::null_mut();
        };

        let mut h = self.0.lock();
        let Some(owner_index) = find_owner(&h, owner) else {
            h.last_failures[hart] = Some(AllocationFailure::UnknownOwner { owner });
            return ptr::null_mut();
        };

        let arena_index = if domain.arena.is_tracked() {
            let Some(index) = find_arena(&h, domain.arena) else {
                h.last_failures[hart] = Some(AllocationFailure::UnknownArena {
                    owner,
                    arena: domain.arena,
                });
                return ptr::null_mut();
            };
            let arena_owner = h.arenas[index].owner;
            if arena_owner != owner {
                h.last_failures[hart] = Some(AllocationFailure::ArenaOwnerMismatch {
                    owner,
                    arena: domain.arena,
                    arena_owner,
                });
                return ptr::null_mut();
            }
            Some(index)
        } else {
            None
        };

        let account = h.owners[owner_index];
        let Some(new_owner_live) = account.live_bytes.checked_add(plan.charge) else {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failures[hart] = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };
        if owner != OwnerId::SYSTEM && new_owner_live > account.quota_bytes {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failures[hart] = Some(AllocationFailure::QuotaExceeded {
                owner,
                requested_bytes: plan.charge,
                live_bytes: account.live_bytes,
                quota_bytes: account.quota_bytes,
            });
            return ptr::null_mut();
        }
        let Some(new_owner_allocations) = account.live_allocations.checked_add(1) else {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failures[hart] = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };
        let new_arena_totals = if let Some(index) = arena_index {
            let arena = h.arenas[index];
            let Some(live_bytes) = arena.live_bytes.checked_add(plan.charge) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::AccountingOverflow {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            };
            let Some(live_allocations) = arena.live_allocations.checked_add(1) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::AccountingOverflow {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            };
            Some((live_bytes, live_allocations))
        } else {
            None
        };
        let Some(new_global_live) = h.live_bytes.checked_add(plan.charge) else {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failures[hart] = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };

        let (base, user) = if let Some(node) = h.free[plan.class] {
            let base = node.as_ptr().cast::<u8>() as usize;
            let Some(user) = user_address(base, plan, layout) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::LayoutOverflow { owner });
                return ptr::null_mut();
            };
            h.free[plan.class] = unsafe { node.as_ref().next };
            (base, user)
        } else {
            let base = h.cursor;
            let Some(next) = base.checked_add(plan.charge) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::HeapExhausted {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            };
            if next > h.end {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::HeapExhausted {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            }
            let Some(user) = user_address(base, plan, layout) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failures[hart] = Some(AllocationFailure::LayoutOverflow { owner });
                return ptr::null_mut();
            };
            h.cursor = next;
            (base, user)
        };

        let header = (user - size_of::<AllocationHeader>()) as *mut AllocationHeader;
        let header_ptr = unsafe { NonNull::new_unchecked(header) };
        let arena_next = arena_index.and_then(|index| h.arenas[index].head);
        unsafe {
            header.write(AllocationHeader {
                magic: HEADER_MAGIC,
                owner,
                arena: domain.arena,
                base,
                class: plan.class,
                arena_prev: None,
                arena_next,
            });
            if let Some(mut next) = arena_next {
                next.as_mut().arena_prev = Some(header_ptr);
            }
        }

        let account = &mut h.owners[owner_index];
        account.live_bytes = new_owner_live;
        account.peak_bytes = account.peak_bytes.max(new_owner_live);
        account.live_allocations = new_owner_allocations;
        if let (Some(index), Some((live_bytes, live_allocations))) = (arena_index, new_arena_totals)
        {
            h.arenas[index].head = Some(header_ptr);
            h.arenas[index].live_bytes = live_bytes;
            h.arenas[index].live_allocations = live_allocations;
        }
        h.live_bytes = new_global_live;
        h.peak_bytes = h.peak_bytes.max(new_global_live);
        h.last_failures[hart] = None;
        user as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let header_ptr =
            unsafe { ptr.sub(size_of::<AllocationHeader>()) }.cast::<AllocationHeader>();
        let header = unsafe { header_ptr.read() };
        if header.magic != HEADER_MAGIC || header.class >= NUM_CLASSES {
            // A bad pointer is already a GlobalAlloc contract violation. Leak
            // rather than panicking/longjmping while a caller may hold a lock.
            return;
        }

        let charge = class_size(header.class);
        let mut h = self.0.lock();
        let Some(owner_index) = find_owner(&h, header.owner) else {
            return;
        };
        let header_node = unsafe { NonNull::new_unchecked(header_ptr) };
        let arena_index = if header.arena.is_tracked() {
            let Some(index) = find_arena(&h, header.arena) else {
                return;
            };
            let arena = h.arenas[index];
            if arena.owner != header.owner {
                return;
            }
            match header.arena_prev {
                Some(previous) => {
                    let previous = unsafe { previous.as_ref() };
                    if previous.magic != HEADER_MAGIC
                        || previous.arena != header.arena
                        || previous.arena_next != Some(header_node)
                    {
                        return;
                    }
                }
                None if arena.head != Some(header_node) => return,
                None => {}
            }
            if let Some(next) = header.arena_next {
                let next = unsafe { next.as_ref() };
                if next.magic != HEADER_MAGIC
                    || next.arena != header.arena
                    || next.arena_prev != Some(header_node)
                {
                    return;
                }
            }
            Some(index)
        } else {
            if header.arena_prev.is_some() || header.arena_next.is_some() {
                return;
            }
            None
        };
        let account = h.owners[owner_index];
        let (Some(owner_live), Some(owner_allocations), Some(global_live)) = (
            account.live_bytes.checked_sub(charge),
            account.live_allocations.checked_sub(1),
            h.live_bytes.checked_sub(charge),
        ) else {
            return;
        };
        let new_arena_totals = if let Some(index) = arena_index {
            let arena = h.arenas[index];
            let (Some(live_bytes), Some(live_allocations)) = (
                arena.live_bytes.checked_sub(charge),
                arena.live_allocations.checked_sub(1),
            ) else {
                return;
            };
            Some((live_bytes, live_allocations))
        } else {
            None
        };

        unsafe {
            if let Some(mut previous) = header.arena_prev {
                previous.as_mut().arena_next = header.arena_next;
            } else if let Some(index) = arena_index {
                h.arenas[index].head = header.arena_next;
            }
            if let Some(mut next) = header.arena_next {
                next.as_mut().arena_prev = header.arena_prev;
            }
            header_ptr.write(AllocationHeader {
                magic: FREED_MAGIC,
                ..header
            });
            let node = header.base as *mut FreeNode;
            node.write(FreeNode {
                next: h.free[header.class],
            });
            h.free[header.class] = NonNull::new(node);
        }
        h.owners[owner_index].live_bytes = owner_live;
        h.owners[owner_index].live_allocations = owner_allocations;
        if let (Some(index), Some((live_bytes, live_allocations))) = (arena_index, new_arena_totals)
        {
            h.arenas[index].live_bytes = live_bytes;
            h.arenas[index].live_allocations = live_allocations;
        }
        h.live_bytes = global_live;
    }
}

#[cfg(test)]
mod fresh_domain_batch_tests {
    use super::*;

    fn assert_only_system_owner_is_active(h: &HeapInner) {
        assert_eq!(h.owners.iter().filter(|account| account.active).count(), 1);
        assert!(h.owners[0].active);
        assert_eq!(h.owners[0].owner, OwnerId::SYSTEM);
        assert!(h.owners[1..].iter().all(|account| !account.active));
        assert!(h.arenas.iter().all(|arena| !arena.active));
    }

    #[test]
    fn fresh_owner_identity_exhaustion_mutates_nothing() {
        let heap = Heap::new();
        {
            let mut h = heap.0.lock();
            h.next_owner_id = u64::MAX;
            h.next_arena_id = 73;
        }

        assert_eq!(
            heap.create_fresh_domains_batch(&[1024, 2048]),
            Err(FreshDomainBatchError::OwnerIdentityExhausted)
        );
        let h = heap.0.lock();
        assert_eq!(h.next_owner_id, u64::MAX);
        assert_eq!(h.next_arena_id, 73);
        assert_eq!(h.live_bytes, 0);
        assert_only_system_owner_is_active(&h);
    }

    #[test]
    fn fresh_arena_identity_exhaustion_mutates_nothing() {
        let heap = Heap::new();
        {
            let mut h = heap.0.lock();
            h.next_owner_id = 91;
            h.next_arena_id = u64::MAX;
        }

        assert_eq!(
            heap.create_fresh_domains_batch(&[1024, 2048]),
            Err(FreshDomainBatchError::ArenaIdentityExhausted)
        );
        let h = heap.0.lock();
        assert_eq!(h.next_owner_id, 91);
        assert_eq!(h.next_arena_id, u64::MAX);
        assert_eq!(h.live_bytes, 0);
        assert_only_system_owner_is_active(&h);
    }
}
