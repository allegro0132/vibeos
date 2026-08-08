//! Kernel heap: a tagged, quota-aware size-class allocator.
//!
//! Every allocation carries immutable provenance in a private header.  The
//! component that frees a block therefore need not be the component that
//! allocated it: accounting is always returned to the original owner.

use core::alloc::{GlobalAlloc, Layout};
use core::fmt;
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch;
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

static CURRENT_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.0);
static CURRENT_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.0);

/// Allocation owner active on the single v0.1 hart.
pub fn current_owner() -> OwnerId {
    OwnerId(CURRENT_OWNER.load(Ordering::SeqCst))
}

/// Allocation arena active on the single v0.1 hart.
pub fn current_arena() -> ArenaId {
    ArenaId(CURRENT_ARENA.load(Ordering::SeqCst))
}

/// Complete allocation identity active on the single v0.1 hart.
pub fn current_domain() -> AllocationDomain {
    AllocationDomain {
        owner: current_owner(),
        arena: current_arena(),
    }
}

/// Enter an allocation-owner scope.
///
/// Normal Rust unwinding restores through `Drop`. A target fault uses longjmp,
/// so the executor must keep this value in its caller frame and invoke
/// [`OwnerScope::restore`] explicitly after its landing pad returns.
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
pub unsafe fn enter_domain(domain: AllocationDomain) -> OwnerScope {
    let irq = arch::irq_save();
    let previous = current_domain();
    CURRENT_OWNER.store(domain.owner.0, Ordering::SeqCst);
    CURRENT_ARENA.store(domain.arena.0, Ordering::SeqCst);
    arch::irq_restore(irq);
    OwnerScope {
        previous,
        active: true,
    }
}

pub struct OwnerScope {
    previous: AllocationDomain,
    active: bool,
}

impl OwnerScope {
    pub const fn previous(&self) -> OwnerId {
        self.previous.owner
    }

    pub const fn previous_domain(&self) -> AllocationDomain {
        self.previous
    }

    /// Restore now rather than waiting for Drop. This is idempotent.
    pub fn restore(&mut self) {
        if self.active {
            let irq = arch::irq_save();
            CURRENT_OWNER.store(self.previous.owner.0, Ordering::SeqCst);
            CURRENT_ARENA.store(self.previous.arena.0, Ordering::SeqCst);
            arch::irq_restore(irq);
            self.active = false;
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
    TableFull,
    ArenaIdExhausted,
    ArenaBusy {
        live_bytes: usize,
        live_allocations: usize,
    },
    CorruptList,
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
    cursor: usize,
    end: usize,
    free: [Option<NonNull<FreeNode>>; NUM_CLASSES],
    live_bytes: usize,
    peak_bytes: usize,
    owners: [OwnerAccount; MAX_OWNER_ACCOUNTS],
    arenas: [ArenaRecord; MAX_ALLOCATION_ARENAS],
    next_owner_id: u64,
    next_arena_id: u64,
    last_failure: Option<AllocationFailure>,
}

unsafe impl Send for HeapInner {}

pub struct Heap(SpinLock<HeapInner>);

impl Heap {
    pub const fn new() -> Self {
        let mut owners = [OwnerAccount::EMPTY; MAX_OWNER_ACCOUNTS];
        owners[0] = OwnerAccount::SYSTEM;
        Heap(SpinLock::new(HeapInner {
            cursor: 0,
            end: 0,
            free: [None; NUM_CLASSES],
            live_bytes: 0,
            peak_bytes: 0,
            owners,
            arenas: [ArenaRecord::EMPTY; MAX_ALLOCATION_ARENAS],
            next_owner_id: 1,
            next_arena_id: 1,
            last_failure: None,
        }))
    }

    /// # Safety
    /// `start..end` must be a unique, otherwise-unused region of writable RAM.
    pub unsafe fn init(&self, start: usize, end: usize) {
        let mut h = self.0.lock();
        let start = align_up(start, MIN_CLASS_SIZE).unwrap_or(end);
        let end = end & !(MIN_CLASS_SIZE - 1);
        h.cursor = start.min(end);
        h.end = end;
        h.free = [None; NUM_CLASSES];
        h.live_bytes = 0;
        h.peak_bytes = 0;
        h.owners = [OwnerAccount::EMPTY; MAX_OWNER_ACCOUNTS];
        h.owners[0] = OwnerAccount::SYSTEM;
        h.arenas = [ArenaRecord::EMPTY; MAX_ALLOCATION_ARENAS];
        h.next_owner_id = 1;
        h.next_arena_id = 1;
        h.last_failure = None;
    }

    /// Global physical live/peak bytes and never-yet-used bump bytes.
    pub fn stats(&self) -> (usize, usize, usize) {
        let h = self.0.lock();
        (h.live_bytes, h.peak_bytes, h.end.saturating_sub(h.cursor))
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

    /// Close an arena after normal Drop has returned every tracked block.
    pub fn close_empty_arena(&self, arena: ArenaId) -> Result<(), ArenaError> {
        if !arena.is_tracked() {
            return Err(ArenaError::UntrackedArenaReserved);
        }
        let mut h = self.0.lock();
        let Some(index) = find_arena(&h, arena) else {
            return Err(ArenaError::UnknownArena);
        };
        let record = h.arenas[index];
        if record.live_bytes != 0 || record.live_allocations != 0 || record.head.is_some() {
            return Err(ArenaError::ArenaBusy {
                live_bytes: record.live_bytes,
                live_allocations: record.live_allocations,
            });
        }
        h.arenas[index] = ArenaRecord::EMPTY;
        Ok(())
    }

    /// Raw-reclaim every allocation belonging to a faulted incarnation.
    ///
    /// # Safety
    /// The caller must have permanently quiesced every task in `arena`, raw
    /// deallocated their future envelopes, removed runtime registrations, and
    /// proved that no pointer or reference into an arena allocation escaped.
    /// No destructor is run here.
    pub unsafe fn reclaim_faulted_arena(&self, arena: ArenaId) -> Result<ReclaimStats, ArenaError> {
        if !arena.is_tracked() {
            return Err(ArenaError::UntrackedArenaReserved);
        }
        let mut h = self.0.lock();
        let Some(arena_index) = find_arena(&h, arena) else {
            return Err(ArenaError::UnknownArena);
        };
        let record = h.arenas[arena_index];
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
            if allocations >= record.live_allocations {
                return Err(ArenaError::CorruptList);
            }
            let header = unsafe { header_ptr.as_ref() };
            if header.magic != HEADER_MAGIC
                || header.owner != record.owner
                || header.arena != arena
                || header.class >= NUM_CLASSES
                || header.arena_prev != previous
            {
                return Err(ArenaError::CorruptList);
            }
            bytes = bytes
                .checked_add(class_size(header.class))
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
            arena,
            owner: record.owner,
            reclaimed_bytes: bytes,
            reclaimed_allocations: allocations,
        })
    }

    pub fn account_stats(&self, owner: OwnerId) -> Option<OwnerStats> {
        let h = self.0.lock();
        find_owner(&h, owner).map(|index| h.owners[index].stats())
    }

    pub fn last_failure(&self) -> Option<AllocationFailure> {
        self.0.lock().last_failure
    }

    pub fn take_last_failure(&self) -> Option<AllocationFailure> {
        self.0.lock().last_failure.take()
    }

    /// Physical bytes charged for this layout, including allocator metadata,
    /// alignment padding, and size-class rounding.
    pub fn allocation_charge(layout: Layout) -> Option<usize> {
        allocation_plan(layout).map(|plan| plan.charge)
    }

    fn record_failure(&self, owner: OwnerId, failure: AllocationFailure) {
        let mut h = self.0.lock();
        if let Some(index) = find_owner(&h, owner) {
            h.owners[index].denials = h.owners[index].denials.saturating_add(1);
        }
        h.last_failure = Some(failure);
    }
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
        let domain = current_domain();
        let owner = domain.owner;
        let Some(plan) = allocation_plan(layout) else {
            self.record_failure(owner, AllocationFailure::LayoutOverflow { owner });
            return ptr::null_mut();
        };

        let mut h = self.0.lock();
        let Some(owner_index) = find_owner(&h, owner) else {
            h.last_failure = Some(AllocationFailure::UnknownOwner { owner });
            return ptr::null_mut();
        };

        let arena_index = if domain.arena.is_tracked() {
            let Some(index) = find_arena(&h, domain.arena) else {
                h.last_failure = Some(AllocationFailure::UnknownArena {
                    owner,
                    arena: domain.arena,
                });
                return ptr::null_mut();
            };
            let arena_owner = h.arenas[index].owner;
            if arena_owner != owner {
                h.last_failure = Some(AllocationFailure::ArenaOwnerMismatch {
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
            h.last_failure = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };
        if owner != OwnerId::SYSTEM && new_owner_live > account.quota_bytes {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failure = Some(AllocationFailure::QuotaExceeded {
                owner,
                requested_bytes: plan.charge,
                live_bytes: account.live_bytes,
                quota_bytes: account.quota_bytes,
            });
            return ptr::null_mut();
        }
        let Some(new_owner_allocations) = account.live_allocations.checked_add(1) else {
            h.owners[owner_index].denials = account.denials.saturating_add(1);
            h.last_failure = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };
        let new_arena_totals = if let Some(index) = arena_index {
            let arena = h.arenas[index];
            let Some(live_bytes) = arena.live_bytes.checked_add(plan.charge) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::AccountingOverflow {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            };
            let Some(live_allocations) = arena.live_allocations.checked_add(1) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::AccountingOverflow {
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
            h.last_failure = Some(AllocationFailure::AccountingOverflow {
                owner,
                requested_bytes: plan.charge,
            });
            return ptr::null_mut();
        };

        let (base, user) = if let Some(node) = h.free[plan.class] {
            let base = node.as_ptr().cast::<u8>() as usize;
            let Some(user) = user_address(base, plan, layout) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::LayoutOverflow { owner });
                return ptr::null_mut();
            };
            h.free[plan.class] = unsafe { node.as_ref().next };
            (base, user)
        } else {
            let base = h.cursor;
            let Some(next) = base.checked_add(plan.charge) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::HeapExhausted {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            };
            if next > h.end {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::HeapExhausted {
                    owner,
                    requested_bytes: plan.charge,
                });
                return ptr::null_mut();
            }
            let Some(user) = user_address(base, plan, layout) else {
                h.owners[owner_index].denials = account.denials.saturating_add(1);
                h.last_failure = Some(AllocationFailure::LayoutOverflow { owner });
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
        h.last_failure = None;
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
