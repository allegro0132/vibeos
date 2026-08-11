//! Capabilities: the only way to name anything in VibeOS.
//!
//! There is no global namespace, no path lookup, no uid, no root. A task can
//! act on a resource only by presenting a `Cap` it holds in its own `CSpace`,
//! and every operation names the rights it needs. `Cap` has private fields, so
//! safe code cannot mint one — it can only receive one from someone who already
//! had it, and only ever with a subset of that holder's rights.

extern crate alloc;

#[cfg(not(target_arch = "riscv64"))]
use alloc::alloc::{alloc, dealloc};
use alloc::alloc::{handle_alloc_error, Layout};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ops::Deref;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::heap::{self, OwnerId};
use vibeos_durable_format::{
    DerivationId, DurableRights, GrantRecord, ObjectId, RecoveredGrant, RecoveredSlot,
    ResourceKind, SlotIdentity, SpaceId,
};

pub const MAX_PERSISTENT_SLOTS: u32 = 4096;
pub const CAPABILITY_TABLE_PAGE_SIZE: usize = 4096;

pub type AllocateCapabilityTablePages = fn(page_count: usize) -> *mut u8;
pub type ProtectCapabilityTablePages = fn(start: usize, page_count: usize, read_only: bool);
pub type ReleaseCapabilityTablePages = unsafe fn(start: usize, page_count: usize);

/// Target-owned page storage for published capability tables.
///
/// The allocator must return one writable, contiguous, 4 KiB-aligned run of
/// exactly `page_count` pages. `set_read_only` must complete any required
/// all-hart permission synchronization before returning. `release_pages` is
/// called only after the run is writable again and every resident slot has
/// been dropped.
#[derive(Clone, Copy)]
pub struct CapabilityTableBackend {
    allocate_pages: AllocateCapabilityTablePages,
    set_read_only: ProtectCapabilityTablePages,
    release_pages: ReleaseCapabilityTablePages,
}

impl CapabilityTableBackend {
    /// Build a backend from target-owned raw-page operations.
    ///
    /// # Safety
    ///
    /// For every non-zero request, `allocate_pages` must return null or a
    /// unique writable run of exactly that many contiguous 4 KiB pages. A
    /// non-null run must remain live until the matching `release_pages` call.
    /// `set_read_only` must accept only such live, exact runs and synchronously
    /// complete the requested permission transition on every hart before it
    /// returns. `release_pages` must accept a retired writable run after every
    /// resident slot has been dropped, and must release that exact run once.
    /// All three callbacks must remain callable for the process lifetime and
    /// be safe under the CSpace synchronization used by the target.
    pub const unsafe fn new(
        allocate_pages: AllocateCapabilityTablePages,
        set_read_only: ProtectCapabilityTablePages,
        release_pages: ReleaseCapabilityTablePages,
    ) -> Self {
        Self {
            allocate_pages,
            set_read_only,
            release_pages,
        }
    }
}

const BACKEND_UNSET: u8 = 0;
const BACKEND_INSTALLING: u8 = 1;
const BACKEND_READY: u8 = 2;
static CAPABILITY_TABLE_BACKEND_STATE: AtomicU8 = AtomicU8::new(BACKEND_UNSET);
static CAPABILITY_TABLE_ALLOCATE: AtomicUsize = AtomicUsize::new(0);
static CAPABILITY_TABLE_PROTECT: AtomicUsize = AtomicUsize::new(0);
static CAPABILITY_TABLE_RELEASE: AtomicUsize = AtomicUsize::new(0);

const _: () = {
    assert!(mem::size_of::<AllocateCapabilityTablePages>() == mem::size_of::<usize>());
    assert!(mem::size_of::<ProtectCapabilityTablePages>() == mem::size_of::<usize>());
    assert!(mem::size_of::<ReleaseCapabilityTablePages>() == mem::size_of::<usize>());
};

/// Install the page backend used by every subsequently published capability
/// table. The target must do this once, during quiescent bootstrap, before the
/// first non-empty CSpace mutation. Existing tables retain the exact backend
/// which allocated them, so host fallback tables cannot later be released
/// through a newly installed backend.
pub fn set_capability_table_backend(backend: CapabilityTableBackend) {
    assert_eq!(
        CAPABILITY_TABLE_BACKEND_STATE.compare_exchange(
            BACKEND_UNSET,
            BACKEND_INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ),
        Ok(BACKEND_UNSET),
        "capability-table backend installed more than once",
    );
    CAPABILITY_TABLE_PROTECT.store(backend.set_read_only as usize, Ordering::Relaxed);
    CAPABILITY_TABLE_RELEASE.store(backend.release_pages as usize, Ordering::Relaxed);
    // The allocator address is part of the record, but BACKEND_READY is the
    // release publication point for all three function pointers.
    CAPABILITY_TABLE_ALLOCATE.store(backend.allocate_pages as usize, Ordering::Relaxed);
    CAPABILITY_TABLE_BACKEND_STATE.store(BACKEND_READY, Ordering::Release);
}

fn installed_capability_table_backend() -> Option<CapabilityTableBackend> {
    match CAPABILITY_TABLE_BACKEND_STATE.load(Ordering::Acquire) {
        BACKEND_UNSET => None,
        BACKEND_READY => {
            let allocate = CAPABILITY_TABLE_ALLOCATE.load(Ordering::Relaxed);
            let protect = CAPABILITY_TABLE_PROTECT.load(Ordering::Relaxed);
            let release = CAPABILITY_TABLE_RELEASE.load(Ordering::Relaxed);
            assert!(allocate != 0 && protect != 0 && release != 0);
            Some(CapabilityTableBackend {
                // Safety: the published words came only from the corresponding
                // function-pointer fields accepted by the setter above.
                allocate_pages: unsafe {
                    mem::transmute::<usize, AllocateCapabilityTablePages>(allocate)
                },
                set_read_only: unsafe {
                    mem::transmute::<usize, ProtectCapabilityTablePages>(protect)
                },
                release_pages: unsafe {
                    mem::transmute::<usize, ReleaseCapabilityTablePages>(release)
                },
            })
        }
        BACKEND_INSTALLING => panic!("capability-table backend observed during installation"),
        _ => unreachable!(),
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn host_allocate_capability_table_pages(page_count: usize) -> *mut u8 {
    let layout = capability_table_page_layout(page_count);
    // Safety: the layout is non-zero and has the exact page alignment promised
    // by the host fallback backend.
    unsafe { alloc(layout) }
}

#[cfg(not(target_arch = "riscv64"))]
fn host_protect_capability_table_pages(_start: usize, _page_count: usize, _read_only: bool) {}

#[cfg(not(target_arch = "riscv64"))]
unsafe fn host_release_capability_table_pages(start: usize, page_count: usize) {
    let layout = capability_table_page_layout(page_count);
    // Safety: this exact pointer/layout pair came from the host fallback
    // allocator and all resident Slots were dropped by CapTable first.
    unsafe { dealloc(start as *mut u8, layout) };
}

fn capability_table_backend() -> CapabilityTableBackend {
    if let Some(backend) = installed_capability_table_backend() {
        return backend;
    }

    #[cfg(not(target_arch = "riscv64"))]
    {
        // Safety: the fallback allocator uses an exact 4 KiB-aligned Layout,
        // its logical protection hook is synchronous, and release reconstructs
        // the identical pointer/Layout pair after CapTable drops every Slot.
        unsafe {
            CapabilityTableBackend::new(
                host_allocate_capability_table_pages,
                host_protect_capability_table_pages,
                host_release_capability_table_pages,
            )
        }
    }

    #[cfg(target_arch = "riscv64")]
    {
        panic!("riscv64 capability tables require an installed page backend")
    }
}

fn capability_table_page_layout(page_count: usize) -> Layout {
    let bytes = page_count
        .checked_mul(CAPABILITY_TABLE_PAGE_SIZE)
        .expect("capability-table page length overflowed");
    Layout::from_size_align(bytes, CAPABILITY_TABLE_PAGE_SIZE)
        .expect("capability-table page layout is invalid")
}

/// Capability tables and derivation nodes are supervisor metadata. They can be
/// mutated while a caller holds a CSpace lock, so their growth must not consume
/// the currently-polled component's quota and fault past that shared lock.
fn system_allocation<T>(f: impl FnOnce() -> T) -> T {
    let mut scope = heap::enter_owner(OwnerId::SYSTEM);
    let value = f();
    scope.restore();
    value
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rights(u32);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const SEND: Rights = Rights(1 << 2);
    pub const RECV: Rights = Rights(1 << 3);
    /// May copy this cap into another CSpace (never with more rights).
    pub const GRANT: Rights = Rights(1 << 4);
    /// May destroy this cap and every cap derived from it.
    pub const REVOKE: Rights = Rights(1 << 5);
    /// May invoke an audited volatile Command resource.
    ///
    /// This bit is deliberately outside the durable-v1 rights mask. Command
    /// capabilities are boot-local authority; persisted program artifacts use
    /// the separately reviewed READ/loader path.
    pub const INVOKE: Rights = Rights(1 << 6);

    /// All durable-v1 rights. Kept stable so generic resource roots do not
    /// accidentally gain command invocation authority.
    pub const ALL: Rights = Rights(0b11_1111);
    pub const ALL_VOLATILE: Rights = Rights(0b111_1111);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
    #[allow(dead_code)] // API surface: used when merging rights masks
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn from_durable(rights: DurableRights) -> Self {
        Self(rights.bits())
    }

    pub const fn durable(self) -> DurableRights {
        assert!(
            !self.contains(Self::INVOKE),
            "INVOKE is not durable-v1 authority"
        );
        match DurableRights::from_bits(self.0) {
            Some(rights) => rights,
            None => unreachable!(),
        }
    }
}

/// Renders as the same `rwsvgx` string as `Display`, so a failed assertion in a
/// test names the rights instead of a bitmask.
impl fmt::Debug for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(Rights, char); 6] = [
            (Rights::READ, 'r'),
            (Rights::WRITE, 'w'),
            (Rights::SEND, 's'),
            (Rights::RECV, 'v'),
            (Rights::GRANT, 'g'),
            (Rights::REVOKE, 'x'),
        ];
        for (bit, ch) in NAMES {
            f.write_str(if self.contains(bit) {
                match ch {
                    'r' => "r",
                    'w' => "w",
                    's' => "s",
                    'v' => "v",
                    'g' => "g",
                    _ => "x",
                }
            } else {
                "-"
            })?;
        }
        if self.contains(Rights::INVOKE) {
            f.write_str("i")?;
        }
        Ok(())
    }
}

/// A node in the derivation graph.
///
/// Every capability points at one. A cap is live only if its own node is alive
/// *and* every ancestor is — which is what makes revocation reach copies that
/// have travelled into other spaces. The graph is held together by `Arc`, so
/// there is no registry to keep in sync and no requirement that the revoker be
/// able to reach the spaces holding the copies.
struct Derivation {
    alive: AtomicBool,
    parent: Option<Arc<Derivation>>,
    persistent: Option<PersistentNodeIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PersistentNodeIdentity {
    derivation_id: DerivationId,
    object_id: ObjectId,
    resource_kind: ResourceKind,
}

impl Derivation {
    fn root() -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            parent: None,
            persistent: None,
        })
    }

    fn child(parent: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            parent: Some(parent.clone()),
            persistent: None,
        })
    }

    fn persistent_root(identity: PersistentNodeIdentity) -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            parent: None,
            persistent: Some(identity),
        })
    }

    fn persistent_child(parent: &Arc<Self>, identity: PersistentNodeIdentity) -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            parent: Some(parent.clone()),
            persistent: Some(identity),
        })
    }

    fn is_alive(&self) -> bool {
        let mut node = self;
        loop {
            if !node.alive.load(Ordering::Acquire) {
                return false;
            }
            match &node.parent {
                Some(p) => node = p,
                None => return true,
            }
        }
    }

    fn kill(&self) {
        self.alive.store(false, Ordering::Release);
    }

    fn descends_from(node: &Arc<Self>, ancestor: &Arc<Self>) -> bool {
        let mut current = node.as_ref();
        loop {
            if core::ptr::eq(current, ancestor.as_ref()) {
                return true;
            }
            match current.parent.as_deref() {
                Some(parent) => current = parent,
                None => return false,
            }
        }
    }
}

/// An opaque handle. Meaningless outside the `CSpace` that issued it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    slot: u32,
    /// 64 bits so exhausting it is unreachable; a slot that somehow did exhaust
    /// it is retired rather than reused (see `alloc_slot`).
    generation: u64,
}

impl Cap {
    #[allow(dead_code)] // API surface: slot identity for external cap tables
    pub fn slot(self) -> u32 {
        self.slot
    }
}

impl fmt::Display for Cap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cap:{}.{}", self.slot, self.generation)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// The slot is empty, or the generation is stale (it was revoked).
    Invalid,
    /// The cap is live but does not carry the rights this operation needs.
    InsufficientRights,
    /// Attempted to derive a cap with rights the parent does not hold.
    Amplification,
    /// The object behind the cap is not of the requested type.
    WrongType,
    /// The operation requires a durably committed grant or tombstone.
    PersistentLifecycleRequired,
    /// The live capability has no durable derivation identity.
    NotPersistent,
    /// Stable durable identity did not exactly match the live slot.
    PersistentIdentityMismatch,
    /// The durable CSpace was isolated after its live state diverged from disk.
    PersistentQuarantined,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CapError::Invalid => "invalid or revoked capability",
            CapError::InsufficientRights => "insufficient rights",
            CapError::Amplification => "rights amplification refused",
            CapError::WrongType => "capability names the wrong resource type",
            CapError::PersistentLifecycleRequired => "durable capability lifecycle required",
            CapError::NotPersistent => "capability has no durable identity",
            CapError::PersistentIdentityMismatch => "durable capability identity mismatch",
            CapError::PersistentQuarantined => "durable capability space is quarantined",
        })
    }
}

pub trait Resource: Any + Send + Sync {
    fn kind(&self) -> &'static str;
    fn describe(&self) -> String {
        String::from(self.kind())
    }
    fn as_any(&self) -> &dyn Any;
}

#[derive(Clone)]
struct Slot {
    generation: u64,
    entry: Option<Entry>,
    reservation: Option<u64>,
}

#[derive(Clone)]
struct Entry {
    obj: Arc<dyn Resource>,
    rights: Rights,
    node: Arc<Derivation>,
}

/// Page range occupied by one immutable published capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityTableRange {
    pub start: usize,
    pub page_count: usize,
    pub slot_count: usize,
}

/// Raw page-backed storage for the one authoritative slot slice.
///
/// No mutable slice is ever exposed. Mutations clone into an ordinary Vec,
/// publish a separately allocated read-only table, and only then retire this
/// backing. Keeping the allocating backend in the object makes Drop exact even
/// if a host test installs a target-like backend after fallback tables exist.
struct CapTable {
    slots: NonNull<Slot>,
    slot_count: usize,
    page_count: usize,
    read_only: bool,
    backend: Option<CapabilityTableBackend>,
}

// Slot contains only Send+Sync resource/derivation Arcs and scalar metadata.
// Exclusive mutation remains owned by CSpace; published readers see &[Slot].
unsafe impl Send for CapTable {}
unsafe impl Sync for CapTable {}

impl CapTable {
    const fn empty() -> Self {
        Self {
            slots: NonNull::dangling(),
            slot_count: 0,
            page_count: 0,
            read_only: false,
            backend: None,
        }
    }

    fn from_slots(slots: Vec<Slot>) -> Self {
        if slots.is_empty() {
            return Self::empty();
        }
        let slot_bytes = slots
            .len()
            .checked_mul(mem::size_of::<Slot>())
            .expect("capability-table slot length overflowed");
        let page_count = slot_bytes
            .checked_add(CAPABILITY_TABLE_PAGE_SIZE - 1)
            .expect("capability-table page rounding overflowed")
            / CAPABILITY_TABLE_PAGE_SIZE;
        let backend = capability_table_backend();
        let allocation = (backend.allocate_pages)(page_count);
        let Some(bytes) = NonNull::new(allocation) else {
            handle_alloc_error(capability_table_page_layout(page_count));
        };
        assert_eq!(
            bytes.as_ptr() as usize % CAPABILITY_TABLE_PAGE_SIZE,
            0,
            "capability-table backend returned an unaligned run",
        );
        let destination = bytes.cast::<Slot>();
        let slot_count = slots.len();
        for (index, slot) in slots.into_iter().enumerate() {
            // Safety: the backend returned `page_count` writable pages, the
            // rounded allocation covers every Slot, and each index is written
            // exactly once before publication.
            unsafe { destination.as_ptr().add(index).write(slot) };
        }
        Self {
            slots: destination,
            slot_count,
            page_count,
            read_only: false,
            backend: Some(backend),
        }
    }

    fn publish_read_only(mut self) -> Self {
        if let Some(backend) = self.backend {
            (backend.set_read_only)(self.slots.as_ptr() as usize, self.page_count, true);
            self.read_only = true;
        }
        self
    }

    fn range(&self) -> Option<CapabilityTableRange> {
        (self.slot_count != 0).then_some(CapabilityTableRange {
            start: self.slots.as_ptr() as usize,
            page_count: self.page_count,
            slot_count: self.slot_count,
        })
    }

    fn as_slice(&self) -> &[Slot] {
        // Safety: construction initialized exactly slot_count elements and the
        // backing remains allocated until Drop. Published pages are immutable.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr(), self.slot_count) }
    }
}

impl Deref for CapTable {
    type Target = [Slot];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Drop for CapTable {
    fn drop(&mut self) {
        let Some(backend) = self.backend else {
            debug_assert_eq!(self.slot_count, 0);
            debug_assert_eq!(self.page_count, 0);
            return;
        };

        // Replacement already made another sealed table authoritative. Only
        // this retired backing is made writable for destructor bookkeeping.
        if self.read_only {
            (backend.set_read_only)(self.slots.as_ptr() as usize, self.page_count, false);
            self.read_only = false;
        }
        // Safety: permission restoration completed, and these are precisely
        // the initialized Slots which have not yet been dropped.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.slots.as_ptr(),
                self.slot_count,
            ));
            (backend.release_pages)(self.slots.as_ptr() as usize, self.page_count);
        }
    }
}

/// A resolved capability that revalidates its derivation at the start of every
/// operation.
///
/// The object and derivation node deliberately remain private. Callers can use
/// the resource only through [`Revocable::try_with`]; there is no `Deref`,
/// `AsRef`, or `Arc` extractor that could turn one successful check into
/// authority which silently survives revocation. Cloning this token is safe:
/// every clone performs the same ancestry check before every operation.
/// The successful check is the operation's authority-acquisition linearization
/// point: a concurrent revocation prevents later acquisitions but does not
/// forcibly interrupt a callback which already passed that check.
///
/// This wrapper prevents the resource borrow and backing `Arc` from escaping.
/// A resource method that deliberately returns an owned handle or raw address
/// defines its own authority boundary and remains part of that resource's TCB.
///
/// A borrow of the resource cannot escape the operation callback:
///
/// ```compile_fail
/// use vibeos_core::cap::{Resource, Revocable};
///
/// fn leak<T: Resource>(token: &Revocable<T>) -> &T {
///     token.try_with(|resource| resource).unwrap()
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_core::cap::{Resource, Revocable};
///
/// fn deref<T: Resource>(token: &Revocable<T>) -> &T {
///     token
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_core::cap::{Resource, Revocable};
///
/// fn as_ref<T: Resource>(token: &Revocable<T>) -> &T {
///     token.as_ref()
/// }
/// ```
///
/// ```compile_fail
/// use std::sync::Arc;
/// use vibeos_core::cap::{Resource, Revocable};
///
/// fn into_arc<T: Resource>(token: Revocable<T>) -> Arc<T> {
///     token.into_inner()
/// }
/// ```
#[must_use = "dropping a revocable token relinquishes the resolved authority"]
pub struct Revocable<T: Resource> {
    object: Arc<T>,
    node: Arc<Derivation>,
}

impl<T: Resource> Clone for Revocable<T> {
    fn clone(&self) -> Self {
        Self {
            object: self.object.clone(),
            node: self.node.clone(),
        }
    }
}

impl<T: Resource> Revocable<T> {
    /// Revalidate the complete derivation ancestry, then perform one operation.
    ///
    /// The higher-ranked callback permits returning owned values but prevents a
    /// reference borrowed from the resource from escaping this call.
    pub fn try_with<R, F>(&self, operation: F) -> Result<R, CapError>
    where
        F: for<'a> FnOnce(&'a T) -> R,
    {
        if !self.node.is_alive() {
            return Err(CapError::Invalid);
        }
        Ok(operation(&self.object))
    }
}

/// A resolved capability whose authority lasts for one explicit invocation.
///
/// Revocation prevents acquisition of a new lease but does not invalidate a
/// lease already acquired. The lease is intentionally non-`Clone`, has no
/// `Deref`, and exposes neither its `Arc` nor a resource reference. Invocation
/// owners must retain this value for the complete lifetime of any raw state
/// derived inside [`InvocationLease::with`].
///
/// Neither the resource borrow nor the backing `Arc` can be extracted:
///
/// ```compile_fail
/// use vibeos_core::cap::{InvocationLease, Resource};
///
/// fn leak<T: Resource>(lease: &InvocationLease<T>) -> &T {
///     lease.with(|resource| resource)
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_core::cap::{InvocationLease, Resource};
///
/// fn deref<T: Resource>(lease: &InvocationLease<T>) -> &T {
///     lease
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_core::cap::{InvocationLease, Resource};
///
/// fn as_ref<T: Resource>(lease: &InvocationLease<T>) -> &T {
///     lease.as_ref()
/// }
/// ```
///
/// ```compile_fail
/// use std::sync::Arc;
/// use vibeos_core::cap::{InvocationLease, Resource};
///
/// fn into_arc<T: Resource>(lease: InvocationLease<T>) -> Arc<T> {
///     lease.into_inner()
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_core::cap::{InvocationLease, Resource};
///
/// fn duplicate<T: Resource>(lease: &InvocationLease<T>) -> InvocationLease<T> {
///     (*lease).clone()
/// }
/// ```
#[must_use = "the invocation lease must remain alive for the complete invocation"]
pub struct InvocationLease<T: Resource> {
    object: Arc<T>,
    rights: Rights,
}

impl<T: Resource> InvocationLease<T> {
    /// Test whether this already-resolved invocation carries a required right.
    /// The full slot rights are retained even when lookup requested `NONE`, so
    /// a service API can enforce its own operation-specific boundary.
    pub const fn authorizes(&self, need: Rights) -> bool {
        self.rights.contains(need)
    }

    /// Perform work through this invocation's already-resolved authority.
    ///
    /// Unlike [`Revocable::try_with`], this intentionally does not revalidate:
    /// revocation affects the next lease acquisition, not the active invocation.
    pub fn with<R, F>(&self, operation: F) -> R
    where
        F: for<'a> FnOnce(&'a T) -> R,
    {
        operation(&self.object)
    }
}

/// Stable identity of one live durable capability. Fields are private so safe
/// callers cannot synthesize an identity and use it as authority; lookup still
/// revalidates the exact live CSpace entry and Rust resource type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentCapIdentity {
    space: SpaceId,
    slot: u32,
    generation: u64,
    derivation_id: DerivationId,
    object_id: ObjectId,
    resource_kind: ResourceKind,
    rights: Rights,
}

impl PersistentCapIdentity {
    pub const fn space(self) -> SpaceId {
        self.space
    }

    pub const fn slot(self) -> u32 {
        self.slot
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn derivation_id(self) -> DerivationId {
        self.derivation_id
    }

    pub const fn object_id(self) -> ObjectId {
        self.object_id
    }

    pub const fn resource_kind(self) -> ResourceKind {
        self.resource_kind
    }

    pub const fn rights(self) -> Rights {
        self.rights
    }

    pub const fn target(self) -> SlotIdentity {
        SlotIdentity {
            space: self.space,
            slot: self.slot,
            generation: self.generation,
        }
    }
}

/// Typed, non-forgeable view of one live durable derivation. It retains the
/// object and ancestry only inside the capability module, allowing a child to
/// be installed after an asynchronous commit without exposing a raw lookup.
pub struct PersistentDerivationWitness<T: Resource> {
    identity: PersistentCapIdentity,
    object: Arc<T>,
    node: Arc<Derivation>,
    marker: PhantomData<fn() -> T>,
}

impl<T: Resource> PersistentDerivationWitness<T> {
    pub const fn identity(&self) -> PersistentCapIdentity {
        self.identity
    }

    fn into_revocable(self) -> Revocable<T> {
        Revocable {
            object: self.object,
            node: self.node,
        }
    }
}

/// One fixed typed resource supplied by the supervisor for a single recovery
/// installation. This is not an ambient ObjectId registry and exposes no Arc
/// getter after type erasure.
pub struct PersistentResourceWitness {
    object_id: ObjectId,
    resource_kind: ResourceKind,
    object: Arc<dyn Resource>,
}

impl PersistentResourceWitness {
    pub fn new<T: Resource>(
        object_id: ObjectId,
        resource_kind: ResourceKind,
        object: Arc<T>,
    ) -> Self {
        Self {
            object_id,
            resource_kind,
            object,
        }
    }

    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }
}

/// Opaque reservation held while grant records are written and flushed. It is
/// exact to one CSpace incarnation, slot generation, and internal token.
#[must_use = "a pending durable slot must be installed or explicitly cancelled"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSlotReservation {
    space: SpaceId,
    slot: u32,
    generation: u64,
    incarnation: u64,
    token: u64,
}

impl PendingSlotReservation {
    pub const fn target(&self) -> SlotIdentity {
        SlotIdentity {
            space: self.space,
            slot: self.slot,
            generation: self.generation,
        }
    }

    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentInstallError {
    NotPersistentSpace,
    PersistentQuarantined,
    IncarnationChanged,
    SlotOutOfRange,
    SlotBusy,
    ReservationMismatch,
    ReservationExhausted,
    DuplicateSlot,
    DuplicateDerivation,
    DuplicateResource,
    MissingResource,
    ResourceKindMismatch,
    GenerationRegression,
    LiveSlotMismatch,
    MissingLiveGrant,
    ForeignSpace,
    RootShape,
    MissingParent,
    ParentCannotGrant,
    RightsAmplification,
    ObjectMismatch,
    ParentNotPersistent,
}

impl fmt::Display for PersistentInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotPersistentSpace => "CSpace has no durable SpaceId",
            Self::PersistentQuarantined => "durable capability space is quarantined",
            Self::IncarnationChanged => "CSpace incarnation changed",
            Self::SlotOutOfRange => "durable slot is out of range",
            Self::SlotBusy => "durable slot is already occupied",
            Self::ReservationMismatch => "durable slot reservation does not match",
            Self::ReservationExhausted => "durable slot reservation identity exhausted",
            Self::DuplicateSlot => "duplicate durable slot history",
            Self::DuplicateDerivation => "duplicate durable derivation",
            Self::DuplicateResource => "duplicate durable resource witness",
            Self::MissingResource => "durable resource witness is missing",
            Self::ResourceKindMismatch => "durable resource kind does not match",
            Self::GenerationRegression => "durable slot generation would regress",
            Self::LiveSlotMismatch => "live grant does not match durable slot history",
            Self::MissingLiveGrant => "durable live slot has no grant",
            Self::ForeignSpace => "durable state belongs to another CSpace",
            Self::RootShape => "durable root shape is invalid",
            Self::MissingParent => "durable parent is missing",
            Self::ParentCannotGrant => "durable parent lacks GRANT",
            Self::RightsAmplification => "durable child amplifies rights",
            Self::ObjectMismatch => "durable child changes object identity",
            Self::ParentNotPersistent => "parent capability is not durable",
        })
    }
}

/// A task's capability space. Owning one *is* the task's entire authority.
pub struct CSpace {
    pub name: String,
    slots: CapTable,
    incarnation: u64,
    persistent_space: Option<SpaceId>,
    persistent_quarantined: bool,
    next_reservation: u64,
}

impl CSpace {
    fn candidate_slots(&self, additional: usize) -> Vec<Slot> {
        system_allocation(|| {
            let capacity = self
                .slots
                .len()
                .checked_add(additional)
                .expect("capability-table candidate capacity overflowed");
            let mut candidate = Vec::with_capacity(capacity);
            candidate.extend_from_slice(self.slots.as_slice());
            candidate
        })
    }

    fn publish_slots(&mut self, candidate: Vec<Slot>) {
        // The detached candidate is moved into a fresh writable page run under
        // SYSTEM accounting. Protection completes before the pointer becomes
        // authoritative; the old backing is retired only after replacement.
        let next = system_allocation(|| CapTable::from_slots(candidate)).publish_read_only();
        let retired = mem::replace(&mut self.slots, next);
        drop(retired);
    }

    fn alloc_candidate_slot(candidate: &mut Vec<Slot>) -> u32 {
        // A slot whose generation saturated is retired forever rather than
        // reused, so a stale handle can never alias a fresh one.
        if let Some(index) = candidate.iter().position(|slot| {
            slot.entry.is_none() && slot.reservation.is_none() && slot.generation != u64::MAX
        }) {
            return u32::try_from(index).expect("capability slot index exceeds u32");
        }
        candidate.push(Slot {
            generation: 0,
            entry: None,
            reservation: None,
        });
        u32::try_from(candidate.len() - 1).expect("capability slot index exceeds u32")
    }

    /// Physical page range of the currently published read-only slot table.
    /// Empty CSpaces have no backing allocation until their first mutation.
    pub fn capability_table_range(&self) -> Option<CapabilityTableRange> {
        self.slots.range()
    }

    /// Reserve the exact slot generation that a durable `GrantRecord` will
    /// name. The reservation survives ordinary allocation and space-reset
    /// attempts until it is installed or explicitly cancelled.
    pub fn reserve_persistent_slot(
        &mut self,
        expected_incarnation: u64,
    ) -> Result<PendingSlotReservation, PersistentInstallError> {
        let space = self
            .persistent_space
            .ok_or(PersistentInstallError::NotPersistentSpace)?;
        self.ensure_persistent_not_quarantined()?;
        if self.incarnation != expected_incarnation {
            return Err(PersistentInstallError::IncarnationChanged);
        }
        let next_token = self
            .next_reservation
            .checked_add(1)
            .ok_or(PersistentInstallError::ReservationExhausted)?;
        let reusable = self.slots.iter().position(|slot| {
            slot.entry.is_none() && slot.reservation.is_none() && slot.generation != u64::MAX
        });
        if reusable.is_none() {
            if self.slots.len() >= MAX_PERSISTENT_SLOTS as usize {
                return Err(PersistentInstallError::SlotOutOfRange);
            }
        }
        let mut candidate = self.candidate_slots(usize::from(reusable.is_none()));
        let index = reusable.unwrap_or_else(|| {
            candidate.push(Slot {
                generation: 0,
                entry: None,
                reservation: None,
            });
            candidate.len() - 1
        });
        let token = self.next_reservation;
        candidate[index].reservation = Some(token);
        let reservation = PendingSlotReservation {
            space,
            slot: index as u32,
            generation: candidate[index].generation,
            incarnation: self.incarnation,
            token,
        };
        self.publish_slots(candidate);
        self.next_reservation = next_token;
        Ok(reservation)
    }

    /// Release a reservation after its durable append failed. Cancelling does
    /// not advance the generation because no grant became durable.
    pub fn cancel_persistent_slot(
        &mut self,
        reservation: &PendingSlotReservation,
    ) -> Result<(), PersistentInstallError> {
        let index = self.validate_reservation(reservation)?;
        let mut candidate = self.candidate_slots(0);
        candidate[index].reservation = None;
        self.publish_slots(candidate);
        Ok(())
    }

    fn validate_reservation(
        &self,
        reservation: &PendingSlotReservation,
    ) -> Result<usize, PersistentInstallError> {
        let space = self
            .persistent_space
            .ok_or(PersistentInstallError::NotPersistentSpace)?;
        self.ensure_persistent_not_quarantined()?;
        if self.incarnation != reservation.incarnation {
            return Err(PersistentInstallError::IncarnationChanged);
        }
        if space != reservation.space {
            return Err(PersistentInstallError::ReservationMismatch);
        }
        let index = usize::try_from(reservation.slot)
            .map_err(|_| PersistentInstallError::SlotOutOfRange)?;
        let slot = self
            .slots
            .get(index)
            .ok_or(PersistentInstallError::SlotOutOfRange)?;
        if slot.generation != reservation.generation
            || slot.entry.is_some()
            || slot.reservation != Some(reservation.token)
        {
            return Err(PersistentInstallError::ReservationMismatch);
        }
        Ok(index)
    }

    fn contains_persistent_derivation(&self, derivation_id: DerivationId) -> bool {
        self.slots.iter().any(|slot| {
            slot.entry
                .as_ref()
                .and_then(|entry| entry.node.persistent)
                .is_some_and(|identity| identity.derivation_id == derivation_id)
        })
    }

    fn persistent_identity(
        &self,
        cap: Cap,
        entry: &Entry,
    ) -> Result<PersistentCapIdentity, CapError> {
        let space = self.persistent_space.ok_or(CapError::NotPersistent)?;
        let persistent = entry.node.persistent.ok_or(CapError::NotPersistent)?;
        Ok(PersistentCapIdentity {
            space,
            slot: cap.slot,
            generation: cap.generation,
            derivation_id: persistent.derivation_id,
            object_id: persistent.object_id,
            resource_kind: persistent.resource_kind,
            rights: entry.rights,
        })
    }

    fn exact_persistent_entry(
        &self,
        identity: PersistentCapIdentity,
        need: Rights,
    ) -> Result<&Entry, CapError> {
        if self.persistent_space != Some(identity.space) {
            return Err(CapError::PersistentIdentityMismatch);
        }
        let cap = Cap {
            slot: identity.slot,
            generation: identity.generation,
        };
        let entry = self.checked_entry(cap, need)?;
        let Some(persistent) = entry.node.persistent else {
            return Err(CapError::PersistentIdentityMismatch);
        };
        if persistent.derivation_id != identity.derivation_id
            || persistent.object_id != identity.object_id
            || persistent.resource_kind != identity.resource_kind
            || entry.rights != identity.rights
        {
            return Err(CapError::PersistentIdentityMismatch);
        }
        Ok(entry)
    }

    /// Convert a live capability into a typed, unforgeable durable witness.
    /// Ephemeral capabilities are rejected even if their Rust resource type and
    /// rights otherwise match.
    pub fn persistent_witness<T: Resource>(
        &self,
        cap: Cap,
        need: Rights,
    ) -> Result<PersistentDerivationWitness<T>, CapError> {
        let (object, node, _rights) = self.typed_parts(cap, need)?;
        let entry = self.entry(cap)?;
        let identity = self.persistent_identity(cap, entry)?;
        Ok(PersistentDerivationWitness {
            identity,
            object,
            node,
            marker: PhantomData,
        })
    }

    /// Resolve only a durable capability into an operation-time token.
    /// Ephemeral capabilities are rejected even when their type and rights
    /// match, and every operation still revalidates the durable ancestry.
    pub fn lookup_persistent_revocable<T: Resource>(
        &self,
        cap: Cap,
        need: Rights,
    ) -> Result<Revocable<T>, CapError> {
        Ok(self.persistent_witness::<T>(cap, need)?.into_revocable())
    }

    /// Reconstitute a typed witness from a previously returned exact identity.
    /// This is the durable equivalent of resolving a `Cap`; it never exposes an
    /// ambient `ObjectId` lookup.
    pub fn persistent_witness_for_identity<T: Resource>(
        &self,
        identity: PersistentCapIdentity,
        need: Rights,
    ) -> Result<PersistentDerivationWitness<T>, CapError> {
        let entry = self.exact_persistent_entry(identity, need)?;
        let object: Arc<dyn Any + Send + Sync> = entry.obj.clone();
        let object = Arc::downcast::<T>(object).map_err(|_| CapError::WrongType)?;
        Ok(PersistentDerivationWitness {
            identity,
            object,
            node: entry.node.clone(),
            marker: PhantomData,
        })
    }

    /// Resolve one exact durable identity into a typed invocation lease.
    pub fn lookup_persistent_identity<T: Resource>(
        &self,
        identity: PersistentCapIdentity,
        need: Rights,
    ) -> Result<InvocationLease<T>, CapError> {
        let entry = self.exact_persistent_entry(identity, need)?;
        let object: Arc<dyn Any + Send + Sync> = entry.obj.clone();
        let object = Arc::downcast::<T>(object).map_err(|_| CapError::WrongType)?;
        Ok(InvocationLease {
            object,
            rights: entry.rights,
        })
    }

    /// Install a committed root grant into its exact reserved generation.
    pub fn install_reserved_root<T: Resource>(
        &mut self,
        reservation: &PendingSlotReservation,
        grant: &GrantRecord,
        object: Arc<T>,
    ) -> Result<(Cap, PersistentDerivationWitness<T>), PersistentInstallError> {
        let index = self.validate_reservation(reservation)?;
        if grant.target != reservation.target() {
            return Err(PersistentInstallError::ReservationMismatch);
        }
        if !grant.flags.is_root() || grant.parent_id.is_some() {
            return Err(PersistentInstallError::RootShape);
        }
        if self.contains_persistent_derivation(grant.derivation_id) {
            return Err(PersistentInstallError::DuplicateDerivation);
        }
        let erased: Arc<dyn Resource> = object.clone();
        for entry in self.slots.iter().filter_map(|slot| slot.entry.as_ref()) {
            let Some(existing) = entry.node.persistent else {
                continue;
            };
            if existing.object_id == grant.object_id {
                if existing.resource_kind != grant.resource_kind {
                    return Err(PersistentInstallError::ResourceKindMismatch);
                }
                if !Arc::ptr_eq(&entry.obj, &erased) {
                    return Err(PersistentInstallError::ObjectMismatch);
                }
            }
        }
        let identity = PersistentNodeIdentity {
            derivation_id: grant.derivation_id,
            object_id: grant.object_id,
            resource_kind: grant.resource_kind,
        };
        let node = system_allocation(|| Derivation::persistent_root(identity));
        let rights = Rights::from_durable(grant.rights);
        let cap_identity = PersistentCapIdentity {
            space: grant.target.space,
            slot: grant.target.slot,
            generation: grant.target.generation,
            derivation_id: grant.derivation_id,
            object_id: grant.object_id,
            resource_kind: grant.resource_kind,
            rights,
        };
        let mut candidate = self.candidate_slots(0);
        candidate[index].entry = Some(Entry {
            obj: erased,
            rights,
            node: node.clone(),
        });
        candidate[index].reservation = None;
        let cap = Cap {
            slot: grant.target.slot,
            generation: grant.target.generation,
        };
        self.publish_slots(candidate);
        Ok((
            cap,
            PersistentDerivationWitness {
                identity: cap_identity,
                object,
                node,
                marker: PhantomData,
            },
        ))
    }

    /// Install a committed child grant, preserving the parent's exact object
    /// and enforcing monotone rights attenuation.
    pub fn install_reserved_child<T: Resource>(
        &mut self,
        reservation: &PendingSlotReservation,
        parent: &PersistentDerivationWitness<T>,
        grant: &GrantRecord,
    ) -> Result<(Cap, PersistentDerivationWitness<T>), PersistentInstallError> {
        let index = self.validate_reservation(reservation)?;
        if grant.target != reservation.target() {
            return Err(PersistentInstallError::ReservationMismatch);
        }
        if grant.flags.is_root() || grant.parent_id != Some(parent.identity.derivation_id) {
            return Err(PersistentInstallError::RootShape);
        }
        if grant.object_id != parent.identity.object_id
            || grant.resource_kind != parent.identity.resource_kind
        {
            return Err(PersistentInstallError::ObjectMismatch);
        }
        let parent_entry = self
            .exact_persistent_entry(parent.identity, Rights::GRANT)
            .map_err(|error| match error {
                CapError::InsufficientRights => PersistentInstallError::ParentCannotGrant,
                CapError::NotPersistent => PersistentInstallError::ParentNotPersistent,
                _ => PersistentInstallError::ParentNotPersistent,
            })?;
        if !Arc::ptr_eq(&parent_entry.node, &parent.node) {
            return Err(PersistentInstallError::ParentNotPersistent);
        }
        let parent_object: Arc<dyn Any + Send + Sync> = parent_entry.obj.clone();
        let parent_object = Arc::downcast::<T>(parent_object)
            .map_err(|_| PersistentInstallError::ObjectMismatch)?;
        if !Arc::ptr_eq(&parent_object, &parent.object) {
            return Err(PersistentInstallError::ObjectMismatch);
        }
        let rights = Rights::from_durable(grant.rights);
        if !parent.identity.rights.contains(rights) {
            return Err(PersistentInstallError::RightsAmplification);
        }
        if self.contains_persistent_derivation(grant.derivation_id) {
            return Err(PersistentInstallError::DuplicateDerivation);
        }
        let identity = PersistentNodeIdentity {
            derivation_id: grant.derivation_id,
            object_id: grant.object_id,
            resource_kind: grant.resource_kind,
        };
        let node = system_allocation(|| Derivation::persistent_child(&parent.node, identity));
        let cap_identity = PersistentCapIdentity {
            space: grant.target.space,
            slot: grant.target.slot,
            generation: grant.target.generation,
            derivation_id: grant.derivation_id,
            object_id: grant.object_id,
            resource_kind: grant.resource_kind,
            rights,
        };
        let erased: Arc<dyn Resource> = parent.object.clone();
        let mut candidate = self.candidate_slots(0);
        candidate[index].entry = Some(Entry {
            obj: erased,
            rights,
            node: node.clone(),
        });
        candidate[index].reservation = None;
        let cap = Cap {
            slot: grant.target.slot,
            generation: grant.target.generation,
        };
        self.publish_slots(candidate);
        Ok((
            cap,
            PersistentDerivationWitness {
                identity: cap_identity,
                object: parent.object.clone(),
                node,
                marker: PhantomData,
            },
        ))
    }

    /// Validate and install one recovered durable CSpace as an atomic graph.
    ///
    /// `slots` must include every historical slot for this space, including
    /// tombstoned ones; `grants` must contain exactly the live graph. All
    /// allocation and validation happens in a detached candidate table, so an
    /// error leaves `self` byte-for-byte authoritative as it was before.
    pub fn install_recovered_graph(
        &mut self,
        expected_incarnation: u64,
        slots: &[RecoveredSlot],
        grants: &[RecoveredGrant],
        resources: &[PersistentResourceWitness],
    ) -> Result<Vec<PersistentCapIdentity>, PersistentInstallError> {
        system_allocation(|| {
            self.install_recovered_graph_system(expected_incarnation, slots, grants, resources)
        })
    }

    /// The caller holds the CSpace lock. Keep every candidate map, set, vector,
    /// erased Arc clone, and derivation allocation in the supervisor domain so
    /// a component quota fault cannot unwind across that shared lock.
    fn install_recovered_graph_system(
        &mut self,
        expected_incarnation: u64,
        slots: &[RecoveredSlot],
        grants: &[RecoveredGrant],
        resources: &[PersistentResourceWitness],
    ) -> Result<Vec<PersistentCapIdentity>, PersistentInstallError> {
        let space = self
            .persistent_space
            .ok_or(PersistentInstallError::NotPersistentSpace)?;
        self.ensure_persistent_not_quarantined()?;
        if self.incarnation != expected_incarnation {
            return Err(PersistentInstallError::IncarnationChanged);
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.entry.is_some() || slot.reservation.is_some())
        {
            return Err(PersistentInstallError::SlotBusy);
        }
        if self.slots.len() > MAX_PERSISTENT_SLOTS as usize {
            return Err(PersistentInstallError::SlotOutOfRange);
        }

        let mut resource_map = BTreeMap::new();
        for resource in resources {
            if resource_map.insert(resource.object_id, resource).is_some() {
                return Err(PersistentInstallError::DuplicateResource);
            }
        }

        let mut history = BTreeMap::new();
        let mut live_derivations = BTreeSet::new();
        let mut candidate_len = self.slots.len();
        for recovered in slots {
            if recovered.space != space {
                return Err(PersistentInstallError::ForeignSpace);
            }
            if recovered.slot >= MAX_PERSISTENT_SLOTS {
                return Err(PersistentInstallError::SlotOutOfRange);
            }
            candidate_len = candidate_len.max(recovered.slot as usize + 1);
            if history.insert(recovered.slot, *recovered).is_some() {
                return Err(PersistentInstallError::DuplicateSlot);
            }
            if let Some(derivation_id) = recovered.live_derivation {
                if !live_derivations.insert(derivation_id) {
                    return Err(PersistentInstallError::DuplicateDerivation);
                }
            }
        }

        let mut candidate = system_allocation(|| Vec::with_capacity(candidate_len));
        for index in 0..candidate_len {
            let existing_generation = self
                .slots
                .get(index)
                .map(|slot| slot.generation)
                .unwrap_or(0);
            let generation = match history.get(&(index as u32)) {
                Some(recovered) if recovered.live_derivation.is_some() => recovered.max_generation,
                Some(recovered) => recovered.max_generation.saturating_add(1),
                None => {
                    if existing_generation != 0 {
                        return Err(PersistentInstallError::GenerationRegression);
                    }
                    0
                }
            };
            if generation < existing_generation {
                return Err(PersistentInstallError::GenerationRegression);
            }
            candidate.push(Slot {
                generation,
                entry: None,
                reservation: None,
            });
        }

        type InstalledNode = (
            Arc<dyn Resource>,
            Arc<Derivation>,
            Rights,
            ObjectId,
            ResourceKind,
        );
        let mut installed: BTreeMap<DerivationId, InstalledNode> = BTreeMap::new();
        let mut identities = system_allocation(|| Vec::with_capacity(grants.len()));
        for recovered in grants {
            let grant = &recovered.grant;
            if grant.target.space != space {
                return Err(PersistentInstallError::ForeignSpace);
            }
            if grant.target.slot >= MAX_PERSISTENT_SLOTS {
                return Err(PersistentInstallError::SlotOutOfRange);
            }
            let Some(recovered_slot) = history.get(&grant.target.slot) else {
                return Err(PersistentInstallError::LiveSlotMismatch);
            };
            if recovered_slot.max_generation != grant.target.generation
                || recovered_slot.live_derivation != Some(grant.derivation_id)
            {
                return Err(PersistentInstallError::LiveSlotMismatch);
            }
            if installed.contains_key(&grant.derivation_id) {
                return Err(PersistentInstallError::DuplicateDerivation);
            }
            let slot = candidate
                .get(grant.target.slot as usize)
                .ok_or(PersistentInstallError::SlotOutOfRange)?;
            if slot.entry.is_some() || slot.generation != grant.target.generation {
                return Err(PersistentInstallError::LiveSlotMismatch);
            }

            let rights = Rights::from_durable(grant.rights);
            let persistent = PersistentNodeIdentity {
                derivation_id: grant.derivation_id,
                object_id: grant.object_id,
                resource_kind: grant.resource_kind,
            };
            let (object, node) = if grant.flags.is_root() {
                if grant.parent_id.is_some() {
                    return Err(PersistentInstallError::RootShape);
                }
                let resource = resource_map
                    .get(&grant.object_id)
                    .ok_or(PersistentInstallError::MissingResource)?;
                if resource.resource_kind != grant.resource_kind {
                    return Err(PersistentInstallError::ResourceKindMismatch);
                }
                (
                    resource.object.clone(),
                    system_allocation(|| Derivation::persistent_root(persistent)),
                )
            } else {
                let parent_id = grant.parent_id.ok_or(PersistentInstallError::RootShape)?;
                let (parent_object, parent_node, parent_rights, parent_object_id, parent_kind) =
                    installed
                        .get(&parent_id)
                        .ok_or(PersistentInstallError::MissingParent)?;
                if !parent_rights.contains(Rights::GRANT) {
                    return Err(PersistentInstallError::ParentCannotGrant);
                }
                if !parent_rights.contains(rights) {
                    return Err(PersistentInstallError::RightsAmplification);
                }
                if *parent_object_id != grant.object_id || *parent_kind != grant.resource_kind {
                    return Err(PersistentInstallError::ObjectMismatch);
                }
                (
                    parent_object.clone(),
                    system_allocation(|| Derivation::persistent_child(parent_node, persistent)),
                )
            };

            candidate[grant.target.slot as usize].entry = Some(Entry {
                obj: object.clone(),
                rights,
                node: node.clone(),
            });
            installed.insert(
                grant.derivation_id,
                (object, node, rights, grant.object_id, grant.resource_kind),
            );
            identities.push(PersistentCapIdentity {
                space,
                slot: grant.target.slot,
                generation: grant.target.generation,
                derivation_id: grant.derivation_id,
                object_id: grant.object_id,
                resource_kind: grant.resource_kind,
                rights,
            });
        }

        if installed.len() != live_derivations.len()
            || live_derivations
                .iter()
                .any(|derivation_id| !installed.contains_key(derivation_id))
        {
            return Err(PersistentInstallError::MissingLiveGrant);
        }

        self.publish_slots(candidate);
        Ok(identities)
    }

    pub fn new(name: &str) -> Self {
        system_allocation(|| Self {
            name: String::from(name),
            slots: CapTable::empty(),
            incarnation: 1,
            persistent_space: None,
            persistent_quarantined: false,
            next_reservation: 1,
        })
    }

    /// Construct a capability space whose durable identity is fixed by an
    /// externally allocated `SpaceId`. Durable grants can only be installed in
    /// a space created through this constructor.
    pub fn new_persistent(name: &str, space: SpaceId) -> Self {
        system_allocation(|| Self {
            name: String::from(name),
            slots: CapTable::empty(),
            incarnation: 1,
            persistent_space: Some(space),
            persistent_quarantined: false,
            next_reservation: 1,
        })
    }

    pub const fn persistent_space_id(&self) -> Option<SpaceId> {
        self.persistent_space
    }

    /// Whether this durable space has been fail-closed after an in-memory
    /// publication fault. A quarantined instance can only be recovered by
    /// constructing a fresh CSpace from durable state after restart.
    pub const fn is_persistent_quarantined(&self) -> bool {
        self.persistent_quarantined
    }

    fn ensure_persistent_not_quarantined(&self) -> Result<(), PersistentInstallError> {
        if self.persistent_quarantined {
            return Err(PersistentInstallError::PersistentQuarantined);
        }
        Ok(())
    }

    /// Fail closed after durable commit succeeded but publishing the matching
    /// live state did not. Authority denial commits first: the CSpace becomes
    /// unavailable and every derivation is killed before the detached COW table
    /// clears reservation tokens. Thus an allocation/protection failure cannot
    /// leave live authority or make the current authoritative backing writable.
    /// Entries and generation numbers remain retained until reboot, so this path
    /// never invokes a resource destructor. A second call is idempotent.
    pub fn quarantine_persistent(&mut self) -> Result<usize, PersistentInstallError> {
        if self.persistent_space.is_none() {
            return Err(PersistentInstallError::NotPersistentSpace);
        }
        if self.persistent_quarantined {
            return Ok(0);
        }

        let mut quarantined = 0;
        for slot in self.slots.iter() {
            if let Some(entry) = &slot.entry {
                entry.node.kill();
                quarantined += 1;
            }
        }
        self.persistent_quarantined = true;

        let mut candidate = self.candidate_slots(0);
        for slot in &mut candidate {
            slot.reservation = None;
        }
        self.publish_slots(candidate);
        Ok(quarantined)
    }

    /// Monotonic identity of the live CSpace incarnation. Async services use
    /// this to avoid publishing a capability into a component which restarted
    /// while an external transaction was being committed.
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    fn invalidate(slot: &mut Slot) {
        slot.entry = None;
        slot.reservation = None;
        slot.generation = slot.generation.saturating_add(1);
    }

    /// Mint a fresh capability for a resource. This is the root of authority —
    /// only the code that creates a resource can do it.
    pub fn mint(&mut self, obj: Arc<dyn Resource>, rights: Rights) -> Cap {
        let node = system_allocation(Derivation::root);
        let mut candidate = self.candidate_slots(1);
        let slot = Self::alloc_candidate_slot(&mut candidate);
        candidate[slot as usize].entry = Some(Entry { obj, rights, node });
        let cap = Cap {
            slot,
            generation: candidate[slot as usize].generation,
        };
        self.publish_slots(candidate);
        cap
    }

    /// Mint only if the caller's pre-await incarnation is still current.
    pub fn mint_if_incarnation(
        &mut self,
        expected: u64,
        obj: Arc<dyn Resource>,
        rights: Rights,
    ) -> Option<Cap> {
        if self.incarnation != expected {
            return None;
        }
        Some(self.mint(obj, rights))
    }

    fn entry(&self, cap: Cap) -> Result<&Entry, CapError> {
        if self.persistent_quarantined {
            return Err(CapError::PersistentQuarantined);
        }
        let slot = self.slots.get(cap.slot as usize).ok_or(CapError::Invalid)?;
        if slot.generation != cap.generation {
            return Err(CapError::Invalid);
        }
        let entry = slot.entry.as_ref().ok_or(CapError::Invalid)?;
        // An ancestor revoked in another space kills this cap too; the slot
        // here simply has not been swept yet.
        if !entry.node.is_alive() {
            return Err(CapError::Invalid);
        }
        Ok(entry)
    }

    pub fn rights_of(&self, cap: Cap) -> Result<Rights, CapError> {
        Ok(self.entry(cap)?.rights)
    }

    /// Validate a handle and rights before disclosing either object type or
    /// resolved authority. All typed resolve APIs share this path so their
    /// observable error order remains Invalid -> rights -> type.
    fn checked_entry(&self, cap: Cap, need: Rights) -> Result<&Entry, CapError> {
        let entry = self.entry(cap)?;
        if !entry.rights.contains(need) {
            return Err(CapError::InsufficientRights);
        }
        Ok(entry)
    }

    fn typed_parts<T: Resource>(
        &self,
        cap: Cap,
        need: Rights,
    ) -> Result<(Arc<T>, Arc<Derivation>, Rights), CapError> {
        let entry = self.checked_entry(cap, need)?;
        // Upcast through the real trait-object metadata and let `Any` perform
        // the downcast. This must not trust `Resource::as_any`: safe external
        // code implements that method and could return a different object.
        let object: Arc<dyn Any + Send + Sync> = entry.obj.clone();
        let object = Arc::downcast::<T>(object).map_err(|_| CapError::WrongType)?;
        let node = entry.node.clone();
        Ok((object, node, entry.rights))
    }

    /// Legacy untyped TCB resolve into an owned `Arc` lease.
    ///
    /// The returned object remains usable after revocation. New code should
    /// prefer an operation-time service API or one of the explicit typed lease
    /// forms below so this lifetime choice is visible at the call site.
    pub fn lookup(&self, cap: Cap, need: Rights) -> Result<Arc<dyn Resource>, CapError> {
        Ok(self.checked_entry(cap, need)?.obj.clone())
    }

    /// Legacy TCB typed resolve: rights check plus a downcast to an owned
    /// resolved-object lease.
    ///
    /// The returned `Arc` intentionally remains usable after revocation. New
    /// code that needs operation-time revocation must use `lookup_revocable`;
    /// code with explicit invocation semantics should use `lookup_lease`.
    pub fn lookup_as<T: Resource>(&self, cap: Cap, need: Rights) -> Result<Arc<T>, CapError> {
        self.typed_parts(cap, need)
            .map(|(object, _node, _rights)| object)
    }

    /// Resolve a typed operation-time token. Every call through the returned
    /// token rechecks whether this capability or any ancestor was revoked.
    pub fn lookup_revocable<T: Resource>(
        &self,
        cap: Cap,
        need: Rights,
    ) -> Result<Revocable<T>, CapError> {
        let (object, node, _rights) = self.typed_parts(cap, need)?;
        Ok(Revocable { object, node })
    }

    /// Resolve a typed invocation lease.
    ///
    /// Revocation after this call does not interrupt the active lease, but it
    /// does make every subsequent lookup fail.
    pub fn lookup_lease<T: Resource>(
        &self,
        cap: Cap,
        need: Rights,
    ) -> Result<InvocationLease<T>, CapError> {
        let (object, _node, rights) = self.typed_parts(cap, need)?;
        Ok(InvocationLease { object, rights })
    }

    /// Attenuate: produce a new cap on the same object with a *subset* of the
    /// parent's rights. There is deliberately no way to widen rights.
    pub fn derive(&mut self, cap: Cap, rights: Rights) -> Result<Cap, CapError> {
        let e = self.entry(cap)?;
        if e.node.persistent.is_some() {
            return Err(CapError::PersistentLifecycleRequired);
        }
        if !e.rights.contains(Rights::GRANT) {
            return Err(CapError::InsufficientRights);
        }
        if !e.rights.contains(rights) {
            return Err(CapError::Amplification);
        }
        let obj = e.obj.clone();
        let parent = e.node.clone();
        let node = system_allocation(|| Derivation::child(&parent));
        let mut candidate = self.candidate_slots(1);
        let slot = Self::alloc_candidate_slot(&mut candidate);
        candidate[slot as usize].entry = Some(Entry { obj, rights, node });
        let derived = Cap {
            slot,
            generation: candidate[slot as usize].generation,
        };
        self.publish_slots(candidate);
        Ok(derived)
    }

    /// Destroy a cap and everything derived from it. Bumping the slot
    /// generation is what makes outstanding copies of the handle go stale.
    /// Destroy a cap and everything derived from it, in every space.
    pub fn revoke(&mut self, cap: Cap) -> Result<usize, CapError> {
        let e = self.entry(cap)?;
        if e.node.persistent.is_some() {
            return Err(CapError::PersistentLifecycleRequired);
        }
        if !e.rights.contains(Rights::REVOKE) {
            return Err(CapError::InsufficientRights);
        }
        e.node.kill();
        Ok(self.collect())
    }

    /// Administrative revoke, used by a holder of a cap on *this whole space*.
    /// Authority lives in the space cap, so no per-cap right is required here.
    pub fn revoke_slot(&mut self, slot: u32) -> usize {
        let Some(node) = self
            .slots
            .get(slot as usize)
            .and_then(|s| s.entry.as_ref())
            .map(|e| e.node.clone())
        else {
            return 0;
        };
        if node.persistent.is_some() {
            return 0;
        }
        node.kill();
        self.collect()
    }

    /// Revoke everything in this space. What an operator means by "revoke that
    /// component": not one handle, but all of its authority.
    pub fn revoke_all(&mut self) -> usize {
        if self.slots.iter().any(|slot| {
            slot.reservation.is_some()
                || slot
                    .entry
                    .as_ref()
                    .is_some_and(|entry| entry.node.persistent.is_some())
        }) {
            return 0;
        }
        for slot in self.slots.iter() {
            if let Some(e) = &slot.entry {
                e.node.kill();
            }
        }
        self.collect()
    }

    /// Retire every capability in preparation for a fresh component
    /// incarnation.
    ///
    /// Vacant slots are deliberately retained with their incremented
    /// generations. Replacing the table with `CSpace::new` would let an old
    /// `Cap { slot, generation }` alias the first grant in the new incarnation.
    pub fn reset(&mut self) -> usize {
        if self.slots.iter().any(|slot| {
            slot.reservation.is_some()
                || slot
                    .entry
                    .as_ref()
                    .is_some_and(|entry| entry.node.persistent.is_some())
        }) {
            return 0;
        }
        let killed = self.revoke_all();
        self.incarnation = self
            .incarnation
            .checked_add(1)
            .expect("CSpace incarnation space exhausted");
        killed
    }

    /// Finalize an already-durable tombstone. This is the only operation which
    /// may kill a persistent derivation; ordinary revoke/reset paths refuse to
    /// cross the durable lifecycle boundary.
    pub fn complete_persistent_revoke<T: Resource>(
        &mut self,
        authority: &PersistentDerivationWitness<T>,
        target: PersistentCapIdentity,
    ) -> Result<usize, CapError> {
        let authority_entry = self.exact_persistent_entry(authority.identity, Rights::REVOKE)?;
        if !Arc::ptr_eq(&authority_entry.node, &authority.node) {
            return Err(CapError::PersistentIdentityMismatch);
        }
        let object: Arc<dyn Any + Send + Sync> = authority_entry.obj.clone();
        let object = Arc::downcast::<T>(object).map_err(|_| CapError::WrongType)?;
        if !Arc::ptr_eq(&object, &authority.object) {
            return Err(CapError::PersistentIdentityMismatch);
        }
        let target_entry = self.exact_persistent_entry(target, Rights::NONE)?;
        if !Derivation::descends_from(&target_entry.node, &authority_entry.node) {
            return Err(CapError::PersistentIdentityMismatch);
        }
        let node = target_entry.node.clone();
        node.kill();
        Ok(self.collect())
    }

    /// Drop every slot whose derivation is dead; returns how many went.
    ///
    /// Killing a node takes effect immediately for lookups everywhere; this is
    /// the local bookkeeping that frees slots and updates `list`.
    pub fn collect(&mut self) -> usize {
        if !self.slots.iter().any(|slot| {
            slot.entry
                .as_ref()
                .is_some_and(|entry| !entry.node.is_alive())
        }) {
            return 0;
        }
        let mut candidate = self.candidate_slots(0);
        let mut killed = 0;
        for slot in &mut candidate {
            if slot.entry.as_ref().is_some_and(|e| !e.node.is_alive()) {
                Self::invalidate(slot);
                killed += 1;
            }
        }
        self.publish_slots(candidate);
        killed
    }

    pub fn list(&self) -> Vec<(Cap, &'static str, Rights, String)> {
        if self.persistent_quarantined {
            return Vec::new();
        }
        system_allocation(|| {
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(i, s)| {
                    let e = s.entry.as_ref().filter(|e| e.node.is_alive())?;
                    Some((
                        Cap {
                            slot: i as u32,
                            generation: s.generation,
                        },
                        e.obj.kind(),
                        e.rights,
                        e.obj.describe(),
                    ))
                })
                .collect()
        })
    }
}

/// Copy a capability from one space into another, attenuating on the way.
///
/// The source must hold `GRANT`, and `rights` must be a subset of what the
/// source already has — authority can only ever shrink as it travels.
pub fn grant(src: &CSpace, cap: Cap, rights: Rights, dst: &mut CSpace) -> Result<Cap, CapError> {
    let held = src.rights_of(cap)?;
    if !held.contains(Rights::GRANT) {
        return Err(CapError::InsufficientRights);
    }
    if !held.contains(rights) {
        return Err(CapError::Amplification);
    }
    // The copy is a *child* of the source in the derivation graph, so revoking
    // the source later reaches it even though it now lives in another space.
    let parent = src.entry(cap)?;
    if parent.node.persistent.is_some() {
        return Err(CapError::PersistentLifecycleRequired);
    }
    let node = system_allocation(|| Derivation::child(&parent.node));
    let obj = parent.obj.clone();

    let mut candidate = dst.candidate_slots(1);
    let slot = CSpace::alloc_candidate_slot(&mut candidate);
    candidate[slot as usize].entry = Some(Entry { obj, rights, node });
    let granted = Cap {
        slot,
        generation: candidate[slot as usize].generation,
    };
    dst.publish_slots(candidate);
    Ok(granted)
}
