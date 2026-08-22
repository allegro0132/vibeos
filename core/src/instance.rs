//! Stable lifecycle records for raw-reclaimable component instances.
//!
//! The executor deliberately owns runnable futures while this registry owns
//! every object which must survive abandoning one of those futures.  An
//! [`InstanceToken`] is consequently only a copyable, non-owning lookup key;
//! it can neither keep a capability space alive nor authorize reuse of a
//! recycled slot.  Slot generations, the executor's private status seal, the
//! allocation domain, scheduler incarnation, hart affinity, `InstanceSpace`
//! address, CSpace-lock address, CSpace identity, and CSpace incarnation all
//! have to agree before fault reclamation is attempted.

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::fmt;
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll};

#[cfg(feature = "wasm-c48-target-acceptance")]
use crate::cap::CapabilityTableRange;
use crate::cap::{CSpace, CSpaceIdentity, CSpaceResetError};
use crate::exec::{
    OneShotWaitFuture, OneShotWaitQueue, OneShotWake, PreparedReclaimableActivation,
    PreparedReclaimableBinding, ReclaimableFaultWitness, ReclaimableSchedulerIdentity,
    ReclaimableTaskWitness, TaskHandle, TaskId, TaskState,
};
use crate::heap::{self, AllocationDomain, OwnerId};
use crate::runqueue::HartId;
use crate::sync::{ConditionalRecovery, SpinLock, TaskRecoveryKey};

/// Maximum number of live or quarantined managed component instances.
///
/// The table is fixed so the scheduler's activation callback never allocates.
pub const MAX_INSTANCE_SLOTS: usize = 16;

/// Maximum number of component principals which can be reserved atomically.
///
/// This name describes the graph-facing admission limit while
/// [`MAX_INSTANCE_SLOTS`] remains the stable-table compatibility name. They
/// intentionally denote the same fixed SYSTEM-owned capacity.
pub const MAX_COMPONENT_INSTANCES: usize = MAX_INSTANCE_SLOTS;

static PAYLOAD_POLL_ALWAYS_ALLOWED: AtomicU8 = AtomicU8::new(1);

const PHASE_BITS: u32 = 4;
const PHASE_MASK: u64 = (1 << PHASE_BITS) - 1;
const MAX_INSTANCE_GENERATION: u64 = u64::MAX >> PHASE_BITS;

/// Non-owning key for one exact incarnation of one stable registry slot.
///
/// Both fields are private.  In particular, a caller cannot manufacture a
/// token for a reused slot by guessing its generation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceToken {
    slot: u8,
    generation: u64,
}

impl InstanceToken {
    /// Compare the stable registry/Space slot without revealing its index.
    /// Different generations of one slot must never be retained as two live
    /// lifecycle owners; callers may use this only as an alias-rejection
    /// predicate, never as authority for lookup, reclaim, or reset.
    pub fn shares_stable_slot(self, other: Self) -> bool {
        self.slot == other.slot
    }

    /// Produce a token for the same stable slot with a guaranteed-different
    /// generation. This is crate-private and exists only so the executor can
    /// construct the directed C4.8 rejection witness; acceptance code cannot
    /// select a slot or generation.
    #[cfg(feature = "wasm-c48-target-acceptance")]
    pub(crate) fn with_mismatched_generation_for_acceptance(mut self) -> Self {
        self.generation ^= 1;
        self
    }
}

impl fmt::Debug for InstanceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceToken(<opaque>)")
    }
}

/// One exact suspension of one managed instance generation.
///
/// This is deliberately an opaque, copy-only lookup key. It owns neither the
/// continuation state nor its SYSTEM wait registration, and its operation
/// generation prevents a late completion from aliasing a later suspension in
/// the same stable instance slot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstanceContinuationToken {
    instance: InstanceToken,
    generation: u64,
}

/// Number of fixed machine words in the external continuation signal bridge.
pub const INSTANCE_CONTINUATION_SIGNAL_WORDS: usize = 4;

const CONTINUATION_SIGNAL_TAG: usize = 0x5649_4245_4353_3533;

impl InstanceContinuationToken {
    /// Encode this non-owning token for a fixed-size SYSTEM wake callback.
    ///
    /// The words contain no pointer, CSpace, resource, or ownership. They are
    /// meaningful only to [`InstanceRegistry::signal_continuation_words`],
    /// which reconstructs the candidate and repeats the complete live seal
    /// validation before changing or waking anything.
    pub fn signal_words(self) -> [usize; INSTANCE_CONTINUATION_SIGNAL_WORDS] {
        assert!(
            usize::BITS >= 64,
            "managed continuation wake requires 64-bit words"
        );
        let slot = usize::from(self.instance.slot);
        let instance_generation = self.instance.generation as usize;
        let operation_generation = self.generation as usize;
        [
            slot,
            instance_generation,
            operation_generation,
            continuation_signal_tag(slot, instance_generation, operation_generation),
        ]
    }
}

const fn continuation_signal_tag(
    slot: usize,
    instance_generation: usize,
    operation_generation: usize,
) -> usize {
    CONTINUATION_SIGNAL_TAG
        ^ slot.rotate_left(7)
        ^ instance_generation.rotate_left(19)
        ^ operation_generation.rotate_left(37)
}

impl fmt::Debug for InstanceContinuationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceContinuationToken(<opaque>)")
    }
}

/// Exact proof that one continuation was consumed by its owning task.
///
/// The receipt is copy-only and carries no ownership. Its token remains
/// opaque, but callers which registered an external operation can recover or
/// compare the exact token before committing the corresponding backend
/// completion.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstanceContinuationConsumed {
    token: InstanceContinuationToken,
}

impl InstanceContinuationConsumed {
    /// Return the exact continuation token consumed at the success
    /// linearization point.
    pub const fn token(self) -> InstanceContinuationToken {
        self.token
    }

    /// Test whether this receipt consumed one exact continuation operation.
    pub fn matches_token(self, token: InstanceContinuationToken) -> bool {
        self.token == token
    }
}

impl fmt::Debug for InstanceContinuationConsumed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceContinuationConsumed(<opaque>)")
    }
}

/// Exact proof that the owning task cancelled one continuation during payload
/// destruction.
///
/// `InstanceContinuation::drop` performs the cancellation but cannot return a
/// value. SYSTEM cleanup may therefore request this copy-only receipt while
/// the exact payload-drop witness is still current. The receipt carries no
/// ownership and exposes only equality against the opaque operation token.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstanceContinuationCancelled {
    token: InstanceContinuationToken,
}

impl InstanceContinuationCancelled {
    /// Return the exact continuation operation cancelled by its owner.
    pub const fn token(self) -> InstanceContinuationToken {
        self.token
    }

    /// Test whether this receipt names one exact cancellation operation.
    pub fn matches_token(self, token: InstanceContinuationToken) -> bool {
        self.token == token
    }
}

impl fmt::Debug for InstanceContinuationCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceContinuationCancelled(<opaque>)")
    }
}

/// Exact fault-gate proof for the continuation projection of one instance.
///
/// A receipt always names the validated managed instance. Its continuation is
/// `None` only when that instance entered the fault gate with an idle
/// continuation record; otherwise it is the exact operation changed to
/// `Abandoned` by that invocation. Private fields and match-only accessors keep
/// both identities opaque to diagnostic formatting.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FaultContinuationAbandonReceipt {
    instance: InstanceToken,
    continuation: Option<InstanceContinuationToken>,
}

impl FaultContinuationAbandonReceipt {
    /// Test the exact managed instance validated by the fault gate.
    pub fn matches_instance(self, instance: InstanceToken) -> bool {
        self.instance == instance
    }

    /// Test the exact continuation abandoned by this gate. Pass `None` only
    /// when the caller expects the validated continuation record to be idle.
    pub fn matches_continuation(self, continuation: Option<InstanceContinuationToken>) -> bool {
        self.continuation == continuation
    }

    /// Test the complete instance/continuation projection atomically.
    pub fn matches_exact(
        self,
        instance: InstanceToken,
        continuation: Option<InstanceContinuationToken>,
    ) -> bool {
        self.matches_instance(instance) && self.matches_continuation(continuation)
    }
}

impl fmt::Debug for FaultContinuationAbandonReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FaultContinuationAbandonReceipt(<opaque>)")
    }
}

/// Scheduling contract selected before a continuation becomes visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceContinuationKind {
    /// Bounded interpreter/canonical work remains. The wait future publishes
    /// exactly one self-wake and yields one executor turn.
    Quantum,
    /// Progress requires an external SYSTEM operation. No self-wake occurs;
    /// the task remains parked until the exact token is signalled.
    External,
}

/// Result of publishing completion for an opaque continuation token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceContinuationSignal {
    Signalled,
    AlreadySignalled,
    /// The exact operation was already consumed by its owning task before
    /// this signal attempt. The copy-only receipt proves that precise winner;
    /// callers must not infer consumption from [`Self::Stale`].
    AlreadyConsumed(InstanceContinuationConsumed),
    /// The instance or operation generation is no longer current. No current
    /// slot, task, continuation, or wake queue was changed.
    Stale,
    /// The token named the current record but its full lifecycle seal did not
    /// match. The instance is sticky-quarantined and is not woken.
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceContinuationError {
    IdentityMismatch,
    Busy,
    GenerationExhausted,
    Cancelled,
    WrongPhase,
    Quarantined,
}

/// Stable SYSTEM object which contains the capability space for an instance.
///
/// The registry retains the allocation across successful slot reuse.  A new
/// generation therefore observes the same Space and lock objects but a newer
/// CSpace incarnation produced by the preceding exact reset.
pub struct InstanceSpace {
    cspace: SpinLock<CSpace>,
}

impl InstanceSpace {
    fn new(name: &str) -> Self {
        Self {
            cspace: SpinLock::new_recoverable(CSpace::new(name)),
        }
    }

    /// Borrow the recoverable lock without transferring ownership of it.
    pub const fn cspace(&self) -> &SpinLock<CSpace> {
        &self.cspace
    }
}

/// Arena-owned component state driven one bounded quantum at a time.
///
/// The registry, rather than the executor future, owns the boxed trait object.
/// Implementations must not retain `space`, a CSpace guard, or authority
/// derived from either argument after [`Self::poll_quantum`] returns.  A
/// quantum is synchronous: it must not await, block, migrate harts, or arrange
/// for `self` or `space` to escape through a waker.  It must return with the
/// same allocation domain installed.  Detached completion data is deliberately
/// restricted to `u64` so it cannot carry arena ownership.
///
/// # Safety
///
/// Implementors must obey the no-escape rules above during construction, every
/// poll, and Drop.  Any allocation, reference, `Arc` control block, trait
/// object, pointer, or ownership whose storage can be raw-reclaimed with the
/// instance arena must remain wholly inside the payload.  It must never be
/// written into a CSpace, SYSTEM/static object, another task, channel, waker or
/// external callback.  In particular, an arena-backed [`crate::cap::Resource`]
/// must never be installed into the stable instance CSpace.  External wake,
/// timer, join, probe, or wait registrations are permitted only through the
/// exact TaskStatus-owned executor paths which are synchronously drained before
/// raw fault reclaim; implementors may not create an independent registration
/// escape path.
///
/// The registry exclusively owns CSpace lifecycle.  A payload may use a
/// short-lived guarded borrow during its quantum, but must not call CSpace
/// reset APIs, advance its incarnation, enable or alter durable/persistent
/// lifecycle state, or replace stable authority ownership.  Those operations
/// remain reserved for the exact terminal registry path.
///
/// The destructor is run at most once inside the exact child poll, before
/// terminal publication.  It must obey the same arena no-escape rules and be
/// bounded and non-reentrant.  Drop must not change or leak allocator-domain or
/// arena state, re-enter instance lifecycle APIs, publish ownership, block, or
/// deliberately unwind.  An architecture fault may non-returningly interrupt
/// any Drop instruction; the exact fault gate then abandons the tombstoned
/// allocation and never retries the destructor.
pub unsafe trait InstancePayload: Send {
    fn poll_quantum(&mut self, space: &InstanceSpace, context: &mut Context<'_>) -> Poll<u64>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InstancePhase {
    Vacant = 0,
    Reserved = 1,
    Bound = 2,
    Active = 3,
    /// Raw reclamation was authorized and is currently in the caller hook.
    /// A hook which does not return leaves this slot fail-stopped here.
    FaultReclaiming = 4,
    FaultReclaimed = 5,
    /// Normal arena close was authorized and is currently in the caller hook.
    /// A hook which does not return leaves this slot fail-stopped here.
    NormalClosing = 6,
    NormalTerminal = 7,
    Quarantined = 8,
    /// The exact child poll has tombstoned the payload and is running its
    /// normal destructor behind that child's fault landing pad.
    PayloadDropping = 9,
    /// The payload destructor completed in the exact child domain.  The
    /// detached completion word is now stable until terminal finalization.
    PayloadDropped = 10,
    /// A fault-reclaimed arena is in its external owner-retirement hook.
    FaultRetiring = 11,
    /// Both raw arena reclaim and external owner retirement are complete.
    FaultTerminal = 12,
}

const INSTANCE_PHASE_COUNT: usize = InstancePhase::FaultTerminal as usize + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// Managed instances require a non-SYSTEM tracked allocation arena.
    InvalidDomain,
    /// A live or quarantined record already names this arena identity.  A
    /// different OwnerId cannot turn the same raw arena into a second domain.
    ArenaConflict,
    /// Every fixed slot is live, transitional, or permanently quarantined.
    Capacity,
}

/// Why an atomic component-principal reservation was rejected.
///
/// No variant carries a slot, generation, domain, CSpace identity, or name.
/// Every returned error leaves all registry records and headers unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchReserveError {
    /// At least one component principal is required.
    Empty,
    /// The request exceeds [`MAX_COMPONENT_INSTANCES`].
    TooMany,
    /// One input does not name a non-SYSTEM tracked allocation domain.
    InvalidDomain,
    /// Two inputs name the same raw arena, even if their owners differ.
    DuplicateArena,
    /// A retained registry generation already projects one requested arena.
    ArenaConflict,
    /// Too few stable slots are vacant.
    Capacity,
    /// Vacant slot or CSpace incarnation generations cannot cover the batch.
    GenerationExhausted,
    /// A stable record, header, or reusable CSpace failed structural checks.
    RegistryMismatch,
}

/// Why an exact unpublished reservation abort was rejected.
///
/// Rejection never resets a CSpace or changes any registry record. Identity is
/// deliberately classified without embedding the rejected token in the
/// diagnostic value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedBatchAbortError {
    Empty,
    TooMany,
    /// Two candidates address the same stable slot, including stale
    /// generations of that slot.
    DuplicateSlot,
    IdentityMismatch,
    /// At least one exact generation is no longer pristine and unpublished in
    /// `Reserved`.
    WrongPhase,
    GenerationExhausted,
    CSpaceResetRejected,
}

/// Allocation-free summary of one complete unpublished reservation abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedBatchAbortOutcome {
    aborted_instances: usize,
}

impl ReservedBatchAbortOutcome {
    pub const fn aborted_instances(self) -> usize {
        self.aborted_instances
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    IdentityMismatch,
    TerminalCompletionMismatch,
    WrongPhase,
    TaskNotTerminal,
    TerminalPublishFailed,
    NormalCloseFailed,
    TerminalRetireFailed,
    CSpaceResetRejected,
    Quarantined,
}

#[derive(Clone, Copy)]
enum CompletionExpectation {
    Any,
    Exact(Option<u64>),
}

impl CompletionExpectation {
    fn matches(self, observed: Option<u64>) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => observed == expected,
        }
    }
}

/// Classification returned to the kernel fault-reclaimer dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultGateOutcome {
    /// The witness does not name a managed registry instance.  A caller may
    /// continue with its legacy/non-component reclamation policy.
    NotManaged,
    /// The exact managed arena was reclaimed once and the stable record now
    /// carries the proof required by terminal finalization.
    ManagedReclaimed,
    /// A managed token was present but some proof failed.  Raw reclamation and
    /// CSpace reset were not authorized (or the supplied reclaim hook failed).
    Quarantined,
}

/// Allocator/owner action required before a terminal CSpace reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalRetireKind {
    /// Drop already completed in the child poll (or no payload was installed);
    /// the hook must close the empty arena and retire its owner registration.
    Normal,
    /// Raw arena reclaim already completed; the hook must retire the remaining
    /// owner registration without attempting a second arena traversal.
    FaultReclaimed,
}

/// Result of recording a cooperative payload cancellation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CooperativeCancelOutcome {
    /// The stable completion word is installed; wake this task after the
    /// registry call returns.
    Requested(TaskId),
    /// Normal completion already tombstoned or dropped the payload.  The
    /// caller lost the completion race and must not mutate or wake this slot.
    AlreadyCompleting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeOutcome {
    /// Number of live volatile capabilities revoked by the exact reset.
    pub revoked_capabilities: usize,
    /// Incarnation installed by the reset.  This is diagnostic evidence, not
    /// an authority token.
    pub next_cspace_incarnation: u64,
    /// Copy-only value detached from the instance arena by its last completed
    /// payload quantum, if one completed before terminal publication.
    pub detached_completion: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceSnapshot {
    pub phase: InstancePhase,
    pub domain: AllocationDomain,
    pub task: Option<TaskId>,
    pub home_hart: Option<HartId>,
}

/// Allocation-free occupancy telemetry for the stable instance table.
///
/// Counts contain no slot indexes, generations, addresses, task identities,
/// or allocation-domain identities. A quarantined slot remains occupied until
/// reboot and is therefore included in `occupied`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceRegistryStats {
    /// Number of non-vacant stable slots, including sticky quarantines.
    pub occupied: usize,
    /// Number of record/header pairs which disagree at the sample point.
    pub header_mismatches: usize,
    phase_counts: [usize; INSTANCE_PHASE_COUNT],
}

impl InstanceRegistryStats {
    /// Number of stable table slots in `phase` at the linearized sample.
    pub const fn phase_count(self, phase: InstancePhase) -> usize {
        self.phase_counts[phase as usize]
    }

    /// Fixed capacity of the registry sampled by this record.
    pub const fn capacity(self) -> usize {
        MAX_INSTANCE_SLOTS
    }
}

/// Directed seal corruptions admitted only by the C4.8 QEMU acceptance image.
///
/// Variants carry no caller-selected identity. The acceptance harness can
/// demonstrate fail-closed rejection, but cannot install a chosen Space or
/// CSpace seal.
#[cfg(feature = "wasm-c48-target-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceSealMismatch {
    /// Corrupt only the sealed [`InstanceSpace`] object identity.
    SpaceObject,
    /// Corrupt only the sealed CSpace lock-object identity while preserving
    /// the enclosing Space and the CSpace's logical identity/incarnation.
    CSpaceObject,
    /// Corrupt only the sealed CSpace incarnation.
    CSpaceIncarnation,
}

/// Allocation-free, read-only view of one stable acceptance slot.
///
/// Identity fields remain private and can only be compared through predicates,
/// preventing acceptance diagnostics from becoming lookup or reset authority.
/// This type and every constructor for it are absent from production builds.
#[cfg(feature = "wasm-c48-target-acceptance")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AcceptanceInstanceProbe {
    exact: bool,
    phase: InstancePhase,
    generation: u64,
    space_object_identity: Option<usize>,
    cspace_lock_identity: Option<usize>,
    cspace_identity: Option<CSpaceIdentity>,
    cspace_incarnation: Option<u64>,
    capability_table: Option<CapabilityTableRange>,
    installed_capabilities: usize,
    seal_matches_space: bool,
    seal_matches_cspace: bool,
}

#[cfg(feature = "wasm-c48-target-acceptance")]
impl fmt::Debug for AcceptanceInstanceProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptanceInstanceProbe")
            .field("exact", &self.exact)
            .field("phase", &self.phase)
            .field("generation", &self.generation)
            .field("space_object_identity", &"<opaque>")
            .field("cspace_lock_identity", &"<opaque>")
            .field("cspace_identity", &"<opaque>")
            .field("cspace_incarnation", &self.cspace_incarnation)
            .field("capability_table_identity", &"<opaque>")
            .field("capability_table_len", &self.capability_table_len())
            .field(
                "installed_capability_count",
                &self.installed_capability_count(),
            )
            .field("seal_matches_space", &self.seal_matches_space)
            .field("seal_matches_cspace", &self.seal_matches_cspace)
            .finish()
    }
}

#[cfg(feature = "wasm-c48-target-acceptance")]
impl AcceptanceInstanceProbe {
    /// Whether the requested token still names the slot's exact generation and
    /// the atomic header agrees with the locked record.
    pub const fn is_exact(self) -> bool {
        self.exact
    }

    /// Current record phase even when the requested token is stale.
    pub const fn current_phase(self) -> InstancePhase {
        self.phase
    }

    /// Current slot generation. This diagnostic scalar is not a token and
    /// cannot be converted into one by acceptance code.
    pub const fn current_generation(self) -> u64 {
        self.generation
    }

    /// Current phase only when the requested token is exact.
    pub const fn exact_phase(self) -> Option<InstancePhase> {
        if self.exact {
            Some(self.phase)
        } else {
            None
        }
    }

    pub fn same_space_object(self, other: Self) -> bool {
        self.space_object_identity == other.space_object_identity
    }

    pub fn same_cspace_lock(self, other: Self) -> bool {
        self.cspace_lock_identity == other.cspace_lock_identity
    }

    pub fn same_cspace_identity(self, other: Self) -> bool {
        self.cspace_identity == other.cspace_identity
    }

    pub fn same_cspace_incarnation(self, other: Self) -> bool {
        self.cspace_incarnation == other.cspace_incarnation
    }

    /// Monotonic CSpace incarnation, detached from reset authority.
    pub const fn cspace_incarnation(self) -> Option<u64> {
        self.cspace_incarnation
    }

    /// Compare the exact authoritative capability-table backing/range. Empty
    /// tables compare equal as `None` and can be distinguished by length zero.
    pub fn same_capability_table(self, other: Self) -> bool {
        self.capability_table == other.capability_table
    }

    /// Current immutable capability-table slot count without allocating a
    /// diagnostic `CSpace::list`.
    pub const fn capability_table_len(self) -> usize {
        match self.capability_table {
            Some(range) => range.slot_count,
            None => 0,
        }
    }

    /// Number of installed entries, independent of the vacant slots retained
    /// to preserve stale-handle generations across reset.
    pub const fn installed_capability_count(self) -> usize {
        self.installed_capabilities
    }

    /// Whether the stored seal still names the actual stable Space and lock.
    pub const fn seal_matches_space(self) -> bool {
        self.seal_matches_space
    }

    /// Whether the stored seal still names the actual CSpace identity and
    /// incarnation.
    pub const fn seal_matches_cspace(self) -> bool {
        self.seal_matches_cspace
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstanceSpaceSeal {
    object_identity: usize,
    lock_identity: usize,
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ContinuationPhase {
    Idle,
    Armed,
    Signalled,
    Consumed,
    Cancelled,
    /// The executor permanently detached the exact task and drained its
    /// TaskStatus-owned wait edge before raw arena reclamation.
    Abandoned,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContinuationSeal {
    instance: InstanceToken,
    operation_generation: u64,
    kind: InstanceContinuationKind,
    task: TaskId,
    domain: AllocationDomain,
    scheduler: ReclaimableSchedulerIdentity,
    home_hart: HartId,
    space: InstanceSpaceSeal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContinuationRecord {
    generation: u64,
    phase: ContinuationPhase,
    kind: Option<InstanceContinuationKind>,
    seal: Option<ContinuationSeal>,
}

impl ContinuationRecord {
    const fn idle() -> Self {
        Self {
            generation: 0,
            phase: ContinuationPhase::Idle,
            kind: None,
            seal: None,
        }
    }

    const fn terminal_phase_safe(self) -> bool {
        matches!(
            self.phase,
            ContinuationPhase::Idle | ContinuationPhase::Consumed | ContinuationPhase::Cancelled
        )
    }

    const fn fault_phase_safe(self) -> bool {
        matches!(
            self.phase,
            ContinuationPhase::Idle | ContinuationPhase::Abandoned
        )
    }

    fn retire(&mut self) {
        // Keep the monotonic operation generation across instance-slot reuse.
        // The enclosing instance generation is a second, independent ABA
        // barrier, not a reason to recycle the inner counter.
        self.phase = ContinuationPhase::Idle;
        self.kind = None;
        self.seal = None;
    }
}

impl InstanceSpaceSeal {
    fn capture(space: &InstanceSpace) -> Self {
        let cspace = space.cspace.lock();
        Self {
            object_identity: space as *const InstanceSpace as usize,
            lock_identity: space.cspace() as *const SpinLock<CSpace> as usize,
            cspace_identity: cspace.identity(),
            cspace_incarnation: cspace.incarnation(),
        }
    }

    fn immutable_objects_match(self, space: &InstanceSpace) -> bool {
        self.object_identity == space as *const InstanceSpace as usize
            && self.lock_identity == space.cspace() as *const SpinLock<CSpace> as usize
    }

    fn cspace_matches(self, cspace: &CSpace) -> bool {
        self.cspace_identity == cspace.identity() && self.cspace_incarnation == cspace.incarnation()
    }

    fn reset_preflight_matches(self, cspace: &CSpace) -> bool {
        self.cspace_matches(cspace)
            && cspace
                .preflight_reset_exact(self.cspace_identity, self.cspace_incarnation)
                .is_ok()
    }
}

struct SlotRecord {
    generation: u64,
    phase: InstancePhase,
    domain: Option<AllocationDomain>,
    space: Option<Box<InstanceSpace>>,
    space_seal: Option<InstanceSpaceSeal>,
    prepared: Option<PreparedReclaimableBinding>,
    task: Option<TaskHandle>,
    scheduler: Option<ReclaimableSchedulerIdentity>,
    home_hart: Option<HartId>,
    /// The trait object and its allocation both belong to `domain`.  Wrapping
    /// the box in ManuallyDrop makes quarantine and raw fault teardown a
    /// conservative leak rather than an accidental destructor call.
    payload: Option<ManuallyDrop<Box<dyn InstancePayload>>>,
    payload_installed: bool,
    payload_abandoned: bool,
    payload_completion: Option<u64>,
    payload_cancel: Option<u64>,
    continuation: ContinuationRecord,
}

impl SlotRecord {
    const fn vacant() -> Self {
        Self {
            generation: 0,
            phase: InstancePhase::Vacant,
            domain: None,
            space: None,
            space_seal: None,
            prepared: None,
            task: None,
            scheduler: None,
            home_hart: None,
            payload: None,
            payload_installed: false,
            payload_abandoned: false,
            payload_completion: None,
            payload_cancel: None,
            continuation: ContinuationRecord::idle(),
        }
    }

    fn retire_after_reset(&mut self) {
        // Retain `space`: its address and lock address remain stable across
        // generations, while reset_exact supplies the CSpace ABA barrier.
        self.generation += 1;
        self.phase = InstancePhase::Vacant;
        self.domain = None;
        self.space_seal = None;
        self.prepared = None;
        self.task = None;
        self.scheduler = None;
        self.home_hart = None;
        debug_assert!(self.payload.is_none());
        self.payload_installed = false;
        self.payload_abandoned = false;
        self.payload_completion = None;
        self.payload_cancel = None;
        self.continuation.retire();
    }
}

struct InstanceSlot {
    /// Allocation-free phase/generation publication and corruption witness.
    header: AtomicU64,
    /// Recoverable by construction, although component code is never allowed
    /// to retain this guard across an untrusted poll.
    record: SpinLock<SlotRecord>,
    /// Stable, fixed-single-waiter handoff for the one continuation admitted
    /// per instance. The wait object survives arena faults and slot reuse.
    continuation_wait: OneShotWaitQueue,
}

impl InstanceSlot {
    const fn new() -> Self {
        Self {
            header: AtomicU64::new(encode_header(0, InstancePhase::Vacant)),
            record: SpinLock::new_recoverable(SlotRecord::vacant()),
            continuation_wait: OneShotWaitQueue::new(),
        }
    }
}

const fn encode_header(generation: u64, phase: InstancePhase) -> u64 {
    (generation << PHASE_BITS) | phase as u64
}

/// Fixed, SYSTEM-owned managed-instance table.
///
/// `transaction` makes multi-slot activation one allocation-free critical
/// section.  Every mutating API takes it before a slot lock, establishing a
/// single registry lock order.  The executor activation path is therefore
/// `SCHED -> transaction -> slot`; registry code must never call the executor.
pub struct InstanceRegistry {
    transaction: SpinLock<()>,
    slots: [InstanceSlot; MAX_INSTANCE_SLOTS],
}

/// Awaiter for one registry-owned continuation operation.
///
/// The future retains only opaque copy tokens plus a non-owning listener into
/// the stable SYSTEM slot. It never owns a component, CSpace, resource table,
/// allocator guard, task handle, or backend object.
pub struct InstanceContinuation<'a> {
    registry: &'a InstanceRegistry,
    token: InstanceContinuationToken,
    listener: Option<OneShotWaitFuture<'a>>,
    kind: InstanceContinuationKind,
    self_wake_published: bool,
    terminal: bool,
}

impl InstanceRegistry {
    pub const fn new() -> Self {
        Self {
            transaction: SpinLock::new(()),
            slots: [const { InstanceSlot::new() }; MAX_INSTANCE_SLOTS],
        }
    }

    /// Sample exact phase occupancy without allocating or exposing stable-slot
    /// identity. The registry transaction makes the phase counts mutually
    /// consistent; a previously corrupted header is reported, not repaired.
    pub fn occupancy_stats(&self) -> InstanceRegistryStats {
        let _transaction = self.transaction.lock();
        let mut stats = InstanceRegistryStats {
            occupied: 0,
            header_mismatches: 0,
            phase_counts: [0; INSTANCE_PHASE_COUNT],
        };
        for slot in &self.slots {
            let record = slot.record.lock();
            stats.phase_counts[record.phase as usize] += 1;
            if record.phase != InstancePhase::Vacant {
                stats.occupied += 1;
            }
            if !Self::header_matches(slot, &record) {
                stats.header_mismatches += 1;
            }
        }
        stats
    }

    /// Reserve one stable slot for a non-SYSTEM tracked allocation domain.
    pub fn reserve(&self, domain: AllocationDomain) -> Result<InstanceToken, ReserveError> {
        self.reserve_named(domain, "wasm-component")
    }

    /// Named form of [`Self::reserve`].  Naming and first-use Space allocation
    /// occur in SYSTEM before any task is bound or runnable.
    pub fn reserve_named(
        &self,
        domain: AllocationDomain,
        cspace_name: &str,
    ) -> Result<InstanceToken, ReserveError> {
        if !domain.arena.is_tracked() || domain.owner == OwnerId::SYSTEM {
            return Err(ReserveError::InvalidDomain);
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();

        // Resolve arena aliases before choosing a vacant slot.  This mirrors
        // the executor's admission rule and prevents a wrong OwnerId from
        // creating a second registry identity for the same raw allocation
        // incarnation.
        for slot in &self.slots {
            let mut record = slot.record.lock();
            if !Self::header_matches(slot, &record) {
                Self::quarantine_locked(slot, &mut record);
            }
            let projections = Self::projected_domains(&record);
            if Self::domain_projections_disagree(projections)
                || (record.phase == InstancePhase::Vacant
                    && (projections.iter().any(Option::is_some)
                        || record.continuation.phase != ContinuationPhase::Idle
                        || record.continuation.kind.is_some()
                        || record.continuation.seal.is_some()
                        || slot.continuation_wait.waiter_count() != 0))
            {
                Self::quarantine_locked(slot, &mut record);
            }
            if projections
                .iter()
                .flatten()
                .any(|existing| existing.arena == domain.arena)
            {
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(ReserveError::ArenaConflict);
            }
        }

        for (index, slot) in self.slots.iter().enumerate() {
            let mut record = slot.record.lock();
            if !Self::header_matches(slot, &record) {
                Self::quarantine_locked(slot, &mut record);
                continue;
            }
            if record.phase != InstancePhase::Vacant {
                continue;
            }
            if record.continuation.phase != ContinuationPhase::Idle
                || record.continuation.kind.is_some()
                || record.continuation.seal.is_some()
                || slot.continuation_wait.waiter_count() != 0
            {
                Self::quarantine_locked(slot, &mut record);
                continue;
            }
            if record.generation == MAX_INSTANCE_GENERATION {
                Self::quarantine_locked(slot, &mut record);
                continue;
            }

            if record.space.is_none() {
                record.space = Some(Box::new(InstanceSpace::new(cspace_name)));
            }
            let seal = InstanceSpaceSeal::capture(
                record
                    .space
                    .as_deref()
                    .expect("reserved slot owns its stable Space"),
            );
            // Generation zero is the never-used boot representation.  Later
            // Vacant states already carry the next generation installed by
            // terminal retirement, which invalidated every old token before
            // the slot became observable as reusable.
            if record.generation == 0 {
                record.generation = 1;
            }
            record.phase = InstancePhase::Reserved;
            record.domain = Some(domain);
            record.space_seal = Some(seal);
            record.prepared = None;
            record.task = None;
            record.scheduler = None;
            record.home_hart = None;
            record.payload = None;
            record.payload_installed = false;
            record.payload_abandoned = false;
            record.payload_completion = None;
            record.payload_cancel = None;
            record.continuation.retire();
            Self::publish_header(slot, &record);
            let token = InstanceToken {
                slot: index as u8,
                generation: record.generation,
            };
            drop(record);
            drop(_transaction);
            system.restore();
            return Ok(token);
        }
        drop(_transaction);
        system.restore();
        Err(ReserveError::Capacity)
    }

    /// Reserve one stable, independently named CSpace for every component
    /// principal in a bounded batch.
    ///
    /// Inputs and returned tokens have the same order. Arena identity, rather
    /// than the caller-provided owner alone, must be distinct across the
    /// request and every retained registry projection. First-use Space
    /// allocation and every `Reserved` publication occur under the registry
    /// transaction in SYSTEM; a reused stable Space retains its original name,
    /// matching [`Self::reserve_named`].
    ///
    /// All validation, capacity, slot-generation, and CSpace-generation checks
    /// finish before the first record/header mutation. Consequently every
    /// returned error leaves the registry exactly as it was at entry.
    pub fn reserve_named_batch(
        &self,
        inputs: &[(AllocationDomain, &str)],
    ) -> Result<Vec<InstanceToken>, BatchReserveError> {
        self.reserve_named_batch_with_preflight(inputs, |_, cspace| {
            cspace.preflight_reset_exact(cspace.identity(), cspace.incarnation())
        })
    }

    fn reserve_named_batch_with_preflight(
        &self,
        inputs: &[(AllocationDomain, &str)],
        mut preflight_cspace: impl FnMut(usize, &CSpace) -> Result<(), CSpaceResetError>,
    ) -> Result<Vec<InstanceToken>, BatchReserveError> {
        if inputs.is_empty() {
            return Err(BatchReserveError::Empty);
        }
        if inputs.len() > MAX_COMPONENT_INSTANCES {
            return Err(BatchReserveError::TooMany);
        }
        for (index, (domain, _)) in inputs.iter().enumerate() {
            if !domain.arena.is_tracked() || domain.owner == OwnerId::SYSTEM {
                return Err(BatchReserveError::InvalidDomain);
            }
            if inputs[index + 1..]
                .iter()
                .any(|(other, _)| other.arena == domain.arena)
            {
                return Err(BatchReserveError::DuplicateArena);
            }
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let result = (|| {
            let _transaction = self.transaction.lock();
            let mut vacant = [usize::MAX; MAX_COMPONENT_INSTANCES];
            let mut vacant_count = 0usize;
            let mut viable_count = 0usize;

            for (index, slot) in self.slots.iter().enumerate() {
                let record = slot.record.lock();
                let projections = Self::projected_domains(&record);
                if !Self::header_matches(slot, &record)
                    || Self::domain_projections_disagree(projections)
                    || (record.phase == InstancePhase::Vacant
                        && !Self::vacant_record_is_pristine(slot, &record))
                    || (record.phase != InstancePhase::Vacant
                        && record.phase != InstancePhase::Quarantined
                        && projections.iter().all(Option::is_none))
                {
                    return Err(BatchReserveError::RegistryMismatch);
                }
                if projections.iter().flatten().any(|existing| {
                    inputs
                        .iter()
                        .any(|(requested, _)| requested.arena == existing.arena)
                }) {
                    return Err(BatchReserveError::ArenaConflict);
                }
                if record.phase != InstancePhase::Vacant {
                    continue;
                }
                vacant_count += 1;
                if record.generation == MAX_INSTANCE_GENERATION {
                    continue;
                }
                if let Some(space) = record.space.as_deref() {
                    let cspace = space.cspace().lock();
                    match preflight_cspace(index, &cspace) {
                        Ok(()) => {}
                        Err(CSpaceResetError::IncarnationExhausted) => continue,
                        Err(_) => return Err(BatchReserveError::RegistryMismatch),
                    }
                }
                vacant[viable_count] = index;
                viable_count += 1;
            }

            if vacant_count < inputs.len() {
                return Err(BatchReserveError::Capacity);
            }
            if viable_count < inputs.len() {
                return Err(BatchReserveError::GenerationExhausted);
            }

            // Allocate every missing stable Space and all return capacity
            // before the linearization loop. Target SYSTEM OOM is fail-stop;
            // no recoverable error can escape after the first publication.
            let mut allocated_spaces = Vec::with_capacity(inputs.len());
            let mut tokens = Vec::with_capacity(inputs.len());
            for ((_, name), index) in inputs.iter().zip(vacant.iter().copied().take(inputs.len())) {
                let record = self.slots[index].record.lock();
                allocated_spaces.push(
                    record
                        .space
                        .is_none()
                        .then(|| Box::new(InstanceSpace::new(name))),
                );
            }

            // Linearization point: the transaction excludes every mutating
            // observer until all selected records and headers are Reserved.
            for (((domain, _), index), allocated_space) in inputs
                .iter()
                .zip(vacant.iter().copied().take(inputs.len()))
                .zip(allocated_spaces.into_iter())
            {
                let slot = &self.slots[index];
                let mut record = slot.record.lock();
                assert!(Self::vacant_record_is_pristine(slot, &record));
                assert_ne!(record.generation, MAX_INSTANCE_GENERATION);
                if let Some(space) = allocated_space {
                    assert!(record.space.replace(space).is_none());
                }
                let seal = InstanceSpaceSeal::capture(
                    record
                        .space
                        .as_deref()
                        .expect("batch-reserved slot owns its stable Space"),
                );
                if record.generation == 0 {
                    record.generation = 1;
                }
                record.phase = InstancePhase::Reserved;
                record.domain = Some(*domain);
                record.space_seal = Some(seal);
                record.prepared = None;
                record.task = None;
                record.scheduler = None;
                record.home_hart = None;
                record.payload = None;
                record.payload_installed = false;
                record.payload_abandoned = false;
                record.payload_completion = None;
                record.payload_cancel = None;
                record.continuation.retire();
                Self::publish_header(slot, &record);
                tokens.push(InstanceToken {
                    slot: index as u8,
                    generation: record.generation,
                });
            }
            Ok(tokens)
        })();
        system.restore();
        result
    }

    /// Reset and vacate a complete set of exact, still-unpublished
    /// reservations.
    ///
    /// Volatile capabilities installed by [`Self::configure_reserved_space`]
    /// are revoked. No task, prepared binding, payload, scheduler identity,
    /// continuation, or waiter may have been attached. Every token and CSpace
    /// is checked before the first reset, so a returned error mutates nothing.
    pub fn abort_reserved_batch(
        &self,
        tokens: &[InstanceToken],
    ) -> Result<ReservedBatchAbortOutcome, ReservedBatchAbortError> {
        if tokens.is_empty() {
            return Err(ReservedBatchAbortError::Empty);
        }
        if tokens.len() > MAX_COMPONENT_INSTANCES {
            return Err(ReservedBatchAbortError::TooMany);
        }
        for (index, token) in tokens.iter().enumerate() {
            if tokens[index + 1..]
                .iter()
                .any(|other| token.shares_stable_slot(*other))
            {
                return Err(ReservedBatchAbortError::DuplicateSlot);
            }
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let result = (|| {
            let _transaction = self.transaction.lock();

            // Validate the whole candidate set without quarantining a stale or
            // otherwise ineligible generation.
            for token in tokens {
                let Some(slot) = self.slot(*token) else {
                    return Err(ReservedBatchAbortError::IdentityMismatch);
                };
                let record = slot.record.lock();
                if !Self::token_matches(slot, &record, *token) {
                    return Err(ReservedBatchAbortError::IdentityMismatch);
                }
                if !Self::reserved_record_is_unpublished(slot, &record) {
                    return Err(ReservedBatchAbortError::WrongPhase);
                }
                if record.generation == MAX_INSTANCE_GENERATION {
                    return Err(ReservedBatchAbortError::GenerationExhausted);
                }
                let (space, seal) = record
                    .space
                    .as_deref()
                    .zip(record.space_seal)
                    .expect("validated reserved shape retains its Space seal");
                if !seal.immutable_objects_match(space) {
                    return Err(ReservedBatchAbortError::IdentityMismatch);
                }
                let cspace = space.cspace().lock();
                match cspace.preflight_reset_exact(seal.cspace_identity, seal.cspace_incarnation) {
                    Ok(()) => {}
                    Err(CSpaceResetError::IncarnationExhausted) => {
                        return Err(ReservedBatchAbortError::GenerationExhausted);
                    }
                    Err(_) => {
                        return Err(ReservedBatchAbortError::CSpaceResetRejected);
                    }
                }
            }

            // No recoverable branch remains. The transaction prevents record
            // changes between preflight and these exact CSpace resets.
            for token in tokens {
                let slot = self
                    .slot(*token)
                    .expect("preflighted opaque token remains in range");
                let mut record = slot.record.lock();
                let seal = record
                    .space_seal
                    .expect("preflighted reservation retains its Space seal");
                record
                    .space
                    .as_deref()
                    .expect("preflighted reservation retains its Space")
                    .cspace()
                    .lock()
                    .reset_exact(seal.cspace_identity, seal.cspace_incarnation)
                    .unwrap_or_else(|error| {
                        panic!("preflighted unpublished CSpace reset changed: {error:?}")
                    });
                record.retire_after_reset();
                Self::publish_header(slot, &record);
            }
            Ok(ReservedBatchAbortOutcome {
                aborted_instances: tokens.len(),
            })
        })();
        system.restore();
        result
    }

    /// Configure the exact registry-owned CSpace before an instance is bound
    /// to, or published by, the executor.
    ///
    /// The registry keeps its transaction, slot, and CSpace guards across the
    /// callback.  A successful return is therefore linearized entirely in the
    /// `Reserved` phase.  The callback may mint only SYSTEM-owned resources
    /// and may return only detached copy metadata (for example attenuated
    /// [`crate::cap::Cap`] values and the observed CSpace incarnation).
    ///
    /// # Safety
    ///
    /// `configure` must not reset the CSpace, alter persistent lifecycle
    /// state, block, panic, re-enter instance lifecycle APIs, or retain/return
    /// a reference, guard, `Arc`, resource, or ownership obtained from the
    /// CSpace. Any resource installed into the CSpace must be independently
    /// SYSTEM-owned and safe to abandon if the enclosing instance is later
    /// quarantined. The returned `R` must contain only detached copy values.
    pub unsafe fn configure_reserved_space<R>(
        &self,
        token: InstanceToken,
        configure: impl FnOnce(&mut CSpace) -> R,
    ) -> Result<R, RegistryError> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        let exact_reserved = Self::token_matches(slot, &record, token)
            && record.phase == InstancePhase::Reserved
            && record.domain.is_some()
            && record.prepared.is_none()
            && record.task.is_none()
            && record.scheduler.is_none()
            && record.home_hart.is_none()
            && record.payload.is_none()
            && !record.payload_installed
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && record.payload_cancel.is_none()
            && record.continuation.phase == ContinuationPhase::Idle
            && record.continuation.kind.is_none()
            && record.continuation.seal.is_none()
            && slot.continuation_wait.waiter_count() == 0;
        let Some((space, seal)) = record.space.as_deref().zip(record.space_seal) else {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        if !exact_reserved || !seal.immutable_objects_match(space) {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        let mut cspace = space.cspace().lock();
        if !seal.reset_preflight_matches(&cspace) {
            drop(cspace);
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }

        let result = configure(&mut cspace);
        let post_matches = Self::token_matches(slot, &record, token)
            && record.phase == InstancePhase::Reserved
            && record.space_seal == Some(seal)
            && record
                .space
                .as_deref()
                .is_some_and(|current| seal.immutable_objects_match(current))
            && seal.reset_preflight_matches(&cspace);
        drop(cspace);
        if !post_matches {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(result)
    }

    /// Construct and install arena-owned component state in a reserved slot.
    ///
    /// Validation is deliberately split around construction.  The first pass
    /// resolves the exact reserved domain without allocating.  Construction
    /// then runs in that domain with no registry lock held.  A second pass
    /// proves that the same token, generation, domain, Space, and CSpace seal
    /// are still reserved before the registry accepts ownership.  If that
    /// proof fails, the newly allocated box is abandoned without running its
    /// destructor and the addressed generation is quarantined.
    ///
    /// # Safety
    ///
    /// `construct` and `P` must obey the complete tracked-arena no-escape
    /// contract documented by [`InstancePayload`], including its prohibition
    /// on publishing arena-backed ownership into the stable CSpace or any
    /// SYSTEM/static/external object.  Construction must not block, fault, or
    /// panic after publishing external ownership.  The caller must serialize
    /// lifecycle coordination so a successful installation precedes
    /// binding/publication.
    pub unsafe fn install_payload<P>(
        &self,
        token: InstanceToken,
        construct: impl FnOnce() -> P,
    ) -> Result<(), RegistryError>
    where
        P: InstancePayload + 'static,
    {
        let (domain, expected_seal) = {
            let mut system = heap::enter_owner(OwnerId::SYSTEM);
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            let exact_reserved =
                Self::token_matches(slot, &record, token)
                    && record.phase == InstancePhase::Reserved
                    && record.domain.is_some()
                    && record.prepared.is_none()
                    && record.task.is_none()
                    && record.scheduler.is_none()
                    && record.home_hart.is_none()
                    && record.payload.is_none()
                    && !record.payload_installed
                    && !record.payload_abandoned
                    && record.payload_completion.is_none()
                    && record.payload_cancel.is_none()
                    && record.continuation.phase == ContinuationPhase::Idle
                    && record.continuation.kind.is_none()
                    && record.continuation.seal.is_none()
                    && slot.continuation_wait.waiter_count() == 0
                    && record.space.as_deref().zip(record.space_seal).is_some_and(
                        |(space, seal)| {
                            if !seal.immutable_objects_match(space) {
                                return false;
                            }
                            let cspace = space.cspace().lock();
                            seal.reset_preflight_matches(&cspace)
                        },
                    );
            if !exact_reserved {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
            let result = (
                record
                    .domain
                    .expect("validated reserved payload slot has a domain"),
                record
                    .space_seal
                    .expect("validated reserved payload slot has a Space seal"),
            );
            drop(record);
            drop(_transaction);
            system.restore();
            result
        };

        // Safety: the first pass proved the exact tracked domain retained by
        // this registry generation; the caller supplies the arena no-escape
        // proof required by this unsafe installation boundary.
        let mut allocation = unsafe { heap::enter_domain(domain) };
        let payload = ManuallyDrop::new(Box::new(construct()) as Box<dyn InstancePayload>);
        allocation.restore();

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            // `token` was in range in pass one; retain this fail-stop arm for
            // completeness if the fixed table representation ever changes.
            core::mem::forget(payload);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        let exact_reserved = Self::token_matches(slot, &record, token)
            && record.phase == InstancePhase::Reserved
            && record.domain == Some(domain)
            && record.space_seal == Some(expected_seal)
            && record.prepared.is_none()
            && record.task.is_none()
            && record.scheduler.is_none()
            && record.home_hart.is_none()
            && record.payload.is_none()
            && !record.payload_installed
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && record.payload_cancel.is_none()
            && record.continuation.phase == ContinuationPhase::Idle
            && record.continuation.kind.is_none()
            && record.continuation.seal.is_none()
            && slot.continuation_wait.waiter_count() == 0
            && record.space.as_deref().is_some_and(|space| {
                if !expected_seal.immutable_objects_match(space) {
                    return false;
                }
                let cspace = space.cspace().lock();
                expected_seal.reset_preflight_matches(&cspace)
            });
        if !exact_reserved {
            Self::quarantine_locked(slot, &mut record);
            // The box belongs to the possibly corrupted/revoked arena.  Do
            // not execute P::drop or deallocate through a mismatched owner.
            core::mem::forget(payload);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        record.payload = Some(payload);
        record.payload_installed = true;
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(())
    }

    /// Bind the executor's pre-publication identity and retained status handle
    /// to an already reserved registry generation.
    pub fn bind(
        &self,
        token: InstanceToken,
        binding: PreparedReclaimableBinding,
        handle: &TaskHandle,
    ) -> Result<(), RegistryError> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::token_matches(slot, &record, token) {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        if record.phase == InstancePhase::Quarantined {
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::Quarantined);
        }

        let identity_matches = record.phase == InstancePhase::Reserved
            && record.domain == Some(binding.allocation_domain())
            && record.domain == Some(handle.allocation_domain())
            && binding.instance_token() == Some(token)
            && binding.scheduler_identity().is_none()
            && binding.matches_handle(handle)
            && !handle.is_published()
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && record.payload_cancel.is_none()
            && record.continuation.phase == ContinuationPhase::Idle
            && record.continuation.kind.is_none()
            && record.continuation.seal.is_none()
            && slot.continuation_wait.waiter_count() == 0
            && record
                .space
                .as_deref()
                .zip(record.space_seal)
                .is_some_and(|(space, seal)| seal.immutable_objects_match(space));
        if !identity_matches {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }

        record.prepared = Some(binding);
        record.task = Some(handle.clone());
        record.home_hart = Some(binding.home_hart());
        record.phase = InstancePhase::Bound;
        Self::publish_header(slot, &record);
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(())
    }

    /// Atomically bind an ordered batch of executor-prepared task identities
    /// to exact reserved component generations.
    ///
    /// The three slices are positional and must be nonempty, equal in length,
    /// bounded by [`MAX_COMPONENT_INSTANCES`], and address distinct stable
    /// slots. Every record, binding, and unpublished handle is validated under
    /// one registry transaction before any record becomes `Bound`. A rejected
    /// batch therefore never leaves a successfully validated prefix bound;
    /// exact candidates which can be identified from either token projection
    /// are quarantined together according to the registry's fail-closed
    /// convention.
    pub fn bind_batch(
        &self,
        tokens: &[InstanceToken],
        bindings: &[PreparedReclaimableBinding],
        handles: &[TaskHandle],
    ) -> Result<(), RegistryError> {
        // Reject caller-controlled oversize slices before taking the registry
        // transaction. Candidate quarantine is intentionally reserved for
        // structurally bounded batches, so every rejection path remains
        // bounded by the fixed instance table.
        if tokens.len() > MAX_COMPONENT_INSTANCES
            || bindings.len() > MAX_COMPONENT_INSTANCES
            || handles.len() > MAX_COMPONENT_INSTANCES
        {
            return Err(RegistryError::IdentityMismatch);
        }
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        if tokens.is_empty() || tokens.len() != bindings.len() || tokens.len() != handles.len() {
            self.quarantine_bind_batch_candidates_locked(tokens, bindings);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }

        // Validation pass: no task handle or Bound phase is retained until
        // the complete ordered batch has proved exact.
        for (index, ((token, binding), handle)) in tokens
            .iter()
            .copied()
            .zip(bindings.iter().copied())
            .zip(handles)
            .enumerate()
        {
            if tokens[..index]
                .iter()
                .any(|other| token.shares_stable_slot(*other))
            {
                self.quarantine_bind_batch_candidates_locked(tokens, bindings);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
            let Some(slot) = self.slot(token) else {
                self.quarantine_bind_batch_candidates_locked(tokens, bindings);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            };
            let record = slot.record.lock();
            let already_quarantined = Self::token_matches(slot, &record, token)
                && record.phase == InstancePhase::Quarantined;
            let valid = Self::token_matches(slot, &record, token)
                && record.phase == InstancePhase::Reserved
                && record.domain == Some(binding.allocation_domain())
                && record.domain == Some(handle.allocation_domain())
                && binding.instance_token() == Some(token)
                && binding.scheduler_identity().is_none()
                && binding.matches_handle(handle)
                && !handle.is_published()
                && record.prepared.is_none()
                && record.task.is_none()
                && record.scheduler.is_none()
                && record.home_hart.is_none()
                && !record.payload_abandoned
                && record.payload_completion.is_none()
                && record.payload_cancel.is_none()
                && record.continuation.phase == ContinuationPhase::Idle
                && record.continuation.kind.is_none()
                && record.continuation.seal.is_none()
                && slot.continuation_wait.waiter_count() == 0
                && record
                    .space
                    .as_deref()
                    .zip(record.space_seal)
                    .is_some_and(|(space, seal)| seal.immutable_objects_match(space));
            drop(record);
            if !valid {
                self.quarantine_bind_batch_candidates_locked(tokens, bindings);
                drop(_transaction);
                system.restore();
                return Err(if already_quarantined {
                    RegistryError::Quarantined
                } else {
                    RegistryError::IdentityMismatch
                });
            }
        }

        // Commit pass. `transaction` excludes every other registry mutation,
        // and TaskHandle cloning is allocation-free, so no recoverable branch
        // remains after the first phase transition.
        for ((token, binding), handle) in tokens
            .iter()
            .copied()
            .zip(bindings.iter().copied())
            .zip(handles)
        {
            let slot = self
                .slot(token)
                .expect("preflighted batch token remains in range");
            let mut record = slot.record.lock();
            record.prepared = Some(binding);
            record.task = Some(handle.clone());
            record.home_hart = Some(binding.home_hart());
            record.phase = InstancePhase::Bound;
            Self::publish_header(slot, &record);
        }
        drop(_transaction);
        system.restore();
        Ok(())
    }

    /// Atomically activate every binding supplied by the scheduler staging
    /// transaction.  This function allocates nothing and never acquires a
    /// CSpace lock, making it suitable for the executor's `SCHED -> registry`
    /// callback boundary.
    pub fn activate_batch(
        &self,
        bindings: &[PreparedReclaimableBinding],
    ) -> PreparedReclaimableActivation {
        let _transaction = self.transaction.lock();
        if bindings.is_empty() || bindings.len() > MAX_INSTANCE_SLOTS {
            self.quarantine_bindings_locked(bindings);
            return PreparedReclaimableActivation::Quarantined;
        }

        // Validation pass: no record changes phase until the entire batch has
        // proved unique and exact.
        for (index, binding) in bindings.iter().copied().enumerate() {
            let Some(token) = binding.instance_token() else {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            };
            if bindings[..index]
                .iter()
                .any(|other| other.instance_token() == Some(token))
            {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            }
            let Some(slot) = self.slot(token) else {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            };
            let record = slot.record.lock();
            let valid = Self::token_matches(slot, &record, token)
                && record.phase == InstancePhase::Bound
                && record.domain == Some(binding.allocation_domain())
                && record.home_hart == Some(binding.home_hart())
                && binding.scheduler_identity().is_some()
                && record
                    .prepared
                    .is_some_and(|prepared| binding.matches_prepared_identity(prepared))
                && record
                    .task
                    .as_ref()
                    .is_some_and(|handle| binding.matches_handle(handle) && !handle.is_published())
                && record.scheduler.is_none()
                && !record.payload_abandoned
                && record.payload_completion.is_none()
                && record.payload_cancel.is_none()
                && record.continuation.phase == ContinuationPhase::Idle
                && record.continuation.kind.is_none()
                && record.continuation.seal.is_none()
                && slot.continuation_wait.waiter_count() == 0
                && record
                    .space
                    .as_deref()
                    .zip(record.space_seal)
                    .is_some_and(|(space, seal)| seal.immutable_objects_match(space));
            drop(record);
            if !valid {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            }
        }

        // Commit pass.  `transaction` excludes every other registry writer,
        // so nothing can invalidate the completed proof between the passes.
        for binding in bindings.iter().copied() {
            let Some(token) = binding.instance_token() else {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            };
            let Some(slot) = self.slot(token) else {
                self.quarantine_bindings_locked(bindings);
                return PreparedReclaimableActivation::Quarantined;
            };
            let mut record = slot.record.lock();
            record.scheduler = binding.scheduler_identity();
            record.phase = InstancePhase::Active;
            Self::publish_header(slot, &record);
        }
        PreparedReclaimableActivation::Activated
    }

    /// Record a cooperative terminal word for an active payload.
    ///
    /// This method deliberately does not wake the executor while holding a
    /// registry lock.  For [`CooperativeCancelOutcome::Requested`], the caller
    /// must wake the returned TaskId after this method returns.  On the next
    /// exact child poll, [`Self::poll_payload`]
    /// tombstones and drops the payload behind that child's fault landing pad,
    /// then returns the supplied detached word as `Ready`.
    pub fn request_cooperative_cancel(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        detached_completion: u64,
    ) -> Result<CooperativeCancelOutcome, RegistryError> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        // Do not acquire the CSpace lock here.  A faulting task may have
        // abandoned its guard while another hart races cancellation; holding
        // transaction+slot while waiting for that guard would prevent the
        // fault reclaimer from entering the registry to recover it.  The next
        // exact child poll repeats the full sealed CSpace gate before reading
        // the stable cancellation word.
        if !Self::structural_identity_matches(slot, &record, token, handle) {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }

        let outcome = match record.phase {
            InstancePhase::Active
                if record.payload_installed
                    && record.payload.is_some()
                    && !record.payload_abandoned
                    && record.payload_completion.is_none() =>
            {
                match record.payload_cancel {
                    Some(existing) if existing != detached_completion => {
                        CooperativeCancelOutcome::AlreadyCompleting
                    }
                    Some(_) => CooperativeCancelOutcome::Requested(handle.id()),
                    None => {
                        record.payload_cancel = Some(detached_completion);
                        CooperativeCancelOutcome::Requested(handle.id())
                    }
                }
            }
            InstancePhase::PayloadDropping
                if record.payload_installed
                    && record.payload.is_none()
                    && !record.payload_abandoned
                    && record.payload_completion.is_none() =>
            {
                CooperativeCancelOutcome::AlreadyCompleting
            }
            InstancePhase::PayloadDropped
                if record.payload_installed
                    && record.payload.is_none()
                    && !record.payload_abandoned
                    && record.payload_completion.is_some()
                    && record.payload_cancel.is_none() =>
            {
                CooperativeCancelOutcome::AlreadyCompleting
            }
            InstancePhase::Quarantined => {
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::Quarantined);
            }
            InstancePhase::FaultReclaiming
            | InstancePhase::FaultReclaimed
            | InstancePhase::FaultRetiring
            | InstancePhase::FaultTerminal
                if record.payload.is_none() && record.payload_abandoned =>
            {
                CooperativeCancelOutcome::AlreadyCompleting
            }
            InstancePhase::NormalClosing | InstancePhase::NormalTerminal
                if record.payload.is_none()
                    && !record.payload_abandoned
                    && ((record.payload_installed
                        && record.payload_completion.is_some()
                        && record.payload_cancel.is_none())
                        || (!record.payload_installed
                            && record.payload_completion.is_none()
                            && record.payload_cancel.is_none())) =>
            {
                CooperativeCancelOutcome::AlreadyCompleting
            }
            InstancePhase::Active
            | InstancePhase::PayloadDropping
            | InstancePhase::PayloadDropped
            | InstancePhase::FaultReclaiming
            | InstancePhase::FaultReclaimed
            | InstancePhase::FaultRetiring
            | InstancePhase::FaultTerminal
            | InstancePhase::NormalClosing
            | InstancePhase::NormalTerminal => {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
            InstancePhase::Vacant | InstancePhase::Reserved | InstancePhase::Bound => {
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::WrongPhase);
            }
        };
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(outcome)
    }

    /// Poll one bounded payload quantum using a witness minted for this exact
    /// child-task poll.  Registry locks are released before both target code
    /// and its normal destructor run.
    ///
    /// A `Ready` result is not published until the payload has been
    /// tombstoned, dropped once in its exact arena, and the complete registry
    /// identity has passed a post-check.  Consequently a token-only executor
    /// future may return immediately after observing `Ready`; external
    /// finalization never needs to run component Drop code.
    ///
    /// # Safety
    ///
    /// `witness` must have been freshly minted by the executor in the current
    /// child poll.  The caller must remain inside that poll's fault guard for
    /// this entire synchronous call and must not finalize the task
    /// concurrently.  `context` belongs to that same poll.  The future may
    /// retain only its opaque token between calls.  The installed payload and
    /// all code it invokes must satisfy [`InstancePayload`]'s full arena
    /// no-escape and TaskStatus-registration contract.
    pub unsafe fn poll_payload(
        &self,
        witness: ReclaimableTaskWitness,
        context: &mut Context<'_>,
    ) -> Result<Poll<u64>, RegistryError> {
        unsafe { self.poll_payload_if(witness, context, &PAYLOAD_POLL_ALWAYS_ALLOWED, 1) }
    }

    /// Poll one payload quantum only while a boot-static monotonic permit has
    /// the exact expected value. The permit is sampled under the registry
    /// transaction before exposing the payload pointer and immediately before
    /// each irreversible payload take/Drop. A mismatch sticky-quarantines the
    /// record without polling, taking, dropping, or reclaiming its payload.
    ///
    /// # Safety
    ///
    /// This has all requirements of [`Self::poll_payload`]. `permit` must be
    /// boot-static SYSTEM state whose departure from `expected` is monotonic
    /// for this instance lifetime; it must never reside in a reclaimable arena.
    pub unsafe fn poll_payload_if(
        &self,
        witness: ReclaimableTaskWitness,
        context: &mut Context<'_>,
        permit: &'static AtomicU8,
        expected: u8,
    ) -> Result<Poll<u64>, RegistryError> {
        let Some(token) = witness.instance_token() else {
            return Err(RegistryError::IdentityMismatch);
        };
        if heap::current_domain() != witness.allocation_domain() {
            let _transaction = self.transaction.lock();
            if let Some(slot) = self.slot(token) {
                let mut record = slot.record.lock();
                Self::quarantine_locked(slot, &mut record);
            }
            return Err(RegistryError::Quarantined);
        }

        let (space_pointer, payload_pointer) = {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            if record.phase == InstancePhase::PayloadDropped
                && Self::active_witness_identity_matches(
                    slot,
                    &record,
                    token,
                    witness,
                    InstancePhase::PayloadDropped,
                )
                && record.payload_installed
                && record.payload.is_none()
                && !record.payload_abandoned
                && record.payload_cancel.is_none()
                && Self::continuation_terminal_safe(&record)
                && slot.continuation_wait.waiter_count() == 0
            {
                let Some(completion) = record.payload_completion else {
                    Self::quarantine_locked(slot, &mut record);
                    return Err(RegistryError::Quarantined);
                };
                if !Self::sealed_cspace_matches(&record) {
                    Self::quarantine_locked(slot, &mut record);
                    return Err(RegistryError::Quarantined);
                }
                return Ok(Poll::Ready(completion));
            }
            if !Self::active_witness_identity_matches(
                slot,
                &record,
                token,
                witness,
                InstancePhase::Active,
            ) {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            if !record.payload_installed {
                return Err(RegistryError::WrongPhase);
            }
            if record.payload_abandoned
                || record.payload_completion.is_some()
                || record.payload.is_none()
                || !Self::continuation_projection_matches(&record)
                || !Self::sealed_cspace_matches(&record)
            {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            if permit.load(Ordering::Acquire) != expected {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }

            let space_pointer = record
                .space
                .as_deref()
                .map(core::ptr::from_ref)
                .expect("exact active payload record has no Space");
            let payload_pointer = record
                .payload
                .as_mut()
                .map(|payload| {
                    let boxed: &mut Box<dyn InstancePayload> = &mut **payload;
                    boxed.as_mut() as *mut dyn InstancePayload
                })
                .expect("exact active payload record has no payload");

            if let Some(completion) = record.payload_cancel {
                if permit.load(Ordering::Acquire) != expected {
                    Self::quarantine_locked(slot, &mut record);
                    return Err(RegistryError::Quarantined);
                }
                let payload = record
                    .payload
                    .take()
                    .expect("cooperative payload cancel lost its payload");
                record.phase = InstancePhase::PayloadDropping;
                Self::publish_header(slot, &record);
                drop(record);
                drop(_transaction);
                return unsafe { self.drop_payload_and_publish(witness, payload, completion) };
            }
            (space_pointer, payload_pointer)
        };

        // Safety: the exact witness and stable record exclude lifecycle
        // mutation for this child poll.  Neither pointer may escape this
        // synchronous quantum under InstancePayload's unsafe contract.
        let polled = unsafe { (&mut *payload_pointer).poll_quantum(&*space_pointer, context) };

        if heap::current_domain() != witness.allocation_domain() {
            let _transaction = self.transaction.lock();
            let slot = self
                .slot(token)
                .expect("opaque poll token retained its fixed in-range slot");
            let mut record = slot.record.lock();
            // Target code changed allocator provenance.  Preserve the payload
            // allocation and refuse to enter either normal Drop or raw
            // reclamation from this poll-time boundary.
            Self::quarantine_locked(slot, &mut record);
            return Err(RegistryError::Quarantined);
        }

        let mut ready = match polled {
            Poll::Ready(completion) => Some(completion),
            Poll::Pending => None,
        };
        let payload = {
            let _transaction = self.transaction.lock();
            let slot = self
                .slot(token)
                .expect("opaque poll token retained its fixed in-range slot");
            let mut record = slot.record.lock();
            let same_payload = record.payload.as_ref().is_some_and(|payload| {
                let boxed: &Box<dyn InstancePayload> = &**payload;
                core::ptr::eq(boxed.as_ref(), unsafe { &*payload_pointer })
            });
            if !Self::active_witness_identity_matches(
                slot,
                &record,
                token,
                witness,
                InstancePhase::Active,
            ) || !record.payload_installed
                || record.payload_abandoned
                || record.payload_completion.is_some()
                || !same_payload
                || !Self::continuation_projection_matches(&record)
                || !Self::sealed_cspace_matches(&record)
            {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            if permit.load(Ordering::Acquire) != expected {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            if let Some(cancelled) = record.payload_cancel {
                ready = Some(cancelled);
            }
            let Some(completion) = ready else {
                return Ok(Poll::Pending);
            };
            let payload = record
                .payload
                .take()
                .expect("post-checked ready payload disappeared");
            record.phase = InstancePhase::PayloadDropping;
            Self::publish_header(slot, &record);
            (payload, completion)
        };
        unsafe { self.drop_payload_and_publish(witness, payload.0, payload.1) }
    }

    /// Complete the normal payload tombstone outside registry locks but still
    /// inside the exact child poll and its architecture fault guard.
    unsafe fn drop_payload_and_publish(
        &self,
        witness: ReclaimableTaskWitness,
        payload: ManuallyDrop<Box<dyn InstancePayload>>,
        completion: u64,
    ) -> Result<Poll<u64>, RegistryError> {
        let token = witness
            .instance_token()
            .expect("payload drop witness lost its instance token");
        assert_eq!(
            heap::current_domain(),
            witness.allocation_domain(),
            "managed payload Drop lost the exact child allocation domain"
        );
        // Safety: the same exact witness proved this tracked domain before the
        // payload was tombstoned.  Drop and deallocation therefore retain the
        // child's fault attribution and allocator provenance.
        let mut allocation = unsafe { heap::enter_domain(witness.allocation_domain()) };
        drop(ManuallyDrop::into_inner(payload));
        allocation.restore();
        assert_eq!(
            heap::current_domain(),
            witness.allocation_domain(),
            "managed payload Drop did not restore the exact child allocation domain"
        );

        let _transaction = self.transaction.lock();
        let slot = self
            .slot(token)
            .expect("opaque payload drop token retained its fixed slot");
        let mut record = slot.record.lock();
        let post_matches = Self::active_witness_identity_matches(
            slot,
            &record,
            token,
            witness,
            InstancePhase::PayloadDropping,
        ) && record.payload_installed
            && record.payload.is_none()
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && Self::continuation_terminal_safe(&record)
            && slot.continuation_wait.waiter_count() == 0
            && Self::sealed_cspace_matches(&record);
        assert!(
            post_matches,
            "managed payload identity changed after irreversible normal Drop"
        );
        record.payload_completion = Some(completion);
        record.payload_cancel = None;
        record.phase = InstancePhase::PayloadDropped;
        Self::publish_header(slot, &record);
        Ok(Poll::Ready(completion))
    }

    /// Validate and reclaim one permanently detached managed fault arena.
    ///
    /// # Safety
    ///
    /// `witness` must have been minted by the executor after its all-hart
    /// quiescence and permanent-detach boundary.  `reclaim` must reclaim only
    /// its argument domain, at most once, without allocating, blocking,
    /// panicking, resetting a CSpace, or calling the executor.  Returning
    /// `false` reports that no exact reclaim proof was obtained.
    ///
    /// The first exact caller linearizes by publishing `FaultReclaiming` while
    /// the registry transaction is held. That phase is an immutable in-flight
    /// lease until the caller returns from `reclaim`: a concurrent exact replay
    /// or any token/task/status/domain/Space/CSpace alias is rejected as
    /// [`FaultGateOutcome::Quarantined`] without invoking its callback or
    /// changing the leased record. The executor normally supplies only one
    /// caller, but this rule also makes copied stale witnesses fail closed. No
    /// registry lock is held across `reclaim`.
    pub unsafe fn fault_reclaim<F>(
        &self,
        witness: ReclaimableFaultWitness,
        reclaim: F,
    ) -> FaultGateOutcome
    where
        F: FnOnce(AllocationDomain) -> bool,
    {
        unsafe {
            self.fault_reclaim_with_space(witness, |domain, _space, _continuation| reclaim(domain))
        }
    }

    /// Validate one permanently detached managed fault arena and expose its
    /// already-recovered, exactly sealed Space to the reclaim callback.
    ///
    /// This is the resource-cleanup form of [`Self::fault_reclaim`]. The
    /// borrowed Space is exposed only after the complete token/task/domain/
    /// scheduler/Space/CSpace proof has linearized `FaultReclaiming`, and no
    /// registry lock is held while the callback runs. This lets a SYSTEM
    /// lifecycle coordinator cancel fixed backend operations which would
    /// otherwise survive raw arena reclamation. The callback must release all
    /// CSpace leases before returning and may not reset the CSpace. The
    /// copy-only continuation receipt identifies the exact instance and the
    /// operation abandoned by this invocation, or proves that its continuation
    /// was idle.
    ///
    /// # Safety
    ///
    /// This has every requirement of [`Self::fault_reclaim`]. In addition,
    /// `reclaim` must not retain any reference, pointer, lease, capability, or
    /// resource obtained from `space` after it returns.
    pub unsafe fn fault_reclaim_with_space<F>(
        &self,
        witness: ReclaimableFaultWitness,
        reclaim: F,
    ) -> FaultGateOutcome
    where
        F: FnOnce(AllocationDomain, &InstanceSpace, FaultContinuationAbandonReceipt) -> bool,
    {
        let Some(token) = witness.instance_token() else {
            // Absence is `NotManaged` only when no live registry record names
            // this exact globally-unique TaskId or exact allocation domain.
            // Otherwise a lost executor token must not fall through to a
            // legacy reclaimer and bypass the registry's generation checks.
            let _transaction = self.transaction.lock();
            if self.fault_reclaiming_alias_locked(witness) {
                return FaultGateOutcome::Quarantined;
            }
            return if self.quarantine_exact_fault_candidates_locked(witness) {
                FaultGateOutcome::Quarantined
            } else {
                FaultGateOutcome::NotManaged
            };
        };
        let mut system = heap::enter_owner(OwnerId::SYSTEM);

        let (domain, abandoned_payload, space_pointer, continuation_receipt) = {
            let _transaction = self.transaction.lock();
            if self.fault_reclaiming_alias_locked(witness) {
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            }
            let Some(slot) = self.slot(token) else {
                self.quarantine_exact_fault_candidates_locked(witness);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            };
            let mut record = slot.record.lock();
            if !Self::fault_identity_matches(slot, &record, token, witness) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                self.quarantine_exact_fault_candidates_locked(witness);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            }

            let domain = record
                .domain
                .expect("validated managed fault record has a domain");
            if self.quarantine_identity_conflicts_locked(
                token,
                domain.arena,
                witness.task_id(),
                Some(witness.scheduler_identity()),
            ) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            }

            let (Some(seal), Some(space), Some(domain), Some(recovery_key)) = (
                record.space_seal,
                record.space.as_deref(),
                record.domain,
                TaskRecoveryKey::new(witness.task_id().0),
            ) else {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            };
            // Safety: the executor witness establishes exact-task permanent
            // quiescence.  A matching predicate releases only this abandoned
            // CSpace guard; a value mismatch leaves it fail-stopped forever.
            let recovery = unsafe {
                space.cspace().recover_after_task_fault_if(
                    witness.allocation_domain(),
                    recovery_key,
                    |cspace| seal.reset_preflight_matches(cspace),
                )
            };
            let cspace_matches = match recovery {
                ConditionalRecovery::Recovered => {
                    let cspace = space.cspace().lock();
                    seal.reset_preflight_matches(&cspace)
                }
                ConditionalRecovery::NotHeldUnvalidated => {
                    // The immutable SYSTEM record and executor witness are the
                    // separate proof required by this recovery result.  The
                    // exact task is detached, so no component can race this
                    // validation lock.
                    let cspace = space.cspace().lock();
                    seal.reset_preflight_matches(&cspace)
                }
                ConditionalRecovery::ProvenanceMismatch | ConditionalRecovery::ValueMismatch => {
                    false
                }
            };
            if !cspace_matches {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            }
            let space_pointer = core::ptr::from_ref(space);

            // The executor drained every TaskStatus-owned wait edge before it
            // invoked this fault gate. A retained waiter means the arena still
            // has an outbound wake edge and therefore cannot be reclaimed.
            if slot.continuation_wait.waiter_count() != 0 {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return FaultGateOutcome::Quarantined;
            }
            let abandoned_continuation = match record.continuation.phase {
                ContinuationPhase::Idle if Self::continuation_projection_matches(&record) => None,
                ContinuationPhase::Armed
                | ContinuationPhase::Signalled
                | ContinuationPhase::Consumed
                | ContinuationPhase::Cancelled => {
                    let Some(continuation_seal) = record.continuation.seal else {
                        Self::quarantine_locked(slot, &mut record);
                        drop(record);
                        drop(_transaction);
                        system.restore();
                        return FaultGateOutcome::Quarantined;
                    };
                    if !Self::continuation_seal_projection_matches(&record, continuation_seal) {
                        Self::quarantine_locked(slot, &mut record);
                        drop(record);
                        drop(_transaction);
                        system.restore();
                        return FaultGateOutcome::Quarantined;
                    }
                    record.continuation.phase = ContinuationPhase::Abandoned;
                    Some(InstanceContinuationToken {
                        instance: continuation_seal.instance,
                        generation: continuation_seal.operation_generation,
                    })
                }
                ContinuationPhase::Idle
                | ContinuationPhase::Abandoned
                | ContinuationPhase::Quarantined => {
                    Self::quarantine_locked(slot, &mut record);
                    drop(record);
                    drop(_transaction);
                    system.restore();
                    return FaultGateOutcome::Quarantined;
                }
            };
            let continuation_receipt = FaultContinuationAbandonReceipt {
                instance: token,
                continuation: abandoned_continuation,
            };

            // This is the fault-path ownership linearization point.  The
            // pointer is removed from the stable record before any raw arena
            // operation, but remains ManuallyDrop so even a returning hook
            // cannot run target code or deallocate reclaimed memory.
            let abandoned_payload = record.payload.take();
            record.payload_abandoned = true;
            record.phase = InstancePhase::FaultReclaiming;
            Self::publish_header(slot, &record);
            (
                domain,
                abandoned_payload,
                space_pointer,
                continuation_receipt,
            )
        };

        core::mem::forget(abandoned_payload);

        // No registry lock is held across the target's allocator operation.
        // FaultReclaiming prevents a replay from authorizing a second reclaim.
        // Safety: `FaultReclaiming` is an immutable in-flight lease which
        // excludes finalization and CSpace reset until this callback returns.
        // The exact Space object remains owned by the stable registry record.
        let reclaimed = reclaim(domain, unsafe { &*space_pointer }, continuation_receipt);

        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            drop(_transaction);
            system.restore();
            return FaultGateOutcome::Quarantined;
        };
        let mut record = slot.record.lock();
        let post_matches = Self::fault_identity_matches_in_phase(
            slot,
            &record,
            token,
            witness,
            InstancePhase::FaultReclaiming,
        ) && record.domain == Some(domain)
            && record.payload.is_none()
            && record.payload_abandoned
            && Self::continuation_fault_safe(&record)
            && slot.continuation_wait.waiter_count() == 0
            && record
                .space
                .as_deref()
                .zip(record.space_seal)
                .is_some_and(|(space, seal)| {
                    if !seal.immutable_objects_match(space) {
                        return false;
                    }
                    let cspace = space.cspace().lock();
                    seal.reset_preflight_matches(&cspace)
                });
        if !reclaimed {
            Self::force_quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return FaultGateOutcome::Quarantined;
        }
        let post_unique = !self.quarantine_identity_conflicts_locked(
            token,
            domain.arena,
            witness.task_id(),
            Some(witness.scheduler_identity()),
        );
        assert!(
            post_matches && post_unique,
            "managed fault identity changed after irreversible arena reclaim"
        );
        record.phase = InstancePhase::FaultReclaimed;
        Self::publish_header(slot, &record);
        drop(record);
        drop(_transaction);
        system.restore();
        FaultGateOutcome::ManagedReclaimed
    }

    /// Finalize without publishing any additional registry-owned resource
    /// terminal state. Callers which installed capabilities into the stable
    /// instance CSpace must use [`Self::finalize_with_space`] instead.
    ///
    /// # Safety
    ///
    /// The complete contract is identical to [`Self::finalize_with_space`].
    pub unsafe fn finalize<F>(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        retire: F,
    ) -> Result<FinalizeOutcome, RegistryError>
    where
        F: FnOnce(AllocationDomain, TerminalRetireKind) -> bool,
    {
        unsafe { self.finalize_with_space(token, handle, |_, _| true, retire) }
    }

    /// Publish normal/fault terminal proof, finalize registry-owned resource
    /// state, retire the allocator/owner state, perform the one exact CSpace
    /// reset, and finally make the slot reusable with a newer generation.
    ///
    /// Installed payloads are never dropped here.  Normal `Exited` is accepted
    /// only after [`Self::poll_payload`] published `PayloadDropped`; an
    /// unexpected executor `Cancelled` while a payload remains live is
    /// quarantined.  Fault finalization requires the payload-abandon proof
    /// published before raw reclaim.
    ///
    /// # Safety
    ///
    /// `publish_terminal` runs only after the exact terminal TaskExit and the
    /// complete generation/TaskId/owner/arena/Space/CSpace proof have been
    /// validated and the record has entered a non-reentrant retiring phase.
    /// It must perform only bounded, allocation-free publication through the
    /// supplied registry-owned Space and return `true` only if that exact
    /// publication completed. It must not retain any authority or reset the
    /// CSpace. A `false` return quarantines the generation and conservatively
    /// leaks it without calling `retire` or resetting its CSpace.
    ///
    /// Publishing `NormalClosing` or `FaultRetiring` is the exact caller's
    /// linearization point. That phase is an immutable in-flight lease across
    /// both external callbacks: concurrent finalization, stale observation,
    /// and public quarantine are rejected without invoking their callbacks or
    /// changing the record. Only this caller may force the lease to
    /// `Quarantined` when its callback fails or its complete post-callback
    /// identity proof no longer matches. No registry lock is held across
    /// either callback.
    ///
    /// `retire` must act only on the supplied exact domain.  For `Normal`, it
    /// must close the proven-empty arena and unregister its owner.  For
    /// `FaultReclaimed`, it must only unregister the owner after the earlier
    /// raw arena reclaim.  It may return `true` only after that action is
    /// irreversible, and must not allocate, block, panic, reset a CSpace, run
    /// payload code, or call the executor.  `true` is not a forgeable
    /// safe-code receipt.
    pub unsafe fn finalize_with_space<P, F>(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        publish_terminal: P,
        retire: F,
    ) -> Result<FinalizeOutcome, RegistryError>
    where
        P: FnOnce(&InstanceSpace, TerminalRetireKind) -> bool,
        F: FnOnce(AllocationDomain, TerminalRetireKind) -> bool,
    {
        unsafe {
            self.finalize_with_space_inner(
                token,
                handle,
                CompletionExpectation::Any,
                publish_terminal,
                retire,
            )
        }
    }

    /// Finalize only if the registry's detached payload completion is exactly
    /// the caller's already-arbitrated terminal word.
    ///
    /// Unlike inspecting [`FinalizeOutcome::detached_completion`] after this
    /// operation, this gate runs before resource terminal publication, owner
    /// retirement, or CSpace reset. A mismatch sticky-quarantines the exact
    /// generation and invokes neither callback. `None` is the exact expected
    /// value for faulted or executor-cancelled tasks which must not carry a
    /// normal payload completion.
    ///
    /// # Safety
    ///
    /// The safety contract is identical to [`Self::finalize_with_space`]. The
    /// expected scalar must come from the caller's exact terminal arbitration,
    /// never from an untrusted payload or a stale token lookup.
    pub unsafe fn finalize_with_space_expect_completion<P, F>(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        expected_completion: Option<u64>,
        publish_terminal: P,
        retire: F,
    ) -> Result<FinalizeOutcome, RegistryError>
    where
        P: FnOnce(&InstanceSpace, TerminalRetireKind) -> bool,
        F: FnOnce(AllocationDomain, TerminalRetireKind) -> bool,
    {
        unsafe {
            self.finalize_with_space_inner(
                token,
                handle,
                CompletionExpectation::Exact(expected_completion),
                publish_terminal,
                retire,
            )
        }
    }

    unsafe fn finalize_with_space_inner<P, F>(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        completion: CompletionExpectation,
        publish_terminal: P,
        retire: F,
    ) -> Result<FinalizeOutcome, RegistryError>
    where
        P: FnOnce(&InstanceSpace, TerminalRetireKind) -> bool,
        F: FnOnce(AllocationDomain, TerminalRetireKind) -> bool,
    {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);

        // Distinguish an exact task which is merely still running from a
        // caller presenting an unrelated/non-owning handle.  The latter is an
        // identity violation and must isolate the named registry generation,
        // even though neither case may authorize close or reset.
        {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                self.quarantine_terminal_candidates_locked(handle);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            if !Self::structural_identity_matches(slot, &record, token, handle) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                self.quarantine_terminal_candidates_locked(handle);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
        }
        let Some(exit) = handle.try_exit() else {
            system.restore();
            return Err(RegistryError::TaskNotTerminal);
        };

        let (domain, retire_kind, retiring_phase, terminal_phase, space_pointer) = {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            if !Self::terminal_identity_matches(slot, &record, token, handle) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
            if !completion.matches(record.payload_completion) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::TerminalCompletionMismatch);
            }
            let domain = record
                .domain
                .expect("validated terminal record has a domain");
            if self.quarantine_identity_conflicts_locked(
                token,
                domain.arena,
                handle.id(),
                record.scheduler,
            ) {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::IdentityMismatch);
            }
            let transition = match exit.state() {
                TaskState::Faulted
                    if record.phase == InstancePhase::FaultReclaimed
                        && record.payload.is_none()
                        && record.payload_abandoned
                        && Self::continuation_fault_safe(&record)
                        && slot.continuation_wait.waiter_count() == 0 =>
                {
                    (
                        TerminalRetireKind::FaultReclaimed,
                        InstancePhase::FaultRetiring,
                        InstancePhase::FaultTerminal,
                    )
                }
                TaskState::Exited
                    if (record.payload_installed
                        && record.phase == InstancePhase::PayloadDropped
                        && record.payload.is_none()
                        && !record.payload_abandoned
                        && record.payload_completion.is_some()
                        && record.payload_cancel.is_none()
                        && Self::continuation_terminal_safe(&record)
                        && slot.continuation_wait.waiter_count() == 0)
                        || (!record.payload_installed
                            && record.phase == InstancePhase::Active
                            && record.payload.is_none()
                            && !record.payload_abandoned
                            && record.payload_completion.is_none()
                            && record.payload_cancel.is_none()
                            && Self::continuation_terminal_safe(&record)
                            && slot.continuation_wait.waiter_count() == 0) =>
                {
                    (
                        TerminalRetireKind::Normal,
                        InstancePhase::NormalClosing,
                        InstancePhase::NormalTerminal,
                    )
                }
                TaskState::Cancelled
                    if !record.payload_installed
                        && record.phase == InstancePhase::Active
                        && record.payload.is_none()
                        && !record.payload_abandoned
                        && record.payload_completion.is_none()
                        && record.payload_cancel.is_none()
                        && Self::continuation_terminal_safe(&record)
                        && slot.continuation_wait.waiter_count() == 0 =>
                {
                    (
                        TerminalRetireKind::Normal,
                        InstancePhase::NormalClosing,
                        InstancePhase::NormalTerminal,
                    )
                }
                TaskState::Running => unreachable!("TaskExit cannot contain Running"),
                _ => {
                    Self::quarantine_locked(slot, &mut record);
                    drop(record);
                    drop(_transaction);
                    system.restore();
                    return Err(RegistryError::WrongPhase);
                }
            };
            record.phase = transition.1;
            Self::publish_header(slot, &record);
            let space_pointer = record
                .space
                .as_deref()
                .expect("validated terminal record retains its Space")
                as *const InstanceSpace;
            (
                domain,
                transition.0,
                transition.1,
                transition.2,
                space_pointer,
            )
        };

        // The terminal TaskExit and non-reentrant retiring phase were already
        // published. No registry or CSpace lock is held while the bounded
        // supervisor finalizes exact resource terminal state.
        let terminal_published = publish_terminal(unsafe { &*space_pointer }, retire_kind);
        let _transaction = self.transaction.lock();
        let slot = self
            .slot(token)
            .expect("opaque token retained its fixed in-range slot");
        let mut record = slot.record.lock();
        let post_publish_unique = !self.quarantine_identity_conflicts_locked(
            token,
            domain.arena,
            handle.id(),
            record.scheduler,
        );
        let post_publish_matches = Self::terminal_identity_matches(slot, &record, token, handle)
            && record.phase == retiring_phase
            && record.domain == Some(domain)
            && completion.matches(record.payload_completion)
            && slot.continuation_wait.waiter_count() == 0
            && match retire_kind {
                TerminalRetireKind::Normal => Self::continuation_terminal_safe(&record),
                TerminalRetireKind::FaultReclaimed => Self::continuation_fault_safe(&record),
            }
            && post_publish_unique;
        if !terminal_published || !post_publish_matches {
            Self::force_quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(if terminal_published {
                RegistryError::IdentityMismatch
            } else {
                RegistryError::TerminalPublishFailed
            });
        }
        drop(record);
        drop(_transaction);

        // Resource terminal publication is now stable. No registry lock is
        // held while the allocator/owner performs its irreversible close or
        // unregister operation.
        let retired = retire(domain, retire_kind);
        let _transaction = self.transaction.lock();
        let slot = self
            .slot(token)
            .expect("opaque token retained its fixed in-range slot");
        let mut record = slot.record.lock();
        if !retired {
            Self::force_quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(match retire_kind {
                TerminalRetireKind::Normal => RegistryError::NormalCloseFailed,
                TerminalRetireKind::FaultReclaimed => RegistryError::TerminalRetireFailed,
            });
        }
        let post_unique = !self.quarantine_identity_conflicts_locked(
            token,
            domain.arena,
            handle.id(),
            record.scheduler,
        );
        if !Self::terminal_identity_matches(slot, &record, token, handle)
            || record.phase != retiring_phase
            || record.domain != Some(domain)
            || !completion.matches(record.payload_completion)
            || slot.continuation_wait.waiter_count() != 0
            || match retire_kind {
                TerminalRetireKind::Normal => !Self::continuation_terminal_safe(&record),
                TerminalRetireKind::FaultReclaimed => !Self::continuation_fault_safe(&record),
            }
            || !post_unique
        {
            panic!("managed instance identity changed after irreversible terminal retirement");
        }
        record.phase = terminal_phase;
        Self::publish_header(slot, &record);
        if record.generation == MAX_INSTANCE_GENERATION {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::CSpaceResetRejected);
        }

        let seal = record
            .space_seal
            .expect("validated terminal record retains its CSpace seal");
        let space = record
            .space
            .as_deref()
            .expect("validated terminal record retains its Space");
        if !seal.immutable_objects_match(space) {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        let reset = space
            .cspace()
            .lock()
            .reset_exact(seal.cspace_identity, seal.cspace_incarnation);
        let revoked = reset.unwrap_or_else(|error| {
            panic!("preflighted managed CSpace reset changed after arena retirement: {error:?}")
        });
        let next_cspace_incarnation = seal
            .cspace_incarnation
            .checked_add(1)
            .expect("reset_exact rejected CSpace incarnation exhaustion");
        let detached_completion = record.payload_completion;
        record.retire_after_reset();
        Self::publish_header(slot, &record);
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(FinalizeOutcome {
            revoked_capabilities: revoked,
            next_cspace_incarnation,
            detached_completion,
        })
    }

    /// Run a short operation against the stable Space of one active task.
    /// The registry locks are released before `operation` runs.
    ///
    /// # Safety
    ///
    /// The witness must have been reacquired in the current poll and name the
    /// exact executor task bound to its token.  The lifecycle coordinator must
    /// not finalize that task concurrently.  The operation must not retain the
    /// borrowed Space after it returns, nor return/store a CSpace guard,
    /// resource `Arc`, capability lease, pointer, reference, or other owned
    /// authority obtained through it.  `R` may contain only detached values.
    /// A future must retain just its opaque token and reacquire a witness for
    /// every operation rather than caching any registry-owned object in its
    /// state machine.
    pub unsafe fn with_active_space<R>(
        &self,
        witness: ReclaimableTaskWitness,
        operation: impl FnOnce(&InstanceSpace) -> R,
    ) -> Result<R, RegistryError> {
        let Some(token) = witness.instance_token() else {
            return Err(RegistryError::IdentityMismatch);
        };
        if heap::current_domain() != witness.allocation_domain() {
            let _transaction = self.transaction.lock();
            if let Some(slot) = self.slot(token) {
                let mut record = slot.record.lock();
                Self::quarantine_locked(slot, &mut record);
            }
            return Err(RegistryError::Quarantined);
        }
        let pointer = {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            if !Self::active_witness_identity_matches(
                slot,
                &record,
                token,
                witness,
                InstancePhase::Active,
            ) {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            let Some((space, seal)) = record.space.as_deref().zip(record.space_seal) else {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            };
            if !seal.immutable_objects_match(space) {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            let cspace_matches = {
                let cspace = space.cspace().lock();
                seal.cspace_matches(&cspace)
            };
            if !cspace_matches {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            space as *const InstanceSpace
        };
        // Safety: the caller promises exact-task liveness across this call;
        // lifecycle finalization is therefore excluded until operation ends.
        Ok(operation(unsafe { &*pointer }))
    }

    /// Reacquire the exact registry-owned Space while an instance payload is
    /// either running or executing its bounded terminal destructor.
    ///
    /// This narrow variant exists so a dispatcher Drop can detach one exact
    /// SYSTEM-owned wake registration. It does not relax any generation,
    /// task, owner/arena, scheduler, hart, Space-object, CSpace-object, or
    /// CSpace-incarnation check performed by [`Self::with_active_space`].
    ///
    /// # Safety
    ///
    /// The witness must have been reacquired by the exact current child poll.
    /// The caller must serialize finalization and obey the same no-escape
    /// contract as [`Self::with_active_space`]. `operation` may perform only
    /// bounded cleanup and must not publish new authority or reset the CSpace.
    pub unsafe fn with_current_space_for_cleanup<R>(
        &self,
        witness: ReclaimableTaskWitness,
        operation: impl FnOnce(&InstanceSpace) -> R,
    ) -> Result<R, RegistryError> {
        let Some(token) = witness.instance_token() else {
            return Err(RegistryError::IdentityMismatch);
        };
        if heap::current_domain() != witness.allocation_domain() {
            let _transaction = self.transaction.lock();
            if let Some(slot) = self.slot(token) {
                let mut record = slot.record.lock();
                Self::quarantine_locked(slot, &mut record);
            }
            return Err(RegistryError::Quarantined);
        }
        let pointer = {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            let phase = record.phase;
            if !matches!(
                phase,
                InstancePhase::Active | InstancePhase::PayloadDropping
            ) || !Self::active_witness_identity_matches(slot, &record, token, witness, phase)
            {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            let Some((space, seal)) = record.space.as_deref().zip(record.space_seal) else {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            };
            if !seal.immutable_objects_match(space) {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            let cspace_matches = {
                let cspace = space.cspace().lock();
                seal.cspace_matches(&cspace)
            };
            if !cspace_matches {
                Self::quarantine_locked(slot, &mut record);
                return Err(RegistryError::Quarantined);
            }
            space as *const InstanceSpace
        };
        // Safety: exact current-poll identity excludes concurrent retirement;
        // the caller promises that no borrowed authority escapes.
        Ok(operation(unsafe { &*pointer }))
    }

    /// Reserve the sole bounded continuation slot for the managed instance
    /// executing in this exact poll.
    ///
    /// All complete lifecycle identity and CSpace-incarnation checks happen
    /// before the operation token is published. A subsequent await stores its
    /// waker only in the stable one-shot queue and the executor's TaskStatus
    /// cleanup ledger; no arena ownership escapes this call.
    pub fn arm_continuation_current(
        &self,
        instance: InstanceToken,
        kind: InstanceContinuationKind,
    ) -> Result<InstanceContinuationToken, InstanceContinuationError> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        if witness.instance_token() != Some(instance)
            || heap::current_domain() != witness.allocation_domain()
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }

        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(instance) else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::active_witness_identity_matches(
            slot,
            &record,
            instance,
            witness,
            InstancePhase::Active,
        ) || !Self::sealed_cspace_matches(&record)
        {
            Self::quarantine_locked(slot, &mut record);
            return Err(InstanceContinuationError::Quarantined);
        }
        match record.continuation.phase {
            ContinuationPhase::Armed | ContinuationPhase::Signalled => {
                return Err(InstanceContinuationError::Busy);
            }
            ContinuationPhase::Abandoned | ContinuationPhase::Quarantined => {
                Self::quarantine_locked(slot, &mut record);
                return Err(InstanceContinuationError::Quarantined);
            }
            ContinuationPhase::Idle
            | ContinuationPhase::Consumed
            | ContinuationPhase::Cancelled
                if Self::continuation_terminal_safe(&record) => {}
            ContinuationPhase::Idle
            | ContinuationPhase::Consumed
            | ContinuationPhase::Cancelled => {
                Self::quarantine_locked(slot, &mut record);
                return Err(InstanceContinuationError::Quarantined);
            }
        }
        if slot.continuation_wait.waiter_count() != 0 {
            Self::quarantine_locked(slot, &mut record);
            return Err(InstanceContinuationError::Quarantined);
        }
        let Some(generation) = record.continuation.generation.checked_add(1) else {
            Self::quarantine_locked(slot, &mut record);
            return Err(InstanceContinuationError::GenerationExhausted);
        };
        let seal = ContinuationSeal {
            instance,
            operation_generation: generation,
            kind,
            task: witness.task_id(),
            domain: witness.allocation_domain(),
            scheduler: witness.scheduler_identity(),
            home_hart: witness.home_hart(),
            space: record
                .space_seal
                .expect("validated active instance lost its Space seal"),
        };
        record.continuation = ContinuationRecord {
            generation,
            phase: ContinuationPhase::Armed,
            kind: Some(kind),
            seal: Some(seal),
        };
        Ok(InstanceContinuationToken {
            instance,
            generation,
        })
    }

    /// Construct the non-owning wait future for an already armed operation.
    /// The listener is created before state is rechecked, closing completion's
    /// signal-before-register race.
    pub fn wait_continuation(
        &self,
        token: InstanceContinuationToken,
    ) -> Result<InstanceContinuation<'_>, InstanceContinuationError> {
        let Some(slot) = self.slot(token.instance) else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        let listener = slot.continuation_wait.wait(token.generation);
        let kind = {
            let _transaction = self.transaction.lock();
            let mut record = slot.record.lock();
            if !Self::token_matches(slot, &record, token.instance)
                || record.continuation.generation != token.generation
            {
                return Err(InstanceContinuationError::IdentityMismatch);
            }
            if record.phase == InstancePhase::Quarantined
                || record.continuation.phase == ContinuationPhase::Quarantined
            {
                return Err(InstanceContinuationError::Quarantined);
            }
            let Some(seal) = record.continuation.seal else {
                Self::quarantine_locked(slot, &mut record);
                return Err(InstanceContinuationError::Quarantined);
            };
            if !matches!(
                record.continuation.phase,
                ContinuationPhase::Armed | ContinuationPhase::Signalled
            ) || !Self::continuation_live_seal_matches(&record, seal)
            {
                Self::quarantine_locked(slot, &mut record);
                return Err(InstanceContinuationError::WrongPhase);
            }
            record
                .continuation
                .kind
                .ok_or(InstanceContinuationError::WrongPhase)?
        };
        Ok(InstanceContinuation {
            registry: self,
            token,
            listener: Some(listener),
            kind,
            self_wake_published: false,
            terminal: false,
        })
    }

    /// Convenience path for bounded interpreter/canonical progress. Every
    /// call creates a fresh generation and its future self-wakes exactly once.
    pub fn yield_continuation_current(
        &self,
        instance: InstanceToken,
    ) -> Result<InstanceContinuation<'_>, InstanceContinuationError> {
        let token = self.arm_continuation_current(instance, InstanceContinuationKind::Quantum)?;
        self.wait_continuation(token)
    }

    /// Publish an external operation's readiness. This never executes guest
    /// code; it only changes the exact SYSTEM record and wakes after all
    /// registry locks have been released. Guest resume remains behind
    /// the next fresh `poll_payload` witness check.
    pub fn signal_continuation(
        &self,
        token: InstanceContinuationToken,
    ) -> InstanceContinuationSignal {
        let Some(slot) = self.slot(token.instance) else {
            return InstanceContinuationSignal::Stale;
        };
        let (wake, fallback, outcome) = {
            let _transaction = self.transaction.lock();
            let mut record = slot.record.lock();
            if !Self::token_matches(slot, &record, token.instance)
                || record.continuation.generation != token.generation
            {
                return InstanceContinuationSignal::Stale;
            }
            if record.phase == InstancePhase::Quarantined
                || record.continuation.phase == ContinuationPhase::Quarantined
            {
                return InstanceContinuationSignal::Quarantined;
            }
            match record.continuation.phase {
                ContinuationPhase::Idle
                | ContinuationPhase::Cancelled
                | ContinuationPhase::Abandoned => {
                    return InstanceContinuationSignal::Stale;
                }
                ContinuationPhase::Armed
                | ContinuationPhase::Signalled
                | ContinuationPhase::Consumed => {}
                ContinuationPhase::Quarantined => {
                    return InstanceContinuationSignal::Quarantined;
                }
            }
            match record.phase {
                InstancePhase::Active => {}
                InstancePhase::PayloadDropping
                | InstancePhase::PayloadDropped
                | InstancePhase::FaultReclaiming
                | InstancePhase::FaultReclaimed
                | InstancePhase::FaultRetiring
                | InstancePhase::FaultTerminal
                | InstancePhase::NormalClosing
                | InstancePhase::NormalTerminal => {
                    return InstanceContinuationSignal::Stale;
                }
                InstancePhase::Vacant | InstancePhase::Reserved | InstancePhase::Bound => {
                    Self::quarantine_locked(slot, &mut record);
                    return InstanceContinuationSignal::Quarantined;
                }
                InstancePhase::Quarantined => {
                    return InstanceContinuationSignal::Quarantined;
                }
            }
            if record.continuation.phase == ContinuationPhase::Consumed
                && record
                    .task
                    .as_ref()
                    .is_some_and(|handle| handle.try_exit().is_some())
            {
                return InstanceContinuationSignal::Stale;
            }
            let Some(seal) = record.continuation.seal else {
                Self::quarantine_locked(slot, &mut record);
                return InstanceContinuationSignal::Quarantined;
            };
            if !Self::continuation_live_seal_matches(&record, seal) {
                Self::quarantine_locked(slot, &mut record);
                return InstanceContinuationSignal::Quarantined;
            }
            let fallback = record.task.as_ref().map(TaskHandle::exact_wake);
            match record.continuation.phase {
                ContinuationPhase::Armed => {
                    let wake = match slot.continuation_wait.publish(token.generation) {
                        Ok(wake) => wake,
                        Err(_) => {
                            Self::quarantine_locked(slot, &mut record);
                            return InstanceContinuationSignal::Quarantined;
                        }
                    };
                    record.continuation.phase = ContinuationPhase::Signalled;
                    (Some(wake), fallback, InstanceContinuationSignal::Signalled)
                }
                ContinuationPhase::Signalled => {
                    (None, fallback, InstanceContinuationSignal::AlreadySignalled)
                }
                ContinuationPhase::Consumed => (
                    None,
                    None,
                    InstanceContinuationSignal::AlreadyConsumed(InstanceContinuationConsumed {
                        token,
                    }),
                ),
                ContinuationPhase::Idle
                | ContinuationPhase::Cancelled
                | ContinuationPhase::Abandoned => unreachable!(
                    "terminal continuation phases returned before live signal validation"
                ),
                ContinuationPhase::Quarantined => {
                    return InstanceContinuationSignal::Quarantined;
                }
            }
        };
        if !wake.is_some_and(OneShotWake::dispatch) {
            if let Some(fallback) = fallback {
                let _ = fallback.wake_if_exact();
            }
        }
        outcome
    }

    /// Decode and publish one fixed-size external continuation signal.
    ///
    /// Invalid, truncated, corrupted, stale, or ABA-replayed words are inert.
    /// A well-formed candidate still carries no authority: the ordinary
    /// [`Self::signal_continuation`] path validates the current instance token,
    /// operation generation, Task/status projection, owner/arena, scheduler,
    /// hart, stable Space object, and CSpace seal before waking.
    pub fn signal_continuation_words(
        &self,
        words: [usize; INSTANCE_CONTINUATION_SIGNAL_WORDS],
    ) -> InstanceContinuationSignal {
        if usize::BITS < 64 {
            return InstanceContinuationSignal::Stale;
        }
        let [slot, instance_generation, operation_generation, tag] = words;
        if slot >= MAX_INSTANCE_SLOTS
            || instance_generation == 0
            || instance_generation > MAX_INSTANCE_GENERATION as usize
            || operation_generation == 0
            || tag != continuation_signal_tag(slot, instance_generation, operation_generation)
        {
            return InstanceContinuationSignal::Stale;
        }
        self.signal_continuation(InstanceContinuationToken {
            instance: InstanceToken {
                slot: slot as u8,
                generation: instance_generation as u64,
            },
            generation: operation_generation as u64,
        })
    }

    fn poll_continuation_current(
        &self,
        token: InstanceContinuationToken,
    ) -> Result<Poll<InstanceContinuationConsumed>, InstanceContinuationError> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        if witness.instance_token() != Some(token.instance)
            || heap::current_domain() != witness.allocation_domain()
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token.instance) else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::token_matches(slot, &record, token.instance)
            || record.continuation.generation != token.generation
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }
        if !Self::active_witness_identity_matches(
            slot,
            &record,
            token.instance,
            witness,
            InstancePhase::Active,
        ) || !record
            .continuation
            .seal
            .is_some_and(|seal| Self::continuation_live_seal_matches(&record, seal))
            || !Self::sealed_cspace_matches(&record)
        {
            Self::quarantine_locked(slot, &mut record);
            return Err(InstanceContinuationError::Quarantined);
        }
        match record.continuation.phase {
            ContinuationPhase::Armed => Ok(Poll::Pending),
            ContinuationPhase::Signalled => {
                record.continuation.phase = ContinuationPhase::Consumed;
                Ok(Poll::Ready(InstanceContinuationConsumed { token }))
            }
            ContinuationPhase::Cancelled => Err(InstanceContinuationError::Cancelled),
            ContinuationPhase::Quarantined | ContinuationPhase::Abandoned => {
                Err(InstanceContinuationError::Quarantined)
            }
            ContinuationPhase::Idle | ContinuationPhase::Consumed => {
                Self::quarantine_locked(slot, &mut record);
                Err(InstanceContinuationError::WrongPhase)
            }
        }
    }

    fn cancel_continuation_current(
        &self,
        token: InstanceContinuationToken,
    ) -> Result<(), InstanceContinuationError> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        if witness.instance_token() != Some(token.instance)
            || heap::current_domain() != witness.allocation_domain()
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }
        let Some(slot) = self.slot(token.instance) else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        let (wake, fallback) =
            {
                let _transaction = self.transaction.lock();
                let mut record = slot.record.lock();
                if !Self::token_matches(slot, &record, token.instance)
                    || record.continuation.generation != token.generation
                {
                    return Err(InstanceContinuationError::IdentityMismatch);
                }
                let phase = record.phase;
                if !matches!(
                    phase,
                    InstancePhase::Active | InstancePhase::PayloadDropping
                ) || !Self::active_witness_identity_matches(
                    slot,
                    &record,
                    token.instance,
                    witness,
                    phase,
                ) || !record.continuation.seal.is_some_and(|seal| {
                    Self::continuation_current_seal_matches(&record, seal, phase)
                }) || !Self::sealed_cspace_matches(&record)
                {
                    Self::quarantine_locked(slot, &mut record);
                    return Err(InstanceContinuationError::Quarantined);
                }
                let fallback = record.task.as_ref().map(TaskHandle::exact_wake);
                match record.continuation.phase {
                    ContinuationPhase::Armed | ContinuationPhase::Signalled => {
                        let wake = match slot.continuation_wait.publish(token.generation) {
                            Ok(wake) => wake,
                            Err(_) => {
                                Self::quarantine_locked(slot, &mut record);
                                return Err(InstanceContinuationError::Quarantined);
                            }
                        };
                        record.continuation.phase = ContinuationPhase::Cancelled;
                        (Some(wake), fallback)
                    }
                    ContinuationPhase::Cancelled => (None, fallback),
                    ContinuationPhase::Consumed => return Ok(()),
                    ContinuationPhase::Idle => return Err(InstanceContinuationError::WrongPhase),
                    ContinuationPhase::Abandoned | ContinuationPhase::Quarantined => {
                        return Err(InstanceContinuationError::Quarantined);
                    }
                }
            };
        if !wake.is_some_and(OneShotWake::dispatch) {
            if let Some(fallback) = fallback {
                let _ = fallback.wake_if_exact();
            }
        }
        Ok(())
    }

    /// Confirm that `InstanceContinuation::drop` cancelled one exact external
    /// operation while the owning payload-drop witness is still current.
    ///
    /// The cancellation itself remains owned by the future destructor. This
    /// method is a read-only typed receipt boundary for a SYSTEM lifecycle
    /// ledger; it cannot cancel, signal, or otherwise advance a continuation.
    pub fn confirm_cancelled_continuation_current(
        &self,
        token: InstanceContinuationToken,
    ) -> Result<InstanceContinuationCancelled, InstanceContinuationError> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        if witness.instance_token() != Some(token.instance)
            || heap::current_domain() != witness.allocation_domain()
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token.instance) else {
            return Err(InstanceContinuationError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::token_matches(slot, &record, token.instance)
            || record.continuation.generation != token.generation
        {
            return Err(InstanceContinuationError::IdentityMismatch);
        }
        let phase = record.phase;
        if !matches!(
            phase,
            InstancePhase::Active | InstancePhase::PayloadDropping
        ) || !Self::active_witness_identity_matches(
            slot,
            &record,
            token.instance,
            witness,
            phase,
        ) || !record
            .continuation
            .seal
            .is_some_and(|seal| Self::continuation_current_seal_matches(&record, seal, phase))
            || !Self::sealed_cspace_matches(&record)
        {
            Self::quarantine_locked(slot, &mut record);
            return Err(InstanceContinuationError::Quarantined);
        }
        if record.continuation.phase != ContinuationPhase::Cancelled {
            return Err(InstanceContinuationError::WrongPhase);
        }
        Ok(InstanceContinuationCancelled { token })
    }

    /// Sticky-quarantine one generation after a publication or lifecycle
    /// mismatch.  The retained Space and status handle are conservatively
    /// leaked by a production-static registry.
    pub fn quarantine(&self, token: InstanceToken) -> bool {
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            return false;
        };
        let mut record = slot.record.lock();
        Self::quarantine_locked(slot, &mut record);
        record.phase == InstancePhase::Quarantined
    }

    pub fn snapshot(&self, token: InstanceToken) -> Result<InstanceSnapshot, RegistryError> {
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::token_matches(slot, &record, token) {
            Self::quarantine_locked(slot, &mut record);
            return Err(RegistryError::IdentityMismatch);
        }
        if record.phase == InstancePhase::Quarantined {
            return Err(RegistryError::Quarantined);
        }
        Ok(InstanceSnapshot {
            phase: record.phase,
            domain: record
                .domain
                .expect("every non-quarantined token phase retains its domain"),
            task: record.task.as_ref().map(TaskHandle::id),
            home_hart: record.home_hart,
        })
    }

    /// Observe the actual stable objects and current phase behind an opaque
    /// token without allocating or changing lifecycle state.
    ///
    /// Unlike [`Self::snapshot`], this acceptance-only probe also returns the
    /// current slot phase for a stale generation, allowing the ABA test to
    /// prove that an old token did not alias a reused slot. Object identities
    /// stay private in [`AcceptanceInstanceProbe`] and can only be compared.
    ///
    /// # Safety model
    ///
    /// The caller must invoke this only at an acceptance harness quiescence
    /// point. The probe acquires the CSpace lock and therefore must not run
    /// while the faulting task may have abandoned that lock; fault recovery
    /// must complete first. The returned copy carries no lookup/reset authority
    /// and may be retained only as diagnostic evidence.
    #[cfg(feature = "wasm-c48-target-acceptance")]
    pub fn acceptance_probe(&self, token: InstanceToken) -> Option<AcceptanceInstanceProbe> {
        let _transaction = self.transaction.lock();
        let slot = self.slot(token)?;
        let record = slot.record.lock();
        let exact = Self::token_matches(slot, &record, token);
        let (space_object_identity, cspace_lock_identity, cspace) = match record.space.as_deref() {
            Some(space) => {
                let cspace = space.cspace().lock();
                (
                    Some(space as *const InstanceSpace as usize),
                    Some(space.cspace() as *const SpinLock<CSpace> as usize),
                    Some((
                        cspace.identity(),
                        cspace.incarnation(),
                        cspace.capability_table_range(),
                        cspace.acceptance_installed_capability_count(),
                    )),
                )
            }
            None => (None, None, None),
        };
        let cspace_identity = cspace.map(|value| value.0);
        let cspace_incarnation = cspace.map(|value| value.1);
        let capability_table = cspace.and_then(|value| value.2);
        let installed_capabilities = cspace.map_or(0, |value| value.3);
        let seal_matches_space = record.space_seal.is_some_and(|seal| {
            seal.object_identity == space_object_identity.unwrap_or(0)
                && seal.lock_identity == cspace_lock_identity.unwrap_or(0)
        });
        let seal_matches_cspace = record.space_seal.is_some_and(|seal| {
            Some(seal.cspace_identity) == cspace_identity
                && Some(seal.cspace_incarnation) == cspace_incarnation
        });
        Some(AcceptanceInstanceProbe {
            exact,
            phase: record.phase,
            generation: record.generation,
            space_object_identity,
            cspace_lock_identity,
            cspace_identity,
            cspace_incarnation,
            capability_table,
            installed_capabilities,
            seal_matches_space,
            seal_matches_cspace,
        })
    }

    /// Corrupt exactly one component of an otherwise valid Active seal for a
    /// target acceptance rejection test.
    ///
    /// This API cannot select or install an identity: each mismatch is a
    /// fixed transform of the already sealed value, and production builds do
    /// not contain the method. No phase/header/domain/task field is changed.
    ///
    /// # Safety
    ///
    /// The caller must own the C4.8 acceptance scenario for this exact token
    /// and serialize against every lifecycle operation. After this returns
    /// `Ok`, the task must enter the intended fault gate without another guest
    /// quantum or normal finalization attempt. The resulting quarantined slot
    /// is intentionally leaked until reboot; this method must never be used by
    /// a production image or as a way to recover an already corrupt record.
    #[cfg(feature = "wasm-c48-target-acceptance")]
    pub unsafe fn corrupt_active_seal(
        &self,
        token: InstanceToken,
        mismatch: AcceptanceSealMismatch,
    ) -> Result<(), RegistryError> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let result = (|| {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            let structurally_active =
                record.phase == InstancePhase::Active
                    && record.task.as_ref().is_some_and(|handle| {
                        Self::structural_identity_matches(slot, &record, token, handle)
                    })
                    && record.space.as_deref().zip(record.space_seal).is_some_and(
                        |(space, seal)| {
                            if !seal.immutable_objects_match(space) {
                                return false;
                            }
                            let cspace = space.cspace().lock();
                            seal.cspace_matches(&cspace)
                        },
                    );
            if !structurally_active {
                return Err(RegistryError::IdentityMismatch);
            }
            let seal = record
                .space_seal
                .as_mut()
                .expect("validated active acceptance record has no seal");
            match mismatch {
                AcceptanceSealMismatch::SpaceObject => seal.object_identity ^= 1,
                AcceptanceSealMismatch::CSpaceObject => seal.lock_identity ^= 1,
                AcceptanceSealMismatch::CSpaceIncarnation => seal.cspace_incarnation ^= 1,
            }
            Ok(())
        })();
        system.restore();
        result
    }

    /// Observe one retained lifecycle record only after matching the executor's
    /// exact, unforgeable status handle and every stable structural projection.
    ///
    /// This is the read-only gate for a SYSTEM control table which publishes a
    /// scalar `Running` state.  It verifies token generation/header, TaskId and
    /// TaskStatus object identity, owner/arena domain, prepared binding, home
    /// hart, scheduler incarnation, and the stable [`InstanceSpace`] plus
    /// CSpace-lock object addresses.  It deliberately does not acquire or
    /// recover the CSpace lock: no observation authorizes payload access,
    /// terminal publication, owner retirement, reset, or raw reclamation.
    /// Those irreversible operations retain their separate complete CSpace
    /// identity/incarnation gates.
    ///
    /// A mismatch sticky-quarantines both the addressed generation and every
    /// retained record which aliases the supplied handle.  It never attempts a
    /// best-effort lookup by TaskId or allocation domain.
    pub fn observe_structural(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
    ) -> Result<InstanceSnapshot, RegistryError> {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::structural_identity_matches(slot, &record, token, handle)
            || matches!(
                record.phase,
                InstancePhase::Vacant | InstancePhase::Reserved | InstancePhase::Bound
            )
        {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        if record.phase == InstancePhase::Quarantined {
            drop(record);
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::Quarantined);
        }
        let snapshot = InstanceSnapshot {
            phase: record.phase,
            domain: record
                .domain
                .expect("a structurally observed record retains its domain"),
            task: record.task.as_ref().map(TaskHandle::id),
            home_hart: record.home_hart,
        };
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(snapshot)
    }

    /// Read the immutable detached payload completion of one exact terminal
    /// task without authorizing terminal publication, owner retirement, or a
    /// CSpace reset.
    ///
    /// A faulted managed task may have failed before publishing a payload
    /// completion, or while dropping a payload whose exact completion was
    /// already stored. Lifecycle CONTROL uses this read-only proof to select
    /// one of the existing exact finalization gates; it never turns an absent
    /// completion into authority to retire resources.
    pub fn observe_terminal_completion(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
    ) -> Result<Option<u64>, RegistryError> {
        if handle.try_exit().is_none() {
            return Err(RegistryError::TaskNotTerminal);
        }
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let _transaction = self.transaction.lock();
        let Some(slot) = self.slot(token) else {
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        };
        let mut record = slot.record.lock();
        if !Self::structural_identity_matches(slot, &record, token, handle)
            || matches!(
                record.phase,
                InstancePhase::Vacant | InstancePhase::Reserved | InstancePhase::Bound
            )
        {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
        if record.phase == InstancePhase::Quarantined {
            drop(record);
            self.quarantine_terminal_candidates_locked(handle);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::Quarantined);
        }
        let completion = record.payload_completion;
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(completion)
    }

    fn slot(&self, token: InstanceToken) -> Option<&InstanceSlot> {
        self.slots.get(token.slot as usize)
    }

    fn header_matches(slot: &InstanceSlot, record: &SlotRecord) -> bool {
        slot.header.load(Ordering::Acquire) == encode_header(record.generation, record.phase)
            && (slot.header.load(Ordering::Relaxed) & PHASE_MASK) == record.phase as u64
    }

    fn token_matches(slot: &InstanceSlot, record: &SlotRecord, token: InstanceToken) -> bool {
        record.generation == token.generation && Self::header_matches(slot, record)
    }

    fn publish_header(slot: &InstanceSlot, record: &SlotRecord) {
        slot.header.store(
            encode_header(record.generation, record.phase),
            Ordering::Release,
        );
    }

    /// Sticky-quarantine unless the first exact lifecycle owner is currently in
    /// an irreversible external callback. Replays, stale observers, and public
    /// quarantine requests must not perturb that owner's linearized phase.
    fn quarantine_locked(slot: &InstanceSlot, record: &mut SlotRecord) {
        if matches!(
            record.phase,
            InstancePhase::FaultReclaiming
                | InstancePhase::PayloadDropping
                | InstancePhase::NormalClosing
                | InstancePhase::FaultRetiring
        ) {
            return;
        }
        Self::force_quarantine_locked(slot, record);
    }

    /// Quarantine requested by the exact in-flight lifecycle owner after its
    /// own callback refused or invalidated the operation. This is deliberately
    /// separate from observer-side quarantine so callback failure cannot leave
    /// a transitional phase reusable.
    fn force_quarantine_locked(slot: &InstanceSlot, record: &mut SlotRecord) {
        record.phase = InstancePhase::Quarantined;
        record.continuation.phase = ContinuationPhase::Quarantined;
        Self::publish_header(slot, record);
    }

    /// Detect a copied or mismatched witness which aliases the exact record
    /// whose first fault gate is already executing its raw-reclaim callback.
    /// The caller holds `transaction`, so a false result remains false until it
    /// either locks the addressed record or publishes its own in-flight phase.
    fn fault_reclaiming_alias_locked(&self, witness: ReclaimableFaultWitness) -> bool {
        self.slots.iter().enumerate().any(|(index, slot)| {
            let record = slot.record.lock();
            if record.phase != InstancePhase::FaultReclaiming {
                return false;
            }
            let token_alias = witness
                .instance_token()
                .is_some_and(|candidate| candidate.slot as usize == index);
            let task_alias = record
                .task
                .as_ref()
                .is_some_and(|handle| handle.id() == witness.task_id())
                || record
                    .prepared
                    .is_some_and(|binding| binding.task_id() == witness.task_id());
            let domain_alias = Self::projected_domains(&record)
                .iter()
                .flatten()
                .any(|domain| {
                    *domain == witness.allocation_domain()
                        || domain.owner == witness.allocation_domain().owner
                        || domain.arena == witness.allocation_domain().arena
                });
            token_alias || task_alias || domain_alias
        })
    }

    fn quarantine_bindings_locked(&self, bindings: &[PreparedReclaimableBinding]) {
        for binding in bindings {
            let Some(token) = binding.instance_token() else {
                continue;
            };
            let Some(slot) = self.slot(token) else {
                continue;
            };
            let mut record = slot.record.lock();
            Self::quarantine_locked(slot, &mut record);
        }
    }

    fn quarantine_bind_batch_candidates_locked(
        &self,
        tokens: &[InstanceToken],
        bindings: &[PreparedReclaimableBinding],
    ) {
        for token in tokens.iter().copied().chain(
            bindings
                .iter()
                .filter_map(|binding| binding.instance_token()),
        ) {
            let Some(slot) = self.slot(token) else {
                continue;
            };
            let mut record = slot.record.lock();
            if Self::token_matches(slot, &record, token) {
                Self::quarantine_locked(slot, &mut record);
            }
        }
    }

    fn quarantine_exact_fault_candidates_locked(&self, witness: ReclaimableFaultWitness) -> bool {
        let mut found = false;
        for slot in &self.slots {
            let mut record = slot.record.lock();
            let projections = Self::projected_domains(&record);
            if record.phase == InstancePhase::Vacant
                && projections.iter().all(Option::is_none)
                && Self::header_matches(slot, &record)
            {
                continue;
            }
            if !Self::header_matches(slot, &record)
                || Self::domain_projections_disagree(projections)
                || record.phase == InstancePhase::Vacant
            {
                Self::quarantine_locked(slot, &mut record);
            }
            let task_matches = record
                .task
                .as_ref()
                .is_some_and(|handle| handle.id() == witness.task_id())
                || record
                    .prepared
                    .is_some_and(|binding| binding.task_id() == witness.task_id());
            let domain_alias = projections.iter().flatten().any(|domain| {
                *domain == witness.allocation_domain()
                    || domain.owner == witness.allocation_domain().owner
                    || domain.arena == witness.allocation_domain().arena
            });
            if task_matches || domain_alias {
                Self::quarantine_locked(slot, &mut record);
                found = true;
            }
        }
        found
    }

    /// Isolate every retained generation which could be the actual target of
    /// a caller-supplied terminal handle.  A wrong/stale token must not merely
    /// quarantine the slot it happens to address while leaving the exact
    /// TaskId/status/domain record eligible for a later close and reset.
    fn quarantine_terminal_candidates_locked(&self, handle: &TaskHandle) -> bool {
        let mut found = false;
        for slot in &self.slots {
            let mut record = slot.record.lock();
            let projections = Self::projected_domains(&record);
            if record.phase == InstancePhase::Vacant
                && projections.iter().all(Option::is_none)
                && Self::header_matches(slot, &record)
            {
                continue;
            }
            if !Self::header_matches(slot, &record)
                || Self::domain_projections_disagree(projections)
                || record.phase == InstancePhase::Vacant
            {
                Self::quarantine_locked(slot, &mut record);
            }
            let task_alias = record
                .task
                .as_ref()
                .is_some_and(|stored| stored.id() == handle.id())
                || record
                    .prepared
                    .is_some_and(|binding| binding.task_id() == handle.id());
            let exact_status = record.task.as_ref().is_some_and(|stored| {
                record.prepared.is_some_and(|binding| {
                    binding.matches_handle(stored) && binding.matches_handle(handle)
                })
            });
            let domain_alias = projections.iter().flatten().any(|domain| {
                *domain == handle.allocation_domain()
                    || domain.owner == handle.allocation_domain().owner
                    || domain.arena == handle.allocation_domain().arena
            });
            if task_alias || exact_status || domain_alias {
                Self::quarantine_locked(slot, &mut record);
                found = true;
            }
        }
        found
    }

    fn projected_domains(record: &SlotRecord) -> [Option<AllocationDomain>; 3] {
        [
            record.domain,
            record.task.as_ref().map(TaskHandle::allocation_domain),
            record
                .prepared
                .map(PreparedReclaimableBinding::allocation_domain),
        ]
    }

    fn vacant_record_is_pristine(slot: &InstanceSlot, record: &SlotRecord) -> bool {
        record.phase == InstancePhase::Vacant
            && record.domain.is_none()
            && record.space_seal.is_none()
            && record.prepared.is_none()
            && record.task.is_none()
            && record.scheduler.is_none()
            && record.home_hart.is_none()
            && record.payload.is_none()
            && !record.payload_installed
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && record.payload_cancel.is_none()
            && record.continuation.phase == ContinuationPhase::Idle
            && record.continuation.kind.is_none()
            && record.continuation.seal.is_none()
            && slot.continuation_wait.waiter_count() == 0
    }

    fn reserved_record_is_unpublished(slot: &InstanceSlot, record: &SlotRecord) -> bool {
        record.phase == InstancePhase::Reserved
            && record.domain.is_some()
            && record.space.is_some()
            && record.space_seal.is_some()
            && record.prepared.is_none()
            && record.task.is_none()
            && record.scheduler.is_none()
            && record.home_hart.is_none()
            && record.payload.is_none()
            && !record.payload_installed
            && !record.payload_abandoned
            && record.payload_completion.is_none()
            && record.payload_cancel.is_none()
            && record.continuation.phase == ContinuationPhase::Idle
            && record.continuation.kind.is_none()
            && record.continuation.seal.is_none()
            && slot.continuation_wait.waiter_count() == 0
    }

    fn domain_projections_disagree(projections: [Option<AllocationDomain>; 3]) -> bool {
        let Some(expected) = projections.iter().flatten().next().copied() else {
            return false;
        };
        projections
            .iter()
            .flatten()
            .any(|domain| *domain != expected)
    }

    /// Prove that no other retained registry generation can own or reference
    /// the arena about to be raw-reclaimed.  This is repeated at the fault
    /// linearization point rather than relying only on admission-time checks:
    /// a stale/corrupt projection in another quarantined slot must remain a
    /// permanent tombstone, never an alias into reclaimable memory.
    fn quarantine_identity_conflicts_locked(
        &self,
        current: InstanceToken,
        arena: crate::heap::ArenaId,
        task: TaskId,
        scheduler: Option<ReclaimableSchedulerIdentity>,
    ) -> bool {
        let mut conflict = false;
        for (index, slot) in self.slots.iter().enumerate() {
            if index == current.slot as usize {
                continue;
            }
            let mut record = slot.record.lock();
            let projections = Self::projected_domains(&record);
            if !Self::header_matches(slot, &record)
                || Self::domain_projections_disagree(projections)
                || (record.phase == InstancePhase::Vacant
                    && projections.iter().any(Option::is_some))
            {
                Self::quarantine_locked(slot, &mut record);
            }
            let arena_alias = projections
                .iter()
                .flatten()
                .any(|domain| domain.arena == arena);
            let task_alias = record
                .task
                .as_ref()
                .is_some_and(|handle| handle.id() == task)
                || record
                    .prepared
                    .is_some_and(|binding| binding.task_id() == task);
            let token_alias = record
                .prepared
                .is_some_and(|binding| binding.instance_token() == Some(current));
            let scheduler_alias = scheduler.is_some() && record.scheduler == scheduler;
            if arena_alias || task_alias || token_alias || scheduler_alias {
                Self::quarantine_locked(slot, &mut record);
                conflict = true;
            }
        }
        conflict
    }

    fn fault_identity_matches(
        slot: &InstanceSlot,
        record: &SlotRecord,
        token: InstanceToken,
        witness: ReclaimableFaultWitness,
    ) -> bool {
        let lifecycle_matches = match record.phase {
            InstancePhase::Active => {
                !record.payload_abandoned
                    && record.payload_completion.is_none()
                    && if record.payload_installed {
                        record.payload.is_some()
                    } else {
                        record.payload.is_none() && record.payload_cancel.is_none()
                    }
            }
            InstancePhase::PayloadDropping => {
                record.payload_installed
                    && record.payload.is_none()
                    && !record.payload_abandoned
                    && record.payload_completion.is_none()
            }
            InstancePhase::PayloadDropped => {
                record.payload_installed
                    && record.payload.is_none()
                    && !record.payload_abandoned
                    && record.payload_completion.is_some()
                    && record.payload_cancel.is_none()
            }
            _ => false,
        };
        lifecycle_matches
            && Self::fault_identity_matches_in_phase(slot, record, token, witness, record.phase)
    }

    fn fault_identity_matches_in_phase(
        slot: &InstanceSlot,
        record: &SlotRecord,
        token: InstanceToken,
        witness: ReclaimableFaultWitness,
        expected_phase: InstancePhase,
    ) -> bool {
        let Some(handle) = record.task.as_ref() else {
            return false;
        };
        let Some(binding) = record.prepared else {
            return false;
        };
        let Some(seal) = record.space_seal else {
            return false;
        };
        let Some(space) = record.space.as_deref() else {
            return false;
        };
        Self::token_matches(slot, record, token)
            && record.phase == expected_phase
            && witness.instance_token() == Some(token)
            && binding.instance_token() == Some(token)
            && binding.scheduler_identity().is_none()
            && record.domain == Some(witness.allocation_domain())
            && handle.allocation_domain() == witness.allocation_domain()
            && binding.allocation_domain() == witness.allocation_domain()
            && handle.id() == witness.task_id()
            && binding.task_id() == witness.task_id()
            && witness.matches_handle(handle)
            && binding.matches_handle(handle)
            && record.home_hart == Some(witness.home_hart())
            && binding.home_hart() == witness.home_hart()
            && witness.current_hart() == witness.home_hart()
            && record.scheduler == Some(witness.scheduler_identity())
            && record
                .scheduler
                .map(ReclaimableSchedulerIdentity::generation)
                == Some(witness.scheduler_identity().generation())
            && seal.immutable_objects_match(space)
    }

    fn active_witness_identity_matches(
        slot: &InstanceSlot,
        record: &SlotRecord,
        token: InstanceToken,
        witness: ReclaimableTaskWitness,
        expected_phase: InstancePhase,
    ) -> bool {
        let Some(handle) = record.task.as_ref() else {
            return false;
        };
        let Some(binding) = record.prepared else {
            return false;
        };
        let Some(seal) = record.space_seal else {
            return false;
        };
        let Some(space) = record.space.as_deref() else {
            return false;
        };
        Self::token_matches(slot, record, token)
            && record.phase == expected_phase
            && witness.instance_token() == Some(token)
            && binding.instance_token() == Some(token)
            && binding.scheduler_identity().is_none()
            && record.domain == Some(witness.allocation_domain())
            && handle.allocation_domain() == witness.allocation_domain()
            && binding.allocation_domain() == witness.allocation_domain()
            && handle.id() == witness.task_id()
            && binding.task_id() == witness.task_id()
            && witness.matches_handle(handle)
            && binding.matches_handle(handle)
            && record.home_hart == Some(witness.home_hart())
            && binding.home_hart() == witness.home_hart()
            && witness.current_hart() == witness.home_hart()
            && record.scheduler == Some(witness.scheduler_identity())
            && record
                .scheduler
                .map(ReclaimableSchedulerIdentity::generation)
                == Some(witness.scheduler_identity().generation())
            && seal.immutable_objects_match(space)
    }

    fn sealed_cspace_matches(record: &SlotRecord) -> bool {
        record
            .space
            .as_deref()
            .zip(record.space_seal)
            .is_some_and(|(space, seal)| {
                if !seal.immutable_objects_match(space) {
                    return false;
                }
                let cspace = space.cspace().lock();
                seal.reset_preflight_matches(&cspace)
            })
    }

    /// Compare a non-idle continuation's frozen projections with the current
    /// stable record without acquiring the CSpace lock. This structural form
    /// is safe for external readiness publication: a task fault cannot leave
    /// the signal path holding the registry transaction while waiting for an
    /// abandoned guest-held CSpace lock.
    fn continuation_seal_projection_matches(record: &SlotRecord, seal: ContinuationSeal) -> bool {
        let Some(handle) = record.task.as_ref() else {
            return false;
        };
        let Some(binding) = record.prepared else {
            return false;
        };
        record.continuation.generation != 0
            && record.continuation.generation == seal.operation_generation
            && record.continuation.seal == Some(seal)
            && record.continuation.kind == Some(seal.kind)
            && seal.instance.generation == record.generation
            && record.domain == Some(seal.domain)
            && handle.allocation_domain() == seal.domain
            && binding.allocation_domain() == seal.domain
            && handle.id() == seal.task
            && binding.task_id() == seal.task
            && binding.instance_token() == Some(seal.instance)
            && binding.scheduler_identity().is_none()
            && binding.matches_handle(handle)
            && record.home_hart == Some(seal.home_hart)
            && binding.home_hart() == seal.home_hart
            && record.scheduler == Some(seal.scheduler)
            && record
                .scheduler
                .map(ReclaimableSchedulerIdentity::generation)
                == Some(seal.scheduler.generation())
            && record.space_seal == Some(seal.space)
            && record
                .space
                .as_deref()
                .is_some_and(|space| seal.space.immutable_objects_match(space))
    }

    /// Validate the complete phase-specific continuation shape. Empty state
    /// must carry no stale authority; every other operation phase must retain
    /// one exact non-zero-generation seal. Quarantine is intentionally never
    /// accepted by a reclaim or reset path.
    fn continuation_projection_matches(record: &SlotRecord) -> bool {
        match record.continuation.phase {
            ContinuationPhase::Idle => {
                record.continuation.kind.is_none() && record.continuation.seal.is_none()
            }
            ContinuationPhase::Armed
            | ContinuationPhase::Signalled
            | ContinuationPhase::Consumed
            | ContinuationPhase::Cancelled
            | ContinuationPhase::Abandoned => record
                .continuation
                .seal
                .is_some_and(|seal| Self::continuation_seal_projection_matches(record, seal)),
            ContinuationPhase::Quarantined => false,
        }
    }

    fn continuation_live_seal_matches(record: &SlotRecord, seal: ContinuationSeal) -> bool {
        Self::continuation_current_seal_matches(record, seal, InstancePhase::Active)
    }

    fn continuation_current_seal_matches(
        record: &SlotRecord,
        seal: ContinuationSeal,
        phase: InstancePhase,
    ) -> bool {
        record.phase == phase
            && record
                .task
                .as_ref()
                .is_some_and(|handle| handle.is_published() && handle.try_exit().is_none())
            && Self::continuation_seal_projection_matches(record, seal)
    }

    fn continuation_terminal_safe(record: &SlotRecord) -> bool {
        record.continuation.terminal_phase_safe() && Self::continuation_projection_matches(record)
    }

    fn continuation_fault_safe(record: &SlotRecord) -> bool {
        record.continuation.fault_phase_safe() && Self::continuation_projection_matches(record)
    }

    fn terminal_identity_matches(
        slot: &InstanceSlot,
        record: &SlotRecord,
        token: InstanceToken,
        handle: &TaskHandle,
    ) -> bool {
        Self::structural_identity_matches(slot, record, token, handle)
            && record
                .space
                .as_deref()
                .zip(record.space_seal)
                .is_some_and(|(space, seal)| {
                    let cspace = space.cspace().lock();
                    seal.reset_preflight_matches(&cspace)
                })
    }

    /// Validate every immutable registry/executor projection without touching
    /// the CSpace lock.  In particular, `finalize` uses this while the exact
    /// task may still be Running: a faulting task can have abandoned that lock
    /// and needs the registry transaction in order to recover it.
    fn structural_identity_matches(
        slot: &InstanceSlot,
        record: &SlotRecord,
        token: InstanceToken,
        handle: &TaskHandle,
    ) -> bool {
        Self::token_matches(slot, record, token)
            && record.domain == Some(handle.allocation_domain())
            && record.task.as_ref().is_some_and(|stored| {
                stored.id() == handle.id()
                    && stored.allocation_domain() == handle.allocation_domain()
                    && record.prepared.is_some_and(|binding| {
                        binding.instance_token() == Some(token)
                            && binding.scheduler_identity().is_none()
                            && record.home_hart == Some(binding.home_hart())
                            && record.scheduler.is_some()
                            && binding.matches_handle(stored)
                            && binding.matches_handle(handle)
                    })
            })
            && record
                .space
                .as_deref()
                .zip(record.space_seal)
                .is_some_and(|(space, seal)| seal.immutable_objects_match(space))
    }
}

impl Default for InstanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Future for InstanceContinuation<'_> {
    type Output = Result<InstanceContinuationConsumed, InstanceContinuationError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.terminal {
            return Poll::Ready(Err(InstanceContinuationError::WrongPhase));
        }

        // At most one event recheck is needed to close the register/complete
        // race. This bounded loop is not an interpreter or service spin loop.
        for recheck in 0..2 {
            match this.registry.poll_continuation_current(this.token) {
                Ok(Poll::Ready(consumed)) => {
                    this.terminal = true;
                    drop(this.listener.take());
                    return Poll::Ready(Ok(consumed));
                }
                Ok(Poll::Pending) => {}
                Err(error) => {
                    this.terminal = true;
                    drop(this.listener.take());
                    return Poll::Ready(Err(error));
                }
            }

            let Some(listener) = this.listener.as_mut() else {
                this.terminal = true;
                let _ = this.registry.quarantine(this.token.instance);
                return Poll::Ready(Err(InstanceContinuationError::Quarantined));
            };
            match Pin::new(listener).poll(context) {
                Poll::Ready(Ok(())) if recheck == 0 => continue,
                Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                    this.terminal = true;
                    drop(this.listener.take());
                    let _ = this.registry.quarantine(this.token.instance);
                    return Poll::Ready(Err(InstanceContinuationError::Quarantined));
                }
                Poll::Pending => {}
            }

            if this.kind == InstanceContinuationKind::Quantum && !this.self_wake_published {
                this.self_wake_published = true;
                match this.registry.signal_continuation(this.token) {
                    InstanceContinuationSignal::Signalled
                    | InstanceContinuationSignal::AlreadySignalled => {}
                    InstanceContinuationSignal::AlreadyConsumed(_) => {
                        this.terminal = true;
                        drop(this.listener.take());
                        let _ = this.registry.quarantine(this.token.instance);
                        return Poll::Ready(Err(InstanceContinuationError::Quarantined));
                    }
                    InstanceContinuationSignal::Stale => {
                        this.terminal = true;
                        drop(this.listener.take());
                        return Poll::Ready(Err(InstanceContinuationError::IdentityMismatch));
                    }
                    InstanceContinuationSignal::Quarantined => {
                        this.terminal = true;
                        drop(this.listener.take());
                        return Poll::Ready(Err(InstanceContinuationError::Quarantined));
                    }
                }
            }
            return Poll::Pending;
        }

        this.terminal = true;
        drop(this.listener.take());
        let _ = this.registry.quarantine(this.token.instance);
        Poll::Ready(Err(InstanceContinuationError::Quarantined))
    }
}

impl Drop for InstanceContinuation<'_> {
    fn drop(&mut self) {
        // Remove the TaskStatus-owned edge before changing operation state, so
        // normal cancellation leaves no stale waker. A target architecture
        // fault skips this destructor; permanent-detach cleanup drains the
        // ledger and `fault_reclaim` publishes Abandoned instead.
        drop(self.listener.take());
        if !self.terminal
            && self
                .registry
                .cancel_continuation_current(self.token)
                .is_err()
        {
            let _ = self.registry.quarantine(self.token.instance);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::{Resource, Rights};
    use crate::exec::{
        self, CancelOutcome, FaultReclaimOutcome, PreparedTaskBatch, PreparedTaskBatchError,
    };
    use crate::heap::{ArenaId, OwnerId};
    use std::any::Any;
    use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering as AtomicOrdering};
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};

    static TEST_REGISTRY: AtomicPtr<InstanceRegistry> = AtomicPtr::new(core::ptr::null_mut());
    static TEST_FAULT_NEXT: AtomicBool = AtomicBool::new(false);
    static TEST_RECLAIM_SUCCEEDS: AtomicBool = AtomicBool::new(true);
    static TEST_RAW_RECLAIMS: AtomicU64 = AtomicU64::new(0);
    static TEST_FAULT_WITNESS: Mutex<Option<ReclaimableFaultWitness>> = Mutex::new(None);
    static TEST_TASK_WITNESS: Mutex<Option<ReclaimableTaskWitness>> = Mutex::new(None);
    static TEST_PAYLOAD_POLLS: AtomicU64 = AtomicU64::new(0);
    static TEST_PAYLOAD_DROPS: AtomicU64 = AtomicU64::new(0);
    static TEST_PAYLOAD_COMPLETION: AtomicU64 = AtomicU64::new(u64::MAX);
    static TEST_PAYLOAD_DROP_FAULT: AtomicBool = AtomicBool::new(false);
    static TEST_CONTINUATION_TOKEN: Mutex<Option<InstanceContinuationToken>> = Mutex::new(None);
    static TEST_CONTINUATION_BEFORE: Mutex<Option<ReclaimableTaskWitness>> = Mutex::new(None);
    static TEST_CONTINUATION_AFTER: Mutex<Option<ReclaimableTaskWitness>> = Mutex::new(None);
    static TEST_CONTINUATION_STAGE: AtomicU64 = AtomicU64::new(0);
    static TEST_CONTINUATION_BUSY: AtomicBool = AtomicBool::new(false);
    static TEST_CONTINUATION_PAYLOAD_DROPS: AtomicU64 = AtomicU64::new(0);
    static TEST_CONTINUATION_CANCELLED: Mutex<Option<InstanceContinuationCancelled>> =
        Mutex::new(None);

    struct TestSpaceResource;

    impl Resource for TestSpaceResource {
        fn kind(&self) -> &'static str {
            "instance-space-test"
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn opaque_tokens_expose_only_stable_slot_alias_rejection() {
        let first = InstanceToken {
            slot: 3,
            generation: 7,
        };
        let replacement = InstanceToken {
            slot: 3,
            generation: 8,
        };
        let unrelated = InstanceToken {
            slot: 4,
            generation: 7,
        };

        assert_ne!(first, replacement);
        assert!(first.shares_stable_slot(replacement));
        assert!(!first.shares_stable_slot(unrelated));
    }

    #[test]
    fn named_batch_reservation_is_ordered_distinct_and_atomically_abortable() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let inputs = [
            (domain(60_001), "graph-node-decoder"),
            (domain(60_002), "graph-node-filter"),
            (domain(60_003), "graph-node-sink"),
        ];

        let tokens = registry.reserve_named_batch(&inputs).unwrap();
        assert_eq!(tokens.len(), inputs.len());
        assert_eq!(format!("{:?}", tokens[0]), "InstanceToken(<opaque>)");
        for (index, token) in tokens.iter().copied().enumerate() {
            assert!(tokens[index + 1..]
                .iter()
                .all(|other| !token.shares_stable_slot(*other)));
            let record = registry.slots[token.slot as usize].record.lock();
            assert_eq!(record.phase, InstancePhase::Reserved);
            assert_eq!(record.domain, Some(inputs[index].0));
            assert_eq!(
                record.space.as_deref().unwrap().cspace().lock().name,
                inputs[index].1
            );
        }
        let stats = registry.occupancy_stats();
        assert_eq!(stats.occupied, inputs.len());
        assert_eq!(stats.phase_count(InstancePhase::Reserved), inputs.len());

        let mut before_abort = Vec::new();
        for token in tokens.iter().copied() {
            unsafe {
                registry
                    .configure_reserved_space(token, |cspace| {
                        cspace.mint(Arc::new(TestSpaceResource), Rights::READ)
                    })
                    .unwrap();
            }
            before_abort.push(cspace_state(&registry, token));
        }

        let outcome = registry.abort_reserved_batch(&tokens).unwrap();
        assert_eq!(outcome.aborted_instances(), inputs.len());
        let stats = registry.occupancy_stats();
        assert_eq!(stats.occupied, 0);
        assert_eq!(
            stats.phase_count(InstancePhase::Vacant),
            MAX_COMPONENT_INSTANCES
        );
        for (token, before) in tokens.iter().copied().zip(before_abort) {
            let record = registry.slots[token.slot as usize].record.lock();
            assert_eq!(record.phase, InstancePhase::Vacant);
            assert_eq!(record.generation, token.generation + 1);
            assert!(record.domain.is_none());
            assert!(record.space_seal.is_none());
            let cspace = record.space.as_deref().unwrap().cspace().lock();
            assert_eq!(cspace.identity(), before.0);
            assert_eq!(cspace.incarnation(), before.1 + 1);
            assert!(cspace.list().is_empty());
        }

        let replacements = registry.reserve_named_batch(&inputs).unwrap();
        for (old, replacement) in tokens.iter().zip(&replacements) {
            assert!(old.shares_stable_slot(*replacement));
            assert_eq!(replacement.generation, old.generation + 1);
        }
        registry.abort_reserved_batch(&replacements).unwrap();
    }

    #[test]
    fn named_batch_skips_an_early_exhausted_cspace_for_a_later_viable_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let early = registry
            .reserve_named_batch(&[(domain(60_100), "early-retained-cspace")])
            .unwrap()
            .remove(0);
        registry.abort_reserved_batch(&[early]).unwrap();

        // Model an exhausted retained CSpace in the earliest vacant slot. The
        // production callback is exactly `preflight_reset_exact`; injecting
        // its terminal result here avoids iterating an incarnation counter to
        // u64::MAX while exercising the complete selection/publication path.
        let exhausted_cspace_before = cspace_state(&registry, early);
        let fallback = registry
            .reserve_named_batch_with_preflight(
                &[(domain(60_101), "later-viable-cspace")],
                |index, cspace| {
                    if index == early.slot as usize {
                        Err(CSpaceResetError::IncarnationExhausted)
                    } else {
                        cspace.preflight_reset_exact(cspace.identity(), cspace.incarnation())
                    }
                },
            )
            .unwrap();

        assert_eq!(fallback.len(), 1);
        assert!(!fallback[0].shares_stable_slot(early));
        {
            let record = registry.slots[early.slot as usize].record.lock();
            assert_eq!(record.phase, InstancePhase::Vacant);
            assert_eq!(record.generation, early.generation + 1);
        }
        assert_eq!(cspace_state(&registry, early), exhausted_cspace_before);
        registry.abort_reserved_batch(&fallback).unwrap();
        assert_eq!(registry.occupancy_stats().occupied, 0);
    }

    #[test]
    fn named_batch_validation_capacity_and_generation_failures_mutate_nothing() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        assert_eq!(
            registry.reserve_named_batch(&[]),
            Err(BatchReserveError::Empty)
        );
        let too_many: Vec<_> = (0..=MAX_COMPONENT_INSTANCES)
            .map(|index| (domain(61_000 + index as u64), "too-many"))
            .collect();
        assert_eq!(
            registry.reserve_named_batch(&too_many),
            Err(BatchReserveError::TooMany)
        );
        assert_eq!(
            registry.reserve_named_batch(&[(
                AllocationDomain::untracked(OwnerId::new(61_100)),
                "untracked",
            )]),
            Err(BatchReserveError::InvalidDomain)
        );
        assert_eq!(
            registry.reserve_named_batch(&[(
                AllocationDomain::new(OwnerId::SYSTEM, ArenaId::new(61_101)),
                "system",
            )]),
            Err(BatchReserveError::InvalidDomain)
        );
        let alias_arena = ArenaId::new(61_102);
        assert_eq!(
            registry.reserve_named_batch(&[
                (
                    AllocationDomain::new(OwnerId::new(61_103), alias_arena),
                    "alias-a",
                ),
                (
                    AllocationDomain::new(OwnerId::new(61_104), alias_arena),
                    "alias-b",
                ),
            ]),
            Err(BatchReserveError::DuplicateArena)
        );
        assert_pristine_registry(&registry);

        let existing_domain = domain(61_200);
        let existing = registry.reserve(existing_domain).unwrap();
        let before = registry.occupancy_stats();
        let conflict = AllocationDomain::new(OwnerId::new(61_201), existing_domain.arena);
        assert_eq!(
            registry.reserve_named_batch(&[(conflict, "live-alias")]),
            Err(BatchReserveError::ArenaConflict)
        );
        assert_eq!(registry.occupancy_stats(), before);
        let capacity_inputs: Vec<_> = (0..MAX_COMPONENT_INSTANCES)
            .map(|index| (domain(61_300 + index as u64), "capacity"))
            .collect();
        assert_eq!(
            registry.reserve_named_batch(&capacity_inputs),
            Err(BatchReserveError::Capacity)
        );
        assert_eq!(registry.occupancy_stats(), before);
        assert_eq!(retained_space_count(&registry), 1);
        registry.abort_reserved_batch(&[existing]).unwrap();

        let exhausted = InstanceRegistry::new();
        {
            let slot = &exhausted.slots[0];
            let mut record = slot.record.lock();
            record.generation = MAX_INSTANCE_GENERATION;
            InstanceRegistry::publish_header(slot, &record);
        }
        let before_headers: Vec<_> = exhausted
            .slots
            .iter()
            .map(|slot| slot.header.load(Ordering::Acquire))
            .collect();
        let generation_inputs: Vec<_> = (0..MAX_COMPONENT_INSTANCES)
            .map(|index| (domain(61_400 + index as u64), "generation"))
            .collect();
        assert_eq!(
            exhausted.reserve_named_batch(&generation_inputs),
            Err(BatchReserveError::GenerationExhausted)
        );
        assert_eq!(
            exhausted
                .slots
                .iter()
                .map(|slot| slot.header.load(Ordering::Acquire))
                .collect::<Vec<_>>(),
            before_headers
        );
        assert_eq!(retained_space_count(&exhausted), 0);
    }

    #[test]
    fn reserved_batch_abort_rejects_the_complete_set_before_mutation() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let inputs = [(domain(62_001), "abort-a"), (domain(62_002), "abort-b")];
        let tokens = registry.reserve_named_batch(&inputs).unwrap();
        for token in tokens.iter().copied() {
            unsafe {
                registry
                    .configure_reserved_space(token, |cspace| {
                        cspace.mint(Arc::new(TestSpaceResource), Rights::READ)
                    })
                    .unwrap();
            }
        }
        let before = [
            cspace_state(&registry, tokens[0]),
            cspace_state(&registry, tokens[1]),
        ];
        assert_eq!(
            registry.abort_reserved_batch(&[]),
            Err(ReservedBatchAbortError::Empty)
        );
        assert_eq!(
            registry.abort_reserved_batch(&[tokens[0], tokens[0]]),
            Err(ReservedBatchAbortError::DuplicateSlot)
        );
        let stale = InstanceToken {
            slot: tokens[0].slot,
            generation: tokens[0].generation + 1,
        };
        assert_eq!(
            registry.abort_reserved_batch(&[stale, tokens[1]]),
            Err(ReservedBatchAbortError::IdentityMismatch)
        );
        assert_eq!(cspace_state(&registry, tokens[0]), before[0]);
        assert_eq!(cspace_state(&registry, tokens[1]), before[1]);

        {
            let slot = &registry.slots[tokens[1].slot as usize];
            let mut record = slot.record.lock();
            record.phase = InstancePhase::Bound;
            InstanceRegistry::publish_header(slot, &record);
        }
        assert_eq!(
            registry.abort_reserved_batch(&tokens),
            Err(ReservedBatchAbortError::WrongPhase)
        );
        assert_eq!(cspace_state(&registry, tokens[0]), before[0]);
        assert_eq!(cspace_state(&registry, tokens[1]), before[1]);
        {
            let slot = &registry.slots[tokens[1].slot as usize];
            let mut record = slot.record.lock();
            record.phase = InstancePhase::Reserved;
            InstanceRegistry::publish_header(slot, &record);
        }

        assert_eq!(
            registry.abort_reserved_batch(&tokens).unwrap(),
            ReservedBatchAbortOutcome {
                aborted_instances: 2,
            }
        );
        assert_eq!(registry.occupancy_stats().occupied, 0);
    }

    #[test]
    fn bind_batch_preserves_order_and_is_compatible_with_atomic_activation() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let inputs = [
            (domain(63_001), "bind-decoder"),
            (domain(63_002), "bind-filter"),
            (domain(63_003), "bind-sink"),
        ];
        let tokens = registry.reserve_named_batch(&inputs).unwrap();
        let mut batch = PreparedTaskBatch::new();
        batch.try_reserve(inputs.len()).unwrap();
        for ((token, (allocation, name)), index) in tokens
            .iter()
            .copied()
            .zip(inputs.iter().copied())
            .zip(0u64..)
        {
            unsafe {
                batch.prepare_managed_instance_owned(token, allocation, name, async move {
                    let _ = (token, index);
                    core::future::pending::<()>().await;
                });
            }
        }

        registry
            .bind_batch(
                &tokens,
                batch.prepared_reclaimable_bindings(),
                batch.prepared_handles(),
            )
            .unwrap();
        for (index, token) in tokens.iter().copied().enumerate() {
            let record = registry.slots[token.slot as usize].record.lock();
            let prepared = record.prepared.expect("batch-bound record lost binding");
            let handle = record.task.as_ref().expect("batch-bound record lost task");
            assert_eq!(record.phase, InstancePhase::Bound);
            assert_eq!(record.domain, Some(inputs[index].0));
            assert!(
                batch.prepared_reclaimable_bindings()[index].matches_prepared_identity(prepared)
            );
            assert!(handle.shares_status_with(&batch.prepared_handles()[index]));
            assert_eq!(
                record.home_hart,
                Some(batch.prepared_reclaimable_bindings()[index].home_hart())
            );
        }

        let handles = unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap();
        assert_eq!(handles.len(), inputs.len());
        for (token, handle) in tokens.iter().copied().zip(&handles) {
            assert!(handle.is_published());
            assert_eq!(
                registry.snapshot(token).unwrap().phase,
                InstancePhase::Active
            );
            assert_eq!(handle.cancel(), CancelOutcome::Requested);
        }
        for ((token, (allocation, _)), handle) in tokens
            .iter()
            .copied()
            .zip(inputs.iter().copied())
            .zip(&handles)
        {
            unsafe {
                registry
                    .finalize(token, handle, |closed, kind| {
                        assert_eq!(closed, allocation);
                        assert_eq!(kind, TerminalRetireKind::Normal);
                        true
                    })
                    .unwrap();
            }
        }
        assert_eq!(registry.occupancy_stats().occupied, 0);
    }

    #[test]
    fn bind_batch_late_mismatch_never_leaves_a_bound_prefix() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        assert_eq!(
            registry.bind_batch(&[], &[], &[]),
            Err(RegistryError::IdentityMismatch)
        );
        assert_pristine_registry(&registry);

        let inputs = [
            (domain(63_101), "late-match-a"),
            (domain(63_102), "late-match-b"),
            (domain(63_103), "late-mismatch"),
        ];
        let tokens = registry.reserve_named_batch(&inputs).unwrap();
        let mut batch = PreparedTaskBatch::new();
        batch.try_reserve(inputs.len()).unwrap();
        for (token, (allocation, name)) in tokens.iter().copied().zip(inputs.iter().copied()) {
            unsafe {
                batch.prepare_managed_instance_owned(token, allocation, name, async move {
                    let _ = token;
                    core::future::pending::<()>().await;
                });
            }
        }
        let mut mismatched_handles = batch.prepared_handles().to_vec();
        mismatched_handles[2] = mismatched_handles[0].clone();

        assert_eq!(
            registry.bind_batch(
                &tokens,
                batch.prepared_reclaimable_bindings(),
                &mismatched_handles,
            ),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(
            registry.occupancy_stats().phase_count(InstancePhase::Bound),
            0
        );
        for token in tokens {
            let record = registry.slots[token.slot as usize].record.lock();
            assert_eq!(record.phase, InstancePhase::Quarantined);
            assert!(record.prepared.is_none());
            assert!(record.task.is_none());
            assert!(record.home_hart.is_none());
        }
        assert!(batch
            .prepared_handles()
            .iter()
            .all(|handle| !handle.is_published()));
    }

    #[test]
    fn bind_batch_rejects_oversize_before_candidate_scan_or_mutation() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(63_201);
        let token = registry.reserve(allocation).unwrap();
        let mut batch = PreparedTaskBatch::new();
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, "oversize", async move {
                core::future::pending::<()>().await;
            });
        }
        let binding = batch.prepared_reclaimable_bindings()[0];
        let handle = batch.prepared_handles()[0].clone();
        let tokens = vec![token; MAX_COMPONENT_INSTANCES + 1];
        let bindings = vec![binding; MAX_COMPONENT_INSTANCES + 1];
        let handles = (0..MAX_COMPONENT_INSTANCES + 1)
            .map(|_| handle.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            registry.bind_batch(&tokens, &bindings, &handles),
            Err(RegistryError::IdentityMismatch)
        );
        let record = registry.slots[token.slot as usize].record.lock();
        assert_eq!(record.phase, InstancePhase::Reserved);
        assert!(record.prepared.is_none());
        assert!(record.task.is_none());
        assert!(record.home_hart.is_none());
        drop(record);
        assert_eq!(
            registry.abort_reserved_batch(&[token]).unwrap(),
            ReservedBatchAbortOutcome {
                aborted_instances: 1,
            }
        );
    }

    #[cfg(feature = "wasm-c48-target-acceptance")]
    #[test]
    fn acceptance_probe_and_directed_seal_corruption_preserve_aba_evidence() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let empty = registry.occupancy_stats();
        assert_eq!(empty.capacity(), MAX_INSTANCE_SLOTS);
        assert_eq!(empty.occupied, 0);
        assert_eq!(empty.header_mismatches, 0);
        assert_eq!(empty.phase_count(InstancePhase::Vacant), MAX_INSTANCE_SLOTS);

        let allocation = domain(48_001);
        let token = registry.reserve(allocation).unwrap();
        let handle = publish_pending_managed(&registry, token, allocation, "c48-acceptance-probe");
        let projection = record_projection(&registry, token);
        let before = registry
            .acceptance_probe(token)
            .expect("active acceptance token has no stable slot");
        assert!(before.is_exact());
        assert_eq!(before.exact_phase(), Some(InstancePhase::Active));
        assert_eq!(before.current_phase(), InstancePhase::Active);
        assert!(before.seal_matches_space());
        assert!(before.seal_matches_cspace());
        assert_eq!(before.capability_table_len(), 0);

        // Safety: this executor-serialized host test restores the exact seal
        // before allowing any task or lifecycle operation to proceed.
        unsafe {
            registry
                .corrupt_active_seal(token, AcceptanceSealMismatch::SpaceObject)
                .unwrap();
        }
        let space_mismatch = registry.acceptance_probe(token).unwrap();
        assert!(space_mismatch.is_exact());
        assert!(before.same_space_object(space_mismatch));
        assert!(before.same_cspace_lock(space_mismatch));
        assert!(before.same_cspace_identity(space_mismatch));
        assert!(before.same_cspace_incarnation(space_mismatch));
        assert!(before.same_capability_table(space_mismatch));
        assert!(!space_mismatch.seal_matches_space());
        assert!(space_mismatch.seal_matches_cspace());
        install_space_seal_for_test(&registry, token, projection.space_seal);

        // Corrupt the CSpace lock-object identity independently of both the
        // enclosing Space address and the logical CSpace incarnation.
        unsafe {
            registry
                .corrupt_active_seal(token, AcceptanceSealMismatch::CSpaceObject)
                .unwrap();
        }
        let cspace_object_mismatch = registry.acceptance_probe(token).unwrap();
        assert!(cspace_object_mismatch.is_exact());
        assert!(before.same_space_object(cspace_object_mismatch));
        assert!(before.same_cspace_lock(cspace_object_mismatch));
        assert!(before.same_cspace_identity(cspace_object_mismatch));
        assert!(before.same_cspace_incarnation(cspace_object_mismatch));
        assert!(before.same_capability_table(cspace_object_mismatch));
        assert!(!cspace_object_mismatch.seal_matches_space());
        assert!(cspace_object_mismatch.seal_matches_cspace());
        install_space_seal_for_test(&registry, token, projection.space_seal);

        // Safety: as above, no guest quantum or terminal path can race this
        // intentional acceptance-only corruption.
        unsafe {
            registry
                .corrupt_active_seal(token, AcceptanceSealMismatch::CSpaceIncarnation)
                .unwrap();
        }
        let incarnation_mismatch = registry.acceptance_probe(token).unwrap();
        assert!(incarnation_mismatch.seal_matches_space());
        assert!(!incarnation_mismatch.seal_matches_cspace());
        assert!(before.same_cspace_incarnation(incarnation_mismatch));
        install_space_seal_for_test(&registry, token, projection.space_seal);

        let active = registry.occupancy_stats();
        assert_eq!(active.occupied, 1);
        assert_eq!(active.phase_count(InstancePhase::Active), 1);
        assert_eq!(active.header_mismatches, 0);

        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);
        unsafe {
            registry.finalize(token, &handle, |closed, kind| {
                assert_eq!(closed, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                true
            })
        }
        .unwrap();

        let retired = registry
            .acceptance_probe(token)
            .expect("retired stable slot disappeared");
        assert!(!retired.is_exact());
        assert_eq!(retired.exact_phase(), None);
        assert_eq!(retired.current_phase(), InstancePhase::Vacant);
        assert_eq!(
            retired.current_generation(),
            before.current_generation() + 1
        );
        assert!(before.same_space_object(retired));
        assert!(before.same_cspace_lock(retired));
        assert!(before.same_cspace_identity(retired));
        assert!(!before.same_cspace_incarnation(retired));
        assert_eq!(
            before.capability_table_len(),
            retired.capability_table_len()
        );
        assert_eq!(retired.installed_capability_count(), 0);

        let vacant = registry.occupancy_stats();
        assert_eq!(vacant.occupied, 0);
        assert_eq!(
            vacant.phase_count(InstancePhase::Vacant),
            MAX_INSTANCE_SLOTS
        );
        assert_eq!(vacant.header_mismatches, 0);

        let replacement = registry.reserve(domain(48_002)).unwrap();
        assert!(token.shares_stable_slot(replacement));
        let replacement_probe = registry.acceptance_probe(replacement).unwrap();
        let stale_probe = registry.acceptance_probe(token).unwrap();
        assert!(replacement_probe.is_exact());
        assert_eq!(replacement_probe.current_phase(), InstancePhase::Reserved);
        assert!(!stale_probe.is_exact());
        assert_eq!(stale_probe.exact_phase(), None);
        assert_eq!(stale_probe.current_phase(), InstancePhase::Reserved);
        assert_eq!(
            stale_probe.current_generation(),
            replacement_probe.current_generation()
        );
        assert!(stale_probe.same_space_object(replacement_probe));
        assert!(stale_probe.same_cspace_lock(replacement_probe));
        assert!(stale_probe.same_cspace_identity(replacement_probe));
        assert!(stale_probe.same_cspace_incarnation(replacement_probe));
        assert!(stale_probe.same_capability_table(replacement_probe));
    }

    struct TestPayload {
        ready: Option<u64>,
    }

    // Safety: in normal mode the test payload neither retains its borrowed
    // Space/Context nor exports arena ownership, and its destructor performs
    // one bounded atomic increment.  One dedicated test enables an injected
    // panic solely so the host fault guard can model a non-returning target
    // fault after PayloadDropping publication; that unwind is not treated as
    // a conforming production InstancePayload destructor.
    unsafe impl InstancePayload for TestPayload {
        fn poll_quantum(
            &mut self,
            _space: &InstanceSpace,
            _context: &mut Context<'_>,
        ) -> Poll<u64> {
            TEST_PAYLOAD_POLLS.fetch_add(1, AtomicOrdering::SeqCst);
            match self.ready {
                Some(completion) => Poll::Ready(completion),
                None => Poll::Pending,
            }
        }
    }

    impl Drop for TestPayload {
        fn drop(&mut self) {
            TEST_PAYLOAD_DROPS.fetch_add(1, AtomicOrdering::SeqCst);
            if TEST_PAYLOAD_DROP_FAULT.swap(false, AtomicOrdering::SeqCst) {
                panic!("injected managed payload Drop fault");
            }
        }
    }

    struct TestContinuationPayload {
        token: InstanceToken,
        kind: InstanceContinuationKind,
        continuation: Option<InstanceContinuation<'static>>,
        completion: u64,
    }

    // Safety: the only state retained across polls is the opaque instance
    // token and a non-owning continuation listener into the SYSTEM registry.
    // No Space, CSpace guard, resource, or arena-backed reference escapes.
    unsafe impl InstancePayload for TestContinuationPayload {
        fn poll_quantum(&mut self, _space: &InstanceSpace, context: &mut Context<'_>) -> Poll<u64> {
            if self.continuation.is_none() {
                let pointer = TEST_REGISTRY.load(AtomicOrdering::Acquire);
                assert!(
                    !pointer.is_null(),
                    "continuation payload registry is absent"
                );
                // Safety: every caller retains the executor-serialized stack
                // registry until the managed task is terminal and finalized.
                let registry: &'static InstanceRegistry = unsafe { &*pointer };
                let operation = registry
                    .arm_continuation_current(self.token, self.kind)
                    .expect("continuation payload could not arm its exact operation");
                *TEST_CONTINUATION_TOKEN
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(operation);
                self.continuation = Some(
                    registry
                        .wait_continuation(operation)
                        .expect("continuation payload could not construct its listener"),
                );
            }
            let continuation = self
                .continuation
                .as_mut()
                .expect("continuation payload lost its armed future");
            let operation = continuation.token;
            match Pin::new(&mut *continuation).poll(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(consumed)) => {
                    assert!(consumed.matches_token(operation));
                    assert_eq!(consumed.token(), operation);
                    drop(self.continuation.take());
                    Poll::Ready(self.completion)
                }
                Poll::Ready(Err(error)) => {
                    panic!("continuation payload was quarantined: {error:?}")
                }
            }
        }
    }

    impl Drop for TestContinuationPayload {
        fn drop(&mut self) {
            let operation = self
                .continuation
                .as_ref()
                .map(|continuation| continuation.token);
            drop(self.continuation.take());
            if let Some(operation) = operation {
                let pointer = TEST_REGISTRY.load(AtomicOrdering::Acquire);
                assert!(
                    !pointer.is_null(),
                    "continuation payload registry is absent during Drop"
                );
                // Safety: the serialized test retains the registry until the
                // managed payload has completed its exact Drop transaction.
                let registry: &'static InstanceRegistry = unsafe { &*pointer };
                let cancelled = registry
                    .confirm_cancelled_continuation_current(operation)
                    .expect("payload Drop did not expose its exact cancellation receipt");
                assert!(cancelled.matches_token(operation));
                assert_eq!(cancelled.token(), operation);
                assert_eq!(
                    format!("{cancelled:?}"),
                    "InstanceContinuationCancelled(<opaque>)"
                );
                *TEST_CONTINUATION_CANCELLED
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(cancelled);
            }
            TEST_CONTINUATION_PAYLOAD_DROPS.fetch_add(1, AtomicOrdering::SeqCst);
            if TEST_PAYLOAD_DROP_FAULT.swap(false, AtomicOrdering::SeqCst) {
                panic!("injected continuation payload Drop fault");
            }
        }
    }

    unsafe fn reject_unexpected_fault(_: ReclaimableFaultWitness) -> FaultReclaimOutcome {
        FaultReclaimOutcome::Quarantined
    }

    unsafe fn capture_fault_witness(witness: ReclaimableFaultWitness) -> FaultReclaimOutcome {
        *TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(witness);
        // Deliberately do not enter the registry.  The executor still
        // quarantines its scheduler record, while the test retains the exact
        // pre-reclaim Active registry projection for mismatch injection.
        FaultReclaimOutcome::Quarantined
    }

    fn pass_fault_guard(operation: &mut dyn FnMut()) -> bool {
        operation();
        false
    }

    fn fault_next_guard(operation: &mut dyn FnMut()) -> bool {
        if TEST_FAULT_NEXT.swap(false, AtomicOrdering::SeqCst) {
            true
        } else {
            operation();
            false
        }
    }

    fn catch_payload_drop_fault_guard(operation: &mut dyn FnMut()) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| operation())).is_err()
    }

    fn fault_after_payload_poll_guard(operation: &mut dyn FnMut()) -> bool {
        operation();
        true
    }

    unsafe fn reclaim_test_instance(witness: ReclaimableFaultWitness) -> FaultReclaimOutcome {
        *TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(witness);
        let registry = TEST_REGISTRY.load(AtomicOrdering::Acquire);
        assert!(!registry.is_null(), "registry fault test pointer is absent");
        // Safety: every caller holds EXECUTOR_SERIAL and retains the pointed-to
        // stack registry until polling and any explicit replay have returned.
        match unsafe {
            (&*registry).fault_reclaim(witness, |_| {
                TEST_RAW_RECLAIMS.fetch_add(1, AtomicOrdering::SeqCst);
                TEST_RECLAIM_SUCCEEDS.load(AtomicOrdering::Acquire)
            })
        } {
            FaultGateOutcome::ManagedReclaimed => FaultReclaimOutcome::Reclaimed,
            FaultGateOutcome::NotManaged | FaultGateOutcome::Quarantined => {
                FaultReclaimOutcome::Quarantined
            }
        }
    }

    fn executor() -> MutexGuard<'static, ()> {
        let guard = exec::EXECUTOR_TEST_SERIAL
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        crate::arch::set_test_hart_id(0);
        exec::run_until_idle(1_024);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        TEST_FAULT_NEXT.store(false, AtomicOrdering::SeqCst);
        TEST_RECLAIM_SUCCEEDS.store(true, AtomicOrdering::SeqCst);
        TEST_RAW_RECLAIMS.store(0, AtomicOrdering::SeqCst);
        TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        TEST_TASK_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        TEST_PAYLOAD_POLLS.store(0, AtomicOrdering::SeqCst);
        TEST_PAYLOAD_DROPS.store(0, AtomicOrdering::SeqCst);
        TEST_PAYLOAD_COMPLETION.store(u64::MAX, AtomicOrdering::SeqCst);
        TEST_PAYLOAD_DROP_FAULT.store(false, AtomicOrdering::SeqCst);
        TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        TEST_CONTINUATION_BEFORE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        TEST_CONTINUATION_AFTER
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        TEST_CONTINUATION_STAGE.store(0, AtomicOrdering::SeqCst);
        TEST_CONTINUATION_BUSY.store(false, AtomicOrdering::SeqCst);
        TEST_CONTINUATION_PAYLOAD_DROPS.store(0, AtomicOrdering::SeqCst);
        TEST_CONTINUATION_CANCELLED
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        guard
    }

    fn domain(index: u64) -> AllocationDomain {
        AllocationDomain::new(OwnerId::new(10_000 + index), ArenaId::new(20_000 + index))
    }

    fn retained_space_count(registry: &InstanceRegistry) -> usize {
        registry
            .slots
            .iter()
            .filter(|slot| slot.record.lock().space.is_some())
            .count()
    }

    fn assert_pristine_registry(registry: &InstanceRegistry) {
        let stats = registry.occupancy_stats();
        assert_eq!(stats.occupied, 0);
        assert_eq!(stats.header_mismatches, 0);
        assert_eq!(
            stats.phase_count(InstancePhase::Vacant),
            MAX_COMPONENT_INSTANCES
        );
        assert_eq!(retained_space_count(registry), 0);
        for slot in &registry.slots {
            let record = slot.record.lock();
            assert_eq!(record.generation, 0);
            assert!(InstanceRegistry::vacant_record_is_pristine(slot, &record));
        }
    }

    fn publish_pending_managed(
        registry: &InstanceRegistry,
        token: InstanceToken,
        allocation: AllocationDomain,
        name: &str,
    ) -> TaskHandle {
        let mut batch = PreparedTaskBatch::new();
        // Safety: the future captures only its opaque non-owning token.  The
        // exact registry binding and activation complete before publication.
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, name, async move {
                let _ = token;
                core::future::pending::<()>().await;
            });
        }
        let prepared = batch.prepared_handles()[0].clone();
        let binding = batch.prepared_reclaimable_bindings()[0];
        registry.bind(token, binding, &prepared).unwrap();
        let handles = unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap();
        handles
            .into_iter()
            .next()
            .expect("managed publication returned no task handle")
    }

    fn publish_continuation_managed(
        registry: &InstanceRegistry,
        token: InstanceToken,
        allocation: AllocationDomain,
        name: &str,
        kind: InstanceContinuationKind,
    ) -> TaskHandle {
        let mut batch = PreparedTaskBatch::new();
        // Safety: the task captures only copy tokens. The registry reference
        // is recovered from the test-static pointer after exact activation and
        // remains valid until this executor-serialized test finalizes it.
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, name, async move {
                let pointer = TEST_REGISTRY.load(AtomicOrdering::Acquire);
                assert!(!pointer.is_null(), "continuation test registry is absent");
                let registry: &'static InstanceRegistry = &*pointer;
                let before = exec::current_reclaimable_task_witness()
                    .expect("continuation task has no first-poll witness");
                *TEST_CONTINUATION_BEFORE
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(before);
                let operation = registry
                    .arm_continuation_current(token, kind)
                    .expect("exact continuation arm failed");
                *TEST_CONTINUATION_TOKEN
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(operation);
                TEST_CONTINUATION_BUSY.store(
                    registry.arm_continuation_current(token, kind)
                        == Err(InstanceContinuationError::Busy),
                    AtomicOrdering::SeqCst,
                );
                TEST_CONTINUATION_STAGE.store(1, AtomicOrdering::Release);
                let consumed = registry
                    .wait_continuation(operation)
                    .expect("exact continuation wait failed")
                    .await
                    .expect("exact continuation resume failed");
                assert!(consumed.matches_token(operation));
                assert_eq!(consumed.token(), operation);
                assert!(!consumed.matches_token(InstanceContinuationToken {
                    instance: token,
                    generation: operation.generation ^ 1,
                }));
                assert_eq!(
                    format!("{consumed:?}"),
                    "InstanceContinuationConsumed(<opaque>)"
                );
                let after = exec::current_reclaimable_task_witness()
                    .expect("continuation task has no resume witness");
                *TEST_CONTINUATION_AFTER
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(after);
                TEST_CONTINUATION_STAGE.store(2, AtomicOrdering::Release);
            });
        }
        let prepared = batch.prepared_handles()[0].clone();
        let binding = batch.prepared_reclaimable_bindings()[0];
        registry.bind(token, binding, &prepared).unwrap();
        unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap()
        .remove(0)
    }

    unsafe fn install_test_payload(
        registry: &InstanceRegistry,
        token: InstanceToken,
        ready: Option<u64>,
    ) {
        // Safety: TestPayload obeys the no-escape contract and construction is
        // allocation-free apart from the registry-owned box itself.
        unsafe {
            registry
                .install_payload(token, || TestPayload { ready })
                .unwrap();
        }
    }

    unsafe fn install_continuation_payload(
        registry: &InstanceRegistry,
        token: InstanceToken,
        kind: InstanceContinuationKind,
        completion: u64,
    ) {
        // Safety: TestContinuationPayload obeys the registry's non-owning
        // continuation and arena no-escape contract.
        unsafe {
            registry
                .install_payload(token, || TestContinuationPayload {
                    token,
                    kind,
                    continuation: None,
                    completion,
                })
                .unwrap();
        }
    }

    fn publish_payload_managed(
        registry: &InstanceRegistry,
        token: InstanceToken,
        allocation: AllocationDomain,
        name: &str,
    ) -> TaskHandle {
        let mut batch = PreparedTaskBatch::new();
        // Safety: the executor future retains only the opaque token.  Every
        // payload access reacquires a current-poll witness and routes through
        // the registry's exact gate.
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, name, async move {
                let completion = core::future::poll_fn(|context| {
                    let witness = exec::current_reclaimable_task_witness()
                        .expect("payload task poll has no reclaimable witness");
                    assert_eq!(witness.instance_token(), Some(token));
                    let registry = TEST_REGISTRY.load(AtomicOrdering::Acquire);
                    assert!(!registry.is_null(), "payload test registry is absent");
                    // Safety: this call remains in the current child poll and
                    // behind the executor test fault guard.
                    (&*registry)
                        .poll_payload(witness, context)
                        .expect("exact payload poll was rejected")
                })
                .await;
                TEST_PAYLOAD_COMPLETION.store(completion, AtomicOrdering::SeqCst);
            });
        }
        let prepared = batch.prepared_handles()[0].clone();
        let binding = batch.prepared_reclaimable_bindings()[0];
        registry.bind(token, binding, &prepared).unwrap();
        let handles = unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap();
        handles
            .into_iter()
            .next()
            .expect("payload publication returned no task handle")
    }

    fn cspace_incarnation(registry: &InstanceRegistry, token: InstanceToken) -> u64 {
        let _transaction = registry.transaction.lock();
        let record = registry.slot(token).unwrap().record.lock();
        let incarnation = record
            .space
            .as_deref()
            .expect("reserved slot lost its stable Space")
            .cspace()
            .lock()
            .incarnation();
        incarnation
    }

    #[derive(Clone, Copy)]
    struct TestRecordProjection {
        space_seal: InstanceSpaceSeal,
        home_hart: HartId,
        scheduler: ReclaimableSchedulerIdentity,
    }

    fn record_projection(
        registry: &InstanceRegistry,
        token: InstanceToken,
    ) -> TestRecordProjection {
        let _transaction = registry.transaction.lock();
        let record = registry.slot(token).unwrap().record.lock();
        TestRecordProjection {
            space_seal: record
                .space_seal
                .expect("active test record lost its Space seal"),
            home_hart: record
                .home_hart
                .expect("active test record lost its home hart"),
            scheduler: record
                .scheduler
                .expect("active test record lost its scheduler identity"),
        }
    }

    fn cspace_state(
        registry: &InstanceRegistry,
        token: InstanceToken,
    ) -> (CSpaceIdentity, u64, usize) {
        let _transaction = registry.transaction.lock();
        let record = registry.slot(token).unwrap().record.lock();
        let cspace = record
            .space
            .as_deref()
            .expect("active test record lost its stable Space")
            .cspace()
            .lock();
        (cspace.identity(), cspace.incarnation(), cspace.list().len())
    }

    fn restore_active_projection_for_test(
        registry: &InstanceRegistry,
        token: InstanceToken,
        projection: TestRecordProjection,
    ) {
        // Production quarantine is deliberately irreversible.  This direct
        // record repair exists only to exercise every independent gate with
        // one executor-minted witness and one stable Space allocation.
        let _transaction = registry.transaction.lock();
        let slot = registry.slot(token).unwrap();
        let mut record = slot.record.lock();
        record.phase = InstancePhase::Active;
        record.space_seal = Some(projection.space_seal);
        record.home_hart = Some(projection.home_hart);
        record.scheduler = Some(projection.scheduler);
        record.continuation.retire();
        InstanceRegistry::publish_header(slot, &record);
    }

    fn restore_continuation_projection_for_test(
        registry: &InstanceRegistry,
        token: InstanceToken,
        projection: TestRecordProjection,
        continuation: ContinuationRecord,
    ) {
        let _transaction = registry.transaction.lock();
        let slot = registry.slot(token).unwrap();
        let mut record = slot.record.lock();
        record.phase = InstancePhase::Active;
        record.space_seal = Some(projection.space_seal);
        record.home_hart = Some(projection.home_hart);
        record.scheduler = Some(projection.scheduler);
        record.continuation = continuation;
        InstanceRegistry::publish_header(slot, &record);
    }

    fn install_space_seal_for_test(
        registry: &InstanceRegistry,
        token: InstanceToken,
        seal: InstanceSpaceSeal,
    ) {
        let _transaction = registry.transaction.lock();
        let slot = registry.slot(token).unwrap();
        let mut record = slot.record.lock();
        record.space_seal = Some(seal);
        InstanceRegistry::publish_header(slot, &record);
    }

    fn mutate_active_record_for_test(
        registry: &InstanceRegistry,
        token: InstanceToken,
        mutate: impl FnOnce(&mut SlotRecord),
    ) {
        let _transaction = registry.transaction.lock();
        let slot = registry.slot(token).unwrap();
        let mut record = slot.record.lock();
        assert_eq!(record.phase, InstancePhase::Active);
        mutate(&mut record);
        InstanceRegistry::publish_header(slot, &record);
    }

    fn assert_fault_mismatch_is_inert(
        registry: &InstanceRegistry,
        token: InstanceToken,
        witness: ReclaimableFaultWitness,
        projection: TestRecordProjection,
        expected_cspace: (CSpaceIdentity, u64, usize),
        case: &str,
    ) {
        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(witness, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined,
            "{case} mismatch was not quarantined"
        );
        assert_eq!(raw_calls, 0, "{case} mismatch reached raw reclaim");
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined,
            "{case} mismatch did not publish sticky quarantine"
        );
        assert_eq!(
            cspace_state(registry, token),
            expected_cspace,
            "{case} mismatch changed CSpace identity/incarnation/list"
        );
        restore_active_projection_for_test(registry, token, projection);
    }

    fn assert_finalize_mismatch_is_inert(
        registry: &InstanceRegistry,
        token: InstanceToken,
        handle: &TaskHandle,
        projection: TestRecordProjection,
        expected_cspace: (CSpaceIdentity, u64, usize),
        case: &str,
    ) {
        let mut close_calls = 0;
        assert_eq!(
            unsafe {
                registry.finalize(token, handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::IdentityMismatch),
            "{case} mismatch was not rejected"
        );
        assert_eq!(close_calls, 0, "{case} mismatch reached arena close");
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined,
            "{case} mismatch did not publish sticky quarantine"
        );
        assert_eq!(
            cspace_state(registry, token),
            expected_cspace,
            "{case} mismatch changed CSpace identity/incarnation/list"
        );
        restore_active_projection_for_test(registry, token, projection);
    }

    fn assert_continuation_fault_mismatch_is_inert(
        registry: &InstanceRegistry,
        token: InstanceToken,
        witness: ReclaimableFaultWitness,
        projection: TestRecordProjection,
        continuation: ContinuationRecord,
        expected_cspace: (CSpaceIdentity, u64, usize),
        mutate: impl FnOnce(&mut ContinuationRecord),
    ) {
        mutate_active_record_for_test(registry, token, |record| mutate(&mut record.continuation));
        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(witness, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(raw_calls, 0, "continuation mismatch authorized raw reclaim");
        assert_eq!(cspace_state(registry, token), expected_cspace);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            0
        );
        restore_continuation_projection_for_test(registry, token, projection, continuation);
    }

    #[test]
    fn external_continuation_parks_without_spinning_and_resumes_on_exact_task_hart() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(52_001);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_continuation_managed(
            &registry,
            token,
            allocation,
            "external-continuation",
            InstanceContinuationKind::External,
        );

        assert!(exec::poll_once());
        assert_eq!(TEST_CONTINUATION_STAGE.load(AtomicOrdering::Acquire), 1);
        assert!(TEST_CONTINUATION_BUSY.load(AtomicOrdering::Acquire));
        assert_eq!(handle.polls(), 1);
        assert_eq!(handle.owned_registration_count_for_test(), 1);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            1
        );
        assert_eq!(
            cspace_incarnation(&registry, token),
            incarnation,
            "suspension retained a registry or CSpace lock"
        );
        for _ in 0..8 {
            assert!(!exec::poll_once(), "parked continuation remained runnable");
        }
        assert_eq!(handle.polls(), 1, "idle executor repolled a parked task");

        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("external continuation did not publish its opaque token");
        let words = operation.signal_words();
        let mut corrupt_tag = words;
        corrupt_tag[3] ^= 1;
        assert_eq!(
            registry.signal_continuation_words(corrupt_tag),
            InstanceContinuationSignal::Stale
        );
        let mut stale_operation_words = words;
        stale_operation_words[2] = stale_operation_words[2].checked_add(1).unwrap();
        stale_operation_words[3] = continuation_signal_tag(
            stale_operation_words[0],
            stale_operation_words[1],
            stale_operation_words[2],
        );
        assert_eq!(
            registry.signal_continuation_words(stale_operation_words),
            InstanceContinuationSignal::Stale
        );
        let forged = InstanceContinuationToken {
            instance: token,
            generation: operation.generation + 1,
        };
        assert_eq!(
            registry.signal_continuation(forged),
            InstanceContinuationSignal::Stale
        );
        assert_eq!(handle.polls(), 1);

        let projection = record_projection(&registry, token);
        let continuation = registry.slot(token).unwrap().record.lock().continuation;
        mutate_active_record_for_test(&registry, token, |record| {
            record.continuation.phase = ContinuationPhase::Consumed;
        });
        match registry.signal_continuation(operation) {
            InstanceContinuationSignal::AlreadyConsumed(consumed) => {
                assert!(consumed.matches_token(operation));
                assert_eq!(consumed.token(), operation);
                assert_eq!(
                    format!("{consumed:?}"),
                    "InstanceContinuationConsumed(<opaque>)"
                );
            }
            other => panic!("consumed continuation did not return an exact receipt: {other:?}"),
        }
        mutate_active_record_for_test(&registry, token, |record| {
            let generation = record
                .continuation
                .generation
                .checked_add(1)
                .expect("continuation generation exhausted in directed stale-token test");
            record.continuation.generation = generation;
            record
                .continuation
                .seal
                .as_mut()
                .expect("consumed continuation lost its exact seal")
                .operation_generation = generation;
        });
        let successor = registry.slot(token).unwrap().record.lock().continuation;
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale,
            "an older operation generation must not receive the current consumed receipt"
        );
        assert_eq!(
            registry.slot(token).unwrap().record.lock().continuation,
            successor,
            "a stale signal must be inert for the exact current continuation"
        );
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            1,
            "consumption proof must not detach or wake the parked listener"
        );
        restore_continuation_projection_for_test(&registry, token, projection, continuation);

        mutate_active_record_for_test(&registry, token, |record| {
            record.phase = InstancePhase::PayloadDropping;
        });
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale,
            "completion racing payload tombstone must not quarantine or detach its waiter"
        );
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            1
        );
        restore_continuation_projection_for_test(&registry, token, projection, continuation);

        crate::arch::set_test_hart_id(1);
        assert_eq!(
            registry.signal_continuation_words(words),
            InstanceContinuationSignal::Signalled
        );
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::AlreadySignalled
        );
        assert!(
            !exec::poll_once(),
            "a remote hart polled a pinned continuation"
        );
        crate::arch::set_test_hart_id(0);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(handle.polls(), 2);
        assert_eq!(TEST_CONTINUATION_STAGE.load(AtomicOrdering::Acquire), 2);
        assert_eq!(handle.owned_registration_count_for_test(), 0);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            0
        );
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale
        );

        let before = TEST_CONTINUATION_BEFORE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("first continuation witness is absent");
        let after = TEST_CONTINUATION_AFTER
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("resume continuation witness is absent");
        assert_eq!(before.task_id(), after.task_id());
        assert_eq!(before.allocation_domain(), after.allocation_domain());
        assert_eq!(before.instance_token(), after.instance_token());
        assert_eq!(before.scheduler_identity(), after.scheduler_identity());
        assert_eq!(before.home_hart(), HartId::BOOT);
        assert_eq!(after.home_hart(), HartId::BOOT);
        assert_eq!(before.current_hart(), HartId::BOOT);
        assert_eq!(after.current_hart(), HartId::BOOT);

        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                assert_eq!(cspace_incarnation(&registry, token), incarnation);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn quantum_continuation_self_wakes_once_and_uses_two_exact_polls() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(52_002);
        let token = registry.reserve(allocation).unwrap();
        let handle = publish_continuation_managed(
            &registry,
            token,
            allocation,
            "quantum-continuation",
            InstanceContinuationKind::Quantum,
        );

        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Running);
        assert_eq!(handle.polls(), 1);
        assert_eq!(handle.owned_registration_count_for_test(), 1);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            0
        );
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(handle.polls(), 2);
        assert_eq!(handle.owned_registration_count_for_test(), 0);
        assert!(
            !exec::poll_once(),
            "quantum continuation self-woke more than once"
        );

        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("quantum continuation token is absent");
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale
        );
        unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                true
            })
        }
        .unwrap();
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn terminal_continuation_mismatch_never_retires_or_resets_cspace() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(52_009);
        let token = registry.reserve(allocation).unwrap();
        let handle = publish_continuation_managed(
            &registry,
            token,
            allocation,
            "continuation-terminal-mismatch",
            InstanceContinuationKind::External,
        );
        assert!(exec::poll_once());
        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("terminal mismatch operation is absent");
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Signalled
        );
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        let before = cspace_state(&registry, token);
        mutate_active_record_for_test(&registry, token, |record| {
            record.continuation.generation += 1;
        });
        let mut retire_calls = 0;
        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |_, _| {
                    retire_calls += 1;
                    true
                })
            },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(retire_calls, 0);
        assert_eq!(cspace_state(&registry, token), before);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn stale_continuation_cannot_wake_a_reused_instance_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );

        let first_domain = domain(52_003);
        let first = registry.reserve(first_domain).unwrap();
        let first_cspace = cspace_state(&registry, first);
        let first_handle = publish_continuation_managed(
            &registry,
            first,
            first_domain,
            "continuation-aba-first",
            InstanceContinuationKind::External,
        );
        assert!(exec::poll_once());
        let stale = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("first continuation token is absent");
        assert_eq!(
            registry.signal_continuation(stale),
            InstanceContinuationSignal::Signalled
        );
        assert!(exec::poll_once());
        unsafe { registry.finalize(first, &first_handle, |_, _| true) }.unwrap();

        TEST_CONTINUATION_STAGE.store(0, AtomicOrdering::Release);
        TEST_CONTINUATION_BUSY.store(false, AtomicOrdering::Release);
        TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        let replacement_domain = domain(52_004);
        let replacement = registry.reserve(replacement_domain).unwrap();
        assert!(first.shares_stable_slot(replacement));
        assert_ne!(first, replacement);
        let replacement_cspace = cspace_state(&registry, replacement);
        assert_eq!(replacement_cspace.0, first_cspace.0);
        assert_eq!(replacement_cspace.1, first_cspace.1 + 1);
        let replacement_handle = publish_continuation_managed(
            &registry,
            replacement,
            replacement_domain,
            "continuation-aba-replacement",
            InstanceContinuationKind::External,
        );
        assert!(exec::poll_once());
        let current = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("replacement continuation token is absent");
        assert_ne!(stale.generation, current.generation);
        let forged_old_operation = InstanceContinuationToken {
            instance: replacement,
            generation: stale.generation,
        };
        let before = cspace_state(&registry, replacement);
        assert_eq!(
            registry.signal_continuation_words(stale.signal_words()),
            InstanceContinuationSignal::Stale
        );
        assert_eq!(
            registry.signal_continuation(forged_old_operation),
            InstanceContinuationSignal::Stale
        );
        assert_eq!(replacement_handle.polls(), 1);
        assert_eq!(cspace_state(&registry, replacement), before);
        assert_eq!(
            registry
                .slot(replacement)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            1
        );

        assert_eq!(
            registry.signal_continuation(current),
            InstanceContinuationSignal::Signalled
        );
        assert!(exec::poll_once());
        assert_eq!(replacement_handle.state(), TaskState::Exited);
        unsafe { registry.finalize(replacement, &replacement_handle, |_, _| true) }.unwrap();
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn fault_detach_drains_a_parked_continuation_before_raw_reclaim_and_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_after_payload_poll_guard);
        let allocation = domain(52_005);
        let token = registry.reserve(allocation).unwrap();
        let before = cspace_state(&registry, token);
        let handle = publish_continuation_managed(
            &registry,
            token,
            allocation,
            "continuation-live-fault",
            InstanceContinuationKind::External,
        );

        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(handle.owned_registration_count_for_test(), 0);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::Acquire), 1);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            0
        );
        {
            let record = registry.slot(token).unwrap().record.lock();
            assert_eq!(record.phase, InstancePhase::FaultReclaimed);
            assert_eq!(record.continuation.phase, ContinuationPhase::Abandoned);
        }
        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("faulted continuation token is absent");
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale
        );
        assert_eq!(cspace_state(&registry, token), before);
        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                assert_eq!(cspace_state(&registry, token), before);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.next_cspace_incarnation, before.1 + 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn continuation_fault_gate_rejects_every_frozen_projection_mismatch() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_after_payload_poll_guard);
        let allocation = domain(52_008);
        let token = registry.reserve(allocation).unwrap();
        let expected_cspace = cspace_state(&registry, token);
        let handle = publish_continuation_managed(
            &registry,
            token,
            allocation,
            "continuation-fault-mismatch-matrix",
            InstanceContinuationKind::External,
        );
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(handle.owned_registration_count_for_test(), 0);
        let witness = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("continuation mismatch test lost its fault witness");
        let projection = record_projection(&registry, token);
        let continuation = registry.slot(token).unwrap().record.lock().continuation;
        assert_eq!(continuation.phase, ContinuationPhase::Armed);

        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.generation += 1,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.phase = ContinuationPhase::Idle,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.kind = Some(InstanceContinuationKind::Quantum),
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.kind = None,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal = None,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().operation_generation += 1,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().kind = InstanceContinuationKind::Quantum,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().instance.generation ^= 1,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| {
                let seal = record.seal.as_mut().unwrap();
                seal.task = TaskId(seal.task.0 + 1);
            },
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| {
                let seal = record.seal.as_mut().unwrap();
                seal.domain.owner = OwnerId::new(seal.domain.owner.get() + 1);
            },
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| {
                let seal = record.seal.as_mut().unwrap();
                seal.domain.arena = ArenaId::new(seal.domain.arena.get() + 1);
            },
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().home_hart = HartId::new(1).unwrap(),
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().space.object_identity ^= 1,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().space.lock_identity ^= 1,
        );
        assert_continuation_fault_mismatch_is_inert(
            &registry,
            token,
            witness,
            projection,
            continuation,
            expected_cspace,
            |record| record.seal.as_mut().unwrap().space.cspace_incarnation += 1,
        );

        mutate_active_record_for_test(&registry, token, |record| {
            record.space_seal.as_mut().unwrap().cspace_incarnation += 1;
        });
        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(witness, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(raw_calls, 0);
        assert_eq!(cspace_state(&registry, token), expected_cspace);
        restore_continuation_projection_for_test(&registry, token, projection, continuation);
        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("continuation receipt test lost its operation token");

        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim_with_space(witness, |reclaimed, _space, abandoned| {
                    assert_eq!(reclaimed, allocation);
                    assert!(abandoned.matches_exact(token, Some(operation)));
                    assert!(
                        !abandoned.matches_continuation(Some(InstanceContinuationToken {
                            instance: token,
                            generation: operation.generation ^ 1,
                        }))
                    );
                    assert_eq!(
                        format!("{abandoned:?}"),
                        "FaultContinuationAbandonReceipt(<opaque>)"
                    );
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::ManagedReclaimed
        );
        assert_eq!(raw_calls, 1);
        assert_eq!(cspace_state(&registry, token), expected_cspace);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .record
                .lock()
                .continuation
                .phase,
            ContinuationPhase::Abandoned
        );
        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.next_cspace_incarnation, expected_cspace.1 + 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn cooperative_cancel_drops_a_parked_payload_without_quarantine() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(52_006);
        let token = registry.reserve(allocation).unwrap();
        unsafe {
            install_continuation_payload(
                &registry,
                token,
                InstanceContinuationKind::External,
                0x52_006,
            )
        };
        let handle =
            publish_payload_managed(&registry, token, allocation, "continuation-cancel-payload");
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Running);
        assert_eq!(handle.polls(), 1);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            1
        );
        let operation = TEST_CONTINUATION_TOKEN
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("payload continuation token is absent");

        let task = match registry
            .request_cooperative_cancel(token, &handle, 0xCA_52)
            .unwrap()
        {
            CooperativeCancelOutcome::Requested(task) => task,
            CooperativeCancelOutcome::AlreadyCompleting => {
                panic!("parked payload unexpectedly completed before cancellation")
            }
        };
        exec::wake(task);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(
            TEST_PAYLOAD_COMPLETION.load(AtomicOrdering::Acquire),
            0xCA_52
        );
        assert_eq!(
            TEST_CONTINUATION_PAYLOAD_DROPS.load(AtomicOrdering::Acquire),
            1
        );
        let cancelled = TEST_CONTINUATION_CANCELLED
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("payload Drop did not retain its cancellation receipt");
        assert!(cancelled.matches_token(operation));
        assert!(!cancelled.matches_token(InstanceContinuationToken {
            instance: token,
            generation: operation.generation ^ 1,
        }));
        assert_eq!(handle.owned_registration_count_for_test(), 0);
        assert_eq!(
            registry
                .slot(token)
                .unwrap()
                .continuation_wait
                .waiter_count(),
            0
        );
        {
            let record = registry.slot(token).unwrap().record.lock();
            assert_eq!(record.phase, InstancePhase::PayloadDropped);
            assert_eq!(record.continuation.phase, ContinuationPhase::Cancelled);
        }
        assert_eq!(
            registry.signal_continuation(operation),
            InstanceContinuationSignal::Stale
        );
        let finalized = unsafe { registry.finalize(token, &handle, |_, _| true) }.unwrap();
        assert_eq!(finalized.detached_completion, Some(0xCA_52));
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn consumed_continuation_survives_payload_drop_fault_without_second_drop() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(catch_payload_drop_fault_guard);
        let allocation = domain(52_007);
        let token = registry.reserve(allocation).unwrap();
        unsafe {
            install_continuation_payload(
                &registry,
                token,
                InstanceContinuationKind::Quantum,
                0x52_007,
            )
        };
        let handle = publish_payload_managed(
            &registry,
            token,
            allocation,
            "continuation-consumed-drop-fault",
        );
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Running);
        TEST_PAYLOAD_DROP_FAULT.store(true, AtomicOrdering::Release);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(
            TEST_CONTINUATION_PAYLOAD_DROPS.load(AtomicOrdering::Acquire),
            1
        );
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::Acquire), 1);
        {
            let record = registry.slot(token).unwrap().record.lock();
            assert_eq!(record.phase, InstancePhase::FaultReclaimed);
            assert_eq!(record.continuation.phase, ContinuationPhase::Abandoned);
            assert!(record.payload.is_none());
            assert!(record.payload_abandoned);
        }
        unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                true
            })
        }
        .unwrap();
        assert_eq!(
            TEST_CONTINUATION_PAYLOAD_DROPS.load(AtomicOrdering::Acquire),
            1
        );
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fixed_table_never_allocates_a_seventeenth_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        for index in 0..MAX_INSTANCE_SLOTS {
            let token = registry.reserve(domain(index as u64)).unwrap();
            assert_eq!(
                registry.snapshot(token).unwrap().phase,
                InstancePhase::Reserved
            );
        }
        assert_eq!(registry.reserve(domain(99)), Err(ReserveError::Capacity));
    }

    #[test]
    fn only_non_system_tracked_domains_are_admitted() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        assert_eq!(
            registry.reserve(AllocationDomain::untracked(OwnerId::new(7))),
            Err(ReserveError::InvalidDomain)
        );
        assert_eq!(
            registry.reserve(AllocationDomain::new(OwnerId::SYSTEM, ArenaId::new(8))),
            Err(ReserveError::InvalidDomain)
        );
    }

    #[test]
    fn structural_observation_checks_status_domain_and_space_without_touching_cspace() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(7);
        let token = registry.reserve(allocation).unwrap();
        let handle = publish_pending_managed(
            &registry,
            token,
            allocation,
            "managed-structural-observation",
        );
        let expected_cspace = cspace_state(&registry, token);

        assert_eq!(
            registry.observe_structural(token, &handle),
            Ok(InstanceSnapshot {
                phase: InstancePhase::Active,
                domain: allocation,
                task: Some(handle.id()),
                home_hart: Some(HartId::BOOT),
            })
        );
        assert_eq!(cspace_state(&registry, token), expected_cspace);

        mutate_active_record_for_test(&registry, token, |record| {
            record
                .space_seal
                .as_mut()
                .expect("active observation record lost its Space seal")
                .object_identity ^= 1;
        });
        assert_eq!(
            registry.observe_structural(token, &handle),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, token), expected_cspace);
        assert_eq!(handle.cancel(), crate::exec::CancelOutcome::Requested);
    }

    #[test]
    fn structural_observation_rejects_a_different_status_handle_without_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let first_domain = domain(70);
        let second_domain = domain(71);
        let first = registry.reserve(first_domain).unwrap();
        let second = registry.reserve(second_domain).unwrap();
        let first_handle =
            publish_pending_managed(&registry, first, first_domain, "managed-observe-first");
        let second_handle =
            publish_pending_managed(&registry, second, second_domain, "managed-observe-second");
        let first_cspace = cspace_state(&registry, first);
        let second_cspace = cspace_state(&registry, second);
        assert!(registry.quarantine(first));

        assert_eq!(
            registry.observe_structural(first, &second_handle),
            Err(RegistryError::IdentityMismatch),
            "an already-quarantined addressed slot must not hide the live handle alias"
        );
        assert_eq!(
            registry.slot(first).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry.slot(second).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, first), first_cspace);
        assert_eq!(cspace_state(&registry, second), second_cspace);
        assert_eq!(first_handle.cancel(), crate::exec::CancelOutcome::Requested);
        assert_eq!(
            second_handle.cancel(),
            crate::exec::CancelOutcome::Requested
        );
    }

    #[test]
    fn cooperative_cancel_mismatched_handle_quarantines_both_without_cspace_change() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let first_domain = domain(72);
        let second_domain = domain(73);
        let first = registry.reserve(first_domain).unwrap();
        let second = registry.reserve(second_domain).unwrap();
        let first_handle =
            publish_pending_managed(&registry, first, first_domain, "managed-cancel-first");
        let second_handle =
            publish_pending_managed(&registry, second, second_domain, "managed-cancel-second");
        let first_cspace = cspace_state(&registry, first);
        let second_cspace = cspace_state(&registry, second);

        assert_eq!(
            registry.request_cooperative_cancel(first, &second_handle, 0xcafe),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(
            registry.slot(first).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry.slot(second).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, first), first_cspace);
        assert_eq!(cspace_state(&registry, second), second_cspace);
        assert_eq!(first_handle.cancel(), crate::exec::CancelOutcome::Requested);
        assert_eq!(
            second_handle.cancel(),
            crate::exec::CancelOutcome::Requested
        );
    }

    #[test]
    fn one_arena_cannot_be_registered_again_under_a_different_owner() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let first_domain = domain(8);
        let first = registry.reserve(first_domain).unwrap();
        let owner_alias = AllocationDomain::new(OwnerId::new(99_999), first_domain.arena);

        assert_eq!(
            registry.reserve(owner_alias),
            Err(ReserveError::ArenaConflict)
        );
        assert_eq!(
            registry.snapshot(first).unwrap().phase,
            InstancePhase::Reserved
        );
    }

    #[test]
    fn corrupt_header_cannot_hide_a_retained_arena_from_duplicate_scan() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let first_domain = domain(10);
        let first = registry.reserve(first_domain).unwrap();
        let mut batch = PreparedTaskBatch::new();
        // Safety: the task remains unpublished.  Binding makes the retained
        // task/domain projection realistic before publication corruption is
        // injected into the registry header.
        unsafe {
            batch.prepare_managed_instance_owned(first, first_domain, "header-alias", async move {
                let _ = first;
                core::future::pending::<()>().await;
            });
        }
        registry
            .bind(
                first,
                batch.prepared_reclaimable_bindings()[0],
                &batch.prepared_handles()[0],
            )
            .unwrap();

        let slot = registry.slot(first).unwrap();
        slot.header.store(0, Ordering::Release);
        let owner_alias = AllocationDomain::new(
            OwnerId::new(first_domain.owner.get() + 1),
            first_domain.arena,
        );
        assert_eq!(
            registry.reserve(owner_alias),
            Err(ReserveError::ArenaConflict)
        );
        assert_eq!(
            registry.reserve(first_domain),
            Err(ReserveError::ArenaConflict)
        );
        assert_eq!(slot.record.lock().phase, InstancePhase::Quarantined);

        let retained_domains = registry
            .slots
            .iter()
            .filter(|candidate| candidate.record.lock().domain.is_some())
            .count();
        let retained_spaces = registry
            .slots
            .iter()
            .filter(|candidate| candidate.record.lock().space.is_some())
            .count();
        assert_eq!(retained_domains, 1);
        assert_eq!(retained_spaces, 1);
    }

    #[test]
    fn reserve_checks_bound_task_and_prepared_domains_when_record_domain_disagrees() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let retained_domain = domain(11);
        let token = registry.reserve(retained_domain).unwrap();
        let mut batch = PreparedTaskBatch::new();
        // Safety: the task remains unpublished and the Bound slot retains all
        // three independently inspectable domain projections.
        unsafe {
            batch.prepare_managed_instance_owned(
                token,
                retained_domain,
                "reserve-projection-alias",
                async move {
                    let _ = token;
                    core::future::pending::<()>().await;
                },
            );
        }
        registry
            .bind(
                token,
                batch.prepared_reclaimable_bindings()[0],
                &batch.prepared_handles()[0],
            )
            .unwrap();
        let expected_cspace = cspace_state(&registry, token);

        // Keep the atomic header valid while corrupting only the primary
        // record projection.  The retained task and prepared binding continue
        // to name `retained_domain` and must block a duplicate reservation.
        {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(token).unwrap();
            let mut record = slot.record.lock();
            assert_eq!(record.phase, InstancePhase::Bound);
            record.domain = Some(domain(12));
            InstanceRegistry::publish_header(slot, &record);
            assert!(InstanceRegistry::header_matches(slot, &record));
        }

        let owner_alias = AllocationDomain::new(
            OwnerId::new(retained_domain.owner.get() + 1),
            retained_domain.arena,
        );
        assert_eq!(
            registry.reserve(owner_alias),
            Err(ReserveError::ArenaConflict)
        );
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, token), expected_cspace);

        let retained_records = registry
            .slots
            .iter()
            .filter(|slot| {
                let record = slot.record.lock();
                InstanceRegistry::projected_domains(&record)
                    .iter()
                    .any(Option::is_some)
            })
            .count();
        let retained_spaces = registry
            .slots
            .iter()
            .filter(|slot| slot.record.lock().space.is_some())
            .count();
        assert_eq!(retained_records, 1);
        assert_eq!(retained_spaces, 1);
    }

    #[test]
    fn token_loss_with_an_arena_owner_alias_quarantines_without_legacy_reclaim() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let registered_domain = domain(9);
        let token = registry.reserve(registered_domain).unwrap();
        let before = registry
            .slot(token)
            .unwrap()
            .record
            .lock()
            .space_seal
            .unwrap();
        let aliased_domain = AllocationDomain::new(
            OwnerId::new(registered_domain.owner.get() + 1),
            registered_domain.arena,
        );
        let witness =
            exec::reclaimable_fault_witness_for_test(None, TaskId(88_001), aliased_domain);
        let mut reclaims = 0;

        assert_eq!(
            unsafe {
                registry.fault_reclaim(witness, |_| {
                    reclaims += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(reclaims, 0);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert_eq!(record.space_seal, Some(before));
        let cspace = record.space.as_deref().unwrap().cspace().lock();
        assert_eq!(cspace.identity(), before.cspace_identity);
        assert_eq!(cspace.incarnation(), before.cspace_incarnation);
    }

    #[test]
    fn stale_generation_quarantines_the_new_occupant_without_aliasing_it() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let stale = registry.reserve(domain(1)).unwrap();

        // Emulate the already-tested exact terminal/reset boundary locally so
        // this unit test can focus on the registry's generation ABA seal
        // without constructing an executor task.
        {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(stale).unwrap();
            let mut record = slot.record.lock();
            let seal = record.space_seal.unwrap();
            record
                .space
                .as_deref()
                .unwrap()
                .cspace()
                .lock()
                .reset_exact(seal.cspace_identity, seal.cspace_incarnation)
                .unwrap();
            assert!(record.generation < MAX_INSTANCE_GENERATION);
            record.retire_after_reset();
            InstanceRegistry::publish_header(slot, &record);
        }
        let current = registry.reserve(domain(2)).unwrap();
        assert_ne!(stale, current);

        assert_eq!(
            registry.snapshot(stale),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(registry.snapshot(current), Err(RegistryError::Quarantined));
    }

    #[test]
    fn atomic_header_mismatch_is_sticky_quarantine() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let token = registry.reserve(domain(3)).unwrap();
        let slot = registry.slot(token).unwrap();
        slot.header.store(0, Ordering::Release);

        assert_eq!(
            registry.snapshot(token),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(slot.record.lock().phase, InstancePhase::Quarantined);
        assert_eq!(
            slot.header.load(Ordering::Acquire),
            encode_header(token.generation, InstancePhase::Quarantined)
        );
    }

    #[test]
    fn explicit_quarantine_never_vacates_or_resets_the_space() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let token = registry.reserve(domain(4)).unwrap();
        let slot = registry.slot(token).unwrap();
        let before = slot.record.lock().space_seal.unwrap();

        assert!(registry.quarantine(token));
        let record = slot.record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert_eq!(record.space_seal, Some(before));
        let cspace = record.space.as_deref().unwrap().cspace().lock();
        assert_eq!(cspace.identity(), before.cspace_identity);
        assert_eq!(cspace.incarnation(), before.cspace_incarnation);
    }

    #[test]
    fn real_terminal_lifecycle_resets_once_then_invalidates_the_old_token() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(50);
        let token = registry.reserve(allocation).unwrap();
        let (space_identity, lock_identity, cspace_identity, incarnation) = {
            let _transaction = registry.transaction.lock();
            let record = registry.slot(token).unwrap().record.lock();
            let seal = record.space_seal.unwrap();
            (
                seal.object_identity,
                seal.lock_identity,
                seal.cspace_identity,
                seal.cspace_incarnation,
            )
        };

        let mut batch = PreparedTaskBatch::new();
        // Safety: this test creates one exclusive synthetic domain, captures
        // only its opaque token, binds before publication, and drives it on
        // its fixed boot-hart home.
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, "managed-normal", async move {
                let witness = exec::current_reclaimable_task_witness()
                    .expect("managed task poll has no executor witness");
                assert_eq!(witness.instance_token(), Some(token));
            });
        }
        let prepared_handle = batch.prepared_handles()[0].clone();
        let binding = batch.prepared_reclaimable_bindings()[0];
        registry.bind(token, binding, &prepared_handle).unwrap();
        let handles = unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap();
        let handle = &handles[0];
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::Active
        );
        assert!(exec::poll_once());
        assert_eq!(handle.try_exit().unwrap().state(), TaskState::Exited);

        let mut close_calls = 0;
        let finalized = unsafe {
            registry.finalize(token, handle, |closed_domain, kind| {
                assert_eq!(closed_domain, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                assert!(
                    handle.try_exit().is_some(),
                    "close preceded terminal publication"
                );
                close_calls += 1;
                true
            })
        }
        .unwrap();
        assert_eq!(close_calls, 1);
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);

        // Retirement advances the generation before Vacant is published, so
        // even the pre-reservation window cannot accept the old token.
        {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(token).unwrap();
            let record = slot.record.lock();
            assert_eq!(record.phase, InstancePhase::Vacant);
            assert!(!InstanceRegistry::token_matches(slot, &record, token));
            let space = record.space.as_deref().unwrap();
            let cspace = space.cspace().lock();
            assert_eq!(space as *const InstanceSpace as usize, space_identity);
            assert_eq!(
                space.cspace() as *const SpinLock<CSpace> as usize,
                lock_identity
            );
            assert_eq!(cspace.identity(), cspace_identity);
            assert_eq!(cspace.incarnation(), incarnation + 1);
        }

        let current = registry.reserve(domain(51)).unwrap();
        assert_eq!(current.slot, token.slot);
        assert_ne!(current.generation, token.generation);
        {
            let _transaction = registry.transaction.lock();
            let record = registry.slot(current).unwrap().record.lock();
            let seal = record.space_seal.unwrap();
            assert_eq!(seal.object_identity, space_identity);
            assert_eq!(seal.lock_identity, lock_identity);
            assert_eq!(seal.cspace_identity, cspace_identity);
            assert_eq!(seal.cspace_incarnation, incarnation + 1);
        }
        assert_eq!(
            registry.snapshot(token),
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(registry.snapshot(current), Err(RegistryError::Quarantined));
    }

    #[test]
    fn prepared_binding_mismatch_is_sticky_quarantine() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let reserved_domain = domain(60);
        let wrong_domain = domain(61);
        let token = registry.reserve(reserved_domain).unwrap();
        let before = registry
            .slot(token)
            .unwrap()
            .record
            .lock()
            .space_seal
            .unwrap();

        let mut batch = PreparedTaskBatch::new();
        // Safety: the task is never published; failed binding causes its raw
        // envelope to be conservatively abandoned by PreparedTaskBatch::drop.
        unsafe {
            batch.prepare_managed_instance_owned(token, wrong_domain, "wrong-domain", async move {
                let _ = token;
            });
        }
        let binding = batch.prepared_reclaimable_bindings()[0];
        let handle = &batch.prepared_handles()[0];
        assert_eq!(
            registry.bind(token, binding, handle),
            Err(RegistryError::IdentityMismatch)
        );
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert_eq!(record.space_seal, Some(before));
        let cspace = record.space.as_deref().unwrap().cspace().lock();
        assert_eq!(cspace.identity(), before.cspace_identity);
        assert_eq!(cspace.incarnation(), before.cspace_incarnation);
    }

    #[test]
    fn activation_failure_quarantines_the_whole_batch_without_publication() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let first_domain = domain(70);
        let second_domain = domain(71);
        let first = registry.reserve(first_domain).unwrap();
        let second = registry.reserve(second_domain).unwrap();
        let mut batch = PreparedTaskBatch::new();
        unsafe {
            batch.prepare_managed_instance_owned(first, first_domain, "batch-first", async move {
                let _ = first;
            });
            batch.prepare_managed_instance_owned(
                second,
                second_domain,
                "batch-second",
                async move {
                    let _ = second;
                },
            );
        }
        for index in 0..2 {
            registry
                .bind(
                    batch.prepared_reclaimable_bindings()[index]
                        .instance_token()
                        .unwrap(),
                    batch.prepared_reclaimable_bindings()[index],
                    &batch.prepared_handles()[index],
                )
                .unwrap();
        }

        // Corrupt only member two's immutable lock seal.  The activation
        // callback must validate both before changing either to Active, then
        // quarantine both records as one transaction.
        {
            let _transaction = registry.transaction.lock();
            let mut record = registry.slot(second).unwrap().record.lock();
            record.space_seal.as_mut().unwrap().lock_identity ^= 1;
        }
        assert!(matches!(
            unsafe {
                batch.publish_exclusive_reclaimable_with(|bindings| {
                    registry.activate_batch(bindings)
                })
            },
            Err(PreparedTaskBatchError::ExclusiveBindingRejected)
        ));
        assert_eq!(
            registry.slot(first).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry.slot(second).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(exec::reclaimable_domain_snapshot(first_domain), None);
        assert_eq!(exec::reclaimable_domain_snapshot(second_domain), None);
    }

    #[test]
    fn fault_gate_rejects_every_mismatched_identity_projection_before_reclaim() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(83);
        let token = registry.reserve(allocation).unwrap();
        let handle = publish_pending_managed(&registry, token, allocation, "managed-fault-matrix");
        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);

        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook did not retain its witness");
        assert_eq!(exact.instance_token(), Some(token));
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::Active,
            "capture-only fault hook unexpectedly entered the registry"
        );
        let projection = record_projection(&registry, token);
        let expected_cspace = cspace_state(&registry, token);
        let foreign_hart = HartId::new(1).unwrap();
        assert_ne!(foreign_hart, exact.home_hart());

        #[cfg(feature = "wasm-c48-target-acceptance")]
        for (case, mismatch) in [
            (
                "directed instance generation",
                exec::AcceptanceWitnessMismatch::Generation,
            ),
            ("directed task id", exec::AcceptanceWitnessMismatch::Task),
            (
                "directed status identity",
                exec::AcceptanceWitnessMismatch::Status,
            ),
            ("directed owner", exec::AcceptanceWitnessMismatch::Owner),
            ("directed arena", exec::AcceptanceWitnessMismatch::Arena),
            (
                "directed current hart",
                exec::AcceptanceWitnessMismatch::CurrentHart,
            ),
        ] {
            let witness = exact
                .with_acceptance_mismatch(mismatch)
                .expect("managed exact witness accepts every directed mismatch");
            assert_fault_mismatch_is_inert(
                &registry,
                token,
                witness,
                projection,
                expected_cspace,
                case,
            );
        }

        let stale_token = InstanceToken {
            slot: token.slot,
            generation: token.generation.checked_add(1).unwrap(),
        };
        let owner_alias =
            AllocationDomain::new(OwnerId::new(allocation.owner.get() + 1), allocation.arena);
        let arena_alias =
            AllocationDomain::new(allocation.owner, ArenaId::new(allocation.arena.get() + 1));
        let witness_mismatches = [
            (
                "instance token generation",
                exact.with_instance_for_test(Some(stale_token)),
            ),
            (
                "task id",
                exact.with_task_for_test(TaskId(exact.task_id().0.checked_add(1).unwrap())),
            ),
            (
                "status object identity",
                exact.corrupt_status_identity_for_test(),
            ),
            ("owner only", exact.with_domain_for_test(owner_alias)),
            ("arena only", exact.with_domain_for_test(arena_alias)),
            (
                "scheduler generation",
                exact.with_scheduler_generation_for_test(
                    exact
                        .scheduler_identity()
                        .generation()
                        .checked_add(1)
                        .unwrap(),
                ),
            ),
            ("home hart", exact.with_home_hart_for_test(foreign_hart)),
            (
                "current hart",
                exact.with_current_hart_for_test(foreign_hart),
            ),
        ];
        for (case, witness) in witness_mismatches {
            assert_fault_mismatch_is_inert(
                &registry,
                token,
                witness,
                projection,
                expected_cspace,
                case,
            );
        }

        let mut mismatched_seal = projection.space_seal;
        mismatched_seal.object_identity ^= 1;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_fault_mismatch_is_inert(
            &registry,
            token,
            exact,
            projection,
            expected_cspace,
            "Space object identity",
        );

        mismatched_seal = projection.space_seal;
        mismatched_seal.lock_identity ^= 1;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_fault_mismatch_is_inert(
            &registry,
            token,
            exact,
            projection,
            expected_cspace,
            "CSpace lock identity",
        );

        let counterfeit_cspace_identity = CSpace::new("counterfeit-fault-gate").identity();
        mismatched_seal = projection.space_seal;
        mismatched_seal.cspace_identity = counterfeit_cspace_identity;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_fault_mismatch_is_inert(
            &registry,
            token,
            exact,
            projection,
            expected_cspace,
            "CSpace identity",
        );

        mismatched_seal = projection.space_seal;
        mismatched_seal.cspace_incarnation =
            mismatched_seal.cspace_incarnation.checked_add(1).unwrap();
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_fault_mismatch_is_inert(
            &registry,
            token,
            exact,
            projection,
            expected_cspace,
            "CSpace incarnation",
        );

        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fault_linearization_quarantines_a_retained_arena_alias_in_another_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);

        let target_domain = domain(85);
        let target = registry.reserve(target_domain).unwrap();
        let target_handle =
            publish_pending_managed(&registry, target, target_domain, "fault-alias-target");

        let other_domain = domain(86);
        let other = registry.reserve(other_domain).unwrap();
        let mut other_batch = PreparedTaskBatch::new();
        // Safety: this second task remains unpublished and retains its own
        // domain in both the prepared binding and handle projections.
        unsafe {
            other_batch.prepare_managed_instance_owned(
                other,
                other_domain,
                "fault-alias-other",
                async move {
                    let _ = other;
                    core::future::pending::<()>().await;
                },
            );
        }
        registry
            .bind(
                other,
                other_batch.prepared_reclaimable_bindings()[0],
                &other_batch.prepared_handles()[0],
            )
            .unwrap();

        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(target_handle.state(), TaskState::Faulted);
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook did not retain its witness");
        let target_cspace = cspace_state(&registry, target);
        let other_cspace = cspace_state(&registry, other);

        // Simulate corruption after both slots passed admission: only the
        // other slot's record projection aliases the target arena, while its
        // retained handle and prepared binding still name `other_domain`.
        {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(other).unwrap();
            let mut record = slot.record.lock();
            assert_eq!(record.phase, InstancePhase::Bound);
            record.domain = Some(AllocationDomain::new(
                other_domain.owner,
                target_domain.arena,
            ));
            InstanceRegistry::publish_header(slot, &record);
        }

        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(exact, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(raw_calls, 0);
        assert_eq!(
            registry.slot(target).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry.slot(other).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, target), target_cspace);
        assert_eq!(cspace_state(&registry, other), other_cspace);

        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn missing_token_scan_checks_task_and_prepared_domain_projections() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(87);
        let token = registry.reserve(allocation).unwrap();
        let mut batch = PreparedTaskBatch::new();
        unsafe {
            batch.prepare_managed_instance_owned(token, allocation, "missing-token", async move {
                let _ = token;
                core::future::pending::<()>().await;
            });
        }
        registry
            .bind(
                token,
                batch.prepared_reclaimable_bindings()[0],
                &batch.prepared_handles()[0],
            )
            .unwrap();
        let expected_cspace = cspace_state(&registry, token);

        // Hide the exact domain from the primary record projection.  The
        // retained task and prepared binding must still prevent a missing
        // token from falling through to legacy reclamation.
        {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(token).unwrap();
            let mut record = slot.record.lock();
            record.domain = Some(domain(88));
            InstanceRegistry::publish_header(slot, &record);
        }
        let missing = exec::reclaimable_fault_witness_for_test(None, TaskId(88_002), allocation);
        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(missing, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(raw_calls, 0);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, token), expected_cspace);
    }

    #[test]
    fn normal_finalize_rejects_projection_mismatches_before_close_or_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(84);
        let token = registry.reserve(allocation).unwrap();
        let handle =
            publish_pending_managed(&registry, token, allocation, "managed-finalize-matrix");
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);

        let projection = record_projection(&registry, token);
        let expected_cspace = cspace_state(&registry, token);
        let foreign_hart = HartId::new(1).unwrap();
        assert_ne!(foreign_hart, projection.home_hart);

        mutate_active_record_for_test(&registry, token, |record| {
            record.home_hart = Some(foreign_hart);
        });
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "home hart projection",
        );

        mutate_active_record_for_test(&registry, token, |record| {
            record.scheduler = None;
        });
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "missing scheduler projection",
        );

        let mut mismatched_seal = projection.space_seal;
        mismatched_seal.object_identity ^= 1;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "Space object identity projection",
        );

        mismatched_seal = projection.space_seal;
        mismatched_seal.lock_identity ^= 1;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "CSpace lock identity projection",
        );

        let counterfeit_cspace_identity = CSpace::new("counterfeit-finalize-gate").identity();
        mismatched_seal = projection.space_seal;
        mismatched_seal.cspace_identity = counterfeit_cspace_identity;
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "CSpace identity projection",
        );

        mismatched_seal = projection.space_seal;
        mismatched_seal.cspace_incarnation =
            mismatched_seal.cspace_incarnation.checked_add(1).unwrap();
        install_space_seal_for_test(&registry, token, mismatched_seal);
        assert_finalize_mismatch_is_inert(
            &registry,
            token,
            &handle,
            projection,
            expected_cspace,
            "CSpace incarnation projection",
        );

        let mut close_calls = 0;
        let finalized = unsafe {
            registry.finalize(token, &handle, |closed, kind| {
                assert_eq!(closed, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                close_calls += 1;
                true
            })
        }
        .unwrap();
        assert_eq!(close_calls, 1);
        assert_eq!(finalized.next_cspace_incarnation, expected_cspace.1 + 1);
    }

    #[test]
    fn wrong_in_range_token_quarantines_the_exact_terminal_handle_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(89);
        let actual = registry.reserve(allocation).unwrap();
        let handle = publish_pending_managed(&registry, actual, allocation, "wrong-token-terminal");
        let wrong = registry.reserve(domain(90)).unwrap();
        assert_ne!(wrong.slot, actual.slot);
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);
        let expected_cspace = cspace_state(&registry, actual);
        let mut close_calls = 0;

        assert_eq!(
            unsafe {
                registry.finalize(wrong, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(
            registry.slot(wrong).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(
            registry.slot(actual).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, actual), expected_cspace);

        assert_eq!(
            unsafe {
                registry.finalize(actual, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(cspace_state(&registry, actual), expected_cspace);
    }

    #[test]
    fn out_of_range_token_quarantines_the_exact_terminal_handle_slot() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(91);
        let actual = registry.reserve(allocation).unwrap();
        let handle =
            publish_pending_managed(&registry, actual, allocation, "missing-token-terminal");
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);
        let expected_cspace = cspace_state(&registry, actual);
        let out_of_range = InstanceToken {
            slot: MAX_INSTANCE_SLOTS as u8,
            generation: actual.generation,
        };
        let mut close_calls = 0;

        assert_eq!(
            unsafe {
                registry.finalize(out_of_range, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(
            registry.slot(actual).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_state(&registry, actual), expected_cspace);

        assert_eq!(
            unsafe {
                registry.finalize(actual, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(cspace_state(&registry, actual), expected_cspace);
    }

    #[test]
    fn refused_raw_reclaim_quarantines_without_close_or_cspace_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        TEST_RECLAIM_SUCCEEDS.store(false, AtomicOrdering::Release);
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(80);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_pending_managed(&registry, token, allocation, "managed-refused");

        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        let mut close_calls = 0;
        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fault_reclaim_space_callback_runs_unlocked_before_reclaim_and_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(10_199);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_pending_managed(&registry, token, allocation, "fault-space-callback");
        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook lost its witness");

        let mut callback_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim_with_space(exact, |domain, space, continuation| {
                    callback_calls += 1;
                    assert_eq!(domain, allocation);
                    assert!(continuation.matches_exact(token, None));
                    assert!(!continuation.matches_instance(InstanceToken {
                        slot: token.slot,
                        generation: token.generation ^ 1,
                    }));
                    assert_eq!(
                        format!("{continuation:?}"),
                        "FaultContinuationAbandonReceipt(<opaque>)"
                    );
                    // Reentrant observation proves that no registry lock is
                    // retained across the callback.
                    assert_eq!(
                        registry.snapshot(token).unwrap().phase,
                        InstancePhase::FaultReclaiming
                    );
                    // Taking the CSpace guard proves that recovery and seal
                    // validation completed and the guard is not retained.
                    let cspace = space.cspace().lock();
                    assert_eq!(cspace.incarnation(), incarnation);
                    drop(cspace);
                    true
                })
            },
            FaultGateOutcome::ManagedReclaimed
        );
        assert_eq!(callback_calls, 1);
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::FaultReclaimed
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn refused_fault_space_cleanup_quarantines_before_any_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(10_203);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_pending_managed(&registry, token, allocation, "fault-space-refused");
        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook lost its witness");

        let mut callback_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim_with_space(exact, |domain, space, continuation| {
                    callback_calls += 1;
                    assert_eq!(domain, allocation);
                    assert!(continuation.matches_exact(token, None));
                    assert_eq!(space.cspace().lock().incarnation(), incarnation);
                    false
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(callback_calls, 1);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);
        assert_eq!(
            unsafe { registry.finalize(token, &handle, |_, _| true) },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn running_finalize_is_inert_and_terminal_finalize_resets_exactly_once() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(81);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_pending_managed(&registry, token, allocation, "managed-running");
        let mut close_calls = 0;

        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::TaskNotTerminal)
        );
        assert_eq!(close_calls, 0);
        assert_eq!(cspace_incarnation(&registry, token), incarnation);
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::Active
        );

        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);
        let finalized = unsafe {
            registry.finalize(token, &handle, |closed, kind| {
                assert_eq!(closed, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                assert!(
                    handle.try_exit().is_some(),
                    "close preceded terminal publication"
                );
                close_calls += 1;
                true
            })
        }
        .unwrap();
        assert_eq!(close_calls, 1);
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);

        let slot = registry.slot(token).unwrap();
        {
            let record = slot.record.lock();
            assert_eq!(record.phase, InstancePhase::Vacant);
            assert_eq!(record.generation, token.generation + 1);
            let cspace = record.space.as_deref().unwrap().cspace().lock();
            assert_eq!(cspace.incarnation(), incarnation + 1);
        }

        // A duplicate terminal observer is stale.  It may quarantine the
        // retired slot, but it cannot invoke close or cross the CSpace ABA
        // boundary a second time.
        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |_, _| {
                    close_calls += 1;
                    true
                })
            },
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(close_calls, 1);
        let record = slot.record.lock();
        let cspace = record.space.as_deref().unwrap().cspace().lock();
        assert_eq!(cspace.incarnation(), incarnation + 1);
    }

    #[test]
    fn fault_replay_after_reclaimed_never_invokes_raw_reclaim_or_reset_twice() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        TEST_RECLAIM_SUCCEEDS.store(true, AtomicOrdering::Release);
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(82);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        let handle = publish_pending_managed(&registry, token, allocation, "managed-replay");

        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::FaultReclaimed
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        let witness = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .expect("fault hook did not retain its exact witness");
        assert_eq!(
            unsafe {
                registry.fault_reclaim(witness, |_| {
                    TEST_RAW_RECLAIMS.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(
            registry.slot(token).unwrap().record.lock().phase,
            InstancePhase::Quarantined
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |_, _| {
                    panic!("fault finalization attempted normal close")
                })
            },
            Err(RegistryError::WrongPhase)
        );
        assert_eq!(cspace_incarnation(&registry, token), incarnation);

        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fault_reclaiming_is_an_unperturbed_cross_hart_lease() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);

        let allocation = domain(10_200);
        let token = registry.reserve(allocation).unwrap();
        let handle =
            publish_pending_managed(&registry, token, allocation, "fault-reclaiming-lease");
        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook lost its witness");

        let stale_token = InstanceToken {
            slot: token.slot,
            generation: token.generation.checked_add(1).unwrap(),
        };
        let owner_alias =
            AllocationDomain::new(OwnerId::new(allocation.owner.get() + 1), allocation.arena);
        let arena_alias =
            AllocationDomain::new(allocation.owner, ArenaId::new(allocation.arena.get() + 1));
        let replays = [
            exact,
            exact.with_instance_for_test(Some(stale_token)),
            exact.with_task_for_test(TaskId(exact.task_id().0 + 1)),
            exact.corrupt_status_identity_for_test(),
            exact.with_domain_for_test(owner_alias),
            exact.with_domain_for_test(arena_alias),
            exact.with_instance_for_test(None),
        ];

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let primary_calls = AtomicU64::new(0);
        let replay_calls = AtomicU64::new(0);
        std::thread::scope(|scope| {
            let registry = &registry;
            let primary_calls = &primary_calls;
            let first_entered = Arc::clone(&entered);
            let first_release = Arc::clone(&release);
            let first = scope.spawn(move || unsafe {
                registry.fault_reclaim(exact, |_| {
                    primary_calls.fetch_add(1, AtomicOrdering::SeqCst);
                    first_entered.wait();
                    first_release.wait();
                    true
                })
            });

            entered.wait();
            crate::arch::set_test_hart_id(1);
            let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for replay in replays {
                    assert_eq!(
                        unsafe {
                            registry.fault_reclaim(replay, |_| {
                                replay_calls.fetch_add(1, AtomicOrdering::SeqCst);
                                true
                            })
                        },
                        FaultGateOutcome::Quarantined
                    );
                    assert_eq!(
                        registry.snapshot(token).unwrap().phase,
                        InstancePhase::FaultReclaiming
                    );
                }
                assert!(!registry.quarantine(token));
                assert_eq!(
                    registry.snapshot(token).unwrap().phase,
                    InstancePhase::FaultReclaiming
                );
                assert_eq!(replay_calls.load(AtomicOrdering::SeqCst), 0);
            }));
            crate::arch::set_test_hart_id(0);
            release.wait();
            let first_outcome = first.join().expect("first fault reclaimer panicked");
            observations.expect("concurrent fault observer panicked");
            assert_eq!(first_outcome, FaultGateOutcome::ManagedReclaimed);
        });

        assert_eq!(primary_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(replay_calls.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(
            registry.snapshot(token).unwrap().phase,
            InstancePhase::FaultReclaimed
        );
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn terminal_retirement_phases_are_unperturbed_cross_hart_leases() {
        let _executor = executor();

        let normal_registry = InstanceRegistry::new();
        let normal_domain = domain(10_201);
        let normal_token = normal_registry.reserve(normal_domain).unwrap();
        let normal_incarnation = cspace_incarnation(&normal_registry, normal_token);
        let normal_handle = publish_pending_managed(
            &normal_registry,
            normal_token,
            normal_domain,
            "normal-retire-lease",
        );
        assert_eq!(normal_handle.cancel(), CancelOutcome::Requested);
        assert_eq!(normal_handle.state(), TaskState::Cancelled);

        let normal_entered = Arc::new(Barrier::new(2));
        let normal_release = Arc::new(Barrier::new(2));
        let normal_publish_calls = AtomicU64::new(0);
        let normal_retire_calls = AtomicU64::new(0);
        let normal_replay_calls = AtomicU64::new(0);
        std::thread::scope(|scope| {
            let registry = &normal_registry;
            let handle = &normal_handle;
            let publish_calls = &normal_publish_calls;
            let retire_calls = &normal_retire_calls;
            let entered = Arc::clone(&normal_entered);
            let release = Arc::clone(&normal_release);
            let first = scope.spawn(move || unsafe {
                registry.finalize_with_space(
                    normal_token,
                    handle,
                    |_, kind| {
                        assert_eq!(kind, TerminalRetireKind::Normal);
                        publish_calls.fetch_add(1, AtomicOrdering::SeqCst);
                        true
                    },
                    |domain, kind| {
                        assert_eq!(domain, normal_domain);
                        assert_eq!(kind, TerminalRetireKind::Normal);
                        retire_calls.fetch_add(1, AtomicOrdering::SeqCst);
                        entered.wait();
                        release.wait();
                        true
                    },
                )
            });
            normal_entered.wait();
            crate::arch::set_test_hart_id(1);
            let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_eq!(
                    unsafe {
                        normal_registry.finalize_with_space(
                            normal_token,
                            &normal_handle,
                            |_, _| {
                                normal_replay_calls.fetch_add(1, AtomicOrdering::SeqCst);
                                true
                            },
                            |_, _| {
                                normal_replay_calls.fetch_add(1, AtomicOrdering::SeqCst);
                                true
                            },
                        )
                    },
                    Err(RegistryError::WrongPhase)
                );
                assert!(!normal_registry.quarantine(normal_token));
                assert_eq!(
                    normal_registry.snapshot(normal_token).unwrap().phase,
                    InstancePhase::NormalClosing
                );
                assert_eq!(normal_replay_calls.load(AtomicOrdering::SeqCst), 0);
                assert_eq!(
                    cspace_incarnation(&normal_registry, normal_token),
                    normal_incarnation
                );
            }));
            crate::arch::set_test_hart_id(0);
            normal_release.wait();
            let finalized = first
                .join()
                .expect("normal terminal owner panicked")
                .expect("normal terminal owner was rejected");
            observations.expect("normal terminal observer panicked");
            assert_eq!(finalized.next_cspace_incarnation, normal_incarnation + 1);
        });
        assert_eq!(normal_publish_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(normal_retire_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(normal_replay_calls.load(AtomicOrdering::SeqCst), 0);

        let fault_registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);
        let fault_domain = domain(10_202);
        let fault_token = fault_registry.reserve(fault_domain).unwrap();
        let fault_incarnation = cspace_incarnation(&fault_registry, fault_token);
        let fault_handle = publish_pending_managed(
            &fault_registry,
            fault_token,
            fault_domain,
            "fault-retire-lease",
        );
        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook lost its witness");
        assert_eq!(
            unsafe { fault_registry.fault_reclaim(exact, |_| true) },
            FaultGateOutcome::ManagedReclaimed
        );

        let fault_entered = Arc::new(Barrier::new(2));
        let fault_release = Arc::new(Barrier::new(2));
        let fault_publish_calls = AtomicU64::new(0);
        let fault_retire_calls = AtomicU64::new(0);
        let fault_replay_calls = AtomicU64::new(0);
        std::thread::scope(|scope| {
            let registry = &fault_registry;
            let handle = &fault_handle;
            let publish_calls = &fault_publish_calls;
            let retire_calls = &fault_retire_calls;
            let entered = Arc::clone(&fault_entered);
            let release = Arc::clone(&fault_release);
            let first = scope.spawn(move || unsafe {
                registry.finalize_with_space(
                    fault_token,
                    handle,
                    |_, kind| {
                        assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                        publish_calls.fetch_add(1, AtomicOrdering::SeqCst);
                        true
                    },
                    |domain, kind| {
                        assert_eq!(domain, fault_domain);
                        assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                        retire_calls.fetch_add(1, AtomicOrdering::SeqCst);
                        entered.wait();
                        release.wait();
                        true
                    },
                )
            });
            fault_entered.wait();
            crate::arch::set_test_hart_id(1);
            let observations = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_eq!(
                    unsafe {
                        fault_registry.finalize_with_space(
                            fault_token,
                            &fault_handle,
                            |_, _| {
                                fault_replay_calls.fetch_add(1, AtomicOrdering::SeqCst);
                                true
                            },
                            |_, _| {
                                fault_replay_calls.fetch_add(1, AtomicOrdering::SeqCst);
                                true
                            },
                        )
                    },
                    Err(RegistryError::WrongPhase)
                );
                assert!(!fault_registry.quarantine(fault_token));
                assert_eq!(
                    fault_registry.snapshot(fault_token).unwrap().phase,
                    InstancePhase::FaultRetiring
                );
                assert_eq!(fault_replay_calls.load(AtomicOrdering::SeqCst), 0);
                assert_eq!(
                    cspace_incarnation(&fault_registry, fault_token),
                    fault_incarnation
                );
            }));
            crate::arch::set_test_hart_id(0);
            fault_release.wait();
            let finalized = first
                .join()
                .expect("fault terminal owner panicked")
                .expect("fault terminal owner was rejected");
            observations.expect("fault terminal observer panicked");
            assert_eq!(finalized.next_cspace_incarnation, fault_incarnation + 1);
        });
        assert_eq!(fault_publish_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(fault_retire_calls.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(fault_replay_calls.load(AtomicOrdering::SeqCst), 0);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn payload_normal_completion_drops_once_in_child_poll_and_detaches_word() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(90);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, Some(0x5a)) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-ready");

        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_COMPLETION.load(AtomicOrdering::SeqCst), 0x5a);
        {
            let record = registry.slot(token).unwrap().record.lock();
            assert_eq!(record.phase, InstancePhase::PayloadDropped);
            assert!(record.payload.is_none());
            assert!(record.payload_installed);
            assert!(!record.payload_abandoned);
            assert_eq!(record.payload_completion, Some(0x5a));
        }

        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.detached_completion, Some(0x5a));
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn expected_payload_completion_mismatch_never_publishes_retires_or_resets() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(10_103);
        let token = registry.reserve(allocation).unwrap();
        unsafe {
            registry
                .configure_reserved_space(token, |cspace| {
                    cspace.mint(Arc::new(TestSpaceResource), Rights::READ)
                })
                .unwrap();
        }
        unsafe { install_test_payload(&registry, token, Some(0x5a)) };
        let handle =
            publish_payload_managed(&registry, token, allocation, "payload-completion-mismatch");
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        let before = cspace_state(&registry, token);
        let publications = AtomicU64::new(0);
        let retires = AtomicU64::new(0);

        let result = unsafe {
            registry.finalize_with_space_expect_completion(
                token,
                &handle,
                Some(0x5b),
                |_space, _kind| {
                    publications.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
                |_domain, _kind| {
                    retires.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
            )
        };

        assert_eq!(result, Err(RegistryError::TerminalCompletionMismatch));
        assert_eq!(publications.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(retires.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(cspace_state(&registry, token), before);
        assert_eq!(registry.snapshot(token), Err(RegistryError::Quarantined));
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn cooperative_cancel_tombstones_and_drops_on_next_exact_child_poll() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(91);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, None) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-cancel");

        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Running);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        let CooperativeCancelOutcome::Requested(task) = registry
            .request_cooperative_cancel(token, &handle, 0xcafe)
            .unwrap()
        else {
            panic!("first cooperative cancel unexpectedly lost completion race");
        };
        exec::wake(task);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);

        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.detached_completion, Some(0xcafe));
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn cooperative_cancel_loses_to_payload_dropping_without_mutation() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(98);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, None) };
        let handle =
            publish_payload_managed(&registry, token, allocation, "payload-dropping-cancel");
        let expected_cspace = cspace_state(&registry, token);

        // Model the exact linearization point immediately after the child
        // tombstones the box and before its normal Drop returns.  The box is
        // ManuallyDrop, so removing this test value cannot run target code.
        let tombstone = {
            let _transaction = registry.transaction.lock();
            let slot = registry.slot(token).unwrap();
            let mut record = slot.record.lock();
            let payload = record.payload.take();
            record.payload_cancel = Some(0x11);
            record.phase = InstancePhase::PayloadDropping;
            InstanceRegistry::publish_header(slot, &record);
            payload
        };
        core::mem::forget(tombstone);

        assert_eq!(
            registry.request_cooperative_cancel(token, &handle, 0x11),
            Ok(CooperativeCancelOutcome::AlreadyCompleting)
        );
        assert_eq!(
            registry.request_cooperative_cancel(token, &handle, 0x22),
            Ok(CooperativeCancelOutcome::AlreadyCompleting)
        );
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::PayloadDropping);
        assert!(record.payload.is_none());
        assert!(!record.payload_abandoned);
        assert_eq!(record.payload_cancel, Some(0x11));
        assert_eq!(record.payload_completion, None);
        drop(record);
        assert_eq!(cspace_state(&registry, token), expected_cspace);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
    }

    #[test]
    fn cooperative_cancel_after_payload_drop_is_inert_and_does_not_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(99);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        unsafe { install_test_payload(&registry, token, Some(0x44)) };
        let handle =
            publish_payload_managed(&registry, token, allocation, "payload-dropped-cancel");
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        let expected_cspace = cspace_state(&registry, token);

        assert_eq!(
            registry.request_cooperative_cancel(token, &handle, 0x44),
            Ok(CooperativeCancelOutcome::AlreadyCompleting)
        );
        assert_eq!(
            registry.request_cooperative_cancel(token, &handle, 0x55),
            Ok(CooperativeCancelOutcome::AlreadyCompleting)
        );
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::PayloadDropped);
        assert!(record.payload.is_none());
        assert!(!record.payload_abandoned);
        assert_eq!(record.payload_cancel, None);
        assert_eq!(record.payload_completion, Some(0x44));
        drop(record);
        assert_eq!(cspace_state(&registry, token), expected_cspace);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);

        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::Normal);
                true
            })
        }
        .unwrap();
        assert_eq!(finalized.detached_completion, Some(0x44));
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn exact_fault_abandons_payload_without_drop_and_retires_owner_before_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_next_guard);
        let allocation = domain(92);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        unsafe { install_test_payload(&registry, token, None) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-fault");

        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        {
            let record = registry.slot(token).unwrap().record.lock();
            assert_eq!(record.phase, InstancePhase::FaultReclaimed);
            assert!(record.payload.is_none());
            assert!(record.payload_abandoned);
        }

        let mut retire_calls = 0;
        let finalized = unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                assert_eq!(cspace_incarnation(&registry, token), incarnation);
                retire_calls += 1;
                true
            })
        }
        .unwrap();
        assert_eq!(retire_calls, 1);
        assert_eq!(finalized.detached_completion, None);
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fault_after_real_pending_quantum_abandons_without_payload_drop() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_after_payload_poll_guard);
        let allocation = domain(1000);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, None) };
        let handle =
            publish_payload_managed(&registry, token, allocation, "payload-post-poll-fault");

        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::FaultReclaimed);
        assert!(record.payload.is_none());
        assert!(record.payload_abandoned);
        drop(record);

        unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                true
            })
        }
        .unwrap();
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn payload_drop_fault_reaches_exact_dropping_gate_without_second_drop() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(catch_payload_drop_fault_guard);
        let allocation = domain(97);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, Some(0x97)) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-drop-fault");

        // Host tests cannot model the target's non-unwinding longjmp.  Catching
        // this injected destructor panic at the executor guard nevertheless
        // exercises the real child path after poll_payload published
        // PayloadDropping and removed the box from the stable record.
        TEST_PAYLOAD_DROP_FAULT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), 1);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::FaultReclaimed);
        assert!(record.payload.is_none());
        assert!(record.payload_abandoned);
        drop(record);
        unsafe {
            registry.finalize(token, &handle, |retired, kind| {
                assert_eq!(retired, allocation);
                assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                true
            })
        }
        .unwrap();
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn fault_identity_mismatch_keeps_payload_and_never_polls_or_reclaims() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        exec::set_fault_reclaimer(capture_fault_witness);
        exec::set_fault_guard(fault_next_guard);
        let allocation = domain(93);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, None) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-mismatch");

        TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Faulted);
        let exact = TEST_FAULT_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("capture-only fault hook lost its witness");
        let mismatched = exact.with_task_for_test(TaskId(exact.task_id().0 + 1));
        let mut raw_calls = 0;
        assert_eq!(
            unsafe {
                registry.fault_reclaim(mismatched, |_| {
                    raw_calls += 1;
                    true
                })
            },
            FaultGateOutcome::Quarantined
        );
        assert_eq!(raw_calls, 0);
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert!(record.payload.is_some());
        assert!(!record.payload_abandoned);
        drop(record);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn stale_poll_witness_quarantines_without_poll_or_payload_tombstone() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(94);
        let token = registry.reserve(allocation).unwrap();
        unsafe { install_test_payload(&registry, token, None) };

        let mut batch = PreparedTaskBatch::new();
        unsafe {
            batch.prepare_managed_instance_owned(
                token,
                allocation,
                "payload-stale-witness",
                async move {
                    let witness = exec::current_reclaimable_task_witness()
                        .expect("managed task did not mint a poll witness");
                    assert_eq!(witness.instance_token(), Some(token));
                    *TEST_TASK_WITNESS
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(witness);
                    core::future::pending::<()>().await;
                },
            );
        }
        let prepared = batch.prepared_handles()[0].clone();
        registry
            .bind(token, batch.prepared_reclaimable_bindings()[0], &prepared)
            .unwrap();
        let handle = unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
        }
        .unwrap()
        .remove(0);
        assert!(exec::poll_once());
        let stale = TEST_TASK_WITNESS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("test task did not retain its first-poll witness");
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        assert_eq!(
            unsafe { registry.poll_payload(stale, &mut context) },
            Err(RegistryError::Quarantined)
        );
        assert_eq!(TEST_PAYLOAD_POLLS.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert!(record.payload.is_some());
        assert!(!record.payload_abandoned);
        drop(record);
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
    }

    #[test]
    fn failed_normal_retire_does_not_reset_after_child_drop() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        let allocation = domain(95);
        let token = registry.reserve(allocation).unwrap();
        let incarnation = cspace_incarnation(&registry, token);
        unsafe { install_test_payload(&registry, token, Some(7)) };
        let handle = publish_payload_managed(&registry, token, allocation, "payload-close-false");
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);

        let mut retire_calls = 0;
        assert_eq!(
            unsafe {
                registry.finalize(token, &handle, |retired, kind| {
                    assert_eq!(retired, allocation);
                    assert_eq!(kind, TerminalRetireKind::Normal);
                    retire_calls += 1;
                    false
                })
            },
            Err(RegistryError::NormalCloseFailed)
        );
        assert_eq!(retire_calls, 1);
        assert_eq!(cspace_incarnation(&registry, token), incarnation);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert!(record.payload.is_none());
        assert_eq!(record.payload_completion, Some(7));
        drop(record);
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 1);
        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
    }

    #[test]
    fn second_install_validation_mismatch_leaks_without_payload_drop() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let token = registry.reserve(domain(96)).unwrap();
        assert_eq!(
            unsafe {
                registry.install_payload(token, || {
                    assert!(registry.quarantine(token));
                    TestPayload { ready: Some(1) }
                })
            },
            Err(RegistryError::IdentityMismatch)
        );
        assert_eq!(TEST_PAYLOAD_DROPS.load(AtomicOrdering::SeqCst), 0);
        let record = registry.slot(token).unwrap().record.lock();
        assert_eq!(record.phase, InstancePhase::Quarantined);
        assert!(record.payload.is_none());
        assert!(!record.payload_installed);
    }

    #[test]
    fn repeated_fault_generations_reuse_one_slot_without_registry_leaks() {
        const CYCLES: u64 = 16;

        let _executor = executor();
        let registry = InstanceRegistry::new();
        TEST_REGISTRY.store(
            core::ptr::from_ref(&registry).cast_mut(),
            AtomicOrdering::Release,
        );
        TEST_RECLAIM_SUCCEEDS.store(true, AtomicOrdering::Release);
        exec::set_fault_reclaimer(reclaim_test_instance);
        exec::set_fault_guard(fault_next_guard);
        let scheduler_domains = exec::reclaimable_domain_count();
        let mut previous_token: Option<InstanceToken> = None;
        let mut stable_space = None;
        let mut stable_lock = None;
        let mut stable_cspace = None;
        let mut expected_incarnation = 1;

        for cycle in 0..CYCLES {
            let allocation = domain(100 + cycle);
            let token = registry.reserve(allocation).unwrap();
            if let Some(previous) = previous_token {
                assert_eq!(token.slot, previous.slot);
                assert_eq!(token.generation, previous.generation + 1);
            }

            let seal = registry
                .slot(token)
                .unwrap()
                .record
                .lock()
                .space_seal
                .unwrap();
            assert_eq!(seal.cspace_incarnation, expected_incarnation);
            match (stable_space, stable_lock, stable_cspace) {
                (Some(space), Some(lock), Some(cspace)) => {
                    assert_eq!(seal.object_identity, space);
                    assert_eq!(seal.lock_identity, lock);
                    assert_eq!(seal.cspace_identity, cspace);
                }
                (None, None, None) => {
                    stable_space = Some(seal.object_identity);
                    stable_lock = Some(seal.lock_identity);
                    stable_cspace = Some(seal.cspace_identity);
                }
                _ => unreachable!("stable identity tuple was only partially initialized"),
            }

            let handle =
                publish_pending_managed(&registry, token, allocation, "managed-repeated-fault");
            TEST_FAULT_NEXT.store(true, AtomicOrdering::SeqCst);
            assert!(exec::poll_once());
            assert_eq!(handle.state(), TaskState::Faulted);
            assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), cycle + 1);
            assert_eq!(
                registry.snapshot(token).unwrap().phase,
                InstancePhase::FaultReclaimed
            );
            assert_eq!(cspace_incarnation(&registry, token), expected_incarnation);

            let finalized = unsafe {
                registry.finalize(token, &handle, |closed, kind| {
                    assert_eq!(closed, allocation);
                    assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
                    true
                })
            }
            .unwrap();
            expected_incarnation += 1;
            assert_eq!(finalized.next_cspace_incarnation, expected_incarnation);
            let slot = registry.slot(token).unwrap();
            let record = slot.record.lock();
            assert_eq!(record.phase, InstancePhase::Vacant);
            assert_eq!(record.generation, token.generation + 1);
            assert!(record.domain.is_none());
            assert!(record.prepared.is_none());
            assert!(record.task.is_none());
            assert!(record.scheduler.is_none());
            assert!(record.home_hart.is_none());
            let cspace = record.space.as_deref().unwrap().cspace().lock();
            assert_eq!(cspace.incarnation(), expected_incarnation);
            assert!(cspace.list().is_empty());
            drop(cspace);
            drop(record);
            assert_eq!(exec::reclaimable_domain_count(), scheduler_domains);
            previous_token = Some(token);
        }

        let live_records = registry
            .slots
            .iter()
            .filter(|slot| slot.record.lock().phase != InstancePhase::Vacant)
            .count();
        let retained_spaces = registry
            .slots
            .iter()
            .filter(|slot| slot.record.lock().space.is_some())
            .count();
        assert_eq!(live_records, 0);
        assert_eq!(retained_spaces, 1);
        assert_eq!(TEST_RAW_RECLAIMS.load(AtomicOrdering::SeqCst), CYCLES);

        TEST_REGISTRY.store(core::ptr::null_mut(), AtomicOrdering::Release);
        exec::set_fault_guard(pass_fault_guard);
        exec::set_fault_reclaimer(reject_unexpected_fault);
    }

    #[test]
    fn reserved_space_configuration_is_system_stable_and_resets_after_terminal_publication() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(10_100);
        let token = registry
            .reserve_named(allocation, "configured-instance")
            .unwrap();
        let before = cspace_state(&registry, token);

        let (cap, identity, incarnation) = unsafe {
            registry.configure_reserved_space(token, |cspace| {
                let identity = cspace.identity();
                let incarnation = cspace.incarnation();
                let cap = cspace.mint(Arc::new(TestSpaceResource), Rights::READ);
                (cap, identity, incarnation)
            })
        }
        .unwrap();
        assert_eq!(identity, before.0);
        assert_eq!(incarnation, before.1);
        assert_eq!(cspace_state(&registry, token), (before.0, before.1, 1));

        let handle =
            publish_pending_managed(&registry, token, allocation, "configured-instance-terminal");
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        assert_eq!(handle.state(), TaskState::Cancelled);
        let publications = AtomicU64::new(0);
        let retires = AtomicU64::new(0);
        let finalized = unsafe {
            registry.finalize_with_space(
                token,
                &handle,
                |space, kind| {
                    assert_eq!(kind, TerminalRetireKind::Normal);
                    let cspace = space.cspace().lock();
                    assert_eq!(cspace.identity(), identity);
                    assert_eq!(cspace.incarnation(), incarnation);
                    assert_eq!(cspace.rights_of(cap), Ok(Rights::READ));
                    publications.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
                |closed, kind| {
                    assert_eq!(closed, allocation);
                    assert_eq!(kind, TerminalRetireKind::Normal);
                    assert_eq!(publications.load(AtomicOrdering::SeqCst), 1);
                    retires.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
            )
        }
        .unwrap();
        assert_eq!(publications.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(retires.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(finalized.revoked_capabilities, 1);
        assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);
        assert_eq!(
            cspace_state(&registry, token),
            (identity, incarnation + 1, 0)
        );
    }

    #[test]
    fn failed_terminal_publication_quarantines_without_retire_or_cspace_reset() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(10_101);
        let token = registry
            .reserve_named(allocation, "publish-failure")
            .unwrap();
        unsafe {
            registry
                .configure_reserved_space(token, |cspace| {
                    cspace.mint(Arc::new(TestSpaceResource), Rights::READ)
                })
                .unwrap();
        }
        let handle =
            publish_pending_managed(&registry, token, allocation, "publish-failure-terminal");
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        let before = cspace_state(&registry, token);
        let retire_calls = AtomicU64::new(0);
        let result = unsafe {
            registry.finalize_with_space(
                token,
                &handle,
                |_space, _kind| false,
                |_closed, _kind| {
                    retire_calls.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
            )
        };
        assert_eq!(result, Err(RegistryError::TerminalPublishFailed));
        assert_eq!(retire_calls.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(cspace_state(&registry, token), before);
        assert_eq!(registry.snapshot(token), Err(RegistryError::Quarantined));
    }

    #[test]
    fn terminal_publication_projection_mismatch_never_retires_or_resets() {
        let _executor = executor();
        let registry = InstanceRegistry::new();
        let allocation = domain(10_102);
        let token = registry
            .reserve_named(allocation, "publish-mismatch")
            .unwrap();
        unsafe {
            registry
                .configure_reserved_space(token, |cspace| {
                    cspace.mint(Arc::new(TestSpaceResource), Rights::READ)
                })
                .unwrap();
        }
        let handle =
            publish_pending_managed(&registry, token, allocation, "publish-mismatch-terminal");
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        let before = cspace_state(&registry, token);
        let retire_calls = AtomicU64::new(0);
        let result = unsafe {
            registry.finalize_with_space(
                token,
                &handle,
                |_space, _kind| {
                    let _transaction = registry.transaction.lock();
                    let slot = registry.slot(token).unwrap();
                    let mut record = slot.record.lock();
                    let mut seal = record.space_seal.unwrap();
                    seal.cspace_incarnation = seal.cspace_incarnation.checked_add(1).unwrap();
                    record.space_seal = Some(seal);
                    true
                },
                |_closed, _kind| {
                    retire_calls.fetch_add(1, AtomicOrdering::SeqCst);
                    true
                },
            )
        };
        assert_eq!(result, Err(RegistryError::IdentityMismatch));
        assert_eq!(retire_calls.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(cspace_state(&registry, token), before);
        assert_eq!(registry.snapshot(token), Err(RegistryError::Quarantined));
    }
}
