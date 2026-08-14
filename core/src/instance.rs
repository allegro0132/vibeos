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

use alloc::boxed::Box;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::{CSpace, CSpaceIdentity};
use crate::exec::{
    PreparedReclaimableActivation, PreparedReclaimableBinding, ReclaimableFaultWitness,
    ReclaimableSchedulerIdentity, ReclaimableTaskWitness, TaskHandle, TaskId, TaskState,
};
use crate::heap::{self, AllocationDomain, OwnerId};
use crate::runqueue::HartId;
use crate::sync::{ConditionalRecovery, SpinLock, TaskRecoveryKey};

/// Maximum number of live or quarantined managed component instances.
///
/// The table is fixed so the scheduler's activation callback never allocates.
pub const MAX_INSTANCE_SLOTS: usize = 16;

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

impl fmt::Debug for InstanceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InstanceToken(<opaque>)")
    }
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
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    IdentityMismatch,
    WrongPhase,
    TaskNotTerminal,
    NormalCloseFailed,
    CSpaceResetRejected,
    Quarantined,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizeOutcome {
    /// Number of live volatile capabilities revoked by the exact reset.
    pub revoked_capabilities: usize,
    /// Incarnation installed by the reset.  This is diagnostic evidence, not
    /// an authority token.
    pub next_cspace_incarnation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceSnapshot {
    pub phase: InstancePhase,
    pub domain: AllocationDomain,
    pub task: Option<TaskId>,
    pub home_hart: Option<HartId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstanceSpaceSeal {
    object_identity: usize,
    lock_identity: usize,
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
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
    }
}

struct InstanceSlot {
    /// Allocation-free phase/generation publication and corruption witness.
    header: AtomicU64,
    /// Recoverable by construction, although component code is never allowed
    /// to retain this guard across an untrusted poll.
    record: SpinLock<SlotRecord>,
}

impl InstanceSlot {
    const fn new() -> Self {
        Self {
            header: AtomicU64::new(encode_header(0, InstancePhase::Vacant)),
            record: SpinLock::new_recoverable(SlotRecord::vacant()),
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

impl InstanceRegistry {
    pub const fn new() -> Self {
        Self {
            transaction: SpinLock::new(()),
            slots: [const { InstanceSlot::new() }; MAX_INSTANCE_SLOTS],
        }
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
                    && projections.iter().any(Option::is_some))
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

    /// Validate and reclaim one permanently detached managed fault arena.
    ///
    /// # Safety
    ///
    /// `witness` must have been minted by the executor after its all-hart
    /// quiescence and permanent-detach boundary.  `reclaim` must reclaim only
    /// its argument domain, at most once, without allocating, blocking,
    /// panicking, resetting a CSpace, or calling the executor.  Returning
    /// `false` reports that no exact reclaim proof was obtained.
    pub unsafe fn fault_reclaim<F>(
        &self,
        witness: ReclaimableFaultWitness,
        reclaim: F,
    ) -> FaultGateOutcome
    where
        F: FnOnce(AllocationDomain) -> bool,
    {
        let Some(token) = witness.instance_token() else {
            // Absence is `NotManaged` only when no live registry record names
            // this exact globally-unique TaskId or exact allocation domain.
            // Otherwise a lost executor token must not fall through to a
            // legacy reclaimer and bypass the registry's generation checks.
            let _transaction = self.transaction.lock();
            return if self.quarantine_exact_fault_candidates_locked(witness) {
                FaultGateOutcome::Quarantined
            } else {
                FaultGateOutcome::NotManaged
            };
        };
        let mut system = heap::enter_owner(OwnerId::SYSTEM);

        let domain = {
            let _transaction = self.transaction.lock();
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

            record.phase = InstancePhase::FaultReclaiming;
            Self::publish_header(slot, &record);
            domain
        };

        // No registry lock is held across the target's allocator operation.
        // FaultReclaiming prevents a replay from authorizing a second reclaim.
        let reclaimed = reclaim(domain);

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
            Self::quarantine_locked(slot, &mut record);
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

    /// Publish normal/fault terminal proof, perform the one exact CSpace
    /// reset, and finally make the slot reusable with a newer token generation.
    ///
    /// `normal_close` is called only for `Exited`/`Cancelled`; a faulted task
    /// must already carry the `FaultReclaimed` proof produced above.
    ///
    /// # Safety
    ///
    /// For a normal terminal state, `normal_close` must close only the exact
    /// supplied domain and return `true` only after that arena is proven empty
    /// and irreversibly retired.  It must not allocate, block, panic, reset a
    /// CSpace, or call the executor.  A production caller must obtain this
    /// proof from the allocator; `true` is not a forgeable safe-code receipt.
    pub unsafe fn finalize<F>(
        &self,
        token: InstanceToken,
        handle: &TaskHandle,
        normal_close: F,
    ) -> Result<FinalizeOutcome, RegistryError>
    where
        F: FnOnce(AllocationDomain) -> bool,
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

        let mut close = Some(normal_close);
        let domain = {
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
            match exit.state() {
                TaskState::Faulted if record.phase == InstancePhase::FaultReclaimed => domain,
                TaskState::Exited | TaskState::Cancelled
                    if record.phase == InstancePhase::Active =>
                {
                    record.phase = InstancePhase::NormalClosing;
                    Self::publish_header(slot, &record);
                    domain
                }
                TaskState::Running => unreachable!("TaskExit cannot contain Running"),
                _ => {
                    Self::quarantine_locked(slot, &mut record);
                    drop(record);
                    drop(_transaction);
                    system.restore();
                    return Err(RegistryError::WrongPhase);
                }
            }
        };

        if matches!(exit.state(), TaskState::Exited | TaskState::Cancelled) {
            let closed =
                close
                    .take()
                    .expect("normal finalization retains its close hook")(domain);
            let _transaction = self.transaction.lock();
            let slot = self
                .slot(token)
                .expect("opaque token retained its fixed in-range slot");
            let mut record = slot.record.lock();
            if !closed {
                Self::quarantine_locked(slot, &mut record);
                drop(record);
                drop(_transaction);
                system.restore();
                return Err(RegistryError::NormalCloseFailed);
            }
            let post_unique = !self.quarantine_identity_conflicts_locked(
                token,
                domain.arena,
                handle.id(),
                record.scheduler,
            );
            if !Self::terminal_identity_matches(slot, &record, token, handle)
                || record.phase != InstancePhase::NormalClosing
                || record.domain != Some(domain)
                || !post_unique
            {
                panic!("managed instance identity changed after irreversible normal arena close");
            }
            record.phase = InstancePhase::NormalTerminal;
            Self::publish_header(slot, &record);
        }

        let _transaction = self.transaction.lock();
        let slot = self
            .slot(token)
            .expect("opaque token retained its fixed in-range slot");
        let mut record = slot.record.lock();
        let expected_phase = match exit.state() {
            TaskState::Faulted => InstancePhase::FaultReclaimed,
            TaskState::Exited | TaskState::Cancelled => InstancePhase::NormalTerminal,
            TaskState::Running => unreachable!("TaskExit cannot contain Running"),
        };
        if !Self::terminal_identity_matches(slot, &record, token, handle)
            || record.phase != expected_phase
        {
            Self::quarantine_locked(slot, &mut record);
            drop(record);
            drop(_transaction);
            system.restore();
            return Err(RegistryError::IdentityMismatch);
        }
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
        record.retire_after_reset();
        Self::publish_header(slot, &record);
        drop(record);
        drop(_transaction);
        system.restore();
        Ok(FinalizeOutcome {
            revoked_capabilities: revoked,
            next_cspace_incarnation,
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
        let pointer = {
            let _transaction = self.transaction.lock();
            let Some(slot) = self.slot(token) else {
                return Err(RegistryError::IdentityMismatch);
            };
            let mut record = slot.record.lock();
            let exact_task = record.task.as_ref().is_some_and(|handle| {
                handle.id() == witness.task_id()
                    && handle.allocation_domain() == witness.allocation_domain()
                    && witness.matches_handle(handle)
            });
            if !Self::token_matches(slot, &record, token)
                || record.phase != InstancePhase::Active
                || record.domain != Some(witness.allocation_domain())
                || record.home_hart != Some(witness.home_hart())
                || witness.current_hart() != witness.home_hart()
                || record.scheduler != Some(witness.scheduler_identity())
                || !exact_task
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
        // Safety: the caller promises exact-task liveness across this call;
        // lifecycle finalization is therefore excluded until operation ends.
        Ok(operation(unsafe { &*pointer }))
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
        true
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

    fn quarantine_locked(slot: &InstanceSlot, record: &mut SlotRecord) {
        record.phase = InstancePhase::Quarantined;
        Self::publish_header(slot, record);
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
        Self::fault_identity_matches_in_phase(slot, record, token, witness, InstancePhase::Active)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{
        self, CancelOutcome, FaultReclaimOutcome, PreparedTaskBatch, PreparedTaskBatchError,
    };
    use crate::heap::{ArenaId, OwnerId};
    use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering as AtomicOrdering};
    use std::sync::{Mutex, MutexGuard};

    static EXECUTOR_SERIAL: Mutex<()> = Mutex::new(());
    static TEST_REGISTRY: AtomicPtr<InstanceRegistry> = AtomicPtr::new(core::ptr::null_mut());
    static TEST_FAULT_NEXT: AtomicBool = AtomicBool::new(false);
    static TEST_RECLAIM_SUCCEEDS: AtomicBool = AtomicBool::new(true);
    static TEST_RAW_RECLAIMS: AtomicU64 = AtomicU64::new(0);
    static TEST_FAULT_WITNESS: Mutex<Option<ReclaimableFaultWitness>> = Mutex::new(None);

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
        let guard = EXECUTOR_SERIAL
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
        guard
    }

    fn domain(index: u64) -> AllocationDomain {
        AllocationDomain::new(OwnerId::new(10_000 + index), ArenaId::new(20_000 + index))
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
                registry.finalize(token, handle, |_| {
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

    #[test]
    fn fixed_table_never_allocates_a_seventeenth_slot() {
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
    fn one_arena_cannot_be_registered_again_under_a_different_owner() {
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
            registry.finalize(token, handle, |closed_domain| {
                assert_eq!(closed_domain, allocation);
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
            registry.finalize(token, &handle, |closed| {
                assert_eq!(closed, allocation);
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
                registry.finalize(wrong, &handle, |_| {
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
                registry.finalize(actual, &handle, |_| {
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
                registry.finalize(out_of_range, &handle, |_| {
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
                registry.finalize(actual, &handle, |_| {
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
                registry.finalize(token, &handle, |_| {
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
                registry.finalize(token, &handle, |_| {
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
            registry.finalize(token, &handle, |closed| {
                assert_eq!(closed, allocation);
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
                registry.finalize(token, &handle, |_| {
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
                registry.finalize(token, &handle, |_| {
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
                registry.finalize(token, &handle, |_| {
                    panic!("fault generation attempted normal arena close")
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
}
