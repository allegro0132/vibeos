//! Kernel-owned single-slot boundary for the C8.4 target profiler.
//!
//! The two storage-bearing typestates always live in [`SLOT`] while an async
//! task is allowed to suspend. `RunLease` and `StreamLease` carry only sealed
//! task/sample identity. Finish, verification, cancellation, and recycling
//! move a handle through an exact synchronous tombstone, release the
//! IRQ-masking [`SpinLock`], do the O(n) work, then reinstall only into that
//! same tombstone. No storage-bearing handle is held across `.await`.
//!
//! A task-detach callback is registered before the start tick. It can recover
//! an `Active` or `Verified` handle even when the executor's raw-fault path
//! skips the future's `Drop`. The callback context is the lineage epoch and is
//! additionally checked against the exact task and allocation domain.
//!
//! The optional Core-poll observers are caller-owned adapters over either an
//! exact [`RunLease`] or a claimed `ChildRunLease`; ordinary runtime `poll()`
//! remains untouched. A bounded delegation seam can bind one still-hidden
//! prepared child to the same request lineage before scheduler publication. A
//! separate default-off trap overlay can bracket an interrupt with a linear
//! cookie; SSH and publication hooks remain deliberately disconnected.
//! Isolated QEMU workers prove each boundary without composing their exact
//! transcripts.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem;
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
use core::sync::atomic::AtomicBool;
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::exec::{
    CurrentTaskDetachLease, PreparedTaskDetachSeal, TaskDetachDisarm, TaskDetachReason,
    TaskDetachRegistrationError, TaskDetachTarget, TaskId,
};
use crate::heap::AllocationDomain;
use crate::sync::SpinLock;
#[cfg(feature = "wasm-c84-core-poll-observer")]
use vibeos_component_runtime::sync::ProfileClock;
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
use vibeos_wasm_aot_profile::IrqCookie;
use vibeos_wasm_aot_profile::{
    FacadeFaults, Interval, Phase, SampleToken, Storage, Summary, TargetActive, TargetContext,
    TargetReady, TargetRejected, TargetStartError, TargetVerified, VerificationError,
    INTERVAL_CAPACITY,
};

static SLOT: SpinLock<SlotState> = SpinLock::new(SlotState::Uninitialized);
static POISON: AtomicU8 = AtomicU8::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
static ACTIVE_EPOCH: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
static ACCEPTANCE_SSIP_PAIRED: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
static ACCEPTANCE_SSIP_INACTIVE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_CHILD_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_CHILD_RELEASE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_CHILD_CLAIMED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_CHILD_RELEASED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_WRONG_TASK_INERT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_CANCEL_CHILD_INERT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_RELEASED_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_FINISH_CHILD_INERT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_LATE_CLAIM_REJECTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_FAULT_ARMED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_CHILD_CORE_RETURN_TICK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_OBSERVER_DROP_STICKY: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_OPEN_RELEASE_REJECTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_OPEN_PHASE_REJECTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_REPLACEMENT_REJECTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_CHILD_CORE_OPEN: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_PARENT_MUTATION_RESUME: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
static ACCEPTANCE_PARENT_MUTATION_REJECTED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_IDLE: u8 = 0;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_BOUND: u8 = 1;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_CLAIMED: u8 = 2;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_CORE: u8 = 3;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_PROFILED: u8 = 4;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_RELEASED: u8 = 5;
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
const MANAGED_TRACE_DETACHED: u8 = 6;

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
#[derive(Clone, Copy)]
struct ManagedChildTrace {
    epoch: u64,
    state: u8,
    core_pairs: u64,
    typed_polls: u64,
    core_polls: u64,
    detach: Option<TaskDetachReason>,
    invalid: bool,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
impl ManagedChildTrace {
    const EMPTY: Self = Self {
        epoch: 0,
        state: MANAGED_TRACE_IDLE,
        core_pairs: 0,
        typed_polls: 0,
        core_polls: 0,
        detach: None,
        invalid: false,
    };
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
static MANAGED_CHILD_TRACE: SpinLock<ManagedChildTrace> = SpinLock::new(ManagedChildTrace::EMPTY);

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
#[derive(Clone, Copy)]
pub(crate) struct ManagedChildCoreObservation {
    pub(crate) core_pairs: u64,
    pub(crate) typed_polls: u64,
    pub(crate) core_polls: u64,
}

/// Acceptance-only destructor that takes the executor's real task-fault
/// landing pad without printing a kernel panic. If no pad is armed the call
/// returns, so the terminal-state assertion remains fail-closed.
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
struct AcceptanceSilentDestructorFault;

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
impl Drop for AcceptanceSilentDestructorFault {
    fn drop(&mut self) {
        crate::trampoline::unwind_faulted_task();
    }
}

#[derive(Clone, Copy)]
struct OwnerSeal {
    epoch: u64,
    detach: CurrentTaskDetachLease,
}

impl OwnerSeal {
    fn matches(self, epoch: u64, detach: CurrentTaskDetachLease) -> bool {
        self.epoch == epoch && self.detach.matches_exact(detach)
    }

    fn callback_matches(self, epoch: u64, task: TaskId, domain: AllocationDomain) -> bool {
        self.epoch == epoch
            && self.detach.task_id() == task
            && self.detach.allocation_domain() == domain
    }
}

impl DelegatedChild {
    fn matches(self, epoch: u64, detach: PreparedTaskDetachSeal) -> bool {
        self.epoch == epoch && self.detach.matches_exact(detach)
    }

    fn callback_matches(self, epoch: u64, task: TaskId, domain: AllocationDomain) -> bool {
        self.epoch == epoch
            && self.detach.task_id() == task
            && self.detach.allocation_domain() == domain
    }

    fn current_irq_owner(self) -> bool {
        matches!(
            self.state,
            DelegatedChildState::Claimed | DelegatedChildState::CompletedPendingDetach
        ) && self.detach.is_current_irq_scope_exact()
    }
}

enum SlotState {
    Uninitialized,
    Ready(TargetReady<'static>),
    Reserved {
        ready: TargetReady<'static>,
        owner: OwnerSeal,
    },
    Active {
        sample: TargetActive<'static>,
        owner: OwnerSeal,
        child: Option<DelegatedChild>,
        child_detach: Option<TaskDetachReason>,
        faults: SlotFaults,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase: ManagedPhaseSidecar,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner: CoreObserverOwner,
    },
    Transit {
        owner: OwnerSeal,
        kind: TransitKind,
    },
    Verified {
        sample: TargetVerified<'static>,
        owner: OwnerSeal,
        cursor: usize,
    },
    Rejected {
        ready: TargetReady<'static>,
        report: RejectionReport,
    },
    Poisoned(SlotPoison),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DelegatedChildState {
    Attached,
    Claimed,
    CompletedPendingDetach,
    Abandoned,
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CoreObserverOwner {
    Closed,
    Parent,
    Child,
}

/// The managed child's resumable base phase. Wait and Host are lexical
/// overlays and therefore cannot replace this state. Cleanup is irreversible.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedChildBasePhase {
    Validation,
    Instantiation,
    Abi,
    Cleanup,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
impl ManagedChildBasePhase {
    const fn phase(self) -> Phase {
        match self {
            Self::Validation => Phase::Validation,
            Self::Instantiation => Phase::Instantiation,
            Self::Abi => Phase::Abi,
            Self::Cleanup => Phase::Cleanup,
        }
    }
}

/// Storage-resident diagnostic state for the exact SSH parent and its one
/// managed child. No guard or wait future owns this state across suspension.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ManagedPhaseSidecar {
    parent_waiting: bool,
    parent_host_active: bool,
    child_waiting: bool,
    child_host_open: bool,
    child_base: ManagedChildBasePhase,
    cleanup_latched: bool,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    parent_host_starts: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    parent_host_finishes: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    parent_wait_starts: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    parent_wait_finishes: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    child_host_starts: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    child_host_finishes: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    child_wait_starts: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    child_wait_finishes: u64,
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    cleanup_count: u64,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
impl ManagedPhaseSidecar {
    const NEW: Self = Self {
        parent_waiting: false,
        parent_host_active: false,
        child_waiting: false,
        child_host_open: false,
        child_base: ManagedChildBasePhase::Validation,
        cleanup_latched: false,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        parent_host_starts: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        parent_host_finishes: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        parent_wait_starts: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        parent_wait_finishes: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        child_host_starts: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        child_host_finishes: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        child_wait_starts: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        child_wait_finishes: 0,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        cleanup_count: 0,
    };

    /// Returns whether the ledger needs a real phase transition. Repeated
    /// runnable work in an already-open parent Host interval is a no-op.
    fn parent_host(&mut self) -> bool {
        let changed = self.parent_waiting || !self.parent_host_active;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        let closed_wait = self.parent_waiting;
        self.parent_waiting = false;
        self.parent_host_active = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.parent_host_starts = self.parent_host_starts.saturating_add(1);
            self.parent_host_finishes = self.parent_host_finishes.saturating_add(1);
            if closed_wait {
                self.parent_wait_finishes = self.parent_wait_finishes.saturating_add(1);
            }
        }
        changed
    }

    fn parent_wait(&mut self) -> Result<(), ()> {
        if self.parent_waiting {
            return Err(());
        }
        self.parent_waiting = true;
        self.parent_host_active = false;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.parent_wait_starts = self.parent_wait_starts.saturating_add(1);
        }
        Ok(())
    }

    fn parent_instantiation(&mut self) -> Result<(), ()> {
        if self.parent_waiting {
            return Err(());
        }
        self.parent_host_active = false;
        Ok(())
    }

    fn child_set_phase(&mut self, phase: Phase) -> Result<(), ()> {
        if self.child_waiting || self.child_host_open || self.cleanup_latched {
            return Err(());
        }
        let next = match (self.child_base, phase) {
            (ManagedChildBasePhase::Validation, Phase::Validation) => {
                ManagedChildBasePhase::Validation
            }
            (
                ManagedChildBasePhase::Validation | ManagedChildBasePhase::Instantiation,
                Phase::Instantiation,
            ) => ManagedChildBasePhase::Instantiation,
            (ManagedChildBasePhase::Instantiation | ManagedChildBasePhase::Abi, Phase::Abi) => {
                ManagedChildBasePhase::Abi
            }
            _ => return Err(()),
        };
        self.child_base = next;
        Ok(())
    }

    fn child_enter_wait(&mut self) -> Result<(), ()> {
        if self.child_waiting || self.child_host_open {
            return Err(());
        }
        self.child_waiting = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.child_wait_starts = self.child_wait_starts.saturating_add(1);
        }
        Ok(())
    }

    fn child_resume_from_wait(&mut self) -> Result<Phase, ()> {
        if !self.child_waiting || self.child_host_open {
            return Err(());
        }
        self.child_waiting = false;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.child_wait_finishes = self.child_wait_finishes.saturating_add(1);
        }
        Ok(self.child_base.phase())
    }

    fn child_enter_host(&mut self) -> Result<(), ()> {
        if self.child_waiting || self.child_host_open {
            return Err(());
        }
        self.child_host_open = true;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.child_host_starts = self.child_host_starts.saturating_add(1);
        }
        Ok(())
    }

    fn child_finish_host(&mut self) -> Result<Phase, ()> {
        if !self.child_host_open || self.child_waiting {
            return Err(());
        }
        self.child_host_open = false;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.child_host_finishes = self.child_host_finishes.saturating_add(1);
        }
        Ok(self.child_base.phase())
    }

    fn child_begin_cleanup(&mut self) -> Result<(), ()> {
        if self.cleanup_latched || self.child_waiting || self.child_host_open {
            return Err(());
        }
        self.cleanup_latched = true;
        self.child_base = ManagedChildBasePhase::Cleanup;
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        {
            self.cleanup_count = self.cleanup_count.saturating_add(1);
        }
        Ok(())
    }

    const fn child_release_ready(self) -> bool {
        self.cleanup_latched
            && matches!(self.child_base, ManagedChildBasePhase::Cleanup)
            && !self.child_waiting
            && !self.child_host_open
    }
}

#[cfg(all(test, feature = "wasm-c84-ssh-managed-child-phase-sidecar"))]
mod managed_phase_sidecar_tests {
    use super::*;

    #[test]
    fn child_wait_and_host_restore_the_stored_base() {
        let mut state = ManagedPhaseSidecar::NEW;
        state.child_set_phase(Phase::Validation).unwrap();
        state.child_set_phase(Phase::Instantiation).unwrap();
        state.child_set_phase(Phase::Abi).unwrap();

        state.child_enter_wait().unwrap();
        assert!(state.child_waiting);
        assert_eq!(state.child_resume_from_wait(), Ok(Phase::Abi));
        assert!(!state.child_waiting);

        state.child_begin_cleanup().unwrap();
        assert!(state.cleanup_latched);
        state.child_enter_host().unwrap();
        assert_eq!(state.child_finish_host(), Ok(Phase::Cleanup));
        state.child_enter_wait().unwrap();
        assert_eq!(state.child_resume_from_wait(), Ok(Phase::Cleanup));
        assert!(state.child_release_ready());
    }

    #[test]
    fn malformed_or_regressive_transitions_fail_closed() {
        let mut state = ManagedPhaseSidecar::NEW;
        assert_eq!(state.child_set_phase(Phase::Abi), Err(()));
        state.child_set_phase(Phase::Instantiation).unwrap();
        assert_eq!(state.child_set_phase(Phase::Validation), Err(()));

        state.child_enter_wait().unwrap();
        assert_eq!(state.child_enter_wait(), Err(()));
        assert_eq!(state.child_enter_host(), Err(()));
        state.child_resume_from_wait().unwrap();
        assert_eq!(state.child_resume_from_wait(), Err(()));

        state.child_set_phase(Phase::Abi).unwrap();
        state.child_begin_cleanup().unwrap();
        assert_eq!(state.child_begin_cleanup(), Err(()));
        assert_eq!(state.child_set_phase(Phase::Abi), Err(()));

        assert!(state.parent_host());
        assert!(!state.parent_host());
        state.parent_wait().unwrap();
        assert_eq!(state.parent_wait(), Err(()));
        assert!(state.parent_host());
        assert!(!state.parent_waiting);
    }

    #[test]
    fn parent_phase_only_bypasses_exact_wait_open_child_drop() {
        let exact = |change| {
            managed_parent_phase_bypasses_child_drop(
                change,
                false,
                Some(TaskDetachReason::Exited),
                SlotFaults::CHILD_ABANDONED_DETACHED,
                CoreObserverOwner::Closed,
                true,
                true,
                false,
            )
        };
        assert!(exact(ManagedParentPhaseChange::Host));
        assert!(exact(ManagedParentPhaseChange::Wait));
        assert!(!exact(ManagedParentPhaseChange::Instantiation));

        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            true,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Closed,
            true,
            true,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Cancelled),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Closed,
            true,
            true,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED,
            CoreObserverOwner::Closed,
            true,
            true,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Child,
            true,
            true,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Closed,
            false,
            true,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Closed,
            true,
            false,
            false,
        ));
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            SlotFaults::CHILD_ABANDONED_DETACHED,
            CoreObserverOwner::Closed,
            true,
            true,
            true,
        ));
        let mut extra_fault = SlotFaults::CHILD_ABANDONED_DETACHED;
        extra_fault.insert(SlotFaults::PARENT_PHASE);
        assert!(!managed_parent_phase_bypasses_child_drop(
            ManagedParentPhaseChange::Host,
            false,
            Some(TaskDetachReason::Exited),
            extra_fault,
            CoreObserverOwner::Closed,
            true,
            true,
            false,
        ));
    }

    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
    #[test]
    fn acceptance_counters_track_entries_and_exact_closures() {
        let mut state = ManagedPhaseSidecar::NEW;
        state.parent_host();
        state.parent_wait().unwrap();
        state.parent_host();
        state.child_enter_host().unwrap();
        state.child_finish_host().unwrap();
        state.child_enter_wait().unwrap();

        assert_eq!(state.parent_host_starts, 2);
        assert_eq!(state.parent_host_finishes, 2);
        assert_eq!(state.parent_wait_starts, 1);
        assert_eq!(state.parent_wait_finishes, 1);
        assert_eq!(state.child_host_starts, 1);
        assert_eq!(state.child_host_finishes, 1);
        assert_eq!(state.child_wait_starts, 1);
        assert_eq!(state.child_wait_finishes, 0);
        assert!(state.child_waiting);
    }
}

#[derive(Clone, Copy)]
struct DelegatedChild {
    epoch: u64,
    detach: PreparedTaskDetachSeal,
    state: DelegatedChildState,
    #[cfg(feature = "wasm-c84-ssh-managed-child-core")]
    driver_completed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitKind {
    Start,
    Finish,
    Cancel,
    Recycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SlotPoison {
    DuplicateInitialization = 1,
    StateMismatch = 2,
    DetachDisarm = 3,
    DetachedDuringTransit = 4,
    IrqStateMismatch = 5,
}

impl SlotPoison {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::DuplicateInitialization),
            2 => Some(Self::StateMismatch),
            3 => Some(Self::DetachDisarm),
            4 => Some(Self::DetachedDuringTransit),
            5 => Some(Self::IrqStateMismatch),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SlotFaults(u8);

impl SlotFaults {
    const NONE: Self = Self(0);
    const OWNER_NOT_CURRENT: Self = Self(1 << 0);
    const CHILD_OWNER_NOT_CURRENT: Self = Self(1 << 1);
    const CHILD_ABANDONED: Self = Self(1 << 2);
    const CHILD_DETACHED: Self = Self(1 << 3);
    const CHILD_ABANDONED_DETACHED: Self = Self((1 << 2) | (1 << 3));
    const CHILD_OBSERVER: Self = Self(1 << 4);
    const CORE_OBSERVER: Self = Self(1 << 5);
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    const CHILD_PHASE: Self = Self(1 << 6);
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    const PARENT_PHASE: Self = Self(1 << 7);

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
fn record_open_core_fault(faults: &mut SlotFaults, owner: CoreObserverOwner) {
    match owner {
        CoreObserverOwner::Closed => {}
        CoreObserverOwner::Parent => faults.insert(SlotFaults::CORE_OBSERVER),
        CoreObserverOwner::Child => faults.insert(SlotFaults::CHILD_OBSERVER),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionCause {
    LeaseCancelled,
    StreamAbandoned,
    TargetRejected,
    TaskDetached(TaskDetachReason),
    DelegatedChildAttached,
    DelegatedTaskDetached(TaskDetachReason),
    SlotFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RejectionReport {
    pub epoch: u64,
    pub cause: RejectionCause,
    pub facade_faults: FacadeFaults,
    pub ledger_error: Option<VerificationError>,
    pub slot_faults: SlotFaults,
    pub intervals_emitted: usize,
}

impl RejectionReport {
    fn from_target(
        target: &TargetRejected<'_>,
        cause: RejectionCause,
        slot_faults: SlotFaults,
        intervals_emitted: usize,
    ) -> Self {
        Self {
            epoch: target.token().epoch(),
            cause,
            facade_faults: target.facade_faults(),
            ledger_error: target.ledger_error(),
            slot_faults,
            intervals_emitted,
        }
    }

    fn detached_verified(epoch: u64, reason: TaskDetachReason, cursor: usize) -> Self {
        Self {
            epoch,
            cause: RejectionCause::TaskDetached(reason),
            facade_faults: FacadeFaults::NONE,
            ledger_error: None,
            slot_faults: SlotFaults::NONE,
            intervals_emitted: cursor,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotStatus {
    Uninitialized,
    Ready {
        next_epoch: Option<u64>,
    },
    Reserved {
        epoch: u64,
    },
    Active {
        epoch: u64,
    },
    Delegated {
        epoch: u64,
        claimed: bool,
    },
    Transit {
        epoch: u64,
        kind: TransitKind,
    },
    Verified {
        epoch: u64,
        cursor: usize,
        intervals: usize,
    },
    Rejected(RejectionReport),
    Poisoned(SlotPoison),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileError {
    Uninitialized,
    Busy,
    Exhausted,
    RejectionPending,
    RegistrationReserveFailed,
    Registration(TaskDetachRegistrationError),
    Detach(TaskDetachDisarm),
    OwnerNotCurrent,
    DelegatedChildAttached,
    DelegatedChildUnavailable,
    StateMismatch,
    Start(TargetStartError),
    Facade(FacadeFaults),
    SlotFault(SlotFaults),
    IncompleteStream { emitted: usize, required: usize },
    Rejected(RejectionReport),
    Poisoned(SlotPoison),
}

/// One Core-finish boundary even when the slot operation latched a failure.
///
/// `ProfileClock` is infallible. Keeping the original tick beside the sticky
/// error lets the runtime close its aggregate with the exact tick already used
/// by the target ledger instead of taking an unsound replacement sample.
#[cfg(feature = "wasm-c84-core-poll-observer")]
struct PhaseBoundary {
    tick: u64,
    error: Option<ProfileError>,
}

fn poison(reason: SlotPoison) {
    let _ = POISON.compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire);
    #[cfg(feature = "wasm-c84-profile-irq-overlay")]
    ACTIVE_EPOCH.store(0, Ordering::Release);
}

fn poison_reason() -> Option<SlotPoison> {
    SlotPoison::from_code(POISON.load(Ordering::Acquire))
}

fn ensure_not_poisoned() -> Result<(), ProfileError> {
    match poison_reason() {
        Some(reason) => Err(ProfileError::Poisoned(reason)),
        None => Ok(()),
    }
}

fn live_context() -> TargetContext {
    TargetContext::new(
        u64::try_from(crate::online_hart_mask()).unwrap_or(u64::MAX),
        crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
        crate::sbi::current_hart_id(),
    )
}

fn live_tick() -> u64 {
    crate::sbi::time()
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
fn publish_active_epoch(epoch: u64) -> Result<(), ProfileError> {
    if let Some(reason) = poison_reason() {
        ACTIVE_EPOCH.store(0, Ordering::Release);
        return Err(ProfileError::Poisoned(reason));
    }
    if epoch == 0
        || ACTIVE_EPOCH
            .compare_exchange(0, epoch, Ordering::Release, Ordering::Acquire)
            .is_err()
    {
        poison(SlotPoison::IrqStateMismatch);
        return Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch));
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
fn clear_active_epoch(epoch: u64) -> Result<(), ProfileError> {
    if let Some(reason) = poison_reason() {
        ACTIVE_EPOCH.store(0, Ordering::Release);
        return Err(ProfileError::Poisoned(reason));
    }
    if epoch == 0
        || ACTIVE_EPOCH
            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        poison(SlotPoison::IrqStateMismatch);
        return Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch));
    }
    Ok(())
}

/// Linear trap-stack witness for one target interrupt overlay. The inactive
/// value keeps trap exit unconditional without exposing the facade cookie.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
#[must_use]
pub(crate) struct TrapIrqCookie {
    epoch: u64,
    inner: IrqCookie,
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
impl TrapIrqCookie {
    const fn inactive() -> Self {
        Self {
            epoch: 0,
            inner: IrqCookie::inactive(),
        }
    }
}

/// Opens a Wait overlay at the assembly-captured trap-entry tick. Only an IRQ
/// preempting the exact current slot owner may mutate the sample.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
pub(crate) fn profile_irq_enter(irq_entry: u64) -> TrapIrqCookie {
    if poison_reason().is_some() {
        return TrapIrqCookie::inactive();
    }
    let epoch = ACTIVE_EPOCH.load(Ordering::Acquire);
    if epoch == 0 {
        return TrapIrqCookie::inactive();
    }

    let mut slot = SLOT.lock();
    if poison_reason().is_some() {
        return TrapIrqCookie::inactive();
    }
    let SlotState::Active {
        sample,
        owner,
        child,
        faults,
        ..
    } = &mut *slot
    else {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return TrapIrqCookie::inactive();
    };
    let token = sample.token();
    if token.epoch() != epoch {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return TrapIrqCookie::inactive();
    }
    if !owner.detach.is_current_irq_scope_exact()
        && !child
            .as_ref()
            .is_some_and(|child| child.current_irq_owner())
    {
        return TrapIrqCookie::inactive();
    }
    if !faults.is_empty() {
        return TrapIrqCookie::inactive();
    }
    let context = live_context();
    let inner = sample.interrupt_enter(token, context, irq_entry);
    TrapIrqCookie { epoch, inner }
}

/// Closes one active overlay at the trap-supplied exit boundary. The caller
/// samples that boundary after handler work and allocation-owner restoration,
/// before this function can wait for the slot lock.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
pub(crate) fn profile_irq_exit(cookie: TrapIrqCookie, exit_tick: u64) -> bool {
    if cookie.epoch == 0 {
        return false;
    }
    if poison_reason().is_some() || ACTIVE_EPOCH.load(Ordering::Acquire) != cookie.epoch {
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }

    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        child,
        faults,
        ..
    } = &mut *slot
    else {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    };
    let token = sample.token();
    if token.epoch() != cookie.epoch {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }
    if !owner.detach.is_current_irq_scope_exact()
        && !child
            .as_ref()
            .is_some_and(|child| child.current_irq_owner())
    {
        faults.insert(SlotFaults::OWNER_NOT_CURRENT);
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }
    let context = live_context();
    let applied = cookie.inner.is_active();
    sample.interrupt_exit(cookie.inner, context, exit_tick);
    applied
}

/// Acceptance-only attribution for the code=1 trap branch. Production state
/// remains limited to the active-epoch gate and the target's linear cookie.
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
pub(crate) fn profile_irq_acceptance_note_ssip(applied: bool) {
    if applied {
        ACCEPTANCE_SSIP_PAIRED.fetch_add(1, Ordering::Relaxed);
    } else {
        ACCEPTANCE_SSIP_INACTIVE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Allocates and installs the exact packed storage once, before secondary
/// harts are released. Box leaking is deliberate: the unique mutable borrows
/// then live only inside the single target lineage for the life of the kernel.
pub(crate) fn init() {
    let endpoints = Box::leak(alloc::vec![0_u64; INTERVAL_CAPACITY].into_boxed_slice());
    let phases = Box::leak(alloc::vec![0_u8; INTERVAL_CAPACITY].into_boxed_slice());
    let storage = Storage::new(endpoints, phases).expect("C8.4 slot storage has exact capacity");
    let ready = TargetReady::new(storage);

    let mut slot = SLOT.lock();
    if matches!(&*slot, SlotState::Uninitialized) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return;
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::DuplicateInitialization);
    panic!("C8.4 profile slot initialized more than once");
}

pub(crate) fn status() -> SlotStatus {
    if let Some(reason) = poison_reason() {
        return SlotStatus::Poisoned(reason);
    }
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Uninitialized => SlotStatus::Uninitialized,
        SlotState::Ready(ready) => SlotStatus::Ready {
            next_epoch: ready.next_epoch(),
        },
        SlotState::Reserved { owner, .. } => SlotStatus::Reserved { epoch: owner.epoch },
        SlotState::Active {
            sample,
            child: Some(child),
            ..
        } => SlotStatus::Delegated {
            epoch: sample.token().epoch(),
            claimed: child.state != DelegatedChildState::Attached,
        },
        SlotState::Active { sample, .. } => SlotStatus::Active {
            epoch: sample.token().epoch(),
        },
        SlotState::Transit { owner, kind } => SlotStatus::Transit {
            epoch: owner.epoch,
            kind: *kind,
        },
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } => SlotStatus::Verified {
            epoch: owner.epoch,
            cursor: *cursor,
            intervals: sample.summary().interval_count(),
        },
        SlotState::Rejected { report, .. } => SlotStatus::Rejected(*report),
        SlotState::Poisoned(reason) => SlotStatus::Poisoned(*reason),
    }
}

/// Require the real managed child to have released and then reached its exact
/// executor `Exited` callback before an SSH response may close the request.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn managed_child_response_ready(epoch: u64) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Active {
            sample,
            child: None,
            child_detach: Some(TaskDetachReason::Exited),
            faults,
            core_owner,
            ..
        } if sample.token().epoch() == epoch
            && faults.is_empty()
            && *core_owner == CoreObserverOwner::Closed =>
        {
            Ok(())
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

/// Require the complete phase sidecar closure before the authenticated parent
/// emits its response. Unlike cancellation, a stale Wait is a successful-path
/// protocol violation and becomes a sticky request-local fault.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_phase_response_ready(epoch: u64) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child,
        child_detach,
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token().epoch() != epoch {
        return Err(ProfileError::StateMismatch);
    }
    if managed_phase.parent_waiting {
        faults.insert(SlotFaults::PARENT_PHASE);
    }
    if managed_phase.child_waiting
        || managed_phase.child_host_open
        || !managed_phase.cleanup_latched
    {
        faults.insert(SlotFaults::CHILD_PHASE);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    if child.is_none()
        && *child_detach == Some(TaskDetachReason::Exited)
        && *core_owner == CoreObserverOwner::Closed
    {
        Ok(())
    } else {
        Err(ProfileError::StateMismatch)
    }
}

/// Acceptance-only non-consuming snapshot. Reading it neither repairs an
/// open wait nor advances the existing managed-child trace state.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManagedPhaseObservation {
    pub(crate) parent_host_starts: u64,
    pub(crate) parent_host_finishes: u64,
    pub(crate) parent_wait_starts: u64,
    pub(crate) parent_wait_finishes: u64,
    pub(crate) child_host_starts: u64,
    pub(crate) child_host_finishes: u64,
    pub(crate) child_wait_starts: u64,
    pub(crate) child_wait_finishes: u64,
    pub(crate) cleanup_count: u64,
    pub(crate) cleanup_latched: bool,
    pub(crate) parent_wait_open: bool,
    pub(crate) child_wait_open: bool,
    pub(crate) child_host_open: bool,
    pub(crate) child_base: Phase,
    pub(crate) child_phase_fault: bool,
    pub(crate) parent_phase_fault: bool,
    pub(crate) child_attached: bool,
    pub(crate) child_detach: Option<TaskDetachReason>,
    pub(crate) slot_faults: SlotFaults,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
pub(crate) fn managed_phase_observation(
    epoch: u64,
) -> Result<ManagedPhaseObservation, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child,
        child_detach,
        faults,
        managed_phase,
        ..
    } = &*slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token().epoch() != epoch {
        return Err(ProfileError::StateMismatch);
    }
    Ok(ManagedPhaseObservation {
        parent_host_starts: managed_phase.parent_host_starts,
        parent_host_finishes: managed_phase.parent_host_finishes,
        parent_wait_starts: managed_phase.parent_wait_starts,
        parent_wait_finishes: managed_phase.parent_wait_finishes,
        child_host_starts: managed_phase.child_host_starts,
        child_host_finishes: managed_phase.child_host_finishes,
        child_wait_starts: managed_phase.child_wait_starts,
        child_wait_finishes: managed_phase.child_wait_finishes,
        cleanup_count: managed_phase.cleanup_count,
        cleanup_latched: managed_phase.cleanup_latched,
        parent_wait_open: managed_phase.parent_waiting,
        child_wait_open: managed_phase.child_waiting,
        child_host_open: managed_phase.child_host_open,
        child_base: managed_phase.child_base.phase(),
        child_phase_fault: faults.contains(SlotFaults::CHILD_PHASE),
        parent_phase_fault: faults.contains(SlotFaults::PARENT_PHASE),
        child_attached: child.is_some(),
        child_detach: *child_detach,
        slot_faults: *faults,
    })
}

/// Freeze the only request-Drop child outcomes accepted by the production
/// composition. This is deliberately not “accept whatever faults are there”:
/// an open observer, a wrong-owner fault, or any unrelated slot bit remains a
/// hard mismatch.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn managed_child_drop_faults(epoch: u64) -> Result<SlotFaults, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child,
        child_detach,
        faults,
        core_owner,
        ..
    } = &*slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token().epoch() != epoch || *core_owner != CoreObserverOwner::Closed {
        return Err(ProfileError::StateMismatch);
    }
    let mut detached = SlotFaults::NONE;
    detached.insert(SlotFaults::CHILD_DETACHED);
    let mut abandoned = detached;
    abandoned.insert(SlotFaults::CHILD_ABANDONED);
    match (child, child_detach, *faults) {
        (None, None, exact) if exact.is_empty() => Ok(exact),
        (None, Some(TaskDetachReason::Exited), exact) if exact.is_empty() || exact == abandoned => {
            Ok(exact)
        }
        (None, Some(TaskDetachReason::Cancelled | TaskDetachReason::Faulted), exact)
            if exact == detached || exact == abandoned =>
        {
            Ok(exact)
        }
        _ => Err(ProfileError::SlotFault(*faults)),
    }
}

/// The QEMU active-kill proof accepts one diagnostic outcome only: the real
/// child was abandoned by its executor envelope, then detached as Exited with
/// its Core observer closed. Broader production request-Drop cleanup remains
/// available above for failures which happen before this acceptance scenario.
#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn managed_child_active_drop_ready(epoch: u64) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Active {
            sample,
            child: None,
            child_detach: Some(TaskDetachReason::Exited),
            faults,
            core_owner,
            ..
        } if sample.token().epoch() == epoch
            && *faults == SlotFaults::CHILD_ABANDONED_DETACHED
            && *core_owner == CoreObserverOwner::Closed =>
        {
            Ok(())
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn record_managed_child_bound(epoch: u64) -> Result<(), ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    if epoch == 0 || trace.state != MANAGED_TRACE_IDLE {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    *trace = ManagedChildTrace {
        epoch,
        state: MANAGED_TRACE_BOUND,
        ..ManagedChildTrace::EMPTY
    };
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn record_managed_child_claimed(epoch: u64) -> Result<(), ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    if trace.epoch != epoch || trace.state != MANAGED_TRACE_BOUND || trace.invalid {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    trace.state = MANAGED_TRACE_CLAIMED;
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn record_managed_child_core_pair(
    epoch: u64,
    before: u64,
    after: u64,
) -> Result<bool, ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    let first = trace.core_pairs == 0;
    if trace.epoch != epoch
        || !matches!(trace.state, MANAGED_TRACE_CLAIMED | MANAGED_TRACE_CORE)
        || trace.invalid
        || before != trace.core_pairs
        || after != before.checked_add(1).ok_or(ProfileError::Exhausted)?
    {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    trace.core_pairs = after;
    trace.state = MANAGED_TRACE_CORE;
    Ok(first)
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn record_managed_child_core_profile(
    epoch: u64,
    profile: vibeos_component_runtime::sync::SyncCallProfile,
) {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    let exact = trace.epoch == epoch
        && trace.state == MANAGED_TRACE_CORE
        && !trace.invalid
        && trace.core_pairs != 0
        && trace.core_pairs == profile.core_polls
        && profile.typed_polls >= profile.core_polls
        && profile.typed_polls != u64::MAX
        && profile.core_polls != u64::MAX
        && profile.outer_poll_ticks != u64::MAX
        && profile.core_interpreter_ticks != u64::MAX
        && profile.consumed_work != u64::MAX;
    if exact {
        trace.typed_polls = profile.typed_polls;
        trace.core_polls = profile.core_polls;
        trace.state = MANAGED_TRACE_PROFILED;
    } else {
        trace.invalid = true;
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn record_managed_child_released(epoch: u64) -> Result<(), ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    if trace.epoch != epoch || trace.state != MANAGED_TRACE_PROFILED || trace.invalid {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    trace.state = MANAGED_TRACE_RELEASED;
    Ok(())
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
fn record_managed_child_detached(epoch: u64, reason: TaskDetachReason, clean: bool) {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    let state_exact = if clean {
        trace.state == MANAGED_TRACE_RELEASED && reason == TaskDetachReason::Exited
    } else {
        matches!(
            trace.state,
            MANAGED_TRACE_BOUND | MANAGED_TRACE_CLAIMED | MANAGED_TRACE_CORE
        ) && reason == TaskDetachReason::Exited
    };
    if trace.epoch == epoch && !trace.invalid && state_exact {
        trace.state = MANAGED_TRACE_DETACHED;
        trace.detach = Some(reason);
    } else {
        trace.invalid = true;
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn take_managed_child_response_observation(
    epoch: u64,
) -> Result<ManagedChildCoreObservation, ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    let exact = trace.epoch == epoch
        && trace.state == MANAGED_TRACE_DETACHED
        && trace.detach == Some(TaskDetachReason::Exited)
        && !trace.invalid
        && trace.core_pairs != 0
        && trace.core_pairs == trace.core_polls
        && trace.typed_polls >= trace.core_polls;
    if !exact {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    let observation = ManagedChildCoreObservation {
        core_pairs: trace.core_pairs,
        typed_polls: trace.typed_polls,
        core_polls: trace.core_polls,
    };
    *trace = ManagedChildTrace::EMPTY;
    Ok(observation)
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
pub(crate) fn take_managed_child_drop_observation(
    epoch: u64,
) -> Result<(u64, TaskDetachReason), ProfileError> {
    let mut trace = MANAGED_CHILD_TRACE.lock();
    let exact = trace.epoch == epoch
        && trace.state == MANAGED_TRACE_DETACHED
        && trace.detach == Some(TaskDetachReason::Exited)
        && !trace.invalid
        && trace.core_pairs != 0
        && trace.typed_polls == 0
        && trace.core_polls == 0;
    if !exact {
        trace.invalid = true;
        return Err(ProfileError::StateMismatch);
    }
    let observation = (
        trace.core_pairs,
        trace
            .detach
            .expect("exact Drop trace has one detach reason"),
    );
    *trace = ManagedChildTrace::EMPTY;
    Ok(observation)
}

fn next_epoch_for_prepare() -> Result<u64, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Ready(ready) => ready.next_epoch().ok_or(ProfileError::Exhausted),
        SlotState::Uninitialized => Err(ProfileError::Uninitialized),
        SlotState::Rejected { .. } => Err(ProfileError::RejectionPending),
        SlotState::Poisoned(reason) => Err(ProfileError::Poisoned(*reason)),
        _ => Err(ProfileError::Busy),
    }
}

fn task_detach_target(epoch: u64) -> TaskDetachTarget {
    // SAFETY: `profile_task_detached` is a permanent kernel function. Its
    // context is a scalar epoch; it allocates nothing, never awaits, only
    // holds the IRQ-masking slot lock for O(1) transitions, and performs the
    // bounded full-buffer clear after releasing that lock.
    unsafe { TaskDetachTarget::new(epoch, profile_task_detached) }
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn child_task_detach_target(epoch: u64) -> TaskDetachTarget {
    // SAFETY: `profile_child_detached` is a permanent, allocation-free kernel
    // callback. Its scalar epoch is checked together with the exact prepared
    // task and allocation domain stored in the active slot.
    unsafe { TaskDetachTarget::new(epoch, profile_child_detached) }
}

fn disarm(detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    let result = detach.disarm();
    if result == TaskDetachDisarm::Disarmed {
        Ok(())
    } else {
        poison(SlotPoison::DetachDisarm);
        Err(ProfileError::Detach(result))
    }
}

fn reserve_ready(epoch: u64, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    match &*slot {
        SlotState::Ready(ready) if ready.next_epoch() == Some(epoch) => {}
        SlotState::Ready(ready) if ready.is_exhausted() => return Err(ProfileError::Exhausted),
        SlotState::Ready(_) => return Err(ProfileError::Busy),
        SlotState::Rejected { .. } => return Err(ProfileError::RejectionPending),
        SlotState::Uninitialized => return Err(ProfileError::Uninitialized),
        SlotState::Poisoned(reason) => return Err(ProfileError::Poisoned(*reason)),
        _ => return Err(ProfileError::Busy),
    }

    let owner = OwnerSeal { epoch, detach };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Start,
        },
    );
    let SlotState::Ready(ready) = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    *slot = SlotState::Reserved { ready, owner };
    Ok(())
}

/// Preallocates one detach-ledger entry and reserves the current Ready epoch.
/// This must run before the request acceptance/start tick boundary.
pub(crate) fn prepare_current() -> Result<StartPermit, ProfileError> {
    let epoch = next_epoch_for_prepare()?;
    if !crate::exec::try_reserve_current_task_registrations(1) {
        return Err(ProfileError::RegistrationReserveFailed);
    }
    let target = task_detach_target(epoch);
    // SAFETY: `target` satisfies TaskDetachTarget's permanent SYSTEM callback
    // contract, and the returned exact lease remains both in the reservation
    // state and in the storage-free permit until one side disarms or detaches.
    let detach = unsafe { crate::exec::register_current_task_detach(target) }
        .map_err(ProfileError::Registration)?;
    if !detach.is_current_running_exact() {
        let _ = disarm(detach);
        return Err(ProfileError::OwnerNotCurrent);
    }
    if let Err(error) = reserve_ready(epoch, detach) {
        disarm(detach)?;
        return Err(error);
    }
    Ok(StartPermit {
        epoch,
        detach,
        live: true,
        not_sync: PhantomData,
    })
}

fn owner_matches(owner: OwnerSeal, epoch: u64, detach: CurrentTaskDetachLease) -> bool {
    owner.matches(epoch, detach)
}

fn release_reservation(epoch: u64, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let owner = OwnerSeal { epoch, detach };
    let ready = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Reserved { owner, .. } if owner_matches(*owner, epoch, detach)
        );
        if !exact {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Start,
            },
        );
        let SlotState::Reserved { ready, .. } = previous else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        ready
    };

    if let Err(error) = disarm(detach) {
        drop(ready);
        return Err(error);
    }

    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Start }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && ready.next_epoch() == Some(epoch) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn start_reserved(epoch: u64, detach: CurrentTaskDetachLease) -> Result<SampleToken, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Reserved { owner, .. } if owner_matches(*owner, epoch, detach)
    );
    if !exact {
        return Err(ProfileError::StateMismatch);
    }

    let context = live_context();
    let tick = live_tick();
    let owner = OwnerSeal { epoch, detach };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Start,
        },
    );
    let SlotState::Reserved { ready, .. } = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    match ready.start(context, tick) {
        Ok(sample) => {
            let token = sample.token();
            if token.epoch() != epoch {
                poison(SlotPoison::StateMismatch);
                drop(slot);
                let rejected = sample.cancel(token, context);
                drop(rejected);
                return Err(ProfileError::StateMismatch);
            }
            #[cfg(feature = "wasm-c84-profile-irq-overlay")]
            if let Err(error) = publish_active_epoch(token.epoch()) {
                *slot = SlotState::Poisoned(SlotPoison::IrqStateMismatch);
                drop(sample);
                return Err(error);
            }
            *slot = SlotState::Active {
                sample,
                owner,
                child: None,
                child_detach: None,
                faults: SlotFaults::NONE,
                #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
                managed_phase: ManagedPhaseSidecar::NEW,
                #[cfg(feature = "wasm-c84-core-poll-observer")]
                core_owner: CoreObserverOwner::Closed,
            };
            Ok(token)
        }
        Err(failure) => {
            let error = failure.error();
            *slot = SlotState::Reserved {
                ready: failure.into_ready(),
                owner,
            };
            Err(ProfileError::Start(error))
        }
    }
}

/// Storage-free reservation proof. It is `Send` but deliberately not `Sync`.
pub(crate) struct StartPermit {
    epoch: u64,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl StartPermit {
    pub(crate) const fn expected_epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn start(mut self) -> Result<RunLease, ProfileError> {
        if !self.detach.is_current_running_exact() {
            let error = release_reservation(self.epoch, self.detach)
                .err()
                .unwrap_or(ProfileError::OwnerNotCurrent);
            self.live = false;
            return Err(error);
        }
        match start_reserved(self.epoch, self.detach) {
            Ok(token) => {
                self.live = false;
                Ok(RunLease {
                    token,
                    detach: self.detach,
                    live: true,
                    not_sync: PhantomData,
                })
            }
            Err(error) => {
                let release = release_reservation(self.epoch, self.detach);
                self.live = false;
                match release {
                    Ok(()) => Err(error),
                    Err(release_error) => Err(release_error),
                }
            }
        }
    }
}

impl Drop for StartPermit {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = release_reservation(self.epoch, self.detach);
        }
    }
}

fn mark_owner_fault(token: SampleToken, detach: CurrentTaskDetachLease) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        owner,
        faults,
        ..
    } = &mut *slot
    {
        if sample.token() == token && owner.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::OWNER_NOT_CURRENT);
        }
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
fn mark_core_observer_fault(token: SampleToken, detach: CurrentTaskDetachLease) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        owner,
        faults,
        ..
    } = &mut *slot
    {
        if sample.token() == token && owner.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::CORE_OBSERVER);
        }
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
fn parent_core_is_closed(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<bool, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        core_owner,
        ..
    } = &*slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return Err(ProfileError::StateMismatch);
    }
    Ok(*core_owner == CoreObserverOwner::Closed)
}

fn apply_phase(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    phase: Option<Phase>,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        faults,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return Err(ProfileError::StateMismatch);
    }
    #[cfg(feature = "wasm-c84-core-poll-observer")]
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CORE_OBSERVER);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    let context = live_context();
    let tick = live_tick();
    match phase {
        Some(phase) => sample.set_phase(token, context, tick, phase),
        None => sample.begin_cleanup(token, context, tick),
    }
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Facade(facade))
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
#[derive(Clone, Copy)]
enum ManagedParentPhaseChange {
    Host,
    Wait,
    Instantiation,
}

/// Once the exact active child has been abandoned and detached while its
/// Wait remains open, waking the parent is part of cancellation diagnosis,
/// not a new transport phase. Keep both Wait ledgers untouched so the parent
/// Drop path can report the precise open-at-cancel state.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn managed_parent_phase_bypasses_child_drop(
    change: ManagedParentPhaseChange,
    child_attached: bool,
    child_detach: Option<TaskDetachReason>,
    faults: SlotFaults,
    core_owner: CoreObserverOwner,
    parent_waiting: bool,
    child_waiting: bool,
    child_host_open: bool,
) -> bool {
    matches!(change, ManagedParentPhaseChange::Host | ManagedParentPhaseChange::Wait)
        && !child_attached
        && child_detach == Some(TaskDetachReason::Exited)
        && faults == SlotFaults::CHILD_ABANDONED_DETACHED
        && core_owner == CoreObserverOwner::Closed
        && parent_waiting
        && child_waiting
        && !child_host_open
}

/// Apply one parent transport transition after the caller has proved the
/// current task outside SLOT. The sidecar mutation and ledger tick are one
/// synchronous critical section; no async or telemetry edge is reachable.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn apply_managed_parent_phase(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    change: ManagedParentPhaseChange,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        child,
        child_detach,
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::PARENT_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if managed_parent_phase_bypasses_child_drop(
        change,
        child.is_some(),
        *child_detach,
        *faults,
        *core_owner,
        managed_phase.parent_waiting,
        managed_phase.child_waiting,
        managed_phase.child_host_open,
    ) {
        return Ok(());
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }

    let (phase, changed) = match change {
        ManagedParentPhaseChange::Host => (Phase::Host, managed_phase.parent_host()),
        ManagedParentPhaseChange::Wait => {
            if managed_phase.parent_wait().is_err() {
                faults.insert(SlotFaults::PARENT_PHASE);
                return Err(ProfileError::StateMismatch);
            }
            (Phase::Wait, true)
        }
        ManagedParentPhaseChange::Instantiation => {
            if managed_phase.parent_instantiation().is_err() {
                faults.insert(SlotFaults::PARENT_PHASE);
                return Err(ProfileError::StateMismatch);
            }
            (Phase::Instantiation, true)
        }
    };
    if changed {
        sample.set_phase(token, live_context(), live_tick(), phase);
    }
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::PARENT_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

/// Set the exact current SSH request parent to Instantiation without lending
/// its RunLease to component preparation. A non-parent task is inert.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_current_parent_set_instantiation() -> Result<Option<u64>, ProfileError> {
    ensure_not_poisoned()?;
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active { sample, owner, .. } => Some((sample.token(), owner.detach)),
            _ => None,
        }
    };
    let Some((token, detach)) = candidate else {
        return Ok(None);
    };
    if !detach.is_current_running_exact() {
        return Ok(None);
    }
    apply_managed_parent_phase(token, detach, ManagedParentPhaseChange::Instantiation)?;
    Ok(Some(token.epoch()))
}

/// Opens parent-owned Interpretation only while no delegated child or other
/// Core observer owns the request-wide ledger boundary.
#[cfg(feature = "wasm-c84-core-poll-observer")]
fn begin_core_phase(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        child,
        faults,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return Err(ProfileError::StateMismatch);
    }
    if child.is_some() || *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CORE_OBSERVER);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    *core_owner = CoreObserverOwner::Parent;
    sample.set_phase(token, live_context(), live_tick(), Phase::Interpretation);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Facade(facade))
    }
}

/// Closes Interpretation with one tick that is both recorded in the ledger
/// and returned to the portable runtime observer.
#[cfg(feature = "wasm-c84-core-poll-observer")]
fn end_core_phase(token: SampleToken, detach: CurrentTaskDetachLease) -> PhaseBoundary {
    if let Err(error) = ensure_not_poisoned() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(error),
        };
    }
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        faults,
        core_owner,
        ..
    } = &mut *slot
    else {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    if *core_owner != CoreObserverOwner::Parent {
        faults.insert(SlotFaults::CORE_OBSERVER);
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    if !faults.is_empty() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::SlotFault(*faults)),
        };
    }
    let context = live_context();
    let tick = live_tick();
    sample.set_phase(token, context, tick, Phase::Abi);
    *core_owner = CoreObserverOwner::Closed;
    let facade = sample.facade_faults();
    PhaseBoundary {
        tick,
        error: if facade.is_empty() {
            None
        } else {
            Some(ProfileError::Facade(facade))
        },
    }
}

fn install_verified(owner: OwnerSeal, sample: TargetVerified<'static>) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Finish }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && sample.token().epoch() == owner.epoch && poison_reason().is_none() {
        *slot = SlotState::Verified {
            sample,
            owner,
            cursor: 0,
        };
        return Ok(());
    }
    drop(slot);
    drop(sample);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn install_rejected(
    owner: OwnerSeal,
    expected_kind: TransitKind,
    ready: TargetReady<'static>,
    report: RejectionReport,
) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind }
            if actual.matches(owner.epoch, owner.detach) && *kind == expected_kind
    );
    if exact
        && report.epoch == owner.epoch
        && ready.next_epoch() == owner.epoch.checked_add(1)
        && poison_reason().is_none()
    {
        *slot = SlotState::Rejected { ready, report };
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn reject_target_normal(
    owner: OwnerSeal,
    expected_kind: TransitKind,
    rejected: TargetRejected<'static>,
    cause: RejectionCause,
    slot_faults: SlotFaults,
    intervals_emitted: usize,
) -> Result<RejectionReport, ProfileError> {
    let report = RejectionReport::from_target(&rejected, cause, slot_faults, intervals_emitted);
    let ready = rejected.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    install_rejected(owner, expected_kind, ready, report)?;
    Ok(report)
}

fn finish_active(token: SampleToken, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let (sample, owner, child_attached, child_detach, slot_faults, context, tick) = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Active { sample, owner, .. }
                if sample.token() == token && owner.matches(token.epoch(), detach)
        );
        if !exact {
            return Err(ProfileError::StateMismatch);
        }
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        if let SlotState::Active {
            core_owner, faults, ..
        } = &mut *slot
        {
            record_open_core_fault(faults, *core_owner);
        }
        let context = live_context();
        let tick = live_tick();
        let owner = OwnerSeal {
            epoch: token.epoch(),
            detach,
        };
        #[cfg(feature = "wasm-c84-profile-irq-overlay")]
        if let Err(error) = clear_active_epoch(token.epoch()) {
            let previous = mem::replace(
                &mut *slot,
                SlotState::Poisoned(SlotPoison::IrqStateMismatch),
            );
            drop(previous);
            return Err(error);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Finish,
            },
        );
        let SlotState::Active {
            sample,
            owner,
            child,
            child_detach,
            faults,
            ..
        } = previous
        else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        (
            sample,
            owner,
            child.is_some(),
            child_detach,
            faults,
            context,
            tick,
        )
    };

    if child_attached
        || !slot_faults.is_empty()
        || matches!(child_detach, Some(reason) if reason != TaskDetachReason::Exited)
    {
        let rejected = sample.cancel(token, context);
        let cause = if child_attached {
            RejectionCause::DelegatedChildAttached
        } else if slot_faults.contains(SlotFaults::CHILD_DETACHED) {
            let reason = child_detach.expect("a delegated detach fault records its exact reason");
            RejectionCause::DelegatedTaskDetached(reason)
        } else {
            RejectionCause::SlotFault
        };
        let report =
            reject_target_normal(owner, TransitKind::Finish, rejected, cause, slot_faults, 0)?;
        return Err(ProfileError::Rejected(report));
    }

    let finished = match sample.finish(token, context, tick) {
        Ok(finished) => finished,
        Err(rejected) => {
            let report = reject_target_normal(
                owner,
                TransitKind::Finish,
                rejected,
                RejectionCause::TargetRejected,
                slot_faults,
                0,
            )?;
            return Err(ProfileError::Rejected(report));
        }
    };
    match finished.verify() {
        Ok(verified) => install_verified(owner, verified),
        Err(rejected) => {
            let report = reject_target_normal(
                owner,
                TransitKind::Finish,
                rejected,
                RejectionCause::TargetRejected,
                slot_faults,
                0,
            )?;
            Err(ProfileError::Rejected(report))
        }
    }
}

fn cancel_active(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    cause: RejectionCause,
) -> Result<RejectionReport, ProfileError> {
    ensure_not_poisoned()?;
    let (sample, owner, faults, context) = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Active { sample, owner, .. }
                if sample.token() == token && owner.matches(token.epoch(), detach)
        );
        if !exact {
            return Err(ProfileError::StateMismatch);
        }
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        if let SlotState::Active {
            managed_phase,
            faults,
            ..
        } = &mut *slot
        {
            // Wait is an expected cancellation snapshot. A synchronous Host
            // guard cannot legally survive to this boundary.
            if managed_phase.child_host_open {
                faults.insert(SlotFaults::CHILD_PHASE);
            }
        }
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        if let SlotState::Active {
            core_owner, faults, ..
        } = &mut *slot
        {
            record_open_core_fault(faults, *core_owner);
        }
        let context = live_context();
        let owner = OwnerSeal {
            epoch: token.epoch(),
            detach,
        };
        #[cfg(feature = "wasm-c84-profile-irq-overlay")]
        if let Err(error) = clear_active_epoch(token.epoch()) {
            let previous = mem::replace(
                &mut *slot,
                SlotState::Poisoned(SlotPoison::IrqStateMismatch),
            );
            drop(previous);
            return Err(error);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Cancel,
            },
        );
        let SlotState::Active {
            sample,
            owner,
            faults,
            ..
        } = previous
        else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        (sample, owner, faults, context)
    };
    let rejected = sample.cancel(token, context);
    reject_target_normal(owner, TransitKind::Cancel, rejected, cause, faults, 0)
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn attach_prepared_child(
    token: SampleToken,
    parent: CurrentTaskDetachLease,
    batch: &mut crate::exec::PreparedTaskBatch,
    task_index: usize,
) -> Result<(), ProfileError> {
    if !parent.is_current_running_exact() {
        mark_owner_fault(token, parent);
        return Err(ProfileError::OwnerNotCurrent);
    }
    {
        ensure_not_poisoned()?;
        let mut slot = SLOT.lock();
        match &mut *slot {
            SlotState::Active {
                sample,
                owner,
                child: None,
                child_detach: None,
                faults,
                #[cfg(feature = "wasm-c84-core-poll-observer")]
                core_owner,
                ..
            } if sample.token() == token
                && owner.matches(token.epoch(), parent)
                && faults.is_empty() =>
            {
                #[cfg(feature = "wasm-c84-core-poll-observer")]
                if *core_owner != CoreObserverOwner::Closed {
                    faults.insert(SlotFaults::CORE_OBSERVER);
                    return Err(ProfileError::StateMismatch);
                }
            }
            SlotState::Active {
                sample,
                owner,
                child: Some(_),
                ..
            } if sample.token() == token && owner.matches(token.epoch(), parent) => {
                return Err(ProfileError::DelegatedChildAttached);
            }
            SlotState::Active {
                sample,
                owner,
                child_detach: Some(_),
                ..
            } if sample.token() == token && owner.matches(token.epoch(), parent) => {
                return Err(ProfileError::DelegatedChildAttached);
            }
            _ => return Err(ProfileError::StateMismatch),
        }
    }

    let target = child_task_detach_target(token.epoch());
    let child_detach = batch
        .install_prepared_task_detach_seal(task_index, target)
        .ok_or(ProfileError::RegistrationReserveFailed)?;
    if child_detach.task_id() == parent.task_id() {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    }
    let delegated = DelegatedChild {
        epoch: token.epoch(),
        detach: child_detach,
        state: DelegatedChildState::Attached,
        #[cfg(feature = "wasm-c84-ssh-managed-child-core")]
        driver_completed: false,
    };

    let mut slot = SLOT.lock();
    match &mut *slot {
        SlotState::Active {
            sample,
            owner,
            child,
            child_detach,
            faults,
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            core_owner,
            ..
        } if sample.token() == token
            && owner.matches(token.epoch(), parent)
            && child.is_none()
            && child_detach.is_none()
            && faults.is_empty()
            && poison_reason().is_none() =>
        {
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            if *core_owner != CoreObserverOwner::Closed {
                faults.insert(SlotFaults::CORE_OBSERVER);
                return Err(ProfileError::StateMismatch);
            }
            *child = Some(delegated);
            Ok(())
        }
        _ => {
            drop(slot);
            poison(SlotPoison::StateMismatch);
            Err(ProfileError::StateMismatch)
        }
    }
}

/// Bind the exact production managed child while its authenticated request
/// parent is still in the synchronous start stack.
///
/// This is intentionally narrower than projecting a parent `RunLease`: the
/// caller receives only the epoch copied into the arena-owned payload. The
/// slot's complete parent seal remains private, and a different current task
/// observes no attachable lineage.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn attach_current_request_managed_child(
    batch: &mut crate::exec::PreparedTaskBatch,
    task_index: usize,
) -> Result<Option<u64>, ProfileError> {
    ensure_not_poisoned()?;
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active { sample, owner, .. } => Some((sample.token(), owner.detach)),
            _ => None,
        }
    };
    let Some((token, parent)) = candidate else {
        return Ok(None);
    };
    if !parent.is_current_running_exact() {
        return Ok(None);
    }
    attach_prepared_child(token, parent, batch, task_index)?;
    Ok(Some(token.epoch()))
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn claim_current_child() -> Result<ChildRunLease, ProfileError> {
    ensure_not_poisoned()?;
    // Do not invert SLOT -> TaskStatus/SCHED. Copy the scalar exact seal, drop
    // SLOT, prove the current poll stack, then re-lock and compare the complete
    // state again. A parent cancellation between the two locks makes the claim
    // inert rather than reviving a stale child.
    let (token, detach) = {
        let slot = SLOT.lock();
        let SlotState::Active {
            sample,
            child: Some(child),
            faults,
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            core_owner,
            ..
        } = &*slot
        else {
            return Err(ProfileError::DelegatedChildUnavailable);
        };
        if child.state != DelegatedChildState::Attached {
            return Err(ProfileError::DelegatedChildUnavailable);
        }
        if !faults.is_empty() {
            return Err(ProfileError::SlotFault(*faults));
        }
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        if *core_owner != CoreObserverOwner::Closed {
            return Err(ProfileError::DelegatedChildUnavailable);
        }
        (sample.token(), child.detach)
    };
    if !detach.is_current_running_exact() {
        return Err(ProfileError::OwnerNotCurrent);
    }
    if !detach.is_current_first_poll_exact() {
        return Err(ProfileError::DelegatedChildUnavailable);
    }
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    match &mut *slot {
        SlotState::Active {
            sample,
            child: Some(child),
            faults,
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            core_owner,
            ..
        } if sample.token() == token
            && child.matches(token.epoch(), detach)
            && child.state == DelegatedChildState::Attached
            && faults.is_empty() =>
        {
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            if *core_owner != CoreObserverOwner::Closed {
                return Err(ProfileError::DelegatedChildUnavailable);
            }
            child.state = DelegatedChildState::Claimed;
            Ok(ChildRunLease {
                token,
                detach,
                live: true,
                not_sync: PhantomData,
            })
        }
        _ => Err(ProfileError::DelegatedChildUnavailable),
    }
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn mark_child_fault(token: SampleToken, detach: PreparedTaskDetachSeal) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        ..
    } = &mut *slot
    {
        if sample.token() == token && child.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::CHILD_OWNER_NOT_CURRENT);
        }
    }
}

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
fn mark_child_observer_fault(token: SampleToken, detach: PreparedTaskDetachSeal) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        ..
    } = &mut *slot
    {
        if sample.token() == token && child.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::CHILD_OBSERVER);
        }
    }
}

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
fn child_core_is_closed(
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
) -> Result<bool, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        core_owner,
        ..
    } = &*slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(*core_owner == CoreObserverOwner::Closed)
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn apply_child_phase(
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
    phase: Phase,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    #[cfg(feature = "wasm-c84-core-poll-observer")]
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_OBSERVER);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    sample.set_phase(token, live_context(), live_tick(), phase);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Facade(facade))
    }
}

/// Opens child-owned Interpretation in the globally resident lineage before
/// the portable runtime enters Core. Keeping the bit in `SLOT` makes an open
/// edge observable even if both storage-free owner objects are forgotten.
#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
fn begin_child_core_phase(
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_OBSERVER);
        return Err(ProfileError::StateMismatch);
    }
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    if managed_phase.child_waiting
        || managed_phase.child_host_open
        || !matches!(
            managed_phase.child_base,
            ManagedChildBasePhase::Abi | ManagedChildBasePhase::Cleanup
        )
    {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    *core_owner = CoreObserverOwner::Child;
    sample.set_phase(token, live_context(), live_tick(), Phase::Interpretation);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Facade(facade))
    }
}

/// Closes child-owned Interpretation with the same exact tick returned to the
/// portable runtime observer. The parent lease is deliberately absent: the
/// complete prepared-task seal and `Claimed` state are the only authority for
/// mutating a delegated child's Core boundary.
#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
fn end_child_core_phase(token: SampleToken, detach: PreparedTaskDetachSeal) -> PhaseBoundary {
    if let Err(error) = ensure_not_poisoned() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(error),
        };
    }
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        core_owner,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase,
        ..
    } = &mut *slot
    else {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    if *core_owner != CoreObserverOwner::Child {
        faults.insert(SlotFaults::CHILD_OBSERVER);
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    if !faults.is_empty() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::SlotFault(*faults)),
        };
    }
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    if managed_phase.child_waiting || managed_phase.child_host_open {
        faults.insert(SlotFaults::CHILD_PHASE);
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    let context = live_context();
    let tick = live_tick();
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    let restore_phase = managed_phase.child_base.phase();
    #[cfg(not(feature = "wasm-c84-ssh-managed-child-phase-sidecar"))]
    let restore_phase = Phase::Abi;
    sample.set_phase(token, context, tick, restore_phase);
    *core_owner = CoreObserverOwner::Closed;
    let facade = sample.facade_faults();
    PhaseBoundary {
        tick,
        error: if facade.is_empty() {
            None
        } else {
            Some(ProfileError::Facade(facade))
        },
    }
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn release_child(token: SampleToken, detach: PreparedTaskDetachSeal) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    #[cfg(feature = "wasm-c84-core-poll-observer")]
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_OBSERVER);
        return Err(ProfileError::StateMismatch);
    }
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    if !managed_phase.child_release_ready() {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    // Keep the child's exact detach callback armed across the remainder of
    // its future and the complete future destructor. Only the executor's
    // terminal detach pass can distinguish clean Exited from a later Drop
    // fault or cancellation. The parent cannot finish while this marker is
    // still present.
    child.state = DelegatedChildState::CompletedPendingDetach;
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
fn abandon_child(token: SampleToken, detach: PreparedTaskDetachSeal) {
    if poison_reason().is_some() {
        return;
    }
    // These checks borrow TaskStatus/SCHED. Evaluate them before SLOT so the
    // executor's detach path and the profiler always retain one lock order.
    let exact_scope = detach.is_current_running_exact() || detach.is_current_reclaiming_exact();
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner,
        ..
    } = &mut *slot
    {
        if sample.token() == token && child.matches(token.epoch(), detach) {
            if !exact_scope {
                faults.insert(SlotFaults::CHILD_OWNER_NOT_CURRENT);
            }
            #[cfg(feature = "wasm-c84-core-poll-observer")]
            if *core_owner == CoreObserverOwner::Child {
                faults.insert(SlotFaults::CHILD_OBSERVER);
            }
            faults.insert(SlotFaults::CHILD_ABANDONED);
            child.state = DelegatedChildState::Abandoned;
        }
    }
}

/// Storage-free exact owner of one globally resident Active sample.
pub(crate) struct RunLease {
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl RunLease {
    pub(crate) const fn token(&self) -> SampleToken {
        self.token
    }

    pub(crate) fn set_phase(&self, phase: Phase) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_phase(self.token, self.detach, Some(phase))
    }

    pub(crate) fn begin_cleanup(&self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_phase(self.token, self.detach, None)
    }

    /// Mark synchronous SSH transport/protocol work. This also resumes a
    /// parent Wait, but repeated work in the same Host turn does not create a
    /// synthetic zero-length transition.
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    pub(crate) fn managed_parent_host(&self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_managed_parent_phase(self.token, self.detach, ManagedParentPhaseChange::Host)
    }

    /// Open the parent's independent Wait state immediately before one real
    /// suspension. The RunLease itself remains exclusively parent-owned.
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    pub(crate) fn managed_parent_wait(&self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_managed_parent_phase(self.token, self.detach, ManagedParentPhaseChange::Wait)
    }

    /// Bind one still-hidden prepared task to this exact request lineage.
    /// The child's detach callback is installed before this method publishes
    /// its seal into the slot, so no scheduler-visible child can precede
    /// fail-closed cleanup ownership.
    #[cfg(feature = "wasm-c84-profile-child-delegation")]
    pub(crate) fn attach_prepared_child(
        &self,
        batch: &mut crate::exec::PreparedTaskBatch,
        task_index: usize,
    ) -> Result<(), ProfileError> {
        attach_prepared_child(self.token, self.detach, batch, task_index)
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn begin_core_interpretation(&self) -> Option<ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            Some(ProfileError::OwnerNotCurrent)
        } else {
            begin_core_phase(self.token, self.detach).err()
        }
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn end_core_interpretation(&self) -> PhaseBoundary {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return PhaseBoundary {
                tick: live_tick(),
                error: Some(ProfileError::OwnerNotCurrent),
            };
        }
        end_core_phase(self.token, self.detach)
    }

    pub(crate) fn finish(mut self) -> Result<StreamLease, ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
        }
        let result = finish_active(self.token, self.detach);
        match result {
            Ok(()) => {
                self.live = false;
                Ok(StreamLease {
                    token: self.token,
                    detach: self.detach,
                    live: true,
                    not_sync: PhantomData,
                })
            }
            Err(error @ ProfileError::Rejected(_)) => {
                self.live = false;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn cancel(mut self) -> Result<RejectionReport, ProfileError> {
        self.live = false;
        cancel_active(self.token, self.detach, RejectionCause::LeaseCancelled)
    }
}

/// Storage-free exact child borrower for one active request lineage.
///
/// A child must claim this inside its first exact poll and explicitly release
/// it before ordinary completion. Drop, cancellation, or raw task detach while
/// live latches a request-local diagnostic fault. The parent remains the sole
/// finish/cancel/recycle owner, and the component lifecycle remains outside the
/// profiling verdict.
#[cfg(feature = "wasm-c84-profile-child-delegation")]
pub(crate) struct ChildRunLease {
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

/// Claim or revalidate the real managed-child ownership held by the executor
/// future itself. The returned boolean is true only for the first-poll
/// Attached -> Claimed transition; no parent `RunLease` enters the child.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn claim_current_request_managed_child() -> Result<Option<(u64, bool)>, ProfileError> {
    ensure_not_poisoned()?;
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active {
                sample,
                child: Some(child),
                ..
            } => Some((sample.token(), child.detach, child.state)),
            _ => None,
        }
    };
    let Some((token, detach, state)) = candidate else {
        return Ok(None);
    };
    if !detach.is_current_running_exact() {
        return Ok(None);
    }
    match state {
        DelegatedChildState::Attached => {
            if !detach.is_current_first_poll_exact() {
                return Err(ProfileError::DelegatedChildUnavailable);
            }
            let mut child = claim_current_child()?;
            if child.token != token || !child.detach.matches_exact(detach) {
                return Err(ProfileError::StateMismatch);
            }
            // The exact outer ManagedChildFuture is now the linear owner. Its
            // Drop path below supplies abandonment; suppress only this
            // temporary full lease's duplicate Drop action.
            child.live = false;
            Ok(Some((token.epoch(), true)))
        }
        DelegatedChildState::Claimed => Ok(Some((token.epoch(), false))),
        DelegatedChildState::CompletedPendingDetach | DelegatedChildState::Abandoned => {
            Err(ProfileError::StateMismatch)
        }
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
fn managed_child_snapshot(
    epoch: u64,
) -> Result<(SampleToken, PreparedTaskDetachSeal), ProfileError> {
    ensure_not_poisoned()?;
    {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active {
                sample,
                child: Some(child),
                ..
            } if sample.token().epoch() == epoch
                && child.epoch == epoch
                && child.state == DelegatedChildState::Claimed =>
            {
                Some((sample.token(), child.detach))
            }
            _ => None,
        }
    }
    .ok_or(ProfileError::DelegatedChildUnavailable)
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
fn current_managed_child(
    epoch: u64,
) -> Result<(SampleToken, PreparedTaskDetachSeal), ProfileError> {
    let candidate = managed_child_snapshot(epoch)?;
    if !candidate.1.is_current_running_exact() {
        mark_child_fault(candidate.0, candidate.1);
        return Err(ProfileError::OwnerNotCurrent);
    }
    Ok(candidate)
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn mark_managed_child_phase_fault(token: SampleToken, detach: PreparedTaskDetachSeal) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        ..
    } = &mut *slot
    {
        if sample.token() == token && child.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::CHILD_PHASE);
        }
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn managed_child_phase_parts(
    epoch: u64,
) -> Result<(SampleToken, PreparedTaskDetachSeal), ProfileError> {
    // `current_managed_child` performs its TaskStatus/SCHED proof after
    // dropping SLOT. Every caller then re-locks and compares the copied seal.
    current_managed_child(epoch)
}

/// Report whether exact runtime cancellation must bypass a new Host overlay.
/// A live operation owned by an open Wait is cancelled without contradicting
/// that Wait. Once the executor has already marked this exact child Abandoned,
/// every destructor cancellation also bypasses Host because the linear child
/// owner is gone. Neither case closes or repairs phase state.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_child_cancel_bypasses_host(epoch: u64) -> Result<bool, ProfileError> {
    ensure_not_poisoned()?;
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active {
                sample,
                child: Some(child),
                ..
            } if sample.token().epoch() == epoch
                && child.epoch == epoch
                && matches!(
                    child.state,
                    DelegatedChildState::Claimed | DelegatedChildState::Abandoned
                ) => Some((sample.token(), child.detach)),
            _ => None,
        }
    }
    .ok_or(ProfileError::DelegatedChildUnavailable)?;
    let (token, detach) = candidate;
    if !detach.is_current_running_exact() && !detach.is_current_reclaiming_exact() {
        mark_child_fault(token, detach);
        return Err(ProfileError::OwnerNotCurrent);
    }
    let slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &*slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(epoch, detach)
        || *core_owner != CoreObserverOwner::Closed
    {
        return Err(ProfileError::StateMismatch);
    }
    match child.state {
        DelegatedChildState::Claimed if faults.is_empty() => Ok(managed_phase.child_waiting),
        DelegatedChildState::Abandoned if *faults == SlotFaults::CHILD_ABANDONED => Ok(true),
        _ => Err(ProfileError::SlotFault(*faults)),
    }
}

/// Change the claimed child's resumable base phase. Host, Wait, Cleanup, and
/// Interpretation have dedicated linear entry points and are rejected here.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_child_set_phase(epoch: u64, phase: Phase) -> Result<(), ProfileError> {
    if !matches!(phase, Phase::Validation | Phase::Instantiation | Phase::Abi) {
        return Err(ProfileError::StateMismatch);
    }
    let (token, detach) = managed_child_phase_parts(epoch)?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(epoch, detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed || !faults.is_empty() {
        if *core_owner != CoreObserverOwner::Closed {
            faults.insert(SlotFaults::CHILD_PHASE);
        }
        return Err(if faults.is_empty() {
            ProfileError::StateMismatch
        } else {
            ProfileError::SlotFault(*faults)
        });
    }
    if managed_phase.child_set_phase(phase).is_err() {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    sample.set_phase(token, live_context(), live_tick(), phase);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

/// Open the child's independent Wait immediately before suspension. This
/// function receives only the copyable epoch and never returns a live guard.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_child_enter_wait(epoch: u64) -> Result<(), ProfileError> {
    let (token, detach) = managed_child_phase_parts(epoch)?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(epoch, detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    if managed_phase.child_enter_wait().is_err() {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    sample.set_phase(token, live_context(), live_tick(), Phase::Wait);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

/// Revalidate the resumed child and restore its stored base phase. Cleanup is
/// therefore preserved across Wait rather than being inferred by the caller.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_child_resume_from_wait(epoch: u64) -> Result<(), ProfileError> {
    let (token, detach) = managed_child_phase_parts(epoch)?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(epoch, detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    let phase = match managed_phase.child_resume_from_wait() {
        Ok(phase) => phase,
        Err(()) => {
            faults.insert(SlotFaults::CHILD_PHASE);
            return Err(ProfileError::StateMismatch);
        }
    };
    sample.set_phase(token, live_context(), live_tick(), phase);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn managed_child_open_host(
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    if managed_phase.child_enter_host().is_err() {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    sample.set_phase(token, live_context(), live_tick(), Phase::Host);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
fn managed_child_close_host(
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(token.epoch(), detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    let phase = match managed_phase.child_finish_host() {
        Ok(phase) => phase,
        Err(()) => {
            faults.insert(SlotFaults::CHILD_PHASE);
            return Err(ProfileError::StateMismatch);
        }
    };
    sample.set_phase(token, live_context(), live_tick(), phase);
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

/// Synchronous, non-Send sentinel for one child Host entry. Explicit finish
/// is required; Drop or forget is recorded in the storage-resident state and
/// can never pass release.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
#[must_use]
pub(crate) struct ManagedChildHostPhase {
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
    live: bool,
    not_send: PhantomData<*mut ()>,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
impl ManagedChildHostPhase {
    pub(crate) fn enter(epoch: u64) -> Result<Self, ProfileError> {
        let (token, detach) = managed_child_phase_parts(epoch)?;
        managed_child_open_host(token, detach)?;
        Ok(Self {
            token,
            detach,
            live: true,
            not_send: PhantomData,
        })
    }

    pub(crate) fn finish(mut self) -> Result<(), ProfileError> {
        let result = if self.detach.is_current_running_exact() {
            managed_child_close_host(self.token, self.detach)
        } else {
            mark_child_fault(self.token, self.detach);
            mark_managed_child_phase_fault(self.token, self.detach);
            Err(ProfileError::OwnerNotCurrent)
        };
        self.live = false;
        result
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
impl Drop for ManagedChildHostPhase {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let exact_scope =
                self.detach.is_current_running_exact() || self.detach.is_current_reclaiming_exact();
            if !exact_scope {
                mark_child_fault(self.token, self.detach);
            }
            mark_managed_child_phase_fault(self.token, self.detach);
        }
    }
}

/// Irreversibly latch Cleanup once, before the runtime performs cleanup work.
#[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
pub(crate) fn managed_child_begin_cleanup(epoch: u64) -> Result<(), ProfileError> {
    let (token, detach) = managed_child_phase_parts(epoch)?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token
        || !child.matches(epoch, detach)
        || child.state != DelegatedChildState::Claimed
    {
        return Err(ProfileError::StateMismatch);
    }
    if *core_owner != CoreObserverOwner::Closed {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    if managed_phase.child_begin_cleanup().is_err() {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    sample.begin_cleanup(token, live_context(), live_tick());
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        faults.insert(SlotFaults::CHILD_PHASE);
        Err(ProfileError::Facade(facade))
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn current_managed_child_driver_state() -> Result<Option<(u64, bool)>, ProfileError> {
    ensure_not_poisoned()?;
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active {
                sample,
                child: Some(child),
                ..
            } if child.state == DelegatedChildState::Claimed => {
                Some((sample.token(), child.detach, child.driver_completed))
            }
            _ => None,
        }
    };
    let Some((token, detach, completed)) = candidate else {
        return Ok(None);
    };
    if !detach.is_current_running_exact() {
        return Ok(None);
    }
    Ok(Some((token.epoch(), completed)))
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn release_current_request_managed_child() -> Result<Option<u64>, ProfileError> {
    let Some((epoch, completed)) = current_managed_child_driver_state()? else {
        return Ok(None);
    };
    if !completed {
        return Err(ProfileError::StateMismatch);
    }
    let (token, detach) = current_managed_child(epoch)?;
    release_child(token, detach)?;
    Ok(Some(epoch))
}

/// ManagedChildFuture's destructor counterpart to the temporary full lease
/// suppressed at claim. Running and executor-reclaiming scopes are both
/// accepted, matching `ChildRunLease::Drop`; a wrong task remains inert.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn abandon_current_request_managed_child() {
    let candidate = {
        let slot = SLOT.lock();
        match &*slot {
            SlotState::Active {
                sample,
                child: Some(child),
                ..
            } if child.state == DelegatedChildState::Claimed => {
                Some((sample.token(), child.detach))
            }
            _ => None,
        }
    };
    let Some((token, detach)) = candidate else {
        return;
    };
    if detach.is_current_running_exact() || detach.is_current_reclaiming_exact() {
        abandon_child(token, detach);
    }
}

/// Mark the successful target driver return which alone authorizes the outer
/// executor envelope to convert its compact claim into an explicit release.
/// Cooperative registry cancellation drops the driver without reaching this
/// function, so its later Ready word cannot wash cancellation into Exited.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) fn mark_managed_child_driver_completed(epoch: u64) -> Result<(), ProfileError> {
    let (token, detach) = current_managed_child(epoch)?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child: Some(child),
        faults,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase,
        core_owner,
        ..
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    let phase_incomplete = !managed_phase.child_release_ready();
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    if sample.token() == token
        && child.matches(epoch, detach)
        && child.state == DelegatedChildState::Claimed
        && phase_incomplete
    {
        faults.insert(SlotFaults::CHILD_PHASE);
        return Err(ProfileError::StateMismatch);
    }
    if sample.token() != token
        || !child.matches(epoch, detach)
        || child.state != DelegatedChildState::Claimed
        || child.driver_completed
        || !faults.is_empty()
        || *core_owner != CoreObserverOwner::Closed
    {
        return Err(ProfileError::StateMismatch);
    }
    child.driver_completed = true;
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
impl ChildRunLease {
    pub(crate) const fn token(&self) -> SampleToken {
        self.token
    }

    pub(crate) fn set_phase(&self, phase: Phase) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_child_phase(self.token, self.detach, phase)
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn begin_core_interpretation(&self) -> Option<ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            Some(ProfileError::OwnerNotCurrent)
        } else {
            begin_child_core_phase(self.token, self.detach).err()
        }
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn end_core_interpretation(&self) -> PhaseBoundary {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            return PhaseBoundary {
                tick: live_tick(),
                error: Some(ProfileError::OwnerNotCurrent),
            };
        }
        end_child_core_phase(self.token, self.detach)
    }

    pub(crate) fn release(mut self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            self.live = false;
            abandon_child(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        let result = release_child(self.token, self.detach);
        self.live = result.is_err();
        result
    }
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
impl Drop for ChildRunLease {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            abandon_child(self.token, self.detach);
        }
    }
}

#[cfg(feature = "wasm-c84-profile-child-delegation")]
pub(crate) fn claim_delegated_child() -> Result<ChildRunLease, ProfileError> {
    claim_current_child()
}

/// Lexically scoped Core observer owned by one exact claimed child.
///
/// The observer borrows no parent `RunLease`, so it cannot finish, cancel,
/// stream, or recycle the request. Any local start/finish protocol violation
/// is copied into the slot's sticky child-fault ledger; ignoring `error()` can
/// therefore never turn a malformed observer sequence into verified evidence.
#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
pub(crate) struct ChildSlotCorePollClock<'a> {
    child: &'a mut ChildRunLease,
    first_error: Option<ProfileError>,
    owns_open: bool,
}

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
impl<'a> ChildSlotCorePollClock<'a> {
    pub(crate) const fn new(child: &'a mut ChildRunLease) -> Self {
        Self {
            child,
            first_error: None,
            owns_open: false,
        }
    }

    fn latch(&mut self, error: Option<ProfileError>) {
        if error.is_some() {
            mark_child_observer_fault(self.child.token, self.child.detach);
        }
        if self.first_error.is_none() {
            self.first_error = error;
        }
    }

    pub(crate) const fn error(&self) -> Option<ProfileError> {
        self.first_error
    }

    pub(crate) fn core_is_closed(&self) -> bool {
        matches!(
            child_core_is_closed(self.child.token, self.child.detach),
            Ok(true)
        )
    }
}

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
impl ProfileClock for ChildSlotCorePollClock<'_> {
    fn ticks(&mut self) -> u64 {
        live_tick()
    }

    fn core_poll_started(&mut self) -> u64 {
        if self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        let error = self.child.begin_core_interpretation();
        self.owns_open = error.is_none();
        self.latch(error);
        live_tick()
    }

    fn core_poll_finished(&mut self) -> u64 {
        if !self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        self.owns_open = false;
        let boundary = self.child.end_core_interpretation();
        self.latch(boundary.error);
        boundary.tick
    }
}

#[cfg(all(
    feature = "wasm-c84-profile-child-delegation",
    feature = "wasm-c84-core-poll-observer"
))]
impl Drop for ChildSlotCorePollClock<'_> {
    fn drop(&mut self) {
        if self.owns_open {
            self.owns_open = false;
            mark_child_observer_fault(self.child.token, self.child.detach);
        }
    }
}

/// Lexical Core observer for the compact real-managed-child lease.
///
/// Construction revalidates the globally stored prepared-task seal against
/// the current executor poll. The observer owns no task or request authority;
/// an open edge is sticky in `SLOT` even if this adapter is forgotten.
#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
pub(crate) struct ManagedChildSlotCorePollClock {
    token: SampleToken,
    detach: PreparedTaskDetachSeal,
    first_error: Option<ProfileError>,
    owns_open: bool,
    not_send: PhantomData<*mut ()>,
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
impl ManagedChildSlotCorePollClock {
    pub(crate) fn current(epoch: u64) -> Result<Self, ProfileError> {
        let (token, detach) = current_managed_child(epoch)?;
        Ok(Self {
            token,
            detach,
            first_error: None,
            owns_open: false,
            not_send: PhantomData,
        })
    }

    fn latch(&mut self, error: Option<ProfileError>) {
        if error.is_some() {
            mark_child_observer_fault(self.token, self.detach);
        }
        if self.first_error.is_none() {
            self.first_error = error;
        }
    }

    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    fn latch_phase(&mut self, error: Option<ProfileError>) {
        if error.is_some() {
            mark_managed_child_phase_fault(self.token, self.detach);
        }
        if self.first_error.is_none() {
            self.first_error = error;
        }
    }

    pub(crate) const fn error(&self) -> Option<ProfileError> {
        self.first_error
    }

    pub(crate) fn core_is_closed(&self) -> bool {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            mark_child_observer_fault(self.token, self.detach);
            return false;
        }
        matches!(child_core_is_closed(self.token, self.detach), Ok(true))
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
impl ProfileClock for ManagedChildSlotCorePollClock {
    fn ticks(&mut self) -> u64 {
        live_tick()
    }

    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    fn cleanup_started(&mut self) {
        let epoch = self.token.epoch();
        let error = managed_child_begin_cleanup(epoch).err();
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar-qemu-acceptance")]
        if error.is_none() {
            // SLOT is no longer held: telemetry can never invert SLOT -> UART.
            crate::println!(
                "WASM_C84_SSH_MANAGED_CHILD_PHASE_SIDECAR CHILD_PHASE epoch={} phase=cleanup",
                epoch
            );
        }
        self.latch_phase(error);
    }

    fn core_poll_started(&mut self) -> u64 {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            self.latch(Some(ProfileError::OwnerNotCurrent));
            return live_tick();
        }
        if self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        let error = begin_child_core_phase(self.token, self.detach).err();
        self.owns_open = error.is_none();
        self.latch(error);
        live_tick()
    }

    fn core_poll_finished(&mut self) -> u64 {
        if !self.detach.is_current_running_exact() {
            mark_child_fault(self.token, self.detach);
            self.latch(Some(ProfileError::OwnerNotCurrent));
            return live_tick();
        }
        if !self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        self.owns_open = false;
        let boundary = end_child_core_phase(self.token, self.detach);
        self.latch(boundary.error);
        boundary.tick
    }
}

#[cfg(feature = "wasm-c84-ssh-managed-child-core")]
impl Drop for ManagedChildSlotCorePollClock {
    fn drop(&mut self) {
        if self.owns_open {
            self.owns_open = false;
            if !self.detach.is_current_running_exact() && !self.detach.is_current_reclaiming_exact()
            {
                mark_child_fault(self.token, self.detach);
            }
            mark_child_observer_fault(self.token, self.detach);
        }
    }
}

/// Lexically scoped bridge from portable Core observers to one exact slot
/// owner. Construct one around each `poll_profiled` call and inspect its sticky
/// error and closed state before the next poll or any `.await`.
#[cfg(feature = "wasm-c84-core-poll-observer")]
pub(crate) struct SlotCorePollClock<'a> {
    run: &'a RunLease,
    first_error: Option<ProfileError>,
    owns_open: bool,
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
impl<'a> SlotCorePollClock<'a> {
    pub(crate) const fn new(run: &'a RunLease) -> Self {
        Self {
            run,
            first_error: None,
            owns_open: false,
        }
    }

    fn latch(&mut self, error: Option<ProfileError>) {
        if error.is_some() {
            mark_core_observer_fault(self.run.token, self.run.detach);
        }
        if self.first_error.is_none() {
            self.first_error = error;
        }
    }

    pub(crate) const fn error(&self) -> Option<ProfileError> {
        self.first_error
    }

    pub(crate) fn core_is_closed(&self) -> bool {
        matches!(
            parent_core_is_closed(self.run.token, self.run.detach),
            Ok(true)
        )
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
impl ProfileClock for SlotCorePollClock<'_> {
    fn ticks(&mut self) -> u64 {
        live_tick()
    }

    fn core_poll_started(&mut self) -> u64 {
        if self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        let error = self.run.begin_core_interpretation();
        self.owns_open = error.is_none();
        self.latch(error);
        // The portable contract requires this to be the final observer work.
        live_tick()
    }

    fn core_poll_finished(&mut self) -> u64 {
        if !self.owns_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        self.owns_open = false;
        let boundary = self.run.end_core_interpretation();
        self.latch(boundary.error);
        boundary.tick
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
impl Drop for SlotCorePollClock<'_> {
    fn drop(&mut self) {
        if self.owns_open {
            self.owns_open = false;
            mark_core_observer_fault(self.run.token, self.run.detach);
        }
    }
}

impl Drop for RunLease {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = cancel_active(self.token, self.detach, RejectionCause::LeaseCancelled);
        }
    }
}

fn stream_summary(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<Summary, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Verified { sample, owner, .. }
            if sample.token() == token && owner.matches(token.epoch(), detach) =>
        {
            Ok(sample.summary())
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

fn stream_next(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<Option<Interval>, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    match &mut *slot {
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } if sample.token() == token && owner.matches(token.epoch(), detach) => {
            let interval = sample.interval(*cursor);
            if interval.is_some() {
                *cursor += 1;
            }
            Ok(interval)
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

fn take_verified(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    require_complete: bool,
) -> Result<(TargetVerified<'static>, OwnerSeal, usize), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let (required, emitted) = match &*slot {
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } if sample.token() == token && owner.matches(token.epoch(), detach) => {
            (sample.summary().interval_count(), *cursor)
        }
        _ => return Err(ProfileError::StateMismatch),
    };
    if require_complete && emitted != required {
        return Err(ProfileError::IncompleteStream { emitted, required });
    }
    let owner = OwnerSeal {
        epoch: token.epoch(),
        detach,
    };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Recycle,
        },
    );
    let SlotState::Verified {
        sample,
        owner,
        cursor,
    } = previous
    else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    Ok((sample, owner, cursor))
}

fn complete_stream(token: SampleToken, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    let (sample, owner, _) = take_verified(token, detach, true)?;
    let ready = sample.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Recycle }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && ready.next_epoch() == owner.epoch.checked_add(1) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn discard_stream(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<RejectionReport, ProfileError> {
    let (sample, owner, cursor) = take_verified(token, detach, false)?;
    let report = RejectionReport {
        epoch: token.epoch(),
        cause: RejectionCause::StreamAbandoned,
        facade_faults: FacadeFaults::NONE,
        ledger_error: None,
        slot_faults: SlotFaults::NONE,
        intervals_emitted: cursor,
    };
    let ready = sample.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    install_rejected(owner, TransitKind::Recycle, ready, report)?;
    Ok(report)
}

/// Storage-free cursor for one globally resident verified sample.
pub(crate) struct StreamLease {
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl StreamLease {
    pub(crate) const fn token(&self) -> SampleToken {
        self.token
    }

    pub(crate) fn summary(&self) -> Result<Summary, ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        stream_summary(self.token, self.detach)
    }

    pub(crate) fn next_interval(&mut self) -> Result<Option<Interval>, ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        stream_next(self.token, self.detach)
    }

    pub(crate) fn complete(mut self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        match complete_stream(self.token, self.detach) {
            Ok(()) => {
                self.live = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn discard(mut self) -> Result<RejectionReport, ProfileError> {
        self.live = false;
        discard_stream(self.token, self.detach)
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = discard_stream(self.token, self.detach);
        }
    }
}

pub(crate) fn rejection() -> Option<RejectionReport> {
    if poison_reason().is_some() {
        return None;
    }
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Rejected { report, .. } => Some(*report),
        _ => None,
    }
}

pub(crate) fn acknowledge_rejection(epoch: u64) -> Result<RejectionReport, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let report = match &*slot {
        SlotState::Rejected { report, .. } if report.epoch == epoch => *report,
        SlotState::Rejected { .. } => return Err(ProfileError::StateMismatch),
        _ => return Err(ProfileError::StateMismatch),
    };
    // Rejected has no armed detach callback. `Uninitialized` is therefore a
    // private move placeholder which cannot be observed while this lock is
    // held; the slot is restored to Ready before unlocking.
    let previous = mem::replace(&mut *slot, SlotState::Uninitialized);
    let SlotState::Rejected { ready, .. } = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    *slot = SlotState::Ready(ready);
    Ok(report)
}

/// Finalize one delegated child's exact executor lifecycle edge.
///
/// This callback deliberately performs only a constant-time slot mutation.
/// The request parent remains the only party that may finish, cancel, or
/// recycle target storage. A callback after the parent has already left Active
/// is stale and therefore inert.
#[cfg(feature = "wasm-c84-profile-child-delegation")]
unsafe fn profile_child_detached(
    epoch: u64,
    task: TaskId,
    domain: AllocationDomain,
    reason: TaskDetachReason,
) {
    if poison_reason().is_some() {
        return;
    }
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        child,
        child_detach,
        faults,
        #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
        managed_phase,
        #[cfg(feature = "wasm-c84-core-poll-observer")]
        core_owner,
        ..
    } = &mut *slot
    else {
        return;
    };
    if sample.token().epoch() != epoch
        || !child
            .as_ref()
            .is_some_and(|child| child.callback_matches(epoch, task, domain))
    {
        return;
    }

    let exact_child = child
        .as_ref()
        .expect("exact delegated child was checked above");
    let state = exact_child.state;
    #[cfg(feature = "wasm-c84-core-poll-observer")]
    if *core_owner == CoreObserverOwner::Child {
        faults.insert(SlotFaults::CHILD_OBSERVER);
    }
    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
    if managed_phase.child_host_open {
        faults.insert(SlotFaults::CHILD_PHASE);
    }
    let clean =
        state == DelegatedChildState::CompletedPendingDetach && reason == TaskDetachReason::Exited;
    if !clean {
        faults.insert(SlotFaults::CHILD_DETACHED);
        if state == DelegatedChildState::Abandoned {
            faults.insert(SlotFaults::CHILD_ABANDONED);
        }
    }
    *child_detach = Some(reason);
    *child = None;
    drop(slot);
    #[cfg(feature = "wasm-c84-ssh-managed-child-core-qemu-acceptance")]
    record_managed_child_detached(epoch, reason, clean);
}

enum DetachAction {
    None,
    Cancel {
        sample: TargetActive<'static>,
        owner: OwnerSeal,
        faults: SlotFaults,
        context: TargetContext,
        reason: TaskDetachReason,
    },
    Recycle {
        sample: TargetVerified<'static>,
        owner: OwnerSeal,
        cursor: usize,
        reason: TaskDetachReason,
    },
}

unsafe fn profile_task_detached(
    epoch: u64,
    task: TaskId,
    domain: AllocationDomain,
    reason: TaskDetachReason,
) {
    if poison_reason().is_some() {
        return;
    }
    let action = {
        let mut slot = SLOT.lock();
        match &*slot {
            SlotState::Reserved { owner, .. } if owner.callback_matches(epoch, task, domain) => {
                let previous = mem::replace(&mut *slot, SlotState::Uninitialized);
                let SlotState::Reserved { ready, .. } = previous else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                *slot = SlotState::Ready(ready);
                DetachAction::None
            }
            SlotState::Active { sample, owner, .. }
                if sample.token().epoch() == epoch
                    && owner.callback_matches(epoch, task, domain) =>
            {
                let owner = *owner;
                let context = live_context();
                #[cfg(feature = "wasm-c84-profile-irq-overlay")]
                if clear_active_epoch(epoch).is_err() {
                    let previous = mem::replace(
                        &mut *slot,
                        SlotState::Poisoned(SlotPoison::IrqStateMismatch),
                    );
                    drop(previous);
                    return;
                }
                let previous = mem::replace(
                    &mut *slot,
                    SlotState::Transit {
                        owner,
                        kind: TransitKind::Cancel,
                    },
                );
                let SlotState::Active {
                    sample,
                    faults,
                    #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
                    managed_phase,
                    #[cfg(feature = "wasm-c84-core-poll-observer")]
                    core_owner,
                    ..
                } = previous
                else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                #[cfg(feature = "wasm-c84-core-poll-observer")]
                let mut faults = faults;
                #[cfg(feature = "wasm-c84-core-poll-observer")]
                record_open_core_fault(&mut faults, core_owner);
                #[cfg(feature = "wasm-c84-ssh-managed-child-phase-sidecar")]
                if managed_phase.child_host_open {
                    faults.insert(SlotFaults::CHILD_PHASE);
                }
                DetachAction::Cancel {
                    sample,
                    owner,
                    faults,
                    context,
                    reason,
                }
            }
            SlotState::Verified {
                sample,
                owner,
                cursor,
            } if sample.token().epoch() == epoch && owner.callback_matches(epoch, task, domain) => {
                let owner = *owner;
                let previous = mem::replace(
                    &mut *slot,
                    SlotState::Transit {
                        owner,
                        kind: TransitKind::Recycle,
                    },
                );
                let SlotState::Verified { sample, cursor, .. } = previous else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                DetachAction::Recycle {
                    sample,
                    owner,
                    cursor,
                    reason,
                }
            }
            SlotState::Transit { owner, .. } if owner.callback_matches(epoch, task, domain) => {
                *slot = SlotState::Poisoned(SlotPoison::DetachedDuringTransit);
                poison(SlotPoison::DetachedDuringTransit);
                DetachAction::None
            }
            _ => DetachAction::None,
        }
    };

    match action {
        DetachAction::None => {}
        DetachAction::Cancel {
            sample,
            owner,
            faults,
            context,
            reason,
        } => {
            let token = sample.token();
            let rejected = sample.cancel(token, context);
            let report = RejectionReport::from_target(
                &rejected,
                RejectionCause::TaskDetached(reason),
                faults,
                0,
            );
            let ready = rejected.recycle();
            let _ = install_rejected(owner, TransitKind::Cancel, ready, report);
        }
        DetachAction::Recycle {
            sample,
            owner,
            cursor,
            reason,
        } => {
            let report = RejectionReport::detached_verified(owner.epoch, reason, cursor);
            let ready = sample.recycle();
            let _ = install_rejected(owner, TransitKind::Recycle, ready, report);
        }
    }
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-core-poll-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
fn wait_for_tick_progress() {
    let start = live_tick();
    while live_tick().wrapping_sub(start) < 32 {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
fn start_seven_phase_sample(expected_epoch: u64) -> Result<StreamLease, ProfileError> {
    let permit = prepare_current()?;
    if permit.expected_epoch() != expected_epoch {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != expected_epoch {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_tick_progress();
    run.set_phase(Phase::Instantiation)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Abi)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Interpretation)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Host)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Wait)?;
    wait_for_tick_progress();
    run.begin_cleanup()?;
    wait_for_tick_progress();
    run.finish()
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
async fn wait_for_rejection(epoch: u64) -> Result<RejectionReport, ProfileError> {
    for _ in 0..128 {
        if let Some(report) = rejection() {
            if report.epoch == epoch {
                return Ok(report);
            }
        }
        crate::exec::yield_now().await;
    }
    Err(ProfileError::StateMismatch)
}

#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
async fn run_positive_acceptance() -> Result<(), ProfileError> {
    let active =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-detach-active", async {
            let permit = prepare_current().expect("C8.4 active detach permit");
            assert_eq!(permit.expected_epoch(), 1);
            let run = permit.start().expect("C8.4 active detach start");
            wait_for_tick_progress();
            run.set_phase(Phase::Host)
                .expect("C8.4 active detach phase");
            core::mem::forget(run);
        });
    if active.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let active_report = wait_for_rejection(1).await?;
    if active_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited) {
        return Err(ProfileError::Rejected(active_report));
    }
    acknowledge_rejection(1)?;

    let streaming =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-detach-stream", async {
            let mut stream = start_seven_phase_sample(2).expect("C8.4 stream detach sample");
            assert_eq!(
                stream
                    .summary()
                    .expect("C8.4 stream summary")
                    .interval_count(),
                7
            );
            assert!(stream
                .next_interval()
                .expect("C8.4 first interval")
                .is_some());
            core::mem::forget(stream);
        });
    if streaming.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let stream_report = wait_for_rejection(2).await?;
    if stream_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited)
        || stream_report.intervals_emitted != 1
    {
        return Err(ProfileError::Rejected(stream_report));
    }
    acknowledge_rejection(2)?;

    let mut stream = start_seven_phase_sample(3)?;
    let summary = stream.summary()?;
    if summary.interval_count() != 7 || stream.token().epoch() != 3 {
        return Err(ProfileError::StateMismatch);
    }
    let mut previous_end = 0;
    let mut count = 0;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count || interval.start_offset_ticks() != previous_end {
            return Err(ProfileError::StateMismatch);
        }
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != 7 || previous_end != summary.total_ticks() {
        return Err(ProfileError::StateMismatch);
    }
    stream.complete()?;
    if status()
        != (SlotStatus::Ready {
            next_epoch: Some(4),
        })
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-core-poll-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
fn run_topology_rejection() -> Result<(), ProfileError> {
    let permit = prepare_current()?;
    let epoch = permit.expected_epoch();
    match permit.start() {
        Err(ProfileError::Start(TargetStartError::InvalidContext(faults)))
            if faults.contains(FacadeFaults::WRONG_ONLINE_MASK)
                && !faults.contains(FacadeFaults::WRONG_LOGICAL_HART)
                && !faults.contains(FacadeFaults::WRONG_PHYSICAL_HART)
                && epoch == 1
                && status()
                    == (SlotStatus::Ready {
                        next_epoch: Some(1),
                    }) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(run) => {
            drop(run);
            Err(ProfileError::StateMismatch)
        }
    }
}

/// QEMU-only positive single-hart and negative multi-hart ownership proof.
#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
pub(crate) async fn run_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_positive_acceptance().await {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_SLOT PASS detached_active=1 detached_stream=1 epochs=1,2,3 intervals=7 indexed=1 complete=1 ready_epoch=4"
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_SLOT FAIL {:?}", error),
        }
    } else {
        match run_topology_rejection() {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_SLOT TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_SLOT FAIL {:?}", error),
        }
    }
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn exact_stream_resource_types(
    component: &vibeos_component_runtime::sync::SynchronousComponent,
    entrypoint: &str,
) -> Option<(
    vibeos_component_runtime::resource::ResourceTypeId,
    vibeos_component_runtime::resource::ResourceTypeId,
)> {
    use vibeos_component_runtime::value::{ResourceOwnership, ValueType};

    let function = component.function_type(entrypoint)?;
    let [reader, writer] = function.parameters.as_slice() else {
        return None;
    };
    let borrowed = |value: &ValueType| match value {
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } => Some(*resource_type),
        _ => None,
    };
    Some((borrowed(&reader.value)?, borrowed(&writer.value)?))
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn profile_is_publishable(profile: &vibeos_component_runtime::sync::SyncCallProfile) -> bool {
    profile.typed_polls != u64::MAX
        && profile.core_polls != u64::MAX
        && profile.outer_poll_ticks != u64::MAX
        && profile.core_interpreter_ticks != u64::MAX
        && profile.consumed_work != u64::MAX
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn run_core_poll_positive_acceptance() -> Result<(), ProfileError> {
    use alloc::vec::Vec;
    use vibeos_component_runtime::{
        decode::inspect_component,
        resource::ResourceTable,
        sync::{SyncCallProfile, SynchronousComponent, TypedPoll},
        value::CanonicalValue,
    };
    use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

    let permit = prepare_current()?;
    if permit.expected_epoch() != 1 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let pin = vibeos_image_policy::SSH_EXEC_COMPONENT;
    let limits = pin.limits();

    wait_for_tick_progress();
    let plan = inspect_component(pin.artifact_bytes()).map_err(|_| ProfileError::StateMismatch)?;
    if !plan.runtime_ready() {
        return Err(ProfileError::StateMismatch);
    }

    run.set_phase(Phase::Instantiation)?;
    let engine = ProfileEngine::new();
    let mut component = SynchronousComponent::instantiate_with_memory_limit(
        &plan,
        &engine,
        OwnerAllocationReservation::new(limits.memory_bytes),
        limits.memory_bytes,
    )
    .map_err(|_| ProfileError::StateMismatch)?;
    let (reader_type, writer_type) = exact_stream_resource_types(&component, pin.entrypoint())
        .ok_or(ProfileError::StateMismatch)?;

    run.set_phase(Phase::Abi)?;
    let mut resources =
        ResourceTable::<u8>::new(1, limits.resources).map_err(|_| ProfileError::StateMismatch)?;
    let reader = resources
        .insert_owned(reader_type, 1)
        .map_err(|_| ProfileError::StateMismatch)?;
    let writer = resources
        .insert_owned(writer_type, 2)
        .map_err(|_| ProfileError::StateMismatch)?;
    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(2)
        .map_err(|_| ProfileError::StateMismatch)?;
    arguments.push(CanonicalValue::Resource(reader));
    arguments.push(CanonicalValue::Resource(writer));
    let mut call = component
        .start_typed_call(
            &mut resources,
            pin.entrypoint(),
            arguments,
            limits.total_fuel,
            limits.poll_quantum,
        )
        .map_err(|_| ProfileError::StateMismatch)?;
    let mut profile = SyncCallProfile::default();
    let mut observed_core = false;

    for _ in 0..4_096 {
        let before = profile.core_polls;
        let mut clock = SlotCorePollClock::new(&run);
        let result = call.poll_profiled(&mut clock, &mut profile);
        if clock.error().is_some() || !clock.core_is_closed() {
            return Err(clock.error().unwrap_or(ProfileError::StateMismatch));
        }
        if !profile_is_publishable(&profile) {
            return Err(ProfileError::StateMismatch);
        }
        if profile.core_polls > before {
            if profile.core_polls - before != 1 {
                return Err(ProfileError::StateMismatch);
            }
            observed_core = true;
            break;
        }
        if !matches!(result, TypedPoll::Pending(_)) {
            return Err(ProfileError::StateMismatch);
        }
    }
    if !observed_core || profile.core_interpreter_ticks == 0 {
        return Err(ProfileError::StateMismatch);
    }

    wait_for_tick_progress();
    run.begin_cleanup()?;
    drop(call);
    drop(resources);
    drop(component);
    drop(engine);
    wait_for_tick_progress();

    let mut stream = run.finish()?;
    let summary = stream.summary()?;
    if summary.phase_ticks().interpretation < profile.core_interpreter_ticks
        || !summary.intervals_complete()
        || summary.interval_count() != 6
    {
        return Err(ProfileError::StateMismatch);
    }
    let expected_phases = [
        Phase::Validation,
        Phase::Instantiation,
        Phase::Abi,
        Phase::Interpretation,
        Phase::Abi,
        Phase::Cleanup,
    ];
    let mut count = 0;
    let mut previous_end = 0;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count
            || interval.start_offset_ticks() != previous_end
            || expected_phases.get(count) != Some(&interval.phase())
        {
            return Err(ProfileError::StateMismatch);
        }
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != expected_phases.len() || previous_end != summary.total_ticks() {
        return Err(ProfileError::StateMismatch);
    }
    stream.complete()?;
    if status()
        != (SlotStatus::Ready {
            next_epoch: Some(2),
        })
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

/// QEMU-only proof that the explicit portable observer drives a real wasmi
/// Core poll into the exact task-owned slot. It does not modify ordinary
/// `TypedCall::poll` or claim SSH/trap/publication integration.
#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
pub(crate) async fn run_core_poll_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_core_poll_positive_acceptance() {
            Ok(()) => crate::println!(
                "WASM_C84_CORE_POLL PASS exact_artifact=1 real_core=1 observer_paired=1 interpretation_nonzero=1 complete=1 ready_epoch=2"
            ),
            Err(error) => crate::println!("WASM_C84_CORE_POLL FAIL {:?}", error),
        }
    } else {
        match run_topology_rejection() {
            Ok(()) => crate::println!(
                "WASM_C84_CORE_POLL TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_CORE_POLL FAIL {:?}", error),
        }
    }
}

/// Publish one local runnable reason, then deliberately force its pending
/// doorbell through OpenSBI as a real supervisor self-IPI. The worker remains
/// in one synchronous poll stack while the trap runs and returns.
#[cfg(any(
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
    feature = "wasm-c84-profile-child-delegation-qemu-acceptance"
))]
fn force_boot_self_ssip(expect_profiled: bool) -> Result<(), ProfileError> {
    use crate::ipi::DoorbellDisposition;

    let hart = crate::exec::HartId::BOOT;
    let before = crate::ipi::stats(hart);
    let paired_before = ACCEPTANCE_SSIP_PAIRED.load(Ordering::Acquire);
    let inactive_before = ACCEPTANCE_SSIP_INACTIVE.load(Ordering::Acquire);
    if crate::ipi::publish_runnable(hart) != DoorbellDisposition::Local
        || crate::ipi::retry_pending(hart) != DoorbellDisposition::Sent
    {
        return Err(ProfileError::StateMismatch);
    }

    let start = live_tick();
    let after = loop {
        let observed = crate::ipi::stats(hart);
        if observed.acknowledged.wrapping_sub(before.acknowledged) == 1
            && observed.pending_reasons == 0
        {
            break observed;
        }
        if live_tick().wrapping_sub(start) >= crate::exec::timebase_hz() {
            return Err(ProfileError::StateMismatch);
        }
        core::hint::spin_loop();
    };

    if after.notifications.wrapping_sub(before.notifications) < 1
        || after.doorbells.wrapping_sub(before.doorbells) != 1
        || after.send_failures != before.send_failures
        || after.idle_consumed != before.idle_consumed
        || after.stale != before.stale
    {
        return Err(ProfileError::StateMismatch);
    }
    let paired_delta = ACCEPTANCE_SSIP_PAIRED
        .load(Ordering::Acquire)
        .wrapping_sub(paired_before);
    let inactive_delta = ACCEPTANCE_SSIP_INACTIVE
        .load(Ordering::Acquire)
        .wrapping_sub(inactive_before);
    if (expect_profiled && (paired_delta != 1 || inactive_delta != 0))
        || (!expect_profiled && (paired_delta != 0 || inactive_delta != 1))
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
async fn wait_for_task_state(
    handle: &crate::exec::TaskHandle,
    expected: crate::exec::TaskState,
) -> Result<(), ProfileError> {
    for _ in 0..1_024 {
        if let Some(exit) = handle.try_exit() {
            return if exit.state() == expected {
                Ok(())
            } else {
                Err(ProfileError::StateMismatch)
            };
        }
        crate::exec::yield_now().await;
    }
    Err(ProfileError::StateMismatch)
}

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
async fn wait_for_acceptance_flag(flag: &AtomicBool) -> Result<(), ProfileError> {
    for _ in 0..1_024 {
        if flag.load(Ordering::Acquire) {
            return Ok(());
        }
        crate::exec::yield_now().await;
    }
    Err(ProfileError::StateMismatch)
}

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
fn require_delegated_rejection(
    result: Result<StreamLease, ProfileError>,
    epoch: u64,
    reason: TaskDetachReason,
    abandoned: bool,
) -> Result<(), ProfileError> {
    let report = match result {
        Err(ProfileError::Rejected(report)) => report,
        Err(error) => return Err(error),
        Ok(stream) => {
            drop(stream);
            return Err(ProfileError::StateMismatch);
        }
    };
    if report.epoch != epoch
        || report.cause != RejectionCause::DelegatedTaskDetached(reason)
        || !report.slot_faults.contains(SlotFaults::CHILD_DETACHED)
        || report.slot_faults.contains(SlotFaults::CHILD_ABANDONED) != abandoned
        || !report.facade_faults.is_empty()
        || report.ledger_error.is_some()
    {
        return Err(ProfileError::Rejected(report));
    }
    acknowledge_rejection(epoch)?;
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
fn require_child_observer_rejection(
    result: Result<StreamLease, ProfileError>,
    epoch: u64,
    abandoned: bool,
    parent_observer: bool,
) -> Result<(), ProfileError> {
    let report = match result {
        Err(ProfileError::Rejected(report)) => report,
        Err(error) => return Err(error),
        Ok(stream) => {
            drop(stream);
            return Err(ProfileError::StateMismatch);
        }
    };
    let mut expected_faults = SlotFaults::NONE;
    expected_faults.insert(SlotFaults::CHILD_OBSERVER);
    if abandoned {
        expected_faults.insert(SlotFaults::CHILD_ABANDONED);
    }
    if parent_observer {
        expected_faults.insert(SlotFaults::CORE_OBSERVER);
    }
    expected_faults.insert(SlotFaults::CHILD_DETACHED);
    if report.epoch != epoch
        || report.cause != RejectionCause::DelegatedTaskDetached(TaskDetachReason::Exited)
        || report.slot_faults != expected_faults
        || !report.facade_faults.is_empty()
        || report.ledger_error.is_some()
    {
        return Err(ProfileError::Rejected(report));
    }
    acknowledge_rejection(epoch)?;
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
fn acceptance_child_observer_drop_is_sticky(child: &ChildRunLease) -> bool {
    let slot = SLOT.lock();
    matches!(
        &*slot,
        SlotState::Active {
            sample,
            child: Some(exact),
            faults,
            core_owner: CoreObserverOwner::Child,
            ..
        } if sample.token() == child.token
            && exact.matches(child.token.epoch(), child.detach)
            && exact.state == DelegatedChildState::Claimed
            && faults.contains(SlotFaults::CHILD_OBSERVER)
    )
}

/// Prove the narrow request-parent -> prepared-child lineage without touching
/// the ordinary component runner. The accepted child is sealed before batch
/// publication, may mutate phases and receive a real SSIP only while exact,
/// and must retain its callback through future Drop until the executor reports
/// the final terminal reason.
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
async fn run_child_delegation_positive_acceptance() -> Result<(), ProfileError> {
    use crate::exec::{CancelOutcome, PreparedTaskBatch, TaskState};

    ACCEPTANCE_CHILD_CLAIMED.store(false, Ordering::Release);
    ACCEPTANCE_CHILD_RELEASED.store(false, Ordering::Release);
    ACCEPTANCE_WRONG_TASK_INERT.store(false, Ordering::Release);
    ACCEPTANCE_CANCEL_CHILD_INERT.store(false, Ordering::Release);
    ACCEPTANCE_RELEASED_PENDING.store(false, Ordering::Release);
    ACCEPTANCE_FINISH_CHILD_INERT.store(false, Ordering::Release);
    ACCEPTANCE_LATE_CLAIM_REJECTED.store(false, Ordering::Release);
    ACCEPTANCE_FAULT_ARMED.store(false, Ordering::Release);
    ACCEPTANCE_CHILD_CORE_RETURN_TICK.store(0, Ordering::Release);
    ACCEPTANCE_OBSERVER_DROP_STICKY.store(false, Ordering::Release);
    ACCEPTANCE_OPEN_RELEASE_REJECTED.store(false, Ordering::Release);
    ACCEPTANCE_OPEN_PHASE_REJECTED.store(false, Ordering::Release);
    ACCEPTANCE_REPLACEMENT_REJECTED.store(false, Ordering::Release);
    ACCEPTANCE_CHILD_CORE_OPEN.store(false, Ordering::Release);
    ACCEPTANCE_PARENT_MUTATION_RESUME.store(false, Ordering::Release);
    ACCEPTANCE_PARENT_MUTATION_REJECTED.store(false, Ordering::Release);

    let ready_one = SlotStatus::Ready {
        next_epoch: Some(1),
    };
    if status() != ready_one || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }
    force_boot_self_ssip(false)?;

    // Epoch 1: only task index 1 owns the prepared-child seal. Index 0 may
    // attempt both claim and a real SSIP, but neither operation can mutate the
    // sample. The exact child explicitly releases, returns normally, and only
    // its final Exited callback clears the delegation marker.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 1 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    wait_for_tick_progress();
    run.set_phase(Phase::Instantiation)?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-wrong", async {
        let claim_inert = matches!(
            claim_delegated_child(),
            Err(ProfileError::OwnerNotCurrent | ProfileError::DelegatedChildUnavailable)
        );
        let irq_inert = force_boot_self_ssip(false).is_ok();
        ACCEPTANCE_WRONG_TASK_INERT.store(claim_inert && irq_inert, Ordering::Release);
    });
    batch.prepare("c84-delegation-exact", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        ACCEPTANCE_CHILD_CLAIMED.store(true, Ordering::Release);
        wait_for_tick_progress();
        if child.set_phase(Phase::Abi).is_err() {
            return;
        }
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let core_started = clock.core_poll_started();
        wait_for_tick_progress();
        let core_finished = clock.core_poll_finished();
        if core_finished.wrapping_sub(core_started) == 0
            || clock.error().is_some()
            || !clock.core_is_closed()
        {
            return;
        }
        ACCEPTANCE_CHILD_CORE_RETURN_TICK.store(core_finished, Ordering::Release);
        drop(clock);
        wait_for_tick_progress();
        if force_boot_self_ssip(true).is_err() {
            return;
        }
        wait_for_tick_progress();
        if child.set_phase(Phase::Host).is_err() {
            return;
        }
        wait_for_tick_progress();
        if child.release().is_ok() {
            ACCEPTANCE_CHILD_RELEASED.store(true, Ordering::Release);
        }
    });
    if !matches!(
        run.attach_prepared_child(&mut batch, 2),
        Err(ProfileError::RegistrationReserveFailed)
    ) || batch
        .prepared_handles()
        .iter()
        .any(|handle| handle.is_published())
    {
        return Err(ProfileError::StateMismatch);
    }
    run.attach_prepared_child(&mut batch, 1)?;
    if status()
        != (SlotStatus::Delegated {
            epoch: 1,
            claimed: false,
        })
        || !matches!(
            run.attach_prepared_child(&mut batch, 0),
            Err(ProfileError::DelegatedChildAttached)
        )
    {
        return Err(ProfileError::StateMismatch);
    }
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    if handles.len() != 2 {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    wait_for_task_state(&handles[1], TaskState::Exited).await?;
    if !ACCEPTANCE_WRONG_TASK_INERT.load(Ordering::Acquire)
        || !ACCEPTANCE_CHILD_CLAIMED.load(Ordering::Acquire)
        || !ACCEPTANCE_CHILD_RELEASED.load(Ordering::Acquire)
        || status() != (SlotStatus::Active { epoch: 1 })
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 1
        || !matches!(
            run.attach_prepared_child(&mut batch, 0),
            Err(ProfileError::DelegatedChildAttached)
        )
    {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_tick_progress();
    run.set_phase(Phase::Wait)?;
    wait_for_tick_progress();
    run.begin_cleanup()?;
    wait_for_tick_progress();
    let mut stream = run.finish()?;
    let summary = stream.summary()?;
    if !summary.intervals_complete()
        || summary.phase_ticks().abi == 0
        || summary.phase_ticks().interpretation == 0
        || summary.phase_ticks().host == 0
        || summary.phase_ticks().wait == 0
    {
        return Err(ProfileError::StateMismatch);
    }
    let mut count = 0;
    let mut previous_end = 0;
    let mut interpretation_end_tick = None;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count || interval.start_offset_ticks() != previous_end {
            return Err(ProfileError::StateMismatch);
        }
        if interval.phase() == Phase::Interpretation {
            interpretation_end_tick = Some(
                summary
                    .start_tick()
                    .wrapping_add(interval.end_offset_ticks()),
            );
        }
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    let returned_core_end = ACCEPTANCE_CHILD_CORE_RETURN_TICK.load(Ordering::Acquire);
    if returned_core_end == 0
        || interpretation_end_tick != Some(returned_core_end)
        || count != summary.interval_count()
        || previous_end != summary.total_ticks()
    {
        return Err(ProfileError::StateMismatch);
    }
    stream.complete()?;
    if status()
        != (SlotStatus::Ready {
            next_epoch: Some(2),
        })
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }

    // Epoch 2: parent cancellation wins before publication. Its sample is
    // rejected and acknowledged first; the later child claim and detach
    // callback are stale and cannot alter the next Ready epoch.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 2 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-cancel-stale", async {
        let inert = matches!(
            claim_delegated_child(),
            Err(ProfileError::DelegatedChildUnavailable)
        ) && force_boot_self_ssip(false).is_ok();
        ACCEPTANCE_CANCEL_CHILD_INERT.store(inert, Ordering::Release);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let report = run.cancel()?;
    if report.epoch != 2
        || report.cause != RejectionCause::LeaseCancelled
        || !report.slot_faults.is_empty()
    {
        return Err(ProfileError::Rejected(report));
    }
    acknowledge_rejection(2)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_CANCEL_CHILD_INERT.load(Ordering::Acquire)
        || status()
            != (SlotStatus::Ready {
                next_epoch: Some(3),
            })
    {
        return Err(ProfileError::StateMismatch);
    }

    // Epoch 3: returning with a claimed lease deliberately forgotten is an
    // Exited detach without explicit release, hence a request-local rejection.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 3 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-forget", async {
        let Ok(child) = claim_delegated_child() else {
            return;
        };
        let _ = child.set_phase(Phase::Host);
        wait_for_tick_progress();
        core::mem::forget(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    require_delegated_rejection(run.finish(), 3, TaskDetachReason::Exited, false)?;

    // Epoch 4: ordinary ChildRunLease Drop records Abandoned; the final Exited
    // callback adds the exact terminal reason and clears the child seal.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 4 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-abandon", async {
        let Ok(child) = claim_delegated_child() else {
            return;
        };
        let _ = child.set_phase(Phase::Host);
        wait_for_tick_progress();
        drop(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    require_delegated_rejection(run.finish(), 4, TaskDetachReason::Exited, true)?;

    // Epoch 5: release is not a detach disarm. Cancellation after release must
    // still be reported as Cancelled rather than mistaken for clean Exited.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 5 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-release-cancel", async {
        let Ok(child) = claim_delegated_child() else {
            return;
        };
        let _ = child.set_phase(Phase::Host);
        wait_for_tick_progress();
        if child.release().is_err() || force_boot_self_ssip(true).is_err() {
            return;
        }
        ACCEPTANCE_RELEASED_PENDING.store(true, Ordering::Release);
        loop {
            crate::exec::yield_now().await;
        }
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_acceptance_flag(&ACCEPTANCE_RELEASED_PENDING).await?;
    if !matches!(handles[0].cancel(), CancelOutcome::Requested) {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_task_state(&handles[0], TaskState::Cancelled).await?;
    require_delegated_rejection(run.finish(), 5, TaskDetachReason::Cancelled, false)?;

    // Epoch 6: finish itself is fail-closed while a child remains Attached.
    // The parent emits a diagnostic rejection; a subsequent publication can
    // neither claim the old seal nor perturb Ready epoch 7.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 6 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-finish-stale", async {
        let inert = matches!(
            claim_delegated_child(),
            Err(ProfileError::DelegatedChildUnavailable)
        );
        ACCEPTANCE_FINISH_CHILD_INERT.store(inert, Ordering::Release);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let report = match run.finish() {
        Err(ProfileError::Rejected(report)) => report,
        Err(error) => return Err(error),
        Ok(stream) => {
            drop(stream);
            return Err(ProfileError::StateMismatch);
        }
    };
    if report.epoch != 6
        || report.cause != RejectionCause::DelegatedChildAttached
        || !report.slot_faults.is_empty()
    {
        return Err(ProfileError::Rejected(report));
    }
    acknowledge_rejection(6)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    let ready_seven = SlotStatus::Ready {
        next_epoch: Some(7),
    };
    if !ACCEPTANCE_FINISH_CHILD_INERT.load(Ordering::Acquire)
        || status() != ready_seven
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }
    // Epoch 7: claiming after a deliberate first-poll yield is too late. The
    // child cannot omit its unprofiled prefix and still produce a clean sample.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 7 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-late-claim", async {
        crate::exec::yield_now().await;
        ACCEPTANCE_LATE_CLAIM_REJECTED.store(
            matches!(
                claim_delegated_child(),
                Err(ProfileError::DelegatedChildUnavailable)
            ),
            Ordering::Release,
        );
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_LATE_CLAIM_REJECTED.load(Ordering::Acquire) {
        return Err(ProfileError::StateMismatch);
    }
    require_delegated_rejection(run.finish(), 7, TaskDetachReason::Exited, false)?;

    // Epoch 8: the child releases cleanly, then its parked future faults while
    // the executor drops it for cancellation. The real guarded-reclaim path
    // must report Faulted to the still-armed detach callback without emitting
    // a panic or accepting the sample.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 8 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-release-fault", async {
        let Ok(child) = claim_delegated_child() else {
            return;
        };
        let _ = child.set_phase(Phase::Host);
        wait_for_tick_progress();
        if child.release().is_err() {
            return;
        }
        let fault = AcceptanceSilentDestructorFault;
        ACCEPTANCE_FAULT_ARMED.store(true, Ordering::Release);
        core::future::pending::<()>().await;
        core::hint::black_box(&fault);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_acceptance_flag(&ACCEPTANCE_FAULT_ARMED).await?;
    if !matches!(handles[0].cancel(), CancelOutcome::Requested) {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_task_state(&handles[0], TaskState::Faulted).await?;
    require_delegated_rejection(run.finish(), 8, TaskDetachReason::Faulted, false)?;

    // Epoch 9: a child-side Core observer finish without a matching start is
    // sticky even if the immediate error is ignored. The child cannot complete
    // cleanly, and the parent must reject the otherwise ordinary Exited edge.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 9 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-observer-fault", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_finished();
        if clock.error() != Some(ProfileError::StateMismatch) || !clock.core_is_closed() {
            return;
        }
        drop(clock);
        drop(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    require_child_observer_rejection(run.finish(), 9, true, false)?;

    // Epoch 10: dropping an open child observer is independently sticky. No
    // immediate return value exists for the caller to inspect, so the final
    // parent rejection is the only acceptable outcome.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 10 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-observer-drop-open", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_started();
        wait_for_tick_progress();
        drop(clock);
        ACCEPTANCE_OBSERVER_DROP_STICKY.store(
            acceptance_child_observer_drop_is_sticky(&child),
            Ordering::Release,
        );
        drop(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_OBSERVER_DROP_STICKY.load(Ordering::Acquire) {
        return Err(ProfileError::StateMismatch);
    }
    require_child_observer_rejection(run.finish(), 10, true, false)?;

    // Epoch 11: forgetting an open observer leaves the request-wide Core edge
    // latched in SLOT. Release itself must reject before ChildRunLease Drop can
    // contribute an abandonment fault.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 11 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-observer-release-open", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_started();
        wait_for_tick_progress();
        core::mem::forget(clock);
        ACCEPTANCE_OPEN_RELEASE_REJECTED.store(
            matches!(child.release(), Err(ProfileError::StateMismatch)),
            Ordering::Release,
        );
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_OPEN_RELEASE_REJECTED.load(Ordering::Acquire) {
        return Err(ProfileError::StateMismatch);
    }
    require_child_observer_rejection(run.finish(), 11, true, false)?;

    // Epoch 12: direct phase mutation and a replacement observer are each
    // checked independently while the forgotten observer still owns Core.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 12 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-observer-forget-open", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_started();
        wait_for_tick_progress();
        core::mem::forget(clock);
        ACCEPTANCE_OPEN_PHASE_REJECTED.store(
            matches!(
                child.set_phase(Phase::Abi),
                Err(ProfileError::StateMismatch)
            ),
            Ordering::Release,
        );
        let mut replacement = ChildSlotCorePollClock::new(&mut child);
        let _ = replacement.core_poll_started();
        ACCEPTANCE_REPLACEMENT_REJECTED.store(
            replacement.error() == Some(ProfileError::StateMismatch)
                && !replacement.core_is_closed(),
            Ordering::Release,
        );
        drop(replacement);
        let _ = child.release();
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_OPEN_PHASE_REJECTED.load(Ordering::Acquire)
        || !ACCEPTANCE_REPLACEMENT_REJECTED.load(Ordering::Acquire)
    {
        return Err(ProfileError::StateMismatch);
    }
    require_child_observer_rejection(run.finish(), 12, true, false)?;

    // Epoch 13: forgetting both the open observer and its child owner still
    // leaves the Core edge in SLOT. The exact terminal callback must preserve
    // CHILD_OBSERVER without fabricating a ChildRunLease Drop.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 13 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-observer-double-forget", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_started();
        wait_for_tick_progress();
        core::mem::forget(clock);
        core::mem::forget(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    require_child_observer_rejection(run.finish(), 13, false, false)?;

    // Epoch 14: while child Core is open, the parent cannot mutate the ledger.
    // Its rejected phase write becomes a parent-observer fault; the child's
    // subsequent close also fails closed and records the child side.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 14 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-delegation-parent-mutation", async {
        let Ok(mut child) = claim_delegated_child() else {
            return;
        };
        let mut clock = ChildSlotCorePollClock::new(&mut child);
        let _ = clock.core_poll_started();
        if clock.error().is_some() || clock.core_is_closed() {
            return;
        }
        ACCEPTANCE_CHILD_CORE_OPEN.store(true, Ordering::Release);
        for _ in 0..1_024 {
            if ACCEPTANCE_PARENT_MUTATION_RESUME.load(Ordering::Acquire) {
                break;
            }
            crate::exec::yield_now().await;
        }
        if !ACCEPTANCE_PARENT_MUTATION_RESUME.load(Ordering::Acquire) {
            return;
        }
        let _ = clock.core_poll_finished();
        drop(clock);
        drop(child);
    });
    run.attach_prepared_child(&mut batch, 0)?;
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_acceptance_flag(&ACCEPTANCE_CHILD_CORE_OPEN).await?;
    let parent_rejected = matches!(run.set_phase(Phase::Host), Err(ProfileError::StateMismatch));
    ACCEPTANCE_PARENT_MUTATION_REJECTED.store(parent_rejected, Ordering::Release);
    ACCEPTANCE_PARENT_MUTATION_RESUME.store(true, Ordering::Release);
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    if !ACCEPTANCE_PARENT_MUTATION_REJECTED.load(Ordering::Acquire) {
        return Err(ProfileError::StateMismatch);
    }
    require_child_observer_rejection(run.finish(), 14, true, true)?;

    // Epoch 15: forgetting both a parent-owned open observer and its RunLease
    // leaves only the exact owner-task detach callback. It must preserve the
    // global Core owner fault while cancelling and recycling the sample.
    let mut batch = PreparedTaskBatch::new();
    batch.prepare("c84-parent-observer-double-forget", async {
        let Ok(permit) = prepare_current() else {
            return;
        };
        if permit.expected_epoch() != 15 {
            return;
        }
        let Ok(run) = permit.start() else {
            return;
        };
        let mut clock = SlotCorePollClock::new(&run);
        let _ = clock.core_poll_started();
        wait_for_tick_progress();
        core::mem::forget(clock);
        core::mem::forget(run);
    });
    let handles = batch.publish().map_err(|_| ProfileError::StateMismatch)?;
    wait_for_task_state(&handles[0], TaskState::Exited).await?;
    let report = rejection().ok_or(ProfileError::StateMismatch)?;
    if report.epoch != 15
        || report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited)
        || report.slot_faults != SlotFaults::CORE_OBSERVER
        || !report.facade_faults.is_empty()
        || report.ledger_error.is_some()
        || report.intervals_emitted != 0
    {
        return Err(ProfileError::Rejected(report));
    }
    acknowledge_rejection(15)?;

    let ready_sixteen = SlotStatus::Ready {
        next_epoch: Some(16),
    };
    force_boot_self_ssip(false)?;
    if status() != ready_sixteen || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

/// QEMU-only proof of the bounded prepared-child seam. This marker says
/// nothing about SSH acceptance, the frozen component runner, ordinary Core
/// polling, publication, or physical Milk-V timing evidence.
#[cfg(feature = "wasm-c84-profile-child-delegation-qemu-acceptance")]
pub(crate) async fn run_child_delegation_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_child_delegation_positive_acceptance().await {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_CHILD_DELEGATION PASS bind_before_publish=1 exact_prepared=1 first_poll_only=1 duplicate_inert=1 wrong_task_inert=1 child_core_pair=1 same_end_tick=1 child_irq_pair=1 clean_detach=1 complete=1 cancel_stale_inert=1 forget_rejected=1 abandoned_rejected=1 release_cancelled=1 finish_attached_rejected=1 late_claim_rejected=1 release_faulted=1 observer_fault_sticky=1 observer_drop_open=1 observer_release_open=1 observer_forget_open=1 observer_double_forget=1 parent_double_forget=1 open_phase_rejected=1 replacement_rejected=1 parent_mutation_rejected=1 gate_cleared=1 epochs=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 ready_epoch=16"
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_CHILD_DELEGATION FAIL {:?}", error),
        }
    } else {
        let result = run_topology_rejection().and_then(|()| {
            if ACTIVE_EPOCH.load(Ordering::Acquire) == 0 {
                Ok(())
            } else {
                Err(ProfileError::StateMismatch)
            }
        });
        match result {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_CHILD_DELEGATION TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_CHILD_DELEGATION FAIL {:?}", error),
        }
    }
}

#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
async fn run_irq_positive_acceptance() -> Result<(), ProfileError> {
    let ready_epoch_one = SlotStatus::Ready {
        next_epoch: Some(1),
    };
    if status() != ready_epoch_one || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // A real SSIP before Active must remain observationally inert.
    force_boot_self_ssip(false)?;
    if status() != ready_epoch_one || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // Hold epoch 1 across suspension. The parent then receives a real SSIP
    // while it is not the sample owner; that trap must be a total no-op. The
    // child's ordinary RunLease Drop independently proves gate clearing.
    ACCEPTANCE_CHILD_ACTIVE.store(false, Ordering::Release);
    ACCEPTANCE_CHILD_RELEASE.store(false, Ordering::Release);
    let suspended =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-irq-non-owner-drop", async {
            let permit = prepare_current().expect("C8.4 IRQ suspended permit");
            assert_eq!(permit.expected_epoch(), 1);
            let run = permit.start().expect("C8.4 IRQ suspended start");
            assert_eq!(run.token().epoch(), 1);
            assert_eq!(ACTIVE_EPOCH.load(Ordering::Acquire), 1);
            ACCEPTANCE_CHILD_ACTIVE.store(true, Ordering::Release);
            while !ACCEPTANCE_CHILD_RELEASE.load(Ordering::Acquire) {
                crate::exec::yield_now().await;
            }
            drop(run);
        });
    for _ in 0..128 {
        if ACCEPTANCE_CHILD_ACTIVE.load(Ordering::Acquire) {
            break;
        }
        crate::exec::yield_now().await;
    }
    if !ACCEPTANCE_CHILD_ACTIVE.load(Ordering::Acquire)
        || status() != (SlotStatus::Active { epoch: 1 })
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 1
    {
        return Err(ProfileError::StateMismatch);
    }
    force_boot_self_ssip(false)?;
    if status() != (SlotStatus::Active { epoch: 1 }) || ACTIVE_EPOCH.load(Ordering::Acquire) != 1 {
        return Err(ProfileError::StateMismatch);
    }
    ACCEPTANCE_CHILD_RELEASE.store(true, Ordering::Release);
    if suspended.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let drop_report = wait_for_rejection(1).await?;
    if drop_report.cause != RejectionCause::LeaseCancelled
        || !drop_report.slot_faults.is_empty()
        || !drop_report.facade_faults.is_empty()
        || drop_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(drop_report));
    }
    acknowledge_rejection(1)?;

    // Explicit cancel is a distinct public exit through the shared cancel
    // transition and must clear epoch 2 before installing Rejected.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 2 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != 2 || ACTIVE_EPOCH.load(Ordering::Acquire) != 2 {
        return Err(ProfileError::StateMismatch);
    }
    let cancel_report = run.cancel()?;
    if cancel_report.cause != RejectionCause::LeaseCancelled
        || !cancel_report.slot_faults.is_empty()
        || !cancel_report.facade_faults.is_empty()
        || cancel_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(cancel_report));
    }
    acknowledge_rejection(2)?;

    // Forget epoch 3 so only the executor's exact task-detach callback can
    // recover Active and clear the gate.
    let detached =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-irq-detach", async {
            let permit = prepare_current().expect("C8.4 IRQ detach permit");
            assert_eq!(permit.expected_epoch(), 3);
            let run = permit.start().expect("C8.4 IRQ detach start");
            assert_eq!(run.token().epoch(), 3);
            assert_eq!(ACTIVE_EPOCH.load(Ordering::Acquire), 3);
            core::mem::forget(run);
        });
    if detached.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let detach_report = wait_for_rejection(3).await?;
    if detach_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited)
        || !detach_report.slot_faults.is_empty()
        || !detach_report.facade_faults.is_empty()
        || detach_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(detach_report));
    }
    acknowledge_rejection(3)?;

    // Epoch 4 is the publishable sample. The SSIP-specific acceptance counter
    // proves the forced doorbell, rather than a periodic timer, supplied one
    // successfully closed active cookie.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 4 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != 4 || ACTIVE_EPOCH.load(Ordering::Acquire) != 4 {
        return Err(ProfileError::StateMismatch);
    }

    wait_for_tick_progress();
    run.set_phase(Phase::Host)?;
    wait_for_tick_progress();
    force_boot_self_ssip(true)?;
    // Make the restored Host interval independently non-zero before Cleanup.
    wait_for_tick_progress();
    run.begin_cleanup()?;
    wait_for_tick_progress();

    let mut stream = run.finish()?;
    let summary = stream.summary()?;
    if !summary.intervals_complete() || summary.phase_ticks().wait == 0 {
        return Err(ProfileError::StateMismatch);
    }

    let mut count = 0;
    let mut previous_end = 0;
    let mut previous_phase = None;
    let mut phase_before_previous = None;
    let mut previous_nonzero = false;
    let mut wait_count = 0;
    let mut paired_count = 0;
    let mut restored_host = false;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count || interval.start_offset_ticks() != previous_end {
            return Err(ProfileError::StateMismatch);
        }
        let phase = interval.phase();
        if phase == Phase::Wait {
            wait_count += 1;
        }
        if previous_phase == Some(Phase::Wait) {
            let Some(base) = phase_before_previous else {
                return Err(ProfileError::StateMismatch);
            };
            if base == Phase::Wait || phase != base || !previous_nonzero {
                return Err(ProfileError::StateMismatch);
            }
            paired_count += 1;
            restored_host |= base == Phase::Host;
        }
        previous_nonzero = interval.end_offset_ticks() > interval.start_offset_ticks();
        phase_before_previous = previous_phase;
        previous_phase = Some(phase);
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != summary.interval_count()
        || previous_end != summary.total_ticks()
        || previous_phase == Some(Phase::Wait)
        || wait_count == 0
        || paired_count != wait_count
        || !restored_host
    {
        return Err(ProfileError::StateMismatch);
    }

    stream.complete()?;
    let ready_epoch_five = SlotStatus::Ready {
        next_epoch: Some(5),
    };
    if status() != ready_epoch_five || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // A final real SSIP proves the gate was cleared by Active -> Verified
    // before streaming and remains inert after Verified -> Ready recycling.
    force_boot_self_ssip(false)?;
    if status() != ready_epoch_five || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // Acceptance-only mismatch injection proves the first poison remains
    // stable, forcibly clears the fast gate, makes inactive-cookie exit a
    // no-op, and prevents either helper or prepare from re-arming the slot.
    ACTIVE_EPOCH.store(77, Ordering::Release);
    if publish_active_epoch(88) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || poison_reason() != Some(SlotPoison::IrqStateMismatch)
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }
    poison(SlotPoison::StateMismatch);
    let inactive = profile_irq_enter(live_tick());
    if profile_irq_exit(inactive, live_tick())
        || publish_active_epoch(99) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || clear_active_epoch(99) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || !matches!(
            prepare_current(),
            Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        )
        || poison_reason() != Some(SlotPoison::IrqStateMismatch)
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

/// QEMU-only proof of the default-off trap overlay using real OpenSBI
/// self-SSIPs, exactly one of which is an active-owner profiled pair. Timer,
/// PLIC, SSH, and publication integration remain separate.
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
pub(crate) async fn run_irq_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_irq_positive_acceptance().await {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_IRQ_OVERLAY PASS inactive_before=1 forced_ssip=4 causal_ssip_pair=1 non_owner_inert=1 cleared_cancel=1 cleared_drop=1 cleared_detach=1 wait_nonzero=1 restored=1 paired=1 complete=1 ready_epoch=5 inactive_after=1 poison_fail_closed=1"
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_IRQ_OVERLAY FAIL {:?}", error),
        }
    } else {
        let result = run_topology_rejection().and_then(|()| {
            if ACTIVE_EPOCH.load(Ordering::Acquire) == 0 {
                Ok(())
            } else {
                Err(ProfileError::StateMismatch)
            }
        });
        match result {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_IRQ_OVERLAY TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_IRQ_OVERLAY FAIL {:?}", error),
        }
    }
}
