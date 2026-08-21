//! The VibeOS scheduler.
//!
//! There are no kernel threads and no preemption. The unit of scheduling is a
//! `Future`; a task runs until it returns `Pending`, at which point its stack
//! is gone and all that remains is the state machine the compiler built. Wakeups
//! come from interrupt handlers, so "blocking" costs a queue push instead of a
//! context switch.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::arch;
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
use crate::instance::InstanceToken;
use crate::ipi;
use crate::runqueue::{EnqueueError, RunQueues};
use crate::sync::{SpinLock, TaskRecoveryContext, TaskRecoveryKey};

pub use crate::runqueue::{HartId, HartRunQueueStats, MAX_HARTS};

/// Default timer frequency used by host tests and QEMU `virt`.
///
/// Bare-metal platforms configure the actual firmware timebase once during
/// early boot through [`configure_timebase`]. Keeping this constant preserves
/// deterministic host-test calculations while timer code reads the runtime
/// value through [`timebase_hz`].
pub const TIMEBASE_HZ: u64 = 10_000_000;
const UNCONFIGURED_TIMEBASE_HZ: u64 = 0;
static CONFIGURED_TIMEBASE_HZ: AtomicU64 = AtomicU64::new(UNCONFIGURED_TIMEBASE_HZ);

/// Configure the firmware timer frequency before any timer is armed.
///
/// Repeating the same value is harmless; changing an already configured value
/// is rejected because outstanding deadlines would otherwise change units.
pub fn configure_timebase(hz: u64) {
    assert!(
        hz >= 1_000_000,
        "timer timebase must provide microsecond resolution"
    );
    let previous = CONFIGURED_TIMEBASE_HZ
        .compare_exchange(
            UNCONFIGURED_TIMEBASE_HZ,
            hz,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .unwrap_or_else(|configured| configured);
    assert!(
        previous == UNCONFIGURED_TIMEBASE_HZ || previous == hz,
        "timer timebase changed after configuration"
    );
}

pub fn timebase_hz() -> u64 {
    match CONFIGURED_TIMEBASE_HZ.compare_exchange(
        UNCONFIGURED_TIMEBASE_HZ,
        TIMEBASE_HZ,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => TIMEBASE_HZ,
        Err(configured) => configured,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TaskId(pub u64);

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "task:{}", self.0)
    }
}

/// Stable, allocation-free callback installed in one exact task's cleanup
/// ledger before an independently owned SYSTEM supervisor publishes work.
///
/// The executor invokes this target only after the task has crossed permanent
/// detach and after every ordinary wait/timer/join registration in the same
/// ledger has been removed. `context` is deliberately opaque: it commonly
/// carries a generational index into a fixed SYSTEM registry, never a pointer
/// into the task's allocation domain.
#[derive(Clone, Copy)]
pub struct TaskDetachTarget {
    context: u64,
    notify: unsafe fn(u64, TaskId, AllocationDomain, TaskDetachReason),
}

/// Exact executor terminal transition which caused permanent TaskStatus
/// detach. Stable supervisors use this to distinguish raw poll fault from
/// cooperative cancellation without inspecting or retaining the future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskDetachReason {
    Exited,
    Cancelled,
    Faulted,
}

impl TaskDetachTarget {
    /// Construct one supervisor callback target.
    ///
    /// # Safety
    ///
    /// `notify` must remain executable for the lifetime of the kernel. It must
    /// be allocation-free, bounded, nonblocking, and safe to invoke in SYSTEM
    /// after the exact task and its wake registrations are permanently
    /// detached. `context` must resolve only stable SYSTEM state and must carry
    /// its own generation/ABA protection.
    pub const unsafe fn new(
        context: u64,
        notify: unsafe fn(u64, TaskId, AllocationDomain, TaskDetachReason),
    ) -> Self {
        Self { context, notify }
    }

    fn matches(self, other: Self) -> bool {
        self.context == other.context && core::ptr::fn_addr_eq(self.notify, other.notify)
    }
}

/// Copy-only proof that one exact current TaskStatus owns a detach callback.
///
/// This token owns no task handle, future, queue, allocator, or callback
/// state. Its private status seal prevents a same-number TaskId or same-domain
/// task from disarming another incarnation's cleanup entry.
#[derive(Clone, Copy)]
pub struct CurrentTaskDetachLease {
    task: TaskId,
    domain: AllocationDomain,
    status_identity: usize,
    registration: u64,
    target: TaskDetachTarget,
}

impl CurrentTaskDetachLease {
    pub const fn task_id(self) -> TaskId {
        self.task
    }

    pub const fn allocation_domain(self) -> AllocationDomain {
        self.domain
    }

    /// Compare every private identity dimension of two copy-only leases.
    /// This reveals no TaskStatus address or registration token; stable
    /// registries use it only to reject a same-number task/domain projection
    /// whose status incarnation, callback, or ledger generation differs.
    pub fn matches_exact(self, other: Self) -> bool {
        self.task == other.task
            && self.domain == other.domain
            && self.status_identity == other.status_identity
            && self.registration == other.registration
            && self.target.matches(other.target)
    }

    /// Whether this lease's exact parent is still in its ordinary poll stack.
    ///
    /// A task-wide reclaim destructor retains CurrentTaskScope but has already
    /// detached the scheduler `running` slot. Supervisors use this distinction
    /// to avoid guessing Cancelled from a nested guard Drop before the executor
    /// knows whether a later destructor fault changes the final reason.
    pub fn is_current_running_exact(self) -> bool {
        let Some(hart) = current_scheduler_hart() else {
            return false;
        };
        let Some(status) = CURRENT_TASK_STATUS[hart.index()].lock().clone() else {
            return false;
        };
        let sched = SCHED.lock();
        sched.harts[hart.index()]
            .running
            .as_ref()
            .is_some_and(|running| {
                running.id == self.task
                    && running.domain == self.domain
                    && Arc::ptr_eq(&running.status, &status)
                    && Arc::as_ptr(&status) as usize == self.status_identity
            })
    }

    /// Whether Drop is reclaiming this exact whole task after its running slot
    /// was detached. In this state callers must leave the detach callback
    /// armed until the executor determines the final destructor outcome.
    pub fn is_current_reclaiming_exact(self) -> bool {
        let Some(hart) = current_scheduler_hart() else {
            return false;
        };
        let Some(status) = CURRENT_TASK_STATUS[hart.index()].lock().clone() else {
            return false;
        };
        let scope_exact = CURRENT_TASK_ID[hart.index()].load(Ordering::Acquire) == self.task.0
            && Arc::as_ptr(&status) as usize == self.status_identity
            && heap::current_domain() == self.domain;
        scope_exact && !self.is_current_running_exact()
    }

    /// Remove this exact callback while the original task incarnation is
    /// still executing. Repeating an already successful disarm is idempotent;
    /// a different task/status/domain can never consume the entry.
    pub fn disarm(self) -> TaskDetachDisarm {
        let Some(hart) = current_scheduler_hart() else {
            return TaskDetachDisarm::IdentityMismatch;
        };
        let Some(status) = CURRENT_TASK_STATUS[hart.index()].lock().clone() else {
            return TaskDetachDisarm::IdentityMismatch;
        };
        // A normal future destructor runs after its scheduler `running` slot
        // has been detached, but the executor reinstalls the same private
        // CurrentTaskScope and allocation domain around Drop. Validate that
        // scope directly so RAII can disarm; a longjmp fault skips the guard
        // and leaves the entry for the executor's final-reason detach pass.
        let exact = CURRENT_TASK_ID[hart.index()].load(Ordering::Acquire) == self.task.0
            && Arc::as_ptr(&status) as usize == self.status_identity
            && heap::current_domain() == self.domain;
        if !exact {
            return TaskDetachDisarm::IdentityMismatch;
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let removed = status.disarm_owned(self.registration);
        system.restore();
        match removed {
            Some(OwnedRegistration::TaskDetach {
                target,
                task,
                domain,
            }) if target.matches(self.target) && task == self.task && domain == self.domain => {
                TaskDetachDisarm::Disarmed
            }
            Some(_) => panic!("task detach registration identity changed"),
            None => TaskDetachDisarm::AlreadyDisarmed,
        }
    }

    /// Wake only the exact TaskStatus incarnation captured by this lease.
    /// TaskId values are monotonic and never reused; after the locked identity
    /// check, a concurrent permanent detach can only make the wake inactive.
    pub fn wake_if_exact(self) -> bool {
        let exact = {
            let sched = SCHED.lock();
            sched.tasks.get(&self.task).is_some_and(|task| {
                task.domain == self.domain
                    && Arc::as_ptr(&task.status) as usize == self.status_identity
            }) || sched.harts.iter().any(|hart| {
                hart.running.as_ref().is_some_and(|running| {
                    running.id == self.task
                        && running.domain == self.domain
                        && Arc::as_ptr(&running.status) as usize == self.status_identity
                })
            })
        };
        exact && !matches!(wake_with_disposition(self.task), WakeDisposition::Inactive)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskDetachRegistrationError {
    NotInTask,
    RegistrationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskDetachDisarm {
    Disarmed,
    AlreadyDisarmed,
    IdentityMismatch,
}

/// Copy-only scheduler wake projection sealed to one exact TaskStatus.
/// Stable SYSTEM registries may retain this scalar without retaining a task
/// handle or allocation-domain object.
#[derive(Clone, Copy)]
pub struct ExactTaskWake {
    task: TaskId,
    domain: AllocationDomain,
    status_identity: usize,
}

impl ExactTaskWake {
    /// Wake only while all three identity dimensions still resolve to the
    /// same live scheduler record. A terminal/detached or replaced task is
    /// observationally inert.
    pub fn wake_if_exact(self) -> bool {
        let exact = {
            let sched = SCHED.lock();
            sched.tasks.get(&self.task).is_some_and(|task| {
                task.domain == self.domain
                    && Arc::as_ptr(&task.status) as usize == self.status_identity
            }) || sched.harts.iter().any(|hart| {
                hart.running.as_ref().is_some_and(|running| {
                    running.id == self.task
                        && running.domain == self.domain
                        && Arc::as_ptr(&running.status) as usize == self.status_identity
                })
            })
        };
        exact && !matches!(wake_with_disposition(self.task), WakeDisposition::Inactive)
    }
}

/// Attach a stable orphan-handoff target to the exact task poll currently
/// executing.
///
/// Unlike [`current_reclaimable_task_witness`], this accepts both shared and
/// exclusive tracked domains (and ordinary untracked tasks). Production SSH
/// parents use the shared raw-reclaimable mode. The private TaskStatus object
/// seal is captured together with TaskId and allocation domain.
///
/// # Safety
///
/// `target` must satisfy [`TaskDetachTarget::new`]. The caller must retain its
/// target registry generation until this lease is exactly disarmed or the
/// callback has run.
pub unsafe fn register_current_task_detach(
    target: TaskDetachTarget,
) -> Result<CurrentTaskDetachLease, TaskDetachRegistrationError> {
    let Some(hart) = current_scheduler_hart() else {
        return Err(TaskDetachRegistrationError::NotInTask);
    };
    let Some(status) = CURRENT_TASK_STATUS[hart.index()].lock().clone() else {
        return Err(TaskDetachRegistrationError::NotInTask);
    };
    let (task, domain) = {
        let sched = SCHED.lock();
        let Some(running) = sched.harts[hart.index()].running.as_ref() else {
            return Err(TaskDetachRegistrationError::NotInTask);
        };
        if running.hart != hart || !Arc::ptr_eq(&running.status, &status) {
            return Err(TaskDetachRegistrationError::NotInTask);
        }
        (running.id, running.domain)
    };
    let status_identity = Arc::as_ptr(&status) as usize;
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let registration = status
        .register_owned(OwnedRegistration::TaskDetach {
            target,
            task,
            domain,
        })
        .map_err(|_| TaskDetachRegistrationError::RegistrationFailed);
    system.restore();
    Ok(CurrentTaskDetachLease {
        task,
        domain,
        status_identity,
        registration: registration?,
        target,
    })
}

/// Remove the exact detach target installed for the task whose poll is
/// currently executing.
///
/// Prepared SYSTEM supervisors cannot capture a lease minted only after their
/// future has already been boxed into a [`PreparedTaskBatch`].  They instead
/// capture the same copy-only target used by
/// [`PreparedTaskBatch::install_prepared_task_detach`] and disarm it at the
/// final safe point before returning.  No other task or callback target can be
/// consumed by this operation.
pub fn disarm_current_task_detach(target: TaskDetachTarget) -> TaskDetachDisarm {
    let Some(status) = current_task_status() else {
        return TaskDetachDisarm::IdentityMismatch;
    };
    let Some(task) = current_task_scope_id() else {
        return TaskDetachDisarm::IdentityMismatch;
    };
    let domain = heap::current_domain();
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let removed = {
        let mut registrations = status.registrations.lock();
        let mut matching =
            registrations
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match entry.registration {
                    OwnedRegistration::TaskDetach {
                        target: registered,
                        task: registered_task,
                        domain: registered_domain,
                    } if registered.matches(target)
                        && registered_task == task
                        && registered_domain == domain =>
                    {
                        Some(index)
                    }
                    _ => None,
                });
        let index = matching.next();
        assert!(
            matching.next().is_none(),
            "one task cannot own duplicate exact detach targets"
        );
        index.map(|index| registrations.swap_remove(index).registration)
    };
    system.restore();
    match removed {
        Some(OwnedRegistration::TaskDetach {
            target: registered,
            task: registered_task,
            domain: registered_domain,
        }) if registered.matches(target)
            && registered_task == task
            && registered_domain == domain =>
        {
            TaskDetachDisarm::Disarmed
        }
        Some(_) => panic!("task detach registration identity changed"),
        None => TaskDetachDisarm::AlreadyDisarmed,
    }
}

/// Read-only proof that the current exact task still owns one matching detach
/// target. This does not consume or clone the registration and grants no wake
/// or cleanup authority; it exists so a SYSTEM supervisor can prove its
/// fail-stop callback remains armed immediately before an irreversible
/// lifecycle transaction.
pub fn current_task_detach_is_armed(target: TaskDetachTarget) -> bool {
    let Some(status) = current_task_status() else {
        return false;
    };
    let Some(task) = current_task_scope_id() else {
        return false;
    };
    let domain = heap::current_domain();
    let registrations = status.registrations.lock();
    let mut matches = registrations.iter().filter(|entry| {
        matches!(
            entry.registration,
            OwnedRegistration::TaskDetach {
                target: registered,
                task: registered_task,
                domain: registered_domain,
            } if registered.matches(target)
                && registered_task == task
                && registered_domain == domain
        )
    });
    let armed = matches.next().is_some();
    assert!(
        matches.next().is_none(),
        "one task cannot own duplicate exact detach targets"
    );
    armed
}

/// Preallocate fixed TaskStatus cleanup-ledger capacity for the task whose
/// poll is currently executing.
///
/// SYSTEM supervisors use this before publishing dependent work so later
/// fixed-queue waits cannot encounter a recoverable allocation failure after
/// that work is live. Capacity is retained when individual registrations are
/// disarmed. This function never reserves a wait target or grants authority.
pub fn try_reserve_current_task_registrations(additional: usize) -> bool {
    const MAX_SUPERVISOR_REGISTRATION_RESERVE: usize = 4;
    if additional == 0 || additional > MAX_SUPERVISOR_REGISTRATION_RESERVE {
        return false;
    }
    let Some(status) = current_task_status() else {
        return false;
    };
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let reserved = status
        .registrations
        .lock()
        .try_reserve_exact(additional)
        .is_ok();
    system.restore();
    reserved
}

/// The lifecycle states shared by the executor and a supervising component.
///
/// Cancellation is a terminal state of a task incarnation; the supervising
/// component keeps its own stable identity across that transition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum TaskState {
    Running = 0,
    Exited = 1,
    Faulted = 2,
    Cancelled = 3,
}

const CANCEL_REQUESTED: u8 = 4;
const EXIT_COMMITTED: u8 = 5;
const CANCEL_COMMITTED: u8 = 6;
const FAULT_COMMITTED: u8 = 7;

impl TaskState {
    pub const fn terminal_reason(self) -> Option<&'static str> {
        match self {
            Self::Running => None,
            Self::Exited => Some("returned"),
            Self::Faulted => Some("fault"),
            Self::Cancelled => Some("cancelled"),
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Running,
            1 => Self::Exited,
            2 => Self::Faulted,
            3 => Self::Cancelled,
            // Cancellation is cooperative. Until the executor reaches a poll
            // boundary and reclaims the future, the public lifecycle remains
            // Running rather than claiming a terminal state too early.
            CANCEL_REQUESTED | EXIT_COMMITTED | CANCEL_COMMITTED | FAULT_COMMITTED => Self::Running,
            _ => unreachable!("invalid task state"),
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Running => "running",
            Self::Exited => "exited",
            Self::Faulted => "faulted",
            Self::Cancelled => "cancelled",
        })
    }
}

struct JoinWaiter {
    id: u64,
    waker: Waker,
}

#[derive(Clone)]
enum OwnedRegistration {
    Wait {
        queue: usize,
        id: u64,
    },
    OneShotWait {
        queue: usize,
        generation: u64,
    },
    Timer {
        id: u64,
    },
    Join {
        status: Arc<TaskStatus>,
        id: u64,
    },
    IrqPollProbe {
        generation: u64,
    },
    TaskDetach {
        target: TaskDetachTarget,
        task: TaskId,
        domain: AllocationDomain,
    },
}

struct OwnedRegistrationEntry {
    token: u64,
    registration: OwnedRegistration,
}

#[derive(Clone, Copy, Debug)]
struct TerminalClaim {
    state: TaskState,
    raw: u8,
}

impl TerminalClaim {
    const fn new(state: TaskState) -> Self {
        let raw = match state {
            TaskState::Exited => EXIT_COMMITTED,
            TaskState::Faulted => FAULT_COMMITTED,
            TaskState::Cancelled => CANCEL_COMMITTED,
            TaskState::Running => unreachable!(),
        };
        Self { state, raw }
    }
}

enum CancelRequest {
    Requested,
    Terminal,
    TooLate(TaskState),
}

struct TaskStatus {
    published: Arc<AtomicBool>,
    polls: AtomicU64,
    state: AtomicU8,
    next_joiner: AtomicU64,
    joiners: SpinLock<Vec<JoinWaiter>>,
    next_registration: AtomicU64,
    registrations: SpinLock<Vec<OwnedRegistrationEntry>>,
}

impl TaskStatus {
    fn new(published: Arc<AtomicBool>) -> Self {
        Self {
            published,
            polls: AtomicU64::new(0),
            state: AtomicU8::new(TaskState::Running as u8),
            next_joiner: AtomicU64::new(1),
            joiners: SpinLock::new(Vec::new()),
            next_registration: AtomicU64::new(1),
            registrations: SpinLock::new(Vec::new()),
        }
    }

    fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    fn state(&self) -> TaskState {
        TaskState::from_raw(self.state.load(Ordering::Acquire))
    }

    fn raw_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    fn cancellation_requested(&self) -> bool {
        self.state.load(Ordering::Acquire) == CANCEL_REQUESTED
    }

    fn request_cancel(&self) -> CancelRequest {
        loop {
            let current = self.raw_state();
            match current {
                x if x == TaskState::Running as u8 => {
                    if self
                        .state
                        .compare_exchange(
                            current,
                            CANCEL_REQUESTED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return CancelRequest::Requested;
                    }
                }
                CANCEL_REQUESTED => return CancelRequest::Requested,
                1..=3 => return CancelRequest::Terminal,
                EXIT_COMMITTED => return CancelRequest::TooLate(TaskState::Exited),
                CANCEL_COMMITTED => return CancelRequest::TooLate(TaskState::Cancelled),
                FAULT_COMMITTED => return CancelRequest::TooLate(TaskState::Faulted),
                _ => unreachable!("invalid task state"),
            }
        }
    }

    /// Commit the terminal action while holding SCHED, before reclaiming the
    /// future. The public state remains Running until `publish` establishes the
    /// reclamation boundary.
    fn claim_terminal(&self, requested: TaskState) -> Option<TerminalClaim> {
        debug_assert!(requested != TaskState::Running);
        loop {
            let current = self.raw_state();
            let terminal = match (requested, current) {
                (TaskState::Faulted, x)
                    if x == TaskState::Running as u8 || x == CANCEL_REQUESTED =>
                {
                    TaskState::Faulted
                }
                (TaskState::Exited, CANCEL_REQUESTED)
                | (TaskState::Cancelled, CANCEL_REQUESTED) => TaskState::Cancelled,
                (TaskState::Exited, x) if x == TaskState::Running as u8 => TaskState::Exited,
                (TaskState::Cancelled, x) if x == TaskState::Running as u8 => TaskState::Cancelled,
                _ => return None,
            };
            let claim = TerminalClaim::new(terminal);
            if self
                .state
                .compare_exchange(current, claim.raw, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(claim);
            }
        }
    }

    fn promote_to_fault(&self, claim: TerminalClaim) -> TerminalClaim {
        if claim.state == TaskState::Faulted {
            return claim;
        }
        let fault = TerminalClaim::new(TaskState::Faulted);
        self.state
            .compare_exchange(claim.raw, fault.raw, Ordering::AcqRel, Ordering::Acquire)
            .expect("only the executor may own a terminal claim");
        fault
    }

    /// Publish only after normal reclamation completed, or after a faulted
    /// future was deliberately abandoned without running its destructor.
    fn publish(&self, claim: TerminalClaim) -> bool {
        if self
            .state
            .compare_exchange(
                claim.raw,
                claim.state as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.wake_joiners();
        true
    }

    fn next_joiner_id(&self) -> u64 {
        self.next_joiner
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("task join registration space exhausted")
    }

    fn wake_joiners(&self) {
        let joiners = {
            let mut joiners = self.joiners.lock();
            core::mem::take(&mut *joiners)
        };
        for waiter in joiners {
            waiter.waker.wake();
        }
    }

    fn unregister_joiner(&self, id: u64) -> Option<Waker> {
        let mut joiners = self.joiners.lock();
        joiners
            .iter()
            .position(|waiter| waiter.id == id)
            .map(|index| joiners.swap_remove(index).waker)
    }

    fn register_owned(&self, registration: OwnedRegistration) -> Result<u64, OwnedRegistration> {
        let token = self
            .next_registration
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("task registration token space exhausted");
        let mut registrations = self.registrations.lock();
        if registrations.try_reserve(1).is_err() {
            return Err(registration);
        }
        registrations.push(OwnedRegistrationEntry {
            token,
            registration,
        });
        Ok(token)
    }

    fn disarm_owned(&self, token: u64) -> Option<OwnedRegistration> {
        let mut registrations = self.registrations.lock();
        registrations
            .iter()
            .position(|entry| entry.token == token)
            .map(|index| registrations.swap_remove(index).registration)
    }
}

static CURRENT_TASK_STATUS: [SpinLock<Option<Arc<TaskStatus>>>; MAX_HARTS] =
    [const { SpinLock::new(None) }; MAX_HARTS];
static CURRENT_TASK_ID: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];

#[cfg(test)]
pub(crate) static EXECUTOR_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Resolve the scheduler identity of this CPU without ever aliasing an
/// unmapped target hart onto the boot slot. Host tests use dense physical ids
/// as their logical model when no SBI topology has been installed.
#[inline(always)]
fn current_scheduler_hart() -> Option<HartId> {
    if let Some(hart) = ipi::current_logical_hart() {
        return Some(hart);
    }

    #[cfg(not(target_arch = "riscv64"))]
    {
        return HartId::new(arch::current_hart_id());
    }

    #[cfg(target_arch = "riscv64")]
    None
}

#[inline(always)]
fn require_current_scheduler_hart(boundary: &str) -> HartId {
    current_scheduler_hart()
        .unwrap_or_else(|| panic!("{boundary} requires a mapped logical scheduler hart"))
}

fn current_task_status() -> Option<Arc<TaskStatus>> {
    let hart = current_scheduler_hart()?;
    CURRENT_TASK_STATUS[hart.index()].lock().clone()
}

struct CurrentTaskScope {
    slot: &'static SpinLock<Option<Arc<TaskStatus>>>,
    id_slot: &'static AtomicU64,
    previous: Option<Arc<TaskStatus>>,
    previous_id: u64,
    recovery: TaskRecoveryContext,
    active: bool,
    // A current-task scope changes hart-local scheduler and recovery state.
    // Moving it to another hart could restore both slots under the wrong CPU.
    not_send: PhantomData<*mut ()>,
}

// Compile-time negative auto-trait assertion. If `CurrentTaskScope` ever
// becomes `Send`, type inference sees both implementations and this item no
// longer compiles.
const _: fn() = || {
    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    let _ = <CurrentTaskScope as AmbiguousIfSend<_>>::marker;
};

fn enter_current_task(id: TaskId, status: Arc<TaskStatus>) -> CurrentTaskScope {
    let hart = require_current_scheduler_hart("task execution");
    // Safety: require_current_scheduler_hart resolved this CPU's exact slot.
    unsafe { enter_current_task_on_hart(hart, id, status) }
}

unsafe fn enter_current_task_on_hart(
    hart: HartId,
    id: TaskId,
    status: Arc<TaskStatus>,
) -> CurrentTaskScope {
    debug_assert_eq!(current_scheduler_hart(), Some(hart));
    let slot = &CURRENT_TASK_STATUS[hart.index()];
    let id_slot = &CURRENT_TASK_ID[hart.index()];
    let (previous, previous_id) = {
        let mut current = slot.lock();
        let previous = core::mem::replace(&mut *current, Some(status));
        let previous_id = id_slot.swap(id.0, Ordering::AcqRel);
        (previous, previous_id)
    };
    let recovery = unsafe {
        crate::sync::enter_task_recovery_context_on_hart(
            hart,
            TaskRecoveryKey::new(id.0).expect("TaskId zero is reserved"),
        )
    };
    CurrentTaskScope {
        slot,
        id_slot,
        previous,
        previous_id,
        recovery,
        active: true,
        not_send: PhantomData,
    }
}

impl CurrentTaskScope {
    fn restore(&mut self) {
        if self.active {
            if !self.recovery.is_current_hart() {
                // Prevent Drop from attempting a second restore while the
                // recovery scope reports the same hart-affinity violation.
                self.active = false;
                self.recovery.restore();
                unreachable!("task recovery restore must reject the wrong hart");
            }
            {
                let mut current = self.slot.lock();
                *current = self.previous.take();
                self.id_slot.store(self.previous_id, Ordering::Release);
            }
            self.active = false;
            // Safety: the physical-hart check above covers both hart-local
            // scopes, and logical mappings are immutable once installed.
            unsafe { self.recovery.restore_on_verified_hart() };
        }
    }
}

impl Drop for CurrentTaskScope {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Identity of the task whose poll is currently executing. Destructors run
/// after the running slot is detached and therefore return `None`, as do
/// scheduler, interrupt, and boot boundaries.
pub fn current_task_id() -> Option<TaskId> {
    let hart = current_scheduler_hart()?;
    let status = CURRENT_TASK_STATUS[hart.index()].lock().clone()?;
    let sched = SCHED.lock();
    sched.harts[hart.index()]
        .running
        .as_ref()
        .filter(|running| Arc::ptr_eq(&running.status, &status))
        .map(|running| running.id)
}

fn current_task_exact_wake() -> Option<ExactTaskWake> {
    let hart = current_scheduler_hart()?;
    let status = CURRENT_TASK_STATUS[hart.index()].lock().clone()?;
    let sched = SCHED.lock();
    let running = sched.harts[hart.index()]
        .running
        .as_ref()
        .filter(|running| running.hart == hart && Arc::ptr_eq(&running.status, &status))?;
    Some(ExactTaskWake {
        task: running.id,
        domain: running.domain,
        status_identity: Arc::as_ptr(&status) as usize,
    })
}

fn current_task_scope_id() -> Option<TaskId> {
    let hart = current_scheduler_hart()?;
    let current = CURRENT_TASK_STATUS[hart.index()].lock();
    let id = CURRENT_TASK_ID[hart.index()].load(Ordering::Acquire);
    (id != 0 && current.is_some()).then_some(TaskId(id))
}

/// Resolve the complete active reclaimable-task proof for the current poll.
/// Both the hart-local current-status cell and the scheduler running slot must
/// identify the same object in the same domain generation.  Callers must not
/// cache this witness across a poll boundary.
pub fn current_reclaimable_task_witness() -> Option<ReclaimableTaskWitness> {
    let hart = current_scheduler_hart()?;
    let status = CURRENT_TASK_STATUS[hart.index()].lock().clone()?;
    let sched = SCHED.lock();
    let running = sched.harts[hart.index()].running.as_ref()?;
    if running.hart != hart || !Arc::ptr_eq(&running.status, &status) {
        return None;
    }
    let key = running.reclaimable_domain?;
    let record = sched
        .reclaimable_domains
        .validate_active_task(
            key,
            running.domain,
            hart,
            running.id,
            &status,
            running.instance_token,
        )
        .ok()?;
    if !record.exclusive {
        return None;
    }
    Some(ReclaimableTaskWitness(ReclaimableFaultWitness {
        instance: record.exclusive_instance,
        scheduler: ReclaimableSchedulerIdentity(key),
        task: running.id,
        domain: running.domain,
        home_hart: record.home_hart,
        current_hart: hart,
        status_identity: Arc::as_ptr(&status) as usize,
    }))
}

fn register_owned_for_current(
    registration: OwnedRegistration,
) -> Result<Option<u64>, OwnedRegistration> {
    let status = current_task_status();
    match status {
        Some(status) => status.register_owned(registration).map(Some),
        None => Ok(None),
    }
}

fn disarm_owned_for_current(token: Option<u64>) {
    let Some(token) = token else {
        return;
    };
    if let Some(status) = current_task_status() {
        drop(status.disarm_owned(token));
    }
}

fn disarm_owned_for_task(task: TaskId, token: Option<u64>) {
    let Some(token) = token else {
        return;
    };
    let status = if current_task_scope_id() == Some(task) {
        current_task_status()
    } else {
        let sched = SCHED.lock();
        sched
            .harts
            .iter()
            .filter_map(|hart| hart.running.as_ref())
            .find(|running| running.id == task)
            .map(|running| running.status.clone())
            .or_else(|| sched.tasks.get(&task).map(|task| task.status.clone()))
    };
    if let Some(status) = status {
        drop(status.disarm_owned(token));
    }
}

fn take_owned_registration(status: &TaskStatus, task_detach: bool) -> Option<OwnedRegistration> {
    let mut registrations = status.registrations.lock();
    let index = registrations.iter().position(|entry| {
        matches!(entry.registration, OwnedRegistration::TaskDetach { .. }) == task_detach
    })?;
    Some(registrations.swap_remove(index).registration)
}

fn drain_ordinary_task_registrations(status: &TaskStatus) {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    while let Some(registration) = take_owned_registration(status, false) {
        cleanup_owned_registration(registration, None);
    }
    system.restore();
}

fn drain_task_detach_registrations(status: &TaskStatus, reason: TaskDetachReason) {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    while let Some(registration) = take_owned_registration(status, true) {
        cleanup_owned_registration(registration, Some(reason));
    }
    system.restore();
}

fn drain_task_registrations(status: &TaskStatus, reason: TaskDetachReason) {
    // Remove all old wait/timer/join edges before any SYSTEM orphan callback.
    drain_ordinary_task_registrations(status);
    drain_task_detach_registrations(status, reason);
}

fn task_detach_reason(status: &TaskStatus) -> TaskDetachReason {
    match status.raw_state() {
        x if x == TaskState::Exited as u8 || x == EXIT_COMMITTED => TaskDetachReason::Exited,
        x if x == TaskState::Faulted as u8 || x == FAULT_COMMITTED => TaskDetachReason::Faulted,
        x if x == TaskState::Cancelled as u8 || x == CANCEL_REQUESTED || x == CANCEL_COMMITTED => {
            TaskDetachReason::Cancelled
        }
        // An unpublished/never-polled task is being rolled back rather than
        // faulted; no future state is inferred from that administrative path.
        _ => TaskDetachReason::Cancelled,
    }
}

/// The immutable result retained after a task reaches a terminal state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TaskExit {
    id: TaskId,
    state: TaskState,
    polls: u64,
}

impl TaskExit {
    fn new(id: TaskId, state: TaskState, polls: u64) -> Self {
        assert!(
            state != TaskState::Running,
            "TaskExit requires a terminal state"
        );
        Self { id, state, polls }
    }

    pub fn id(self) -> TaskId {
        self.id
    }

    pub fn state(self) -> TaskState {
        self.state
    }

    pub fn polls(self) -> u64 {
        self.polls
    }

    pub fn reason(self) -> &'static str {
        match self.state.terminal_reason() {
            Some(reason) => reason,
            None => unreachable!("TaskExit cannot contain a running task"),
        }
    }
}

/// Result of requesting cancellation through a retained task handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CancelOutcome {
    Requested,
    AlreadyTerminal(TaskExit),
    /// The executor already committed return, fault, or cancellation and is
    /// finishing reclamation before publishing the terminal report.
    TooLate(TaskState),
    /// The task identity exists but its prepared batch has not published it.
    NotPublished,
}

/// A persistent view of one task's identity and lifecycle.
///
/// The scheduler owns the future; a `Component` owns this handle. That keeps a
/// terminal task observable after its future has been removed (or deliberately
/// leaked after a fault).
#[derive(Clone)]
pub struct TaskHandle {
    id: TaskId,
    domain: AllocationDomain,
    status: Arc<TaskStatus>,
}

/// Allocation-free C4.8 evidence that one terminal task retained no outbound
/// wake edge after the executor's permanent-detach drain.
#[cfg(feature = "wasm-c48-target-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptanceTaskRegistrationStats {
    pub total: usize,
    pub waits: usize,
    pub timers: usize,
    pub joins: usize,
    pub irq_poll_probes: usize,
    pub task_detaches: usize,
}

impl TaskHandle {
    pub fn id(&self) -> TaskId {
        self.id
    }

    pub fn owner(&self) -> OwnerId {
        self.domain.owner
    }

    pub fn arena(&self) -> ArenaId {
        self.domain.arena
    }

    pub fn allocation_domain(&self) -> AllocationDomain {
        self.domain
    }

    pub fn exact_wake(&self) -> ExactTaskWake {
        ExactTaskWake {
            task: self.id,
            domain: self.domain,
            status_identity: Arc::as_ptr(&self.status) as usize,
        }
    }

    /// Compare the stable, unforgeable status object behind two retained
    /// handles without exposing its address. Lifecycle registries use this to
    /// reject cross-slot aliases even if other scalar projections were
    /// corrupted independently.
    pub fn shares_status_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.status, &other.status)
    }

    pub fn is_published(&self) -> bool {
        self.status.is_published()
    }

    pub fn state(&self) -> TaskState {
        assert!(
            self.is_published(),
            "an unpublished task has no public state"
        );
        self.status.state()
    }

    pub fn polls(&self) -> u64 {
        assert!(
            self.is_published(),
            "an unpublished task has no public poll count"
        );
        self.status.polls.load(Ordering::Acquire)
    }

    /// Number of tasks currently registered to join this task.
    ///
    /// This is exposed for runtime diagnostics and reclamation invariants.
    pub fn joiner_count(&self) -> usize {
        assert!(
            self.is_published(),
            "an unpublished task has no public join ledger"
        );
        self.status.joiners.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn owned_registration_count_for_test(&self) -> usize {
        self.status.registrations.lock().len()
    }

    /// Inspect only the exact TaskStatus-owned outbound registration ledger.
    ///
    /// This API is absent from production builds. C4.8 samples it after the
    /// executor has published a terminal state, proving that fault detach
    /// drained this task's wait/timer/join/IRQ edges without relying on noisy
    /// machine-global service counters.
    #[cfg(feature = "wasm-c48-target-acceptance")]
    pub fn acceptance_registration_stats(&self) -> AcceptanceTaskRegistrationStats {
        assert!(
            self.is_published(),
            "an unpublished task has no registration ledger"
        );
        let registrations = self.status.registrations.lock();
        let mut stats = AcceptanceTaskRegistrationStats {
            total: registrations.len(),
            waits: 0,
            timers: 0,
            joins: 0,
            irq_poll_probes: 0,
            task_detaches: 0,
        };
        for entry in registrations.iter() {
            match entry.registration {
                OwnedRegistration::Wait { .. } | OwnedRegistration::OneShotWait { .. } => {
                    stats.waits += 1;
                }
                OwnedRegistration::Timer { .. } => stats.timers += 1,
                OwnedRegistration::Join { .. } => stats.joins += 1,
                OwnedRegistration::IrqPollProbe { .. } => stats.irq_poll_probes += 1,
                OwnedRegistration::TaskDetach { .. } => stats.task_detaches += 1,
            }
        }
        stats
    }

    /// Request cooperative cancellation.
    ///
    /// Outside user poll/Drop code, a ready or parked task is reclaimed before
    /// this call returns. Calls made by another active task are deferred to the
    /// next outer executor boundary so nested destructors cannot fault through
    /// that task's live stack. A running task observes its request at the poll
    /// boundary; a trusted future that never yields still cannot be rescued.
    pub fn cancel(&self) -> CancelOutcome {
        cancel_task(self)
    }

    pub fn cancellation_requested(&self) -> bool {
        assert!(
            self.is_published(),
            "an unpublished task has no public cancellation state"
        );
        self.status.cancellation_requested()
    }

    pub fn try_exit(&self) -> Option<TaskExit> {
        if !self.is_published() {
            return None;
        }
        let state = self.status.state();
        (state != TaskState::Running)
            .then(|| TaskExit::new(self.id, state, self.status.polls.load(Ordering::Acquire)))
    }

    /// Wait for return, fault, or cancellation without losing terminal state
    /// when completion races waiter registration.
    pub fn join(&self) -> Join {
        assert!(self.is_published(), "an unpublished task cannot be joined");
        Join {
            id: self.id,
            status: self.status.clone(),
            registration: None,
            owned_registration: None,
        }
    }
}

pub struct Join {
    id: TaskId,
    status: Arc<TaskStatus>,
    registration: Option<u64>,
    owned_registration: Option<u64>,
}

impl Future for Join {
    type Output = TaskExit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let state = this.status.state();
        if state != TaskState::Running {
            disarm_owned_for_current(this.owned_registration.take());
            if let Some(id) = this.registration.take() {
                drop(this.status.unregister_joiner(id));
            }
            return Poll::Ready(TaskExit::new(
                this.id,
                state,
                this.status.polls.load(Ordering::Acquire),
            ));
        }

        let status = this.status.clone();
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        let mut allocation_failed = false;
        let mut terminal = None;
        {
            // Register under the waiter lock, then re-read the terminal state.
            // `publish` changes state before draining this list, so either this
            // read observes terminal state or publication owns our waker.
            let mut joiners = status.joiners.lock();
            let state = status.state();
            if state != TaskState::Running {
                disarm_owned_for_current(this.owned_registration.take());
                if let Some(id) = this.registration.take() {
                    if let Some(index) = joiners.iter().position(|waiter| waiter.id == id) {
                        discarded = Some(joiners.swap_remove(index).waker);
                    }
                }
                terminal = Some(state);
            } else {
                let id = this.registration.unwrap_or_else(|| status.next_joiner_id());
                if this.registration.is_none() && this.owned_registration.is_none() {
                    match register_owned_for_current(OwnedRegistration::Join {
                        status: status.clone(),
                        id,
                    }) {
                        Ok(token) => this.owned_registration = token,
                        Err(_) => allocation_failed = true,
                    }
                }
                if allocation_failed {
                    // The target registry remains untouched when the owning
                    // task could not reserve its cleanup ledger.
                } else if let Some(waiter) = joiners.iter_mut().find(|waiter| waiter.id == id) {
                    if !waiter.waker.will_wake(cx.waker()) {
                        discarded = Some(core::mem::replace(
                            &mut waiter.waker,
                            candidate.take().expect("waker candidate exists"),
                        ));
                    }
                } else if joiners.try_reserve(1).is_err() {
                    allocation_failed = true;
                } else {
                    joiners.push(JoinWaiter {
                        id,
                        waker: candidate.take().expect("waker candidate exists"),
                    });
                    this.registration = Some(id);
                }
            }
        }
        drop(discarded);
        drop(candidate);
        system.restore();
        if allocation_failed {
            panic!("task join registration allocation failed");
        }
        if let Some(state) = terminal {
            return Poll::Ready(TaskExit::new(
                this.id,
                state,
                status.polls.load(Ordering::Acquire),
            ));
        }
        Poll::Pending
    }
}

impl Drop for Join {
    fn drop(&mut self) {
        disarm_owned_for_current(self.owned_registration.take());
        if let Some(id) = self.registration.take() {
            drop(self.status.unregister_joiner(id));
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaskReport {
    pub id: TaskId,
    pub owner: OwnerId,
    pub arena: ArenaId,
    pub name: String,
    pub state: TaskState,
    pub polls: u64,
}

struct Task {
    id: TaskId,
    domain: AllocationDomain,
    name: Arc<str>,
    future: ManuallyDrop<Pin<Box<dyn Future<Output = ()> + Send>>>,
    status: Arc<TaskStatus>,
    queue_owner: HartId,
    ready: bool,
    stealable: bool,
    publication: TaskPublication,
    reclaimable_domain: Option<ReclaimableDomainKey>,
    instance_token: Option<InstanceToken>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskPublication {
    Prepared(u64),
    Staged(u64),
    Published,
}

impl Task {
    const fn is_published(&self) -> bool {
        matches!(self.publication, TaskPublication::Published)
    }
}

/// Runs `f` with a landing pad installed, returning true if `f` faulted.
///
/// The kernel supplies this; `core` cannot, because a landing pad is
/// architecture-specific assembly. On the host there is none, and a panicking
/// task simply fails the test — which is the right behaviour there.
pub type FaultGuard = fn(&mut dyn FnMut()) -> bool;

/// Reclaim all raw allocations in one audited fault arena without running
/// their Rust destructors. The kernel installs this alongside its heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultReclaimOutcome {
    Reclaimed,
    Quarantined,
}

/// Executor-forged proof for one permanently detached reclaimable task.
///
/// Every field is private.  A fault reclaimer can inspect the tuple only
/// through exact comparisons, so it cannot manufacture a different scheduler
/// generation, status object, or managed-instance generation.  The witness is
/// created from the teardown permit while `SCHED` still owns the authoritative
/// projection, then passed by value after the scheduler lock is released.
#[derive(Clone, Copy)]
pub struct ReclaimableFaultWitness {
    instance: Option<InstanceToken>,
    scheduler: ReclaimableSchedulerIdentity,
    task: TaskId,
    domain: AllocationDomain,
    home_hart: HartId,
    current_hart: HartId,
    status_identity: usize,
}

impl ReclaimableFaultWitness {
    pub const fn instance_token(self) -> Option<InstanceToken> {
        self.instance
    }

    pub const fn scheduler_identity(self) -> ReclaimableSchedulerIdentity {
        self.scheduler
    }

    pub const fn task_id(self) -> TaskId {
        self.task
    }

    pub const fn allocation_domain(self) -> AllocationDomain {
        self.domain
    }

    pub const fn home_hart(self) -> HartId {
        self.home_hart
    }

    pub const fn current_hart(self) -> HartId {
        self.current_hart
    }

    pub fn matches_handle(self, handle: &TaskHandle) -> bool {
        self.task == handle.id
            && self.domain == handle.domain
            && self.status_identity == Arc::as_ptr(&handle.status) as usize
    }

    /// Produce one deliberately invalid projection for the C4.8 target
    /// acceptance matrix.
    ///
    /// This API is absent from production builds. Each enum case changes
    /// exactly one proof component by a fixed, non-caller-selected transform;
    /// it cannot be used to assemble a chosen witness or restore authority.
    /// `None` is returned only when [`AcceptanceWitnessMismatch::Generation`]
    /// is requested for a witness which does not name a managed instance.
    ///
    /// # Safety model
    ///
    /// The returned value is intentionally invalid and may only be submitted
    /// to a fail-closed acceptance gate after the original witness's task has
    /// crossed the executor's permanent-detach boundary. It must never replace
    /// the original witness in normal lifecycle control flow.
    #[cfg(feature = "wasm-c48-target-acceptance")]
    pub fn with_acceptance_mismatch(mut self, mismatch: AcceptanceWitnessMismatch) -> Option<Self> {
        match mismatch {
            AcceptanceWitnessMismatch::Generation => {
                self.instance = Some(self.instance?.with_mismatched_generation_for_acceptance());
            }
            AcceptanceWitnessMismatch::Task => {
                self.task = TaskId(self.task.0 ^ 1);
            }
            AcceptanceWitnessMismatch::Status => {
                self.status_identity ^= 1;
            }
            AcceptanceWitnessMismatch::Owner => {
                self.domain.owner = OwnerId::new(self.domain.owner.get() ^ 1);
            }
            AcceptanceWitnessMismatch::Arena => {
                self.domain.arena = ArenaId::new(self.domain.arena.get() ^ 1);
            }
            AcceptanceWitnessMismatch::CurrentHart => {
                let next = (self.current_hart.index() + 1) % MAX_HARTS;
                self.current_hart =
                    HartId::new(next).expect("acceptance hart transform stays in range");
            }
        }
        Some(self)
    }
}

/// Single-field corruptions available to the C4.8 target acceptance image.
///
/// The variants deliberately carry no values: acceptance code may prove that
/// each registry predicate rejects a mismatch, but cannot forge arbitrary
/// task, allocator, scheduler, or hart authority.
#[cfg(feature = "wasm-c48-target-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceWitnessMismatch {
    /// Change only the managed [`InstanceToken`] generation.
    Generation,
    /// Change only the [`TaskId`].
    Task,
    /// Change only the private TaskStatus object identity.
    Status,
    /// Change only the allocation owner projection.
    Owner,
    /// Change only the allocation arena projection.
    Arena,
    /// Change only the physical/logical hart-at-fault projection.
    CurrentHart,
}

#[cfg(test)]
pub(crate) fn reclaimable_fault_witness_for_test(
    instance: Option<InstanceToken>,
    task: TaskId,
    domain: AllocationDomain,
) -> ReclaimableFaultWitness {
    ReclaimableFaultWitness {
        instance,
        scheduler: ReclaimableSchedulerIdentity(ReclaimableDomainKey {
            slot: 0,
            generation: 1,
        }),
        task,
        domain,
        home_hart: HartId::BOOT,
        current_hart: HartId::BOOT,
        status_identity: 0,
    }
}

#[cfg(test)]
impl ReclaimableFaultWitness {
    pub(crate) fn with_instance_for_test(mut self, instance: Option<InstanceToken>) -> Self {
        self.instance = instance;
        self
    }

    pub(crate) fn with_task_for_test(mut self, task: TaskId) -> Self {
        self.task = task;
        self
    }

    pub(crate) fn with_domain_for_test(mut self, domain: AllocationDomain) -> Self {
        self.domain = domain;
        self
    }

    pub(crate) fn with_scheduler_generation_for_test(mut self, generation: u64) -> Self {
        self.scheduler.0.generation = generation;
        self
    }

    pub(crate) fn with_home_hart_for_test(mut self, home_hart: HartId) -> Self {
        self.home_hart = home_hart;
        self
    }

    pub(crate) fn with_current_hart_for_test(mut self, current_hart: HartId) -> Self {
        self.current_hart = current_hart;
        self
    }

    pub(crate) fn corrupt_status_identity_for_test(mut self) -> Self {
        self.status_identity ^= 1;
        self
    }
}

/// Poll-time counterpart of [`ReclaimableFaultWitness`].  It is valid only for
/// the current call stack and must be reacquired for every registry operation.
#[derive(Clone, Copy)]
pub struct ReclaimableTaskWitness(ReclaimableFaultWitness);

impl ReclaimableTaskWitness {
    pub const fn instance_token(self) -> Option<InstanceToken> {
        self.0.instance_token()
    }

    pub const fn scheduler_identity(self) -> ReclaimableSchedulerIdentity {
        self.0.scheduler_identity()
    }

    pub const fn task_id(self) -> TaskId {
        self.0.task_id()
    }

    pub const fn allocation_domain(self) -> AllocationDomain {
        self.0.allocation_domain()
    }

    pub const fn home_hart(self) -> HartId {
        self.0.home_hart()
    }

    pub const fn current_hart(self) -> HartId {
        self.0.current_hart()
    }

    pub fn matches_handle(self, handle: &TaskHandle) -> bool {
        self.0.matches_handle(handle)
    }
}

pub type FaultReclaimer = unsafe fn(ReclaimableFaultWitness) -> FaultReclaimOutcome;

/// Repair task-stable state abandoned by one exact faulted task. The executor
/// invokes this only after that task is detached forever and before publishing
/// `Faulted`. For a tracked arena, every abandoned sibling is reported once
/// before the domain reclaimer runs.
///
/// The callback runs in the SYSTEM allocation domain and must not allocate,
/// block, or panic. It may recover synchronization primitives owned by the
/// exact `(TaskId, AllocationDomain)` pair.
pub type FaultCleanup = unsafe fn(TaskId, AllocationDomain);

/// Allocation-free notification boundary reserved for M5.2. The hook runs
/// after `SCHED` is released and receives the queue owner that became ready.
/// M5.1 leaves it unset; no IPI is sent.
pub type ReadyNotifyHook = fn(HartId);

const _: () = {
    assert!(core::mem::size_of::<FaultGuard>() == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<FaultReclaimer>() == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<FaultCleanup>() == core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<ReadyNotifyHook>() == core::mem::size_of::<usize>());
};

// These callbacks are installed during single-threaded kernel bootstrap.  The
// ready notification is then read on every wake path, including interrupt
// context, so publishing the immutable function address directly avoids
// putting a global lock in that hot path.  Tests may replace a callback while
// the executor is quiescent; Release/Acquire makes that replacement visible.
static FAULT_GUARD: AtomicUsize = AtomicUsize::new(0);
static FAULT_RECLAIMER: AtomicUsize = AtomicUsize::new(0);
static FAULT_CLEANUP: AtomicUsize = AtomicUsize::new(0);
static READY_NOTIFY_HOOK: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(target_arch = "riscv64"))]
static RECLAIMABLE_TEARDOWN_TEST_HOOK: AtomicUsize = AtomicUsize::new(0);

fn load_fault_guard() -> Option<FaultGuard> {
    let address = FAULT_GUARD.load(Ordering::Acquire);
    (address != 0).then(|| {
        // SAFETY: the only non-zero values stored in this slot come from a
        // `FaultGuard` function pointer in `set_fault_guard`.
        unsafe { core::mem::transmute::<usize, FaultGuard>(address) }
    })
}

fn load_fault_reclaimer() -> Option<FaultReclaimer> {
    let address = FAULT_RECLAIMER.load(Ordering::Acquire);
    (address != 0).then(|| {
        // SAFETY: the slot is populated only by `set_fault_reclaimer`.
        unsafe { core::mem::transmute::<usize, FaultReclaimer>(address) }
    })
}

fn load_fault_cleanup() -> Option<FaultCleanup> {
    let address = FAULT_CLEANUP.load(Ordering::Acquire);
    (address != 0).then(|| {
        // SAFETY: the slot is populated only by `set_fault_cleanup`.
        unsafe { core::mem::transmute::<usize, FaultCleanup>(address) }
    })
}

fn load_ready_notify_hook() -> Option<ReadyNotifyHook> {
    let address = READY_NOTIFY_HOOK.load(Ordering::Acquire);
    (address != 0).then(|| {
        // SAFETY: the slot is populated only by `set_ready_notify_hook`.
        unsafe { core::mem::transmute::<usize, ReadyNotifyHook>(address) }
    })
}

pub fn set_fault_guard(guard: FaultGuard) {
    FAULT_GUARD.store(guard as usize, Ordering::Release);
}

pub fn set_fault_reclaimer(reclaimer: FaultReclaimer) {
    FAULT_RECLAIMER.store(reclaimer as usize, Ordering::Release);
}

pub fn set_fault_cleanup(cleanup: FaultCleanup) {
    FAULT_CLEANUP.store(cleanup as usize, Ordering::Release);
}

pub fn set_ready_notify_hook(hook: ReadyNotifyHook) {
    READY_NOTIFY_HOOK.store(hook as usize, Ordering::Release);
}

/// Remove the ready notification hook while the executor is quiescent.
/// Host tests use this to isolate publication-order probes; kernels normally
/// install their immutable IPI hook once during bootstrap.
#[cfg(not(target_arch = "riscv64"))]
pub fn clear_ready_notify_hook() {
    READY_NOTIFY_HOOK.store(0, Ordering::Release);
}

/// Host-only deterministic interleaving hook after a tracked domain and all
/// siblings have committed Faulted, but before sibling detachment begins.
#[cfg(not(target_arch = "riscv64"))]
pub fn set_reclaimable_teardown_test_hook(hook: fn(AllocationDomain)) {
    RECLAIMABLE_TEARDOWN_TEST_HOOK.store(hook as usize, Ordering::Release);
}

#[cfg(not(target_arch = "riscv64"))]
pub fn clear_reclaimable_teardown_test_hook() {
    RECLAIMABLE_TEARDOWN_TEST_HOOK.store(0, Ordering::Release);
}

#[cfg(not(target_arch = "riscv64"))]
fn run_reclaimable_teardown_test_hook(domain: AllocationDomain) {
    let address = RECLAIMABLE_TEARDOWN_TEST_HOOK.swap(0, Ordering::AcqRel);
    if address != 0 {
        // SAFETY: the host-only slot is populated exclusively by the typed
        // setter above and consumed once while SCHED is not held.
        let hook = unsafe { core::mem::transmute::<usize, fn(AllocationDomain)>(address) };
        hook(domain);
    }
}

#[cfg(target_arch = "riscv64")]
fn run_reclaimable_teardown_test_hook(_domain: AllocationDomain) {}

fn notify_ready_hart(hart: HartId) {
    if let Some(hook) = load_ready_notify_hook() {
        hook(hart);
    }
}

fn notify_fault_cleanup(task: TaskId, domain: AllocationDomain) {
    if let Some(cleanup) = load_fault_cleanup() {
        // Safety: every call site has detached this exact task permanently and
        // invokes the callback before terminal publication or arena reclaim.
        unsafe { cleanup(task, domain) };
    }
}

/// Scheduler-visible phase of one raw-reclaimable allocation domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimableDomainPhase {
    Active,
    TearingDown,
    TerminalReady,
    Quarantined,
}

/// Allocation-free diagnostic snapshot of one tracked-domain scheduler gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimableDomainSnapshot {
    pub home_hart: HartId,
    pub live_tasks: usize,
    pub exclusive: bool,
    pub phase: ReclaimableDomainPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReclaimableDomainMode {
    Shared,
    Exclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReclaimableDomainError {
    TableFull,
    Missing,
    WrongHome,
    NotActive,
    Exclusive,
    LiveTaskOverflow,
    LiveTaskMismatch,
    RemoteRunning,
    DomainMismatch,
    GenerationExhausted,
    KeyMismatch,
    TaskMismatch,
    StatusMismatch,
    InstanceMismatch,
    LifecycleMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReclaimableDomainKey {
    slot: u8,
    generation: u64,
}

/// Opaque scheduler incarnation assigned to one admitted raw-reclaimable
/// allocation domain.  The slot may be reused only with a strictly newer
/// generation, so lifecycle code can compare the whole value without learning
/// or reconstructing its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimableSchedulerIdentity(ReclaimableDomainKey);

impl ReclaimableSchedulerIdentity {
    pub const fn generation(self) -> u64 {
        self.0.generation
    }
}

#[derive(Clone, Copy)]
struct ReclaimableDomainRecord {
    key: ReclaimableDomainKey,
    domain: AllocationDomain,
    home_hart: HartId,
    live_tasks: usize,
    exclusive: bool,
    exclusive_task: Option<TaskId>,
    exclusive_status: Option<usize>,
    exclusive_instance: Option<InstanceToken>,
    phase: ReclaimableDomainPhase,
}

impl ReclaimableDomainRecord {
    const fn snapshot(self) -> ReclaimableDomainSnapshot {
        ReclaimableDomainSnapshot {
            home_hart: self.home_hart,
            live_tasks: self.live_tasks,
            exclusive: self.exclusive,
            phase: self.phase,
        }
    }
}

/// Fixed SYSTEM-owned scheduler metadata for every active allocator arena.
/// The table never allocates while SCHED is held or during fault teardown.
#[derive(Clone, Copy)]
struct ReclaimableDomains {
    records: [Option<ReclaimableDomainRecord>; heap::MAX_ALLOCATION_ARENAS],
    generations: [u64; heap::MAX_ALLOCATION_ARENAS],
}

impl ReclaimableDomains {
    const fn new() -> Self {
        Self {
            records: [None; heap::MAX_ALLOCATION_ARENAS],
            generations: [0; heap::MAX_ALLOCATION_ARENAS],
        }
    }

    fn index_of_arena(&self, arena: ArenaId) -> Option<usize> {
        self.records.iter().position(|record| {
            record
                .as_ref()
                .is_some_and(|record| record.domain.arena == arena)
        })
    }

    fn record(&self, domain: AllocationDomain) -> Option<ReclaimableDomainRecord> {
        self.index_of_arena(domain.arena)
            .and_then(|index| self.records[index])
            .filter(|record| record.domain == domain)
    }

    fn record_exact(
        &self,
        key: ReclaimableDomainKey,
        domain: AllocationDomain,
    ) -> Result<ReclaimableDomainRecord, ReclaimableDomainError> {
        let record = self
            .records
            .get(key.slot as usize)
            .and_then(|record| *record)
            .ok_or(ReclaimableDomainError::Missing)?;
        if record.key != key {
            return Err(ReclaimableDomainError::KeyMismatch);
        }
        if record.domain != domain {
            return Err(ReclaimableDomainError::DomainMismatch);
        }
        Ok(record)
    }

    fn validate_active_task(
        &self,
        key: ReclaimableDomainKey,
        domain: AllocationDomain,
        home_hart: HartId,
        task: TaskId,
        status: &Arc<TaskStatus>,
        instance: Option<InstanceToken>,
    ) -> Result<ReclaimableDomainRecord, ReclaimableDomainError> {
        let record = self.record_exact(key, domain)?;
        if record.phase != ReclaimableDomainPhase::Active {
            return Err(ReclaimableDomainError::NotActive);
        }
        if record.home_hart != home_hart {
            return Err(ReclaimableDomainError::WrongHome);
        }
        if record.exclusive {
            if record.live_tasks != 1 || record.exclusive_task != Some(task) {
                return Err(ReclaimableDomainError::TaskMismatch);
            }
            if record.exclusive_status != Some(Arc::as_ptr(status) as usize) {
                return Err(ReclaimableDomainError::StatusMismatch);
            }
            if record.exclusive_instance != instance {
                return Err(ReclaimableDomainError::InstanceMismatch);
            }
        }
        Ok(record)
    }

    fn preflight(
        &self,
        domain: AllocationDomain,
        home_hart: HartId,
        mode: ReclaimableDomainMode,
    ) -> Result<(), ReclaimableDomainError> {
        debug_assert!(domain.arena.is_tracked());
        if let Some(index) = self.index_of_arena(domain.arena) {
            let record = self.records[index].expect("tracked-domain index remains occupied");
            if record.domain != domain {
                return Err(ReclaimableDomainError::DomainMismatch);
            }
            if record.phase != ReclaimableDomainPhase::Active {
                return Err(ReclaimableDomainError::NotActive);
            }
            if record.home_hart != home_hart {
                return Err(ReclaimableDomainError::WrongHome);
            }
            if record.exclusive || mode == ReclaimableDomainMode::Exclusive {
                return Err(ReclaimableDomainError::Exclusive);
            }
            record
                .live_tasks
                .checked_add(1)
                .ok_or(ReclaimableDomainError::LiveTaskOverflow)?;
            return Ok(());
        }
        if !self
            .records
            .iter()
            .enumerate()
            .any(|(index, record)| record.is_none() && self.generations[index] != u64::MAX)
        {
            return Err(ReclaimableDomainError::TableFull);
        }
        Ok(())
    }

    fn admit(
        &mut self,
        domain: AllocationDomain,
        home_hart: HartId,
        mode: ReclaimableDomainMode,
        task: TaskId,
        status: &Arc<TaskStatus>,
        instance: Option<InstanceToken>,
    ) -> Result<ReclaimableDomainKey, ReclaimableDomainError> {
        self.preflight(domain, home_hart, mode)?;
        if let Some(index) = self.index_of_arena(domain.arena) {
            let record = self.records[index]
                .as_mut()
                .expect("tracked-domain index remains occupied");
            record.live_tasks += 1;
            return Ok(record.key);
        }
        let index = self
            .records
            .iter()
            .enumerate()
            .find_map(|(index, record)| {
                (record.is_none() && self.generations[index] != u64::MAX).then_some(index)
            })
            .ok_or(ReclaimableDomainError::TableFull)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(ReclaimableDomainError::GenerationExhausted)?;
        self.generations[index] = generation;
        let key = ReclaimableDomainKey {
            slot: u8::try_from(index).expect("reclaimable-domain table exceeds u8"),
            generation,
        };
        self.records[index] = Some(ReclaimableDomainRecord {
            key,
            domain,
            home_hart,
            live_tasks: 1,
            exclusive: mode == ReclaimableDomainMode::Exclusive,
            exclusive_task: (mode == ReclaimableDomainMode::Exclusive).then_some(task),
            exclusive_status: (mode == ReclaimableDomainMode::Exclusive)
                .then_some(Arc::as_ptr(status) as usize),
            exclusive_instance: (mode == ReclaimableDomainMode::Exclusive)
                .then_some(instance)
                .flatten(),
            phase: ReclaimableDomainPhase::Active,
        });
        Ok(key)
    }

    fn retire_terminal(
        &mut self,
        key: ReclaimableDomainKey,
        domain: AllocationDomain,
    ) -> Result<(), ReclaimableDomainError> {
        let record = self.record_exact(key, domain)?;
        if record.phase != ReclaimableDomainPhase::TerminalReady {
            return Err(ReclaimableDomainError::NotActive);
        }
        self.records[key.slot as usize] = None;
        Ok(())
    }

    fn active_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.is_some())
            .count()
    }
}

struct Sched {
    tasks: BTreeMap<TaskId, Task>,
    ready: RunQueues<TaskId>,
    reclaimable_domains: ReclaimableDomains,
    /// Each hart owns one independently polled task. A task is lifted out of
    /// `tasks` while its future is executing, so lifecycle and wake paths must
    /// inspect all hart slots before treating an id as inactive.
    harts: [HartRunState; MAX_HARTS],
    completed: u64,
    faulted: u64,
    cancelled: u64,
}

struct HartRunState {
    running: Option<RunningTask>,
    /// Set when this hart's running task is woken while it is being polled —
    /// by itself (`yield_now`) or by an interrupt that lands mid-poll.
    woken: bool,
}

impl HartRunState {
    const fn new() -> Self {
        Self {
            running: None,
            woken: false,
        }
    }
}

struct RunningTask {
    id: TaskId,
    hart: HartId,
    domain: AllocationDomain,
    name: Arc<str>,
    status: Arc<TaskStatus>,
    reclaimable_domain: Option<ReclaimableDomainKey>,
    instance_token: Option<InstanceToken>,
}

#[derive(Clone, Copy)]
struct ReclaimableTeardownPermit {
    key: ReclaimableDomainKey,
    domain: AllocationDomain,
    home_hart: HartId,
    live_tasks: usize,
    exclusive: bool,
    primary_task: TaskId,
    primary_status: usize,
    instance_token: Option<InstanceToken>,
}

impl ReclaimableTeardownPermit {
    fn fault_witness(self) -> ReclaimableFaultWitness {
        let current_hart = require_current_scheduler_hart("reclaimable fault teardown");
        assert_eq!(
            current_hart, self.home_hart,
            "reclaimable fault teardown escaped its proven home hart"
        );
        ReclaimableFaultWitness {
            instance: self.instance_token,
            scheduler: ReclaimableSchedulerIdentity(self.key),
            task: self.primary_task,
            domain: self.domain,
            home_hart: self.home_hart,
            current_hart,
            status_identity: self.primary_status,
        }
    }
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    tasks: BTreeMap::new(),
    ready: RunQueues::new(),
    reclaimable_domains: ReclaimableDomains::new(),
    harts: [const { HartRunState::new() }; MAX_HARTS],
    completed: 0,
    faulted: 0,
    cancelled: 0,
});

impl Sched {
    fn running_count(&self) -> usize {
        self.harts
            .iter()
            .filter(|hart| hart.running.is_some())
            .count()
    }

    fn running_tasks(&self) -> impl Iterator<Item = &RunningTask> {
        self.harts.iter().filter_map(|hart| hart.running.as_ref())
    }

    fn running_hart_for(&self, id: TaskId) -> Option<HartId> {
        self.harts.iter().enumerate().find_map(|(index, state)| {
            state
                .running
                .as_ref()
                .is_some_and(|running| running.id == id)
                .then(|| HartId::new(index).expect("scheduler hart index is valid"))
        })
    }

    fn install_running(&mut self, hart: HartId, running: RunningTask) {
        let index = hart.index();
        debug_assert!(
            self.harts[index].running.is_none() && !self.harts[index].woken,
            "dispatch requires an idle hart slot"
        );
        self.harts[index].running = Some(running);
    }

    fn clear_running(&mut self, hart: HartId) {
        let index = hart.index();
        debug_assert!(self.harts[index].running.is_some());
        self.harts[index].running = None;
    }

    /// Close dispatch and spawn admission for one exact tracked domain.
    ///
    /// The primary task is either the exact running slot named by
    /// `running_status`, or has already been detached by guarded Drop. It
    /// remains counted in `live_tasks`. All tuple checks happen before the
    /// phase/running-slot mutation. Once TearingDown is published under SCHED,
    /// no same-domain task may become runnable or be newly admitted.
    fn begin_reclaimable_teardown(
        &mut self,
        domain: AllocationDomain,
        key: ReclaimableDomainKey,
        home_hart: HartId,
        primary_task: TaskId,
        primary_status: &Arc<TaskStatus>,
        primary_instance: Option<InstanceToken>,
        primary_running: bool,
    ) -> Result<ReclaimableTeardownPermit, ReclaimableDomainError> {
        let record = self.reclaimable_domains.record_exact(key, domain)?;
        let index = key.slot as usize;
        if record.phase != ReclaimableDomainPhase::Active {
            return Err(ReclaimableDomainError::NotActive);
        }
        if record.home_hart != home_hart {
            return Err(ReclaimableDomainError::WrongHome);
        }
        if record.exclusive && record.exclusive_task != Some(primary_task) {
            return Err(ReclaimableDomainError::TaskMismatch);
        }
        let primary_status_identity = Arc::as_ptr(primary_status) as usize;
        if record.exclusive && record.exclusive_status != Some(primary_status_identity) {
            return Err(ReclaimableDomainError::StatusMismatch);
        }
        if record.exclusive && record.exclusive_instance != primary_instance {
            return Err(ReclaimableDomainError::InstanceMismatch);
        }
        if self
            .running_tasks()
            .any(|running| running.domain == domain && running.hart != home_hart)
        {
            return Err(ReclaimableDomainError::RemoteRunning);
        }
        if self
            .tasks
            .values()
            .any(|task| task.domain == domain && task.queue_owner != home_hart)
        {
            return Err(ReclaimableDomainError::WrongHome);
        }
        if primary_running {
            if !self.harts[home_hart.index()]
                .running
                .as_ref()
                .is_some_and(|running| {
                    running.id == primary_task
                        && running.hart == home_hart
                        && running.domain == domain
                        && Arc::ptr_eq(&running.status, primary_status)
                        && running.instance_token == record.exclusive_instance
                })
            {
                return Err(ReclaimableDomainError::LiveTaskMismatch);
            }
        } else if self.running_tasks().any(|running| running.domain == domain) {
            return Err(ReclaimableDomainError::LiveTaskMismatch);
        }
        let mapped_siblings = self
            .tasks
            .values()
            .filter(|task| task.domain == domain)
            .count();
        let expected_live = mapped_siblings
            .checked_add(1)
            .ok_or(ReclaimableDomainError::LiveTaskOverflow)?;
        if expected_live != record.live_tasks {
            return Err(ReclaimableDomainError::LiveTaskMismatch);
        }

        // Validate the complete sibling set before changing any lifecycle
        // cell. Every mapped member is then committed to Faulted in this same
        // scheduler critical section, closing the cancel-before-detach race.
        for task in self.tasks.values().filter(|task| task.domain == domain) {
            if task.reclaimable_domain != Some(key) {
                return Err(ReclaimableDomainError::KeyMismatch);
            }
            if !task.is_published() || task.stealable {
                return Err(ReclaimableDomainError::LifecycleMismatch);
            }
            let raw = task.status.raw_state();
            if raw != TaskState::Running as u8 && raw != CANCEL_REQUESTED {
                return Err(ReclaimableDomainError::LifecycleMismatch);
            }
        }
        for task in self.tasks.values().filter(|task| task.domain == domain) {
            task.status
                .claim_terminal(TaskState::Faulted)
                .expect("validated arena sibling lost its fault claim under SCHED");
        }

        self.reclaimable_domains.records[index]
            .as_mut()
            .expect("validated tracked-domain record remains occupied")
            .phase = ReclaimableDomainPhase::TearingDown;
        if primary_running {
            self.clear_running(home_hart);
            self.harts[home_hart.index()].woken = false;
        }
        Ok(ReclaimableTeardownPermit {
            key,
            domain,
            home_hart,
            live_tasks: record.live_tasks,
            exclusive: record.exclusive,
            primary_task,
            primary_status: primary_status_identity,
            instance_token: record.exclusive_instance,
        })
    }

    fn verify_reclaimable_teardown(
        &self,
        permit: ReclaimableTeardownPermit,
    ) -> Result<(), ReclaimableDomainError> {
        let record = self
            .reclaimable_domains
            .record_exact(permit.key, permit.domain)?;
        if record.phase != ReclaimableDomainPhase::TearingDown {
            return Err(ReclaimableDomainError::NotActive);
        }
        if record.home_hart != permit.home_hart {
            return Err(ReclaimableDomainError::WrongHome);
        }
        if record.live_tasks != permit.live_tasks {
            return Err(ReclaimableDomainError::LiveTaskMismatch);
        }
        if record.exclusive && record.exclusive_task != Some(permit.primary_task) {
            return Err(ReclaimableDomainError::TaskMismatch);
        }
        if record.exclusive && record.exclusive_status != Some(permit.primary_status) {
            return Err(ReclaimableDomainError::StatusMismatch);
        }
        if record.exclusive && record.exclusive_instance != permit.instance_token {
            return Err(ReclaimableDomainError::InstanceMismatch);
        }
        if self.tasks.values().any(|task| task.domain == permit.domain)
            || self
                .running_tasks()
                .any(|running| running.domain == permit.domain)
        {
            return Err(ReclaimableDomainError::LiveTaskMismatch);
        }
        Ok(())
    }

    fn finish_reclaimable_teardown(
        &mut self,
        permit: ReclaimableTeardownPermit,
        outcome: FaultReclaimOutcome,
    ) -> Result<(), ReclaimableDomainError> {
        self.verify_reclaimable_teardown(permit)?;
        let record = self.reclaimable_domains.records[permit.key.slot as usize]
            .as_mut()
            .expect("verified teardown record remains occupied");
        record.phase = match outcome {
            FaultReclaimOutcome::Reclaimed => ReclaimableDomainPhase::TerminalReady,
            FaultReclaimOutcome::Quarantined => ReclaimableDomainPhase::Quarantined,
        };
        Ok(())
    }

    /// Account one exact task after guarded Drop completed normally. The last
    /// task closes spawn/dispatch admission before terminal publication; the
    /// retained record is removed only after observers can see the terminal
    /// state.
    fn finish_reclaimable_task(
        &mut self,
        key: ReclaimableDomainKey,
        domain: AllocationDomain,
        home_hart: HartId,
        task: TaskId,
        status: &Arc<TaskStatus>,
        instance_token: Option<InstanceToken>,
    ) -> Result<bool, ReclaimableDomainError> {
        let record = self.reclaimable_domains.record_exact(key, domain)?;
        if record.phase != ReclaimableDomainPhase::Active {
            return Err(ReclaimableDomainError::NotActive);
        }
        if record.home_hart != home_hart {
            return Err(ReclaimableDomainError::WrongHome);
        }
        if record.exclusive {
            if record.exclusive_task != Some(task) {
                return Err(ReclaimableDomainError::TaskMismatch);
            }
            if record.exclusive_status != Some(Arc::as_ptr(status) as usize) {
                return Err(ReclaimableDomainError::StatusMismatch);
            }
            if record.exclusive_instance != instance_token {
                return Err(ReclaimableDomainError::InstanceMismatch);
            }
            if record.live_tasks != 1 {
                return Err(ReclaimableDomainError::LiveTaskMismatch);
            }
        }
        let retained = self.reclaimable_domains.records[key.slot as usize]
            .as_mut()
            .expect("validated reclaimable-domain record remains occupied");
        if retained.live_tasks == 1 {
            retained.phase = ReclaimableDomainPhase::TerminalReady;
            Ok(true)
        } else {
            retained.live_tasks = retained
                .live_tasks
                .checked_sub(1)
                .ok_or(ReclaimableDomainError::LiveTaskMismatch)?;
            Ok(false)
        }
    }
}

/// Validate the queue/future ownership projection while `SCHED` is locked.
///
/// This intentionally allocates nothing: wake can call it from IRQ context,
/// and debug checking must not invalidate the ready queue's allocation-free
/// contract.  Lifecycle commits whose future has already been detached do not
/// appear in `Sched`; retained `TaskStatus` is their sole owner until publish.
#[cfg(debug_assertions)]
fn assert_sched_invariants(s: &Sched) {
    let live = s.tasks.len() + s.running_count();
    for index in 0..MAX_HARTS {
        let hart = HartId::new(index).expect("scheduler hart index is valid");
        debug_assert!(
            s.ready.capacity(hart) >= live,
            "hart {index} ready capacity {} is below live-task bound {live}",
            s.ready.capacity(hart)
        );
        debug_assert!(
            s.harts[index].running.is_some() || !s.harts[index].woken,
            "hart {index} is marked woken without a running task"
        );
    }

    for (owner, id, stealable) in s.ready.entries() {
        let task = s
            .tasks
            .get(&id)
            .expect("ready task is absent from the task map");
        debug_assert!(
            task.is_published() && task.ready && task.queue_owner == owner,
            "ready task {id} metadata disagrees with hart {}",
            owner.index()
        );
        debug_assert!(
            task.stealable == stealable,
            "ready task {id} steal policy disagrees with its queue entry"
        );
    }

    for (id, task) in &s.tasks {
        let raw = task.status.raw_state();
        debug_assert!(
            !task.domain.arena.is_tracked() || !task.stealable,
            "tracked task {id} must remain hart-affine"
        );
        let tracked_record = if task.domain.arena.is_tracked() {
            let key = task
                .reclaimable_domain
                .expect("tracked task has no scheduler domain key");
            let record = s
                .reclaimable_domains
                .record_exact(key, task.domain)
                .expect("tracked task has no scheduler domain record");
            debug_assert_eq!(
                record.home_hart, task.queue_owner,
                "tracked task {id} escaped its domain home hart"
            );
            Some(record)
        } else {
            None
        };
        debug_assert!(
            raw == TaskState::Running as u8
                || raw == CANCEL_REQUESTED
                || (raw == FAULT_COMMITTED
                    && tracked_record.is_some_and(|record| {
                        record.phase == ReclaimableDomainPhase::TearingDown
                    })),
            "mapped task {id} has detached lifecycle phase {raw}"
        );
        debug_assert_eq!(
            s.ready.owner(*id),
            task.ready.then_some(task.queue_owner),
            "task {id} queue metadata has a second or missing owner"
        );
        if matches!(
            task.publication,
            TaskPublication::Prepared(_) | TaskPublication::Staged(_)
        ) {
            debug_assert!(
                !task.ready,
                "unpublished task {id} acquired ready ownership"
            );
        }
        if raw == CANCEL_REQUESTED {
            debug_assert!(
                task.is_published() && task.ready,
                "cancel-requested mapped task {id} is not queued for its boundary"
            );
        }
        for running in s.running_tasks() {
            debug_assert_ne!(*id, running.id, "task {id} is mapped and running");
            debug_assert!(
                !Arc::ptr_eq(&task.status, &running.status),
                "two scheduler locations share one task status"
            );
        }
    }

    for (index, state) in s.harts.iter().enumerate() {
        let Some(running) = &state.running else {
            continue;
        };
        debug_assert_eq!(
            running.hart.index(),
            index,
            "running task {} is published in the wrong hart slot",
            running.id
        );
        debug_assert!(
            !s.ready.contains(running.id),
            "running task {} also has a ready entry",
            running.id
        );
        debug_assert!(
            !s.tasks.contains_key(&running.id),
            "running task {} also remains in the task map",
            running.id
        );
        let raw = running.status.raw_state();
        debug_assert!(
            raw == TaskState::Running as u8 || raw == CANCEL_REQUESTED,
            "running task {} has invalid lifecycle phase {raw}",
            running.id
        );
        if running.domain.arena.is_tracked() {
            let key = running
                .reclaimable_domain
                .expect("running tracked task has no scheduler domain key");
            let record = s
                .reclaimable_domains
                .record_exact(key, running.domain)
                .expect("running tracked task has no scheduler domain record");
            debug_assert_eq!(
                record.home_hart, running.hart,
                "running tracked task {} escaped its domain home hart",
                running.id
            );
            debug_assert_eq!(
                record.phase,
                ReclaimableDomainPhase::Active,
                "a tearing-down domain remained runnable"
            );
        }
        for other in s
            .harts
            .iter()
            .skip(index + 1)
            .filter_map(|hart| hart.running.as_ref())
        {
            debug_assert_ne!(
                running.id, other.id,
                "task {} occupies two running slots",
                running.id
            );
            debug_assert!(
                !Arc::ptr_eq(&running.status, &other.status),
                "two running slots share task {} status",
                running.id
            );
        }
    }

    for record in s.reclaimable_domains.records.iter().flatten() {
        let mapped = s
            .tasks
            .values()
            .filter(|task| task.domain == record.domain)
            .count();
        let running = s
            .running_tasks()
            .filter(|task| task.domain == record.domain)
            .count();
        debug_assert!(
            mapped + running <= record.live_tasks,
            "tracked-domain scheduler projection exceeds its live task count"
        );
        debug_assert!(record.live_tasks != 0);
        if record.exclusive {
            debug_assert_eq!(record.live_tasks, 1);
        }
    }
}

#[cfg(debug_assertions)]
fn assert_status_detached(s: &Sched, status: &TaskStatus) {
    debug_assert!(
        !s.tasks
            .values()
            .any(|task| core::ptr::eq(task.status.as_ref(), status)),
        "a committed/published status still owns a mapped future"
    );
    debug_assert!(
        !s.running_tasks()
            .any(|running| core::ptr::eq(running.status.as_ref(), status)),
        "a committed/published status still owns the running future"
    );
}

#[cfg(debug_assertions)]
fn assert_arena_detached(s: &Sched, domain: AllocationDomain) {
    debug_assert!(domain.arena.is_tracked());
    debug_assert!(
        s.tasks.values().all(|task| task.domain != domain),
        "fault teardown left an arena sibling in the task map"
    );
    debug_assert!(
        !s.running_tasks().any(|running| running.domain == domain),
        "fault teardown left its arena in a running slot"
    );
}

#[cfg(debug_assertions)]
fn assert_active_poll(id: TaskId, domain: AllocationDomain, status: &Arc<TaskStatus>) {
    debug_assert_eq!(
        heap::current_domain(),
        domain,
        "poll is executing under the wrong allocation domain"
    );
    {
        let hart = require_current_scheduler_hart("active poll validation");
        let current = CURRENT_TASK_STATUS[hart.index()].lock();
        debug_assert!(
            current
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, status)),
            "poll status is not installed as the active task"
        );
    }
    let s = SCHED.lock();
    assert_sched_invariants(&s);
    let hart = require_current_scheduler_hart("active poll validation");
    debug_assert!(
        s.harts[hart.index()]
            .running
            .as_ref()
            .is_some_and(|running| {
                running.id == id && running.domain == domain && Arc::ptr_eq(&running.status, status)
            }),
        "active poll does not match the scheduler running slot"
    );
}

// In release builds each invocation, including its argument expressions,
// disappears at cfg expansion time.
macro_rules! check_sched {
    ($sched:expr) => {
        #[cfg(debug_assertions)]
        assert_sched_invariants($sched)
    };
}

macro_rules! check_status_detached {
    ($sched:expr, $status:expr) => {
        #[cfg(debug_assertions)]
        assert_status_detached($sched, $status)
    };
}

macro_rules! check_arena_detached {
    ($sched:expr, $domain:expr) => {
        #[cfg(debug_assertions)]
        assert_arena_detached($sched, $domain)
    };
}

macro_rules! check_active_poll {
    ($id:expr, $domain:expr, $status:expr) => {
        #[cfg(debug_assertions)]
        assert_active_poll($id, $domain, $status)
    };
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PREPARED_BATCH: AtomicU64 = AtomicU64::new(1);

fn next_task_id() -> TaskId {
    let id = NEXT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("TaskId space exhausted");
    TaskId(id)
}

fn next_prepared_batch_id() -> u64 {
    NEXT_PREPARED_BATCH
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("prepared task batch identity space exhausted")
}

fn current_queue_hart() -> HartId {
    let hart = require_current_scheduler_hart("task placement");
    let status = CURRENT_TASK_STATUS[hart.index()].lock().clone();
    let Some(status) = status else {
        return hart;
    };
    SCHED.lock().harts[hart.index()]
        .running
        .as_ref()
        .filter(|running| Arc::ptr_eq(&running.status, &status))
        .map_or(hart, |running| running.hart)
}

/// Spawn a future as a task. Safe to call from inside another task.
pub fn spawn(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskId {
    spawn_tracked(name, fut).id()
}

/// Spawn an untracked task into one explicit logical hart queue. This is the
/// M5.1 placement primitive; tracked raw-reclaim arenas remain hart-affine and
/// are intentionally admitted only through the current-hart API below.
pub fn spawn_on(
    hart: HartId,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskId {
    spawn_tracked_on(hart, name, fut).id()
}

/// Spawn a future and inherit the allocation owner active at the call site.
pub fn spawn_tracked(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskHandle {
    let domain = heap::current_domain();
    spawn_tracked_domain(
        domain,
        current_queue_hart(),
        !domain.arena.is_tracked(),
        name,
        fut,
    )
}

/// Tracked lifecycle handle with explicit logical ready-queue placement. Safe
/// callers can only carry an untracked allocation domain here, so the task is
/// eligible for stealing.
pub fn spawn_tracked_on(
    hart: HartId,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    let domain = heap::current_domain();
    assert!(
        !domain.arena.is_tracked(),
        "explicit remote placement cannot move a raw-reclaimable arena"
    );
    spawn_tracked_domain(domain, hart, true, name, fut)
}

/// Spawn an untracked task that may run only on one logical hart.
///
/// Ordinary tasks remain stealable through [`spawn_tracked_on`]. This narrower
/// primitive is for work whose acceptance contract or machine-local state
/// requires a stable hart. Raw-reclaimable component arenas continue to use
/// [`spawn_reclaimable_owned`] so their stronger teardown contract is not
/// confused with scheduling affinity.
pub fn spawn_pinned_on(
    hart: HartId,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    let domain = heap::current_domain();
    assert!(
        !domain.arena.is_tracked(),
        "explicit remote placement cannot move a raw-reclaimable arena"
    );
    spawn_tracked_domain(domain, hart, false, name, fut)
}

/// Spawn a future under an explicit component allocation owner.
///
/// The task envelope and scheduler collections are kernel infrastructure and
/// are therefore allocated to `SYSTEM`; only polling and destroying the future
/// run with `owner` installed.
pub fn spawn_tracked_owned(
    owner: OwnerId,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    spawn_tracked_domain(
        AllocationDomain::untracked(owner),
        current_queue_hart(),
        true,
        name,
        fut,
    )
}

/// Spawn an untracked owner-accounted task that remains on the current hart.
///
/// This is the component-facing counterpart of [`spawn_pinned_on`]. It is
/// used for machine-local control tasks such as the UART shell, whose command
/// execution must stay on the physical hart that owns external interrupts.
pub fn spawn_pinned_owned(
    owner: OwnerId,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    spawn_tracked_domain(
        AllocationDomain::untracked(owner),
        current_queue_hart(),
        false,
        name,
        fut,
    )
}

/// Spawn into an audited, raw-reclaimable allocation arena.
///
/// # Safety
/// Every allocation left in `domain.arena` at a task fault must be local to
/// that arena. No pointer, owning smart pointer, borrowed reference, or payload
/// backed by one of those allocations may escape to another arena or SYSTEM
/// storage. Child tasks spawned with [`spawn`] inherit this same domain and are
/// torn down together if any member faults. Executor registries may only be
/// given the task waker supplied through this future's executor-owned
/// [`Context`], using executor primitives whose cleanup is non-panicking; the
/// future must not poll those primitives with a fabricated custom context.
/// Every wait/registration target must live in SYSTEM or supervisor-stable
/// storage for the entire domain teardown; arena-owned `WaitQueue` values may
/// not be shared with siblings because a faulting destructor may already have
/// destroyed such a target before sibling ledgers are drained.
/// `domain.arena` must already be active and registered to `domain.owner` for
/// the complete lifetime of this task incarnation.
pub unsafe fn spawn_reclaimable_owned(
    domain: AllocationDomain,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    assert!(
        domain.arena.is_tracked(),
        "a reclaimable task needs a tracked arena"
    );
    assert!(
        domain.owner != OwnerId::SYSTEM,
        "SYSTEM cannot be a raw-reclaimable component arena"
    );
    assert!(
        load_fault_reclaimer().is_some(),
        "a reclaimable task needs an installed fault reclaimer"
    );
    spawn_tracked_domain(domain, current_queue_hart(), false, name, fut)
}

/// Host-model helper that immediately spawns the sole task permitted to
/// execute in one audited allocation arena.
///
/// The executor records a stable home hart and rejects every sibling before it
/// can become runnable. Target managed components must instead use the prepared
/// registry publication path: an immediately runnable future cannot be bound
/// to its SYSTEM lifecycle record first. Keeping this helper off target builds
/// prevents it from becoming an accidental production admission boundary.
///
/// # Safety
///
/// The escape, registration, and active-arena requirements of
/// [`spawn_reclaimable_owned`] apply. In addition, the caller must not race two
/// first publications for the same arena. The future and its Drop path must
/// not attempt to spawn a child in the same domain; that is a fail-stop
/// contract violation.
#[cfg(not(target_arch = "riscv64"))]
pub unsafe fn spawn_exclusive_reclaimable_owned(
    domain: AllocationDomain,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    assert!(
        domain.arena.is_tracked(),
        "an exclusive reclaimable task needs a tracked arena"
    );
    assert!(
        domain.owner != OwnerId::SYSTEM,
        "SYSTEM cannot be a raw-reclaimable component arena"
    );
    assert!(
        load_fault_reclaimer().is_some(),
        "an exclusive reclaimable task needs an installed fault reclaimer"
    );
    spawn_tracked_domain_mode(
        domain,
        current_queue_hart(),
        false,
        ReclaimableDomainMode::Exclusive,
        name,
        fut,
    )
}

/// One future whose task envelope and lifecycle identity have been allocated,
/// but which is not yet visible to ready queues, wakes, cancellation, task
/// reports, or queue-owner lookup. Prepared tasks can only become runnable by
/// publishing their complete batch through [`PreparedTaskBatch::publish`].
pub struct PreparedTask {
    id: TaskId,
    queue_owner: HartId,
    exclusive_reclaimable: bool,
    task: Option<Task>,
}

impl PreparedTask {
    pub const fn id(&self) -> TaskId {
        self.id
    }

    pub const fn is_exclusive_reclaimable(&self) -> bool {
        self.exclusive_reclaimable
    }
}

/// Exact executor identity presented to the SYSTEM-owned instance registry
/// before one prepared raw-reclaimable task can become runnable.
///
/// The status seal is deliberately private: callers can compare this value to
/// the exact [`TaskHandle`] minted by the same preparation, but cannot assemble
/// a replacement binding from a recycled TaskId or allocation domain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreparedReclaimableBinding {
    batch: u64,
    task: TaskId,
    domain: AllocationDomain,
    home_hart: HartId,
    status_identity: usize,
    instance: Option<InstanceToken>,
    scheduler: Option<ReclaimableSchedulerIdentity>,
}

impl PreparedReclaimableBinding {
    pub const fn task_id(self) -> TaskId {
        self.task
    }

    pub const fn allocation_domain(self) -> AllocationDomain {
        self.domain
    }

    pub const fn home_hart(self) -> HartId {
        self.home_hart
    }

    pub const fn instance_token(self) -> Option<InstanceToken> {
        self.instance
    }

    /// The scheduler identity is absent while the candidate is merely bound
    /// and becomes present only in the activation callback, after the complete
    /// fixed domain-table transaction has been staged under `SCHED`.
    pub const fn scheduler_identity(self) -> Option<ReclaimableSchedulerIdentity> {
        self.scheduler
    }

    /// Compare the executor-forged preparation seal while deliberately
    /// ignoring the scheduler generation, which does not exist until the
    /// later all-or-none activation transaction.
    pub fn matches_prepared_identity(self, other: Self) -> bool {
        self.batch == other.batch
            && self.task == other.task
            && self.domain == other.domain
            && self.home_hart == other.home_hart
            && self.status_identity == other.status_identity
            && self.instance == other.instance
    }

    /// Check the complete executor identity, including the exact TaskStatus
    /// object rather than only its externally visible TaskId and domain.
    pub fn matches_handle(self, handle: &TaskHandle) -> bool {
        self.task == handle.id
            && self.domain == handle.domain
            && self.status_identity == Arc::as_ptr(&handle.status) as usize
    }
}

impl fmt::Debug for PreparedReclaimableBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedReclaimableBinding")
            .field("batch", &self.batch)
            .field("task", &self.task)
            .field("domain", &self.domain)
            .field("home_hart", &self.home_hart)
            .field("status_identity", &"<redacted>")
            .field("managed_instance", &self.instance.is_some())
            .field("scheduler_identity", &self.scheduler)
            .finish()
    }
}

/// Result of the panic-free SYSTEM registry activation transaction executed at
/// the prepared scheduler publication boundary.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedReclaimableActivation {
    Activated,
    /// Every involved stable registry entry is already sticky-quarantined.
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedTaskBatchError {
    Empty,
    AlreadyPublished,
    /// A raw-reclaimable candidate may only use the registry-aware publication
    /// entry point.
    ExclusiveBindingRequired,
    /// The registry rejected the exact prepared identity. This state is sticky
    /// and the tracked futures will be abandoned without running Drop.
    ExclusiveBindingRejected,
    DuplicateReclaimableArena,
    ReclaimableDomainMismatch,
    ReclaimableWrongHome,
    ReclaimableDomainUnavailable,
    ReclaimableCapacity,
    Capacity,
}

impl PreparedTaskBatchError {
    /// Whether a caller that already bound stable instance records must leave
    /// them quarantined and abandon every tracked candidate. Pure capacity and
    /// API-order errors do not claim an identity mismatch.
    pub const fn requires_registry_quarantine(self) -> bool {
        matches!(
            self,
            Self::ExclusiveBindingRejected
                | Self::DuplicateReclaimableArena
                | Self::ReclaimableDomainMismatch
                | Self::ReclaimableWrongHome
                | Self::ReclaimableDomainUnavailable
        )
    }
}

/// A bounded collection of task envelopes held entirely outside the global
/// scheduler until [`publish`](Self::publish). If the preparing task faults,
/// these candidates may be conservatively leaked with that task, but no hidden
/// scheduler node, wake target, or partial pipeline is left behind.
pub struct PreparedTaskBatch {
    id: u64,
    tasks: Vec<PreparedTask>,
    handles: Vec<TaskHandle>,
    reclaimable_bindings: Vec<PreparedReclaimableBinding>,
    published: bool,
    staged: bool,
    binding_rejected: bool,
    publication: Arc<AtomicBool>,
}

impl PreparedTaskBatch {
    pub fn new() -> Self {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let publication = Arc::new(AtomicBool::new(false));
        system.restore();
        Self {
            id: next_prepared_batch_id(),
            tasks: Vec::new(),
            handles: Vec::new(),
            reclaimable_bindings: Vec::new(),
            published: false,
            staged: false,
            binding_rejected: false,
            publication,
        }
    }

    pub fn try_reserve(
        &mut self,
        additional: usize,
    ) -> Result<(), alloc::collections::TryReserveError> {
        assert!(
            !self.published && !self.binding_rejected,
            "a closed task batch is immutable"
        );
        self.tasks.try_reserve_exact(additional)?;
        self.handles.try_reserve_exact(additional)?;
        self.reclaimable_bindings.try_reserve_exact(additional)
    }

    /// Borrow opaque, non-owning lifecycle tokens for the candidates already
    /// prepared in this batch. Before publication these handles expose only
    /// identity/domain data and `is_published == false`; state, polls, joins,
    /// and cancellation remain unavailable. The batch retains every future
    /// and is the only object that can publish or roll it back.
    pub fn prepared_handles(&self) -> &[TaskHandle] {
        &self.handles
    }

    /// Reserve a small, fixed number of outbound cleanup-ledger entries for
    /// one still-hidden prepared task.
    ///
    /// This is the batch-local counterpart of
    /// [`try_reserve_current_task_registrations`]. It is used when a SYSTEM
    /// supervisor will await a fixed lifecycle edge rather than retain an
    /// owning [`TaskHandle::join`] future. The narrow bound prevents this from
    /// becoming a caller-sized SYSTEM allocation surface.
    pub fn try_reserve_prepared_task_registrations(
        &mut self,
        task_index: usize,
        additional: usize,
    ) -> bool {
        const MAX_PREPARED_REGISTRATION_RESERVE: usize = 2;
        if self.published
            || self.binding_rejected
            || task_index >= self.handles.len()
            || additional == 0
            || additional > MAX_PREPARED_REGISTRATION_RESERVE
        {
            return false;
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let reserved = self.handles[task_index]
            .status
            .registrations
            .lock()
            .try_reserve_exact(additional)
            .is_ok();
        system.restore();
        reserved
    }

    /// Install a detach callback directly on one still-hidden prepared task.
    ///
    /// This closes the publication-to-first-poll window for a SYSTEM
    /// supervisor: the callback is already part of its `TaskStatus` ledger
    /// before any raw-reclaimable child in the batch becomes runnable.  The
    /// future captures the same copy-only `target` and removes it with
    /// [`disarm_current_task_detach`] only after its stable lifecycle commit.
    /// Callers that also await a fixed SYSTEM edge install this entry first and
    /// then reserve one additional outbound slot with
    /// [`Self::try_reserve_prepared_task_registrations`].
    pub fn install_prepared_task_detach(
        &mut self,
        task_index: usize,
        target: TaskDetachTarget,
    ) -> bool {
        if self.published || self.binding_rejected || task_index >= self.handles.len() {
            return false;
        }

        let handle = &self.handles[task_index];
        let task = handle.id;
        let domain = handle.domain;
        let status = &handle.status;
        let token = status
            .next_registration
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("task registration token space exhausted");
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let installed = {
            let mut registrations = status.registrations.lock();
            let duplicate = registrations.iter().any(|entry| {
                matches!(
                    entry.registration,
                    OwnedRegistration::TaskDetach {
                        target: registered,
                        task: registered_task,
                        domain: registered_domain,
                    } if registered.matches(target)
                        && registered_task == task
                        && registered_domain == domain
                )
            });
            if duplicate || registrations.try_reserve_exact(1).is_err() {
                false
            } else {
                registrations.push(OwnedRegistrationEntry {
                    token,
                    registration: OwnedRegistration::TaskDetach {
                        target,
                        task,
                        domain,
                    },
                });
                true
            }
        };
        system.restore();
        installed
    }

    /// Exact, non-owning executor identities for the raw-reclaimable members
    /// of this batch. A SYSTEM registry binds these to its reserved stable
    /// slots before calling `publish_exclusive_reclaimable_with`.
    pub fn prepared_reclaimable_bindings(&self) -> &[PreparedReclaimableBinding] {
        &self.reclaimable_bindings
    }

    pub fn prepare(
        &mut self,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        assert!(
            !self.published && !self.binding_rejected,
            "a closed task batch is immutable"
        );
        let domain = heap::current_domain();
        assert!(
            !domain.arena.is_tracked(),
            "safe prepared tasks cannot enter a raw-reclaimable arena"
        );
        self.prepare_domain(domain, current_queue_hart(), true, false, None, name, fut)
    }

    /// Prepare one hart-affine task whose future allocation belongs to an
    /// audited raw-reclaimable arena. The task stays absent from every global
    /// scheduler projection until the exact binding above has been accepted by
    /// the SYSTEM instance registry during special publication.
    ///
    /// # Safety
    ///
    /// `domain` must name a live, exclusively reserved component incarnation.
    /// The future and everything it captures must remain inside that arena or
    /// in stable SYSTEM objects represented only by opaque non-owning tokens.
    /// The caller must bind the returned task identity to exactly one stable
    /// registry slot before special publication. Dropping an unpublished batch
    /// deliberately leaks this future; no Rust destructor is run in the raw
    /// arena and this function never authorizes reset or reclamation.
    pub unsafe fn prepare_exclusive_reclaimable_owned(
        &mut self,
        domain: AllocationDomain,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        assert!(
            !self.published && !self.binding_rejected,
            "a closed task batch is immutable"
        );
        assert!(
            domain.arena.is_tracked(),
            "an exclusive prepared task needs a tracked arena"
        );
        assert!(
            domain.owner != OwnerId::SYSTEM,
            "SYSTEM cannot be a raw-reclaimable component arena"
        );
        assert!(
            load_fault_reclaimer().is_some(),
            "an exclusive prepared task needs an installed fault reclaimer"
        );
        self.prepare_domain(domain, current_queue_hart(), false, true, None, name, fut)
    }

    /// Prepare the sole executor future for one SYSTEM-registry-managed
    /// component instance.  The opaque token is copied into scheduler-owned
    /// metadata and into every later fault witness; the future may capture the
    /// same non-owning token, but no registry-owned CSpace or task handle.
    ///
    /// # Safety
    ///
    /// The raw-arena and bind-before-publication requirements of
    /// [`Self::prepare_exclusive_reclaimable_owned`] apply. `instance` must be
    /// a live reservation for exactly `domain`, and the caller must use the
    /// managed binding/activation path before publication.
    pub unsafe fn prepare_managed_instance_owned(
        &mut self,
        instance: InstanceToken,
        domain: AllocationDomain,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        assert!(
            !self.published && !self.binding_rejected,
            "a closed task batch is immutable"
        );
        assert!(
            domain.arena.is_tracked(),
            "a managed instance task needs a tracked arena"
        );
        assert!(
            domain.owner != OwnerId::SYSTEM,
            "SYSTEM cannot be a raw-reclaimable component arena"
        );
        assert!(
            load_fault_reclaimer().is_some(),
            "a managed instance task needs an installed fault reclaimer"
        );
        self.prepare_domain(
            domain,
            current_queue_hart(),
            false,
            true,
            Some(instance),
            name,
            fut,
        )
    }

    fn prepare_domain(
        &mut self,
        domain: AllocationDomain,
        queue_owner: HartId,
        stealable: bool,
        exclusive_reclaimable: bool,
        instance_token: Option<InstanceToken>,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        self.tasks
            .try_reserve_exact(1)
            .unwrap_or_else(|_| panic!("prepared task metadata allocation failed"));
        self.handles
            .try_reserve_exact(1)
            .unwrap_or_else(|_| panic!("prepared task handle allocation failed"));
        if exclusive_reclaimable {
            self.reclaimable_bindings
                .try_reserve_exact(1)
                .unwrap_or_else(|_| panic!("prepared task binding allocation failed"));
        }
        let (mut task, handle) = make_task(
            domain,
            queue_owner,
            stealable,
            name,
            fut,
            self.publication.clone(),
            instance_token,
        );
        task.publication = TaskPublication::Prepared(self.id);
        let id = task.id;

        if exclusive_reclaimable {
            self.reclaimable_bindings.push(PreparedReclaimableBinding {
                batch: self.id,
                task: id,
                domain,
                home_hart: queue_owner,
                status_identity: Arc::as_ptr(&handle.status) as usize,
                instance: instance_token,
                scheduler: None,
            });
        }

        self.tasks.push(PreparedTask {
            id,
            queue_owner,
            exclusive_reclaimable,
            task: Some(task),
        });
        self.handles.push(handle);
        self.tasks.last().expect("the prepared task was appended")
    }

    /// Publish every member under one scheduler lock. Recoverable ready-queue
    /// capacity is reserved before mutation. BTreeMap nodes are then allocated
    /// only under SYSTEM ownership; target global OOM is fail-stop, so it can
    /// never return through a component landing pad after partial mutation.
    /// Returned handles have the same order as the preceding `prepare` calls.
    pub fn publish(&mut self) -> Result<Vec<TaskHandle>, PreparedTaskBatchError> {
        if self.published {
            return Err(PreparedTaskBatchError::AlreadyPublished);
        }
        if self.binding_rejected {
            return Err(PreparedTaskBatchError::ExclusiveBindingRejected);
        }
        if self.tasks.is_empty() {
            return Err(PreparedTaskBatchError::Empty);
        }
        if !self.reclaimable_bindings.is_empty() {
            return Err(PreparedTaskBatchError::ExclusiveBindingRequired);
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut s = SCHED.lock();
        let live_after_publish = s
            .tasks
            .len()
            .checked_add(s.running_count())
            .and_then(|live| live.checked_add(self.tasks.len()))
            .expect("live task count overflow");
        if s.ready.reserve_live_bound(live_after_publish).is_err() {
            drop(s);
            system.restore();
            return Err(PreparedTaskBatchError::Capacity);
        }

        // Validate every local candidate before the first scheduler mutation.
        for prepared in &self.tasks {
            let task = prepared
                .task
                .as_ref()
                .expect("unpublished batch retains every candidate");
            assert_eq!(task.publication, TaskPublication::Prepared(self.id));
            assert!(!task.ready);
            assert!(!s.tasks.contains_key(&prepared.id));
            assert!(!s.ready.contains(prepared.id));
        }

        // Install every still-hidden map node before any task becomes ready.
        // BTreeMap node allocation is charged to SYSTEM. Target global OOM is
        // a machine fail-stop in the kernel allocator, never a component
        // longjmp that could continue after a partially installed batch.
        for prepared in &mut self.tasks {
            let task = prepared
                .task
                .take()
                .expect("validated candidate remains batch-local");
            assert!(
                s.tasks.insert(prepared.id, task).is_none(),
                "fresh TaskId collided during batch publication"
            );
        }

        // Linearization point. Every future, map node, handle, and ready slot
        // now exists; this loop performs only fixed scheduler mutations.
        for prepared in &self.tasks {
            let (owner, stealable) = {
                let task = s
                    .tasks
                    .get_mut(&prepared.id)
                    .expect("validated prepared task remains installed");
                task.publication = TaskPublication::Published;
                task.ready = true;
                (task.queue_owner, task.stealable)
            };
            s.ready
                .enqueue(owner, prepared.id, stealable)
                .expect("prepared task has unique reserved queue capacity");
        }
        // One shared release flag makes every pre-registered handle visible at
        // the same linearization point after the complete batch is runnable.
        self.publication.store(true, Ordering::Release);
        // Publication is irreversible before any notification hook can run.
        // A target IPI failure or test-hook panic must never make Drop treat
        // already-runnable tasks as unpublished rollback candidates.
        self.published = true;
        check_sched!(&s);
        drop(s);
        system.restore();
        for prepared in &self.tasks {
            notify_ready_hart(prepared.queue_owner);
        }
        Ok(core::mem::take(&mut self.handles))
    }

    /// Stage a mixed batch containing one or more exclusive raw-reclaimable
    /// tasks after a SYSTEM-owned registry has already bound their exact
    /// identities. Staging installs the scheduler/domain identities but keeps
    /// every future unpublished, not-ready, and impossible to poll.
    ///
    /// The executor first simulates every tracked admission in a private copy
    /// of its fixed domain table, reserves all queues, and constructs a private
    /// BTree node set. It then calls `activate` while holding `SCHED`, but before
    /// changing any global scheduler projection. Only an accepted, complete
    /// registry transaction is followed only by the map/domain commit. The
    /// caller may then commit an independent fixed lifecycle record without
    /// holding SCHED, before invoking the returned stage's allocation-free
    /// ready publication. The map merge remains SYSTEM-charged; a
    /// target allocation failure takes the kernel's explicit fatal allocator
    /// path and cannot return through a component landing pad.
    ///
    /// # Safety
    ///
    /// `activate` must validate every supplied binding against already-bound
    /// stable registry records and atomically transition the complete set to
    /// its active phase. It must not allocate, block, panic, acquire a CSpace or
    /// heap lock, or call any executor operation; its only permitted lock order
    /// is `SCHED -> registry`. On
    /// [`PreparedReclaimableActivation::Quarantined`], it must leave every
    /// involved record sticky-quarantined. It must never reset or reclaim an
    /// arena. Code that holds the registry lock must never call this method.
    pub unsafe fn stage_exclusive_reclaimable_with(
        &mut self,
        activate: impl FnOnce(&[PreparedReclaimableBinding]) -> PreparedReclaimableActivation,
    ) -> Result<PreparedReclaimableStage<'_>, PreparedTaskBatchError> {
        if self.published {
            return Err(PreparedTaskBatchError::AlreadyPublished);
        }
        if self.binding_rejected {
            return Err(PreparedTaskBatchError::ExclusiveBindingRejected);
        }
        if self.tasks.is_empty() {
            return Err(PreparedTaskBatchError::Empty);
        }
        if self.reclaimable_bindings.is_empty() {
            return Err(PreparedTaskBatchError::ExclusiveBindingRequired);
        }

        // Reject aliases before entering the scheduler or invoking registry
        // code. Equality by ArenaId is deliberate: a wrong OwnerId must not
        // turn the same raw allocation incarnation into a second domain.
        for (index, binding) in self.reclaimable_bindings.iter().enumerate() {
            for other in &self.reclaimable_bindings[index + 1..] {
                if binding.domain.arena != other.domain.arena {
                    continue;
                }
                self.binding_rejected = true;
                return Err(if binding.domain == other.domain {
                    PreparedTaskBatchError::DuplicateReclaimableArena
                } else {
                    PreparedTaskBatchError::ReclaimableDomainMismatch
                });
            }
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut s = SCHED.lock();

        // Validate all batch-local envelopes before planning any admission.
        for prepared in &self.tasks {
            let task = prepared
                .task
                .as_ref()
                .expect("unpublished batch retains every candidate");
            assert_eq!(task.publication, TaskPublication::Prepared(self.id));
            assert!(!task.ready);
            assert_eq!(
                task.domain.arena.is_tracked(),
                prepared.exclusive_reclaimable
            );
            assert_eq!(task.stealable, !prepared.exclusive_reclaimable);
            assert!(!s.tasks.contains_key(&prepared.id));
            assert!(!s.ready.contains(prepared.id));
        }

        // `staged` owns the complete generational admission plan. Failure of a
        // later member cannot leave an earlier domain record in global state.
        let mut staged = s.reclaimable_domains;
        for prepared in &self.tasks {
            if !prepared.exclusive_reclaimable {
                continue;
            }
            let task = prepared
                .task
                .as_ref()
                .expect("validated tracked candidate remains batch-local");
            if let Err(error) = staged.admit(
                task.domain,
                task.queue_owner,
                ReclaimableDomainMode::Exclusive,
                task.id,
                &task.status,
                task.instance_token,
            ) {
                let error = map_prepared_reclaimable_error(error);
                if error.requires_registry_quarantine() {
                    self.binding_rejected = true;
                }
                drop(s);
                system.restore();
                return Err(error);
            }
        }

        let live_after_publish = s
            .tasks
            .len()
            .checked_add(s.running_count())
            .and_then(|live| live.checked_add(self.tasks.len()))
            .expect("live task count overflow");
        if s.ready.reserve_live_bound(live_after_publish).is_err() {
            drop(s);
            system.restore();
            return Err(PreparedTaskBatchError::Capacity);
        }

        // The scheduler slot/generation exists only after the complete domain
        // table has staged successfully.  Seal it into the callback bindings
        // now; the registry's earlier bind compares the preparation identity
        // separately and records this additional non-forgeable incarnation at
        // activation.
        for binding in &mut self.reclaimable_bindings {
            let key = staged
                .record(binding.domain)
                .expect("staged exclusive binding has no scheduler record")
                .key;
            binding.scheduler = Some(ReclaimableSchedulerIdentity(key));
        }

        // Attach the opaque scheduler generation and build a private BTree
        // before registry activation. Appending into a nonempty global tree may
        // still split SYSTEM nodes; its only failure path is the target fatal
        // allocator handler. A callback panic on a host drops only this private
        // envelope map (whose futures are ManuallyDrop) and cannot strand a
        // hidden node or unmatched generation in global SCHED.
        let mut staged_tasks = BTreeMap::new();
        for prepared in &mut self.tasks {
            let mut task = prepared
                .task
                .take()
                .expect("validated candidate remains batch-local");
            if prepared.exclusive_reclaimable {
                task.reclaimable_domain = Some(
                    staged
                        .record(task.domain)
                        .expect("staged exclusive admission remains exact")
                        .key,
                );
            }
            assert!(
                staged_tasks.insert(prepared.id, task).is_none(),
                "fresh TaskId collided during exclusive batch staging"
            );
        }

        // Sticky-close before entering trusted registry code. On host unwind
        // the scheduler guard is released and tracked futures remain forgotten;
        // target callbacks are additionally required to be panic-free because
        // task fault landing pads use non-local return rather than Rust unwind.
        self.binding_rejected = true;
        if activate(&self.reclaimable_bindings) != PreparedReclaimableActivation::Activated {
            // Registry rejection is sticky, while global executor state was
            // never changed. Restore local envelopes without allocation so
            // Drop forgets tracked futures and normally reclaims safe ones.
            for prepared in &mut self.tasks {
                prepared.task = Some(
                    staged_tasks
                        .remove(&prepared.id)
                        .expect("rejected staged candidate remains private"),
                );
            }
            debug_assert!(staged_tasks.is_empty());
            check_sched!(&s);
            drop(s);
            system.restore();
            return Err(PreparedTaskBatchError::ExclusiveBindingRejected);
        }

        // No recoverable branch follows registry activation. BTreeMap::append
        // may split a nonempty SYSTEM tree; target SYSTEM OOM is an explicit
        // machine fail-stop, not a component fault. The SCHED lock keeps every
        // staged task absent from every ready queue. A dropped stage is a
        // deliberate stable leak: activated registry/domain state is never
        // guessed back into a prepublication rollback.
        s.tasks.append(&mut staged_tasks);
        debug_assert!(staged_tasks.is_empty());
        s.reclaimable_domains = staged;
        for prepared in &self.tasks {
            s.tasks
                .get_mut(&prepared.id)
                .expect("activated staged task remains installed")
                .publication = TaskPublication::Staged(self.id);
        }
        self.staged = true;
        check_sched!(&s);
        drop(s);
        system.restore();
        Ok(PreparedReclaimableStage { batch: self })
    }

    /// Preserve the original one-call API for callers which need no external
    /// lifecycle commit between registry activation and ready publication.
    pub unsafe fn publish_exclusive_reclaimable_with(
        &mut self,
        activate: impl FnOnce(&[PreparedReclaimableBinding]) -> PreparedReclaimableActivation,
    ) -> Result<Vec<TaskHandle>, PreparedTaskBatchError> {
        let stage = unsafe { self.stage_exclusive_reclaimable_with(activate) }?;
        Ok(stage.publish_ready_unconditional())
    }
}

/// Activated scheduler/domain staging which is still impossible to poll.
/// Every future has moved into SCHED, remains unpublished and not-ready, and
/// is explicitly excluded from `PreparedTaskBatch` rollback.
#[must_use = "an activated stage must be published ready or quarantined"]
pub struct PreparedReclaimableStage<'a> {
    batch: &'a mut PreparedTaskBatch,
}

impl PreparedReclaimableStage<'_> {
    /// Make the complete staged batch visible and ready in one fixed scheduler
    /// transaction. All map nodes and ready capacity were installed/reserved
    /// during staging; this method allocates nothing and invokes no caller code.
    fn publish_ready_unconditional(self) -> Vec<TaskHandle> {
        match self.publish_ready_inner(None) {
            Ok(handles) => handles,
            Err(_) => unreachable!("internal immediate publication has no external permit"),
        }
    }

    /// Publish only while one boot-static monotonic SYSTEM permit still has
    /// the expected value. The permit is sampled under SCHED before the first
    /// mutation; a fail-stop which linearized first leaves all tasks staged.
    ///
    /// # Safety
    ///
    /// `permit` must be boot-static SYSTEM state whose mismatch is monotonic
    /// for this stage's lifetime. It may not point into a task arena or be
    /// restored to `expected` after lifecycle rejection.
    pub unsafe fn publish_ready_if(
        self,
        permit: &'static AtomicU64,
        expected: u64,
    ) -> Result<Vec<TaskHandle>, Self> {
        self.publish_ready_inner(Some((permit, expected)))
    }

    fn publish_ready_inner(
        self,
        permit: Option<(&'static AtomicU64, u64)>,
    ) -> Result<Vec<TaskHandle>, Self> {
        if permit.is_some_and(|(permit, expected)| permit.load(Ordering::Acquire) != expected) {
            return Err(self);
        }
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut s = SCHED.lock();
        if permit.is_some_and(|(permit, expected)| permit.load(Ordering::Acquire) != expected) {
            drop(s);
            system.restore();
            return Err(self);
        }
        assert!(!self.batch.published);
        assert!(self.batch.staged);
        assert!(self.batch.binding_rejected);
        assert_eq!(self.batch.tasks.len(), self.batch.handles.len());
        for (prepared, handle) in self.batch.tasks.iter().zip(&self.batch.handles) {
            let task = s
                .tasks
                .get(&prepared.id)
                .expect("activated stage lost its scheduler task");
            assert_eq!(task.publication, TaskPublication::Staged(self.batch.id));
            assert!(!task.ready);
            assert_eq!(task.id, handle.id);
            assert_eq!(task.domain, handle.domain);
            assert!(Arc::ptr_eq(&task.status, &handle.status));
            assert!(!s.ready.contains(prepared.id));
            if prepared.exclusive_reclaimable {
                let binding = self
                    .batch
                    .reclaimable_bindings
                    .iter()
                    .find(|binding| binding.task == prepared.id)
                    .expect("staged tracked task lost its binding");
                let scheduler = binding
                    .scheduler
                    .expect("activated tracked binding has no scheduler generation");
                assert!(s
                    .reclaimable_domains
                    .validate_active_task(
                        scheduler.0,
                        task.domain,
                        task.queue_owner,
                        task.id,
                        &task.status,
                        task.instance_token,
                    )
                    .is_ok());
            }
        }
        for prepared in &self.batch.tasks {
            let (owner, stealable) = {
                let task = s
                    .tasks
                    .get_mut(&prepared.id)
                    .expect("validated staged task remains installed");
                task.publication = TaskPublication::Published;
                task.ready = true;
                (task.queue_owner, task.stealable)
            };
            s.ready
                .enqueue(owner, prepared.id, stealable)
                .expect("staging reserved exact ready capacity");
        }
        self.batch.publication.store(true, Ordering::Release);
        self.batch.published = true;
        self.batch.staged = false;
        self.batch.binding_rejected = false;
        check_sched!(&s);
        drop(s);
        system.restore();
        for prepared in &self.batch.tasks {
            notify_ready_hart(prepared.queue_owner);
        }
        Ok(core::mem::take(&mut self.batch.handles))
    }
}

fn map_prepared_reclaimable_error(error: ReclaimableDomainError) -> PreparedTaskBatchError {
    match error {
        ReclaimableDomainError::TableFull | ReclaimableDomainError::GenerationExhausted => {
            PreparedTaskBatchError::ReclaimableCapacity
        }
        ReclaimableDomainError::DomainMismatch => PreparedTaskBatchError::ReclaimableDomainMismatch,
        ReclaimableDomainError::WrongHome => PreparedTaskBatchError::ReclaimableWrongHome,
        ReclaimableDomainError::Missing
        | ReclaimableDomainError::NotActive
        | ReclaimableDomainError::Exclusive
        | ReclaimableDomainError::LiveTaskOverflow
        | ReclaimableDomainError::LiveTaskMismatch
        | ReclaimableDomainError::RemoteRunning
        | ReclaimableDomainError::KeyMismatch
        | ReclaimableDomainError::TaskMismatch
        | ReclaimableDomainError::StatusMismatch
        | ReclaimableDomainError::InstanceMismatch
        | ReclaimableDomainError::LifecycleMismatch => {
            PreparedTaskBatchError::ReclaimableDomainUnavailable
        }
    }
}

impl Default for PreparedTaskBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PreparedTaskBatch {
    fn drop(&mut self) {
        if self.published || self.staged {
            return;
        }
        for prepared in &mut self.tasks {
            if let Some(task) = prepared.task.take() {
                if prepared.exclusive_reclaimable {
                    abandon_task_without_drop(task);
                } else {
                    rollback_unpublished_task(task);
                }
            }
        }
    }
}

/// Reclaim a safe, unpublished future without ever entering raw arena
/// teardown. Prepared batches reject tracked domains at their public boundary;
/// if user Drop itself faults, retain the ordinary executor policy of leaking
/// its untracked allocation while still running exact-task cleanup once.
fn rollback_unpublished_task(task: Task) {
    debug_assert!(!task.domain.arena.is_tracked());
    let result = reclaim_task(task);
    if result.faulted {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        notify_fault_cleanup(result.id, result.domain);
        system.restore();
    }
}

fn make_task(
    domain: AllocationDomain,
    queue_owner: HartId,
    stealable: bool,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
    publication: Arc<AtomicBool>,
    instance_token: Option<InstanceToken>,
) -> (Task, TaskHandle) {
    let id = next_task_id();
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let status = Arc::new(TaskStatus::new(publication));
    let task_name = Arc::<str>::from(name);
    system.restore();

    let mut allocation = unsafe { heap::enter_domain(domain) };
    let future = ManuallyDrop::new(Box::pin(fut) as Pin<Box<dyn Future<Output = ()> + Send>>);
    allocation.restore();

    let task = Task {
        id,
        domain,
        name: task_name,
        future,
        status: status.clone(),
        queue_owner,
        ready: false,
        stealable,
        publication: TaskPublication::Prepared(0),
        reclaimable_domain: None,
        instance_token,
    };
    let handle = TaskHandle { id, domain, status };
    (task, handle)
}

fn spawn_tracked_domain(
    domain: AllocationDomain,
    queue_owner: HartId,
    stealable: bool,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    spawn_tracked_domain_mode(
        domain,
        queue_owner,
        stealable,
        ReclaimableDomainMode::Shared,
        name,
        fut,
    )
}

fn spawn_tracked_domain_mode(
    domain: AllocationDomain,
    queue_owner: HartId,
    stealable: bool,
    reclaimable_mode: ReclaimableDomainMode,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    if domain.arena.is_tracked() {
        let preflight =
            SCHED
                .lock()
                .reclaimable_domains
                .preflight(domain, queue_owner, reclaimable_mode);
        if let Err(error) = preflight {
            panic!("reclaimable domain spawn preflight rejected: {error:?}");
        }
    }
    let id = next_task_id();
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(true))));
    let task_name = Arc::<str>::from(name);
    system.restore();

    // The future state itself belongs to the incarnation arena. Scheduler
    // metadata remains SYSTEM-owned and can be dropped after a longjmp.
    // Safe callers can supply only untracked domains. A tracked domain comes
    // from `spawn_reclaimable_owned`, whose unsafe contract covers this scope.
    let mut allocation = unsafe { heap::enter_domain(domain) };
    let future = ManuallyDrop::new(Box::pin(fut) as Pin<Box<dyn Future<Output = ()> + Send>>);
    allocation.restore();

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut task = Task {
        id,
        domain,
        name: task_name,
        future,
        status: status.clone(),
        queue_owner,
        ready: true,
        stealable,
        publication: TaskPublication::Published,
        reclaimable_domain: None,
        instance_token: None,
    };
    let mut s = SCHED.lock();
    // Every live task can migrate to any queue after a steal and then become
    // ready at once. Reserve that upper bound in all four queues in task
    // context so an IRQ wake never allocates while holding SCHED.
    let live_after_spawn = s.tasks.len() + 1 + s.running_count();
    if s.ready.reserve_live_bound(live_after_spawn).is_err() {
        drop(s);
        system.restore();
        // Even a task that could not be admitted owns its future's destructor.
        // Reclaim it at the same guarded owner boundary as a scheduled task.
        let _ = reclaim_task(task);
        panic!("ready queue allocation failed");
    }
    if domain.arena.is_tracked() {
        let key = match s.reclaimable_domains.admit(
            domain,
            queue_owner,
            reclaimable_mode,
            id,
            &status,
            None,
        ) {
            Ok(key) => key,
            Err(error) => {
                drop(s);
                system.restore();
                // A concurrent unsafe first-publication violation cannot
                // safely run Drop against an arena which may now execute
                // elsewhere. Keep the future inert and leak only its arena
                // bytes; the scheduler owns no record or wake target for it.
                abandon_task_without_drop(task);
                panic!("reclaimable domain spawn commit rejected: {error:?}");
            }
        };
        task.reclaimable_domain = Some(key);
    }
    s.tasks.insert(id, task);
    s.ready
        .enqueue(queue_owner, id, stealable)
        .expect("a newly admitted task has unique reserved queue capacity");
    check_sched!(&s);
    drop(s);
    system.restore();
    notify_ready_hart(queue_owner);
    TaskHandle { id, domain, status }
}

fn publish_terminal(status: &TaskStatus, claim: TerminalClaim) -> Option<TaskState> {
    if !status.publish(claim) {
        return None;
    }
    let mut s = SCHED.lock();
    match claim.state {
        TaskState::Exited => s.completed += 1,
        TaskState::Faulted => s.faulted += 1,
        TaskState::Cancelled => s.cancelled += 1,
        TaskState::Running => unreachable!("a terminal transition returned Running"),
    }
    check_sched!(&s);
    check_status_detached!(&s, status);
    Some(claim.state)
}

struct ReclaimResult {
    id: TaskId,
    domain: AllocationDomain,
    home_hart: HartId,
    reclaimable_domain: Option<ReclaimableDomainKey>,
    instance_token: Option<InstanceToken>,
    faulted: bool,
}

/// Drop a normally suspended/completed future behind the same fault domain as
/// polling it. If the destructor faults, its allocation stays linked in the
/// arena and the caller performs raw domain teardown without invoking Drop
/// again.
fn reclaim_task(task: Task) -> ReclaimResult {
    let Task {
        id,
        domain,
        name,
        mut future,
        status,
        queue_owner,
        reclaimable_domain,
        instance_token,
        ..
    } = task;

    // Registration targets may themselves live inside the future. Remove the
    // ordinary wait/timer/join edges before entering user Drop: a destructor
    // fault may longjmp past the rest of that destructor after it already
    // destroyed one of those targets. Keep TaskDetach registrations armed
    // across Drop so a normal destructor can disarm its lease and a faulting
    // destructor is reported with the final Faulted reason.
    drain_ordinary_task_registrations(&status);
    let future = unsafe { ManuallyDrop::take(&mut future) };

    let guard = load_fault_guard();
    let mut current_task = enter_current_task(id, status.clone());
    // Task construction established the domain provenance; polling and Drop
    // must re-enter that exact audited domain.
    let mut owner_scope = unsafe { heap::enter_domain(domain) };
    let faulted = match guard {
        Some(run_guarded) => {
            let mut future = Some(future);
            let faulted = run_guarded(&mut || {
                if let Some(future) = future.take() {
                    drop(future);
                }
            });
            if faulted {
                // A synthetic host guard may report a fault without entering
                // the closure. Real longjmp faults have already taken it.
                if let Some(future) = future.take() {
                    core::mem::forget(future);
                }
            }
            faulted
        }
        None => {
            drop(future);
            false
        }
    };
    // A real task fault returns through longjmp and skips Rust destructors in
    // the guarded closure. Restore explicitly after the landing pad returns.
    owner_scope.restore();
    current_task.restore();

    let detach_reason = if faulted {
        TaskDetachReason::Faulted
    } else {
        task_detach_reason(&status)
    };
    drain_task_detach_registrations(&status, detach_reason);

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    drop(name);
    drop(status);
    system.restore();
    ReclaimResult {
        id,
        domain,
        home_hart: queue_owner,
        reclaimable_domain,
        instance_token,
        faulted,
    }
}

fn abandon_task_without_drop(task: Task) {
    let Task {
        id: _,
        domain: _,
        name,
        future,
        status,
        ..
    } = task;
    // ManuallyDrop's wrapper is discarded, but the future and its fields are
    // never visited. The heap reclaimer returns the arena bytes afterwards.
    core::mem::forget(future);
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    drop(name);
    drop(status);
    system.restore();
}

struct FaultVictim {
    id: TaskId,
    task: Option<Task>,
    status: Arc<TaskStatus>,
    claim: TerminalClaim,
}

fn teardown_faulted_domain(
    permit: ReclaimableTeardownPermit,
    primary_id: TaskId,
    mut primary_task: Option<Task>,
    primary_status: Arc<TaskStatus>,
    primary_claim: TerminalClaim,
) {
    let domain = permit.domain;
    debug_assert!(domain.arena.is_tracked());
    run_reclaimable_teardown_test_hook(domain);

    // Managed component instances use an exclusive domain. Once the fault
    // transition clears its exact running slot there can be no sibling to
    // discover, so keep this safety-critical path allocation-free. The shared
    // path below remains for the older audited task-group contract.
    if permit.exclusive {
        assert_eq!(permit.live_tasks, 1, "exclusive fault permit is not unique");
        assert_eq!(permit.primary_task, primary_id);
        assert_eq!(
            permit.primary_status,
            Arc::as_ptr(&primary_status) as usize,
            "exclusive fault permit status changed"
        );
        {
            let s = SCHED.lock();
            s.verify_reclaimable_teardown(permit)
                .unwrap_or_else(|error| panic!("exclusive fault teardown mismatch: {error:?}"));
            check_sched!(&s);
            check_arena_detached!(&s, domain);
        }

        // This is part of permanent executor detach, not component-state
        // recovery: remove only the exact TaskStatus-owned wake edges after
        // SCHED proved this task can never run again.  It remains mandatory on
        // a later registry mismatch, where the future/arena are leaked but a
        // stale wait/timer/join/probe must not revive the isolated TaskId.
        // Store/device cleanup and raw arena reclaim stay behind the
        // reclaimer's complete managed-instance gate below. The legacy World
        // hook remains exclusive to the legacy route.
        drain_task_registrations(&primary_status, TaskDetachReason::Faulted);
        if let Some(task) = primary_task.take() {
            abandon_task_without_drop(task);
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        // A managed instance must not mutate even exact-task stable state
        // until its registry has validated the complete generation/status/
        // scheduler/Space/CSpace tuple.  Its kernel reclaimer performs this
        // cleanup inside the registry-authorized raw-reclaim closure instead.
        if permit.instance_token.is_none() {
            notify_fault_cleanup(primary_id, domain);
        }
        let outcome = load_fault_reclaimer()
            .map_or(FaultReclaimOutcome::Quarantined, |reclaim| unsafe {
                reclaim(permit.fault_witness())
            });
        system.restore();

        {
            let mut s = SCHED.lock();
            s.finish_reclaimable_teardown(permit, outcome)
                .unwrap_or_else(|error| {
                    panic!("exclusive fault teardown completion mismatch: {error:?}")
                });
            check_sched!(&s);
        }
        publish_terminal(&primary_status, primary_claim);
        if outcome == FaultReclaimOutcome::Reclaimed {
            let mut s = SCHED.lock();
            s.reclaimable_domains
                .retire_terminal(permit.key, domain)
                .unwrap_or_else(|error| {
                    panic!("exclusive fault terminal retirement mismatch: {error:?}")
                });
            check_sched!(&s);
        }
        return;
    }

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut victims = Vec::new();
    {
        let s = SCHED.lock();
        check_sched!(&s);
        victims.reserve(s.tasks.len() + 1);
    }
    victims.push(FaultVictim {
        id: primary_id,
        task: primary_task,
        status: primary_status,
        claim: primary_claim,
    });

    {
        let mut s = SCHED.lock();
        let sibling_ids: Vec<_> = s
            .tasks
            .iter()
            .filter_map(|(id, task)| (task.domain == domain).then_some(*id))
            .collect();
        for id in sibling_ids {
            let task = s
                .tasks
                .remove(&id)
                .expect("an arena sibling disappeared under SCHED");
            assert_eq!(
                task.reclaimable_domain,
                Some(permit.key),
                "fault victim carries a stale reclaimable-domain generation"
            );
            assert_eq!(
                task.queue_owner, permit.home_hart,
                "fault victim escaped its reclaimable-domain home hart"
            );
            if task.ready {
                assert!(
                    s.ready.remove(task.queue_owner, id),
                    "fault victim ready metadata must identify its exact queue"
                );
            }
            let status = task.status.clone();
            assert_eq!(
                status.raw_state(),
                FAULT_COMMITTED,
                "an arena sibling lost its committed fault before detach"
            );
            let claim = TerminalClaim::new(TaskState::Faulted);
            victims.push(FaultVictim {
                id,
                task: Some(task),
                status,
                claim,
            });
        }
        s.verify_reclaimable_teardown(permit)
            .unwrap_or_else(|error| panic!("fault teardown gate mismatch: {error:?}"));
        check_sched!(&s);
        check_arena_detached!(&s, domain);
    }
    system.restore();

    // Registration targets may point into any sibling future. Drain every
    // ledger while all arena memory is still intact, then abandon holders.
    for victim in &victims {
        drain_task_registrations(&victim.status, TaskDetachReason::Faulted);
    }
    for victim in &mut victims {
        if let Some(task) = victim.task.take() {
            abandon_task_without_drop(task);
        }
    }

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    for victim in &victims {
        notify_fault_cleanup(victim.id, domain);
    }
    let outcome = load_fault_reclaimer()
        .map_or(FaultReclaimOutcome::Quarantined, |reclaim| unsafe {
            reclaim(permit.fault_witness())
        });
    system.restore();

    {
        let mut s = SCHED.lock();
        s.finish_reclaimable_teardown(permit, outcome)
            .unwrap_or_else(|error| panic!("fault teardown completion mismatch: {error:?}"));
        check_sched!(&s);
    }

    // Publication is the teardown linearization point: a supervisor cannot
    // observe Faulted and restart the component before raw reclaim completed.
    for victim in victims {
        publish_terminal(&victim.status, victim.claim);
    }
    if outcome == FaultReclaimOutcome::Reclaimed {
        let mut s = SCHED.lock();
        s.reclaimable_domains
            .retire_terminal(permit.key, domain)
            .unwrap_or_else(|error| panic!("fault terminal retirement mismatch: {error:?}"));
        check_sched!(&s);
    }
}

fn reclaim_and_publish(task: Task, status: &Arc<TaskStatus>, claim: TerminalClaim) {
    let result = reclaim_task(task);
    let claim = if result.faulted {
        status.promote_to_fault(claim)
    } else {
        claim
    };
    if result.faulted && result.domain.arena.is_tracked() {
        let key = result
            .reclaimable_domain
            .expect("a tracked destructor fault has no domain generation");
        let permit = {
            let mut s = SCHED.lock();
            let permit = s
                .begin_reclaimable_teardown(
                    result.domain,
                    key,
                    result.home_hart,
                    result.id,
                    status,
                    result.instance_token,
                    false,
                )
                .unwrap_or_else(|error| {
                    panic!("tracked destructor fault gate mismatch: {error:?}")
                });
            check_sched!(&s);
            permit
        };
        teardown_faulted_domain(permit, result.id, None, status.clone(), claim);
    } else {
        if result.faulted {
            let mut system = heap::enter_owner(OwnerId::SYSTEM);
            notify_fault_cleanup(result.id, result.domain);
            system.restore();
        }
        let terminal_domain = if result.domain.arena.is_tracked() {
            let key = result
                .reclaimable_domain
                .expect("a tracked task has no domain generation");
            let mut s = SCHED.lock();
            let last = s
                .finish_reclaimable_task(
                    key,
                    result.domain,
                    result.home_hart,
                    result.id,
                    status,
                    result.instance_token,
                )
                .unwrap_or_else(|error| panic!("tracked task terminal gate mismatch: {error:?}"));
            check_sched!(&s);
            last.then_some((key, result.domain))
        } else {
            None
        };
        publish_terminal(status, claim);
        if let Some((key, domain)) = terminal_domain {
            let mut s = SCHED.lock();
            s.reclaimable_domains
                .retire_terminal(key, domain)
                .unwrap_or_else(|error| {
                    panic!("tracked task terminal retirement mismatch: {error:?}")
                });
            check_sched!(&s);
        }
    }
}

fn requested_outcome(handle: &TaskHandle) -> CancelOutcome {
    match handle.status.request_cancel() {
        CancelRequest::Requested => CancelOutcome::Requested,
        CancelRequest::Terminal => CancelOutcome::AlreadyTerminal(
            handle
                .try_exit()
                .expect("a published terminal state has an exit report"),
        ),
        CancelRequest::TooLate(state) => CancelOutcome::TooLate(state),
    }
}

/// Report a cancellation that lost to a scheduler-domain lifecycle transition
/// without mutating the task status. A non-active reclaimable record must
/// already have a matching committed or published terminal status; observing
/// an ordinary Running/CANCEL_REQUESTED value here is a fail-stop invariant
/// violation rather than permission to reopen the lifecycle.
fn nonactive_cancel_outcome(handle: &TaskHandle) -> CancelOutcome {
    match handle.status.raw_state() {
        raw @ 1..=3 => CancelOutcome::AlreadyTerminal(TaskExit::new(
            handle.id,
            TaskState::from_raw(raw),
            handle.status.polls.load(Ordering::Acquire),
        )),
        EXIT_COMMITTED => CancelOutcome::TooLate(TaskState::Exited),
        CANCEL_COMMITTED => CancelOutcome::TooLate(TaskState::Cancelled),
        FAULT_COMMITTED => CancelOutcome::TooLate(TaskState::Faulted),
        raw => panic!("a non-active reclaimable task retained mutable lifecycle state {raw}"),
    }
}

fn cancel_task(handle: &TaskHandle) -> CancelOutcome {
    enum Action {
        Reclaim(Task, TerminalClaim),
        Return(CancelOutcome),
        InvariantViolation,
    }

    if !handle.is_published() {
        return CancelOutcome::NotPublished;
    }

    // Reclamation may enter arbitrary user Drop code. Never do that while this
    // hart already owns a user poll/Drop landing pad; for tracked arenas, also
    // require complete same-domain quiescence across every hart. Otherwise a
    // destructor fault could tear down live arena state before the owning
    // executor boundary regains control. Defer those cases to the target
    // queue's next top-level `poll_once` boundary.
    let caller_hart = current_scheduler_hart();
    let user_code_active = current_task_status().is_some();
    let mut ready_capacity_exhausted = false;
    let mut notify_hart = None;
    let action = {
        let mut s = SCHED.lock();
        check_sched!(&s);
        let action = if let Some(running_hart) = s.running_hart_for(handle.id) {
            let running = s.harts[running_hart.index()]
                .running
                .as_ref()
                .expect("running hart lookup remains exact");
            assert!(
                Arc::ptr_eq(&running.status, &handle.status),
                "a task handle resolved to a different running status object"
            );
            let active = if running.domain.arena.is_tracked() {
                let key = running
                    .reclaimable_domain
                    .expect("running tracked cancel target has no domain generation");
                match s.reclaimable_domains.validate_active_task(
                    key,
                    running.domain,
                    running_hart,
                    handle.id,
                    &running.status,
                    running.instance_token,
                ) {
                    Ok(_) => true,
                    Err(ReclaimableDomainError::NotActive) => false,
                    Err(error) => panic!("running tracked cancel gate mismatch: {error:?}"),
                }
            } else {
                true
            };
            Action::Return(if active {
                requested_outcome(handle)
            } else {
                nonactive_cancel_outcome(handle)
            })
        } else if let Some(target) = s.tasks.get(&handle.id) {
            // The caller hart's running slot covers the small dispatch/return
            // windows before the current-task scope is installed or after it
            // is restored, which matters for cancellation from an IRQ hook.
            // An unmapped caller always defers instead of borrowing a logical
            // slot for user Drop and fault recovery.
            let caller_running = caller_hart.map_or_else(
                || s.running_count() != 0,
                |hart| s.harts[hart.index()].running.is_some(),
            );
            assert!(
                Arc::ptr_eq(&target.status, &handle.status),
                "a task handle resolved to a different mapped status object"
            );
            let target_domain = target.domain;
            let target_owner = target.queue_owner;
            let active = if target_domain.arena.is_tracked() {
                let key = target
                    .reclaimable_domain
                    .expect("mapped tracked cancel target has no domain generation");
                match s.reclaimable_domains.validate_active_task(
                    key,
                    target_domain,
                    target_owner,
                    handle.id,
                    &target.status,
                    target.instance_token,
                ) {
                    Ok(_) => true,
                    Err(ReclaimableDomainError::NotActive) => false,
                    Err(error) => panic!("mapped tracked cancel gate mismatch: {error:?}"),
                }
            } else {
                true
            };
            if !active {
                Action::Return(nonactive_cancel_outcome(handle))
            } else {
                let tracked_domain_running = target_domain.arena.is_tracked()
                    && s.running_tasks()
                        .any(|running| running.domain == target_domain);
                let remote_tracked_reclaim =
                    target_domain.arena.is_tracked() && caller_hart != Some(target_owner);
                if caller_hart.is_none()
                    || user_code_active
                    || caller_running
                    || tracked_domain_running
                    || remote_tracked_reclaim
                {
                    let outcome = requested_outcome(handle);
                    let (ready, owner, stealable) = {
                        let task = s
                            .tasks
                            .get(&handle.id)
                            .expect("mapped cancellation target remains present");
                        (task.ready, task.queue_owner, task.stealable)
                    };
                    if outcome == CancelOutcome::Requested && !ready {
                        match s.ready.enqueue(owner, handle.id, stealable) {
                            Ok(()) => {
                                s.tasks
                                    .get_mut(&handle.id)
                                    .expect("mapped cancellation target remains present")
                                    .ready = true;
                                notify_hart = Some(owner);
                            }
                            Err(EnqueueError::CapacityExhausted) => {
                                ready_capacity_exhausted = true;
                            }
                            Err(EnqueueError::Duplicate) => {
                                panic!("cancel target acquired duplicate ready ownership")
                            }
                        }
                    }
                    Action::Return(outcome)
                } else {
                    match handle.status.claim_terminal(TaskState::Cancelled) {
                        Some(claim) => {
                            let task = s
                                .tasks
                                .remove(&handle.id)
                                .expect("contains_key was checked under the same lock");
                            if task.ready {
                                assert!(
                                    s.ready.remove(task.queue_owner, handle.id),
                                    "cancel target metadata must identify its exact queue"
                                );
                            }
                            Action::Reclaim(task, claim)
                        }
                        None => Action::Return(requested_outcome(handle)),
                    }
                }
            }
        } else {
            match requested_outcome(handle) {
                CancelOutcome::Requested => Action::InvariantViolation,
                outcome => Action::Return(outcome),
            }
        };
        check_sched!(&s);
        #[cfg(debug_assertions)]
        if matches!(&action, Action::Reclaim(_, _)) {
            check_status_detached!(&s, handle.status.as_ref());
        }
        action
    };

    if ready_capacity_exhausted {
        panic!("ready queue reservation invariant violated during deferred cancellation");
    }
    if let Some(hart) = notify_hart {
        notify_ready_hart(hart);
    }

    match action {
        Action::Reclaim(task, claim) => {
            // Never reclaim under SCHED: destructors may wake another task or
            // unregister from a wait primitive.
            reclaim_and_publish(task, &handle.status, claim);
            CancelOutcome::Requested
        }
        Action::Return(outcome) => outcome,
        Action::InvariantViolation => {
            panic!("a running task handle has no scheduler location or terminal claim")
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeDisposition {
    Enqueued { hart: HartId },
    AlreadyQueued { hart: HartId },
    Running { hart: HartId },
    Inactive,
}

impl WakeDisposition {
    pub const fn target_hart(self) -> Option<HartId> {
        match self {
            Self::Enqueued { hart } | Self::AlreadyQueued { hart } | Self::Running { hart } => {
                Some(hart)
            }
            Self::Inactive => None,
        }
    }
}

/// Wake one task without allocating, preserving the original executor API.
pub fn wake(id: TaskId) {
    let _ = wake_with_disposition(id);
}

/// Wake one task and report its logical target for the M5.2 notification path.
/// Queue ownership and the disposition are decided in the same `SCHED`
/// critical section.
pub fn wake_with_disposition(id: TaskId) -> WakeDisposition {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut s = SCHED.lock();
    check_sched!(&s);
    let mut capacity_exhausted = false;
    // Parked/ready tasks dominate ordinary channel and timer wakes. Resolve
    // the indexed task map first; only a detached running task requires the
    // bounded four-slot scan.
    let disposition = if let Some(task) = s.tasks.get(&id).filter(|task| task.is_published()) {
        let owner = task.queue_owner;
        let ready = task.ready;
        let stealable = task.stealable;
        let active = if task.domain.arena.is_tracked() {
            let key = task
                .reclaimable_domain
                .expect("tracked wake target has no domain generation");
            match s.reclaimable_domains.validate_active_task(
                key,
                task.domain,
                owner,
                id,
                &task.status,
                task.instance_token,
            ) {
                Ok(_) => true,
                Err(ReclaimableDomainError::NotActive) => false,
                Err(error) => panic!("tracked wake gate mismatch: {error:?}"),
            }
        } else {
            true
        };
        if !active {
            WakeDisposition::Inactive
        } else if ready {
            WakeDisposition::AlreadyQueued { hart: owner }
        } else {
            match s.ready.enqueue(owner, id, stealable) {
                Ok(()) => {
                    s.tasks
                        .get_mut(&id)
                        .expect("wake target remains mapped under SCHED")
                        .ready = true;
                    WakeDisposition::Enqueued { hart: owner }
                }
                Err(EnqueueError::CapacityExhausted) => {
                    capacity_exhausted = true;
                    WakeDisposition::Inactive
                }
                Err(EnqueueError::Duplicate) => {
                    panic!("wake target acquired duplicate ready ownership")
                }
            }
        }
    } else if let Some(hart) = s.running_hart_for(id) {
        let running = s.harts[hart.index()]
            .running
            .as_ref()
            .expect("running hart lookup remains exact");
        let active = if running.domain.arena.is_tracked() {
            let key = running
                .reclaimable_domain
                .expect("running tracked wake target has no domain generation");
            match s.reclaimable_domains.validate_active_task(
                key,
                running.domain,
                hart,
                id,
                &running.status,
                running.instance_token,
            ) {
                Ok(_) => true,
                Err(ReclaimableDomainError::NotActive) => false,
                Err(error) => panic!("running tracked wake gate mismatch: {error:?}"),
            }
        } else {
            true
        };
        if active {
            s.harts[hart.index()].woken = true;
            WakeDisposition::Running { hart }
        } else {
            WakeDisposition::Inactive
        }
    } else {
        WakeDisposition::Inactive
    };
    check_sched!(&s);
    drop(s);
    system.restore();
    if capacity_exhausted {
        panic!("ready queue reservation invariant violated");
    }
    if let WakeDisposition::Enqueued { hart } = disposition {
        notify_ready_hart(hart);
    }
    disposition
}

/// Identity and poll accounting for every live task.
pub fn task_report() -> Vec<TaskReport> {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut out = Vec::new();
    let mut allocation_failed = false;
    {
        let s = SCHED.lock();
        check_sched!(&s);
        let total = s.tasks.values().filter(|task| task.is_published()).count() + s.running_count();
        if out.try_reserve(total).is_err() {
            allocation_failed = true;
        } else {
            for (id, task) in &s.tasks {
                if !task.is_published() {
                    continue;
                }
                let mut name = String::new();
                if name.try_reserve(task.name.len()).is_err() {
                    allocation_failed = true;
                    break;
                }
                name.push_str(&task.name);
                out.push(TaskReport {
                    id: *id,
                    owner: task.domain.owner,
                    arena: task.domain.arena,
                    name,
                    state: task.status.state(),
                    polls: task.status.polls.load(Ordering::Acquire),
                });
            }
            if !allocation_failed {
                for running in s.running_tasks() {
                    let mut name = String::new();
                    if name.try_reserve(running.name.len()).is_err() {
                        allocation_failed = true;
                        break;
                    }
                    name.push_str(&running.name);
                    out.push(TaskReport {
                        id: running.id,
                        owner: running.domain.owner,
                        arena: running.domain.arena,
                        name,
                        state: running.status.state(),
                        polls: running.status.polls.load(Ordering::Acquire),
                    });
                }
            }
        }
    }
    if allocation_failed {
        system.restore();
        panic!("task report allocation failed");
    }
    // The report order is deterministic but does not require a stable sort.
    // Keeping this in-place also avoids another infallible allocation path.
    out.sort_unstable_by_key(|report| report.id);
    system.restore();
    out
}

pub fn completed_count() -> u64 {
    SCHED.lock().completed
}

/// Tasks killed by a fault rather than by returning.
pub fn faulted_count() -> u64 {
    SCHED.lock().faulted
}

/// Tasks reclaimed at a cooperative poll boundary after cancellation.
pub fn cancelled_count() -> u64 {
    SCHED.lock().cancelled
}

/// Capacity reserved for IRQ/task wakes. Spawn keeps this at least as large as
/// the live-task upper bound so the wake path never allocates.
pub fn ready_queue_capacity() -> usize {
    SCHED.lock().ready.min_capacity()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedulerStats {
    pub harts: [HartRunQueueStats; MAX_HARTS],
}

pub fn scheduler_stats() -> SchedulerStats {
    SchedulerStats {
        harts: SCHED.lock().ready.stats(),
    }
}

/// Allocation-free telemetry for the retained transactional scheduler lock.
///
/// M5.3 samples this boundary explicitly instead of claiming the scheduler is
/// lock-free: task lifecycle and queue ownership still linearize together.
pub fn scheduler_lock_stats() -> crate::sync::SpinLockStats {
    SCHED.stats()
}

/// Inspect one exact tracked allocation domain without exposing its scheduler
/// lease generation. A reused arena carrying a different owner is unrelated
/// and therefore returns `None` rather than aliasing the live incarnation.
pub fn reclaimable_domain_snapshot(domain: AllocationDomain) -> Option<ReclaimableDomainSnapshot> {
    SCHED
        .lock()
        .reclaimable_domains
        .record(domain)
        .map(ReclaimableDomainRecord::snapshot)
}

/// Number of scheduler-domain slots retained in any lifecycle phase. Sticky
/// quarantines deliberately remain included until reboot/fail-stop.
pub fn reclaimable_domain_count() -> usize {
    SCHED.lock().reclaimable_domains.active_count()
}

/// Linearizable logical queue affinity for one live task. A running task owns
/// the executing hart; a ready or parked task owns its metadata hart.
pub fn task_queue_owner(id: TaskId) -> Option<HartId> {
    let s = SCHED.lock();
    if let Some(hart) = s.running_hart_for(id) {
        let running = s.harts[hart.index()]
            .running
            .as_ref()
            .expect("running hart lookup remains exact");
        if running.domain.arena.is_tracked() {
            let key = running
                .reclaimable_domain
                .expect("running tracked queue-owner target has no domain generation");
            match s.reclaimable_domains.validate_active_task(
                key,
                running.domain,
                hart,
                id,
                &running.status,
                running.instance_token,
            ) {
                Ok(_) => return Some(hart),
                Err(ReclaimableDomainError::NotActive) => return None,
                Err(error) => panic!("running tracked queue-owner gate mismatch: {error:?}"),
            }
        }
        return Some(hart);
    }
    s.tasks
        .get(&id)
        .filter(|task| task.is_published())
        .and_then(|task| {
            if !task.domain.arena.is_tracked() {
                return Some(task.queue_owner);
            }
            let key = task
                .reclaimable_domain
                .expect("tracked queue-owner target has no domain generation");
            match s.reclaimable_domains.validate_active_task(
                key,
                task.domain,
                task.queue_owner,
                id,
                &task.status,
                task.instance_token,
            ) {
                Ok(_) => Some(task.queue_owner),
                Err(ReclaimableDomainError::NotActive) => None,
                Err(error) => panic!("tracked queue-owner gate mismatch: {error:?}"),
            }
        })
}

/// True when `hart` has neither local work nor stealable remote work.
pub fn hart_idle(hart: HartId) -> bool {
    SCHED.lock().ready.hart_idle(hart)
}

// --- Waker: the pointer *is* the TaskId. No refcount, no allocation. ---

const VTABLE: RawWakerVTable = RawWakerVTable::new(
    |p| RawWaker::new(p, &VTABLE),
    |p| wake(TaskId(p as u64)),
    |p| wake(TaskId(p as u64)),
    |_| {},
);

fn waker_for(id: TaskId) -> Waker {
    unsafe { Waker::from_raw(RawWaker::new(id.0 as *const (), &VTABLE)) }
}

/// Drive tasks forever. Sleeps the hart in `wfi` whenever nothing is runnable,
/// which is what makes an idle VibeOS box draw no CPU.
pub fn run() -> ! {
    let hart = require_current_scheduler_hart("executor run loop");
    loop {
        if poll_once_on(hart) {
            continue;
        }
        // Nothing was ready. "Check the queue" and "sleep" have to be one
        // atomic step: with interrupts unmasked in between, a wake landing in
        // the gap is not lost but is not seen either, and the hart sleeps until
        // something else happens to fire.
        //
        // Masking interrupts closes it. `wfi` still wakes on a pending enabled
        // interrupt when the global enable is off -- the RISC-V spec makes it a
        // hint that resumes whenever `sip & sie` is non-zero, regardless of
        // `sstatus.SIE` -- so an interrupt arriving inside this window stays
        // pending and resumes us immediately. Unmasking then lets it be taken.
        let irq = arch::irq_save();
        // The ready queue is published before the Release mailbox bit. With
        // SIE masked, observing both empty closes the queue-check/WFI race:
        // a later successful doorbell remains pending and makes WFI resume,
        // while an earlier publisher is observed by one of these checks.
        let queue_idle = SCHED.lock().ready.hart_idle(hart);
        let reasons = ipi::take_idle_reasons(hart);
        if queue_idle && reasons == 0 {
            arch::wait_for_interrupt();
        }
        arch::irq_restore(irq);
    }
}

/// Poll at most one ready task. Returns false when nothing was runnable.
///
/// Split out of `run` so tests can drive the scheduler a step at a time.
pub fn poll_once() -> bool {
    let hart = require_current_scheduler_hart("executor poll");
    poll_once_on(hart)
}

fn poll_once_on(hart: HartId) -> bool {
    debug_assert_eq!(
        current_scheduler_hart(),
        Some(hart),
        "a hart may only drive its own scheduler slot"
    );
    // Each hart lifts its current task out of `tasks`. Reject same-hart
    // re-entry while its fault guard is authoritative, while allowing a host
    // model (and real SMP execution) to drive a different hart concurrently.
    assert!(
        CURRENT_TASK_STATUS[hart.index()].lock().is_none()
            && CURRENT_TASK_ID[hart.index()].load(Ordering::Acquire) == 0
            && SCHED.lock().harts[hart.index()].running.is_none(),
        "a hart cannot drive the executor recursively from task poll or Drop"
    );

    enum Dispatch {
        Poll(TaskId, Task, Arc<TaskStatus>),
        Reclaim(Task, Arc<TaskStatus>, TerminalClaim),
        Invalid(Task),
    }

    // Pop, detach, and publish `running` under one lock. This is the start-poll
    // linearization point: cancellation before it detaches the task without a
    // poll; cancellation after it waits for this poll boundary.
    // Safety: callers resolved `hart` from this CPU before entering this
    // synchronous, non-migrating executor turn.
    let mut system = unsafe { heap::enter_owner_on_hart(OwnerId::SYSTEM, hart) };
    let dispatch = {
        let mut s = SCHED.lock();
        check_sched!(&s);
        let Some(ready_dispatch) = s.ready.dispatch(hart) else {
            return false;
        };
        let id = ready_dispatch.task;
        if let Some(candidate) = s.tasks.get(&id) {
            if candidate.domain.arena.is_tracked() {
                let key = candidate
                    .reclaimable_domain
                    .expect("tracked dispatch candidate has no domain key");
                let record = s
                    .reclaimable_domains
                    .record_exact(key, candidate.domain)
                    .unwrap_or_else(|error| panic!("tracked dispatch domain mismatch: {error:?}"));
                assert_eq!(
                    record.phase,
                    ReclaimableDomainPhase::Active,
                    "a non-active reclaimable domain reached dispatch"
                );
                assert_eq!(
                    record.home_hart, hart,
                    "a reclaimable task reached a non-home executor hart"
                );
                assert_eq!(
                    candidate.queue_owner, record.home_hart,
                    "reclaimable task queue owner changed"
                );
                assert_eq!(
                    ready_dispatch.source, record.home_hart,
                    "reclaimable task was dispatched from a foreign queue"
                );
                assert!(!candidate.stealable && !ready_dispatch.stolen);
                if record.exclusive {
                    assert_eq!(record.live_tasks, 1);
                    assert_eq!(record.exclusive_task, Some(id));
                    assert_eq!(
                        record.exclusive_status,
                        Some(Arc::as_ptr(&candidate.status) as usize)
                    );
                }
            }
        }
        let mut task = s
            .tasks
            .remove(&id)
            .expect("a dispatched task must remain in the task map");
        assert!(
            task.ready && task.queue_owner == ready_dispatch.source,
            "dispatch must consume the task's exact ready owner"
        );
        task.ready = false;
        task.queue_owner = hart;
        let status = task.status.clone();
        let dispatch = if status.cancellation_requested() {
            match status.claim_terminal(TaskState::Cancelled) {
                Some(claim) => Dispatch::Reclaim(task, status, claim),
                None => Dispatch::Invalid(task),
            }
        } else if status.raw_state() == TaskState::Running as u8 {
            s.install_running(
                hart,
                RunningTask {
                    id,
                    hart,
                    domain: task.domain,
                    name: task.name.clone(),
                    status: status.clone(),
                    reclaimable_domain: task.reclaimable_domain,
                    instance_token: task.instance_token,
                },
            );
            Dispatch::Poll(id, task, status)
        } else {
            Dispatch::Invalid(task)
        };
        check_sched!(&s);
        #[cfg(debug_assertions)]
        if let Dispatch::Reclaim(_, status, _) = &dispatch {
            check_status_detached!(&s, status.as_ref());
        }
        dispatch
    };
    // Safety: poll_once_on is pinned to `hart` for this complete executor turn.
    unsafe { system.restore_on_verified_hart() };

    let (id, mut task, status) = match dispatch {
        Dispatch::Poll(id, task, status) => (id, task, status),
        Dispatch::Reclaim(task, status, claim) => {
            reclaim_and_publish(task, &status, claim);
            return true;
        }
        Dispatch::Invalid(task) => {
            core::mem::forget(task);
            panic!("a queued task had an invalid lifecycle phase");
        }
    };

    let waker = waker_for(id);
    let mut cx = Context::from_waker(&waker);

    // Poll behind the kernel's landing pad when one is installed, so a
    // component that panics costs its own task instead of the machine.
    let guard = load_fault_guard();
    let mut poll = Poll::Pending;
    // Safety: poll_once_on is pinned to `hart` for this complete turn.
    let mut current_task = unsafe { enter_current_task_on_hart(hart, id, status.clone()) };
    // Tracked task domains originate only at the unsafe reclaimable spawn
    // boundary; ordinary safe tasks carry an untracked domain.
    let mut owner_scope = unsafe { heap::enter_domain_on_hart(task.domain, hart) };
    check_active_poll!(id, task.domain, &status);
    let faulted = match guard {
        Some(run_guarded) => {
            let fut = task.future.as_mut();
            let mut once = Some(fut);
            run_guarded(&mut || {
                if let Some(f) = once.take() {
                    complete_irq_poll_probe(id);
                    status.polls.fetch_add(1, Ordering::Relaxed);
                    poll = f.poll(&mut cx);
                }
            })
        }
        None => {
            complete_irq_poll_probe(id);
            status.polls.fetch_add(1, Ordering::Relaxed);
            poll = task.future.as_mut().poll(&mut cx);
            false
        }
    };
    // `run_guarded` may have returned through a longjmp, which bypasses Drop
    // for scopes created inside the guarded call. Restore at the executor
    // boundary before touching scheduler infrastructure or another task.
    // Safety: CurrentTaskScope validates the same physical hart immediately
    // below; target tasks cannot migrate during one synchronous poll.
    unsafe { owner_scope.restore_on_verified_hart() };
    current_task.restore();

    if faulted {
        // Detach and commit under the same IRQ-masking scheduler critical
        // section. Otherwise a wake interrupt could observe the intermediate
        // FaultCommitted + running combination that neither the model nor the
        // public ownership rules permit.
        // Safety: this remains inside the same hart-pinned executor turn.
        let mut system = unsafe { heap::enter_owner_on_hart(OwnerId::SYSTEM, hart) };
        let (claim, teardown) = {
            let mut s = SCHED.lock();
            assert!(s.harts[hart.index()]
                .running
                .as_ref()
                .is_some_and(|running| {
                    running.id == id
                        && running.hart == hart
                        && running.domain == task.domain
                        && Arc::ptr_eq(&running.status, &status)
                }));
            let teardown = if task.domain.arena.is_tracked() {
                let key = task
                    .reclaimable_domain
                    .expect("a running tracked fault has no domain generation");
                Some(
                    s.begin_reclaimable_teardown(
                        task.domain,
                        key,
                        hart,
                        id,
                        &status,
                        task.instance_token,
                        true,
                    )
                    .unwrap_or_else(|error| panic!("tracked poll fault gate mismatch: {error:?}")),
                )
            } else {
                s.clear_running(hart);
                s.harts[hart.index()].woken = false;
                None
            };
            let claim = status.claim_terminal(TaskState::Faulted);
            check_sched!(&s);
            check_status_detached!(&s, status.as_ref());
            (claim, teardown)
        };
        // Safety: this remains inside the same hart-pinned executor turn.
        unsafe { system.restore_on_verified_hart() };
        let Some(claim) = claim else {
            panic!("a faulted running task could not claim its terminal state");
        };
        if task.domain.arena.is_tracked() {
            teardown_faulted_domain(
                teardown.expect("tracked poll fault produced no teardown permit"),
                id,
                Some(task),
                status,
                claim,
            );
        } else {
            // Ordinary tasks have no audited escape contract. Clean external
            // registrations, but conservatively leak their future allocation.
            let domain = task.domain;
            drain_task_registrations(&status, TaskDetachReason::Faulted);
            core::mem::forget(task);
            // Safety: this remains inside the same hart-pinned executor turn.
            let mut system = unsafe { heap::enter_owner_on_hart(OwnerId::SYSTEM, hart) };
            notify_fault_cleanup(id, domain);
            // Safety: this remains inside the same hart-pinned executor turn.
            unsafe { system.restore_on_verified_hart() };
            publish_terminal(&status, claim);
        }
        return true;
    }

    // Safety: this remains inside the same hart-pinned executor turn.
    let mut system = unsafe { heap::enter_owner_on_hart(OwnerId::SYSTEM, hart) };
    let mut s = SCHED.lock();
    if task.domain.arena.is_tracked() {
        let key = task
            .reclaimable_domain
            .expect("a running tracked task has no domain generation");
        s.reclaimable_domains
            .validate_active_task(key, task.domain, hart, id, &status, task.instance_token)
            .unwrap_or_else(|error| panic!("tracked poll return gate mismatch: {error:?}"));
        assert_eq!(
            s.harts[hart.index()]
                .running
                .as_ref()
                .and_then(|running| running.reclaimable_domain),
            Some(key),
            "running slot carries a stale reclaimable-domain generation"
        );
    }
    s.clear_running(hart);
    let woken = core::mem::take(&mut s.harts[hart.index()].woken);
    if poll == Poll::Pending && !status.cancellation_requested() {
        // A cancellation cannot slip between this decision and reinsertion:
        // it also takes SCHED. A nested request was already published before
        // this branch, while an outer request sees the reinserted parked task.
        if woken {
            s.ready
                .enqueue(task.queue_owner, id, task.stealable)
                .expect("a running task retains reserved ready capacity");
            task.ready = true;
        }
        s.tasks.insert(id, task);
        check_sched!(&s);
        drop(s);
        // Safety: this remains inside the same hart-pinned executor turn.
        unsafe { system.restore_on_verified_hart() };
        return true;
    }

    let requested = if poll == Poll::Ready(()) {
        TaskState::Exited
    } else {
        TaskState::Cancelled
    };
    let claim = status.claim_terminal(requested);
    check_sched!(&s);
    check_status_detached!(&s, status.as_ref());
    drop(s);
    // Safety: this remains inside the same hart-pinned executor turn.
    unsafe { system.restore_on_verified_hart() };

    let Some(claim) = claim else {
        core::mem::forget(task);
        panic!("a running task could not commit its terminal state");
    };
    // The claim prevents a late cancellation from rewriting Ready into
    // Cancelled while the destructor runs. Publication follows reclamation.
    reclaim_and_publish(task, &status, claim);
    true
}

/// Drive tasks until nothing is runnable, or until `budget` polls have run.
///
/// The budget is not a nicety: a task that wakes itself every poll (`yield_now`
/// in a loop) never goes idle, and a test that hangs is a test nobody runs.
pub fn run_until_idle(budget: usize) -> usize {
    let mut polls = 0;
    while polls < budget && poll_once() {
        polls += 1;
    }
    polls
}

// --- Wait queues ---

/// A parking spot for tasks waiting on an event an interrupt will signal.
pub struct WaitQueue {
    inner: SpinLock<WaitQueueInner>,
}

struct WaitQueueInner {
    epoch: u64,
    next_id: u64,
    waiters: Vec<QueueWaiter>,
}

struct QueueWaiter {
    id: u64,
    waker: Waker,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(WaitQueueInner {
                epoch: 0,
                next_id: 1,
                waiters: Vec::new(),
            }),
        }
    }

    pub fn wake_all(&self) {
        let waiters = {
            let mut inner = self.inner.lock();
            // A listener created before this point observes the event even if
            // it has not reached its first poll yet. Wrapping only creates an
            // ABA after 2^64 signals to the same queue.
            inner.epoch = inner.epoch.wrapping_add(1);
            core::mem::take(&mut inner.waiters)
        };
        for waiter in waiters {
            waiter.waker.wake();
        }
    }

    /// Number of futures currently registered on this queue.
    pub fn waiter_count(&self) -> usize {
        self.inner.lock().waiters.len()
    }

    /// Allocation-free contention telemetry for this IRQ/task handoff queue.
    pub fn lock_stats(&self) -> crate::sync::SpinLockStats {
        self.inner.stats()
    }

    /// Prepare to park until the next `wake_all`.
    ///
    /// Construct this listener *before* checking the condition it protects,
    /// then await it only when that check says to block. The captured epoch
    /// closes the condition-check/register race with an interrupt.
    pub fn wait(&self) -> WaitFuture<'_> {
        let epoch = self.inner.lock().epoch;
        WaitFuture {
            queue: self,
            epoch,
            registration: None,
            owned_registration: None,
        }
    }

    fn unregister(&self, id: u64) -> Option<Waker> {
        let removed = {
            let mut inner = self.inner.lock();
            inner
                .waiters
                .iter()
                .position(|waiter| waiter.id == id)
                .map(|index| inner.waiters.swap_remove(index).waker)
        };
        // A custom RawWaker may run arbitrary code from Drop, including
        // re-entering this queue. Never release it under the queue lock.
        removed
    }
}

pub struct WaitFuture<'a> {
    queue: &'a WaitQueue,
    epoch: u64,
    registration: Option<u64>,
    owned_registration: Option<u64>,
}

impl Future for WaitFuture<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        // Cloning may invoke a custom RawWaker, so do it before taking the
        // queue lock. Registry wakers are SYSTEM infrastructure, including
        // custom RawWakers whose clone/drop callbacks allocate.
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        let mut allocation_failed = false;

        let result = {
            let mut inner = this.queue.inner.lock();
            if inner.epoch != this.epoch {
                disarm_owned_for_current(this.owned_registration.take());
                if let Some(id) = this.registration.take() {
                    if let Some(index) = inner.waiters.iter().position(|waiter| waiter.id == id) {
                        discarded = Some(inner.waiters.swap_remove(index).waker);
                    }
                }
                Poll::Ready(())
            } else {
                let id = this.registration.unwrap_or_else(|| {
                    let id = inner.next_id;
                    inner.next_id = inner.next_id.wrapping_add(1).max(1);
                    id
                });

                if this.owned_registration.is_none() {
                    match register_owned_for_current(OwnedRegistration::Wait {
                        queue: this.queue as *const WaitQueue as usize,
                        id,
                    }) {
                        Ok(token) => this.owned_registration = token,
                        Err(_) => allocation_failed = true,
                    }
                }

                if allocation_failed {
                    Poll::Pending
                } else if let Some(waiter) = inner.waiters.iter_mut().find(|waiter| waiter.id == id)
                {
                    if !waiter.waker.will_wake(cx.waker()) {
                        discarded = Some(core::mem::replace(
                            &mut waiter.waker,
                            candidate.take().expect("waker candidate exists"),
                        ));
                    }
                    Poll::Pending
                } else if inner.waiters.try_reserve(1).is_err() {
                    allocation_failed = true;
                    Poll::Pending
                } else {
                    inner.waiters.push(QueueWaiter {
                        id,
                        waker: candidate.take().expect("waker candidate exists"),
                    });
                    this.registration = Some(id);
                    Poll::Pending
                }
            }
        };

        drop(discarded);
        drop(candidate);
        system.restore();
        if allocation_failed {
            panic!("wait queue registration allocation failed");
        }
        result
    }
}

impl Drop for WaitFuture<'_> {
    fn drop(&mut self) {
        disarm_owned_for_current(self.owned_registration.take());
        if let Some(id) = self.registration.take() {
            drop(self.queue.unregister(id));
        }
    }
}

/// A fixed-capacity, SYSTEM-stable handoff for exactly one parked task.
///
/// Unlike [`WaitQueue`], this primitive never grows a waiter collection. The
/// queue must live in SYSTEM or equally stable supervisor storage for longer
/// than every future returned by [`Self::wait`]. A reclaimable task records
/// its exact registration in `TaskStatus`, so cancellation and fault detach
/// remove the wake edge before the task arena can be reclaimed.
pub struct OneShotWaitQueue {
    inner: SpinLock<OneShotWaitQueueInner>,
}

struct OneShotWaitQueueInner {
    /// Highest caller-supplied event generation published by this stable
    /// queue. Callers must allocate strictly increasing, non-zero generations.
    /// Keeping this independently from registration generations prevents a
    /// delayed completion from touching a replacement operation's waiter.
    published_generation: u64,
    /// Independent registration generation. A listener may be dropped and a
    /// replacement registered without an event, so epoch alone is not an ABA
    /// barrier for task-owned cleanup.
    next_generation: u64,
    /// Exact TaskStatus target detached by the latest published generation.
    /// Retaining only this copy scalar lets a same-generation recovery replay
    /// repair a publisher fault after the ordinary Waker was removed.
    published_exact_wake: Option<ExactTaskWake>,
    waiter: Option<OneShotWaiter>,
}

struct OneShotWaiter {
    registration_generation: u64,
    event_generation: u64,
    waker: Waker,
    exact_wake: Option<ExactTaskWake>,
}

/// A waker detached from one exact event while the caller still held its
/// authoritative state lock.
///
/// The caller must invoke [`Self::dispatch`] only after releasing every state
/// and queue lock. A delayed dispatch can schedule only the task captured by
/// the matching registration; it cannot inspect or remove a later waiter.
#[must_use = "a published one-shot event must dispatch its detached waker"]
pub struct OneShotWake {
    waker: Option<Waker>,
    exact_wake: Option<ExactTaskWake>,
}

impl OneShotWake {
    pub fn dispatch(mut self) -> bool {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let dispatched = match self.waker.take() {
            Some(waker) => {
                waker.wake();
                true
            }
            None => false,
        };
        system.restore();
        dispatched
            || self
                .exact_wake
                .take()
                .is_some_and(ExactTaskWake::wake_if_exact)
    }
}

impl Drop for OneShotWake {
    fn drop(&mut self) {
        let Some(waker) = self.waker.take() else {
            return;
        };
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        drop(waker);
        system.restore();
    }
}

/// Fail-closed outcomes from registering a [`OneShotWaitFuture`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotWaitError {
    /// Another future already owns the queue's sole waiter slot.
    CapacityExceeded,
    /// Registrations must belong to the currently executing scheduler task.
    NotInTask,
    /// The task cleanup ledger could not reserve its ownership record.
    RegistrationFailed,
    /// No fresh registration generation remains; reuse would permit ABA.
    GenerationExhausted,
    /// This future's opaque generation no longer names the installed waiter.
    RegistrationMismatch,
}

impl OneShotWaitQueue {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(OneShotWaitQueueInner {
                published_generation: 0,
                next_generation: 1,
                published_exact_wake: None,
                waiter: None,
            }),
        }
    }

    /// Publish one exact event while the caller still holds the state lock
    /// which proves that generation authoritative.
    ///
    /// The returned waker is detached under the queue lock but is not invoked
    /// or dropped there. A generation older than the last publication, or a
    /// publication which does not name the installed waiter, fails closed
    /// without changing either the waiter or publication watermark.
    pub fn publish(&self, event_generation: u64) -> Result<OneShotWake, OneShotWaitError> {
        let mut inner = self.inner.lock();
        if event_generation == 0 || event_generation < inner.published_generation {
            return Err(OneShotWaitError::RegistrationMismatch);
        }
        if event_generation == inner.published_generation {
            return Ok(OneShotWake {
                waker: None,
                exact_wake: inner.published_exact_wake,
            });
        }
        if inner
            .waiter
            .as_ref()
            .is_some_and(|waiter| waiter.event_generation != event_generation)
        {
            return Err(OneShotWaitError::RegistrationMismatch);
        }
        inner.published_generation = event_generation;
        let waiter = inner.waiter.take();
        inner.published_exact_wake = waiter.as_ref().and_then(|waiter| waiter.exact_wake);
        Ok(OneShotWake {
            waker: waiter.map(|waiter| waiter.waker),
            exact_wake: inner.published_exact_wake,
        })
    }

    /// Number of futures installed in the fixed waiter slot (zero or one).
    pub fn waiter_count(&self) -> usize {
        usize::from(self.inner.lock().waiter.is_some())
    }

    /// Construct a listener before rechecking the condition it protects.
    ///
    /// If [`Self::publish`] wins before the first poll, the generation
    /// watermark makes the future immediately ready without installing a
    /// stale wake edge.
    pub fn wait(&self, event_generation: u64) -> OneShotWaitFuture<'_> {
        OneShotWaitFuture {
            queue: self,
            event_generation,
            registration_generation: None,
            owned_registration: None,
            owner_task: None,
            terminal: None,
        }
    }

    fn unregister(&self, generation: u64) -> Option<Waker> {
        let mut inner = self.inner.lock();
        if inner
            .waiter
            .as_ref()
            .is_some_and(|waiter| waiter.registration_generation == generation)
        {
            inner.waiter.take().map(|waiter| waiter.waker)
        } else {
            None
        }
    }
}

impl Default for OneShotWaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A non-owning listener for one exact [`OneShotWaitQueue`] event generation.
///
/// The future owns neither the stable queue nor its task status. Its two
/// numeric tokens only let normal completion/Drop disarm the executor-owned
/// cleanup ledger and remove the matching waiter generation.
pub struct OneShotWaitFuture<'a> {
    queue: &'a OneShotWaitQueue,
    event_generation: u64,
    registration_generation: Option<u64>,
    owned_registration: Option<u64>,
    owner_task: Option<TaskId>,
    terminal: Option<Result<(), OneShotWaitError>>,
}

impl Future for OneShotWaitFuture<'_> {
    type Output = Result<(), OneShotWaitError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(result) = this.terminal {
            return Poll::Ready(result);
        }
        if this.event_generation == 0 {
            this.terminal = Some(Err(OneShotWaitError::RegistrationMismatch));
            return Poll::Ready(Err(OneShotWaitError::RegistrationMismatch));
        }

        let current_owner = current_task_scope_id();
        let current_exact_wake = current_task_exact_wake();
        if this.owner_task.is_some() && this.owner_task != current_owner {
            let mut system = heap::enter_owner(OwnerId::SYSTEM);
            disarm_owned_for_task(
                this.owner_task
                    .take()
                    .expect("registered wait lost its owner"),
                this.owned_registration.take(),
            );
            if let Some(generation) = this.registration_generation.take() {
                drop(this.queue.unregister(generation));
            }
            system.restore();
            this.terminal = Some(Err(OneShotWaitError::RegistrationMismatch));
            return Poll::Ready(Err(OneShotWaitError::RegistrationMismatch));
        }

        // Custom RawWakers may allocate or re-enter this queue from clone or
        // Drop. Both operations, as well as wake(), stay outside `inner`.
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        let mut disarm = None;

        let result = {
            let mut inner = this.queue.inner.lock();
            if inner.published_generation >= this.event_generation {
                disarm = this.owner_task.take().zip(this.owned_registration.take());
                if let Some(generation) = this.registration_generation.take() {
                    if inner.waiter.as_ref().is_some_and(|waiter| {
                        waiter.registration_generation == generation
                            && waiter.event_generation == this.event_generation
                    }) {
                        discarded = inner.waiter.take().map(|waiter| waiter.waker);
                    }
                }
                if inner.published_generation == this.event_generation {
                    Ok(())
                } else {
                    Err(OneShotWaitError::RegistrationMismatch)
                }
            } else if let Some(generation) = this.registration_generation {
                match inner.waiter.as_mut() {
                    Some(waiter)
                        if waiter.registration_generation == generation
                            && waiter.event_generation == this.event_generation =>
                    {
                        if !waiter.waker.will_wake(cx.waker()) {
                            discarded = Some(core::mem::replace(
                                &mut waiter.waker,
                                candidate.take().expect("waker candidate exists"),
                            ));
                        }
                        drop(inner);
                        drop(discarded);
                        drop(candidate);
                        system.restore();
                        return Poll::Pending;
                    }
                    _ => {
                        // Never remove a different generation. A stale future
                        // cannot consume a replacement waiter after slot reuse.
                        disarm = this.owner_task.take().zip(this.owned_registration.take());
                        this.registration_generation = None;
                        Err(OneShotWaitError::RegistrationMismatch)
                    }
                }
            } else if inner.waiter.is_some() {
                Err(OneShotWaitError::CapacityExceeded)
            } else {
                let generation = match inner.next_generation.checked_add(1) {
                    Some(next) => {
                        let generation = inner.next_generation;
                        inner.next_generation = next;
                        generation
                    }
                    None => {
                        drop(inner);
                        drop(candidate);
                        system.restore();
                        this.terminal = Some(Err(OneShotWaitError::GenerationExhausted));
                        return Poll::Ready(Err(OneShotWaitError::GenerationExhausted));
                    }
                };
                let Some(owner_task) = current_owner else {
                    drop(inner);
                    drop(candidate);
                    system.restore();
                    this.terminal = Some(Err(OneShotWaitError::NotInTask));
                    return Poll::Ready(Err(OneShotWaitError::NotInTask));
                };
                match register_owned_for_current(OwnedRegistration::OneShotWait {
                    queue: this.queue as *const OneShotWaitQueue as usize,
                    generation,
                }) {
                    Ok(Some(token)) => {
                        inner.waiter = Some(OneShotWaiter {
                            registration_generation: generation,
                            event_generation: this.event_generation,
                            waker: candidate.take().expect("waker candidate exists"),
                            exact_wake: current_exact_wake,
                        });
                        this.registration_generation = Some(generation);
                        this.owned_registration = Some(token);
                        this.owner_task = Some(owner_task);
                        drop(inner);
                        drop(candidate);
                        system.restore();
                        return Poll::Pending;
                    }
                    Ok(None) => Err(OneShotWaitError::NotInTask),
                    Err(_) => Err(OneShotWaitError::RegistrationFailed),
                }
            }
        };

        // Disarm after releasing the queue lock. Task teardown takes the
        // registration vector and then calls back into this queue, so keeping
        // the lock ordering flat makes that cleanup trivially deadlock-free.
        if let Some((task, token)) = disarm {
            disarm_owned_for_task(task, Some(token));
        }
        drop(discarded);
        drop(candidate);
        system.restore();
        this.terminal = Some(result);
        Poll::Ready(result)
    }
}

impl Drop for OneShotWaitFuture<'_> {
    fn drop(&mut self) {
        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        if let Some(task) = self.owner_task.take() {
            disarm_owned_for_task(task, self.owned_registration.take());
        }
        if let Some(generation) = self.registration_generation.take() {
            drop(self.queue.unregister(generation));
        }
        system.restore();
    }
}

// --- One-shot timer IRQ -> task poll profiling ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqPollProbeError {
    /// Probes are task-owned so cancellation and fault teardown can clean them.
    NotInTask,
    /// M3.13 deliberately provides one global slot to keep the IRQ path fixed.
    Busy,
    /// The task cleanup ledger could not reserve its ownership record.
    RegistrationFailed,
}

#[derive(Clone, Copy)]
struct IrqPollProbeState {
    generation: u64,
    target: Option<TaskId>,
    timer_id: Option<u64>,
    irq_entry: Option<u64>,
    sample: Option<u64>,
}

impl IrqPollProbeState {
    const EMPTY: Self = Self {
        generation: 0,
        target: None,
        timer_id: None,
        irq_entry: None,
        sample: None,
    };
}

static IRQ_POLL_PROBE: SpinLock<IrqPollProbeState> = SpinLock::new(IrqPollProbeState::EMPTY);
static NEXT_IRQ_POLL_PROBE: AtomicU64 = AtomicU64::new(1);
const IRQ_POLL_PROBE_IDLE: u8 = 0;
const IRQ_POLL_PROBE_ARMED: u8 = 1;
const IRQ_POLL_PROBE_IRQ_RECORDED: u8 = 2;
const IRQ_POLL_PROBE_COMPLETE: u8 = 3;
static IRQ_POLL_PROBE_PHASE: AtomicU8 = AtomicU8::new(IRQ_POLL_PROBE_IDLE);

fn next_irq_poll_probe_generation() -> u64 {
    NEXT_IRQ_POLL_PROBE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("IRQ-to-poll probe generation space exhausted")
}

/// A task-owned, one-shot measurement of timer IRQ entry to its next poll.
///
/// Arm this from inside the target task immediately before awaiting a timer:
///
/// ```ignore
/// let probe = arm_irq_poll_probe()?;
/// sleep_ms(1).await;
/// let ticks = probe.finish().expect("the timer IRQ woke this task");
/// ```
///
/// The first timer this task registers after arming is bound to the probe; only
/// that exact timer starts the clock when it becomes due. The
/// endpoint is captured immediately before the executor invokes the task's
/// next `Future::poll`, so unrelated heartbeat interrupts cannot poison a
/// sample. Dropping the token disarms it; task cancellation and fault cleanup
/// also clear it through the executor's ownership ledger.
pub struct IrqPollProbe {
    generation: u64,
    target: TaskId,
    owned_registration: Option<u64>,
    active: bool,
}

impl IrqPollProbe {
    /// Read the completed sample without disarming the probe.
    pub fn sample(&self) -> Option<u64> {
        let probe = IRQ_POLL_PROBE.lock();
        (self.active && probe.generation == self.generation && probe.target == Some(self.target))
            .then_some(probe.sample)
            .flatten()
    }

    /// Return the completed timer-tick sample and release the global slot.
    ///
    /// `None` means the token was dropped/finished before a matching timer IRQ
    /// followed by a target poll.
    pub fn finish(mut self) -> Option<u64> {
        let sample = self.sample();
        self.deactivate();
        sample
    }

    fn deactivate(&mut self) {
        if !self.active {
            return;
        }
        clear_irq_poll_probe(self.generation);
        disarm_owned_for_task(self.target, self.owned_registration.take());
        self.active = false;
    }
}

impl Drop for IrqPollProbe {
    fn drop(&mut self) {
        self.deactivate();
    }
}

/// Arm the single allocation-free IRQ-to-poll profiler for the current task.
pub fn arm_irq_poll_probe() -> Result<IrqPollProbe, IrqPollProbeError> {
    let hart = current_scheduler_hart().ok_or(IrqPollProbeError::NotInTask)?;
    let current_status = CURRENT_TASK_STATUS[hart.index()]
        .lock()
        .clone()
        .ok_or(IrqPollProbeError::NotInTask)?;
    let target = {
        let sched = SCHED.lock();
        sched.harts[hart.index()]
            .running
            .as_ref()
            .filter(|running| Arc::ptr_eq(&running.status, &current_status))
            .map(|running| running.id)
            .ok_or(IrqPollProbeError::NotInTask)?
    };
    let generation = next_irq_poll_probe_generation();

    // Cleanup records are executor infrastructure even when the task itself is
    // using a reclaimable component arena.
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let owned_registration = current_status
        .register_owned(OwnedRegistration::IrqPollProbe { generation })
        .map_err(|_| IrqPollProbeError::RegistrationFailed)?;
    let mut probe = IRQ_POLL_PROBE.lock();
    if probe.target.is_some() {
        drop(probe);
        drop(current_status.disarm_owned(owned_registration));
        system.restore();
        return Err(IrqPollProbeError::Busy);
    }
    *probe = IrqPollProbeState {
        generation,
        target: Some(target),
        timer_id: None,
        irq_entry: None,
        sample: None,
    };
    IRQ_POLL_PROBE_PHASE.store(IRQ_POLL_PROBE_ARMED, Ordering::Release);
    drop(probe);
    system.restore();

    Ok(IrqPollProbe {
        generation,
        target,
        owned_registration: Some(owned_registration),
        active: true,
    })
}

/// Number of active profiling slots (currently always zero or one).
pub fn irq_poll_probe_count() -> usize {
    usize::from(IRQ_POLL_PROBE_PHASE.load(Ordering::Acquire) != IRQ_POLL_PROBE_IDLE)
}

fn clear_irq_poll_probe(generation: u64) {
    let mut probe = IRQ_POLL_PROBE.lock();
    if probe.target.is_some() && probe.generation == generation {
        *probe = IrqPollProbeState::EMPTY;
        IRQ_POLL_PROBE_PHASE.store(IRQ_POLL_PROBE_IDLE, Ordering::Release);
    }
}

fn bind_timer_to_probe(task: Option<TaskId>, timer_id: u64) {
    let Some(task) = task else {
        return;
    };
    if IRQ_POLL_PROBE_PHASE.load(Ordering::Acquire) != IRQ_POLL_PROBE_ARMED {
        return;
    }
    let mut probe = IRQ_POLL_PROBE.lock();
    if probe.target == Some(task) && probe.timer_id.is_none() {
        probe.timer_id = Some(timer_id);
    }
}

fn record_timer_irq_for_probe(task: TaskId, timer_id: u64, irq_entry: u64) {
    if IRQ_POLL_PROBE_PHASE.load(Ordering::Acquire) != IRQ_POLL_PROBE_ARMED {
        return;
    }
    let mut probe = IRQ_POLL_PROBE.lock();
    if probe.target == Some(task)
        && probe.timer_id == Some(timer_id)
        && probe.irq_entry.is_none()
        && probe.sample.is_none()
    {
        probe.irq_entry = Some(irq_entry);
        IRQ_POLL_PROBE_PHASE.store(IRQ_POLL_PROBE_IRQ_RECORDED, Ordering::Release);
    }
}

fn complete_irq_poll_probe(task: TaskId) {
    // The common scheduler path does only this load; inactive and merely
    // armed probes do not add a timer read or lock to unrelated task polls.
    if IRQ_POLL_PROBE_PHASE.load(Ordering::Acquire) != IRQ_POLL_PROBE_IRQ_RECORDED {
        return;
    }
    // Capture the endpoint before taking the profiling lock: the intended
    // endpoint is entry to Future::poll, not completion of bookkeeping.
    let poll_entry = arch::time();
    let mut probe = IRQ_POLL_PROBE.lock();
    if probe.target == Some(task) && probe.sample.is_none() {
        if let Some(irq_entry) = probe.irq_entry {
            probe.sample = Some(poll_entry.saturating_sub(irq_entry));
            IRQ_POLL_PROBE_PHASE.store(IRQ_POLL_PROBE_COMPLETE, Ordering::Release);
        }
    }
}

// --- Timers ---

struct TimerEntry {
    id: u64,
    deadline: u64,
    task: Option<TaskId>,
    waker: Waker,
}

// Entries are ordered by descending deadline, so the next deadline is the
// final element and timer IRQ handling can pop without allocating.
static TIMERS: SpinLock<Vec<TimerEntry>> = SpinLock::new(Vec::new());
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

fn next_timer_id() -> u64 {
    NEXT_TIMER_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("timer registration space exhausted")
}

fn arm_locked(timers: &[TimerEntry]) {
    let heartbeat = arch::time().saturating_add(HEARTBEAT_SECS.saturating_mul(timebase_hz()));
    let next = timers.last().map(|timer| timer.deadline);
    arch::set_timer(next.map_or(heartbeat, |deadline| deadline.min(heartbeat)));
}

fn unregister_timer(id: u64) -> Option<Waker> {
    let removed = {
        let mut timers = TIMERS.lock();
        let removed = timers
            .iter()
            .position(|timer| timer.id == id)
            .map(|index| timers.remove(index).waker);
        if removed.is_some() {
            arm_locked(&timers);
        }
        removed
    };
    // See WaitQueue::unregister: Waker Drop must run outside registry locks.
    removed
}

fn cleanup_owned_registration(
    registration: OwnedRegistration,
    detach_reason: Option<TaskDetachReason>,
) {
    match registration {
        OwnedRegistration::Wait { queue, id } => {
            // Safety: the WaitFuture that registered this token remains inside
            // its still-allocated task arena until every ledger is drained.
            let queue = unsafe { &*(queue as *const WaitQueue) };
            drop(queue.unregister(id));
        }
        OwnedRegistration::OneShotWait { queue, generation } => {
            // Safety: the future containing this token remains allocated until
            // the executor drains its TaskStatus ledger. The queue itself is
            // required to live in SYSTEM-stable supervisor storage.
            let queue = unsafe { &*(queue as *const OneShotWaitQueue) };
            drop(queue.unregister(generation));
        }
        OwnedRegistration::Timer { id } => drop(unregister_timer(id)),
        OwnedRegistration::Join { status, id } => drop(status.unregister_joiner(id)),
        OwnedRegistration::IrqPollProbe { generation } => clear_irq_poll_probe(generation),
        OwnedRegistration::TaskDetach {
            target,
            task,
            domain,
        } => {
            // Safety: registration required a kernel-static callback and a
            // generational SYSTEM context. `drain_task_registrations` invokes
            // this arm only after removing all ordinary wake edges.
            let reason = detach_reason.expect("task detach cleanup requires terminal reason");
            unsafe { (target.notify)(target.context, task, domain, reason) };
        }
    }
}

/// Number of live sleep registrations, for scheduler diagnostics and tests.
pub fn timer_registration_count() -> usize {
    TIMERS.lock().len()
}

/// Allocation-free telemetry for the timer registry's IRQ/task lock.
pub fn timer_lock_stats() -> crate::sync::SpinLockStats {
    TIMERS.stats()
}

/// Called when no earlier architecture-specific trap timestamp is available.
/// Host tests use this entry point; real targets should call
/// [`timer_tick_at`] with a timestamp captured in their trap prologue.
pub fn timer_tick() {
    timer_tick_at(arch::time());
}

/// Wake due timers using a timestamp captured at the architecture IRQ entry.
///
/// The probe endpoint is captured immediately before the target
/// `Future::poll`; this supplied endpoint lets the measurement include trap
/// save/dispatch and all executor work between hardware entry and that poll.
pub fn timer_tick_at(irq_entry: u64) {
    loop {
        let due = {
            let mut timers = TIMERS.lock();
            if timers
                .last()
                .is_some_and(|timer| timer.deadline <= arch::time())
            {
                timers.pop()
            } else {
                arm_locked(&timers);
                None
            }
        };
        let Some(timer) = due else {
            return;
        };
        if let Some(task) = timer.task {
            record_timer_irq_for_probe(task, timer.id, irq_entry);
        }
        timer.waker.wake();
    }
}

/// How long an idle hart sleeps with nothing scheduled.
///
/// This used to be 50 ms and was load-bearing: it bounded the latency of a wake
/// lost to the check-then-sleep race in `run`. With that race closed the
/// heartbeat is only a backstop, so it can be long enough to be nearly free.
pub const HEARTBEAT_SECS: u64 = 10;

fn arm_next() {
    let timers = TIMERS.lock();
    arm_locked(&timers);
}

pub fn init_timer() {
    arm_next();
}

pub fn sleep_ms(ms: u64) -> Sleep {
    Sleep {
        deadline: arch::time().saturating_add(ms.saturating_mul(timebase_hz() / 1000)),
        registration: None,
        owned_registration: None,
    }
}

pub struct Sleep {
    deadline: u64,
    registration: Option<u64>,
    owned_registration: Option<u64>,
}

impl Future for Sleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if arch::time() >= this.deadline {
            disarm_owned_for_current(this.owned_registration.take());
            if let Some(id) = this.registration.take() {
                drop(unregister_timer(id));
            }
            return Poll::Ready(());
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        if let Some(id) = this.registration {
            let mut allocation_failed = false;
            if this.owned_registration.is_none() {
                match register_owned_for_current(OwnedRegistration::Timer { id }) {
                    Ok(token) => this.owned_registration = token,
                    Err(_) => allocation_failed = true,
                }
            }
            if allocation_failed {
                drop(candidate);
                system.restore();
                panic!("timer cleanup ledger allocation failed");
            }
            let found = {
                let mut timers = TIMERS.lock();
                if let Some(timer) = timers.iter_mut().find(|timer| timer.id == id) {
                    if !timer.waker.will_wake(cx.waker()) {
                        discarded = Some(core::mem::replace(
                            &mut timer.waker,
                            candidate.take().expect("waker candidate exists"),
                        ));
                    }
                    true
                } else {
                    false
                }
            };
            drop(discarded);
            drop(candidate);
            system.restore();
            if found {
                return Poll::Pending;
            }
            // timer_tick owns and has already woken the removed registration.
            disarm_owned_for_current(this.owned_registration.take());
            this.registration = None;
            return Poll::Ready(());
        }

        let id = next_timer_id();
        let task = current_scheduler_hart().and_then(|hart| {
            SCHED.lock().harts[hart.index()]
                .running
                .as_ref()
                .map(|running| running.id)
        });
        let mut allocation_failed = false;
        match register_owned_for_current(OwnedRegistration::Timer { id }) {
            Ok(token) => this.owned_registration = token,
            Err(_) => allocation_failed = true,
        }
        {
            let mut timers = TIMERS.lock();
            if allocation_failed || timers.try_reserve(1).is_err() {
                allocation_failed = true;
            } else {
                let index = timers
                    .iter()
                    .position(|timer| timer.deadline < this.deadline)
                    .unwrap_or(timers.len());
                timers.insert(
                    index,
                    TimerEntry {
                        id,
                        deadline: this.deadline,
                        task,
                        waker: candidate.take().expect("waker candidate exists"),
                    },
                );
                this.registration = Some(id);
                // Bind while timer IRQs are still masked by the registry lock;
                // otherwise an immediately-due timer could fire in the gap.
                bind_timer_to_probe(task, id);
                arm_locked(&timers);
            }
        }
        drop(candidate);
        system.restore();
        if allocation_failed {
            panic!("timer registration allocation failed");
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        disarm_owned_for_current(self.owned_registration.take());
        if let Some(id) = self.registration.take() {
            drop(unregister_timer(id));
        }
    }
}

/// Cooperatively give the scheduler a turn.
pub fn yield_now() -> Yield {
    Yield { yielded: false }
}

pub struct Yield {
    yielded: bool,
}

impl Future for Yield {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod one_shot_wait_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    static DETACH_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DETACH_CONTEXT: AtomicUsize = AtomicUsize::new(0);
    static DETACH_TASK: AtomicUsize = AtomicUsize::new(0);
    static DETACH_REASON: AtomicUsize = AtomicUsize::new(0);
    static DETACH_QUEUE: AtomicUsize = AtomicUsize::new(0);

    unsafe fn record_task_detach(
        context: u64,
        task: TaskId,
        _domain: AllocationDomain,
        reason: TaskDetachReason,
    ) {
        let queue = DETACH_QUEUE.load(Ordering::SeqCst) as *const OneShotWaitQueue;
        if !queue.is_null() {
            // Safety: the serial test retains the queue until the synchronous
            // detach callback returns.
            assert_eq!(unsafe { (*queue).waiter_count() }, 0);
        }
        DETACH_CONTEXT.store(context as usize, Ordering::SeqCst);
        DETACH_TASK.store(task.0 as usize, Ordering::SeqCst);
        DETACH_REASON.store(
            match reason {
                TaskDetachReason::Exited => 1,
                TaskDetachReason::Cancelled => 2,
                TaskDetachReason::Faulted => 3,
            },
            Ordering::SeqCst,
        );
        DETACH_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct QueueInspectWake {
        queue: Arc<OneShotWaitQueue>,
        wakes: Arc<AtomicUsize>,
        waiters_seen: Arc<AtomicUsize>,
    }

    impl Wake for QueueInspectWake {
        fn wake(self: Arc<Self>) {
            self.waiters_seen
                .store(self.queue.waiter_count(), Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct QueueInspectDrop {
        queue: Arc<OneShotWaitQueue>,
        drops: Arc<AtomicUsize>,
        waiters_seen: Arc<AtomicUsize>,
    }

    impl Wake for QueueInspectDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for QueueInspectDrop {
        fn drop(&mut self) {
            self.waiters_seen
                .store(self.queue.waiter_count(), Ordering::SeqCst);
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn prepared_detach_and_wait_capacity_exist_before_publication() {
        let _serial = EXECUTOR_TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::arch::set_test_hart_id(0);
        DETACH_CONTEXT.store(0, Ordering::SeqCst);
        run_until_idle(10_000);

        let queue: &'static OneShotWaitQueue = Box::leak(Box::new(OneShotWaitQueue::new()));
        let detach = unsafe { TaskDetachTarget::new(700, record_task_detach) };
        let mut batch = PreparedTaskBatch::new();
        batch.prepare("prepared-edge-supervisor", async move {
            queue.wait(1).await.expect("fixed edge remains exact");
            assert_eq!(
                disarm_current_task_detach(detach),
                TaskDetachDisarm::Disarmed
            );
        });

        assert!(!batch.install_prepared_task_detach(1, detach));
        assert!(batch.install_prepared_task_detach(0, detach));
        assert!(!batch.install_prepared_task_detach(0, detach));
        assert!(!batch.try_reserve_prepared_task_registrations(0, 0));
        assert!(!batch.try_reserve_prepared_task_registrations(0, 3));
        assert!(!batch.try_reserve_prepared_task_registrations(1, 1));
        assert!(batch.try_reserve_prepared_task_registrations(0, 1));

        let waiter_capacity = batch.prepared_handles()[0]
            .status
            .registrations
            .lock()
            .capacity();
        let handles = batch.publish().expect("prepared edge supervisor publishes");
        run_until_idle(10_000);

        assert_eq!(queue.waiter_count(), 1);
        assert_eq!(handles[0].status.registrations.lock().len(), 2);
        assert_eq!(
            handles[0].status.registrations.lock().capacity(),
            waiter_capacity,
            "waiting did not grow the supervisor outbound ledger"
        );
        assert!(!batch.try_reserve_prepared_task_registrations(0, 1));

        let lost = queue
            .publish(1)
            .expect("first publication detaches the waiter");
        assert_eq!(queue.waiter_count(), 0);
        drop(lost);
        assert_eq!(handles[0].state(), TaskState::Running);
        assert!(
            queue.publish(1).unwrap().dispatch(),
            "same-generation replay uses the retained exact TaskStatus wake"
        );
        run_until_idle(10_000);
        assert_eq!(handles[0].state(), TaskState::Exited);
        assert_eq!(queue.waiter_count(), 0);
        assert!(handles[0].status.registrations.lock().is_empty());
        assert_eq!(
            DETACH_CONTEXT.load(Ordering::SeqCst),
            0,
            "normal supervisor exit disarmed its preinstalled callback"
        );
    }

    #[test]
    fn task_detach_is_exact_bounded_and_runs_after_ordinary_wait_cleanup() {
        let _serial = EXECUTOR_TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::arch::set_test_hart_id(0);
        DETACH_CALLS.store(0, Ordering::SeqCst);
        DETACH_QUEUE.store(0, Ordering::SeqCst);

        let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(true))));
        let task = TaskId(90_000);
        let domain = heap::current_domain();
        // Safety: the serial host test stays on hart zero for the scope.
        let _task = unsafe { enter_current_task_on_hart(HartId::BOOT, task, status.clone()) };

        assert!(!try_reserve_current_task_registrations(0));
        assert!(!try_reserve_current_task_registrations(5));
        assert!(try_reserve_current_task_registrations(3));

        let target = unsafe { TaskDetachTarget::new(17, record_task_detach) };
        let registration = status
            .register_owned(OwnedRegistration::TaskDetach {
                target,
                task,
                domain,
            })
            .unwrap_or_else(|_| panic!("reserved detach registration failed"));
        let lease = CurrentTaskDetachLease {
            task,
            domain,
            status_identity: Arc::as_ptr(&status) as usize,
            registration,
            target,
        };
        assert_eq!(lease.disarm(), TaskDetachDisarm::Disarmed);

        // A copied stale token cannot consume a later registration even when
        // its callback address and task identity are otherwise unchanged.
        let next_registration = status
            .register_owned(OwnedRegistration::TaskDetach {
                target,
                task,
                domain,
            })
            .unwrap_or_else(|_| panic!("replacement detach registration failed"));
        assert_eq!(lease.disarm(), TaskDetachDisarm::AlreadyDisarmed);
        assert_eq!(status.registrations.lock().len(), 1);
        let next_lease = CurrentTaskDetachLease {
            task,
            domain,
            status_identity: Arc::as_ptr(&status) as usize,
            registration: next_registration,
            target,
        };
        assert_eq!(next_lease.disarm(), TaskDetachDisarm::Disarmed);
        assert_eq!(next_lease.disarm(), TaskDetachDisarm::AlreadyDisarmed);

        let queue = OneShotWaitQueue::new();
        let wake = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(wake);
        DETACH_QUEUE.store(
            (&queue as *const OneShotWaitQueue) as usize,
            Ordering::SeqCst,
        );
        for (index, reason) in [
            TaskDetachReason::Exited,
            TaskDetachReason::Cancelled,
            TaskDetachReason::Faulted,
        ]
        .into_iter()
        .enumerate()
        {
            let mut listener = Box::pin(queue.wait(index as u64 + 1));
            assert_eq!(
                listener.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Pending
            );
            let target = unsafe { TaskDetachTarget::new(index as u64 + 101, record_task_detach) };
            status
                .register_owned(OwnedRegistration::TaskDetach {
                    target,
                    task,
                    domain,
                })
                .unwrap_or_else(|_| panic!("reserved reason registration failed"));
            let before = DETACH_CALLS.load(Ordering::SeqCst);
            drain_task_registrations(&status, reason);
            assert_eq!(DETACH_CALLS.load(Ordering::SeqCst), before + 1);
            assert_eq!(DETACH_CONTEXT.load(Ordering::SeqCst), index + 101);
            assert_eq!(DETACH_TASK.load(Ordering::SeqCst), task.0 as usize);
            assert_eq!(DETACH_REASON.load(Ordering::SeqCst), index + 1);
            assert_eq!(queue.waiter_count(), 0);
            assert!(status.registrations.lock().is_empty());
            drop(listener);
            assert_eq!(DETACH_CALLS.load(Ordering::SeqCst), before + 1);
        }
        DETACH_QUEUE.store(0, Ordering::SeqCst);
    }

    #[test]
    fn one_shot_wait_is_bounded_generation_safe_and_task_owned() {
        let _serial = EXECUTOR_TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::arch::set_test_hart_id(0);
        let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(true))));
        // Safety: this host test remains on physical/logical hart zero until
        // the scope is dropped and installs no competing current-task scope.
        let _task =
            unsafe { enter_current_task_on_hart(HartId::BOOT, TaskId(90_001), status.clone()) };

        let queue = Arc::new(OneShotWaitQueue::new());
        let first = Arc::new(CountWake(AtomicUsize::new(0)));
        let second = Arc::new(CountWake(AtomicUsize::new(0)));
        let first_waker = Waker::from(first.clone());
        let second_waker = Waker::from(second.clone());
        let first_baseline = Arc::strong_count(&first);
        let second_baseline = Arc::strong_count(&second);
        let mut listener = Box::pin(queue.wait(1));

        assert_eq!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Pending
        );
        assert_eq!(queue.waiter_count(), 1);
        assert_eq!(status.registrations.lock().len(), 1);
        assert_eq!(Arc::strong_count(&first), first_baseline + 1);

        assert_eq!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker)),
            Poll::Pending
        );
        assert_eq!(queue.waiter_count(), 1, "repoll keeps the same slot");
        assert_eq!(status.registrations.lock().len(), 1);
        assert_eq!(Arc::strong_count(&first), first_baseline);
        assert_eq!(Arc::strong_count(&second), second_baseline + 1);

        let mut contender = Box::pin(queue.wait(1));
        assert_eq!(
            contender
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(Err(OneShotWaitError::CapacityExceeded))
        );
        assert_eq!(queue.waiter_count(), 1);
        assert_eq!(status.registrations.lock().len(), 1);

        assert!(queue.publish(1).unwrap().dispatch());
        assert_eq!(queue.waiter_count(), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker)),
            Poll::Ready(Ok(()))
        );
        assert!(status.registrations.lock().is_empty());

        // Listener-before-recheck observes an event that lands before poll and
        // never installs a waiter or cleanup edge.
        let mut prewake = Box::pin(queue.wait(2));
        assert!(!queue.publish(2).unwrap().dispatch());
        assert_eq!(
            prewake
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(Ok(()))
        );
        assert_eq!(queue.waiter_count(), 0);
        assert!(status.registrations.lock().is_empty());

        // A stale cleanup token cannot remove a replacement registered after
        // a wake advanced the event epoch.
        let mut stale = Box::pin(queue.wait(3));
        assert_eq!(
            stale.as_mut().poll(&mut Context::from_waker(&first_waker)),
            Poll::Pending
        );
        let stale_generation = stale
            .registration_generation
            .expect("pending listener has a generation");
        let delayed = queue.publish(3).unwrap();
        let mut replacement = Box::pin(queue.wait(4));
        assert_eq!(
            replacement
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker)),
            Poll::Pending
        );
        cleanup_owned_registration(
            OwnedRegistration::OneShotWait {
                queue: Arc::as_ptr(&queue) as usize,
                generation: stale_generation,
            },
            None,
        );
        assert_eq!(queue.waiter_count(), 1, "stale generation is inert");
        assert!(delayed.dispatch());
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            queue.waiter_count(),
            1,
            "delayed wake preserves replacement"
        );
        assert!(
            matches!(
                queue.publish(5),
                Err(OneShotWaitError::RegistrationMismatch)
            ),
            "a different event cannot consume the installed waiter"
        );
        assert_eq!(
            stale.as_mut().poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(Ok(()))
        );
        assert!(queue.publish(4).unwrap().dispatch());
        assert_eq!(
            replacement
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker)),
            Poll::Ready(Ok(()))
        );
        assert!(status.registrations.lock().is_empty());

        // Permanent task detach drains the TaskStatus edge and the queue slot
        // before the future itself is destroyed. Its Drop remains idempotent.
        let mut detached = Box::pin(queue.wait(5));
        assert_eq!(
            detached
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Pending
        );
        assert_eq!(queue.waiter_count(), 1);
        drain_task_registrations(&status, TaskDetachReason::Cancelled);
        assert_eq!(queue.waiter_count(), 0);
        assert!(status.registrations.lock().is_empty());
        drop(detached);
        assert_eq!(queue.waiter_count(), 0);

        drop(_task);
        let unowned_queue = OneShotWaitQueue::new();
        let mut unowned = Box::pin(unowned_queue.wait(1));
        assert_eq!(
            unowned
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(Err(OneShotWaitError::NotInTask))
        );
        assert_eq!(unowned_queue.waiter_count(), 0);

        let mut zero = Box::pin(unowned_queue.wait(0));
        assert_eq!(
            zero.as_mut().poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(Err(OneShotWaitError::RegistrationMismatch))
        );
        assert_eq!(unowned_queue.waiter_count(), 0);
    }

    #[test]
    fn one_shot_wake_and_replaced_waker_drop_reenter_outside_the_lock() {
        let _serial = EXECUTOR_TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::arch::set_test_hart_id(0);
        let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(true))));
        // Safety: this host test remains on physical/logical hart zero until
        // the scope is dropped and installs no competing current-task scope.
        let _task =
            unsafe { enter_current_task_on_hart(HartId::BOOT, TaskId(90_002), status.clone()) };
        let queue = Arc::new(OneShotWaitQueue::new());

        let drops = Arc::new(AtomicUsize::new(0));
        let drop_waiters = Arc::new(AtomicUsize::new(usize::MAX));
        let first_waker = Waker::from(Arc::new(QueueInspectDrop {
            queue: queue.clone(),
            drops: drops.clone(),
            waiters_seen: drop_waiters.clone(),
        }));
        let replacement_counter = Arc::new(CountWake(AtomicUsize::new(0)));
        let replacement_waker = Waker::from(replacement_counter.clone());
        let mut listener = Box::pin(queue.wait(1));

        assert_eq!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Pending
        );
        drop(first_waker);
        assert_eq!(
            listener
                .as_mut()
                .poll(&mut Context::from_waker(&replacement_waker)),
            Poll::Pending
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            drop_waiters.load(Ordering::SeqCst),
            1,
            "replaced Waker Drop re-entered after installing its replacement"
        );
        assert!(queue.publish(1).unwrap().dispatch());
        assert_eq!(replacement_counter.0.load(Ordering::SeqCst), 1);

        let wakes = Arc::new(AtomicUsize::new(0));
        let wake_waiters = Arc::new(AtomicUsize::new(usize::MAX));
        let inspect_waker = Waker::from(Arc::new(QueueInspectWake {
            queue: queue.clone(),
            wakes: wakes.clone(),
            waiters_seen: wake_waiters.clone(),
        }));
        let mut inspect_listener = Box::pin(queue.wait(2));
        assert_eq!(
            inspect_listener
                .as_mut()
                .poll(&mut Context::from_waker(&inspect_waker)),
            Poll::Pending
        );
        assert!(queue.publish(2).unwrap().dispatch());
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        assert_eq!(
            wake_waiters.load(Ordering::SeqCst),
            0,
            "wake callback re-entered the already-drained queue"
        );
    }
}

#[cfg(test)]
mod reclaimable_domain_tests {
    use super::*;

    #[test]
    fn prepared_binding_rejects_a_same_number_counterfeit_status() {
        let domain = AllocationDomain::new(OwnerId::new(90), ArenaId::new(91));
        let publication = Arc::new(AtomicBool::new(false));
        let status = Arc::new(TaskStatus::new(publication.clone()));
        let task = TaskId(9_000);
        let handle = TaskHandle {
            id: task,
            domain,
            status: status.clone(),
        };
        let binding = PreparedReclaimableBinding {
            batch: 7,
            task,
            domain,
            home_hart: HartId::BOOT,
            status_identity: Arc::as_ptr(&status) as usize,
            instance: None,
            scheduler: None,
        };
        let counterfeit = TaskHandle {
            id: task,
            domain,
            status: Arc::new(TaskStatus::new(publication)),
        };
        let retained = handle.clone();

        assert!(binding.matches_handle(&handle));
        assert!(!binding.matches_handle(&counterfeit));
        assert!(handle.shares_status_with(&retained));
        assert!(!handle.shares_status_with(&counterfeit));
    }

    #[test]
    fn failed_staged_batch_admission_does_not_advance_the_live_table() {
        let first_domain = AllocationDomain::new(OwnerId::new(94), ArenaId::new(95));
        let conflicting_domain = AllocationDomain::new(OwnerId::new(96), first_domain.arena);
        let home = HartId::BOOT;
        let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(false))));
        let live = ReclaimableDomains::new();
        let generations_before = live.generations;
        let mut staged = live;

        staged
            .admit(
                first_domain,
                home,
                ReclaimableDomainMode::Exclusive,
                TaskId(9_003),
                &status,
                None,
            )
            .unwrap();
        assert!(matches!(
            staged.admit(
                conflicting_domain,
                home,
                ReclaimableDomainMode::Exclusive,
                TaskId(9_004),
                &status,
                None,
            ),
            Err(ReclaimableDomainError::DomainMismatch)
        ));

        assert_eq!(live.active_count(), 0);
        assert_eq!(live.generations, generations_before);
        assert!(live.record(first_domain).is_none());
        assert!(live.record(conflicting_domain).is_none());
    }

    #[test]
    fn full_staged_domain_table_fails_without_touching_the_source_copy() {
        let home = HartId::BOOT;
        let status = Arc::new(TaskStatus::new(Arc::new(AtomicBool::new(false))));
        let mut live = ReclaimableDomains::new();
        for index in 0..heap::MAX_ALLOCATION_ARENAS {
            live.admit(
                AllocationDomain::new(
                    OwnerId::new(10_000 + index as u64),
                    ArenaId::new(20_000 + index as u64),
                ),
                home,
                ReclaimableDomainMode::Exclusive,
                TaskId(30_000 + index as u64),
                &status,
                None,
            )
            .unwrap();
        }
        let generations_before = live.generations;
        let mut staged = live;
        let overflow = AllocationDomain::new(OwnerId::new(40_000), ArenaId::new(50_000));

        assert!(matches!(
            staged.admit(
                overflow,
                home,
                ReclaimableDomainMode::Exclusive,
                TaskId(60_000),
                &status,
                None,
            ),
            Err(ReclaimableDomainError::TableFull)
        ));
        assert_eq!(live.active_count(), heap::MAX_ALLOCATION_ARENAS);
        assert_eq!(live.generations, generations_before);
        assert!(live.record(overflow).is_none());
    }

    #[test]
    fn stale_domain_generation_cannot_resolve_a_reused_slot() {
        let first_domain = AllocationDomain::new(OwnerId::new(91), ArenaId::new(92));
        let second_domain = AllocationDomain::new(OwnerId::new(93), first_domain.arena);
        let home = HartId::new(0).unwrap();
        let published = Arc::new(AtomicBool::new(true));
        let first_status = Arc::new(TaskStatus::new(published.clone()));
        let second_status = Arc::new(TaskStatus::new(published));
        let first_task = TaskId(9_001);
        let second_task = TaskId(9_002);
        let mut domains = ReclaimableDomains::new();

        let stale = domains
            .admit(
                first_domain,
                home,
                ReclaimableDomainMode::Exclusive,
                first_task,
                &first_status,
                None,
            )
            .unwrap();
        domains.records[stale.slot as usize].as_mut().unwrap().phase =
            ReclaimableDomainPhase::TerminalReady;
        domains.retire_terminal(stale, first_domain).unwrap();

        let current = domains
            .admit(
                second_domain,
                home,
                ReclaimableDomainMode::Exclusive,
                second_task,
                &second_status,
                None,
            )
            .unwrap();
        assert_eq!(current.slot, stale.slot);
        assert_ne!(current.generation, stale.generation);
        assert!(matches!(
            domains.record_exact(stale, second_domain),
            Err(ReclaimableDomainError::KeyMismatch)
        ));
        assert!(matches!(
            domains.validate_active_task(
                stale,
                second_domain,
                home,
                second_task,
                &second_status,
                None,
            ),
            Err(ReclaimableDomainError::KeyMismatch)
        ));
        assert!(matches!(
            domains.validate_active_task(
                current,
                second_domain,
                home,
                first_task,
                &first_status,
                None,
            ),
            Err(ReclaimableDomainError::TaskMismatch)
        ));
    }
}
