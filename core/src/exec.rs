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
    Wait { queue: usize, id: u64 },
    Timer { id: u64 },
    Join { status: Arc<TaskStatus>, id: u64 },
    IrqPollProbe { generation: u64 },
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

    fn take_owned_registrations(&self) -> Vec<OwnedRegistrationEntry> {
        let mut registrations = self.registrations.lock();
        core::mem::take(&mut *registrations)
    }
}

static CURRENT_TASK_STATUS: [SpinLock<Option<Arc<TaskStatus>>>; MAX_HARTS] =
    [const { SpinLock::new(None) }; MAX_HARTS];

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
    previous: Option<Arc<TaskStatus>>,
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
    let previous = core::mem::replace(&mut *slot.lock(), Some(status));
    let recovery = unsafe {
        crate::sync::enter_task_recovery_context_on_hart(
            hart,
            TaskRecoveryKey::new(id.0).expect("TaskId zero is reserved"),
        )
    };
    CurrentTaskScope {
        slot,
        previous,
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
            *self.slot.lock() = self.previous.take();
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
    let status = {
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

fn drain_task_registrations(status: &TaskStatus) {
    let registrations = status.take_owned_registrations();
    for entry in registrations {
        cleanup_owned_registration(entry.registration);
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskPublication {
    Prepared(u64),
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

pub type FaultReclaimer = unsafe fn(TaskId, AllocationDomain) -> FaultReclaimOutcome;

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
    LifecycleMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReclaimableDomainKey {
    slot: u8,
    generation: u64,
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
        if let TaskPublication::Prepared(_) = task.publication {
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
    task: Option<Task>,
}

impl PreparedTask {
    pub const fn id(&self) -> TaskId {
        self.id
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedTaskBatchError {
    Empty,
    AlreadyPublished,
    Capacity,
}

/// A bounded collection of task envelopes held entirely outside the global
/// scheduler until [`publish`](Self::publish). If the preparing task faults,
/// these candidates may be conservatively leaked with that task, but no hidden
/// scheduler node, wake target, or partial pipeline is left behind.
pub struct PreparedTaskBatch {
    id: u64,
    tasks: Vec<PreparedTask>,
    handles: Vec<TaskHandle>,
    published: bool,
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
            published: false,
            publication,
        }
    }

    pub fn try_reserve(
        &mut self,
        additional: usize,
    ) -> Result<(), alloc::collections::TryReserveError> {
        assert!(!self.published, "a published task batch is immutable");
        self.tasks.try_reserve_exact(additional)?;
        self.handles.try_reserve_exact(additional)
    }

    /// Borrow opaque, non-owning lifecycle tokens for the candidates already
    /// prepared in this batch. Before publication these handles expose only
    /// identity/domain data and `is_published == false`; state, polls, joins,
    /// and cancellation remain unavailable. The batch retains every future
    /// and is the only object that can publish or roll it back.
    pub fn prepared_handles(&self) -> &[TaskHandle] {
        &self.handles
    }

    pub fn prepare(
        &mut self,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        assert!(!self.published, "a published task batch is immutable");
        let domain = heap::current_domain();
        assert!(
            !domain.arena.is_tracked(),
            "safe prepared tasks cannot enter a raw-reclaimable arena"
        );
        self.prepare_domain(domain, current_queue_hart(), true, name, fut)
    }

    fn prepare_domain(
        &mut self,
        domain: AllocationDomain,
        queue_owner: HartId,
        stealable: bool,
        name: &str,
        fut: impl Future<Output = ()> + Send + 'static,
    ) -> &PreparedTask {
        self.tasks
            .try_reserve_exact(1)
            .unwrap_or_else(|_| panic!("prepared task metadata allocation failed"));
        self.handles
            .try_reserve_exact(1)
            .unwrap_or_else(|_| panic!("prepared task handle allocation failed"));
        let (mut task, handle) = make_task(
            domain,
            queue_owner,
            stealable,
            name,
            fut,
            self.publication.clone(),
        );
        task.publication = TaskPublication::Prepared(self.id);
        let id = task.id;

        self.tasks.push(PreparedTask {
            id,
            queue_owner,
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
        if self.tasks.is_empty() {
            return Err(PreparedTaskBatchError::Empty);
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
}

impl Default for PreparedTaskBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for PreparedTaskBatch {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        for prepared in &mut self.tasks {
            if let Some(task) = prepared.task.take() {
                rollback_unpublished_task(task);
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
        let key =
            match s
                .reclaimable_domains
                .admit(domain, queue_owner, reclaimable_mode, id, &status)
            {
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
        ..
    } = task;

    // Registration targets may themselves live inside the future. Detach all
    // external references before entering user Drop: a destructor fault may
    // longjmp past the rest of that destructor, after it already destroyed a
    // WaitQueue (or another registration target). Individual future drops
    // unregister again, idempotently, on the normal path.
    drain_task_registrations(&status);
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

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    drop(name);
    drop(status);
    system.restore();
    ReclaimResult {
        id,
        domain,
        home_hart: queue_owner,
        reclaimable_domain,
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

        drain_task_registrations(&primary_status);
        if let Some(task) = primary_task.take() {
            abandon_task_without_drop(task);
        }

        let mut system = heap::enter_owner(OwnerId::SYSTEM);
        notify_fault_cleanup(primary_id, domain);
        let outcome = load_fault_reclaimer()
            .map_or(FaultReclaimOutcome::Quarantined, |reclaim| unsafe {
                reclaim(primary_id, domain)
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
        drain_task_registrations(&victim.status);
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
            reclaim(primary_id, domain)
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
                .finish_reclaimable_task(key, result.domain, result.home_hart, result.id, status)
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
                    s.begin_reclaimable_teardown(task.domain, key, hart, id, &status, true)
                        .unwrap_or_else(|error| {
                            panic!("tracked poll fault gate mismatch: {error:?}")
                        }),
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
            drain_task_registrations(&status);
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
            .validate_active_task(key, task.domain, hart, id, &status)
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

fn cleanup_owned_registration(registration: OwnedRegistration) {
    match registration {
        OwnedRegistration::Wait { queue, id } => {
            // Safety: the WaitFuture that registered this token remains inside
            // its still-allocated task arena until every ledger is drained.
            let queue = unsafe { &*(queue as *const WaitQueue) };
            drop(queue.unregister(id));
        }
        OwnedRegistration::Timer { id } => drop(unregister_timer(id)),
        OwnedRegistration::Join { status, id } => drop(status.unregister_joiner(id)),
        OwnedRegistration::IrqPollProbe { generation } => clear_irq_poll_probe(generation),
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
mod reclaimable_domain_tests {
    use super::*;

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
            )
            .unwrap();
        assert_eq!(current.slot, stale.slot);
        assert_ne!(current.generation, stale.generation);
        assert!(matches!(
            domains.record_exact(stale, second_domain),
            Err(ReclaimableDomainError::KeyMismatch)
        ));
        assert!(matches!(
            domains.validate_active_task(stale, second_domain, home, second_task, &second_status,),
            Err(ReclaimableDomainError::KeyMismatch)
        ));
        assert!(matches!(
            domains.validate_active_task(current, second_domain, home, first_task, &first_status,),
            Err(ReclaimableDomainError::TaskMismatch)
        ));
    }
}
