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
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::arch;
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
use crate::ipi;
use crate::runqueue::{EnqueueError, RunQueues};
use crate::sync::{SpinLock, TaskRecoveryContext, TaskRecoveryKey};

pub use crate::runqueue::{HartId, HartRunQueueStats, MAX_HARTS};

/// QEMU `virt` drives `mtime` at 10 MHz.
pub const TIMEBASE_HZ: u64 = 10_000_000;

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
    polls: AtomicU64,
    state: AtomicU8,
    next_joiner: AtomicU64,
    joiners: SpinLock<Vec<JoinWaiter>>,
    next_registration: AtomicU64,
    registrations: SpinLock<Vec<OwnedRegistrationEntry>>,
}

impl TaskStatus {
    fn new() -> Self {
        Self {
            polls: AtomicU64::new(0),
            state: AtomicU8::new(TaskState::Running as u8),
            next_joiner: AtomicU64::new(1),
            joiners: SpinLock::new(Vec::new()),
            next_registration: AtomicU64::new(1),
            registrations: SpinLock::new(Vec::new()),
        }
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

    pub fn state(&self) -> TaskState {
        self.status.state()
    }

    pub fn polls(&self) -> u64 {
        self.status.polls.load(Ordering::Acquire)
    }

    /// Number of tasks currently registered to join this task.
    ///
    /// This is exposed for runtime diagnostics and reclamation invariants.
    pub fn joiner_count(&self) -> usize {
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
        self.status.cancellation_requested()
    }

    pub fn try_exit(&self) -> Option<TaskExit> {
        let state = self.status.state();
        (state != TaskState::Running)
            .then(|| TaskExit::new(self.id, state, self.status.polls.load(Ordering::Acquire)))
    }

    /// Wait for return, fault, or cancellation without losing terminal state
    /// when completion races waiter registration.
    pub fn join(&self) -> Join {
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
}

/// Runs `f` with a landing pad installed, returning true if `f` faulted.
///
/// The kernel supplies this; `core` cannot, because a landing pad is
/// architecture-specific assembly. On the host there is none, and a panicking
/// task simply fails the test — which is the right behaviour there.
pub type FaultGuard = fn(&mut dyn FnMut()) -> bool;

/// Reclaim all raw allocations in one audited fault arena without running
/// their Rust destructors. The kernel installs this alongside its heap.
pub type FaultReclaimer = unsafe fn(AllocationDomain);

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

struct Sched {
    tasks: BTreeMap<TaskId, Task>,
    ready: RunQueues<TaskId>,
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
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    tasks: BTreeMap::new(),
    ready: RunQueues::new(),
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
            task.ready && task.queue_owner == owner,
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
            raw == TaskState::Running as u8 || raw == CANCEL_REQUESTED,
            "mapped task {id} has detached lifecycle phase {raw}"
        );
        debug_assert!(
            !task.domain.arena.is_tracked() || !task.stealable,
            "tracked task {id} must remain hart-affine"
        );
        debug_assert_eq!(
            s.ready.owner(*id),
            task.ready.then_some(task.queue_owner),
            "task {id} queue metadata has a second or missing owner"
        );
        if raw == CANCEL_REQUESTED {
            debug_assert!(
                task.ready,
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

fn next_task_id() -> TaskId {
    let id = NEXT_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("TaskId space exhausted");
    TaskId(id)
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

fn spawn_tracked_domain(
    domain: AllocationDomain,
    queue_owner: HartId,
    stealable: bool,
    name: &str,
    fut: impl Future<Output = ()> + Send + 'static,
) -> TaskHandle {
    let id = next_task_id();
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let status = Arc::new(TaskStatus::new());
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
    let task = Task {
        id,
        domain,
        name: task_name,
        future,
        status: status.clone(),
        queue_owner,
        ready: true,
        stealable,
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
    domain: AllocationDomain,
    primary_id: TaskId,
    primary_task: Option<Task>,
    primary_status: Arc<TaskStatus>,
    primary_claim: TerminalClaim,
) {
    debug_assert!(domain.arena.is_tracked());
    {
        let s = SCHED.lock();
        check_sched!(&s);
        assert!(
            s.running_tasks().all(|running| running.domain != domain),
            "fault teardown cannot reclaim a domain still running on another hart"
        );
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
            if task.ready {
                assert!(
                    s.ready.remove(task.queue_owner, id),
                    "fault victim ready metadata must identify its exact queue"
                );
            }
            let status = task.status.clone();
            let claim = status
                .claim_terminal(TaskState::Faulted)
                .expect("an arena sibling could not claim fault teardown");
            victims.push(FaultVictim {
                id,
                task: Some(task),
                status,
                claim,
            });
        }
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
    if let Some(reclaim) = load_fault_reclaimer() {
        unsafe { reclaim(domain) };
    }
    system.restore();

    // Publication is the teardown linearization point: a supervisor cannot
    // observe Faulted and restart the component before raw reclaim completed.
    for victim in victims {
        publish_terminal(&victim.status, victim.claim);
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
        teardown_faulted_domain(result.domain, result.id, None, status.clone(), claim);
    } else {
        if result.faulted {
            let mut system = heap::enter_owner(OwnerId::SYSTEM);
            notify_fault_cleanup(result.id, result.domain);
            system.restore();
        }
        publish_terminal(status, claim);
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

fn cancel_task(handle: &TaskHandle) -> CancelOutcome {
    enum Action {
        Reclaim(Task, TerminalClaim),
        Return(CancelOutcome),
        InvariantViolation,
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
        let action = if s.running_hart_for(handle.id).is_some() {
            Action::Return(requested_outcome(handle))
        } else if s.tasks.contains_key(&handle.id) {
            // The caller hart's running slot covers the small dispatch/return
            // windows before the current-task scope is installed or after it
            // is restored, which matters for cancellation from an IRQ hook.
            // An unmapped caller always defers instead of borrowing a logical
            // slot for user Drop and fault recovery.
            let caller_running = caller_hart.map_or_else(
                || s.running_count() != 0,
                |hart| s.harts[hart.index()].running.is_some(),
            );
            let (target_domain, target_owner) = {
                let task = s
                    .tasks
                    .get(&handle.id)
                    .expect("mapped cancellation target remains present");
                (task.domain, task.queue_owner)
            };
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
    let disposition = if let Some(task) = s.tasks.get(&id) {
        let owner = task.queue_owner;
        let ready = task.ready;
        let stealable = task.stealable;
        if ready {
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
        s.harts[hart.index()].woken = true;
        WakeDisposition::Running { hart }
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
        let total = s.tasks.len() + s.running_count();
        if out.try_reserve(total).is_err() {
            allocation_failed = true;
        } else {
            for (id, task) in &s.tasks {
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

/// Linearizable logical queue affinity for one live task. A running task owns
/// the executing hart; a ready or parked task owns its metadata hart.
pub fn task_queue_owner(id: TaskId) -> Option<HartId> {
    let s = SCHED.lock();
    s.running_hart_for(id)
        .or_else(|| s.tasks.get(&id).map(|task| task.queue_owner))
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
        let claim = {
            let mut s = SCHED.lock();
            debug_assert!(s.harts[hart.index()]
                .running
                .as_ref()
                .is_some_and(|running| {
                    running.id == id
                        && running.hart == hart
                        && running.domain == task.domain
                        && Arc::ptr_eq(&running.status, &status)
                }));
            s.clear_running(hart);
            s.harts[hart.index()].woken = false;
            if task.domain.arena.is_tracked() {
                assert!(
                    s.running_tasks()
                        .all(|running| running.domain != task.domain),
                    "a tracked fault domain is concurrently running on another hart"
                );
            }
            let claim = status.claim_terminal(TaskState::Faulted);
            check_sched!(&s);
            check_status_detached!(&s, status.as_ref());
            claim
        };
        // Safety: this remains inside the same hart-pinned executor turn.
        unsafe { system.restore_on_verified_hart() };
        let Some(claim) = claim else {
            panic!("a faulted running task could not claim its terminal state");
        };
        if task.domain.arena.is_tracked() {
            let domain = task.domain;
            teardown_faulted_domain(domain, id, Some(task), status, claim);
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
    let heartbeat = arch::time().saturating_add(HEARTBEAT_SECS.saturating_mul(TIMEBASE_HZ));
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
        deadline: arch::time().saturating_add(ms.saturating_mul(TIMEBASE_HZ / 1000)),
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
