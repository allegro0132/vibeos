//! The VibeOS scheduler.
//!
//! There are no kernel threads and no preemption. The unit of scheduling is a
//! `Future`; a task runs until it returns `Pending`, at which point its stack
//! is gone and all that remains is the state machine the compiler built. Wakeups
//! come from interrupt handlers, so "blocking" costs a queue push instead of a
//! context switch.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::arch;
use crate::sync::SpinLock;

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
}

impl TaskStatus {
    fn new() -> Self {
        Self {
            polls: AtomicU64::new(0),
            state: AtomicU8::new(TaskState::Running as u8),
            next_joiner: AtomicU64::new(1),
            joiners: SpinLock::new(Vec::new()),
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
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
    status: Arc<TaskStatus>,
}

impl TaskHandle {
    pub fn id(&self) -> TaskId {
        self.id
    }

    pub fn state(&self) -> TaskState {
        self.status.state()
    }

    pub fn polls(&self) -> u64 {
        self.status.polls.load(Ordering::Acquire)
    }

    /// Request cooperative cancellation.
    ///
    /// A ready or parked task is reclaimed before this call returns. A task
    /// currently inside `Future::poll` observes the request at that poll's
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
        }
    }
}

pub struct Join {
    id: TaskId,
    status: Arc<TaskStatus>,
    registration: Option<u64>,
}

impl Future for Join {
    type Output = TaskExit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let state = this.status.state();
        if state != TaskState::Running {
            if let Some(id) = this.registration.take() {
                this.status.joiners.lock().retain(|waiter| waiter.id != id);
            }
            return Poll::Ready(TaskExit::new(
                this.id,
                state,
                this.status.polls.load(Ordering::Acquire),
            ));
        }

        // Register under the waiter lock, then re-read the terminal state.
        // `finish` publishes before acquiring this lock, so either this read
        // observes the terminal state or `finish` drains the waker we insert.
        let status = this.status.clone();
        let mut joiners = status.joiners.lock();
        let state = status.state();
        if state != TaskState::Running {
            if let Some(id) = this.registration.take() {
                joiners.retain(|waiter| waiter.id != id);
            }
            drop(joiners);
            return Poll::Ready(TaskExit::new(
                this.id,
                state,
                status.polls.load(Ordering::Acquire),
            ));
        }

        match this.registration {
            Some(id) => {
                if let Some(waiter) = joiners.iter_mut().find(|waiter| waiter.id == id) {
                    if !waiter.waker.will_wake(cx.waker()) {
                        waiter.waker = cx.waker().clone();
                    }
                } else {
                    joiners.push(JoinWaiter {
                        id,
                        waker: cx.waker().clone(),
                    });
                }
            }
            None => {
                let id = status.next_joiner_id();
                joiners.push(JoinWaiter {
                    id,
                    waker: cx.waker().clone(),
                });
                this.registration = Some(id);
            }
        }
        Poll::Pending
    }
}

impl Drop for Join {
    fn drop(&mut self) {
        if let Some(id) = self.registration.take() {
            self.status.joiners.lock().retain(|waiter| waiter.id != id);
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaskReport {
    pub id: TaskId,
    pub name: String,
    pub state: TaskState,
    pub polls: u64,
}

struct Task {
    name: String,
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    status: Arc<TaskStatus>,
}

/// Runs `f` with a landing pad installed, returning true if `f` faulted.
///
/// The kernel supplies this; `core` cannot, because a landing pad is
/// architecture-specific assembly. On the host there is none, and a panicking
/// task simply fails the test — which is the right behaviour there.
pub type FaultGuard = fn(&mut dyn FnMut()) -> bool;

static FAULT_GUARD: SpinLock<Option<FaultGuard>> = SpinLock::new(None);

pub fn set_fault_guard(guard: FaultGuard) {
    *FAULT_GUARD.lock() = Some(guard);
}

struct Sched {
    tasks: BTreeMap<TaskId, Task>,
    ready: VecDeque<TaskId>,
    /// The task being polled right now. It is lifted out of `tasks` for the
    /// duration of the poll, so both introspection and `wake` have to look
    /// for it here rather than in the map.
    running: Option<(TaskId, String, Arc<TaskStatus>)>,
    /// Set when the running task is woken while it is being polled — by itself
    /// (`yield_now`) or by an interrupt that lands mid-poll. Without this the
    /// wake would be dropped and the task would never be scheduled again.
    running_woken: bool,
    completed: u64,
    faulted: u64,
    cancelled: u64,
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    tasks: BTreeMap::new(),
    ready: VecDeque::new(),
    running: None,
    running_woken: false,
    completed: 0,
    faulted: 0,
    cancelled: 0,
});

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn next_task_id() -> TaskId {
    let id = NEXT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .expect("TaskId space exhausted");
    TaskId(id)
}

/// Spawn a future as a task. Safe to call from inside another task.
pub fn spawn(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskId {
    spawn_tracked(name, fut).id()
}

/// Spawn a future and retain a handle suitable for a supervising component.
pub fn spawn_tracked(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskHandle {
    let id = next_task_id();
    let status = Arc::new(TaskStatus::new());
    let task = Task {
        name: String::from(name),
        future: Box::pin(fut),
        status: status.clone(),
    };
    let mut s = SCHED.lock();
    // Every live task can become ready at once. Reserve that upper bound in
    // task context so an IRQ wake never grows the ready queue while holding
    // SCHED. A currently polled task is outside `tasks` and counts separately.
    let live_after_spawn = s.tasks.len() + 1 + usize::from(s.running.is_some());
    let ready_additional = live_after_spawn - s.ready.len();
    if s.ready.capacity() < live_after_spawn && s.ready.try_reserve(ready_additional).is_err() {
        drop(s);
        drop(task);
        panic!("ready queue allocation failed");
    }
    s.tasks.insert(id, task);
    s.ready.push_back(id);
    TaskHandle { id, status }
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
    Some(claim.state)
}

/// Drop a normally suspended/completed future behind the same fault domain as
/// polling it. The task metadata is reclaimed first; if the future destructor
/// faults, the landing pad leaves its Option empty and the interrupted future
/// allocation is deliberately leaked rather than dropped a second time.
fn reclaim_task(task: Task) -> bool {
    let Task {
        name,
        future,
        status,
    } = task;
    drop(name);
    drop(status);

    let guard = *FAULT_GUARD.lock();
    match guard {
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
    }
}

fn reclaim_and_publish(task: Task, status: &TaskStatus, claim: TerminalClaim) {
    let destructor_faulted = reclaim_task(task);
    let claim = if destructor_faulted {
        status.promote_to_fault(claim)
    } else {
        claim
    };
    publish_terminal(status, claim);
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

    // Ready and parked tasks can be detached synchronously. A running task is
    // cooperative: only publish its request here and let `poll_once` reclaim
    // it after the current poll returns.
    let action = {
        let mut s = SCHED.lock();
        if s.running
            .as_ref()
            .is_some_and(|(id, _, _)| *id == handle.id)
        {
            Action::Return(requested_outcome(handle))
        } else if s.tasks.contains_key(&handle.id) {
            match handle.status.claim_terminal(TaskState::Cancelled) {
                Some(claim) => {
                    let task = s
                        .tasks
                        .remove(&handle.id)
                        .expect("contains_key was checked under the same lock");
                    s.ready.retain(|id| *id != handle.id);
                    Action::Reclaim(task, claim)
                }
                None => Action::Return(requested_outcome(handle)),
            }
        } else {
            match requested_outcome(handle) {
                CancelOutcome::Requested => Action::InvariantViolation,
                outcome => Action::Return(outcome),
            }
        }
    };

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

pub fn wake(id: TaskId) {
    let mut s = SCHED.lock();
    if s.running.as_ref().is_some_and(|(r, _, _)| *r == id) {
        s.running_woken = true;
    } else if s.tasks.contains_key(&id) && !s.ready.contains(&id) {
        s.ready.push_back(id);
    }
}

/// Identity and poll accounting for every live task.
pub fn task_report() -> Vec<TaskReport> {
    let s = SCHED.lock();
    let mut out: Vec<TaskReport> = s
        .tasks
        .iter()
        .map(|(id, task)| TaskReport {
            id: *id,
            name: task.name.clone(),
            state: task.status.state(),
            polls: task.status.polls.load(Ordering::Acquire),
        })
        .collect();
    out.extend(s.running.iter().map(|(id, name, status)| TaskReport {
        id: *id,
        name: name.clone(),
        state: status.state(),
        polls: status.polls.load(Ordering::Acquire),
    }));
    out.sort_by_key(|report| report.id);
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
    SCHED.lock().ready.capacity()
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
    loop {
        if poll_once() {
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
        if SCHED.lock().ready.is_empty() {
            arch::wait_for_interrupt();
        }
        arch::irq_restore(irq);
    }
}

/// Poll at most one ready task. Returns false when nothing was runnable.
///
/// Split out of `run` so tests can drive the scheduler a step at a time.
pub fn poll_once() -> bool {
    enum Dispatch {
        Poll(TaskId, Task, Arc<TaskStatus>),
        Reclaim(Task, Arc<TaskStatus>, TerminalClaim),
        Invalid(Task),
    }

    // Pop, detach, and publish `running` under one lock. This is the start-poll
    // linearization point: cancellation before it detaches the task without a
    // poll; cancellation after it waits for this poll boundary.
    let dispatch = {
        let mut s = SCHED.lock();
        let Some(id) = s.ready.pop_front() else {
            return false;
        };
        let Some(task) = s.tasks.remove(&id) else {
            return true;
        };
        let status = task.status.clone();
        if status.cancellation_requested() {
            match status.claim_terminal(TaskState::Cancelled) {
                Some(claim) => Dispatch::Reclaim(task, status, claim),
                None => Dispatch::Invalid(task),
            }
        } else if status.raw_state() == TaskState::Running as u8 {
            s.running = Some((id, task.name.clone(), status.clone()));
            s.running_woken = false;
            Dispatch::Poll(id, task, status)
        } else {
            Dispatch::Invalid(task)
        }
    };

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
    let guard = *FAULT_GUARD.lock();
    let mut poll = Poll::Pending;
    let faulted = match guard {
        Some(run_guarded) => {
            let fut = task.future.as_mut();
            let mut once = Some(fut);
            run_guarded(&mut || {
                if let Some(f) = once.take() {
                    status.polls.fetch_add(1, Ordering::Relaxed);
                    poll = f.poll(&mut cx);
                }
            })
        }
        None => {
            status.polls.fetch_add(1, Ordering::Relaxed);
            poll = task.future.as_mut().poll(&mut cx);
            false
        }
    };

    if faulted {
        // The future was interrupted mid-poll. Dropping it would run
        // destructors over state it never finished writing, so the task is
        // leaked instead: leaking is always sound, and a faulted component is
        // not going to be resumed.
        let claim = {
            let mut s = SCHED.lock();
            s.running = None;
            s.running_woken = false;
            status.claim_terminal(TaskState::Faulted)
        };
        core::mem::forget(task);
        let Some(claim) = claim else {
            panic!("a faulted running task could not claim its terminal state");
        };
        publish_terminal(&status, claim);
        return true;
    }

    let mut s = SCHED.lock();
    s.running = None;
    let woken = core::mem::take(&mut s.running_woken);
    if poll == Poll::Pending && !status.cancellation_requested() {
        // A concurrent cancel cannot slip between this decision and reinsertion:
        // it also takes SCHED, then detaches the parked task synchronously.
        s.tasks.insert(id, task);
        if woken {
            s.ready.push_back(id);
        }
        return true;
    }

    let requested = if poll == Poll::Ready(()) {
        TaskState::Exited
    } else {
        TaskState::Cancelled
    };
    let claim = status.claim_terminal(requested);
    drop(s);

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
}

impl Future for WaitFuture<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        // Cloning may invoke a custom RawWaker, so do it before taking the
        // queue lock. The unused candidate is likewise dropped afterwards.
        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        let mut allocation_failed = false;

        let result = {
            let mut inner = this.queue.inner.lock();
            if inner.epoch != this.epoch {
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

                if let Some(waiter) = inner.waiters.iter_mut().find(|waiter| waiter.id == id) {
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
        if allocation_failed {
            panic!("wait queue registration allocation failed");
        }
        result
    }
}

impl Drop for WaitFuture<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.registration.take() {
            drop(self.queue.unregister(id));
        }
    }
}

// --- Timers ---

struct TimerEntry {
    id: u64,
    deadline: u64,
    waker: Waker,
}

// Entries are ordered by descending deadline, so the next deadline is the
// final element and timer IRQ handling can pop without allocating.
static TIMERS: SpinLock<Vec<TimerEntry>> = SpinLock::new(Vec::new());
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

fn next_timer_id() -> u64 {
    NEXT_TIMER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
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

/// Number of live sleep registrations, for scheduler diagnostics and tests.
pub fn timer_registration_count() -> usize {
    TIMERS.lock().len()
}

/// Called from the timer trap. Wakes everything due and re-arms the hardware.
pub fn timer_tick() {
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
    }
}

pub struct Sleep {
    deadline: u64,
    registration: Option<u64>,
}

impl Future for Sleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if arch::time() >= this.deadline {
            if let Some(id) = this.registration.take() {
                drop(unregister_timer(id));
            }
            return Poll::Ready(());
        }

        let mut candidate = Some(cx.waker().clone());
        let mut discarded = None;
        if let Some(id) = this.registration {
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
            if found {
                return Poll::Pending;
            }
            // timer_tick owns and has already woken the removed registration.
            this.registration = None;
            return Poll::Ready(());
        }

        let id = next_timer_id();
        let mut allocation_failed = false;
        {
            let mut timers = TIMERS.lock();
            if timers.try_reserve(1).is_err() {
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
                        waker: candidate.take().expect("waker candidate exists"),
                    },
                );
                this.registration = Some(id);
                arm_locked(&timers);
            }
        }
        drop(candidate);
        if allocation_failed {
            panic!("timer registration allocation failed");
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
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
