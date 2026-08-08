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
use core::mem::ManuallyDrop;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::arch;
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
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

#[derive(Clone)]
enum OwnedRegistration {
    Wait { queue: usize, id: u64 },
    Timer { id: u64 },
    Join { status: Arc<TaskStatus>, id: u64 },
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
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
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

static CURRENT_TASK_STATUS: SpinLock<Option<Arc<TaskStatus>>> = SpinLock::new(None);

struct CurrentTaskScope {
    previous: Option<Arc<TaskStatus>>,
    active: bool,
}

fn enter_current_task(status: Arc<TaskStatus>) -> CurrentTaskScope {
    let previous = core::mem::replace(&mut *CURRENT_TASK_STATUS.lock(), Some(status));
    CurrentTaskScope {
        previous,
        active: true,
    }
}

impl CurrentTaskScope {
    fn restore(&mut self) {
        if self.active {
            *CURRENT_TASK_STATUS.lock() = self.previous.take();
            self.active = false;
        }
    }
}

impl Drop for CurrentTaskScope {
    fn drop(&mut self) {
        self.restore();
    }
}

fn register_owned_for_current(
    registration: OwnedRegistration,
) -> Result<Option<u64>, OwnedRegistration> {
    let status = CURRENT_TASK_STATUS.lock().clone();
    match status {
        Some(status) => status.register_owned(registration).map(Some),
        None => Ok(None),
    }
}

fn disarm_owned_for_current(token: Option<u64>) {
    let Some(token) = token else {
        return;
    };
    if let Some(status) = CURRENT_TASK_STATUS.lock().clone() {
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
    domain: AllocationDomain,
    name: Arc<str>,
    future: ManuallyDrop<Pin<Box<dyn Future<Output = ()> + Send>>>,
    status: Arc<TaskStatus>,
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

static FAULT_GUARD: SpinLock<Option<FaultGuard>> = SpinLock::new(None);
static FAULT_RECLAIMER: SpinLock<Option<FaultReclaimer>> = SpinLock::new(None);

pub fn set_fault_guard(guard: FaultGuard) {
    *FAULT_GUARD.lock() = Some(guard);
}

pub fn set_fault_reclaimer(reclaimer: FaultReclaimer) {
    *FAULT_RECLAIMER.lock() = Some(reclaimer);
}

struct Sched {
    tasks: BTreeMap<TaskId, Task>,
    ready: VecDeque<TaskId>,
    /// The task being polled right now. It is lifted out of `tasks` for the
    /// duration of the poll, so both introspection and `wake` have to look
    /// for it here rather than in the map.
    running: Option<(TaskId, AllocationDomain, Arc<str>, Arc<TaskStatus>)>,
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

/// Spawn a future and inherit the allocation owner active at the call site.
pub fn spawn_tracked(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskHandle {
    spawn_tracked_domain(heap::current_domain(), name, fut)
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
    spawn_tracked_domain(AllocationDomain::untracked(owner), name, fut)
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
        FAULT_RECLAIMER.lock().is_some(),
        "a reclaimable task needs an installed fault reclaimer"
    );
    spawn_tracked_domain(domain, name, fut)
}

fn spawn_tracked_domain(
    domain: AllocationDomain,
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
        domain,
        name: task_name,
        future,
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
        system.restore();
        // Even a task that could not be admitted owns its future's destructor.
        // Reclaim it at the same guarded owner boundary as a scheduled task.
        let _ = reclaim_task(task);
        panic!("ready queue allocation failed");
    }
    s.tasks.insert(id, task);
    s.ready.push_back(id);
    drop(s);
    system.restore();
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
    Some(claim.state)
}

struct ReclaimResult {
    domain: AllocationDomain,
    faulted: bool,
}

/// Drop a normally suspended/completed future behind the same fault domain as
/// polling it. If the destructor faults, its allocation stays linked in the
/// arena and the caller performs raw domain teardown without invoking Drop
/// again.
fn reclaim_task(task: Task) -> ReclaimResult {
    let Task {
        domain,
        name,
        mut future,
        status,
    } = task;

    // Registration targets may themselves live inside the future. Detach all
    // external references before entering user Drop: a destructor fault may
    // longjmp past the rest of that destructor, after it already destroyed a
    // WaitQueue (or another registration target). Individual future drops
    // unregister again, idempotently, on the normal path.
    drain_task_registrations(&status);
    let future = unsafe { ManuallyDrop::take(&mut future) };

    let guard = *FAULT_GUARD.lock();
    let mut current_task = enter_current_task(status.clone());
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
    ReclaimResult { domain, faulted }
}

fn abandon_task_without_drop(task: Task) {
    let Task {
        domain: _,
        name,
        future,
        status,
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
    task: Option<Task>,
    status: Arc<TaskStatus>,
    claim: TerminalClaim,
}

fn teardown_faulted_domain(
    domain: AllocationDomain,
    primary_task: Option<Task>,
    primary_status: Arc<TaskStatus>,
    primary_claim: TerminalClaim,
) {
    debug_assert!(domain.arena.is_tracked());
    {
        let s = SCHED.lock();
        if let Some((_, running_domain, _, running_status)) = &s.running {
            assert!(
                primary_task.is_some()
                    && *running_domain == domain
                    && Arc::ptr_eq(running_status, &primary_status),
                "nested arena teardown cannot reclaim an active user poll"
            );
        }
    }
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut victims = Vec::new();
    {
        let s = SCHED.lock();
        victims.reserve(s.tasks.len() + 1);
    }
    victims.push(FaultVictim {
        task: primary_task,
        status: primary_status,
        claim: primary_claim,
    });

    {
        let mut s = SCHED.lock();
        s.running = None;
        s.running_woken = false;
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
            s.ready.retain(|ready| *ready != id);
            let status = task.status.clone();
            let claim = status
                .claim_terminal(TaskState::Faulted)
                .expect("an arena sibling could not claim fault teardown");
            victims.push(FaultVictim {
                task: Some(task),
                status,
                claim,
            });
        }
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
    if let Some(reclaim) = *FAULT_RECLAIMER.lock() {
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
        teardown_faulted_domain(result.domain, None, status.clone(), claim);
    } else {
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

    // Reclamation may enter arbitrary user Drop code. Never do that while a
    // different user poll/Drop is already active: a destructor fault could
    // otherwise tear down the active task's arena before its outer executor
    // boundary regains control. Turn such cancellation into a ready request;
    // the next top-level `poll_once` boundary performs the reclamation.
    let user_code_active = CURRENT_TASK_STATUS.lock().is_some();
    let mut ready_capacity_exhausted = false;
    let action = {
        let mut s = SCHED.lock();
        if s.running
            .as_ref()
            .is_some_and(|(id, _, _, _)| *id == handle.id)
        {
            Action::Return(requested_outcome(handle))
        } else if s.tasks.contains_key(&handle.id) {
            // `running` covers the small dispatch/return windows before the
            // current-task scope is installed or after it is restored, which
            // matters if cancellation is requested from an interrupt hook.
            if user_code_active || s.running.is_some() {
                let outcome = requested_outcome(handle);
                if outcome == CancelOutcome::Requested && !s.ready.contains(&handle.id) {
                    if s.ready.len() >= s.ready.capacity() {
                        ready_capacity_exhausted = true;
                    } else {
                        s.ready.push_back(handle.id);
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
                        s.ready.retain(|id| *id != handle.id);
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
        }
    };

    if ready_capacity_exhausted {
        panic!("ready queue reservation invariant violated during deferred cancellation");
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

pub fn wake(id: TaskId) {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut s = SCHED.lock();
    let mut capacity_exhausted = false;
    if s.running
        .as_ref()
        .is_some_and(|(running, _, _, _)| *running == id)
    {
        s.running_woken = true;
    } else if s.tasks.contains_key(&id) && !s.ready.contains(&id) {
        if s.ready.len() >= s.ready.capacity() {
            capacity_exhausted = true;
        } else {
            s.ready.push_back(id);
        }
    }
    drop(s);
    system.restore();
    if capacity_exhausted {
        panic!("ready queue reservation invariant violated");
    }
}

/// Identity and poll accounting for every live task.
pub fn task_report() -> Vec<TaskReport> {
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut out = Vec::new();
    let mut allocation_failed = false;
    {
        let s = SCHED.lock();
        let total = s.tasks.len() + usize::from(s.running.is_some());
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
                if let Some((id, domain, running_name, status)) = &s.running {
                    let mut name = String::new();
                    if name.try_reserve(running_name.len()).is_err() {
                        allocation_failed = true;
                    } else {
                        name.push_str(running_name);
                        out.push(TaskReport {
                            id: *id,
                            owner: domain.owner,
                            arena: domain.arena,
                            name,
                            state: status.state(),
                            polls: status.polls.load(Ordering::Acquire),
                        });
                    }
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
    // The scheduler lifts its current task out of `tasks`, so recursive
    // driving would overwrite `SCHED.running`. More importantly, an inner
    // same-arena fault could raw-reclaim the still-executing outer future.
    // Reject re-entry while the outer fault guard is still authoritative.
    assert!(
        CURRENT_TASK_STATUS.lock().is_none() && SCHED.lock().running.is_none(),
        "the executor cannot be driven recursively from task poll or Drop"
    );

    enum Dispatch {
        Poll(TaskId, Task, Arc<TaskStatus>),
        Reclaim(Task, Arc<TaskStatus>, TerminalClaim),
        Invalid(Task),
    }

    // Pop, detach, and publish `running` under one lock. This is the start-poll
    // linearization point: cancellation before it detaches the task without a
    // poll; cancellation after it waits for this poll boundary.
    let mut system = heap::enter_owner(OwnerId::SYSTEM);
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
            s.running = Some((id, task.domain, task.name.clone(), status.clone()));
            s.running_woken = false;
            Dispatch::Poll(id, task, status)
        } else {
            Dispatch::Invalid(task)
        }
    };
    system.restore();

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
    let mut current_task = enter_current_task(status.clone());
    // Tracked task domains originate only at the unsafe reclaimable spawn
    // boundary; ordinary safe tasks carry an untracked domain.
    let mut owner_scope = unsafe { heap::enter_domain(task.domain) };
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
    // `run_guarded` may have returned through a longjmp, which bypasses Drop
    // for scopes created inside the guarded call. Restore at the executor
    // boundary before touching scheduler infrastructure or another task.
    owner_scope.restore();
    current_task.restore();

    if faulted {
        let Some(claim) = status.claim_terminal(TaskState::Faulted) else {
            panic!("a faulted running task could not claim its terminal state");
        };
        if task.domain.arena.is_tracked() {
            let domain = task.domain;
            teardown_faulted_domain(domain, Some(task), status, claim);
        } else {
            let mut s = SCHED.lock();
            s.running = None;
            s.running_woken = false;
            drop(s);
            // Ordinary tasks have no audited escape contract. Clean external
            // registrations, but conservatively leak their future allocation.
            drain_task_registrations(&status);
            core::mem::forget(task);
            publish_terminal(&status, claim);
        }
        return true;
    }

    let mut system = heap::enter_owner(OwnerId::SYSTEM);
    let mut s = SCHED.lock();
    s.running = None;
    let woken = core::mem::take(&mut s.running_woken);
    if poll == Poll::Pending && !status.cancellation_requested() {
        // A cancellation cannot slip between this decision and reinsertion:
        // it also takes SCHED. A nested request was already published before
        // this branch, while an outer request sees the reinserted parked task.
        s.tasks.insert(id, task);
        let mut capacity_exhausted = false;
        if woken {
            if s.ready.len() >= s.ready.capacity() {
                capacity_exhausted = true;
            } else {
                s.ready.push_back(id);
            }
        }
        drop(s);
        system.restore();
        if capacity_exhausted {
            panic!("ready queue reservation invariant violated");
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
    system.restore();

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
    }
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
                        waker: candidate.take().expect("waker candidate exists"),
                    },
                );
                this.registration = Some(id);
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
