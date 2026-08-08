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
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::arch;
use crate::sync::SpinLock;

/// QEMU `virt` drives `mtime` at 10 MHz.
pub const TIMEBASE_HZ: u64 = 10_000_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct TaskId(pub u64);

struct Task {
    name: String,
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    polls: u64,
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
    running: Option<(TaskId, String, u64)>,
    /// Set when the running task is woken while it is being polled — by itself
    /// (`yield_now`) or by an interrupt that lands mid-poll. Without this the
    /// wake would be dropped and the task would never be scheduled again.
    running_woken: bool,
    completed: u64,
    faulted: u64,
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    tasks: BTreeMap::new(),
    ready: VecDeque::new(),
    running: None,
    running_woken: false,
    completed: 0,
    faulted: 0,
});

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Spawn a future as a task. Safe to call from inside another task.
pub fn spawn(name: &str, fut: impl Future<Output = ()> + Send + 'static) -> TaskId {
    let id = TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let mut s = SCHED.lock();
    s.tasks.insert(id, Task { name: String::from(name), future: Box::pin(fut), polls: 0 });
    s.ready.push_back(id);
    id
}

pub fn wake(id: TaskId) {
    let mut s = SCHED.lock();
    if s.running.as_ref().is_some_and(|(r, _, _)| *r == id) {
        s.running_woken = true;
    } else if s.tasks.contains_key(&id) && !s.ready.contains(&id) {
        s.ready.push_back(id);
    }
}

/// (name, polls) for every live task.
pub fn task_report() -> Vec<(String, u64)> {
    let s = SCHED.lock();
    let mut out: Vec<(String, u64)> =
        s.tasks.values().map(|t| (t.name.clone(), t.polls)).collect();
    out.extend(s.running.iter().map(|(_, n, p)| (n.clone(), *p)));
    out
}

pub fn completed_count() -> u64 {
    SCHED.lock().completed
}

/// Tasks killed by a fault rather than by returning.
pub fn faulted_count() -> u64 {
    SCHED.lock().faulted
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
    let Some(id) = SCHED.lock().ready.pop_front() else { return false };

    // Take the future out of the map so the task can spawn/wake freely
    // while it is being polled without deadlocking on SCHED.
    let Some(mut task) = SCHED.lock().tasks.remove(&id) else { return true };

    task.polls += 1;
    {
        let mut s = SCHED.lock();
        s.running = Some((id, task.name.clone(), task.polls));
        s.running_woken = false;
    }
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
                    poll = f.poll(&mut cx);
                }
            })
        }
        None => {
            poll = task.future.as_mut().poll(&mut cx);
            false
        }
    };

    if faulted {
        // The future was interrupted mid-poll. Dropping it would run
        // destructors over state it never finished writing, so the task is
        // leaked instead: leaking is always sound, and a faulted component is
        // not going to be resumed.
        core::mem::forget(task);
        let mut s = SCHED.lock();
        s.running = None;
        s.running_woken = false;
        s.faulted += 1;
        return true;
    }

    let mut s = SCHED.lock();
    s.running = None;
    let woken = core::mem::take(&mut s.running_woken);
    match poll {
        Poll::Ready(()) => s.completed += 1,
        Poll::Pending => {
            s.tasks.insert(id, task);
            if woken {
                s.ready.push_back(id);
            }
        }
    }
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
    waiters: SpinLock<Vec<Waker>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self { waiters: SpinLock::new(Vec::new()) }
    }

    pub fn wake_all(&self) {
        let mut w = self.waiters.lock();
        for waker in w.drain(..) {
            waker.wake();
        }
    }

    /// Park until the next `wake_all`. Registers on first poll, completes on
    /// second — so a wake that races in between is never lost.
    pub fn wait(&self) -> WaitFuture<'_> {
        WaitFuture { queue: self, registered: false }
    }
}

pub struct WaitFuture<'a> {
    queue: &'a WaitQueue,
    registered: bool,
}

impl Future for WaitFuture<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.registered {
            return Poll::Ready(());
        }
        self.registered = true;
        self.queue.waiters.lock().push(cx.waker().clone());
        Poll::Pending
    }
}

// --- Timers ---

static TIMERS: SpinLock<Vec<(u64, Waker)>> = SpinLock::new(Vec::new());

/// Called from the timer trap. Wakes everything due and re-arms the hardware.
pub fn timer_tick() {
    let now = arch::time();
    let mut due = Vec::new();
    {
        let mut t = TIMERS.lock();
        t.retain(|(deadline, waker)| {
            if *deadline <= now {
                due.push(waker.clone());
                false
            } else {
                true
            }
        });
    }
    for w in due {
        w.wake();
    }
    arm_next();
}

/// How long an idle hart sleeps with nothing scheduled.
///
/// This used to be 50 ms and was load-bearing: it bounded the latency of a wake
/// lost to the check-then-sleep race in `run`. With that race closed the
/// heartbeat is only a backstop, so it can be long enough to be nearly free.
pub const HEARTBEAT_SECS: u64 = 10;

fn arm_next() {
    let next = TIMERS.lock().iter().map(|(d, _)| *d).min();
    let heartbeat = arch::time() + HEARTBEAT_SECS * TIMEBASE_HZ;
    arch::set_timer(next.map_or(heartbeat, |n| n.min(heartbeat)));
}

pub fn init_timer() {
    arm_next();
}

pub fn sleep_ms(ms: u64) -> Sleep {
    Sleep { deadline: arch::time() + ms * (TIMEBASE_HZ / 1000), armed: false }
}

pub struct Sleep {
    deadline: u64,
    armed: bool,
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if arch::time() >= self.deadline {
            return Poll::Ready(());
        }
        if !self.armed {
            self.armed = true;
            TIMERS.lock().push((self.deadline, cx.waker().clone()));
            arm_next();
        }
        Poll::Pending
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
