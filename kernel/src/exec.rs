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

use crate::sbi;
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
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    tasks: BTreeMap::new(),
    ready: VecDeque::new(),
    running: None,
    running_woken: false,
    completed: 0,
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
        let next = SCHED.lock().ready.pop_front();

        let Some(id) = next else {
            // Nothing ready. Enable interrupts and idle until one arrives.
            unsafe { core::arch::asm!("csrs sstatus, {}", in(reg) 1usize << 1) };
            unsafe { core::arch::asm!("wfi") };
            continue;
        };

        // Take the future out of the map so the task can spawn/wake freely
        // while it is being polled without deadlocking on SCHED.
        let Some(mut task) = SCHED.lock().tasks.remove(&id) else { continue };

        task.polls += 1;
        {
            let mut s = SCHED.lock();
            s.running = Some((id, task.name.clone(), task.polls));
            s.running_woken = false;
        }
        let waker = waker_for(id);
        let mut cx = Context::from_waker(&waker);
        let poll = task.future.as_mut().poll(&mut cx);

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
    }
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
    let now = sbi::time();
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

fn arm_next() {
    let next = TIMERS.lock().iter().map(|(d, _)| *d).min();
    // Always keep a heartbeat so the idle hart wakes even with no timers armed.
    let heartbeat = sbi::time() + TIMEBASE_HZ / 20;
    sbi::set_timer(next.map_or(heartbeat, |n| n.min(heartbeat)));
}

pub fn init_timer() {
    arm_next();
}

pub fn sleep_ms(ms: u64) -> Sleep {
    Sleep { deadline: sbi::time() + ms * (TIMEBASE_HZ / 1000), armed: false }
}

pub struct Sleep {
    deadline: u64,
    armed: bool,
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if sbi::time() >= self.deadline {
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
