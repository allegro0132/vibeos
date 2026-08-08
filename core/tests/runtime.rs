//! Scheduler, wait queues, timers, and async channels — driven on the host.
//!
//! The scheduler is global state, so these tests serialise on one mutex rather
//! than running in parallel. They also never assume the scheduler is empty:
//! tasks from earlier tests may still be parked, so every assertion is about
//! this test's own tasks.
//!
//! What this file *cannot* test is interrupt ordering, because the host arch
//! shim makes interrupts a no-op. That belongs to the in-kernel self-test.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vibeos_core::arch::{advance_time, armed_timer, reset_time};
use vibeos_core::chan::Endpoint;
use vibeos_core::exec::{self, WaitQueue};

static SERIAL: Mutex<()> = Mutex::new(());

fn scheduler() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const BUDGET: usize = 10_000;

#[test]
fn a_spawned_task_runs_to_completion() {
    let _g = scheduler();
    let flag = Arc::new(AtomicU64::new(0));
    let f = flag.clone();
    let before = exec::completed_count();

    exec::spawn("t", async move {
        f.store(7, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(flag.load(Ordering::SeqCst), 7);
    assert_eq!(exec::completed_count(), before + 1);
}

/// Regression. `poll_once` lifts the task out of the map before polling it, so
/// a wake arriving *during* that poll used to find nothing and be dropped.
/// `yield_now` wakes the running task from inside its own poll, which hung the
/// shell after every `probe`.
#[test]
fn a_task_that_wakes_itself_mid_poll_is_rescheduled() {
    let _g = scheduler();
    let count = Arc::new(AtomicU64::new(0));
    let c = count.clone();

    exec::spawn("yielder", async move {
        for _ in 0..32 {
            exec::yield_now().await;
            c.fetch_add(1, Ordering::SeqCst);
        }
    });
    let polls = exec::run_until_idle(BUDGET);

    assert_eq!(count.load(Ordering::SeqCst), 32, "every yield resumed");
    assert!(polls >= 32, "each yield cost a poll, got {polls}");
    assert!(polls < BUDGET, "the task finished instead of spinning");
}

#[test]
fn a_parked_task_stays_parked_until_woken() {
    let _g = scheduler();
    static WQ: WaitQueue = WaitQueue::new();
    let stage = Arc::new(AtomicU64::new(0));
    let s = stage.clone();

    exec::spawn("waiter", async move {
        s.store(1, Ordering::SeqCst);
        WQ.wait().await;
        s.store(2, Ordering::SeqCst);
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(stage.load(Ordering::SeqCst), 1, "reached the wait and parked");

    // Nothing should reschedule it on its own.
    exec::run_until_idle(BUDGET);
    assert_eq!(stage.load(Ordering::SeqCst), 1, "still parked");

    WQ.wake_all();
    exec::run_until_idle(BUDGET);
    assert_eq!(stage.load(Ordering::SeqCst), 2, "the wake resumed it");
}

/// The wait future registers on its first poll and completes on its second, so
/// a wake landing between the two must not be lost.
#[test]
fn a_wake_racing_registration_is_not_lost() {
    let _g = scheduler();
    static WQ: WaitQueue = WaitQueue::new();
    let done = Arc::new(AtomicU64::new(0));
    let d = done.clone();

    exec::spawn("racer", async move {
        WQ.wait().await;
        d.store(1, Ordering::SeqCst);
    });

    // Poll exactly once: the task registers and returns Pending.
    exec::poll_once();
    WQ.wake_all();
    exec::run_until_idle(BUDGET);

    assert_eq!(done.load(Ordering::SeqCst), 1);
}

#[test]
fn the_running_task_is_visible_while_it_is_polled() {
    let _g = scheduler();
    let seen = Arc::new(AtomicU64::new(0));
    let s = seen.clone();

    exec::spawn("introspector", async move {
        let n = exec::task_report()
            .into_iter()
            .filter(|(name, _)| name == "introspector")
            .count();
        s.store(n as u64, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(seen.load(Ordering::SeqCst), 1, "a task can see itself in `ps`");
}

#[test]
fn poll_once_reports_whether_anything_ran() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    assert!(!exec::poll_once(), "nothing ready");

    exec::spawn("once", async {});
    assert!(exec::poll_once(), "one task ran");
}

// --- timers ---

#[test]
fn a_sleeping_task_wakes_when_its_deadline_passes() {
    let _g = scheduler();
    reset_time();
    let done = Arc::new(AtomicU64::new(0));
    let d = done.clone();

    exec::spawn("sleeper", async move {
        exec::sleep_ms(10).await;
        d.store(1, Ordering::SeqCst);
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 0, "deadline has not passed");

    // The timer interrupt alone must not wake it early.
    advance_time(exec::TIMEBASE_HZ / 1000); // 1 ms
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 0, "1 ms of a 10 ms sleep");

    advance_time(10 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 1, "woke after the deadline");
}

#[test]
fn a_sleep_already_past_completes_without_parking() {
    let _g = scheduler();
    reset_time();
    let done = Arc::new(AtomicU64::new(0));
    let d = done.clone();

    exec::spawn("instant", async move {
        exec::sleep_ms(0).await;
        d.store(1, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(done.load(Ordering::SeqCst), 1);
}

#[test]
fn the_hardware_timer_is_armed_no_later_than_the_heartbeat() {
    let _g = scheduler();
    reset_time();
    exec::init_timer();
    let heartbeat = exec::TIMEBASE_HZ / 20;
    assert!(
        armed_timer() <= heartbeat,
        "idle must still wake within the heartbeat, armed at {}",
        armed_timer()
    );
}

// --- channels under the scheduler ---

#[test]
fn a_send_wakes_a_parked_receiver() {
    let _g = scheduler();
    let ep: Arc<Endpoint<u64>> = Endpoint::new("t", 4);
    let got = Arc::new(AtomicU64::new(0));

    let rx = ep.clone();
    let g = got.clone();
    exec::spawn("rx", async move {
        let v = rx.recv().await;
        g.store(v, Ordering::SeqCst);
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(got.load(Ordering::SeqCst), 0, "receiver is parked on an empty channel");

    let tx = ep.clone();
    exec::spawn("tx", async move { tx.send(99).await });
    exec::run_until_idle(BUDGET);

    assert_eq!(got.load(Ordering::SeqCst), 99);
}

/// Backpressure is an await, not an error the caller may ignore.
#[test]
fn a_full_channel_parks_the_sender_until_space_appears() {
    let _g = scheduler();
    let ep: Arc<Endpoint<u64>> = Endpoint::new("t", 1);
    let sent = Arc::new(AtomicU64::new(0));

    let tx = ep.clone();
    let s = sent.clone();
    exec::spawn("tx", async move {
        for i in 1..=3 {
            tx.send(i).await;
            s.store(i, Ordering::SeqCst);
        }
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(sent.load(Ordering::SeqCst), 1, "one queued, sender parked on the second");

    assert_eq!(ep.try_recv(), Some(1));
    exec::run_until_idle(BUDGET);
    assert_eq!(sent.load(Ordering::SeqCst), 2);

    assert_eq!(ep.try_recv(), Some(2));
    exec::run_until_idle(BUDGET);
    assert_eq!(sent.load(Ordering::SeqCst), 3);
}
