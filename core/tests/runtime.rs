//! Scheduler, wait queues, timers, and async channels — driven on the host.
//!
//! The scheduler is global state, so these tests serialise on one mutex rather
//! than running in parallel. They also never assume the scheduler is empty:
//! tasks from earlier tests may still be parked, so every assertion is about
//! this test's own tasks.
//!
//! What this file *cannot* test is interrupt ordering, because the host arch
//! shim makes interrupts a no-op. That belongs to the in-kernel self-test.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use vibeos_core::arch::{advance_time, armed_timer, reset_time};
use vibeos_core::chan::Endpoint;
use vibeos_core::exec::{self, CancelOutcome, TaskExit, TaskState, WaitQueue};

static SERIAL: Mutex<()> = Mutex::new(());
static FAULT_NEXT_POLL: AtomicBool = AtomicBool::new(false);

fn fault_once_then_passthrough(poll: &mut dyn FnMut()) -> bool {
    if FAULT_NEXT_POLL.swap(false, Ordering::SeqCst) {
        true
    } else {
        poll();
        false
    }
}

fn fault_after_poll(poll: &mut dyn FnMut()) -> bool {
    poll();
    true
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct WakeCounter(AtomicU64);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct ReadyThenCancelOnDrop {
    handle: Arc<Mutex<Option<exec::TaskHandle>>>,
    outcome: Arc<Mutex<Option<CancelOutcome>>>,
}

impl Future for ReadyThenCancelOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

impl Drop for ReadyThenCancelOnDrop {
    fn drop(&mut self) {
        let handle = self.handle.lock().unwrap().clone().unwrap();
        *self.outcome.lock().unwrap() = Some(handle.cancel());
    }
}

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

#[test]
fn a_tracked_task_preserves_its_identity_and_terminal_state() {
    let _g = scheduler();
    let handle = exec::spawn_tracked("tracked", async {});
    let id = handle.id();

    assert_eq!(handle.state(), TaskState::Running);
    assert_eq!(handle.state().terminal_reason(), None);
    assert_eq!(handle.polls(), 0);
    assert_eq!(format!("{id}"), format!("task:{}", id.0));

    exec::run_until_idle(BUDGET);

    assert_eq!(handle.id(), id, "completion does not replace task identity");
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(handle.state().terminal_reason(), Some("returned"));
    assert_eq!(handle.polls(), 1);
    assert!(exec::task_report().iter().all(|report| report.id != id));

    exec::wake(id);
    exec::run_until_idle(BUDGET);
    assert_eq!(
        handle.state(),
        TaskState::Exited,
        "a stale wake cannot revive a terminal task"
    );
    assert_eq!(
        handle.polls(),
        1,
        "a stale wake cannot poll a terminal task again"
    );
}

#[test]
fn a_pending_tracked_task_remains_running_until_it_returns() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let handle = exec::spawn_tracked("tracked-waiter", async move {
        waiter.wait().await;
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Running);
    assert_eq!(handle.polls(), 1);

    queue.wake_all();
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(handle.polls(), 2);
}

#[test]
fn a_tracked_fault_retains_its_terminal_state_and_cannot_be_revived() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);

    let ran = Arc::new(AtomicU64::new(0));
    let task_ran = ran.clone();
    let faults_before = exec::faulted_count();
    exec::set_fault_guard(fault_once_then_passthrough);
    FAULT_NEXT_POLL.store(true, Ordering::SeqCst);
    let handle = exec::spawn_tracked("faulted", async move {
        task_ran.store(1, Ordering::SeqCst);
    });
    let id = handle.id();

    exec::run_until_idle(BUDGET);
    assert_eq!(
        ran.load(Ordering::SeqCst),
        0,
        "the injected fault interrupted the poll"
    );
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(handle.state().terminal_reason(), Some("fault"));
    assert_eq!(
        handle.polls(),
        0,
        "the synthetic guard faulted before entering Future::poll"
    );
    assert_eq!(exec::faulted_count(), faults_before + 1);
    assert!(exec::task_report().iter().all(|report| report.id != id));

    exec::wake(id);
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(handle.polls(), 0, "a stale wake cannot poll a faulted task");
}

#[test]
fn task_ids_disambiguate_reused_names() {
    let _g = scheduler();
    let first = exec::spawn_tracked("replica", async {});
    let second = exec::spawn_tracked("replica", async {});

    assert_ne!(first.id(), second.id());
    let reports = exec::task_report();
    assert!(reports.iter().any(|report| report.id == first.id()));
    assert!(reports.iter().any(|report| report.id == second.id()));

    exec::run_until_idle(BUDGET);
    assert_eq!(first.state(), TaskState::Exited);
    assert_eq!(second.state(), TaskState::Exited);
}

#[test]
fn cancelling_a_ready_task_reclaims_it_without_polling() {
    let _g = scheduler();
    let ran = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let task_ran = ran.clone();
    let drop_flag = DropFlag(dropped.clone());
    let cancelled_before = exec::cancelled_count();
    let handle = exec::spawn_tracked("cancel-ready", async move {
        let _keep_until_drop = drop_flag;
        task_ran.store(true, Ordering::SeqCst);
    });
    let id = handle.id();

    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 0, "cancellation is not a task poll");
    assert!(!ran.load(Ordering::SeqCst));
    assert!(
        dropped.load(Ordering::SeqCst),
        "a suspended future is reclaimed normally"
    );
    assert_eq!(exec::cancelled_count(), cancelled_before + 1);

    let exit = handle.try_exit().expect("cancel publishes an exit report");
    assert_eq!(exit.id(), id);
    assert_eq!(exit.state(), TaskState::Cancelled);
    assert_eq!(exit.polls(), 0);
    assert_eq!(exit.reason(), "cancelled");
    assert_eq!(handle.cancel(), CancelOutcome::AlreadyTerminal(exit));

    exec::wake(id);
    exec::run_until_idle(BUDGET);
    assert_eq!(
        handle.polls(),
        0,
        "a stale wake cannot revive a cancelled task"
    );
}

#[test]
fn cancelling_a_parked_task_never_polls_it_again() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let resumed = Arc::new(AtomicBool::new(false));
    let task_resumed = resumed.clone();
    let handle = exec::spawn_tracked("cancel-parked", async move {
        waiter.wait().await;
        task_resumed.store(true, Ordering::SeqCst);
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(handle.polls(), 1);
    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);

    // 3.10 removes this stale wait registration at Drop. Even before that
    // cleanup lands, waking it must not put the terminal task back on a queue.
    queue.wake_all();
    exec::run_until_idle(BUDGET);
    assert!(!resumed.load(Ordering::SeqCst));
    assert_eq!(handle.polls(), 1);
}

#[test]
fn cancelling_a_self_waking_task_removes_its_ready_entry() {
    let _g = scheduler();
    let resumed = Arc::new(AtomicU64::new(0));
    let task_resumed = resumed.clone();
    let handle = exec::spawn_tracked("cancel-self-wake", async move {
        loop {
            exec::yield_now().await;
            task_resumed.fetch_add(1, Ordering::SeqCst);
        }
    });

    assert!(
        exec::poll_once(),
        "first poll self-wakes and returns Pending"
    );
    assert_eq!(handle.polls(), 1);
    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    exec::run_until_idle(BUDGET);

    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);
    assert_eq!(resumed.load(Ordering::SeqCst), 0);
}

#[test]
fn a_running_task_cancels_only_at_its_poll_boundary() {
    let _g = scheduler();
    let own_handle: Arc<Mutex<Option<exec::TaskHandle>>> = Arc::new(Mutex::new(None));
    let inside = own_handle.clone();
    let stages = Arc::new(AtomicU64::new(0));
    let task_stages = stages.clone();
    let handle = exec::spawn_tracked("cancel-self", async move {
        let outcome = inside.lock().unwrap().as_ref().unwrap().cancel();
        assert_eq!(outcome, CancelOutcome::Requested);
        task_stages.store(1, Ordering::SeqCst);
        exec::yield_now().await;
        task_stages.store(2, Ordering::SeqCst);
    });
    *own_handle.lock().unwrap() = Some(handle.clone());

    assert!(exec::poll_once());
    assert_eq!(
        stages.load(Ordering::SeqCst),
        1,
        "the active poll reached its boundary"
    );
    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);
    exec::run_until_idle(BUDGET);
    assert_eq!(
        stages.load(Ordering::SeqCst),
        1,
        "the task was never polled again"
    );
}

#[test]
fn cancellation_cannot_rewrite_an_exit_committed_before_future_drop() {
    let _g = scheduler();
    let own_handle: Arc<Mutex<Option<exec::TaskHandle>>> = Arc::new(Mutex::new(None));
    let outcome: Arc<Mutex<Option<CancelOutcome>>> = Arc::new(Mutex::new(None));
    let handle = exec::spawn_tracked(
        "exit-then-drop-cancel",
        ReadyThenCancelOnDrop {
            handle: own_handle.clone(),
            outcome: outcome.clone(),
        },
    );
    *own_handle.lock().unwrap() = Some(handle.clone());

    exec::run_until_idle(BUDGET);

    assert_eq!(
        *outcome.lock().unwrap(),
        Some(CancelOutcome::TooLate(TaskState::Exited))
    );
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(handle.polls(), 1);
}

#[test]
fn joiners_observe_the_same_exit_before_and_after_completion() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let handle = exec::spawn_tracked("join-target", async move {
        waiter.wait().await;
    });
    let exits: Arc<Mutex<Vec<TaskExit>>> = Arc::new(Mutex::new(Vec::new()));

    for name in ["join-one", "join-two"] {
        let target = handle.clone();
        let observed = exits.clone();
        exec::spawn(name, async move {
            let exit = target.join().await;
            observed.lock().unwrap().push(exit);
        });
    }
    exec::run_until_idle(BUDGET);
    assert!(
        exits.lock().unwrap().is_empty(),
        "joiners remain parked while target runs"
    );

    queue.wake_all();
    exec::run_until_idle(BUDGET);
    let expected = handle.try_exit().expect("target exited");
    assert_eq!(expected.state(), TaskState::Exited);
    assert_eq!(exits.lock().unwrap().as_slice(), &[expected, expected]);

    let late = exits.clone();
    let target = handle.clone();
    exec::spawn("join-late", async move {
        let exit = target.join().await;
        late.lock().unwrap().push(exit);
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(
        exits.lock().unwrap().as_slice(),
        &[expected, expected, expected]
    );
}

#[test]
fn a_live_joiner_observes_cancellation() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let handle = exec::spawn_tracked("join-cancel-target", async move {
        waiter.wait().await;
    });
    let observed: Arc<Mutex<Option<TaskExit>>> = Arc::new(Mutex::new(None));
    let result = observed.clone();
    let target = handle.clone();
    exec::spawn("join-cancel-observer", async move {
        *result.lock().unwrap() = Some(target.join().await);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    exec::run_until_idle(BUDGET);

    let exit = observed.lock().unwrap().expect("joiner was woken");
    assert_eq!(exit.state(), TaskState::Cancelled);
    assert_eq!(exit.id(), handle.id());
}

#[test]
fn dropped_joiners_unregister_and_repoll_replaces_the_waker() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let handle = exec::spawn_tracked("join-waker-target", async move {
        waiter.wait().await;
    });
    exec::run_until_idle(BUDGET);

    let first = Arc::new(WakeCounter(AtomicU64::new(0)));
    let second = Arc::new(WakeCounter(AtomicU64::new(0)));
    let abandoned = Arc::new(WakeCounter(AtomicU64::new(0)));
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    let abandoned_waker = Waker::from(abandoned.clone());

    let mut active = Box::pin(handle.join());
    assert!(active
        .as_mut()
        .poll(&mut Context::from_waker(&first_waker))
        .is_pending());
    assert!(active
        .as_mut()
        .poll(&mut Context::from_waker(&second_waker))
        .is_pending());

    let mut dropped = Box::pin(handle.join());
    assert!(dropped
        .as_mut()
        .poll(&mut Context::from_waker(&abandoned_waker))
        .is_pending());
    drop(dropped);

    queue.wake_all();
    exec::run_until_idle(BUDGET);

    assert_eq!(first.0.load(Ordering::SeqCst), 0, "old waker was replaced");
    assert_eq!(
        second.0.load(Ordering::SeqCst),
        1,
        "current waker fired once"
    );
    assert_eq!(
        abandoned.0.load(Ordering::SeqCst),
        0,
        "dropped join unregistered"
    );
    assert!(active
        .as_mut()
        .poll(&mut Context::from_waker(&second_waker))
        .is_ready());
}

#[test]
fn a_fault_wins_over_a_mid_poll_cancellation_request() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let own_handle: Arc<Mutex<Option<exec::TaskHandle>>> = Arc::new(Mutex::new(None));
    let inside = own_handle.clone();
    exec::set_fault_guard(fault_after_poll);
    let handle = exec::spawn_tracked("fault-vs-cancel", async move {
        assert_eq!(
            inside.lock().unwrap().as_ref().unwrap().cancel(),
            CancelOutcome::Requested
        );
    });
    *own_handle.lock().unwrap() = Some(handle.clone());

    exec::run_until_idle(BUDGET);
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(handle.polls(), 1);
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
    assert_eq!(
        stage.load(Ordering::SeqCst),
        1,
        "reached the wait and parked"
    );

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
            .filter(|report| report.name == "introspector" && report.state == TaskState::Running)
            .count();
        s.store(n as u64, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "a task can see itself in `ps`"
    );
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
    let heartbeat = exec::HEARTBEAT_SECS * exec::TIMEBASE_HZ;
    assert!(
        armed_timer() <= heartbeat,
        "idle must still wake within the heartbeat, armed at {}",
        armed_timer()
    );
}

/// A pending sleep must pull the hardware timer in ahead of the heartbeat,
/// otherwise a 10 ms sleep would take 10 s.
#[test]
fn a_pending_sleep_arms_the_timer_before_the_heartbeat() {
    let _g = scheduler();
    reset_time();
    exec::spawn("sleeper", async { exec::sleep_ms(10).await });
    exec::run_until_idle(BUDGET);

    let heartbeat = exec::HEARTBEAT_SECS * exec::TIMEBASE_HZ;
    let deadline = 10 * exec::TIMEBASE_HZ / 1000;
    assert!(
        armed_timer() <= deadline,
        "armed at {} for a {} tick sleep",
        armed_timer(),
        deadline
    );
    assert!(armed_timer() < heartbeat);
}

#[test]
fn cancelling_a_sleeping_task_prevents_a_deadline_from_polling_it_again() {
    let _g = scheduler();
    reset_time();
    let handle = exec::spawn_tracked("cancel-sleeper", async {
        exec::sleep_ms(10).await;
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.polls(), 1);

    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    advance_time(20 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);

    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);
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
    assert_eq!(
        got.load(Ordering::SeqCst),
        0,
        "receiver is parked on an empty channel"
    );

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
    assert_eq!(
        sent.load(Ordering::SeqCst),
        1,
        "one queued, sender parked on the second"
    );

    assert_eq!(ep.try_recv(), Some(1));
    exec::run_until_idle(BUDGET);
    assert_eq!(sent.load(Ordering::SeqCst), 2);

    assert_eq!(ep.try_recv(), Some(2));
    exec::run_until_idle(BUDGET);
    assert_eq!(sent.load(Ordering::SeqCst), 3);
}
