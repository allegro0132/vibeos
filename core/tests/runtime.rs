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

use vibeos_core::arch::{advance_time, armed_timer, reset_time, time};
use vibeos_core::chan::Endpoint;
use vibeos_core::exec::{self, CancelOutcome, TaskExit, TaskState, WaitQueue};
use vibeos_core::heap::{self, AllocationDomain, ArenaId, OwnerId};

static SERIAL: Mutex<()> = Mutex::new(());
static FAULT_NEXT_POLL: AtomicBool = AtomicBool::new(false);
static FAULT_AFTER_GUARDED_CALLS: AtomicU64 = AtomicU64::new(0);
static OWNER_SEEN_BY_FAULT_GUARD: Mutex<Option<OwnerId>> = Mutex::new(None);
static RECLAIMED_DOMAINS: Mutex<Vec<AllocationDomain>> = Mutex::new(Vec::new());
static CLEANED_TASKS: Mutex<Vec<(exec::TaskId, AllocationDomain)>> = Mutex::new(Vec::new());
static FAULT_WAIT_QUEUE: WaitQueue = WaitQueue::new();

unsafe fn record_fault_reclaim(domain: AllocationDomain) {
    RECLAIMED_DOMAINS.lock().unwrap().push(domain);
}

unsafe fn record_fault_cleanup(task: exec::TaskId, domain: AllocationDomain) {
    CLEANED_TASKS.lock().unwrap().push((task, domain));
}

unsafe fn ignore_fault_cleanup(_task: exec::TaskId, _domain: AllocationDomain) {}

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

fn fault_after_guarded_calls(poll: &mut dyn FnMut()) -> bool {
    poll();
    let remaining = FAULT_AFTER_GUARDED_CALLS.load(Ordering::SeqCst);
    if remaining == 0 {
        false
    } else {
        FAULT_AFTER_GUARDED_CALLS.store(remaining - 1, Ordering::SeqCst);
        remaining == 1
    }
}

fn fault_once_and_record_owner(poll: &mut dyn FnMut()) -> bool {
    *OWNER_SEEN_BY_FAULT_GUARD.lock().unwrap() = Some(heap::current_owner());
    fault_once_then_passthrough(poll)
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct OwnerDropFuture {
    owner_seen: Arc<Mutex<Option<OwnerId>>>,
    ready: bool,
}

impl Future for OwnerDropFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for OwnerDropFuture {
    fn drop(&mut self) {
        *self.owner_seen.lock().unwrap() = Some(heap::current_owner());
    }
}

struct DropBombFuture {
    drops: Arc<AtomicU64>,
}

impl Future for DropBombFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for DropBombFuture {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct RegisteredDropBombFuture {
    wait: exec::WaitFuture<'static>,
    sleep: exec::Sleep,
    join: exec::Join,
    probe: Option<exec::IrqPollProbe>,
    drops: Arc<AtomicU64>,
}

impl Future for RegisteredDropBombFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        assert!(Pin::new(&mut this.wait).poll(cx).is_pending());
        assert!(Pin::new(&mut this.sleep).poll(cx).is_pending());
        assert!(Pin::new(&mut this.join).poll(cx).is_pending());
        if this.probe.is_none() {
            this.probe = Some(
                exec::arm_irq_poll_probe().expect("the registered task owns the probe slot"),
            );
        }
        Poll::Pending
    }
}

impl Drop for RegisteredDropBombFuture {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
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

struct QueueInspectWake {
    queue: Arc<WaitQueue>,
    wakes: AtomicU64,
    waiters_seen_during_wake: AtomicU64,
}

struct QueueDropInspectWake {
    queue: Arc<WaitQueue>,
    drops: Arc<AtomicU64>,
    waiters_seen_during_drop: Arc<AtomicU64>,
}

impl Wake for QueueDropInspectWake {
    fn wake(self: Arc<Self>) {}
}

impl Drop for QueueDropInspectWake {
    fn drop(&mut self) {
        self.waiters_seen_during_drop
            .store(self.queue.waiter_count() as u64, Ordering::SeqCst);
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct TimerDropInspectWake {
    drops: Arc<AtomicU64>,
    timers_seen_during_drop: Arc<AtomicU64>,
}

impl Wake for TimerDropInspectWake {
    fn wake(self: Arc<Self>) {}
}

impl Drop for TimerDropInspectWake {
    fn drop(&mut self) {
        self.timers_seen_during_drop
            .store(exec::timer_registration_count() as u64, Ordering::SeqCst);
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

impl Wake for QueueInspectWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.waiters_seen_during_wake
            .store(self.queue.waiter_count() as u64, Ordering::SeqCst);
        self.wakes.fetch_add(1, Ordering::SeqCst);
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
fn an_owned_task_installs_its_owner_for_pending_and_ready_polls() {
    let _g = scheduler();
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
    let owner = OwnerId::new(10_001);
    let queue = Arc::new(WaitQueue::new());
    let waiter = queue.clone();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let task_observed = observed.clone();
    let handle = exec::spawn_tracked_owned(owner, "owned-poll", async move {
        task_observed.lock().unwrap().push(heap::current_owner());
        waiter.wait().await;
        task_observed.lock().unwrap().push(heap::current_owner());
    });

    assert_eq!(handle.owner(), owner);
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Running);
    assert_eq!(observed.lock().unwrap().as_slice(), &[owner]);
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
    assert!(exec::task_report()
        .iter()
        .any(|report| report.id == handle.id() && report.owner == owner));
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);

    queue.wake_all();
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(observed.lock().unwrap().as_slice(), &[owner, owner]);
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
}

#[test]
fn nested_spawn_inherits_owner_and_explicit_spawn_restores_the_parent() {
    let _g = scheduler();
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
    let parent_owner = OwnerId::new(10_002);
    let child_owner = OwnerId::new(10_003);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let parent_observed = observed.clone();

    let parent = exec::spawn_tracked_owned(parent_owner, "owner-parent", async move {
        parent_observed
            .lock()
            .unwrap()
            .push(("parent-before", heap::current_owner()));

        let inherited_observed = parent_observed.clone();
        exec::spawn("owner-inherited-child", async move {
            inherited_observed
                .lock()
                .unwrap()
                .push(("inherited-child", heap::current_owner()));
        });
        parent_observed
            .lock()
            .unwrap()
            .push(("parent-after-inherited", heap::current_owner()));

        let explicit_observed = parent_observed.clone();
        let explicit = exec::spawn_tracked_owned(child_owner, "owner-explicit-child", async move {
            explicit_observed
                .lock()
                .unwrap()
                .push(("explicit-child", heap::current_owner()));
        });
        assert_eq!(explicit.owner(), child_owner);
        parent_observed
            .lock()
            .unwrap()
            .push(("parent-after-explicit", heap::current_owner()));
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(parent.state(), TaskState::Exited);
    assert_eq!(parent.owner(), parent_owner);
    assert_eq!(
        observed.lock().unwrap().as_slice(),
        &[
            ("parent-before", parent_owner),
            ("parent-after-inherited", parent_owner),
            ("parent-after-explicit", parent_owner),
            ("inherited-child", parent_owner),
            ("explicit-child", child_owner),
        ]
    );
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
}

#[test]
fn fault_and_destructor_paths_restore_the_system_owner() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);

    let fault_owner = OwnerId::new(10_004);
    *OWNER_SEEN_BY_FAULT_GUARD.lock().unwrap() = None;
    exec::set_fault_guard(fault_once_and_record_owner);
    FAULT_NEXT_POLL.store(true, Ordering::SeqCst);
    let faulted = exec::spawn_tracked_owned(fault_owner, "owner-fault", async {});
    exec::run_until_idle(BUDGET);
    assert_eq!(faulted.state(), TaskState::Faulted);
    assert_eq!(
        *OWNER_SEEN_BY_FAULT_GUARD.lock().unwrap(),
        Some(fault_owner)
    );
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);

    exec::set_fault_guard(fault_once_then_passthrough);
    let ready_owner = OwnerId::new(10_005);
    let ready_drop_owner = Arc::new(Mutex::new(None));
    let ready = exec::spawn_tracked_owned(
        ready_owner,
        "owner-ready-drop",
        OwnerDropFuture {
            owner_seen: ready_drop_owner.clone(),
            ready: true,
        },
    );
    exec::run_until_idle(BUDGET);
    assert_eq!(ready.state(), TaskState::Exited);
    assert_eq!(*ready_drop_owner.lock().unwrap(), Some(ready_owner));
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);

    let pending_owner = OwnerId::new(10_006);
    let pending_drop_owner = Arc::new(Mutex::new(None));
    let pending = exec::spawn_tracked_owned(
        pending_owner,
        "owner-pending-drop",
        OwnerDropFuture {
            owner_seen: pending_drop_owner.clone(),
            ready: false,
        },
    );
    assert!(exec::poll_once());
    assert_eq!(pending.state(), TaskState::Running);
    assert_eq!(pending.cancel(), CancelOutcome::Requested);
    assert_eq!(pending.state(), TaskState::Cancelled);
    assert_eq!(*pending_drop_owner.lock().unwrap(), Some(pending_owner));
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);

    // A destructor fault is reported by the synthetic guard after it ran the
    // destructor. The executor must still restore the prior owner explicitly,
    // just as it does after the kernel landing pad returns through longjmp.
    exec::set_fault_guard(fault_after_poll);
    let destructor_owner = OwnerId::new(10_007);
    let faulting_drop_owner = Arc::new(Mutex::new(None));
    let destructor_fault = exec::spawn_tracked_owned(
        destructor_owner,
        "owner-destructor-fault",
        OwnerDropFuture {
            owner_seen: faulting_drop_owner.clone(),
            ready: false,
        },
    );
    assert_eq!(destructor_fault.cancel(), CancelOutcome::Requested);
    assert_eq!(destructor_fault.state(), TaskState::Faulted);
    assert_eq!(*faulting_drop_owner.lock().unwrap(), Some(destructor_owner));
    assert_eq!(heap::current_owner(), OwnerId::SYSTEM);
    exec::set_fault_guard(fault_once_then_passthrough);
}

#[test]
fn an_untracked_fault_notifies_exact_task_cleanup_once() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    CLEANED_TASKS.lock().unwrap().clear();
    exec::set_fault_cleanup(record_fault_cleanup);

    let fault_domain = AllocationDomain::untracked(OwnerId::new(10_008));
    let survivor_domain = AllocationDomain::untracked(OwnerId::new(10_009));
    exec::set_fault_guard(fault_after_poll);
    let faulted = exec::spawn_tracked_owned(fault_domain.owner, "cleanup-fault", async {});
    let survivor = exec::spawn_tracked_owned(
        survivor_domain.owner,
        "cleanup-survivor",
        std::future::pending::<()>(),
    );

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(faulted.state(), TaskState::Faulted);
    assert_eq!(survivor.state(), TaskState::Running);
    assert_eq!(
        CLEANED_TASKS.lock().unwrap().as_slice(),
        &[(faulted.id(), fault_domain)]
    );

    assert!(exec::poll_once(), "the unrelated task still runs normally");
    assert_eq!(survivor.state(), TaskState::Running);
    assert_eq!(survivor.cancel(), CancelOutcome::Requested);
    assert_eq!(survivor.state(), TaskState::Cancelled);
    assert_eq!(CLEANED_TASKS.lock().unwrap().len(), 1);
    exec::set_fault_cleanup(ignore_fault_cleanup);
}

#[test]
fn a_reclaimable_poll_fault_skips_drop_and_invokes_the_reclaimer() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();

    let domain = AllocationDomain::new(OwnerId::new(20_001), ArenaId::new(30_001));
    let drops = Arc::new(AtomicU64::new(0));
    let faults_before = exec::faulted_count();
    exec::set_fault_guard(fault_after_poll);
    let handle = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "reclaimable-drop-bomb",
            DropBombFuture {
                drops: drops.clone(),
            },
        )
    };

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(handle.polls(), 1);
    assert_eq!(handle.allocation_domain(), domain);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "fault teardown ran Drop");
    assert_eq!(exec::faulted_count(), faults_before + 1);
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[domain]);
    assert_eq!(heap::current_domain(), AllocationDomain::SYSTEM);
}

#[test]
fn a_reclaimable_fault_detaches_every_sibling_in_the_same_arena() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();
    CLEANED_TASKS.lock().unwrap().clear();
    exec::set_fault_cleanup(record_fault_cleanup);

    let domain = AllocationDomain::new(OwnerId::new(20_002), ArenaId::new(30_002));
    let primary_drops = Arc::new(AtomicU64::new(0));
    let sibling_drops = Arc::new(AtomicU64::new(0));
    let faults_before = exec::faulted_count();
    exec::set_fault_guard(fault_after_poll);
    let primary = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "reclaimable-primary",
            DropBombFuture {
                drops: primary_drops.clone(),
            },
        )
    };
    let sibling = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "reclaimable-sibling",
            DropBombFuture {
                drops: sibling_drops.clone(),
            },
        )
    };

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(primary.state(), TaskState::Faulted);
    assert_eq!(sibling.state(), TaskState::Faulted);
    assert_eq!(primary.polls(), 1);
    assert_eq!(sibling.polls(), 0, "the sibling ran before arena teardown");
    assert_eq!(primary_drops.load(Ordering::SeqCst), 0);
    assert_eq!(sibling_drops.load(Ordering::SeqCst), 0);
    assert_eq!(exec::faulted_count(), faults_before + 2);
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[domain]);
    assert_eq!(
        CLEANED_TASKS.lock().unwrap().as_slice(),
        &[(primary.id(), domain), (sibling.id(), domain)]
    );
    assert!(exec::task_report()
        .iter()
        .all(|task| task.id != primary.id() && task.id != sibling.id()));
    assert!(!exec::poll_once(), "a detached sibling remained ready");
    exec::set_fault_cleanup(ignore_fault_cleanup);
}

#[test]
fn reclaimable_fault_teardown_restores_wait_sleep_and_join_registries() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();
    assert_eq!(FAULT_WAIT_QUEUE.waiter_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);

    let target = exec::spawn_tracked("reclaimable-join-target", std::future::pending::<()>());
    assert!(exec::poll_once());
    assert_eq!(target.polls(), 1);
    let timers_before = exec::timer_registration_count();
    let joiners_before = target.joiner_count();
    let domain = AllocationDomain::new(OwnerId::new(20_003), ArenaId::new(30_003));
    let drops = Arc::new(AtomicU64::new(0));
    exec::set_fault_guard(fault_after_poll);
    let handle = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "reclaimable-registered",
            RegisteredDropBombFuture {
                wait: FAULT_WAIT_QUEUE.wait(),
                sleep: exec::sleep_ms(60_000),
                join: target.join(),
                probe: None,
                drops: drops.clone(),
            },
        )
    };

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(FAULT_WAIT_QUEUE.waiter_count(), 0);
    assert_eq!(exec::timer_registration_count(), timers_before);
    assert_eq!(target.joiner_count(), joiners_before);
    assert_eq!(exec::irq_poll_probe_count(), 0);
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[domain]);
    assert_eq!(target.cancel(), CancelOutcome::Requested);
    assert_eq!(target.state(), TaskState::Cancelled);
}

#[test]
fn a_reclaimable_destructor_fault_cleans_registries_before_entering_drop() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();
    assert_eq!(FAULT_WAIT_QUEUE.waiter_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);

    let target = exec::spawn_tracked(
        "reclaimable-destructor-join-target",
        std::future::pending::<()>(),
    );
    assert!(exec::poll_once());
    let timers_before = exec::timer_registration_count();
    let joiners_before = target.joiner_count();
    let domain = AllocationDomain::new(OwnerId::new(20_004), ArenaId::new(30_004));
    let drops = Arc::new(AtomicU64::new(0));
    let handle = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "reclaimable-destructor-registered",
            RegisteredDropBombFuture {
                wait: FAULT_WAIT_QUEUE.wait(),
                sleep: exec::sleep_ms(60_000),
                join: target.join(),
                probe: None,
                drops: drops.clone(),
            },
        )
    };
    assert!(exec::poll_once(), "the task must first register and park");
    assert_eq!(FAULT_WAIT_QUEUE.waiter_count(), 1);
    assert_eq!(exec::timer_registration_count(), timers_before + 1);
    assert_eq!(target.joiner_count(), joiners_before + 1);
    assert_eq!(exec::irq_poll_probe_count(), 1);

    // The synthetic guard reports a destructor fault after executing Drop.
    // Real target faults may longjmp partway through Drop, so the ledger must
    // already be empty before the guarded destructor starts.
    exec::set_fault_guard(fault_after_poll);
    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(FAULT_WAIT_QUEUE.waiter_count(), 0);
    assert_eq!(exec::timer_registration_count(), timers_before);
    assert_eq!(target.joiner_count(), joiners_before);
    assert_eq!(exec::irq_poll_probe_count(), 0);
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[domain]);
    assert_eq!(target.cancel(), CancelOutcome::Requested);
}

#[test]
fn nested_cancel_defers_a_same_arena_destructor_fault_to_the_outer_boundary() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    exec::set_fault_guard(fault_once_then_passthrough);
    RECLAIMED_DOMAINS.lock().unwrap().clear();

    let domain = AllocationDomain::new(OwnerId::new(20_006), ArenaId::new(30_006));
    let victim_drops = Arc::new(AtomicU64::new(0));
    let victim = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "nested-cancel-same-victim",
            DropBombFuture {
                drops: victim_drops.clone(),
            },
        )
    };
    assert!(exec::poll_once(), "the victim must first become parked");

    let actor_handle: Arc<Mutex<Option<exec::TaskHandle>>> = Arc::new(Mutex::new(None));
    let actor_handle_inside = actor_handle.clone();
    let actor_dropped = Arc::new(AtomicBool::new(false));
    let actor_drop_guard = DropFlag(actor_dropped.clone());
    let continued = Arc::new(AtomicBool::new(false));
    let continued_inside = continued.clone();
    let running_visible = Arc::new(AtomicBool::new(false));
    let running_visible_inside = running_visible.clone();
    let victim_inside = victim.clone();
    let actor = unsafe {
        exec::spawn_reclaimable_owned(domain, "nested-cancel-same-actor", async move {
            let _drop_guard = actor_drop_guard;
            assert_eq!(victim_inside.cancel(), CancelOutcome::Requested);
            let actor_id = actor_handle_inside.lock().unwrap().as_ref().unwrap().id();
            running_visible_inside.store(
                exec::task_report().iter().any(|task| task.id == actor_id),
                Ordering::SeqCst,
            );
            continued_inside.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        })
    };
    *actor_handle.lock().unwrap() = Some(actor.clone());

    // First guarded call polls the actor. The second is the victim's deferred
    // destructor, which synthetically faults after Drop executes.
    FAULT_AFTER_GUARDED_CALLS.store(2, Ordering::SeqCst);
    exec::set_fault_guard(fault_after_guarded_calls);
    assert!(exec::poll_once());
    assert!(continued.load(Ordering::SeqCst));
    assert!(running_visible.load(Ordering::SeqCst));
    assert_eq!(actor.state(), TaskState::Running);
    assert_eq!(victim.state(), TaskState::Running);

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(FAULT_AFTER_GUARDED_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(victim.state(), TaskState::Faulted);
    assert_eq!(actor.state(), TaskState::Faulted);
    assert_eq!(victim_drops.load(Ordering::SeqCst), 1);
    assert!(!actor_dropped.load(Ordering::SeqCst));
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[domain]);
    assert!(exec::task_report()
        .iter()
        .all(|task| task.id != actor.id() && task.id != victim.id()));
}

#[test]
fn nested_cancel_keeps_a_different_domain_running_across_destructor_fault() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    exec::set_fault_guard(fault_once_then_passthrough);
    RECLAIMED_DOMAINS.lock().unwrap().clear();

    let victim_domain =
        AllocationDomain::new(OwnerId::new(20_007), ArenaId::new(30_007));
    let actor_domain =
        AllocationDomain::new(OwnerId::new(20_008), ArenaId::new(30_008));
    let victim_drops = Arc::new(AtomicU64::new(0));
    let victim = unsafe {
        exec::spawn_reclaimable_owned(
            victim_domain,
            "nested-cancel-other-victim",
            DropBombFuture {
                drops: victim_drops.clone(),
            },
        )
    };
    assert!(exec::poll_once(), "the victim must first become parked");

    let actor_handle: Arc<Mutex<Option<exec::TaskHandle>>> = Arc::new(Mutex::new(None));
    let actor_handle_inside = actor_handle.clone();
    let actor_dropped = Arc::new(AtomicBool::new(false));
    let actor_drop_guard = DropFlag(actor_dropped.clone());
    let stage = Arc::new(AtomicU64::new(0));
    let stage_inside = stage.clone();
    let running_visible = Arc::new(AtomicBool::new(false));
    let running_visible_inside = running_visible.clone();
    let victim_inside = victim.clone();
    let actor = unsafe {
        exec::spawn_reclaimable_owned(
            actor_domain,
            "nested-cancel-other-actor",
            async move {
                let _drop_guard = actor_drop_guard;
                assert_eq!(victim_inside.cancel(), CancelOutcome::Requested);
                let actor_id = actor_handle_inside.lock().unwrap().as_ref().unwrap().id();
                running_visible_inside.store(
                    exec::task_report().iter().any(|task| task.id == actor_id),
                    Ordering::SeqCst,
                );
                stage_inside.store(1, Ordering::SeqCst);
                exec::yield_now().await;
                stage_inside.store(2, Ordering::SeqCst);
            },
        )
    };
    *actor_handle.lock().unwrap() = Some(actor.clone());

    FAULT_AFTER_GUARDED_CALLS.store(2, Ordering::SeqCst);
    exec::set_fault_guard(fault_after_guarded_calls);
    assert!(exec::poll_once());
    assert_eq!(stage.load(Ordering::SeqCst), 1);
    assert!(running_visible.load(Ordering::SeqCst));

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(victim.state(), TaskState::Faulted);
    assert_eq!(victim_drops.load(Ordering::SeqCst), 1);
    assert_eq!(actor.state(), TaskState::Running);
    assert!(exec::task_report().iter().any(|task| task.id == actor.id()));
    assert_eq!(RECLAIMED_DOMAINS.lock().unwrap().as_slice(), &[victim_domain]);

    assert!(exec::poll_once());
    assert_eq!(actor.state(), TaskState::Exited);
    assert_eq!(actor.polls(), 2);
    assert_eq!(stage.load(Ordering::SeqCst), 2);
    assert!(actor_dropped.load(Ordering::SeqCst));
}

#[test]
fn a_task_cannot_reenter_the_executor_and_overwrite_running_state() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);

    let rejected = Arc::new(AtomicBool::new(false));
    let rejected_inside = rejected.clone();
    let handle = exec::spawn_tracked("recursive-executor-drive", async move {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exec::poll_once();
        }));
        rejected_inside.store(result.is_err(), Ordering::SeqCst);
    });

    assert!(exec::poll_once());
    assert!(rejected.load(Ordering::SeqCst));
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(handle.polls(), 1);
    assert!(exec::task_report().iter().all(|task| task.id != handle.id()));
}

#[test]
fn an_untracked_fault_remains_conservative_and_never_raw_reclaims() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();

    let drops = Arc::new(AtomicU64::new(0));
    exec::set_fault_guard(fault_after_poll);
    let handle = exec::spawn_tracked_owned(
        OwnerId::new(20_005),
        "ordinary-drop-bomb",
        DropBombFuture {
            drops: drops.clone(),
        },
    );
    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(handle.arena(), ArenaId::UNTRACKED);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(RECLAIMED_DOMAINS.lock().unwrap().is_empty());
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
    assert_eq!(queue.waiter_count(), 1);
    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);
    assert_eq!(
        queue.waiter_count(),
        0,
        "cancellation drops and unregisters the suspended waiter"
    );

    queue.wake_all();
    exec::run_until_idle(BUDGET);
    assert!(!resumed.load(Ordering::SeqCst));
    assert_eq!(handle.polls(), 1);
}

#[test]
fn cancelling_many_parked_tasks_leaves_no_wait_registrations() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let mut handles = Vec::new();

    for _ in 0..256 {
        let waiter = queue.clone();
        handles.push(exec::spawn_tracked("cancel-wait-stress", async move {
            waiter.wait().await;
        }));
    }
    exec::run_until_idle(BUDGET);
    assert_eq!(queue.waiter_count(), handles.len());

    for handle in &handles {
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
    }
    assert_eq!(queue.waiter_count(), 0);

    queue.wake_all();
    exec::run_until_idle(BUDGET);
    assert!(handles
        .iter()
        .all(|handle| { handle.state() == TaskState::Cancelled && handle.polls() == 1 }));
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

/// Once the first poll registers a token, a wake must consume that token and
/// make the following poll ready rather than getting lost.
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
fn a_wait_listener_observes_a_wake_before_its_first_poll() {
    let _g = scheduler();
    let queue = WaitQueue::new();
    let counter = Arc::new(WakeCounter(AtomicU64::new(0)));
    let waker = Waker::from(counter.clone());
    let mut listener = Box::pin(queue.wait());

    queue.wake_all();

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_ready());
    assert_eq!(queue.waiter_count(), 0);
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "an unregistered listener observes the epoch without a stale wake"
    );
}

#[test]
fn a_wait_listener_repolls_pending_and_replaces_its_waker() {
    let _g = scheduler();
    let queue = WaitQueue::new();
    let first = Arc::new(WakeCounter(AtomicU64::new(0)));
    let second = Arc::new(WakeCounter(AtomicU64::new(0)));
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    let first_baseline = Arc::strong_count(&first);
    let second_baseline = Arc::strong_count(&second);
    let mut listener = Box::pin(queue.wait());

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&first_waker))
        .is_pending());
    assert_eq!(queue.waiter_count(), 1);
    assert_eq!(Arc::strong_count(&first), first_baseline + 1);

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&second_waker))
        .is_pending());
    assert_eq!(queue.waiter_count(), 1, "repoll does not duplicate entry");
    assert_eq!(Arc::strong_count(&first), first_baseline);
    assert_eq!(Arc::strong_count(&second), second_baseline + 1);

    queue.wake_all();
    assert_eq!(queue.waiter_count(), 0);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&second_waker))
        .is_ready());

    queue.wake_all();
    assert_eq!(second.0.load(Ordering::SeqCst), 1, "a token wakes once");
}

#[test]
fn dropping_a_wait_listener_unregisters_and_releases_its_waker() {
    let _g = scheduler();
    let queue = WaitQueue::new();
    let counter = Arc::new(WakeCounter(AtomicU64::new(0)));
    let waker = Waker::from(counter.clone());
    let baseline = Arc::strong_count(&counter);
    let mut listener = Box::pin(queue.wait());

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert_eq!(queue.waiter_count(), 1);
    assert_eq!(Arc::strong_count(&counter), baseline + 1);

    drop(listener);
    assert_eq!(queue.waiter_count(), 0);
    assert_eq!(Arc::strong_count(&counter), baseline);
    queue.wake_all();
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
}

#[test]
fn wait_listener_releases_a_reentrant_waker_outside_the_queue_lock() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let drops = Arc::new(AtomicU64::new(0));
    let seen = Arc::new(AtomicU64::new(u64::MAX));
    let waker = Waker::from(Arc::new(QueueDropInspectWake {
        queue: queue.clone(),
        drops: drops.clone(),
        waiters_seen_during_drop: seen.clone(),
    }));
    let mut listener = Box::pin(queue.wait());

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    drop(waker);
    drop(listener);

    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[test]
fn wait_queue_wakes_and_drops_wakers_outside_its_lock() {
    let _g = scheduler();
    let queue = Arc::new(WaitQueue::new());
    let observer = Arc::new(QueueInspectWake {
        queue: queue.clone(),
        wakes: AtomicU64::new(0),
        waiters_seen_during_wake: AtomicU64::new(u64::MAX),
    });
    let waker = Waker::from(observer.clone());
    let mut listener = Box::pin(queue.wait());

    assert!(listener
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    queue.wake_all();

    assert_eq!(observer.wakes.load(Ordering::SeqCst), 1);
    assert_eq!(
        observer.waiters_seen_during_wake.load(Ordering::SeqCst),
        0,
        "the callback re-entered the already-drained queue"
    );
}

#[test]
fn wait_queue_registration_stress_returns_to_zero() {
    let _g = scheduler();
    let queue = WaitQueue::new();
    let counter = Arc::new(WakeCounter(AtomicU64::new(0)));
    let waker = Waker::from(counter.clone());
    let mut listeners: Vec<_> = (0..512).map(|_| Box::pin(queue.wait())).collect();

    for listener in &mut listeners {
        assert!(listener
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
    }
    assert_eq!(queue.waiter_count(), 512);

    let mut survivors = listeners.split_off(256);
    drop(listeners);
    assert_eq!(queue.waiter_count(), 256);

    queue.wake_all();
    assert_eq!(queue.waiter_count(), 0);
    assert_eq!(counter.0.load(Ordering::SeqCst), 256);
    for listener in &mut survivors {
        assert!(listener
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready());
    }
}

#[test]
fn waking_many_individually_parked_tasks_does_not_allocate_ready_capacity() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let queue = Arc::new(WaitQueue::new());
    let target = exec::ready_queue_capacity() + 64;
    let mut handles = Vec::with_capacity(target);

    // Spawn and park one at a time so the ready queue itself never grows from
    // ordinary spawn pressure. Capacity must instead track the live-task bound.
    for _ in 0..target {
        let waiter = queue.clone();
        handles.push(exec::spawn_tracked("wake-capacity", async move {
            waiter.wait().await;
        }));
        assert!(exec::poll_once());
    }
    assert_eq!(queue.waiter_count(), target);
    let capacity_before_wake = exec::ready_queue_capacity();
    assert!(capacity_before_wake >= target);

    queue.wake_all();
    assert_eq!(
        exec::ready_queue_capacity(),
        capacity_before_wake,
        "IRQ-style wakes consume capacity reserved by spawn"
    );
    exec::run_until_idle(BUDGET);
    assert!(handles
        .iter()
        .all(|handle| handle.state() == TaskState::Exited));
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
fn an_irq_poll_probe_requires_a_running_task() {
    let _g = scheduler();
    assert_eq!(exec::irq_poll_probe_count(), 0);
    assert!(matches!(
        exec::arm_irq_poll_probe(),
        Err(exec::IrqPollProbeError::NotInTask)
    ));
}

#[test]
fn a_timer_irq_probe_observes_the_target_tasks_next_poll() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);
    let observed = Arc::new(AtomicU64::new(u64::MAX));
    let task_observed = observed.clone();

    exec::spawn("irq-poll-probe", async move {
        let probe = exec::arm_irq_poll_probe().expect("task owns the profiling slot");
        exec::sleep_ms(10).await;
        task_observed.store(
            probe.finish().expect("the matching timer IRQ was observed"),
            Ordering::SeqCst,
        );
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(exec::timer_registration_count(), 1);
    assert_eq!(exec::irq_poll_probe_count(), 1);
    advance_time(10 * exec::TIMEBASE_HZ / 1000);
    let irq_entry = time();
    // Eleven ticks model the architecture trap save/dispatch work before the
    // portable timer registry runs; the supplied entry timestamp must retain
    // them in the sample.
    advance_time(11);
    exec::timer_tick_at(irq_entry);
    // The remaining ticks model interrupt return and scheduler dispatch before
    // the next Future::poll endpoint.
    advance_time(26);
    exec::run_until_idle(BUDGET);

    assert_eq!(observed.load(Ordering::SeqCst), 37);
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);
}

#[test]
fn an_irq_poll_probe_ignores_another_timer_owned_by_the_same_task() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);
    let observed = Arc::new(AtomicU64::new(u64::MAX));
    let task_observed = observed.clone();

    exec::spawn("irq-poll-exact-timer", async move {
        let probe = exec::arm_irq_poll_probe().expect("task owns the profiling slot");
        let mut measured = Box::pin(exec::sleep_ms(10));
        let mut earlier = Box::pin(exec::sleep_ms(5));
        // Poll the measured timer first so it is the registration bound to the
        // probe, then wait on another timer in the same task.
        std::future::poll_fn(|cx| {
            assert!(measured.as_mut().poll(cx).is_pending());
            earlier.as_mut().poll(cx)
        })
        .await;
        assert_eq!(probe.sample(), None, "the unrelated timer poisoned the probe");
        measured.await;
        task_observed.store(
            probe.finish().expect("the bound timer IRQ was observed"),
            Ordering::SeqCst,
        );
    });
    exec::run_until_idle(BUDGET);

    advance_time(5 * exec::TIMEBASE_HZ / 1000);
    let unrelated_entry = time();
    exec::timer_tick_at(unrelated_entry);
    advance_time(7);
    exec::run_until_idle(BUDGET);
    assert_eq!(observed.load(Ordering::SeqCst), u64::MAX);
    assert_eq!(exec::irq_poll_probe_count(), 1);

    advance_time(5 * exec::TIMEBASE_HZ / 1000);
    let measured_entry = time();
    exec::timer_tick_at(measured_entry);
    advance_time(19);
    exec::run_until_idle(BUDGET);
    assert_eq!(observed.load(Ordering::SeqCst), 19);
    assert_eq!(exec::irq_poll_probe_count(), 0);
    assert_eq!(exec::timer_registration_count(), 0);
}

#[test]
fn cancelling_a_profiled_sleeper_clears_timer_and_probe_ledgers() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);

    let handle = exec::spawn_tracked("cancel-profiled-sleeper", async {
        let _probe = exec::arm_irq_poll_probe().expect("task owns the profiling slot");
        exec::sleep_ms(10).await;
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(exec::timer_registration_count(), 1);
    assert_eq!(exec::irq_poll_probe_count(), 1);

    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(exec::irq_poll_probe_count(), 0);

    advance_time(20 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.polls(), 1, "a cancelled probe cannot wake its task");
}

#[test]
fn dropping_a_probe_releases_the_single_slot_immediately() {
    let _g = scheduler();
    assert_eq!(exec::irq_poll_probe_count(), 0);
    let saw_busy = Arc::new(AtomicBool::new(false));
    let task_saw_busy = saw_busy.clone();

    exec::spawn("drop-irq-poll-probe", async move {
        let first = exec::arm_irq_poll_probe().expect("first probe owns the slot");
        task_saw_busy.store(
            matches!(
                exec::arm_irq_poll_probe(),
                Err(exec::IrqPollProbeError::Busy)
            ),
            Ordering::SeqCst,
        );
        drop(first);
        assert_eq!(exec::irq_poll_probe_count(), 0);
    });
    exec::run_until_idle(BUDGET);

    assert!(saw_busy.load(Ordering::SeqCst));
    assert_eq!(exec::irq_poll_probe_count(), 0);
}

#[test]
fn a_sleeping_task_wakes_when_its_deadline_passes() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let done = Arc::new(AtomicU64::new(0));
    let d = done.clone();

    exec::spawn("sleeper", async move {
        exec::sleep_ms(10).await;
        d.store(1, Ordering::SeqCst);
    });

    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 0, "deadline has not passed");
    assert_eq!(exec::timer_registration_count(), 1);

    // The timer interrupt alone must not wake it early.
    advance_time(exec::TIMEBASE_HZ / 1000); // 1 ms
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 0, "1 ms of a 10 ms sleep");

    advance_time(10 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert_eq!(done.load(Ordering::SeqCst), 1, "woke after the deadline");
    assert_eq!(exec::timer_registration_count(), 0);
}

#[test]
fn a_sleep_already_past_completes_without_parking() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let done = Arc::new(AtomicU64::new(0));
    let d = done.clone();

    exec::spawn("instant", async move {
        exec::sleep_ms(0).await;
        d.store(1, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(done.load(Ordering::SeqCst), 1);
    assert_eq!(exec::timer_registration_count(), 0);
}

#[test]
fn the_hardware_timer_is_armed_no_later_than_the_heartbeat() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
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
    assert_eq!(exec::timer_registration_count(), 0);
    let sleeper = exec::spawn_tracked("sleeper", async { exec::sleep_ms(10).await });
    exec::run_until_idle(BUDGET);

    let heartbeat = exec::HEARTBEAT_SECS * exec::TIMEBASE_HZ;
    let deadline = 10 * exec::TIMEBASE_HZ / 1000;
    assert_eq!(exec::timer_registration_count(), 1);
    assert!(
        armed_timer() <= deadline,
        "armed at {} for a {} tick sleep",
        armed_timer(),
        deadline
    );
    assert!(armed_timer() < heartbeat);

    assert_eq!(sleeper.cancel(), CancelOutcome::Requested);
    assert_eq!(exec::timer_registration_count(), 0);
}

#[test]
fn cancelling_a_sleeping_task_prevents_a_deadline_from_polling_it_again() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let handle = exec::spawn_tracked("cancel-sleeper", async {
        exec::sleep_ms(10).await;
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.polls(), 1);
    assert_eq!(exec::timer_registration_count(), 1);

    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    assert_eq!(
        exec::timer_registration_count(),
        0,
        "cancellation removes the timer before its deadline"
    );
    advance_time(20 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);

    assert_eq!(handle.state(), TaskState::Cancelled);
    assert_eq!(handle.polls(), 1);
}

#[test]
fn a_sleep_repoll_replaces_its_waker_and_drop_unregisters_it() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);

    let first = Arc::new(WakeCounter(AtomicU64::new(0)));
    let second = Arc::new(WakeCounter(AtomicU64::new(0)));
    let first_waker = Waker::from(first.clone());
    let second_waker = Waker::from(second.clone());
    let first_baseline = Arc::strong_count(&first);
    let second_baseline = Arc::strong_count(&second);
    let mut sleep = Box::pin(exec::sleep_ms(10));

    assert!(sleep
        .as_mut()
        .poll(&mut Context::from_waker(&first_waker))
        .is_pending());
    assert_eq!(exec::timer_registration_count(), 1);
    assert_eq!(Arc::strong_count(&first), first_baseline + 1);

    assert!(sleep
        .as_mut()
        .poll(&mut Context::from_waker(&second_waker))
        .is_pending());
    assert_eq!(exec::timer_registration_count(), 1);
    assert_eq!(Arc::strong_count(&first), first_baseline);
    assert_eq!(Arc::strong_count(&second), second_baseline + 1);

    drop(sleep);
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(Arc::strong_count(&second), second_baseline);
    advance_time(20 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 0);
}

#[test]
fn sleep_releases_a_reentrant_waker_outside_the_timer_lock() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let drops = Arc::new(AtomicU64::new(0));
    let seen = Arc::new(AtomicU64::new(u64::MAX));
    let waker = Waker::from(Arc::new(TimerDropInspectWake {
        drops: drops.clone(),
        timers_seen_during_drop: seen.clone(),
    }));
    let mut sleep = Box::pin(exec::sleep_ms(10));

    assert!(sleep
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    drop(waker);
    drop(sleep);

    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[test]
fn polling_a_past_deadline_removes_the_timer_before_the_tick() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let counter = Arc::new(WakeCounter(AtomicU64::new(0)));
    let waker = Waker::from(counter.clone());
    let mut sleep = Box::pin(exec::sleep_ms(10));

    assert!(sleep
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    advance_time(11 * exec::TIMEBASE_HZ / 1000);
    assert!(sleep
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_ready());

    assert_eq!(exec::timer_registration_count(), 0);
    exec::timer_tick();
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
}

#[test]
fn removing_the_earliest_timer_rearms_the_next_deadline() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let counter = Arc::new(WakeCounter(AtomicU64::new(0)));
    let waker = Waker::from(counter);
    let mut early = Box::pin(exec::sleep_ms(10));
    let mut late = Box::pin(exec::sleep_ms(20));

    assert!(early
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert!(late
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_pending());
    assert_eq!(exec::timer_registration_count(), 2);
    assert_eq!(armed_timer(), 10 * exec::TIMEBASE_HZ / 1000);

    drop(early);
    assert_eq!(exec::timer_registration_count(), 1);
    assert_eq!(armed_timer(), 20 * exec::TIMEBASE_HZ / 1000);

    drop(late);
    assert_eq!(exec::timer_registration_count(), 0);
    assert_eq!(armed_timer(), exec::HEARTBEAT_SECS * exec::TIMEBASE_HZ);
}

#[test]
fn cancelling_many_sleepers_leaves_no_timer_registrations() {
    let _g = scheduler();
    reset_time();
    assert_eq!(exec::timer_registration_count(), 0);
    let mut handles = Vec::new();

    for _ in 0..256 {
        handles.push(exec::spawn_tracked("cancel-timer-stress", async {
            exec::sleep_ms(1_000).await;
        }));
    }
    exec::run_until_idle(BUDGET);
    assert_eq!(exec::timer_registration_count(), handles.len());

    for handle in &handles {
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
    }
    assert_eq!(exec::timer_registration_count(), 0);

    advance_time(2_000 * exec::TIMEBASE_HZ / 1000);
    exec::timer_tick();
    exec::run_until_idle(BUDGET);
    assert!(handles
        .iter()
        .all(|handle| { handle.state() == TaskState::Cancelled && handle.polls() == 1 }));
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

#[test]
fn cancelling_a_channel_receiver_does_not_poison_the_next_receiver() {
    let _g = scheduler();
    let ep: Arc<Endpoint<u64>> = Endpoint::new("cancel-rx", 1);
    let abandoned = ep.clone();
    let cancelled = exec::spawn_tracked("cancel-channel-rx", async move {
        let _ = abandoned.recv().await;
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(cancelled.polls(), 1);
    assert_eq!(cancelled.cancel(), CancelOutcome::Requested);

    assert!(ep.try_send(41).is_ok());
    let got = Arc::new(AtomicU64::new(0));
    let fresh = ep.clone();
    let result = got.clone();
    exec::spawn("fresh-channel-rx", async move {
        result.store(fresh.recv().await, Ordering::SeqCst);
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(got.load(Ordering::SeqCst), 41);
    assert_eq!(cancelled.state(), TaskState::Cancelled);
    assert_eq!(cancelled.polls(), 1);
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

#[test]
fn cancelling_a_channel_sender_does_not_poison_the_next_sender() {
    let _g = scheduler();
    let ep: Arc<Endpoint<u64>> = Endpoint::new("cancel-tx", 1);
    assert!(ep.try_send(1).is_ok());

    let blocked = ep.clone();
    let cancelled = exec::spawn_tracked("cancel-channel-tx", async move {
        blocked.send(2).await;
    });
    exec::run_until_idle(BUDGET);
    assert_eq!(cancelled.polls(), 1);
    assert_eq!(cancelled.cancel(), CancelOutcome::Requested);

    assert_eq!(ep.try_recv(), Some(1));
    let fresh = ep.clone();
    let replacement = exec::spawn_tracked("fresh-channel-tx", async move {
        fresh.send(3).await;
    });
    exec::run_until_idle(BUDGET);

    assert_eq!(replacement.state(), TaskState::Exited);
    assert_eq!(ep.try_recv(), Some(3));
    assert_eq!(cancelled.state(), TaskState::Cancelled);
    assert_eq!(cancelled.polls(), 1);
}
