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
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker};

use vibeos_core::arch::{
    advance_time, armed_timer, current_hart_id, reset_time, set_test_hart_id, time,
};
use vibeos_core::chan::Endpoint;
use vibeos_core::exec::{self, CancelOutcome, TaskExit, TaskState, WaitQueue};
use vibeos_core::heap::{self, AllocationDomain, ArenaId, OwnerId};
use vibeos_core::instance::{
    CooperativeCancelOutcome, FaultGateOutcome, InstancePayload, InstancePhase, InstanceRegistry,
    InstanceSpace, InstanceToken, RegistryError, TerminalRetireKind,
};

static SERIAL: Mutex<()> = Mutex::new(());
static FAULT_NEXT_POLL: AtomicBool = AtomicBool::new(false);
static FAULT_AFTER_GUARDED_CALLS: AtomicU64 = AtomicU64::new(0);
static OWNER_SEEN_BY_FAULT_GUARD: Mutex<Option<OwnerId>> = Mutex::new(None);
static RECLAIMED_DOMAINS: Mutex<Vec<AllocationDomain>> = Mutex::new(Vec::new());
static CLEANED_TASKS: Mutex<Vec<(exec::TaskId, AllocationDomain)>> = Mutex::new(Vec::new());
static FAULT_WAIT_QUEUE: WaitQueue = WaitQueue::new();
static NOTIFY_EXPECTED_IDS: Mutex<Vec<exec::TaskId>> = Mutex::new(Vec::new());
static NOTIFY_CALLS: AtomicU64 = AtomicU64::new(0);
static EXCLUSIVE_REGISTRY_ACTIVE: AtomicBool = AtomicBool::new(false);
static EXCLUSIVE_NOTIFY_EXPECTED: Mutex<Vec<(exec::TaskId, AllocationDomain, exec::HartId)>> =
    Mutex::new(Vec::new());
static EXPECTED_EXCLUSIVE_FAULT: Mutex<Option<exec::TaskHandle>> = Mutex::new(None);
static EXCLUSIVE_FAULT_HOOK_CALLS: AtomicU64 = AtomicU64::new(0);
static SHARED_TEARDOWN_SIBLING: Mutex<Option<exec::TaskHandle>> = Mutex::new(None);
static SHARED_TEARDOWN_PROBES: AtomicU64 = AtomicU64::new(0);
static MANAGED_REGISTRY: AtomicPtr<InstanceRegistry> = AtomicPtr::new(core::ptr::null_mut());
static MANAGED_RECLAIMS: AtomicU64 = AtomicU64::new(0);
static MANAGED_CSPACE_INCARNATION: AtomicU64 = AtomicU64::new(0);
static MANAGED_FAULT_WITNESS: Mutex<Option<exec::ReclaimableFaultWitness>> = Mutex::new(None);
static MANAGED_FIRST_POLLS: AtomicU64 = AtomicU64::new(0);
static MANAGED_SECOND_POLLS: AtomicU64 = AtomicU64::new(0);
static MANAGED_DROPS: AtomicU64 = AtomicU64::new(0);
static MANAGED_ABANDONED_GUARD_READY: AtomicBool = AtomicBool::new(false);
static MANAGED_EARLY_FINALIZE_DONE: AtomicBool = AtomicBool::new(false);

struct PendingManagedPayload;

// Safety: this test payload is synchronous, retains neither argument, exports
// no authority, and has a trivial non-reentrant destructor.
unsafe impl InstancePayload for PendingManagedPayload {
    fn poll_quantum(&mut self, _space: &InstanceSpace, _context: &mut Context<'_>) -> Poll<u64> {
        Poll::Pending
    }
}

unsafe fn record_fault_reclaim(
    witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    let domain = witness.allocation_domain();
    RECLAIMED_DOMAINS.lock().unwrap().push(domain);
    exec::FaultReclaimOutcome::Reclaimed
}

unsafe fn record_fault_cleanup(task: exec::TaskId, domain: AllocationDomain) {
    CLEANED_TASKS.lock().unwrap().push((task, domain));
}

unsafe fn reclaim_managed_test_instance(
    witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    assert!(
        CLEANED_TASKS.lock().unwrap().is_empty(),
        "managed faults must reach the registry gate before generic fault cleanup"
    );
    *MANAGED_FAULT_WITNESS.lock().unwrap() = Some(witness);
    let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
    assert!(
        !registry.is_null(),
        "managed registry test pointer is absent"
    );
    // Safety: the serialized test retains the pointed-to registry until the
    // executor and every replay below have returned.
    match unsafe {
        (&*registry).fault_reclaim(witness, |domain| {
            assert_eq!(domain, witness.allocation_domain());
            MANAGED_RECLAIMS.fetch_add(1, Ordering::SeqCst);
            true
        })
    } {
        FaultGateOutcome::ManagedReclaimed => exec::FaultReclaimOutcome::Reclaimed,
        FaultGateOutcome::NotManaged | FaultGateOutcome::Quarantined => {
            exec::FaultReclaimOutcome::Quarantined
        }
    }
}

fn publish_managed_test_instance(
    registry: &InstanceRegistry,
    token: InstanceToken,
    domain: AllocationDomain,
    name: &str,
    future: impl Future<Output = ()> + Send + 'static,
) -> exec::TaskHandle {
    CLEANED_TASKS.lock().unwrap().clear();
    exec::set_fault_cleanup(record_fault_cleanup);
    let mut batch = exec::PreparedTaskBatch::new();
    // Safety: each caller reserves `token` for exactly `domain`, passes a
    // token-only test future, and binds that exact prepared identity before
    // the special all-or-none publication below.
    unsafe {
        batch.prepare_managed_instance_owned(token, domain, name, future);
    }
    let prepared = batch.prepared_handles()[0].clone();
    let binding = batch.prepared_reclaimable_bindings()[0];
    registry.bind(token, binding, &prepared).unwrap();
    unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
    }
    .unwrap()
    .remove(0)
}

fn restore_managed_test_hooks() {
    MANAGED_REGISTRY.store(core::ptr::null_mut(), Ordering::Release);
    exec::set_fault_guard(fault_once_then_passthrough);
    exec::set_fault_reclaimer(record_fault_reclaim);
    exec::set_fault_cleanup(ignore_fault_cleanup);
}

fn observe_exclusive_fault_gate(task: exec::TaskId, domain: AllocationDomain) {
    let handle = EXPECTED_EXCLUSIVE_FAULT
        .lock()
        .unwrap()
        .as_ref()
        .expect("exclusive fault test installed no expected handle")
        .clone();
    assert_eq!(handle.id(), task);
    assert_eq!(handle.allocation_domain(), domain);
    assert_eq!(handle.state(), TaskState::Running);
    assert_eq!(
        exec::reclaimable_domain_snapshot(domain),
        Some(exec::ReclaimableDomainSnapshot {
            home_hart: exec::HartId::new(current_hart_id()).unwrap(),
            live_tasks: 1,
            exclusive: true,
            phase: exec::ReclaimableDomainPhase::TearingDown,
        })
    );
    assert_eq!(exec::task_queue_owner(task), None);
    assert_eq!(
        exec::wake_with_disposition(task),
        exec::WakeDisposition::Inactive
    );
    assert_eq!(handle.cancel(), CancelOutcome::TooLate(TaskState::Faulted));
    EXCLUSIVE_FAULT_HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn observe_and_reclaim_exclusive_fault(
    witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    observe_exclusive_fault_gate(witness.task_id(), witness.allocation_domain());
    exec::FaultReclaimOutcome::Reclaimed
}

unsafe fn observe_and_quarantine_exclusive_fault(
    witness: exec::ReclaimableFaultWitness,
) -> exec::FaultReclaimOutcome {
    observe_exclusive_fault_gate(witness.task_id(), witness.allocation_domain());
    exec::FaultReclaimOutcome::Quarantined
}

fn cancel_committed_shared_sibling(domain: AllocationDomain) {
    let sibling = SHARED_TEARDOWN_SIBLING
        .lock()
        .unwrap()
        .as_ref()
        .expect("shared teardown probe installed no sibling")
        .clone();
    assert_eq!(sibling.allocation_domain(), domain);
    assert_eq!(sibling.state(), TaskState::Running);
    assert_eq!(
        sibling.cancel(),
        CancelOutcome::TooLate(TaskState::Faulted),
        "a committed arena sibling accepted cancellation before detach"
    );
    assert_eq!(
        exec::wake_with_disposition(sibling.id()),
        exec::WakeDisposition::Inactive
    );
    SHARED_TEARDOWN_PROBES.fetch_add(1, Ordering::SeqCst);
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

fn fault_after_abandoning_cspace(poll: &mut dyn FnMut()) -> bool {
    poll();
    assert!(
        MANAGED_ABANDONED_GUARD_READY.load(Ordering::Acquire),
        "managed poll returned without abandoning its CSpace guard"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !MANAGED_EARLY_FINALIZE_DONE.load(Ordering::Acquire)
        && std::time::Instant::now() < deadline
    {
        std::thread::yield_now();
    }
    assert!(
        MANAGED_EARLY_FINALIZE_DONE.load(Ordering::Acquire),
        "concurrent cancel/finalize probe did not return promptly"
    );
    true
}

fn fault_only_hart_one(poll: &mut dyn FnMut()) -> bool {
    if current_hart_id() == 1 {
        true
    } else {
        poll();
        false
    }
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

fn assert_batch_published_from_notify(_hart: exec::HartId) {
    let ids = NOTIFY_EXPECTED_IDS.lock().unwrap().clone();
    assert!(!ids.is_empty());
    for id in ids {
        assert!(exec::task_report().iter().any(|task| task.id == id));
        assert_ne!(
            exec::wake_with_disposition(id),
            exec::WakeDisposition::Inactive
        );
    }
    NOTIFY_CALLS.fetch_add(1, Ordering::SeqCst);
}

fn panic_after_batch_publication(_hart: exec::HartId) {
    panic!("synthetic ready notification failure after publication")
}

fn assert_exclusive_batch_active_from_notify(_hart: exec::HartId) {
    assert!(
        EXCLUSIVE_REGISTRY_ACTIVE.load(Ordering::Acquire),
        "ready notification preceded registry activation"
    );
    let expected = EXCLUSIVE_NOTIFY_EXPECTED.lock().unwrap().clone();
    assert!(!expected.is_empty());
    for (id, domain, home_hart) in expected {
        assert!(exec::task_report().iter().any(|task| task.id == id));
        assert_eq!(exec::task_queue_owner(id), Some(home_hart));
        assert_eq!(
            exec::reclaimable_domain_snapshot(domain),
            Some(exec::ReclaimableDomainSnapshot {
                home_hart,
                live_tasks: 1,
                exclusive: true,
                phase: exec::ReclaimableDomainPhase::Active,
            })
        );
    }
    NOTIFY_CALLS.fetch_add(1, Ordering::SeqCst);
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

struct ManagedDropBombFuture {
    token: InstanceToken,
}

impl Future for ManagedDropBombFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let witness = exec::current_reclaimable_task_witness()
            .expect("managed destructor poll has no executor witness");
        assert_eq!(witness.instance_token(), Some(self.token));
        Poll::Pending
    }
}

impl Drop for ManagedDropBombFuture {
    fn drop(&mut self) {
        MANAGED_DROPS.fetch_add(1, Ordering::SeqCst);
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
            this.probe =
                Some(exec::arm_irq_poll_probe().expect("the registered task owns the probe slot"));
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
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_test_hart_id(0);
    guard
}

struct TestHartScope(usize);

impl TestHartScope {
    fn enter(hart: usize) -> Self {
        let previous = current_hart_id();
        set_test_hart_id(hart);
        Self(previous)
    }
}

impl Drop for TestHartScope {
    fn drop(&mut self) {
        set_test_hart_id(self.0);
    }
}

const BUDGET: usize = 10_000;

#[test]
fn prepared_batch_is_invisible_until_atomic_publication() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let ran = Arc::new(AtomicU64::new(0));
    let mut batch = exec::PreparedTaskBatch::new();
    batch.try_reserve(2).unwrap();
    let first_ran = ran.clone();
    let first = batch.prepare("prepared-first", async move {
        first_ran.fetch_add(1, Ordering::SeqCst);
    });
    let first_id = first.id();
    let second_ran = ran.clone();
    let second = batch.prepare("prepared-second", async move {
        second_ran.fetch_add(1, Ordering::SeqCst);
    });
    let second_id = second.id();

    for hart in 0..exec::MAX_HARTS {
        let _hart = TestHartScope::enter(hart);
        assert_eq!(
            exec::wake_with_disposition(first_id),
            exec::WakeDisposition::Inactive
        );
        assert_eq!(
            exec::wake_with_disposition(second_id),
            exec::WakeDisposition::Inactive
        );
        assert_eq!(exec::task_queue_owner(first_id), None);
        assert_eq!(exec::task_queue_owner(second_id), None);
        assert!(exec::task_report()
            .iter()
            .all(|task| task.id != first_id && task.id != second_id));
        assert!(
            !exec::poll_once(),
            "a prepared task became runnable on hart {hart}"
        );
    }
    assert_eq!(ran.load(Ordering::SeqCst), 0);

    let handles = batch.publish().unwrap();
    assert!(matches!(
        batch.publish(),
        Err(exec::PreparedTaskBatchError::AlreadyPublished)
    ));
    assert_eq!(handles.len(), 2);
    assert!(exec::task_report().iter().any(|task| task.id == first_id));
    assert!(exec::task_report().iter().any(|task| task.id == second_id));
    exec::run_until_idle(BUDGET);
    assert_eq!(ran.load(Ordering::SeqCst), 2);
    assert!(handles
        .iter()
        .all(|handle| handle.state() == TaskState::Exited));
}

#[test]
fn dropping_prepared_batch_rolls_back_every_future() {
    let _g = scheduler();
    let drops = Arc::new(AtomicU64::new(0));
    let mut batch = exec::PreparedTaskBatch::new();
    let first = batch.prepare(
        "rollback-first",
        DropBombFuture {
            drops: drops.clone(),
        },
    );
    let first_id = first.id();
    let second = batch.prepare(
        "rollback-second",
        DropBombFuture {
            drops: drops.clone(),
        },
    );
    let second_id = second.id();
    drop(batch);

    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(
        exec::wake_with_disposition(first_id),
        exec::WakeDisposition::Inactive
    );
    assert_eq!(
        exec::wake_with_disposition(second_id),
        exec::WakeDisposition::Inactive
    );
    assert!(exec::task_report()
        .iter()
        .all(|task| task.id != first_id && task.id != second_id));
}

#[test]
fn prepared_handles_are_inert_until_the_whole_batch_is_published() {
    let _g = scheduler();
    let mut batch = exec::PreparedTaskBatch::new();
    batch.prepare("prepared-inert-first", std::future::pending::<()>());
    batch.prepare("prepared-inert-second", std::future::pending::<()>());
    let handles: Vec<_> = batch.prepared_handles().to_vec();

    assert!(handles.iter().all(|handle| !handle.is_published()));
    assert!(handles.iter().all(|handle| handle.try_exit().is_none()));
    assert!(handles
        .iter()
        .all(|handle| handle.cancel() == CancelOutcome::NotPublished));

    let published = batch.publish().unwrap();
    assert!(handles.iter().all(exec::TaskHandle::is_published));
    assert_eq!(
        handles.iter().map(exec::TaskHandle::id).collect::<Vec<_>>(),
        published
            .iter()
            .map(exec::TaskHandle::id)
            .collect::<Vec<_>>()
    );
    for handle in published {
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
    }
}

#[test]
fn every_notify_observes_the_complete_multi_hart_batch_publication() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let mut batch = exec::PreparedTaskBatch::new();
    batch.prepare("notify-first", std::future::pending::<()>());
    batch.prepare("notify-second", std::future::pending::<()>());
    let handles = batch.prepared_handles().to_vec();
    *NOTIFY_EXPECTED_IDS.lock().unwrap() = handles.iter().map(exec::TaskHandle::id).collect();
    NOTIFY_CALLS.store(0, Ordering::SeqCst);
    exec::set_ready_notify_hook(assert_batch_published_from_notify);

    batch.publish().unwrap();
    exec::clear_ready_notify_hook();
    assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), handles.len() as u64);

    for hart in 0..exec::MAX_HARTS {
        let _hart = TestHartScope::enter(hart);
        assert!(handles.iter().all(exec::TaskHandle::is_published));
    }
    for handle in handles {
        let _ = handle.cancel();
    }
    NOTIFY_EXPECTED_IDS.lock().unwrap().clear();
}

#[test]
fn notification_panic_cannot_roll_back_an_already_published_batch() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let ran = Arc::new(AtomicU64::new(0));
    let ran_task = ran.clone();
    let mut batch = exec::PreparedTaskBatch::new();
    batch.prepare("notify-panic", async move {
        ran_task.fetch_add(1, Ordering::SeqCst);
    });
    let handle = batch.prepared_handles()[0].clone();
    exec::set_ready_notify_hook(panic_after_batch_publication);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| batch.publish()));
    exec::clear_ready_notify_hook();
    assert!(panic.is_err());
    assert!(handle.is_published());
    drop(batch);
    exec::run_until_idle(BUDGET);
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(handle.state(), TaskState::Exited);
}

#[test]
fn faulting_prepared_rollback_leaks_conservatively_without_scheduler_visibility() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_guard(fault_once_then_passthrough);
    exec::set_fault_cleanup(record_fault_cleanup);
    exec::set_fault_reclaimer(record_fault_reclaim);
    CLEANED_TASKS.lock().unwrap().clear();
    RECLAIMED_DOMAINS.lock().unwrap().clear();

    let first_drops = Arc::new(AtomicU64::new(0));
    let second_drops = Arc::new(AtomicU64::new(0));
    let mut batch = exec::PreparedTaskBatch::new();
    let first = batch.prepare(
        "prepared-faulting-drop",
        DropBombFuture {
            drops: first_drops.clone(),
        },
    );
    let first_id = first.id();
    let domain = batch.prepared_handles()[0].allocation_domain();
    let second = batch.prepare(
        "prepared-normal-drop",
        DropBombFuture {
            drops: second_drops.clone(),
        },
    );
    let second_id = second.id();
    let tombstones = batch.prepared_handles().to_vec();

    FAULT_NEXT_POLL.store(true, Ordering::SeqCst);
    drop(batch);
    exec::set_fault_guard(fault_once_then_passthrough);

    assert_eq!(first_drops.load(Ordering::SeqCst), 0);
    assert_eq!(second_drops.load(Ordering::SeqCst), 1);
    assert_eq!(
        CLEANED_TASKS.lock().unwrap().as_slice(),
        &[(first_id, domain)]
    );
    assert!(RECLAIMED_DOMAINS.lock().unwrap().is_empty());
    for id in [first_id, second_id] {
        assert_eq!(
            exec::wake_with_disposition(id),
            exec::WakeDisposition::Inactive
        );
        assert!(exec::task_report().iter().all(|task| task.id != id));
    }
    assert!(tombstones.iter().all(|handle| !handle.is_published()));
    assert!(tombstones.iter().all(|handle| handle.try_exit().is_none()));
    exec::set_fault_cleanup(ignore_fault_cleanup);
}

#[test]
fn prepared_batch_reservation_failure_has_no_scheduler_effect() {
    let _g = scheduler();
    let reports_before = exec::task_report();
    let mut batch = exec::PreparedTaskBatch::new();
    assert!(batch.try_reserve(usize::MAX).is_err());
    drop(batch);
    assert_eq!(exec::task_report(), reports_before);
}

#[test]
fn empty_prepared_batch_fails_without_scheduler_effect() {
    let _g = scheduler();
    let reports_before = exec::task_report();
    assert!(matches!(
        exec::PreparedTaskBatch::new().publish(),
        Err(exec::PreparedTaskBatchError::Empty)
    ));
    assert_eq!(exec::task_report(), reports_before);
}

#[test]
fn exclusive_prepared_task_is_inert_until_exact_registry_activation() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let home = exec::HartId::new(2).unwrap();
    let domain = AllocationDomain::new(OwnerId::new(21_001), ArenaId::new(31_001));
    let registry_active = Arc::new(AtomicBool::new(false));
    let observed_active = registry_active.clone();
    let mut batch = exec::PreparedTaskBatch::new();
    {
        let _hart = TestHartScope::enter(home.index());
        unsafe {
            batch.prepare_exclusive_reclaimable_owned(
                domain,
                "prepared-exclusive-inert",
                async move {
                    assert!(observed_active.load(Ordering::Acquire));
                },
            );
        }
    }
    let handle = batch.prepared_handles()[0].clone();
    let binding = batch.prepared_reclaimable_bindings()[0];
    assert!(binding.matches_handle(&handle));
    assert_eq!(binding.task_id(), handle.id());
    assert_eq!(binding.allocation_domain(), domain);
    assert_eq!(binding.home_hart(), home);
    assert!(!handle.is_published());
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);

    for hart in 0..exec::MAX_HARTS {
        let _hart = TestHartScope::enter(hart);
        assert_eq!(
            exec::wake_with_disposition(handle.id()),
            exec::WakeDisposition::Inactive
        );
        assert_eq!(exec::task_queue_owner(handle.id()), None);
        assert!(exec::task_report()
            .iter()
            .all(|task| task.id != handle.id()));
        let _ = exec::poll_once();
        assert!(!handle.is_published());
    }
    assert!(matches!(
        batch.publish(),
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRequired)
    ));
    assert!(!handle.is_published());
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);

    let activation_calls = AtomicU64::new(0);
    let published = unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            activation_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(bindings.len(), 1);
            assert!(bindings[0].matches_prepared_identity(binding));
            assert!(bindings[0].scheduler_identity().is_some());
            assert!(bindings[0].matches_handle(&handle));
            assert!(!handle.is_published());
            registry_active.store(true, Ordering::Release);
            exec::PreparedReclaimableActivation::Activated
        })
    }
    .unwrap();
    assert_eq!(activation_calls.load(Ordering::SeqCst), 1);
    assert_eq!(published.len(), 1);
    assert!(handle.is_published());
    assert_eq!(
        exec::reclaimable_domain_snapshot(domain),
        Some(exec::ReclaimableDomainSnapshot {
            home_hart: home,
            live_tasks: 1,
            exclusive: true,
            phase: exec::ReclaimableDomainPhase::Active,
        })
    );
    let _ = exec::poll_once();
    assert_eq!(handle.polls(), 0, "hart 0 stole the exclusive task");
    {
        let _hart = TestHartScope::enter(home.index());
        for _ in 0..BUDGET {
            if handle.state() != TaskState::Running {
                break;
            }
            let _ = exec::poll_once();
        }
    }
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
}

#[test]
fn exclusive_prepared_aliases_are_rejected_before_registry_callback() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let drops = Arc::new(AtomicU64::new(0));
    let domain = AllocationDomain::new(OwnerId::new(21_002), ArenaId::new(31_002));
    let mut duplicate = exec::PreparedTaskBatch::new();
    for name in [
        "prepared-exclusive-duplicate-a",
        "prepared-exclusive-duplicate-b",
    ] {
        unsafe {
            duplicate.prepare_exclusive_reclaimable_owned(
                domain,
                name,
                DropBombFuture {
                    drops: drops.clone(),
                },
            );
        }
    }
    let duplicate_calls = AtomicU64::new(0);
    assert!(matches!(
        unsafe {
            duplicate.publish_exclusive_reclaimable_with(|_| {
                duplicate_calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::DuplicateReclaimableArena)
    ));
    assert_eq!(duplicate_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        unsafe {
            duplicate.publish_exclusive_reclaimable_with(|_| {
                duplicate_calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    assert!(duplicate
        .prepared_handles()
        .iter()
        .all(|handle| !handle.is_published()));
    drop(duplicate);

    let arena = ArenaId::new(31_003);
    let first = AllocationDomain::new(OwnerId::new(21_003), arena);
    let second = AllocationDomain::new(OwnerId::new(21_004), arena);
    let mut owner_alias = exec::PreparedTaskBatch::new();
    unsafe {
        owner_alias.prepare_exclusive_reclaimable_owned(
            first,
            "prepared-exclusive-owner-a",
            DropBombFuture {
                drops: drops.clone(),
            },
        );
        owner_alias.prepare_exclusive_reclaimable_owned(
            second,
            "prepared-exclusive-owner-b",
            DropBombFuture {
                drops: drops.clone(),
            },
        );
    }
    let alias_calls = AtomicU64::new(0);
    assert!(matches!(
        unsafe {
            owner_alias.publish_exclusive_reclaimable_with(|_| {
                alias_calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::ReclaimableDomainMismatch)
    ));
    assert_eq!(alias_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        unsafe {
            owner_alias.publish_exclusive_reclaimable_with(|_| {
                alias_calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    assert_eq!(exec::reclaimable_domain_snapshot(first), None);
    assert_eq!(exec::reclaimable_domain_snapshot(second), None);
    drop(owner_alias);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "tracked rollback ran Drop");
}

#[test]
fn exclusive_admission_mismatch_stays_closed_after_the_conflict_retires() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let domain = AllocationDomain::new(OwnerId::new(21_009), ArenaId::new(31_009));
    let active = unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            domain,
            "prepared-exclusive-existing-conflict",
            std::future::pending::<()>(),
        )
    };
    let drops = Arc::new(AtomicU64::new(0));
    let mut batch = exec::PreparedTaskBatch::new();
    unsafe {
        // This is an adversarial host test of the unsafe admission boundary:
        // the live scheduler record, not caller discipline, must reject it.
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-exclusive-conflicting-candidate",
            DropBombFuture {
                drops: drops.clone(),
            },
        );
    }
    let callback_calls = AtomicU64::new(0);
    let first_error = match unsafe {
        batch.publish_exclusive_reclaimable_with(|_| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
            exec::PreparedReclaimableActivation::Activated
        })
    } {
        Err(error) => error,
        Ok(_) => panic!("a live exclusive domain accepted a second incarnation"),
    };
    assert_eq!(
        first_error,
        exec::PreparedTaskBatchError::ReclaimableDomainUnavailable
    );
    assert!(first_error.requires_registry_quarantine());
    assert_eq!(callback_calls.load(Ordering::SeqCst), 0);

    assert_eq!(active.cancel(), CancelOutcome::Requested);
    assert_eq!(active.state(), TaskState::Cancelled);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    assert!(matches!(
        unsafe {
            batch.publish_exclusive_reclaimable_with(|_| {
                callback_calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
    drop(batch);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

#[test]
fn rejected_exclusive_binding_is_sticky_and_leaks_conservatively() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();
    let drops = Arc::new(AtomicU64::new(0));
    let domain = AllocationDomain::new(OwnerId::new(21_005), ArenaId::new(31_005));
    let mut batch = exec::PreparedTaskBatch::new();
    unsafe {
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-exclusive-rejected",
            DropBombFuture {
                drops: drops.clone(),
            },
        );
    }
    let handle = batch.prepared_handles()[0].clone();
    let calls = AtomicU64::new(0);
    assert!(matches!(
        unsafe {
            batch.publish_exclusive_reclaimable_with(|bindings| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(bindings.len(), 1);
                exec::PreparedReclaimableActivation::Quarantined
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    assert!(matches!(
        unsafe {
            batch.publish_exclusive_reclaimable_with(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                exec::PreparedReclaimableActivation::Activated
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!handle.is_published());
    assert_eq!(exec::task_queue_owner(handle.id()), None);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    drop(batch);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(RECLAIMED_DOMAINS.lock().unwrap().is_empty());
}

#[test]
fn rejected_mixed_batch_drops_only_the_safe_future() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_guard(fault_once_then_passthrough);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let safe_drops = Arc::new(AtomicU64::new(0));
    let tracked_drops = Arc::new(AtomicU64::new(0));
    let domain = AllocationDomain::new(OwnerId::new(21_010), ArenaId::new(31_010));
    let mut batch = exec::PreparedTaskBatch::new();
    batch.prepare(
        "prepared-mixed-safe",
        DropBombFuture {
            drops: safe_drops.clone(),
        },
    );
    unsafe {
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-mixed-tracked",
            DropBombFuture {
                drops: tracked_drops.clone(),
            },
        );
    }
    let handles = batch.prepared_handles().to_vec();
    assert!(matches!(
        unsafe {
            batch.publish_exclusive_reclaimable_with(|_| {
                exec::PreparedReclaimableActivation::Quarantined
            })
        },
        Err(exec::PreparedTaskBatchError::ExclusiveBindingRejected)
    ));
    for handle in &handles {
        assert!(!handle.is_published());
        assert_eq!(
            exec::wake_with_disposition(handle.id()),
            exec::WakeDisposition::Inactive
        );
        assert_eq!(exec::task_queue_owner(handle.id()), None);
    }
    drop(batch);
    assert_eq!(safe_drops.load(Ordering::SeqCst), 1);
    assert_eq!(tracked_drops.load(Ordering::SeqCst), 0);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
}

#[test]
fn mixed_batch_publishes_safe_and_exclusive_members_together() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let ran = Arc::new(AtomicU64::new(0));
    let safe_ran = ran.clone();
    let tracked_ran = ran.clone();
    let registry_active = Arc::new(AtomicBool::new(false));
    let observed_active = registry_active.clone();
    let domain = AllocationDomain::new(OwnerId::new(21_013), ArenaId::new(31_013));
    let mut batch = exec::PreparedTaskBatch::new();
    batch.prepare("prepared-mixed-success-safe", async move {
        safe_ran.fetch_or(1, Ordering::SeqCst);
    });
    unsafe {
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-mixed-success-exclusive",
            async move {
                assert!(observed_active.load(Ordering::Acquire));
                tracked_ran.fetch_or(2, Ordering::SeqCst);
            },
        );
    }
    let handles = batch.prepared_handles().to_vec();
    let tracked_binding = batch.prepared_reclaimable_bindings()[0];
    assert_eq!(tracked_binding.task_id(), handles[1].id());

    let published = unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            assert_eq!(bindings.len(), 1);
            assert!(bindings[0].matches_prepared_identity(tracked_binding));
            assert!(bindings[0].scheduler_identity().is_some());
            assert!(bindings[0].matches_handle(&handles[1]));
            assert!(!bindings[0].matches_handle(&handles[0]));
            registry_active.store(true, Ordering::Release);
            exec::PreparedReclaimableActivation::Activated
        })
    }
    .unwrap();
    assert_eq!(published.len(), 2);
    assert!(handles.iter().all(exec::TaskHandle::is_published));
    assert!(handles.iter().all(|handle| exec::task_report()
        .iter()
        .any(|task| task.id == handle.id())));
    exec::run_until_idle(BUDGET);
    assert_eq!(ran.load(Ordering::SeqCst), 3);
    assert!(handles
        .iter()
        .all(|handle| handle.state() == TaskState::Exited));
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
}

#[test]
fn panicking_exclusive_activation_cannot_strand_a_scheduler_node_on_host() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let drops = Arc::new(AtomicU64::new(0));
    let domain = AllocationDomain::new(OwnerId::new(21_011), ArenaId::new(31_011));
    let mut batch = exec::PreparedTaskBatch::new();
    unsafe {
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-exclusive-activation-panic",
            DropBombFuture {
                drops: drops.clone(),
            },
        );
    }
    let handle = batch.prepared_handles()[0].clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        batch.publish_exclusive_reclaimable_with(|_| panic!("synthetic registry activation panic"))
    }));
    assert!(panic.is_err());
    assert!(!handle.is_published());
    assert_eq!(
        exec::wake_with_disposition(handle.id()),
        exec::WakeDisposition::Inactive
    );
    assert_eq!(exec::task_queue_owner(handle.id()), None);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    drop(batch);
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    let probe = exec::spawn_tracked("scheduler-after-activation-panic", async {});
    exec::run_until_idle(BUDGET);
    assert_eq!(probe.state(), TaskState::Exited);
}

#[test]
fn exclusive_multi_hart_batch_is_complete_before_every_notification() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    EXCLUSIVE_REGISTRY_ACTIVE.store(false, Ordering::Release);
    NOTIFY_CALLS.store(0, Ordering::SeqCst);
    let mut batch = exec::PreparedTaskBatch::new();
    let domains = [
        AllocationDomain::new(OwnerId::new(21_006), ArenaId::new(31_006)),
        AllocationDomain::new(OwnerId::new(21_007), ArenaId::new(31_007)),
    ];
    let homes = [exec::HartId::new(1).unwrap(), exec::HartId::new(3).unwrap()];
    for (index, (domain, home)) in domains.into_iter().zip(homes).enumerate() {
        let _hart = TestHartScope::enter(home.index());
        unsafe {
            batch.prepare_exclusive_reclaimable_owned(
                domain,
                if index == 0 {
                    "prepared-exclusive-hart-one"
                } else {
                    "prepared-exclusive-hart-three"
                },
                std::future::pending::<()>(),
            );
        }
    }
    let handles = batch.prepared_handles().to_vec();
    *EXCLUSIVE_NOTIFY_EXPECTED.lock().unwrap() = handles
        .iter()
        .zip(domains)
        .zip(homes)
        .map(|((handle, domain), home)| (handle.id(), domain, home))
        .collect();
    exec::set_ready_notify_hook(assert_exclusive_batch_active_from_notify);

    unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            assert_eq!(bindings.len(), 2);
            assert!(bindings
                .iter()
                .zip(&handles)
                .all(|(binding, handle)| binding.matches_handle(handle)));
            EXCLUSIVE_REGISTRY_ACTIVE.store(true, Ordering::Release);
            exec::PreparedReclaimableActivation::Activated
        })
    }
    .unwrap();
    exec::clear_ready_notify_hook();
    assert_eq!(NOTIFY_CALLS.load(Ordering::SeqCst), 2);
    let _ = exec::poll_once();
    assert!(handles.iter().all(|handle| handle.polls() == 0));
    for (handle, home) in handles.iter().zip(homes) {
        {
            let _hart = TestHartScope::enter(home.index());
            for _ in 0..BUDGET {
                if handle.polls() != 0 {
                    break;
                }
                let _ = exec::poll_once();
            }
        }
        assert_eq!(handle.polls(), 1);
        assert_eq!(handle.cancel(), CancelOutcome::Requested);
        {
            let _hart = TestHartScope::enter(home.index());
            for _ in 0..BUDGET {
                if handle.state() != TaskState::Running {
                    break;
                }
                let _ = exec::poll_once();
            }
        }
        assert_eq!(handle.state(), TaskState::Cancelled);
    }
    EXCLUSIVE_NOTIFY_EXPECTED.lock().unwrap().clear();
}

#[test]
fn exclusive_publication_merges_with_a_nonempty_scheduler_map() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let resident = exec::spawn_tracked(
        "prepared-exclusive-map-resident",
        std::future::pending::<()>(),
    );
    assert!(exec::poll_once());
    assert_eq!(resident.polls(), 1);

    let domain = AllocationDomain::new(OwnerId::new(21_012), ArenaId::new(31_012));
    let mut batch = exec::PreparedTaskBatch::new();
    unsafe {
        batch.prepare_exclusive_reclaimable_owned(
            domain,
            "prepared-exclusive-nonempty-map",
            async {},
        );
    }
    let handle = batch.prepared_handles()[0].clone();
    unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            assert_eq!(bindings.len(), 1);
            exec::PreparedReclaimableActivation::Activated
        })
    }
    .unwrap();
    assert_eq!(resident.state(), TaskState::Running);
    assert!(exec::task_report()
        .iter()
        .any(|task| task.id == resident.id()));
    assert!(exec::task_report()
        .iter()
        .any(|task| task.id == handle.id()));
    exec::run_until_idle(BUDGET);
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(resident.state(), TaskState::Running);
    assert_eq!(resident.cancel(), CancelOutcome::Requested);
    assert_eq!(resident.state(), TaskState::Cancelled);
}

#[test]
fn exclusive_notification_panic_cannot_roll_back_registry_publication() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let home = exec::HartId::new(1).unwrap();
    let domain = AllocationDomain::new(OwnerId::new(21_008), ArenaId::new(31_008));
    let mut batch = exec::PreparedTaskBatch::new();
    {
        let _hart = TestHartScope::enter(home.index());
        unsafe {
            batch.prepare_exclusive_reclaimable_owned(
                domain,
                "prepared-exclusive-notify-panic",
                async {},
            );
        }
    }
    let handle = batch.prepared_handles()[0].clone();
    exec::set_ready_notify_hook(panic_after_batch_publication);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            assert_eq!(bindings.len(), 1);
            exec::PreparedReclaimableActivation::Activated
        })
    }));
    exec::clear_ready_notify_hook();
    assert!(panic.is_err());
    assert!(handle.is_published());
    drop(batch);
    {
        let _hart = TestHartScope::enter(home.index());
        assert!(exec::poll_once());
    }
    assert_eq!(handle.state(), TaskState::Exited);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
}

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
fn an_exclusive_reclaimable_domain_is_single_home_and_retires_after_publication() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let domains_before = exec::reclaimable_domain_count();
    let home = exec::HartId::new(2).unwrap();
    let domain = AllocationDomain::new(OwnerId::new(20_101), ArenaId::new(30_101));
    let handle = {
        let _hart = TestHartScope::enter(home.index());
        unsafe { exec::spawn_exclusive_reclaimable_owned(domain, "exclusive-home", async {}) }
    };

    assert_eq!(
        exec::reclaimable_domain_snapshot(domain),
        Some(exec::ReclaimableDomainSnapshot {
            home_hart: home,
            live_tasks: 1,
            exclusive: true,
            phase: exec::ReclaimableDomainPhase::Active,
        })
    );
    assert_eq!(exec::reclaimable_domain_count(), domains_before + 1);
    assert!(!exec::poll_once(), "hart 0 stole an exclusive task");
    {
        let _hart = TestHartScope::enter(1);
        assert!(!exec::poll_once(), "hart 1 stole an exclusive task");
    }
    assert_eq!(handle.polls(), 0);
    {
        let _hart = TestHartScope::enter(home.index());
        assert!(exec::poll_once());
        assert_eq!(handle.state(), TaskState::Exited);
        assert_eq!(
            exec::reclaimable_domain_snapshot(domain),
            None,
            "the scheduler record retired before terminal publication returned"
        );
    }
    assert_eq!(exec::reclaimable_domain_count(), domains_before);
}

#[test]
fn a_reclaimable_domain_rejects_cross_hart_and_exclusive_siblings() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let domains_before = exec::reclaimable_domain_count();
    let shared_domain = AllocationDomain::new(OwnerId::new(20_102), ArenaId::new(30_102));
    let shared = unsafe {
        exec::spawn_reclaimable_owned(shared_domain, "shared-home", std::future::pending::<()>())
    };

    let remote = {
        let _hart = TestHartScope::enter(1);
        std::panic::catch_unwind(|| unsafe {
            exec::spawn_reclaimable_owned(
                shared_domain,
                "shared-remote-sibling",
                std::future::pending::<()>(),
            )
        })
    };
    assert!(remote.is_err());
    assert_eq!(shared.polls(), 0);
    assert_eq!(shared.cancel(), CancelOutcome::Requested);
    assert_eq!(shared.state(), TaskState::Cancelled);

    let exclusive_domain = AllocationDomain::new(OwnerId::new(20_103), ArenaId::new(30_103));
    let exclusive = unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            exclusive_domain,
            "exclusive-only",
            std::future::pending::<()>(),
        )
    };
    let sibling = std::panic::catch_unwind(|| unsafe {
        exec::spawn_reclaimable_owned(
            exclusive_domain,
            "exclusive-forbidden-sibling",
            std::future::pending::<()>(),
        )
    });
    assert!(sibling.is_err());
    assert_eq!(exclusive.polls(), 0);
    assert_eq!(exclusive.cancel(), CancelOutcome::Requested);
    assert_eq!(exclusive.state(), TaskState::Cancelled);
    assert_eq!(exec::reclaimable_domain_snapshot(shared_domain), None);
    assert_eq!(exec::reclaimable_domain_snapshot(exclusive_domain), None);
    assert_eq!(exec::reclaimable_domain_count(), domains_before);
}

#[test]
fn an_exclusive_fault_closes_dispatch_before_reclaim_and_rejects_stale_events() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let domains_before = exec::reclaimable_domain_count();
    EXCLUSIVE_FAULT_HOOK_CALLS.store(0, Ordering::SeqCst);
    exec::set_fault_reclaimer(observe_and_reclaim_exclusive_fault);
    exec::set_fault_guard(fault_after_poll);
    let home = exec::HartId::new(3).unwrap();
    let domain = AllocationDomain::new(OwnerId::new(20_104), ArenaId::new(30_104));
    let handle = {
        let _hart = TestHartScope::enter(home.index());
        unsafe {
            exec::spawn_exclusive_reclaimable_owned(
                domain,
                "exclusive-fault-gate",
                std::future::pending::<()>(),
            )
        }
    };
    *EXPECTED_EXCLUSIVE_FAULT.lock().unwrap() = Some(handle.clone());

    assert!(!exec::poll_once(), "hart 0 stole the faulting task");
    {
        let _hart = TestHartScope::enter(home.index());
        assert!(exec::poll_once());
    }
    exec::set_fault_guard(fault_once_then_passthrough);
    exec::set_fault_reclaimer(record_fault_reclaim);
    EXPECTED_EXCLUSIVE_FAULT.lock().unwrap().take();

    assert_eq!(EXCLUSIVE_FAULT_HOOK_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    assert_eq!(exec::reclaimable_domain_count(), domains_before);
    assert!(matches!(
        handle.cancel(),
        CancelOutcome::AlreadyTerminal(exit) if exit.state() == TaskState::Faulted
    ));
    for _ in 0..3 {
        assert_eq!(
            exec::wake_with_disposition(handle.id()),
            exec::WakeDisposition::Inactive
        );
    }
    assert_eq!(EXCLUSIVE_FAULT_HOOK_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn a_managed_fault_uses_the_exact_registry_witness_and_resets_only_after_terminal() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let domains_before = exec::reclaimable_domain_count();
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_CSPACE_INCARNATION.store(0, Ordering::SeqCst);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    CLEANED_TASKS.lock().unwrap().clear();
    exec::set_fault_cleanup(record_fault_cleanup);
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_after_poll);

    let domain = AllocationDomain::new(OwnerId::new(20_140), ArenaId::new(30_140));
    let token = registry.reserve(domain).unwrap();
    let mut batch = exec::PreparedTaskBatch::new();
    let future = async move {
        let witness = exec::current_reclaimable_task_witness()
            .expect("managed poll has no exact executor witness");
        let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
        assert!(!registry.is_null());
        // Safety: the serialized test retains the registry and this exact
        // task is still inside the poll named by `witness`.
        unsafe {
            (&*registry)
                .with_active_space(witness, |space| {
                    MANAGED_CSPACE_INCARNATION
                        .store(space.cspace().lock().incarnation(), Ordering::SeqCst);
                })
                .unwrap();
        }
        core::future::pending::<()>().await;
    };
    // Safety: the sole arena future captures only the opaque non-owning token;
    // bind and activation complete before it becomes runnable.
    unsafe {
        batch.prepare_managed_instance_owned(token, domain, "managed-fault", future);
    }
    let prepared = batch.prepared_handles()[0].clone();
    let binding = batch.prepared_reclaimable_bindings()[0];
    registry.bind(token, binding, &prepared).unwrap();
    let handles = unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
    }
    .unwrap();
    let handle = &handles[0];

    assert!(exec::poll_once());
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert!(CLEANED_TASKS.lock().unwrap().is_empty());
    assert_eq!(
        registry.snapshot(token).unwrap().phase,
        InstancePhase::FaultReclaimed
    );
    let incarnation = MANAGED_CSPACE_INCARNATION.load(Ordering::SeqCst);
    assert_ne!(incarnation, 0);

    let finalized = unsafe {
        registry.finalize(token, handle, |retired, kind| {
            assert_eq!(retired, domain);
            assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
            true
        })
    }
    .unwrap();
    assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);

    // Replaying the executor-forged old witness cannot raw-reclaim or reset a
    // second time.  The generation mismatch is isolated as sticky quarantine.
    let stale = MANAGED_FAULT_WITNESS
        .lock()
        .unwrap()
        .take()
        .expect("managed reclaimer did not retain its witness");
    assert_eq!(
        unsafe {
            registry.fault_reclaim(stale, |_| {
                MANAGED_RECLAIMS.fetch_add(1, Ordering::SeqCst);
                true
            })
        },
        FaultGateOutcome::Quarantined
    );
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_eq!(exec::reclaimable_domain_count(), domains_before);

    restore_managed_test_hooks();
}

#[test]
fn a_managed_fault_witness_replay_before_finalize_never_reclaims_or_resets_twice() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_CSPACE_INCARNATION.store(0, Ordering::SeqCst);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_after_poll);

    let domain = AllocationDomain::new(OwnerId::new(20_141), ArenaId::new(30_141));
    let token = registry.reserve(domain).unwrap();
    let future = async move {
        let witness = exec::current_reclaimable_task_witness()
            .expect("managed replay poll has no exact executor witness");
        assert_eq!(witness.instance_token(), Some(token));
        let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
        assert!(!registry.is_null());
        unsafe {
            (&*registry)
                .with_active_space(witness, |space| {
                    MANAGED_CSPACE_INCARNATION
                        .store(space.cspace().lock().incarnation(), Ordering::SeqCst);
                })
                .unwrap();
        }
        core::future::pending::<()>().await;
    };
    let handle = publish_managed_test_instance(&registry, token, domain, "managed-replay", future);

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_ne!(MANAGED_CSPACE_INCARNATION.load(Ordering::SeqCst), 0);
    assert_eq!(
        registry.snapshot(token).unwrap().phase,
        InstancePhase::FaultReclaimed
    );

    let replay = MANAGED_FAULT_WITNESS
        .lock()
        .unwrap()
        .take()
        .expect("managed reclaimer did not retain its witness");
    assert_eq!(
        unsafe {
            registry.fault_reclaim(replay, |_| {
                MANAGED_RECLAIMS.fetch_add(1, Ordering::SeqCst);
                true
            })
        },
        FaultGateOutcome::Quarantined
    );
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_eq!(registry.snapshot(token), Err(RegistryError::Quarantined));
    assert_eq!(
        unsafe {
            registry.finalize(token, &handle, |_, _| {
                panic!("a replay-quarantined fault authorized normal close")
            })
        },
        Err(RegistryError::WrongPhase),
        "quarantine must make the sole reset path unreachable"
    );

    restore_managed_test_hooks();
}

#[test]
fn an_old_managed_fault_witness_cannot_reclaim_or_reset_a_reused_slot() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_CSPACE_INCARNATION.store(0, Ordering::SeqCst);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_after_poll);

    let old_domain = AllocationDomain::new(OwnerId::new(20_142), ArenaId::new(30_142));
    let old_token = registry.reserve(old_domain).unwrap();
    let old_future = async move {
        let witness = exec::current_reclaimable_task_witness()
            .expect("old managed poll has no exact executor witness");
        assert_eq!(witness.instance_token(), Some(old_token));
        let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
        unsafe {
            (&*registry)
                .with_active_space(witness, |space| {
                    MANAGED_CSPACE_INCARNATION
                        .store(space.cspace().lock().incarnation(), Ordering::SeqCst);
                })
                .unwrap();
        }
        core::future::pending::<()>().await;
    };
    let old_handle = publish_managed_test_instance(
        &registry,
        old_token,
        old_domain,
        "managed-aba-old",
        old_future,
    );
    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    let old_incarnation = MANAGED_CSPACE_INCARNATION.load(Ordering::SeqCst);
    let stale = MANAGED_FAULT_WITNESS
        .lock()
        .unwrap()
        .take()
        .expect("old managed fault retained no witness");
    let finalized = unsafe {
        registry.finalize(old_token, &old_handle, |retired, kind| {
            assert_eq!(retired, old_domain);
            assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
            true
        })
    }
    .unwrap();
    assert_eq!(finalized.next_cspace_incarnation, old_incarnation + 1);

    let new_domain = AllocationDomain::new(OwnerId::new(20_143), ArenaId::new(30_143));
    let new_token = registry.reserve(new_domain).unwrap();
    assert_ne!(
        new_token, old_token,
        "slot reuse must advance the generation"
    );
    MANAGED_CSPACE_INCARNATION.store(0, Ordering::SeqCst);
    let new_future = async move {
        let witness = exec::current_reclaimable_task_witness()
            .expect("new managed poll has no exact executor witness");
        assert_eq!(witness.instance_token(), Some(new_token));
        let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
        unsafe {
            (&*registry)
                .with_active_space(witness, |space| {
                    MANAGED_CSPACE_INCARNATION
                        .store(space.cspace().lock().incarnation(), Ordering::SeqCst);
                })
                .unwrap();
        }
        core::future::pending::<()>().await;
    };
    let new_handle = publish_managed_test_instance(
        &registry,
        new_token,
        new_domain,
        "managed-aba-new",
        new_future,
    );
    assert!(exec::poll_once());
    assert_eq!(
        MANAGED_CSPACE_INCARNATION.load(Ordering::SeqCst),
        finalized.next_cspace_incarnation
    );
    assert_eq!(
        registry.snapshot(new_token).unwrap().phase,
        InstancePhase::Active
    );

    assert_eq!(
        unsafe {
            registry.fault_reclaim(stale, |_| {
                MANAGED_RECLAIMS.fetch_add(1, Ordering::SeqCst);
                true
            })
        },
        FaultGateOutcome::Quarantined
    );
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_eq!(new_handle.state(), TaskState::Running);
    assert_eq!(
        registry.snapshot(new_token),
        Err(RegistryError::Quarantined)
    );
    assert_eq!(
        exec::wake_with_disposition(new_handle.id()),
        exec::WakeDisposition::Enqueued {
            hart: exec::HartId::BOOT,
        },
        "an old witness must not detach the new executor incarnation"
    );
    assert!(exec::poll_once());
    assert_eq!(new_handle.state(), TaskState::Running);
    assert_eq!(new_handle.cancel(), CancelOutcome::Requested);
    assert_eq!(new_handle.state(), TaskState::Cancelled);

    restore_managed_test_hooks();
}

#[test]
fn managed_instances_on_two_harts_fault_independently() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_FIRST_POLLS.store(0, Ordering::SeqCst);
    MANAGED_SECOND_POLLS.store(0, Ordering::SeqCst);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_once_then_passthrough);

    let first_domain = AllocationDomain::new(OwnerId::new(20_144), ArenaId::new(30_144));
    let first_token = registry.reserve(first_domain).unwrap();
    let first = {
        let _hart = TestHartScope::enter(1);
        let future = async move {
            let witness = exec::current_reclaimable_task_witness()
                .expect("hart-1 managed poll has no exact witness");
            assert_eq!(witness.instance_token(), Some(first_token));
            assert_eq!(witness.home_hart(), exec::HartId::new(1).unwrap());
            MANAGED_FIRST_POLLS.fetch_add(1, Ordering::SeqCst);
            core::future::pending::<()>().await;
        };
        publish_managed_test_instance(
            &registry,
            first_token,
            first_domain,
            "managed-hart-1",
            future,
        )
    };

    let second_domain = AllocationDomain::new(OwnerId::new(20_145), ArenaId::new(30_145));
    let second_token = registry.reserve(second_domain).unwrap();
    let second = {
        let _hart = TestHartScope::enter(3);
        let future = async move {
            let witness = exec::current_reclaimable_task_witness()
                .expect("hart-3 managed poll has no exact witness");
            assert_eq!(witness.instance_token(), Some(second_token));
            assert_eq!(witness.home_hart(), exec::HartId::new(3).unwrap());
            MANAGED_SECOND_POLLS.fetch_add(1, Ordering::SeqCst);
            core::future::pending::<()>().await;
        };
        publish_managed_test_instance(
            &registry,
            second_token,
            second_domain,
            "managed-hart-3",
            future,
        )
    };

    assert!(!exec::poll_once(), "hart 0 stole a managed instance");
    {
        let _hart = TestHartScope::enter(1);
        assert!(exec::poll_once());
    }
    assert_eq!(MANAGED_FIRST_POLLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        registry.snapshot(first_token).unwrap().phase,
        InstancePhase::Active
    );

    exec::set_fault_guard(fault_after_poll);
    {
        let _hart = TestHartScope::enter(3);
        assert!(exec::poll_once());
    }
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(MANAGED_SECOND_POLLS.load(Ordering::SeqCst), 1);
    assert_eq!(second.state(), TaskState::Faulted);
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_eq!(
        registry.snapshot(second_token).unwrap().phase,
        InstancePhase::FaultReclaimed
    );
    assert_eq!(first.state(), TaskState::Running);
    assert_eq!(
        registry.snapshot(first_token).unwrap().phase,
        InstancePhase::Active
    );

    assert_eq!(
        exec::wake_with_disposition(first.id()),
        exec::WakeDisposition::Enqueued {
            hart: exec::HartId::new(1).unwrap(),
        }
    );
    {
        let _hart = TestHartScope::enter(1);
        assert!(exec::poll_once());
    }
    assert_eq!(first.state(), TaskState::Running);
    assert_eq!(
        registry.snapshot(first_token).unwrap().phase,
        InstancePhase::Active
    );
    unsafe {
        registry.finalize(second_token, &second, |retired, kind| {
            assert_eq!(retired, second_domain);
            assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
            true
        })
    }
    .unwrap();
    {
        let _hart = TestHartScope::enter(1);
        assert_eq!(first.cancel(), CancelOutcome::Requested);
    }
    unsafe {
        registry.finalize(first_token, &first, |retired, kind| {
            assert_eq!(retired, first_domain);
            assert_eq!(kind, TerminalRetireKind::Normal);
            true
        })
    }
    .unwrap();

    restore_managed_test_hooks();
}

#[test]
fn a_managed_destructor_fault_uses_the_registry_gate() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_DROPS.store(0, Ordering::SeqCst);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_once_then_passthrough);

    let domain = AllocationDomain::new(OwnerId::new(20_146), ArenaId::new(30_146));
    let token = registry.reserve(domain).unwrap();
    let handle = publish_managed_test_instance(
        &registry,
        token,
        domain,
        "managed-destructor-fault",
        ManagedDropBombFuture { token },
    );
    assert!(exec::poll_once(), "the managed drop bomb must first park");
    assert_eq!(
        registry.snapshot(token).unwrap().phase,
        InstancePhase::Active
    );

    exec::set_fault_guard(fault_after_poll);
    assert_eq!(handle.cancel(), CancelOutcome::Requested);
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(MANAGED_DROPS.load(Ordering::SeqCst), 1);
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(
        registry.snapshot(token).unwrap().phase,
        InstancePhase::FaultReclaimed
    );
    unsafe {
        registry.finalize(token, &handle, |retired, kind| {
            assert_eq!(retired, domain);
            assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
            true
        })
    }
    .unwrap();

    restore_managed_test_hooks();
}

#[test]
fn managed_cancel_does_not_deadlock_abandoned_cspace_fault_recovery() {
    const CHILD_ENV: &str = "VIBEOS_MANAGED_CANCEL_ABANDONED_CSPACE_CHILD";
    const TEST_NAME: &str = "managed_cancel_does_not_deadlock_abandoned_cspace_fault_recovery";

    if std::env::var_os(CHILD_ENV).is_none() {
        let executable = std::env::current_exe().expect("runtime test binary has no path");
        let mut child = std::process::Command::new(executable)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .spawn()
            .expect("failed to spawn bounded abandoned-CSpace test child");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
        loop {
            if let Some(status) = child.try_wait().expect("failed to poll test child") {
                assert!(
                    status.success(),
                    "abandoned-CSpace test child failed: {status}"
                );
                return;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("abandoned-CSpace recovery or concurrent cancel deadlocked");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let registry = InstanceRegistry::new();
    MANAGED_REGISTRY.store(core::ptr::from_ref(&registry).cast_mut(), Ordering::Release);
    MANAGED_RECLAIMS.store(0, Ordering::SeqCst);
    MANAGED_CSPACE_INCARNATION.store(0, Ordering::SeqCst);
    MANAGED_ABANDONED_GUARD_READY.store(false, Ordering::Release);
    MANAGED_EARLY_FINALIZE_DONE.store(false, Ordering::Release);
    MANAGED_FAULT_WITNESS.lock().unwrap().take();
    exec::set_fault_reclaimer(reclaim_managed_test_instance);
    exec::set_fault_guard(fault_after_abandoning_cspace);

    let home = exec::HartId::new(1).unwrap();
    let domain = AllocationDomain::new(OwnerId::new(20_147), ArenaId::new(30_147));
    let token = registry.reserve(domain).unwrap();
    unsafe {
        registry
            .install_payload(token, || PendingManagedPayload)
            .unwrap();
    }
    let handle = {
        let _hart = TestHartScope::enter(home.index());
        let future = async move {
            let witness = exec::current_reclaimable_task_witness()
                .expect("abandoning managed poll has no exact witness");
            assert_eq!(witness.instance_token(), Some(token));
            assert_eq!(witness.home_hart(), home);
            let registry = MANAGED_REGISTRY.load(Ordering::Acquire);
            assert!(!registry.is_null());
            unsafe {
                (&*registry)
                    .with_active_space(witness, |space| {
                        let guard = space.cspace().lock();
                        MANAGED_CSPACE_INCARNATION.store(guard.incarnation(), Ordering::SeqCst);
                        // Safety: deliberately forgetting this exact-task
                        // guard models a target fault that abandons a Rust
                        // frame. The executor witness permanently detaches
                        // this task before the registry alone recovers the
                        // matching TaskId/domain lock provenance. The outer
                        // process kills this child on any recovery deadlock.
                        core::mem::forget(guard);
                        MANAGED_ABANDONED_GUARD_READY.store(true, Ordering::Release);
                    })
                    .unwrap();
            }
            core::future::pending::<()>().await;
        };
        publish_managed_test_instance(&registry, token, domain, "managed-abandoned-cspace", future)
    };

    let (cancel_outcome, early_finalize, elapsed) = std::thread::scope(|scope| {
        let concurrent_handle = handle.clone();
        let registry_ref = &registry;
        let attempt = scope.spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !MANAGED_ABANDONED_GUARD_READY.load(Ordering::Acquire)
                && std::time::Instant::now() < deadline
            {
                std::thread::yield_now();
            }
            assert!(
                MANAGED_ABANDONED_GUARD_READY.load(Ordering::Acquire),
                "managed task never reached the abandoned-guard point"
            );
            // Do not change the process-global host hart selector until the
            // child poll has installed its exact hart-1 witness and abandoned
            // the guard.  The polling thread is now stopped in its fault-guard
            // barrier, so hart 3 can model the remote cancel deterministically.
            let hart_scope = TestHartScope::enter(3);
            assert_eq!(concurrent_handle.state(), TaskState::Running);
            let started = std::time::Instant::now();
            let cancel = registry_ref
                .request_cooperative_cancel(token, &concurrent_handle, 0x147)
                .expect("exact concurrent cooperative cancel was rejected");
            if let CooperativeCancelOutcome::Requested(task) = cancel {
                // The API returns without any registry lock held.  A caller
                // may therefore wake only after the stable word is published.
                exec::wake(task);
            }
            let result = unsafe {
                registry_ref.finalize(token, &concurrent_handle, |_, _| {
                    panic!("pre-terminal finalize attempted arena close")
                })
            };
            let elapsed = started.elapsed();
            // The host hart selector is process-global. Restore hart 1 before
            // releasing the fault guard on the polling thread, otherwise its
            // owner/current-task scope restoration could transiently observe
            // hart 3 and make this ordering test flaky.
            drop(hart_scope);
            MANAGED_EARLY_FINALIZE_DONE.store(true, Ordering::Release);
            (cancel, result, elapsed)
        });
        {
            let _hart = TestHartScope::enter(home.index());
            assert!(exec::poll_once());
        }
        attempt.join().expect("concurrent finalize thread panicked")
    });

    assert_eq!(
        cancel_outcome,
        CooperativeCancelOutcome::Requested(handle.id())
    );
    assert_eq!(early_finalize, Err(RegistryError::TaskNotTerminal));
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "pre-terminal finalize waited on abandoned CSpace for {elapsed:?}"
    );
    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(MANAGED_RECLAIMS.load(Ordering::SeqCst), 1);
    assert!(CLEANED_TASKS.lock().unwrap().is_empty());
    assert_eq!(
        registry.snapshot(token).unwrap().phase,
        InstancePhase::FaultReclaimed
    );
    let incarnation = MANAGED_CSPACE_INCARNATION.load(Ordering::SeqCst);
    assert_ne!(incarnation, 0);
    let finalized = unsafe {
        registry.finalize(token, &handle, |retired, kind| {
            assert_eq!(retired, domain);
            assert_eq!(kind, TerminalRetireKind::FaultReclaimed);
            true
        })
    }
    .unwrap();
    assert_eq!(finalized.next_cspace_incarnation, incarnation + 1);

    restore_managed_test_hooks();
}

#[test]
fn a_refused_exclusive_reclaim_is_sticky_and_never_reopens_the_domain() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let domains_before = exec::reclaimable_domain_count();
    EXCLUSIVE_FAULT_HOOK_CALLS.store(0, Ordering::SeqCst);
    exec::set_fault_reclaimer(observe_and_quarantine_exclusive_fault);
    exec::set_fault_guard(fault_after_poll);
    let domain = AllocationDomain::new(OwnerId::new(20_105), ArenaId::new(30_105));
    let handle = unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            domain,
            "exclusive-quarantine",
            std::future::pending::<()>(),
        )
    };
    *EXPECTED_EXCLUSIVE_FAULT.lock().unwrap() = Some(handle.clone());

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    exec::set_fault_reclaimer(record_fault_reclaim);
    EXPECTED_EXCLUSIVE_FAULT.lock().unwrap().take();

    assert_eq!(handle.state(), TaskState::Faulted);
    assert_eq!(EXCLUSIVE_FAULT_HOOK_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        exec::reclaimable_domain_snapshot(domain),
        Some(exec::ReclaimableDomainSnapshot {
            home_hart: exec::HartId::new(0).unwrap(),
            live_tasks: 1,
            exclusive: true,
            phase: exec::ReclaimableDomainPhase::Quarantined,
        })
    );
    assert_eq!(exec::reclaimable_domain_count(), domains_before + 1);
    assert_eq!(exec::task_queue_owner(handle.id()), None);
    assert_eq!(
        exec::wake_with_disposition(handle.id()),
        exec::WakeDisposition::Inactive
    );
    assert!(matches!(
        handle.cancel(),
        CancelOutcome::AlreadyTerminal(exit) if exit.state() == TaskState::Faulted
    ));

    let replacement = std::panic::catch_unwind(|| unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            domain,
            "exclusive-quarantine-replacement",
            std::future::pending::<()>(),
        )
    });
    assert!(replacement.is_err());
    let wrong_owner = AllocationDomain::new(OwnerId::new(20_205), domain.arena);
    assert_eq!(
        exec::reclaimable_domain_snapshot(wrong_owner),
        None,
        "a quarantined arena aliased a different owner"
    );
    let owner_replacement = std::panic::catch_unwind(|| unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            wrong_owner,
            "exclusive-quarantine-owner-mismatch",
            std::future::pending::<()>(),
        )
    });
    assert!(owner_replacement.is_err());
    assert_eq!(EXCLUSIVE_FAULT_HOOK_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        exec::reclaimable_domain_snapshot(domain)
            .expect("quarantine disappeared")
            .phase,
        exec::ReclaimableDomainPhase::Quarantined
    );
}

#[test]
fn a_reused_exclusive_domain_ignores_the_previous_task_identity() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    let domains_before = exec::reclaimable_domain_count();
    let arena = ArenaId::new(30_106);
    let domain = AllocationDomain::new(OwnerId::new(20_106), arena);
    let first = unsafe {
        exec::spawn_exclusive_reclaimable_owned(domain, "exclusive-generation-one", async {})
    };
    assert!(exec::poll_once());
    assert_eq!(first.state(), TaskState::Exited);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);

    let next_domain = AllocationDomain::new(OwnerId::new(20_206), arena);
    let second = unsafe {
        exec::spawn_exclusive_reclaimable_owned(
            next_domain,
            "exclusive-generation-two",
            std::future::pending::<()>(),
        )
    };
    assert_ne!(first.id(), second.id());
    assert_eq!(
        exec::wake_with_disposition(first.id()),
        exec::WakeDisposition::Inactive
    );
    assert!(matches!(
        first.cancel(),
        CancelOutcome::AlreadyTerminal(exit) if exit.id() == first.id()
    ));
    assert_eq!(second.polls(), 0);
    assert_eq!(second.cancel(), CancelOutcome::Requested);
    assert_eq!(second.state(), TaskState::Cancelled);
    assert_eq!(exec::reclaimable_domain_snapshot(domain), None);
    assert_eq!(exec::reclaimable_domain_snapshot(next_domain), None);
    assert_eq!(exec::reclaimable_domain_count(), domains_before);
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
fn shared_fault_commits_every_sibling_before_the_cancel_window() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    exec::set_fault_guard(fault_after_poll);
    SHARED_TEARDOWN_PROBES.store(0, Ordering::SeqCst);
    let domain = AllocationDomain::new(OwnerId::new(20_107), ArenaId::new(30_107));
    let primary =
        unsafe { exec::spawn_reclaimable_owned(domain, "shared-commit-primary", async {}) };
    let sibling = unsafe {
        exec::spawn_reclaimable_owned(
            domain,
            "shared-commit-sibling",
            std::future::pending::<()>(),
        )
    };
    *SHARED_TEARDOWN_SIBLING.lock().unwrap() = Some(sibling.clone());
    exec::set_reclaimable_teardown_test_hook(cancel_committed_shared_sibling);

    assert!(exec::poll_once());
    exec::clear_reclaimable_teardown_test_hook();
    exec::set_fault_guard(fault_once_then_passthrough);
    SHARED_TEARDOWN_SIBLING.lock().unwrap().take();

    assert_eq!(SHARED_TEARDOWN_PROBES.load(Ordering::SeqCst), 1);
    assert_eq!(primary.state(), TaskState::Faulted);
    assert_eq!(sibling.state(), TaskState::Faulted);
    assert_eq!(sibling.polls(), 0);
    assert!(matches!(
        sibling.cancel(),
        CancelOutcome::AlreadyTerminal(exit) if exit.state() == TaskState::Faulted
    ));
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

    let victim_domain = AllocationDomain::new(OwnerId::new(20_007), ArenaId::new(30_007));
    let actor_domain = AllocationDomain::new(OwnerId::new(20_008), ArenaId::new(30_008));
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
        exec::spawn_reclaimable_owned(actor_domain, "nested-cancel-other-actor", async move {
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
        })
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
    assert_eq!(
        RECLAIMED_DOMAINS.lock().unwrap().as_slice(),
        &[victim_domain]
    );

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
    assert!(exec::task_report()
        .iter()
        .all(|task| task.id != handle.id()));
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
fn hart0_steals_each_logical_remote_task_exactly_once() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let before = exec::scheduler_stats();
    let mut counters = Vec::new();
    let mut handles = Vec::new();

    for index in 1..exec::MAX_HARTS {
        let hart = exec::HartId::new(index).unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        let task_counter = counter.clone();
        let handle = exec::spawn_tracked_on(hart, "logical-remote", async move {
            task_counter.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(exec::task_queue_owner(handle.id()), Some(hart));
        counters.push(counter);
        handles.push(handle);
    }

    exec::run_until_idle(BUDGET);
    let after = exec::scheduler_stats();
    assert!(counters
        .iter()
        .all(|counter| counter.load(Ordering::SeqCst) == 1));
    assert!(handles
        .iter()
        .all(|handle| handle.state() == TaskState::Exited && handle.polls() == 1));
    assert_eq!(
        after.harts[0].steals - before.harts[0].steals,
        (exec::MAX_HARTS - 1) as u64
    );
}

#[test]
fn pinned_remote_task_waits_for_its_exact_hart() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let remote = exec::HartId::new(1).unwrap();
    let observed = Arc::new(AtomicU64::new(u64::MAX));
    let task_observed = observed.clone();
    let handle = exec::spawn_pinned_on(remote, "pinned-logical-remote", async move {
        task_observed.store(current_hart_id() as u64, Ordering::SeqCst);
    });

    assert!(
        !exec::poll_once(),
        "the boot hart must not steal explicitly pinned work"
    );
    assert_eq!(handle.state(), TaskState::Running);
    assert_eq!(exec::task_queue_owner(handle.id()), Some(remote));

    {
        let _hart = TestHartScope::enter(remote.index());
        assert!(exec::poll_once());
    }
    assert_eq!(observed.load(Ordering::SeqCst), remote.index() as u64);
    assert_eq!(handle.state(), TaskState::Exited);
}

#[test]
fn stolen_wake_during_poll_migrates_one_ready_owner_to_hart0() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let polls = Arc::new(AtomicU64::new(0));
    let task_polls = polls.clone();
    let remote = exec::HartId::new(3).unwrap();
    let handle = exec::spawn_tracked_on(remote, "remote-self-wake", async move {
        task_polls.fetch_add(1, Ordering::SeqCst);
        exec::yield_now().await;
        task_polls.fetch_add(1, Ordering::SeqCst);
    });

    assert!(exec::poll_once());
    assert_eq!(handle.polls(), 1);
    assert_eq!(
        exec::task_queue_owner(handle.id()),
        Some(exec::HartId::BOOT)
    );
    assert_eq!(
        exec::wake_with_disposition(handle.id()),
        exec::WakeDisposition::AlreadyQueued {
            hart: exec::HartId::BOOT
        }
    );
    assert!(exec::poll_once());
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(handle.state(), TaskState::Exited);
}

#[test]
fn two_harts_keep_running_slots_current_tasks_and_domains_isolated() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);

    let outer_owner = OwnerId::new(31_000);
    let inner_owner = OwnerId::new(31_001);
    let outer_id = Arc::new(AtomicU64::new(0));
    let inner_id = Arc::new(AtomicU64::new(0));
    let outer_seen_from_inner = Arc::new(AtomicU64::new(0));
    let both_visible = Arc::new(AtomicBool::new(false));
    let first_inner_poll = Arc::new(AtomicBool::new(true));

    let inner = {
        let _hart = TestHartScope::enter(1);
        let inner_id = inner_id.clone();
        let outer_id = outer_id.clone();
        let outer_seen_from_inner = outer_seen_from_inner.clone();
        let both_visible = both_visible.clone();
        let first_inner_poll = first_inner_poll.clone();
        exec::spawn_tracked_owned(inner_owner, "m54-inner-running", async move {
            std::future::poll_fn(move |_cx| {
                let this = exec::current_task_id().expect("hart 1 task is current");
                assert_eq!(this.0, inner_id.load(Ordering::SeqCst));
                assert_eq!(heap::current_owner(), inner_owner);

                let outer = exec::TaskId(outer_id.load(Ordering::SeqCst));
                let reports = exec::task_report();
                both_visible.store(
                    reports.iter().any(|report| report.id == outer)
                        && reports.iter().any(|report| report.id == this),
                    Ordering::SeqCst,
                );

                if first_inner_poll.swap(false, Ordering::SeqCst) {
                    let _hart = TestHartScope::enter(0);
                    let active_outer =
                        exec::current_task_id().expect("hart 0 task remains current");
                    outer_seen_from_inner.store(active_outer.0, Ordering::SeqCst);
                    assert_eq!(heap::current_owner(), outer_owner);
                    assert_eq!(
                        exec::wake_with_disposition(this),
                        exec::WakeDisposition::Running {
                            hart: exec::HartId::new(1).unwrap()
                        }
                    );
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        })
    };
    inner_id.store(inner.id().0, Ordering::SeqCst);

    let outer = {
        let outer_id = outer_id.clone();
        exec::spawn_tracked_owned(outer_owner, "m54-outer-running", async move {
            let this = exec::current_task_id().expect("hart 0 task is current");
            outer_id.store(this.0, Ordering::SeqCst);
            assert_eq!(heap::current_owner(), outer_owner);
            {
                let _hart = TestHartScope::enter(1);
                assert!(exec::poll_once());
            }
            assert_eq!(exec::current_task_id(), Some(this));
            assert_eq!(heap::current_owner(), outer_owner);
        })
    };

    assert!(exec::poll_once());
    assert_eq!(outer.state(), TaskState::Exited);
    assert_eq!(outer_seen_from_inner.load(Ordering::SeqCst), outer.id().0);
    assert!(both_visible.load(Ordering::SeqCst));
    assert_eq!(inner.state(), TaskState::Running);
    assert_eq!(
        exec::task_queue_owner(inner.id()),
        Some(exec::HartId::new(1).unwrap())
    );

    {
        let _hart = TestHartScope::enter(1);
        assert!(exec::poll_once());
    }
    assert_eq!(inner.state(), TaskState::Exited);
}

#[test]
fn an_unknown_host_hart_cannot_alias_the_boot_scheduler_slot() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    let task = exec::spawn_tracked("m54-unmapped-hart", async {});

    {
        let _hart = TestHartScope::enter(exec::MAX_HARTS);
        assert_eq!(exec::current_task_id(), None);
        assert!(std::panic::catch_unwind(exec::poll_once).is_err());
    }

    assert_eq!(task.polls(), 0);
    assert_eq!(task.state(), TaskState::Running);
    assert!(exec::poll_once());
    assert_eq!(task.state(), TaskState::Exited);
}

#[test]
fn a_remote_hart_can_cancel_the_task_running_in_another_slot() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);

    let inner_handle = Arc::new(Mutex::new(None::<exec::TaskHandle>));
    let outcome = Arc::new(Mutex::new(None));
    let inner = {
        let _hart = TestHartScope::enter(1);
        let inner_handle = inner_handle.clone();
        let outcome = outcome.clone();
        exec::spawn_tracked_owned(OwnerId::new(31_011), "m54-remote-cancel", async move {
            {
                let _hart = TestHartScope::enter(0);
                assert!(exec::current_task_id().is_some());
                let handle = inner_handle.lock().unwrap().clone().unwrap();
                *outcome.lock().unwrap() = Some(handle.cancel());
            }
            std::future::pending::<()>().await;
        })
    };
    *inner_handle.lock().unwrap() = Some(inner.clone());

    let outer = exec::spawn_tracked_owned(OwnerId::new(31_010), "m54-cancel-caller", async {
        let this = exec::current_task_id().unwrap();
        {
            let _hart = TestHartScope::enter(1);
            assert!(exec::poll_once());
        }
        assert_eq!(exec::current_task_id(), Some(this));
    });

    assert!(exec::poll_once());
    assert_eq!(*outcome.lock().unwrap(), Some(CancelOutcome::Requested));
    assert_eq!(inner.state(), TaskState::Cancelled);
    assert_eq!(inner.polls(), 1);
    assert_eq!(outer.state(), TaskState::Exited);
    assert_eq!(exec::task_queue_owner(inner.id()), None);
}

#[test]
fn a_fault_on_one_hart_does_not_detach_another_harts_running_task() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_guard(fault_only_hart_one);

    let faulted = {
        let _hart = TestHartScope::enter(1);
        exec::spawn_tracked_owned(
            OwnerId::new(31_021),
            "m54-hart1-fault",
            std::future::pending::<()>(),
        )
    };
    let outer_survived = Arc::new(AtomicBool::new(false));
    let survived = outer_survived.clone();
    let outer = exec::spawn_tracked_owned(OwnerId::new(31_020), "m54-hart0-survivor", async move {
        let this = exec::current_task_id().unwrap();
        {
            let _hart = TestHartScope::enter(1);
            assert!(exec::poll_once());
        }
        assert_eq!(exec::current_task_id(), Some(this));
        assert!(exec::task_report().iter().any(|report| report.id == this));
        survived.store(true, Ordering::SeqCst);
    });

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(faulted.state(), TaskState::Faulted);
    assert_eq!(outer.state(), TaskState::Exited);
    assert!(outer_survived.load(Ordering::SeqCst));
}

#[test]
fn an_exclusive_fault_on_one_hart_preserves_another_harts_running_task() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);
    exec::set_fault_reclaimer(record_fault_reclaim);
    RECLAIMED_DOMAINS.lock().unwrap().clear();
    exec::set_fault_guard(fault_only_hart_one);

    let victim_domain = AllocationDomain::new(OwnerId::new(31_121), ArenaId::new(41_121));
    let victim = {
        let _hart = TestHartScope::enter(1);
        unsafe {
            exec::spawn_exclusive_reclaimable_owned(
                victim_domain,
                "m54-exclusive-hart1-fault",
                std::future::pending::<()>(),
            )
        }
    };
    let outer_survived = Arc::new(AtomicBool::new(false));
    let survived = outer_survived.clone();
    let outer = exec::spawn_tracked_owned(OwnerId::new(31_120), "m54-hart0-survivor", async move {
        let this = exec::current_task_id().unwrap();
        {
            let _hart = TestHartScope::enter(1);
            assert!(exec::poll_once());
        }
        assert_eq!(exec::current_task_id(), Some(this));
        assert!(exec::task_report().iter().any(|report| report.id == this));
        survived.store(true, Ordering::SeqCst);
    });

    assert!(exec::poll_once());
    exec::set_fault_guard(fault_once_then_passthrough);
    assert_eq!(victim.state(), TaskState::Faulted);
    assert_eq!(
        victim.polls(),
        0,
        "the synthetic hart fault guard fired before entering the poll closure"
    );
    assert_eq!(exec::reclaimable_domain_snapshot(victim_domain), None);
    assert_eq!(
        RECLAIMED_DOMAINS.lock().unwrap().as_slice(),
        &[victim_domain]
    );
    assert_eq!(outer.state(), TaskState::Exited);
    assert!(outer_survived.load(Ordering::SeqCst));
}

#[test]
fn remote_cancel_and_fault_leave_no_queue_owner_or_stale_wake() {
    let _g = scheduler();
    exec::run_until_idle(BUDGET);

    let cancelled = exec::spawn_tracked_on(
        exec::HartId::new(2).unwrap(),
        "remote-cancel",
        std::future::pending::<()>(),
    );
    assert_eq!(cancelled.cancel(), CancelOutcome::Requested);
    assert_eq!(cancelled.state(), TaskState::Cancelled);
    assert_eq!(cancelled.polls(), 0);
    assert_eq!(exec::task_queue_owner(cancelled.id()), None);
    assert_eq!(
        exec::wake_with_disposition(cancelled.id()),
        exec::WakeDisposition::Inactive
    );

    exec::set_fault_guard(fault_once_then_passthrough);
    FAULT_NEXT_POLL.store(true, Ordering::SeqCst);
    let faulted = exec::spawn_tracked_on(
        exec::HartId::new(1).unwrap(),
        "remote-fault",
        std::future::pending::<()>(),
    );
    assert!(exec::poll_once());
    assert_eq!(faulted.state(), TaskState::Faulted);
    assert_eq!(exec::task_queue_owner(faulted.id()), None);
    assert_eq!(
        exec::wake_with_disposition(faulted.id()),
        exec::WakeDisposition::Inactive
    );
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
        assert_eq!(
            probe.sample(),
            None,
            "the unrelated timer poisoned the probe"
        );
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
