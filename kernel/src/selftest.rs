//! In-kernel self-test.
//!
//! Host unit tests cover logic; these cover the things a host cannot fake —
//! real timer interrupts, real wakeups from a trap handler, the live capability
//! graph, and machine code actually executing. CI drives this through the shell
//! and fails the build on a nonzero failure count.
//!
//! Both bugs that have reached `main` so far are regression cases here.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use crate::cap::{CSpace, CapError, Rights};
use crate::chan::Endpoint;
use crate::dev::{ConsoleDev, MemoryInvocation, MemoryRegion};
use crate::trampoline::{self, CatchThunk, JmpBuf};
use crate::world::{world, Space};
use crate::{exec, heap, println, sbi};

pub struct Report {
    pub passed: usize,
    pub failed: usize,
}

struct Harness {
    passed: usize,
    failures: Vec<String>,
}

struct PanicOnDrop;

struct CountingWake(AtomicUsize);

const CATCH_STATUS: i64 = 0x315;
const NESTED_CATCHES: usize = 8;
const NESTED_STATUS_BASE: i64 = 0x380;
const CATCH_CANARY_LOW: u64 = 0x1357_2468_89ab_cdef;
const CATCH_CANARY_HIGH: u64 = 0xfedc_ba98_7531_6420;

#[repr(C)]
struct CatchJump {
    buf: *mut JmpBuf,
    status: i64,
}

struct NestedCatchState {
    caught: usize,
    mismatches: usize,
}

#[repr(C)]
struct NestedCatch {
    buf: *mut JmpBuf,
    level: usize,
    state: *mut NestedCatchState,
    low: u64,
    high: u64,
}

struct NestedTaskFault {
    entered: usize,
    caught: usize,
    canary_failures: usize,
}

unsafe extern "C" fn catch_noop(_ctx: *mut ()) {}

unsafe extern "C" fn catch_disable_irqs(_ctx: *mut ()) {
    let _ = sbi::irq_save();
}

unsafe extern "C" fn catch_enable_irqs(_ctx: *mut ()) {
    sbi::enable_interrupts();
}

unsafe extern "C" fn catch_disable_irqs_and_jump(ctx: *mut ()) {
    // Safety: catcher_abi supplies this exact context for an active buffer.
    let jump = unsafe { &*ctx.cast::<CatchJump>() };
    let _ = sbi::irq_save();
    unsafe { trampoline::vibe_longjmp(jump.buf, jump.status) }
}

unsafe extern "C" fn catch_enable_irqs_and_jump(ctx: *mut ()) {
    // Safety: catcher_abi supplies this exact context for an active buffer.
    let jump = unsafe { &*ctx.cast::<CatchJump>() };
    sbi::enable_interrupts();
    unsafe { trampoline::vibe_longjmp(jump.buf, jump.status) }
}

fn interrupts_enabled() -> bool {
    let enabled = sbi::irq_save();
    sbi::irq_restore(enabled);
    enabled
}

fn run_nested_catch(level: usize, state: *mut NestedCatchState) -> i64 {
    let mut buf = JmpBuf::ZERO;
    let mut catch = NestedCatch {
        buf: &mut buf,
        level,
        state,
        low: CATCH_CANARY_LOW,
        high: CATCH_CANARY_HIGH,
    };
    let status = unsafe {
        trampoline::vibe_catch(
            &mut buf,
            nested_catch_thunk,
            (&mut catch as *mut NestedCatch).cast(),
        )
    };
    if catch.low != CATCH_CANARY_LOW || catch.high != CATCH_CANARY_HIGH {
        // Safety: every recursive frame receives the same live state pointer.
        unsafe { (*state).mismatches += 1 };
    }
    status
}

unsafe extern "C" fn nested_catch_thunk(ctx: *mut ()) {
    // Safety: run_nested_catch keeps this context alive until its catch returns.
    let catch = unsafe { &mut *ctx.cast::<NestedCatch>() };
    if catch.level + 1 < NESTED_CATCHES {
        let child = run_nested_catch(catch.level + 1, catch.state);
        if child != NESTED_STATUS_BASE + catch.level as i64 + 1 {
            unsafe { (*catch.state).mismatches += 1 };
        }
    }
    unsafe { (*catch.state).caught += 1 };
    unsafe { trampoline::vibe_longjmp(catch.buf, NESTED_STATUS_BASE + catch.level as i64) }
}

fn nested_task_panic(remaining: usize, state: &mut NestedTaskFault) -> bool {
    let mut canaries = [CATCH_CANARY_LOW, CATCH_CANARY_HIGH];
    core::hint::black_box(&mut canaries);
    let mut body = || {
        state.entered += 1;
        if remaining == 1 {
            panic!("deliberate nested catcher fault from the self-test");
        }
        if nested_task_panic(remaining - 1, state) {
            state.caught += 1;
        }
    };
    let faulted = trampoline::guard_task(&mut body);
    core::hint::black_box(&mut canaries);
    if canaries != [CATCH_CANARY_LOW, CATCH_CANARY_HIGH] {
        state.canary_failures += 1;
    }
    faulted
}

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Future for PanicOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("deliberate destructor fault from the self-test");
    }
}

fn nested_task_fault_guard(
    remaining: usize,
    entered: &mut usize,
    overflow_seen: &mut bool,
) -> bool {
    let mut body = || {
        *entered += 1;
        if remaining != 0 && nested_task_fault_guard(remaining - 1, entered, overflow_seen) {
            *overflow_seen = true;
        }
    };
    crate::trampoline::guard_task(&mut body)
}

impl Harness {
    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failures.push(String::from(name));
        }
    }

    fn eq<T: PartialEq + core::fmt::Debug>(&mut self, name: &str, got: T, want: T) {
        if got == want {
            self.passed += 1;
        } else {
            self.failures
                .push(format!("{} (got {:?}, want {:?})", name, got, want));
        }
    }
}

pub async fn run() -> Report {
    let mut h = Harness {
        passed: 0,
        failures: Vec::new(),
    };

    paging(&mut h);
    timers(&mut h).await;
    scheduler(&mut h).await;
    cancellation(&mut h).await;
    catcher_abi(&mut h).await;
    components(&mut h);
    component_restart(&mut h).await;
    channels(&mut h).await;
    fault_isolation(&mut h).await;
    component_memory(&mut h).await;
    fault_arena_restart(&mut h).await;
    capabilities(&mut h);
    compiler(&mut h);

    for f in &h.failures {
        println!("  FAIL  {}", f);
    }
    println!(
        "  selftest: {} passed, {} failed",
        h.passed,
        h.failures.len()
    );
    Report {
        passed: h.passed,
        failed: h.failures.len(),
    }
}

/// M6.1--M6.3: one identity-mapped Sv39 root is active on every online hart;
/// stack guards, W^X, execute-only code, and non-executable devices are live.
fn paging(h: &mut Harness) {
    use vibeos_core::mmu::{PagePermissions, PAGE_SIZE};

    h.check(
        "the current hart has Sv39 enabled",
        crate::mmu::local_paging_enabled(),
    );
    h.eq(
        "every online hart read back the shared satp root",
        crate::mmu::enabled_hart_mask(),
        crate::online_hart_mask(),
    );
    h.eq(
        "every paging-enabled hart cleared sstatus.MXR",
        crate::mmu::mxr_cleared_hart_mask(),
        crate::mmu::enabled_hart_mask(),
    );
    h.eq(
        "the Sv39 root is page aligned",
        crate::mmu::root_physical() % PAGE_SIZE,
        0,
    );

    let text_address = paging as *const () as usize;
    let text = crate::mmu::mapping(text_address).expect("self-test text is mapped");
    h.eq(
        "kernel text remains identity mapped",
        text.physical,
        text_address,
    );
    h.eq("kernel RAM uses 4 KiB leaves", text.page_size, PAGE_SIZE);
    h.eq(
        "kernel text is readable and executable but not writable",
        text.permissions,
        PagePermissions::READ.union(PagePermissions::EXECUTE),
    );
    h.check(
        "multicore W^X has synchronous SBI RFENCE support",
        crate::mmu::wx_remote_fence_ready(),
    );
    let (code_start, code_end) = crate::mmu::code_pool_range();
    h.check(
        "free code-pool endpoints are identity-mapped RW-NX pages",
        [code_start, code_end - PAGE_SIZE]
            .into_iter()
            .all(|address| {
                crate::mmu::mapping(address).is_some_and(|mapping| {
                    mapping.physical == address
                        && mapping.page_size == PAGE_SIZE
                        && mapping.permissions
                            == PagePermissions::READ.union(PagePermissions::WRITE)
                })
            }),
    );
    h.eq(
        "no mapped RAM page is both writable and executable",
        crate::mmu::first_writable_executable_ram_page(),
        None,
    );

    for (name, address) in [
        ("PLIC is identity mapped", crate::mmu::PLIC_START),
        (
            "UART/virtio is identity mapped",
            crate::mmu::UART_VIRTIO_START,
        ),
    ] {
        let device = crate::mmu::mapping(address).expect("required MMIO aperture is mapped");
        h.eq(name, device.physical, address);
        h.eq("MMIO uses 4 KiB leaves", device.page_size, PAGE_SIZE);
        h.check(
            "MMIO is readable and writable but not executable",
            device
                .permissions
                .contains(PagePermissions::READ.union(PagePermissions::WRITE))
                && !device.permissions.contains(PagePermissions::EXECUTE),
        );
    }
    h.check(
        "the null page is absent from the shared address space",
        crate::mmu::mapping(0).is_none(),
    );
    h.check(
        "the OpenSBI firmware prefix is absent from S-mode mappings",
        crate::mmu::mapping(0x8000_0000).is_none(),
    );
    h.check(
        "RAM beyond the configured machine is absent",
        crate::mmu::mapping(crate::mmu::KERNEL_RAM_END).is_none(),
    );
    h.check(
        "unused PLIC pages are absent",
        crate::mmu::mapping(crate::mmu::PLIC_START + PAGE_SIZE).is_none(),
    );
    let boot_physical = sbi::current_hart_id();
    let boot_s_context = crate::mmu::plic_s_context_page(boot_physical)
        .expect("the boot physical hart is within the dense QEMU topology");
    h.check(
        "only the boot hart's PLIC S-context is mapped",
        crate::mmu::mapping(boot_s_context).is_some(),
    );
    h.check(
        "PLIC M-context and unused S-context pages are absent",
        (0..exec::MAX_HARTS * 2)
            .map(|context| crate::mmu::PLIC_CONTEXT_START + context * PAGE_SIZE)
            .filter(|address| *address != boot_s_context)
            .all(|address| crate::mmu::mapping(address).is_none()),
    );
    h.check(
        "the end of the PLIC aperture is absent",
        crate::mmu::mapping(crate::mmu::PLIC_END).is_none(),
    );
    h.check(
        "unused UART/virtio pages are absent",
        crate::mmu::mapping(crate::mmu::UART_VIRTIO_END).is_none(),
    );
    h.check(
        "the diagnostic walker rejects non-canonical Sv39 addresses",
        crate::mmu::mapping(1usize << 39).is_none(),
    );
    h.check(
        "every logical stack guard is unmapped",
        (0..exec::MAX_HARTS).all(|index| {
            crate::mmu::stack_guard_page(index)
                .is_some_and(|guard| crate::mmu::mapping(guard).is_none())
        }),
    );
    h.check(
        "every usable stack begins and ends on identity-mapped RW-NX pages",
        (0..exec::MAX_HARTS).all(|index| {
            let Some(start) = crate::mmu::stack_usable_start(index) else {
                return false;
            };
            let end = crate::mmu::stack_guard_page(index).expect("guard exists")
                + crate::mmu::STACK_SLOT_STRIDE
                - PAGE_SIZE;
            [start, end].into_iter().all(|address| {
                crate::mmu::mapping(address).is_some_and(|mapping| {
                    mapping.physical == address
                        && mapping.page_size == PAGE_SIZE
                        && mapping
                            .permissions
                            .contains(PagePermissions::READ.union(PagePermissions::WRITE))
                        && !mapping.permissions.contains(PagePermissions::EXECUTE)
                })
            })
        }),
    );
    let current_hart =
        crate::ipi::current_logical_hart().expect("self-test runs on a registered hart");
    h.eq(
        "generated code retains 8 KiB of mapped abort stack above the guard",
        crate::stack_floor(),
        crate::mmu::stack_usable_start(current_hart.index())
            .expect("current stack slot exists")
            + 8192,
    );
    h.check(
        "stack guards are page-aligned, evenly strided, and exclude usable bytes",
        (0..exec::MAX_HARTS).all(|index| {
            let guard = crate::mmu::stack_guard_page(index).expect("guard exists");
            guard % PAGE_SIZE == 0
                && (index == 0
                    || guard
                        - crate::mmu::stack_guard_page(index - 1).expect("previous guard exists")
                        == crate::mmu::STACK_SLOT_STRIDE)
                && crate::mmu::stack_guard_hart(guard) == Some(index)
                && crate::mmu::stack_guard_hart(guard + crate::mmu::STACK_GUARD_SIZE).is_none()
        }),
    );
}

/// ROADMAP 3.12. A restart keeps the supervised identity and Space route while
/// replacing the task incarnation and every explicitly granted capability.
async fn component_restart(h: &mut Harness) {
    let w = world();
    let guest = w
        .component_named("guest")
        .expect("the system image has a guest component");
    let stable_space = guest.space();
    let before = guest.snapshot();
    let stable_owner = guest.memory_owner();
    let stale_cap = stable_space
        .0
        .lock()
        .list()
        .first()
        .expect("guest begins with one console grant")
        .0;
    let (_, stale_join) = guest.join_current();

    h.eq(
        "the boot guest can be stopped for restart",
        guest.cancel(),
        exec::CancelOutcome::Requested,
    );
    h.eq(
        "the pre-restart join retains the cancelled incarnation",
        stale_join.await.state(),
        exec::TaskState::Cancelled,
    );

    let report = w
        .restart_component("guest")
        .expect("guest has an audited restart template");
    let after = guest.snapshot();
    h.eq("restart retains ComponentId", after.id, before.id);
    h.eq(
        "restart increments the component generation",
        after.generation,
        before.generation + 1,
    );
    h.check(
        "restart installs a fresh TaskId",
        after.task_id != before.task_id && after.task_id == report.new_task,
    );
    h.eq(
        "restart preserves the allocation owner",
        guest.memory_owner(),
        stable_owner,
    );
    h.check(
        "restart preserves the boot-static Space route",
        Arc::ptr_eq(&stable_space, &guest.space()),
    );
    h.eq(
        "a stale capability cannot alias a fresh-incarnation slot",
        stable_space.0.lock().lookup(stale_cap, Rights::WRITE).err(),
        Some(CapError::Invalid),
    );
    let fresh_caps = stable_space.0.lock().list();
    h.eq(
        "the fresh guest CSpace is explicitly regranted once",
        fresh_caps.len(),
        1,
    );
    h.eq(
        "the fresh guest grant remains WRITE-only",
        stable_space.0.lock().rights_of(fresh_caps[0].0),
        Ok(Rights::WRITE),
    );
    h.eq(
        "a running incarnation cannot be restarted over itself",
        w.restart_component("guest").err(),
        Some(crate::world::RestartError::StillRunning),
    );
}

/// Needs a real timer interrupt to fire and a real waker to run.
async fn timers(h: &mut Harness) {
    let start = sbi::time();
    exec::sleep_ms(25).await;
    let elapsed_ms = (sbi::time() - start) / (exec::TIMEBASE_HZ / 1000);
    h.check(
        "sleep_ms waits at least the requested time",
        elapsed_ms >= 25,
    );
    // With the check-then-sleep race closed, the heartbeat is 10 s and no longer
    // masks a lost wake. Anything past a few ms here means the wake was lost and
    // we are riding the backstop -- which would now show up as a 10 s stall.
    h.check("sleep_ms wakes promptly", elapsed_ms < 100);

    let t0 = sbi::time();
    exec::sleep_ms(0).await;
    h.check(
        "sleep_ms(0) does not block",
        sbi::time() - t0 < exec::TIMEBASE_HZ / 100,
    );
}

async fn scheduler(h: &mut Harness) {
    // Regression: a task that wakes itself mid-poll had the wake dropped,
    // because `poll_once` lifts the task out of the map before polling it.
    // `yield_now` is exactly that case, and it hung the shell.
    let before = sbi::time();
    for _ in 0..64 {
        exec::yield_now().await;
    }
    h.check(
        "yield_now resumes (self-wake during poll)",
        sbi::time() >= before,
    );

    h.check(
        "task_report sees the running components",
        exec::task_report().len() >= 3,
    );

    // Regression: `ps` omitted the task being polled, because `poll_once` lifts
    // it out of the map first. The only faithful way to test that is to ask
    // from inside a task's own poll, so a probe task reports on itself.
    let ep: Arc<Endpoint<(bool, u64)>> = Endpoint::new("selftest-probe", 1);
    let tx = ep.clone();
    exec::spawn("selftest-probe", async move {
        exec::yield_now().await; // guarantee this is not the first poll
        let seen = exec::task_report()
            .into_iter()
            .find(|report| report.name == "selftest-probe")
            .map(|report| report.polls);
        tx.send((seen.is_some(), seen.unwrap_or(0))).await;
    });
    let (visible, polls) = ep.recv().await;
    h.check(
        "a task polling right now is visible in task_report",
        visible,
    );
    h.check("poll counts advance", polls > 1);
}

/// ROADMAP 3.9. Cancellation is cooperative for a task inside `poll`, but a
/// ready or parked future is detached and reclaimed without one extra poll.
async fn cancellation(h: &mut Harness) {
    let cancelled_before = exec::cancelled_count();
    let ready = exec::spawn_tracked("selftest-cancel-ready", async {
        panic!("a cancelled ready task must never be polled");
    });
    h.eq(
        "cancelling a ready task is accepted",
        ready.cancel(),
        exec::CancelOutcome::Requested,
    );
    h.eq(
        "a ready task is cancelled before its first poll",
        ready.polls(),
        0,
    );
    let ready_exit = ready.join().await;
    h.eq(
        "a cancelled task retains its exact state",
        ready.state(),
        exec::TaskState::Cancelled,
    );
    h.eq(
        "join reports a cancelled exit",
        ready_exit.state(),
        exec::TaskState::Cancelled,
    );

    let queue = Arc::new(exec::WaitQueue::new());
    let waiter = queue.clone();
    let parked = exec::spawn_tracked("selftest-cancel-parked", async move {
        waiter.wait().await;
        panic!("a cancelled parked task must never resume");
    });
    exec::yield_now().await;
    h.eq(
        "the cancellation probe parked after one poll",
        parked.polls(),
        1,
    );
    h.eq(
        "the parked cancellation probe owns one wait registration",
        queue.waiter_count(),
        1,
    );
    h.eq(
        "cancelling a parked task is accepted",
        parked.cancel(),
        exec::CancelOutcome::Requested,
    );
    let parked_exit = parked.join().await;
    h.eq(
        "join reports the parked task cancellation",
        parked_exit.state(),
        exec::TaskState::Cancelled,
    );
    h.eq(
        "cancelling a parked task removes its wait registration",
        queue.waiter_count(),
        0,
    );
    queue.wake_all();
    for _ in 0..2 {
        exec::yield_now().await;
    }
    h.eq(
        "a cancelled parked task is not polled again",
        parked.polls(),
        1,
    );
    h.eq(
        "kernel cancellation accounting advances",
        exec::cancelled_count(),
        cancelled_before + 2,
    );

    let faults_before = exec::faulted_count();
    let bad_drop = exec::spawn_tracked("selftest-drop-fault", PanicOnDrop);
    h.eq(
        "cancelling a task with a faulting destructor returns control",
        bad_drop.cancel(),
        exec::CancelOutcome::Requested,
    );
    let bad_drop_exit = bad_drop.join().await;
    h.eq(
        "a faulting destructor takes precedence over cancellation",
        bad_drop_exit.state(),
        exec::TaskState::Faulted,
    );
    h.eq(
        "a faulting destructor is counted in its task domain",
        exec::faulted_count(),
        faults_before + 1,
    );

    let timer_wakes = Arc::new(CountingWake(AtomicUsize::new(0)));
    let timer_waker = Waker::from(timer_wakes.clone());
    let timer_waker_baseline = Arc::strong_count(&timer_wakes);
    let mut sleep = exec::sleep_ms(60_000);
    h.check(
        "a live sleep registers its waker",
        Pin::new(&mut sleep)
            .poll(&mut Context::from_waker(&timer_waker))
            .is_pending(),
    );
    h.eq(
        "the timer registry owns exactly one waker reference",
        Arc::strong_count(&timer_wakes),
        timer_waker_baseline + 1,
    );
    drop(sleep);
    h.eq(
        "dropping a sleep releases its timer waker immediately",
        Arc::strong_count(&timer_wakes),
        timer_waker_baseline,
    );
    h.eq(
        "dropping a sleep does not spuriously wake it",
        timer_wakes.0.load(Ordering::SeqCst),
        0,
    );

    let mut guards_entered = 0;
    let mut guard_overflow_seen = false;
    let outer_faulted = nested_task_fault_guard(8, &mut guards_entered, &mut guard_overflow_seen);
    h.check(
        "outer fault guard survives nested saturation",
        !outer_faulted,
    );
    h.check(
        "nested fault guard saturation reports a local fault",
        guard_overflow_seen,
    );
    h.eq(
        "nested fault guard saturation skips the overflowing body",
        guards_entered,
        7,
    );

    let mut recovery_ran = false;
    let recovery_faulted = crate::trampoline::guard_task(&mut || recovery_ran = true);
    h.check(
        "fault guard depth recovers after saturation",
        !recovery_faulted,
    );
    h.check(
        "fault guard accepts later work after saturation",
        recovery_ran,
    );
}

/// ROADMAP 3.15. Rust sees a conventional, single-return FFI call even though
/// a panic or generated-code abort may abandon every frame inside its thunk.
/// Exercise the actual release ABI on target, including the state LLVM assumes
/// a C callee preserves.
fn catcher_abi_sync(h: &mut Harness) {
    h.eq(
        "catch buffer has the assembly ABI size",
        core::mem::size_of::<JmpBuf>(),
        128,
    );
    h.eq(
        "catch buffer has the assembly ABI alignment",
        core::mem::align_of::<JmpBuf>(),
        16,
    );

    let mut normal_buf = JmpBuf::ZERO;
    let normal_mismatches = unsafe {
        trampoline::vibe_catch_abi_probe(&mut normal_buf, catch_noop, core::ptr::null_mut(), 0)
    };
    h.eq(
        "normal catch preserves callee registers, stack, and canaries",
        normal_mismatches,
        0,
    );

    let mut jump_buf = JmpBuf::ZERO;
    let mut jump = CatchJump {
        buf: &mut jump_buf,
        status: CATCH_STATUS,
    };
    let jump_mismatches = unsafe {
        trampoline::vibe_catch_abi_probe(
            &mut jump_buf,
            trampoline::vibe_catch_test_jump as CatchThunk,
            (&mut jump as *mut CatchJump).cast(),
            CATCH_STATUS,
        )
    };
    h.eq(
        "longjmp restores callee registers, exact stack, and canaries",
        jump_mismatches,
        0,
    );

    let mut zero_buf = JmpBuf::ZERO;
    let mut zero_jump = CatchJump {
        buf: &mut zero_buf,
        status: 0,
    };
    let zero_mismatches = unsafe {
        trampoline::vibe_catch_abi_probe(
            &mut zero_buf,
            trampoline::vibe_catch_test_jump as CatchThunk,
            (&mut zero_jump as *mut CatchJump).cast(),
            1,
        )
    };
    h.eq(
        "a zero longjmp status is normalized to one",
        zero_mismatches,
        0,
    );

    let mut nested = NestedCatchState {
        caught: 0,
        mismatches: 0,
    };
    let outer_status = run_nested_catch(0, &mut nested);
    h.eq(
        "eight nested catchers return the outer status",
        outer_status,
        NESTED_STATUS_BASE,
    );
    h.eq(
        "eight nested catchers each take a non-local exit",
        nested.caught,
        NESTED_CATCHES,
    );
    h.eq(
        "eight nested catcher frames retain statuses and canaries",
        nested.mismatches,
        0,
    );

    // The executor's guard around this self-test is the first active layer;
    // these seven make eight total and panic in the deepest one.
    let mut task_nested = NestedTaskFault {
        entered: 0,
        caught: 0,
        canary_failures: 0,
    };
    let outer_faulted = nested_task_panic(7, &mut task_nested);
    h.check(
        "an eight-layer task catch faults only the innermost guard",
        !outer_faulted,
    );
    h.eq(
        "all seven nested task bodies run before the deepest panic",
        task_nested.entered,
        7,
    );
    h.eq(
        "exactly one nested task guard observes the panic",
        task_nested.caught,
        1,
    );
    h.eq(
        "nested task catch restores every caller stack canary",
        task_nested.canary_failures,
        0,
    );
    let mut fresh_ran = false;
    let fresh_faulted = trampoline::guard_task(&mut || fresh_ran = true);
    h.check(
        "a fresh task catch runs after an eight-layer fault",
        !fresh_faulted && fresh_ran,
    );

    let original_irq = interrupts_enabled();
    h.check(
        "catcher ABI tests begin with interrupts enabled",
        original_irq,
    );
    if !original_irq {
        sbi::enable_interrupts();
    }

    let mut enabled_normal_buf = JmpBuf::ZERO;
    let enabled_normal_status = unsafe {
        trampoline::vibe_catch(
            &mut enabled_normal_buf,
            catch_disable_irqs,
            core::ptr::null_mut(),
        )
    };
    let enabled_after_normal = interrupts_enabled();
    h.eq(
        "normal catch returns zero after masking interrupts",
        enabled_normal_status,
        0,
    );
    h.check(
        "normal catch restores an enabled IRQ entry state",
        enabled_after_normal,
    );

    let mut enabled_jump_buf = JmpBuf::ZERO;
    let mut enabled_jump = CatchJump {
        buf: &mut enabled_jump_buf,
        status: CATCH_STATUS,
    };
    let enabled_jump_status = unsafe {
        trampoline::vibe_catch(
            &mut enabled_jump_buf,
            catch_disable_irqs_and_jump,
            (&mut enabled_jump as *mut CatchJump).cast(),
        )
    };
    let enabled_after_jump = interrupts_enabled();
    h.eq(
        "longjmp returns its status after masking interrupts",
        enabled_jump_status,
        CATCH_STATUS,
    );
    h.check(
        "longjmp restores an enabled IRQ entry state",
        enabled_after_jump,
    );

    let disabled_normal_restore = sbi::irq_save();
    let mut disabled_normal_buf = JmpBuf::ZERO;
    let disabled_normal_status = unsafe {
        trampoline::vibe_catch(
            &mut disabled_normal_buf,
            catch_enable_irqs,
            core::ptr::null_mut(),
        )
    };
    let disabled_after_normal = !interrupts_enabled();
    let _ = sbi::irq_save();
    sbi::irq_restore(disabled_normal_restore);
    h.eq(
        "normal catch returns zero after enabling interrupts",
        disabled_normal_status,
        0,
    );
    h.check(
        "normal catch restores a disabled IRQ entry state",
        disabled_after_normal,
    );

    let disabled_jump_restore = sbi::irq_save();
    let mut disabled_jump_buf = JmpBuf::ZERO;
    let mut disabled_jump = CatchJump {
        buf: &mut disabled_jump_buf,
        status: CATCH_STATUS,
    };
    let disabled_jump_status = unsafe {
        trampoline::vibe_catch(
            &mut disabled_jump_buf,
            catch_enable_irqs_and_jump,
            (&mut disabled_jump as *mut CatchJump).cast(),
        )
    };
    let disabled_after_jump = !interrupts_enabled();
    let _ = sbi::irq_save();
    sbi::irq_restore(disabled_jump_restore);
    h.eq(
        "longjmp returns its status after enabling interrupts",
        disabled_jump_status,
        CATCH_STATUS,
    );
    h.check(
        "longjmp restores a disabled IRQ entry state",
        disabled_after_jump,
    );

    // The four quadrants deliberately perturb SIE in both directions. Repair
    // the exact state observed on entry even if an earlier assertion failed.
    let _ = sbi::irq_save();
    sbi::irq_restore(original_irq);
}

async fn catcher_abi(h: &mut Harness) {
    // Keep raw jump-buffer pointers out of the async state machine. Every
    // synchronous catch has completed before this future reaches its await.
    catcher_abi_sync(h);
    let timer_entry_irq = interrupts_enabled();
    if !timer_entry_irq {
        sbi::enable_interrupts();
    }
    let timer_start = sbi::time();
    exec::sleep_ms(1).await;
    let timer_ms = (sbi::time() - timer_start) / (exec::TIMEBASE_HZ / 1000);
    h.check(
        "timer IRQs remain live after nested non-local exits",
        timer_ms < 100,
    );
    let _ = sbi::irq_save();
    sbi::irq_restore(timer_entry_irq);
}

/// ROADMAP 2.8. A component that panics must cost its own task, not the box.
/// This can only be tested on target: the host has no landing pad, and a panic
/// there correctly fails the test run instead.
async fn fault_isolation(h: &mut Harness) {
    let faults_before = exec::faulted_count();
    let live_before = exec::task_report().len();

    let doomed = exec::spawn_tracked("selftest-doomed", async {
        exec::yield_now().await;
        panic!("deliberate fault from the self-test");
    });

    // Give it enough turns to be polled, panic, and be reaped.
    for _ in 0..8 {
        exec::yield_now().await;
    }

    h.eq(
        "a panicking task is counted as faulted",
        exec::faulted_count(),
        faults_before + 1,
    );
    h.eq(
        "a panicking task retains its exact faulted state",
        doomed.state(),
        exec::TaskState::Faulted,
    );
    h.eq(
        "a panicking task retains its terminal reason",
        doomed.state().terminal_reason(),
        Some("fault"),
    );
    h.check(
        "a panicking task is removed from the scheduler",
        !exec::task_report()
            .iter()
            .any(|report| report.id == doomed.id()),
    );
    h.check(
        "the other tasks are untouched",
        exec::task_report().len() >= live_before.saturating_sub(1),
    );
    // And the machine is obviously still running, because we got here.
    h.check("the kernel survived the fault", true);
}

/// ROADMAP 3.11. Allocation ownership follows the supervised component across
/// polls. Exhausting A's quota faults A, while B retains an independent budget;
/// a normal B exit drops its allocations back to the account baseline.
async fn component_memory(h: &mut Harness) {
    const TEST_BUDGET: usize = 4 * 1024;

    let w = world();
    let shell_owner = w
        .component_named("shell")
        .expect("the self-test runs inside the shell component")
        .memory_owner();
    let unaffected = w
        .component_named("guest")
        .expect("the system image has a guest component");
    let unaffected_before = unaffected.snapshot().memory;
    let offender = w.spawn_fault_probe("selftest-quota-offender", TEST_BUDGET);
    let (_, offender_join) = offender.join_current();
    let offender_exit = offender_join.await;
    let offender_snapshot = offender.snapshot();

    h.eq(
        "a component exceeding its allocation quota is faulted",
        offender_exit.state(),
        exec::TaskState::Faulted,
    );
    h.check(
        "the quota account records the refused allocation",
        offender_snapshot.memory.denials > 0,
    );
    h.check(
        "a refused allocation never pushes the offender beyond its budget",
        offender_snapshot.memory.live_bytes <= offender_snapshot.memory.budget_bytes,
    );

    let irq_probe_start = sbi::time();
    exec::sleep_ms(1).await;
    let irq_probe_ms = (sbi::time() - irq_probe_start) / (exec::TIMEBASE_HZ / 1000);
    h.check(
        "quota fault restores interrupts skipped by longjmp",
        irq_probe_ms < 100,
    );

    let unaffected_after = unaffected.snapshot().memory;
    h.eq(
        "quota exhaustion does not consume another component's live budget",
        unaffected_after.live_bytes,
        unaffected_before.live_bytes,
    );
    h.eq(
        "quota exhaustion does not deny another component",
        unaffected_after.denials,
        unaffected_before.denials,
    );

    let survivor = w.spawn_component(
        "selftest-quota-survivor",
        Space::new("selftest-quota-survivor"),
        TEST_BUDGET,
        async {
            // Keep this comfortably below the quota after the future itself
            // is charged to its owner. An inferred Vec<i32> would consume a
            // 4 KiB size class before accounting for that future envelope.
            let mut bytes = Vec::<u8>::new();
            bytes.resize(512, 0x5A);
            exec::yield_now().await;
            core::hint::black_box(&bytes);
        },
    );
    let survivor_baseline = survivor.snapshot().memory.live_bytes;
    let (_, survivor_join) = survivor.join_current();
    let survivor_exit = survivor_join.await;
    let survivor_snapshot = survivor.snapshot();

    h.eq(
        "a fresh component still allocates after another owner exhausts its quota",
        survivor_exit.state(),
        exec::TaskState::Exited,
    );
    h.check(
        "the survivor account observes its component allocation",
        survivor_snapshot.memory.peak_bytes > survivor_baseline,
    );
    h.eq(
        "normal component exit drops all live allocation use",
        survivor_snapshot.memory.live_bytes,
        0,
    );
    h.eq(
        "the survivor uses none of the offender's denial budget",
        survivor_snapshot.memory.denials,
        0,
    );
    h.eq(
        "the executor restores the polling component's allocation owner",
        heap::current_owner(),
        shell_owner,
    );

    h.check(
        "the terminal offender component record can be reaped",
        w.remove_terminal_component(offender_snapshot.id),
    );
    h.check(
        "the terminal survivor component record can be reaped",
        w.remove_terminal_component(survivor_snapshot.id),
    );
}

/// ROADMAP 3.12. Raw fault teardown is per incarnation: it never invokes the
/// interrupted future's destructors, and a fresh arena can be installed under
/// the same supervised identity without monotonically consuming the heap.
async fn fault_arena_restart(h: &mut Harness) {
    const CYCLES: usize = 16;
    const TEST_BUDGET: usize = 4 * 1024;

    let w = world();
    let drops_before = crate::world::fault_probe_drop_count();
    let code_pages_before = crate::code_pool::stats().live_pages;
    let probe = w.spawn_fault_probe("selftest-fault-arena", TEST_BUDGET);
    let stable_id = probe.snapshot().id;
    let stable_owner = probe.memory_owner();
    let stable_space = probe.space();
    let mut previous_task = None;
    let mut previous_arena = None;
    let mut warm_remaining = None;
    let mut warm_live = None;

    for cycle in 0..CYCLES {
        let before = probe.snapshot();
        h.eq(
            "fault restart generation is monotonic",
            before.generation,
            cycle as u64 + 1,
        );
        h.eq(
            "fault restart retains ComponentId",
            before.id,
            stable_id,
        );
        h.eq(
            "fault restart retains OwnerId",
            probe.memory_owner(),
            stable_owner,
        );
        h.check(
            "fault restart assigns a fresh TaskId",
            previous_task.is_none_or(|old| old != before.task_id),
        );
        h.check(
            "fault restart assigns a fresh ArenaId",
            previous_arena.is_none_or(|old| old != before.arena),
        );

        let (_, join) = probe.join_current();
        h.eq(
            "the audited fault probe reaches Faulted",
            join.await.state(),
            exec::TaskState::Faulted,
        );
        let faulted = probe.snapshot();
        h.check(
            "fault publication follows raw arena reclamation",
            crate::HEAP.arena_stats(faulted.arena).is_none(),
        );
        h.eq(
            "raw fault reclamation returns owner live bytes to zero",
            faulted.memory.live_bytes,
            0,
        );
        h.eq(
            "raw fault reclamation returns code-pool pages to baseline",
            crate::code_pool::stats().live_pages,
            code_pages_before,
        );
        h.eq(
            "raw fault reclamation never invokes the future destructor",
            crate::world::fault_probe_drop_count(),
            drops_before,
        );
        let irq_probe_start = sbi::time();
        exec::sleep_ms(1).await;
        let irq_probe_ms =
            (sbi::time() - irq_probe_start) / (exec::TIMEBASE_HZ / 1000);
        h.check(
            "a faulted CSpace lock does not leave interrupts masked",
            irq_probe_ms < 100,
        );

        let (live, _, remaining) = crate::HEAP.stats();
        if cycle == 1 {
            warm_remaining = Some(remaining);
            warm_live = Some(live);
        }
        previous_task = Some(faulted.task_id);
        previous_arena = Some(faulted.arena);

        if cycle + 1 != CYCLES {
            let report = w
                .restart_component("selftest-fault-arena")
                .expect("the sealed fault probe is restartable");
            h.eq(
                "restart report advances exactly one generation",
                report.new_generation,
                report.old_generation + 1,
            );
            h.check(
                "restart keeps the stable Space object",
                Arc::ptr_eq(&stable_space, &probe.space()),
            );
        }
    }

    let (_, _, final_remaining) = crate::HEAP.stats();
    h.eq(
        "fault/restart heap bump use stabilizes after warmup",
        final_remaining,
        warm_remaining.expect("sixteen cycles include a warmup point"),
    );
    h.check(
        "fault/restart global live use never exceeds its warm baseline",
        crate::HEAP.stats().0 <= warm_live.expect("sixteen cycles include a warmup point"),
    );
    h.check(
        "the terminal fault probe can be fully reaped",
        w.remove_terminal_component(probe.snapshot().id),
    );
    drop(probe);
    drop(stable_space);
    h.eq(
        "reaping unregisters the fault probe allocation owner",
        crate::HEAP.account_stats(stable_owner),
        None,
    );
}

/// ROADMAP 3.8. Scheduler identity, authority, and declared memory ownership
/// are one supervised record rather than three name-based conventions.
fn components(h: &mut Harness) {
    let w = world();
    let components = w.components();
    let snapshots: Vec<_> = components
        .iter()
        .map(|component| component.snapshot())
        .collect();
    let tasks = exec::task_report();

    h.eq(
        "the system image registers every discovered supervised component",
        snapshots.len(),
        4 + usize::from(w.block.is_some()),
    );
    h.check(
        "component memory accounts use the stable component identity",
        snapshots.iter().all(|snapshot| {
            snapshot.memory.owner == snapshot.id && snapshot.memory.budget_bytes > 0
        }),
    );
    h.check(
        "component instance generations are explicit",
        snapshots.iter().all(|snapshot| snapshot.generation >= 1),
    );
    h.check(
        "component joins bind the current task generation",
        components
            .iter()
            .zip(&snapshots)
            .all(|(component, snapshot)| {
                let (generation, join) = component.join_current();
                drop(join);
                generation == snapshot.generation
            }),
    );
    h.check(
        "component lifecycle agrees with scheduler liveness",
        snapshots.iter().all(|snapshot| {
            let live = tasks.iter().find(|task| task.id == snapshot.task_id);
            match snapshot.state {
                exec::TaskState::Running => live
                    .is_some_and(|task| task.name == snapshot.name && task.polls == snapshot.polls),
                exec::TaskState::Exited | exec::TaskState::Faulted | exec::TaskState::Cancelled => {
                    live.is_none() && snapshot.terminal_reason.is_some()
                }
            }
        }),
    );

    let init = w.spaces["init"].clone();
    h.check(
        "the shell component explicitly owns the init CSpace",
        w.component_for_space(&init)
            .is_some_and(|component| component.snapshot().name == "shell"),
    );
    let guest = w.spaces["guest"].clone();
    h.check(
        "the guest CSpace resolves to the guest component by object identity",
        w.component_for_space(&guest)
            .is_some_and(|component| component.snapshot().name == "guest"),
    );
    h.check(
        "the synchronous program CSpace is honestly unbound",
        w.component_for_space(&w.spaces["prog"]).is_none(),
    );
}

async fn channels(h: &mut Harness) {
    let ep: Arc<Endpoint<u64>> = Endpoint::new("selftest", 2);

    h.check("try_send into space succeeds", ep.try_send(1).is_ok());
    h.check("try_send fills the bound", ep.try_send(2).is_ok());
    h.check("try_send refuses when full", ep.try_send(3).is_err());
    h.eq("try_recv returns in order", ep.try_recv(), Some(1));
    h.eq("try_recv drains", ep.try_recv(), Some(2));
    h.eq("try_recv on empty", ep.try_recv(), None);

    // Cross-task delivery: the producer's send must wake this task's recv.
    let producer = ep.clone();
    exec::spawn("selftest-tx", async move {
        for i in 0..4u64 {
            producer.send(i * 10).await;
        }
    });
    let mut got = Vec::new();
    for _ in 0..4 {
        got.push(ep.recv().await);
    }
    h.eq(
        "channel delivers across tasks",
        got,
        alloc::vec![0, 10, 20, 30],
    );

    let (sent, received, depth) = ep.stats();
    h.eq("channel accounting", (sent, received, depth), (6, 6, 0));
}

/// The live capability graph, not a synthetic one.
fn capabilities(h: &mut Harness) {
    let w = world();

    let sensor = w.spaces["sensor"].clone();
    let sensor_cap = sensor.0.lock().list()[0].0;
    h.eq(
        "sensor cannot RECV on the channel it publishes to",
        sensor.0.lock().lookup(sensor_cap, Rights::RECV).err(),
        Some(CapError::InsufficientRights),
    );
    h.check(
        "sensor can still SEND",
        sensor.0.lock().lookup(sensor_cap, Rights::SEND).is_ok(),
    );

    let logger = w.spaces["logger"].clone();
    let logger_chan = logger.0.lock().list()[0].0;
    let logger_con = logger.0.lock().list()[1].0;
    h.eq(
        "logger cannot forge a reading",
        logger.0.lock().lookup(logger_chan, Rights::SEND).err(),
        Some(CapError::InsufficientRights),
    );
    h.eq(
        "logger cannot pass its console on",
        crate::cap::grant(
            &logger.0.lock(),
            logger_con,
            Rights::WRITE,
            &mut CSpace::new("selftest-scratch"),
        )
        .err(),
        Some(CapError::InsufficientRights),
    );

    let init = w.spaces["init"].clone();
    let weak = init
        .0
        .lock()
        .derive(w.console, Rights::WRITE.union(Rights::GRANT))
        .unwrap();
    h.eq(
        "a cap cannot derive rights it lacks",
        init.0.lock().derive(weak, Rights::REVOKE).err(),
        Some(CapError::Amplification),
    );
    h.check(
        "a cap can derive a subset of what it holds",
        init.0.lock().derive(weak, Rights::WRITE).is_ok(),
    );

    // Revoking the parent must take the derived child with it.
    let killed = init.0.lock().revoke_slot(weak.slot());
    h.check("revoke cascades to derived caps", killed >= 2);
    h.eq(
        "a revoked handle is invalid",
        init.0.lock().lookup(weak, Rights::WRITE).err(),
        Some(CapError::Invalid),
    );
    h.check(
        "revoking a derived cap leaves the parent alone",
        init.0.lock().lookup(w.console, Rights::WRITE).is_ok(),
    );

    // Type confusion: the console cap does not name an endpoint.
    h.eq(
        "typed lookup rejects the wrong resource type",
        init.0
            .lock()
            .lookup_as::<Endpoint<u64>>(w.console, Rights::WRITE)
            .err(),
        Some(CapError::WrongType),
    );
    h.check(
        "typed lookup accepts the right resource type",
        init.0
            .lock()
            .lookup_as::<ConsoleDev>(w.console, Rights::WRITE)
            .is_ok(),
    );
    h.check(
        "a space is itself a resource",
        init.0
            .lock()
            .lookup_as::<Space>(w.prog_space, Rights::REVOKE)
            .is_ok(),
    );
}

/// Machine code actually executing. Host tests can check what the emitter
/// *emits*; only this can check what the CPU *does* with it.
fn compiler(h: &mut Harness) {
    let hello = crate::rustc::compile(crate::rustc::HELLO_SRC);
    h.check("hello compiles", hello.is_ok());
    h.check(
        "compiled code is identity-mapped with execute-only 4 KiB leaves",
        hello.as_ref().is_ok_and(|compiled| {
            (0..compiled.code_pages()).all(|page| {
                let address = compiled.code_start() + page * vibeos_core::mmu::PAGE_SIZE;
                crate::mmu::mapping(address).is_some_and(|mapping| {
                    mapping.physical == address
                        && mapping.page_size == vibeos_core::mmu::PAGE_SIZE
                        && mapping.permissions == vibeos_core::mmu::PagePermissions::EXECUTE
                })
            })
        }),
    );
    h.check(
        "sealed code keeps the global RAM map free of writable-executable leaves",
        crate::mmu::first_writable_executable_ram_page().is_none(),
    );
    h.check(
        "released code pages are zeroed before same-address reuse",
        crate::code_pool::reuse_zero_probe(),
    );
    h.check(
        "the console revoke hook rejects its reserved arm state",
        !crate::rustc::arm_console_revoke_hook(usize::MAX),
    );

    let w = world();
    let memory_region = w.spaces["init"]
        .0
        .lock()
        .lookup_as::<MemoryRegion>(w.region, Rights::READ)
        .expect("init retains the program memory root");
    h.check(
        "the program memory claim starts released",
        !memory_region.invocation_claimed(),
    );

    let leases = {
        let cspace = w.spaces["prog"].0.lock();
        (
            cspace.lookup_lease::<MemoryRegion>(
                w.prog_memory,
                Rights::READ.union(Rights::WRITE),
            ),
            cspace.lookup_lease::<MemoryRegion>(
                w.prog_memory,
                Rights::READ.union(Rights::WRITE),
            ),
        )
    };
    if let (Ok(first), Ok(second)) = leases {
        let first = MemoryInvocation::claim(first).ok();
        let second_refused = MemoryInvocation::claim(second).is_err();
        h.check(
            "the program memory region permits one invocation claim",
            first.is_some() && second_refused,
        );
        drop(first);
        h.check(
            "dropping a memory invocation releases its claim",
            !memory_region.invocation_claimed(),
        );
    } else {
        h.check("the program memory region permits one invocation claim", false);
        h.check("dropping a memory invocation releases its claim", false);
    }

    // Layout must be identical across the sizing pass and the real pass, or
    // every absolute address in the program is wrong.
    if let (Ok(a), Ok(b)) = (
        crate::rustc::compile(crate::rustc::DEMO_SRC),
        crate::rustc::compile(crate::rustc::DEMO_SRC),
    ) {
        h.eq("codegen is deterministic in size", a.bytes, b.bytes);
        h.check("demo emits code", a.bytes > 0);
    } else {
        h.check("demo compiles", false);
    }

    h.check(
        "a program that returns a value runs",
        crate::rustc::compile("fn main() -> i64 { 6 * 7 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 42,
    );
    h.check(
        "a normal generated return releases its memory claim",
        !memory_region.invocation_claimed(),
    );
    h.check(
        "recursion runs",
        crate::rustc::compile(
            "fn f(n: i64) -> i64 { if n < 2 { n } else { f(n-1) + f(n-2) } }\nfn main() -> i64 { f(20) }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 6765,
    );
    h.check(
        "loops and mutation run",
        crate::rustc::compile(
            "fn main() -> i64 { let mut s = 0; let mut i = 0; while i <= 100 { s = s + i; i = i + 1; } s }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 5050,
    );

    // M2: every emitted safety check, exercised end to end. These need real
    // execution -- a host test can prove the check was *emitted*, only this can
    // prove it fires and that the shell survives it.
    let aborts: [(&str, &str); 6] = [
        ("fn main() -> i64 { let z = 0; 1 / z }", "attempt to divide by zero"),
        (
            "fn main() -> i64 { let z = 0; 1 % z }",
            "attempt to calculate the remainder with a divisor of zero",
        ),
        (
            // Through variables, so it is a runtime check: the literal form is
            // now folded and rejected at compile time, as real rustc does.
            "fn main() -> i64 { let a = 9223372036854775807; let b = 1; a + b }",
            "attempt to perform arithmetic that overflowed",
        ),
        (
            "fn main() -> i64 { let a = 9223372036854775807; let b = 0 - a - 1; let c = 0 - 1; b / c }",
            "attempt to divide with overflow",
        ),
        (
            "fn main() -> i64 { let mut i = 0; while i >= 0 { i = i + 0; } i }",
            "exceeded execution budget",
        ),
        ("fn f(n: i64) -> i64 { f(n) }\nfn main() -> i64 { f(0) }", "stack overflow"),
    ];
    for (src, want) in aborts {
        match crate::rustc::compile(src) {
            Ok(c) => {
                let out = crate::rustc::run(&c);
                h.eq(want, out.aborted, Some(want));
            }
            Err(e) => {
                crate::println!("  FAIL  {} did not compile: {}", want, e);
                h.check(want, false);
            }
        }
    }
    h.check(
        "a generated longjmp releases its memory claim",
        !memory_region.invocation_claimed(),
    );
    h.check(
        "the shell survives an aborted program",
        crate::rustc::compile("fn main() -> i64 { 2 + 2 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 4,
    );

    // M3: arrays in the capability-granted region.
    h.check(
        "arrays round-trip through the region",
        crate::rustc::compile(
            "fn main() -> i64 { let mut a = [0; 8]; let mut i = 0; let mut v = 0;\
             while i < 8 { a[i] = v * v; v = v + 1; i = i + 1; }\
             let mut s = 0; i = 0; while i < 8 { s = s + a[i]; i = i + 1; } s }",
        )
        .map(|c| crate::rustc::run(&c).value)
        .unwrap_or(-1)
            == 140,
    );
    let region_aborts: [(&str, &str); 3] = [
        (
            "fn main() -> i64 { let mut a = [1; 4]; a[9] }",
            "index out of bounds",
        ),
        (
            "fn main() -> i64 { let mut a = [1; 4]; let i = 0 - 1; a[i] }",
            "index out of bounds",
        ),
        (
            "fn main() -> i64 { let mut a = [0; 3000]; let mut b = [0; 3000]; a[0] + b[0] }",
            "the granted memory region is too small for this program",
        ),
    ];
    for (src, want) in region_aborts {
        match crate::rustc::compile(src) {
            Ok(c) => h.eq(want, crate::rustc::run(&c).aborted, Some(want)),
            Err(e) => {
                crate::println!("  FAIL  {} did not compile: {}", want, e);
                h.check(want, false);
            }
        }
    }
    h.check(
        "a program with no memory capability cannot allocate",
        crate::rustc::compile("fn main() -> i64 { let mut a = [1; 2]; a[0] }").is_ok(),
    );

    h.check(
        "undefined names are rejected",
        crate::rustc::compile("fn main() { y; }").is_err(),
    );
    h.check(
        "a literal zero divisor is a compile error",
        crate::rustc::compile("fn main() -> i64 { 1 / 0 }").is_err(),
    );
    h.check(
        "literal overflow is a compile error, as in rustc",
        crate::rustc::compile("fn main() -> i64 { 9223372036854775807 + 1 }").is_err(),
    );
    h.check(
        "constant folding preserves the value",
        crate::rustc::compile("fn main() -> i64 { 2 + 3 * 4 - 1 }")
            .map(|c| crate::rustc::run(&c).value)
            .unwrap_or(-1)
            == 13,
    );
    h.check(
        "immutable reassignment is rejected",
        crate::rustc::compile("fn main() { let x = 1; x = 2; }").is_err(),
    );
    h.check(
        "arity mismatch is rejected",
        crate::rustc::compile("fn f(a: i64) -> i64 { a }\nfn main() { f(1, 2); }").is_err(),
    );
    h.check(
        "a program with no main is rejected",
        crate::rustc::compile("fn f() {}").is_err(),
    );
}
