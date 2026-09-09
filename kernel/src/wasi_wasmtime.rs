//! Opt-in native backend for the existing supervised WASI command job.
//! The arena borrows SYSTEM's job; it never owns an Arc to its I/O or authority.
use super::*;
use crate::wasmtime_platform::async_call::NativeFuture;
use vibeos_wasmtime_runtime::{wasi as w, wasmtime::{self, Engine, Store, Trap}};
#[cfg(feature = "wasmtime-threads")]
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicU8, AtomicUsize};
static ACTIVE: SpinLock<Option<(AllocationDomain, usize)>> = SpinLock::new(None);
pub(super) fn register(domain: AllocationDomain, job: usize) {
    let mut active = ACTIVE.lock();
    assert!(active.is_none());
    *active = Some((domain, job));
}
pub(super) fn retire(domain: AllocationDomain, job: usize) {
    let mut active = ACTIVE.lock();
    assert_eq!(*active, Some((domain, job)));
    let record = unsafe { &*(job as *const Job) };
    assert_eq!(Arc::strong_count(&record.native_signal.inner), 2, "native I/O waker escaped retirement");
    assert!(record.native_signal.inner.0.lock().parent.is_none());
    #[cfg(feature = "wasmtime-threads")]
    for slot in &record.threads.slots {
        assert_eq!(Arc::strong_count(&slot.signal.inner), 2, "thread waker escaped retirement");
        assert!(slot.signal.inner.0.lock().parent.is_none());
        assert!(slot.handle.lock().is_none(), "thread handle survived retirement");
    }
    *active = None;
}
/// Executor quiescence plus this private exact-domain registration admits only
/// the one job published by launch. The SYSTEM reaper keeps the loan alive.
pub(crate) unsafe fn recover(domain: AllocationDomain) -> bool {
    let raw = match *ACTIVE.lock() { Some((d, raw)) if d == domain => raw, _ => return false };
    let job = unsafe { &*(raw as *const Job) };
    close(job);
    #[cfg(feature = "wasmtime-threads")]
    {
        crate::wasmtime_platform::thread_hooks::clear_job(raw);
        job.threads.group.store(0, Ordering::Release);
        job.threads.cancelled.store(true, Ordering::Release);
    }
    unsafe { crate::wasmtime_platform::recover_command_graph(domain); }
    true
}
fn close(job: &Job) { job.native_signal.clear(); job.io.stdin.close(); job.io.stdout.close(); job.io.stderr.close(); }
fn stopped(job: &Job) -> Option<WasiTerminal> {
    #[cfg(feature = "wasmtime-threads")]
    if job.threads.cancelled.load(Ordering::Acquire) {
        return Some(job.threads.terminal());
    }
    if job.io.cancelled() {
        Some(if job.io.denied() { WasiTerminal::Denied } else { WasiTerminal::Cancelled })
    } else if job.authority.as_ref().is_some_and(|check| !check())
        || job.caps.iter().any(|cap| job.space.rights_of(*cap).is_err()) {
        Some(WasiTerminal::Denied)
    } else { None }
}

#[cfg(feature = "wasmtime-command-fuel-batch")]
pub(super) struct FuelBatch {
    remaining: core::sync::atomic::AtomicUsize,
    checks: core::sync::atomic::AtomicUsize,
    continued: core::sync::atomic::AtomicUsize,
    /// The owning SYSTEM job record; every thread's batch points at one job.
    job: core::sync::atomic::AtomicUsize,
}
#[cfg(feature = "wasmtime-command-fuel-batch")]
impl FuelBatch {
    pub(super) fn new() -> Self {
        Self { remaining: 0.into(), checks: 0.into(), continued: 0.into(), job: 0.into() }
    }
}
#[cfg(feature = "wasmtime-command-fuel-batch")]
fn fuel_may_continue(context: usize) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    // Installed only in one Store of this job. The SYSTEM reaper retains the
    // job until every Store/fiber has been dropped and every task joined. No
    // owning SYSTEM reference is carried on an abandonable guest stack.
    let fuel = unsafe { &*(context as *const FuelBatch) };
    let job = unsafe { &*(fuel.job.load(Relaxed) as *const Job) };
    // Only this exact task's poll (including its fiber callback) writes these
    // cells; the reaper waits for its join. Atomic loads/stores permit shared
    // Job references without imposing unnecessary RMW operations on every
    // quantum. No cancellation or authority state uses this single-writer rule.
    fuel.checks.store(fuel.checks.load(Relaxed) + 1, Relaxed);
    let remaining = fuel.remaining.load(Relaxed);
    if stopped(job).is_some() || remaining == 0
        || !exec::current_task_may_continue() {
        return false;
    }
    // Threads each carry a full budget; the job-wide ceiling bounds their sum.
    #[cfg(feature = "wasmtime-threads")]
    if !job.threads.charge_quantum(invocation_limits()) {
        return false;
    }
    fuel.remaining.store(remaining - 1, Relaxed);
    fuel.continued.store(fuel.continued.load(Relaxed) + 1, Relaxed);
    true
}
struct Streams(usize);
impl Streams {
    fn job(&self) -> &Job { unsafe { &*(self.0 as *const Job) } }
}
impl w::Streams for Streams {
    fn read(&mut self, cx: &mut Context<'_>, data: &mut [u8]) -> Poll<Result<usize, i32>> {
        if stopped(self.job()).is_some() { return Poll::Ready(Err(76)); }
        GuestIo(&self.job().io).read(cx, data).map(|r| r.map_err(io_errno))
    }
    fn write(&mut self, cx: &mut Context<'_>, fd: u32, data: &[u8]) -> Poll<Result<usize, i32>> {
        if stopped(self.job()).is_some() { return Poll::Ready(Err(76)); }
        let result = GuestIo(&self.job().io).write(cx, fd, data).map(|r| r.map_err(io_errno));
        #[cfg(feature = "wasmtime-threads")]
        if let Poll::Ready(Ok(n)) = result {
            self.job().threads.output_remaining.fetch_sub(n, Ordering::AcqRel);
        }
        result
    }
    #[cfg(feature = "wasmtime-threads")]
    fn output_remaining(&self) -> usize { self.job().threads.output_remaining.load(Ordering::Acquire) }
    fn close(&mut self, fd: u32) -> Result<(), i32> {
        let io = &self.job().io;
        match fd { 0 => io.stdin.close(), 1 => io.stdout.close(), 2 => io.stderr.close(), _ => return Err(8) }
        Ok(())
    }
}
impl Drop for Streams {
    fn drop(&mut self) {
        // With threads every store carries a Streams; only the process end
        // (main's Guest) closes the shared pipes.
        #[cfg(not(feature = "wasmtime-threads"))]
        close(self.job());
    }
}
fn io_errno(error: WasiIoError) -> i32 {
    match error { WasiIoError::Closed => 64, WasiIoError::Denied => 76, WasiIoError::Failed => 29 }
}
struct Clock;
impl w::Clock for Clock {
    fn time(&mut self, id: u32, precision: u64) -> Result<u64, i32> { crate::wasi_clock::time(id, precision) }
    fn resolution(&mut self, id: u32) -> Result<u64, i32> { crate::wasi_clock::resolution(id) }
}
pub(super) struct Guest {
    job: usize,
    future: Option<Pin<Box<dyn Future<Output = WasiTerminal> + Send>>>,
    polls: u64,
    dispatches: u64,
    started: u64,
    check_ticks: u64,
    guest_ticks: u64,
}
impl Guest { pub(super) fn new(job: usize) -> Self { Self { job, future: None, polls: 0, dispatches: 0, started: 0, check_ticks: 0, guest_ticks: 0 } } }
impl Future for Guest {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let job = unsafe { &*(this.job as *const Job) };
        this.dispatches += 1;
        if this.started == 0 { this.started = crate::sbi::time(); }
        // Waker storage is SYSTEM-owned. Borrow its persistent Waker instead of
        // cloning an owning SYSTEM reference onto an abandonable guest stack.
        job.native_signal.begin(cx.waker());
        #[cfg(feature = "wasmtime-command-fuel-batch")]
        job.native_fuel.remaining.store(31, core::sync::atomic::Ordering::Relaxed);
        let mut native_cx = Context::from_waker(&job.native_signal.waker);
        for quantum in 0..32 {
            let begin = crate::sbi::time();
            let terminal = stopped(job);
            this.check_ticks += crate::sbi::time() - begin;
            if let Some(terminal) = terminal {
                this.future = None;
                close(job);
                *job.result.lock() = Some(terminal);
                return Poll::Ready(());
            }
            if this.future.is_none() { this.future = Some(Box::pin(run(this.job))); }
            this.polls += 1;
            let begin = crate::sbi::time();
            #[cfg(feature = "wasmtime-threads")]
            crate::wasmtime_platform::thread_hooks::enter(this.job, 0);
            let outcome = this.future.as_mut().unwrap().as_mut().poll(&mut native_cx);
            #[cfg(feature = "wasmtime-threads")]
            crate::wasmtime_platform::thread_hooks::leave();
            this.guest_ticks += crate::sbi::time() - begin;
            match outcome {
                Poll::Pending => {
                    let ready = job.native_signal.take_ready();
                    // Fuel batching already bounds this poll to 32 quanta on
                    // the fiber. Never multiply that bound with outer batching.
                    if !cfg!(feature = "wasmtime-command-fuel-batch")
                        && ready && quantum < 31 && exec::current_task_may_continue() { continue; }
                    job.native_signal.finish(ready);
                    return Poll::Pending;
                }
                Poll::Ready(terminal) => {
                    this.future = None;
                    close(job);
                    *job.result.lock() = Some(terminal);
                    #[cfg(feature = "wasmtime-threads")]
                    crate::println!("WASI Wasmtime threads spawned={} harts_used={:#x}", job.threads.next_tid.load(Ordering::Relaxed), job.threads.harts_used.load(Ordering::Relaxed));
                    crate::println!("WASI Wasmtime polls={} quantum=10000 scheduler=exec", this.polls);
                    #[cfg(feature = "wasmtime-command-fuel-batch")]
                    crate::println!("WASI Wasmtime fuel checks={} continued={} max_batch=32", job.native_fuel.checks.load(core::sync::atomic::Ordering::Relaxed), job.native_fuel.continued.load(core::sync::atomic::Ordering::Relaxed));
                    crate::println!("WASI Wasmtime profile dispatches={} polls={} check_ticks={} guest_ticks={} wall_ticks={} hz={}",
                        this.dispatches, this.polls, this.check_ticks, this.guest_ticks, crate::sbi::time() - this.started, exec::timebase_hz());
                    return Poll::Ready(());
                }
            }
        }
        unreachable!()

    }
}
async fn run(raw: usize) -> WasiTerminal {
    match execute(raw).await {
        Ok(terminal) => terminal,
        Err(error) => {
            crate::println!("WASI Wasmtime admission error: {error:#}");
            if error.downcast_ref::<w::AdmissionError>() == Some(&w::AdmissionError::Limit) { WasiTerminal::LimitExceeded } else { WasiTerminal::Denied }
        }
    }
}
async fn execute(raw: usize) -> wasmtime::Result<WasiTerminal> {
    let job = unsafe { &*(raw as *const Job) };
    #[cfg(not(feature = "wasmtime-threads"))]
    let mut config = crate::wasmtime_platform::configuration();
    #[cfg(feature = "wasmtime-threads")]
    let mut config = crate::wasmtime_platform::configuration_threads();
    config.max_wasm_stack(32 * 1024).async_stack_size(256 * 1024);
    let engine = Engine::new(&config)?;
    let begin = crate::sbi::time();
    let module = w::compile_with(&engine, &job.bytes, cfg!(feature = "wasmtime-threads"))?;
    crate::println!("WASI Wasmtime compiled ticks={}", crate::sbi::time() - begin);
    // Compilation is synchronous. Recheck authority before any guest entry.
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    #[cfg(not(feature = "wasmtime-threads"))]
    let linker = w::linker_streams::<Clock>(&engine, &module)?;
    #[cfg(feature = "wasmtime-threads")]
    let (mut linker, memory) = if w::uses_threads(&module) {
        let memory = w::threads::create_shared_memory(&engine, &module)?;
        (w::threads::linker_threads::<Clock>(&engine, &module, Arc::new(Spawner(raw)))?, Some(memory))
    } else {
        (w::linker_streams::<Clock>(&engine, &module)?, None)
    };
    let mut store = Store::new(&engine, w::Invocation::with_streams(&job.argv, Clock, Box::new(Streams(raw)))?);
    store.limiter(|state| state.resource_limits());
    let limits = invocation_limits();
    store.set_fuel(limits.total_fuel)?;
    store.fuel_async_yield_interval(Some(limits.poll_quantum))?;
    #[cfg(feature = "wasmtime-command-fuel-batch")]
    {
        job.native_fuel.job.store(raw, Ordering::Relaxed);
        store.fuel_async_yield_callback(fuel_may_continue, &job.native_fuel as *const FuelBatch as usize);
    }
    // The shared runtime graph lives in this arena; sibling tasks in the same
    // arena share it. SYSTEM only records its address and never follows it.
    #[cfg(feature = "wasmtime-threads")]
    let group = match memory {
        Some(memory) => {
            w::threads::define_shared_memory(&mut linker, &store, &memory)?;
            let group = Arc::new(ThreadGroup { engine: engine.clone(), module: module.clone(), memory, linker: linker.clone() });
            job.threads.group.store(Arc::as_ptr(&group) as usize, Ordering::Release);
            Some(group)
        }
        None => None,
    };
    let instance = match NativeFuture::new(linker.instantiate_async(&mut store, &module)).await {
        Ok(instance) => instance,
        Err(error) => { drop(error); return Ok(if store.data().resource_limit_hit() { WasiTerminal::LimitExceeded } else { WasiTerminal::Trapped }); }
    };
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    crate::println!("WASI running backend=wasmtime");
    let result = NativeFuture::new(start.call_async(&mut store, ())).await;
    let terminal = if store.data().resource_limit_hit() { WasiTerminal::LimitExceeded }
        else if let Some(code) = store.data().exit { WasiTerminal::Exited(code) }
        else { match &result {
            Ok(()) => WasiTerminal::Exited(0),
            Err(error) if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) => WasiTerminal::LimitExceeded,
            Err(_) => WasiTerminal::Trapped,
        }};
    drop(result);
    // Process semantics: main returning or exiting ends every thread. A
    // worker's earlier proc_exit/trap already cancelled us and wins below.
    #[cfg(feature = "wasmtime-threads")]
    if let Some(group) = group {
        job.threads.end(match terminal { WasiTerminal::Exited(code) => Some(code), _ => None }, terminal == WasiTerminal::Trapped, terminal == WasiTerminal::LimitExceeded);
        join_threads(job).await;
        drop(store);
        drop(group);
        job.threads.group.store(0, Ordering::Release);
        return Ok(job.threads.terminal());
    }
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    Ok(terminal)
}

#[cfg(feature = "wasmtime-threads")]
pub(super) const MAX_GUEST_THREADS: usize = crate::mmu::NATIVE_FIBER_SLOTS - 1;
#[cfg(feature = "wasmtime-threads")]
const FREE: u8 = 0;
#[cfg(feature = "wasmtime-threads")]
const RUNNING: u8 = 1;
#[cfg(feature = "wasmtime-threads")]
const DONE: u8 = 2;
/// Arena-owned objects every thread of one command shares.
#[cfg(feature = "wasmtime-threads")]
#[allow(dead_code)] // `memory` keeps the shared mapping alive for every thread.
struct ThreadGroup { engine: Engine, module: wasmtime::Module, memory: wasmtime::SharedMemory, linker: wasmtime::Linker<w::Invocation<Clock>> }
/// SYSTEM-owned per-thread control. Index 0 is the main thread's `native_signal`.
#[cfg(feature = "wasmtime-threads")]
pub(super) struct ThreadSlot {
    signal: PollSignal,
    #[cfg(feature = "wasmtime-command-fuel-batch")]
    fuel: FuelBatch,
    handle: SpinLock<Option<exec::TaskHandle>>,
    state: AtomicU8,
    tid: AtomicU32,
    start_arg: AtomicI32,
}
#[cfg(feature = "wasmtime-threads")]
pub(super) struct Threads {
    slots: [ThreadSlot; MAX_GUEST_THREADS],
    next_tid: AtomicU32,
    /// Set once the process is ending; every task drops its fiber at the next
    /// quantum and parked waiters are woken to observe it.
    cancelled: AtomicBool,
    exit: SpinLock<Option<u32>>,
    trapped: AtomicBool,
    limit: AtomicBool,
    output_remaining: AtomicUsize,
    fuel_spent: AtomicU64,
    /// Raw address of the arena `ThreadGroup`; zero outside the run.
    group: AtomicUsize,
    /// Bit mask of harts that polled a guest thread of this job.
    harts_used: AtomicUsize,
}
#[cfg(feature = "wasmtime-threads")]
impl Threads {
    pub(super) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| ThreadSlot {
                signal: PollSignal::new(),
                #[cfg(feature = "wasmtime-command-fuel-batch")]
                fuel: FuelBatch::new(),
                handle: SpinLock::new(None),
                state: AtomicU8::new(FREE),
                tid: AtomicU32::new(0),
                start_arg: AtomicI32::new(0),
            }),
            next_tid: AtomicU32::new(0),
            cancelled: AtomicBool::new(false),
            exit: SpinLock::new(None),
            trapped: AtomicBool::new(false),
            limit: AtomicBool::new(false),
            output_remaining: AtomicUsize::new(65536),
            fuel_spent: AtomicU64::new(0),
            group: AtomicUsize::new(0),
            harts_used: AtomicUsize::new(0),
        }
    }
    /// Record a process-ending event and stop every thread.
    fn end(&self, exit: Option<u32>, trapped: bool, limit: bool) {
        if let Some(code) = exit {
            let mut slot = self.exit.lock();
            if slot.is_none() { *slot = Some(code); }
        }
        if trapped { self.trapped.store(true, Ordering::Release); }
        if limit { self.limit.store(true, Ordering::Release); }
        self.cancelled.store(true, Ordering::Release);
    }
    fn terminal(&self) -> WasiTerminal {
        if self.limit.load(Ordering::Acquire) { WasiTerminal::LimitExceeded }
        else if let Some(code) = *self.exit.lock() { WasiTerminal::Exited(code) }
        else if self.trapped.load(Ordering::Acquire) { WasiTerminal::Trapped }
        else { WasiTerminal::Exited(0) }
    }
    fn charge_quantum(&self, limits: WasiLimits) -> bool {
        let spent = self.fuel_spent.fetch_add(limits.poll_quantum, Ordering::AcqRel) + limits.poll_quantum;
        if spent > limits.total_fuel.saturating_mul(MAX_GUEST_THREADS as u64 + 1) {
            self.end(None, false, true);
            return false;
        }
        true
    }
}
/// Wake every task of the job so parked waiters re-check cancellation.
#[cfg(feature = "wasmtime-threads")]
pub(super) fn wake_all(raw: usize) {
    let job = unsafe { &*(raw as *const Job) };
    job.native_signal.waker.wake_by_ref();
    for slot in &job.threads.slots { slot.signal.waker.wake_by_ref(); }
}
/// `ThreadHooks::wake`: the SYSTEM job outlives every thread task, so the
/// token names live signal storage until the reaper retires the record.
#[cfg(feature = "wasmtime-threads")]
pub(crate) fn wake_thread(raw: usize, index: usize) {
    if ACTIVE.lock().is_none_or(|(_, job)| job != raw) { return; }
    let job = unsafe { &*(raw as *const Job) };
    match index {
        0 => job.native_signal.waker.wake_by_ref(),
        n if n <= MAX_GUEST_THREADS => job.threads.slots[n - 1].signal.waker.wake_by_ref(),
        _ => (),
    }
}
#[cfg(feature = "wasmtime-threads")]
static NEXT_HART: AtomicUsize = AtomicUsize::new(0);
/// The next online logical hart in round-robin order.
#[cfg(feature = "wasmtime-threads")]
fn next_thread_hart() -> vibeos_core::runqueue::HartId {
    for _ in 0..exec::MAX_HARTS {
        let index = NEXT_HART.fetch_add(1, Ordering::Relaxed) % exec::MAX_HARTS;
        let hart = vibeos_core::runqueue::HartId::new(index).expect("hart index in range");
        if crate::ipi::is_online(hart) { return hart; }
    }
    crate::ipi::current_logical_hart().expect("thread spawn needs a registered hart")
}
#[cfg(feature = "wasmtime-threads")]
struct Spawner(usize);
#[cfg(feature = "wasmtime-threads")]
impl w::threads::ThreadSpawner for Spawner {
    /// Runs on the spawning thread's fiber inside the arena. The new task
    /// inherits this arena; its handle is stored in the SYSTEM slot.
    fn spawn(&self, start_arg: i32) -> i32 {
        let raw = self.0;
        let job = unsafe { &*(raw as *const Job) };
        let threads = &job.threads;
        if threads.cancelled.load(Ordering::Acquire) || stopped(job).is_some() {
            return w::threads::SPAWN_AGAIN;
        }
        let group = threads.group.load(Ordering::Acquire);
        if group == 0 { return w::threads::SPAWN_AGAIN; }
        let Some(index) = threads.slots.iter().position(|slot| {
            slot.state.compare_exchange(FREE, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_ok()
        }) else {
            return w::threads::SPAWN_AGAIN;
        };
        let slot = &threads.slots[index];
        let tid = threads.next_tid.fetch_add(1, Ordering::AcqRel) + 1;
        slot.tid.store(tid, Ordering::Release);
        slot.start_arg.store(start_arg, Ordering::Release);
        // SAFETY: `group` was published by execute() from a live Arc in this
        // arena and is cleared before that Arc can be dropped.
        let group = unsafe { Arc::increment_strong_count(group as *const ThreadGroup); Arc::from_raw(group as *const ThreadGroup) };
        // Round-robin over online harts so threads run in parallel; each task
        // stays pinned to the hart it was placed on.
        let hart = next_thread_hart();
        let handle = exec::spawn_sibling_on(hart, "wasi-thread", ThreadTask { job: raw, index, group: Some(group), future: None });
        *slot.handle.lock() = Some(handle);
        tid as i32
    }
}
#[cfg(feature = "wasmtime-threads")]
struct ThreadOutcome { exit: Option<u32>, trapped: bool, limit: bool }
#[cfg(feature = "wasmtime-threads")]
struct ThreadTask {
    job: usize,
    index: usize,
    group: Option<Arc<ThreadGroup>>,
    future: Option<Pin<Box<dyn Future<Output = ThreadOutcome> + Send>>>,
}
#[cfg(feature = "wasmtime-threads")]
impl Future for ThreadTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        let job = unsafe { &*(this.job as *const Job) };
        let slot = &job.threads.slots[this.index];
        job.threads.harts_used.fetch_or(1 << crate::wasmtime_platform::hart(), Ordering::Relaxed);
        slot.signal.begin(cx.waker());
        #[cfg(feature = "wasmtime-command-fuel-batch")]
        slot.fuel.remaining.store(31, Ordering::Relaxed);
        let mut native_cx = Context::from_waker(&slot.signal.waker);
        for quantum in 0..32 {
            if stopped(job).is_some() {
                // Dropping the future disposes a suspended fiber (including one
                // parked in an atomic wait) and releases its stack slot.
                this.future = None;
                this.group = None;
                slot.state.store(DONE, Ordering::Release);
                return Poll::Ready(());
            }
            if this.future.is_none() {
                let group = this.group.clone().expect("thread group");
                this.future = Some(Box::pin(run_thread(this.job, this.index, group)));
            }
            crate::wasmtime_platform::thread_hooks::enter(this.job, this.index + 1);
            let outcome = this.future.as_mut().unwrap().as_mut().poll(&mut native_cx);
            crate::wasmtime_platform::thread_hooks::leave();
            match outcome {
                Poll::Pending => {
                    let ready = slot.signal.take_ready();
                    if !cfg!(feature = "wasmtime-command-fuel-batch")
                        && ready && quantum < 31 && exec::current_task_may_continue() { continue; }
                    slot.signal.finish(ready);
                    return Poll::Pending;
                }
                Poll::Ready(outcome) => {
                    this.future = None;
                    this.group = None;
                    if outcome.exit.is_some() || outcome.trapped || outcome.limit {
                        job.threads.end(outcome.exit, outcome.trapped, outcome.limit);
                        wake_all(this.job);
                    }
                    slot.state.store(DONE, Ordering::Release);
                    return Poll::Ready(());
                }
            }
        }
        unreachable!()
    }
}
#[cfg(feature = "wasmtime-threads")]
async fn run_thread(raw: usize, index: usize, group: Arc<ThreadGroup>) -> ThreadOutcome {
    let job = unsafe { &*(raw as *const Job) };
    let slot = &job.threads.slots[index];
    let tid = slot.tid.load(Ordering::Acquire);
    let start_arg = slot.start_arg.load(Ordering::Acquire);
    let run = async {
        let mut state = w::Invocation::with_streams(&job.argv, Clock, Box::new(Streams(raw)))?;
        state.tid = tid;
        let mut store = Store::new(&group.engine, state);
        store.limiter(|state| state.resource_limits());
        let limits = invocation_limits();
        store.set_fuel(limits.total_fuel)?;
        store.fuel_async_yield_interval(Some(limits.poll_quantum))?;
        #[cfg(feature = "wasmtime-command-fuel-batch")]
        {
            slot.fuel.job.store(raw, Ordering::Relaxed);
            store.fuel_async_yield_callback(fuel_may_continue, &slot.fuel as *const FuelBatch as usize);
        }
        let instance = NativeFuture::new(group.linker.instantiate_async(&mut store, &group.module)).await?;
        let start = w::threads::thread_start(&instance, &mut store)?;
        let result = NativeFuture::new(start.call_async(&mut store, (tid as i32, start_arg))).await;
        let exit = store.data().exit;
        let limit = store.data().resource_limit_hit();
        let (trapped, fuel) = match result {
            Ok(()) => (false, false),
            Err(error) => {
                let fuel = error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel);
                drop(error);
                (exit.is_none() && !fuel && !limit, fuel)
            }
        };
        drop(store);
        Ok::<_, wasmtime::Error>(ThreadOutcome { exit, trapped, limit: limit || fuel })
    };
    match run.await {
        Ok(outcome) => outcome,
        Err(error) => { drop(error); ThreadOutcome { exit: None, trapped: true, limit: false } }
    }
}
/// Cancel and join every spawned thread. Runs on the executor (not a fiber);
/// join registrations use the SYSTEM-owned poll signal waker.
#[cfg(feature = "wasmtime-threads")]
async fn join_threads(job: &Job) {
    wake_all(job as *const Job as usize);
    for slot in &job.threads.slots {
        let handle = slot.handle.lock().take();
        if let Some(handle) = handle {
            let _ = handle.cancel();
            handle.join().await;
        }
    }
}
/// Reaper support: join stragglers after the main task ended and wake parked
/// waiters when authority is lost while the job is blocked.
#[cfg(feature = "wasmtime-threads")]
pub(super) async fn reap_threads(raw: usize) {
    let job = unsafe { &*(raw as *const Job) };
    job.threads.cancelled.store(true, Ordering::Release);
    join_threads(job).await;
    // Every thread task has joined: release the parent wakers their last polls
    // left behind, as `close` does for the main signal.
    for slot in &job.threads.slots { slot.signal.clear(); }
}
#[cfg(feature = "wasmtime-threads")]
pub(super) fn notify_denied(raw: usize) { wake_all(raw); }


// Fuel yields wake immediately. Coalesce only wakes during one bounded poll;
// asynchronous I/O wakes after it returns must still schedule the task. The
// parent Waker and every clone stored in pipes point to SYSTEM-owned state.
struct SignalState { active: bool, ready: bool, parent: Option<core::task::Waker> }
struct Signal(SpinLock<SignalState>);
impl alloc::task::Wake for Signal {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) {
        let parent = {
            let mut state = self.0.lock();
            state.ready = true;
            if state.active { None } else { state.parent.clone() }
        };
        if let Some(parent) = parent { parent.wake(); }
    }
}
pub(super) struct PollSignal { inner: Arc<Signal>, waker: core::task::Waker }
impl PollSignal {
    pub(super) fn new() -> Self {
        let inner = Arc::new(Signal(SpinLock::new(SignalState { active: false, ready: false, parent: None })));
        let waker = core::task::Waker::from(inner.clone());
        Self { inner, waker }
    }
    fn begin(&self, parent: &core::task::Waker) {
        let mut state = self.inner.0.lock();
        state.parent = Some(parent.clone());
        state.active = true;
        state.ready = false;
    }
    fn take_ready(&self) -> bool {
        let mut state = self.inner.0.lock();
        core::mem::take(&mut state.ready)
    }
    fn finish(&self, ready: bool) {
        let parent = {
            let mut state = self.inner.0.lock();
            state.active = false;
            if ready || state.ready { state.parent.clone() } else { None }
        };
        if let Some(parent) = parent { parent.wake(); }
    }
    fn clear(&self) {
        let mut state = self.inner.0.lock();
        state.parent = None; state.active = false; state.ready = false;
    }
}
