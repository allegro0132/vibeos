//! Opt-in native backend for the existing supervised WASI command job.
//! The arena borrows SYSTEM's job; it never owns an Arc to its I/O or authority.
use super::*;
use crate::wasmtime_platform::async_call::NativeFuture;
use vibeos_wasmtime_runtime::{wasi as w, wasmtime::{self, Engine, Store, Trap}};
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
    *active = None;
}
/// Executor quiescence plus this private exact-domain registration admits only
/// the one job published by launch. The SYSTEM reaper keeps the loan alive.
pub(crate) unsafe fn recover(domain: AllocationDomain) -> bool {
    let raw = match *ACTIVE.lock() { Some((d, raw)) if d == domain => raw, _ => return false };
    let job = unsafe { &*(raw as *const Job) };
    close(job);
    unsafe { crate::wasmtime_platform::recover_command_graph(domain); }
    true
}
fn close(job: &Job) { job.native_signal.clear(); job.io.stdin.close(); job.io.stdout.close(); job.io.stderr.close(); }
fn stopped(job: &Job) -> Option<WasiTerminal> {
    if job.io.cancelled() {
        Some(if job.io.denied() { WasiTerminal::Denied } else { WasiTerminal::Cancelled })
    } else if job.authority.as_ref().is_some_and(|check| !check())
        || job.caps.iter().any(|cap| job.space.rights_of(*cap).is_err()) {
        Some(WasiTerminal::Denied)
    } else { None }
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
        GuestIo(&self.job().io).write(cx, fd, data).map(|r| r.map_err(io_errno))
    }
    fn close(&mut self, fd: u32) -> Result<(), i32> {
        let io = &self.job().io;
        match fd { 0 => io.stdin.close(), 1 => io.stdout.close(), 2 => io.stderr.close(), _ => return Err(8) }
        Ok(())
    }
}
impl Drop for Streams { fn drop(&mut self) { close(self.job()); } }
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
            let outcome = this.future.as_mut().unwrap().as_mut().poll(&mut native_cx);
            this.guest_ticks += crate::sbi::time() - begin;
            match outcome {
                Poll::Pending => {
                    let ready = job.native_signal.take_ready();
                    if ready && quantum < 31 && exec::current_task_may_continue() { continue; }
                    job.native_signal.finish(ready);
                    return Poll::Pending;
                }
                Poll::Ready(terminal) => {
                    this.future = None;
                    close(job);
                    *job.result.lock() = Some(terminal);
                    crate::println!("WASI Wasmtime polls={} quantum=10000 scheduler=exec", this.polls);
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
    let mut config = crate::wasmtime_platform::configuration();
    config.max_wasm_stack(32 * 1024).async_stack_size(256 * 1024);
    let engine = Engine::new(&config)?;
    let begin = crate::sbi::time();
    let module = w::compile(&engine, &job.bytes)?;
    crate::println!("WASI Wasmtime compiled ticks={}", crate::sbi::time() - begin);
    // Compilation is synchronous. Recheck authority before any guest entry.
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    let linker = w::linker_streams::<Clock>(&engine, &module)?;
    let mut store = Store::new(&engine, w::Invocation::with_streams(&job.argv, Clock, Box::new(Streams(raw)))?);
    store.limiter(|state| state.resource_limits());
    let limits = invocation_limits();
    store.set_fuel(limits.total_fuel)?;
    store.fuel_async_yield_interval(Some(limits.poll_quantum))?;
    let instance = match NativeFuture::new(linker.instantiate_async(&mut store, &module)).await {
        Ok(instance) => instance,
        Err(error) => { drop(error); return Ok(if store.data().resource_limit_hit() { WasiTerminal::LimitExceeded } else { WasiTerminal::Trapped }); }
    };
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    crate::println!("WASI running backend=wasmtime");
    let result = NativeFuture::new(start.call_async(&mut store, ())).await;
    if let Some(terminal) = stopped(job) { return Ok(terminal); }
    let terminal = if store.data().resource_limit_hit() { WasiTerminal::LimitExceeded }
        else if let Some(code) = store.data().exit { WasiTerminal::Exited(code) }
        else { match &result {
            Ok(()) => WasiTerminal::Exited(0),
            Err(error) if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) => WasiTerminal::LimitExceeded,
            Err(_) => WasiTerminal::Trapped,
        }};
    drop(result);
    Ok(terminal)
}


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
