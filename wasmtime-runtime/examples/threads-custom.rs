//! wasi-threads through the no_std custom platform: one shared memory, one
//! Store per guest thread, a round-robin host driver standing in for the
//! kernel executor. Usage: threads-custom [--cap N] MODULE.wasm [arguments...]
#[path = "support/host_platform.rs"]
mod host_platform;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use vibeos_wasmtime_runtime::wasi::threads::{self, ThreadSpawner};
use vibeos_wasmtime_runtime::wasi::{self, Clock, Invocation, Streams};
use vibeos_wasmtime_runtime::{configuration, enable_threads, wasmtime};

const MAX_THREADS: usize = 32;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static READY: [AtomicBool; MAX_THREADS] = [const { AtomicBool::new(true) }; MAX_THREADS];
static WAKES: AtomicUsize = AtomicUsize::new(0);
static SLEEPS: AtomicUsize = AtomicUsize::new(0);

struct HostHooks;
impl wasmtime::ThreadHooks for HostHooks {
    fn current(&self) -> [usize; 2] { [CURRENT.load(SeqCst), 0] }
    fn wake(&self, token: [usize; 2]) {
        WAKES.fetch_add(1, SeqCst);
        READY[token[0]].store(true, SeqCst);
    }
    fn sleep(&self, nanoseconds: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        SLEEPS.fetch_add(1, SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_nanos(nanoseconds);
        Box::pin(std::future::poll_fn(move |cx| {
            if std::time::Instant::now() >= deadline { Poll::Ready(()) } else { cx.waker().wake_by_ref(); Poll::Pending }
        }))
    }
}
struct ThreadWaker(usize);
impl Wake for ThreadWaker {
    fn wake(self: Arc<Self>) { READY[self.0].store(true, SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { READY[self.0].store(true, SeqCst); }
}
struct Spawner { cap: usize, count: AtomicUsize, next_tid: AtomicI32, pending: Mutex<Vec<(i32, i32)>> }
impl ThreadSpawner for Spawner {
    fn spawn(&self, start_arg: i32) -> i32 {
        if self.count.fetch_add(1, SeqCst) >= self.cap {
            self.count.fetch_sub(1, SeqCst);
            return threads::SPAWN_AGAIN;
        }
        let tid = self.next_tid.fetch_add(1, SeqCst);
        self.pending.lock().unwrap().push((tid, start_arg));
        tid
    }
}
struct HostClock(std::time::Instant);
impl Clock for HostClock {
    fn time(&mut self, id: u32, _precision: u64) -> Result<u64, i32> {
        match id {
            0 => Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| 29)?.as_nanos() as u64),
            1 => Ok(self.0.elapsed().as_nanos() as u64),
            _ => Err(52),
        }
    }
    fn resolution(&mut self, id: u32) -> Result<u64, i32> { if id < 2 { Ok(1) } else { Err(52) } }
}
// Job-wide output budget shared by every thread's streams, as in the kernel.
static OUTPUT_REMAINING: AtomicUsize = AtomicUsize::new(65536);
struct HostStreams;
impl Streams for HostStreams {
    fn read(&mut self, _cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize, i32>> {
        use std::io::Read;
        Poll::Ready(std::io::stdin().read(bytes).map_err(|_| 29))
    }
    fn write(&mut self, _cx: &mut Context<'_>, fd: u32, bytes: &[u8]) -> Poll<Result<usize, i32>> {
        use std::io::Write;
        let result = if fd == 1 { std::io::stdout().write(bytes) } else { std::io::stderr().write(bytes) }.map_err(|_| 29);
        if let Ok(n) = result { OUTPUT_REMAINING.fetch_sub(n, SeqCst); }
        Poll::Ready(result)
    }
    fn output_remaining(&self) -> usize { OUTPUT_REMAINING.load(SeqCst) }
}
struct Outcome { tid: i32, exit: Option<u32>, result: wasmtime::Result<()>, fuel: u64 }
type Thread = (usize, Waker, Pin<Box<dyn Future<Output = Outcome>>>);

fn main() -> wasmtime::Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut cap = 3usize;
    if args.first().map(String::as_str) == Some("--cap") {
        args.remove(0);
        cap = args.remove(0).parse().expect("--cap N");
    }
    let path = args.first().cloned().expect("MODULE.wasm [arguments...]");
    let argv = args.clone();
    let mut config = configuration();
    config.max_wasm_stack(32 * 1024).async_stack_size(256 * 1024);
    enable_threads(&mut config, Arc::new(HostHooks));
    let engine = wasmtime::Engine::new(&config)?;
    let module = wasi::compile_with(&engine, &std::fs::read(&path)?, true)?;
    let spawner = Arc::new(Spawner { cap, count: AtomicUsize::new(0), next_tid: AtomicI32::new(1), pending: Mutex::new(Vec::new()) });
    let memory = if wasi::uses_threads(&module) { Some(threads::create_shared_memory(&engine, &module)?) } else { None };
    let mut linker = threads::linker_threads::<HostClock>(&engine, &module, spawner.clone())?;
    let linker = if let Some(memory) = &memory {
        let probe = wasmtime::Store::new(&engine, Invocation::with_streams(&argv, HostClock(std::time::Instant::now()), Box::new(HostStreams))?);
        threads::define_shared_memory(&mut linker, &probe, memory)?;
        Arc::new(linker)
    } else { Arc::new(linker) };
    let run_thread = {
        let engine = engine.clone(); let module = module.clone(); let linker = linker.clone(); let argv = argv.clone();
        move |tid: i32, start_arg: i32| -> Pin<Box<dyn Future<Output = Outcome>>> {
            let (engine, module, linker, argv) = (engine.clone(), module.clone(), linker.clone(), argv.clone());
            Box::pin(async move {
                let run = async {
                    let mut state = Invocation::with_streams(&argv, HostClock(std::time::Instant::now()), Box::new(HostStreams))?;
                    state.tid = tid as u32;
                    let mut store = wasmtime::Store::new(&engine, state);
                    store.limiter(|state| state.resource_limits());
                    store.set_fuel(10_000_000)?;
                    store.fuel_async_yield_interval(Some(10_000))?;
                    let instance = linker.instantiate_async(&mut store, &module).await?;
                    let result = if tid == 0 {
                        instance.get_typed_func::<(), ()>(&mut store, "_start")?.call_async(&mut store, ()).await
                    } else {
                        threads::thread_start(&instance, &mut store)?.call_async(&mut store, (tid, start_arg)).await
                    };
                    let exit = store.data().exit;
                    let fuel = store.get_fuel()?;
                    let result = match result {
                        Err(error) if exit.is_some() => { drop(error); Ok(()) }
                        other => other,
                    };
                    Ok::<_, wasmtime::Error>((exit, result, fuel))
                };
                match run.await {
                    Ok((exit, result, fuel)) => Outcome { tid, exit, result, fuel },
                    Err(error) => Outcome { tid, exit: None, result: Err(error), fuel: 0 },
                }
            })
        }
    };
    let mut threads: Vec<Thread> = Vec::new();
    let mut next_index = 0usize;
    let mut add = |threads: &mut Vec<Thread>, tid: i32, arg: i32| {
        let index = next_index; next_index += 1;
        assert!(index < MAX_THREADS);
        READY[index].store(true, SeqCst);
        threads.push((index, Waker::from(Arc::new(ThreadWaker(index))), run_thread(tid, arg)));
    };
    add(&mut threads, 0, 0);
    let mut exit: Option<u32> = None;
    let mut trap: Option<wasmtime::Error> = None;
    let mut polls = 0usize;
    let mut finished = 0usize;
    let mut fuel_used = 0u64;
    let mut idle_rounds = 0usize;
    let cancel_after: Option<usize> = std::env::var("THREADS_CUSTOM_CANCEL_AFTER").ok().map(|v| v.parse().unwrap());
    'run: loop {
        if cancel_after == Some(polls) { eprintln!("cancelling after {polls} polls"); break 'run; }
        for (tid, arg) in spawner.pending.lock().unwrap().drain(..).collect::<Vec<_>>() { add(&mut threads, tid, arg); }
        let mut progressed = false;
        let mut i = 0;
        while i < threads.len() {
            let (index, waker, future) = &mut threads[i];
            if !READY[*index].swap(false, SeqCst) { i += 1; continue; }
            progressed = true;
            polls += 1;
            CURRENT.store(*index, SeqCst);
            match future.as_mut().poll(&mut Context::from_waker(waker)) {
                Poll::Pending => { i += 1; }
                Poll::Ready(outcome) => {
                    finished += 1;
                    fuel_used += 10_000_000 - outcome.fuel;
                    let main = outcome.tid == 0;
                    drop(threads.remove(i));
                    if let Some(code) = outcome.exit { exit = Some(code); break 'run; }
                    if let Err(error) = outcome.result { trap = Some(error); break 'run; }
                    if main { break 'run; }
                }
            }
        }
        if !progressed {
            idle_rounds += 1;
            assert!(idle_rounds < 200_000, "all guest threads are blocked");
            std::thread::sleep(std::time::Duration::from_micros(50));
        } else { idle_rounds = 0; }
    }
    // Process semantics: whatever ended the process cancels every other thread.
    let cancelled = threads.len();
    drop(threads);
    let exit = match (exit, trap) {
        (Some(code), _) => code,
        (None, Some(error)) => { eprintln!("wasi_trap={error}"); drop(error); 128 }
        (None, None) => 0,
    };
    eprintln!("wasi_exit={exit} threads={} finished={finished} cancelled={cancelled} polls={polls} wakes={} sleeps={} fuel_used={fuel_used} output_remaining={}",
        spawner.count.load(SeqCst) + 1, WAKES.load(SeqCst), SLEEPS.load(SeqCst), OUTPUT_REMAINING.load(SeqCst));
    drop(add);
    drop(run_thread);
    drop((spawner, linker, memory, module, engine));
    assert_eq!(host_platform::memory_counts().2, 0, "code or memory mappings leaked");
    if exit != 0 { std::process::exit(if exit <= 255 { exit as i32 } else { 1 }); }
    Ok(())
}
