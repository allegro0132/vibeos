//! Trusted CoreMark-only Linux control, not an untrusted command service.
//! Standard Wasmtime 48 + official Preview 1, one OS thread/Store per worker.
use std::sync::{Arc, Mutex, atomic::{AtomicI32, Ordering}};
use std::thread::JoinHandle;
use std::time::Instant;
use wasmtime::*;
use wasmtime_wasi::{I32Exit, WasiCtxBuilder, p1::{self, WasiP1Ctx}};

const FUEL: u64 = 100_000_000_000;
struct Runtime {
    engine: Engine,
    module: Module,
    linker: Linker<State>,
    args: Vec<String>,
    fuel: bool,
    next_tid: AtomicI32,
    workers: Mutex<Vec<JoinHandle<Result<()>>>>,
}
struct State {
    wasi: WasiP1Ctx,
    runtime: Option<Arc<Runtime>>,
}
impl Runtime {
    fn run(self: &Arc<Self>, thread: Option<(i32, i32)>) -> Result<()> {
        let state = State {
            wasi: WasiCtxBuilder::new().args(&self.args).inherit_stdout().inherit_stderr().build_p1(),
            runtime: Some(self.clone()),
        };
        let mut store = Store::new(&self.engine, state);
        if self.fuel { store.set_fuel(FUEL)?; }
        let instance = self.linker.instantiate(&mut store, &self.module)?;
        let result = if let Some(args) = thread {
            instance.get_typed_func::<(i32, i32), ()>(&mut store, "wasi_thread_start")?.call(&mut store, args)
        } else {
            instance.get_typed_func::<(), ()>(&mut store, "_start")?.call(&mut store, ())
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) if thread.is_none() && error.downcast_ref::<I32Exit>().is_some_and(|exit| exit.0 == 0) => Ok(()),
            Err(error) => Err(error),
        }
    }
}
fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--version") {
        println!("wasmtime-threads 48.0.0 std-linux; vendored RISC-V compiler correctness fixes");
        return Ok(());
    }
    let fuel = args.first().map(String::as_str) == Some("--fuel");
    if fuel { args.remove(0); }
    ensure!(!args.is_empty(), "wasmtime-threads [--fuel] MODULE [arguments...]");
    let started = Instant::now();
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift).cranelift_opt_level(OptLevel::Speed)
        .wasm_threads(true).shared_memory(true).consume_fuel(fuel).wasm_simd(false).wasm_relaxed_simd(false)
        .wasm_memory64(false).wasm_multi_memory(false);
    // Match VibeOS's scalar target ISA, retaining Linux's normal memory/traps.
    config.target("riscv64gc-unknown-linux-gnu")?;
    unsafe { config.cranelift_flag_enable("has_c"); }
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, std::fs::read(&args[0])?)?;
    let memory_type = module.imports().find_map(|import| {
        if import.module() == "env" && import.name() == "memory" {
            if let ExternType::Memory(ty) = import.ty() { return Some(ty); }
        }
        None
    }).ok_or_else(|| format_err!("shared env.memory import required"))?;
    ensure!(memory_type.is_shared() && memory_type.maximum().is_some_and(|n| n <= 256), "bounded shared memory required");
    let memory = SharedMemory::new(&engine, memory_type)?;
    let mut linker = Linker::<State>::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    let probe = Store::new(&engine, State { wasi: WasiCtxBuilder::new().build_p1(), runtime: None });
    linker.define(&probe, "env", "memory", memory)?;
    drop(probe);
    linker.func_wrap("wasi", "thread-spawn", |caller: Caller<'_, State>, arg: i32| -> i32 {
        let runtime = caller.data().runtime.as_ref().expect("worker runtime").clone();
        let tid = runtime.next_tid.fetch_add(1, Ordering::Relaxed);
        // CoreMark has at most four workers. Bound accidental fixture misuse.
        if tid > 4 { return -6; }
        let worker = runtime.clone();
        match std::thread::Builder::new().name(format!("wasm-{tid}")).spawn(move || worker.run(Some((tid, arg)))) {
            Ok(handle) => { runtime.workers.lock().unwrap().push(handle); tid }
            Err(_) => -6,
        }
    })?;
    let runtime = Arc::new(Runtime { engine, module, linker, args, fuel,
        next_tid: AtomicI32::new(1), workers: Mutex::new(Vec::new()) });
    let compiled = started.elapsed();
    let run = Instant::now();
    runtime.run(None)?;
    loop {
        let handle = runtime.workers.lock().unwrap().pop();
        let Some(handle) = handle else { break; };
        handle.join().map_err(|_| format_err!("worker panicked"))??;
    }
    eprintln!("engine=wasmtime-48.0.0 platform=std-linux scheduler=os-threads isa=rv64gc fuel={fuel} setup_seconds={:.6} run_seconds={:.6} spawned={}",
        compiled.as_secs_f64(), run.elapsed().as_secs_f64(), runtime.next_tid.load(Ordering::Relaxed)-1);
    ensure!(Arc::strong_count(&runtime) == 1, "thread runtime reference survived join");
    Ok(())
}
