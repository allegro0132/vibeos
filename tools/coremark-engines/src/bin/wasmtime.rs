use std::time::Instant;
use wasmtime::*;
use wasmtime_wasi::{p1::{self, WasiP1Ctx}, WasiCtxBuilder, I32Exit};
struct State { wasi: WasiP1Ctx, limits: StoreLimits }
fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let fuel = args.first().is_some_and(|s| s == "--fuel");
    if fuel { args.remove(0); }
    assert!(!args.is_empty(), "wasmtime [--fuel] MODULE [args...]");
    let bytes = std::fs::read(&args[0])?;
    let setup = Instant::now();
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift).cranelift_opt_level(OptLevel::Speed)
        .consume_fuel(fuel).wasm_simd(false).wasm_relaxed_simd(false)
        .wasm_memory64(false).wasm_multi_memory(false);
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, &bytes)?;
    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi)?;
    let state = State {
        wasi: WasiCtxBuilder::new().args(&args).inherit_stdout().inherit_stderr().build_p1(),
        limits: StoreLimitsBuilder::new().memory_size(16 * 1024 * 1024).build(),
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|s| &mut s.limits);
    if fuel { store.set_fuel(100_000_000_000)?; }
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    eprintln!("engine=wasmtime-48.0.0 backend=cranelift opt=speed fuel={fuel} setup_seconds={:.6}", setup.elapsed().as_secs_f64());
    let run = Instant::now();
    let result = start.call(&mut store, ());
    eprintln!("execution_seconds={:.6} consumed_fuel={:?}", run.elapsed().as_secs_f64(), if fuel {Some(100_000_000_000-store.get_fuel()?)} else {None});
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.downcast_ref::<I32Exit>().is_some_and(|exit| exit.0 == 0) => Ok(()),
        Err(e) => Err(e),
    }
}
