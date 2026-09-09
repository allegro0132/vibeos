use std::time::Instant;
use wasmtime::*;
use wasmtime_wasi::{
    p1::{self, WasiP1Ctx},
    I32Exit, WasiCtxBuilder,
};
struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}
fn main() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut fuel = false;
    let mut profile = String::from("native");
    while let Some(arg) = args.first() {
        match arg.as_str() {
            "--fuel" => {
                fuel = true;
                args.remove(0);
            }
            "--profile" => {
                args.remove(0);
                if args.is_empty() {
                    bail!("--profile needs native, explicit-gc or guards-gc");
                }
                profile = args.remove(0);
            }
            _ => break,
        }
    }
    assert!(
        !args.is_empty(),
        "wasmtime [--fuel] [--profile NAME] MODULE [args...]"
    );
    let bytes = std::fs::read(&args[0])?;
    let setup = Instant::now();
    let mut config = Config::new();
    config
        .strategy(Strategy::Cranelift)
        .cranelift_opt_level(OptLevel::Speed)
        .consume_fuel(fuel)
        .wasm_simd(false)
        .wasm_relaxed_simd(false)
        .wasm_memory64(false)
        .wasm_multi_memory(false);
    match profile.as_str() {
        "native" => (), // Preserve the original benchmark's CPU/VM defaults.
        "explicit-gc" | "guards-gc" => {
            if !cfg!(all(
                target_arch = "riscv64",
                target_feature = "c",
                target_feature = "d"
            )) {
                bail!("GC controls require a RISC-V host");
            }
            // An explicit target disables native CPU feature discovery. Both
            // controls use the same GC ISA, with no opportunistic B extensions.
            config.target("riscv64gc-unknown-linux-gnu")?;
            // SAFETY: this runner is built for riscv64gc-unknown-linux-gnu.
            unsafe {
                config.cranelift_flag_enable("has_c");
            }
            config.max_wasm_stack(32 * 1024).memory_init_cow(false);
            if profile == "explicit-gc" {
                config
                    .signals_based_traps(false)
                    .memory_guard_size(0)
                    .memory_reservation(0)
                    .memory_may_move(true)
                    .memory_reservation_for_growth(0);
            } else {
                config
                    .signals_based_traps(true)
                    .memory_guard_size(64 * 1024)
                    .memory_reservation(1u64 << 32)
                    .memory_may_move(false)
                    .memory_reservation_for_growth(0);
            }
        }
        _ => bail!("unknown benchmark profile {profile}"),
    }
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, &bytes)?;
    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi)?;
    let state = State {
        wasi: WasiCtxBuilder::new()
            .args(&args)
            .inherit_stdout()
            .inherit_stderr()
            .build_p1(),
        limits: StoreLimitsBuilder::new()
            .memory_size(16 * 1024 * 1024)
            .build(),
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|s| &mut s.limits);
    if fuel {
        store.set_fuel(100_000_000_000)?;
    }
    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    eprintln!("engine=wasmtime-48.0.0 backend=cranelift opt=speed profile={profile} fuel={fuel} setup_seconds={:.6}", setup.elapsed().as_secs_f64());
    let run = Instant::now();
    let result = start.call(&mut store, ());
    eprintln!(
        "execution_seconds={:.6} consumed_fuel={:?}",
        run.elapsed().as_secs_f64(),
        if fuel {
            Some(100_000_000_000 - store.get_fuel()?)
        } else {
            None
        }
    );
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.downcast_ref::<I32Exit>().is_some_and(|exit| exit.0 == 0) => Ok(()),
        Err(e) => Err(e),
    }
}
