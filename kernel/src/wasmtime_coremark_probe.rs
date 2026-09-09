//! Opt-in trusted CoreMark measurement, not the upload/command service.
use alloc::{string::String, vec::Vec};
use vibeos_wasmtime_runtime::{
    wasi::{self, Invocation},
    wasmtime::{self, Engine, Store},
};
const WASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/coremark.wasm"));
pub fn run() -> wasmtime::Result<()> {
    // Compiler/instance allocations use a measured owner. Untracked allocations
    // deliberately avoid claiming the unfinished arena no-escape contract.
    // Reserve the entire 2 MiB code pool from the 32 MiB total budget.
    let owner = crate::HEAP
        .create_owner(super::invocation_heap_budget())
        .expect("probe owner");
    let scope = vibeos_core::heap::enter_owner(owner);
    let result = execute();
    // Format/drop any error inside its owner; no error/backtrace escapes.
    let success = match result {
        Ok(()) => true,
        Err(e) => {
            crate::println!("WASMTIME COREMARK ERROR {e:#}");
            false
        }
    };
    drop(scope);
    let stats = crate::HEAP.account_stats(owner).unwrap();
    crate::println!(
        "WASMTIME COREMARK heap_peak={} heap_live={} denials={}",
        stats.peak_bytes,
        stats.live_bytes,
        stats.denials
    );
    assert_eq!(stats.live_bytes, 0, "probe allocations remain live");
    crate::HEAP
        .unregister_owner(owner)
        .expect("release probe owner");
    if !success {
        wasmtime::bail!("CoreMark probe failed");
    }
    Ok(())
}
fn execute() -> wasmtime::Result<()> {
    let mut config = super::configuration();
    config.max_wasm_stack(32 * 1024);
    #[cfg(feature = "wasmtime-async")]
    config.async_support(true).async_stack_size(256 * 1024);
    let engine = Engine::new(&config)?;
    let compile_start = crate::sbi::time();
    let module = wasi::compile(&engine, WASM)?;
    let compiled = crate::sbi::time();
    let linker = wasi::linker::<super::wasi_probe::KernelClock>(&engine, &module)?;
    let seed = if env!("VIBEOS_COREMARK_VALIDATION") == "1" { "0x3415" } else { "0" };
    let args = [
        "coremark.wasm",
        seed,
        seed,
        "0x66",
        env!("VIBEOS_COREMARK_ITERATIONS"),
    ]
    .map(String::from);
    let mut store = Store::new(
        &engine,
        Invocation::new(&args, Vec::new(), super::wasi_probe::KernelClock)?,
    );
    store.set_fuel(100_000_000_000)?;
    #[cfg(not(feature = "wasmtime-async"))]
    let instance = linker.instantiate(&mut store, &module)?;
    #[cfg(feature = "wasmtime-async")]
    let instance = {
        store.fuel_async_yield_interval(Some(10_000))?;
        drive(linker.instantiate_async(&mut store, &module)).0?
    };
    let run_start = crate::sbi::time();
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    #[cfg(not(feature = "wasmtime-async"))]
    let result = super::call(&start, &mut store, ());
    #[cfg(feature = "wasmtime-async")]
    let (result, polls) = drive(start.call_async(&mut store, ()));
    let end = crate::sbi::time();
    #[cfg(feature = "wasmtime-async")]
    crate::println!("WASMTIME COREMARK async_polls={} fuel_quantum=10000 scheduler=manual", polls);
    crate::println!("WASMTIME COREMARK stdout begin");
    crate::print!("{}", core::str::from_utf8(&store.data().stdout).unwrap());
    crate::println!("WASMTIME COREMARK stdout end");
    assert!(store.data().stderr.is_empty());
    match store.data().exit {
        Some(0) => drop(result),
        Some(code) => {
            drop(result);
            wasmtime::bail!("CoreMark exit {code}");
        }
        None => result?,
    }
    crate::println!(
        "WASMTIME COREMARK compile_ticks={} run_ticks={} hz={} fuel={}",
        compiled - compile_start,
        end - run_start,
        vibeos_core::exec::timebase_hz(),
        100_000_000_000 - store.get_fuel()?
    );
    Ok(())
}

/// Timing control for fiber overhead only. Production will await through exec.
#[cfg(feature = "wasmtime-async")]
fn drive<F: core::future::Future>(future: F) -> (F::Output, usize) {
    use core::{future::Future, task::{Context, Poll, Waker}};
    let mut future = core::pin::pin!(super::async_call::NativeFuture::new(future));
    let mut count = 0;
    loop {
        count += 1;
        assert!(count <= 20_000_000, "async measurement exceeded its poll bound");
        if let Poll::Ready(result) = future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            return (result, count);
        }
    }
}
