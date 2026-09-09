//! Verify bounded fuel batching without changing fuel exhaustion or cancellation.
#[path = "support/host_platform.rs"]
mod host_platform;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::future::Future;
use vibeos_wasmtime_runtime::{configuration, wasmtime};
struct Policy { remaining: AtomicUsize, checks: AtomicUsize, continued: AtomicUsize }
fn decision(raw: usize) -> bool {
    // The boxed policy outlives Store and its native future in this harness.
    let policy = unsafe { &*(raw as *const Policy) };
    policy.checks.fetch_add(1, Relaxed);
    if policy.remaining.load(Relaxed) == 0 { return false; }
    policy.remaining.fetch_sub(1, Relaxed);
    policy.continued.fetch_add(1, Relaxed);
    true
}
fn drive<F: std::future::Future>(future: F, policy: &Policy, budget: usize) -> (F::Output, usize) {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut polls = 0;
    loop {
        policy.remaining.store(budget, Relaxed);
        let before = policy.checks.load(Relaxed);
        polls += 1;
        let result = future.as_mut().poll(&mut cx);
        assert!(policy.checks.load(Relaxed)-before <= budget+1);
        if let std::task::Poll::Ready(value) = result { return (value, polls); }
    }
}
fn main() -> wasmtime::Result<()> {
    let mut config = configuration();
    config.max_wasm_stack(32*1024).async_stack_size(256*1024);
    let engine = wasmtime::Engine::new(&config)?;
    let module = wasmtime::Module::new(&engine, b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x09\x01\x07\0\x03\x40\x0c\0\x0b\x0b")?;
    let mut controls = Vec::new();
    for budget in [None, Some(0), Some(31)] {
        let policy = Box::new(Policy { remaining: 0.into(), checks: 0.into(), continued: 0.into() });
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_fuel(1_000_000)?;
        store.fuel_async_yield_interval(Some(10_000))?;
        if budget.is_some() { store.fuel_async_yield_callback(decision, (&*policy as *const Policy) as usize); }
        let instance = drive(wasmtime::Instance::new_async(&mut store, &module, &[]), &policy, budget.unwrap_or(0)).0?;
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
        let (result, polls) = drive(run.call_async(&mut store, ()), &policy, budget.unwrap_or(0));
        assert_eq!(result.unwrap_err().downcast_ref::<wasmtime::Trap>(), Some(&wasmtime::Trap::OutOfFuel));
        assert_eq!(store.get_fuel()?, 0);
        let checks = policy.checks.load(Relaxed);
        println!("budget={budget:?} polls={polls} checks={checks} continued={} fuel=0", policy.continued.load(Relaxed));
        controls.push((polls, checks));
        // Drop a pending native call, then run again on the same store.
        store.set_fuel(1_000_000)?;
        {
            let mut future = Box::pin(run.call_async(&mut store, ()));
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            policy.remaining.store(budget.unwrap_or(0), Relaxed);
            assert!(future.as_mut().poll(&mut cx).is_pending());
        }
        store.set_fuel(1_000_000)?;
        let (result, _) = drive(run.call_async(&mut store, ()), &policy, budget.unwrap_or(0));
        assert_eq!(result.unwrap_err().downcast_ref::<wasmtime::Trap>(), Some(&wasmtime::Trap::OutOfFuel));
        drop(store);
    }
    assert_eq!(controls[0].0, controls[1].0);
    assert_eq!(controls[1].1, controls[2].1);
    assert!(controls[2].0 * 16 < controls[1].0);
    drop((module, engine));
    assert_eq!(host_platform::memory_counts().2, 0);
    println!("PASS unchanged fuel, bounded polls, cancellation and reuse");
    Ok(())
}
