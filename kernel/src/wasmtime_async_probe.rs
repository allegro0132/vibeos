//! Native fiber admission tests before connecting the command service.
use alloc::boxed::Box;
use super::async_call::{NativeFuture, fcsr, set_fcsr};
use core::{future::Future, task::{Context, Poll, Waker}};
use vibeos_wasmtime_runtime::wasmtime::{self, Engine, Instance, Module, Store, Trap};
fn poll<F: Future>(future: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    let saved = fcsr();
    set_fcsr(0x60);
    let result = future.poll(&mut Context::from_waker(Waker::noop()));
    assert_eq!(fcsr(), 0x60, "host FCSR leaked across poll");
    set_fcsr(saved);
    result
}
fn run_inner() -> wasmtime::Result<()> {
    let mut config = super::configuration();
    config.async_support(true).async_stack_size(256 * 1024).max_wasm_stack(32 * 1024);
    let engine = Engine::new(&config)?;
    let bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x09\x01\x07\0\x03\x40\x0c\0\x0b\x0b";
    let module = Module::new(&engine, bytes)?;
    for cycle in 0..100 {
        let mut store = Store::new(&engine, ());
        store.set_fuel(100_000)?;
        store.fuel_async_yield_interval(Some(10_000))?;
        let instance = {
            let mut future = Box::pin(NativeFuture::new(Instance::new_async(&mut store, &module, &[])));
            match poll(future.as_mut()) {
                Poll::Ready(result) => result?,
                Poll::Pending => wasmtime::bail!("unexpected instantiation yield"),
            }
        };
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
        let mut future = Box::pin(NativeFuture::new(run.call_async(&mut store, ())));
        assert!(poll(future.as_mut()).is_pending());
        assert!(poll(future.as_mut()).is_pending());
        if cycle % 2 == 0 {
            let mut polls = 2;
            loop {
                polls += 1;
                assert!(polls < 20, "fuel exhausted without termination");
                if let Poll::Ready(result) = poll(future.as_mut()) {
                    assert_eq!(result.unwrap_err().downcast_ref::<Trap>(), Some(&Trap::OutOfFuel));
                    break;
                }
            }
        }
        // Dropping a suspended future must unwind and free the active fiber.
        // Its destructor can execute guest cleanup and bypass sret on a trap.
        {
            let _state = super::native_traps::CallState::enter();
            drop(future);
        }
        assert!(store.get_fuel()? < 100_000);
    }
    stack_limit(&engine)?;
    host_wait(&engine)?;
    super::streams_probe::run(&engine)?;
    crate::println!("  WASMTIME ASYNC PASS cycles=100 fuel_quantum=10000 exhausted=50 suspended_cancel=50 host_wait=1 guest_fcsr=1");
    Ok(())
}

fn host_wait(engine: &Engine) -> wasmtime::Result<()> {
    use wasmtime::Linker;
    // (import "h" "f" (func)) (func (export "run") call 0 unreachable).
    let bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x02\x07\x01\x01h\x01f\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\x01\x0a\x07\x01\x05\0\x10\0\0\x0b";
    let module = Module::new(engine, bytes)?;
    let mut linker = Linker::<()>::new(engine);
    linker.func_wrap_async("h", "f", |_, (): ()| Box::new(async {
        super::fiber_stack::assert_current();
        assert_eq!(fcsr(), 0);
        set_fcsr(0x40);
        let mut yielded = false;
        core::future::poll_fn(|cx| {
            if yielded { Poll::Ready(()) } else {
                yielded = true; cx.waker().wake_by_ref(); Poll::Pending
            }
        }).await;
        assert_eq!(fcsr(), 0x40, "guest FCSR lost while host future waited");
    }))?;
    let mut store = Store::new(engine, ());
    store.set_fuel(10_000)?;
    let instance = {
        let mut future = Box::pin(NativeFuture::new(linker.instantiate_async(&mut store, &module)));
        match poll(future.as_mut()) { Poll::Ready(r) => r?, Poll::Pending => wasmtime::bail!("unexpected instantiation wait") }
    };
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    let mut future = Box::pin(NativeFuture::new(run.call_async(&mut store, ())));
    assert!(poll(future.as_mut()).is_pending());
    match poll(future.as_mut()) {
        Poll::Ready(result) => assert_eq!(result.unwrap_err().downcast_ref::<Trap>(), Some(&Trap::UnreachableCodeReached)),
        Poll::Pending => wasmtime::bail!("host wait did not resume"),
    }
    drop(future);
    Ok(())
}

pub(super) fn run() -> wasmtime::Result<()> {
    let owner = crate::HEAP.create_owner(super::invocation_heap_budget()).expect("async probe owner");
    let scope = vibeos_core::heap::enter_owner(owner);
    let success = match run_inner() {
        Ok(()) => true,
        Err(error) => { crate::println!("WASMTIME ASYNC ERROR {error:#}"); false }
    };
    drop(scope);
    let stats = crate::HEAP.account_stats(owner).unwrap();
    assert_eq!(stats.live_bytes, 0, "async store/fiber allocations leaked");
    assert_eq!(stats.denials, 0);
    crate::HEAP.unregister_owner(owner).expect("async owner released");
    crate::println!("  WASMTIME ASYNC HEAP live={} peak={}", stats.live_bytes, stats.peak_bytes);
    if !success { wasmtime::bail!("async probe failed"); }
    Ok(())
}


fn stack_limit(engine: &Engine) -> wasmtime::Result<()> {
    // Ordinary recursive call (not return_call), so every call consumes stack.
    let bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x06\x01\x04\0\x10\0\x0b";
    let module = Module::new(engine, bytes)?;
    for _ in 0..16 {
        let mut store = Store::new(engine, ());
        store.set_fuel(1_000_000)?;
        store.fuel_async_yield_interval(Some(10_000))?;
        let instance = {
            let mut future = Box::pin(NativeFuture::new(Instance::new_async(&mut store, &module, &[])));
            match poll(future.as_mut()) { Poll::Ready(r) => r?, Poll::Pending => wasmtime::bail!("stack probe instantiate yielded") }
        };
        let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
        let mut future = Box::pin(NativeFuture::new(run.call_async(&mut store, ())));
        let error = loop {
            match poll(future.as_mut()) {
                Poll::Ready(r) => break r.unwrap_err(),
                Poll::Pending => continue,
            }
        };
        assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::StackOverflow));
        drop(error); drop(future);
        assert!(store.get_fuel()? > 0);
    }
    crate::println!("  WASMTIME STACK LIMIT PASS recursive_traps=16 fuel_remaining=1");
    Ok(())
}
