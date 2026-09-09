//! Fixed code registry; every opaque strong reference has an allocation domain.
use vibeos_core::heap::AllocationDomain;
#[derive(Clone, Copy)]
struct Entry { start: usize, end: usize, code: usize, domain: AllocationDomain }
static CODE: crate::sync::SpinLock<[Option<Entry>; 16]> = crate::sync::SpinLock::new([None; 16]);
#[no_mangle]
extern "C" fn wasmtime_code_register(start: usize, end: usize, code: *const u8) -> i32 {
    if start >= end || code.is_null() { return 22; }
    let domain = {
        let maps = super::MAPS.lock();
        let Some(mapping) = maps.iter().flatten().find(|m| start >= m.base && end <= m.base + m.len
            && matches!(m.image, Some(super::Image::Frozen(_)))) else { return 22 };
        mapping.domain
    };
    let mut entries = CODE.lock();
    if entries.iter().flatten().any(|e| start < e.end && e.start < end) { return 22; }
    let Some(slot) = entries.iter_mut().find(|e| e.is_none()) else { return 12 };
    *slot = Some(Entry { start, end, code: code as usize, domain });
    0
}
#[no_mangle]
unsafe extern "C" fn wasmtime_code_lookup(pc: usize, retain: unsafe extern "C" fn(*const u8), offset: &mut usize) -> *const u8 {
    let entries = CODE.lock();
    let Some(entry) = entries.iter().flatten().find(|e| e.start <= pc && pc < e.end) else { return core::ptr::null() };
    let code = entry.code as *const u8;
    // Runtime callback only increments a valid Arc counter; it cannot allocate
    // or reenter this registry. Removal is excluded until the retain completes.
    unsafe { retain(code); }
    *offset = pc - entry.start;
    code
}
#[no_mangle]
extern "C" fn wasmtime_code_unregister(start: usize, end: usize) -> *const u8 {
    let mut entries = CODE.lock();
    let Some(slot) = entries.iter_mut().find(|e| e.is_some_and(|e| e.start == start && e.end == end)) else { return core::ptr::null() };
    slot.take().unwrap().code as *const u8
}
pub(super) fn assert_idle() {
    let idle = CODE.lock().iter().all(Option::is_none);
    assert!(idle);
    crate::println!("  WASMTIME CODE REGISTRY PASS capacity=16 live=0");
}

// Private admission for fixed runtime fault fixtures: active TLS must be
// repaired by exact-task cleanup; no external host resource or module escapes.
static PROBE: crate::sync::SpinLock<Option<AllocationDomain>> = crate::sync::SpinLock::new(None);
static REMOVED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static DROPS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
struct DropProbe;
impl Drop for DropProbe { fn drop(&mut self) { DROPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed); } }
/// The caller has the executor's all-domain quiescence witness. Forget strong
/// references rather than running destructors in an interrupted object graph.
pub(super) unsafe fn recover_probe(domain: AllocationDomain) -> bool {
    if *PROBE.lock() != Some(domain) { return false; }
    unsafe { recover_owned_graph(domain); }
    *PROBE.lock() = None;
    true
}
/// Only private fixtures or the command supervisor may admit an entire graph.
pub(super) unsafe fn recover_owned_graph(domain: AllocationDomain) {
    use core::sync::atomic::Ordering;
    // Calls either returned normally or exact-task cleanup restored their TLS.
    for slots in &super::TLS {
        assert_eq!(slots[0].load(Ordering::Relaxed).addr() & !1, 0);
        assert!(slots[1].load(Ordering::Relaxed).is_null());
    }
    let mut removed = 0;
    {
        let mut entries = CODE.lock();
        for slot in entries.iter_mut() {
            if slot.is_some_and(|e| e.domain == domain) { *slot = None; removed += 1; }
        }
    }
    let mut mappings = 0;
    {
        let mut maps = super::MAPS.lock();
        for slot in maps.iter_mut() {
            if slot.as_ref().is_some_and(|m| m.domain == domain) {
                core::mem::forget(slot.take().unwrap()); mappings += 1;
            }
        }
    }
    unsafe { super::fiber_stack::recover(domain); }
    unsafe { super::guarded_memory::recover(domain); }
    unsafe { crate::code_pool::recover_faulted_domain(domain); }
    REMOVED.store(removed.min(mappings), Ordering::Release);
}
pub(super) async fn recovery_selftest() {
    use core::sync::atomic::Ordering;
    use vibeos_wasmtime_runtime::wasmtime::{Engine, Module, Store, Instance};
    let baseline = crate::code_pool::stats();
    let drops = DROPS.load(Ordering::Relaxed);
    for cycle in 0..80 {
        let owner = crate::HEAP.create_owner(4 * 1024 * 1024).unwrap();
        let arena = crate::HEAP.create_arena(owner).unwrap();
        let domain = AllocationDomain::new(owner, arena);
        { let mut probe = PROBE.lock(); assert!(probe.is_none()); *probe = Some(domain); }
        REMOVED.store(0, Ordering::Release);
        ASYNC_STAGE.store(0, Ordering::Relaxed);
        let recovered = super::call_recovery::RECOVERED.load(Ordering::Relaxed);
        // Only copied registry/mapping records escape. No Engine/Store/Module
        // handle, host stream, or error/backtrace crosses this child boundary.
        let child = unsafe { crate::exec::spawn_reclaimable_owned(domain, "wasmtime-code-fault", async move {
            let _drop = DropProbe;
            if cycle >= 32 { async_fault_fixture(if cycle >= 64 { 2 } else if cycle >= 48 { 1 } else { 0 }).await; }
            let mut config = super::configuration(); config.max_wasm_stack(32 * 1024);
            let engine = Engine::new(&config).unwrap();
            // An ordinary memory-bearing module exporting run() -> 42.
            let bytes = b"\0asm\x01\0\0\0\x01\x05\x01\x60\0\x01\x7f\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x10\x02\x03run\0\0\x06memory\x02\0\x0a\x06\x01\x04\0\x41\x2a\x0b";
            let module = Module::new(&engine, bytes).unwrap();
            let mut store = Store::new(&engine, ()); store.set_fuel(10_000).unwrap();
            let instance = Instance::new(&mut store, &module, &[]).unwrap();
            if cycle >= 16 {
                // The imported function panics while Wasmtime TLS still points
                // into this arena's active call. It owns no external resource.
                let callback = vibeos_wasmtime_runtime::wasmtime::Func::wrap(&mut store, || -> i32 {
                    assert_ne!(super::TLS[super::hart()][0].load(Ordering::Relaxed).addr() & !1, 0);
                    super::async_call::set_fcsr(0x40);
                    panic!("deliberate active Wasmtime host callback fault");
                });
                let active_bytes = b"\0asm\x01\0\0\0\x01\x05\x01\x60\0\x01\x7f\x02\x0d\x01\x04host\x04fail\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\x01\x0a\x06\x01\x04\0\x10\0\x0b";
                let active_module = Module::new(&engine, active_bytes).unwrap();
                let active = Instance::new(&mut store, &active_module, &[callback.into()]).unwrap();
                let run = active.get_typed_func::<(), i32>(&mut store, "run").unwrap();
                let _ = super::call(&run, &mut store, ());
                panic!("faulting host callback returned");
            }
            let run = instance.get_typed_func::<(), i32>(&mut store, "run").unwrap();
            assert_eq!(super::call(&run, &mut store, ()).unwrap(), 42);
            assert!(CODE.lock().iter().flatten().any(|e| e.domain == domain));
            panic!("deliberate post-call Wasmtime arena fault");
        }) };
        if cycle >= 64 {
            while ASYNC_STAGE.load(Ordering::Acquire) == 0 { crate::exec::yield_now().await; }
            let _ = child.cancel();
        }
        assert_eq!(child.join().await.state(), crate::exec::TaskState::Faulted);
        assert_eq!(super::call_recovery::RECOVERED.load(Ordering::Relaxed) - recovered, usize::from((16..32).contains(&cycle) || cycle >= 48));
        assert_eq!(ASYNC_STAGE.load(Ordering::Relaxed), if cycle >= 64 { 3 } else if cycle >= 48 { 2 } else if cycle >= 32 { 1 } else { 0 });
        assert!(REMOVED.load(Ordering::Acquire) > 0);
        assert!(CODE.lock().iter().all(Option::is_none));
        assert!(super::MAPS.lock().iter().all(Option::is_none));
        assert!(crate::mmu::mapping(crate::mmu::WASM_MEMORY_BASE).is_none());
        let stats = crate::HEAP.account_stats(owner).unwrap();
        assert_eq!(stats.live_bytes, 0); assert_eq!(stats.denials, 0);
        assert!(crate::HEAP.arena_stats(arena).is_none());
        assert_eq!(crate::code_pool::stats().live_pages, baseline.live_pages);
        assert_eq!(crate::code_pool::stats().sealed_pages, baseline.sealed_pages);
        assert_eq!(DROPS.load(Ordering::Relaxed), drops);
        crate::HEAP.unregister_owner(owner).unwrap(); drop(child);
    }
    compile_recovery_selftest().await;
    crate::println!("  WASMTIME FIBER RECOVERY PASS suspended=16 resumed_fault=16 cancel_drop_fault=16 tls=0 drops=0 registry=0 maps=0 heap=0");
    crate::println!("  WASMTIME ACTIVE RECOVERY PASS faults=16 tls=0 drops=0 registry=0 maps=0 heap=0");
    crate::println!("  WASMTIME CODE RECOVERY PASS faults=16 post_call=1 drops=0 registry=0 maps=0 heap=0");
}


static ASYNC_STAGE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// All runtime objects and host futures stay in the one privately admitted arena.
/// No I/O reference or saved external waker is published by this fixture.
async fn async_fault_fixture(mode: u8) -> ! {
    use alloc::boxed::Box;
    use core::{future::{Future, poll_fn}, task::Poll, sync::atomic::Ordering};
    use super::async_call::{NativeFuture, fcsr, set_fcsr};
    use vibeos_wasmtime_runtime::wasmtime::{Engine, Module, Store, Linker};
    let mut config = super::configuration();
    config.async_support(true).async_stack_size(256 * 1024).max_wasm_stack(32 * 1024);
    let engine = Engine::new(&config).unwrap();
    // A memory-bearing module imports h.f and calls it from run().
    let bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x02\x07\x01\x01h\x01f\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x07\x01\x03run\0\x01\x0a\x06\x01\x04\0\x10\0\x0b";
    let module = Module::new(&engine, bytes).unwrap();
    let mut linker = Linker::<()>::new(&engine);
    linker.func_wrap_async::<_, _, ()>("h", "f", move |_, (): ()| Box::new(async move {
        let _drop = AsyncDropFault(mode == 2);
        set_fcsr(0x40);
        let mut yielded = false;
        poll_fn(|cx| {
            if yielded { Poll::Ready(()) } else {
                yielded = true;
                ASYNC_STAGE.store(1, Ordering::Relaxed);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }).await;
        assert_eq!(fcsr(), 0x40);
        assert_ne!(super::TLS[super::hart()][0].load(Ordering::Relaxed).addr() & !1, 0);
        ASYNC_STAGE.store(2, Ordering::Relaxed);
        panic!("deliberate resumed native fiber fault");
    })).unwrap();
    let mut store = Store::new(&engine, ());
    store.set_fuel(100_000).unwrap();
    store.fuel_async_yield_interval(Some(10_000)).unwrap();
    let instance = NativeFuture::new(linker.instantiate_async(&mut store, &module)).await.unwrap();
    let run = instance.get_typed_func::<(), ()>(&mut store, "run").unwrap();
    let mut call = Box::pin(NativeFuture::new(run.call_async(&mut store, ())));
    poll_fn(|cx| {
        assert!(call.as_mut().poll(cx).is_pending());
        assert_eq!(ASYNC_STAGE.load(Ordering::Relaxed), 1);
        Poll::Ready(())
    }).await;
    // Return to the real executor with the native fiber suspended in this task.
    crate::exec::yield_now().await;
    if mode == 2 {
        core::future::pending::<()>().await;
    }
    if mode == 1 {
        let _ = call.await;
        panic!("faulting async callback returned");
    }
    // Skip fiber Drop while its suspended frames and runtime graph are live.
    panic!("deliberate suspended native fiber arena fault");
}

struct AsyncDropFault(bool);
impl Drop for AsyncDropFault {
    fn drop(&mut self) {
        if !self.0 { return; }
        // The executor is destroying a detached task, not polling a running one.
        assert!(crate::exec::current_task_id().is_none());
        assert!(crate::exec::current_task_scope_id().is_some());
        ASYNC_STAGE.store(3, core::sync::atomic::Ordering::Release);
        panic!("deliberate native host future cancellation destructor fault");
    }
}


static COMPILE_STAGE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
async fn compile_recovery_selftest() {
    use core::sync::atomic::Ordering;
    use vibeos_wasmtime_runtime::{wasmtime::Engine, wasi};
    let baseline = crate::code_pool::stats();
    let mut denied = 0;
    let mut compiled = 0;
    // Sweep independent budgets through config/engine/validator/compiler/image
    // construction. A copied phase marker is the only extra escaping state.
    for budget in [8192, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152] {
        let owner = crate::HEAP.create_owner(budget).unwrap();
        let arena = crate::HEAP.create_arena(owner).unwrap();
        let domain = AllocationDomain::new(owner, arena);
        { let mut probe = PROBE.lock(); assert!(probe.is_none()); *probe = Some(domain); }
        COMPILE_STAGE.store(0, Ordering::Relaxed);
        let child = unsafe { crate::exec::spawn_reclaimable_owned(domain, "wasmtime-compile-limit", async move {
            COMPILE_STAGE.store(1, Ordering::Relaxed);
            let config = super::configuration();
            let engine = Engine::new(&config).unwrap();
            COMPILE_STAGE.store(2, Ordering::Relaxed);
            let bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02\x07\x13\x02\x06_start\0\0\x06memory\x02\0\x0a\x04\x01\x02\0\x0b";
            let module = wasi::compile(&engine, bytes);
            COMPILE_STAGE.store(if module.is_ok() { 4 } else { 3 }, Ordering::Release);
            core::hint::black_box(&module);
            panic!("deliberate compiler result arena fault");
        }) };
        assert_eq!(child.join().await.state(), crate::exec::TaskState::Faulted);
        let stage = COMPILE_STAGE.load(Ordering::Acquire);
        let stats = crate::HEAP.account_stats(owner).unwrap();
        denied += usize::from(stats.denials > 0);
        compiled += usize::from(stage == 4);
        assert!(stage == 4 || stats.denials > 0, "compile fixture failed without resource pressure");
        assert_eq!(stats.live_bytes, 0);
        assert!(crate::HEAP.arena_stats(arena).is_none());
        assert!(CODE.lock().iter().all(Option::is_none));
        assert!(super::MAPS.lock().iter().all(Option::is_none));
        assert_eq!(crate::code_pool::stats().live_pages, baseline.live_pages);
        assert_eq!(crate::code_pool::stats().sealed_pages, baseline.sealed_pages);
        crate::println!("  WASMTIME COMPILE BUDGET bytes={} stage={} peak={} denials={}", budget, stage, stats.peak_bytes, stats.denials);
        crate::HEAP.unregister_owner(owner).unwrap(); drop(child);
    }
    assert!(denied > 0 && compiled > 0);
    crate::println!("  WASMTIME COMPILE RECOVERY PASS budgets=8 denied={} compiled={} heap=0 maps=0 registry=0", denied, compiled);
}
