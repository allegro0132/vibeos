//! Two instances on one shared memory, driven by hand like the async probe:
//! atomics across stores, a wait that suspends its fiber, notify, timeout,
//! and shared growth visible to both. No command service is involved.
use alloc::boxed::Box;
use super::async_call::NativeFuture;
use core::{future::Future, pin::Pin, task::{Context, Poll, Waker}};
use vibeos_wasmtime_runtime::wasmtime::{self, Engine, Linker, Module, SharedMemory, Store, MemoryType};
// (import "env" "memory" (memory 1 4 shared)) with exports add/wait/waitt/notify/grow/size/load/store.
const MODULE: &[u8] = b"\x00\x61\x73\x6d\x01\x00\x00\x00\x01\x0f\x03\x60\x01\x7f\x01\x7f\x60\x00\x01\x7f\x60\x02\x7f\x7f\x00\x02\x10\x01\x03\x65\x6e\x76\x06\x6d\x65\x6d\x6f\x72\x79\x02\x03\x01\x04\x03\x09\x08\x00\x01\x01\x01\x01\x01\x00\x02\x07\x3c\x08\x03\x61\x64\x64\x00\x00\x04\x77\x61\x69\x74\x00\x01\x05\x77\x61\x69\x74\x74\x00\x02\x06\x6e\x6f\x74\x69\x66\x79\x00\x03\x04\x67\x72\x6f\x77\x00\x04\x04\x73\x69\x7a\x65\x00\x05\x04\x6c\x6f\x61\x64\x00\x06\x05\x73\x74\x6f\x72\x65\x00\x07\x0a\x5c\x08\x0a\x00\x41\x00\x20\x00\xfe\x1e\x02\x00\x0b\x0c\x00\x41\x04\x41\x00\x42\x7f\xfe\x01\x02\x00\x0b\x0f\x00\x41\x08\x41\x00\x42\x80\x89\xfa\x00\xfe\x01\x02\x00\x0b\x12\x00\x41\x04\x41\x01\xfe\x17\x02\x00\x41\x04\x41\x01\xfe\x00\x02\x00\x0b\x06\x00\x41\x01\x40\x00\x0b\x04\x00\x3f\x00\x0b\x08\x00\x20\x00\xfe\x10\x02\x00\x0b\x0a\x00\x20\x00\x20\x01\xfe\x17\x02\x00\x0b";
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(NativeFuture::new(future));
    let mut polls = 0;
    loop {
        if let Poll::Ready(value) = poll(future.as_mut()) { return value; }
        polls += 1;
        assert!(polls < 1_000_000, "threads probe future never completed");
    }
}
fn call<P: wasmtime::WasmParams + Sync, R: wasmtime::WasmResults + Sync>(store: &mut Store<()>, instance: &wasmtime::Instance, name: &str, args: P) -> wasmtime::Result<R> {
    let func = instance.get_typed_func::<P, R>(&mut *store, name)?;
    ready(func.call_async(store, args))
}
fn run_inner() -> wasmtime::Result<()> {
    let mut config = super::configuration_threads();
    config.async_stack_size(256 * 1024).max_wasm_stack(32 * 1024);
    let engine = Engine::new(&config)?;
    let module = Module::new(&engine, MODULE)?;
    let memory = SharedMemory::new(&engine, MemoryType::shared(1, 4))?;
    let mut a = Store::new(&engine, ());
    let mut b = Store::new(&engine, ());
    for store in [&mut a, &mut b] {
        store.set_fuel(10_000_000)?;
        store.fuel_async_yield_interval(Some(10_000))?;
    }
    let mut linker = Linker::<()>::new(&engine);
    linker.define(&a, "env", "memory", memory.clone())?;
    let ia = ready(linker.instantiate_async(&mut a, &module))?;
    let ib = ready(linker.instantiate_async(&mut b, &module))?;
    super::guarded_memory::assert_live(65536);
    // Atomics on the same bytes from two stores.
    assert_eq!(call::<i32, i32>(&mut a, &ia, "add", 5)?, 0);
    assert_eq!(call::<i32, i32>(&mut b, &ib, "add", 7)?, 5);
    assert_eq!(call::<i32, i32>(&mut a, &ia, "load", 0)?, 12);
    // A wait suspends its fiber; notify from the other store resumes it.
    let wait = ia.get_typed_func::<(), i32>(&mut a, "wait")?;
    let mut waiting = Box::pin(NativeFuture::new(wait.call_async(&mut a, ())));
    assert!(poll(waiting.as_mut()).is_pending(), "wait must suspend");
    assert!(poll(waiting.as_mut()).is_pending(), "wait must stay suspended");
    assert_eq!(call::<(), i32>(&mut b, &ib, "notify", ())?, 1, "one waiter notified");
    let woken = loop {
        if let Poll::Ready(result) = poll(waiting.as_mut()) { break result?; }
    };
    assert_eq!(woken, 0, "WaitResult::Ok");
    drop(waiting);
    // A bounded wait times out through the executor timer.
    let started = crate::sbi::time();
    assert_eq!(call::<(), i32>(&mut a, &ia, "waitt", ())?, 2, "WaitResult::TimedOut");
    let elapsed = crate::sbi::time() - started;
    assert!(elapsed >= crate::exec::timebase_hz() / 1000, "timeout returned early");
    // Mismatch returns immediately without suspending.
    assert_eq!(call::<(), i32>(&mut b, &ib, "wait", ())?, 1, "WaitResult::Mismatch");
    // Growth from one store is visible in the other and keeps the base.
    assert_eq!(call::<(), i32>(&mut b, &ib, "grow", ())?, 1);
    assert_eq!(call::<(), i32>(&mut a, &ia, "size", ())?, 2);
    call::<(i32, i32), ()>(&mut a, &ia, "store", (65536, 42))?;
    assert_eq!(call::<i32, i32>(&mut b, &ib, "load", 65536)?, 42);
    assert_eq!(memory.size(), 2);
    super::guarded_memory::assert_live(2 * 65536);
    assert!(memory.grow(3).is_err(), "growth beyond the declared maximum fails");
    assert_eq!(memory.grow(2)?, 2);
    assert_eq!(call::<(), i32>(&mut a, &ia, "size", ())?, 4);
    super::guarded_memory::assert_live(4 * 65536);
    drop((ia, ib, a, b, linker, memory, module, engine));
    crate::println!("  WASMTIME THREADS PASS instances=2 wait=1 notify=1 timeout=1 mismatch=1 grow_shared=1 slots={}", crate::mmu::NATIVE_FIBER_SLOTS);
    Ok(())
}
pub(super) fn run() -> wasmtime::Result<()> {
    let owner = crate::HEAP.create_owner(super::invocation_heap_budget()).expect("threads probe owner");
    let scope = vibeos_core::heap::enter_owner(owner);
    let result = run_inner();
    drop(scope);
    let stats = crate::HEAP.account_stats(owner).unwrap();
    if let Err(error) = &result { crate::println!("WASMTIME THREADS ERROR {error:#}"); }
    assert_eq!(stats.live_bytes, 0, "threads probe leaked arena bytes");
    assert_eq!(stats.denials, 0);
    crate::HEAP.unregister_owner(owner).expect("threads owner released");
    super::guarded_memory::assert_idle();
    result
}

// ---- Parallel tracked-domain fault recovery on real harts ----
static SIBLINGS: [crate::sync::SpinLock<Option<crate::exec::TaskHandle>>; 3] =
    [const { crate::sync::SpinLock::new(None) }; 3];
static STARTED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static HARTS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static DROPS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// The fixture's exact domain. It publishes no Engine/Store/TLS or service
/// state, so recovery only reclaims the arena raw.
static PROBE: crate::sync::SpinLock<Option<vibeos_core::heap::AllocationDomain>> = crate::sync::SpinLock::new(None);
static RECOVERED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
pub(super) unsafe fn recover_probe(domain: vibeos_core::heap::AllocationDomain) -> bool {
    if *PROBE.lock() != Some(domain) { return false; }
    RECOVERED.fetch_add(1, core::sync::atomic::Ordering::Release);
    true
}
struct DropProbe;
impl Drop for DropProbe { fn drop(&mut self) { DROPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed); } }
fn hold(ticks: u64) {
    let start = crate::sbi::time();
    while crate::sbi::time().wrapping_sub(start) < ticks { core::hint::spin_loop(); }
}
/// One arena, one primary plus three siblings pinned round-robin on the other
/// harts, all spinning through fuel-quantum-sized polls. The primary faults;
/// every sibling must be collected (queued or mid-poll on its hart), no
/// destructor may run, and the arena must reclaim raw.
pub(super) async fn parallel_recovery_selftest() {
    use core::sync::atomic::Ordering;
    use vibeos_core::heap::AllocationDomain;
    let drops = DROPS.load(Ordering::Relaxed);
    let detaches = crate::exec::parallel_remote_detaches();
    let quantum = crate::exec::timebase_hz() / 10_000;
    for _ in 0..16 {
        let owner = crate::HEAP.create_owner(1024 * 1024).unwrap();
        let arena = crate::HEAP.create_arena(owner).unwrap();
        let domain = AllocationDomain::new(owner, arena);
        STARTED.store(0, Ordering::Relaxed);
        HARTS.store(0, Ordering::Relaxed);
        { let mut probe = PROBE.lock(); assert!(probe.is_none()); *probe = Some(domain); }
        let recovered = RECOVERED.load(Ordering::Acquire);
        let child = unsafe { crate::exec::spawn_reclaimable_owned_parallel(domain, "wasmtime-parallel-fault", async move {
            let _drop = DropProbe;
            for index in 0..3usize {
                // Spread siblings over the other online harts: index 0 takes
                // the next hart, index 1 the one after, and so on.
                let current = crate::ipi::current_logical_hart().unwrap();
                let mut hart = current;
                let mut skip = index;
                for candidate in 1..=crate::exec::MAX_HARTS * 2 {
                    let id = vibeos_core::runqueue::HartId::new((current.index() + candidate) % crate::exec::MAX_HARTS).unwrap();
                    if id != current && crate::ipi::is_online(id) {
                        if skip == 0 { hart = id; break; }
                        skip -= 1;
                    }
                }
                let handle = crate::exec::spawn_sibling_on(hart, "wasmtime-parallel-sibling", async move {
                    let _drop = DropProbe;
                    STARTED.fetch_add(1, Ordering::Release);
                    loop {
                        HARTS.fetch_or(1 << super::hart(), Ordering::Relaxed);
                        hold(quantum);
                        crate::exec::yield_now().await;
                    }
                });
                *SIBLINGS[index].lock() = Some(handle);
            }
            while STARTED.load(Ordering::Acquire) < 3 { crate::exec::yield_now().await; }
            hold(quantum * 4);
            panic!("deliberate parallel arena fault");
        }) };
        assert_eq!(child.join().await.state(), crate::exec::TaskState::Faulted);
        for slot in &SIBLINGS {
            let handle = slot.lock().take().expect("sibling handle published");
            let mut polls = 0usize;
            while handle.state() != crate::exec::TaskState::Faulted {
                polls += 1;
                assert!(polls < 1_000_000, "sibling never reached Faulted");
                crate::exec::yield_now().await;
            }
        }
        assert_eq!(RECOVERED.load(Ordering::Acquire), recovered + 1, "fault reclaim did not reach the probe");
        *PROBE.lock() = None;
        let stats = crate::HEAP.account_stats(owner).unwrap();
        assert_eq!(stats.live_bytes, 0);
        assert_eq!(stats.denials, 0);
        assert!(crate::HEAP.arena_stats(arena).is_none());
        crate::HEAP.unregister_owner(owner).unwrap();
        drop(child);
    }
    assert_eq!(DROPS.load(Ordering::Relaxed), drops, "raw parallel teardown ran a destructor");
    let harts = HARTS.load(Ordering::Relaxed);
    let remote = crate::exec::parallel_remote_detaches() - detaches;
    crate::println!("  WASMTIME PARALLEL RECOVERY PASS cycles=16 siblings=3 drops=0 harts={harts:#x} remote_detaches={remote}");
}
