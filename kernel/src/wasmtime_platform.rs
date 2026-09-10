//! Experimental Wasmtime platform bridge, enabled only in the native test image.
//! Code images use the dedicated pool; guest memory uses a bounded creator.
#[cfg(feature = "wasmtime-guarded-memory")]
#[path = "wasmtime_guarded_memory.rs"]
mod guarded_memory;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_code_registry.rs"]
mod code_registry;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_call_recovery.rs"]
pub(crate) mod call_recovery;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_async_call.rs"]
pub(crate) mod async_call;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_fiber_stack.rs"]
mod fiber_stack;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_command_io.rs"]
mod command_io;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_streams_probe.rs"]
mod streams_probe;
#[cfg(feature = "wasmtime-async")]
#[path = "wasmtime_async_probe.rs"]
mod async_probe;
#[path = "wasmtime_wasi_probe.rs"]
mod wasi_probe;
#[cfg(feature = "wasmtime-hardware-traps")]
#[path = "wasmtime_native_traps.rs"]
pub(crate) mod native_traps;
#[cfg(feature = "wasmtime-coremark-probe")]
#[path = "wasmtime_coremark_probe.rs"]
mod coremark_probe;
#[cfg(feature = "wasmtime-threads")]
#[path = "wasmtime_thread_hooks.rs"]
pub(crate) mod thread_hooks;
#[cfg(feature = "wasmtime-threads")]
#[path = "wasmtime_threads_probe.rs"]
mod threads_probe;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use crate::code_pool::{CodeImage, WritableCode};
use crate::sync::SpinLock;
const PAGE: usize = 4096;
const INVALID: i32 = 22;
const BUSY: i32 = 16;
const NOMEM: i32 = 12;
enum Image { Writable(WritableCode), Frozen(CodeImage) }
struct Mapping { base: usize, len: usize, image: Option<Image>, domain: vibeos_core::heap::AllocationDomain }
static MAPS: SpinLock<[Option<Mapping>; 16]> = SpinLock::new([const { None }; 16]);
static TLS: [[AtomicPtr<u8>; 2]; crate::exec::MAX_HARTS] =
    [const { [const { AtomicPtr::new(core::ptr::null_mut()) }; 2] }; crate::exec::MAX_HARTS];
pub(crate) fn hart() -> usize { crate::ipi::current_logical_hart().expect("Wasmtime needs a registered hart").index() }
#[no_mangle]
extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 { TLS[hart()][slot].load(Ordering::Relaxed) }
#[no_mangle]
extern "C" fn wasmtime_tls_set(slot: usize, ptr: *mut u8) { TLS[hart()][slot].store(ptr, Ordering::Relaxed); }
// Wasmtime never holds these locks across a fiber suspension, so a holder is
// always running on some hart. Guest threads of one command may contend from
// several harts. The wait is bounded by wall time, not iterations: a holder
// may legitimately zero up to 16 MiB and shoot down every hart's TLB under the
// shared-memory write lock, which takes far longer under TCG than any
// iteration count would suggest. A holder that faulted is detected through
// its domain teardown instead; exceeding the time bound means an invariant
// broke, and the panic becomes a recoverable task fault rather than a
// silently hung hart.
const SPIN_SECS: u64 = 60;
const WRITER: usize = 1 << (usize::BITS - 1);
struct Spin { iterations: usize, started: u64 }
impl Spin {
    const fn new() -> Self { Self { iterations: 0, started: 0 } }
    fn once(&mut self) {
        core::hint::spin_loop();
        self.iterations += 1;
        if self.iterations % 4096 != 0 { return; }
        // A sibling on another hart faulted: the holder will never run again, so
        // fault this thread too and let the domain teardown collect it.
        if crate::exec::current_domain_tearing_down() {
            panic!("wasmtime sync hook abandoned by a torn-down guest thread");
        }
        let now = crate::sbi::time();
        if self.started == 0 {
            self.started = now.max(1);
        } else if now.saturating_sub(self.started) > SPIN_SECS.saturating_mul(crate::exec::timebase_hz()) {
            panic!("wasmtime sync hook exceeded its {SPIN_SECS} s wait bound");
        }
    }
}
unsafe fn lock(ptr: *mut usize) {
    let value = unsafe { AtomicUsize::from_ptr(ptr) };
    let mut spin = Spin::new();
    while value.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() { spin.once(); }
}
unsafe fn unlock(ptr: *mut usize) { unsafe { AtomicUsize::from_ptr(ptr) }.store(0, Ordering::Release); }
// Reader/writer word: bit 63 marks the writer, the low bits count readers.
unsafe fn read(ptr: *mut usize) {
    let value = unsafe { AtomicUsize::from_ptr(ptr) };
    let mut spin = Spin::new();
    loop {
        let current = value.load(Ordering::Relaxed);
        if current & WRITER == 0
            && value.compare_exchange_weak(current, current + 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
        { return; }
        spin.once();
    }
}
unsafe fn read_release(ptr: *mut usize) { unsafe { AtomicUsize::from_ptr(ptr) }.fetch_sub(1, Ordering::Release); }
unsafe fn write(ptr: *mut usize) {
    let value = unsafe { AtomicUsize::from_ptr(ptr) };
    let mut spin = Spin::new();
    while value.compare_exchange_weak(0, WRITER, Ordering::Acquire, Ordering::Relaxed).is_err() { spin.once(); }
}
unsafe fn write_release(ptr: *mut usize) { unsafe { AtomicUsize::from_ptr(ptr) }.store(0, Ordering::Release); }
macro_rules! sync_hook { ($name:ident, $f:ident) => { #[no_mangle] unsafe extern "C" fn $name(ptr: *mut usize) { unsafe { $f(ptr) }; } }; }
sync_hook!(wasmtime_sync_lock_acquire, lock);
sync_hook!(wasmtime_sync_lock_release, unlock);
sync_hook!(wasmtime_sync_rwlock_read, read);
sync_hook!(wasmtime_sync_rwlock_read_release, read_release);
sync_hook!(wasmtime_sync_rwlock_write, write);
sync_hook!(wasmtime_sync_rwlock_write_release, write_release);
#[no_mangle]
extern "C" fn wasmtime_sync_lock_free(_: *mut usize) {}
#[no_mangle]
extern "C" fn wasmtime_sync_rwlock_free(_: *mut usize) {}
#[no_mangle]
extern "C" fn wasmtime_page_size() -> usize { PAGE }
#[no_mangle]
unsafe extern "C" fn wasmtime_mmap_new(size: usize, flags: u32, ret: &mut *mut u8) -> i32 {
    if size == 0 || size % PAGE != 0 || flags != 3 { return INVALID; }
    let Ok(code) = WritableCode::allocate(size / 4) else { return NOMEM; };
    let base = code.start();
    let mut maps = MAPS.lock();
    let Some(slot) = maps.iter_mut().find(|entry| entry.is_none()) else {
        drop(maps); drop(code); return NOMEM;
    };
    *slot = Some(Mapping { base, len: size, image: Some(Image::Writable(code)), domain: vibeos_core::heap::current_domain() });
    *ret = base as *mut u8;
    0
}
#[no_mangle]
unsafe extern "C" fn wasmtime_mprotect(ptr: *mut u8, len: usize, flags: u32) -> i32 {
    let base = ptr as usize;
    if len == 0 || base % PAGE != 0 { return INVALID; }
    // Like page protection APIs, cover the final partial page of an image.
    let Some(rounded) = len.checked_add(PAGE - 1) else { return INVALID; };
    let len = rounded / PAGE * PAGE;
    let Some(end) = base.checked_add(len) else { return INVALID; };
    let (index, offset, full, image) = {
        let mut maps = MAPS.lock();
        let Some((index, mapping)) = maps.iter_mut().enumerate().filter_map(|(i,m)| m.as_mut().map(|m|(i,m)))
            .find(|(_,m)| base >= m.base && end <= m.base + m.len) else { return INVALID; };
        let Some(image) = mapping.image.take() else { return BUSY; };
        (index, base-mapping.base, base==mapping.base && len==mapping.len, image)
    };
    // Never hold MAPS across cross-hart PTE/TLB synchronization.
    let (image, result) = match image {
        Image::Writable(code) if flags == 1 && full => (Image::Frozen(code.freeze_image()), 0),
        Image::Frozen(mut code) if flags == 5 => {
            let result = if code.publish_text(offset, len).is_ok() { 0 } else { INVALID };
            (Image::Frozen(code), result)
        }
        image => {
            crate::println!("Wasmtime protection unsupported: offset={offset} len={len} flags={flags} full={full}");
            (image, INVALID)
        },
    };
    MAPS.lock()[index].as_mut().expect("busy mapping retains its slot").image = Some(image);
    result
}
#[no_mangle]
unsafe extern "C" fn wasmtime_munmap(ptr: *mut u8, len: usize) -> i32 {
    let mapping = {
        let mut maps = MAPS.lock();
        let Some(slot) = maps.iter_mut().find(|m| m.as_ref().is_some_and(|m| m.base == ptr as usize && m.len == len)) else { return INVALID; };
        if slot.as_ref().unwrap().image.is_none() { return BUSY; }
        slot.take().unwrap()
    };
    drop(mapping); 0
}
#[no_mangle]
extern "C" fn wasmtime_mmap_remap(_: *mut u8, _: usize, _: u32) -> i32 { 38 }
#[no_mangle]
extern "C" fn wasmtime_memory_image_new(_: *const u8, _: usize, ret: &mut *mut u8) -> i32 { *ret = core::ptr::null_mut(); 0 }
#[no_mangle]
extern "C" fn wasmtime_memory_image_map_at(_: *mut u8, _: *mut u8, _: usize) -> i32 { INVALID }
#[no_mangle]
extern "C" fn wasmtime_memory_image_free(_: *mut u8) {}

// Only the boot hart publishes these before starting any secondary hart.
static BOOT_ISA: AtomicUsize = AtomicUsize::new(0);

/// Read the firmware DTB before the heap reuses its storage. No slices escape.
///
/// Safety: `dtb` is OpenSBI's initialized, immutable boot blob when nonzero;
/// the caller has not yet initialized the heap covering [heap_start,heap_end)
/// or enabled Sv39. The firmware pointer must name readable physical RAM;
/// allocator bounds are not the size of the RAM configured in QEMU.
pub unsafe fn capture_boot_isa(dtb: usize, heap_start: usize, heap_end: usize) -> usize {
    use vibeos_wasmtime_runtime::riscv_isa::Features;
    // The QEMU benchmark uses 1 GiB, placing its DTB near 0xc0000000, while
    // the linker deliberately caps the kernel heap at 128 MiB. Capture before
    // paging, using the supported board RAM envelope rather than rejecting a
    // valid firmware blob simply because it lies outside our allocator.
    #[cfg(feature = "qemu-virt")]
    let firmware_end = heap_end.max(0xc000_0000);
    #[cfg(not(feature = "qemu-virt"))]
    let firmware_end = heap_end;
    let detected = (|| {
        if dtb % 8 != 0 || dtb < heap_start || dtb.checked_add(40)? > firmware_end { return None; }
        // The firmware supplies readable physical memory; the checks constrain
        // its address/size envelope. No guest pointer is admitted here.
        let header = unsafe { core::slice::from_raw_parts(dtb as *const u8, 40) };
        let size = u32::from_be_bytes(header[4..8].try_into().ok()?) as usize;
        if !(40..=1024*1024).contains(&size) || dtb.checked_add(size)? > firmware_end { return None; }
        let mut harts = [0u64; crate::exec::MAX_HARTS];
        let mut count = 0;
        let boot = crate::sbi::current_hart_id();
        if !crate::platform::HART_IDS.contains(&boot) { return None; }
        for &hart in crate::platform::HART_IDS {
            if hart != boot {
                match crate::sbi::hart_status(hart) {
                    Ok(crate::sbi::HartState::Stopped) => (),
                    Err(crate::sbi::IpiError::InvalidParam) => continue,
                    _ => return None,
                }
            }
            *harts.get_mut(count)? = hart as u64; count += 1;
        }
        let bytes = unsafe { core::slice::from_raw_parts(dtb as *const u8, size) };
        Some((vibeos_wasmtime_runtime::riscv_isa::common(bytes, &harts[..count])?,count))
    })();
    let (features, harts) = detected.unwrap_or((Features::NONE,0));
    BOOT_ISA.store(features.bits() as usize, Ordering::Release);
    harts
}
pub fn report_boot_isa(harts: usize) {
    crate::println!("  Wasmtime ISA firmware_harts={} extra_mask={:#x}", harts, BOOT_ISA.load(Ordering::Acquire));
}

pub(crate) fn configuration() -> vibeos_wasmtime_runtime::Config {
    let mut config = vibeos_wasmtime_runtime::configuration();
    #[cfg(feature = "wasmtime-hardware-traps")]
    config.signals_based_traps(true);
    #[cfg(feature = "wasmtime-guarded-memory")]
    guarded_memory::configure(&mut config);
    #[cfg(feature = "wasmtime-async")]
    fiber_stack::configure(&mut config);
    let features = vibeos_wasmtime_runtime::riscv_isa::Features::from_bits(BOOT_ISA.load(Ordering::Acquire) as u8);
    // SAFETY: only boot firmware, intersected across every HSM-discovered hart
    // that this kernel can start, supplied BOOT_ISA. Guests cannot modify it.
    // Current TCG controls favor GC. Keep broader instruction selection opt-in
    // until the target-specific benchmark demonstrates a benefit.
    if cfg!(feature = "wasmtime-discovered-isa") {
        unsafe { features.configure(&mut config); }
    }
    config
}

/// The threads configuration: shared memory, atomics, and waits that suspend
/// the guest thread's fiber through the kernel executor.
#[cfg(feature = "wasmtime-threads")]
pub(crate) fn configuration_threads() -> vibeos_wasmtime_runtime::Config {
    let mut config = configuration();
    vibeos_wasmtime_runtime::enable_threads(&mut config, alloc::sync::Arc::new(thread_hooks::KernelThreadHooks));
    config
}

/// All synchronous kernel entries restore privileged state after a native trap
/// resumes Wasmtime's handler without returning through the kernel's sret.
pub(super) fn call<P, R, T>(func: &vibeos_wasmtime_runtime::wasmtime::TypedFunc<P, R>, store: &mut vibeos_wasmtime_runtime::Store<T>, args: P)
    -> vibeos_wasmtime_runtime::wasmtime::Result<R>
where P: vibeos_wasmtime_runtime::wasmtime::WasmParams, R: vibeos_wasmtime_runtime::wasmtime::WasmResults {
    #[cfg(feature = "wasmtime-hardware-traps")]
    let _state = native_traps::CallState::enter();
    func.call(store, args)
}

pub fn selftest() -> Result<(), vibeos_wasmtime_runtime::wasmtime::Error> {
    use vibeos_wasmtime_runtime::wasmtime::{Engine, Module, Store, Instance};
    let before = crate::code_pool::stats();
    #[cfg(feature = "wasmtime-async")]
    async_probe::run()?;
    {
        let mut config = configuration();
        config.max_wasm_stack(32 * 1024);
        let engine = Engine::new(&config)?;
        wasi_probe::run(&engine)?;
        #[cfg(feature = "wasmtime-hardware-traps")]
        native_traps::selftest(&engine)?;
        #[cfg(feature = "wasmtime-threads")]
        threads_probe::run()?;
        #[cfg(feature = "wasmtime-coremark-probe")]
        coremark_probe::run()?;
        // Ordinary unmodified core Wasm: (func (export "run") (result i32) i32.const 42).
        let bytes = b"\0asm\x01\0\0\0\x01\x05\x01\x60\0\x01\x7f\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x06\x01\x04\0\x41\x2a\x0b";
        let module = Module::new(&engine, bytes)?;
        let mut store = Store::new(&engine, ());
        store.set_fuel(10_000)?;
        let instance = Instance::new(&mut store, &module, &[])?;
        assert_eq!(call(&instance.get_typed_func::<(), i32>(&mut store, "run")?, &mut store, ())?, 42);
        assert!(store.get_fuel()? < 10_000);
        // Export a one-page memory (maximum three) and a checked i32 load.
        let memory_bytes = b"\0asm\x01\0\0\0\x01\x06\x01\x60\x01\x7f\x01\x7f\x03\x03\x02\0\0\x05\x04\x01\x01\x01\x03\x07\x17\x03\x03run\0\0\x06memory\x02\0\x04grow\0\x01\x0a\x16\x02\x07\0\x20\0\x28\x02\0\x0b\x0c\0\x20\0\x40\0\x1a\x41\0\x28\x02\0\x0b";
        let memory_module = Module::new(&engine, memory_bytes)?;
        let memory_instance = Instance::new(&mut store, &memory_module, &[])?;
        let memory = memory_instance.get_memory(&mut store, "memory").unwrap();
        assert_eq!(memory.size(&store), 1);
        assert!(memory.data(&store).iter().all(|b| *b == 0));
        memory.write(&mut store, 0, &42i32.to_le_bytes())?;
        memory.write(&mut store, 65532, &0x12345678i32.to_le_bytes())?;
        let load = memory_instance.get_typed_func::<i32, i32>(&mut store, "run")?;
        assert_eq!(call(&load, &mut store, 65532)?, 0x12345678);
        let error = call(&load, &mut store, 65533).unwrap_err();
        assert_eq!(error.downcast_ref::<vibeos_wasmtime_runtime::wasmtime::Trap>(),
            Some(&vibeos_wasmtime_runtime::wasmtime::Trap::MemoryOutOfBounds));
        #[cfg(feature = "wasmtime-guarded-memory")]
        {
            guarded_memory::assert_live(65536);
            // A second module cannot acquire the sole guest reservation.
            assert!(Instance::new(&mut store, &memory_module, &[]).is_err());
            for address in [65536, 16 * 1024 * 1024, -1] {
                let error = call(&load, &mut store, address).unwrap_err();
                assert_eq!(error.downcast_ref::<vibeos_wasmtime_runtime::wasmtime::Trap>(),
                    Some(&vibeos_wasmtime_runtime::wasmtime::Trap::MemoryOutOfBounds));
            }
        }
        let base = memory.data_ptr(&store);
        assert_eq!(memory.grow(&mut store, 1)?, 1);
        assert_eq!(base, memory.data_ptr(&store));
        assert!(memory.data(&store)[65536..].iter().all(|b| *b == 0));
        assert_eq!(call(&load, &mut store, 65536)?, 0);
        let grow = memory_instance.get_typed_func::<i32, i32>(&mut store, "grow")?;
        // The load is in the same compiled function after memory.grow. It must
        // use the relocated base rather than a stale cached pointer.
        assert_eq!(call(&grow, &mut store, 1)?, 42);
        assert_eq!(memory.size(&store), 3);
        #[cfg(not(feature = "wasmtime-guarded-memory"))]
        assert_ne!(base, memory.data_ptr(&store));
        #[cfg(feature = "wasmtime-guarded-memory")]
        assert_eq!(base, memory.data_ptr(&store));
        assert_eq!(call(&load, &mut store, 65532)?, 0x12345678);
        assert_eq!(call(&load, &mut store, 131072)?, 0);
        assert!(memory.grow(&mut store, 1).is_err());
        assert_eq!(memory.size(&store), 3);
        #[cfg(feature = "wasmtime-guarded-memory")]
        guarded_memory::assert_live(3 * 65536);
        let loop_bytes = b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x09\x01\x07\0\x03\x40\x0c\0\x0b\x0b";
        let loop_module = Module::new(&engine, loop_bytes)?;
        let loop_instance = Instance::new(&mut store, &loop_module, &[])?;
        store.set_fuel(100)?;
        let error = call(&loop_instance.get_typed_func::<(), ()>(&mut store, "run")?, &mut store, ()).unwrap_err();
        assert_eq!(error.downcast_ref::<vibeos_wasmtime_runtime::wasmtime::Trap>(),
            Some(&vibeos_wasmtime_runtime::wasmtime::Trap::OutOfFuel));
    }
    #[cfg(feature = "wasmtime-hardware-traps")]
    native_traps::report();
    #[cfg(feature = "wasmtime-guarded-memory")]
    guarded_memory::assert_idle();
    #[cfg(feature = "wasmtime-async")]
    { code_registry::assert_idle(); fiber_stack::assert_idle(); }
    assert!(MAPS.lock().iter().all(Option::is_none));
    // Wasmtime 48 encodes its per-thread initialization marker in bit 0 of
    // slot 0. It may persist; no active CallThreadState pointer may persist.
    assert_eq!(TLS[hart()][0].load(Ordering::Relaxed).addr() & !1, 0);
    assert!(TLS[hart()][1].load(Ordering::Relaxed).is_null());
    let after = crate::code_pool::stats();
    assert_eq!(after.live_pages, before.live_pages);
    assert_eq!(after.sealed_pages, before.sealed_pages);
    crate::println!("  WASMTIME NATIVE PASS compiled_in_kernel=1 result=42 fuel_trap=1 memory_grow_bounds=1 maps=0 tls_active=0");
    Ok(())
}

#[cfg(feature = "wasmtime-guarded-memory")]
pub async fn memory_recovery_selftest() { guarded_memory::recovery_selftest().await; }
/// Requires the executor's quiescence witness, before heap arena reclamation.
/// Only guest-memory metadata is repaired here; this is not full runtime recovery.
#[cfg(feature = "wasmtime-guarded-memory")]
pub unsafe fn recover_guest_memory(domain: vibeos_core::heap::AllocationDomain) {
    unsafe { guarded_memory::recover(domain); }
}

/// Only the fixed memory-only fault fixture can register this exact domain.
#[cfg(feature = "wasmtime-guarded-memory")]
pub unsafe fn recover_memory_probe(domain: vibeos_core::heap::AllocationDomain) -> bool {
    unsafe { guarded_memory::recover_probe(domain) }
}

#[cfg(feature = "wasmtime-async")]
pub async fn code_recovery_selftest() { code_registry::recovery_selftest().await; }
#[cfg(feature = "wasmtime-threads")]
pub async fn threads_recovery_selftest() { threads_probe::parallel_recovery_selftest().await; }
#[cfg(feature = "wasmtime-threads")]
pub unsafe fn recover_threads_probe(domain: vibeos_core::heap::AllocationDomain) -> bool {
    unsafe { threads_probe::recover_probe(domain) }
}
#[cfg(feature = "wasmtime-async")]
pub unsafe fn recover_code_probe(domain: vibeos_core::heap::AllocationDomain) -> bool {
    unsafe { code_registry::recover_probe(domain) }
}


/// Shared native platform storage reserved against the sole invocation's 32 MiB
/// total limit: code pool, guest tables, trap stacks/tables, fiber tables and a
/// conservative fixed-record allowance. Heap allocation is charged separately.
pub(crate) fn invocation_heap_budget() -> usize {
    let mut reserved = 2 * 1024 * 1024;
    if cfg!(feature = "wasmtime-guarded-memory") { reserved += 9 * 4096; }
    #[cfg(feature = "wasmtime-async")]
    { reserved += crate::exec::MAX_HARTS * (crate::mmu::NATIVE_TRAP_STACK_SIZE + 2 * 4096) + 2 * 4096 + 16 * 1024; }
    32 * 1024 * 1024 - reserved
}

#[cfg(feature = "wasmtime-command")]
pub(crate) unsafe fn recover_command_graph(domain: vibeos_core::heap::AllocationDomain) {
    unsafe { code_registry::recover_owned_graph(domain); }
}
