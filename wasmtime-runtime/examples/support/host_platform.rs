//! Host-only implementation of Wasmtime's custom platform API for port tests.
//! This is not the VibeOS platform implementation. Never linked into the kernel.
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! { static TLS: [Cell<*mut u8>; 2] = const { [Cell::new(std::ptr::null_mut()), Cell::new(std::ptr::null_mut())] }; }

#[unsafe(no_mangle)]
extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    TLS.with(|tls| tls[slot].get())
}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_tls_set(slot: usize, value: *mut u8) {
    TLS.with(|tls| tls[slot].set(value));
}

// The custom ABI supplies aligned, initially zero usize storage. The rwlock
// is a real reader/writer lock (bit 63 = writer, low bits = reader count),
// matching the kernel hooks so shared memories behave the same on both.
const WRITER: usize = 1 << (usize::BITS - 1);
unsafe fn acquire(lock: *mut usize) {
    let lock = unsafe { AtomicUsize::from_ptr(lock) };
    while lock
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        std::thread::yield_now();
    }
}
unsafe fn release(lock: *mut usize) {
    unsafe { AtomicUsize::from_ptr(lock) }.store(0, Ordering::Release);
}
unsafe fn read(lock: *mut usize) {
    let lock = unsafe { AtomicUsize::from_ptr(lock) };
    loop {
        let value = lock.load(Ordering::Relaxed);
        if value & WRITER == 0
            && lock
                .compare_exchange_weak(value, value + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            return;
        }
        std::thread::yield_now();
    }
}
unsafe fn read_release(lock: *mut usize) {
    unsafe { AtomicUsize::from_ptr(lock) }.fetch_sub(1, Ordering::Release);
}
unsafe fn write(lock: *mut usize) {
    let lock = unsafe { AtomicUsize::from_ptr(lock) };
    while lock
        .compare_exchange_weak(0, WRITER, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        std::thread::yield_now();
    }
}
unsafe fn write_release(lock: *mut usize) {
    unsafe { AtomicUsize::from_ptr(lock) }.store(0, Ordering::Release);
}
macro_rules! lock_hook {
    ($name:ident, $operation:ident) => {
        #[unsafe(no_mangle)]
        unsafe extern "C" fn $name(lock: *mut usize) {
            unsafe { $operation(lock) };
        }
    };
}
lock_hook!(wasmtime_sync_lock_acquire, acquire);
lock_hook!(wasmtime_sync_lock_release, release);
lock_hook!(wasmtime_sync_rwlock_read, read);
lock_hook!(wasmtime_sync_rwlock_read_release, read_release);
lock_hook!(wasmtime_sync_rwlock_write, write);
lock_hook!(wasmtime_sync_rwlock_write_release, write_release);
#[unsafe(no_mangle)]
extern "C" fn wasmtime_sync_lock_free(_: *mut usize) {}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_sync_rwlock_free(_: *mut usize) {}

fn protection(flags: u32) -> Option<i32> {
    if flags & !7 != 0 || flags & 6 == 6 {
        return None;
    }
    Some(
        (if flags & 1 != 0 { libc::PROT_READ } else { 0 })
            | (if flags & 2 != 0 { libc::PROT_WRITE } else { 0 })
            | (if flags & 4 != 0 { libc::PROT_EXEC } else { 0 }),
    )
}
#[unsafe(no_mangle)]
unsafe extern "C" fn wasmtime_mmap_new(size: usize, flags: u32, ret: &mut *mut u8) -> i32 {
    let Some(prot) = protection(flags) else {
        return libc::EINVAL;
    };
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return libc::ENOMEM;
    }
    add(&MAP_LIVE, &MAP_PEAK, size);
    *ret = ptr.cast();
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn wasmtime_mmap_remap(addr: *mut u8, size: usize, flags: u32) -> i32 {
    let Some(prot) = protection(flags) else {
        return libc::EINVAL;
    };
    let ptr = unsafe {
        libc::mmap(
            addr.cast(),
            size,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        libc::ENOMEM
    } else {
        0
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn wasmtime_munmap(ptr: *mut u8, size: usize) -> i32 {
    if unsafe { libc::munmap(ptr.cast(), size) } == 0 {
        MAP_LIVE.fetch_sub(size, Ordering::Relaxed);
        0
    } else {
        libc::EINVAL
    }
}
#[unsafe(no_mangle)]
unsafe extern "C" fn wasmtime_mprotect(ptr: *mut u8, size: usize, flags: u32) -> i32 {
    let Some(prot) = protection(flags) else {
        return libc::EINVAL;
    };
    if unsafe { libc::mprotect(ptr.cast(), size, prot) } == 0 {
        if flags & 4 != 0 {
            unsafe { flush_icache(ptr, size) };
        }
        0
    } else {
        libc::EINVAL
    }
}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_page_size() -> usize {
    usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap()
}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_memory_image_new(_: *const u8, _: usize, ret: &mut *mut u8) -> i32 {
    *ret = std::ptr::null_mut(); // ABI explicitly permits declining image creation.
    0
}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_memory_image_map_at(_: *mut u8, _: *mut u8, _: usize) -> i32 {
    libc::EINVAL
}
#[unsafe(no_mangle)]
extern "C" fn wasmtime_memory_image_free(_: *mut u8) {}

// The custom virtual-memory API owns instruction-cache synchronization.
unsafe fn flush_icache(ptr: *mut u8, size: usize) {
    #[cfg(target_os = "macos")]
    unsafe {
        unsafe extern "C" {
            fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
        }
        sys_icache_invalidate(ptr.cast(), size);
    }
    #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
    unsafe {
        // Linux RISC-V __NR_arch_specific_syscall + 15.
        assert_eq!(libc::syscall(259, ptr, ptr.add(size), 0usize), 0);
    }
    #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_arch = "riscv64"))))]
    compile_error!("host test adapter needs an instruction-cache implementation for this target");
}

use std::alloc::{GlobalAlloc, Layout, System};
static HEAP_LIVE: AtomicUsize = AtomicUsize::new(0);
static HEAP_PEAK: AtomicUsize = AtomicUsize::new(0);
static MAP_LIVE: AtomicUsize = AtomicUsize::new(0);
static MAP_PEAK: AtomicUsize = AtomicUsize::new(0);
struct MeasuredAllocator;
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;
fn add(live: &AtomicUsize, peak: &AtomicUsize, size: usize) {
    let now = live.fetch_add(size, Ordering::Relaxed) + size;
    peak.fetch_max(now, Ordering::Relaxed);
}
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add(&HEAP_LIVE, &HEAP_PEAK, layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        HEAP_LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}
pub fn memory_counts() -> (usize, usize, usize, usize) {
    (
        HEAP_LIVE.load(Ordering::Relaxed),
        HEAP_PEAK.load(Ordering::Relaxed),
        MAP_LIVE.load(Ordering::Relaxed),
        MAP_PEAK.load(Ordering::Relaxed),
    )
}
