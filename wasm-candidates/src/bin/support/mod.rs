#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    ptr::{null_mut, write_volatile},
    sync::atomic::{AtomicUsize, Ordering},
};
#[cfg(target_os = "none")]
use vibeos_wasm_candidates::baseline_contract::PROBE_HEAP_BYTES;

#[allow(dead_code)]
pub const EMPTY_CORE: &[u8] = b"\0asm\x01\0\0\0";

#[cfg(target_os = "none")]
#[repr(align(16))]
pub struct ProbeHeap(UnsafeCell<[u8; PROBE_HEAP_BYTES]>);

#[cfg(target_os = "none")]
unsafe impl Sync for ProbeHeap {}

#[cfg(target_os = "none")]
#[no_mangle]
pub static C0_PROBE_HEAP: ProbeHeap = ProbeHeap(UnsafeCell::new([0; PROBE_HEAP_BYTES]));

#[cfg(target_os = "none")]
struct BumpAllocator {
    next: AtomicUsize,
}

#[cfg(target_os = "none")]
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let mut current = self.next.load(Ordering::Relaxed);
        loop {
            let start = match current.checked_add(align_mask) {
                Some(value) => value & !align_mask,
                None => return null_mut(),
            };
            let end = match start.checked_add(layout.size()) {
                Some(value) if value <= PROBE_HEAP_BYTES => value,
                _ => return null_mut(),
            };
            match self.next.compare_exchange_weak(
                current,
                end,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return C0_PROBE_HEAP.0.get().cast::<u8>().add(start),
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _pointer: *mut u8, _layout: Layout) {}
}

#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator {
    next: AtomicUsize::new(0),
};

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(target_os = "none")]
static mut PROBE_RESULT: usize = 0;

#[cfg(target_os = "none")]
#[no_mangle]
pub static mut C0_PROBE_POINTER: usize = 0;

#[cfg(target_os = "none")]
#[inline(never)]
#[allow(dead_code)]
pub fn escaped_box(value: usize) -> usize {
    let pointer = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(value));
    // SAFETY: the allocation is deliberately retained until the non-returning
    // probe exit, and this is the only writer to the exported observation slot.
    unsafe {
        write_volatile(&raw mut C0_PROBE_POINTER, pointer as usize);
        pointer.read_volatile()
    }
}

#[cfg(target_os = "none")]
pub fn finish(value: usize) -> ! {
    // SAFETY: the single entrypoint is the only writer and never returns.
    unsafe {
        write_volatile(&raw mut PROBE_RESULT, value);
    }
    loop {
        core::hint::spin_loop();
    }
}
