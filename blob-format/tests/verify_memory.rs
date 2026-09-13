use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use vibeos_blob_format::{encode_blob, BlobView};

thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}
struct Meter;
fn allocation() {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            let _ = CALLS.try_with(|calls| calls.set(calls.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;

#[test]
fn complete_tree_verification_does_not_allocate() {
    for size in [
        0,
        1,
        4096,
        4097,
        3 * 4096 + 7,
        128 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ] {
        let encoded = encode_blob(7, &vec![0xa5; size]).unwrap();
        let view = BlobView::decode(&encoded).unwrap();
        CALLS.with(|calls| calls.set(0));
        TRACK.with(|track| track.set(true));
        let result = view.verify_all();
        TRACK.with(|track| track.set(false));
        result.unwrap();
        assert_eq!(CALLS.with(Cell::get), 0, "allocated for {size} bytes");
    }
}
