//! Allocator behaviour. Each test owns its own heap over a private buffer, so
//! these run in parallel and never touch the kernel's global allocator.

use std::alloc::{GlobalAlloc, Layout};

use vibeos_core::heap::Heap;

/// Build a heap over a leaked buffer. Leaking is deliberate: generated pointers
/// must stay valid for the whole test, and the process exits right after.
fn heap_of(bytes: usize) -> &'static Heap {
    let buf = vec![0u8; bytes].leak();
    let start = buf.as_ptr() as usize;
    let h = Box::leak(Box::new(Heap::new()));
    unsafe { h.init(start, start + bytes) };
    h
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

#[test]
fn allocations_are_aligned_and_distinct() {
    let h = heap_of(64 * 1024);
    let l = layout(24, 8);
    let a = unsafe { h.alloc(l) };
    let b = unsafe { h.alloc(l) };
    assert!(!a.is_null() && !b.is_null());
    assert_ne!(a, b);
    assert_eq!(a as usize % 16, 0, "bump allocations are 16-byte aligned");
}

#[test]
fn a_freed_block_is_reused_for_the_same_size_class() {
    let h = heap_of(64 * 1024);
    let l = layout(24, 8); // 32-byte class
    let a = unsafe { h.alloc(l) };
    unsafe { h.dealloc(a, l) };
    let b = unsafe { h.alloc(l) };
    assert_eq!(a, b, "the free list handed the block straight back");
}

#[test]
fn size_classes_do_not_leak_into_each_other() {
    let h = heap_of(64 * 1024);
    let small = layout(16, 8);
    let large = layout(1024, 8);
    let a = unsafe { h.alloc(small) };
    unsafe { h.dealloc(a, small) };
    let b = unsafe { h.alloc(large) };
    assert_ne!(a, b, "a 1 KiB request must not be served from the 16 B list");
}

#[test]
fn every_size_class_round_trips() {
    let h = heap_of(1024 * 1024);
    for shift in 4..=16 {
        let size = 1usize << shift;
        let l = layout(size, 8);
        let p = unsafe { h.alloc(l) };
        assert!(!p.is_null(), "class of {size} B");
        unsafe { h.dealloc(p, l) };
        let q = unsafe { h.alloc(l) };
        assert_eq!(p, q, "class of {size} B recycles");
    }
}

#[test]
fn over_aligned_requests_bypass_the_free_lists() {
    let h = heap_of(64 * 1024);
    let l = layout(32, 64);
    let a = unsafe { h.alloc(l) };
    assert_eq!(a as usize % 64, 0, "requested alignment is honoured");
    unsafe { h.dealloc(a, l) };
    let b = unsafe { h.alloc(l) };
    assert_ne!(a, b, "not recycled -- documented in README known limits");
}

#[test]
fn exhaustion_returns_null_rather_than_wrapping() {
    let h = heap_of(4096);
    let l = layout(1024, 8);
    let mut nulls = 0;
    for _ in 0..16 {
        if unsafe { h.alloc(l) }.is_null() {
            nulls += 1;
        }
    }
    assert!(nulls > 0, "a heap this small must refuse eventually");
}

#[test]
fn a_request_larger_than_the_heap_is_refused() {
    let h = heap_of(4096);
    assert!(unsafe { h.alloc(layout(1 << 20, 8)) }.is_null());
}

#[test]
fn stats_track_live_and_peak() {
    let h = heap_of(64 * 1024);
    let l = layout(64, 8);
    let (live0, _, free0) = h.stats();

    let p = unsafe { h.alloc(l) };
    let (live1, peak1, free1) = h.stats();
    assert!(live1 > live0, "live grew");
    assert!(free1 < free0, "bump region shrank");

    unsafe { h.dealloc(p, l) };
    let (live2, peak2, _) = h.stats();
    assert_eq!(live2, live0, "live returned to baseline");
    assert_eq!(peak2, peak1, "peak is a high-water mark");
}

#[test]
fn recycled_memory_is_usable() {
    let h = heap_of(64 * 1024);
    let l = layout(64, 8);
    let a = unsafe { h.alloc(l) };
    unsafe { std::ptr::write_bytes(a, 0xAB, 64) };
    unsafe { h.dealloc(a, l) };

    let b = unsafe { h.alloc(l) };
    unsafe { std::ptr::write_bytes(b, 0xCD, 64) };
    assert_eq!(unsafe { *b }, 0xCD, "the block is writable after reuse");
}
