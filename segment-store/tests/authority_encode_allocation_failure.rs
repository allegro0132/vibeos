//! Keep allocator fault injection isolated from the rest of the storage tests.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use vibeos_durable_format::{RecordBody, RecordChain, StoreId};
use vibeos_segment_store::{encode_persistent_authority_snapshot,
    AuthoritySnapshotError, decode_persistent_authority_snapshot};

struct FaultAllocator;
thread_local! {
    static REMAINING: Cell<usize> = const { Cell::new(0) };
    static DENIED: Cell<bool> = const { Cell::new(false) };
}
fn deny() -> bool {
    REMAINING.try_with(|remaining| {
        let count = remaining.get();
        if count == 0 { return false; }
        remaining.set(count - 1);
        if count == 1 {
            DENIED.with(|denied| denied.set(true));
            true
        } else { false }
    }).unwrap_or(false)
}
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if deny() { std::ptr::null_mut() } else { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if deny() { std::ptr::null_mut() } else { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn snapshot_output_allocation_failure_returns_memory_limit() {
    let records = RecordChain::new(StoreId::new(7).unwrap())
        .append(None, RecordBody::Format).unwrap().to_vec();
    // Build a canonical empty-authority fixture independently of the encoder.
    let mut expected = vec![0; 128];
    expected[..8].copy_from_slice(b"VIBEAUT2");
    expected[8..10].copy_from_slice(&2u16.to_le_bytes());
    expected[10..12].copy_from_slice(&128u16.to_le_bytes());
    expected[16..24].copy_from_slice(&1u64.to_le_bytes());
    expected[24..56].fill(1);
    for (offset, value) in [(0x40, 1u32), (0x44, 48), (0x48, 64),
        (0x4c, 512), (0x74, 32)] {
        expected[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, value) in [(0x50, 128u64), (0x58, 128), (0x60, 128),
        (0x68, 640), (0x78, 128)] {
        expected[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    expected.extend_from_slice(&records);
    let snapshot = decode_persistent_authority_snapshot(&expected).unwrap();
    assert_eq!(encode_persistent_authority_snapshot(&snapshot).unwrap(), expected);
    DENIED.with(|value| value.set(false));
    REMAINING.with(|value| value.set(1));
    let result = encode_persistent_authority_snapshot(&snapshot);
    REMAINING.with(|value| value.set(0));
    assert!(DENIED.with(Cell::get));
    assert_eq!(result, Err(AuthoritySnapshotError::MemoryLimit));
    assert_eq!(encode_persistent_authority_snapshot(&snapshot).unwrap(), expected);
}
