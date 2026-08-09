//! Allocation-peak regression for the fixed 512-sector M4.2 journal.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibeos_core::durable::{ObjectId, StoreId, TransactionId};
use vibeos_core::store::{
    encode_object_transaction, recover, ObjectKind, RecordBody, RecordChain, RecoveryPolicy,
    CHUNK_DATA_SIZE,
};

struct TrackingAllocator;

static TRACKING: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn add_live(bytes: usize) {
    if !TRACKING.load(Ordering::Relaxed) {
        return;
    }
    let live = CURRENT.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn remove_live(bytes: usize) {
    if TRACKING.load(Ordering::Relaxed) {
        CURRENT.fetch_sub(bytes, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            add_live(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc_zeroed(layout);
        if !pointer.is_null() {
            add_live(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        remove_live(layout.size());
        System.dealloc(pointer, layout);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let replacement = System.realloc(pointer, layout, new_size);
        if !replacement.is_null() && TRACKING.load(Ordering::Relaxed) {
            if new_size >= layout.size() {
                add_live(new_size - layout.size());
            } else {
                remove_live(layout.size() - new_size);
            }
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn begin_tracking() {
    CURRENT.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    TRACKING.store(true, Ordering::SeqCst);
}

fn finish_tracking() -> usize {
    TRACKING.store(false, Ordering::SeqCst);
    PEAK.load(Ordering::Relaxed)
}

#[test]
fn densest_fixed_journal_recovery_stays_within_the_caller_headroom_floor() {
    const CHUNKS: usize = 508;
    const BYTE_LEN: usize = CHUNKS * CHUNK_DATA_SIZE;
    const DYNAMIC_LIMIT: usize = 186 * 1024;

    let store_id = StoreId::new(9_000).unwrap();
    let mut chain = RecordChain::new(store_id);
    let mut sectors = Vec::with_capacity(512);
    sectors.push(chain.append(None, RecordBody::Format).unwrap());
    sectors.push(
        chain
            .append(
                None,
                RecordBody::IdHighWater {
                    exclusive_end: 1_000,
                },
            )
            .unwrap(),
    );
    let content: Vec<_> = (0..BYTE_LEN)
        .map(|index| (index.wrapping_mul(29) ^ (index >> 8)) as u8)
        .collect();
    let transaction = encode_object_transaction(
        &mut chain,
        TransactionId::new(30).unwrap(),
        ObjectId::new(20).unwrap(),
        ObjectKind::new(7).unwrap(),
        &content,
    )
    .unwrap();
    sectors.extend(transaction.records);
    assert_eq!(sectors.len(), 512);

    begin_tracking();
    let recovered = recover(&sectors, RecoveryPolicy { store_id }).unwrap();
    let peak = finish_tracking();

    assert_eq!(recovered.objects[0].bytes, content);
    assert!(
        peak < DYNAMIC_LIMIT,
        "recovery dynamically allocated {peak} bytes; retained decoded chunks or a commit clone likely returned"
    );
    // The kernel's 256-KiB physical scan array lives in fixed `.bss`, while
    // these dynamic recovery allocations are charged to the caller. Keeping
    // the peak below 186 KiB guards the 4-MiB preflight floor against decoded
    // record retention or a second full-content copy.
}
