#![cfg(feature = "receive-buffer-exchange")]
//! Audit stable receive storage allocation and reuse under a component context.
//! Host System owns the bytes; this test observes the runtime allocation domain
//! passed to an allocator, rather than pretending to exercise raw reclamation.
use std::num::NonZeroU64;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use vibeos_core::heap::{self, OwnerId};
use vibeos_core::{
    heap::{AllocationDomain, ArenaId},
    sync::TaskRecoveryKey,
};
use vibeos_net_api::receive_ownership::Owner;
use vibeos_net_api::receive_storage::Storage;

thread_local! {
    static RECORD: Cell<bool> = const { Cell::new(false) };
    static SYSTEM_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static COMPONENT_ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
struct Audit;
fn record() {
    if RECORD.try_with(Cell::get).unwrap_or(false) {
        let domain = heap::current_domain();
        if domain.owner == OwnerId::SYSTEM && !domain.arena.is_tracked() {
            SYSTEM_ALLOCATIONS.with(|n| n.set(n.get() + 1));
        } else {
            COMPONENT_ALLOCATIONS.with(|n| n.set(n.get() + 1));
        }
    }
}
unsafe impl GlobalAlloc for Audit {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        record();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        record();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Audit = Audit;

#[test]
fn storage_is_system_owned_and_transfer_operations_do_not_allocate() {
    vibeos_core::arch::set_test_hart_id(0);
    let mut context = heap::enter_owner(OwnerId::new(42002));
    let before = heap::current_domain();
    RECORD.with(|r| r.set(true));
    let pool = Storage::<2>::new_static(64, 64).unwrap();
    RECORD.with(|r| r.set(false));
    assert_eq!(heap::current_domain(), before);
    assert_eq!(COMPONENT_ALLOCATIONS.with(Cell::get), 0);
    assert_eq!(SYSTEM_ALLOCATIONS.with(Cell::get), 3);
    SYSTEM_ALLOCATIONS.with(|n| n.set(0));
    let owner = Owner {
        domain: AllocationDomain::new(OwnerId::new(7), ArenaId::new(1)),
        task: TaskRecoveryKey::new(1).unwrap(),
    };
    let connection = NonZeroU64::new(1).unwrap();
    let mut output = [0; 5];
    RECORD.with(|r| r.set(true));
    for _ in 0..100 {
        let ticket = pool.reserve(owner).unwrap();
        let (pointer, _) = pool.writer_address(ticket, owner).unwrap();
        unsafe {
            std::slice::from_raw_parts_mut(pointer.as_ptr(), 5).copy_from_slice(b"hello");
        }
        unsafe {
            pool.prepare(ticket, owner, connection, 0, 5).unwrap();
        }
        pool.publish(ticket, owner, connection).unwrap();
        assert_eq!(pool.read(ticket, connection, owner, &mut output), Ok(5));
    }
    RECORD.with(|r| r.set(false));
    context.restore();
    assert_eq!(&output, b"hello");
    assert_eq!(SYSTEM_ALLOCATIONS.with(Cell::get), 0);
    assert_eq!(COMPONENT_ALLOCATIONS.with(Cell::get), 0);
}
