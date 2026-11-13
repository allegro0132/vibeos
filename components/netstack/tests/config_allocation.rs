//! Audit real control-table allocation and growth under a component context.
//! Host System owns the bytes; this test observes the runtime allocation domain
//! passed to an allocator, rather than pretending to exercise raw reclamation.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use vibeos_core::heap::{self, OwnerId};
use vibeos_netstack::{config, NetworkInterfaceId};

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
fn persistent_tables_allocate_and_grow_outside_component_domain() {
    vibeos_core::arch::set_test_hart_id(0);
    let mut owner = heap::enter_owner(OwnerId::new(42001));
    let previous = heap::current_domain();
    RECORD.with(|r| r.set(true));
    let first = config::register_interface(NetworkInterfaceId::FIRST, true);
    let listener = config::register_listener(NetworkInterfaceId::FIRST, 101);
    let grew = config::register_interface(NetworkInterfaceId::new(17), false);
    let another = config::register_listener(NetworkInterfaceId::new(17), 102);
    let restored = heap::current_domain() == previous;
    RECORD.with(|r| r.set(false));
    owner.restore();
    assert!(first && listener && grew && another && restored);
    let system = SYSTEM_ALLOCATIONS.with(Cell::get);
    let component = COMPONENT_ALLOCATIONS.with(Cell::get);
    assert_eq!(
        component, 0,
        "persistent table allocation escaped from the caller domain"
    );
    assert!(
        system >= 4,
        "both initial allocation and growth must be audited"
    );
    assert_eq!(
        config::runtime_status_for_listener(101),
        config::runtime_status_on(NetworkInterfaceId::FIRST)
    );
}
