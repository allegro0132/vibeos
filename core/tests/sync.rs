//! Fault recovery must never unlock a guard owned by another allocation
//! domain. These tests model the single-hart longjmp boundary on the host.

use vibeos_core::heap::{enter_domain, AllocationDomain, Heap, OwnerId};
use vibeos_core::sync::SpinLock;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tracked_domain() -> AllocationDomain {
    let storage = vec![0u8; 4096].leak();
    let heap = Box::leak(Box::new(Heap::new()));
    let start = storage.as_mut_ptr() as usize;
    unsafe { heap.init(start, start + storage.len()) };
    let owner = OwnerId::new(40_001);
    heap.register_owner(owner, storage.len()).unwrap();
    let arena = heap.create_arena(owner).unwrap();
    AllocationDomain::new(owner, arena)
}

#[test]
fn fault_recovery_does_not_unlock_a_system_guard() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let domain = tracked_domain();
    let lock = SpinLock::new(7u64);
    let mut guard = lock.lock();

    assert!(!unsafe { lock.recover_after_fault(domain) });
    *guard = 8;
    drop(guard);

    assert_eq!(*lock.lock(), 8);
}

#[test]
fn fault_recovery_unlocks_only_a_matching_abandoned_guard() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let domain = tracked_domain();
    let lock = SpinLock::new(11u64);
    let mut scope = unsafe { enter_domain(domain) };
    let guard = lock.lock();
    core::mem::forget(guard);
    scope.restore();

    assert!(unsafe { lock.recover_after_fault(domain) });
    assert!(!unsafe { lock.recover_after_fault(domain) });
    assert_eq!(*lock.lock(), 11);
}
