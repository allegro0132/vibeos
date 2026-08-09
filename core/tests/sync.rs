//! SpinLock's host evidence covers domain recovery, hart affinity, and real
//! concurrent contention. The guard's compile-fail test lives on its API docs.

use std::sync::Arc;

use vibeos_core::arch;
use vibeos_core::heap::{enter_domain, AllocationDomain, Heap, OwnerId};
use vibeos_core::sync::{enter_task_recovery_context, SpinLock, TaskRecoveryKey};

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
    let lock = SpinLock::new_recoverable(7u64);
    arch::reset_ipi_test_state();
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
    let lock = SpinLock::new_recoverable(11u64);
    let _ = lock.stats();
    arch::reset_ipi_test_state();
    let mut scope = unsafe { enter_domain(domain) };
    let guard = lock.lock();
    core::mem::forget(guard);
    scope.restore();

    assert!(unsafe { lock.recover_after_fault(domain) });
    assert!(!unsafe { lock.recover_after_fault(domain) });
    assert_eq!(lock.stats().fault_recoveries, 1);
    assert_eq!(*lock.lock(), 11);
}

#[test]
fn guard_drop_rejects_a_different_hart_before_unlocking() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    arch::reset_ipi_test_state();
    arch::set_test_hart_id(0);
    let lock = SpinLock::new(19u64);
    let _ = lock.stats();
    let guard = lock.lock();

    arch::set_test_hart_id(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard)));
    arch::set_test_hart_id(0);

    assert!(result.is_err());
    assert_eq!(lock.stats().acquisitions, 1);
}

#[test]
fn concurrent_contender_is_serialized_and_counted_once() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    arch::reset_ipi_test_state();
    let lock = Arc::new(SpinLock::new(0u64));
    let _ = lock.stats();
    let first = lock.lock();

    std::thread::scope(|scope| {
        let contender_lock = Arc::clone(&lock);
        let contender = scope.spawn(move || {
            let mut value = contender_lock.lock();
            *value += 1;
        });

        // Keep the first guard live until the second thread has observed HELD.
        while lock.stats().contended_acquisitions == 0 {
            std::thread::yield_now();
        }
        drop(first);
        contender.join().unwrap();
    });

    let stats = lock.stats();
    assert_eq!(stats.acquisitions, 2);
    assert_eq!(stats.contended_acquisitions, 1);
    assert_eq!(*lock.lock(), 1);
}

#[test]
fn exact_task_recovery_separates_system_domain_tasks() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    arch::reset_ipi_test_state();
    vibeos_core::ipi::reset_test_state();
    arch::set_test_hart_id(0);

    let task_a = TaskRecoveryKey::new(70_001).unwrap();
    let task_b = TaskRecoveryKey::new(70_002).unwrap();
    let lock = SpinLock::new_recoverable(23u64);
    let _ = lock.stats();
    let mut context = enter_task_recovery_context(task_a);
    let guard = lock.lock();
    core::mem::forget(guard);
    context.restore();

    // Domain-wide recovery must reject all untracked domains. A different
    // task sharing SYSTEM cannot claim A's guard, while A's exact key can.
    assert!(!unsafe { lock.recover_after_fault(AllocationDomain::SYSTEM) });
    assert!(!unsafe { lock.recover_after_task_fault(AllocationDomain::SYSTEM, task_b) });
    assert!(unsafe { lock.recover_after_task_fault(AllocationDomain::SYSTEM, task_a) });
    assert_eq!(lock.stats().fault_recoveries, 1);
    assert_eq!(*lock.lock(), 23);
}
