//! Allocator behaviour. Each test owns its own heap over a private buffer, so
//! these run in parallel and never touch the kernel's global allocator.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::{Mutex, MutexGuard};

use vibeos_core::heap::{
    current_domain, current_owner, enter_domain, enter_owner, AllocationDomain, AllocationFailure,
    ArenaError, ArenaId, Heap, OwnerError, OwnerId,
};

// Allocation owner is deliberately a single-hart global. Serialize this test
// binary so an owner-scope test cannot change the provenance seen by another
// local Heap instance running on a host worker thread.
static HEAP_TEST: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    HEAP_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    let _serial = serial();
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
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let l = layout(24, 8); // 32-byte class
    let a = unsafe { h.alloc(l) };
    unsafe { h.dealloc(a, l) };
    let b = unsafe { h.alloc(l) };
    assert_eq!(a, b, "the free list handed the block straight back");
}

#[test]
fn size_classes_do_not_leak_into_each_other() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let small = layout(16, 8);
    let large = layout(1024, 8);
    let a = unsafe { h.alloc(small) };
    unsafe { h.dealloc(a, small) };
    let b = unsafe { h.alloc(large) };
    assert_ne!(
        a, b,
        "a 1 KiB request must not be served from the 16 B list"
    );
}

#[test]
fn every_size_class_round_trips() {
    let _serial = serial();
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
fn over_aligned_requests_are_aligned_and_recycled() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let l = layout(32, 64);
    let a = unsafe { h.alloc(l) };
    assert_eq!(a as usize % 64, 0, "requested alignment is honoured");
    unsafe { h.dealloc(a, l) };
    let b = unsafe { h.alloc(l) };
    assert_eq!(
        a, b,
        "the tagged block retains enough base provenance to recycle"
    );
}

#[test]
fn exhaustion_returns_null_rather_than_wrapping() {
    let _serial = serial();
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
    let _serial = serial();
    let h = heap_of(4096);
    assert!(unsafe { h.alloc(layout(1 << 20, 8)) }.is_null());
}

#[test]
fn stats_track_live_and_peak() {
    let _serial = serial();
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

    let snapshot = h.snapshot();
    assert_eq!(snapshot.live_bytes, live0);
    assert_eq!(snapshot.peak_live_bytes, peak1);
    assert!(
        snapshot.bump_used_bytes > 0,
        "the bump high-water is retained"
    );
    assert_eq!(
        snapshot.bump_used_bytes + snapshot.bump_remaining_bytes,
        free0,
        "the aligned test heap capacity is fully accounted"
    );
}

#[test]
fn recycled_memory_is_usable() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let l = layout(64, 8);
    let a = unsafe { h.alloc(l) };
    unsafe { std::ptr::write_bytes(a, 0xAB, 64) };
    unsafe { h.dealloc(a, l) };

    let b = unsafe { h.alloc(l) };
    unsafe { std::ptr::write_bytes(b, 0xCD, 64) };
    assert_eq!(unsafe { *b }, 0xCD, "the block is writable after reuse");
}

#[test]
fn owner_scopes_nest_and_support_explicit_restore() {
    let _serial = serial();
    assert_eq!(current_owner(), OwnerId::SYSTEM);
    let first = OwnerId::new(41);
    let second = OwnerId::new(42);

    let mut outer = enter_owner(first);
    assert_eq!(outer.previous(), OwnerId::SYSTEM);
    assert_eq!(current_owner(), first);
    {
        let _inner = enter_owner(second);
        assert_eq!(current_owner(), second);
    }
    assert_eq!(current_owner(), first);

    outer.restore();
    assert_eq!(current_owner(), OwnerId::SYSTEM);
    outer.restore();
    assert_eq!(current_owner(), OwnerId::SYSTEM, "restore is idempotent");
}

#[test]
fn domain_scopes_restore_both_owner_and_arena() {
    let _serial = serial();
    assert_eq!(current_domain(), AllocationDomain::SYSTEM);
    let h = heap_of(64 * 1024);
    let owner = h.create_owner(8192).unwrap();
    let arena = h.create_arena(owner).unwrap();

    let mut outer = unsafe { enter_domain(AllocationDomain::new(owner, arena)) };
    assert_eq!(outer.previous_domain(), AllocationDomain::SYSTEM);
    assert_eq!(current_domain(), AllocationDomain::new(owner, arena));
    {
        let _system = enter_owner(OwnerId::SYSTEM);
        assert_eq!(
            current_domain(),
            AllocationDomain::SYSTEM,
            "legacy owner scopes deliberately clear the tracked arena"
        );
    }
    assert_eq!(current_domain(), AllocationDomain::new(owner, arena));

    outer.restore();
    h.close_empty_arena(arena).unwrap();
    h.unregister_owner(owner).unwrap();
    assert_eq!(current_domain(), AllocationDomain::SYSTEM);
}

#[test]
fn quotas_charge_physical_blocks_and_denial_changes_no_heap_state() {
    let _serial = serial();
    let h = heap_of(1024 * 1024);
    let owner = OwnerId::new(1);
    let l = layout(100, 8);
    let charge = Heap::allocation_charge(l).expect("layout is representable");
    h.register_owner(owner, charge * 2).unwrap();

    let mut scope = enter_owner(owner);
    let a = unsafe { h.alloc(l) };
    let b = unsafe { h.alloc(l) };
    assert!(!a.is_null() && !b.is_null());
    let before = h.stats();
    let denied = unsafe { h.alloc(l) };
    let after = h.stats();
    scope.restore();

    assert!(denied.is_null());
    assert_eq!(
        after, before,
        "denial consumes neither a free block nor bump space"
    );
    let stats = h.account_stats(owner).unwrap();
    assert_eq!(stats.live_bytes, charge * 2);
    assert_eq!(stats.peak_bytes, charge * 2);
    assert_eq!(stats.live_allocations, 2);
    assert_eq!(stats.denials, 1);
    assert_eq!(
        h.last_failure(),
        Some(AllocationFailure::QuotaExceeded {
            owner,
            requested_bytes: charge,
            live_bytes: charge * 2,
            quota_bytes: charge * 2,
        })
    );

    unsafe {
        h.dealloc(a, l);
        h.dealloc(b, l);
    }
    let stats = h.account_stats(owner).unwrap();
    assert_eq!(stats.live_bytes, 0);
    assert_eq!(stats.live_allocations, 0);
    assert_eq!(
        stats.peak_bytes,
        charge * 2,
        "peak remains a high-water mark"
    );
}

#[test]
fn deallocation_uses_header_owner_not_current_owner() {
    let _serial = serial();
    let h = heap_of(1024 * 1024);
    let producer = OwnerId::new(7);
    let consumer = OwnerId::new(8);
    let l = layout(200, 16);
    let charge = Heap::allocation_charge(l).unwrap();
    h.register_owner(producer, charge).unwrap();
    h.register_owner(consumer, charge).unwrap();

    let p = {
        let _scope = enter_owner(producer);
        unsafe { h.alloc(l) }
    };
    assert!(!p.is_null());
    {
        let _scope = enter_owner(consumer);
        unsafe { h.dealloc(p, l) };
    }

    assert_eq!(h.account_stats(producer).unwrap().live_bytes, 0);
    assert_eq!(h.account_stats(producer).unwrap().live_allocations, 0);
    assert_eq!(h.account_stats(consumer).unwrap().live_bytes, 0);

    let q = {
        let _scope = enter_owner(consumer);
        unsafe { h.alloc(l) }
    };
    assert_eq!(
        q, p,
        "the other owner can reuse the returned physical block"
    );
    unsafe { h.dealloc(q, l) };
}

#[test]
fn one_owners_quota_denial_does_not_touch_another_account() {
    let _serial = serial();
    let h = heap_of(1024 * 1024);
    let first = OwnerId::new(10);
    let second = OwnerId::new(11);
    let l = layout(64, 8);
    let charge = Heap::allocation_charge(l).unwrap();
    h.register_owner(first, charge).unwrap();
    h.register_owner(second, charge).unwrap();

    let first_ptr = {
        let _scope = enter_owner(first);
        let p = unsafe { h.alloc(l) };
        assert!(unsafe { h.alloc(l) }.is_null());
        p
    };
    let second_before = h.account_stats(second).unwrap();
    let second_ptr = {
        let _scope = enter_owner(second);
        unsafe { h.alloc(l) }
    };
    assert!(!second_ptr.is_null());
    assert_eq!(second_before.denials, 0);
    assert_eq!(h.account_stats(second).unwrap().live_bytes, charge);
    assert_eq!(h.account_stats(second).unwrap().denials, 0);

    unsafe {
        h.dealloc(first_ptr, l);
        h.dealloc(second_ptr, l);
    }
}

#[test]
fn unknown_owner_is_refused_without_falling_back_to_system() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let unknown = OwnerId::new(999);
    let l = layout(16, 8);
    let system_before = h.account_stats(OwnerId::SYSTEM).unwrap();
    let p = {
        let _scope = enter_owner(unknown);
        unsafe { h.alloc(l) }
    };

    assert!(p.is_null());
    assert_eq!(
        h.last_failure(),
        Some(AllocationFailure::UnknownOwner { owner: unknown })
    );
    assert_eq!(h.account_stats(OwnerId::SYSTEM).unwrap(), system_before);
}

#[test]
fn physical_exhaustion_has_a_distinct_failure_reason() {
    let _serial = serial();
    let h = heap_of(4096);
    let l = layout(4096, 8);
    let charge = Heap::allocation_charge(l).unwrap();
    assert!(unsafe { h.alloc(l) }.is_null());
    assert_eq!(
        h.take_last_failure(),
        Some(AllocationFailure::HeapExhausted {
            owner: OwnerId::SYSTEM,
            requested_bytes: charge,
        })
    );
    assert_eq!(h.last_failure(), None, "take consumes the diagnostic");
}

#[test]
fn a_successful_allocation_clears_a_stale_failure() {
    let _serial = serial();
    let h = heap_of(4096);
    let too_large = layout(4096, 8);
    assert!(unsafe { h.alloc(too_large) }.is_null());
    assert!(h.last_failure().is_some());

    let small = layout(16, 8);
    let p = unsafe { h.alloc(small) };
    assert!(!p.is_null());
    assert_eq!(h.last_failure(), None);
    unsafe { h.dealloc(p, small) };
}

#[test]
fn allocations_larger_than_the_old_64k_limit_are_recycled() {
    let _serial = serial();
    let h = heap_of(2 * 1024 * 1024);
    let l = layout(100 * 1024, 4096);
    let a = unsafe { h.alloc(l) };
    assert!(!a.is_null());
    assert_eq!(a as usize % 4096, 0);
    unsafe { h.dealloc(a, l) };
    let b = unsafe { h.alloc(l) };
    assert_eq!(b, a, "large tagged blocks return to their size class");
    unsafe { h.dealloc(b, l) };
    assert_eq!(h.stats().0, 0);
}

#[test]
fn owner_slots_unregister_only_after_provenance_is_gone() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let owner = h.create_owner(4096).unwrap();
    let l = layout(32, 8);
    let p = {
        let _scope = enter_owner(owner);
        unsafe { h.alloc(l) }
    };

    assert!(matches!(
        h.unregister_owner(owner),
        Err(OwnerError::OwnerBusy {
            live_allocations: 1,
            ..
        })
    ));
    unsafe { h.dealloc(p, l) };
    h.unregister_owner(owner).unwrap();
    assert_eq!(h.account_stats(owner), None);
    h.register_owner(owner, 8192).unwrap();
    assert_eq!(h.account_stats(owner).unwrap().quota_bytes, 8192);
}

#[test]
fn arenas_isolate_incarnations_under_one_owner() {
    let _serial = serial();
    let h = heap_of(128 * 1024);
    let owner = h.create_owner(32 * 1024).unwrap();
    let first = h.create_arena(owner).unwrap();
    let second = h.create_arena(owner).unwrap();
    let l = layout(80, 16);
    let charge = Heap::allocation_charge(l).unwrap();

    let first_ptr = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, first)) };
        unsafe { h.alloc(l) }
    };
    let second_ptr = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, second)) };
        unsafe { h.alloc(l) }
    };
    assert!(!first_ptr.is_null() && !second_ptr.is_null());
    unsafe { second_ptr.write(0xA7) };
    assert_eq!(h.account_stats(owner).unwrap().live_bytes, charge * 2);

    let reclaimed = unsafe { h.reclaim_faulted_arena(first) }.unwrap();
    assert_eq!(reclaimed.reclaimed_bytes, charge);
    assert_eq!(reclaimed.reclaimed_allocations, 1);
    assert_eq!(h.arena_stats(first), None);
    assert_eq!(h.arena_stats(second).unwrap().live_bytes, charge);
    assert_eq!(h.account_stats(owner).unwrap().live_bytes, charge);
    assert_eq!(
        unsafe { second_ptr.read() },
        0xA7,
        "the peer arena survives"
    );

    unsafe { h.dealloc(second_ptr, l) };
    h.close_empty_arena(second).unwrap();
    h.unregister_owner(owner).unwrap();
}

#[test]
fn tracked_deallocation_unlinks_head_middle_and_tail() {
    let _serial = serial();
    let h = heap_of(128 * 1024);
    let owner = h.create_owner(32 * 1024).unwrap();
    let arena = h.create_arena(owner).unwrap();
    let l = layout(48, 16);
    let charge = Heap::allocation_charge(l).unwrap();
    let (a, b, c) = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, arena)) };
        unsafe { (h.alloc(l), h.alloc(l), h.alloc(l)) }
    };

    unsafe { h.dealloc(b, l) };
    assert_eq!(h.arena_stats(arena).unwrap().live_bytes, charge * 2);
    unsafe { h.dealloc(c, l) };
    assert_eq!(h.arena_stats(arena).unwrap().live_allocations, 1);
    unsafe { h.dealloc(a, l) };
    assert_eq!(
        h.arena_stats(arena).unwrap().live_allocations,
        0,
        "all intrusive links were removed"
    );
    h.close_empty_arena(arena).unwrap();
    h.unregister_owner(owner).unwrap();
}

#[test]
fn fault_reclaim_returns_every_block_to_its_size_class() {
    let _serial = serial();
    let h = heap_of(128 * 1024);
    let owner = h.create_owner(32 * 1024).unwrap();
    let arena = h.create_arena(owner).unwrap();
    let l = layout(72, 16);
    let charge = Heap::allocation_charge(l).unwrap();
    let pointers = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, arena)) };
        unsafe { [h.alloc(l), h.alloc(l), h.alloc(l)] }
    };
    assert!(pointers.iter().all(|pointer| !pointer.is_null()));

    let reclaimed = unsafe { h.reclaim_faulted_arena(arena) }.unwrap();
    assert_eq!(reclaimed.reclaimed_bytes, charge * pointers.len());
    assert_eq!(reclaimed.reclaimed_allocations, pointers.len());
    assert_eq!(h.account_stats(owner).unwrap().live_bytes, 0);

    let replacement_arena = h.create_arena(owner).unwrap();
    let replacements = {
        let _scope = unsafe {
            enter_domain(AllocationDomain::new(owner, replacement_arena))
        };
        unsafe { [h.alloc(l), h.alloc(l), h.alloc(l)] }
    };
    for pointer in pointers {
        assert!(
            replacements.contains(&pointer),
            "raw-reclaimed blocks are immediately recyclable"
        );
    }
    for pointer in replacements {
        unsafe { h.dealloc(pointer, l) };
    }
    h.close_empty_arena(replacement_arena).unwrap();
    h.unregister_owner(owner).unwrap();
}

#[test]
fn busy_or_active_arenas_block_close_and_owner_unregister() {
    let _serial = serial();
    let h = heap_of(64 * 1024);
    let owner = h.create_owner(8192).unwrap();
    let arena = h.create_arena(owner).unwrap();
    let l = layout(32, 8);
    let p = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, arena)) };
        unsafe { h.alloc(l) }
    };

    assert!(matches!(
        h.close_empty_arena(arena),
        Err(ArenaError::ArenaBusy {
            live_allocations: 1,
            ..
        })
    ));
    assert!(matches!(
        h.unregister_owner(owner),
        Err(OwnerError::OwnerBusy {
            live_allocations: 1,
            ..
        })
    ));

    unsafe { h.dealloc(p, l) };
    assert_eq!(
        h.unregister_owner(owner),
        Err(OwnerError::ArenasActive { active_arenas: 1 })
    );
    h.close_empty_arena(arena).unwrap();
    h.unregister_owner(owner).unwrap();
}

#[test]
fn arena_reclaim_never_touches_untracked_owner_allocations() {
    let _serial = serial();
    let h = heap_of(128 * 1024);
    let owner = h.create_owner(32 * 1024).unwrap();
    let arena = h.create_arena(owner).unwrap();
    let l = layout(64, 16);
    let charge = Heap::allocation_charge(l).unwrap();
    let untracked = {
        let _scope = enter_owner(owner);
        unsafe { h.alloc(l) }
    };
    let tracked = {
        let _scope = unsafe { enter_domain(AllocationDomain::new(owner, arena)) };
        unsafe { h.alloc(l) }
    };
    unsafe { untracked.write(0x5C) };

    unsafe { h.reclaim_faulted_arena(arena) }.unwrap();
    assert_eq!(h.account_stats(owner).unwrap().live_bytes, charge);
    assert_eq!(unsafe { untracked.read() }, 0x5C);
    assert_eq!(h.arena_stats(ArenaId::UNTRACKED), None);
    assert_eq!(
        unsafe { h.reclaim_faulted_arena(ArenaId::UNTRACKED) },
        Err(ArenaError::UntrackedArenaReserved)
    );

    let _ = tracked; // deliberately dangling after the unsafe reclaim contract
    unsafe { h.dealloc(untracked, l) };
    h.unregister_owner(owner).unwrap();
}
