#![cfg(feature = "network-profile")]
use vibeos_core::{arch, net_profile::{self as p, Scope, Stage}};

#[test]
fn nested_scopes_waits_boundaries_and_abandoned_children() {
    arch::set_test_hart_id(0);
    arch::reset_time();
    arch::advance_time(1);
    assert!(!p::start(0, 1000));
    assert!(!p::start(1, 17)); // exactly 100 ms buckets must fit the clock
    assert!(p::start(1, 1000));
    assert!(!p::start(1, 1000));
    let parent = Scope::enter(Stage::Driver);
    arch::advance_time(10);
    let child = Scope::enter(Stage::Rx);
    arch::advance_time(20);
    let wait = p::lock_start();
    arch::advance_time(5);
    p::lock_end_at(wait, true, 0x12340);
    drop(child);
    arch::advance_time(7);
    p::queue("net-inbound", 12, false);
    p::queue("net-inbound", 32, true);
    p::queue("net-inbound", 1, false);
    p::queue("net-outbound", 7, false);
    p::queue("unrelated", 999, true);
    drop(parent);
    let b = p::snapshot(0);
    assert_eq!(b.ticks[Stage::Driver as usize], 17);
    assert_eq!(b.ticks[Stage::Rx as usize], 20);
    assert_eq!(b.wait[Stage::Rx as usize], 5);
    let rows: Vec<_> = (0..=p::LOCK_SLOTS).map(|i| p::lock_snapshot(0, i)).collect();
    let exact = rows.iter().find(|r| r.0 == 0x12340).unwrap();
    assert_eq!(exact.1[Stage::Rx as usize], 5);
    assert_eq!(exact.2[Stage::Rx as usize], 1);
    assert_eq!(b.high, [32, 7]);
    assert_eq!(b.full, [1, 0]);
    assert_eq!(p::snapshot_hart(0).ticks[Stage::Driver as usize], 17);
    assert_eq!(p::snapshot_hart(1).ticks, [0; 8]);
    assert!(p::lock_start().is_none());

    // Model a fault landing pad skipping the inner scope's Drop. The outer
    // executor-owned scope still restores the previous stage, and charges
    // unrecorded child time to its root rather than corrupting the next task.
    let task = Scope::enter(Stage::Application);
    let abandoned = Scope::enter(Stage::Frontend);
    arch::advance_time(10);
    core::mem::forget(abandoned);
    drop(task);
    assert!(p::lock_start().is_none());
    assert_eq!(p::snapshot(0).ticks[Stage::Application as usize], 10);

    let scope = Scope::enter(Stage::Stack);
    for i in 0..=p::LOCK_SLOTS {
        p::lock_end_at(p::lock_start(), true, 0x100000 + 64 * i);
    }
    drop(scope);
    assert!(p::lock_snapshot(0, p::LOCK_SLOTS).2[Stage::Stack as usize] > 0);
    arch::advance_time(900);
    let last = Scope::enter(Stage::Stack);
    arch::advance_time(100);
    drop(last);
    assert_eq!(p::snapshot(9).ticks[Stage::Stack as usize], 48);
    p::queue("net-inbound", 999, true);
    assert_eq!(p::snapshot(9).high, [0, 0]);
    assert!(!p::start(1, 1000));
}
