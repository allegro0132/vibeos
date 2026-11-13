#![cfg(feature = "executor-profile")]

use vibeos_core::{arch, exec};

#[test]
fn execution_timing_excludes_time_outside_executor_turns() {
    arch::set_test_hart_id(0);
    arch::reset_time();
    let task = exec::spawn("timed", async {
        arch::advance_time(7);
        std::future::pending::<()>().await;
    });
    assert!(exec::poll_once());
    let report = exec::task_report().into_iter().find(|r| r.id == task).unwrap();
    assert_eq!((report.polls, report.poll_ticks), (1, 7));
    let (_, ticks, calls) = exec::execution_profile();
    assert_eq!((ticks[0], calls[0]), (7, 1));
    arch::advance_time(1000);
    assert!(!exec::poll_once());
    let (now, ticks, calls) = exec::execution_profile();
    assert_eq!((now, ticks[0], calls[0]), (1007, 7, 2));
    assert!(ticks[1..].iter().all(|ticks| *ticks == 0));
}
