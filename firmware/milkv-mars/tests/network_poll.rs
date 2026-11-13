#[path = "../../../kernel/src/network_poll.rs"]
mod network_poll;
#[test]
fn first_poll_and_elapsed_time_do_not_depend_on_number_of_busy_turns() {
    let mut last = None;
    assert!(network_poll::due(&mut last, 77, 4_000_000));
    for _ in 0..10_000 {
        assert!(!network_poll::due(&mut last, 78, 4_000_000));
    }
    assert!(!network_poll::due(&mut last, 4_000_076, 4_000_000));
    assert!(network_poll::due(&mut last, 4_000_077, 4_000_000));
    assert!(!network_poll::due(&mut last, 4_000_077, 4_000_000));
}
#[test]
fn counter_wrap_preserves_the_cadence() {
    let mut last = Some(u64::MAX - 4);
    assert!(!network_poll::due(&mut last, 3, 10));
    assert!(network_poll::due(&mut last, 5, 10));
}
