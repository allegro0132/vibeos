#![cfg(feature = "network-tso-probe")]
use vibeos_core::net_tso_probe as probe;
#[test]
fn restart_cannot_turn_an_unsubmitted_request_into_success() {
    assert!(probe::start(probe::Request {
        src_mac: [2, 0, 0, 0, 0, 1], dst_mac: [2, 0, 0, 0, 0, 2],
        src_ip: [192, 168, 77, 10], dst_ip: [192, 168, 77, 1], payload: 32714, mss: 1460,
    }));
    assert!(probe::take().is_some());
    probe::finish(true); // An idle ring cannot prove this request was submitted.
    assert_eq!(probe::state(), 2);
    probe::invalidate(); // New driver incarnation after an allocation panic.
    probe::submitted();
    probe::finish(true);
    assert_eq!(probe::state(), 4);
}
