#![cfg(feature = "network-tso-probe")]
use vibeos_core::net_tso_probe as probe;
#[test]
fn only_a_submitted_request_can_complete() {
    assert!(probe::start(probe::Request {
        src_mac: [2, 0, 0, 0, 0, 1], dst_mac: [2, 0, 0, 0, 0, 2],
        src_ip: [192, 168, 77, 10], dst_ip: [192, 168, 77, 1], payload: 32714, mss: 1460,
    }));
    assert!(probe::take().is_some());
    probe::submitted();
    assert_eq!(probe::state(), 6);
    probe::finish(true);
    assert_eq!(probe::state(), 3);
    probe::invalidate();
    assert_eq!(probe::state(), 3);
}
