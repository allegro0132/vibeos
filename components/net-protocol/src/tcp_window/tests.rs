use super::*;
fn seg(seq: u32, ack: u32, window: u16, flags: u8, payload: usize) -> Segment {
    Segment {
        seq,
        ack,
        window,
        flags,
        payload,
        scale: None,
    }
}
fn handshake(
    client: u32,
    server: u32,
    cw: u16,
    sw: u16,
    cs: Option<u8>,
    ss: Option<u8>,
) -> Tracker {
    let mut syn = seg(client, 0, cw, 2, 0);
    syn.scale = cs;
    let t = Tracker::advance(None, true, syn).unwrap();
    let mut synack = seg(server, client.wrapping_add(1), sw, 0x12, 0);
    synack.scale = ss;
    let t = Tracker::advance(Some(t), false, synack).unwrap();
    Tracker::advance(
        Some(t),
        true,
        seg(client.wrapping_add(1), server.wrapping_add(1), cw, 0x10, 0),
    )
    .unwrap()
}
#[test]
fn data_ack_bounds_and_no_mutation_on_failure() {
    let t = handshake(1000, 9000, 4, 8, None, None);
    let t = Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 2)).unwrap();
    assert!(Tracker::advance(Some(t), false, seg(9001, 1004, 8, 0x10, 0)).is_err());
    assert!(Tracker::advance(Some(t), true, seg(1009, 9001, 4, 0x18, 1)).is_err());
    assert!(Tracker::advance(Some(t), true, seg(1008, 9001, 4, 0x18, 2)).is_err());
    let t = Tracker::advance(Some(t), false, seg(9001, 1003, 8, 0x10, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1010, 9001, 4, 0x18, 1)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1011, 9001, 4, 0x18, 1)).is_err());
}
#[test]
fn reordering_retransmission_and_old_window_updates() {
    let t = handshake(1000, 9000, 4, 8, None, None);
    let t = Tracker::advance(Some(t), true, seg(1005, 9001, 4, 0x18, 2)).unwrap();
    let t = Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 4)).unwrap();
    assert_eq!(t.sides[0].unwrap().end, 1007);
    let t = Tracker::advance(Some(t), false, seg(9001, 1007, 8, 0x10, 0)).unwrap();
    let saved = t.sides[0].unwrap();
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 65535, 0x10, 0)).unwrap();
    assert_eq!(t.sides[0].unwrap(), saved); // stale ACK cannot reopen a huge window
    assert!(Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 4)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(9900, 9001, 4, 0x18, 1)).is_err());
}
#[test]
fn window_shrink_retains_previous_grant_for_in_flight_data() {
    let t = handshake(1000, 9000, 4, 8, None, None);
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 1, 0x10, 0)).unwrap();
    assert_eq!(t.sides[0].unwrap().limit, 1009);
    assert!(Tracker::advance(Some(t), true, seg(1008, 9001, 4, 0x18, 1)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1010, 9001, 4, 0x18, 1)).is_err());
}
#[test]
fn zero_window_probes_and_keepalives_are_bounded() {
    let t = handshake(1000, 9000, 4, 0, None, None);
    assert!(Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 2)).is_err());
    assert!(Tracker::advance(Some(t), true, seg(1002, 9001, 4, 0x18, 1)).is_err());
    let t = Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 1)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1000, 9001, 4, 0x10, 0)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1000, 9001, 4, 0x18, 1)).is_ok());
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 0, 0x10, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 1)).is_ok());
}
#[test]
fn scaling_requires_both_offers_and_never_scales_syn_window() {
    let t = handshake(1000, 9000, 2, 2, Some(8), Some(5));
    assert!(Tracker::advance(Some(t), true, seg(1003, 9001, 2, 0x18, 1)).is_err());
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 2, 0x10, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1064, 9001, 2, 0x18, 1)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1065, 9001, 2, 0x18, 1)).is_err());
    let t = handshake(1000, 9000, 2, 2, Some(8), None);
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 2, 0x10, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1064, 9001, 2, 0x18, 1)).is_err());
    let t = handshake(1000, 9000, 65535, 65535, Some(14), Some(14));
    let t = Tracker::advance(Some(t), false, seg(9001, 1001, 65535, 0x10, 0)).unwrap();
    let limit = 1001 + (65535u32 << 14);
    assert!(Tracker::advance(Some(t), true, seg(limit - 1, 9001, 65535, 0x18, 1)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(limit, 9001, 65535, 0x18, 1)).is_err());
}
#[test]
fn sequence_wrap_and_half_space_ambiguity() {
    let c = u32::MAX - 2;
    let s = u32::MAX - 4;
    let t = handshake(c, s, 16, 16, None, None);
    let t = Tracker::advance(Some(t), true, seg(c + 1, s + 1, 16, 0x18, 4)).unwrap();
    assert_eq!(t.sides[0].unwrap().end, 2);
    let t = Tracker::advance(Some(t), false, seg(s + 1, 2, 16, 0x10, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(2, s + 1, 16, 0x18, 4)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(0x80000002, s + 1, 16, 0x10, 0)).is_err());
}
#[test]
fn rst_requires_observed_boundary_and_fin_cannot_move_backwards() {
    let t = handshake(1000, 9000, 4, 8, None, None);
    let t = Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x18, 4)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1003, 9001, 4, 0x14, 0)).is_err());
    assert!(Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x14, 0)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1005, 9001, 4, 0x14, 0)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1001, 9001, 4, 0x11, 0)).is_err());
    let t = Tracker::advance(Some(t), true, seg(1005, 9001, 4, 0x11, 0)).unwrap();
    assert!(Tracker::advance(Some(t), true, seg(1005, 9001, 4, 0x11, 0)).is_ok());
    assert!(Tracker::advance(Some(t), true, seg(1006, 9001, 4, 0x11, 0)).is_err());
    assert!(Tracker::advance(Some(t), true, seg(1006, 9001, 4, 0x18, 1)).is_err());
}
