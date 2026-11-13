use super::*;
const MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 1];
const PEER: [u8; 6] = [2, 3, 4, 5, 6, 7];
const IP: [u8; 4] = [192, 168, 78, 1];
const NEXT: [u8; 4] = [192, 168, 78, 2];
const OTHER: [u8; 4] = [192, 168, 78, 3];
fn interface() -> Interface {
    Interface {
        mac: MAC,
        ip: IP,
        prefix: 24,
        gateway: Some(NEXT),
    }
}
fn reply() -> [u8; 42] {
    let mut f = [0; 42];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER);
    f[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    f[22..28].copy_from_slice(&PEER);
    f[28..32].copy_from_slice(&NEXT);
    f[32..38].copy_from_slice(&MAC);
    f[38..42].copy_from_slice(&IP);
    f
}
fn request() -> [u8; 42] {
    let mut f = reply();
    f[..6].fill(0xff);
    f[21] = 1;
    f[32..38].fill(0);
    f
}
fn transmit<const N: usize>(t: &mut Table<N>, now: u64) -> [u8; 42] {
    let p = t.probe(now).unwrap().unwrap();
    let f = p.frame();
    p.sent();
    f
}

#[test]
fn connected_default_and_invalid_routes() {
    let c = interface();
    assert_eq!(c.next_hop(OTHER), Ok(OTHER));
    assert_eq!(c.next_hop([8, 8, 8, 8]), Ok(NEXT));
    assert_eq!(c.next_hop(IP), Err(Error::Local));
    for ip in [
        [0, 1, 2, 3],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [255; 4],
        [192, 168, 78, 0],
        [192, 168, 78, 255],
    ] {
        assert_eq!(c.next_hop(ip), Err(Error::Address));
    }
    let mut c = c;
    c.gateway = None;
    assert_eq!(c.next_hop([8, 8, 8, 8]), Err(Error::NoRoute));
    for prefix in [0, 31, 32, 255] {
        c.prefix = prefix;
        assert!(Table::<4>::new(c).is_err());
        assert_eq!(c.next_hop(NEXT), Err(Error::Configuration));
    }
    c = interface();
    c.gateway = Some(IP);
    assert!(Table::<4>::new(c).is_err());
    c.gateway = Some([8, 8, 8, 8]);
    assert!(Table::<4>::new(c).is_err());
    c = interface();
    c.mac[0] = 1;
    assert!(Table::<4>::new(c).is_err());
    assert!(Table::<0>::new(interface()).is_err());
}

#[test]
fn real_request_reply_resolution_expiry_and_no_payload_learning() {
    let mut t = Table::<8>::new(interface()).unwrap();
    assert_eq!(t.resolve(NEXT, 0), Ok(Resolution::Pending));
    let mut request = transmit(&mut t, 0);
    assert_eq!(&request[..6], &[255; 6]);
    assert_eq!(&request[6..12], &MAC);
    assert_eq!(&request[28..32], &IP);
    assert_eq!(&request[32..38], &[0; 6]);
    assert_eq!(&request[38..42], &NEXT);
    assert_eq!(
        crate::arp::reply_in_place(&mut request, PEER, NEXT),
        Some(42)
    );
    assert_eq!(request, reply());
    assert_eq!(t.observe(&request, 1), Ok(true));
    assert_eq!(t.resolve(NEXT, 2), Ok(Resolution::Reachable(PEER)));
    assert_eq!(t.next_deadline(2), Ok(None));
    assert!(t.probe(2).unwrap().is_none());
    // Data lookups do not prolong ARP reachability.
    assert_eq!(t.resolve(NEXT, 30000), Ok(Resolution::Reachable(PEER)));
    assert_eq!(t.resolve(NEXT, 30001), Ok(Resolution::Pending));
    assert_eq!(t.observe(&request, 30001), Ok(false)); // no transmitted re-probe
    transmit(&mut t, 30001);
    assert_eq!(t.observe(&request, 30002), Ok(true));
}

#[test]
fn retry_budget_deadline_cooldown_and_no_restart_on_repeated_miss() {
    let mut t = Table::<4>::new(interface()).unwrap();
    assert_eq!(t.resolve(NEXT, 0), Ok(Resolution::Pending));
    assert_eq!(t.next_deadline(0), Ok(Some(0)));
    transmit(&mut t, 0);
    assert_eq!(t.next_deadline(1), Ok(Some(1000)));
    for now in [1, 500, 999] {
        assert_eq!(t.resolve(NEXT, now), Ok(Resolution::Pending));
        assert!(t.probe(now).unwrap().is_none());
    }
    transmit(&mut t, 1000);
    transmit(&mut t, 2000);
    assert_eq!(t.next_deadline(2000), Ok(Some(5000)));
    assert!(t.probe(3000).unwrap().is_none());
    assert_eq!(t.resolve(NEXT, 4999), Ok(Resolution::Pending));
    assert_eq!(t.resolve(NEXT, 5000), Ok(Resolution::Failed));
    assert_eq!(t.observe(&reply(), 5000), Ok(false));
    assert_eq!(t.next_deadline(5000), Ok(None));
    assert_eq!(t.resolve(NEXT, 14999), Ok(Resolution::Failed));
    assert_eq!(t.resolve(NEXT, 15000), Ok(Resolution::Pending));
    transmit(&mut t, 15000);
}

#[test]
fn tx_busy_cancellation_and_global_pacing() {
    let mut t = Table::<8>::new(interface()).unwrap();
    t.resolve(NEXT, 0).unwrap();
    t.resolve(OTHER, 0).unwrap();
    let entries = t.entries;
    let p = t.probe(0).unwrap().unwrap();
    let first = p.frame();
    drop(p);
    assert_eq!(t.entries, entries);
    assert_eq!(t.next_send, 0);
    assert_eq!(transmit(&mut t, 0), first);
    assert!(t.probe(99).unwrap().is_none());
    let second = transmit(&mut t, 100);
    assert_ne!(&first[38..42], &second[38..42]);
    assert!(t.probe(200).unwrap().is_none());
    assert_eq!(t.next_deadline(200), Ok(Some(1000)));
    assert_eq!(transmit(&mut t, 1000), first);
    assert_eq!(transmit(&mut t, 1100), second);
}

#[test]
fn unsolicited_foreign_malformed_and_mac_change_updates_are_rejected() {
    let mut t = Table::<8>::new(interface()).unwrap();
    assert_eq!(t.observe(&reply(), 0), Ok(false));
    assert_eq!(t.observe(&request(), 0), Ok(false));
    assert!(t.entries.iter().all(Option::is_none));
    t.resolve(NEXT, 0).unwrap();
    assert_eq!(t.observe(&reply(), 0), Ok(false));
    transmit(&mut t, 0);
    let original = t.entries;
    for length in 0..42 {
        assert_eq!(t.observe(&reply()[..length], 1), Ok(false));
        assert_eq!(t.entries, original);
    }
    for offset in [0, 6, 12, 14, 16, 18, 19, 20, 21, 22, 28, 32, 38] {
        let mut f = reply();
        f[offset] ^= 1;
        assert_eq!(t.observe(&f, 1), Ok(false), "offset {offset}");
        assert_eq!(t.entries, original);
    }
    let mut f = reply();
    f[..6].fill(255);
    assert_eq!(t.observe(&f, 1), Ok(false));
    assert_eq!(t.observe(&reply(), 1), Ok(true));
    let mut changed = request();
    changed[11] ^= 1;
    changed[27] ^= 1;
    assert_eq!(t.observe(&changed, 2), Ok(false));
    assert_eq!(t.resolve(NEXT, 2), Ok(Resolution::Reachable(PEER)));
    // Even an otherwise valid reply cannot refresh reachability indefinitely.
    assert_eq!(t.observe(&reply(), 2), Ok(false));
    assert_eq!(t.observe(&request(), 3), Ok(true));
    assert_eq!(t.resolve(NEXT, 30003), Ok(Resolution::Pending));
}

#[test]
fn targeted_request_can_complete_existing_resolution_and_interfaces_are_isolated() {
    let mut wan = Table::<8>::new(interface()).unwrap();
    let lan_cfg = Interface {
        mac: [2, 0x42, 0x70, 4, 0, 2],
        ip: [192, 168, 79, 1],
        prefix: 24,
        gateway: None,
    };
    let mut lan = Table::<8>::new(lan_cfg).unwrap();
    wan.resolve(NEXT, 0).unwrap();
    lan.resolve([192, 168, 79, 2], 0).unwrap();
    assert_eq!(wan.observe(&request(), 1), Ok(true));
    assert_eq!(lan.observe(&request(), 1), Ok(false));
    assert_eq!(lan.resolve([192, 168, 79, 2], 1), Ok(Resolution::Pending));
    assert_eq!(lan.resolve(NEXT, 1), Err(Error::Address));
    // Address-conflict probes are replyable by ARP but not usable as neighbors.
    let mut probe = request();
    probe[28..32].fill(0);
    assert_eq!(wan.observe(&probe, 2), Ok(false));
}

#[test]
fn no_live_eviction_and_backpressure_cannot_pin_a_slot_forever() {
    let mut t = Table::<1>::new(interface()).unwrap();
    t.resolve(NEXT, 0).unwrap();
    assert_eq!(t.resolve(OTHER, 1), Err(Error::Capacity));
    // No packet was transmitted, but the hard pending lifetime still expires.
    assert_eq!(t.resolve(NEXT, 5000), Ok(Resolution::Failed));
    assert_eq!(t.resolve(OTHER, 15000), Ok(Resolution::Pending));
    let f = transmit(&mut t, 15000);
    assert_eq!(&f[38..42], &OTHER);
    assert_eq!(t.observe(&reply(), 15001), Ok(false));
    let mut reply = reply();
    reply[28..32].copy_from_slice(&OTHER);
    assert_eq!(t.observe(&reply, 15001), Ok(true));
    assert_eq!(t.resolve(NEXT, 15002), Err(Error::Capacity));
    assert_eq!(t.resolve(NEXT, 45001), Ok(Resolution::Pending));
}

#[test]
fn reconfiguration_and_clock_errors_preserve_invariants() {
    let mut t = Table::<8>::new(interface()).unwrap();
    t.resolve(NEXT, 100).unwrap();
    transmit(&mut t, 100);
    let entries = t.entries;
    assert_eq!(t.resolve(NEXT, 99), Err(Error::Clock));
    assert!(matches!(t.probe(99), Err(Error::Clock)));
    assert_eq!(t.observe(&reply(), 99), Err(Error::Clock));
    assert_eq!(t.next_deadline(99), Err(Error::Clock));
    assert_eq!(t.resolve(NEXT, u64::MAX), Err(Error::Clock));
    assert_eq!(t.entries, entries);
    let mut bad = interface();
    bad.prefix = 0;
    assert_eq!(t.reconfigure(bad), Err(Error::Configuration));
    assert_eq!(t.entries, entries);
    t.reconfigure(interface()).unwrap();
    assert!(t.entries.iter().all(Option::is_none));
    assert_eq!(t.observe(&reply(), 100), Ok(false));
    assert_eq!(t.resolve(NEXT, 100), Ok(Resolution::Pending));
    assert!(t.probe(100).unwrap().is_none()); // pacing survives reconfiguration
    transmit(&mut t, 200);
}

#[test]
fn active_binding_refresh_requires_sent_probe_and_preserves_mac_until_expiry() {
    let mut t = Table::<8>::new(interface()).unwrap();
    t.resolve(NEXT, 0).unwrap();
    transmit(&mut t, 0);
    assert!(t.observe(&reply(), 1).unwrap());
    // Idle entries do not create timer wakeups or unsolicited refresh traffic.
    assert_eq!(t.next_deadline(25000), Ok(None));
    assert!(t.probe(25000).unwrap().is_none());
    assert!(!t.observe(&reply(), 25000).unwrap());
    assert_eq!(t.resolve(NEXT, 25001), Ok(Resolution::Reachable(PEER)));
    assert_eq!(t.next_deadline(25001), Ok(Some(25001)));
    drop(t.probe(25001).unwrap().unwrap()); // DMA Busy: no attempt committed.
    assert!(!t.observe(&reply(), 25001).unwrap());
    transmit(&mut t, 25001);
    let mut changed = reply();
    changed[11] ^= 1;
    changed[27] ^= 1;
    assert!(!t.observe(&changed, 25002).unwrap());
    assert!(t.observe(&reply(), 25002).unwrap());
    assert_eq!(t.next_deadline(25002), Ok(None));
    assert!(!t.observe(&reply(), 25003).unwrap()); // no outstanding refresh now
    assert_eq!(t.resolve(NEXT, 30002), Ok(Resolution::Reachable(PEER)));
    assert_eq!(t.resolve(NEXT, 55002), Ok(Resolution::Pending));
    assert!(!t.observe(&changed, 55002).unwrap());
    transmit(&mut t, 55002);
    assert!(t.observe(&changed, 55003).unwrap()); // new binding after hard expiry
}

#[test]
fn failed_refresh_is_bounded_and_never_extends_binding_lifetime() {
    let mut t = Table::<8>::new(interface()).unwrap();
    t.resolve(NEXT, 0).unwrap();
    transmit(&mut t, 0);
    assert!(t.observe(&reply(), 1).unwrap());
    assert_eq!(t.resolve(NEXT, 25001), Ok(Resolution::Reachable(PEER)));
    for now in [25001, 26001, 27001] {
        transmit(&mut t, now);
        assert!(t.probe(now + 1).unwrap().is_none());
        assert_eq!(t.resolve(NEXT, now + 1), Ok(Resolution::Reachable(PEER)));
    }
    assert!(t.probe(28001).unwrap().is_none());
    assert_eq!(t.next_deadline(28001), Ok(Some(30001)));
    assert_eq!(t.resolve(NEXT, 30000), Ok(Resolution::Reachable(PEER)));
    assert!(!t.observe(&reply(), 30001).unwrap());
    assert_eq!(t.resolve(NEXT, 30001), Ok(Resolution::Pending));
    assert!(!t.observe(&reply(), 30001).unwrap());
    t.reconfigure(interface()).unwrap();
    assert_eq!(t.next_deadline(30002), Ok(None));
}

#[test]
fn refresh_shares_interface_pacing_with_cold_resolution() {
    let mut t = Table::<8>::new(interface()).unwrap();
    t.resolve(NEXT, 0).unwrap();
    transmit(&mut t, 0);
    assert!(t.observe(&reply(), 1).unwrap());
    t.resolve(NEXT, 25001).unwrap();
    transmit(&mut t, 25001);
    assert_eq!(t.resolve(OTHER, 25002), Ok(Resolution::Pending));
    assert!(t.probe(25100).unwrap().is_none());
    let frame = transmit(&mut t, 25101);
    assert_eq!(&frame[38..42], &OTHER);
    assert_eq!(t.resolve(NEXT, 25102), Ok(Resolution::Reachable(PEER)));
}

#[test]
fn offload_neighbor_read_preserves_deadline_and_rejects_expired_authority() {
    let mut table = Table::<4>::new(interface()).unwrap();
    assert_eq!(table.reachable_until(NEXT, 0), Ok(None));
    assert_eq!(table.resolve(NEXT, 0), Ok(Resolution::Pending));
    transmit(&mut table, 0);
    assert_eq!(table.observe(&reply(), 1), Ok(true));
    let before = table.entries;
    assert_eq!(table.reachable_until(NEXT, 5000), Ok(Some((PEER, 30001))));
    assert_eq!(table.reachable_until(NEXT, 30000), Ok(Some((PEER, 30001))));
    assert_eq!(table.reachable_until(NEXT, 30001), Ok(None));
    assert_eq!(table.entries, before);
    assert_eq!(table.last_now, 1);
    assert_eq!(table.reachable_until(NEXT, 0), Err(Error::Clock));
    assert_eq!(table.reachable_until(IP, 1), Err(Error::Address));
    table.reconfigure(interface()).unwrap();
    assert_eq!(table.reachable_until(NEXT, 1), Ok(None));
}


#[test]
fn known_arp_reply_never_changes_neighbor_or_deadline() {
    let mut table = Table::<8>::new(interface()).unwrap();
    table.resolve(NEXT, 0).unwrap();
    transmit(&mut table, 0);
    assert!(table.observe(&reply(), 1).unwrap());
    let before = (table.entries, table.last_now, table.next_send, table.cursor);
    for now in [1, 100, REACHABLE_MS] {
        let mut frame = request();
        assert_eq!(table.reply_known_request(&mut frame, now), Some(42));
        assert_eq!(frame[21], 2);
        assert_eq!(frame[..6], PEER);
        assert_eq!(frame[22..28], MAC);
        assert_eq!((table.entries, table.last_now, table.next_send, table.cursor), before);
    }
    for now in [0, REACHABLE_MS + 1] {
        let mut frame = request(); let original = frame;
        assert_eq!(table.reply_known_request(&mut frame, now), None);
        assert_eq!(frame, original);
    }
}

#[test]
fn known_arp_reply_rejects_unknown_changed_pending_or_invalid_requests() {
    let mut table = Table::<8>::new(interface()).unwrap();
    let mut frame = request();
    assert_eq!(table.reply_known_request(&mut frame, 0), None);
    table.resolve(NEXT, 0).unwrap();
    assert_eq!(table.reply_known_request(&mut frame, 0), None);
    assert_eq!(frame, request());
    transmit(&mut table, 0);
    table.observe(&reply(), 1).unwrap();
    for offset in [0, 6, 12, 14, 16, 18, 20, 21, 22, 28, 32, 38] {
        let mut frame = request(); frame[offset] ^= 1; let original = frame;
        assert_eq!(table.reply_known_request(&mut frame, 2), None, "offset {offset}");
        assert_eq!(frame, original);
    }
    for length in 0..42 {
        let mut frame = request();
        assert_eq!(table.reply_known_request(&mut frame[..length], 2), None);
        assert_eq!(frame, request());
    }
    let mut unsolicited = reply();
    assert_eq!(table.reply_known_request(&mut unsolicited, 2), None);
    assert_eq!(unsolicited, reply());
}

#[test]
fn requested_refresh_probes_early_without_extending_the_binding() {
    let mut t = Table::<8>::new(interface()).unwrap();
    // Nothing to refresh before the binding exists or while it is pending.
    assert_eq!(t.request_refresh(NEXT, 0), Ok(false));
    t.resolve(NEXT, 0).unwrap();
    assert_eq!(t.request_refresh(NEXT, 0), Ok(false));
    transmit(&mut t, 0);
    assert!(t.observe(&reply(), 1).unwrap());
    assert_eq!(t.reachable_until(NEXT, 2), Ok(Some((PEER, 30001))));
    // Well ahead of the traffic-driven window: a probe is scheduled at once,
    // and only once; the lifetime itself is untouched.
    assert_eq!(t.next_deadline(15000), Ok(None));
    assert_eq!(t.request_refresh(NEXT, 15000), Ok(true));
    assert_eq!(t.request_refresh(NEXT, 15000), Ok(false));
    assert_eq!(t.next_deadline(15000), Ok(Some(15000)));
    assert_eq!(t.reachable_until(NEXT, 15000), Ok(Some((PEER, 30001))));
    transmit(&mut t, 15000);
    assert!(t.observe(&reply(), 15002).unwrap());
    assert_eq!(t.reachable_until(NEXT, 15003), Ok(Some((PEER, 45002))));
    assert_eq!(t.next_deadline(15003), Ok(None));
    // Unknown and local addresses, and an expired binding, schedule nothing.
    assert_eq!(t.request_refresh(OTHER, 15003), Ok(false));
    assert_eq!(t.request_refresh(IP, 15003), Err(Error::Address));
    assert_eq!(t.request_refresh(NEXT, 45002), Ok(false));
}
