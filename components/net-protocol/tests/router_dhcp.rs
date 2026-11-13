use vibeos_net_protocol::{
    neighbor, router_config,
    router_dhcp::{Client, Ingress},
};
const MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 1];
const SERVER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
fn client() -> Client {
    Client::new(
        router_config::Config::new([
            neighbor::Interface {
                mac: MAC,
                ip: [192, 168, 78, 1],
                prefix: 24,
                gateway: Some([192, 168, 78, 2]),
            },
            neighbor::Interface {
                mac: [2, 0x42, 0x70, 4, 0, 2],
                ip: [192, 168, 79, 1],
                prefix: 24,
                gateway: None,
            },
        ])
        .unwrap(),
        123,
    )
    .unwrap()
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn response(xid: &[u8], kind: u8, address: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[..3].copy_from_slice(&[2, 1, 6]);
    b[4..8].copy_from_slice(xid);
    b[16..20].copy_from_slice(&address);
    b[28..34].copy_from_slice(&MAC);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[
        53, 1, kind, 54, 4, 192, 168, 78, 2, 51, 4, 0, 0, 0, 10, 58, 4, 0, 0, 0, 4, 59, 4, 0, 0, 0,
        8, 1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 78, 2, 255,
    ]);
    let mut f = vec![0; 42];
    f[..6].fill(255);
    f[6..12].copy_from_slice(&SERVER_MAC);
    f[12..14].copy_from_slice(&[8, 0]);
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((28 + b.len()) as u16).to_be_bytes());
    f[22] = 64;
    f[23] = 17;
    f[26..30].copy_from_slice(&[192, 168, 78, 2]);
    f[30..34].fill(255);
    let sum = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&sum.to_be_bytes());
    f[34..38].copy_from_slice(&[0, 67, 0, 68]);
    f[38..40].copy_from_slice(&((8 + b.len()) as u16).to_be_bytes());
    f.extend_from_slice(&b);
    f
}
fn take(c: &mut Client) -> Vec<u8> {
    let mut result = vec![];
    c.transmit(|f| {
        result.extend_from_slice(f);
        true
    });
    result
}
fn offer(c: &mut Client, address: [u8; 4]) -> Vec<u8> {
    assert_eq!(c.poll(0).unwrap().transition, Some(None));
    let discover = take(c);
    assert_eq!(&discover[34..38], &[0, 68, 0, 67]);
    assert_eq!(
        c.receive(&response(&discover[46..50], 2, address)),
        Ingress::Queued
    );
    assert_eq!(c.poll(1).unwrap().transition, None);
    let request = take(c);
    assert_eq!(&request[46..50], &discover[46..50]);
    request
}
fn bound(c: &mut Client) {
    let req = offer(c, [192, 168, 78, 9]);
    assert_eq!(
        c.receive(&response(&req[46..50], 5, [192, 168, 78, 9])),
        Ingress::Queued
    );
    let report = c.poll(2).unwrap();
    let conf = report.transition.unwrap().unwrap();
    assert_eq!(conf.interfaces[0].ip, [192, 168, 78, 9]);
    assert_eq!(conf.interfaces[0].gateway, Some([192, 168, 78, 2]));
    assert!(!report.rejected_lease);
}
#[test]
fn acquisition_and_real_deadline_expiry_revoke_once() {
    let mut c = client();
    bound(&mut c);
    assert_eq!(c.poll(3).unwrap().transition, None);
    assert_eq!(c.poll(10_003).unwrap().transition, Some(None));
    assert_eq!(c.poll(10_004).unwrap().transition, None);
}
#[test]
fn renewal_of_same_address_preserves_authority_then_expires() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    c.receive(&response(&request[46..50], 5, [192, 168, 78, 9]));
    assert_eq!(c.poll(4005).unwrap().transition, None);
    assert_eq!(c.poll(10003).unwrap().transition, None); // beyond original expiry
    assert_eq!(c.poll(14006).unwrap().transition, Some(None));
}
#[test]
fn malformed_identity_and_control_queue_are_bounded() {
    let mut c = client();
    c.poll(0).unwrap();
    let discover = take(&mut c);
    let mut frame = response(&discover[46..50], 2, [192, 168, 78, 9]);
    frame[46] ^= 1;
    for _ in 0..4 {
        assert_eq!(c.receive(&frame), Ingress::Queued);
    }
    assert_eq!(c.receive(&frame), Ingress::Full);
    assert_eq!(c.poll(1).unwrap().transition, None);
    assert!(take(&mut c).is_empty());
    frame[46] ^= 1;
    frame[36..38].copy_from_slice(&22222u16.to_be_bytes());
    assert_eq!(c.receive(&frame), Ingress::Ignored);
    frame[36..38].copy_from_slice(&68u16.to_be_bytes());
    frame[20] = 0x20;
    assert_eq!(c.receive(&frame), Ingress::Ignored);
    frame[20] = 0;
    frame[0] = 0x12;
    assert_eq!(c.receive(&frame), Ingress::Ignored);
}
#[test]
fn backpressure_retains_exact_discover() {
    let mut c = client();
    c.poll(0).unwrap();
    let mut retained = vec![];
    assert!(!c.transmit(|f| {
        retained.extend_from_slice(f);
        false
    }));
    assert!(!retained.is_empty());
    assert_eq!(take(&mut c), retained);
    assert!(take(&mut c).is_empty());
}
#[test]
fn overlapping_lease_is_never_published() {
    let mut c = client();
    let request = offer(&mut c, [192, 168, 79, 9]);
    c.receive(&response(&request[46..50], 5, [192, 168, 79, 9]));
    let report = c.poll(2).unwrap();
    assert!(report.rejected_lease);
    assert_eq!(report.transition, None); // still revoked since initial poll
}
#[test]
fn unanswered_renewal_and_output_backpressure_do_not_retain_expired_lease() {
    let mut c = client();
    bound(&mut c);
    for now in [4003, 5003, 6003, 7003, 8003, 9003, 9999] {
        assert_eq!(c.poll(now).unwrap().transition, None);
        c.transmit(|_| false);
    }
    assert_eq!(c.poll(10003).unwrap().transition, Some(None));
}
#[test]
fn invalid_udp_checksum_cannot_install_a_lease() {
    let mut c = client();
    let request = offer(&mut c, [192, 168, 78, 9]);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    ack[40..42].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(c.receive(&ack), Ingress::Queued);
    assert_eq!(c.poll(2).unwrap().transition, None);
    assert_eq!(
        c.receive(&response(&request[46..50], 5, [192, 168, 78, 9])),
        Ingress::Queued
    );
    assert!(c.poll(3).unwrap().transition.unwrap().is_some());
}

fn renew_request(c: &mut Client) -> Vec<u8> {
    renew_request_at(c, 4003)
}
fn renew_request_at(c: &mut Client, now: u64) -> Vec<u8> {
    assert_eq!(c.poll(now).unwrap().transition, None);
    let mut request = take(c);
    if request[12..14] == [8, 6] {
        let mut arp = vec![0; 42];
        arp[..6].copy_from_slice(&MAC);
        arp[6..12].copy_from_slice(&SERVER_MAC);
        arp[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
        arp[22..28].copy_from_slice(&SERVER_MAC);
        arp[28..32].copy_from_slice(&[192, 168, 78, 2]);
        arp[32..38].copy_from_slice(&MAC);
        arp[38..42].copy_from_slice(&[192, 168, 78, 9]);
        assert_eq!(c.receive(&arp), Ingress::Queued);
        c.poll(now + 1).unwrap();
        request = take(c);
    }
    assert_eq!(&request[34..38], &[0, 68, 0, 67]);
    request
}

#[test]
fn renewal_nak_revokes_and_new_address_requires_new_acquisition() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    assert_eq!(
        c.receive(&response(&request[46..50], 6, [0; 4])),
        Ingress::Queued
    );
    assert_eq!(c.poll(4005).unwrap().transition, Some(None));
    // Egress may have emitted the new DISCOVER in the same poll.
    c.poll(4006).unwrap();
    let discover = take(&mut c);
    assert!(!discover.is_empty());
    c.receive(&response(&discover[46..50], 2, [192, 168, 78, 10]));
    assert_eq!(c.poll(4007).unwrap().transition, None);
    let request = take(&mut c);
    c.receive(&response(&request[46..50], 5, [192, 168, 78, 10]));
    let config = c.poll(4008).unwrap().transition.unwrap().unwrap();
    assert_eq!(config.interfaces[0].ip, [192, 168, 78, 10]);
}

fn other_server(mut frame: Vec<u8>) -> Vec<u8> {
    frame[26..30].copy_from_slice(&[192, 168, 78, 3]);
    // response() emits message type followed by server identifier.
    assert_eq!(&frame[285..287], &[54, 4]);
    frame[287..291].copy_from_slice(&[192, 168, 78, 3]);
    frame[24..26].fill(0);
    let sum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&sum.to_be_bytes());
    frame
}
#[test]
fn unselected_server_ack_and_nak_do_not_change_selected_lease() {
    let mut c = client();
    let request = offer(&mut c, [192, 168, 78, 9]);
    c.receive(&other_server(response(
        &request[46..50],
        5,
        [192, 168, 78, 10],
    )));
    assert_eq!(c.poll(2).unwrap().transition, None);
    c.receive(&response(&request[46..50], 5, [192, 168, 78, 9]));
    assert!(c.poll(3).unwrap().transition.unwrap().is_some());
    let request = renew_request(&mut c);
    c.receive(&other_server(response(&request[46..50], 6, [0; 4])));
    assert_eq!(c.poll(4005).unwrap().transition, None);
    c.receive(&response(&request[46..50], 5, [192, 168, 78, 9]));
    assert_eq!(c.poll(4006).unwrap().transition, None);
}
#[test]
fn successful_rebind_updates_server_for_next_unicast_renewal() {
    let mut c = client();
    bound(&mut c);
    c.poll(8003).unwrap();
    let request = take(&mut c);
    assert_eq!(&request[30..34], &[255; 4]);
    c.receive(&other_server(response(
        &request[46..50],
        5,
        [192, 168, 78, 9],
    )));
    assert_eq!(c.poll(8004).unwrap().transition, None);
    c.poll(12005).unwrap();
    let request = take(&mut c);
    let destination = if request[12..14] == [8, 6] {
        &request[38..42]
    } else {
        &request[30..34]
    };
    assert_eq!(destination, &[192, 168, 78, 3]);
}
#[test]
fn unicast_renewal_uses_server_identifier_not_offer_source() {
    let mut c = client();
    c.poll(0).unwrap();
    let discover = take(&mut c);
    let mut offer = other_server(response(&discover[46..50], 2, [192, 168, 78, 9]));
    // IP source .2, server identifier .3: the unicast target must be .3.
    offer[26..30].copy_from_slice(&[192, 168, 78, 2]);
    offer[24..26].fill(0);
    let sum = checksum(&offer[14..34]);
    offer[24..26].copy_from_slice(&sum.to_be_bytes());
    c.receive(&offer);
    c.poll(1).unwrap();
    let request = take(&mut c);
    c.receive(&other_server(response(
        &request[46..50],
        5,
        [192, 168, 78, 9],
    )));
    assert!(c.poll(2).unwrap().transition.unwrap().is_some());
    c.poll(4003).unwrap();
    let request = take(&mut c);
    let destination = if request[12..14] == [8, 6] {
        &request[38..42]
    } else {
        &request[30..34]
    };
    assert_eq!(destination, &[192, 168, 78, 3]);
}

#[test]
fn gateway_change_requires_new_router_configuration_even_with_same_address() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    let len = ack.len();
    assert_eq!(&ack[len - 7..len - 5], &[3, 4]);
    ack[len - 5..len - 1].copy_from_slice(&[192, 168, 78, 3]);
    c.receive(&ack);
    let config = c.poll(4005).unwrap().transition.unwrap().unwrap();
    assert_eq!(config.interfaces[0].ip, [192, 168, 78, 9]);
    assert_eq!(config.interfaces[0].gateway, Some([192, 168, 78, 3]));
    assert_eq!(c.poll(4006).unwrap().transition, None);
}

#[test]
fn off_link_gateway_in_renewal_revokes_previous_router_authority() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    let len = ack.len();
    ack[len - 5..len - 1].copy_from_slice(&[192, 168, 80, 3]);
    c.receive(&ack);
    let report = c.poll(4005).unwrap();
    assert!(report.rejected_lease);
    assert_eq!(report.transition, Some(None));
    assert_eq!(c.poll(4006).unwrap().transition, None);
}

#[test]
fn rejected_gateway_recovers_on_valid_renewal_without_client_restart() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    let len = ack.len();
    ack[len - 5..len - 1].copy_from_slice(&[192, 168, 80, 3]);
    c.receive(&ack);
    let report = c.poll(4005).unwrap();
    assert!(report.rejected_lease);
    assert_eq!(report.transition, Some(None));
    let still_rejected = c.poll(8005).unwrap();
    assert!(still_rejected.rejected_lease);
    assert_eq!(still_rejected.transition, None);
    let request = renew_request_at(&mut c, 8006);
    assert_eq!(&request[34..38], &[0, 68, 0, 67]);
    assert_eq!(&request[54..58], &[192, 168, 78, 9]);
    c.receive(&response(&request[46..50], 5, [192, 168, 78, 9]));
    let recovered = c.poll(8008).unwrap();
    assert!(!recovered.rejected_lease);
    let config = recovered.transition.unwrap().unwrap();
    assert_eq!(config.interfaces[0].ip, [192, 168, 78, 9]);
    assert_eq!(config.interfaces[0].gateway, Some([192, 168, 78, 2]));
    assert_eq!(c.poll(8009).unwrap().transition, None);
}

#[test]
fn renewed_prefix_changes_next_hop_and_overlapping_prefix_revokes() {
    let mut c = client();
    bound(&mut c);
    let request = renew_request(&mut c);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    let len = ack.len();
    assert_eq!(&ack[len - 13..len - 11], &[1, 4]);
    ack[len - 8] = 128; // /25: .200 now needs the default gateway.
    c.receive(&ack);
    let narrowed = c.poll(4005).unwrap().transition.unwrap().unwrap();
    assert_eq!(narrowed.interfaces[0].prefix, 25);
    assert_eq!(
        narrowed.interfaces[0].next_hop([192, 168, 78, 200]),
        Ok([192, 168, 78, 2])
    );
    assert_eq!(
        narrowed.interfaces[0].next_hop([192, 168, 78, 100]),
        Ok([192, 168, 78, 100])
    );
    let request = renew_request_at(&mut c, 8006);
    let mut ack = response(&request[46..50], 5, [192, 168, 78, 9]);
    ack[len - 9] = 254; // /23 overlaps LAN 192.168.79.0/24.
    c.receive(&ack);
    let report = c.poll(8008).unwrap();
    assert!(report.rejected_lease);
    assert_eq!(report.transition, Some(None));
}

#[test]
fn forwarding_window_is_bound_to_config_time_and_control_work() {
    let mut c = client();
    bound(&mut c);
    let config = router_config::Config::new([
        neighbor::Interface {
            mac: MAC,
            ip: [192, 168, 78, 9],
            prefix: 24,
            gateway: Some([192, 168, 78, 2]),
        },
        neighbor::Interface {
            mac: [2, 0x42, 0x70, 4, 0, 2],
            ip: [192, 168, 79, 1],
            prefix: 24,
            gateway: None,
        },
    ])
    .unwrap();
    c.poll(3).unwrap();
    let until = c.forwarding_until(config, 3).unwrap();
    assert!(until <= 4002, "must not cross the first renewal deadline");
    assert_eq!(c.forwarding_until(config, 2), None, "clock regression");
    assert_eq!(
        c.forwarding_until(config, until),
        None,
        "deadline is exclusive"
    );
    let mut wrong = config;
    wrong.interfaces[0].ip[3] = 10;
    assert_eq!(c.forwarding_until(wrong, 3), None);
    // An ignored non-control frame does not alter the DHCP proof.
    assert_eq!(c.receive(&[0; 64]), Ingress::Ignored);
    assert_eq!(c.forwarding_until(config, 3), Some(until));
    // Even an invalid transaction must be processed before authority is reused.
    assert_eq!(c.receive(&response(&[0; 4], 6, [0; 4])), Ingress::Queued);
    assert_eq!(c.forwarding_until(config, 3), None);
    c.poll(4).unwrap();
    assert!(c.forwarding_until(config, 4).is_some());
    assert!(c.poll(3).is_err(), "backward poll must fail");
    assert_eq!(
        c.forwarding_until(config, 4),
        None,
        "error revoked previous proof"
    );
    c.poll(5).unwrap();
    assert!(c.forwarding_until(config, 5).is_some());
    // Renewal emits control work: a pending NIC send excludes acceleration.
    c.poll(4003).unwrap();
    assert_eq!(c.forwarding_until(config, 4003), None);
    assert!(!c.transmit(|_| false));
    assert_eq!(c.forwarding_until(config, 4003), None);
    c.poll(10003).unwrap();
    assert_eq!(c.forwarding_until(config, 10003), None, "expired lease");
}
