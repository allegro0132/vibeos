use vibeos_core::{
    cap::{CSpace, Rights},
    chan::Endpoint,
    net::{PacketStamp, StampedPacket},
};
use vibeos_net_protocol::{
    Ipv4RuntimeStatus, StaticIpv4Address, StaticIpv4Config, StaticIpv4EchoStack,
};

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

fn response(xid: &[u8], mac: [u8; 6], kind: u8) -> Vec<u8> {
    let mut b = vec![0u8; 240];
    b[..3].copy_from_slice(&[2, 1, 6]);
    b[4..8].copy_from_slice(xid);
    b[10] = 0x80;
    b[16..20].copy_from_slice(&[192, 168, 77, 1]);
    b[20..24].copy_from_slice(&[192, 168, 77, 2]);
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    b.extend_from_slice(&[
        53, 1, kind, 54, 4, 192, 168, 77, 2, 51, 4, 0, 0, 1, 44, 1, 4, 255, 255, 255, 0, 255,
    ]);
    let mut f = vec![0; 42];
    f[..6].fill(255);
    f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    f[12..14].copy_from_slice(&[8, 0]);
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((28 + b.len()) as u16).to_be_bytes());
    f[22] = 64;
    f[23] = 17;
    f[26..30].copy_from_slice(&[192, 168, 77, 2]);
    f[30..34].fill(255);
    let sum = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&sum.to_be_bytes());
    f[34..38].copy_from_slice(&[0, 67, 0, 68]);
    f[38..40].copy_from_slice(&((8 + b.len()) as u16).to_be_bytes());
    f.extend_from_slice(&b);
    f
}

#[test]
fn dhcp_ack_preserves_offered_address_and_static_restore() {
    let mac = [2, 0x42, 0x70, 4, 0, 1];
    let stamp = PacketStamp::new(1, 1).unwrap();
    let inbound = Endpoint::<StampedPacket>::new("in", 32);
    let outbound = Endpoint::<StampedPacket>::new("out", 32);
    let mut caps = CSpace::new("dhcp");
    let rx = caps.mint(inbound.clone(), Rights::RECV);
    let tx = caps.mint(outbound.clone(), Rights::SEND);
    let mut stack = StaticIpv4EchoStack::new(
        StaticIpv4Config::new(mac, [192, 168, 77, 1], 24, 22222, 123),
        stamp,
        caps.lookup_revocable(rx, Rights::RECV).unwrap(),
        caps.lookup_revocable(tx, Rights::SEND).unwrap(),
    )
    .unwrap();
    stack.start_dhcp().unwrap();
    stack.step(0).unwrap();
    let discover = outbound.try_recv().unwrap().into_packet(stamp).unwrap();
    let xid = &discover.as_bytes()[46..50];
    inbound
        .try_send(StampedPacket::copy_from(&response(xid, mac, 2), stamp).unwrap())
        .unwrap();
    stack.step(1).unwrap();
    let request = outbound.try_recv().unwrap().into_packet(stamp).unwrap();
    assert_eq!(&request.as_bytes()[46..50], xid);
    inbound
        .try_send(StampedPacket::copy_from(&response(xid, mac, 5), stamp).unwrap())
        .unwrap();
    stack.step(2).unwrap();
    let expected = StaticIpv4Address::new([192, 168, 77, 1], 24);
    assert_eq!(stack.ipv4_status(), Ipv4RuntimeStatus::DhcpBound(expected));
    stack.configure_static_ipv4(expected).unwrap();
    assert_eq!(stack.ipv4_status(), Ipv4RuntimeStatus::Static(expected));
}
