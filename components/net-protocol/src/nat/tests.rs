use super::*;
use alloc::vec;
use alloc::vec::Vec;

const MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 1];
const PEER: [u8; 6] = [2, 3, 4, 5, 6, 7];
const LAN: [u8; 4] = [192, 168, 79, 2];
const WAN: [u8; 4] = [192, 168, 78, 1];
const REMOTE: [u8; 4] = [192, 168, 78, 2];
const OTHER: [u8; 4] = [192, 168, 78, 3];
fn config() -> Config {
    Config {
        wan_ip: WAN,
        lan_ip: [192, 168, 79, 1],
        lan_prefix: 24,
    }
}
fn egress() -> Egress {
    Egress {
        source_mac: MAC,
        destination_mac: PEER,
        mtu: 1500,
    }
}
fn word(f: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([f[o], f[o + 1]])
}
fn put(f: &mut [u8], o: usize, v: u16) {
    f[o..o + 2].copy_from_slice(&v.to_be_bytes());
}
fn checksum(b: &[u8]) -> u16 {
    let mut n = 0u64;
    for i in (0..b.len()).step_by(2) {
        n += ((b[i] as u64) << 8) + b.get(i + 1).copied().unwrap_or(0) as u64;
    }
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn fix(f: &mut [u8]) {
    put(f, 24, 0);
    let c = checksum(&f[14..34]);
    put(f, 24, c);
    let offset = match f[23] {
        6 => 50,
        17 => 40,
        _ => 36,
    };
    put(f, offset, 0);
    let mut bytes = Vec::new();
    if f[23] != 1 {
        bytes.extend_from_slice(&f[26..34]);
        bytes.extend_from_slice(&[0, f[23]]);
        bytes.extend_from_slice(&((word(f, 16) - 20).to_be_bytes()));
    }
    let end = 14 + word(f, 16) as usize;
    bytes.extend_from_slice(&f[34..end]);
    let c = checksum(&bytes);
    put(f, offset, if f[23] == 17 && c == 0 { 65535 } else { c });
}
fn frame(
    protocol: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let len = if protocol == 6 { 40 } else { 28 };
    let mut f = vec![0; 60];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER);
    put(&mut f, 12, 0x800);
    f[14] = 0x45;
    put(&mut f, 16, len);
    f[22] = 64;
    f[23] = protocol;
    f[26..30].copy_from_slice(&src);
    f[30..34].copy_from_slice(&dst);
    if protocol == 1 {
        f[34] = flags;
        put(&mut f, 38, sport);
        put(&mut f, 40, 1);
    } else {
        put(&mut f, 34, sport);
        put(&mut f, 36, dport);
        if protocol == 6 {
            f[38..42].copy_from_slice(&seq.to_be_bytes());
            f[42..46].copy_from_slice(&ack.to_be_bytes());
            f[46] = 0x50;
            f[47] = flags;
            put(&mut f, 48, 32768);
        } else {
            put(&mut f, 38, 8);
        }
    }
    fix(&mut f);
    f
}
fn udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    frame(17, src, dst, sport, dport, 0, 0, 0)
}
fn tcp(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    frame(6, src, dst, sport, dport, flags, seq, ack)
}
fn send<const M: usize, const F: usize>(
    t: &mut Table<M, F>,
    d: Direction,
    mut f: Vec<u8>,
    now: u64,
) -> (Result<usize, Error>, Vec<u8>) {
    let original = f.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let generation = t.generation;
    let tcp_sequence = t.tcp_sequence;
    let last_now = t.last_now;
    let result = t.forward(d, Packet::parse(&mut f, MAC).unwrap(), egress(), now);
    if result.is_err() {
        assert_eq!(f, original);
        assert_eq!(t.mappings, maps);
        assert_eq!(t.flows, flows);
        assert_eq!(t.generation, generation);
        assert_eq!(t.tcp_sequence, tcp_sequence);
        assert_eq!(t.last_now, last_now);
    } else {
        let mut expected = f.clone();
        fix(&mut expected);
        assert_eq!(expected, f);
        Packet::parse(&mut f, PEER).unwrap();
    }
    (result, f)
}
use Direction::{LanToWan as OUT, WanToLan as IN};

#[test]
fn endpoint_independent_mapping_with_remote_ip_and_port_filtering() {
    let mut t = Table::<32, 64>::new(config(), 42).unwrap();
    let (r, f) = send(&mut t, OUT, udp(LAN, REMOTE, 12345, 53), 0);
    assert!(r.is_ok());
    let port = word(&f, 34);
    assert!((PORT_BASE..PORT_BASE + 32).contains(&port));
    assert_eq!(&f[26..30], &WAN);
    let (r, f) = send(&mut t, OUT, udp(LAN, OTHER, 12345, 8080), 1);
    assert!(r.is_ok());
    assert_eq!(word(&f, 34), port);
    assert_eq!(t.active_counts(1), (1, 2));
    for (src, sport) in [(REMOTE, 8080), (OTHER, 53), ([192, 168, 78, 4], 53)] {
        assert!(send(&mut t, IN, udp(src, WAN, sport, port), 2).0.is_err());
    }
    for (src, sport) in [(REMOTE, 53), (OTHER, 8080)] {
        let (r, f) = send(&mut t, IN, udp(src, WAN, sport, port), 3);
        assert!(r.is_ok());
        assert_eq!(&f[30..34], &LAN);
        assert_eq!(word(&f, 36), 12345);
        assert_eq!(f[22], 63);
    }
    // A listener on a different public address cannot borrow this mapping.
    assert!(send(&mut t, IN, udp(REMOTE, OTHER, 53, port), 4).0.is_err());
    // Protocol identity is part of the mapping, even at the same external ID.
    assert!(send(&mut t, IN, frame(1, REMOTE, WAN, port, 0, 0, 0, 0), 4)
        .0
        .is_err());
}

#[test]
fn internal_identity_and_direction_cannot_be_spoofed() {
    let mut t = Table::<16, 32>::new(config(), 0).unwrap();
    for src in [
        config().lan_ip,
        [192, 168, 79, 0],
        [192, 168, 79, 255],
        REMOTE,
    ] {
        assert_eq!(
            send(&mut t, OUT, udp(src, REMOTE, 12345, 53), 0).0,
            Err(Error::Denied)
        );
    }
    for dst in [LAN, config().lan_ip, WAN, [192, 168, 79, 255]] {
        assert_eq!(
            send(&mut t, OUT, udp(LAN, dst, 12345, 53), 0).0,
            Err(Error::Denied)
        );
    }
    assert_eq!(t.active_counts(0), (0, 0));
}

#[test]
fn echo_request_response_ids_and_timeout() {
    let mut t = Table::<8, 16>::new(config(), 99).unwrap();
    let (r, f) = send(&mut t, OUT, frame(1, LAN, REMOTE, 55, 0, 8, 0, 0), 100);
    assert!(r.is_ok());
    let id = word(&f, 38);
    assert!(send(&mut t, IN, frame(1, OTHER, WAN, id, 0, 0, 0, 0), 101)
        .0
        .is_err());
    assert!(send(&mut t, IN, frame(1, REMOTE, WAN, id, 0, 8, 0, 0), 101)
        .0
        .is_err());
    assert!(
        send(&mut t, OUT, frame(1, LAN, REMOTE, 55, 0, 0, 0, 0), 101)
            .0
            .is_err()
    );
    let (r, f) = send(&mut t, IN, frame(1, REMOTE, WAN, id, 0, 0, 0, 0), 102);
    assert!(r.is_ok());
    assert_eq!(word(&f, 38), 55);
    assert_eq!(&f[30..34], &LAN);
    assert!(
        send(&mut t, IN, frame(1, REMOTE, WAN, id, 0, 0, 0, 0), 60102)
            .0
            .is_err()
    );
    assert_eq!(t.active_counts(60102), (0, 0));
}

#[test]
fn capacity_failures_do_not_evict_or_leak_state_and_expired_slots_reuse() {
    let mut t = Table::<1, 8>::new(config(), 5).unwrap();
    assert!(send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 0).0.is_ok());
    assert_eq!(
        send(&mut t, OUT, udp(LAN, REMOTE, 101, 53), 1).0,
        Err(Error::MappingCapacity)
    );
    assert!(send(&mut t, IN, udp(REMOTE, WAN, 53, PORT_BASE), 2)
        .0
        .is_ok());
    assert!(
        send(&mut t, OUT, udp([192, 168, 79, 3], OTHER, 100, 53), 120002)
            .0
            .is_ok()
    );
    assert!(send(&mut t, IN, udp(REMOTE, WAN, 53, PORT_BASE), 120003)
        .0
        .is_err());
    let (r, f) = send(&mut t, IN, udp(OTHER, WAN, 53, PORT_BASE), 120004);
    assert!(r.is_ok());
    assert_eq!(&f[30..34], &[192, 168, 79, 3]);

    let mut t = Table::<4, 1>::new(config(), 7).unwrap();
    assert!(send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 0).0.is_ok());
    assert_eq!(
        send(&mut t, OUT, udp(LAN, OTHER, 100, 53), 1).0,
        Err(Error::FlowCapacity)
    );
    assert_eq!(
        send(&mut t, OUT, udp(LAN, OTHER, 101, 53), 1).0,
        Err(Error::FlowCapacity)
    );
    assert_eq!(t.active_counts(1), (1, 1));
    assert!(send(&mut t, OUT, udp(LAN, OTHER, 101, 53), 120000)
        .0
        .is_ok());
    assert_eq!(t.active_counts(120000), (1, 1));
}

#[test]
fn ttl_mtu_and_clock_failures_cannot_create_or_refresh_permission() {
    let mut t = Table::<8, 16>::new(config(), 0).unwrap();
    let mut f = udp(LAN, REMOTE, 100, 53);
    f[22] = 1;
    fix(&mut f);
    assert_eq!(
        send(&mut t, OUT, f, 0).0,
        Err(Error::Packet(ipv4::Error::TtlExpired))
    );
    let mut f = udp(LAN, REMOTE, 100, 53);
    let before = f.clone();
    let mut out = egress();
    out.mtu = 20;
    assert!(t
        .forward(OUT, Packet::parse(&mut f, MAC).unwrap(), out, 0)
        .is_err());
    assert_eq!(f, before);
    assert_eq!(t.active_counts(0), (0, 0));
    assert!(send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 100).0.is_ok());
    assert_eq!(
        send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 99).0,
        Err(Error::Clock)
    );
    assert_eq!(
        send(&mut t, OUT, udp(LAN, OTHER, 100, 53), u64::MAX).0,
        Err(Error::Clock)
    );
    assert_eq!(t.active_counts(120100), (0, 0));
}

#[test]
fn reconfiguration_revokes_state_and_bad_configuration_is_transactional() {
    assert!(Table::<0, 1>::new(config(), 0).is_err());
    assert!(Table::<1, 0>::new(config(), 0).is_err());
    for prefix in [0, 31, 32, 255] {
        let mut c = config();
        c.lan_prefix = prefix;
        assert!(Table::<1, 1>::new(c, 0).is_err());
    }
    let mut t = Table::<8, 16>::new(config(), 1).unwrap();
    let (_, f) = send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 0);
    let port = word(&f, 34);
    let mut bad = config();
    bad.wan_ip = LAN;
    assert_eq!(t.reconfigure(bad), Err(Error::Configuration));
    assert!(send(&mut t, IN, udp(REMOTE, WAN, 53, port), 1).0.is_ok());
    let mut new = config();
    new.wan_ip = [192, 168, 78, 10];
    t.reconfigure(new).unwrap();
    assert_eq!(t.active_counts(1), (0, 0));
    assert!(send(&mut t, IN, udp(REMOTE, WAN, 53, port), 2).0.is_err());
    assert!(send(&mut t, IN, udp(REMOTE, new.wan_ip, 53, port), 2)
        .0
        .is_err());
    let (r, f) = send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 3);
    assert!(r.is_ok());
    assert_eq!(&f[26..30], &new.wan_ip);
}

#[test]
fn tcp_handshake_retransmits_bad_ack_and_wraparound() {
    let mut t = Table::<16, 32>::new(config(), 1).unwrap();
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 0, 0), 0)
        .0
        .is_err());
    let (r, f) = send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, u32::MAX, 0), 1);
    assert!(r.is_ok());
    let port = word(&f, 34);
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, u32::MAX, 0), 2)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x12, 900, 1), 3)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 81, port, 0x12, 900, 0), 3)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x10, 900, 0), 3)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x12, 900, 0), 4)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x12, 900, 0), 5)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, u32::MAX, 0), 6)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 0, 900), 7)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 1, 901), 7)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 0, 901), 8)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x12, 900, 0), 9)
            .0
            .is_ok()
    );
    let (r, f) = send(&mut t, IN, tcp(REMOTE, WAN, 80, port, 0x18, 901, 0), 10);
    assert!(r.is_ok());
    assert_eq!(&f[30..34], &LAN);
    assert_eq!(word(&f, 36), 100);
    assert_eq!(t.active_counts(10 + TCP_ESTABLISHED_MS - 1), (1, 1));
    assert_eq!(t.active_counts(10 + TCP_ESTABLISHED_MS), (0, 0));
}

#[test]
fn tcp_pending_timeout_rst_close_and_new_syn() {
    let mut t = Table::<1, 4>::new(config(), 8).unwrap();
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 10, 0), 0)
        .0
        .is_ok());
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, PORT_BASE, 0x14, 0, 12), 1)
            .0
            .is_err()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, PORT_BASE, 0x14, 0, 11), 2)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, IN, tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 0, 11), 3)
            .0
            .is_err()
    );
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 20, 0), 4)
        .0
        .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 100, 11),
        5
    )
    .0
    .is_err());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 100, 21),
        4 + TCP_TRANSITORY_MS
    )
    .0
    .is_err());
    assert_eq!(t.active_counts(4 + TCP_TRANSITORY_MS), (0, 0));
}

#[test]
fn neighbor_miss_drops_preparation_without_committing_or_mutating() {
    let mut t = Table::<1, 4>::new(config(), 12).unwrap();
    let mut f = udp(LAN, REMOTE, 12345, 53);
    let original = f.clone();
    let prepared = t
        .prepare(OUT, Packet::parse(&mut f, MAC).unwrap(), 0)
        .unwrap();
    assert_eq!(prepared.destination(), REMOTE);
    drop(prepared);
    assert_eq!(f, original);
    assert_eq!(t.active_counts(0), (0, 0));
    assert_eq!(t.generation, 0);
    assert!(send(&mut t, OUT, original, 1).0.is_ok());
    let mut f = udp(REMOTE, WAN, 53, PORT_BASE);
    let original = f.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let prepared = t
        .prepare(IN, Packet::parse(&mut f, MAC).unwrap(), 100)
        .unwrap();
    assert_eq!(prepared.destination(), LAN);
    drop(prepared);
    assert_eq!(f, original);
    assert_eq!(t.mappings, maps);
    assert_eq!(t.flows, flows);
}

#[test]
fn tcp_fin_rst_and_rejected_transition_do_not_extend_flow_lifetime() {
    let mut t = Table::<1, 4>::new(config(), 17).unwrap();
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 10, 0), 0)
        .0
        .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 100, 11),
        1
    )
    .0
    .is_ok());
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 11, 101), 2)
            .0
            .is_ok()
    );
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x11, 11, 101), 3)
            .0
            .is_ok()
    );
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x11, 101, 12),
        4
    )
    .0
    .is_ok());
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 12, 102), 5)
            .0
            .is_ok()
    );
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 20, 0), 6)
        .0
        .is_err());
    assert_eq!(t.active_counts(5 + TCP_TRANSITORY_MS).1, 0);
    // Mapping can outlive its last flow; it must not itself authorize inbound.
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 102, 12),
        5 + TCP_TRANSITORY_MS
    )
    .0
    .is_err());
    assert!(send(
        &mut t,
        OUT,
        tcp(LAN, REMOTE, 100, 80, 2, 20, 0),
        6 + TCP_TRANSITORY_MS
    )
    .0
    .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 200, 21),
        7 + TCP_TRANSITORY_MS
    )
    .0
    .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x14, 201, 21),
        8 + TCP_TRANSITORY_MS
    )
    .0
    .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 201, 21),
        9 + TCP_TRANSITORY_MS
    )
    .0
    .is_err());
}

#[test]
fn bounded_hash_probe_exhaustion_preserves_existing_mappings() {
    let mut t = Table::<32, 128>::new(config(), 91).unwrap();
    let bucket = |port: u16| {
        mix(t.seed ^ u32::from_be_bytes(LAN) as u64 ^ ((port as u64) << 32) ^ (17u64 << 48)) % 32
    };
    let wanted = bucket(1);
    let ports: Vec<u16> = (1..=65535)
        .filter(|p| bucket(*p) == wanted)
        .take(9)
        .collect();
    assert_eq!(ports.len(), 9);
    let mut allocated = Vec::new();
    for port in &ports[..8] {
        let (r, f) = send(&mut t, OUT, udp(LAN, REMOTE, *port, 53), 0);
        assert!(r.is_ok());
        allocated.push(word(&f, 34));
    }
    assert_eq!(
        send(&mut t, OUT, udp(LAN, REMOTE, ports[8], 53), 1).0,
        Err(Error::MappingCapacity)
    );
    assert_eq!(t.active_counts(1), (8, 8));
    for (internal, external) in ports[..8].iter().zip(allocated) {
        let (r, f) = send(&mut t, IN, udp(REMOTE, WAN, 53, external), 2);
        assert!(r.is_ok());
        assert_eq!(word(&f, 36), *internal);
    }
}

#[test]
fn nat_and_two_neighbor_domains_resolve_before_committing_each_direction() {
    use crate::neighbor::{Interface, Resolution, Table as Neighbors};
    let wan_if = Interface {
        mac: MAC,
        ip: WAN,
        prefix: 24,
        gateway: Some(REMOTE),
    };
    let lan_if = Interface {
        mac: [2, 0x42, 0x70, 4, 0, 2],
        ip: config().lan_ip,
        prefix: 24,
        gateway: None,
    };
    let mut wan = Neighbors::<8>::new(wan_if).unwrap();
    let mut lan = Neighbors::<8>::new(lan_if).unwrap();
    let mut t = Table::<1, 4>::new(config(), 9).unwrap();
    let mut outbound = udp(LAN, REMOTE, 12345, 53);
    outbound[..6].copy_from_slice(&lan_if.mac);
    let original = outbound.clone();
    let planned = t
        .prepare(OUT, Packet::parse(&mut outbound, lan_if.mac).unwrap(), 0)
        .unwrap();
    let hop = wan_if.next_hop(planned.destination()).unwrap();
    assert_eq!(wan.resolve(hop, 0), Ok(Resolution::Pending));
    drop(planned);
    assert_eq!(outbound, original);
    assert_eq!(t.active_counts(0), (0, 0));
    // A bounded queue may retain a copy; DMA ownership is not retained while
    // this ordinary ARP request/reply passes through the same RX ring.
    let probe = wan.probe(0).unwrap().unwrap();
    let mut arp = probe.frame();
    probe.sent();
    assert_eq!(crate::arp::reply_in_place(&mut arp, PEER, REMOTE), Some(42));
    assert_eq!(lan.observe(&arp, 1), Ok(false));
    assert_eq!(wan.observe(&arp, 1), Ok(true));
    let Resolution::Reachable(mac) = wan.resolve(hop, 1).unwrap() else {
        panic!("WAN unresolved");
    };
    t.prepare(OUT, Packet::parse(&mut outbound, lan_if.mac).unwrap(), 1)
        .unwrap()
        .forward(Egress {
            source_mac: wan_if.mac,
            destination_mac: mac,
            mtu: 1500,
        })
        .unwrap();
    assert_eq!(&outbound[26..30], &WAN);
    assert_eq!(word(&outbound, 34), PORT_BASE);
    assert_eq!(t.active_counts(1), (1, 1));
    Packet::parse(&mut outbound, PEER).unwrap();

    let mut inbound = udp(REMOTE, WAN, 53, PORT_BASE);
    let original = inbound.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let planned = t
        .prepare(IN, Packet::parse(&mut inbound, wan_if.mac).unwrap(), 2)
        .unwrap();
    let hop = lan_if.next_hop(planned.destination()).unwrap();
    assert_eq!(hop, LAN);
    assert_eq!(lan.resolve(hop, 2), Ok(Resolution::Pending));
    drop(planned);
    assert_eq!(inbound, original);
    assert_eq!(t.mappings, maps);
    assert_eq!(t.flows, flows);
    let probe = lan.probe(2).unwrap().unwrap();
    let mut arp = probe.frame();
    probe.sent();
    let lan_peer = [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    assert_eq!(
        crate::arp::reply_in_place(&mut arp, lan_peer, LAN),
        Some(42)
    );
    assert_eq!(wan.observe(&arp, 3), Ok(false));
    assert_eq!(lan.observe(&arp, 3), Ok(true));
    let Resolution::Reachable(mac) = lan.resolve(hop, 3).unwrap() else {
        panic!("LAN unresolved");
    };
    t.prepare(IN, Packet::parse(&mut inbound, wan_if.mac).unwrap(), 3)
        .unwrap()
        .forward(Egress {
            source_mac: lan_if.mac,
            destination_mac: mac,
            mtu: 1500,
        })
        .unwrap();
    assert_eq!(&inbound[30..34], &LAN);
    assert_eq!(word(&inbound, 36), 12345);
    assert_eq!(&inbound[..6], &lan_peer);
    assert_eq!(&inbound[6..12], &lan_if.mac);
    Packet::parse(&mut inbound, lan_peer).unwrap();
}

fn quoted_error(
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    original: &[u8],
    quote_len: usize,
    kind: u8,
    code: u8,
) -> Vec<u8> {
    let mut f = vec![0; 42 + quote_len];
    f[..6].copy_from_slice(&MAC);
    f[6..12].copy_from_slice(&PEER);
    put(&mut f, 12, 0x800);
    f[14] = 0x45;
    f[22] = 64;
    f[23] = 1;
    put(&mut f, 16, (28 + quote_len) as u16);
    f[26..30].copy_from_slice(&outer_src);
    f[30..34].copy_from_slice(&outer_dst);
    f[34] = kind;
    f[35] = code;
    if kind == 3 && code == 4 {
        put(&mut f, 40, 1400);
    }
    f[42..].copy_from_slice(&original[14..14 + quote_len]);
    fix(&mut f);
    f
}
fn error_send<const M: usize, const F: usize>(
    t: &mut Table<M, F>,
    dir: Direction,
    mut f: Vec<u8>,
    now: u64,
) -> (Result<usize, Error>, Vec<u8>) {
    let original = f.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let result = t
        .prepare_error(
            dir,
            crate::icmp_nat::Packet::parse(&mut f, MAC).unwrap(),
            now,
        )
        .and_then(|p| p.forward(egress()));
    assert_eq!(t.mappings, maps);
    assert_eq!(t.flows, flows);
    if result.is_err() {
        assert_eq!(f, original);
    } else {
        let mut full = f.clone();
        fix(&mut full);
        assert_eq!(f, full);
    }
    (result, f)
}

#[test]
fn icmp_error_nat_both_directions_full_and_minimum_quotes_do_not_refresh_flows() {
    for protocol in [1, 6, 17] {
        for (kind, code) in [(3, 4), (3, 3), (11, 0), (12, 0)] {
            for full in [false, true] {
                let mut t = Table::<1, 8>::new(config(), 1).unwrap();
                let original = frame(
                    protocol,
                    LAN,
                    REMOTE,
                    12345,
                    8080,
                    if protocol == 6 {
                        2
                    } else if protocol == 1 {
                        8
                    } else {
                        0
                    },
                    10,
                    0,
                );
                let (r, translated) = send(&mut t, OUT, original.clone(), 0);
                assert!(r.is_ok());
                let quoted_len = if full {
                    word(&translated, 16) as usize
                } else {
                    28
                };
                // An intermediate WAN router may differ from the remote peer.
                let error = quoted_error(OTHER, WAN, &translated, quoted_len, kind, code);
                let (r, actual) = error_send(&mut t, IN, error, 100);
                assert!(r.is_ok());
                let mut restored = original.clone();
                restored[22] = 63;
                fix(&mut restored);
                let mut expected = quoted_error(OTHER, LAN, &restored, quoted_len, kind, code);
                expected[..6].copy_from_slice(&PEER);
                expected[6..12].copy_from_slice(&MAC);
                expected[22] = 63;
                fix(&mut expected);
                assert_eq!(actual, expected);
                // Quoted reverse packets restore their destination, not source.
                let reply = frame(
                    protocol,
                    REMOTE,
                    WAN,
                    if protocol == 1 { PORT_BASE } else { 8080 },
                    PORT_BASE,
                    if protocol == 6 { 0x12 } else { 0 },
                    100,
                    11,
                );
                let (r, internal) = send(&mut t, IN, reply.clone(), 101);
                assert!(r.is_ok());
                let quoted_len = if full {
                    word(&internal, 16) as usize
                } else {
                    28
                };
                let error = quoted_error(LAN, REMOTE, &internal, quoted_len, kind, code);
                let (r, actual) = error_send(&mut t, OUT, error, 102);
                assert!(r.is_ok());
                let mut restored = reply;
                restored[22] = 63;
                fix(&mut restored);
                let mut expected = quoted_error(WAN, REMOTE, &restored, quoted_len, kind, code);
                expected[..6].copy_from_slice(&PEER);
                expected[6..12].copy_from_slice(&MAC);
                expected[22] = 63;
                fix(&mut expected);
                assert_eq!(actual, expected);
                let expired = if protocol == 1 {
                    60101
                } else if protocol == 6 {
                    240101
                } else {
                    120101
                };
                assert_eq!(t.active_counts(expired), (0, 0));
            }
        }
    }
}

#[test]
fn icmp_errors_cannot_create_refresh_or_borrow_a_different_remote_permission() {
    let mut t = Table::<1, 4>::new(config(), 7).unwrap();
    let trigger = udp(WAN, REMOTE, PORT_BASE, 53);
    assert!(
        error_send(&mut t, IN, quoted_error(OTHER, WAN, &trigger, 28, 11, 0), 0)
            .0
            .is_err()
    );
    let (_, translated) = send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 1);
    let valid = quoted_error(OTHER, WAN, &translated, 28, 11, 0);
    for offset in [26, 30, 54, 58, 62, 64] {
        let mut bad = valid.clone();
        bad[offset] ^= 1;
        // Repair quote IP and outer ICMP checksums so rejection exercises policy.
        put(&mut bad, 52, 0);
        let c = checksum(&bad[42..62]);
        put(&mut bad, 52, c);
        fix(&mut bad);
        if offset == 26 {
            // Another routable intermediate source remains valid.
            assert!(error_send(&mut t, IN, bad, 2).0.is_ok());
        } else {
            assert!(error_send(&mut t, IN, bad, 2).0.is_err(), "offset {offset}");
        }
    }
    assert!(error_send(&mut t, IN, valid.clone(), 120000).0.is_ok());
    assert!(error_send(&mut t, IN, valid, 120001).0.is_err());
}

#[test]
fn icmp_quote_parser_rejects_damage_options_fragments_extensions_and_short_quotes() {
    use crate::icmp_nat::Packet as ErrorPacket;
    let original = udp(WAN, REMOTE, PORT_BASE, 53);
    let valid = quoted_error(OTHER, WAN, &original, 28, 11, 0);
    for length in 0..valid.len() {
        let mut f = valid[..length].to_vec();
        let before = f.clone();
        assert!(ErrorPacket::parse(&mut f, MAC).is_err());
        assert_eq!(f, before);
    }
    for offset in [0, 6, 12, 14, 16, 20, 24, 34, 35, 36, 39, 42, 48, 52, 62] {
        let mut f = valid.clone();
        f[offset] ^= 0xff;
        // Force later gates for malformed quotes and extension headers.
        if matches!(offset, 39 | 42 | 48 | 52) {
            fix(&mut f);
        }
        let before = f.clone();
        assert!(ErrorPacket::parse(&mut f, MAC).is_err(), "offset {offset}");
        assert_eq!(f, before);
    }
}

#[test]
fn icmp_quote_preserves_disabled_udp_and_adjusts_damaged_or_partial_checksums() {
    let mut t = Table::<1, 4>::new(config(), 0).unwrap();
    let (_, mut translated) = send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 0);
    for old in [0, 0x1234] {
        put(&mut translated, 40, old); // Deliberately damaged quoted transport.
        let error = quoted_error(OTHER, WAN, &translated, 28, 11, 0);
        let (r, actual) = error_send(&mut t, IN, error, 1);
        assert!(r.is_ok());
        if old == 0 {
            assert_eq!(word(&actual, 68), 0);
        } else {
            assert_ne!(word(&actual, 68), old);
        }
    }
    let mut t = Table::<1, 4>::new(config(), 0).unwrap();
    let (_, translated) = send(&mut t, OUT, tcp(LAN, REMOTE, 100, 53, 2, 10, 0), 0);
    for bytes in [8, 16, 18, 19, 20] {
        let error = quoted_error(OTHER, WAN, &translated, 20 + bytes, 11, 0);
        assert!(error_send(&mut t, IN, error, 1).0.is_ok());
    }
    let mut half = quoted_error(OTHER, WAN, &translated, 37, 11, 0);
    assert!(crate::icmp_nat::Packet::parse(&mut half, MAC).is_err());
}

#[test]
fn icmp_error_forward_failure_and_dropped_authorization_leave_everything_unchanged() {
    let mut t = Table::<1, 4>::new(config(), 0).unwrap();
    let (_, translated) = send(&mut t, OUT, udp(LAN, REMOTE, 100, 53), 10);
    let mut valid = quoted_error(OTHER, WAN, &translated, 28, 11, 0);
    let original = valid.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let prepared = t
        .prepare_error(
            IN,
            crate::icmp_nat::Packet::parse(&mut valid, MAC).unwrap(),
            20,
        )
        .unwrap();
    assert_eq!(prepared.destination(), LAN);
    drop(prepared);
    assert_eq!(valid, original);
    assert_eq!(t.mappings, maps);
    assert_eq!(t.flows, flows);
    assert_eq!(t.last_now, 10);
    let mut small = egress();
    small.mtu = 40;
    assert!(t
        .prepare_error(
            IN,
            crate::icmp_nat::Packet::parse(&mut valid, MAC).unwrap(),
            20
        )
        .unwrap()
        .forward(small)
        .is_err());
    assert_eq!(valid, original);
    assert_eq!(t.last_now, 10);
    valid[22] = 1;
    fix(&mut valid);
    assert_eq!(
        error_send(&mut t, IN, valid, 20).0,
        Err(Error::Packet(ipv4::Error::TtlExpired))
    );
    assert_eq!(t.last_now, 10);
    assert_eq!(error_send(&mut t, IN, original, 9).0, Err(Error::Clock));
}

#[test]
fn icmp_quoted_echo_checksum_zero_is_valid_after_translation() {
    let mut t = Table::<1, 4>::new(config(), 0).unwrap();
    let mut request = frame(1, LAN, REMOTE, 0xf7ff, 0, 8, 0, 0);
    put(&mut request, 40, 0);
    fix(&mut request);
    assert_eq!(word(&request, 36), 0);
    let (r, translated) = send(&mut t, OUT, request, 0);
    assert!(r.is_ok());
    let (r, actual) = error_send(
        &mut t,
        IN,
        quoted_error(OTHER, WAN, &translated, 28, 11, 0),
        1,
    );
    assert!(r.is_ok());
    assert_eq!(word(&actual, 66), 0xf7ff);
    assert_eq!(checksum(&actual[62..70]), 0);
    assert_eq!(word(&actual, 64), 65535); // Equivalent one's-complement zero.
}

#[test]
fn established_window_rejections_preserve_packet_flow_phase_and_timeout() {
    let mut t = Table::<1, 4>::new(config(), 0).unwrap();
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 1000, 0), 0)
        .0
        .is_ok());
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 9000, 1001),
        1
    )
    .0
    .is_ok());
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 1001, 9001), 2)
            .0
            .is_ok()
    );
    for (seq, ack, flags) in [
        (1001 + 32769, 9001, 0x10),
        (1001, 9002, 0x10),
        (1002, 9001, 0x14),
        (1001, 9000, 0x10),
    ] {
        assert_eq!(
            send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, flags, seq, ack), 3).0,
            Err(Error::Denied)
        );
    }
    // Guessed RST did not close the flow, and a duplicate valid ACK still works.
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 1001, 9001), 4)
            .0
            .is_ok()
    );
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 80, PORT_BASE, 0x14, 9001, 1001),
        5
    )
    .0
    .is_ok());
    assert!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 1001, 9001), 6)
            .0
            .is_err()
    );
}

fn establish_peer(t: &mut Table<1, 8>, remote_port: u16, now: u64) {
    assert!(
        send(t, OUT, tcp(LAN, REMOTE, 100, remote_port, 2, 10, 0), now)
            .0
            .is_ok()
    );
    assert!(send(
        t,
        IN,
        tcp(REMOTE, WAN, remote_port, PORT_BASE, 0x12, 100, 11),
        now + 1
    )
    .0
    .is_ok());
    assert!(send(
        t,
        OUT,
        tcp(LAN, REMOTE, 100, remote_port, 0x10, 11, 101),
        now + 2
    )
    .0
    .is_ok());
}

#[test]
fn tcp_teardown_reclaims_mapping_without_waiting_for_established_timeout() {
    for (flags, timeout) in [(0x14, TCP_CLOSED_MS), (0x11, TCP_TRANSITORY_MS)] {
        let mut t = Table::<1, 8>::new(config(), 17).unwrap();
        establish_peer(&mut t, 80, 0);
        assert!(
            send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, flags, 11, 101), 3)
                .0
                .is_ok()
        );
        assert_eq!(t.active_counts(3 + timeout - 1), (1, 1));
        assert_eq!(t.active_counts(3 + timeout), (0, 0));
        assert!(send(
            &mut t,
            OUT,
            tcp(LAN, REMOTE, 101, 81, 2, 500, 0),
            3 + timeout
        )
        .0
        .is_ok());
        assert!(send(
            &mut t,
            IN,
            tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 101, 11),
            4 + timeout
        )
        .0
        .is_err());
    }
}

#[test]
fn tcp_teardown_preserves_other_remote_and_failed_forward_is_transactional() {
    let mut t = Table::<1, 8>::new(config(), 17).unwrap();
    establish_peer(&mut t, 80, 0);
    establish_peer(&mut t, 81, 3);
    let mut rst = tcp(LAN, REMOTE, 100, 80, 0x14, 11, 101);
    let original = rst.clone();
    let maps = t.mappings;
    let flows = t.flows;
    let prepared = t
        .prepare(OUT, Packet::parse(&mut rst, MAC).unwrap(), 6)
        .unwrap();
    assert!(prepared
        .forward(Egress {
            mtu: 20,
            ..egress()
        })
        .is_err());
    assert_eq!(rst, original);
    assert_eq!(t.mappings, maps);
    assert_eq!(t.flows, flows);
    assert!(send(&mut t, OUT, rst, 7).0.is_ok());
    assert_eq!(t.active_counts(7 + TCP_CLOSED_MS), (1, 1));
    assert!(send(
        &mut t,
        IN,
        tcp(REMOTE, WAN, 81, PORT_BASE, 0x10, 101, 11),
        7 + TCP_CLOSED_MS
    )
    .0
    .is_ok());
    assert!(send(
        &mut t,
        OUT,
        tcp(LAN, REMOTE, 100, 81, 0x14, 11, 101),
        8 + TCP_CLOSED_MS
    )
    .0
    .is_ok());
    assert_eq!(t.active_counts(8 + 2 * TCP_CLOSED_MS), (0, 0));
}

fn permit<const M: usize, const F: usize>(
    table: &mut Table<M, F>,
    direction: Direction,
    mut bytes: Vec<u8>,
    now: u64,
) -> (UdpPermit, Vec<u8>) {
    let (length, receipt) = table
        .prepare(direction, Packet::parse(&mut bytes, MAC).unwrap(), now)
        .unwrap()
        .forward_with_udp_permit(egress())
        .unwrap();
    assert_eq!(length, 42);
    (receipt.unwrap(), bytes)
}

#[test]
fn udp_permits_match_committed_bytes_and_are_direction_specific() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let (out, bytes) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 10);
    assert_eq!(
        out.original(),
        UdpTuple {
            source: LAN,
            destination: REMOTE,
            source_port: 12345,
            destination_port: 53
        }
    );
    assert_eq!(
        out.translated(),
        UdpTuple {
            source: WAN,
            destination: REMOTE,
            source_port: PORT_BASE,
            destination_port: 53
        }
    );
    assert_eq!(&bytes[26..30], &out.translated().source);
    assert_eq!(word(&bytes, 34), out.translated().source_port);
    assert_eq!(out.expires_at(), 120010);
    assert!(table.validate_udp_permit(&out, OUT, 10));
    assert!(!table.validate_udp_permit(&out, IN, 10));
    assert!(!table.validate_udp_permit(&out, OUT, 9));
    let (incoming, bytes) = permit(&mut table, IN, udp(REMOTE, WAN, 53, PORT_BASE), 20);
    assert_eq!(
        incoming.original(),
        UdpTuple {
            source: REMOTE,
            destination: WAN,
            source_port: 53,
            destination_port: PORT_BASE
        }
    );
    assert_eq!(
        incoming.translated(),
        UdpTuple {
            source: REMOTE,
            destination: LAN,
            source_port: 53,
            destination_port: 12345
        }
    );
    assert_eq!(&bytes[30..34], &incoming.translated().destination);
    assert_eq!(word(&bytes, 36), incoming.translated().destination_port);
    assert!(table.validate_udp_permit(&incoming, IN, 20));
    assert!(!table.validate_udp_permit(&incoming, OUT, 20));
    // A later packet refreshed software state, never this copied receipt.
    assert!(table.validate_udp_permit(&out, OUT, 120009));
    assert!(!table.validate_udp_permit(&out, OUT, 120010));
    assert!(table.validate_udp_permit(&incoming, IN, 120010));
    assert!(!table.validate_udp_permit(&out, OUT, 10)); // clock rollback
}

#[test]
fn udp_receipts_do_not_cross_owners_reconfiguration_or_slot_reuse() {
    let mut first = Table::<1, 8>::new(config(), 42).unwrap();
    let mut second = Table::<1, 8>::new(config(), 42).unwrap();
    let (old, _) = permit(&mut first, OUT, udp(LAN, REMOTE, 12345, 53), 1);
    let (other_owner, _) = permit(&mut second, OUT, udp(LAN, REMOTE, 12345, 53), 1);
    assert!(!second.validate_udp_permit(&old, OUT, 1));
    assert!(!first.validate_udp_permit(&other_owner, OUT, 1));
    first.reconfigure(config()).unwrap();
    assert!(!first.validate_udp_permit(&old, OUT, 2));
    let (new, _) = permit(&mut first, OUT, udp(LAN, REMOTE, 12345, 53), 2);
    assert_eq!(new.translated(), old.translated());
    assert!(!first.validate_udp_permit(&old, OUT, 2));
    assert!(first.validate_udp_permit(&new, OUT, 2));
    let (reuse, _) = permit(&mut first, OUT, udp(LAN, OTHER, 34567, 8080), 120002);
    assert_eq!(reuse.translated().source_port, old.translated().source_port);
    assert!(!first.validate_udp_permit(&new, OUT, 120002));
    assert!(first.validate_udp_permit(&reuse, OUT, 120002));
}

#[test]
fn another_remote_cannot_extend_a_udp_permit() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let (old, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 1);
    let (other, _) = permit(&mut table, OUT, udp(LAN, OTHER, 12345, 53), 60_001);
    assert_eq!(table.active_counts(120001), (1, 1));
    assert!(!table.validate_udp_permit(&old, OUT, 120001));
    assert!(table.validate_udp_permit(&other, OUT, 120001));
    assert_eq!(old.original().destination, REMOTE);
    assert_eq!(other.original().destination, OTHER);
    assert!(table
        .prepare(
            IN,
            Packet::parse(&mut udp(REMOTE, WAN, 53, PORT_BASE), MAC).unwrap(),
            120001
        )
        .is_err());
}

#[test]
fn failed_or_abandoned_forward_cannot_issue_or_refresh_udp_permit() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let mut bytes = udp(LAN, REMOTE, 12345, 53);
    let original = bytes.clone();
    let prepared = table
        .prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 1)
        .unwrap();
    drop(prepared);
    assert_eq!(table.active_counts(1), (0, 0));
    let result = table
        .prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 1)
        .unwrap()
        .forward_with_udp_permit(Egress {
            mtu: 27,
            ..egress()
        });
    assert!(result.is_err());
    assert_eq!(bytes, original);
    assert_eq!(table.active_counts(1), (0, 0));
    let (old, _) = permit(&mut table, OUT, original.clone(), 1);
    let result = table
        .prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 60_001)
        .unwrap()
        .forward_with_udp_permit(Egress {
            mtu: 27,
            ..egress()
        });
    assert!(result.is_err());
    assert_eq!(bytes, original);
    assert!(!table.validate_udp_permit(&old, OUT, 120001));
    assert_eq!(table.active_counts(120001), (0, 0));
}

#[test]
fn tcp_and_icmp_commits_never_issue_udp_permits() {
    for mut bytes in [
        frame(6, LAN, REMOTE, 12345, 80, 2, 100, 0),
        frame(1, LAN, REMOTE, 12345, 0, 8, 0, 0),
    ] {
        let mut table = Table::<1, 8>::new(config(), 42).unwrap();
        let (_, receipt) = table
            .prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 1)
            .unwrap()
            .forward_with_udp_permit(egress())
            .unwrap();
        assert!(receipt.is_none());
        assert_eq!(table.active_counts(1), (1, 1));
    }
}

#[test]
fn permitted_udp_fast_forward_matches_commit_without_extending_authority() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let (out, expected_out) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 10);
    let (incoming, expected_in) = permit(&mut table, IN, udp(REMOTE, WAN, 53, PORT_BASE), 20);
    let state = (table.mappings, table.flows, table.generation, table.last_now);
    for now in [21, 60_000, 120_009] {
        for (receipt, direction, mut bytes, expected) in [
            (out, OUT, udp(LAN, REMOTE, 12345, 53), &expected_out),
            (incoming, IN, udp(REMOTE, WAN, 53, PORT_BASE), &expected_in),
        ] {
            let packet = Packet::parse(&mut bytes, MAC).unwrap();
            assert_eq!(table.forward_permitted_udp(&receipt, direction, packet, egress(), now), Ok(42));
            assert_eq!(&bytes, expected);
            assert_eq!((table.mappings, table.flows, table.generation, table.last_now), state);
        }
    }
    let mut bytes = udp(LAN, REMOTE, 12345, 53);
    let original = bytes.clone();
    assert_eq!(table.forward_permitted_udp(&out, OUT, Packet::parse(&mut bytes, MAC).unwrap(), egress(), out.expires_at()), Err(Error::Denied));
    assert_eq!(bytes, original);
    assert_eq!((table.mappings, table.flows, table.generation, table.last_now), state);
    assert_eq!(table.active_counts(incoming.expires_at()), (0, 0));
}

#[test]
fn permitted_udp_rejects_other_tuple_direction_owner_and_packet_errors_atomically() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 10);
    let (receipt, _) = permit(&mut table, IN, udp(REMOTE, WAN, 53, PORT_BASE), 20);
    let state = (table.mappings, table.flows, table.generation, table.last_now);
    for mut bytes in [
        udp(OTHER, WAN, 53, PORT_BASE),
        udp(REMOTE, OTHER, 53, PORT_BASE),
        udp(REMOTE, WAN, 54, PORT_BASE),
        udp(REMOTE, WAN, 53, PORT_BASE + 1),
        frame(6, REMOTE, WAN, 53, PORT_BASE, 2, 1, 0),
    ] {
        let original = bytes.clone();
        assert_eq!(table.forward_permitted_udp(&receipt, IN, Packet::parse(&mut bytes, MAC).unwrap(), egress(), 21), Err(Error::Denied));
        assert_eq!(bytes, original);
    }
    for direction in [OUT, IN] {
        let mut bytes = udp(REMOTE, WAN, 53, PORT_BASE);
        let original = bytes.clone();
        let other = Table::<1, 8>::new(config(), 42).unwrap();
        let owner = if direction == OUT { &table } else { &other };
        assert_eq!(owner.forward_permitted_udp(&receipt, direction, Packet::parse(&mut bytes, MAC).unwrap(), egress(), 21), Err(Error::Denied));
        assert_eq!(bytes, original);
    }
    let mut bytes = udp(REMOTE, WAN, 53, PORT_BASE);
    bytes[22] = 1; fix(&mut bytes);
    let original = bytes.clone();
    assert_eq!(table.forward_permitted_udp(&receipt, IN, Packet::parse(&mut bytes, MAC).unwrap(), egress(), 21), Err(Error::Packet(ipv4::Error::TtlExpired)));
    assert_eq!(bytes, original);
    let mut bytes = udp(REMOTE, WAN, 53, PORT_BASE);
    let original = bytes.clone();
    assert!(matches!(table.forward_permitted_udp(&receipt, IN, Packet::parse(&mut bytes, MAC).unwrap(), Egress { mtu: 27, ..egress() }, 21), Err(Error::Packet(ipv4::Error::Mtu { .. }))));
    assert_eq!(bytes, original);
    assert_eq!((table.mappings, table.flows, table.generation, table.last_now), state);
}

#[test]
fn forward_cache_bounds_replacement_and_preserves_receipts() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let (a, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 10);
    let (b, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 54), 11);
    let (fresh_a, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 12);
    let (c, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 55), 13);
    let mut cache = UdpForwardCache::<2>::new();
    cache.remember(a, egress());
    cache.remember(b, egress());
    cache.remember(fresh_a, egress());
    assert_eq!(cache.lookup(OUT, a.original()).map(|(receipt, _)| receipt), Some(fresh_a));
    assert_eq!(cache.lookup(OUT, b.original()).map(|(receipt, _)| receipt), Some(b));
    assert_eq!(cache.lookup(IN, a.original()).map(|(receipt, _)| receipt), None);
    cache.remember(c, egress());
    assert_eq!(cache.lookup(OUT, a.original()).map(|(receipt, _)| receipt), None);
    assert_eq!(cache.lookup(OUT, b.original()).map(|(receipt, _)| receipt), Some(b));
    assert_eq!(cache.lookup(OUT, c.original()).map(|(receipt, _)| receipt), Some(c));
    cache.forget(IN, b.original());
    assert_eq!(cache.lookup(OUT, b.original()).map(|(receipt, _)| receipt), Some(b));
    cache.forget(OUT, b.original());
    assert_eq!(cache.lookup(OUT, b.original()).map(|(receipt, _)| receipt), None);
    assert_eq!(cache.lookup(OUT, c.original()).map(|(receipt, _)| receipt), Some(c));
    cache.clear();
    assert_eq!(cache.lookup(OUT, b.original()).map(|(receipt, _)| receipt), None);
    assert_eq!(cache.lookup(OUT, c.original()).map(|(receipt, _)| receipt), None);
    let mut empty = UdpForwardCache::<0>::new();
    empty.remember(a, egress());
    assert_eq!(empty.lookup(OUT, a.original()).map(|(receipt, _)| receipt), None);
}

#[test]
fn forward_cache_reuses_forgotten_slots_without_evicting_survivors() {
    for direction in [OUT, IN] {
        let mut table = Table::<1, 8>::new(config(), 42).unwrap();
        let mut receipts = Vec::new();
        for port in 53..57 {
            receipts.push(permit(&mut table, OUT, udp(LAN, REMOTE, 12345, port), port as u64).0);
        }
        if direction == IN {
            receipts.clear();
            for port in 53..57 {
                receipts.push(permit(&mut table, IN, udp(REMOTE, WAN, port, PORT_BASE), 100 + port as u64).0);
            }
        }
        for hole in 0..3 {
            let mut cache = UdpForwardCache::<3>::new();
            for receipt in &receipts[..3] { cache.remember(*receipt, egress()); }
            cache.forget(direction, receipts[hole].original());
            cache.remember(receipts[3], egress());
            for (index, receipt) in receipts.iter().enumerate() {
                assert_eq!(cache.lookup(direction, receipt.original()).map(|(permit, _)| permit),
                    (index != hole).then_some(*receipt),
                    "direction={direction:?} forgotten slot={hole} flow={index}");
            }
        }
    }
}

#[test]
fn forward_cache_updates_existing_receipt_past_a_hole_without_duplication() {
    let mut table = Table::<1, 8>::new(config(), 42).unwrap();
    let (a, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 53), 10);
    let (b, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 54), 11);
    let (c, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 55), 12);
    let (d, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 56), 13);
    let (fresh_c, _) = permit(&mut table, OUT, udp(LAN, REMOTE, 12345, 55), 20);
    let mut cache = UdpForwardCache::<3>::new();
    for receipt in [a, b, c] { cache.remember(receipt, egress()); }
    cache.forget(OUT, a.original());
    cache.remember(fresh_c, egress());
    cache.remember(d, egress());
    assert!(cache.lookup(OUT, a.original()).is_none());
    for receipt in [b, fresh_c, d] {
        assert_eq!(cache.lookup(OUT, receipt.original()).map(|(permit, _)| permit), Some(receipt));
    }
}

fn tcp_receipt(t: &mut Table<1, 8>, port: u16, now: u64) -> TcpPermit {
    let mut bytes = tcp(LAN, REMOTE, 100, port, 0x10, 11, 101);
    t.prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), now)
        .unwrap()
        .forward_with_tcp_permit(egress())
        .unwrap()
        .1
        .unwrap()
}

#[test]
fn tcp_handoff_is_explicit_scoped_and_control_revokes_receipt() {
    for flags in [0x11, 0x14] {
        let mut t = Table::<1, 8>::new(config(), 0).unwrap();
        establish_peer(&mut t, 80, 0);
        establish_peer(&mut t, 81, 3);
        let p = tcp_receipt(&mut t, 80, 6);
        assert_eq!(p.original().source, LAN);
        assert_eq!(p.translated().source, WAN);
        assert!(t.validate_tcp_permit(&p, OUT, 6));
        assert!(!t.enable_tcp_offload(&p, IN, 6));
        assert!(!t.enable_tcp_offload(&p, OUT, 5));
        // Receipt creation alone preserves strict observed windows.
        assert!(
            send(
                &mut t,
                OUT,
                tcp(LAN, REMOTE, 100, 80, flags, 90000, 80000),
                7
            )
            .0
            .is_err()
        );
        let expiry = p.expires_at();
        assert!(t.enable_tcp_offload(&p, OUT, 7));
        assert_eq!(p.expires_at(), expiry);
        // Another peer sharing the mapping remains strict.
        assert!(
            send(
                &mut t,
                OUT,
                tcp(LAN, REMOTE, 100, 81, flags, 90000, 80000),
                8
            )
            .0
            .is_err()
        );
        let mut bytes = tcp(LAN, REMOTE, 100, 80, flags, 90000, 80000);
        assert!(
            t.prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 8)
                .unwrap()
                .forward_with_tcp_permit(egress())
                .unwrap()
                .1
                .is_none()
        );
        assert!(!t.validate_tcp_permit(&p, OUT, 8));
        assert!(!t.enable_tcp_offload(&p, OUT, 8));
    }
}

#[test]
fn tcp_receipt_cannot_revive_after_same_mapping_reopen() {
    let mut t = Table::<1, 8>::new(config(), 0).unwrap();
    establish_peer(&mut t, 80, 0);
    let old = tcp_receipt(&mut t, 80, 3);
    assert!(t.enable_tcp_offload(&old, OUT, 3));
    assert!(
        send(
            &mut t,
            OUT,
            tcp(LAN, REMOTE, 100, 80, 0x14, 99999, 88888),
            4
        )
        .0
        .is_ok()
    );
    let generation = t.generation;
    establish_peer(&mut t, 80, 5);
    let new = tcp_receipt(&mut t, 80, 8);
    assert_eq!(t.generation, generation);
    assert_ne!(old, new);
    assert!(!t.validate_tcp_permit(&old, OUT, 8));
    assert!(t.validate_tcp_permit(&new, OUT, 8));
    assert!(
        send(
            &mut t,
            OUT,
            tcp(LAN, REMOTE, 100, 80, 0x10, 99999, 88888),
            9
        )
        .0
        .is_err()
    );
    assert!(!t.validate_tcp_permit(&new, OUT, new.expires_at()));
    let other = Table::<1, 8>::new(config(), 0).unwrap();
    assert!(!other.validate_tcp_permit(&new, OUT, 8));
    t.reconfigure(config()).unwrap();
    assert!(!t.validate_tcp_permit(&new, OUT, 8));
}

#[test]
fn tcp_incarnation_exhaustion_and_failed_rewrite_are_transactional() {
    let mut t = Table::<1, 8>::new(config(), 0).unwrap();
    t.tcp_sequence = u64::MAX;
    assert_eq!(
        send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 2, 10, 0), 0).0,
        Err(Error::GenerationExhausted)
    );
    t.tcp_sequence = 0;
    let mut bytes = tcp(LAN, REMOTE, 100, 80, 2, 10, 0);
    let original = bytes.clone();
    let mut bad = egress();
    bad.mtu = 1;
    assert!(
        t.prepare(OUT, Packet::parse(&mut bytes, MAC).unwrap(), 0)
            .unwrap()
            .forward_with_tcp_permit(bad)
            .is_err()
    );
    assert_eq!(bytes, original);
    assert_eq!(t.tcp_sequence, 0);
    assert_eq!(t.active_counts(0), (0, 0));
}

#[test]
fn tcp_handshake_receipts_only_start_with_committed_establishment() {
    let mut t = Table::<1, 8>::new(config(), 0).unwrap();
    for (now, direction, mut bytes, eligible) in [
        (0, OUT, tcp(LAN, REMOTE, 100, 80, 2, 10, 0), false),
        (1, IN, tcp(REMOTE, WAN, 80, PORT_BASE, 0x12, 100, 11), false),
        (2, OUT, tcp(LAN, REMOTE, 100, 80, 0x10, 11, 101), true),
        (3, IN, tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 101, 11), true),
    ] {
        let receipt = t
            .prepare(direction, Packet::parse(&mut bytes, MAC).unwrap(), now)
            .unwrap()
            .forward_with_tcp_permit(egress())
            .unwrap()
            .1;
        assert_eq!(receipt.is_some(), eligible);
        if let Some(p) = receipt {
            assert!(t.validate_tcp_permit(&p, direction, now));
            assert_eq!(p.direction(), direction);
        }
    }
}


#[test]
fn tcp_receipt_fallback_matches_slow_translation_without_refresh() {
    for direction in [OUT, IN] {
        let mut t = Table::<1, 8>::new(config(), 0).unwrap();
        establish_peer(&mut t, 80, 0);
        let mut bytes = if direction == OUT { tcp(LAN, REMOTE, 100, 80, 0x10, 11, 101) }
            else { tcp(REMOTE, WAN, 80, PORT_BASE, 0x10, 101, 11) };
        let receipt = t.prepare(direction, Packet::parse(&mut bytes, MAC).unwrap(), 3)
            .unwrap().forward_with_tcp_permit(egress()).unwrap().1.unwrap();
        let original = if direction == OUT { tcp(LAN, REMOTE, 100, 80, 0x18, 90000, 80000) }
            else { tcp(REMOTE, WAN, 80, PORT_BASE, 0x18, 80000, 90000) };
        let mut fast = original.clone();
        assert!(t.forward_permitted_tcp(&receipt, direction, Packet::parse(&mut fast, MAC).unwrap(), egress(), 4).is_err());
        assert_eq!(fast, original);
        assert!(t.enable_tcp_offload(&receipt, direction, 4));
        let before = (t.mappings, t.flows, t.last_now, t.generation, t.tcp_sequence);
        let n = t.forward_permitted_tcp(&receipt, direction, Packet::parse(&mut fast, MAC).unwrap(), egress(), 5).unwrap();
        assert_eq!((t.mappings, t.flows, t.last_now, t.generation, t.tcp_sequence), before);
        let (result, slow) = send(&mut t, direction, original.clone(), 5);
        assert_eq!(result.unwrap(), n);
        assert_eq!(fast, slow);
        let mut expired = original.clone();
        assert!(t.forward_permitted_tcp(&receipt, direction, Packet::parse(&mut expired, MAC).unwrap(), egress(), receipt.expires_at()).is_err());
        assert_eq!(expired, original);
    }
}

#[test]
fn tcp_receipt_fallback_defers_control_malformed_and_wrong_tuple_without_changes() {
    let mut t = Table::<1, 8>::new(config(), 0).unwrap();
    establish_peer(&mut t, 80, 0);
    let p = tcp_receipt(&mut t, 80, 3);
    assert!(t.enable_tcp_offload(&p, OUT, 3));
    let mut cases = Vec::new();
    for flags in [0, 8, 2, 0x12, 0x11, 0x14, 0x17] {
        cases.push(tcp(LAN, REMOTE, 100, 80, flags, 90000, 80000));
    }
    cases.push(tcp(LAN, REMOTE, 100, 81, 0x10, 90000, 80000));
    cases.push(udp(LAN, REMOTE, 100, 80));
    let mut options = tcp(LAN, REMOTE, 100, 80, 0x10, 90000, 80000);
    options[46] = 0x60;
    options.splice(54..54, [3, 1, 0, 0]);
    let total = options.len() - 14;
    put(&mut options, 16, total as u16);
    fix(&mut options);
    cases.push(options);
    let state = (t.mappings, t.flows, t.last_now);
    for original in cases {
        let mut frame = original.clone();
        assert!(t.forward_permitted_tcp(&p, OUT, Packet::parse(&mut frame, MAC).unwrap(), egress(), 4).is_err());
        assert_eq!(frame, original);
        assert_eq!((t.mappings, t.flows, t.last_now), state);
    }
    // Closure, even with a reused tuple later, cannot retain fallback authority.
    assert!(send(&mut t, OUT, tcp(LAN, REMOTE, 100, 80, 0x14, 90000, 80000), 4).0.is_ok());
    establish_peer(&mut t, 80, 5);
    let original = tcp(LAN, REMOTE, 100, 80, 0x10, 11, 101);
    let mut frame = original.clone();
    assert!(t.forward_permitted_tcp(&p, OUT, Packet::parse(&mut frame, MAC).unwrap(), egress(), 8).is_err());
    assert_eq!(frame, original);
}

fn incoming_tcp_receipt(t: &mut Table<1, 8>, port: u16, now: u64) -> TcpPermit {
    let mut bytes = tcp(REMOTE, WAN, port, PORT_BASE, 0x10, 101, 11);
    t.prepare(IN, Packet::parse(&mut bytes, MAC).unwrap(), now)
        .unwrap().forward_with_tcp_permit(egress()).unwrap().1.unwrap()
}

#[test]
fn tcp_pair_rejects_mixed_peers_directions_tables_and_time_without_mutation() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    establish_peer(&mut t,80,0);establish_peer(&mut t,81,3);
    let a=tcp_receipt(&mut t,80,6);let b=incoming_tcp_receipt(&mut t,80,7);
    let c=tcp_receipt(&mut t,81,8);let d=incoming_tcp_receipt(&mut t,81,9);
    let mut other=Table::<1,8>::new(config(),0).unwrap();
    establish_peer(&mut other,80,0);let foreign=incoming_tcp_receipt(&mut other,80,3);
    let before=(t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence);
    for (incoming,outgoing) in [(b,c),(d,a),(a,b),(a,a),(b,b),(foreign,a)] {
        assert!(t.tcp_permit_pair(incoming,outgoing,9).is_none());
        assert_eq!((t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence),before);
    }
    let pair=t.tcp_permit_pair(b,a,9).unwrap();
    assert_eq!(pair.permits(),[b,a]);
    assert_eq!(pair.expires_at(),a.expires_at().min(b.expires_at()));
    for now in [8,pair.expires_at()] {
        assert!(!t.enable_tcp_pair(&pair,now));
        assert_eq!((t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence),before);
    }
    assert!(!other.validate_tcp_pair(&pair,9));
}

#[test]
fn tcp_pair_handoff_is_explicit_and_either_direction_control_revokes_both() {
    for direction in [IN,OUT] { for flags in [0x11,0x14] {
        let mut t=Table::<1,8>::new(config(),0).unwrap();
        establish_peer(&mut t,80,0);establish_peer(&mut t,81,3);
        let outgoing=tcp_receipt(&mut t,80,6);let incoming=incoming_tcp_receipt(&mut t,80,7);
        let pair=t.tcp_permit_pair(incoming,outgoing,7).unwrap();
        let control=if direction==OUT {tcp(LAN,REMOTE,100,80,flags,90000,80000)}
            else {tcp(REMOTE,WAN,80,PORT_BASE,flags,80000,90000)};
        assert!(send(&mut t,direction,control.clone(),8).0.is_err());
        let expiry=pair.expires_at();assert!(t.enable_tcp_pair(&pair,8));
        assert!(t.tcp_offload_enabled(&incoming,IN,8));
        assert!(t.tcp_offload_enabled(&outgoing,OUT,8));
        assert_eq!(pair.expires_at(),expiry);
        let other=if direction==OUT {tcp(LAN,REMOTE,100,81,flags,90000,80000)}
            else {tcp(REMOTE,WAN,81,PORT_BASE,flags,80000,90000)};
        assert!(send(&mut t,direction,other,9).0.is_err());
        assert!(send(&mut t,direction,control,9).0.is_ok());
        assert!(!t.validate_tcp_pair(&pair,9));
        assert!(!t.validate_tcp_permit(&incoming,IN,9));
        assert!(!t.validate_tcp_permit(&outgoing,OUT,9));
        let before=(t.mappings,t.flows,t.last_now);
        assert!(!t.enable_tcp_pair(&pair,9));
        assert_eq!((t.mappings,t.flows,t.last_now),before);
    }}
}

#[test]
fn tcp_pair_cannot_cross_reopen_or_reconfiguration() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    establish_peer(&mut t,80,0);
    let a=tcp_receipt(&mut t,80,3);let b=incoming_tcp_receipt(&mut t,80,4);
    let old=t.tcp_permit_pair(b,a,4).unwrap();assert!(t.enable_tcp_pair(&old,5));
    assert!(send(&mut t,OUT,tcp(LAN,REMOTE,100,80,0x14,90000,80000),6).0.is_ok());
    establish_peer(&mut t,80,7);
    let a2=tcp_receipt(&mut t,80,10);let b2=incoming_tcp_receipt(&mut t,80,11);
    assert!(t.tcp_permit_pair(b,a2,11).is_none());
    assert!(t.tcp_permit_pair(b2,a,11).is_none());
    assert!(!t.enable_tcp_pair(&old,11));
    let new=t.tcp_permit_pair(b2,a2,11).unwrap();assert_ne!(old,new);
    assert!(send(&mut t,OUT,tcp(LAN,REMOTE,100,80,0x10,90000,80000),12).0.is_err());
    t.reconfigure(config()).unwrap();assert!(!t.enable_tcp_pair(&new,12));
}

#[test]
fn tcp_cache_update_after_hole_preserves_other_peers_and_bounded_eviction() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    for (i,port) in [80,81,82,83].into_iter().enumerate() {establish_peer(&mut t,port,i as u64*3);}
    let a=tcp_receipt(&mut t,80,12);let b=tcp_receipt(&mut t,81,13);
    let c=tcp_receipt(&mut t,82,14);let d=tcp_receipt(&mut t,83,15);
    let fresh=tcp_receipt(&mut t,82,16);
    let mut cache=TcpForwardCache::<3>::new();
    for p in [a,b,c] {cache.remember(p,egress());}
    cache.forget(OUT,a.original());cache.remember(fresh,egress());cache.remember(d,egress());
    assert!(cache.lookup(OUT,a.original()).is_none());
    for p in [b,fresh,d] {assert_eq!(cache.lookup(OUT,p.original()).unwrap().0,p);}
    assert!(cache.lookup(IN,b.original()).is_none());
    cache.remember(a,egress());
    assert!(cache.lookup(OUT,b.original()).is_none());
    for p in [a,fresh,d] {assert!(cache.lookup(OUT,p.original()).is_some());}
    cache.clear();assert!(cache.lookup(OUT,a.original()).is_none());
    let mut zero=TcpForwardCache::<0>::new();zero.remember(a,egress());zero.forget(OUT,a.original());
    assert!(zero.lookup(OUT,a.original()).is_none());zero.clear();
}

#[test]
fn tcp_cache_never_authorizes_strict_reopened_closed_or_reconfigured_flows() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();establish_peer(&mut t,80,0);
    let p=tcp_receipt(&mut t,80,3);let incoming=incoming_tcp_receipt(&mut t,80,4);
    let pair=t.tcp_permit_pair(incoming,p,4).unwrap();let mut cache=TcpForwardCache::<2>::new();
    cache.remember(p,egress());
    let original=tcp(LAN,REMOTE,100,80,0x10,90000,80000);
    let (hint,link)=cache.lookup(OUT,p.original()).unwrap();
    let mut bytes=original.clone();
    assert!(t.forward_permitted_tcp(&hint,OUT,Packet::parse(&mut bytes,MAC).unwrap(),link,5).is_err());
    assert_eq!(bytes,original);assert!(t.enable_tcp_pair(&pair,5));
    let state=(t.mappings,t.flows,t.last_now);
    assert!(t.forward_permitted_tcp(&hint,OUT,Packet::parse(&mut bytes,MAC).unwrap(),link,6).is_ok());
    assert_eq!((t.mappings,t.flows,t.last_now),state);
    assert!(send(&mut t,OUT,tcp(LAN,REMOTE,100,80,0x14,90000,80000),7).0.is_ok());
    assert!(cache.lookup(OUT,p.original()).is_some());assert!(!t.tcp_offload_enabled(&hint,OUT,7));
    establish_peer(&mut t,80,8);let fresh=tcp_receipt(&mut t,80,11);
    assert!(!t.validate_tcp_permit(&hint,OUT,11));
    assert!(!cache.refresh(fresh,egress())); // Reopen requires an explicit new admission.
    cache.remember(fresh,egress());
    let (hint,link)=cache.lookup(OUT,p.original()).unwrap();assert_eq!(hint,fresh);
    let mut bytes=original.clone();
    assert!(t.forward_permitted_tcp(&hint,OUT,Packet::parse(&mut bytes,MAC).unwrap(),link,12).is_err());
    assert_eq!(bytes,original);t.reconfigure(config()).unwrap();
    assert!(cache.lookup(OUT,p.original()).is_some());assert!(!t.validate_tcp_permit(&hint,OUT,12));
}

#[test]
fn tcp_cache_refresh_requires_same_retained_instance_and_committed_new_receipt() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    establish_peer(&mut t,80,0);establish_peer(&mut t,81,3);
    let old=tcp_receipt(&mut t,80,6);let incoming=incoming_tcp_receipt(&mut t,80,7);
    let peer=tcp_receipt(&mut t,81,8);let pair=t.tcp_permit_pair(incoming,old,8).unwrap();
    assert!(t.enable_tcp_pair(&pair,9));
    let mut cache=TcpForwardCache::<2>::new();cache.remember(old,egress());cache.remember(peer,egress());
    let near=old.expires_at()-4000;
    let mut bytes=tcp(LAN,REMOTE,100,80,0x10,90000,80000);
    let before=(t.mappings,t.flows,t.last_now);
    assert!(t.forward_permitted_tcp(&old,OUT,Packet::parse(&mut bytes,MAC).unwrap(),egress(),near).is_ok());
    assert_eq!((t.mappings,t.flows,t.last_now),before);
    assert_eq!(cache.lookup(OUT,old.original()).unwrap().0,old);
    let mut changed=egress();changed.destination_mac=[2,3,4,5,6,7];
    let mut bytes=tcp(LAN,REMOTE,100,80,0x10,90000,80000);
    let fresh=t.prepare(OUT,Packet::parse(&mut bytes,MAC).unwrap(),near+1).unwrap()
        .forward_with_tcp_permit(changed).unwrap().1.unwrap();
    assert!(fresh.expires_at()>old.expires_at());
    let committed=(t.mappings,t.flows,t.last_now);
    assert!(cache.refresh(fresh,changed));
    assert_eq!((t.mappings,t.flows,t.last_now),committed);
    let (saved,link)=cache.lookup(OUT,old.original()).unwrap();
    assert_eq!(saved,fresh);
    assert_eq!((link.source_mac,link.destination_mac,link.mtu),(changed.source_mac,changed.destination_mac,changed.mtu));
    assert_eq!(cache.lookup(OUT,peer.original()).unwrap().0,peer);
    assert!(!cache.refresh(old,egress()));
    assert!(!cache.refresh(incoming,egress()));
    assert!(!t.validate_tcp_permit(&old,OUT,old.expires_at()));
    assert!(t.tcp_offload_enabled(&fresh,OUT,old.expires_at()));
    cache.remember(incoming,egress()); // Refresh must not move the replacement cursor.
    assert!(cache.lookup(OUT,fresh.original()).is_none());
    assert!(!cache.refresh(fresh,changed));
    assert_eq!(cache.lookup(OUT,peer.original()).unwrap().0,peer);
    assert!(!TcpForwardCache::<0>::new().refresh(fresh,changed));
}

#[test]
fn tcp_software_lookup_matches_forward_without_refreshing_or_issuing_hardware_receipts() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    let mut slow=Table::<1,8>::new(config(),0).unwrap();
    for table in [&mut t,&mut slow] {
        establish_peer(table,80,0);
        let a=tcp_receipt(table,80,3);let b=incoming_tcp_receipt(table,80,4);
        assert!(table.tcp_software_fallback(OUT,a.original(),4).is_none());
        let pair=table.tcp_permit_pair(b,a,4).unwrap();assert!(table.enable_tcp_pair(&pair,5));
    }
    let state=(t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence);
    for (direction,tuple,original) in [
        (OUT,TcpTuple {source:LAN,destination:REMOTE,source_port:100,destination_port:80},tcp(LAN,REMOTE,100,80,0x10,90000,80000)),
        (IN,TcpTuple {source:REMOTE,destination:WAN,source_port:80,destination_port:PORT_BASE},tcp(REMOTE,WAN,80,PORT_BASE,0x10,80000,90000)),
    ] {
        let grant=t.tcp_software_fallback(direction,tuple,6).unwrap();
        assert_eq!(grant.destination(),if direction==OUT {REMOTE} else {LAN});
        let mut foreign=original.clone();
        assert!(slow.forward_tcp_software_fallback(&grant,direction,Packet::parse(&mut foreign,MAC).unwrap(),egress(),6).is_err());
        assert_eq!(foreign,original);
        let (expected,bytes)=send(&mut slow,direction,original.clone(),6);assert!(expected.is_ok());
        let mut actual=original;
        assert_eq!(t.forward_tcp_software_fallback(&grant,direction,Packet::parse(&mut actual,MAC).unwrap(),egress(),6),expected);
        assert_eq!(actual,bytes);
        for now in [7,1000,grant.expires_at()-1] {
            assert_eq!(t.tcp_software_fallback(direction,tuple,now).unwrap().expires_at(),grant.expires_at());
        }
        assert!(t.tcp_software_fallback(direction,tuple,grant.expires_at()).is_none());
        assert_eq!((t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence),state);
    }
}

#[test]
fn tcp_software_lookup_requires_exact_enabled_peer_direction_and_time() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();
    establish_peer(&mut t,80,0);establish_peer(&mut t,81,3);
    let a=tcp_receipt(&mut t,80,6);let b=incoming_tcp_receipt(&mut t,80,7);
    let pair=t.tcp_permit_pair(b,a,7).unwrap();assert!(t.enable_tcp_pair(&pair,8));
    let out=a.original();let incoming=b.original();
    let state=(t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence);
    for (direction,tuple,now) in [
        (OUT,out,7),(IN,incoming,7),(IN,out,9),(OUT,incoming,9),
        (OUT,TcpTuple {destination_port:81,..out},9),
        (IN,TcpTuple {source_port:81,..incoming},9),
        (OUT,TcpTuple {source_port:101,..out},9),
        (OUT,TcpTuple {destination:OTHER,..out},9),
        (IN,TcpTuple {source:OTHER,..incoming},9),
        (IN,TcpTuple {destination:LAN,..incoming},9),
        (IN,TcpTuple {destination_port:PORT_BASE-1,..incoming},9),
        (IN,TcpTuple {destination_port:PORT_BASE+1,..incoming},9),
        (IN,TcpTuple {destination_port:u16::MAX,..incoming},9),
    ] {assert!(t.tcp_software_fallback(direction,tuple,now).is_none());}
    assert_eq!((t.mappings,t.flows,t.last_now,t.generation,t.tcp_sequence),state);
}

#[test]
fn tcp_software_grant_defers_control_bad_options_and_wrong_packets_without_mutation() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();establish_peer(&mut t,80,0);
    let p=tcp_receipt(&mut t,80,3);assert!(t.enable_tcp_offload(&p,OUT,4));
    let grant=t.tcp_software_fallback(OUT,p.original(),5).unwrap();
    let mut cases=Vec::new();
    for flags in [0,8,2,0x12,0x11,0x14] {cases.push(tcp(LAN,REMOTE,100,80,flags,90000,80000));}
    cases.push(tcp(LAN,REMOTE,100,81,0x10,90000,80000));cases.push(udp(LAN,REMOTE,100,80));
    let mut options=tcp(LAN,REMOTE,100,80,0x10,90000,80000);
    options[46]=0x60;options.splice(54..54,[3,1,0,0]);let total=options.len()-14;put(&mut options,16,total as u16);fix(&mut options);cases.push(options);
    let state=(t.mappings,t.flows,t.last_now);
    for original in cases {
        let mut frame=original.clone();
        assert!(t.forward_tcp_software_fallback(&grant,OUT,Packet::parse(&mut frame,MAC).unwrap(),egress(),5).is_err());
        assert_eq!(frame,original);assert_eq!((t.mappings,t.flows,t.last_now),state);
    }
}

#[test]
fn tcp_software_grant_cannot_survive_closure_reopen_or_reconfiguration() {
    let mut t=Table::<1,8>::new(config(),0).unwrap();establish_peer(&mut t,80,0);
    let p=tcp_receipt(&mut t,80,3);assert!(t.enable_tcp_offload(&p,OUT,4));
    let grant=t.tcp_software_fallback(OUT,p.original(),5).unwrap();
    assert!(send(&mut t,OUT,tcp(LAN,REMOTE,100,80,0x14,90000,80000),6).0.is_ok());
    assert!(t.tcp_software_fallback(OUT,p.original(),6).is_none());
    establish_peer(&mut t,80,7);
    assert!(t.tcp_software_fallback(OUT,p.original(),9).is_none());
    let p2=tcp_receipt(&mut t,80,10);assert!(t.enable_tcp_offload(&p2,OUT,11));
    let fresh=t.tcp_software_fallback(OUT,p2.original(),12).unwrap();
    let original=tcp(LAN,REMOTE,100,80,0x10,90000,80000);let mut frame=original.clone();
    assert!(t.forward_tcp_software_fallback(&grant,OUT,Packet::parse(&mut frame,MAC).unwrap(),egress(),12).is_err());
    assert_eq!(frame,original);
    t.reconfigure(config()).unwrap();
    assert!(t.tcp_software_fallback(OUT,p2.original(),12).is_none());
    assert!(t.forward_tcp_software_fallback(&fresh,OUT,Packet::parse(&mut frame,MAC).unwrap(),egress(),12).is_err());
    assert_eq!(frame,original);
}

#[test]
fn boxed_table_matches_inline_construction_at_product_capacity() {
    let mut inline = Table::<4, 8>::new(config(), 7).unwrap();
    let mut boxed = Table::<4, 8>::new_boxed(config(), 7).unwrap();
    assert_eq!(boxed.capacity(), (4, 8));
    let mut a = udp(LAN, REMOTE, 4000, 53);
    let mut b = a.clone();
    let la = inline
        .forward(Direction::LanToWan, Packet::parse(&mut a, MAC).unwrap(), egress(), 1)
        .unwrap();
    let lb = boxed
        .forward(Direction::LanToWan, Packet::parse(&mut b, MAC).unwrap(), egress(), 1)
        .unwrap();
    assert_eq!((la, &a[..la]), (lb, &b[..lb]));
    assert_eq!(boxed.active_counts(1), (1, 1));
    // A capacity that could not be built on a small kernel stack and moved.
    let large = Table::<4096, 8192>::new_boxed(config(), 7).unwrap();
    assert_eq!(large.active_counts(0), (0, 0));
    assert!(Table::<4, 8>::new_boxed(Config { lan_prefix: 0, ..config() }, 7).is_err());
}

#[test]
fn flow_listing_reports_live_flows_without_refreshing_them() {
    let mut t = Table::<4, 8>::new(config(), 7).unwrap();
    let mut a = udp(LAN, REMOTE, 4000, 53);
    t.forward(Direction::LanToWan, Packet::parse(&mut a, MAC).unwrap(), egress(), 10).unwrap();
    let mut b = udp(LAN, OTHER, 4000, 123);
    t.forward(Direction::LanToWan, Packet::parse(&mut b, MAC).unwrap(), egress(), 20).unwrap();
    let mut listed: Vec<FlowInfo> = t.flows(30).collect();
    listed.sort_by_key(|f| f.remote_port);
    assert_eq!(listed.len(), 2);
    assert_eq!(
        (listed[0].protocol, listed[0].internal, listed[0].internal_port, listed[0].remote, listed[0].remote_port, listed[0].state),
        (17, LAN, 4000, REMOTE, 53, FlowState::Datagram)
    );
    // Endpoint-independent mapping: both remotes share the external port.
    assert_eq!(listed[0].external_port, listed[1].external_port);
    assert!(listed[0].external_port >= 49152 && !listed[0].offloaded);
    assert_eq!((listed[0].expires_at, listed[1].expires_at), (10 + UDP_MS, 20 + UDP_MS));
    // Listing is read-only: expiry still happens on the original deadline.
    assert_eq!(t.flows(10 + UDP_MS).count(), 1);
    assert_eq!(t.flows(20 + UDP_MS).count(), 0);
}
