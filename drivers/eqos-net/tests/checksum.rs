use vibeos_eqos_net::{checksum::{prepare, Error}, descriptor::TxChecksum};

fn frame(protocol: u8, payload: usize, options: bool, vlan: bool) -> Vec<u8> {
    let ip = if vlan { 18 } else { 14 };
    let header = if options { 24 } else { 20 };
    let transport = if protocol == 6 { 20 } else { 8 };
    let total = header + transport + payload;
    let mut f = vec![0; ip + total + 7]; // Explicit Ethernet padding sentinel.
    f[12..14].copy_from_slice(&(if vlan {0x8100u16} else {0x0800}).to_be_bytes());
    if vlan { f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); }
    f[ip] = 0x40 | (header / 4) as u8;
    f[ip + 2..ip + 4].copy_from_slice(&(total as u16).to_be_bytes());
    f[ip + 6] = 0x40; // DF is permitted.
    f[ip + 8] = 64;
    f[ip + 9] = protocol;
    f[ip + 10..ip + 12].copy_from_slice(&[0xde, 0xad]);
    f[ip + 12..ip + 20].copy_from_slice(&[192,0,2,1,198,51,100,2]);
    let t = ip + header;
    f[t..t+4].copy_from_slice(&[0x03,0xe8,0x07,0xd0]);
    if protocol == 6 { f[t+12] = 0x50; }
    else { f[t+4..t+6].copy_from_slice(&((transport + payload) as u16).to_be_bytes()); }
    for (i, b) in f[t+transport..ip+total].iter_mut().enumerate() { *b = (i*37) as u8; }
    f[ip+total..].fill(0xa5);
    f
}
// Independent end-around-carry verifier, one word at a time.
fn valid(parts: &[&[u8]]) -> bool {
    let bytes: Vec<u8> = parts.iter().flat_map(|p| p.iter().copied()).collect();
    let mut acc = 0u16;
    for pair in bytes.chunks(2) {
        let v = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        let (n, carry) = acc.overflowing_add(v);
        acc = n.wrapping_add(u16::from(carry));
    }
    acc == 0xffff
}
fn verify(f: &[u8], ip: usize) {
    let h = usize::from(f[ip] & 15)*4;
    let total = usize::from(u16::from_be_bytes([f[ip+2],f[ip+3]]));
    assert!(valid(&[&f[ip..ip+h]]));
    let n = if f[ip+9] == 17 { usize::from(u16::from_be_bytes([f[ip+h+4],f[ip+h+5]])) } else { total-h };
    let pseudo = [0, f[ip+9], (n>>8) as u8, n as u8];
    assert!(valid(&[&f[ip+12..ip+20], &pseudo, &f[ip+h..ip+h+n]]));
    assert!(f[ip+total..].iter().all(|b| *b == 0xa5));
}
#[test]
fn fallback_checksums_cover_odd_lengths_options_vlan_and_padding() {
    for proto in [6,17] { for payload in [0,1,2,63,511,1440] {
        for (options,vlan) in [(false,false),(true,false),(false,true),(true,true)] {
            let mut f = frame(proto,payload,options,vlan);
            assert_eq!(prepare(&mut f, false), Ok(TxChecksum::None));
            verify(&f, if vlan {18} else {14});
            if options || vlan {
                f[if vlan {28} else {24}] ^= 0x55;
                assert_eq!(prepare(&mut f, true), Ok(TxChecksum::None));
                verify(&f, if vlan {18} else {14});
            }
        }
    }}
}
#[test]
fn hardware_request_clears_only_checksum_fields() {
    for proto in [6,17] {
        let mut f = frame(proto,127,false,false);
        let mut expected = f.clone();
        expected[24..26].fill(0);
        let check = 34 + if proto == 6 {16} else {6};
        expected[check..check+2].fill(0);
        assert_eq!(prepare(&mut f,true), Ok(TxChecksum::Full));
        assert_eq!(f,expected);
    }
}
#[test]
fn malformed_or_fragmented_requests_are_never_partially_modified() {
    let base = frame(6,10,false,false);
    for (at,value) in [(14,0x44),(16,0xff),(20,0x80),(20,0x20),(21,1),(46,0x10),(46,0xf0)] {
        let mut f=base.clone(); f[at]=value;
        let before=f.clone();
        assert!(prepare(&mut f,true).is_err()); assert_eq!(f,before);
    }
    for n in 0..54 {
        let mut f=base[..n].to_vec();let before=f.clone();
        assert!(prepare(&mut f,true).is_err());assert_eq!(f,before);
    }
    let mut f=base;f[20]=0x20;
    assert_eq!(prepare(&mut f,true),Err(Error::Fragmented));
}
#[test]
fn udp_shorter_than_ip_payload_uses_software_and_leaves_trailing_bytes() {
    let mut f=frame(17,7,false,false);
    f[38..40].copy_from_slice(&9u16.to_be_bytes());
    let tail=f[43..].to_vec();
    assert_eq!(prepare(&mut f,true),Ok(TxChecksum::None));
    verify(&f,14);assert_eq!(f[43..],tail);
}
#[test]
fn non_ip_frames_are_unchanged() {
    let mut f=vec![0xa5;60];f[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    let before=f.clone();assert_eq!(prepare(&mut f,true),Ok(TxChecksum::None));assert_eq!(f,before);
}
#[test]
fn udp_computed_zero_is_encoded_as_all_ones() {
    let mut f=frame(17,2,false,false);
    // Find the single payload word whose ones-complement result is zero.
    let mut found=false;
    for word in 0..=u16::MAX {
        f[42..44].copy_from_slice(&word.to_be_bytes());
        prepare(&mut f,false).unwrap();
        if f[40..42] == [0xff,0xff] { verify(&f,14);found=true;break; }
    }
    assert!(found);
}

#[test]
fn rx_fallback_verifies_odd_payloads_vlan_options_and_protocol_mismatch() {
    use vibeos_eqos_net::{checksum::{verify_rx_ipv4 as rx, RxVerified as V}, descriptor::RxChecksum as C};
    for protocol in [6,17] { for n in [0,1,63,511,1440] {
        for (options,vlan) in [(false,false),(true,false),(false,true)] {
            let mut f=frame(protocol,n,options,vlan);prepare(&mut f,false).unwrap();
            verify(&f,if vlan {18} else {14});
            for status in [C::Unavailable,C::Bypassed,C::Ipv6 { payload_type:2 },C::Ipv4 { payload_type:0 }] {
                let before=f.clone();assert_eq!(rx(&f,status),Ok(V::Software));assert_eq!(f,before);
                let mut corrupt=f.clone();let ip=if vlan {18} else {14};corrupt[ip+8]^=1;
                assert_eq!(rx(&corrupt,status),Err(Error::Checksum));
                corrupt=f.clone();let transport=ip+if options {24} else {20};corrupt[transport]^=1;
                assert_eq!(rx(&corrupt,status),Err(Error::Checksum));
            }
        }
    }}
}
#[test]
fn rx_hardware_requires_matching_protocol_and_normal_header_format() {
    use vibeos_eqos_net::{checksum::{verify_rx_ipv4 as rx, RxVerified as V}, descriptor::RxChecksum as C};
    for (protocol,kind) in [(6,2),(17,1)] {
        for (options,vlan) in [(false,false),(true,false),(false,true)] {
            let mut f=frame(protocol,7,options,vlan);prepare(&mut f,false).unwrap();
            assert_eq!(rx(&f,C::Ipv4 { payload_type:kind }),Ok(if options||vlan {V::Software} else {V::Hardware}));
            assert_eq!(rx(&f,C::Ipv4 { payload_type:3-kind }),Ok(V::Software));
            assert_eq!(rx(&f,C::Error),Err(Error::Checksum));
        }
    }
}
#[test]
fn rx_zero_udp_and_short_udp_length_have_precise_software_semantics() {
    use vibeos_eqos_net::{checksum::{verify_rx_ipv4 as rx, RxVerified as V}, descriptor::RxChecksum as C};
    let mut f=frame(17,7,false,false);f[38..40].copy_from_slice(&9u16.to_be_bytes());
    prepare(&mut f,false).unwrap();f[43]^=0xff; // Outside UDP, inside IP payload.
    assert_eq!(rx(&f,C::Ipv4 { payload_type:1 }),Ok(V::Software));
    f[42]^=1;assert_eq!(rx(&f,C::Unavailable),Err(Error::Checksum));
    f[40..42].fill(0);assert_eq!(rx(&f,C::Unavailable),Ok(V::Software));
    f[24]^=1;assert_eq!(rx(&f,C::Unavailable),Err(Error::Checksum));
}
#[test]
fn rx_fragment_and_non_ipv4_never_claim_transport_verification() {
    use vibeos_eqos_net::{checksum::{verify_rx_ipv4 as rx, RxVerified as V}, descriptor::RxChecksum as C};
    let mut f=frame(6,7,false,false);f[20]=0x20;
    assert_eq!(rx(&f,C::Ipv4 { payload_type:2 }),Err(Error::Fragmented));
    for kind in [0x0806u16,0x86dd] {
        let mut f=vec![0u8;60];f[12..14].copy_from_slice(&kind.to_be_bytes());
        assert_eq!(rx(&f,C::Unavailable),Ok(V::NonIpv4));
    }
    assert_eq!(rx(&[0;13],C::Unavailable),Err(Error::Truncated));
}

#[test]
fn tx_icmp_error_repairs_inner_header_and_icmp_checksum_without_quoted_payload() {
    for kind in [3,4,5,11,12] {
        let mut original=frame(17,7,false,false);prepare(&mut original,false).unwrap();
        let mut f=frame(1,28,false,false);f[34..42].fill(0);f[34]=kind;
        f[42..70].copy_from_slice(&original[14..42]);
        f[52..54].fill(0); // Inner checksum omitted under global TX offload.
        let quoted_udp=f[62..70].to_vec();
        assert_eq!(prepare(&mut f,true),Ok(TxChecksum::None));
        assert!(valid(&[&f[14..34]]));assert!(valid(&[&f[42..62]]));
        assert!(valid(&[&f[34..70]]));assert_eq!(&f[62..70],quoted_udp);
        assert!(f[70..].iter().all(|b| *b==0xa5));
        let once=f.clone();prepare(&mut f,true).unwrap();assert_eq!(f,once);
    }
}
