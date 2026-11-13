use super::*;
use alloc::vec;
use alloc::vec::Vec;

const LOCAL: [u8; 6] = [2, 0x42, 0x70, 4, 0, 2];
const PEER: [u8; 6] = [2, 3, 4, 5, 6, 7];
const LAN: [u8; 4] = [192, 168, 79, 2];
const REMOTE: [u8; 4] = [192, 168, 78, 2];
const WAN: [u8; 4] = [192, 168, 78, 1];
fn egress() -> Egress {
    Egress {
        source_mac: LOCAL,
        destination_mac: PEER,
        mtu: 1500,
    }
}

// Independent checksum oracle: accumulate/fold a word at a time in a u64,
// unlike the production implementation's full-buffer u32 sum.
fn check(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    for i in (0..bytes.len()).step_by(2) {
        sum += ((bytes[i] as u64) << 8) + bytes.get(i + 1).copied().unwrap_or(0) as u64;
        sum = (sum & 65535) + (sum >> 16);
    }
    !((sum & 65535) + (sum >> 16)) as u16
}
fn ip_check(f: &mut [u8]) {
    put(f, 24, 0);
    let end = 14 + (f[14] as usize & 15) * 4;
    let c = check(&f[14..end]);
    put(f, 24, c);
}
fn transport_check(f: &mut [u8]) {
    let length = word(f, 16) as usize;
    let end = 14 + length;
    let p = f[23];
    let offset = match p {
        6 => 50,
        17 => 40,
        _ => 36,
    };
    put(f, offset, 0);
    let mut bytes = Vec::new();
    if p != 1 {
        bytes.extend_from_slice(&f[26..34]);
        bytes.extend_from_slice(&[0, p]);
        bytes.extend_from_slice(&((length - 20) as u16).to_be_bytes());
    }
    bytes.extend_from_slice(&f[34..end]);
    let c = check(&bytes);
    put(f, offset, if p == 17 && c == 0 { 65535 } else { c });
}
fn frame(protocol: u8, payload: usize) -> Vec<u8> {
    let transport_len = if protocol == 6 { 20 } else { 8 };
    let len = 20 + transport_len + payload;
    let mut f = vec![0; (14 + len).max(60)];
    f[..6].copy_from_slice(&LOCAL);
    f[6..12].copy_from_slice(&PEER);
    put(&mut f, 12, 0x0800);
    f[14] = 0x45;
    put(&mut f, 16, len as u16);
    put(&mut f, 18, 0xabcd);
    put(&mut f, 20, 0x4000);
    f[22] = 64;
    f[23] = protocol;
    f[26..30].copy_from_slice(&LAN);
    f[30..34].copy_from_slice(&REMOTE);
    if protocol == 1 {
        f[34] = 8;
        put(&mut f, 38, 12345);
        put(&mut f, 40, 18);
    } else {
        put(&mut f, 34, 12345);
        put(&mut f, 36, 8080);
        if protocol == 6 {
            f[46] = 0x50;
            f[47] = 0x12;
            put(&mut f, 48, 32768);
        } else {
            put(&mut f, 38, (transport_len + payload) as u16);
        }
    }
    for (i, b) in f[34 + transport_len..14 + len].iter_mut().enumerate() {
        *b = (i * 71) as u8;
    }
    f[14 + len..].fill(0xa5);
    ip_check(&mut f);
    transport_check(&mut f);
    f
}
fn translation(protocol: u8) -> Translation {
    Translation {
        source: WAN,
        destination: REMOTE,
        ports: if protocol == 1 {
            PortRewrite::EchoIdentifier(60001)
        } else {
            PortRewrite::Ports {
                source: 60001,
                destination: 8080,
            }
        },
    }
}

#[test]
fn forward_nat_and_reverse_match_full_checksum_recomputation() {
    for protocol in [1, 6, 17] {
        for payload in [0, 1, 2, 3, 59, 511, 1440] {
            let mut f = frame(protocol, payload);
            let original = f.clone();
            let p = Packet::parse(&mut f, LOCAL).unwrap();
            assert_eq!(p.source(), LAN);
            assert_eq!(p.destination(), REMOTE);
            let length = p.ip_length();
            assert_eq!(
                p.forward(egress(), Some(translation(protocol))),
                Ok(14 + length)
            );
            assert_eq!(f[22], 63);
            assert_eq!(&f[26..30], &WAN);
            let mut recomputed = f.clone();
            ip_check(&mut recomputed);
            transport_check(&mut recomputed);
            assert_eq!(f, recomputed);
            assert_eq!(&f[54..], &original[54..]);
            // Undo address/port translation as in a reverse flow and verify
            // exact original bytes apart from Ethernet and two TTL decrements.
            let reverse = Translation {
                source: LAN,
                destination: REMOTE,
                ports: if protocol == 1 {
                    PortRewrite::EchoIdentifier(12345)
                } else {
                    PortRewrite::Ports {
                        source: 12345,
                        destination: 8080,
                    }
                },
            };
            Packet::parse(&mut f, PEER)
                .unwrap()
                .forward(egress(), Some(reverse))
                .unwrap();
            let mut expected = original;
            expected[..6].copy_from_slice(&PEER);
            expected[6..12].copy_from_slice(&LOCAL);
            expected[22] = 62;
            ip_check(&mut expected);
            assert_eq!(f, expected);
        }
    }
}

#[test]
fn plain_routing_preserves_transport_and_padding() {
    for protocol in [1, 6, 17] {
        let mut f = frame(protocol, 1);
        let before = f.clone();
        let len = Packet::parse(&mut f, LOCAL)
            .unwrap()
            .forward(egress(), None)
            .unwrap();
        assert_eq!(len, word(&before, 16) as usize + 14);
        assert_eq!(&f[26..], &before[26..]);
        assert_eq!(check(&f[14..34]), 0);
    }
}

#[test]
fn udp_checksum_disabled_and_encoded_zero() {
    let mut f = frame(17, 3);
    put(&mut f, 40, 0);
    Packet::parse(&mut f, LOCAL)
        .unwrap()
        .forward(egress(), Some(translation(17)))
        .unwrap();
    assert_eq!(word(&f, 40), 0);
    Packet::parse(&mut f, PEER).unwrap();
    // Find a new source port whose mathematically computed checksum is zero.
    // Brute force oracle tests the production delta, including UDP's zero rule.
    let original = frame(17, 1);
    let mut found = false;
    for port in 0..=u16::MAX {
        let mut expected = original.clone();
        expected[26..30].copy_from_slice(&WAN);
        put(&mut expected, 34, port);
        transport_check(&mut expected);
        if word(&expected, 40) == 65535 {
            let mut actual = original.clone();
            let mut t = translation(17);
            t.ports = PortRewrite::Ports {
                source: port,
                destination: 8080,
            };
            Packet::parse(&mut actual, LOCAL)
                .unwrap()
                .forward(egress(), Some(t))
                .unwrap();
            assert_eq!(word(&actual, 40), 65535);
            Packet::parse(&mut actual, PEER).unwrap();
            found = true;
            break;
        }
    }
    assert!(found);
}

#[test]
fn all_ttl_checksum_updates_and_rfc1624_zero_boundary() {
    assert_eq!(replace(0xdd2f, 0x5555, 0x3285), 0);
    for ttl in 2..=255 {
        for id in [0, 1, 0xabcd, 0xffff] {
            let mut f = frame(6, 1);
            f[22] = ttl;
            put(&mut f, 18, id);
            ip_check(&mut f);
            Packet::parse(&mut f, LOCAL)
                .unwrap()
                .forward(egress(), None)
                .unwrap();
            assert_eq!(f[22], ttl - 1);
            let mut expected = f.clone();
            ip_check(&mut expected);
            assert_eq!(f, expected);
        }
    }
}

#[test]
fn forwarding_failure_is_transactional() {
    for ttl in [0, 1, 2, 64] {
        for mtu in [0, 40, 1500] {
            for df in [false, true] {
                let mut f = frame(17, 13);
                f[22] = ttl;
                put(&mut f, 20, if df { 0x4000 } else { 0 });
                ip_check(&mut f);
                let original = f.clone();
                let mut out = egress();
                out.mtu = mtu;
                let result = Packet::parse(&mut f, LOCAL)
                    .unwrap()
                    .forward(out, Some(translation(17)));
                if ttl <= 1 {
                    assert_eq!(result, Err(Error::TtlExpired));
                    assert_eq!(f, original);
                } else if mtu < 41 {
                    assert_eq!(
                        result,
                        Err(Error::Mtu {
                            mtu,
                            dont_fragment: df
                        })
                    );
                    assert_eq!(f, original);
                } else {
                    assert!(result.is_ok());
                }
            }
        }
    }
    for protocol in [1, 6, 17] {
        let mut f = frame(protocol, 1);
        let original = f.clone();
        let wrong = translation(if protocol == 1 { 6 } else { 1 });
        assert_eq!(
            Packet::parse(&mut f, LOCAL)
                .unwrap()
                .forward(egress(), Some(wrong)),
            Err(Error::Rewrite)
        );
        assert_eq!(f, original);
        let mut wrong = translation(protocol);
        wrong.source = [224, 0, 0, 1];
        assert_eq!(
            Packet::parse(&mut f, LOCAL)
                .unwrap()
                .forward(egress(), Some(wrong)),
            Err(Error::Rewrite)
        );
        assert_eq!(f, original);
    }
}

fn rejected(mut f: Vec<u8>, expected: Error) {
    let original = f.clone();
    assert_eq!(Packet::parse(&mut f, LOCAL).err(), Some(expected));
    assert_eq!(f, original);
}
#[test]
fn invalid_packets_never_reach_rewrite() {
    for length in 0..42 {
        let f = frame(17, 1);
        rejected(f[..length].to_vec(), Error::Truncated);
    }
    for (offset, value, error, fix_ip) in [
        (0, 0xff, Error::Ethernet, false),
        (6, 1, Error::Ethernet, false),
        (12, 0x81, Error::Ethernet, false),
        (14, 0x65, Error::Header, false),
        (14, 0x44, Error::Header, false),
        (16, 0xff, Error::Truncated, false),
        (17, 19, Error::Header, false),
        (24, 0, Error::Checksum, false),
        (26, 0, Error::Address, true),
        (30, 127, Error::Address, true),
        (30, 224, Error::Address, true),
        (20, 0x20, Error::Fragment, true),
        (21, 1, Error::Fragment, true),
        (23, 47, Error::Protocol, true),
        (39, 8, Error::Transport, false),
        (42, 1, Error::Checksum, false),
    ] {
        let mut f = frame(17, 1);
        f[offset] = value;
        if fix_ip {
            ip_check(&mut f);
        }
        rejected(f, error);
    }
    let mut options = frame(17, 10);
    options[14] = 0x46;
    ip_check(&mut options);
    rejected(options, Error::Options);
    for offset in [46, 50, 54] {
        let mut f = frame(6, 1);
        f[offset] ^= 0xff;
        rejected(
            f,
            if offset == 46 {
                Error::Transport
            } else {
                Error::Checksum
            },
        );
    }
    let mut f = frame(1, 1);
    f[34] = 3;
    transport_check(&mut f);
    rejected(f, Error::Protocol);
}

#[test]
fn arbitrary_frames_do_not_panic_or_mutate_during_parse() {
    let mut seed = 0xa1b2c3d4u32;
    for length in 0..1600 {
        let mut f = vec![0; length];
        for b in &mut f {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let original = f.clone();
        let _ = Packet::parse(&mut f, LOCAL);
        assert_eq!(f, original);
    }
}

#[test]
fn return_traffic_rewrites_destination_and_echo_reply_identifier() {
    for protocol in [1, 6, 17] {
        let mut f = frame(protocol, 33);
        f[26..30].copy_from_slice(&REMOTE);
        f[30..34].copy_from_slice(&WAN);
        if protocol == 1 {
            f[34] = 0;
            put(&mut f, 38, 60001);
        } else {
            put(&mut f, 34, 8080);
            put(&mut f, 36, 60001);
        }
        ip_check(&mut f);
        transport_check(&mut f);
        let mut expected = f.clone();
        expected[30..34].copy_from_slice(&LAN);
        if protocol == 1 {
            put(&mut expected, 38, 12345);
        } else {
            put(&mut expected, 36, 12345);
        }
        expected[..6].copy_from_slice(&PEER);
        expected[6..12].copy_from_slice(&LOCAL);
        expected[22] -= 1;
        ip_check(&mut expected);
        transport_check(&mut expected);
        let p = Packet::parse(&mut f, LOCAL).unwrap();
        if protocol == 1 {
            assert_eq!(
                p.transport(),
                Transport::Echo {
                    identifier: 60001,
                    reply: true
                }
            );
        }
        p.forward(
            egress(),
            Some(Translation {
                source: REMOTE,
                destination: LAN,
                ports: if protocol == 1 {
                    PortRewrite::EchoIdentifier(12345)
                } else {
                    PortRewrite::Ports {
                        source: 8080,
                        destination: 12345,
                    }
                },
            }),
        )
        .unwrap();
        assert_eq!(f, expected);
        Packet::parse(&mut f, PEER).unwrap();
    }
}

#[test]
fn mutated_ipv4_headers_and_transport_lengths_never_panic() {
    let mut seed = 0x19abcde1u32;
    for protocol in [1, 6, 17] {
        for _ in 0..4096 {
            let mut f = frame(protocol, 100);
            for _ in 0..4 {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let offset = 14 + seed as usize % 60;
                f[offset] ^= (seed >> 16) as u8;
            }
            // Exercise past the header checksum gate whenever its extent fits.
            if (f[14] as usize & 15) >= 5 {
                ip_check(&mut f);
            }
            let original = f.clone();
            let _ = Packet::parse(&mut f, LOCAL);
            assert_eq!(f, original);
        }
    }
}

#[test]
fn icmp_errors_preserve_original_quote_and_bound_reply_to_576_bytes() {
    use crate::icmp_error::{generate, Kind, MAX_IP_LEN};
    for protocol in [1, 6, 17] {
        for payload in [0, 1, 59, 511, 1440] {
            let mut f = frame(protocol, payload);
            f[22] = 1;
            f[15] = 0x2b;
            ip_check(&mut f);
            let original = f.clone();
            let packet = Packet::parse(&mut f, LOCAL).unwrap();
            let mut out = [0xa5; MAX_IP_LEN + 16];
            let length =
                generate(&packet, [192, 168, 79, 1], Kind::TimeExceeded, &mut out).unwrap();
            let quoted = (word(&original, 16) as usize).min(548);
            assert_eq!(length, 28 + quoted);
            assert!(length <= 576);
            assert_eq!(&out[28..length], &original[14..14 + quoted]);
            assert_eq!(out[8], 64);
            assert_eq!(out[9], 1);
            assert_eq!(out[1], 0x28);
            assert_eq!(&out[12..16], &[192, 168, 79, 1]);
            assert_eq!(&out[16..20], &LAN);
            assert_eq!(&out[20..22], &[11, 0]);
            assert_eq!(&out[24..28], &[0; 4]);
            assert_eq!(check(&out[..20]), 0);
            assert_eq!(check(&out[20..length]), 0);
            assert!(out[length..].iter().all(|b| *b == 0xa5));
            assert_eq!(f, original);
        }
    }
}

#[test]
fn icmp_fragmentation_needed_reports_mtu_and_rejects_wrong_reason_without_writes() {
    use crate::icmp_error::{generate, Error, Kind};
    let mut f = frame(17, 1440);
    let original = f.clone();
    let packet = Packet::parse(&mut f, LOCAL).unwrap();
    let mut out = [0xa5; 600];
    let length = generate(
        &packet,
        WAN,
        Kind::FragmentationNeeded { mtu: 1400 },
        &mut out,
    )
    .unwrap();
    assert_eq!(&out[20..22], &[3, 4]);
    assert_eq!(word(&out, 26), 1400);
    assert_eq!(check(&out[..20]), 0);
    assert_eq!(check(&out[20..length]), 0);
    for kind in [
        Kind::TimeExceeded,
        Kind::FragmentationNeeded { mtu: 67 },
        Kind::FragmentationNeeded { mtu: 1500 },
    ] {
        let before = out;
        assert_eq!(generate(&packet, WAN, kind, &mut out), Err(Error::Reason));
        assert_eq!(out, before);
    }
    let before = out;
    assert_eq!(
        generate(
            &packet,
            [224, 0, 0, 1],
            Kind::FragmentationNeeded { mtu: 1400 },
            &mut out
        ),
        Err(Error::Source)
    );
    assert_eq!(out, before);
    for size in [0, 20, 27, 575] {
        assert_eq!(
            generate(
                &packet,
                WAN,
                Kind::FragmentationNeeded { mtu: 1400 },
                &mut out[..size]
            ),
            Err(Error::Buffer)
        );
        assert_eq!(out, before);
    }
    assert_eq!(f, original);
    put(&mut f, 20, 0);
    ip_check(&mut f);
    let packet = Packet::parse(&mut f, LOCAL).unwrap();
    assert_eq!(
        generate(
            &packet,
            WAN,
            Kind::FragmentationNeeded { mtu: 1400 },
            &mut out
        ),
        Err(Error::Reason)
    );
    assert_eq!(out, before);
}

#[test]
fn generated_icmp_errors_are_ineligible_as_error_triggers() {
    use crate::icmp_error::{generate, Kind};
    let mut f = frame(17, 8);
    f[22] = 1;
    ip_check(&mut f);
    let packet = Packet::parse(&mut f, LOCAL).unwrap();
    let mut error = [0; 590];
    error[..6].copy_from_slice(&LOCAL);
    error[6..12].copy_from_slice(&PEER);
    put(&mut error, 12, 0x800);
    let len = generate(&packet, WAN, Kind::TimeExceeded, &mut error[14..]).unwrap();
    assert_eq!(
        Packet::parse(&mut error[..14 + len], LOCAL).err(),
        Some(super::Error::Protocol)
    );
}

#[test]
fn nat_echo_reply_with_all_zero_data_retains_valid_negative_zero_checksum() {
    let mut f = frame(1, 0);
    f[34] = 0;
    put(&mut f, 38, 60001);
    put(&mut f, 40, 0);
    transport_check(&mut f);
    Packet::parse(&mut f, LOCAL)
        .unwrap()
        .forward(
            egress(),
            Some(Translation {
                source: REMOTE,
                destination: LAN,
                ports: PortRewrite::EchoIdentifier(0),
            }),
        )
        .unwrap();
    assert_eq!(word(&f, 36), 65535);
    assert_eq!(check(&f[34..42]), 0);
    Packet::parse(&mut f, PEER).unwrap();
}

#[test]
fn tcp_window_scale_options_are_bounded_and_only_negotiated_on_syn() {
    fn with_options(options: &[u8], syn: bool) -> Vec<u8> {
        let mut f = frame(6, 1);
        f.splice(54..54, options.iter().copied());
        let len = word(&f, 16) + options.len() as u16;
        put(&mut f, 16, len);
        f[46] = ((20 + options.len()) / 4) as u8 * 16;
        f[47] = if syn { 2 } else { 0x10 };
        ip_check(&mut f);
        transport_check(&mut f);
        f
    }
    for scale in [0, 5, 14, 15, 255] {
        let mut f = with_options(&[3, 3, scale, 1], true);
        let details = Packet::parse(&mut f, LOCAL)
            .unwrap()
            .tcp_details()
            .unwrap()
            .unwrap();
        assert_eq!(details.scale, Some(scale.min(14)));
        assert_eq!(details.payload, 1);
        assert_eq!(details.window, 32768);
        let mut f = with_options(&[3, 3, scale, 1], false);
        assert_eq!(
            Packet::parse(&mut f, LOCAL)
                .unwrap()
                .tcp_details()
                .unwrap()
                .unwrap()
                .scale,
            None
        );
    }
    for options in [
        &[3, 0, 1, 1][..],
        &[3, 4, 5, 1],
        &[3, 3, 5, 3],
        &[3, 3, 5, 1, 3, 3, 5, 1],
        &[30, 8, 0, 0],
    ] {
        let mut f = with_options(options, true);
        assert!(Packet::parse(&mut f, LOCAL).unwrap().tcp_details().is_err());
    }
    let mut f = with_options(&[0, 255, 255, 255], true);
    assert_eq!(
        Packet::parse(&mut f, LOCAL)
            .unwrap()
            .tcp_details()
            .unwrap()
            .unwrap()
            .scale,
        None
    );
}


#[test]
fn wide_checksum_matches_byte_oracle_across_lengths_and_alignments() {
    // Covers every tail length, both odd/even prefix parity, IPv4 maximum,
    // and carries. Compare the *unfolded* sum as well as the final checksum.
    let mut data = vec![0u8; 65535 + 8];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((i * 73 + (i >> 4) * 31) & 255) as u8;
    }
    for offset in 0..8 {
        let mut expected = 0u32;
        for length in 0..=65535 {
            if length != 0 {
                let i = length - 1;
                expected += (data[offset + i] as u32) << if i & 1 == 0 { 8 } else { 0 };
            }
            // Full all-length coverage near MTU and scalar/wide transition;
            // large lengths sample every tail/alignment at the upper boundary.
            if length <= 1518 || length >= 65520 {
                assert_eq!(sum(&data[offset..offset + length]), expected, "offset={offset} length={length}");
                assert_eq!(!fold(expected), check(&data[offset..offset + length]));
            }
        }
    }
    for byte in [0, 255] {
        data.fill(byte);
        for offset in 0..8 {
            for length in [0, 1, 31, 32, 33, 63, 64, 65, 1500, 1514, 65534, 65535] {
                let bytes = &data[offset..offset + length];
                assert_eq!(!fold(sum(bytes)), check(bytes));
            }
        }
    }
}

#[test]
fn reserved_ipv4_flag_is_preserved_by_forwarding_and_nat() {
    // RFC 1812 4.2.2.3 / 5.2.5: unused flag bits are not a rejection reason.
    for protocol in [1, 6, 17] {
        for flags in [0x8000, 0xc000] {
            let mut f = frame(protocol, 512);
            put(&mut f, 20, flags);
            ip_check(&mut f);
            Packet::parse(&mut f, LOCAL).unwrap()
                .forward(egress(), Some(translation(protocol))).unwrap();
            assert_eq!(word(&f, 20), flags);
            assert_eq!(f[22], 63);
            let mut recomputed = f.clone();
            ip_check(&mut recomputed);
            transport_check(&mut recomputed);
            assert_eq!(f, recomputed);
            Packet::parse(&mut f, PEER).unwrap();
        }
    }
    for flags in [0x8001, 0xa000] {
        let mut f = frame(17, 16);
        put(&mut f, 20, flags);
        ip_check(&mut f);
        let before = f.clone();
        assert_eq!(Packet::parse(&mut f, LOCAL).err(), Some(Error::Fragment));
        assert_eq!(f, before);
    }
}

#[test]
fn reserved_ipv4_flag_is_preserved_in_icmp_outer_and_quote() {
    use crate::{icmp_error, icmp_nat};
    for outer in [0, 0x8000, 0xc000] {
        for quoted in [0, 0x8000, 0xc000] {
            let mut original = frame(17, 16);
            original[22] = 1;
            ip_check(&mut original);
            let p = Packet::parse(&mut original, LOCAL).unwrap();
            let mut error = [0; 590];
            error[..6].copy_from_slice(&LOCAL);
            error[6..12].copy_from_slice(&PEER);
            put(&mut error, 12, 0x800);
            let n = icmp_error::generate(&p, WAN, icmp_error::Kind::TimeExceeded, &mut error[14..]).unwrap();
            // Originated outer headers must still leave the reserved flag clear.
            assert_eq!(word(&error, 20) & 0x8000, 0);
            put(&mut error, 20, outer);
            put(&mut error, 48, quoted);
            put(&mut error, 52, 0);
            let c = check(&error[42..62]);
            put(&mut error, 52, c);
            ip_check(&mut error);
            transport_check(&mut error);
            icmp_nat::Packet::parse(&mut error[..14+n], LOCAL).unwrap()
                .forward(egress(), icmp_nat::Rewrite {
                    source: WAN, destination: REMOTE, quoted: translation(17),
                }).unwrap();
            assert_eq!(word(&error, 20), outer);
            assert_eq!(word(&error, 48), quoted);
            assert_eq!(check(&error[14..34]), 0);
            assert_eq!(check(&error[42..62]), 0);
            assert_eq!(check(&error[34..14+n]), 0);
            icmp_nat::Packet::parse(&mut error[..14+n], PEER).unwrap();
        }
    }
}
