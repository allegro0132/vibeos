//! NETSYS v3 QDMA TX offloads (Linux v6.12 mtk_tx_set_dma_desc_v2).
//! Only plain Ethernet / one 802.1Q tag are accepted. Proprietary switch
//! CPU tags, fragments, IPv6 extension headers and tunnels stay in software.
use crate::{Error, TxPort};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxOffload {
    pub checksum: bool,
    /// Insert an outer 802.1Q tag. Full TCI, including PCP/DEI; VID 4095 rejected.
    pub vlan: Option<u16>,
    /// TCP payload bytes per output segment, not the IP MTU.
    pub tso_mss: Option<u16>,
}

/// Validated metadata bound to a packet length and destination. Fields are
/// private so safe callers cannot manufacture descriptor control bits.
#[derive(Clone, Copy, Debug)]
pub struct Prepared {
    pub(crate) length: usize,
    pub(crate) port: TxPort,
    pub(crate) word5: u32,
    pub(crate) word6: u32,
}

impl TxOffload {
    /// Validate before modifying any bytes. On success TSO replaces TCP's
    /// checksum with the big-endian MSS expected by NETSYS. The caller must
    /// submit that exact packet and retain it until DMA completion.
    pub fn prepare(self, packet: &mut [u8], port: TxPort) -> Result<Prepared, Error> {
        if !matches!(port, TxPort::Wan | TxPort::Internal) {
            return Err(Error::Malformed);
        }
        if packet.len() < 14 || packet.len() > u16::MAX as usize {
            return Err(Error::Length);
        }
        if self.vlan.is_some_and(|tci| tci & 0xfff == 0xfff) {
            return Err(Error::Malformed);
        }
        let mut l3 = 14;
        let mut protocol = be16(packet, 12);
        if protocol == 0x8100 {
            if packet.len() < 18 || self.vlan.is_some() {
                return Err(Error::Malformed);
            }
            protocol = be16(packet, 16);
            l3 = 18;
        }
        if matches!(protocol, 0x8100 | 0x88a8) {
            return Err(Error::Malformed);
        }
        let mut tcp = None;
        let mut headers = 0;
        if self.checksum || self.tso_mss.is_some() {
            let (l4, next, end) = match protocol {
                0x0800 => {
                    if packet.len() < l3 + 20 || packet[l3] >> 4 != 4 {
                        return Err(Error::Malformed);
                    }
                    let ihl = usize::from(packet[l3] & 15) * 4;
                    let total = usize::from(be16(packet, l3 + 2));
                    if ihl < 20
                        || total < ihl
                        || l3 + total > packet.len()
                        || be16(packet, l3 + 6) & 0xbfff != 0
                    {
                        return Err(Error::Malformed);
                    }
                    (l3 + ihl, packet[l3 + 9], l3 + total)
                }
                0x86dd => {
                    if packet.len() < l3 + 40 || packet[l3] >> 4 != 6 {
                        return Err(Error::Malformed);
                    }
                    let end = l3 + 40 + usize::from(be16(packet, l3 + 4));
                    if end > packet.len() {
                        return Err(Error::Malformed);
                    }
                    (l3 + 40, packet[l3 + 6], end)
                }
                _ => return Err(Error::Malformed),
            };
            match next {
                6 => {
                    if l4 + 20 > end {
                        return Err(Error::Malformed);
                    }
                    let size = usize::from(packet[l4 + 12] >> 4) * 4;
                    if size < 20 || l4 + size > end {
                        return Err(Error::Malformed);
                    }
                    tcp = Some(l4);
                    headers = l4 + size;
                    if self.tso_mss.is_some()
                        && (end != packet.len() || headers == end || packet[l4 + 13] & 0x26 != 0)
                    {
                        return Err(Error::Malformed);
                    }
                }
                17 if self.tso_mss.is_none() => {
                    if l4 + 8 > end || usize::from(be16(packet, l4 + 4)) != end - l4 {
                        return Err(Error::Malformed);
                    }
                }
                _ => return Err(Error::Malformed),
            }
        }
        let wire_header = if l3 == 18 || self.vlan.is_some() {
            18
        } else {
            14
        };
        if let Some(mss) = self.tso_mss {
            if !self.checksum
                || mss == 0
                || headers + usize::from(mss) + usize::from(self.vlan.is_some()) * 4
                    > wire_header + 1500
            {
                return Err(Error::Length);
            }
        } else if packet.len() + usize::from(self.vlan.is_some()) * 4 > wire_header + 1500 {
            return Err(Error::Length);
        }
        if let Some(mss) = self.tso_mss {
            let offset = tcp.ok_or(Error::Malformed)? + 16;
            packet[offset..offset + 2].copy_from_slice(&mss.to_be_bytes());
        }
        Ok(Prepared {
            length: packet.len(),
            port,
            word5: if self.checksum { 7 << 28 } else { 0 }
                | if self.tso_mss.is_some() { 1 << 31 } else { 0 },
            word6: self.vlan.map_or(0, |tci| (1 << 16) | u32::from(tci)),
        })
    }
}
fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// Opportunistic checksum and single-tag insertion for existing MTU producers.
/// TSO is explicit: packet length alone cannot determine a connection's MSS.
#[cfg(feature = "tx-offload")]
pub(crate) fn prepare_ordinary(packet: &mut [u8], port: TxPort) -> Option<(usize, Prepared)> {
    if packet.len() < 60 {
        return None;
    }
    let options = TxOffload {
        checksum: true,
        ..TxOffload::default()
    };
    // Validate original bytes before stripping a tag. Rejection is nonmutating.
    let mut meta = options.prepare(packet, port).ok()?;
    let mut length = packet.len();
    if be16(packet, 12) == 0x8100 {
        let tci = be16(packet, 14);
        if tci & 0xfff == 0xfff {
            return None;
        }
        packet.copy_within(16..length, 12);
        length = (length - 4).max(60);
        let end = packet.len();
        packet[end - 4..].fill(0);
        meta.word6 = (1 << 16) | u32::from(tci);
        meta.length = length;
    }
    Some((length, meta))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    extern crate std;
    pub(crate) fn tcp(ipv6: bool, payload: usize) -> std::vec::Vec<u8> {
        let ip = if ipv6 { 40 } else { 20 };
        let mut p = std::vec![0; 14 + ip + 20 + payload];
        p[12..14].copy_from_slice(&(if ipv6 { 0x86ddu16 } else { 0x0800u16 }).to_be_bytes());
        if ipv6 {
            p[14] = 0x60;
            p[18..20].copy_from_slice(&((20 + payload) as u16).to_be_bytes());
            p[20] = 6;
        } else {
            p[14] = 0x45;
            p[16..18].copy_from_slice(&((ip + 20 + payload) as u16).to_be_bytes());
            p[23] = 6;
        }
        p[14 + ip + 12] = 0x50;
        p[14 + ip + 13] = 0x18;
        p
    }
    #[test]
    fn udp4_udp6_and_vlan_only_arp() {
        for ipv6 in [false, true] {
            let mut p = tcp(ipv6, 20);
            let l4 = if ipv6 { 54 } else { 34 };
            p[if ipv6 { 20 } else { 23 }] = 17;
            let size = (p.len() - l4) as u16;
            p[l4 + 4..l4 + 6].copy_from_slice(&size.to_be_bytes());
            let original = p.clone();
            assert_eq!(
                TxOffload {
                    checksum: true,
                    ..Default::default()
                }
                .prepare(&mut p, TxPort::Wan)
                .unwrap()
                .word5,
                0x70000000
            );
            assert_eq!(p, original);
            p[l4 + 5] ^= 1;
            assert!(TxOffload {
                checksum: true,
                ..Default::default()
            }
            .prepare(&mut p, TxPort::Wan)
            .is_err());
        }
        let mut arp = [0; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let meta = TxOffload {
            vlan: Some(100),
            ..Default::default()
        }
        .prepare(&mut arp, TxPort::Wan)
        .unwrap();
        assert_eq!((meta.word5, meta.word6), (0, 0x10064));
    }

    #[test]
    fn tso4_tso6_mss_vlan_and_full_tci() {
        for ipv6 in [false, true] {
            let mut p = tcp(ipv6, 8000);
            let original = p.clone();
            let meta = TxOffload {
                checksum: true,
                vlan: Some(0xb064),
                tso_mss: Some(1400),
            }
            .prepare(&mut p, TxPort::Wan)
            .unwrap();
            assert_eq!(meta.word5, 0xf0000000);
            assert_eq!(meta.word6, 0x1b064);
            let offset = if ipv6 { 70 } else { 50 };
            assert_eq!(&p[offset..offset + 2], &1400u16.to_be_bytes());
            p[offset..offset + 2].copy_from_slice(&original[offset..offset + 2]);
            assert_eq!(p, original);
        }
    }
    #[test]
    fn rejects_bad_tso_without_mutation() {
        for ipv6 in [false, true] {
            for mss in [0, 1500, u16::MAX] {
                let mut p = tcp(ipv6, 8000);
                let original = p.clone();
                assert!(TxOffload {
                    checksum: true,
                    vlan: None,
                    tso_mss: Some(mss)
                }
                .prepare(&mut p, TxPort::Wan)
                .is_err());
                assert_eq!(p, original);
            }
        }
        let mut p = tcp(false, 8000);
        for port in [TxPort::InternalTagged, TxPort::ExternalTagged] {
            assert!(TxOffload {
                checksum: true,
                vlan: None,
                tso_mss: Some(1400)
            }
            .prepare(&mut p, port)
            .is_err());
        }
        assert!(TxOffload {
            tso_mss: Some(1400),
            ..Default::default()
        }
        .prepare(&mut p, TxPort::Wan)
        .is_err());
    }
    #[test]
    fn rejects_truncated_headers_fragments_extensions_and_reserved_vid() {
        for ipv6 in [false, true] {
            let p = tcp(ipv6, 10);
            for end in 0..p.len() {
                assert!(TxOffload {
                    checksum: true,
                    ..Default::default()
                }
                .prepare(&mut p[..end].to_vec(), TxPort::Wan)
                .is_err());
            }
        }
        let mut p = tcp(false, 10);
        p[20] = 0x20; // MF
        assert!(TxOffload {
            checksum: true,
            ..Default::default()
        }
        .prepare(&mut p, TxPort::Wan)
        .is_err());
        p[20] = 0;
        assert!(TxOffload {
            vlan: Some(4095),
            ..Default::default()
        }
        .prepare(&mut p, TxPort::Wan)
        .is_err());
        let mut p = tcp(true, 10);
        p[20] = 44; // IPv6 fragment header
        assert!(TxOffload {
            checksum: true,
            ..Default::default()
        }
        .prepare(&mut p, TxPort::Wan)
        .is_err());
    }
    #[cfg(feature = "tx-offload")]
    #[test]
    fn vlan_conversion_preserves_packet_and_padding_and_fallback() {
        let plain = tcp(false, 20);
        let mut tagged = plain[..12].to_vec();
        tagged.extend_from_slice(&[0x81, 0, 0xb0, 100]);
        tagged.extend_from_slice(&plain[12..]);
        let (length, meta) = prepare_ordinary(&mut tagged, TxPort::Wan).unwrap();
        assert_eq!(length, plain.len());
        assert_eq!(&tagged[..length], &plain);
        assert_eq!(meta.word6, 0x1b064);
        assert_eq!(&tagged[length..], &[0; 4]);
        let mut unsupported = [0xff; 60];
        assert!(prepare_ordinary(&mut unsupported, TxPort::Wan).is_none());
        assert_eq!(unsupported, [0xff; 60]);
    }
}
