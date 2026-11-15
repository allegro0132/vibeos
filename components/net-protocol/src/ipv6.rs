//! Bounded Ethernet/IPv6 wire primitives shared by router products.
//! Extension headers and fragments are deliberately not interpreted as transport.
use alloc::vec::Vec;
pub type Address = [u8; 16];
pub const ALL_NODES: Address = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const ALL_ROUTERS: Address = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub fn link_local(mac: [u8; 6]) -> Address {
    [
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 2,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}
pub fn is_link_local(a: Address) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}
pub fn unicast(a: Address) -> bool {
    a != [0; 16]
        && a[0] != 0xff
        && a != core::net::Ipv6Addr::LOCALHOST.octets()
        && a[..12] != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
}
pub fn global(a: Address) -> bool {
    a[0] & 0xe0 == 0x20 || a[0] & 0xfe == 0xfc
}
pub fn contains(prefix: Address, bits: u8, a: Address) -> bool {
    bits <= 128
        && (bits == 0
            || (u128::from_be_bytes(prefix) ^ u128::from_be_bytes(a)) >> (128 - u32::from(bits))
                == 0)
}
pub fn network(a: Address, bits: u8) -> Option<Address> {
    if bits > 128 {
        return None;
    }
    Some(
        (u128::from_be_bytes(a)
            & if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            })
        .to_be_bytes(),
    )
}
pub fn solicited(a: Address) -> Address {
    let mut out = [0; 16];
    out[0] = 0xff;
    out[1] = 2;
    out[11] = 1;
    out[12] = 0xff;
    out[13..].copy_from_slice(&a[13..]);
    out
}
pub fn multicast_mac(a: Address) -> [u8; 6] {
    [0x33, 0x33, a[12], a[13], a[14], a[15]]
}
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub source: Address,
    pub destination: Address,
    pub next: u8,
    pub hop: u8,
    pub payload: &'a [u8],
    pub length: usize,
}
impl<'a> Packet<'a> {
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        if frame.len() < 54 || frame[12..14] != [0x86, 0xdd] || frame[14] >> 4 != 6 {
            return None;
        }
        let length = 54 + usize::from(u16::from_be_bytes([frame[18], frame[19]]));
        let payload = frame.get(54..length)?;
        Some(Self {
            source: frame[22..38].try_into().ok()?,
            destination: frame[38..54].try_into().ok()?,
            next: frame[20],
            hop: frame[21],
            payload,
            length,
        })
    }
    pub fn checksum_valid(&self) -> bool {
        checksum(self.source, self.destination, self.next, self.payload) == 0
    }
    pub fn udp(&self) -> Option<(u16, u16, &'a [u8])> {
        let b = self.payload;
        if self.next != 17
            || b.len() < 8
            || usize::from(u16::from_be_bytes([b[4], b[5]])) != b.len()
            || b[6..8] == [0, 0]
            || !self.checksum_valid()
        {
            return None;
        }
        Some((
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]]),
            &b[8..],
        ))
    }
}
pub fn checksum(source: Address, destination: Address, next: u8, payload: &[u8]) -> u16 {
    let sum = payload.len() as u32 + u32::from(next)
        + crate::checksum::sum(&source)
        + crate::checksum::sum(&destination)
        + crate::checksum::sum(payload);
    !crate::checksum::fold(sum)
}
pub fn frame(
    mac: [u8; 6],
    peer: [u8; 6],
    source: Address,
    destination: Address,
    next: u8,
    hop: u8,
    payload: &[u8],
) -> Vec<u8> {
    assert!(payload.len() <= 1460);
    let mut out = alloc::vec![0;54+payload.len()];
    out[..6].copy_from_slice(&peer);
    out[6..12].copy_from_slice(&mac);
    out[12..14].copy_from_slice(&[0x86, 0xdd]);
    out[14] = 0x60;
    out[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[20] = next;
    out[21] = hop;
    out[22..38].copy_from_slice(&source);
    out[38..54].copy_from_slice(&destination);
    out[54..].copy_from_slice(payload);
    out
}
pub fn icmp(
    mac: [u8; 6],
    peer: [u8; 6],
    source: Address,
    destination: Address,
    hop: u8,
    mut payload: Vec<u8>,
) -> Vec<u8> {
    payload[2..4].fill(0);
    let sum = checksum(source, destination, 58, &payload);
    payload[2..4].copy_from_slice(&sum.to_be_bytes());
    frame(mac, peer, source, destination, 58, hop, &payload)
}
pub fn udp(
    mac: [u8; 6],
    peer: [u8; 6],
    source: Address,
    destination: Address,
    ports: (u16, u16),
    data: &[u8],
) -> Vec<u8> {
    let mut payload = alloc::vec![0;8+data.len()];
    payload[..2].copy_from_slice(&ports.0.to_be_bytes());
    payload[2..4].copy_from_slice(&ports.1.to_be_bytes());
    let len = payload.len() as u16;
    payload[4..6].copy_from_slice(&len.to_be_bytes());
    payload[8..].copy_from_slice(data);
    let sum = checksum(source, destination, 17, &payload);
    payload[6..8].copy_from_slice(&if sum == 0 { 65535 } else { sum }.to_be_bytes());
    frame(mac, peer, source, destination, 17, 64, &payload)
}
/// Checked ND options. Zero length or truncation invalidates the whole message.
pub fn nd_options(mut bytes: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 || bytes[1] == 0 {
            return None;
        }
        let n = usize::from(bytes[1]) * 8;
        out.push((bytes[0], bytes.get(2..n)?));
        bytes = &bytes[n..];
    }
    Some(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_roundtrip_and_corruption() {
        let a = link_local([2, 1, 2, 3, 4, 5]);
        let mut f = udp([2; 6], [4; 6], a, ALL_ROUTERS, (546, 547), b"hello");
        assert_eq!(
            Packet::parse(&f).unwrap().udp(),
            Some((546, 547, &b"hello"[..]))
        );
        f[62] ^= 1;
        assert!(Packet::parse(&f).unwrap().udp().is_none());
        assert!(Packet::parse(&f[..54]).is_none());
    }
    #[test]
    fn shared_checksum_matches_ipv6_pseudoheader_oracle() {
        let source = [0x23; 16];
        let destination = [0xfe; 16];
        let mut data = alloc::vec![0u8; 65535 + 8];
        for (i, b) in data.iter_mut().enumerate() { *b = (i * 73 + (i >> 4) * 31) as u8; }
        for fill in [None, Some(0), Some(255)] {
            if let Some(byte) = fill { data.fill(byte); }
            for offset in 0..8 {
                for length in (0..=80).chain([1396, 1459, 1460, 1500, 65534, 65535]) {
                    let payload = &data[offset..offset + length];
                    for next in [6, 17, 58] {
                        // Independent byte-wise pseudoheader, including its
                        // 32-bit length and padding, accumulated in u64.
                        let mut pseudo = source.to_vec();
                        pseudo.extend_from_slice(&destination);
                        pseudo.extend_from_slice(&(length as u32).to_be_bytes());
                        pseudo.extend_from_slice(&[0, 0, 0, next]);
                        pseudo.extend_from_slice(payload);
                        let mut sum = 0u64;
                        for (i, byte) in pseudo.iter().enumerate() {
                            sum += u64::from(*byte) << if i & 1 == 0 { 8 } else { 0 };
                        }
                        while sum > 65535 { sum = (sum & 65535) + (sum >> 16); }
                        assert_eq!(checksum(source, destination, next, payload), !(sum as u16),
                            "offset={offset} length={length} next={next}");
                    }
                }
            }
        }
    }
    #[test]
    fn prefixes_and_bad_options() {
        assert!(contains([0; 16], 0, [255; 16]));
        assert!(!contains([0; 16], 129, [0; 16]));
        assert!(nd_options(&[1, 0]).is_none());
        assert!(nd_options(&[1, 1, 0]).is_none());
        assert_eq!(solicited(link_local([2, 1, 2, 3, 4, 5]))[13..], [3, 4, 5]);
    }
}
