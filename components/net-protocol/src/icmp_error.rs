//! Bounded ICMP errors for validated unicast TCP/UDP/echo packets.
//! Route/flow authorization, subnet-directed broadcast exclusion and rate
//! limiting belong to the caller. Taking a
//! validated `Packet` excludes malformed IP, fragments, link broadcast and ICMP
//! errors, so this API cannot generate an error in response to another error.
use crate::ipv4::Packet;

pub const MAX_IP_LEN: usize = 576;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    TimeExceeded,
    FragmentationNeeded { mtu: u16 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Source,
    Reason,
    Buffer,
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        sum += (byte as u32) << if i & 1 == 0 { 8 } else { 0 };
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
/// Write an IPv4 datagram (no Ethernet header) with an unchanged quote capped
/// so the response fits 576 IP bytes. No packet or output mutation on failure.
/// The reply starts with TTL 64; it never copies the exhausted incoming TTL.
/// For DF-clear oversize traffic the caller must fragment or use its explicit
/// unsupported-fragment path, not emit a misleading fragmentation-needed error.
pub fn generate(
    packet: &Packet<'_>,
    source: [u8; 4],
    kind: Kind,
    output: &mut [u8],
) -> Result<usize, Error> {
    if source[0] == 0 || source[0] == 127 || source[0] >= 224 {
        return Err(Error::Source);
    }
    match kind {
        Kind::TimeExceeded if packet.ttl() <= 1 => {}
        Kind::FragmentationNeeded { mtu }
            if mtu >= 68 && packet.dont_fragment() && packet.ip_length() > mtu as usize => {}
        _ => return Err(Error::Reason),
    }
    let original = packet.ip_bytes();
    let quote = original.len().min(MAX_IP_LEN - 28);
    let length = 28 + quote;
    if output.len() < length {
        return Err(Error::Buffer);
    }
    let out = &mut output[..length];
    out.fill(0);
    out[0] = 0x45;
    out[1] = original[1] & 0xfc; // Preserve DSCP, originate this control packet as Not-ECT.
    out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 1;
    out[12..16].copy_from_slice(&source);
    out[16..20].copy_from_slice(&packet.source());
    match kind {
        Kind::TimeExceeded => {
            out[20] = 11;
        }
        Kind::FragmentationNeeded { mtu } => {
            out[20] = 3;
            out[21] = 4;
            out[26..28].copy_from_slice(&mtu.to_be_bytes());
        }
    }
    out[28..].copy_from_slice(&original[..quote]);
    let header_check = checksum(&out[..20]);
    out[10..12].copy_from_slice(&header_check.to_be_bytes());
    let icmp_check = checksum(&out[20..]);
    out[22..24].copy_from_slice(&icmp_check.to_be_bytes());
    Ok(length)
}
