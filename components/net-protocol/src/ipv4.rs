//! Allocation-free IPv4 fast-path packet validation and header rewriting.
//!
//! This is a mechanism, not routing or firewall policy. The owner must authorize
//! a flow and resolve its egress neighbor before calling `forward`. Options,
//! fragments and other protocols require an explicit slow path; they cannot
//! accidentally bypass NAT validation. Every rejected operation leaves bytes
//! unchanged. Ethernet padding is excluded from transport checksums and output.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    Ethernet,
    Header,
    Checksum,
    Address,
    Options,
    Fragment,
    Protocol,
    Transport,
    TtlExpired,
    Mtu { mtu: u16, dont_fragment: bool },
    Rewrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp {
        source: u16,
        destination: u16,
        flags: u8,
    },
    Udp {
        source: u16,
        destination: u16,
    },
    Echo {
        identifier: u16,
        reply: bool,
    },
}

/// Addresses and ports come from the authoritative flow table, never packet
/// hints. ICMP echo has one identifier rather than a pair of port numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRewrite {
    Ports { source: u16, destination: u16 },
    EchoIdentifier(u16),
}
#[derive(Clone, Copy, Debug)]
pub struct Translation {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub ports: PortRewrite,
}
#[derive(Clone, Copy, Debug)]
pub struct Egress {
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub mtu: u16,
}

/// Exclusive borrow keeps validated lengths/checksums from being changed by
/// another consumer before the transaction. No mutable raw view is exposed.
pub struct Packet<'a> {
    frame: &'a mut [u8],
    length: usize,
    transport: Transport,
}

pub(crate) fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
pub(crate) fn put(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}
pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}
pub(crate) fn sum(bytes: &[u8]) -> u32 {
    // Callers bound this to an IPv4 packet (at most 65535 bytes), whose
    // unfolded 16-bit-word sum fits u32. Preserve the scalar small-header path.
    if bytes.len() >= 32 {
        // SAFETY: all u64 bit patterns are valid. align_to returns only aligned,
        // in-bounds whole words; no read extends past the original slice.
        // The caller owns/stabilizes this packet while its checksum is read.
        let (prefix, words, suffix) = unsafe { bytes.align_to::<u64>() };
        let mut result = 0u32;
        for (i, byte) in prefix.iter().enumerate() {
            result += (*byte as u32) << (if i & 1 == 0 { 8 } else { 0 });
        }
        let odd = prefix.len() & 1 != 0;
        for &word in words {
            // An odd prefix makes the first byte of each aligned word the low
            // checksum byte. Reversing byte order swaps all four word lanes;
            // lane order is immaterial to their sum.
            let word = if odd { word.to_le() } else { word.to_be() };
            result += ((word & 0xffff)
                + ((word >> 16) & 0xffff)
                + ((word >> 32) & 0xffff)
                + (word >> 48)) as u32;
        }
        for (i, byte) in suffix.iter().enumerate() {
            result += (*byte as u32) << (if (i + prefix.len()) & 1 == 0 { 8 } else { 0 });
        }
        return result;
    }
    let mut result = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        result += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(last) = chunks.remainder().first() {
        result += (*last as u32) << 8;
    }
    result
}
/// RFC 1624 equation 3, including the positive/negative zero boundary.
pub(crate) fn replace(checksum: u16, old: u16, new: u16) -> u16 {
    !fold((!checksum) as u32 + (!old) as u32 + new as u32)
}
pub(crate) fn unicast_mac(mac: &[u8]) -> bool {
    mac.len() == 6 && mac != [0; 6] && mac[0] & 1 == 0
}
pub(crate) fn unicast_ip(ip: &[u8]) -> bool {
    ip.len() == 4 && ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

impl<'a> Packet<'a> {
    /// Only ordinary unicast Ethernet IPv4 directed at `ingress_mac` is eligible.
    /// Subnet-directed broadcast and source validation are route/policy checks.
    pub fn parse(frame: &'a mut [u8], ingress_mac: [u8; 6]) -> Result<Self, Error> {
        if frame.len() < 34 {
            return Err(Error::Truncated);
        }
        if !unicast_mac(&ingress_mac)
            || frame[..6] != ingress_mac
            || !unicast_mac(&frame[6..12])
            || word(frame, 12) != 0x0800
        {
            return Err(Error::Ethernet);
        }
        let ip = &frame[14..];
        let header = (ip[0] as usize & 15) * 4;
        if ip[0] >> 4 != 4 || header < 20 {
            return Err(Error::Header);
        }
        let length = word(ip, 2) as usize;
        if length < header {
            return Err(Error::Header);
        }
        if ip.len() < length {
            return Err(Error::Truncated);
        }
        if fold(sum(&ip[..header])) != 0xffff {
            return Err(Error::Checksum);
        }
        if !unicast_ip(&ip[12..16]) || !unicast_ip(&ip[16..20]) {
            return Err(Error::Address);
        }
        let fragment = word(ip, 6);
        // RFC 1812 4.2.2.3/5.2.5: preserve the reserved flag when forwarding;
        // only MF and a nonzero offset indicate fragmentation.
        if fragment & 0x3fff != 0 {
            return Err(Error::Fragment);
        }
        if header != 20 {
            return Err(Error::Options);
        }
        let payload = &ip[20..length];
        let pseudo = sum(&ip[12..20]) + ip[9] as u32 + payload.len() as u32;
        let transport = match ip[9] {
            6 => {
                if payload.len() < 20
                    || (payload[12] as usize >> 4) * 4 < 20
                    || (payload[12] as usize >> 4) * 4 > payload.len()
                {
                    return Err(Error::Transport);
                }
                if fold(pseudo + sum(payload)) != 0xffff {
                    return Err(Error::Checksum);
                }
                Transport::Tcp {
                    source: word(payload, 0),
                    destination: word(payload, 2),
                    flags: payload[13],
                }
            }
            17 => {
                if payload.len() < 8 || word(payload, 4) as usize != payload.len() {
                    return Err(Error::Transport);
                }
                if word(payload, 6) != 0 && fold(pseudo + sum(payload)) != 0xffff {
                    return Err(Error::Checksum);
                }
                Transport::Udp {
                    source: word(payload, 0),
                    destination: word(payload, 2),
                }
            }
            1 => {
                if payload.len() < 8 || payload[1] != 0 || !matches!(payload[0], 0 | 8) {
                    return Err(Error::Protocol);
                }
                if fold(sum(payload)) != 0xffff {
                    return Err(Error::Checksum);
                }
                Transport::Echo {
                    identifier: word(payload, 4),
                    reply: payload[0] == 0,
                }
            }
            _ => return Err(Error::Protocol),
        };
        Ok(Self {
            frame,
            length,
            transport,
        })
    }

    pub fn source(&self) -> [u8; 4] {
        self.frame[26..30].try_into().unwrap()
    }
    pub fn destination(&self) -> [u8; 4] {
        self.frame[30..34].try_into().unwrap()
    }
    pub fn transport(&self) -> Transport {
        self.transport
    }
    pub(crate) fn tcp_details(&self) -> Result<Option<crate::tcp_window::Segment>, Error> {
        if !matches!(self.transport, Transport::Tcp { .. }) {
            return Ok(None);
        }
        let header = (self.frame[46] >> 4) as usize * 4;
        let flags = self.frame[47];
        let options = &self.frame[54..34 + header];
        let mut cursor = 0;
        let mut scale = None;
        while cursor < options.len() {
            let kind = options[cursor];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                cursor += 1;
                continue;
            }
            if cursor + 2 > options.len() {
                return Err(Error::Transport);
            }
            let length = options[cursor + 1] as usize;
            if length < 2 || cursor + length > options.len() {
                return Err(Error::Transport);
            }
            if kind == 3 {
                if length != 3 {
                    return Err(Error::Transport);
                }
                if flags & 2 != 0 {
                    if scale.is_some() {
                        return Err(Error::Transport);
                    }
                    scale = Some(options[cursor + 2].min(14));
                }
            }
            cursor += length;
        }
        Ok(Some(crate::tcp_window::Segment {
            seq: u32::from_be_bytes(self.frame[38..42].try_into().unwrap()),
            ack: u32::from_be_bytes(self.frame[42..46].try_into().unwrap()),
            payload: self.length - 20 - header,
            flags,
            window: word(self.frame, 48),
            scale,
        }))
    }
    pub(crate) fn ip_bytes(&self) -> &[u8] {
        &self.frame[14..14 + self.length]
    }
    pub fn dont_fragment(&self) -> bool {
        word(self.frame, 20) & 0x4000 != 0
    }
    pub fn ttl(&self) -> u8 {
        self.frame[22]
    }
    pub fn ip_length(&self) -> usize {
        self.length
    }

    /// Authorize and resolve before this call. Consumes the validated view so a
    /// successful packet cannot accidentally be forwarded/decremented twice.
    /// Errors return the original frame unchanged for bounded ICMP generation.
    /// Returns Ethernet length without padding; DMA owner zeroes wire padding.
    pub fn forward(self, egress: Egress, translation: Option<Translation>) -> Result<usize, Error> {
        if !unicast_mac(&egress.source_mac) || !unicast_mac(&egress.destination_mac) {
            return Err(Error::Rewrite);
        }
        if self.ttl() <= 1 {
            return Err(Error::TtlExpired);
        }
        if self.length > egress.mtu as usize {
            return Err(Error::Mtu {
                mtu: egress.mtu,
                dont_fragment: word(self.frame, 20) & 0x4000 != 0,
            });
        }
        if let Some(t) = translation {
            if !unicast_ip(&t.source)
                || !unicast_ip(&t.destination)
                || !matches!(
                    (self.transport, t.ports),
                    (
                        Transport::Tcp { .. } | Transport::Udp { .. },
                        PortRewrite::Ports { .. }
                    ) | (Transport::Echo { .. }, PortRewrite::EchoIdentifier(_))
                )
            {
                return Err(Error::Rewrite);
            }
        }
        // All fallible checks precede the first write. Only bounded header words
        // are touched here; transport payload was verified once during parsing.
        let f = self.frame;
        let old_ttl_protocol = word(f, 22);
        let mut ip_checksum = replace(word(f, 24), old_ttl_protocol, old_ttl_protocol - 0x100);
        if let Some(t) = translation {
            let (checksum_offset, pseudoheader, enabled) = match self.transport {
                Transport::Tcp { .. } => (50, true, true),
                Transport::Udp { .. } => (40, true, word(f, 40) != 0),
                Transport::Echo { .. } => (36, false, true),
            };
            let mut transport_checksum = word(f, checksum_offset);
            for (offset, addr) in [(26, t.source), (30, t.destination)] {
                for part in [0, 2] {
                    let old = word(f, offset + part);
                    let new = word(&addr, part);
                    ip_checksum = replace(ip_checksum, old, new);
                    if pseudoheader && enabled {
                        transport_checksum = replace(transport_checksum, old, new);
                    }
                    put(f, offset + part, new);
                }
            }
            match t.ports {
                PortRewrite::Ports {
                    source,
                    destination,
                } => {
                    for (offset, new) in [(34, source), (36, destination)] {
                        if enabled {
                            transport_checksum = replace(transport_checksum, word(f, offset), new);
                        }
                        put(f, offset, new);
                    }
                }
                PortRewrite::EchoIdentifier(new) => {
                    transport_checksum = replace(transport_checksum, word(f, 38), new);
                    put(f, 38, new);
                }
            }
            // UDP's calculated zero is encoded as 0xffff; disabled stays zero.
            if enabled {
                if matches!(self.transport, Transport::Udp { .. }) && transport_checksum == 0 {
                    transport_checksum = 0xffff;
                }
                put(f, checksum_offset, transport_checksum);
                if matches!(self.transport, Transport::Echo { .. }) {
                    // An echo reply can be entirely zero apart from checksum;
                    // unlike IPv4 headers it lacks a guaranteed nonzero word.
                    // Recompute this bounded control-protocol checksum so both
                    // representations of one's-complement zero are correct.
                    put(f, checksum_offset, 0);
                    let checksum = !fold(sum(&f[34..14 + self.length]));
                    put(f, checksum_offset, checksum);
                }
            }
        }
        f[22] -= 1;
        put(f, 24, ip_checksum);
        f[..6].copy_from_slice(&egress.destination_mac);
        f[6..12].copy_from_slice(&egress.source_mac);
        Ok(14 + self.length)
    }
}

#[cfg(test)]
mod tests;
