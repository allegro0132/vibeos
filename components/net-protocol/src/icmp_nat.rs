//! Validated traditional ICMP error quotes and allocation-free NAT rewriting.
//! Options, fragments, ICMP extensions and quotes of unsupported protocols are
//! explicitly rejected. Quoted transport checksums are not validated (RFC 5508);
//! they may describe a damaged packet and are often only partially present.
use crate::ipv4::{
    fold, put, replace, sum, unicast_ip, unicast_mac, word, Egress, Error, PortRewrite, Translation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quoted {
    Tcp { source: u16, destination: u16 },
    Udp { source: u16, destination: u16 },
    Echo { identifier: u16, reply: bool },
}
#[derive(Clone, Copy, Debug)]
pub struct Rewrite {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub quoted: Translation,
}
pub struct Packet<'a> {
    frame: &'a mut [u8],
    length: usize,
    quoted: Quoted,
    checksum_offset: Option<usize>,
}
fn header(ip: &[u8]) -> Result<usize, Error> {
    if ip.len() < 20 {
        return Err(Error::Truncated);
    }
    if ip[0] >> 4 != 4 || ip[0] & 15 < 5 {
        return Err(Error::Header);
    }
    if ip[0] != 0x45 {
        return Err(Error::Options);
    }
    if word(ip, 2) < 20 {
        return Err(Error::Header);
    }
    if fold(sum(&ip[..20])) != 65535 {
        return Err(Error::Checksum);
    }
    // Preserve unused flags in both the outer header and quoted original.
    if word(ip, 6) & 0x3fff != 0 {
        return Err(Error::Fragment);
    }
    if !unicast_ip(&ip[12..16]) || !unicast_ip(&ip[16..20]) {
        return Err(Error::Address);
    }
    Ok(word(ip, 2) as usize)
}
impl<'a> Packet<'a> {
    pub fn parse(frame: &'a mut [u8], ingress_mac: [u8; 6]) -> Result<Self, Error> {
        if frame.len() < 70 {
            return Err(Error::Truncated);
        }
        if !unicast_mac(&ingress_mac)
            || frame[..6] != ingress_mac
            || !unicast_mac(&frame[6..12])
            || word(frame, 12) != 0x0800
        {
            return Err(Error::Ethernet);
        }
        let length = header(&frame[14..])?;
        if length < 56 || frame.len() < 14 + length {
            return Err(Error::Truncated);
        }
        if frame[23] != 1 {
            return Err(Error::Protocol);
        }
        let code = frame[35];
        if !matches!((frame[34], code), (3, 0..=15) | (11, 0..=1) | (12, 0..=2)) || frame[39] != 0 {
            return Err(Error::Protocol);
        }
        if fold(sum(&frame[34..14 + length])) != 65535 {
            return Err(Error::Checksum);
        }
        let quoted_length = length - 28;
        let original_length = header(&frame[42..14 + length])?;
        if original_length < 28 || quoted_length > original_length {
            return Err(Error::Transport);
        }
        let payload_length = quoted_length - 20;
        let (quoted, checksum_offset) = match frame[51] {
            6 => {
                // An isolated first checksum byte cannot be adjusted correctly.
                if payload_length == 17 {
                    return Err(Error::Truncated);
                }
                (
                    Quoted::Tcp {
                        source: word(frame, 62),
                        destination: word(frame, 64),
                    },
                    if payload_length >= 18 { Some(78) } else { None },
                )
            }
            17 => (
                Quoted::Udp {
                    source: word(frame, 62),
                    destination: word(frame, 64),
                },
                Some(68),
            ),
            1 if matches!(frame[62], 0 | 8) && frame[63] == 0 => (
                Quoted::Echo {
                    identifier: word(frame, 66),
                    reply: frame[62] == 0,
                },
                Some(64),
            ),
            _ => return Err(Error::Protocol),
        };
        Ok(Self {
            frame,
            length,
            quoted,
            checksum_offset,
        })
    }
    pub fn ttl(&self) -> u8 {
        self.frame[22]
    }
    pub fn ip_length(&self) -> usize {
        self.length
    }
    pub fn source(&self) -> [u8; 4] {
        self.frame[26..30].try_into().unwrap()
    }
    pub fn destination(&self) -> [u8; 4] {
        self.frame[30..34].try_into().unwrap()
    }
    pub fn quoted_source(&self) -> [u8; 4] {
        self.frame[54..58].try_into().unwrap()
    }
    pub fn quoted_destination(&self) -> [u8; 4] {
        self.frame[58..62].try_into().unwrap()
    }
    pub fn quoted(&self) -> Quoted {
        self.quoted
    }
    /// Authorize with the live mapping/permission first. Errors do not change
    /// bytes; successful output preserves ICMP type/code/MTU and quote contents
    /// except the translated tuple and checksums. Only the outer TTL decreases.
    pub fn forward(self, egress: Egress, rewrite: Rewrite) -> Result<usize, Error> {
        if self.frame[22] <= 1 {
            return Err(Error::TtlExpired);
        }
        if self.length > egress.mtu as usize {
            return Err(Error::Mtu {
                mtu: egress.mtu,
                dont_fragment: word(self.frame, 20) & 0x4000 != 0,
            });
        }
        if !unicast_mac(&egress.source_mac)
            || !unicast_mac(&egress.destination_mac)
            || !unicast_ip(&rewrite.source)
            || !unicast_ip(&rewrite.destination)
            || !unicast_ip(&rewrite.quoted.source)
            || !unicast_ip(&rewrite.quoted.destination)
            || !matches!(
                (self.quoted, rewrite.quoted.ports),
                (
                    Quoted::Tcp { .. } | Quoted::Udp { .. },
                    PortRewrite::Ports { .. }
                ) | (Quoted::Echo { .. }, PortRewrite::EchoIdentifier(_))
            )
        {
            return Err(Error::Rewrite);
        }
        let f = self.frame;
        let pseudo = !matches!(self.quoted, Quoted::Echo { .. });
        let enabled = self
            .checksum_offset
            .filter(|&o| !matches!(self.quoted, Quoted::Udp { .. }) || word(f, o) != 0);
        let mut transport_checksum = enabled.map(|o| word(f, o)).unwrap_or(0);
        let mut inner_checksum = word(f, 52);
        for (offset, ip) in [
            (54, rewrite.quoted.source),
            (58, rewrite.quoted.destination),
        ] {
            for part in [0, 2] {
                let old = word(f, offset + part);
                let new = word(&ip, part);
                inner_checksum = replace(inner_checksum, old, new);
                if pseudo && enabled.is_some() {
                    transport_checksum = replace(transport_checksum, old, new);
                }
                put(f, offset + part, new);
            }
        }
        let fields = match rewrite.quoted.ports {
            PortRewrite::Ports {
                source,
                destination,
            } => [(62, source), (64, destination)],
            // Replace the second field with itself; echo has only one identifier.
            PortRewrite::EchoIdentifier(id) => [(66, id), (68, word(f, 68))],
        };
        for (offset, new) in fields {
            if enabled.is_some() {
                transport_checksum = replace(transport_checksum, word(f, offset), new);
            }
            put(f, offset, new);
        }
        put(f, 52, inner_checksum);
        if let Some(offset) = enabled {
            if matches!(self.quoted, Quoted::Udp { .. } | Quoted::Echo { .. })
                && transport_checksum == 0
            {
                transport_checksum = 65535;
            }
            put(f, offset, transport_checksum);
        }
        let ttl_protocol = word(f, 22);
        let mut outer_checksum = replace(word(f, 24), ttl_protocol, ttl_protocol - 256);
        for (offset, ip) in [(26, rewrite.source), (30, rewrite.destination)] {
            for part in [0, 2] {
                outer_checksum = replace(outer_checksum, word(f, offset + part), word(&ip, part));
                put(f, offset + part, word(&ip, part));
            }
        }
        f[22] -= 1;
        put(f, 24, outer_checksum);
        put(f, 36, 0);
        let check = !fold(sum(&f[34..14 + self.length]));
        put(f, 36, check);
        f[..6].copy_from_slice(&egress.destination_mac);
        f[6..12].copy_from_slice(&egress.source_mac);
        Ok(14 + self.length)
    }
}
