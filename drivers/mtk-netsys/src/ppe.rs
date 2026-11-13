//! MT7988 NETSYS-v3 PPE configuration inventory and inert FOE encoding.
//! Register/field facts checked against Linux mediatek/mtk_ppe*.h and
//! mtk_eth_soc.c. The control module provides explicit unsafe ownership
//! transitions and a single-rule UDP hardware diagnostic. Policy authorization
//! and bounded revocation remain the routing owner's responsibility.

pub mod control;
pub mod table;

pub const ENTRY_BYTES: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Ppe0,
    Ppe1,
    Ppe2,
}
impl Engine {
    pub const ALL: [Self; 3] = [Self::Ppe0, Self::Ppe1, Self::Ppe2];
    pub fn offset(self) -> usize {
        match self {
            Self::Ppe0 => 0x2000,
            Self::Ppe1 => 0x2400,
            Self::Ppe2 => 0x2c00,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub global: u32,
    pub flow: u32,
    pub table_config: u32,
    pub table_base: u32,
    pub unbound_age: u32,
    pub bound_age0: u32,
    pub bound_age1: u32,
    pub cache: u32,
    pub mtu_drop: u32,
    pub vlan_mtu0: u32,
    pub vlan_mtu1: u32,
}
impl Snapshot {
    /// Reads configuration registers only, never table memory or MIB counters.
    /// Caller supplies FE-relative MMIO reads from a mapped, clocked aperture.
    pub fn read(engine: Engine, mut read: impl FnMut(usize) -> u32) -> Self {
        let mut reg = |offset| read(engine.offset() + offset);
        Self {
            global: reg(0x200),
            flow: reg(0x204),
            table_config: reg(0x21c),
            table_base: reg(0x220),
            unbound_age: reg(0x238),
            bound_age0: reg(0x23c),
            bound_age1: reg(0x240),
            cache: reg(0x320),
            mtu_drop: reg(0x308),
            vlan_mtu0: reg(0x30c),
            vlan_mtu1: reg(0x310),
        }
    }
    pub fn enabled(self) -> bool {
        self.global & 1 != 0
    }
    pub fn busy(self) -> bool {
        self.global & (1 << 31) != 0
    }
    pub fn cache_enabled(self) -> bool {
        self.cache & 1 != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tuple {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    Mtu,
    Address,
    Port,
    UnsupportedEgress,
}
/// Host-side staging bytes only. IB1 state is always INVALID; callers cannot
/// obtain a bound entry from this API. This is not NAT authorization evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedEntry([u8; ENTRY_BYTES]);
impl StagedEntry {
    pub fn ipv4_napt(
        protocol: Protocol,
        original: Tuple,
        translated: Tuple,
        egress: crate::TxPort,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        let unicast_ip = |ip: [u8; 4]| ip[0] != 0 && ip[0] != 127 && ip[0] < 224;
        let unicast_mac = |mac: [u8; 6]| mac != [0; 6] && mac[0] & 1 == 0;
        if !unicast_mac(source_mac)
            || !unicast_mac(destination_mac)
            || [
                original.source,
                original.destination,
                translated.source,
                translated.destination,
            ]
            .iter()
            .any(|ip| !unicast_ip(*ip))
        {
            return Err(EncodeError::Address);
        }
        if [
            original.source_port,
            original.destination_port,
            translated.source_port,
            translated.destination_port,
        ]
        .contains(&0)
        {
            return Err(EncodeError::Port);
        }
        // MxL tag insertion and its PPE egress policy are a separate gate.
        let port = match egress {
            crate::TxPort::Internal => 1,
            crate::TxPort::Wan => 2,
            crate::TxPort::ExternalTagged => return Err(EncodeError::UnsupportedEgress),
        };
        let mut entry = Self([0; ENTRY_BYTES]);
        // HNAPT packet type = 0; INVALID state = 0. TTL rewrite and cache policy
        // are staged, but neither hardware binding nor the static bit is set.
        entry.word(
            0,
            (1 << 22)
                | (1 << 20)
                | if protocol == Protocol::Udp {
                    1 << 30
                } else {
                    0
                },
        );
        for (offset, tuple) in [(4, original), (20, translated)] {
            entry.word(offset, u32::from_be_bytes(tuple.source));
            entry.word(offset + 4, u32::from_be_bytes(tuple.destination));
            entry.word(
                offset + 8,
                (u32::from(tuple.source_port) << 16) | u32::from(tuple.destination_port),
            );
        }
        entry.word(16, (port << 9) | (0xf << 20));
        entry.half(46, 0x0800);
        entry.word(
            48,
            u32::from_be_bytes(destination_mac[..4].try_into().unwrap()),
        );
        entry.half(
            54,
            u16::from_be_bytes(destination_mac[4..].try_into().unwrap()),
        );
        entry.word(56, u32::from_be_bytes(source_mac[..4].try_into().unwrap()));
        entry.half(62, u16::from_be_bytes(source_mac[4..].try_into().unwrap()));
        Ok(entry)
    }
    /// Stage the owned MxL four-copper LAN bridge's fixed outer 802.1Q tag.
    /// This is INVALID data, not switch-lease or NAT authority. The caller must
    /// own the bridge alias/FDB policy before any hardware publication.
    pub fn ipv4_napt_mxl_bridge(
        protocol: Protocol,
        original: Tuple,
        translated: Tuple,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
    ) -> Result<Self, EncodeError> {
        let mut entry = Self::ipv4_napt(protocol, original, translated,
            crate::TxPort::Internal, source_mac, destination_mac)?;
        let ib1 = u32::from_le_bytes(entry.0[..4].try_into().unwrap());
        // NETSYS v2/v3: one VLAN layer at bit 14, 802.1Q insertion at bit 18.
        // GDM3 is PSE port 15. vlan1 is the first halfword of IPv4 L2 info.
        entry.word(0, ib1 | (1 << 14) | (1 << 18));
        entry.word(16, (15 << 9) | (0xf << 20));
        entry.half(44, 0x0c00);
        Ok(entry)
    }
    fn word(&mut self, offset: usize, value: u32) {
        self.0[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn half(&mut self, offset: usize, value: u16) {
        self.0[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    pub fn bytes(&self) -> &[u8; ENTRY_BYTES] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxPort;
    const ORIGINAL: Tuple = Tuple {
        source: [192, 168, 79, 100],
        destination: [192, 168, 78, 100],
        source_port: 12345,
        destination_port: 33445,
    };
    const TRANSLATED: Tuple = Tuple {
        source: [192, 168, 78, 1],
        source_port: 49152,
        ..ORIGINAL
    };
    const SOURCE: [u8; 6] = [2, 0x42, 0x70, 4, 0, 1];
    const DEST: [u8; 6] = [0xc4, 0xd6, 0xd3, 0xa9, 0x32, 0xa6];
    #[test]
    fn inventory_reads_exact_allowlist_with_nonuniform_third_engine() {
        for (engine, base) in Engine::ALL.into_iter().zip([0x2000, 0x2400, 0x2c00]) {
            let offsets = [
                0x200, 0x204, 0x21c, 0x220, 0x238, 0x23c, 0x240, 0x320, 0x308, 0x30c, 0x310,
            ];
            let mut index = 0;
            let snapshot = Snapshot::read(engine, |address| {
                assert_eq!(address, base + offsets[index]);
                index += 1;
                if address == base + 0x200 {
                    0x80000001
                } else if address == base + 0x320 {
                    1
                } else {
                    address as u32
                }
            });
            assert_eq!(index, offsets.len());
            assert!(snapshot.enabled() && snapshot.busy() && snapshot.cache_enabled());
            assert_eq!(snapshot.table_base, (base + 0x220) as u32);
        }
    }
    #[test]
    fn udp_staging_matches_full_v3_layout_and_remains_invalid() {
        let e = StagedEntry::ipv4_napt(
            Protocol::Udp,
            ORIGINAL,
            TRANSLATED,
            TxPort::Wan,
            SOURCE,
            DEST,
        )
        .unwrap();
        let words: [u32; 32] = [
            0x40500000, 0xc0a84f64, 0xc0a84e64, 0x303982a5, 0x00f00400, 0xc0a84e01, 0xc0a84e64,
            0xc00082a5, 0, 0, 0, 0x08000000, 0xc4d6d3a9, 0x32a60000, 0x02427004, 0x00010000, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for (chunk, expected) in e.bytes().chunks_exact(4).zip(words) {
            assert_eq!(chunk, expected.to_le_bytes());
        }
        assert_eq!(
            u32::from_le_bytes(e.bytes()[..4].try_into().unwrap()) & (3 << 28),
            0
        );
    }
    #[test]
    fn mxl_bridge_layout_has_one_fixed_tag_and_gdm3_without_binding() {
        let e = StagedEntry::ipv4_napt_mxl_bridge(
            Protocol::Udp, ORIGINAL, TRANSLATED, SOURCE, DEST).unwrap();
        let words: [u32; 32] = [
            0x40544000, 0xc0a84f64, 0xc0a84e64, 0x303982a5, 0x00f01e00,
            0xc0a84e01, 0xc0a84e64, 0xc00082a5, 0, 0, 0, 0x08000c00,
            0xc4d6d3a9, 0x32a60000, 0x02427004, 0x00010000,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        for (chunk, expected) in e.bytes().chunks_exact(4).zip(words) {
            assert_eq!(chunk, expected.to_le_bytes());
        }
        assert!(matches!(StagedEntry::ipv4_napt_mxl_bridge(
            Protocol::Udp, ORIGINAL, TRANSLATED, [0; 6], DEST), Err(EncodeError::Address)));
    }
    #[test]
    fn tcp_internal_staging_and_unsupported_inputs() {
        let e = StagedEntry::ipv4_napt(
            Protocol::Tcp,
            TRANSLATED,
            ORIGINAL,
            TxPort::Internal,
            DEST,
            SOURCE,
        )
        .unwrap();
        assert_eq!(&e.bytes()[..4], &0x00500000u32.to_le_bytes());
        assert_eq!(&e.bytes()[16..20], &0x00f00200u32.to_le_bytes());
        assert_eq!(&e.bytes()[4..8], &0xc0a84e01u32.to_le_bytes());
        assert_eq!(&e.bytes()[20..24], &0xc0a84f64u32.to_le_bytes());
        assert_eq!(
            StagedEntry::ipv4_napt(
                Protocol::Udp,
                ORIGINAL,
                TRANSLATED,
                TxPort::ExternalTagged,
                SOURCE,
                DEST
            ),
            Err(EncodeError::UnsupportedEgress)
        );
        for tuple in [
            Tuple {
                source: [224, 0, 0, 1],
                ..ORIGINAL
            },
            Tuple {
                destination: [0; 4],
                ..ORIGINAL
            },
        ] {
            assert_eq!(
                StagedEntry::ipv4_napt(Protocol::Udp, tuple, TRANSLATED, TxPort::Wan, SOURCE, DEST),
                Err(EncodeError::Address)
            );
        }
        assert_eq!(
            StagedEntry::ipv4_napt(
                Protocol::Udp,
                Tuple {
                    source_port: 0,
                    ..ORIGINAL
                },
                TRANSLATED,
                TxPort::Wan,
                SOURCE,
                DEST
            ),
            Err(EncodeError::Port)
        );
        assert_eq!(
            StagedEntry::ipv4_napt(
                Protocol::Udp,
                ORIGINAL,
                TRANSLATED,
                TxPort::Wan,
                [0; 6],
                DEST
            ),
            Err(EncodeError::Address)
        );
    }
}
