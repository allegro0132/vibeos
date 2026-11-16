//! NETSYS v3 receive descriptor facts. No descriptor bit grants forwarding
//! authority. RXD3 bit 2 is L4-valid on MT7988's 32-byte descriptor; it is NOT
//! the checksum bit on MT7981/MT7986's 16-byte descriptors.
//! Reference: Linux mtk_poll_rx and MediaTek mt7988_data (see docs/MT7988A_RX_OFFLOAD.md in vibewrt).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Metadata {
    word3: u32,
    word7: u32,
    queue: u8,
}
impl Metadata {
    pub(crate) fn decode(word3: u32, word7: u32, queue: u8) -> Self {
        Self {
            word3,
            word7,
            queue,
        }
    }
    /// A hardware observation, not a blanket permission to skip validation.
    pub fn l4_valid_bit(self) -> bool {
        self.word3 & (1 << 2) != 0
    }
    pub fn queue(self) -> u8 {
        self.queue
    }
    /// Kept raw until RSS is enabled and its descriptor format is qualified.
    pub fn raw_word7(self) -> u32 {
        self.word7
    }
    /// Only plain, complete IPv4/IPv6 TCP can use this proof. Fragments,
    /// extension headers, VLAN/CPU tags and UDP retain software validation.
    /// `frame` must retain the exact IP/TCP bytes of this owned RX descriptor.
    /// Removing validated L2 tags or moving Ethernet MAC addresses is allowed.
    pub fn tcp_checksum_valid(self, frame: &[u8]) -> bool {
        if !self.l4_valid_bit() || frame.len() < 54 {
            return false;
        }
        let (tcp, end) = match frame[12..14] {
            [8, 0] if frame[14] == 0x45 && frame[23] == 6 => {
                let frag = u16::from_be_bytes([frame[20], frame[21]]);
                if frag & 0xbfff != 0 {
                    return false;
                }
                (
                    34,
                    14 + usize::from(u16::from_be_bytes([frame[16], frame[17]])),
                )
            }
            [0x86, 0xdd] if frame.len() >= 74 && frame[14] >> 4 == 6 && frame[20] == 6 => (
                54,
                54 + usize::from(u16::from_be_bytes([frame[18], frame[19]])),
            ),
            _ => return false,
        };
        if end > frame.len() || end < tcp + 20 {
            return false;
        }
        let header = tcp + usize::from(frame[tcp + 12] >> 4) * 4;
        header >= tcp + 20 && header <= end
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_bit_is_not_a_protocol_or_fragment_proof() {
        let yes = Metadata::decode(4, 0x12345678, 3);
        let no = Metadata::default();
        for v6 in [false, true] {
            let mut p = [0; 74];
            p[12..14].copy_from_slice(if v6 { &[0x86, 0xdd] } else { &[8, 0] });
            let tcp = if v6 {
                p[14] = 0x60;
                p[19] = 20;
                p[20] = 6;
                54
            } else {
                p[14] = 0x45;
                p[17] = 40;
                p[23] = 6;
                34
            };
            p[tcp + 12] = 0x50;
            assert!(yes.tcp_checksum_valid(&p));
            assert!(!no.tcp_checksum_valid(&p));
            p[tcp + 12] = 0xf0;
            assert!(!yes.tcp_checksum_valid(&p));
            p[tcp + 12] = 0x50;
            if v6 {
                p[20] = 44;
            } else {
                p[20] = 0x20;
            }
            assert!(!yes.tcp_checksum_valid(&p));
        }
        assert_eq!((yes.queue(), yes.raw_word7()), (3, 0x12345678));
        assert!(!yes.tcp_checksum_valid(&[0; 13]));
    }
}

use core::sync::atomic::{AtomicU64, Ordering};
static QUEUE_PACKETS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
pub fn queue_packets() -> [u64; 4] {
    core::array::from_fn(|q| QUEUE_PACKETS[q].load(Ordering::Relaxed))
}
pub(crate) fn record_queue(queue: usize) {
    QUEUE_PACKETS[queue].fetch_add(1, Ordering::Relaxed);
}
const RSS: usize = 0x7000;
pub(crate) fn disable_rss(io: &mut impl crate::Io) {
    let value = io.reg(RSS);
    io.set_reg(RSS, value | 4);
    io.set_reg(RSS, (value | 4) & !1);
    io.set_reg(RSS, value & !5);
    io.barrier();
}
pub(crate) fn enable_rss(io: &mut impl crate::Io) {
    // MediaTek's NETSYS v3 Toeplitz key, packed as little-endian MMIO words.
    const KEY: [u8; 40] = [
        0xfa, 0x01, 0xac, 0xbe, 0x3b, 0xb7, 0x42, 0x6a, 0x0c, 0xf2, 0x30, 0x80, 0xa3, 0x2d, 0xcb,
        0x77, 0xb4, 0x30, 0x7b, 0xae, 0xcb, 0x2b, 0xca, 0xd0, 0xb0, 0x8f, 0xa3, 0x43, 0x3d, 0x25,
        0x67, 0x41, 0xc2, 0x0e, 0x5b, 0x25, 0xda, 0x56, 0x5a, 0x6d,
    ];
    let value = (io.reg(RSS) & !5) | (7 << 8) | (7 << 12);
    io.set_reg(RSS, value);
    for (i, word) in KEY.chunks_exact(4).enumerate() {
        io.set_reg(
            RSS + 0x20 + i * 4,
            u32::from_le_bytes(word.try_into().unwrap()),
        );
    }
    // 128 buckets, 16 two-bit entries per word, balanced across rings 0..3.
    for i in 0..8 {
        io.set_reg(RSS + 0x50 + i * 4, 0xe4e4e4e4);
    }
    io.barrier();
    io.set_reg(RSS, value | 4);
    io.set_reg(RSS, value | 5);
    io.set_reg(RSS, value | 1);
    io.barrier();
}
