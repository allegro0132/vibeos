//! Bounded coalescing of already-authorized wire packets for hardware TSO.
//! The caller preserves queue order and holds session/authority publication locks.
//! No waiting for future packets: flush whenever the existing queue is exhausted.
extern crate alloc;
use alloc::vec::Vec;
use crate::net::{PacketStamp, PacketStampMismatch};
use vibeos_hal::tcp_segmentation::{TcpSegments, MAX_LOGICAL_PACKET};

pub struct TxCoalescer {
    bytes: Vec<u8>,
    stamp: Option<PacketStamp>,
    mss: usize,
    frames: usize,
    closed: bool,
}
impl TxCoalescer {
    pub fn new() -> Self {
        Self { bytes: Vec::with_capacity(MAX_LOGICAL_PACKET), stamp: None,
            mss: 0, frames: 0, closed: false }
    }
    pub fn frames(&self) -> usize { self.frames }
    pub fn clear(&mut self) {
        self.bytes.clear(); self.stamp = None; self.frames = 0; self.closed = false;
    }
    /// False leaves both this batch and the caller's frame unchanged. A rejected
    /// frame must remain ahead of all successors. Limit to plain TCP headers until
    /// option replication has physical qualification. DF permits new IP IDs.
    pub fn push(&mut self, packet: &[u8], stamp: PacketStamp) -> bool {
        if packet.len() > 1514 || packet.len() < 55 { return false; }
        let payload = packet.len() - 54;
        let Ok(request) = TcpSegments::new(packet, payload) else { return false; };
        if request.header_bytes() != 54 || self.closed || self.frames >= 16 { return false; }
        if self.frames == 0 {
            if payload < 64 { return false; }
            self.bytes.extend_from_slice(packet);
            self.stamp = Some(stamp); self.mss = payload;
        } else {
            if self.stamp != Some(stamp) || payload > self.mss
                || self.bytes.len() + payload > MAX_LOGICAL_PACKET { return false; }
            let first = &self.bytes;
            let next_seq = u32::from_be_bytes(first[38..42].try_into().unwrap())
                .wrapping_add((first.len() - 54) as u32);
            // Ignore only fields rebuilt by TSO: lengths, IP ID, sequence,
            // checksums and final PSH. All flow, ACK, window and QoS bits match.
            if packet[..16] != first[..16] || packet[20..24] != first[20..24]
                || packet[26..38] != first[26..38] || packet[42..47] != first[42..47]
                || packet[48..50] != first[48..50] || packet[52..54] != first[52..54]
                || u32::from_be_bytes(packet[38..42].try_into().unwrap()) != next_seq {
                return false;
            }
            self.bytes.extend_from_slice(&packet[54..]);
            let ip_len = (self.bytes.len() - 14) as u16;
            self.bytes[16..18].copy_from_slice(&ip_len.to_be_bytes());
            self.bytes[47] = packet[47];
        }
        self.frames += 1;
        self.closed = payload < self.mss || packet[47] & 8 != 0;
        true
    }
    pub fn request(&self, expected: PacketStamp) -> Result<TcpSegments<'_>, PacketStampMismatch> {
        let observed = self.stamp.expect("nonempty transmit batch");
        if observed != expected { return Err(PacketStampMismatch { expected, observed }); }
        Ok(TcpSegments::new(&self.bytes, self.mss).expect("validated coalesced packets"))
    }
}
impl Default for TxCoalescer { fn default() -> Self { Self::new() } }
