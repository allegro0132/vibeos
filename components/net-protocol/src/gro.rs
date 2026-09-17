//! Bounded, synchronous IPv4/TCP receive coalescing. No packet is held waiting
//! for a future poll. Only established-flow data with identical ACK/window and
//! options is eligible; control, fragmentation, ECN and reordering fall back.
//! The buffer belongs to the protocol adapter, never to a DMA descriptor.
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv4Packet, TcpPacket};

pub const MAX_SEGMENTS: usize = 16;
const MAX_BYTES: usize = 32 * 1024;
const TCP: usize = 34;

fn u16_at(b: &[u8], n: usize) -> u16 { u16::from_be_bytes([b[n], b[n + 1]]) }
fn u32_at(b: &[u8], n: usize) -> u32 { u32::from_be_bytes(b[n..n + 4].try_into().unwrap()) }
fn addresses(b: &[u8]) -> (IpAddress, IpAddress) {
    (Ipv4Address::new(b[26], b[27], b[28], b[29]).into(),
     Ipv4Address::new(b[30], b[31], b[32], b[33]).into())
}

fn eligible(b: &[u8], trusted: bool) -> Option<(usize, usize)> {
    if b.len() < 54 || b[12..14] != [8, 0] || b[14] != 0x45
        || b[23] != 6 || b[15] & 3 != 0 || u16_at(b, 20) != 0x4000 {
        return None;
    }
    let end = 14 + u16_at(b, 16) as usize;
    let h = (b[46] >> 4) as usize * 4;
    if end > b.len() || h < 20 || TCP + h >= end || b[46] & 15 != 0
        || !matches!(b[47], 0x10 | 0x18) || u16_at(b, 52) != 0 {
        return None;
    }
    // Only no options or the conventional NOP,NOP,timestamp layout. SACK and
    // unknown options retain their original per-segment protocol processing.
    if h != 20 && !(h == 32 && b[54..58] == [1, 1, 8, 10]) { return None; }
    if !trusted {
        let ip = Ipv4Packet::new_checked(&b[14..end]).ok()?;
        let tcp = TcpPacket::new_checked(&b[TCP..end]).ok()?;
        let (src, dst) = addresses(b);
        if !ip.verify_checksum() || !tcp.verify_checksum(&src, &dst) { return None; }
    }
    Some((TCP + h, end))
}

#[cfg(feature = "gro-end-profile")]
#[derive(Clone, Copy)]
pub enum NoInput { IngressBudget, EmptyEndpoint, Authority, Rejected, Unsupported }

pub struct Buffer {
    #[cfg(feature = "gro-end-profile")]
    pub profile: [u64; 31], // 9 end reasons, sizes 0..=16, then 5 receive-none subreasons.
    #[cfg(feature = "gro-end-profile")]
    profile_reason: usize,
    data: Vec<u8>,
    #[cfg(feature = "gro-scatter")]
    deferred_length: Option<usize>,
    header: usize,
    mss: usize,
    next_seq: u32,
    last_id: u16,
    done: bool,
    segments: usize,
    pub merged_segments: u64,
    pub aggregates: u64,
}
impl Buffer {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "gro-end-profile")]
            profile: [0; 31],
            #[cfg(feature = "gro-end-profile")]
            profile_reason: 0,
            #[cfg(feature = "gro-scatter")]
            deferred_length: None,
            data: Vec::with_capacity(MAX_BYTES), header: 0, mss: 0,
            next_seq: 0, last_id: 0, done: true, segments: 0,
            merged_segments: 0, aggregates: 0 }
    }
    pub fn begin(&mut self, b: &[u8], trusted: bool) -> bool {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::RxGro);
        #[cfg(feature = "gro-end-profile")]
        { self.profile_reason = 0; }
        self.data.clear();
        #[cfg(feature = "gro-scatter")]
        { self.deferred_length = None; }
        self.segments = 0;
        self.done = true;
        let Some((header, end)) = eligible(b, trusted) else { return false; };
        if end > MAX_BYTES { return false; }
        self.header = header;
        self.mss = end - header;
        self.next_seq = u32_at(b, 38).wrapping_add(self.mss as u32);
        self.last_id = u16_at(b, 18);
        self.done = b[47] & 8 != 0;
        self.segments = 1;
        #[cfg(feature = "gro-end-profile")]
        { self.profile_reason = if self.done { 1 } else { 7 }; }
        true
    }
    #[cfg(feature = "gro-scatter")]
    pub fn begin_scattered(&mut self, b: &[u8], trusted: bool) -> bool {
        if !self.begin(b, trusted) { return false; }
        self.deferred_length = Some(self.header + self.mss);
        true
    }
    /// `original` is the same immutable frame passed to begin, still owned by
    /// the receive token builder. Materialize it only on the first actual merge.
    pub fn append(&mut self, original: &[u8], b: &[u8], trusted: bool) -> bool {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::RxGro);
        if self.done || self.segments >= MAX_SEGMENTS { return false; }
        let Some((header, end)) = eligible(b, trusted) else {
            #[cfg(feature = "gro-end-profile")]
            { self.profile_reason = 4; }
            return false;
        };
        let payload = end - header;
        let Some(first) = original.get(..self.header + self.mss) else {
            #[cfg(feature = "gro-end-profile")]
            { self.profile_reason = 8; }
            return false;
        };
        let current_length = if self.segments == 1 { first.len() } else { self.data.len() };
        #[cfg(feature = "gro-scatter")]
        let current_length = self.deferred_length.unwrap_or(current_length);
        let id = u16_at(b, 18);
        if header != self.header || payload > self.mss
            || current_length + payload > MAX_BYTES || u32_at(b, 38) != self.next_seq
            || b[..16] != first[..16] || b[20..24] != first[20..24] || b[26..38] != first[26..38]
            || b[42..47] != first[42..47] || b[48..50] != first[48..50]
            || b[54..header] != first[54..header] {
            #[cfg(feature = "gro-end-profile")]
            { self.profile_reason = 5; }
            return false;
        }
        // eligible() requires DF=1, MF=0 and offset=0 for both frames.
        // RFC 6864 section 4.1 makes their IDs meaningless. This opt-in path
        // produces a local TCP receive packet, not a forwarding/GSO template.
        if !cfg!(feature = "gro-atomic-id")
            && id != self.last_id && id != self.last_id.wrapping_add(1) {
            #[cfg(feature = "gro-end-profile")]
            { self.profile_reason = 6; }
            return false;
        }
        #[cfg(feature = "gro-scatter")]
        let copy_payload = self.deferred_length.is_none();
        #[cfg(not(feature = "gro-scatter"))]
        let copy_payload = true;
        if copy_payload {
        if self.segments == 1 {
            self.data.extend_from_slice(&original[..self.header + self.mss]);
        }
        self.data.extend_from_slice(&b[header..end]);
        self.data[47] = b[47];
        }
        #[cfg(feature = "gro-scatter")]
        if let Some(length) = &mut self.deferred_length { *length += payload; }
        self.next_seq = self.next_seq.wrapping_add(payload as u32);
        self.last_id = id;
        self.done = b[47] & 8 != 0 || payload < self.mss;
        #[cfg(feature = "gro-end-profile")]
        { self.profile_reason = if b[47] & 8 != 0 { 1 } else if payload < self.mss { 2 } else { 7 }; }
        self.segments += 1;
        self.merged_segments += 1;
        true
    }
    /// None includes the adapter's per-poll ingress budget, queue exhaustion,
    /// unsupported transport and capability/acquisition failure. This counter
    /// alone does not establish hardware starvation.
    #[cfg(feature = "gro-end-profile")]
    pub fn profile_no_input(&mut self, why: NoInput) {
        self.profile_reason = 3;
        self.profile[26 + why as usize] += 1;
    }
    /// One attempted group, including rejected first frames (size zero).
    /// Recorded before final authority validation; not a delivered-frame count.
    #[cfg(feature = "gro-end-profile")]
    pub fn profile_record(&mut self) {
        self.profile[self.profile_reason] += 1;
        self.profile[9 + self.segments] += 1;
    }
    pub fn has_aggregate(&self) -> bool { self.segments >= 2 }
    pub fn finished(&self) -> bool { self.done }
    pub fn finish(&mut self, trusted: bool) {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::RxGro);
        if self.segments < 2 { return; }
        self.aggregates += 1;
        #[cfg(feature = "gro-scatter")]
        if self.deferred_length.is_some() { return; }
        let len = (self.data.len() - 14) as u16;
        self.data[16..18].copy_from_slice(&len.to_be_bytes());
        // Hardware-verified ingress is consumed with software RX checking off.
        // Otherwise recompute both checksums for the synthetic protocol packet.
        if !trusted {
            Ipv4Packet::new_unchecked(&mut self.data[14..]).fill_checksum();
            let (src, dst) = addresses(&self.data);
            TcpPacket::new_unchecked(&mut self.data[TCP..]).fill_checksum(&src, &dst);
        }
    }
    pub fn bytes(&self) -> &[u8] { &self.data }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(seq: u32, count: usize) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 66 + count];
        b[..12].copy_from_slice(&[2,0,0,0,0,1,2,0,0,0,0,2]);
        b[12..14].copy_from_slice(&[8,0]); b[14]=0x45;
        b[16..18].copy_from_slice(&((52+count) as u16).to_be_bytes());
        b[20]=0x40; b[22]=64; b[23]=6;
        b[26..34].copy_from_slice(&[192,0,2,2,192,0,2,1]);
        b[34..38].copy_from_slice(&[0x10,0,0x20,0]);
        b[38..42].copy_from_slice(&seq.to_be_bytes());
        b[46]=0x80; b[47]=0x10; b[48]=0x40;
        b[54..66].copy_from_slice(&[1,1,8,10,0,0,0,1,0,0,0,2]);
        for (i,v) in b[66..].iter_mut().enumerate() { *v=seq.wrapping_add(i as u32) as u8; }
        checksums(&mut b); b
    }
    fn checksums(b: &mut [u8]) {
        Ipv4Packet::new_unchecked(&mut b[14..]).fill_checksum();
        let (src,dst)=addresses(b);
        TcpPacket::new_unchecked(&mut b[TCP..]).fill_checksum(&src,&dst);
    }
    #[test]
    fn coalesces_payload_and_preserves_checksums_across_sequence_wrap() {
        let a=frame(u32::MAX-999,1448); let mut b=frame(448,713);
        b[18..20].copy_from_slice(&1u16.to_be_bytes()); b[47]|=8; checksums(&mut b);
        let mut g=Buffer::new(); assert!(g.begin(&a,false)); assert!(g.append(&a,&b,false));
        assert!(g.finished()); g.finish(false);
        assert_eq!(g.bytes().len(),66+1448+713);
        assert_eq!(&g.bytes()[66..1514],&a[66..]);
        assert_eq!(&g.bytes()[1514..],&b[66..]);
        assert!(eligible(g.bytes(),false).is_some());
        assert_eq!(g.bytes()[47],0x18); assert_eq!(g.merged_segments,1);
        assert_eq!(g.aggregates,1);
    }
    #[test]
    fn incompatible_frames_do_not_mutate_pending_aggregate() {
        let a=frame(0,100); let b=frame(100,100);
        // Different flow, ACK, window, options, IP attributes, control flags,
        // fragment offset, reserved flags and sequence gaps all force flush.
        for offset in [0,6,15,20,22,23,26,30,34,36,38,42,46,47,48,52,61] {
            let mut other=b.clone(); other[offset]^=1; checksums(&mut other);
            let mut g=Buffer::new(); assert!(g.begin(&a,false));
            assert!(!g.append(&a,&other,false),"offset {offset}"); assert!(g.bytes().is_empty());
        }
        let mut bad=b.clone(); bad[70]^=1;
        let mut g=Buffer::new(); assert!(g.begin(&a,false)); assert!(!g.append(&a,&bad,false));
        assert!(!g.begin(&bad,false));
        for len in 0..b.len() { assert!(!g.begin(&b[..len],false)); }
    }
    #[test]
    fn poll_budget_and_allocation_are_bounded() {
        let mut g=Buffer::new(); let capacity=g.data.capacity();
        let a=frame(0,1448); assert!(g.begin(&a,false));
        for i in 1..MAX_SEGMENTS { assert!(g.append(&a,&frame((i*1448) as u32,1448),false)); }
        assert!(!g.append(&a,&frame((MAX_SEGMENTS*1448) as u32,1448),false));
        g.finish(false); assert_eq!(g.data.capacity(),capacity);
        assert_eq!(g.merged_segments,15); assert!(g.data.len()<=MAX_BYTES);
        let a=frame(0,10); assert!(g.begin(&a,false)); assert!(!g.append(&a,&frame(10,11),false));
        assert!(g.append(&a,&frame(10,5),false)); assert!(g.finished());
    }
    #[test]
    fn singleton_and_rejected_successor_do_not_copy_payload() {
        let a = frame(0, 1448);
        let mut g = Buffer::new();
        assert!(g.begin(&a, false));
        g.finish(false);
        assert!(!g.has_aggregate());
        assert!(g.bytes().is_empty());
        assert!(!g.append(&a, &frame(3000, 1448), false));
        assert!(g.bytes().is_empty());
        assert!(g.append(&a, &frame(1448, 1448), false));
        assert!(g.has_aggregate());
        assert_eq!(&g.bytes()[66..1514], &a[66..]);
        let mut psh = frame(2896, 1448);
        psh[47] |= 8;
        checksums(&mut psh);
        assert!(g.begin(&psh, false));
        assert!(g.finished());
        assert!(g.bytes().is_empty());
        assert!(!g.has_aggregate());
    }

    #[test]
    fn atomic_id_policy_preserves_payload_checksums_and_fragment_exclusion() {
        for trusted in [false, true] {
            let mut a = frame(0, 100);
            a[18..20].copy_from_slice(&65535u16.to_be_bytes());
            checksums(&mut a);
            // Repeated ID and wrapping successor work in both modes; arbitrary
            // changes are accepted only by the atomic-datagram experiment.
            for id in [65535u16, 0, 32768, 9] {
                let mut b = frame(100, 100);
                b[18..20].copy_from_slice(&id.to_be_bytes());
                checksums(&mut b);
                let mut g = Buffer::new();
                assert!(g.begin(&a, trusted));
                let accepted = cfg!(feature = "gro-atomic-id") || id == 65535 || id == 0;
                assert_eq!(g.append(&a, &b, trusted), accepted);
                if accepted {
                    // Software finalization verifies the synthetic packet even
                    // when original ingress checksums were trusted.
                    g.finish(false);
                    assert!(eligible(g.bytes(), false).is_some());
                    assert_eq!(&g.bytes()[66..166], &a[66..]);
                    assert_eq!(&g.bytes()[166..], &b[66..]);
                    assert_eq!(u16_at(g.bytes(), 18), 65535);
                } else {
                    assert!(!g.has_aggregate());
                    assert!(g.bytes().is_empty());
                }
                for flags in [0u16, 0x2000, 0x6000, 0x4001, 0x0001, 0xc000] {
                    let mut fragment = b.clone();
                    fragment[20..22].copy_from_slice(&flags.to_be_bytes());
                    checksums(&mut fragment);
                    let mut g = Buffer::new();
                    assert!(!g.begin(&fragment, trusted));
                    assert!(g.begin(&a, trusted));
                    assert!(!g.append(&a, &fragment, trusted));
                    assert!(!g.has_aggregate());
                }
            }
        }
    }

    #[cfg(feature = "gro-end-profile")]
    #[test]
    fn end_profile_distinguishes_boundaries_and_conserves_attempts() {
        let a = frame(0, 100);
        let b = frame(100, 100);
        let mut g = Buffer::new();
        assert!(!g.begin(&[], false)); g.profile_record();
        let mut psh = a.clone(); psh[47] |= 8; checksums(&mut psh);
        assert!(g.begin(&psh, false)); g.profile_record();
        assert!(g.begin(&a, false));
        assert!(g.append(&a, &frame(100, 50), false)); g.profile_record();
        assert!(g.begin(&a, false)); g.profile_no_input(NoInput::EmptyEndpoint); g.profile_record();
        assert!(g.begin(&a, false)); assert!(!g.append(&a, &[], false)); g.profile_record();
        let mut changed = b.clone(); changed[48] ^= 1; checksums(&mut changed);
        assert!(g.begin(&a, false)); assert!(!g.append(&a, &changed, false)); g.profile_record();
        let mut id = b.clone(); id[18..20].copy_from_slice(&9u16.to_be_bytes()); checksums(&mut id);
        assert!(g.begin(&a, false));
        assert_eq!(g.append(&a, &id, false), cfg!(feature = "gro-atomic-id"));
        g.profile_record();
        assert!(g.begin(&a, false));
        for n in 1..MAX_SEGMENTS { assert!(g.append(&a, &frame(n as u32 * 100, 100), false)); }
        g.profile_record();
        assert!(g.begin(&a, false)); assert!(!g.append(&[], &b, false)); g.profile_record();
        let atomic = cfg!(feature = "gro-atomic-id");
        assert_eq!(&g.profile[..9], if atomic { &[1,1,1,1,1,1,0,2,1] } else { &[1; 9] });
        assert_eq!(g.profile[9], 1); // ineligible first frame
        assert_eq!(g.profile[10], if atomic { 5 } else { 6 }); // singleton attempts
        assert_eq!(g.profile[11], if atomic { 2 } else { 1 }); // short second frame
        assert_eq!(g.profile[25], 1); // bounded 16-frame group
        assert_eq!(g.profile[..9].iter().sum::<u64>(), g.profile[9..26].iter().sum::<u64>());
        assert_eq!(g.profile[27], 1);
        assert_eq!(g.profile[26..].iter().sum::<u64>(), g.profile[3]);
        // The default path still rejects without materializing the frame.
        assert!(g.begin(&a, false));
        assert_eq!(g.append(&a, &id, false), atomic);
        assert_eq!(g.has_aggregate(), atomic);
        assert_eq!(g.bytes().is_empty(), !atomic);
    }

}
