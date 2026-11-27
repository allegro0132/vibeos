//! Bounded software GRO/GSO for proxy-owned TCP. Never changes the wire MTU.
//! GRO is called only after current socket ownership admission. Unsupported
//! input remains an ordinary packet; original frames are checked before merge.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::wire::{IpAddress, Ipv4Packet, Ipv6Packet, TcpPacket};
pub const MAX_BYTES: usize = 16 * 1024;
/// Maximum LAN aggregate retained by the connection worker before NIC handoff.
pub const LAN_GSO_BYTES: usize = 32 * 1024;
/// MT7988 IPv6 TSO input fits one aligned DMA page, including Ethernet headers.
pub const IPV6_TSO_BYTES: usize = 4096;
pub const MAX_SEGMENTS: usize = 16;
static STATS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// GRO groups, merged segments, merged bytes, ineligible, incompatible,
/// GSO requests, emitted segments, GSO payload bytes.
pub fn counters() -> [u64; 8] {
    core::array::from_fn(|i| STATS[i].load(Ordering::Relaxed))
}
fn inc(i: usize, n: usize) {
    STATS[i].fetch_add(n as u64, Ordering::Relaxed);
}
pub fn record_gro(segments: usize, payload_bytes: usize) {
    inc(0, 1);
    inc(1, segments - 1);
    inc(2, payload_bytes);
}
fn be16(b: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([b[n], b[n + 1]])
}
fn be32(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(b[n..n + 4].try_into().unwrap())
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    tcp: usize,
    header: usize,
    end: usize,
    v6: bool,
}
fn layout(b: &[u8]) -> Option<Layout> {
    if b.len() < 54 {
        return None;
    }
    let (tcp, end, v6) = match b[12..14] {
        [8, 0] if b[14] == 0x45 && b[23] == 6 && be16(b, 20) & 0xbfff == 0 => {
            (34, 14 + be16(b, 16) as usize, false)
        }
        [0x86, 0xdd] if b.len() >= 74 && b[14] >> 4 == 6 && b[20] == 6 => {
            (54, 54 + be16(b, 18) as usize, true)
        }
        _ => return None,
    };
    if end > b.len() || tcp + 20 > end {
        return None;
    }
    let header = tcp + usize::from(b[tcp + 12] >> 4) * 4;
    if header < tcp + 20 || header > end {
        return None;
    }
    Some(Layout {
        tcp,
        header,
        end,
        v6,
    })
}
/// Header buffer size and TCP header length for a validated Ethernet GSO frame.
pub fn tso_headers(frame: &[u8]) -> Option<(usize, usize)> {
    let l = layout(frame)?;
    (l.end == frame.len() && l.header < l.end).then_some((l.header, l.header - l.tcp))
}
/// TCP checksum field in an ordinary Ethernet packet eligible for full TX COE.
pub fn tcp_checksum_field(frame: &[u8]) -> Option<usize> {
    let l = layout(frame)?;
    (frame.len() <= 1514 && l.end == frame.len()).then_some(l.tcp + 16)
}
fn addresses(b: &[u8], l: Layout) -> (IpAddress, IpAddress) {
    if l.v6 {
        let p = Ipv6Packet::new_unchecked(&b[14..l.end]);
        (p.src_addr().into(), p.dst_addr().into())
    } else {
        let p = Ipv4Packet::new_unchecked(&b[14..l.end]);
        (p.src_addr().into(), p.dst_addr().into())
    }
}
pub fn checksum_tcp(b: &mut [u8]) {
    let Some(l) = layout(b) else { return };
    let (src, dst) = addresses(b, l);
    TcpPacket::new_unchecked(&mut b[l.tcp..l.end]).fill_checksum(&src, &dst);
    if !l.v6 {
        Ipv4Packet::new_unchecked(&mut b[14..l.end]).fill_checksum();
    }
}
fn checked_data(b: &[u8], tcp_verified:bool) -> Option<Layout> {
    let l = layout(b)?;
    if l.header == l.end
        || b[l.tcp + 12] & 15 != 0
        || !matches!(b[l.tcp + 13], 0x10 | 0x18)
        || be16(b, l.tcp + 18) != 0
    {
        return None;
    }
    // ECN and unrecognized options stay on the ordinary TCP path.
    if l.v6 {
        if (b[15] >> 4) & 3 != 0 {
            return None;
        }
    } else if b[15] & 3 != 0 || be16(b, 20) != 0x4000 {
        return None;
    }
    if l.header != l.tcp + 20
        && !(l.header == l.tcp + 32 && b[l.tcp + 20..l.tcp + 24] == [1, 1, 8, 10])
    {
        return None;
    }
    if !l.v6 && !Ipv4Packet::new_unchecked(&b[14..l.end]).verify_checksum() {
        return None;
    }
    let (src, dst) = addresses(b, l);
    if !tcp_verified && !TcpPacket::new_unchecked(&b[l.tcp..l.end]).verify_checksum(&src, &dst) {
        return None;
    }
    Some(l)
}
/// Immutable checked prefix. Append is nonmutating on failure and never
/// revalidates an already accepted member. Lifetime pins the original bytes.
pub struct Gro<'a> {
    frames: [&'a [u8]; MAX_SEGMENTS],
    first: &'a [u8],
    layout: Layout,
    next: u32,
    bytes: usize,
    count: usize,
    finished: bool,
    last_flags: u8,
}
impl<'a> Gro<'a> {
    pub fn new(first: &'a [u8]) -> Option<Self> {Self::new_verified(first,false)}
    pub fn new_verified(first:&'a [u8],tcp_verified:bool)->Option<Self> {
        let Some(l) = checked_data(first,tcp_verified) else {
            inc(3, 1);
            return None;
        };
        if l.end > MAX_BYTES {
            return None;
        }
        let n = l.end - l.header;
        let mut frames = [&[][..]; MAX_SEGMENTS];
        frames[0] = &first[l.header..l.end];
        Some(Self {
            frames,
            first,
            layout: l,
            next: be32(first, l.tcp + 4).wrapping_add(n as u32),
            bytes: n,
            count: 1,
            finished: first[l.tcp + 13] & 8 != 0,
            last_flags: first[l.tcp + 13],
        })
    }
    pub fn push(&mut self, b: &'a [u8]) -> bool {self.push_verified(b,false)}
    pub fn push_verified(&mut self,b:&'a [u8],tcp_verified:bool)->bool {
        if self.finished || self.count == MAX_SEGMENTS {
            return false;
        }
        let Some(l) = checked_data(b,tcp_verified) else {
            inc(3, 1);
            return false;
        };
        let f = self.first;
        let a = self.layout;
        let ip_same = if a.v6 && l.v6 {
            b[14..18] == f[14..18] && b[20..54] == f[20..54]
        } else if !a.v6 && !l.v6 {
            b[14..16] == f[14..16] && b[20..24] == f[20..24] && b[26..34] == f[26..34]
        } else {
            false
        };
        if l.tcp != a.tcp
            || l.header != a.header
            || !ip_same
            || b[..14] != f[..14]
            || b[l.tcp..l.tcp + 4] != f[a.tcp..a.tcp + 4]
            || be32(b, l.tcp + 4) != self.next
            || b[l.tcp + 8..l.tcp + 13] != f[a.tcp + 8..a.tcp + 13]
            || b[l.tcp + 14..l.tcp + 16] != f[a.tcp + 14..a.tcp + 16]
            || b[l.tcp + 20..l.header] != f[a.tcp + 20..a.header]
        {
            inc(4, 1);
            return false;
        }
        let n = l.end - l.header;
        if self.bytes + n + l.header > MAX_BYTES {
            return false;
        }
        self.frames[self.count] = &b[l.header..l.end];
        self.bytes += n;
        self.count += 1;
        self.next = self.next.wrapping_add(n as u32);
        self.last_flags = b[l.tcp + 13];
        self.finished = self.last_flags & 8 != 0;
        true
    }
    pub fn count(&self) -> usize {
        self.count
    }
    /// The caller supplies exactly the checked immutable members, in order.
    pub fn materialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.materialize_into(&mut out, true);
        out
    }
    /// An internal aggregate retains the proof from its validated members.
    /// Only the public wire-ready form above needs a fresh TCP checksum.
    pub fn materialize_into(&self, out: &mut Vec<u8>, wire_checksum: bool) {
        let l = self.layout;
        out.clear();
        out.reserve(l.header + self.bytes);
        out.extend_from_slice(&self.first[..l.header]);
        for payload in &self.frames[..self.count] {
            out.extend_from_slice(payload);
        }
        assert_eq!(out.len(), l.header + self.bytes);
        let total = out.len();
        if l.v6 {
            out[18..20].copy_from_slice(&((total - 54) as u16).to_be_bytes());
        } else {
            out[16..18].copy_from_slice(&((total - 14) as u16).to_be_bytes());
        }
        out[l.tcp + 13] = self.last_flags;
        if wire_checksum {checksum_tcp(out);} else {
            out[l.tcp+16..l.tcp+18].fill(0);
            if !l.v6 {Ipv4Packet::new_unchecked(&mut out[14..]).fill_checksum();}
        }
        record_gro(self.count, self.bytes);
    }
}
/// One stack submission and its actual, negotiated payload MSS. Segmentation
/// has a cursor, so TX credit exhaustion never loses the unsent tail.
pub struct Gso {
    bytes: Vec<u8>,
    layout: Layout,
    mss: usize,
    offset: usize,
    segments: u16,
    payload_sums:Option<Vec<u16>>,
}
impl Gso {
    pub fn into_bytes(self)->Vec<u8>{self.bytes}
    pub fn into_packet(self)->crate::tx_packet::Packet {
        self.into_packet_for_nic(false)
    }
    pub fn into_packet_for_nic(self, hardware_checksum: bool)->crate::tx_packet::Packet {
        assert_eq!(self.offset,0);
        // Payload-only partial sums are independent of sequence/flags and
        // computed by this output TCP endpoint's worker, before NIC handoff.
        let payload_sums = if hardware_checksum {
            // The NIC will compute the wire checksums. If the final port
            // changes, write_next_with computes each fallback checksum.
            None
        } else {
            Some(self.bytes[self.layout.header..self.layout.end].chunks(self.mss)
                .map(smoltcp::wire::checksum::data).collect())
        };
        crate::tx_packet::Packet{bytes:self.bytes,mss:Some(self.mss as u16),payload_sums}
    }
    pub fn from_packet(packet:crate::tx_packet::Packet,mtu:usize)->Self {
        let mut g=Self::create(packet.bytes,packet.mss.expect("GSO MSS"),mtu,false);
        g.payload_sums=packet.payload_sums;g
    }
    pub fn new(bytes: Vec<u8>, mss: u16, mtu: usize) -> Self {Self::create(bytes,mss,mtu,true)}
    fn create(bytes: Vec<u8>, mss: u16, mtu: usize,record:bool) -> Self {
        let l = layout(&bytes).expect("stack GSO must be plain IPv4/IPv6 TCP");
        assert!(bytes.len() == l.end && bytes.len() <= LAN_GSO_BYTES && l.header < l.end);
        assert!(mss != 0 && usize::from(mss) + l.header - 14 <= mtu);
        assert!(bytes[l.tcp + 13] & 0x26 == 0 && bytes[l.tcp + 13] & 0x10 != 0);
        if record {inc(5, 1);inc(7, l.end - l.header);}
        Self {
            bytes,
            layout: l,
            mss: usize::from(mss),
            offset: 0,
            segments: 0,
            payload_sums:None,
        }
    }
    pub fn next(&mut self) -> Option<Vec<u8>> {
        let n=(self.layout.end-self.layout.header-self.offset).min(self.mss);
        if n==0{return None;}
        let mut out=alloc::vec![0;self.layout.header+n];self.write_next(&mut out)?;Some(out)
    }
    /// Fill a reserved NIC staging buffer; no per-segment allocation.
    pub fn write_next(&mut self,buffer:&mut [u8])->Option<usize> {self.write_next_with(buffer,|out,bytes|out.copy_from_slice(bytes))}
    /// Render only the L2/L3/TCP headers. Both emitters use the same MSS,
    /// flags, sequence number and IP length for a given cursor.
    fn write_header(&self, out: &mut [u8], n: usize) {
        let l = self.layout;
        let last = self.offset + n == l.end - l.header;
        out[..l.header].copy_from_slice(&self.bytes[..l.header]);
        let seq = be32(&self.bytes, l.tcp + 4).wrapping_add(self.offset as u32);
        out[l.tcp + 4..l.tcp + 8].copy_from_slice(&seq.to_be_bytes());
        if !last {
            out[l.tcp + 13] &= !(1 | 8);
        } // FIN and PSH only on the final segment.
        if self.offset != 0 {
            out[l.tcp + 13] &= !0x80;
        } // CWR only on the first segment.
        let total = l.header+n;
        if l.v6 {
            out[18..20].copy_from_slice(&((total - 54) as u16).to_be_bytes());
        } else {
            out[16..18].copy_from_slice(&((total - 14) as u16).to_be_bytes());
            out[18..20].copy_from_slice(
                &be16(&self.bytes, 18)
                    .wrapping_add(self.segments)
                    .to_be_bytes(),
            );
        }
    }

    /// Temporarily overlay the segment header immediately before its payload.
    /// The NIC copies this view synchronously into its permanent DMA slot.
    /// Restore even the consumed prefix so a retry or software fallback still
    /// sees the original aggregate, including when MSS is shorter than a header.
    pub fn submit_next_checksum<R, E>(&mut self, submit: impl FnOnce(&[u8]) -> Result<R, E>) -> Result<Option<R>, E> {
        let l = self.layout;
        let n = (l.end - l.header - self.offset).min(self.mss);
        if n == 0 { return Ok(None); }
        let receipt = self.with_header(n, submit)?;
        self.advance(n);
        Ok(Some(receipt))
    }

    /// The final physical route can be resolved against the original frame.
    pub fn ipv6_tso_frame(&self) -> Option<&[u8]> {
        (self.layout.v6 && self.layout.end - self.layout.header - self.offset > self.mss)
            .then_some(&self.bytes)
    }

    /// Hand the NIC at least two wire segments, within the bounded IPv6 DMA window.
    /// Leave a one-segment tail to the normal egress path.
    pub fn submit_next_ipv6_tso<R, E>(&mut self, submit: impl FnOnce(&[u8], u16) -> Result<R, E>) -> Result<Option<R>, E> {
        let l = self.layout;
        let remaining = l.end - l.header - self.offset;
        let capacity = IPV6_TSO_BYTES - l.header;
        // Intermediate requests end on an MSS boundary. If two full wire
        // segments do not fit, let the caller send one full segment and
        // reconsider the shorter suffix on the next iteration.
        let n = if remaining <= capacity { remaining } else { capacity / self.mss * self.mss };
        if !l.v6 || n <= self.mss { return Ok(None); }
        let mss = self.mss as u16;
        let receipt = self.with_header(n, |frame| submit(frame, mss))?;
        self.offset += n;
        self.segments += n.div_ceil(self.mss) as u16;
        // Subsequent software fallback can always recompute from the remaining bytes.
        self.payload_sums = None;
        Ok(Some(receipt))
    }

    fn with_header<R>(&mut self, n: usize, submit: impl FnOnce(&[u8]) -> R) -> R {
        let l = self.layout;
        let mut header = [0u8; 14 + 40 + 60];
        self.write_header(&mut header[..l.header], n);
        header[l.tcp+16..l.tcp+18].fill(0);
        if !l.v6 { header[24..26].fill(0); }
        let segment = &mut self.bytes[self.offset..self.offset + l.header + n];
        // After the swap, header holds the original bytes to restore.
        segment[..l.header].swap_with_slice(&mut header[..l.header]);
        let result = submit(segment);
        segment[..l.header].copy_from_slice(&header[..l.header]);
        result
    }

    pub fn write_next_with(&mut self,buffer:&mut [u8],mut copy:impl FnMut(&mut [u8],&[u8]))->Option<usize> {
        let l = self.layout;
        let n = (l.end - l.header - self.offset).min(self.mss);
        if n == 0 { return None; }
        let total = l.header+n;
        let out = &mut buffer[..total];
        self.write_header(out, n);
        copy(&mut out[l.header..],&self.bytes[l.header + self.offset..l.header + self.offset + n]);
        Self::finish_segment(out, l, self.payload_sums.as_ref().map(|s| s[self.segments as usize]));
        self.advance(n);
        Some(total)
    }
    fn finish_segment(out: &mut [u8], l: Layout, payload_sum: Option<u16>) {
        let total = out.len();
        if let Some(payload_sum) = payload_sum {
            use smoltcp::wire::checksum;
            let (src,dst)=addresses(out,Layout{end:total,..l});
            out[l.tcp+16..l.tcp+18].fill(0);
            let sum= !checksum::combine(&[checksum::pseudo_header(&src,&dst,smoltcp::wire::IpProtocol::Tcp,(total-l.tcp) as u32),checksum::data(&out[l.tcp..l.header]),payload_sum]);
            out[l.tcp+16..l.tcp+18].copy_from_slice(&sum.to_be_bytes());
            if !l.v6 {Ipv4Packet::new_unchecked(&mut out[14..]).fill_checksum();}
        } else {checksum_tcp(out);}
    }

    /// Present a checksummed segment with eight writable prefix bytes for PPPoE.
    /// Earlier payload provides the scratch space after the first segment.
    /// The callback can rewrite the headers and must consume the view synchronously.
    pub fn submit_next_pppoe<R, E>(&mut self, submit: impl FnOnce(&mut [u8]) -> Result<R, E>)
        -> Result<Option<R>, E>
    {
        const PREFIX: usize = 8;
        let l = self.layout;
        let n = (l.end - l.header - self.offset).min(self.mss);
        if n == 0 || self.offset < PREFIX { return Ok(None); }
        let mut saved = [0u8; PREFIX + 14 + 40 + 60];
        let headers = PREFIX + l.header;
        self.write_header(&mut saved[PREFIX..headers], n);
        let view = &mut self.bytes[self.offset - PREFIX..self.offset + l.header + n];
        view[..headers].swap_with_slice(&mut saved[..headers]);
        Self::finish_segment(&mut view[PREFIX..], l, self.payload_sums.as_ref().map(|s| s[self.segments as usize]));
        let result = submit(view);
        view[..headers].copy_from_slice(&saved[..headers]);
        let receipt = result?;
        self.advance(n);
        Ok(Some(receipt))
    }

    fn advance(&mut self, n: usize) {
        self.offset += n;
        self.segments = self.segments.wrapping_add(1);
        inc(6, 1);
    }
    pub fn done(&self) -> bool {
        self.offset == self.layout.end - self.layout.header
    }
}

#[cfg(any(test, feature = "packet-offload-test-fixtures"))]
pub mod fixtures {
    use super::*;
    pub fn packet(v6: bool, seq: u32, len: usize, options: bool) -> Vec<u8> {
        let ip = if v6 { 40 } else { 20 };
        let tcp = 14 + ip;
        let header = tcp + if options { 32 } else { 20 };
        let mut b = alloc::vec![0;header+len];
        b[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
        b[12..14].copy_from_slice(&(if v6 { 0x86ddu16 } else { 0x800 }).to_be_bytes());
        if v6 {
            b[14] = 0x60;
            b[18..20].copy_from_slice(&((header + len - 54) as u16).to_be_bytes());
            b[20] = 6;
            b[21] = 64;
            b[22..26].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
            b[37] = 1;
            b[38..42].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
            b[53] = 2;
        } else {
            b[14] = 0x45;
            b[16..18].copy_from_slice(&((header + len - 14) as u16).to_be_bytes());
            b[18..20].copy_from_slice(&65530u16.to_be_bytes());
            b[20] = 0x40;
            b[22] = 64;
            b[23] = 6;
            b[26..30].copy_from_slice(&[192, 0, 2, 1]);
            b[30..34].copy_from_slice(&[192, 0, 2, 2]);
        }
        b[tcp..tcp + 4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        b[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        b[tcp + 8..tcp + 12].copy_from_slice(&42u32.to_be_bytes());
        b[tcp + 12] = (((header - tcp) / 4) as u8) << 4;
        b[tcp + 13] = 0x10;
        b[tcp + 14..tcp + 16].copy_from_slice(&32768u16.to_be_bytes());
        if options {
            b[tcp + 20..header].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        }
        for (i, x) in b[header..].iter_mut().enumerate() {
            *x = (seq.wrapping_add(i as u32) as u8).wrapping_mul(17);
        }
        checksum_tcp(&mut b);
        b
    }
    fn sum(b: &[u8]) -> u32 {
        b.chunks(2)
            .map(|p| u32::from(p[0]) * 256 + u32::from(*p.get(1).unwrap_or(&0)))
            .sum()
    }
    fn folded(mut s: u32) -> u16 {
        while s >> 16 != 0 {
            s = (s & 65535) + (s >> 16);
        }
        s as u16
    }
    pub fn wire_valid(b: &[u8], mtu: usize) {
        let l = layout(b).unwrap();
        assert_eq!(l.end, b.len());
        assert!(b.len() <= mtu + 14);
        let n = (l.end - l.tcp) as u32;
        let pseudo = if l.v6 {
            sum(&b[22..54]) + n + 6
        } else {
            assert_eq!(folded(sum(&b[14..34])), 65535);
            sum(&b[26..34]) + n + 6
        };
        assert_eq!(folded(pseudo + sum(&b[l.tcp..l.end])), 65535);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fixtures::{packet, wire_valid};
    #[test]
    fn gro_ipv4_ipv6_preserves_payload_options_and_sequence_wrap() {
        for v6 in [false, true] {
            for opt in [false, true] {
                let a = packet(v6, u32::MAX - 50, 101, opt);
                let mut b = packet(v6, 50, 73, opt);
                let l = layout(&b).unwrap();
                b[l.tcp + 13] = 0x18;
                checksum_tcp(&mut b);
                let originals = (a.clone(), b.clone());
                let mut gro = Gro::new(&a).unwrap();
                assert!(gro.push(&b));
                let merged = gro.materialize();
                let l = layout(&merged).unwrap();
                assert_eq!(merged[l.tcp + 13], 0x18);
                assert_eq!(
                    &merged[l.header..],
                    [&a[l.header..], &b[l.header..]].concat()
                );
                wire_valid(&merged, 1500);
                assert_eq!((a, b), originals);
            }
        }
    }
    #[test]
    fn gro_rejects_corrupt_control_disorder_and_incompatible_metadata() {
        for v6 in [false, true] {
            let a = packet(v6, 100, 100, true);
            let base = packet(v6, 200, 100, true);
            let l = layout(&base).unwrap();
            for offset in [
                0,
                l.tcp,
                l.tcp + 4,
                l.tcp + 8,
                l.tcp + 14,
                l.tcp + 24,
                if v6 { 21 } else { 22 },
            ] {
                let mut b = base.clone();
                b[offset] ^= 1;
                checksum_tcp(&mut b);
                let mut g = Gro::new(&a).unwrap();
                assert!(!g.push(&b), "offset {offset}");
                assert_eq!(g.count(), 1);
            }
            for flags in [0x11, 0x12, 0x14, 0x30, 0x50, 0x90] {
                let mut b = base.clone();
                b[l.tcp + 13] = flags;
                checksum_tcp(&mut b);
                assert!(Gro::new(&b).is_none());
            }
            let mut b = base.clone();
            *b.last_mut().unwrap() ^= 1;
            assert!(!Gro::new(&a).unwrap().push(&b));
            let mut b = base.clone();
            b[if v6 { 15 } else { 15 }] |= if v6 { 0x10 } else { 1 };
            checksum_tcp(&mut b);
            assert!(Gro::new(&b).is_none());
            let mut b = base.clone();
            if v6 {
                b[20] = 44
            } else {
                b[20] |= 0x20
            };
            assert!(Gro::new(&b).is_none());
            let mut b = base.clone();
            b[l.tcp + 20] = 2;
            checksum_tcp(&mut b);
            assert!(Gro::new(&b).is_none());
        }
    }
    #[test]
    fn gro_bounds_and_psh_flush() {
        for v6 in [false, true] {
            let frames: Vec<_> = (0..20)
                .map(|i| packet(v6, 100 + i * 100, 100, false))
                .collect();
            let mut g = Gro::new(&frames[0]).unwrap();
            for f in &frames[1..MAX_SEGMENTS] {
                assert!(g.push(f));
            }
            assert!(!g.push(&frames[MAX_SEGMENTS]));
            assert_eq!(g.count(), MAX_SEGMENTS);
            let mut first = frames[0].clone();
            let l = layout(&first).unwrap();
            first[l.tcp + 13] = 0x18;
            checksum_tcp(&mut first);
            assert!(!Gro::new(&first).unwrap().push(&frames[1]));
            let frames: Vec<_> = (0..16)
                .map(|i| packet(v6, 100 + i * 1400, 1400, false))
                .collect();
            let mut g = Gro::new(&frames[0]).unwrap();
            for f in &frames[1..] {
                if !g.push(f) {
                    break;
                }
            }
            assert!(g.materialize().len() <= MAX_BYTES);
        }
    }
    #[test]
    fn gso_real_mss_partial_credit_flags_checksums_and_wrap() {
        for v6 in [false, true] {
            for options in [false, true] {
                for mtu in [1280, 1500] {
                    for mss in [64, 536, 1200] {
                        let mut input = packet(v6, u32::MAX - 500, 10003, options);
                        let l = layout(&input).unwrap();
                        input[l.tcp + 13] = 0x19;
                        let payload = input[l.header..].to_vec();
                        let mut send = Gso::new(input, mss, mtu);
                        let mut collected = Vec::new();
                        let mut count = 0;
                        // Simulate an output queue that repeatedly stops after three segments.
                        while !send.done() {
                            for _ in 0..3 {
                                let Some(p) = send.next() else { break };
                                wire_valid(&p, mtu);
                                let h = layout(&p).unwrap();
                                assert_eq!(
                                    be32(&p, h.tcp + 4),
                                    (u32::MAX - 500).wrapping_add(collected.len() as u32)
                                );
                                assert_eq!(
                                    p[h.tcp + 13],
                                    if collected.len() + h.end - h.header == 10003 {
                                        0x19
                                    } else {
                                        0x10
                                    }
                                );
                                assert!(h.end - h.header <= mss as usize);
                                if !v6 {
                                    assert_eq!(be16(&p, 18), 65530u16.wrapping_add(count));
                                }
                                collected.extend_from_slice(&p[h.header..]);
                                count += 1;
                            }
                        }
                        assert_eq!(collected, payload);
                        assert!(send.next().is_none());
                    }
                }
            }
        }
    }
    #[test]
    fn nic_gso_partial_payload_sums_match_full_checksum_for_odd_mss_and_tail() {
        for v6 in [false,true] {for options in [false,true] {for mss in [65,537,1201,1400] {
            let mut bytes=packet(v6,u32::MAX-501,LAN_GSO_BYTES - 96,options);let l=layout(&bytes).unwrap();bytes[l.tcp+13]=0x19;
            let mut reference=Gso::new(bytes.clone(),mss,1500);
            let transfer=Gso::new(bytes,mss,1500).into_packet();assert!(transfer.payload_sums.is_some());
            let mut actual=Gso::from_packet(transfer,1500);let mut buffer=alloc::vec![0;MAX_BYTES];
            while let Some(expected)=reference.next(){let n=actual.write_next(&mut buffer).unwrap();assert_eq!(&buffer[..n],&expected);wire_valid(&buffer[..n],1500);}
            assert!(actual.done());assert!(actual.write_next(&mut buffer).is_none());
        }}}
    }
    #[test]
    fn hardware_candidate_can_fall_back_after_route_lookup() {
        let bytes = packet(false, u32::MAX - 500, 10003, true);
        let mut reference = Gso::new(bytes.clone(), 1201, 1500);
        let packet = Gso::new(bytes, 1201, 1500).into_packet_for_nic(true);
        assert!(packet.payload_sums.is_none());
        let mut fallback = Gso::from_packet(packet, 1500);
        while let Some(expected) = reference.next() {
            assert_eq!(fallback.next().unwrap(), expected);
        }
        assert!(fallback.done());
    }
    #[test]
    fn pppoe_segments_preserve_the_aggregate_and_do_not_advance_on_retry() {
        for v6 in [false, true] {
            for precompute in [false, true] {
                // Short MSS exercises overlaps with the original aggregate header.
                for mss in [7, 63, 1201] {
                    let original = packet(v6, u32::MAX - 13, 2521, true);
                    let mut reference = Gso::new(original.clone(), mss, 1492);
                    let source = Gso::new(original.clone(), mss, 1492).into_packet_for_nic(!precompute);
                    let mut cursor = Gso::from_packet(source, 1492);
                    while let Some(expected) = reference.next() {
                        if cursor.offset < 8 {
                            assert_eq!(cursor.submit_next_pppoe(|_| Ok::<_, ()>(())).unwrap(), None);
                            assert_eq!(cursor.next().unwrap(), expected);
                            continue;
                        }
                        let submit = |view: &mut [u8]| {
                            assert_eq!(&view[8..], &expected);
                            view[..22].fill(0xa5);
                        };
                        assert_eq!(cursor.submit_next_pppoe(|view| { submit(view); Err::<(), _>(()) }), Err(()));
                        assert_eq!(cursor.submit_next_pppoe(|view| { submit(view); Ok::<_, ()>(()) }), Ok(Some(())));
                    }
                    assert!(cursor.done());
                    assert_eq!(cursor.into_bytes(), original);
                }
            }
        }
    }

    #[test]
    fn checksum_offload_segment_matches_software_after_checksum_fill() {
        for v6 in [false, true] {
            for mss in [23, 65, 1201] {
                let mut bytes = packet(v6, u32::MAX - 200, 3903, true);
                let tcp = layout(&bytes).unwrap().tcp;
                bytes[tcp + 13] = 0x99;
                let mut reference = Gso::new(bytes.clone(), mss, 1500);
                let packet = Gso::new(bytes.clone(), mss, 1500).into_packet_for_nic(true);
                let mut actual = Gso::from_packet(packet, 1500);
                while let Some(expected) = reference.next() {
                    assert_eq!(actual.submit_next_checksum(|_| Err::<(), _>("busy")), Err("busy"));
                    let frame = actual.submit_next_checksum(|view| {
                        let mut frame = view.to_vec();
                        assert_eq!(be16(&frame, tcp+16), 0);
                        checksum_tcp(&mut frame);
                        Ok::<_, ()>(frame)
                    }).unwrap().unwrap();
                    assert_eq!(frame, expected);
                }
                assert!(actual.done());
                assert_eq!(actual.into_bytes(), bytes);
            }
        }
    }
    #[test]
    fn ipv6_tso_batches_preserve_wire_bytes_across_retry_and_software_fallback() {
        for mss in [65, 1201, 1440] {
            let mut bytes = packet(true, u32::MAX - 200, 8201, false);
            let l = layout(&bytes).unwrap();
            bytes[l.tcp+13] = 0x99;
            let packet = Gso::new(bytes.clone(), mss, 1500).into_packet();
            let mut gso = Gso::from_packet(packet, 1500);
            let mut payload = Vec::new();
            if 2 * usize::from(mss) <= IPV6_TSO_BYTES - l.header {
                assert_eq!(gso.submit_next_ipv6_tso(|_,_| Err::<(),_>("busy")), Err("busy"));
            }
            for _ in 0..2 {
                let submitted = gso.submit_next_ipv6_tso(|frame, mss| {
                    assert!(frame.len() <= IPV6_TSO_BYTES);
                    assert_eq!(be32(frame,l.tcp+4),(u32::MAX-200).wrapping_add(payload.len() as u32));
                    assert_eq!(frame[l.tcp+13], if payload.is_empty() {0x90} else {0x10});
                    let mut wire = Gso::new(frame.to_vec(), mss, 1500);
                    while let Some(segment) = wire.next() {
                        wire_valid(&segment,1500);
                        payload.extend_from_slice(&segment[l.header..]);
                    }
                    Ok::<_, ()>(())
                }).unwrap();
                if submitted.is_none() {
                    let segment = gso.next().unwrap();
                    assert_eq!(segment.len() - l.header, usize::from(mss));
                    wire_valid(&segment, 1500);
                    payload.extend_from_slice(&segment[l.header..]);
                }
            }
            while let Some(segment) = gso.next() {
                wire_valid(&segment,1500);
                payload.extend_from_slice(&segment[l.header..]);
            }
            assert_eq!(payload,&bytes[l.header..]);
            assert_eq!(gso.into_bytes(),bytes);
        }
    }
    #[test]
    fn last_ipv6_tso_batch_keeps_final_flags_and_short_tail_uses_software() {
        for size in [1220, 1600, 3000, 3900] {
            let mut bytes = packet(true, 123, size, true);
            let l = layout(&bytes).unwrap();
            bytes[l.tcp+13] = 0x99;
            let mut gso = Gso::new(bytes.clone(), 1220, 1500);
            let mut offset = 0;
            while !gso.done() {
                let sent = gso.submit_next_ipv6_tso(|frame,mss| {
                    let n = frame.len() - l.header;
                    assert!(n > usize::from(mss));
                    let flags = 0x10 | if offset == 0 { 0x80 } else { 0 }
                        | if offset + n == size { 0x09 } else { 0 };
                    assert_eq!(frame[l.tcp+13], flags);
                    offset += n;
                    Ok::<_, ()>(())
                }).unwrap();
                if sent.is_some() { continue; }
                let tail = gso.next().unwrap();
                let end = offset + tail.len() - l.header;
                assert_eq!(tail[l.tcp+13] & 9, if end == size {9} else {0});
                assert_eq!(&tail[l.header..], &bytes[l.header+offset..l.header+end]);
                offset = end;
                wire_valid(&tail, 1500);
            }
            assert!(gso.done());
        }
    }
    #[test]
    #[should_panic]
    fn gso_refuses_mss_larger_than_actual_mtu() {
        Gso::new(packet(true, 1, 3000, true), 1400, 1280);
    }
}
