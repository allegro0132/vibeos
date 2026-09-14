//! One-shot diagnostic for the Mars test TCP source port. Counts canonical
//! headers at protocol generation (0) and successful driver admission (1).
//! Fingerprints are commutative and exclude offloaded checksums and payload;
//! they detect count/sequence differences, not corruption or delivery order.

#[cfg(not(feature = "network-tx-audit"))]
#[inline(always)]
pub fn record(_: usize, _: &[u8]) {}

#[cfg(feature = "network-tx-audit")]
mod enabled {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};

    // 0 = never armed, 1 = active, 2 = permanently sealed. No counter reset.
    static STATE: AtomicUsize = AtomicUsize::new(0);
    static HW_REQUEST: AtomicUsize = AtomicUsize::new(0);
    static HW_DONE: AtomicUsize = AtomicUsize::new(0);
    static HW_DATA: [AtomicU64; 11] = [const { AtomicU64::new(0) }; 11];
    // One command requester and one exclusive hardware publisher. Snapshot
    // requests are serviced by the existing driver, never by borrowing its
    // engine concurrently from the shell. Values are firmware-defined.
    pub fn request_hardware() -> usize {
        HW_REQUEST.fetch_add(1, SeqCst) + 1
    }
    pub fn pending_hardware_request() -> Option<usize> {
        let request = HW_REQUEST.load(SeqCst);
        (request != HW_DONE.load(SeqCst)).then_some(request)
    }
    pub fn publish_hardware(request: usize, values: [u64; 11]) {
        for (slot, value) in HW_DATA.iter().zip(values) {
            slot.store(value, SeqCst);
        }
        HW_DONE.store(request, SeqCst);
    }
    pub fn hardware_snapshot(request: usize) -> Option<[u64; 11]> {
        (HW_DONE.load(SeqCst) == request).then(|| core::array::from_fn(|i| HW_DATA[i].load(SeqCst)))
    }
    #[repr(align(64))]
    struct Counters {
        writers: AtomicUsize,
        values: [AtomicU64; 6],
    }
    static DATA: [Counters; 2] = [const {
        Counters {
            writers: AtomicUsize::new(0),
            values: [const { AtomicU64::new(0) }; 6],
        }
    }; 2];

    pub fn start() -> bool {
        STATE.compare_exchange(0, 1, SeqCst, SeqCst).is_ok()
    }
    pub fn seal() -> Option<[[u64; 6]; 2]> {
        if STATE.swap(2, SeqCst) == 0 {
            return None;
        }
        if DATA.iter().any(|d| d.writers.load(SeqCst) != 0) {
            return None;
        }
        Some(core::array::from_fn(|i| {
            core::array::from_fn(|j| DATA[i].values[j].load(SeqCst))
        }))
    }
    fn mix(mut n: u64) -> u64 {
        n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        n = (n ^ (n >> 27)).wrapping_mul(0x94d049bb133111eb);
        n ^ (n >> 31)
    }
    fn fingerprint(frame: &[u8]) -> Option<(u64, u64, u8)> {
        if frame.len() < 54 || frame[12..14] != [8, 0] {
            return None;
        }
        let ip = &frame[14..];
        let ihl = (ip[0] as usize & 15) * 4;
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if ip[0] >> 4 != 4
            || ihl < 20
            || total > ip.len()
            || total < ihl + 20
            || ip[9] != 6
            || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
            || ip[12..16] != [192, 168, 77, 10]
            || ip[16..20] != [192, 168, 77, 1]
        {
            return None;
        }
        let tcp = &ip[ihl..total];
        if tcp[..2] != 5300u16.to_be_bytes() {
            return None;
        }
        let header = (tcp[12] as usize >> 4) * 4;
        if header < 20 || header > tcp.len() {
            return None;
        }
        let payload = (tcp.len() - header) as u64;
        let seq_ack = u64::from_be_bytes(tcp[4..12].try_into().unwrap());
        let ports = u32::from_be_bytes(tcp[..4].try_into().unwrap()) as u64;
        let flags = tcp[13];
        let window = u16::from_be_bytes([tcp[14], tcp[15]]) as u64;
        let shape = payload | ((flags as u64) << 32) | (window << 40) | ((header as u64) << 56);
        Some((
            mix(seq_ack) ^ mix(shape).rotate_left(17) ^ mix(ports).rotate_left(31),
            payload,
            flags,
        ))
    }
    pub fn record(stage: usize, frame: &[u8]) {
        if STATE.load(SeqCst) != 1 || stage >= DATA.len() {
            return;
        }
        let Some((hash, bytes, flags)) = fingerprint(frame) else {
            return;
        };
        let d = &DATA[stage];
        d.writers.fetch_add(1, SeqCst);
        // A writer that raced with seal must not publish after its snapshot.
        if STATE.load(SeqCst) == 1 {
            d.values[0].fetch_add(1, SeqCst);
            d.values[1].fetch_add(bytes, SeqCst);
            d.values[2].fetch_add(hash, SeqCst);
            d.values[3].fetch_xor(hash, SeqCst);
            d.values[4].fetch_add(u64::from(flags & 2 != 0), SeqCst);
            d.values[5].fetch_add(u64::from(flags & 1 != 0), SeqCst);
        }
        d.writers.fetch_sub(1, SeqCst);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn frame() -> [u8; 60] {
            let mut b = [0; 60];
            b[12..14].copy_from_slice(&[8, 0]);
            b[14] = 0x45;
            b[16..18].copy_from_slice(&46u16.to_be_bytes());
            b[23] = 6;
            b[26..30].copy_from_slice(&[192, 168, 77, 10]);
            b[30..34].copy_from_slice(&[192, 168, 77, 1]);
            b[34..36].copy_from_slice(&5300u16.to_be_bytes());
            b[36..38].copy_from_slice(&40000u16.to_be_bytes());
            b[38..42].copy_from_slice(&123456u32.to_be_bytes());
            b[42..46].copy_from_slice(&765432u32.to_be_bytes());
            b[46] = 0x50;
            b[47] = 0x18;
            b[48..50].copy_from_slice(&4096u16.to_be_bytes());
            b
        }
        #[test]
        fn canonical_header_excludes_offload_fields_but_tracks_sequence() {
            let mut b = frame();
            let first = fingerprint(&b).unwrap();
            assert_eq!(first.0, 7696094402707891304); // Shared host-parser vector.
            assert_eq!(first.1, 6);
            assert_eq!(first.2, 0x18);
            b[24] = 0xaa;
            b[50] = 0xbb;
            b[59] = 0xcc;
            assert_eq!(fingerprint(&b), Some(first));
            b[41] ^= 1;
            assert_ne!(fingerprint(&b).unwrap().0, first.0);
            b[34] = 0;
            assert!(fingerprint(&b).is_none());
        }
        #[test]
        fn malformed_or_fragmented_input_is_not_a_source_event() {
            let b = frame();
            for n in 0..60 {
                assert!(fingerprint(&b[..n]).is_none());
            }
            let mut b = frame();
            b[20] = 0x20;
            assert!(fingerprint(&b).is_none());
            let mut b = frame();
            b[46] = 0xf0;
            assert!(fingerprint(&b).is_none());
        }
        #[test]
        fn seal_is_stable_and_cannot_be_rearmed() {
            assert!(start());
            let b = frame();
            record(0, &b);
            record(1, &b);
            let done = seal().unwrap();
            assert_eq!(done[0], done[1]);
            assert_eq!(done[0][0], 1);
            record(0, &b);
            assert_eq!(seal(), Some(done));
            assert!(!start());
        }
    }
}
#[cfg(feature = "network-tx-audit")]
pub use enabled::*;

/// Record protocol-generated wire identities once for a logical send. Keep the
/// entire reconstruction loop absent from non-audit firmware.
#[inline]
pub fn record_segments(stage: usize, request: vibeos_hal::tcp_segmentation::TcpSegments<'_>) {
    #[cfg(feature = "network-tx-audit")]
    {
        let mut wire = [0; crate::net::MAX_PACKET_LEN];
        for index in 0..request.wire_segments() {
            let length = request.write_segment(index, &mut wire).unwrap();
            record(stage, &wire[..length]);
        }
    }
    #[cfg(not(feature = "network-tx-audit"))]
    let _ = (stage, request);
}
