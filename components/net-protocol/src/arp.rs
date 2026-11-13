//! Allocation-free local IPv4 ARP replies for an exclusively owned frame.
//! A miss is unchanged and can be passed to the normal protocol stack.

/// Rewrite a valid Ethernet/IPv4 ARP request for this interface into a reply.
/// Returns the unpadded frame length. The caller supplies interface identity,
/// transmits on the same ingress domain, and zeroes any Ethernet padding.
pub fn reply_in_place(frame: &mut [u8], mac: [u8; 6], ip: [u8; 4]) -> Option<usize> {
    if frame.len() < 42 || mac == [0; 6] || mac[0] & 1 != 0 || ip == [0; 4] || ip[0] >= 224 {
        return None;
    }
    if frame[..6] != mac && frame[..6] != [0xff; 6] {
        return None;
    }
    if frame[12..22] != [8, 6, 0, 1, 8, 0, 6, 4, 0, 1] || frame[38..42] != ip {
        return None;
    }
    let sender: [u8; 6] = frame[22..28].try_into().unwrap();
    if sender == [0; 6] || sender[0] & 1 != 0 || frame[6..12] != sender {
        return None;
    }
    let sender_ip: [u8; 4] = frame[28..32].try_into().unwrap();
    frame[..6].copy_from_slice(&sender);
    frame[6..12].copy_from_slice(&mac);
    frame[21] = 2;
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&ip);
    frame[32..38].copy_from_slice(&sender);
    frame[38..42].copy_from_slice(&sender_ip);
    Some(42)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAC: [u8; 6] = [2, 0x42, 0x70, 4, 0, 2];
    const IP: [u8; 4] = [192, 168, 79, 1];
    const PEER: [u8; 6] = [2, 3, 4, 5, 6, 7];
    fn request() -> [u8; 60] {
        let mut f = [0xa5; 60];
        f[..6].fill(0xff);
        f[6..12].copy_from_slice(&PEER);
        f[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        f[22..28].copy_from_slice(&PEER);
        f[28..32].copy_from_slice(&[192, 168, 79, 2]);
        f[32..38].fill(0);
        f[38..42].copy_from_slice(&IP);
        f
    }
    #[test]
    fn reply_fields_and_probe_source_zero() {
        for source in [[192, 168, 79, 2], [0; 4]] {
            let mut f = request();
            f[28..32].copy_from_slice(&source);
            assert_eq!(reply_in_place(&mut f, MAC, IP), Some(42));
            assert_eq!(&f[..6], &PEER);
            assert_eq!(&f[6..12], &MAC);
            assert_eq!(f[21], 2);
            assert_eq!(&f[22..28], &MAC);
            assert_eq!(&f[28..32], &IP);
            assert_eq!(&f[32..38], &PEER);
            assert_eq!(&f[38..42], &source);
            assert_eq!(&f[42..], &[0xa5; 18]);
        }
    }
    #[test]
    fn foreign_malformed_and_truncated_frames_are_unchanged() {
        for length in 0..42 {
            let mut f = request();
            let original = f;
            assert_eq!(reply_in_place(&mut f[..length], MAC, IP), None);
            assert_eq!(f, original);
        }
        for offset in [0, 6, 12, 14, 16, 18, 19, 20, 21, 22, 38, 41] {
            let mut f = request();
            f[offset] ^= 1;
            let original = f;
            assert_eq!(reply_in_place(&mut f, MAC, IP), None, "offset {offset}");
            assert_eq!(f, original);
        }
        let mut f = request();
        assert_eq!(reply_in_place(&mut f, MAC, [0; 4]), None);
    }
}
