//! Internet checksum primitives shared by IPv4 and IPv6.
pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}
pub(crate) fn sum(bytes: &[u8]) -> u32 {
    // Callers bound this to an IP packet/payload (at most 65535 bytes), whose
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
        let mut lanes = 0u64;
        for &word in words {
            // An odd prefix makes the first byte of each aligned word the low
            // checksum byte. Reversing byte order swaps all four word lanes;
            // lane order is immaterial to their sum.
            let word = if odd { word.to_le() } else { word.to_be() };
            // Two independent 32-bit lanes, each adding two 16-bit words.
            // Even a maximum IP packet cannot carry out of the low lane.
            const MASK: u64 = 0x0000ffff0000ffff;
            lanes += (word & MASK) + ((word >> 16) & MASK);
        }
        result += (lanes as u32) + (lanes >> 32) as u32;
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
