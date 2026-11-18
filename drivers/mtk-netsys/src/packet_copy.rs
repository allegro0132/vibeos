//! Bounded copies between normal-memory packet buffers (never MMIO).
//! The soft-float target's generic memcpy assembles unaligned words byte by
//! byte. Ethernet/tag offsets routinely trigger that path. Integer pairs
//! avoid it without using SIMD state or changing DMA ownership/cache policy.

pub fn copy(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    #[cfg(target_arch = "aarch64")]
    {
        // Normal memory permits unaligned LDP/STP when alignment checking is
        // disabled. Keep the generic path for any alternate loader enabling A.
        #[cfg(target_os = "none")]
        unsafe {
            let control: u64;
            core::arch::asm!("mrs {control}, sctlr_el1", control=out(reg) control, options(nomem, nostack, preserves_flags));
            if control & 2 != 0 { dst.copy_from_slice(src); return; }
        }
        let mut offset = 0;
        while src.len() - offset >= 32 {
            // Both exclusive destination and shared source cover all 32 bytes;
            // no overlap, over-read, or write beyond the caller's slice.
            unsafe {
                core::arch::asm!(
                    "ldp {a}, {b}, [{src}]",
                    "ldp {c}, {d}, [{src}, #16]",
                    "stp {a}, {b}, [{dst}]",
                    "stp {c}, {d}, [{dst}, #16]",
                    src=in(reg) src.as_ptr().add(offset),
                    dst=in(reg) dst.as_mut_ptr().add(offset),
                    a=out(reg) _, b=out(reg) _, c=out(reg) _, d=out(reg) _,
                    options(nostack, preserves_flags),
                );
            }
            offset += 32;
        }
        dst[offset..].copy_from_slice(&src[offset..]);
    }
    #[cfg(not(target_arch = "aarch64"))]
    dst.copy_from_slice(src);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;
    #[test]
    fn every_packet_length_and_alignment_preserves_guards() {
        let source: Vec<u8> = (0..1600+32).map(|i| (i*71+i/17) as u8).collect();
        for length in 0..=1600 {
            for source_offset in 0..16 {
                for destination_offset in 0..16 {
                    let mut dest = [0x5au8; 1632];
                    let start = 8+destination_offset;
                    super::copy(&mut dest[start..start+length], &source[source_offset..source_offset+length]);
                    assert_eq!(&dest[start..start+length], &source[source_offset..source_offset+length]);
                    assert!(dest[..start].iter().chain(dest[start+length..].iter()).all(|&v| v==0x5a));
                }
            }
        }
    }
}
