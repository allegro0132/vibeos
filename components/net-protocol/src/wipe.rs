//! Bulk erasure of initialized packet payloads during stream processing.
use zeroize::Zeroize;

#[inline]
pub fn bytes(payload: &mut [u8]) {
    if payload.is_empty() {
        return;
    }
    // SAFETY: all bit patterns are valid u64s. align_to_mut produces disjoint
    // slices within this exclusive byte slice and aligns the word-sized part.
    let (head, words, tail) = unsafe { payload.align_to_mut::<u64>() };
    head.zeroize();
    words.zeroize();
    tail.zeroize();
}

#[cfg(test)]
mod tests {
    #[test]
    fn wipes_only_the_requested_range_at_every_alignment() {
        for start in 0..8 {
            for len in 0..33 {
                let mut data = [0xa5; 48];
                super::bytes(&mut data[start..start + len]);
                assert!(data[..start].iter().all(|&b| b == 0xa5));
                assert!(data[start..start + len].iter().all(|&b| b == 0));
                assert!(data[start + len..].iter().all(|&b| b == 0xa5));
            }
        }
    }
}
