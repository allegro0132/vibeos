//! Offset-addressed benchmark bytes, shared by specification with the Linux agent.
//! Each aligned eight-byte word is a SplitMix64 permutation of seed + word index.
fn word(seed: u64, index: u64) -> [u8; 8] {
    let mut x = seed.wrapping_add(index.wrapping_mul(0x9e3779b97f4a7c15));
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    (x ^ (x >> 31)).to_le_bytes()
}

pub fn fill(bytes: &mut [u8], seed: u64, mut offset: u64) {
    let mut at = 0;
    while at < bytes.len() {
        let value = word(seed, offset / 8);
        let within = (offset % 8) as usize;
        let take = (8 - within).min(bytes.len() - at);
        bytes[at..at + take].copy_from_slice(&value[within..within + take]);
        offset += take as u64;
        at += take;
    }
}

pub fn matches(bytes: &[u8], seed: u64, mut offset: u64) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let value = word(seed, offset / 8);
        let within = (offset % 8) as usize;
        let take = (8 - within).min(bytes.len() - at);
        if bytes[at..at + take] != value[within..within + take] {
            return false;
        }
        offset += take as u64;
        at += take;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offset_chunking_and_corruption() {
        let mut whole = vec![0; 3 * 1024 * 1024 + 17];
        fill(&mut whole, 19, 0);
        assert_ne!(&whole[..4096], &whole[4096..8192]);
        assert_ne!(&whole[..17], &whole[3 * 1024 * 1024..]);
        for offset in [0, 1, 7, 8, 4095, 3 * 1024 * 1024] {
            let mut part = [0; 17];
            fill(&mut part, 19, offset as u64);
            assert_eq!(&part, &whole[offset..offset + 17]);
            assert!(matches(&part, 19, offset as u64));
            part[9] ^= 1;
            assert!(!matches(&part, 19, offset as u64));
        }
    }
}
