//! Explicit single-domain WAN ingress policy, not VLAN interfaces or isolation.
//! Only callers that have already established WAN physical origin may opt in.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated;

/// Count complete 802.1Q/802.1ad headers. VID/PCP/DEI do not select authority.
/// Unknown EtherTypes remain untouched for the ordinary protocol parser.
/// Work is bounded by the supplied frame length, with no allocation/recursion.
pub fn tag_bytes(frame: &[u8]) -> Result<usize, Truncated> {
    let mut skip = 0;
    loop {
        if frame.len().saturating_sub(skip) < 14 { return Err(Truncated); }
        match &frame[12 + skip..14 + skip] {
            [0x81, 0] | [0x88, 0xa8] => skip += 4,
            _ => return Ok(skip),
        }
    }
}

/// Move only the twelve MAC bytes; the inner EtherType and payload stay put.
/// Returns the new frame offset within this slice. Failure changes no bytes.
/// A deferring caller must restore the twelve bytes at that offset if it used
/// this operation speculatively. No tag value is returned as routing authority.
pub fn strip_header_in_place(frame: &mut [u8]) -> Result<usize, Truncated> {
    let skip = tag_bytes(frame)?;
    if skip != 0 { frame.copy_within(0..12, skip); }
    Ok(skip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    fn frame(tags: &[[u8; 4]]) -> Vec<u8> {
        let mut bytes: Vec<_> = (0..12).collect();
        for tag in tags { bytes.extend_from_slice(tag); }
        bytes.extend_from_slice(&[8, 0]);
        bytes.extend(32..96);
        bytes
    }
    #[test]
    fn stacks_ignore_vid_priority_and_preserve_inner_bytes() {
        for tags in [alloc::vec![], alloc::vec![[0x81,0,0,0]],
            alloc::vec![[0x88,0xa8,0xff,0xff],[0x81,0,0x0c,0]],
            alloc::vec![[0x81,0,0xe0,100]; 32]] {
            let mut bytes=frame(&tags); let before=bytes.clone();
            let skip=strip_header_in_place(&mut bytes).unwrap();
            assert_eq!(skip,tags.len()*4);
            assert_eq!(&bytes[skip..skip+12],&before[..12]);
            assert_eq!(&bytes[skip+12..],&before[skip+12..]);
            assert_eq!(&bytes[skip..],&frame(&[]));
        }
    }
    #[test]
    fn incomplete_headers_never_mutate_input() {
        let bytes=frame(&[[0x81,0,0,0],[0x88,0xa8,0,100]]);
        for length in 0..22 {
            let mut short=bytes[..length].to_vec();let before=short.clone();
            assert_eq!(strip_header_in_place(&mut short),Err(Truncated));
            assert_eq!(short,before);
        }
    }
    #[test]
    fn unknown_tpid_is_not_reinterpreted() {
        for tpid in [[0x91,0],[0x92,0],[8,6]] {
            let mut bytes=frame(&[[tpid[0],tpid[1],0,100]]);let before=bytes.clone();
            assert_eq!(strip_header_in_place(&mut bytes),Ok(0));assert_eq!(bytes,before);
        }
    }
    #[test]
    fn deferred_normalization_can_restore_exact_wire_bytes() {
        for depth in 1..20 {
            let mut bytes=frame(&alloc::vec![[0x81,0,0xff,0xff];depth]);let before=bytes.clone();
            let skip=tag_bytes(&bytes).unwrap();
            let saved: [u8;12]=bytes[skip..skip+12].try_into().unwrap();
            assert_eq!(strip_header_in_place(&mut bytes),Ok(skip));
            bytes[skip..skip+12].copy_from_slice(&saved);assert_eq!(bytes,before);
        }
    }
}
