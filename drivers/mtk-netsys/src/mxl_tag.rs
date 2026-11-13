//! MxL86252 outer 802.1Q port tags, matching the board's vendor DT.
//! Linux tag_mxl862xx_8021q.c / tag_8021q.c at ccaea3d9:
//! standalone VID = 0xc00 | (switch_id << 6) | DT port index.
//! This board owns switch ID zero, copper ports 0..3 and SFP port 12.
//! No broadcast-domain/VBID tags or CPU/unused ports are accepted.

pub const MAX_INNER: usize = 1514;
pub const MAX_WIRE: usize = MAX_INNER + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    Copper0,
    Copper1,
    Copper2,
    Copper3,
    Sfp,
}
impl Port {
    pub fn dt_index(self) -> u8 {
        match self {
            Self::Copper0 => 0,
            Self::Copper1 => 1,
            Self::Copper2 => 2,
            Self::Copper3 => 3,
            Self::Sfp => 12,
        }
    }
    pub fn from_dt(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::Copper0),
            1 => Some(Self::Copper1),
            2 => Some(Self::Copper2),
            3 => Some(Self::Copper3),
            12 => Some(Self::Sfp),
            _ => None,
        }
    }
    pub fn vid(self) -> u16 {
        0xc00 | self.dt_index() as u16
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Length,
    Tag,
    Port,
}

/// Insert one CPU port tag. Caller owns both buffers; no packet is partially
/// modified on validation failure. Inner/customer tags are opaque payload.
pub fn encode(port: Port, frame: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !(14..=MAX_INNER).contains(&frame.len()) || out.len() < frame.len() + 4 {
        return Err(Error::Length);
    }
    out[..12].copy_from_slice(&frame[..12]);
    out[12..14].copy_from_slice(&[0x81, 0]);
    out[14..16].copy_from_slice(&port.vid().to_be_bytes());
    out[16..frame.len() + 4].copy_from_slice(&frame[12..]);
    Ok(frame.len() + 4)
}

/// Decode only a precise source-port tag. MAC origin (GDMA3) must be checked
/// by the ring owner before calling; an arbitrary user VLAN is not authority.
pub fn decode(wire: &[u8], out: &mut [u8]) -> Result<(Port, usize), Error> {
    if !(18..=MAX_WIRE).contains(&wire.len()) || out.len() < wire.len() - 4 {
        return Err(Error::Length);
    }
    let port = source_port(wire)?;
    out[..12].copy_from_slice(&wire[..12]);
    out[12..wire.len() - 4].copy_from_slice(&wire[16..]);
    Ok((port, wire.len() - 4))
}

/// Validate a source tag without changing the packet. The caller must verify
/// physical GDMA3 origin; customer tags cannot establish that authority.
pub fn source_port(wire: &[u8]) -> Result<Port, Error> {
    if !(18..=MAX_WIRE).contains(&wire.len()) {
        return Err(Error::Length);
    }
    if wire[12..14] != [0x81, 0] {
        return Err(Error::Tag);
    }
    let vid = u16::from_be_bytes([wire[14], wire[15]]) & 0xfff;
    if vid & 0xff0 != 0xc00 {
        return Err(Error::Tag);
    }
    Port::from_dt((vid & 15) as u8).ok_or(Error::Port)
}

// DMA buffers are aligned, but a four-byte tag displacement sends generic
// u64 memmove through its unaligned-source path on the strict-alignment target.
// Assemble each shifted word from two aligned loads. Keep generic memmove for
// arbitrary caller alignment and small frames; movement remains linear in
// length. Reuse the adjacent loaded word so each iteration needs one new load.
fn shift_four(bytes: &mut [u8], start: usize, end: usize, right: bool) {
    if bytes.as_ptr().addr() & 7 != 0 || end - start < 128 {
        bytes.copy_within(start..end, if right {start + 4} else {start - 4});
        return;
    }
    // SAFETY: callers validate their full source/destination extents first.
    // start is 12 or 16. Byte prologues align each destination to eight bytes;
    // the matching source is four bytes past an aligned address. Both adjacent
    // u64 loads stay inside the initialized slice, including their unused halves.
    // Backward insertion / forward removal reads before overlapping writes.
    // No overlapping typed borrows are created.
    unsafe {
        let p = bytes.as_mut_ptr();
        if right {
            let mut i = end;
            while i > start && (i + 4) & 7 != 0 {
                i -= 1;
                p.add(i + 4).write(p.add(i).read());
            }
            if i >= start + 8 {
                let mut high = u64::from_le(p.add(i - 4).cast::<u64>().read());
                while i >= start + 8 {
                    i -= 8;
                    let low = u64::from_le(p.add(i - 4).cast::<u64>().read());
                    p.add(i + 4).cast::<u64>().write(((low >> 32) | (high << 32)).to_le());
                    high = low;
                }
            }
            while i > start {
                i -= 1;
                p.add(i + 4).write(p.add(i).read());
            }
        } else {
            let mut i = start;
            while i < end && (i - 4) & 7 != 0 {
                p.add(i - 4).write(p.add(i).read());
                i += 1;
            }
            // The upper half of the second load must also stay in the slice.
            if i + 12 <= end {
                let mut low = u64::from_le(p.add(i - 4).cast::<u64>().read());
                while i + 12 <= end {
                    let high = u64::from_le(p.add(i + 4).cast::<u64>().read());
                    p.add(i - 4).cast::<u64>().write(((low >> 32) | (high << 32)).to_le());
                    low = high;
                    i += 8;
                }
            }
            while i < end {
                p.add(i - 4).write(p.add(i).read());
                i += 1;
            }
        }
    }
}

/// Strip a verified tag; source_port also supports read-only classification.
pub fn strip_in_place(wire: &mut [u8]) -> Result<(Port, usize), Error> {
    let port = source_port(wire)?;
    let length = wire.len() - 4;
    shift_four(wire, 16, wire.len(), false);
    Ok((port, length))
}

/// Remove a source tag by moving only the twelve MAC-address bytes forward.
/// The inner frame is then `wire[4..]`; the owner must transmit from that offset
/// or copy that view into a fresh packet. The payload at byte 16 never moves.
pub fn strip_header_in_place(wire: &mut [u8]) -> Result<(Port, usize), Error> {
    let port = source_port(wire)?;
    wire.copy_within(0..12, 4);
    Ok((port, wire.len() - 4))
}

/// Prepend the owned LAN bridge tag using four bytes of packet headroom.
/// Only the twelve MAC bytes move; EtherType and payload remain in place.
/// Returns (new frame offset, new length). Requires the same bridge lease as
/// insert_bridge_in_place. Rejection never changes the buffer.
pub fn insert_bridge_header_in_place(buffer: &mut [u8], offset: usize, length: usize) -> Result<(usize, usize), Error> {
    if offset < 4 || !(14..=MAX_INNER).contains(&length)
        || offset.checked_add(length).filter(|&end| end <= buffer.len()).is_none() {
        return Err(Error::Length);
    }
    buffer.copy_within(offset..offset + 12, offset - 4);
    buffer[offset + 8..offset + 12].copy_from_slice(&[0x81, 0, 0x0c, 0]);
    Ok((offset - 4, length + 4))
}

/// Common LAN injection tag (CPU classifier 17). Only use while the LAN bridge
/// lease owns alias 17's FDB lookup and four-copper flooding map. This tag does
/// not select physical copper port 0 in that configuration.
pub fn insert_bridge_in_place(frame: &mut [u8], length: usize) -> Result<usize, Error> {
    if !(14..=MAX_INNER).contains(&length) || frame.len() < length + 4 {
        return Err(Error::Length);
    }
    shift_four(frame, 12, length, true);
    frame[12..16].copy_from_slice(&[0x81, 0, 0x0c, 0]);
    Ok(length + 4)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_ports_and_lengths_preserve_payload_and_inner_vlan() {
        for index in [0, 1, 2, 3, 12] {
            let port = Port::from_dt(index).unwrap();
            for len in [14, 42, 60, 1514] {
                let mut frame = [0; MAX_INNER];
                for (i, b) in frame.iter_mut().enumerate() {
                    *b = (i * 13) as u8;
                }
                frame[12..14].copy_from_slice(&[0x81, 0]);
                let mut wire = [0; MAX_WIRE];
                let mut out = [0; MAX_INNER];
                assert_eq!(encode(port, &frame[..len], &mut wire), Ok(len + 4));
                assert_eq!(&wire[12..16], &[0x81, 0, 0x0c, index]);
                // PCP/DEI may be marked by the switch without changing identity.
                wire[14] |= 0xf0;
                assert_eq!(decode(&wire[..len + 4], &mut out), Ok((port, len)));
                assert_eq!(&out[..len], &frame[..len]);
            }
        }
    }
    #[test]
    fn malformed_or_foreign_tags_do_not_modify_output() {
        let mut frame = [0; 18];
        let mut out = [0xaa; MAX_INNER];
        for (tpid, vid) in [
            (0x8101u16, 0xc00u16),
            (0x800, 0xc00),
            (0x8100, 1),
            (0x8100, 0xc40),
            (0x8100, 0xe00),
            (0x8100, 0xc10),
            (0x8100, 0xc08),
        ] {
            frame[12..14].copy_from_slice(&tpid.to_be_bytes());
            frame[14..16].copy_from_slice(&vid.to_be_bytes());
            assert!(decode(&frame, &mut out).is_err());
            assert_eq!(out, [0xaa; MAX_INNER]);
        }
        assert_eq!(decode(&frame[..17], &mut out), Err(Error::Length));
        assert_eq!(decode(&[0; MAX_WIRE + 1], &mut out), Err(Error::Length));
        assert_eq!(
            encode(Port::Copper0, &[0; MAX_INNER + 1], &mut out),
            Err(Error::Length)
        );
        assert_eq!(
            encode(Port::Copper0, &[0; 14], &mut out[..17]),
            Err(Error::Length)
        );
        assert_eq!(out, [0xaa; MAX_INNER]);
    }
}

#[cfg(test)]
mod in_place_tests {
    use super::*;
    #[test]
    fn dma_tag_roundtrip_matches_copy_codec_and_keeps_source_identity() {
        for port in [
            Port::Copper0,
            Port::Copper1,
            Port::Copper2,
            Port::Copper3,
            Port::Sfp,
        ] {
            for length in [14, 42, 60, 512, MAX_INNER] {
                let mut original = [0u8; MAX_INNER];
                for (i, b) in original[..length].iter_mut().enumerate() {
                    *b = (i * 71) as u8;
                }
                // A forged/customer inner CPU tag cannot become the source identity.
                if length >= 18 {
                    original[12..16].copy_from_slice(&[0x81, 0, 0x0c, 0]);
                }
                let mut wire = [0xa5; MAX_WIRE];
                let size = encode(port, &original[..length], &mut wire).unwrap();
                assert_eq!(strip_in_place(&mut wire[..size]), Ok((port, length)));
                assert_eq!(&wire[..length], &original[..length]);
                assert_eq!(insert_bridge_in_place(&mut wire, length), Ok(size));
                let mut expected = [0; MAX_WIRE];
                encode(Port::Copper0, &original[..length], &mut expected).unwrap();
                assert_eq!(&wire[..size], &expected[..size]);
            }
        }
    }
    #[test]
    fn tag_moves_match_memmove_for_every_length_and_alignment() {
        for offset in 0..8 {
            for length in 14..=MAX_INNER {
                let mut original = [0u8; MAX_WIRE + 16];
                for (i, byte) in original.iter_mut().enumerate() { *byte = (i * 71 + length) as u8; }
                let mut actual = original;
                let mut expected = original;
                expected.copy_within(offset + 12..offset + length, offset + 16);
                expected[offset + 12..offset + 16].copy_from_slice(&[0x81, 0, 0x0c, 0]);
                assert_eq!(insert_bridge_in_place(&mut actual[offset..offset + length + 4], length), Ok(length + 4));
                assert_eq!(actual, expected, "insert offset={offset} length={length}");
                expected.copy_within(offset + 16..offset + length + 4, offset + 12);
                assert_eq!(strip_in_place(&mut actual[offset..offset + length + 4]), Ok((Port::Copper0, length)));
                assert_eq!(actual, expected, "strip offset={offset} length={length}");
                assert_eq!(&actual[offset..offset+length], &original[offset..offset+length]);
            }
        }
    }

    #[test]
    fn header_only_strip_matches_codec_without_touching_payload() {
        for offset in 0..8 {
            for length in 14..=MAX_INNER {
                let mut original = [0u8; MAX_INNER];
                for (i,b) in original[..length].iter_mut().enumerate() { *b = (i * 71 + length) as u8; }
                let mut wire = [0xa5; MAX_WIRE + 16];
                encode(Port::Copper3, &original[..length], &mut wire[offset..]).unwrap();
                let before = wire;
                assert_eq!(strip_header_in_place(&mut wire[offset..offset+length+4]), Ok((Port::Copper3,length)));
                assert_eq!(&wire[offset+4..offset+4+length], &original[..length]);
                assert_eq!(&wire[..offset+4], &before[..offset+4]);
                assert_eq!(&wire[offset+16..], &before[offset+16..]);
            }
        }
        let mut bad = [0x55; MAX_WIRE]; let original = bad;
        assert!(strip_header_in_place(&mut bad).is_err());
        assert_eq!(bad, original);
    }

    #[test]
    fn header_only_insert_matches_codec_and_preserves_payload_and_bounds() {
        for offset in 4..12 {
            for length in 14..=MAX_INNER {
                let mut original = [0u8; MAX_INNER];
                for (i,b) in original[..length].iter_mut().enumerate() { *b = (i*71+length) as u8; }
                let mut buffer = [0xa5; MAX_WIRE+16];
                buffer[offset..offset+length].copy_from_slice(&original[..length]);
                let before = buffer;
                let mut expected = [0; MAX_WIRE];
                encode(Port::Copper0, &original[..length], &mut expected).unwrap();
                assert_eq!(insert_bridge_header_in_place(&mut buffer,offset,length),Ok((offset-4,length+4)));
                assert_eq!(&buffer[offset-4..offset+length],&expected[..length+4]);
                assert_eq!(&buffer[..offset-4],&before[..offset-4]);
                assert_eq!(&buffer[offset+12..],&before[offset+12..]);
            }
        }
        for (offset,length) in [(0,60),(3,60),(4,13),(4,1515),(usize::MAX,60),(60,60)] {
            let mut buffer = [0xa5;64];
            assert_eq!(insert_bridge_header_in_place(&mut buffer,offset,length),Err(Error::Length));
            assert_eq!(buffer,[0xa5;64]);
        }
    }

    #[test]
    fn invalid_in_place_operations_never_mutate_the_dma_buffer() {
        let mut bytes = [0x55; MAX_WIRE];
        let original = bytes;
        assert_eq!(
            insert_bridge_in_place(&mut bytes, MAX_INNER + 1),
            Err(Error::Length)
        );
        assert_eq!(
            insert_bridge_in_place(&mut bytes[..60], 60),
            Err(Error::Length)
        );
        assert_eq!(insert_bridge_in_place(&mut bytes, 13), Err(Error::Length));
        assert_eq!(bytes, original);
        for tag in [
            [0x88, 0xa8, 0x0c, 0],
            [0x81, 0, 0x0c, 5],
            [0x81, 0, 0x0d, 0],
        ] {
            bytes[12..16].copy_from_slice(&tag);
            let original = bytes;
            assert!(strip_in_place(&mut bytes).is_err());
            assert_eq!(bytes, original);
        }
    }
}
