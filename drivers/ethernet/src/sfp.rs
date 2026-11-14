//! SFF-8472 A0 identification; offsets match Linux include/linux/sfp.h.
//! Identification is evidence about a module, not permission to enable TX.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Identifier,
    BaseChecksum,
    ExtendedChecksum,
}

#[derive(Debug)]
pub struct Identity<'a> {
    pub vendor: &'a [u8],
    pub part: &'a [u8],
    pub serial: &'a [u8],
    pub ethernet_10g: bool,
    pub ethernet_1g: bool,
    pub passive_dac: bool,
    pub active_cable: bool,
    pub nominal_mbaud: u32,
}
pub fn parse(bytes: &[u8]) -> Result<Identity<'_>, Error> {
    if bytes.len() < 96 {
        return Err(Error::Length);
    }
    if bytes[0] != 3 || bytes[1] != 4 {
        return Err(Error::Identifier);
    }
    let sum = |range: core::ops::Range<usize>| {
        bytes[range].iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
    };
    if sum(0..63) != bytes[63] {
        return Err(Error::BaseChecksum);
    }
    if sum(64..95) != bytes[95] {
        return Err(Error::ExtendedChecksum);
    }
    Ok(Identity {
        vendor: &bytes[20..36],
        part: &bytes[40..56],
        serial: &bytes[68..84],
        ethernet_10g: bytes[3] & 0xf0 != 0,
        ethernet_1g: bytes[6] & 0x0f != 0,
        passive_dac: bytes[8] & 4 != 0,
        active_cable: bytes[8] & 8 != 0,
        // 255 means extended encoding, not 25.5 GBd. Leave unknown here.
        nominal_mbaud: if bytes[12] == 255 {
            0
        } else {
            u32::from(bytes[12]) * 100
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checksum(b: &mut [u8; 96]) {
        b[63] = b[..63].iter().fold(0u8, |s, b| s.wrapping_add(*b));
        b[95] = b[64..95].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    }
    fn module() -> [u8; 96] {
        let mut b = [0; 96];
        b[0] = 3;
        b[1] = 4;
        b[3] = 0x10;
        b[12] = 103;
        b[20..36].copy_from_slice(b"TEST VENDOR     ");
        b[40..56].copy_from_slice(b"10G-SR          ");
        b[68..84].copy_from_slice(b"TEST123         ");
        checksum(&mut b);
        b
    }
    #[test]
    fn optical_and_cable_capabilities_are_distinct() {
        let mut b = module();
        let m = parse(&b).unwrap();
        assert!(m.ethernet_10g && !m.ethernet_1g && !m.passive_dac && !m.active_cable);
        assert_eq!(m.nominal_mbaud, 10300);
        assert_eq!(m.part, b"10G-SR          ");
        assert_eq!(m.vendor, b"TEST VENDOR     ");
        assert_eq!(m.serial, b"TEST123         ");
        b[3] = 0;
        b[6] = 1;
        b[8] = 4;
        b[12] = 255;
        checksum(&mut b);
        let m = parse(&b).unwrap();
        assert!(!m.ethernet_10g && m.ethernet_1g && m.passive_dac && !m.active_cable);
        assert_eq!(m.nominal_mbaud, 0);
    }
    #[test]
    fn corrupt_or_incomplete_identification_is_rejected() {
        let b = module();
        for n in 0..96 {
            assert!(matches!(parse(&b[..n]), Err(Error::Length)));
        }
        for i in 2..96 {
            let mut bad = b;
            bad[i] ^= 1;
            assert!(
                matches!(
                    parse(&bad),
                    Err(Error::BaseChecksum | Error::ExtendedChecksum)
                ),
                "byte {i}"
            );
        }
        let mut bad = b;
        bad[0] = 0x0c;
        checksum(&mut bad);
        assert!(matches!(parse(&bad), Err(Error::Identifier)));
    }
}
