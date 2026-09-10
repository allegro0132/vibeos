#![no_std]
//! SD wire values, shared by SDHCI and DesignWare MSHC transports.
//! Long responses are normalized most-significant word first, with CSD bit
//! 127 at word 0 bit 31. Each controller must normalize its response registers.
pub const SECTOR_SIZE: usize = 512;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    OutOfRange,
    Unsupported,
}

pub fn sector_argument(high_capacity: bool, sector: u64) -> Result<u32, Error> {
    let address = if high_capacity {
        sector
    } else {
        sector
            .checked_mul(SECTOR_SIZE as u64)
            .ok_or(Error::OutOfRange)?
    };
    u32::try_from(address).map_err(|_| Error::OutOfRange)
}

pub fn capacity_from_csd(csd: [u32; 4]) -> Result<u64, Error> {
    let sectors = match bits(csd, 126, 2) {
        1 => (u64::from(bits(csd, 48, 22)) + 1) * 1024,
        0 => {
            let block_len = bits(csd, 80, 4);
            let size = u64::from(bits(csd, 62, 12)) + 1;
            let multiplier = bits(csd, 47, 3) + 2;
            size.checked_shl(multiplier + block_len)
                .ok_or(Error::Unsupported)?
                / 512
        }
        _ => return Err(Error::Unsupported),
    };
    if sectors == 0 {
        Err(Error::Unsupported)
    } else {
        Ok(sectors)
    }
}
fn bits(response: [u32; 4], start: usize, size: usize) -> u32 {
    let offset = 3 - start / 32;
    let shift = start & 31;
    let mut value = response[offset] >> shift;
    if size + shift > 32 {
        value |= response[offset - 1] << (32 - shift);
    }
    value & ((1u32 << size) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn csd(structure: u32, fields: &[(usize, usize, u32)]) -> [u32; 4] {
        let mut value = (structure as u128) << 126;
        for &(start, size, field) in fields {
            value |= (field as u128 & ((1u128 << size) - 1)) << start;
        }
        [
            (value >> 96) as u32,
            (value >> 64) as u32,
            (value >> 32) as u32,
            value as u32,
        ]
    }
    #[test]
    fn block_and_byte_address_limits() {
        assert_eq!(sector_argument(true, u32::MAX as u64), Ok(u32::MAX));
        assert_eq!(
            sector_argument(true, u32::MAX as u64 + 1),
            Err(Error::OutOfRange)
        );
        assert_eq!(sector_argument(false, 0x7fffff), Ok(0xfffffe00));
        assert_eq!(sector_argument(false, 0x800000), Err(Error::OutOfRange));
        assert_eq!(sector_argument(false, u64::MAX), Err(Error::OutOfRange));
    }
    #[test]
    fn both_csd_versions_and_reserved_structure() {
        assert_eq!(
            capacity_from_csd(csd(1, &[(48, 22, 0x3fff)])),
            Ok(16_777_216)
        );
        assert_eq!(
            capacity_from_csd(csd(1, &[(48, 22, 0x3fffff)])),
            Ok(4_294_967_296)
        );
        assert_eq!(
            capacity_from_csd(csd(0, &[(80, 4, 9), (62, 12, 1023), (47, 3, 7)])),
            Ok(524_288)
        );
        assert_eq!(capacity_from_csd(csd(2, &[])), Err(Error::Unsupported));
        assert_eq!(capacity_from_csd([0; 4]), Err(Error::Unsupported));
    }
}
