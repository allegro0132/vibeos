//! Allocation-free boot memory admission and DMA address validation.
use crate::AddressRange;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    InvalidRange,
    Overlap,
    TooManyRegions,
    InvalidAlignment,
    AddressOverflow,
    NotAddressable,
}

/// A sorted list of disjoint usable physical ranges. Reservations split or
/// trim the list transactionally; failure leaves the previous map unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootMemory<const N: usize> {
    ranges: [AddressRange; N],
    len: usize,
}
impl<const N: usize> Default for BootMemory<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> BootMemory<N> {
    pub const fn new() -> Self {
        Self {
            ranges: [AddressRange::new(0, 0); N],
            len: 0,
        }
    }
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges[..self.len]
    }
    pub fn add_ram(&mut self, range: AddressRange) -> Result<(), MemoryError> {
        if range.is_empty() {
            return Err(MemoryError::InvalidRange);
        }
        if self
            .ranges()
            .iter()
            .any(|r| range.start < r.end && r.start < range.end)
        {
            return Err(MemoryError::Overlap);
        }
        if self.len == N {
            return Err(MemoryError::TooManyRegions);
        }
        self.ranges[self.len] = range;
        self.len += 1;
        self.ranges[..self.len].sort_unstable_by_key(|r| r.start);
        Ok(())
    }
    pub fn reserve(&mut self, reserved: AddressRange) -> Result<(), MemoryError> {
        if reserved.is_empty() {
            return Err(MemoryError::InvalidRange);
        }
        let mut next = Self::new();
        for &r in self.ranges() {
            if reserved.end <= r.start || reserved.start >= r.end {
                next.add_ram(r)?;
            } else {
                if r.start < reserved.start {
                    next.add_ram(AddressRange::new(r.start, reserved.start))?;
                }
                if reserved.end < r.end {
                    next.add_ram(AddressRange::new(reserved.end, r.end))?;
                }
            }
        }
        *self = next;
        Ok(())
    }
    pub fn contains(&self, range: AddressRange) -> bool {
        !range.is_empty()
            && self
                .ranges()
                .iter()
                .any(|r| r.start <= range.start && range.end <= r.end)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaConstraints {
    pub address_bits: u8,
    pub alignment: usize,
    pub cache_line: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaRegion {
    pub physical: u64,
    pub bytes: usize,
}
impl DmaConstraints {
    /// Validate the entire device-visible span, including the last byte. This
    /// does not translate virtual addresses or establish cache coherence.
    pub fn validate(self, region: DmaRegion) -> Result<(), MemoryError> {
        if self.address_bits == 0 || self.address_bits > 64 || region.bytes == 0 {
            return Err(MemoryError::InvalidRange);
        }
        if !self.alignment.is_power_of_two()
            || !self.cache_line.is_power_of_two()
            || region.physical % self.alignment as u64 != 0
            || region.physical % self.cache_line as u64 != 0
            || region.bytes % self.cache_line != 0
        {
            return Err(MemoryError::InvalidAlignment);
        }
        let last = region
            .physical
            .checked_add(region.bytes as u64 - 1)
            .ok_or(MemoryError::AddressOverflow)?;
        if self.address_bits < 64 && last >= (1u64 << self.address_bits) {
            return Err(MemoryError::NotAddressable);
        }
        Ok(())
    }
}
/// Platform callbacks must synchronize every cache level needed by the SoC,
/// and order MMIO publication relative to CPU/device accesses. A coherent
/// platform still needs ordering fences. Buffer ownership remains with the
/// caller: after sync_for_device CPU access stops until sync_for_cpu returns.
pub struct DmaOps {
    pub constraints: DmaConstraints,
    pub sync_for_device: unsafe fn(DmaRegion, DmaDirection),
    pub sync_for_cpu: unsafe fn(DmaRegion, DmaDirection),
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mars_four_gib_reservations_preserve_high_physical_memory() {
        let mut m = BootMemory::<8>::new();
        m.add_ram(AddressRange::new(0x40000000, 0x140000000))
            .unwrap();
        m.reserve(AddressRange::new(0x40000000, 0x40200000))
            .unwrap();
        m.reserve(AddressRange::new(0x48000000, 0x48100000))
            .unwrap();
        assert_eq!(
            m.ranges(),
            &[
                AddressRange::new(0x40200000, 0x48000000),
                AddressRange::new(0x48100000, 0x140000000)
            ]
        );
        assert!(m.contains(AddressRange::new(0x100000000, 0x140000000)));
        assert!(!m.contains(AddressRange::new(0x47fff000, 0x48101000)));
    }
    #[test]
    fn reservation_can_span_banks_and_repeat() {
        let mut m = BootMemory::<4>::new();
        m.add_ram(AddressRange::new(10, 20)).unwrap();
        m.add_ram(AddressRange::new(30, 40)).unwrap();
        m.reserve(AddressRange::new(15, 35)).unwrap();
        m.reserve(AddressRange::new(15, 35)).unwrap();
        assert_eq!(
            m.ranges(),
            &[AddressRange::new(10, 15), AddressRange::new(35, 40)]
        );
    }
    #[test]
    fn region_exhaustion_is_transactional() {
        let mut m = BootMemory::<1>::new();
        m.add_ram(AddressRange::new(10, 40)).unwrap();
        let before = m;
        assert_eq!(
            m.reserve(AddressRange::new(20, 30)),
            Err(MemoryError::TooManyRegions)
        );
        assert_eq!(m, before);
        assert_eq!(
            m.add_ram(AddressRange::new(30, 50)),
            Err(MemoryError::Overlap)
        );
    }
    #[test]
    fn dma_checks_end_address_and_cache_isolation() {
        let c = DmaConstraints {
            address_bits: 32,
            alignment: 16,
            cache_line: 64,
        };
        assert_eq!(
            c.validate(DmaRegion {
                physical: 0xffffffc0,
                bytes: 64
            }),
            Ok(())
        );
        assert_eq!(
            c.validate(DmaRegion {
                physical: 0xffffffc0,
                bytes: 128
            }),
            Err(MemoryError::NotAddressable)
        );
        assert_eq!(
            c.validate(DmaRegion {
                physical: 0x40000010,
                bytes: 64
            }),
            Err(MemoryError::InvalidAlignment)
        );
        assert_eq!(
            c.validate(DmaRegion {
                physical: 0x40000000,
                bytes: 65
            }),
            Err(MemoryError::InvalidAlignment)
        );
        let c = DmaConstraints {
            address_bits: 64,
            alignment: 1,
            cache_line: 1,
        };
        assert_eq!(
            c.validate(DmaRegion {
                physical: u64::MAX,
                bytes: 1
            }),
            Ok(())
        );
        assert_eq!(
            c.validate(DmaRegion {
                physical: u64::MAX,
                bytes: 2
            }),
            Err(MemoryError::AddressOverflow)
        );
    }
}
