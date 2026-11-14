//! Allocation-free, 39-bit VA / 40-bit PA, 4 KiB identity tables for early EL1.
//! All leaf pages are EL1-only. No writable executable mapping is expressible.
//! The builder is consumed before activation. The narrow unsafe live-update
//! path below changes only existing NX data leaves for CSpace publication.

pub const PAGE_SIZE: usize = 4096;
pub const BLOCK_SIZE: usize = 2 << 20;
const ADDRESS_MASK: u64 = 0x0000_00ff_ffff_f000;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const RO: u64 = 1 << 7;
const AF: u64 = 1 << 10;
const TABLE_COUNT: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Permission {
    Text,
    ReadOnly,
    Data,
    Device,
    /// Normal memory, inner/outer non-cacheable, privileged RW-NX.
    Dma,
}
impl Permission {
    const fn bits(self) -> u64 {
        // MAIR index 0 = Normal WBWA, 1 = Device-nGnRnE, 2 = Normal NC.
        let normal = 3 | AF | (3 << 8) | UXN;
        match self {
            Self::Text => normal | RO,
            Self::ReadOnly => normal | RO | PXN,
            Self::Data => normal | PXN,
            Self::Dma => normal | (2 << 2) | PXN,
            Self::Device => 3 | AF | (2 << 8) | (1 << 2) | UXN | PXN,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Alignment,
    Range,
    Overlap,
    Exhausted,
}

#[repr(C, align(4096))]
struct Table([u64; 512]);
impl Table {
    const ZERO: Self = Self([0; 512]);
}

/// Must be placed in permanent, page-aligned RAM before passing to Builder.
#[repr(C, align(4096))]
pub struct Tables {
    tables: [Table; TABLE_COUNT],
}
impl Tables {
    pub const fn new() -> Self {
        Self {
            tables: [const { Table::ZERO }; TABLE_COUNT],
        }
    }
}
impl Default for Tables {
    fn default() -> Self {
        Self::new()
    }
}

/// A borrow pins the table location throughout construction. Activation must
/// retain the backing Tables forever. After activation only the serialized
/// unsafe data-permission update path may mutate them.
pub struct Builder<'a> {
    storage: &'a mut Tables,
    used: usize,
}
impl<'a> Builder<'a> {
    pub fn new(storage: &'a mut Tables) -> Self {
        for table in &mut storage.tables {
            table.0.fill(0);
        }
        Self { storage, used: 1 }
    }
    fn base(&self) -> u64 {
        self.storage.tables.as_ptr() as u64
    }
    fn child(&mut self, parent: usize, slot: usize) -> Result<usize, Error> {
        let desc = self.storage.tables[parent].0[slot];
        // A block already covers this slot; it cannot also hold a table.
        if desc & 3 == 1 {
            return Err(Error::Overlap);
        }
        if desc != 0 {
            return Ok(((desc & ADDRESS_MASK) - (self.base() & ADDRESS_MASK)) as usize / PAGE_SIZE);
        }
        if self.used == TABLE_COUNT {
            return Err(Error::Exhausted);
        }
        let index = self.used;
        self.used += 1;
        self.storage.tables[parent].0[slot] =
            ((self.base() + (index * PAGE_SIZE) as u64) & ADDRESS_MASK) | 3;
        Ok(index)
    }
    /// Failures may leave partially built tables; callers must discard the
    /// builder on any error and must not activate a partially built map.
    pub fn map(&mut self, start: usize, end: usize, permission: Permission) -> Result<(), Error> {
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::Alignment);
        }
        if start == 0 || start >= end || end > (1usize << 39) {
            return Err(Error::Range);
        }
        for page in (start..end).step_by(PAGE_SIZE) {
            let l2 = self.child(0, (page >> 30) & 511)?;
            let l3 = self.child(l2, (page >> 21) & 511)?;
            let entry = &mut self.storage.tables[l3].0[(page >> 12) & 511];
            if *entry != 0 {
                return Err(Error::Overlap);
            }
            *entry = (page as u64) | permission.bits();
        }
        Ok(())
    }
    /// Identity-map whole 2 MiB level-2 blocks. Large regions cost no level-3
    /// tables; the range must not share a 2 MiB block with any page mapping.
    /// Blocks carry the same permission bits as pages and are never changed
    /// by the live data-permission update path.
    pub fn map_blocks(&mut self, start: usize, end: usize, permission: Permission) -> Result<(), Error> {
        if start % BLOCK_SIZE != 0 || end % BLOCK_SIZE != 0 {
            return Err(Error::Alignment);
        }
        if start == 0 || start >= end || end > (1usize << 39) {
            return Err(Error::Range);
        }
        if matches!(permission, Permission::Text | Permission::Device) {
            return Err(Error::Range);
        }
        for block in (start..end).step_by(BLOCK_SIZE) {
            let l2 = self.child(0, (block >> 30) & 511)?;
            let entry = &mut self.storage.tables[l2].0[(block >> 21) & 511];
            if *entry != 0 {
                return Err(Error::Overlap);
            }
            // Level-2 block descriptor: type 0b01 instead of the page's 0b11.
            *entry = (block as u64) | (permission.bits() & !3) | 1;
        }
        Ok(())
    }
    /// Descriptor of the 2 MiB block containing `address`, if block-mapped.
    pub fn block_descriptor(&self, address: usize) -> Option<u64> {
        if address >= (1usize << 39) {
            return None;
        }
        let desc = self.storage.tables[0].0[(address >> 30) & 511];
        if desc & 3 != 3 {
            return None;
        }
        let table = ((desc & ADDRESS_MASK) - (self.base() & ADDRESS_MASK)) as usize / PAGE_SIZE;
        let desc = self.storage.tables[table].0[(address >> 21) & 511];
        (desc & 3 == 1).then_some(desc)
    }
    pub fn descriptor(&self, address: usize) -> Option<u64> {
        if address >= (1usize << 39) {
            return None;
        }
        let mut table = 0;
        for shift in [30, 21] {
            let desc = self.storage.tables[table].0[(address >> shift) & 511];
            if desc & 3 != 3 {
                return None;
            }
            table = ((desc & ADDRESS_MASK) - (self.base() & ADDRESS_MASK)) as usize / PAGE_SIZE;
        }
        let desc = self.storage.tables[table].0[(address >> 12) & 511];
        (desc & 3 == 3).then_some(desc)
    }
    pub fn table_count(&self) -> usize {
        self.used
    }
    pub fn root_address(&self) -> usize {
        self.base() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permissions_holes_and_boundaries() {
        let mut tables = Tables::new();
        let mut map = Builder::new(&mut tables);
        map.map(0x40080000, 0x40082000, Permission::Text).unwrap();
        map.map(0x40082000, 0x40083000, Permission::ReadOnly)
            .unwrap();
        // Deliberate unmapped stack guard at 0x40083000.
        map.map(0x40084000, 0x40210000, Permission::Data).unwrap();
        map.map(0x11000000, 0x11001000, Permission::Device).unwrap();
        map.map(0x41000000, 0x41001000, Permission::Dma).unwrap();
        let dma = map.descriptor(0x41000000).unwrap();
        assert_eq!(dma & 0x1c, 8);
        assert_eq!(dma & (PXN | UXN | RO), PXN | UXN);
        assert!(map.descriptor(0).is_none());
        assert!(map.descriptor(0x40083000).is_none());
        assert!(map.descriptor(0x43000000).is_none());
        assert!(map.descriptor(0x40210000).is_none());
        let text = map.descriptor(0x40081000).unwrap();
        assert_eq!(text & (PXN | UXN | RO), UXN | RO);
        assert_eq!(text & ADDRESS_MASK, 0x40081000);
        let ro = map.descriptor(0x40082000).unwrap();
        assert_eq!(ro & (PXN | UXN | RO), PXN | UXN | RO);
        let data = map.descriptor(0x40200000).unwrap();
        assert_eq!(data & (PXN | UXN | RO), PXN | UXN);
        let dev = map.descriptor(0x11000000).unwrap();
        assert_eq!(dev & 0x1c, 4);
        assert_eq!(dev & (PXN | UXN), PXN | UXN);
        assert_eq!(
            map.map(0x40080000, 0x40081000, Permission::Data),
            Err(Error::Overlap)
        );
    }
    #[test]
    fn blocks_use_no_leaf_tables_and_never_overlap_pages() {
        let mut tables = Tables::new();
        let mut map = Builder::new(&mut tables);
        map.map(0x40080000, 0x40082000, Permission::Data).unwrap();
        let before = map.table_count();
        map.map_blocks(0x44000000, 0x50000000, Permission::Data).unwrap();
        map.map_blocks(0x50000000, 0x50800000, Permission::Dma).unwrap();
        assert_eq!(map.table_count(), before);
        let data = map.block_descriptor(0x4fffffff).unwrap();
        assert_eq!(data & 3, 1);
        assert_eq!(data & (PXN | UXN | RO), PXN | UXN);
        assert_eq!(data & ADDRESS_MASK, 0x4fe00000);
        let dma = map.block_descriptor(0x50400000).unwrap();
        assert_eq!(dma & 0x1c, 8);
        assert!(map.block_descriptor(0x43e00000).is_none());
        assert!(map.block_descriptor(0x50800000).is_none());
        assert!(map.block_descriptor(0x40080000).is_none());
        assert!(map.descriptor(0x44000000).is_none());
        assert_eq!(map.map_blocks(0x40000000, 0x40200000, Permission::Data), Err(Error::Overlap));
        assert_eq!(map.map(0x44001000, 0x44002000, Permission::Data), Err(Error::Overlap));
        assert_eq!(map.map_blocks(0x44000000, 0x44200000, Permission::Data), Err(Error::Overlap));
        assert_eq!(map.map_blocks(0x60001000, 0x60200000, Permission::Data), Err(Error::Alignment));
        assert_eq!(map.map_blocks(0x60000000, 0x60200000, Permission::Text), Err(Error::Range));
    }
    #[test]
    fn invalid_ranges_and_table_exhaustion() {
        let mut tables = Tables::new();
        let mut map = Builder::new(&mut tables);
        assert_eq!(map.map(1, 4096, Permission::Data), Err(Error::Alignment));
        assert_eq!(map.map(0, 4096, Permission::Data), Err(Error::Range));
        assert_eq!(map.map(8192, 4096, Permission::Data), Err(Error::Range));
        assert_eq!(
            map.map(1 << 39, (1 << 39) + 4096, Permission::Data),
            Err(Error::Range)
        );
        for i in 1..16 {
            map.map(i << 30, (i << 30) + 4096, Permission::Data)
                .unwrap();
        }
        assert_eq!(
            map.map(16 << 30, (16 << 30) + 4096, Permission::Data),
            Err(Error::Exhausted)
        );
    }
}

/// Change permissions of an existing Normal, privileged NX data page.
///
/// # Safety
/// `root` is the active, permanent identity map constructed by Builder. Only
/// the boot CPU is running. Caller masks IRQs and serializes all table updates,
/// owns this live page and guarantees no aliased access during transition.
/// Page must not contain current code, stack, translation tables or MMIO.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn protect_data_page(root: usize, page: usize, read_only: bool) {
    use core::{
        arch::asm,
        ptr::{read_volatile, write_volatile},
    };
    assert_eq!(page & (PAGE_SIZE - 1), 0);
    assert!(page < (1usize << 39));
    let mut table = root as *mut u64;
    unsafe {
        for shift in [30, 21] {
            let desc = read_volatile(table.add((page >> shift) & 511));
            assert_eq!(desc & 3, 3, "missing table");
            table = (desc & ADDRESS_MASK) as *mut u64;
        }
        let slot = table.add((page >> 12) & 511);
        let old = read_volatile(slot);
        assert_eq!(old & ADDRESS_MASK, page as u64);
        assert_eq!(old & !ADDRESS_MASK & !RO, Permission::Data.bits());
        let new = if read_only { old | RO } else { old & !RO };
        // Break-before-make with inner-shareable broadcast invalidation.
        // All CPUs share these inner-shareable tables; DSB ISH waits for
        // completion on the participating CPUs before publishing the leaf.
        write_volatile(slot, 0);
        asm!("dsb ishst", "tlbi vaae1is, {}", "dsb ish", "isb", in(reg) page >> 12, options(nostack));
        write_volatile(slot, new);
        asm!("dsb ishst", "isb", options(nostack));
    }
}
