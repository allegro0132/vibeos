//! Immutable firmware-to-kernel boot contract. Physical board choices and
//! memory reserved for RAM page tables belong to the final firmware image.
use crate::{AddressRange, BoardInfo, MemoryRegion, MmuDescription};

#[derive(Clone, Copy, Debug)]
pub struct PageTableArena {
    /// Physical address of zeroed, page-aligned, permanently owned storage.
    pub base: usize,
    pub pages: usize,
}

pub struct BootPlatform {
    pub info: BoardInfo,
    pub memory_map: &'static [MemoryRegion],
    pub mmu: MmuDescription,
    pub hart_ids: &'static [usize],
    pub rtc: Option<AddressRange>,
    pub cold_reset: Option<fn() -> !>,
    /// # Safety
    /// The kernel may access this arena only under its page-table ownership
    /// protocol: boot hart before publication, then the global page-table lock.
    pub ram_page_tables: unsafe fn() -> PageTableArena,
}

extern "Rust" {
    static VIBEOS_BOOT_PLATFORM: BootPlatform;
}
pub fn platform() -> &'static BootPlatform {
    // SAFETY: immutable storage defined once by the final firmware.
    unsafe { &VIBEOS_BOOT_PLATFORM }
}

/// Page counts for an identity-mapped RAM span: one level-1 per GiB window
/// crossed, plus one potential level-0 per 2 MiB span. Large-page mappings
/// reserve split storage without exposing it until a fine mapping is needed.
pub const fn ram_page_table_pages(ram: AddressRange) -> usize {
    assert!(!ram.is_empty());
    assert!(ram.start % (2 << 20) == 0 && ram.end % (2 << 20) == 0);
    (ram.end - 1) / (1 << 30) - ram.start / (1 << 30) + 1 + ram.len() / (2 << 20)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn table_storage_counts_every_crossed_root_window() {
        assert_eq!(
            ram_page_table_pages(AddressRange::new(0x80200000, 0x83e00000)),
            31
        );
        assert_eq!(
            ram_page_table_pages(AddressRange::new(0x40200000, 0x140000000)),
            2051
        );
        assert_eq!(
            ram_page_table_pages(AddressRange::new(0x3fe00000, 0x40200000)),
            4
        );
    }
}
