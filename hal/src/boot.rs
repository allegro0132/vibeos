//! Immutable firmware-to-kernel boot contract. Physical board choices and
//! memory reserved for RAM page tables belong to the final firmware image.
use crate::{AddressRange, BoardInfo, MemoryRegion, MmuDescription};

#[derive(Clone, Copy, Debug)]
pub struct PageTableArena {
    /// Physical address of zeroed, page-aligned, permanently owned storage.
    pub base: usize,
    pub pages: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct BootRequest {
    pub physical_hart: usize,
    pub dtb_address: usize,
    pub ram: AddressRange,
    /// Loaded image, static pools, page tables and all initial stacks.
    pub static_memory: AddressRange,
    pub heap_envelope: AddressRange,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    InvalidDtb,
    InvalidMemory,
    InvalidCpu,
    InvalidTimebase,
    AlreadyInitialized,
}
impl BootRequest {
    /// Clip the already reservation-subtracted memory map to the linker heap
    /// envelope, excluding partial pages around every reservation. No physical
    /// memory is read or written. The loaded static span must also be usable.
    pub fn usable_heap<const N: usize>(
        &self,
        memory: &crate::memory::BootMemory<N>,
    ) -> Result<crate::memory::BootMemory<N>, BootError> {
        if !memory.contains(self.static_memory)
            || self.static_memory.start < self.ram.start
            || self.static_memory.end != self.heap_envelope.start
            || self.heap_envelope.is_empty()
            || self.heap_envelope.end > self.ram.end
        {
            return Err(BootError::InvalidMemory);
        }
        let mut heap = crate::memory::BootMemory::new();
        for range in memory.ranges() {
            let start = range.start.max(self.heap_envelope.start);
            let end = range.end.min(self.heap_envelope.end) & !4095;
            let Some(start) = start.checked_add(4095).map(|s| s & !4095) else {
                continue;
            };
            if start < end {
                heap.add_ram(AddressRange::new(start, end))
                    .map_err(|_| BootError::InvalidMemory)?;
            }
        }
        if heap.ranges().is_empty() {
            return Err(BootError::InvalidMemory);
        }
        Ok(heap)
    }

    /// # Safety
    /// The boot firmware supplies immutable, readable physical RAM at this
    /// pointer. Bounds checks do not themselves establish physical readability.
    /// Consume the slice before the allocator can reuse the DTB's storage.
    pub unsafe fn dtb(&self) -> Result<&[u8], BootError> {
        if self.dtb_address % 8 != 0
            || self.dtb_address < self.ram.start
            || self
                .dtb_address
                .checked_add(40)
                .filter(|&end| end <= self.ram.end)
                .is_none()
        {
            return Err(BootError::InvalidDtb);
        }
        let header = unsafe { core::slice::from_raw_parts(self.dtb_address as *const u8, 40) };
        let size = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
        if !(40..=1024 * 1024).contains(&size)
            || self
                .dtb_address
                .checked_add(size)
                .filter(|&end| end <= self.ram.end)
                .is_none()
        {
            return Err(BootError::InvalidDtb);
        }
        let bytes = unsafe { core::slice::from_raw_parts(self.dtb_address as *const u8, size) };
        crate::fdt::Fdt::new(bytes).map_err(|_| BootError::InvalidDtb)?;
        Ok(bytes)
    }
}

pub struct BootPlatform {
    /// Persistent logical device identity is image policy, not controller type.
    pub managed_block_id: core::num::NonZeroU128,
    /// User-visible primary NIC driver label supplied by the composition root.
    pub network_driver_name: &'static str,
    pub info: BoardInfo,
    pub memory_map: &'static [MemoryRegion],
    pub mmu: MmuDescription,
    /// Called only after successful boot admission, when configured.
    pub hart_ids: fn() -> &'static [usize],
    pub timebase_hz: fn() -> u64,
    /// # Safety
    /// Boot-hart-only, before paging, heap setup or secondary release. The
    /// firmware pointer is readable physical memory inside the supplied RAM
    /// envelope. Validate before publishing any immutable runtime description.
    /// No allocation, device registration or references into reusable DTB RAM.
    pub admit_boot: Option<unsafe fn(BootRequest) -> Result<(), BootError>>,
    /// Post-admission immutable usable heap ranges; None retains the linker
    /// envelope. Ranges are sorted, disjoint and exclude all reservations.
    pub heap_regions: Option<fn() -> &'static [AddressRange]>,
    pub rtc: Option<AddressRange>,
    pub cold_reset: Option<fn() -> !>,
    /// # Safety
    /// Boot-hart-only hook after identity mappings exist, before secondary
    /// harts and services start. No allocation or capability policy is allowed.
    pub early_platform_init: unsafe fn(fn(&str)),
    /// # Safety
    /// Called by the same boot hart after early_platform_init, before SMP.
    /// Firmware may report the initialized platform without kernel dependencies.
    pub platform_report: unsafe fn(fn(core::fmt::Arguments<'_>)),
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
