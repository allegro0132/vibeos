#![no_std]
//! Milk-V Mars 4 GiB board facts, pinned to the SDK dev revision below.
//! This crate is a hardware description, not a claim of firmware support.
//! Runtime memory must be admitted from the boot DTB before use.
pub mod harts;
pub mod resources;
pub mod network_resources;
pub mod trng_resources;
mod dtb;

use vibeos_hal::{
    fdt::{Error as FdtError, Fdt},
    memory::BootMemory,
};
use vibeos_hal::{AddressRange, PlicDescription, UartDescription, UartQuirks, UartVariant};

pub const SDK_COMMIT: &str = "1fd6bac9f2efde47fbb8afd28d2903c49f893e3f";
pub const NAME: &str = "Milk-V Mars (JH7110, 4 GiB)";
pub const RAM: AddressRange = AddressRange::new(0x4000_0000, 0x1_4000_0000);
pub const FIRMWARE_RESERVED: AddressRange = AddressRange::new(0x4000_0000, 0x4020_0000);
pub const KERNEL_LOAD_ADDRESS: usize = 0x4020_0000;
pub const TIMEBASE_HZ: u64 = 4_000_000;
/// Hart 0 is the S7 monitor core, disabled in the SDK DTB. It is never an
/// application scheduling slot, even if firmware enumerates five harts.
pub const HART_IDS: &[usize] = &[1, 2, 3, 4];
pub const PLIC: PlicDescription = PlicDescription {
    registers: AddressRange::new(0x0c00_0000, 0x1000_0000),
    max_irq: 136,
};
pub const UART_REGISTERS: AddressRange = AddressRange::new(0x1000_0000, 0x1001_0000);
pub const UART_IRQ: u32 = 32;
/// Clock must be obtained from the initialized platform clock tree. The BSP
/// does not infer a clock from the baud rate or borrow the Duo oscillator.
pub const fn console(clock_hz: u32) -> UartDescription {
    UartDescription {
        variant: UartVariant::DesignWareApb,
        registers: UART_REGISTERS,
        irq: UART_IRQ,
        register_shift: 2,
        register_width: 4,
        clock_hz,
        baud: 115_200,
        quirks: UartQuirks::DESIGNWARE_APB,
    }
}
/// SDK clock tree gates UART0 directly from the 24 MHz oscillator.
pub const UART: UartDescription = console(24_000_000);
pub const SD_REGISTERS: AddressRange = AddressRange::new(0x1602_0000, 0x1603_0000);
/// SDIO1 CLK, CMD, DAT0..3 wiring from the pinned board DTS.
pub const SD_SETTLE_MS: u32 = 200;
pub const SD_PINS: vibeos_platform_jh7110::sd::Pins =
    vibeos_platform_jh7110::sd::Pins([10, 9, 11, 12, 7, 8]);
pub const SYS_SYSCON: AddressRange = AddressRange::new(0x1303_0000, 0x1304_0000);
/// Firmware must pass the actual clock rate returned by platform preparation.
pub const fn sd_controller(source_clock_hz: u32) -> vibeos_hal::DwMshcDescription {
    assert!(source_clock_hz > 0 && source_clock_hz <= SD_SOURCE_CLOCK_CEILING_HZ);
    vibeos_hal::DwMshcDescription {
        registers: SD_REGISTERS,
        irq: SD_IRQ,
        source_clock_hz,
        data_clock_hz: SD_DATA_CLOCK_HZ,
        fifo_depth_words: SD_FIFO_DEPTH_WORDS,
        fifo_offset: 0x200,
    }
}
pub const SD_IRQ: u32 = 75;
/// Requested maximum, not the measured source frequency supplied to MSHC.
pub const SD_SOURCE_CLOCK_CEILING_HZ: u32 = 50_000_000;
pub const SD_DATA_CLOCK_HZ: u32 = 25_000_000;
pub const SD_FIFO_DEPTH_WORDS: u16 = 32;
pub const GMAC0_REGISTERS: AddressRange = AddressRange::new(0x1603_0000, 0x1604_0000);
pub const GMAC0_IRQ: u32 = 7;
pub const SYS_CRG: AddressRange = AddressRange::new(0x1302_0000, 0x1303_0000);
pub const AON_CRG: AddressRange = AddressRange::new(0x1700_0000, 0x1701_0000);
pub const AON_SYSCON: AddressRange = AddressRange::new(0x1701_0000, 0x1701_1000);
pub const AON_PINCTRL: AddressRange = AddressRange::new(0x1702_0000, 0x1703_0000);
pub const GMAC0_TX_DRIVE: u8 = 1;
pub const SYS_PINCTRL: AddressRange = AddressRange::new(0x1304_0000, 0x1305_0000);
pub const L2_CACHE: AddressRange = AddressRange::new(0x0201_0000, 0x0201_4000);
pub const TRNG_REGISTERS: AddressRange = AddressRange::new(0x1600_c000, 0x1601_0000);
pub const TRNG_IRQ: u32 = 30;
pub const STG_CRG: AddressRange = AddressRange::new(0x1023_0000, 0x1024_0000);

pub const fn plic_s_context(physical_hart: usize) -> Option<usize> {
    // S7 has only one M context, followed by M/S pairs for U74 harts 1..4.
    match physical_hart {
        1..=4 => Some(physical_hart * 2),
        _ => None,
    }
}

/// Admit the fixed 4 GiB model, subtracting all DTB reservations and the
/// OpenSBI boot area. The caller must additionally reserve the loaded image,
/// permanent DMA and page-table pools before making ranges allocatable.
pub fn usable_memory<const N: usize>(
    dtb: &[u8],
    physical_address: usize,
) -> Result<BootMemory<N>, FdtError> {
    let tree = Fdt::new(dtb)?;
    validate_board(&tree)?;
    let mut memory = tree.memory::<N>(physical_address)?;
    if memory.ranges().is_empty()
        || memory
            .ranges()
            .iter()
            .any(|r| r.start < RAM.start || r.end > RAM.end)
    {
        return Err(FdtError::InvalidRange);
    }
    memory.reserve(FIRMWARE_RESERVED)?;
    Ok(memory)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_harts_map_to_actual_supervisor_contexts() {
        assert_eq!(HART_IDS, &[1, 2, 3, 4]);
        assert_eq!(plic_s_context(0), None);
        for &(hart, context) in &[(1, 2), (2, 4), (3, 6), (4, 8)] {
            assert_eq!(plic_s_context(hart), Some(context));
        }
        assert_eq!(plic_s_context(5), None);
        assert_eq!(plic_s_context(usize::MAX), None);
    }
    #[test]
    fn four_gib_memory_is_not_truncated_at_four_gib_address() {
        assert_eq!(RAM.len(), 4usize * 1024 * 1024 * 1024);
        assert_eq!(RAM.end, 0x140000000);
        assert_eq!(FIRMWARE_RESERVED.end, KERNEL_LOAD_ADDRESS);
    }
    #[test]
    fn sd_platform_wiring_and_actual_clock_are_board_owned() {
        assert_eq!(SD_PINS.0, [10, 9, 11, 12, 7, 8]);
        assert_eq!(SD_SETTLE_MS, 200);
        let controller = sd_controller(49_500_000);
        assert_eq!(controller.source_clock_hz, 49_500_000);
        assert_eq!(controller.data_clock_hz, 25_000_000);
        assert_eq!(controller.registers, SD_REGISTERS);
    }
    #[test]
    fn microsd_is_mshc_one_and_not_emmc_zero() {
        assert_eq!(SD_REGISTERS.start, 0x16020000);
        assert_eq!(SD_IRQ, 75);
        assert_eq!(console(24_000_000).register_shift, 2);
        assert_eq!(PLIC.max_irq, 136);
    }
    #[test]
    fn invalid_boot_blob_is_not_admitted() {
        assert!(usable_memory::<16>(&[0; 40], 0x48000000).is_err());
    }
}

fn validate_board(tree: &Fdt<'_>) -> Result<(), FdtError> {
    // Identify the board before interpreting its physical addresses.
    let mut mars = false;
    let mut seen = false;
    for event in tree.events() {
        if let vibeos_hal::fdt::Event::Property {
            depth: 0,
            name: "compatible",
            value,
        } = event?
        {
            if seen || value.last() != Some(&0) || value.len() < 2 {
                return Err(FdtError::InvalidStructure);
            }
            seen = true;
            if value[..value.len() - 1]
                .split(|&b| b == 0)
                .any(|s| s.is_empty() || core::str::from_utf8(s).is_err())
            {
                return Err(FdtError::InvalidString);
            }
            mars = value.split(|&x| x == 0).any(|s| s == b"milk-v,mars");
        }
    }
    if !mars {
        return Err(FdtError::InvalidHeader);
    }
    Ok(())
}

/// Static mapping envelope for the console/SD composition. Device resources
/// must pass `resources::admit` before any service is registered. Standard PTE
/// attributes rely on JH7110 PMAs; T-Head attributes/instructions are forbidden.
pub struct Board;
pub const MEMORY_MAP: &[vibeos_hal::MemoryRegion] = &[
    vibeos_hal::MemoryRegion::reserved("boot firmware", RAM.start, KERNEL_LOAD_ADDRESS),
    vibeos_hal::MemoryRegion::ram("kernel RAM", KERNEL_LOAD_ADDRESS, RAM.end),
    vibeos_hal::MemoryRegion::mmio("PLIC", PLIC.registers.start, PLIC.registers.end),
    vibeos_hal::MemoryRegion::mmio("UART0", UART_REGISTERS.start, UART_REGISTERS.end),
    vibeos_hal::MemoryRegion::mmio("SYS CRG/SYSCON/pins", SYS_CRG.start, SYS_PINCTRL.end),
    vibeos_hal::MemoryRegion::mmio("SDIO1/GMAC0", SD_REGISTERS.start, GMAC0_REGISTERS.end),
    vibeos_hal::MemoryRegion::mmio("L2 control", L2_CACHE.start, L2_CACHE.end),
    vibeos_hal::MemoryRegion::mmio("AON CRG/SYSCON", AON_CRG.start, AON_SYSCON.end),
    vibeos_hal::MemoryRegion::mmio("AON pins", AON_PINCTRL.start, AON_PINCTRL.end),
];
pub const MMIO_MAPPINGS: &[vibeos_hal::IdentityMapping] = &[
    vibeos_hal::IdentityMapping::pages("UART0", UART_REGISTERS.start, UART_REGISTERS.end),
    vibeos_hal::IdentityMapping::pages("SYS CRG/SYSCON/pins", SYS_CRG.start, SYS_PINCTRL.end),
    vibeos_hal::IdentityMapping::pages("SDIO1/GMAC0", SD_REGISTERS.start, GMAC0_REGISTERS.end),
    vibeos_hal::IdentityMapping::pages("L2 control", L2_CACHE.start, L2_CACHE.end),
    vibeos_hal::IdentityMapping::pages("AON CRG/SYSCON", AON_CRG.start, AON_SYSCON.end),
    vibeos_hal::IdentityMapping::pages("AON pins", AON_PINCTRL.start, AON_PINCTRL.end),
];
impl vibeos_hal::Board for Board {
    const INFO: vibeos_hal::BoardInfo = vibeos_hal::BoardInfo {
        name: NAME,
        timebase_hz: TIMEBASE_HZ,
        uart: UART,
        plic: PLIC,
        console: vibeos_hal::ConsoleCapabilities {
            early_uart: true,
            usb_keyboard_input: false,
        },
        virtio_mmio: None,
        pci: None,
        dwmac: None,
        sdhci: None,
        dwc2: None,
        status_led: None,
    };
    const MEMORY_MAP: &'static [vibeos_hal::MemoryRegion] = MEMORY_MAP;
    const MMU: vibeos_hal::MmuDescription = vibeos_hal::MmuDescription {
        ram: AddressRange::new(KERNEL_LOAD_ADDRESS, RAM.end),
        ram_granularity: vibeos_hal::MappingGranularity::Megapage2M,
        ram_attributes: vibeos_hal::MemoryAttributes::Standard,
        mmio_attributes: vibeos_hal::MemoryAttributes::Standard,
        identity_mappings: MMIO_MAPPINGS,
        device_level1_tables: 1,
        // UART, SYS, SD/GMAC, L2, AON and the two sparse PLIC windows.
        device_level0_tables: 7,
    };
    const HART_IDS: &'static [usize] = HART_IDS;
    fn plic_s_context(physical_hart: usize) -> Option<usize> {
        plic_s_context(physical_hart)
    }
}
