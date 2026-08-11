#![no_std]

//! Board support description for the Milk-V Duo (CV1800B).

use vibeos_hal::{
    AddressRange, Board as BoardContract, BoardInfo, ConsoleCapabilities, DwmacDescription,
    IdentityMapping, MemoryAttributes, MemoryRegion, MmuDescription, PlicDescription,
    SdhciDescription, UartDescription, UartQuirks, UartVariant,
};

pub const NAME: &str = "Milk-V Duo (CV1800B)";
pub const RAM_START: usize = 0x8020_0000;
pub const RAM_END: usize = 0x83e0_0000;
pub const PLIC_BASE: usize = 0x7000_0000;
pub const PLIC_MMIO_END: usize = PLIC_BASE + 0x0400_0000;
pub const PLIC_MAX_IRQ: u32 = 101;
pub const UART_BASE: usize = 0x0414_0000;
pub const UART_IRQ: u32 = 44;
pub const UART_REG_SHIFT: usize = 2;
pub const UART_REG_WIDTH: usize = 4;
pub const UART_CLOCK_HZ: u32 = 25_000_000;
pub const UART_BAUD: u32 = 115_200;
pub const DEVICE_MMIO_START: usize = UART_BASE;
pub const DEVICE_MMIO_END: usize = UART_BASE + 0x1000;
pub const ETHERNET_BASE: usize = 0x0407_0000;
pub const ETHERNET_MMIO_END: usize = ETHERNET_BASE + 0x1_0000;
pub const ETHERNET_IRQ: u32 = 31;
pub const SDHCI_BASE: usize = 0x0431_0000;
pub const SDHCI_MMIO_END: usize = SDHCI_BASE + 0x1000;
pub const SDHCI_IRQ: u32 = 36;
pub const SOC_CONTROL_BASE: usize = 0x0300_0000;
pub const SOC_CONTROL_MMIO_END: usize = SOC_CONTROL_BASE + 0xa000;
pub const GPIOC_BASE: usize = 0x0302_2000;
pub const GPIOC_MMIO_END: usize = GPIOC_BASE + 0x1000;
pub const EFUSE_BASE: usize = 0x0305_0000;
pub const EFUSE_MMIO_END: usize = EFUSE_BASE + 0x1000;
pub const TIMEBASE_HZ: u64 = 25_000_000;
pub const DWMAC: DwmacDescription = DwmacDescription {
    registers: AddressRange::new(ETHERNET_BASE, ETHERNET_MMIO_END),
    irq: ETHERNET_IRQ,
    soc_control: AddressRange::new(SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    efuse: AddressRange::new(EFUSE_BASE, EFUSE_MMIO_END),
    phy_address: 0,
    dma_address_bits: 32,
    cache_line_bytes: 64,
};
pub const SDHCI: SdhciDescription = SdhciDescription {
    registers: AddressRange::new(SDHCI_BASE, SDHCI_MMIO_END),
    irq: SDHCI_IRQ,
    soc_control: AddressRange::new(SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    source_clock_hz: 375_000_000,
    bus_width: 1,
    init_clock_hz: 400_000,
    data_clock_hz: 25_000_000,
};
pub const HART_IDS: &[usize] = &[0];
pub const CONSOLE_CAPABILITIES: ConsoleCapabilities = ConsoleCapabilities {
    early_uart: true,
    usb_keyboard_input: false,
};

pub const MEMORY_MAP: &[MemoryRegion] = &[
    MemoryRegion::ram("kernel RAM", RAM_START, RAM_END),
    MemoryRegion::mmio("SoC control", SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    MemoryRegion::mmio("GPIOC", GPIOC_BASE, GPIOC_MMIO_END),
    MemoryRegion::mmio("eFuse", EFUSE_BASE, EFUSE_MMIO_END),
    MemoryRegion::mmio("Ethernet", ETHERNET_BASE, ETHERNET_MMIO_END),
    MemoryRegion::mmio("UART", DEVICE_MMIO_START, DEVICE_MMIO_END),
    MemoryRegion::mmio("SDHCI", SDHCI_BASE, SDHCI_MMIO_END),
    MemoryRegion::mmio("PLIC", PLIC_BASE, PLIC_MMIO_END),
];

pub const MMIO_MAPPINGS: &[IdentityMapping] = &[
    IdentityMapping::pages("Ethernet", ETHERNET_BASE, ETHERNET_MMIO_END),
    IdentityMapping::pages("UART", DEVICE_MMIO_START, DEVICE_MMIO_END),
    IdentityMapping::pages("SDHCI", SDHCI_BASE, SDHCI_MMIO_END),
    IdentityMapping::pages("SoC control", SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    IdentityMapping::pages("GPIOC", GPIOC_BASE, GPIOC_MMIO_END),
    IdentityMapping::pages("eFuse", EFUSE_BASE, EFUSE_MMIO_END),
];

pub const MMU: MmuDescription = MmuDescription {
    ram: AddressRange::new(RAM_START, RAM_END),
    ram_attributes: MemoryAttributes::THeadNormal,
    mmio_attributes: MemoryAttributes::THeadDevice,
    identity_mappings: MMIO_MAPPINGS,
    device_level1_tables: 2,
    device_level0_tables: 5,
};

pub struct Board;

impl BoardContract for Board {
    const INFO: BoardInfo = BoardInfo {
        name: NAME,
        timebase_hz: TIMEBASE_HZ,
        uart: UartDescription {
            variant: UartVariant::DesignWareApb,
            registers: AddressRange::new(UART_BASE, UART_BASE + 0x1000),
            irq: UART_IRQ,
            register_shift: UART_REG_SHIFT,
            register_width: UART_REG_WIDTH,
            clock_hz: UART_CLOCK_HZ,
            baud: UART_BAUD,
            quirks: UartQuirks::DESIGNWARE_APB,
        },
        plic: PlicDescription {
            registers: AddressRange::new(PLIC_BASE, PLIC_MMIO_END),
            max_irq: PLIC_MAX_IRQ,
        },
        console: CONSOLE_CAPABILITIES,
        virtio_mmio: None,
        pci: None,
        dwmac: Some(DWMAC),
        sdhci: Some(SDHCI),
    };
    const MEMORY_MAP: &'static [MemoryRegion] = MEMORY_MAP;
    const MMU: MmuDescription = MMU;
    const HART_IDS: &'static [usize] = HART_IDS;

    fn plic_s_context(physical_hart: usize) -> Option<usize> {
        plic_s_context(physical_hart)
    }
}

pub const fn plic_s_context(physical_hart: usize) -> Option<usize> {
    if physical_hart == 0 {
        Some(1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_matches_legacy_contract() {
        assert_eq!(<Board as BoardContract>::INFO.uart.irq, UART_IRQ);
        assert_eq!(
            <Board as BoardContract>::INFO.uart.variant,
            UartVariant::DesignWareApb
        );
        assert_eq!(<Board as BoardContract>::INFO.console, CONSOLE_CAPABILITIES);
        assert_eq!(<Board as BoardContract>::INFO.dwmac, Some(DWMAC));
        assert_eq!(<Board as BoardContract>::INFO.sdhci, Some(SDHCI));
        assert_eq!(<Board as BoardContract>::HART_IDS, &[0]);
        assert_eq!(plic_s_context(0), Some(1));
        assert_eq!(plic_s_context(1), None);
        assert!(MEMORY_MAP.iter().all(|region| !region.range.is_empty()));
        assert_eq!(<Board as BoardContract>::MMU, MMU);
        assert!(MMIO_MAPPINGS.iter().all(|mapping| {
            !mapping.range.is_empty()
                && mapping.range.start % mapping.granularity.bytes() == 0
                && mapping.range.end % mapping.granularity.bytes() == 0
        }));
    }
}
