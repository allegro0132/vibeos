#![no_std]

//! Board support description for the Milk-V Duo (CV1800B).

use vibeos_hal::{
    AddressRange, Board as BoardContract, BoardInfo, MemoryRegion, PlicDescription, UartDescription,
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
pub const HART_IDS: &[usize] = &[0];

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

pub struct Board;

impl BoardContract for Board {
    const INFO: BoardInfo = BoardInfo {
        name: NAME,
        timebase_hz: TIMEBASE_HZ,
        uart: UartDescription {
            registers: AddressRange::new(UART_BASE, UART_BASE + 0x1000),
            irq: UART_IRQ,
            register_shift: UART_REG_SHIFT,
            register_width: UART_REG_WIDTH,
            clock_hz: UART_CLOCK_HZ,
            baud: UART_BAUD,
        },
        plic: PlicDescription {
            registers: AddressRange::new(PLIC_BASE, PLIC_MMIO_END),
            max_irq: PLIC_MAX_IRQ,
        },
    };
    const MEMORY_MAP: &'static [MemoryRegion] = MEMORY_MAP;
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
        assert_eq!(<Board as BoardContract>::HART_IDS, &[0]);
        assert_eq!(plic_s_context(0), Some(1));
        assert_eq!(plic_s_context(1), None);
        assert!(MEMORY_MAP.iter().all(|region| !region.range.is_empty()));
    }
}
