#![no_std]

//! Board support description for QEMU's RISC-V `virt` machine.

use vibeos_hal::{
    AddressRange, Board as BoardContract, BoardInfo, MemoryRegion, PlicDescription, UartDescription,
};

pub const NAME: &str = "QEMU virt";
pub const RAM_START: usize = 0x8020_0000;
pub const RAM_END: usize = 0x8800_0000;
pub const PLIC_BASE: usize = 0x0c00_0000;
pub const PLIC_MMIO_END: usize = PLIC_BASE + 0x0040_0000;
pub const PLIC_MAX_IRQ: u32 = 1023;
pub const UART_BASE: usize = 0x1000_0000;
pub const UART_IRQ: u32 = 10;
pub const UART_REG_SHIFT: usize = 0;
pub const UART_REG_WIDTH: usize = 1;
pub const UART_CLOCK_HZ: u32 = 1_843_200;
pub const UART_BAUD: u32 = 38_400;
pub const DEVICE_MMIO_START: usize = UART_BASE;
pub const DEVICE_MMIO_END: usize = 0x1000_9000;
pub const PCI_ECAM_START: usize = 0x3000_0000;
pub const PCI_ECAM_END: usize = 0x4000_0000;
pub const PCI_IO_START: usize = 0x0300_0000;
pub const PCI_IO_END: usize = 0x0301_0000;
pub const PCI_MMIO_START: usize = 0x4000_0000;
pub const PCI_MMIO_END: usize = 0x8000_0000;
pub const PCI_INTX_FIRST_IRQ: u32 = 32;
pub const TIMEBASE_HZ: u64 = 10_000_000;
pub const VIRTIO_MMIO_SLOTS: usize = 8;
pub const HART_IDS: &[usize] = &[0, 1, 2, 3];

pub const MEMORY_MAP: &[MemoryRegion] = &[
    MemoryRegion::ram("kernel RAM", RAM_START, RAM_END),
    MemoryRegion::mmio("PLIC", PLIC_BASE, PLIC_MMIO_END),
    MemoryRegion::mmio("platform devices", DEVICE_MMIO_START, DEVICE_MMIO_END),
    MemoryRegion::mmio("PCI I/O", PCI_IO_START, PCI_IO_END),
    MemoryRegion::mmio("PCI ECAM", PCI_ECAM_START, PCI_ECAM_END),
    MemoryRegion::mmio("PCI MMIO", PCI_MMIO_START, PCI_MMIO_END),
];

pub struct Board;

impl BoardContract for Board {
    const INFO: BoardInfo = BoardInfo {
        name: NAME,
        timebase_hz: TIMEBASE_HZ,
        uart: UartDescription {
            registers: AddressRange::new(UART_BASE, UART_BASE + 0x100),
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
    if physical_hart <= (usize::MAX - 1) / 2 {
        Some(physical_hart * 2 + 1)
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
        assert_eq!(<Board as BoardContract>::HART_IDS, &[0, 1, 2, 3]);
        assert_eq!(plic_s_context(3), Some(7));
        assert!(MEMORY_MAP.iter().all(|region| !region.range.is_empty()));
    }
}
