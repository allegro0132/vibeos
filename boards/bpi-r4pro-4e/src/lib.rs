#![no_std]
//! MT7988A BPI-R4 Pro 4E boot contract and board peripheral mechanisms.
//!
//! Sources and physical observations: docs/BPI_R4PRO_4E.md.
//! This deliberately does not implement the RISC-V-specific Board contract.
//! Full RAM discovery must use the boot FDT, including every reserved region.

use vibeos_hal::AddressRange;
pub use vibeos_ethernet::sfp as sfp_identity;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod hardware;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use hardware::{sfp, status_leds};

pub const NAME: &str = "BPI-R4PRO-4E";
pub const COMPATIBLE: &str = "bananapi,bpi-r4-pro-4e";
pub const CPU_COUNT: usize = 4;
pub const UART_BASE: usize = 0x1100_0000;
pub const UART_REGISTER_SHIFT: usize = 2;
pub const UART_REGISTER_WIDTH: usize = 4;
pub const UART_BAUD: u32 = 115_200;
/// GIC INTID, not the DT SPI-relative number (123).
pub const UART_INTID: u32 = 32 + 123;
/// NETSYS FE2 group, SPI 198 in the MT7988 DT.
pub const ETHERNET_RX_INTID: u32 = 32 + 198;
pub const GIC_DISTRIBUTOR: AddressRange = AddressRange::new(0x0c00_0000, 0x0c04_0000);
pub const GIC_REDISTRIBUTORS: AddressRange = AddressRange::new(0x0c08_0000, 0x0c28_0000);
pub const NONSECURE_TIMER_INTID: u32 = 16 + 14;
pub const SECURE_MONITOR: AddressRange = AddressRange::new(0x4300_0000, 0x4305_0000);
/// A small bootstrap arena, not a claim about installed RAM capacity.
/// Load through U-Boot only after checking bdinfo and the current FDT.
pub const BOOT_RAM: AddressRange = AddressRange::new(0x4008_0000, 0x4100_0000);
pub const PSCI_USES_SMC: bool = true;

/// Known firmware carveouts on the attached 4 GiB board. These are a minimum,
/// never a replacement for parsing the actual FDT reservation map.
pub const FIRMWARE_RESERVED: &[AddressRange] = &[
    AddressRange::new(0x42ff_0000, 0x4300_0000),
    SECURE_MONITOR,
    AddressRange::new(0x47cc_0000, 0x47dc_0000),
    AddressRange::new(0x4f60_0000, 0x4f6c_0000),
    AddressRange::new(0x4f70_0000, 0x4ff0_0000),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_does_not_overlap_firmware() {
        assert!(!BOOT_RAM.is_empty());
        assert_eq!(BOOT_RAM.start % 0x1000, 0);
        for reserved in FIRMWARE_RESERVED {
            assert!(BOOT_RAM.end <= reserved.start || BOOT_RAM.start >= reserved.end);
        }
    }

    #[test]
    fn gic_ranges_and_interrupt_namespaces_are_consistent() {
        assert_eq!(GIC_DISTRIBUTOR.len(), 0x40000);
        assert_eq!(GIC_REDISTRIBUTORS.len(), 0x200000);
        assert!(GIC_DISTRIBUTOR.end <= GIC_REDISTRIBUTORS.start);
        assert_eq!(UART_INTID, 155);
        assert_eq!(ETHERNET_RX_INTID, 230);
        assert_eq!(NONSECURE_TIMER_INTID, 30);
    }
}
