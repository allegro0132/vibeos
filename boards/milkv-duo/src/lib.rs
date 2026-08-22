#![no_std]

//! Board support description for the Milk-V Duo (CV1800B).

use vibeos_hal::{
    AddressRange, Board as BoardContract, BoardInfo, ConsoleCapabilities, Dwc2Description,
    DwmacDescription, IdentityMapping, MemoryAttributes, MemoryRegion, MmuDescription,
    PlicDescription, SdhciDescription, StatusLedDescription, UartDescription, UartQuirks,
    UartVariant,
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
pub const USB_BASE: usize = 0x0434_0000;
pub const USB_MMIO_END: usize = USB_BASE + 0x1_0000;
pub const USB_PHY_BASE: usize = 0x0300_6000;
pub const USB_PHY_END: usize = USB_PHY_BASE + 0x58;
pub const USB_IRQ: u32 = 30;
pub const SOC_CONTROL_BASE: usize = 0x0300_0000;
pub const SOC_CONTROL_MMIO_END: usize = SOC_CONTROL_BASE + 0xa000;
// RTC system block. Its control registers own the SoC's real reset path: the
// vendor OpenSBI cannot reset this SoC (its SRST handler is a no-op `ebreak`),
// so a working cold reboot must poke these registers directly, exactly as
// U-Boot's `cv_system_reset()` does. Only the two pages holding the warm-reset
// request (0x0502_60cc) and RTC CTRL0 unlock/trigger (0x0502_5004/0x0502_5008)
// are mapped.
pub const RTC_RESET_BASE: usize = 0x0502_5000;
pub const RTC_RESET_MMIO_END: usize = 0x0502_7000;
const RTC_CTRL0_UNLOCKKEY: usize = 0x0502_5004;
const RTC_CTRL0: usize = 0x0502_5008;
const RTC_EN_WARM_RST_REQ: usize = 0x0502_60cc;
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
pub const DWC2: Dwc2Description = Dwc2Description {
    registers: AddressRange::new(USB_BASE, USB_MMIO_END),
    phy: AddressRange::new(USB_PHY_BASE, USB_PHY_END),
    irq: USB_IRQ,
    soc_control: AddressRange::new(SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    dma_address_bits: 32,
    cache_line_bytes: 64,
};
pub const STATUS_LED: StatusLedDescription = StatusLedDescription {
    gpio: AddressRange::new(GPIOC_BASE, GPIOC_MMIO_END),
    pinmux: AddressRange::new(SOC_CONTROL_BASE + 0x1000, SOC_CONTROL_BASE + 0x2000),
    pinmux_register_offset: 0x12c,
    pinmux_function_mask: 0x7,
    pinmux_gpio_function: 3,
    gpio_bit: 24,
    active_high: true,
};
pub const HART_IDS: &[usize] = &[0];
pub const CONSOLE_CAPABILITIES: ConsoleCapabilities = ConsoleCapabilities {
    early_uart: true,
    usb_keyboard_input: true,
};

pub const MEMORY_MAP: &[MemoryRegion] = &[
    MemoryRegion::ram("kernel RAM", RAM_START, RAM_END),
    MemoryRegion::mmio("SoC control", SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    MemoryRegion::mmio("RTC reset", RTC_RESET_BASE, RTC_RESET_MMIO_END),
    MemoryRegion::mmio("GPIOC", GPIOC_BASE, GPIOC_MMIO_END),
    MemoryRegion::mmio("eFuse", EFUSE_BASE, EFUSE_MMIO_END),
    MemoryRegion::mmio("Ethernet", ETHERNET_BASE, ETHERNET_MMIO_END),
    MemoryRegion::mmio("UART", DEVICE_MMIO_START, DEVICE_MMIO_END),
    MemoryRegion::mmio("SDHCI", SDHCI_BASE, SDHCI_MMIO_END),
    MemoryRegion::mmio("USB DWC2", USB_BASE, USB_MMIO_END),
    MemoryRegion::mmio("PLIC", PLIC_BASE, PLIC_MMIO_END),
];

pub const MMIO_MAPPINGS: &[IdentityMapping] = &[
    IdentityMapping::pages("Ethernet", ETHERNET_BASE, ETHERNET_MMIO_END),
    IdentityMapping::pages("UART", DEVICE_MMIO_START, DEVICE_MMIO_END),
    IdentityMapping::pages("SDHCI", SDHCI_BASE, SDHCI_MMIO_END),
    IdentityMapping::pages("USB DWC2", USB_BASE, USB_MMIO_END),
    IdentityMapping::pages("SoC control", SOC_CONTROL_BASE, SOC_CONTROL_MMIO_END),
    IdentityMapping::pages("RTC reset", RTC_RESET_BASE, RTC_RESET_MMIO_END),
    IdentityMapping::pages("GPIOC", GPIOC_BASE, GPIOC_MMIO_END),
    IdentityMapping::pages("eFuse", EFUSE_BASE, EFUSE_MMIO_END),
];

pub const MMU: MmuDescription = MmuDescription {
    ram: AddressRange::new(RAM_START, RAM_END),
    ram_attributes: MemoryAttributes::THeadNormal,
    mmio_attributes: MemoryAttributes::THeadDevice,
    identity_mappings: MMIO_MAPPINGS,
    device_level1_tables: 2,
    // Three device windows in the first gigapage (0x0300_0000, 0x0400_0000,
    // 0x0420_0000) plus the new RTC-reset window (0x0500_0000), and two PLIC
    // windows in the second gigapage.
    device_level0_tables: 6,
};

/// Perform a hardware cold reset of the CV1800B.
///
/// The vendor OpenSBI cannot reset this SoC, so the SBI SRST ecall returns
/// without doing anything and a caller that loops on `wait_for_interrupt()`
/// simply hangs. The real reset path lives in the RTC control block; this
/// reproduces U-Boot's `cv_system_reset()`: raise the warm-reset request, wait
/// for it to latch, unlock RTC CTRL0, then set its reset-trigger bits.
///
/// # Safety
/// The RTC-reset pages (`RTC_RESET_BASE..RTC_RESET_MMIO_END`) must be identity
/// mapped as device memory, which the board [`MMU`] description guarantees.
pub fn cold_reset() -> ! {
    unsafe {
        let warm = RTC_EN_WARM_RST_REQ as *mut u32;
        warm.write_volatile(0x1);
        while warm.read_volatile() != 0x1 {
            core::hint::spin_loop();
        }
        (RTC_CTRL0_UNLOCKKEY as *mut u32).write_volatile(0xAB18);
        let ctrl0 = RTC_CTRL0 as *mut u32;
        let current = ctrl0.read_volatile();
        ctrl0.write_volatile(current | 0xFFFF_0800 | (0x1 << 4));
    }
    loop {
        core::hint::spin_loop();
    }
}

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
        dwc2: Some(DWC2),
        status_led: Some(STATUS_LED),
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
        assert_eq!(<Board as BoardContract>::INFO.dwc2, Some(DWC2));
        assert_eq!(<Board as BoardContract>::INFO.status_led, Some(STATUS_LED));
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
