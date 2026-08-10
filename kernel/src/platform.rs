//! Compile-time board description for the hardware-specific kernel modules.
//!
//! Keep this surface deliberately small: the QEMU and Milk-V Duo ports select
//! identical names so UART, PLIC, MMU, timer, and boot code do not need their
//! own feature conditionals.

#[cfg(all(feature = "qemu-virt", feature = "milkv-duo"))]
compile_error!("features `qemu-virt` and `milkv-duo` are mutually exclusive");

#[cfg(not(any(feature = "qemu-virt", feature = "milkv-duo")))]
compile_error!("exactly one board feature must be enabled: `qemu-virt` or `milkv-duo`");

#[cfg(all(feature = "qemu-virt", not(feature = "milkv-duo")))]
mod selected {
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
    // Preserve the existing QEMU driver setup: divisor 3 at 1.8432 MHz.
    pub const UART_BAUD: u32 = 38_400;
    pub const DEVICE_MMIO_START: usize = UART_BASE;
    pub const DEVICE_MMIO_END: usize = 0x1000_9000;

    pub const TIMEBASE_HZ: u64 = 10_000_000;
    pub const VIRTIO_MMIO_SLOTS: usize = 8;
    pub const HART_IDS: &[usize] = &[0, 1, 2, 3];

    pub const fn plic_s_context(physical_hart: usize) -> Option<usize> {
        if physical_hart <= (usize::MAX - 1) / 2 {
            Some(physical_hart * 2 + 1)
        } else {
            None
        }
    }
}

#[cfg(all(feature = "milkv-duo", not(feature = "qemu-virt")))]
mod selected {
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

    // CV1800B device-tree values from the SDK revision pinned by
    // docs/MILKV_DUO.md. The Ethernet IO Board is wired to the SoC's internal
    // PHY through this RMII DWMAC instance; the boot microSD uses SDIO0.
    pub const ETHERNET_BASE: usize = 0x0407_0000;
    pub const ETHERNET_MMIO_END: usize = ETHERNET_BASE + 0x1_0000;
    pub const ETHERNET_IRQ: u32 = 31;
    pub const SDHCI_BASE: usize = 0x0431_0000;
    pub const SDHCI_MMIO_END: usize = SDHCI_BASE + 0x1000;
    pub const SDHCI_IRQ: u32 = 36;
    // CV1800B top, pinmux, and clock-generator pages used to take explicit
    // ownership of SDIO0 and ETH0 from the boot loader.
    pub const SOC_CONTROL_BASE: usize = 0x0300_0000;
    pub const SOC_CONTROL_MMIO_END: usize = SOC_CONTROL_BASE + 0xa000;
    // The Duo's blue user LED is driven by GPIOC24. GPIOC is outside the
    // compact top/pinmux/clock window above even though both regions share the
    // same Sv39 2 MiB level-0 table.
    pub const GPIOC_BASE: usize = 0x0302_2000;
    pub const GPIOC_MMIO_END: usize = GPIOC_BASE + 0x1000;
    pub const EFUSE_BASE: usize = 0x0305_0000;
    pub const EFUSE_MMIO_END: usize = EFUSE_BASE + 0x1000;

    pub const TIMEBASE_HZ: u64 = 25_000_000;
    // Stock Duo firmware exposes only C906B (hart 0) to OpenSBI. C906L is an
    // AMP core released independently by the FSBL and must not be HSM-probed.
    pub const HART_IDS: &[usize] = &[0];

    pub const fn plic_s_context(physical_hart: usize) -> Option<usize> {
        if physical_hart == 0 {
            Some(1)
        } else {
            None
        }
    }
}

#[cfg(any(
    all(feature = "qemu-virt", feature = "milkv-duo"),
    not(any(feature = "qemu-virt", feature = "milkv-duo"))
))]
mod selected {}

pub use selected::*;
