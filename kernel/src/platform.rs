//! Firmware-provided physical resources. The kernel never selects a BSP.
#![allow(dead_code, unused_imports)]
use vibeos_hal::*;
pub use vibeos_image_policy::{BLOCK_DATA_SLICE, NETWORK_FRONTEND};
pub fn description() -> &'static vibeos_hal::boot::BootPlatform {
    vibeos_hal::boot::platform()
}
pub fn info() -> &'static BoardInfo {
    &description().info
}
pub fn mmu() -> &'static MmuDescription {
    &description().mmu
}
pub fn name() -> &'static str {
    info().name
}
pub fn timebase_hz() -> u64 {
    (description().timebase_hz)()
}
pub fn hart_ids() -> &'static [usize] {
    (description().hart_ids)()
}
pub fn pci() -> PciHostDescription {
    info().pci.expect("firmware did not supply a PCI host")
}
pub fn dwmac() -> DwmacDescription {
    info().dwmac.expect("firmware did not supply a DWMAC")
}
pub fn sdhci() -> SdhciDescription {
    info().sdhci.expect("firmware did not supply SDHCI")
}
pub fn dwc2() -> Dwc2Description {
    info().dwc2.expect("firmware did not supply DWC2")
}
pub fn status_led() -> StatusLedDescription {
    info()
        .status_led
        .expect("firmware did not supply a status LED")
}
pub fn virtio_mmio() -> VirtioMmioDescription {
    info()
        .virtio_mmio
        .expect("firmware did not supply VirtIO MMIO")
}
pub fn rtc_base() -> usize {
    description()
        .rtc
        .expect("firmware did not supply an RTC")
        .start
}
pub fn console_window() -> AddressRange {
    AddressRange::new(
        info().uart.registers.start,
        info()
            .virtio_mmio
            .map_or(info().uart.registers.end, |v| v.registers.end),
    )
}
pub fn cold_reset() -> ! {
    (description()
        .cold_reset
        .expect("firmware did not supply a cold reset"))()
}
