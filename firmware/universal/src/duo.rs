use vibeos_bsp_milkv_duo::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
pub(super) mod early_devices;

#[cfg(feature = "driver-sdhci-blk")]
#[path = "../../milkv-duo/src/storage.rs"]
pub(super) mod storage;

#[cfg(feature = "driver-dwmac-net")]
#[path = "../../milkv-duo/src/network.rs"]
pub(super) mod network;

#[cfg(feature = "driver-milkv-duo-led")]
#[path = "../../milkv-duo/src/platform.rs"]
pub(super) mod platform;
#[cfg(feature = "driver-milkv-duo-led")]
use platform::{platform_init, platform_report};
#[cfg(not(feature = "driver-milkv-duo-led"))]
unsafe fn platform_init(_: fn(&str)) {}
#[cfg(not(feature = "driver-milkv-duo-led"))]
unsafe fn platform_report(_: fn(core::fmt::Arguments<'_>)) {}

#[cfg(feature = "driver-dwc2-host")]
#[path = "../../milkv-duo/src/usb.rs"]
pub(super) mod usb;

// Preserve the established storage namespace independently of HAL frontend choice.
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0002).unwrap();
const NETWORK_DRIVER_NAME: &str = "dwmac";

fn hart_ids() -> &'static [usize] {
    Board::HART_IDS
}
fn timebase_hz() -> u64 {
    Board::INFO.timebase_hz
}
const BOOT_ADMISSION: Option<
    unsafe fn(vibeos_hal::boot::BootRequest) -> Result<(), vibeos_hal::boot::BootError>,
> = None;

const BOOT_HEAP_REGIONS: Option<fn() -> &'static [vibeos_hal::AddressRange]> = None;

const HEAP_END: usize = Board::MMU.ram.end;
