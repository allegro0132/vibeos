#![no_std]
#![no_main]

use core::arch::global_asm;

// The final binary owns the architectural entry symbol. The unresolved jump
// target also forces the kernel boot object out of its rlib archive.
global_asm!(
    r#"
.section .text.boot
.option norvc
.global _start
_start:
    j vibeos_kernel_start
"#
);

extern crate vibeos_kernel;

use vibeos_bsp_milkv_duo::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
mod early_devices;

mod storage;

mod network;

mod platform;
use platform::{platform_init, platform_report};

mod usb;

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
