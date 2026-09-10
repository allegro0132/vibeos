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

use vibeos_bsp_qemu_virt::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
mod early_devices;

#[cfg(all(feature = "mmu-large-memory", any(feature = "python-wasi", feature = "storage-bench")))]
compile_error!("the high-RAM probe requires the ordinary 128 MiB heap contract");

mod entropy;

mod storage;

mod network;

unsafe fn platform_init(_write: fn(&str)) {}
unsafe fn platform_report(_print: fn(core::fmt::Arguments<'_>)) {}

mod pci;

mod usb;

mod transport;

// Preserve the established storage namespace independently of HAL frontend choice.
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0001).unwrap();
const NETWORK_DRIVER_NAME: &str = "virtio-mmio";

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

#[cfg(feature = "mmu-large-memory")]
const HEAP_END: usize = 0x88000000;
#[cfg(not(feature = "mmu-large-memory"))]
const HEAP_END: usize = Board::MMU.ram.end;
