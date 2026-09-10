#![no_std]
#![no_main]
//! Composition acceptance image: real QEMU devices, no kernel board profile.
//! Reuse the production firmware providers rather than mock hardware tables.
use core::arch::global_asm;
global_asm!(".section .text.boot\n.option norvc\n.global _start\n_start:\nj vibeos_kernel_start");
extern crate vibeos_kernel;
use vibeos_bsp_qemu_virt::Board;
use vibeos_hal::Board as BoardContract;
#[path = "../../early_devices.rs"]
mod early_devices;
#[path = "../../qemu-virt/src/storage.rs"]
mod storage;
#[path = "../../qemu-virt/src/network.rs"]
mod network;
#[path = "../../qemu-virt/src/transport.rs"]
mod transport;
unsafe fn platform_init(_write: fn(&str)) {}
#[cfg(feature = "jh7110-sd-model-test")]
mod jh7110_sd_model;
unsafe fn platform_report(_print: fn(core::fmt::Arguments<'_>)) {
    #[cfg(feature = "jh7110-sd-model-test")]
    {
        jh7110_sd_model::run();
        _print(format_args!("JH7110_SD_MODEL PASS source_hz=49500000 timeout_cleanup=ok\n"));
    }
}
const MANAGED_BLOCK_ID: core::num::NonZeroU128 =
    core::num::NonZeroU128::new(0x5649_4245_4f53_0000_0000_0000_0000_0001).unwrap();
const NETWORK_DRIVER_NAME: &str = "virtio-mmio";
