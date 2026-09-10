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
