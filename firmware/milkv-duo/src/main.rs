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
