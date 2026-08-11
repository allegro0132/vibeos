//! Bare-metal RISC-V runtime seam for VibeOS.

#![no_std]

pub use vibeos_hal::arch::{HartState, IpiError};

#[cfg(any(test, all(target_arch = "riscv64", target_os = "none")))]
mod mapping;

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
mod bare;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use bare::*;
