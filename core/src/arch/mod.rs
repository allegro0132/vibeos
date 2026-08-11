//! The thin seam between portable kernel logic and the machine.
//!
//! Everything below this line is riscv64 assembly; everything above it is
//! ordinary Rust. The point is not portability to other ISAs — it is that the
//! scheduler, the allocator, and the lock can be compiled and tested on the
//! host, where iteration takes milliseconds instead of a QEMU boot.

pub use vibeos_hal::arch::{HartState, IpiError};

#[cfg(target_arch = "riscv64")]
mod riscv;
#[cfg(target_arch = "riscv64")]
pub use riscv::*;

#[cfg(not(target_arch = "riscv64"))]
mod host;
#[cfg(not(target_arch = "riscv64"))]
pub use host::*;
