//! The thin seam between portable kernel logic and the machine.
//!
//! Everything below this line is riscv64 assembly; everything above it is
//! ordinary Rust. The point is not portability to other ISAs — it is that the
//! scheduler, the allocator, and the lock can be compiled and tested on the
//! host, where iteration takes milliseconds instead of a QEMU boot.

pub use vibeos_hal::arch::{HartState, IpiError};

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) use vibeos_runtime_riscv::cache_logical_hart_index;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use vibeos_runtime_riscv::{
    cached_logical_hart_index, clear_mxr, clear_software_interrupt, current_hart_id,
    enable_interrupts, fence_ipi, hart_start, hart_status, irq_restore, irq_save, legacy_putchar,
    local_fence_i, local_sfence_vma, mxr_enabled, probe_extension, reboot, remote_fence_i,
    remote_sfence_vma, send_ipi, set_timer, shutdown, time, wait_for_interrupt,
    RFENCE_EXTENSION_ID,
};

#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
mod host;
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
pub use host::*;
