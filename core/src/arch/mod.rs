//! The thin seam between portable kernel logic and the machine.
//!
//! Bare-metal builds select an ISA runtime. Host-only deterministic models
//! remain available for portable tests, never for unsupported firmware ISAs.

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

#[cfg(not(target_os = "none"))]
mod host;
#[cfg(not(target_os = "none"))]
pub use host::*;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub(crate) use vibeos_runtime_aarch64::bare::cache_logical_hart_index;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use vibeos_runtime_aarch64::bare::{
    cached_logical_hart_index, clear_software_interrupt, counter as time,
    current_hart_id, enable_interrupts, fence_ipi, irq_restore, irq_save,
    reboot, send_ipi, set_timer, shutdown, wait_for_interrupt,
};
#[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
compile_error!("vibeos-core requires a real bare-metal architecture runtime");
