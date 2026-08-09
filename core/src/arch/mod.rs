//! The thin seam between portable kernel logic and the machine.
//!
//! Everything below this line is riscv64 assembly; everything above it is
//! ordinary Rust. The point is not portability to other ISAs — it is that the
//! scheduler, the allocator, and the lock can be compiled and tested on the
//! host, where iteration takes milliseconds instead of a QEMU boot.

/// Failure reported by the SBI IPI extension.
///
/// The standardized IPI call currently specifies `FAILED` and
/// `INVALID_PARAM`; retaining the complete SBI error namespace here keeps an
/// unexpected firmware response observable instead of folding it into
/// success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiError {
    Failed,
    NotSupported,
    InvalidParam,
    Denied,
    InvalidAddress,
    AlreadyAvailable,
    AlreadyStarted,
    AlreadyStopped,
    NoSharedMemory,
    Unknown(isize),
}

#[cfg(target_arch = "riscv64")]
impl IpiError {
    pub(crate) const fn from_sbi(error: isize) -> Self {
        match error {
            -1 => Self::Failed,
            -2 => Self::NotSupported,
            -3 => Self::InvalidParam,
            -4 => Self::Denied,
            -5 => Self::InvalidAddress,
            -6 => Self::AlreadyAvailable,
            -7 => Self::AlreadyStarted,
            -8 => Self::AlreadyStopped,
            -9 => Self::NoSharedMemory,
            other => Self::Unknown(other),
        }
    }
}

#[cfg(target_arch = "riscv64")]
mod riscv;
#[cfg(target_arch = "riscv64")]
pub use riscv::*;

#[cfg(not(target_arch = "riscv64"))]
mod host;
#[cfg(not(target_arch = "riscv64"))]
pub use host::*;
