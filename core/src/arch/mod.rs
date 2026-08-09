//! The thin seam between portable kernel logic and the machine.
//!
//! Everything below this line is riscv64 assembly; everything above it is
//! ordinary Rust. The point is not portability to other ISAs — it is that the
//! scheduler, the allocator, and the lock can be compiled and tested on the
//! host, where iteration takes milliseconds instead of a QEMU boot.

/// Failure reported by an SBI extension call.
///
/// The public name predates HSM support, but retaining the complete SBI error
/// namespace here lets the IPI and hart-state calls share one exact firmware
/// error type. Unexpected firmware responses remain observable instead of
/// being folded into success.
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

    #[cfg(not(target_arch = "riscv64"))]
    pub(crate) const fn as_sbi(self) -> isize {
        match self {
            Self::Failed => -1,
            Self::NotSupported => -2,
            Self::InvalidParam => -3,
            Self::Denied => -4,
            Self::InvalidAddress => -5,
            Self::AlreadyAvailable => -6,
            Self::AlreadyStarted => -7,
            Self::AlreadyStopped => -8,
            Self::NoSharedMemory => -9,
            Self::Unknown(other) => other,
        }
    }
}

/// State returned by the SBI Hart State Management extension.
///
/// HSM v0.2 defines states 0 through 6. `Unknown` preserves a newer or broken
/// firmware value for diagnostics rather than assigning it an existing
/// meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HartState {
    Started,
    Stopped,
    StartPending,
    StopPending,
    Suspended,
    SuspendPending,
    ResumePending,
    Unknown(usize),
}

impl HartState {
    pub(crate) const fn from_sbi(value: usize) -> Self {
        match value {
            0 => Self::Started,
            1 => Self::Stopped,
            2 => Self::StartPending,
            3 => Self::StopPending,
            4 => Self::Suspended,
            5 => Self::SuspendPending,
            6 => Self::ResumePending,
            other => Self::Unknown(other),
        }
    }

    #[cfg(not(target_arch = "riscv64"))]
    pub(crate) const fn as_sbi(self) -> usize {
        match self {
            Self::Started => 0,
            Self::Stopped => 1,
            Self::StartPending => 2,
            Self::StopPending => 3,
            Self::Suspended => 4,
            Self::SuspendPending => 5,
            Self::ResumePending => 6,
            Self::Unknown(other) => other,
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
