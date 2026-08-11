//! Architecture-neutral contracts shared by runtime and board code.

/// Failure reported by an inter-processor or hart-management operation.
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

/// Lifecycle state of one hardware thread.
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
