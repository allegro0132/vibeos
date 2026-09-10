//! Firmware-owned queued packet controller; kernel retains packet-session policy.
use crate::MAX_PACKET_LEN;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Offline,
    QueueFull,
    TimedOut,
    Protocol,
    Quarantined,
    IdentityExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetReason {
    Device,
    Protocol,
    Timeout,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedFrame {
    bytes: [u8; MAX_PACKET_LEN],
    len: u16,
}

impl ReceivedFrame {
    pub fn new(bytes: [u8; MAX_PACKET_LEN], len: u16) -> Option<Self> {
        if len == 0 || usize::from(len) > MAX_PACKET_LEN {
            None
        } else {
            Some(Self { bytes, len })
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub accepted_features: u64,
    pub epoch: u64,
    pub rx_inflight: u8,
    pub tx_inflight: u8,
    pub quarantined: bool,
}

/// # Safety
/// Engine mutations require an exclusive incarnation. Shared queries must
/// not race mutation. IRQ acknowledgement and quarantine-before-attach do not
/// borrow mutable instance state. No caller buffer may be retained by DMA.
/// Recovery requires the old owner cannot run or execute its destructor.
pub struct Device {
    pub dma_base: fn() -> usize,
    pub dma_size: usize,
    pub dma_quarantined: fn() -> bool,
    pub attach: unsafe fn(usize, usize, u64) -> Result<(), Error>,
    pub info: unsafe fn() -> Info,
    pub start: unsafe fn() -> Result<(), Error>,
    pub service_events: unsafe fn(u32) -> Result<bool, Error>,
    pub drain_tx: unsafe fn() -> Result<u8, Error>,
    pub receive: unsafe fn() -> Result<Option<ReceivedFrame>, Error>,
    pub transmit: unsafe fn(&[u8], u64) -> Result<(), Error>,
    pub check_timeout: unsafe fn(u64) -> Result<bool, Error>,
    pub reset: unsafe fn(ResetReason) -> Result<u64, Error>,
    pub shutdown: unsafe fn(ResetReason) -> bool,
    pub force_quarantine: unsafe fn(),
    pub quarantine_before_attach: unsafe fn(usize, usize),
    pub recover: unsafe fn(usize, usize) -> bool,
    pub acknowledge: unsafe fn(usize) -> u32,
}
extern "Rust" {
    static VIBEOS_QUEUED_PACKET_DEVICE: Device;
}
pub fn device() -> &'static Device {
    unsafe { &VIBEOS_QUEUED_PACKET_DEVICE }
}
