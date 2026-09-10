//! Firmware-owned queued block device. Kernel scheduling/capability policy is
//! separate from driver DMA publication, completion validation and reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AlreadyClaimed,
    QueueFull,
    ReadOnly,
    FlushUnsupported,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    RestartRequired,
}
#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub read_only: bool,
    pub supports_flush: bool,
    pub epoch: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Read { sector: u64, blocks: u32 },
    Write { sector: u64, blocks: u32 },
    Flush,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub epoch: u64,
    pub serial: u64,
    pub previous_used: u16,
}
impl Submission {
    pub fn previous_used_index(self) -> u16 {
        self.previous_used
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Completion {
    pub id: u32,
    pub length: u32,
}
/// # Safety
/// Mutation requires exclusive ownership; shared queries must not race it.
/// The IRQ acknowledgement callback must not borrow mutable engine state.
/// Driver buffers remain allocated while DMA is possible, including after a
/// failed reset. Submit copies input and never retains caller pointers. Its
/// callback runs at the publication boundary before hardware can mutate media.
/// Finish validates completion before copying into the caller's output.
pub struct Device {
    pub dma_base: fn() -> usize,
    pub dma_bytes: usize,
    pub attach: unsafe fn(usize, usize, u64) -> Result<(), Error>,
    pub info: unsafe fn() -> Info,
    pub mark_ready: unsafe fn(),
    pub needs_reset: unsafe fn() -> bool,
    pub refresh_capacity: unsafe fn() -> Result<u64, Error>,
    pub require_reset: unsafe fn(),
    pub submit: unsafe fn(Operation, &[u8], &mut dyn FnMut()) -> Result<Submission, Error>,
    pub notify: unsafe fn(),
    pub used_index: unsafe fn() -> u16,
    pub used_element: unsafe fn(u16) -> Completion,
    pub complete: unsafe fn(Submission, u16, Completion, &mut [u8]) -> Result<(), Error>,
    pub timeout: unsafe fn(Submission) -> Result<(), Error>,
    pub reset: unsafe fn() -> Result<(), Error>,
    pub shutdown: unsafe fn() -> Result<(), Error>,
    pub recover: unsafe fn(usize, usize) -> Result<(), Error>,
    pub acknowledge: unsafe fn(usize) -> u32,
}
extern "Rust" {
    static VIBEOS_QUEUED_BLOCK_DEVICE: Device;
}
pub fn device() -> &'static Device {
    unsafe { &VIBEOS_QUEUED_BLOCK_DEVICE }
}
