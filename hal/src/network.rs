//! Firmware-owned packet device. Kernel packet queues, capability admission,
//! stack generations, link policy and recovery scheduling remain independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidDescription,
    TimedOut,
    QueueFull,
    PacketTooLarge,
    AddressTooWide,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Telemetry {
    pub phy_link_up: bool,
    /// Optional controller/platform diagnostic words retained for legacy tools.
    pub tx_descriptor_status: u32,
    pub dma_status: u32,
    pub clock_enable: u32,
    pub clock_bypass: u32,
    pub clock_divider: u32,
    pub ephy_control: u32,
    pub resets: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub tx_checksum_offload: bool,
    pub rx_checksum_offload: bool,
}
/// # Safety
/// Claim requires live authority over the device and its fixed DMA pool.
/// Engine operations are serialized by the consumer. Telemetry must be safe
/// concurrently with them and may not borrow mutable engine state. Transmit
/// copies data into owned storage; receive validates and copies one frame.
/// No caller slice is retained or published to DMA. A failed shutdown keeps
/// the pool quarantined; fault recovery requires the old owner cannot resume.
pub struct Device {
    /// False means no hardware instance is composed; discovery must not mint
    /// MMIO/DMA/device capabilities for this slot.
    pub present: bool,
    pub registers: crate::AddressRange,
    pub irq: u32,
    pub rx_queue_size: usize,
    pub dma_base: fn() -> usize,
    pub telemetry: unsafe fn() -> Telemetry,
    pub claim: unsafe fn([u8; 6], fn() -> u64, u64) -> Result<(), Error>,
    pub tx_owned: unsafe fn() -> bool,
    pub transmit: unsafe fn(&[u8]) -> Result<(), Error>,
    pub receive: unsafe fn(&mut [u8]) -> Option<usize>,
    pub poll_link: unsafe fn(),
    pub shutdown: unsafe fn() -> bool,
    pub recover: unsafe fn() -> bool,
}
extern "Rust" {
    static VIBEOS_PACKET_DEVICE: Device;
}
pub fn device() -> &'static Device {
    unsafe { &VIBEOS_PACKET_DEVICE }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlatformTelemetry {
    pub clock_enable: u32,
    pub clock_bypass: u32,
    pub clock_divider: u32,
    pub ephy_control: u32,
}
/// # Safety
/// Firmware binds exclusively assigned clock/PHY resources; initialization is
/// serialized with the controller. Diagnostics must not borrow mutable state.
/// DMA synchronization must cover every cache level on the selected platform.
pub struct Platform {
    pub prepare: unsafe fn(fn() -> u64, u64) -> Result<(), Error>,
    pub telemetry: unsafe fn() -> PlatformTelemetry,
    pub dma: &'static crate::memory::DmaOps,
}
