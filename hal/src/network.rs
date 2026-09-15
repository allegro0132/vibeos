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
/// Optional logical TCP transmit operation. Success admits the whole request;
/// QueueFull admits none. Caller bytes cannot be retained after return. The
/// backend owns all submitted DMA storage through final group completion.
pub struct Segmentation {
    pub max_packet_bytes: usize,
    pub min_mss: usize,
    pub transmit: unsafe fn(crate::tcp_segmentation::TcpSegments<'_>) -> Result<(),Error>,
}
/// Optional RX-only interrupt scheduling. Static MMIO operations never borrow
/// the mutable engine and remain valid through unregister/recovery. The adapter
/// serializes arm/mask against its ISR on the dispatch hart. `pending` instead
/// requires exclusive engine invocation and checks synchronized descriptor OWN.
pub struct RxInterrupts {
    pub mask: unsafe fn(),
    /// Mask and acknowledge RX causes; false reports a fatal controller fault.
    pub acknowledge: unsafe fn() -> bool,
    pub arm: unsafe fn() -> bool,
    pub pending: unsafe fn() -> bool,
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
    pub segmentation: Option<Segmentation>,
    pub rx_interrupts: Option<RxInterrupts>,
    pub receive_buffers: Option<crate::network_rx::Operations>,
    pub receive: unsafe fn(&mut [u8]) -> Option<usize>,
    pub poll_link: unsafe fn(),
    pub shutdown: unsafe fn() -> bool,
    pub recover: unsafe fn() -> bool,
}
#[cfg(not(feature = "runtime-platform"))]
extern "Rust" {
    static VIBEOS_PACKET_DEVICE: Device;
}
#[cfg(not(feature = "runtime-platform"))]
pub fn device() -> &'static Device {
    unsafe { &VIBEOS_PACKET_DEVICE }
}
#[cfg(feature = "runtime-platform")]
pub fn device() -> &'static Device {
    crate::runtime_platform::get().packet.expect("firmware did not admit packet")
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
