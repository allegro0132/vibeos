//! Fixed transport windows are discovered and accessed only by firmware.
use super::Board;
use vibeos_driver_virtio_mmio::MmioTransport;
use vibeos_hal::{
    device_transport::{Descriptor, Host, Kind},
    Board as _,
};
unsafe fn resolve(d: Descriptor) -> Option<MmioTransport> {
    MmioTransport::from_descriptor(Board::INFO.virtio_mmio?, d)
}
#[no_mangle]
pub static VIBEOS_DEVICE_TRANSPORT: Host = Host {
    discover: |kind| unsafe {
        let description = Board::INFO.virtio_mmio?;
        let transport = match kind {
            Kind::Block => MmioTransport::scan_block(description),
            Kind::Network => MmioTransport::scan_network(description),
            Kind::Entropy => MmioTransport::scan_entropy(description),
        }?;
        transport.descriptor()
    },
    status: |d| unsafe {
        resolve(d).map_or(
            vibeos_driver_virtio_core::STATUS_DEVICE_NEEDS_RESET,
            MmioTransport::status,
        )
    },
    reset: |d, budget| unsafe { resolve(d).is_some_and(|t| t.reset(budget)) },
    acknowledge: |d| unsafe { resolve(d).map_or(0, MmioTransport::acknowledge_interrupt) },
};
