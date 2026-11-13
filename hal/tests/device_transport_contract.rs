//! Actual kernel token with firmware callbacks. No hardware or DMA is modeled.
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use vibeos_hal::device_transport::*;
#[path = "../../kernel/src/virtio_mmio.rs"]
mod adapter;
static RESETS: AtomicUsize = AtomicUsize::new(0);
fn descriptor(kind: Kind) -> Descriptor {
    Descriptor {
        kind,
        slot: 3,
        base: 0xdead_0000,
        irq: 9,
        vendor_id: 0x1234,
    }
}
#[no_mangle]
static VIBEOS_DEVICE_TRANSPORT: Host = Host {
    discover: |kind| Some(descriptor(kind)),
    status: |d| {
        assert_eq!(d, descriptor(Kind::Block));
        64
    },
    reset: |d, budget| {
        assert_eq!(d, descriptor(Kind::Entropy));
        RESETS.fetch_add(1, SeqCst);
        budget > 0
    },
    acknowledge: |d| {
        assert_eq!(d, descriptor(Kind::Network));
        3
    },
};
#[test]
fn kernel_token_dispatches_discovery_and_lifecycle_without_mmio() {
    let block = unsafe { adapter::MmioTransport::scan_block() }.unwrap();
    let net = unsafe { adapter::MmioTransport::scan_network() }.unwrap();
    let rng = unsafe { adapter::MmioTransport::scan_entropy() }.unwrap();
    assert_eq!(
        (block.base(), block.slot(), block.irq(), block.vendor_id()),
        (0xdead_0000, 3, 9, 0x1234)
    );
    assert_eq!(block.status(), 64);
    assert_eq!(net.acknowledge_interrupt(), 3);
    assert!(!rng.reset(0));
    assert!(rng.reset(1));
    assert_eq!(RESETS.load(SeqCst), 2);
}
