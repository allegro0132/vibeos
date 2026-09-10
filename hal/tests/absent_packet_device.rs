#[path = "../../kernel/src/packet_device.rs"]
mod adapter;
use vibeos_hal::{network::*, AddressRange};
#[no_mangle]
static VIBEOS_PACKET_DEVICE: Device = Device {
    present: false,
    registers: AddressRange::new(0, 0),
    irq: 0,
    rx_queue_size: 0,
    dma_base: || panic!("absent DMA"),
    telemetry: || panic!("absent telemetry"),
    claim: |_, _, _| panic!("absent device claimed"),
    tx_owned: || panic!(),
    transmit: |_| panic!(),
    receive: |_| panic!(),
    poll_link: || panic!(),
    shutdown: || panic!(),
    recover: || panic!(),
};
#[test]
fn absent_slot_rejects_before_calling_hardware_operations() {
    assert!(matches!(
        unsafe { adapter::Engine::claim([0; 6], || 0, 1) },
        Err(Error::InvalidDescription)
    ));
}
