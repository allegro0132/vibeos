//! Actual kernel adapter with synthetic firmware. DMA/PHY timing is not modeled.
#[path="../../kernel/src/packet_device.rs"] mod adapter;
use vibeos_hal::{network::*,AddressRange};
use std::sync::atomic::{AtomicUsize,Ordering::SeqCst};
static STAGE:AtomicUsize=AtomicUsize::new(0);
#[no_mangle]
static VIBEOS_PACKET_DEVICE:Device=Device{
    present:true,
    registers:AddressRange::new(0x1000,0x2000),irq:31,rx_queue_size:32,
    dma_base:||0x90000000,
    telemetry:||Telemetry{tx_checksum_offload:true,rx_checksum_offload:false,..Telemetry::default()},
    claim:|mac,time,hz|{assert_eq!(mac,[2,0,0,0,0,1]);assert_eq!((time(),hz),(7,25000000));STAGE.store(1,SeqCst);Ok(())},
    tx_owned:||STAGE.load(SeqCst)==2,
    transmit:|packet|{if packet.len()>1500{return Err(Error::PacketTooLarge);}assert_eq!(packet,&[1,2,3]);STAGE.store(2,SeqCst);Ok(())},
    receive:|output|{if output.len()<3{return None;}output[..3].copy_from_slice(&[3,2,1]);Some(3)},
    poll_link:||{STAGE.store(3,SeqCst);},
    shutdown:||{STAGE.store(4,SeqCst);true},recover:||true,
};
#[test]
fn packet_adapter_preserves_frames_errors_and_lifecycle() {
    let mut e=unsafe{adapter::Engine::claim([2,0,0,0,0,1],||7,25000000)}.unwrap();
    assert_eq!(e.irq(),31);assert!(e.tx_checksum_offload());assert!(!e.rx_checksum_offload());assert!(!e.tx_owned());
    assert_eq!(e.transmit(&[0;1501]),Err(Error::PacketTooLarge));
    e.transmit(&[1,2,3]).unwrap();assert!(e.tx_owned());
    let mut output=[0;8];assert_eq!(e.receive(&mut output),Some(3));assert_eq!(output,[3,2,1,0,0,0,0,0]);
    assert_eq!(e.receive(&mut [0;2]),None);
    e.poll_link();assert_eq!(STAGE.load(SeqCst),3);assert!(e.shutdown());assert_eq!(STAGE.load(SeqCst),4);
}
