//! Real kernel adapter against synthetic firmware; QEMU validates real rings.
mod virtio_mmio {
    #[derive(Clone,Copy)]pub struct MmioTransport;
    impl MmioTransport{pub fn slot(self)->usize{1}pub fn base(self)->usize{0x10001000}}
}
#[path="../../kernel/src/queued_network.rs"]mod adapter;
use vibeos_hal::queued_network::*;
use std::sync::atomic::{AtomicU64,AtomicUsize,AtomicBool,Ordering::SeqCst};
static EPOCH:AtomicU64=AtomicU64::new(0);
static ACTIVE:AtomicBool=AtomicBool::new(false);
static SHUTDOWNS:AtomicUsize=AtomicUsize::new(0);
#[no_mangle]
static VIBEOS_QUEUED_PACKET_DEVICE:Device=Device{
    dma_base:||0x90000000,dma_size:8192,dma_quarantined:||false,
    attach:|slot,base,epoch|{assert_eq!((slot,base),(1,0x10001000));assert!(!ACTIVE.swap(true,SeqCst));EPOCH.store(epoch,SeqCst);Ok(())},
    info:||Info{accepted_features:1,epoch:EPOCH.load(SeqCst),rx_inflight:8,tx_inflight:0,quarantined:false},
    start:||Ok(()),service_events:|causes|{assert_eq!(causes,3);Ok(true)},drain_tx:||Ok(2),
    receive:||{let mut bytes=[0;vibeos_hal::MAX_PACKET_LEN];bytes[..3].copy_from_slice(&[4,5,6]);Ok(ReceivedFrame::new(bytes,3))},
    transmit:|frame,deadline|{assert_eq!(frame,&[1,2,3]);if deadline==0{Err(Error::TimedOut)}else{Ok(())}},
    check_timeout:|now|Ok(now>10),reset:|reason|{assert_eq!(reason,ResetReason::Timeout);Ok(EPOCH.fetch_add(1,SeqCst)+1)},
    shutdown:|_|{SHUTDOWNS.fetch_add(1,SeqCst);ACTIVE.store(false,SeqCst);true},
    force_quarantine:||{ACTIVE.store(false,SeqCst);},quarantine_before_attach:|slot,base|{assert_eq!((slot,base),(1,0x10001000));},
    recover:|slot,base|{assert_eq!((slot,base),(1,0x10001000));true},acknowledge:|base|{assert_eq!(base,0x10001000);3},
};
#[test]
fn released_engine_cannot_reset_a_replacement_and_dispatch_preserves_frames() {
    let t=virtio_mmio::MmioTransport;
    let mut old=adapter::Engine::attach(t,1).unwrap();old.start().unwrap();
    assert_eq!(old.transport().base(),t.base());assert_eq!(old.info().epoch,1);
    assert_eq!(old.service_device_events(3),Ok(true));assert_eq!(old.drain_transmit_completions(),Ok(2));
    assert_eq!(old.receive().unwrap().unwrap().as_bytes(),&[4,5,6]);
    old.submit_transmit(&[1,2,3],10).unwrap();assert_eq!(old.submit_transmit(&[1,2,3],0),Err(Error::TimedOut));
    assert_eq!(old.check_timeout(11),Ok(true));assert_eq!(old.reset_and_reinitialize(ResetReason::Timeout),Ok(2));
    assert!(old.shutdown(ResetReason::Cancelled));assert_eq!(SHUTDOWNS.load(SeqCst),1);
    let replacement=adapter::Engine::attach(t,3).unwrap();
    assert!(old.shutdown(ResetReason::Cancelled));old.force_quarantine();drop(old);
    assert!(ACTIVE.load(SeqCst));assert_eq!(replacement.info().epoch,3);assert_eq!(SHUTDOWNS.load(SeqCst),1);
    drop(replacement);assert!(!ACTIVE.load(SeqCst));assert_eq!(SHUTDOWNS.load(SeqCst),2);
    assert_eq!((adapter::dma_base(),adapter::dma_size(),adapter::dma_quarantined()),(0x90000000,8192,false));
    adapter::quarantine_before_attach(t);assert!(unsafe{adapter::recover_faulted_transport(t)});assert_eq!(unsafe{adapter::acknowledge_irq_at_base(t.base())},3);
}
#[test]
fn received_frame_is_bounded_before_exposing_bytes() {
    assert!(ReceivedFrame::new([0;vibeos_hal::MAX_PACKET_LEN],0).is_none());
    assert!(ReceivedFrame::new([0;vibeos_hal::MAX_PACKET_LEN],(vibeos_hal::MAX_PACKET_LEN+1)as u16).is_none());
    let frame=ReceivedFrame::new([7;vibeos_hal::MAX_PACKET_LEN],vibeos_hal::MAX_PACKET_LEN as u16).unwrap();
    assert_eq!(frame.as_bytes(),&[7;vibeos_hal::MAX_PACKET_LEN]);
}
