//! Actual kernel adapter against synthetic firmware. This checks marshaling;
//! QEMU block and block_recovery transcripts exercise real DMA and teardown.
mod virtio { pub use vibeos_driver_virtio_core::{BlockOperation, UsedElement}; }
mod virtio_mmio {
    #[derive(Clone, Copy)] pub struct MmioTransport;
    impl MmioTransport { pub fn slot(self)->usize{2} pub fn base(self)->usize{0x10002000} }
}
#[path="../../kernel/src/queued_block.rs"] mod adapter;
use vibeos_hal::queued_block::*;
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering::SeqCst};
static RESET:AtomicBool=AtomicBool::new(false);
static NOTIFY:AtomicUsize=AtomicUsize::new(0);
fn token()->Submission{Submission{epoch:7,serial:3,previous_used:9}}
#[no_mangle]
static VIBEOS_QUEUED_BLOCK_DEVICE:Device=Device{
    dma_base:||0x90000000,dma_bytes:4096,
    attach:|slot,base,epoch|{assert_eq!((slot,base,epoch),(2,0x10002000,7));Ok(())},
    info:||Info{capacity_sectors:1024,queue_size:8,read_only:false,supports_flush:true,epoch:7},
    mark_ready:||{},needs_reset:||RESET.load(SeqCst),refresh_capacity:||Ok(2048),require_reset:||{RESET.store(true,SeqCst);},
    submit:|operation,data,published|{
        match operation {
            Operation::Read{sector,blocks}=>{assert_eq!((sector,blocks),(5,2));assert!(data.is_empty());},
            Operation::Write{sector,blocks}=>{assert_eq!((sector,blocks),(8,1));assert_eq!(data,&[42;512]);},
            Operation::Flush=>{assert!(data.is_empty());},
        }
        published();published();Ok(token())
    },
    notify:||{NOTIFY.fetch_add(1,SeqCst);},used_index:||10,
    used_element:|previous|{assert_eq!(previous,9);Completion{id:4,length:1025}},
    complete:|submitted,index,used,out|{assert_eq!(submitted,token());assert_eq!((index,used.id,used.length),(10,4,1025));out.fill(17);Ok(())},
    timeout:|submitted|{assert_eq!(submitted,token());RESET.store(true,SeqCst);Ok(())},
    reset:||{RESET.store(false,SeqCst);Ok(())},shutdown:||{RESET.store(true,SeqCst);Ok(())},
    recover:|slot,base|{assert_eq!((slot,base),(2,0x10002000));RESET.store(false,SeqCst);Ok(())},
    acknowledge:|base|{assert_eq!(base,0x10002000);3},
};
#[test]
fn dispatch_preserves_operations_completion_and_reset() {
    use virtio::BlockOperation;
    let t=virtio_mmio::MmioTransport;
    let mut engine=adapter::BlockEngine::attach(t,7).unwrap();
    assert_eq!(engine.transport().base(),0x10002000);
    assert_eq!((engine.info().capacity_sectors,engine.info().epoch),(1024,7));
    engine.mark_ready();assert!(!engine.device_needs_reset());
    let mut publishes=0;
    let submission=engine.submit_tracked(BlockOperation::ReadBlocks{sector:5,block_count:2},&[],||publishes+=1).unwrap();
    assert_eq!(publishes,1);assert_eq!(submission.previous_used_index(),9);
    engine.notify();assert_eq!(NOTIFY.load(SeqCst),1);
    let used=engine.used_element(submission.previous_used_index());
    let mut out=[0;1024];engine.complete(submission,engine.used_index(),used,&mut out).unwrap();assert_eq!(out,[17;1024]);
    engine.submit_tracked(BlockOperation::Write{sector:8},&[42;512],||publishes+=1).unwrap();
    engine.submit_tracked(BlockOperation::Flush,&[],||publishes+=1).unwrap();assert_eq!(publishes,3);
    engine.timeout(submission).unwrap();assert!(engine.device_needs_reset());
    engine.reset_and_reinitialize().unwrap();assert!(!engine.device_needs_reset());
    engine.require_device_reset();assert!(engine.device_needs_reset());
    assert_eq!(engine.refresh_capacity(),Ok(2048));
    engine.shutdown().unwrap();unsafe{adapter::recover_after_fault(t)}.unwrap();assert!(!RESET.load(SeqCst));
    assert_eq!(unsafe{adapter::acknowledge_interrupt_at(t.base())},3);
    assert_eq!((adapter::dma_base(),adapter::dma_bytes()),(0x90000000,4096));
}
