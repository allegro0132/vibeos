//! One-shot diagnostic mailbox; only the existing exclusive driver executes it.
use core::sync::atomic::{AtomicUsize,Ordering};
use crate::sync::SpinLock;
#[derive(Clone,Copy)]
pub struct Request {pub src_mac:[u8;6],pub dst_mac:[u8;6],pub src_ip:[u8;4],pub dst_ip:[u8;4],pub payload:usize,pub mss:usize}
static STATE:AtomicUsize=AtomicUsize::new(0);
static REQUEST:SpinLock<Option<Request>>=SpinLock::new(None);
pub fn start(r:Request)->bool{
    if !(1..=32714).contains(&r.payload)||!(64..=1460).contains(&r.mss)
        ||r.src_mac[0]&1!=0||r.dst_mac[0]&1!=0{return false;}
    if STATE.compare_exchange(0,5,Ordering::AcqRel,Ordering::Acquire).is_err(){return false;}
    *REQUEST.lock()=Some(r);STATE.store(1,Ordering::Release);true
}
pub fn state()->usize{STATE.load(Ordering::Acquire)}
pub fn take()->Option<Request>{
    if state()!=1{return None;}let r=REQUEST.lock().take();STATE.store(2,Ordering::Release);r
}
pub fn submitted(){let _=STATE.compare_exchange(2,6,Ordering::AcqRel,Ordering::Acquire);}
pub fn finish(ok:bool){
    if ok {let _=STATE.compare_exchange(6,3,Ordering::AcqRel,Ordering::Acquire);}
    else {invalidate();}
}
/// A new driver incarnation cannot prove an old descriptor group completed.
pub fn invalidate(){
    loop {
        let state=STATE.load(Ordering::Acquire);
        if state!=2 && state!=6{return;}
        if STATE.compare_exchange(state,4,Ordering::AcqRel,Ordering::Acquire).is_ok(){return;}
    }
}
