//! Runtime-owned receive queue; capability/session retirement policy only.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};
use vibeos_core::{heap::AllocationDomain, net_receive::ReceiveEndpoint};
static QUEUE: AtomicPtr<ReceiveEndpoint> = AtomicPtr::new(core::ptr::null_mut());
pub(crate) fn create(depth: usize) -> Arc<ReceiveEndpoint> {
    let operations = vibeos_hal::network::device().receive_buffers.as_ref()
        .expect("pooled RX requires firmware buffer operations");
    let queue = unsafe { ReceiveEndpoint::new("net-inbound", depth, operations) }.expect("bounded RX queue");
    let pointer = Arc::into_raw(queue.clone()) as *mut ReceiveEndpoint;
    if QUEUE.compare_exchange(core::ptr::null_mut(), pointer, Ordering::Release, Ordering::Relaxed).is_err() {
        unsafe { drop(Arc::from_raw(pointer)); }
        panic!("detached receive queue already installed");
    }
    queue
}
fn queue() -> Option<&'static ReceiveEndpoint> {
    unsafe { QUEUE.load(Ordering::Acquire).as_ref() }
}
pub(crate) fn retire_queued() { if let Some(queue) = queue() { queue.retire_queued(); } }
/// # Safety
/// All tasks in this exact allocation domain have been quiesced permanently.
pub(crate) unsafe fn recover(domain: AllocationDomain) {
    if let Some(queue) = queue() { unsafe { queue.recover(domain); } }
}
