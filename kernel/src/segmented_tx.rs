//! Runtime-owned direct transmit queue; policy-only access for retirement.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};
use vibeos_core::{heap::AllocationDomain, net_transmit::TransmitEndpoint};
static QUEUE: AtomicPtr<TransmitEndpoint> = AtomicPtr::new(core::ptr::null_mut());
pub(crate) fn create(depth: usize) -> Arc<TransmitEndpoint> {
    let queue = TransmitEndpoint::new("net-outbound", depth, 8).expect("bounded transmit pool");
    let pointer = Arc::into_raw(queue.clone()) as *mut TransmitEndpoint;
    if QUEUE.compare_exchange(core::ptr::null_mut(), pointer, Ordering::Release, Ordering::Relaxed).is_err() {
        unsafe { drop(Arc::from_raw(pointer)); }
        panic!("direct transmit queue already installed");
    }
    queue
}
fn queue() -> Option<&'static TransmitEndpoint> {
    let pointer = QUEUE.load(Ordering::Acquire);
    // The runtime owns the published Arc for the firmware lifetime.
    unsafe { pointer.as_ref() }
}
pub(crate) fn retire(domain: AllocationDomain) {
    if let Some(queue) = queue() { queue.pool().invalidate_domain(domain); }
}
pub(crate) fn retire_all() {
    if let Some(queue) = queue() { queue.pool().invalidate_all(); }
}
/// # Safety
/// The executor has quiesced all tasks in the faulted allocation domain.
pub(crate) unsafe fn recover(domain: AllocationDomain) {
    if let Some(queue) = queue() { unsafe { queue.recover_faulted_domain(domain); } }
}
