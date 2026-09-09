//! Per-invocation floating-point and privileged state at every fiber boundary.
use alloc::boxed::Box;
use core::{arch::asm, future::Future, pin::Pin, task::{Context, Poll}};
/// Own the future so its cancellation destructor runs under the same context
/// guard as polling. The fiber ABI saves FP registers but not the FCSR.
pub(crate) struct NativeFuture<F: Future> {
    future: Option<Pin<Box<F>>>,
    fcsr: usize,
}
impl<F: Future> NativeFuture<F> {
    pub(crate) fn new(future: F) -> Self {
        Self { future: Some(Box::pin(future)), fcsr: 0 }
    }
}
pub(super) fn fcsr() -> usize {
    let value: usize;
    unsafe { asm!("frcsr {}", out(reg) value, options(nomem, nostack)); }
    value
}
pub(super) fn set_fcsr(value: usize) {
    unsafe { asm!("fscsr {}", in(reg) value, options(nostack)); }
}
impl<F: Future> Future for NativeFuture<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let _state = super::native_traps::CallState::enter();
        set_fcsr(this.fcsr);
        let result = this.future.as_mut().unwrap().as_mut().poll(cx);
        this.fcsr = fcsr();
        result
    }
}
impl<F: Future> Drop for NativeFuture<F> {
    fn drop(&mut self) {
        let _state = super::native_traps::CallState::enter();
        set_fcsr(self.fcsr);
        drop(self.future.take());
    }
}
