//! Optional elapsed-tick reporting to the firmware profiler.
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

#[derive(Clone, Copy)]
pub enum Phase {
    Prepare,
    OutputCopy,
    Scrub,
    Dma,
    Lock,
    Service,
}
type Observer = fn(Phase, u64);
static OBSERVER: AtomicPtr<Observer> = AtomicPtr::new(ptr::null_mut());

pub fn observe(observer: &'static Observer) {
    OBSERVER.store(ptr::from_ref(observer).cast_mut(), Ordering::Release);
}
pub(super) fn emit(phase: Phase, ticks: u64) {
    // observe only publishes immutable callbacks with static lifetime.
    if let Some(report) = unsafe { OBSERVER.load(Ordering::Acquire).as_ref() } {
        report(phase, ticks);
    }
}
pub(super) struct Span(Phase, u64);
impl Span {
    pub(super) fn start(phase: Phase) -> Self {
        Self(phase, crate::ticks())
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        emit(self.0, crate::ticks().wrapping_sub(self.1));
    }
}
