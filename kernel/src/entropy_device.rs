//! Exclusive invocation token for firmware-owned entropy hardware.
use crate::virtio_mmio::MmioTransport;
use vibeos_hal::entropy::{device, Error, Events, Submission};
pub struct Engine(());
impl Engine {
    /// # Safety
    /// Caller holds the exact device/DMA claim and excludes every old engine.
    pub unsafe fn prepare(t: MmioTransport, epoch: u64, budget: usize) -> Result<Self, Error> {
        (device().prepare)(t.slot(), t.base(), epoch, budget)?;
        Ok(Self(()))
    }
    pub fn start(&self) -> Result<(), Error> {
        unsafe { (device().start)() }
    }
    pub fn epoch(&self) -> u64 {
        unsafe { (device().epoch)() }
    }
    pub fn accepted_features(&self) -> u64 {
        unsafe { (device().accepted_features)() }
    }
    pub fn operational(&self) -> bool {
        unsafe { (device().operational)() }
    }
    pub fn submit(&mut self, bytes: usize) -> Result<Submission, Error> {
        unsafe { (device().submit)(bytes) }
    }
    pub fn completion(&self, token: Submission) -> Option<()> {
        unsafe { (device().completion)(token).then_some(()) }
    }
    pub fn finish(&mut self, token: Submission, out: &mut [u8]) -> Result<usize, Error> {
        unsafe { (device().finish)(token, out) }
    }
    pub fn require_reset(&mut self) {
        unsafe { (device().require_reset)() }
    }
    pub fn reset_and_prepare(&mut self, epoch: u64, budget: usize) -> Result<(), Error> {
        unsafe { (device().reset_and_prepare)(epoch, budget) }
    }
    pub fn shutdown(&mut self, budget: usize) -> Result<(), Error> {
        unsafe { (device().shutdown)(budget) }
    }
}
pub unsafe fn confirmed_reset(t: MmioTransport, budget: usize) -> bool {
    (device().confirmed_reset)(t.slot(), t.base(), budget)
}
pub unsafe fn acknowledge_interrupt_at(base: usize) -> Events {
    (device().acknowledge)(base)
}
pub fn dma_base() -> usize {
    (device().dma_base)()
}
pub fn dma_bytes() -> usize {
    device().dma_bytes
}
