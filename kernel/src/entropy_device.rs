//! Exclusive invocation token for firmware-owned entropy hardware.
use vibeos_hal::device_transport::{Descriptor, Kind};
use vibeos_hal::entropy::{device, Error, Events, Submission};
/// Immutable identity supplied by the firmware's entropy provider. No register
/// access or dependency on the shared block/network transport registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint(Descriptor);
impl Endpoint {
    /// # Safety
    /// Firmware resources are mapped; this is boot-time admission before claims.
    pub unsafe fn discover() -> Option<Self> {
        (device().discover)().filter(|d| d.kind == Kind::Entropy).map(Self)
    }
    pub const fn slot(self) -> usize { self.0.slot }
    pub const fn base(self) -> usize { self.0.base }
    pub const fn irq(self) -> u32 { self.0.irq }
    pub const fn vendor_id(self) -> u32 { self.0.vendor_id }
    /// Does not clear instance state or authorize reuse after uncertain ownership.
    pub fn quiesce(self, budget: usize) -> bool {
        unsafe { (device().quiesce)(self.0, budget) }
    }
    pub fn acknowledge_interrupt(self) -> Events {
        unsafe { (device().acknowledge)(self.base()) }
    }
}
pub struct Engine(());
impl Engine {
    /// # Safety
    /// Caller holds the exact device/backing-state claim and excludes every old engine.
    pub unsafe fn prepare(t: Endpoint, epoch: u64, budget: usize) -> Result<Self, Error> {
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
pub unsafe fn confirmed_reset(t: Endpoint, budget: usize) -> bool {
    (device().confirmed_reset)(t.slot(), t.base(), budget)
}
pub unsafe fn acknowledge_interrupt_at(base: usize) -> Events {
    (device().acknowledge)(base)
}
pub fn backing() -> vibeos_hal::entropy::Backing {
    device().backing
}
