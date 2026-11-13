//! Resource token for firmware-owned transport operations; no MMIO here.
use vibeos_hal::device_transport::{host, Descriptor, Kind};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmioTransport(Descriptor);
impl MmioTransport {
    pub unsafe fn scan_block() -> Option<Self> {
        (host().discover)(Kind::Block).map(Self)
    }
    pub unsafe fn scan_network() -> Option<Self> {
        (host().discover)(Kind::Network).map(Self)
    }
    pub unsafe fn scan_entropy() -> Option<Self> {
        (host().discover)(Kind::Entropy).map(Self)
    }
    pub const fn slot(self) -> usize {
        self.0.slot
    }
    pub const fn base(self) -> usize {
        self.0.base
    }
    pub const fn irq(self) -> u32 {
        self.0.irq
    }
    pub const fn vendor_id(self) -> u32 {
        self.0.vendor_id
    }
    pub fn status(self) -> u32 {
        unsafe { (host().status)(self.0) }
    }
    pub fn reset(self, budget: usize) -> bool {
        unsafe { (host().reset)(self.0, budget) }
    }
    pub fn acknowledge_interrupt(self) -> u32 {
        unsafe { (host().acknowledge)(self.0) }
    }
}
