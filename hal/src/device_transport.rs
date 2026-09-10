//! Firmware-owned discovery and lifecycle operations for fixed device windows.
//! Descriptors carry identity and resource metadata, never register access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Block,
    Network,
    Entropy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub kind: Kind,
    pub slot: usize,
    pub base: usize,
    pub irq: u32,
    pub vendor_id: u32,
}
/// # Safety
/// Firmware validates descriptors against its assigned resources before access.
/// Callers serialize reset against every engine operation and must retain DMA
/// quarantine until reset succeeds. Status/acknowledgement use only immutable
/// device resources, so IRQ acknowledgement cannot alias mutable engine state.
/// Discovery runs only after firmware device windows have been mapped.
pub struct Host {
    pub discover: unsafe fn(Kind) -> Option<Descriptor>,
    pub status: unsafe fn(Descriptor) -> u32,
    pub reset: unsafe fn(Descriptor, usize) -> bool,
    pub acknowledge: unsafe fn(Descriptor) -> u32,
}
extern "Rust" {
    static VIBEOS_DEVICE_TRANSPORT: Host;
}
pub fn host() -> &'static Host {
    unsafe { &VIBEOS_DEVICE_TRANSPORT }
}
