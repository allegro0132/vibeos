#![no_std]

//! Hardware description types shared by the kernel and board support crates.
//!
//! This crate contains data contracts, not device implementations. A board
//! support crate describes address ranges and device wiring through [`Board`];
//! drivers consume the smaller device-specific descriptions.

/// Inclusive start, exclusive end physical address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRange {
    pub start: usize,
    pub end: usize,
}

impl AddressRange {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Ram,
    Mmio,
    Reserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    pub name: &'static str,
    pub range: AddressRange,
    pub kind: MemoryKind,
}

impl MemoryRegion {
    pub const fn ram(name: &'static str, start: usize, end: usize) -> Self {
        Self {
            name,
            range: AddressRange::new(start, end),
            kind: MemoryKind::Ram,
        }
    }

    pub const fn mmio(name: &'static str, start: usize, end: usize) -> Self {
        Self {
            name,
            range: AddressRange::new(start, end),
            kind: MemoryKind::Mmio,
        }
    }

    pub const fn reserved(name: &'static str, start: usize, end: usize) -> Self {
        Self {
            name,
            range: AddressRange::new(start, end),
            kind: MemoryKind::Reserved,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UartDescription {
    pub registers: AddressRange,
    pub irq: u32,
    pub register_shift: usize,
    pub register_width: usize,
    pub clock_hz: u32,
    pub baud: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlicDescription {
    pub registers: AddressRange,
    pub max_irq: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoardInfo {
    pub name: &'static str,
    pub timebase_hz: u64,
    pub uart: UartDescription,
    pub plic: PlicDescription,
}

/// Compile-time board contract consumed by architecture and kernel setup.
pub trait Board {
    const INFO: BoardInfo;
    const MEMORY_MAP: &'static [MemoryRegion];
    const HART_IDS: &'static [usize];

    /// Return the supervisor PLIC context for an OpenSBI-visible physical hart.
    fn plic_s_context(physical_hart: usize) -> Option<usize>;
}
