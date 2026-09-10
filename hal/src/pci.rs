//! PCI inventory records and firmware-owned host bridge operations.
use core::fmt;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bar {
    None,
    Io {
        address: u32,
        size: u32,
    },
    Memory32 {
        address: u32,
        size: u32,
        prefetchable: bool,
    },
    Memory64 {
        address: u64,
        size: u64,
        prefetchable: bool,
    },
}

impl Bar {
    pub const fn address(self) -> Option<u64> {
        match self {
            Self::None => None,
            Self::Io { address, .. } | Self::Memory32 { address, .. } => Some(address as u64),
            Self::Memory64 { address, .. } => Some(address),
        }
    }

    pub const fn size(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Io { size, .. } | Self::Memory32 { size, .. } => size as u64,
            Self::Memory64 { size, .. } => size,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub address: Address,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub programming_interface: u8,
    pub revision: u8,
    pub header_type: u8,
    pub interrupt_pin: u8,
    pub interrupt_line: Option<u32>,
    pub bars: [Bar; 6],
}

impl Function {
    pub const fn class_code(self) -> u32 {
        ((self.class as u32) << 16)
            | ((self.subclass as u32) << 8)
            | self.programming_interface as u32
    }

    pub const fn is_xhci(self) -> bool {
        self.class == 0x0c && self.subclass == 0x03 && self.programming_interface == 0x30
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    InvalidConfigAddress,
    InvalidInterruptPin,
    TooManyFunctions,
    BarAddressExhausted,
    InvalidBarSize,
}

/// # Safety
/// The consumer serializes all calls to this host, whose ECAM/resource ranges
/// stay mapped. Inventory callbacks are borrowed only for the duration of the
/// call. Bus mastering may be enabled only for a currently registered function.
pub struct Host {
    pub init: unsafe fn() -> Result<usize, Error>,
    pub functions: unsafe fn(&mut dyn FnMut(Function)),
    pub enable_bus_mastering: unsafe fn(Function) -> Result<(), Error>,
}
extern "Rust" {
    static VIBEOS_PCI_HOST: Host;
}
pub fn host() -> &'static Host {
    unsafe { &VIBEOS_PCI_HOST }
}
