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

/// Architecture-visible memory type to encode in identity-map leaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAttributes {
    /// Standard RISC-V PTEs without vendor memory-type bits.
    Standard,
    /// T-Head C9xx shareable, cacheable, bufferable normal memory.
    THeadNormal,
    /// T-Head C9xx shareable, strongly ordered device memory.
    THeadDevice,
}

/// Leaf size used for an early identity mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingGranularity {
    Page4K,
    Megapage2M,
    Gigapage1G,
}

impl MappingGranularity {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Page4K => 4 * 1024,
            Self::Megapage2M => 2 * 1024 * 1024,
            Self::Gigapage1G => 1024 * 1024 * 1024,
        }
    }
}

/// One board-owned MMIO aperture mapped at identical virtual and physical
/// addresses during early boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityMapping {
    pub name: &'static str,
    pub range: AddressRange,
    pub granularity: MappingGranularity,
}

impl IdentityMapping {
    pub const fn new(
        name: &'static str,
        start: usize,
        end: usize,
        granularity: MappingGranularity,
    ) -> Self {
        Self {
            name,
            range: AddressRange::new(start, end),
            granularity,
        }
    }

    pub const fn pages(name: &'static str, start: usize, end: usize) -> Self {
        Self::new(name, start, end, MappingGranularity::Page4K)
    }

    pub const fn megapages(name: &'static str, start: usize, end: usize) -> Self {
        Self::new(name, start, end, MappingGranularity::Megapage2M)
    }

    pub const fn gigapages(name: &'static str, start: usize, end: usize) -> Self {
        Self::new(name, start, end, MappingGranularity::Gigapage1G)
    }
}

/// Complete board contract for constructing the allocation-free boot address
/// space. The table counts include the two sparse PLIC windows maintained by
/// the kernel (control/enable and supervisor contexts).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MmuDescription {
    pub ram: AddressRange,
    pub ram_attributes: MemoryAttributes,
    pub mmio_attributes: MemoryAttributes,
    pub identity_mappings: &'static [IdentityMapping],
    pub device_level1_tables: usize,
    pub device_level0_tables: usize,
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
pub enum UartVariant {
    Ns16550,
    DesignWareApb,
}

impl UartVariant {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ns16550 => "ns16550a",
            Self::DesignWareApb => "dw-apb-uart",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UartQuirks {
    pub busy_detect: bool,
    pub phantom_rx_timeout: bool,
}

impl UartQuirks {
    pub const NONE: Self = Self {
        busy_detect: false,
        phantom_rx_timeout: false,
    };

    pub const DESIGNWARE_APB: Self = Self {
        busy_detect: true,
        phantom_rx_timeout: true,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleCapabilities {
    pub early_uart: bool,
    pub usb_keyboard_input: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UartDescription {
    pub variant: UartVariant,
    pub registers: AddressRange,
    pub irq: u32,
    pub register_shift: usize,
    pub register_width: usize,
    pub clock_hz: u32,
    pub baud: u32,
    pub quirks: UartQuirks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlicDescription {
    pub registers: AddressRange,
    pub max_irq: u32,
}

/// One bank of modern VirtIO MMIO transport windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioMmioDescription {
    pub registers: AddressRange,
    pub stride: usize,
    pub slots: usize,
    pub first_irq: u32,
}

/// PCI host bridge apertures and legacy INTx routing base.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciHostDescription {
    pub ecam: AddressRange,
    pub io: AddressRange,
    pub mmio: AddressRange,
    pub intx_first_irq: u32,
}

/// Synopsys DWMAC instance plus board-level clock/PHY wiring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwmacDescription {
    pub registers: AddressRange,
    pub irq: u32,
    pub soc_control: AddressRange,
    pub efuse: AddressRange,
    pub phy_address: u8,
    pub dma_address_bits: u8,
    pub cache_line_bytes: usize,
}

/// SDHCI instance plus board-level pinmux and source-clock wiring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdhciDescription {
    pub registers: AddressRange,
    pub irq: u32,
    pub soc_control: AddressRange,
    pub source_clock_hz: u32,
    pub bus_width: u8,
    pub init_clock_hz: u32,
    pub data_clock_hz: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoardInfo {
    pub name: &'static str,
    pub timebase_hz: u64,
    pub uart: UartDescription,
    pub plic: PlicDescription,
    pub console: ConsoleCapabilities,
    pub virtio_mmio: Option<VirtioMmioDescription>,
    pub pci: Option<PciHostDescription>,
    pub dwmac: Option<DwmacDescription>,
    pub sdhci: Option<SdhciDescription>,
}

/// Compile-time board contract consumed by architecture and kernel setup.
pub trait Board {
    const INFO: BoardInfo;
    const MEMORY_MAP: &'static [MemoryRegion];
    const MMU: MmuDescription;
    const HART_IDS: &'static [usize];

    /// Return the supervisor PLIC context for an OpenSBI-visible physical hart.
    fn plic_s_context(physical_hart: usize) -> Option<usize>;
}
