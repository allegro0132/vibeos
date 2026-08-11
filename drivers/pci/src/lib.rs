#![cfg_attr(not(test), no_std)]

//! Generic PCI ECAM discovery and type-0 BAR assignment.
//!
//! The driver owns no board policy and has no kernel dependency. A board or
//! firmware package supplies a [`PciConfig`], while the kernel is responsible
//! for serializing access to the [`Pci`] instance and routing the resulting
//! INTx interrupt numbers.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
pub use vibeos_hal::PciHostDescription;

const VENDOR_DEVICE: u16 = 0x00;
const COMMAND_STATUS: u16 = 0x04;
const CLASS_REVISION: u16 = 0x08;
const HEADER_TYPE: u16 = 0x0c;
const BAR0: u16 = 0x10;
const INTERRUPT: u16 = 0x3c;

const COMMAND_IO: u16 = 1 << 0;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;

pub const MAX_FUNCTIONS: usize = 256;

/// Compatibility name for callers that treat the board description as this
/// driver's configuration value.
pub type PciConfig = PciHostDescription;

pub const fn validate_config(config: PciHostDescription) -> Result<(), Error> {
    if config.ecam.start >= config.ecam.end
        || config.ecam.end - config.ecam.start < (1 << 20)
        || config.mmio.start >= config.mmio.end
        || config.io.start >= config.io.end
        || config.io.end > u32::MAX as usize
    {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

/// Compute an ECAM register address without accessing hardware.
pub fn config_address(
    config: PciHostDescription,
    address: Address,
    offset: u16,
) -> Result<usize, Error> {
    if address.device >= 32 || address.function >= 8 || offset >= 4096 {
        return Err(Error::InvalidConfigAddress);
    }
    let relative = ((address.bus as usize) << 20)
        | ((address.device as usize) << 15)
        | ((address.function as usize) << 12)
        | offset as usize;
    let absolute = config
        .ecam
        .start
        .checked_add(relative)
        .ok_or(Error::InvalidConfigAddress)?;
    if absolute >= config.ecam.end {
        return Err(Error::InvalidConfigAddress);
    }
    Ok(absolute)
}

/// Apply the host bridge's four-way slot/pin INTx swizzle.
pub const fn intx_irq(config: PciHostDescription, address: Address, pin: u8) -> Result<u32, Error> {
    if pin == 0 || pin > 4 {
        return Err(Error::InvalidInterruptPin);
    }
    let offset = (address.device as u32 + pin as u32 - 1) & 3;
    match config.intx_first_irq.checked_add(offset) {
        Some(irq) => Ok(irq),
        None => Err(Error::InvalidConfig),
    }
}

const fn bus_count(config: PciHostDescription) -> usize {
    let count = (config.ecam.end - config.ecam.start) >> 20;
    if count > 256 {
        256
    } else {
        count
    }
}

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
    config: PciConfig,
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

    pub fn enable_bus_mastering(self) {
        let command = read16(self.config, self.address, COMMAND_STATUS);
        write16(
            self.config,
            self.address,
            COMMAND_STATUS,
            command | COMMAND_MEMORY | COMMAND_BUS_MASTER,
        );
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

#[derive(Clone, Copy)]
struct Allocator {
    memory: u64,
    io: u32,
}

impl Allocator {
    const fn new(config: PciConfig) -> Self {
        Self {
            memory: config.mmio.start as u64,
            io: config.io.start as u32,
        }
    }

    fn allocate_io(&mut self, config: PciConfig, size: u32) -> Result<u32, Error> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidBarSize);
        }
        let assigned = align_up_u32(self.io, size).ok_or(Error::BarAddressExhausted)?;
        let end = assigned
            .checked_add(size)
            .ok_or(Error::BarAddressExhausted)?;
        if end as usize > config.io.end {
            return Err(Error::BarAddressExhausted);
        }
        self.io = end;
        Ok(assigned)
    }

    fn allocate_memory(&mut self, config: PciConfig, size: u64) -> Result<u64, Error> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidBarSize);
        }
        let assigned = align_up_u64(self.memory, size).ok_or(Error::BarAddressExhausted)?;
        let end = assigned
            .checked_add(size)
            .ok_or(Error::BarAddressExhausted)?;
        if end > config.mmio.end as u64 {
            return Err(Error::BarAddressExhausted);
        }
        self.memory = end;
        Ok(assigned)
    }
}

/// One PCI host bridge and its discovered endpoint registry.
///
/// A kernel may place this value inside its own lock. Keeping synchronization
/// outside the crate prevents a dependency on kernel scheduler primitives.
pub struct Pci {
    config: PciConfig,
    entries: [Option<Function>; MAX_FUNCTIONS],
    count: usize,
    initialized: bool,
}

impl Pci {
    pub const fn new(config: PciConfig) -> Self {
        Self {
            config,
            entries: [None; MAX_FUNCTIONS],
            count: 0,
            initialized: false,
        }
    }

    pub const fn config(&self) -> PciConfig {
        self.config
    }

    /// Enumerate and configure every currently present endpoint exactly once.
    pub fn init(&mut self) -> Result<usize, Error> {
        if self.initialized {
            return Ok(self.count);
        }
        validate_config(self.config)?;

        let mut allocator = Allocator::new(self.config);
        let mut count = 0usize;
        for bus in 0..bus_count(self.config) {
            for device in 0u8..32 {
                let first = Address {
                    bus: bus as u8,
                    device,
                    function: 0,
                };
                if read16(self.config, first, VENDOR_DEVICE) == 0xffff {
                    continue;
                }
                let multifunction = read8(self.config, first, HEADER_TYPE + 2) & 0x80 != 0;
                let last = if multifunction { 7 } else { 0 };
                for function in 0..=last {
                    let address = Address {
                        bus: bus as u8,
                        device,
                        function,
                    };
                    if read16(self.config, address, VENDOR_DEVICE) == 0xffff {
                        continue;
                    }
                    if count == MAX_FUNCTIONS {
                        return Err(Error::TooManyFunctions);
                    }
                    self.entries[count] =
                        Some(configure_function(self.config, address, &mut allocator)?);
                    count += 1;
                }
            }
        }
        self.count = count;
        self.initialized = true;
        Ok(count)
    }

    pub fn functions(&self) -> Vec<Function> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .copied()
            .collect()
    }

    pub fn find_xhci(&self) -> Option<Function> {
        self.entries[..self.count]
            .iter()
            .flatten()
            .copied()
            .find(|function| function.is_xhci())
    }
}

fn configure_function(
    config: PciConfig,
    address: Address,
    allocator: &mut Allocator,
) -> Result<Function, Error> {
    let id = read32(config, address, VENDOR_DEVICE);
    let class = read32(config, address, CLASS_REVISION);
    let header_type = read8(config, address, HEADER_TYPE + 2);
    let interrupt = read32(config, address, INTERRUPT);
    let interrupt_pin = ((interrupt >> 8) & 0xff) as u8;
    let interrupt_line = if interrupt_pin == 0 {
        None
    } else {
        Some(intx_irq(config, address, interrupt_pin)?)
    };
    if let Some(irq) = interrupt_line {
        write8(config, address, INTERRUPT, irq as u8);
    }

    let original_command = read16(config, address, COMMAND_STATUS);
    write16(
        config,
        address,
        COMMAND_STATUS,
        original_command & !(COMMAND_IO | COMMAND_MEMORY),
    );
    let mut bars = [Bar::None; 6];
    if header_type & 0x7f == 0 {
        let mut index = 0usize;
        while index < bars.len() {
            let (bar, consumed) = probe_and_assign_bar(config, address, index, allocator)?;
            bars[index] = bar;
            index += consumed;
        }
    }
    let has_io = bars.iter().any(|bar| matches!(bar, Bar::Io { .. }));
    let has_memory = bars
        .iter()
        .any(|bar| matches!(bar, Bar::Memory32 { .. } | Bar::Memory64 { .. }));
    let mut command = original_command;
    if has_io {
        command |= COMMAND_IO;
    }
    if has_memory {
        command |= COMMAND_MEMORY;
    }
    write16(config, address, COMMAND_STATUS, command);

    Ok(Function {
        address,
        vendor_id: id as u16,
        device_id: (id >> 16) as u16,
        revision: class as u8,
        programming_interface: (class >> 8) as u8,
        subclass: (class >> 16) as u8,
        class: (class >> 24) as u8,
        header_type,
        interrupt_pin,
        interrupt_line,
        bars,
        config,
    })
}

fn probe_and_assign_bar(
    config: PciConfig,
    address: Address,
    index: usize,
    allocator: &mut Allocator,
) -> Result<(Bar, usize), Error> {
    let offset = BAR0 + (index as u16) * 4;
    let original_low = read32(config, address, offset);
    write32(config, address, offset, u32::MAX);
    let mask_low = read32(config, address, offset);
    write32(config, address, offset, original_low);
    if mask_low == 0 || mask_low == u32::MAX {
        return Ok((Bar::None, 1));
    }

    if mask_low & 1 != 0 {
        let mask = mask_low & !3;
        let size = (!mask).wrapping_add(1);
        let assigned = allocator.allocate_io(config, size)?;
        write32(config, address, offset, assigned | 1);
        return Ok((
            Bar::Io {
                address: assigned,
                size,
            },
            1,
        ));
    }

    let prefetchable = mask_low & 8 != 0;
    let kind = (mask_low >> 1) & 3;
    if kind == 2 && index + 1 < 6 {
        let original_high = read32(config, address, offset + 4);
        write32(config, address, offset + 4, u32::MAX);
        let mask_high = read32(config, address, offset + 4);
        write32(config, address, offset + 4, original_high);
        let mask = ((mask_high as u64) << 32) | (mask_low as u64 & !0xf);
        let size = (!mask).wrapping_add(1);
        let assigned = allocator.allocate_memory(config, size)?;
        write32(
            config,
            address,
            offset,
            assigned as u32 | (original_low & 0xf),
        );
        write32(config, address, offset + 4, (assigned >> 32) as u32);
        return Ok((
            Bar::Memory64 {
                address: assigned,
                size,
                prefetchable,
            },
            2,
        ));
    }

    let mask = mask_low & !0xf;
    let size = (!mask).wrapping_add(1);
    let assigned = allocator.allocate_memory(config, size as u64)?;
    if assigned > u32::MAX as u64 {
        return Err(Error::BarAddressExhausted);
    }
    write32(
        config,
        address,
        offset,
        assigned as u32 | (original_low & 0xf),
    );
    Ok((
        Bar::Memory32 {
            address: assigned as u32,
            size,
            prefetchable,
        },
        1,
    ))
}

fn align_up_u32(value: u32, alignment: u32) -> Option<u32> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}

fn config_register(config: PciConfig, address: Address, offset: u16) -> usize {
    config_address(config, address, offset).expect("PCI config address outside ECAM")
}

fn read8(config: PciConfig, address: Address, offset: u16) -> u8 {
    let value = unsafe { (config_register(config, address, offset) as *const u8).read_volatile() };
    io_fence();
    value
}

fn read16(config: PciConfig, address: Address, offset: u16) -> u16 {
    debug_assert_eq!(offset & 1, 0);
    let value = unsafe { (config_register(config, address, offset) as *const u16).read_volatile() };
    io_fence();
    value
}

fn read32(config: PciConfig, address: Address, offset: u16) -> u32 {
    debug_assert_eq!(offset & 3, 0);
    let value = unsafe { (config_register(config, address, offset) as *const u32).read_volatile() };
    io_fence();
    value
}

fn write8(config: PciConfig, address: Address, offset: u16, value: u8) {
    io_fence();
    unsafe { (config_register(config, address, offset) as *mut u8).write_volatile(value) };
    io_fence();
}

fn write16(config: PciConfig, address: Address, offset: u16, value: u16) {
    debug_assert_eq!(offset & 1, 0);
    io_fence();
    unsafe { (config_register(config, address, offset) as *mut u16).write_volatile(value) };
    io_fence();
}

fn write32(config: PciConfig, address: Address, offset: u16, value: u32) {
    debug_assert_eq!(offset & 3, 0);
    io_fence();
    unsafe { (config_register(config, address, offset) as *mut u32).write_volatile(value) };
    io_fence();
}

#[inline]
fn io_fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }

    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: PciConfig = PciConfig {
        ecam: vibeos_hal::AddressRange::new(0x3000_0000, 0x4000_0000),
        mmio: vibeos_hal::AddressRange::new(0x4000_0000, 0x8000_0000),
        io: vibeos_hal::AddressRange::new(0x0300_0000, 0x0301_0000),
        intx_first_irq: 32,
    };

    #[test]
    fn computes_ecam_addresses() {
        let address = Address {
            bus: 2,
            device: 3,
            function: 4,
        };
        assert_eq!(config_address(CONFIG, address, 0xabc), Ok(0x3021_cabc),);
        assert_eq!(
            config_address(
                PciConfig {
                    ecam: vibeos_hal::AddressRange::new(
                        CONFIG.ecam.start,
                        CONFIG.ecam.start + (1 << 20)
                    ),
                    ..CONFIG
                },
                Address {
                    bus: 1,
                    device: 0,
                    function: 0
                },
                0
            ),
            Err(Error::InvalidConfigAddress),
        );
        assert_eq!(
            config_address(
                CONFIG,
                Address {
                    bus: 255,
                    device: 31,
                    function: 7,
                },
                0xfff,
            ),
            Ok(CONFIG.ecam.end - 1),
        );
        assert_eq!(
            config_address(
                PciConfig {
                    ecam: vibeos_hal::AddressRange::new(usize::MAX - (1 << 20) + 1, usize::MAX,),
                    ..CONFIG
                },
                Address {
                    bus: 255,
                    device: 31,
                    function: 7,
                },
                0xfff,
            ),
            Err(Error::InvalidConfigAddress),
        );
    }

    #[test]
    fn swizzles_intx_by_slot_and_pin() {
        let slot = Address {
            bus: 0,
            device: 2,
            function: 0,
        };
        assert_eq!(intx_irq(CONFIG, slot, 1), Ok(34));
        assert_eq!(intx_irq(CONFIG, slot, 4), Ok(33));
        assert_eq!(intx_irq(CONFIG, slot, 0), Err(Error::InvalidInterruptPin));
        assert_eq!(
            intx_irq(
                PciConfig {
                    intx_first_irq: u32::MAX,
                    ..CONFIG
                },
                slot,
                1
            ),
            Err(Error::InvalidConfig),
        );
    }

    #[test]
    fn bar_allocator_accepts_exact_end_and_rejects_overflow() {
        let config = PciConfig {
            mmio: vibeos_hal::AddressRange::new(0x4000_1001, 0x4000_3000),
            io: vibeos_hal::AddressRange::new(0x1001, 0x3000),
            ..CONFIG
        };
        let mut allocator = Allocator::new(config);
        assert_eq!(allocator.allocate_memory(config, 0x1000), Ok(0x4000_2000));
        assert_eq!(
            allocator.allocate_memory(config, 0x1000),
            Err(Error::BarAddressExhausted)
        );
        assert_eq!(allocator.allocate_io(config, 0x1000), Ok(0x2000));
        assert_eq!(
            allocator.allocate_io(config, 0x1000),
            Err(Error::BarAddressExhausted)
        );
    }

    #[test]
    fn rejects_invalid_bar_sizes() {
        let mut allocator = Allocator::new(CONFIG);
        assert_eq!(
            allocator.allocate_memory(CONFIG, 0),
            Err(Error::InvalidBarSize)
        );
        assert_eq!(allocator.allocate_io(CONFIG, 3), Err(Error::InvalidBarSize));
    }
}
