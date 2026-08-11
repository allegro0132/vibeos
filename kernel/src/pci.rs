//! Generic PCI ECAM discovery and resource assignment for QEMU `virt`.
//!
//! OpenSBI deliberately leaves PCI configuration to the payload.  This module
//! owns the GPEX apertures selected by the board description, enumerates every
//! function, sizes type-0 BARs while memory decoding is disabled, and assigns
//! stable non-overlapping addresses. Drivers receive value-typed `Function`
//! records and can never redirect config-space access outside ECAM.

extern crate alloc;

use alloc::vec::Vec;
use core::arch::asm;
use core::fmt;
use crate::sync::SpinLock;

const VENDOR_DEVICE: u16 = 0x00;
const COMMAND_STATUS: u16 = 0x04;
const CLASS_REVISION: u16 = 0x08;
const HEADER_TYPE: u16 = 0x0c;
const BAR0: u16 = 0x10;
const INTERRUPT: u16 = 0x3c;

const COMMAND_IO: u16 = 1 << 0;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;

const MAX_FUNCTIONS: usize = 256;

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
    Io { address: u32, size: u32 },
    Memory32 { address: u32, size: u32, prefetchable: bool },
    Memory64 { address: u64, size: u64, prefetchable: bool },
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

    pub fn enable_bus_mastering(self) {
        let command = read16(self.address, COMMAND_STATUS);
        write16(
            self.address,
            COMMAND_STATUS,
            command | COMMAND_MEMORY | COMMAND_BUS_MASTER,
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooManyFunctions,
    BarAddressExhausted,
    InvalidBarSize,
}

#[derive(Clone, Copy)]
struct Allocator {
    memory: u64,
    io: u32,
}

struct Registry {
    entries: [Option<Function>; MAX_FUNCTIONS],
    count: usize,
    initialized: bool,
}

static FUNCTIONS: SpinLock<Registry> = SpinLock::new(Registry {
    entries: [None; MAX_FUNCTIONS],
    count: 0,
    initialized: false,
});

/// Enumerate and configure every currently present endpoint exactly once.
pub fn init() -> Result<usize, Error> {
    let mut published = FUNCTIONS.lock();
    if published.initialized {
        return Ok(published.count);
    }

    let mut allocator = Allocator {
        memory: crate::platform::PCI_MMIO_START as u64,
        io: crate::platform::PCI_IO_START as u32,
    };
    let mut count = 0usize;
    for bus in 0u16..=255 {
        for device in 0u8..32 {
            let first = Address { bus: bus as u8, device, function: 0 };
            if read16(first, VENDOR_DEVICE) == 0xffff {
                continue;
            }
            let multifunction = read8(first, HEADER_TYPE + 2) & 0x80 != 0;
            let last = if multifunction { 7 } else { 0 };
            for function in 0..=last {
                let address = Address { bus: bus as u8, device, function };
                if read16(address, VENDOR_DEVICE) == 0xffff {
                    continue;
                }
                if count == MAX_FUNCTIONS {
                    return Err(Error::TooManyFunctions);
                }
                published.entries[count] = Some(configure_function(address, &mut allocator)?);
                count += 1;
            }
        }
    }
    published.count = count;
    published.initialized = true;
    Ok(count)
}

pub fn functions() -> Vec<Function> {
    let registry = FUNCTIONS.lock();
    registry.entries[..registry.count]
        .iter()
        .flatten()
        .copied()
        .collect()
}

pub fn find_xhci() -> Option<Function> {
    let registry = FUNCTIONS.lock();
    registry.entries[..registry.count]
        .iter()
        .flatten()
        .copied()
        .find(|function| function.is_xhci())
}

fn configure_function(address: Address, allocator: &mut Allocator) -> Result<Function, Error> {
    let id = read32(address, VENDOR_DEVICE);
    let class = read32(address, CLASS_REVISION);
    let header_type = read8(address, HEADER_TYPE + 2);
    let interrupt = read32(address, INTERRUPT);
    let interrupt_pin = ((interrupt >> 8) & 0xff) as u8;
    let interrupt_line = (interrupt_pin != 0).then(|| intx_irq(address, interrupt_pin));
    if let Some(irq) = interrupt_line {
        write8(address, INTERRUPT, irq as u8);
    }

    // BAR sizing must happen with both I/O and memory decoding disabled. Keep
    // the original command word so status W1C bits in the upper half are never
    // copied back accidentally.
    let original_command = read16(address, COMMAND_STATUS);
    write16(address, COMMAND_STATUS, original_command & !(COMMAND_IO | COMMAND_MEMORY));
    let mut bars = [Bar::None; 6];
    if header_type & 0x7f == 0 {
        let mut index = 0usize;
        while index < bars.len() {
            let (bar, consumed) = probe_and_assign_bar(address, index, allocator)?;
            bars[index] = bar;
            index += consumed;
        }
    }
    let has_io = bars.iter().any(|bar| matches!(bar, Bar::Io { .. }));
    let has_memory = bars
        .iter()
        .any(|bar| matches!(bar, Bar::Memory32 { .. } | Bar::Memory64 { .. }));
    let mut command = original_command;
    if has_io { command |= COMMAND_IO; }
    if has_memory { command |= COMMAND_MEMORY; }
    write16(address, COMMAND_STATUS, command);

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
    })
}

fn probe_and_assign_bar(
    address: Address,
    index: usize,
    allocator: &mut Allocator,
) -> Result<(Bar, usize), Error> {
    let offset = BAR0 + (index as u16) * 4;
    let original_low = read32(address, offset);
    write32(address, offset, u32::MAX);
    let mask_low = read32(address, offset);
    write32(address, offset, original_low);
    if mask_low == 0 || mask_low == u32::MAX {
        return Ok((Bar::None, 1));
    }

    if mask_low & 1 != 0 {
        let mask = mask_low & !3;
        let size = (!mask).wrapping_add(1);
        if size == 0 || !size.is_power_of_two() { return Err(Error::InvalidBarSize); }
        let assigned = align_up_u32(allocator.io, size).ok_or(Error::BarAddressExhausted)?;
        let end = assigned.checked_add(size).ok_or(Error::BarAddressExhausted)?;
        if end as usize > crate::platform::PCI_IO_END { return Err(Error::BarAddressExhausted); }
        allocator.io = end;
        write32(address, offset, assigned | 1);
        return Ok((Bar::Io { address: assigned, size }, 1));
    }

    let prefetchable = mask_low & 8 != 0;
    let kind = (mask_low >> 1) & 3;
    if kind == 2 && index + 1 < 6 {
        let original_high = read32(address, offset + 4);
        write32(address, offset + 4, u32::MAX);
        let mask_high = read32(address, offset + 4);
        write32(address, offset + 4, original_high);
        let mask = ((mask_high as u64) << 32) | (mask_low as u64 & !0xf);
        let size = (!mask).wrapping_add(1);
        if size == 0 || !size.is_power_of_two() { return Err(Error::InvalidBarSize); }
        let assigned = align_up_u64(allocator.memory, size).ok_or(Error::BarAddressExhausted)?;
        let end = assigned.checked_add(size).ok_or(Error::BarAddressExhausted)?;
        if end > crate::platform::PCI_MMIO_END as u64 { return Err(Error::BarAddressExhausted); }
        allocator.memory = end;
        write32(address, offset, assigned as u32 | (original_low & 0xf));
        write32(address, offset + 4, (assigned >> 32) as u32);
        return Ok((Bar::Memory64 { address: assigned, size, prefetchable }, 2));
    }

    let mask = mask_low & !0xf;
    let size = (!mask).wrapping_add(1);
    if size == 0 || !size.is_power_of_two() { return Err(Error::InvalidBarSize); }
    let assigned = align_up_u64(allocator.memory, size as u64).ok_or(Error::BarAddressExhausted)?;
    let end = assigned.checked_add(size as u64).ok_or(Error::BarAddressExhausted)?;
    if end > crate::platform::PCI_MMIO_END as u64 || assigned > u32::MAX as u64 {
        return Err(Error::BarAddressExhausted);
    }
    allocator.memory = end;
    write32(address, offset, assigned as u32 | (original_low & 0xf));
    Ok((Bar::Memory32 { address: assigned as u32, size, prefetchable }, 1))
}

const fn intx_irq(address: Address, pin: u8) -> u32 {
    // QEMU virt's interrupt-map swizzles INTA-D by slot onto PLIC 32..35.
    crate::platform::PCI_INTX_FIRST_IRQ + ((address.device as u32 + pin as u32 - 1) & 3)
}

fn align_up_u32(value: u32, alignment: u32) -> Option<u32> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    value.checked_add(alignment - 1).map(|v| v & !(alignment - 1))
}

fn config_address(address: Address, offset: u16) -> usize {
    assert!(address.device < 32 && address.function < 8 && offset < 4096);
    crate::platform::PCI_ECAM_START
        + ((address.bus as usize) << 20)
        + ((address.device as usize) << 15)
        + ((address.function as usize) << 12)
        + offset as usize
}

fn read8(address: Address, offset: u16) -> u8 {
    let value = unsafe { (config_address(address, offset) as *const u8).read_volatile() };
    io_fence();
    value
}

fn read16(address: Address, offset: u16) -> u16 {
    debug_assert_eq!(offset & 1, 0);
    let value = unsafe { (config_address(address, offset) as *const u16).read_volatile() };
    io_fence();
    value
}

fn read32(address: Address, offset: u16) -> u32 {
    debug_assert_eq!(offset & 3, 0);
    let value = unsafe { (config_address(address, offset) as *const u32).read_volatile() };
    io_fence();
    value
}

fn write8(address: Address, offset: u16, value: u8) {
    io_fence();
    unsafe { (config_address(address, offset) as *mut u8).write_volatile(value) };
    io_fence();
}

fn write16(address: Address, offset: u16, value: u16) {
    debug_assert_eq!(offset & 1, 0);
    io_fence();
    unsafe { (config_address(address, offset) as *mut u16).write_volatile(value) };
    io_fence();
}

fn write32(address: Address, offset: u16, value: u32) {
    debug_assert_eq!(offset & 3, 0);
    io_fence();
    unsafe { (config_address(address, offset) as *mut u32).write_volatile(value) };
    io_fence();
}

#[inline]
fn io_fence() {
    unsafe { asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}
