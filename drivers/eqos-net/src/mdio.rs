//! EQoS Clause 22 register transport, separate from legacy DWMAC encoding.
use vibeos_ethernet::MdioPort;

pub const ADDRESS: usize = 0x200;
pub const DATA: usize = 0x204;

/// Implementations must order volatile MMIO accesses on the selected platform.
pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    UnsupportedRate,
}

/// Select an MDC divisor from the GMAC4/5 CSR clock ranges. The caller supplies
/// the actual CSR clock after platform initialization, not a nominal PHY clock.
pub fn clock_range(csr_hz: u64) -> Result<u8, ClockError> {
    match csr_hz {
        20_000_000..35_000_000 => Ok(2),
        35_000_000..60_000_000 => Ok(3),
        60_000_000..100_000_000 => Ok(0),
        100_000_000..150_000_000 => Ok(1),
        150_000_000..250_000_000 => Ok(4),
        250_000_000..=300_000_000 => Ok(5),
        _ => Err(ClockError::UnsupportedRate),
    }
}

pub struct Port<R> {
    registers: R,
    clock: u8,
}
impl<R: Registers> Port<R> {
    pub fn new(registers: R, csr_hz: u64) -> Result<Self, ClockError> {
        Ok(Self {
            registers,
            clock: clock_range(csr_hz)?,
        })
    }
    pub fn into_inner(self) -> R {
        self.registers
    }
    fn command(&self, phy: u8, register: u8, write: bool) -> u32 {
        u32::from(phy) << 21
            | u32::from(register) << 16
            | u32::from(self.clock) << 8
            | if write { 1 << 2 } else { 3 << 2 }
            | 1
    }
}
impl<R: Registers> MdioPort for Port<R> {
    fn busy(&mut self) -> bool {
        self.registers.read(ADDRESS) & 1 != 0
    }
    fn start_read(&mut self, phy: u8, register: u8) {
        self.registers
            .write(ADDRESS, self.command(phy, register, false));
    }
    fn start_write(&mut self, phy: u8, register: u8, value: u16) {
        self.registers.write(DATA, u32::from(value));
        self.registers
            .write(ADDRESS, self.command(phy, register, true));
    }
    fn data(&mut self) -> u16 {
        self.registers.read(DATA) as u16
    }
}
