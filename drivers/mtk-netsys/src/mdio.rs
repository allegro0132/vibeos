//! Bounded MTK PIAC transactions shared by FE MDIO and the internal switch.
//! Layout: U-Boot mdio-mt7531-mmio.c and mtk_eth/mtk_eth.h.
const BUSY: u32 = 1 << 31;

pub trait Io {
    fn read(&self) -> u32;
    fn write(&mut self, value: u32);
    fn now(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    /// No command was submitted by this transaction.
    BusyTimeout,
    /// A submitted command may have completed; writes are not rolled back.
    CompletionTimeout,
}

pub struct Mdio<I: Io> {
    io: I,
    timeout: u64,
}
impl<I: Io> Mdio<I> {
    pub fn new(io: I, timeout_ticks: u64) -> Self {
        assert!(timeout_ticks != 0);
        Self {
            io,
            timeout: timeout_ticks,
        }
    }
    pub(crate) fn now(&self) -> u64 {
        self.io.now()
    }
    fn wait(&self, error: Error) -> Result<u32, Error> {
        let start = self.io.now();
        loop {
            let value = self.io.read();
            if value & BUSY == 0 {
                return Ok(value);
            }
            if self.io.now().wrapping_sub(start) >= self.timeout {
                return Err(error);
            }
            core::hint::spin_loop();
        }
    }
    fn command(&mut self, command: u32) -> Result<u16, Error> {
        self.wait(Error::BusyTimeout)?;
        self.io.write(command | BUSY);
        self.wait(Error::CompletionTimeout).map(|v| v as u16)
    }
    fn address(phy: u8, register_or_device: u8) -> Result<u32, Error> {
        if phy >= 32 || register_or_device >= 32 {
            return Err(Error::InvalidAddress);
        }
        Ok(((phy as u32) << 20) | ((register_or_device as u32) << 25))
    }
    pub fn read_c22(&mut self, phy: u8, register: u8) -> Result<u16, Error> {
        let address = Self::address(phy, register)?;
        self.command(address | (1 << 16) | (2 << 18))
    }
    pub fn write_c22(&mut self, phy: u8, register: u8, value: u16) -> Result<(), Error> {
        let address = Self::address(phy, register)?;
        self.command(address | (1 << 16) | (1 << 18) | value as u32)
            .map(|_| ())
    }
    pub fn read_c45(&mut self, phy: u8, device: u8, register: u16) -> Result<u16, Error> {
        let address = Self::address(phy, device)?;
        self.command(address | register as u32)?;
        self.command(address | (3 << 18))
    }
    pub fn write_c45(
        &mut self,
        phy: u8,
        device: u8,
        register: u16,
        value: u16,
    ) -> Result<(), Error> {
        let address = Self::address(phy, device)?;
        self.command(address | register as u32)?;
        self.command(address | (1 << 18) | value as u32).map(|_| ())
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub struct Mmio {
    register: usize,
    clock: fn() -> u64,
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Mmio {
    /// # Safety
    /// Sole transaction owner of this PIAC register, mapped Device-nGnRnE;
    /// clocks are running. Other owners must not interleave C45 phases.
    pub unsafe fn new(register: usize, clock: fn() -> u64) -> Self {
        assert!(register == 0x1502701c || register == 0x15110004);
        Self { register, clock }
    }
}
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
impl Io for Mmio {
    fn read(&self) -> u32 {
        unsafe { core::ptr::read_volatile(self.register as *const u32) }
    }
    fn write(&mut self, value: u32) {
        unsafe {
            core::ptr::write_volatile(self.register as *mut u32, value);
            core::arch::asm!("dsb sy", options(nostack));
        }
    }
    fn now(&self) -> u64 {
        (self.clock)()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    struct Mock {
        writes: std::vec::Vec<u32>,
        value: u32,
        ticks: Cell<u64>,
        stuck_after: usize,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                writes: std::vec::Vec::new(),
                value: 0,
                ticks: Cell::new(0),
                stuck_after: usize::MAX,
            }
        }
    }
    impl Io for Mock {
        fn read(&self) -> u32 {
            self.value
        }
        fn write(&mut self, value: u32) {
            self.writes.push(value);
            self.value = if self.writes.len() >= self.stuck_after {
                BUSY
            } else {
                0x9481
            };
        }
        fn now(&self) -> u64 {
            let t = self.ticks.get();
            self.ticks.set(t.wrapping_add(1));
            t
        }
    }
    #[test]
    fn c22_and_c45_encoding_and_order() {
        let mut m = Mdio::new(Mock::new(), 10);
        assert_eq!(m.read_c22(0, 3), Ok(0x9481));
        m.write_c22(0, 0, 0x1200).unwrap();
        assert_eq!(m.read_c45(16, 1, 2), Ok(0x9481));
        m.write_c45(16, 30, 0x1234, 0xabcd).unwrap();
        assert_eq!(
            m.io.writes,
            [0x86090000, 0x80051200, 0x83000002, 0x830c0000, 0xbd001234, 0xbd04abcd]
        );
    }
    #[test]
    fn invalid_address_never_touches_bus() {
        let mut m = Mdio::new(Mock::new(), 10);
        assert_eq!(m.read_c22(32, 0), Err(Error::InvalidAddress));
        assert_eq!(m.write_c22(0, 32, 0), Err(Error::InvalidAddress));
        assert_eq!(m.read_c45(0, 32, 0), Err(Error::InvalidAddress));
        assert_eq!(m.write_c45(32, 0, 0, 0), Err(Error::InvalidAddress));
        assert!(m.io.writes.is_empty());
    }
    #[test]
    fn busy_or_incomplete_address_never_submits_next_phase() {
        let mut io = Mock::new();
        io.value = BUSY;
        let mut m = Mdio::new(io, 10);
        assert_eq!(m.read_c22(0, 2), Err(Error::BusyTimeout));
        assert!(m.io.writes.is_empty());
        m.io.value = 0;
        m.io.stuck_after = 1;
        assert_eq!(m.write_c45(0, 1, 2, 3), Err(Error::CompletionTimeout));
        assert_eq!(m.io.writes.len(), 1);
        assert_eq!(m.read_c22(0, 2), Err(Error::BusyTimeout));
        assert_eq!(m.io.writes.len(), 1);
    }
    #[test]
    fn data_phase_timeout_is_reported_without_retry() {
        let mut io = Mock::new();
        io.stuck_after = 2;
        io.ticks.set(u64::MAX - 5);
        let mut m = Mdio::new(io, 10);
        assert_eq!(m.write_c45(0, 1, 2, 3), Err(Error::CompletionTimeout));
        assert_eq!(m.io.writes.len(), 2);
    }
}
