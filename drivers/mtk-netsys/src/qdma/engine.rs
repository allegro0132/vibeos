//! Experimental physical QDMA TX backend. RX remains on PDMA.
use super::{bridge::Bridge, control::Control, Io, TxRing};
use crate::Error;
use core::ptr::{read_volatile, write_volatile};

struct Registers {
    base: usize,
}
impl Io for Registers {
    fn read(&self, slot: usize, word: usize) -> u32 {
        assert!(slot < 34 && word < 8);
        unsafe { read_volatile((self.base + slot * 32 + word * 4) as *const u32) }
    }
    fn write(&mut self, slot: usize, word: usize, value: u32) {
        assert!(slot < 34 && word < 8);
        unsafe {
            write_volatile((self.base + slot * 32 + word * 4) as *mut u32, value);
        }
    }
    fn reg(&self, offset: usize) -> u32 {
        assert!((0x4400..0x6b00).contains(&offset) && offset & 3 == 0);
        unsafe { read_volatile((0x15100000 + offset) as *const u32) }
    }
    fn set_reg(&mut self, offset: usize, value: u32) {
        assert!((0x4400..0x4800).contains(&offset) && offset & 3 == 0);
        unsafe {
            write_volatile((0x15100000 + offset) as *mut u32, value);
        }
    }
    fn barrier(&self) {
        unsafe {
            core::arch::asm!("dsb sy", options(nostack));
        }
    }
}
pub struct Engine {
    registers: Registers,
    bridge: Bridge,
    control: Control,
}
impl Engine {
    /// # Safety
    /// The ring's stopped, initialized descriptors are at `base`, exclusively
    /// owned with all scratch/buffers permanently mapped NC. This backend takes
    /// over exactly that physical allocation; no other owner remains.
    pub unsafe fn new(base: usize, ring: TxRing<34>) -> Self {
        Self {
            registers: Registers { base },
            bridge: Bridge::new(ring),
            control: Control::prepared(),
        }
    }
    pub fn started(&self) -> bool {
        self.control.used()
    }
    pub fn start(&mut self) -> Result<(), Error> {
        self.control.start(&mut self.registers)
    }
    fn close(&mut self) {
        self.control.close(&mut self.registers);
    }
    pub fn stop(&mut self, timeout: u64, now: impl FnMut() -> u64) -> Result<(), Error> {
        self.control.stop(&mut self.registers, timeout, now)
    }
    pub fn poll(&mut self, dma: &mut impl crate::Io) -> Result<(), Error> {
        if !self.control.running() {
            return Err(Error::NotReady);
        }
        let result = self.bridge.poll(&mut self.registers, dma);
        if result.is_err() {
            self.close();
        }
        result
    }
    /// # Safety
    /// Nic owns shadows and buffers according to Bridge::notify's contract.
    pub unsafe fn notify(&mut self, dma: &mut impl crate::Io, end: usize) -> Result<(), Error> {
        if !self.control.running() {
            return Err(Error::NotReady);
        }
        let result = unsafe { self.bridge.notify(&mut self.registers, dma, end) };
        if result.is_err() {
            self.close();
        }
        result
    }
}
