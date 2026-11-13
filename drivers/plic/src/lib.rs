#![no_std]
//! PLIC register engine. Context selection, locking and handler publication
//! belong to the caller. Host tests exercise offsets; they do not emulate IRQs.
use vibeos_hal::PlicDescription;

pub trait Registers {
    fn read(&self, offset: usize) -> u32;
    fn write(&self, offset: usize, value: u32);
}
pub struct Mmio(PlicDescription);
impl Mmio {
    /// # Safety
    /// Each accessed PLIC page must remain mapped as device memory. The caller
    /// must serialize updates to shared enable words and own selected contexts.
    pub const unsafe fn new(description: PlicDescription) -> Self {
        assert!(description.registers.start % 4 == 0 && description.registers.len() >= 4);
        assert!(description.max_irq > 0 && description.max_irq <= 1023);
        Self(description)
    }
}
impl Registers for Mmio {
    fn read(&self, offset: usize) -> u32 {
        assert!(offset % 4 == 0 && offset <= self.0.registers.len().saturating_sub(4));
        unsafe { ((self.0.registers.start + offset) as *const u32).read_volatile() }
    }
    fn write(&self, offset: usize, value: u32) {
        assert!(offset % 4 == 0 && offset <= self.0.registers.len().saturating_sub(4));
        unsafe { ((self.0.registers.start + offset) as *mut u32).write_volatile(value) }
    }
}

pub struct Plic<R> {
    registers: R,
    max_irq: u32,
}
impl<R: Registers> Plic<R> {
    pub const fn new(registers: R, max_irq: u32) -> Self {
        assert!(max_irq > 0 && max_irq <= 1023);
        Self { registers, max_irq }
    }
    fn context_register(context: usize) -> usize {
        assert!(context < 15872); // Standard PLIC context aperture.
        0x20_0000 + context * 0x1000
    }
    fn enable_register(context: usize, word: usize) -> usize {
        assert!(context < 15872 && word < 32);
        0x2000 + context * 0x80 + word * 4
    }
    pub fn init_context(&self, context: usize) {
        self.registers.write(Self::context_register(context), 0);
        for word in 0..(self.max_irq as usize + 32) / 32 {
            self.registers
                .write(Self::enable_register(context, word), 0);
        }
    }
    pub fn set_enabled(&self, context: usize, irq: u32, enabled: bool) {
        assert!(irq > 0 && irq <= self.max_irq);
        let offset = Self::enable_register(context, irq as usize / 32);
        let mask = 1 << (irq % 32);
        let current = self.registers.read(offset);
        self.registers.write(
            offset,
            if enabled {
                current | mask
            } else {
                current & !mask
            },
        );
        if enabled {
            self.registers.write(irq as usize * 4, 1);
        }
    }
    pub fn claim(&self, context: usize) -> Option<u32> {
        let irq = self.registers.read(Self::context_register(context) + 4);
        (irq != 0).then_some(irq)
    }
    pub fn complete(&self, context: usize, irq: u32) {
        assert!(irq > 0 && irq <= self.max_irq);
        self.registers
            .write(Self::context_register(context) + 4, irq);
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::RefCell;
    use std::{collections::BTreeMap, vec::Vec};
    #[derive(Default)]
    struct Fake(RefCell<BTreeMap<usize, u32>>);
    impl Registers for Fake {
        fn read(&self, offset: usize) -> u32 {
            *self.0.borrow().get(&offset).unwrap_or(&0)
        }
        fn write(&self, offset: usize, value: u32) {
            self.0.borrow_mut().insert(offset, value);
        }
    }
    #[test]
    fn duo_context_only_clears_implemented_enable_words() {
        let p = Plic::new(Fake::default(), 101);
        p.init_context(1);
        assert_eq!(
            p.registers.0.borrow().keys().copied().collect::<Vec<_>>(),
            std::vec![0x2080, 0x2084, 0x2088, 0x208c, 0x201000]
        );
    }
    #[test]
    fn context_and_enable_boundaries_preserve_other_sources() {
        let p = Plic::new(Fake::default(), 1023);
        p.set_enabled(8, 31, true);
        p.set_enabled(8, 1, true);
        assert_eq!(p.registers.read(0x2400), 0x80000002);
        p.set_enabled(8, 31, false);
        assert_eq!(p.registers.read(0x2400), 2);
        p.set_enabled(8, 32, true);
        assert_eq!(p.registers.read(0x2404), 1);
        p.set_enabled(8, 1023, true);
        assert_eq!(p.registers.read(0x247c), 0x80000000);
    }
    #[test]
    fn claim_zero_is_empty_and_completion_uses_same_context() {
        let p = Plic::new(Fake::default(), 136);
        assert_eq!(p.claim(4), None);
        p.registers.write(0x204004, 35);
        assert_eq!(p.claim(4), Some(35));
        p.complete(4, 35);
        assert_eq!(p.registers.read(0x204004), 35);
    }
    #[test]
    #[should_panic]
    fn source_zero_cannot_be_enabled() {
        Plic::new(Fake::default(), 136).set_enabled(0, 0, true);
    }
}
