#![no_std]
//! 16550 and DesignWare APB register engine. No kernel queues or locks.
use vibeos_hal::{devices::ConsoleInterrupt, UartDescription};

pub trait Registers {
    fn read(&self, index: usize) -> u8;
    fn write(&self, index: usize, value: u8);
}

pub struct Mmio(UartDescription);
impl Mmio {
    /// # Safety
    /// The complete register aperture must be mapped as device memory and
    /// remain available. The caller serializes TX/configuration and gives RX
    /// to one consumer; no other owner may reconfigure this UART.
    pub const unsafe fn new(description: UartDescription) -> Self {
        assert!(description.register_width == 1 || description.register_width == 4);
        assert!(description.register_shift < usize::BITS as usize - 5);
        assert!(description.registers.start % description.register_width == 0);
        assert!(
            description.registers.len()
                >= (0x1f << description.register_shift) + description.register_width
        );
        assert!(divisor(description.clock_hz, description.baud).is_some());
        Self(description)
    }
}
impl Registers for Mmio {
    fn read(&self, index: usize) -> u8 {
        assert!(index <= 0x1f);
        let address = self.0.registers.start + (index << self.0.register_shift);
        // SAFETY: constructor establishes mapping, access width and lifetime.
        unsafe {
            match self.0.register_width {
                1 => (address as *const u8).read_volatile(),
                4 => (address as *const u32).read_volatile() as u8,
                _ => unreachable!(),
            }
        }
    }
    fn write(&self, index: usize, value: u8) {
        assert!(index <= 0x1f);
        let address = self.0.registers.start + (index << self.0.register_shift);
        unsafe {
            match self.0.register_width {
                1 => (address as *mut u8).write_volatile(value),
                4 => (address as *mut u32).write_volatile(u32::from(value)),
                _ => unreachable!(),
            }
        }
    }
}

pub const fn divisor(clock: u32, baud: u32) -> Option<u16> {
    if baud == 0 {
        return None;
    }
    let value = (clock as u64 + baud as u64 * 8) / (baud as u64 * 16);
    if value == 0 || value > u16::MAX as u64 {
        None
    } else {
        Some(value as u16)
    }
}

pub struct Uart<R> {
    registers: R,
    description: UartDescription,
}
impl<R: Registers> Uart<R> {
    pub const fn new(registers: R, description: UartDescription) -> Self {
        Self {
            registers,
            description,
        }
    }
    pub fn init(&self) {
        let divisor = divisor(self.description.clock_hz, self.description.baud)
            .expect("invalid UART baud divisor");
        let r = &self.registers;
        r.write(1, 0);
        self.drain();
        if self.description.quirks.busy_detect {
            while r.read(0x1f) & 1 != 0 {
                core::hint::spin_loop();
            }
        }
        r.write(3, 0x80);
        r.write(0, divisor as u8);
        r.write(1, (divisor >> 8) as u8);
        r.write(3, 3);
        r.write(2, 7);
        if self.description.quirks.busy_detect {
            let _ = r.read(0x1f);
        }
        r.write(1, 1);
    }
    pub fn write_byte(&self, byte: u8) {
        while self.registers.read(5) & 0x20 == 0 {
            core::hint::spin_loop();
        }
        self.registers.write(0, byte);
    }
    pub fn drain(&self) {
        while self.registers.read(5) & 0x40 == 0 {
            core::hint::spin_loop();
        }
    }
    pub fn interrupt(&self) -> ConsoleInterrupt {
        let r = &self.registers;
        let cause = r.read(2);
        if self.description.quirks.busy_detect && cause & 0x3f == 7 {
            let _ = r.read(0x1f);
            return ConsoleInterrupt::BusyCleared;
        }
        if cause & 1 != 0 {
            return ConsoleInterrupt::None;
        }
        if self.description.quirks.phantom_rx_timeout
            && cause & 0x3f == 0x0c
            && r.read(5) & 0x11 == 0
        {
            let _ = r.read(0);
            return ConsoleInterrupt::PhantomTimeoutCleared;
        }
        ConsoleInterrupt::Receive
    }
    pub fn read_byte(&self) -> Option<u8> {
        (self.registers.read(5) & 1 != 0).then(|| self.registers.read(0))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::RefCell;
    use std::vec::Vec;
    use vibeos_hal::{AddressRange, UartQuirks, UartVariant};
    struct Fake {
        values: [u8; 32],
        trace: RefCell<Vec<(bool, usize, u8)>>,
    }
    impl Registers for Fake {
        fn read(&self, i: usize) -> u8 {
            self.trace.borrow_mut().push((false, i, self.values[i]));
            self.values[i]
        }
        fn write(&self, i: usize, v: u8) {
            self.trace.borrow_mut().push((true, i, v));
        }
    }
    fn uart(cause: u8, status: u8) -> Uart<Fake> {
        let mut values = [0; 32];
        values[2] = cause;
        values[5] = status;
        Uart::new(
            Fake {
                values,
                trace: RefCell::new(Vec::new()),
            },
            UartDescription {
                variant: UartVariant::DesignWareApb,
                registers: AddressRange::new(0, 4096),
                irq: 1,
                register_shift: 2,
                register_width: 4,
                clock_hz: 25_000_000,
                baud: 115_200,
                quirks: UartQuirks::DESIGNWARE_APB,
            },
        )
    }
    #[test]
    fn divisor_bounds_and_rounding() {
        assert_eq!(divisor(1_843_200, 38_400), Some(3));
        assert_eq!(divisor(25_000_000, 115_200), Some(14));
        assert_eq!(divisor(0, 115_200), None);
        assert_eq!(divisor(u32::MAX, 0), None);
        assert_eq!(divisor(u32::MAX, 1), None);
    }
    #[test]
    fn busy_irq_acknowledges_usr_even_with_no_interrupt_bit() {
        let u = uart(7, 0);
        assert_eq!(u.interrupt(), ConsoleInterrupt::BusyCleared);
        assert_eq!(u.registers.trace.borrow().last().unwrap().1, 0x1f);
    }
    #[test]
    fn phantom_timeout_drains_rbr_but_real_data_is_preserved() {
        let u = uart(12, 0);
        assert_eq!(u.interrupt(), ConsoleInterrupt::PhantomTimeoutCleared);
        assert_eq!(u.registers.trace.borrow().last().unwrap().1, 0);
        let u = uart(12, 1);
        assert_eq!(u.interrupt(), ConsoleInterrupt::Receive);
        assert!(!u.registers.trace.borrow().iter().any(|x| x.1 == 0));
        let u = uart(12, 16);
        assert_eq!(u.interrupt(), ConsoleInterrupt::Receive);
    }
    #[test]
    fn configuration_masks_interrupts_and_finishes_with_rx_enabled() {
        let u = uart(1, 0x60);
        u.init();
        let writes: Vec<_> = u
            .registers
            .trace
            .borrow()
            .iter()
            .copied()
            .filter(|x| x.0)
            .collect();
        assert_eq!(
            writes,
            std::vec![
                (true, 1, 0),
                (true, 3, 128),
                (true, 0, 14),
                (true, 1, 0),
                (true, 3, 3),
                (true, 2, 7),
                (true, 1, 1)
            ]
        );
    }
    #[test]
    fn empty_rx_does_not_read_receive_buffer() {
        let u = uart(1, 0);
        assert_eq!(u.read_byte(), None);
        assert_eq!(u.registers.trace.borrow().len(), 1);
    }
}
