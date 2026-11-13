//! SDIO0 clock, pad mux and slot power sequence moved from the SDHCI engine.
use vibeos_hal::{
    block::{Error, SdPlatform},
    AddressRange,
};
const PINMUX: usize = 0x1000;
const CLOCKS: u32 = (1 << 18) | (1 << 19) | (1 << 20);
pub trait Registers {
    fn read8(&mut self, offset: usize) -> u8;
    fn write8(&mut self, offset: usize, value: u8);
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn delay_ms(&mut self, milliseconds: u64);
}
pub struct Mmio {
    base: usize,
    hz: u64,
    time: fn() -> u64,
}
impl Mmio {
    /// # Safety
    /// The caller owns the mapped CV1800B TOP block and SDIO0 pads/clocks.
    /// No other controller or CPU may concurrently change these resources.
    pub unsafe fn new(range: AddressRange, hz: u64, time: fn() -> u64) -> Result<Self, Error> {
        if range.start % 4 != 0
            || range
                .end
                .checked_sub(range.start)
                .filter(|len| *len >= 0x3000)
                .is_none()
            || hz < 1000
        {
            return Err(Error::InvalidConfiguration);
        }
        Ok(Self {
            base: range.start,
            hz,
            time,
        })
    }
}
impl Registers for Mmio {
    fn read8(&mut self, offset: usize) -> u8 {
        assert!(offset < 0x3000);
        unsafe { ((self.base + offset) as *const u8).read_volatile() }
    }
    fn write8(&mut self, offset: usize, value: u8) {
        assert!(offset < 0x3000);
        unsafe { ((self.base + offset) as *mut u8).write_volatile(value) }
    }
    fn read32(&mut self, offset: usize) -> u32 {
        assert!(offset % 4 == 0 && offset <= 0x2ffc);
        unsafe { ((self.base + offset) as *const u32).read_volatile() }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        assert!(offset % 4 == 0 && offset <= 0x2ffc);
        unsafe { ((self.base + offset) as *mut u32).write_volatile(value) }
    }
    fn delay_ms(&mut self, milliseconds: u64) {
        let ticks = milliseconds.saturating_mul(self.hz) / 1000;
        let start = (self.time)();
        while (self.time)().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}
pub struct SdSlot<R: Registers>(pub R);
impl<R: Registers> SdSlot<R> {
    fn function(&mut self, function: u8) {
        self.0.write8(PINMUX + 0x18, 0);
        self.0.write8(PINMUX + 0x1c, 0);
        for offset in [0, 4, 8, 12, 16, 20] {
            self.0.write8(PINMUX + offset, function);
        }
    }
    fn pull(&mut self, offset: usize, up: bool) {
        let value = self.0.read8(PINMUX + offset) & !((1 << 2) | (1 << 3));
        self.0
            .write8(PINMUX + offset, value | if up { 1 << 2 } else { 1 << 3 });
    }
    fn bias(&mut self, online: bool) {
        self.pull(0x900, true);
        self.pull(0x904, false);
        self.pull(0xa00, false);
        for offset in [0xa04, 0xa08, 0xa0c, 0xa10, 0xa14] {
            self.pull(offset, online);
        }
    }
}
impl<R: Registers> SdPlatform for SdSlot<R> {
    fn prepare_clock(&mut self) {
        let enable = self.0.read32(0x2000);
        self.0.write32(0x2000, enable | CLOCKS);
        let bypass = self.0.read32(0x2030);
        self.0.write32(0x2030, bypass & !(1 << 6));
        self.0.write32(0x2070, 0x0004_0009);
    }
    fn power_off(&mut self) {
        self.function(3);
        self.bias(false);
        let power = self.0.read32(0x1f4);
        self.0.write32(0x1f4, (power & !0xf) | 0xe);
        self.0.delay_ms(30);
    }
    fn power_on(&mut self) {
        let power = self.0.read32(0x1f4);
        self.0.write32(0x1f4, (power & !0xf) | 9);
        self.0.delay_ms(1);
        self.function(0);
        self.bias(true);
        self.0.delay_ms(5);
    }
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    struct Fake {
        bytes: [u8; 0x3000],
        delays: std::vec::Vec<u64>,
    }
    impl Registers for Fake {
        fn read8(&mut self, o: usize) -> u8 {
            self.bytes[o]
        }
        fn write8(&mut self, o: usize, v: u8) {
            self.bytes[o] = v;
        }
        fn read32(&mut self, o: usize) -> u32 {
            u32::from_le_bytes(self.bytes[o..o + 4].try_into().unwrap())
        }
        fn write32(&mut self, o: usize, v: u32) {
            self.bytes[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn delay_ms(&mut self, ms: u64) {
            self.delays.push(ms);
        }
    }
    #[test]
    fn slot_power_cycle_preserves_unrelated_bits_and_settling_delays() {
        let mut slot = SdSlot(Fake {
            bytes: [0xff; 0x3000],
            delays: std::vec::Vec::new(),
        });
        slot.0.write32(0x2000, 0x101);
        slot.prepare_clock();
        assert_eq!(slot.0.read32(0x2000), 0x001c_0101);
        assert_eq!(slot.0.read32(0x2030), u32::MAX & !(1 << 6));
        assert_eq!(slot.0.read32(0x2070), 0x40009);
        slot.power_off();
        assert_eq!(slot.0.read32(0x1f4), 0xfffffffe);
        for offset in [0, 4, 8, 12, 16, 20] {
            assert_eq!(slot.0.read8(PINMUX + offset), 3);
        }
        assert_eq!(slot.0.read8(PINMUX + 0xa04), 0xfb);
        assert_eq!(slot.0.delays, [30]);
        slot.power_on();
        assert_eq!(slot.0.read32(0x1f4), 0xfffffff9);
        for offset in [0, 4, 8, 12, 16, 20] {
            assert_eq!(slot.0.read8(PINMUX + offset), 0);
        }
        assert_eq!(slot.0.read8(PINMUX + 0xa04), 0xf7);
        assert_eq!(slot.0.read8(PINMUX + 0xa00), 0xfb);
        assert_eq!(slot.0.delays, [30, 1, 5]);
    }
    #[test]
    fn settling_delay_crosses_counter_wrap() {
        use core::sync::atomic::{AtomicU64, Ordering};
        static TICKS: AtomicU64 = AtomicU64::new(u64::MAX - 2);
        let mut io = unsafe {
            Mmio::new(AddressRange::new(0, 0x3000), 1000, || {
                TICKS.fetch_add(1, Ordering::Relaxed)
            })
        }
        .unwrap();
        io.delay_ms(5);
        assert_eq!(TICKS.load(Ordering::Relaxed), 3);
    }
    #[test]
    fn rejects_invalid_mapping_before_mmio() {
        for range in [
            AddressRange::new(0, 0x2000),
            AddressRange::new(1, 0x4000),
            AddressRange::new(0x4000, 0),
        ] {
            assert!(unsafe { Mmio::new(range, 1000, || 0) }.is_err());
        }
        assert!(unsafe { Mmio::new(AddressRange::new(0, 0x3000), 0, || 0) }.is_err());
    }
}
