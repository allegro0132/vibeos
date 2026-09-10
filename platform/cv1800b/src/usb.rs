//! CV1800B USB clock/role/UTMI wrapper sequence and initialization rollback.
use core::sync::atomic::{compiler_fence, Ordering};
use vibeos_hal::{
    usb_polling::{Error, PlatformState, PlatformTelemetry},
    AddressRange,
};
const ROLE: usize = 0x48;
const CLOCK1: usize = 0x2004;
const CLOCK2: usize = 0x2008;
const UTMI: usize = 0x14;
pub trait Registers {
    fn read_soc(&self, offset: usize) -> u32;
    fn write_soc(&self, offset: usize, value: u32);
    fn read_phy(&self, offset: usize) -> u32;
    fn write_phy(&self, offset: usize, value: u32);
    fn delay_us(&self, us: u64);
}
pub struct Mmio {
    soc: usize,
    phy: usize,
    hz: u64,
    time: fn() -> u64,
    _not_sync: core::marker::PhantomData<core::cell::Cell<()>>,
}
impl Mmio {
    /// # Safety
    /// These mapped CV1800B apertures are exclusively assigned to this USB
    /// instance; no concurrent initializer may modify the clocks/role/PHY.
    pub unsafe fn new(
        soc: AddressRange,
        phy: AddressRange,
        hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        if soc.start % 4 != 0
            || phy.start % 4 != 0
            || hz == 0
            || soc.end.checked_sub(soc.start).is_none_or(|n| n < 0x200c)
            || phy.end.checked_sub(phy.start).is_none_or(|n| n < 0x18)
        {
            return Err(Error::InvalidDescription);
        }
        Ok(Self {
            soc: soc.start,
            phy: phy.start,
            hz,
            time,
            _not_sync: core::marker::PhantomData,
        })
    }
}
impl Registers for Mmio {
    fn read_soc(&self, o: usize) -> u32 {
        assert!(matches!(o, ROLE | CLOCK1 | CLOCK2));
        unsafe { ((self.soc + o) as *const u32).read_volatile() }
    }
    fn write_soc(&self, o: usize, v: u32) {
        assert!(matches!(o, ROLE | CLOCK1 | CLOCK2));
        unsafe { ((self.soc + o) as *mut u32).write_volatile(v) }
    }
    fn read_phy(&self, o: usize) -> u32 {
        assert_eq!(o, UTMI);
        unsafe { ((self.phy + o) as *const u32).read_volatile() }
    }
    fn write_phy(&self, o: usize, v: u32) {
        assert_eq!(o, UTMI);
        unsafe { ((self.phy + o) as *mut u32).write_volatile(v) }
    }
    fn delay_us(&self, us: u64) {
        let start = (self.time)();
        let ticks = (self.hz.saturating_mul(us).saturating_add(999_999) / 1_000_000).max(1);
        while (self.time)().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}
pub struct Usb<R: Registers>(pub R);
impl<R: Registers> Usb<R> {
    pub fn prepare(&mut self) -> PlatformState {
        let c1 = self.0.read_soc(CLOCK1);
        let c2 = self.0.read_soc(CLOCK2);
        let role = self.0.read_soc(ROLE);
        self.0.write_soc(CLOCK1, c1 | 0xf000_0000);
        self.0.write_soc(CLOCK2, c2 | 1);
        self.0.write_soc(ROLE, (role & !0xc0) | 0x40 | 2);
        let utmi = self.0.read_phy(UTMI);
        self.0.write_phy(UTMI, 0x18b);
        compiler_fence(Ordering::SeqCst);
        self.0.write_phy(UTMI, utmi);
        compiler_fence(Ordering::SeqCst);
        self.0.delay_us(100);
        PlatformState([c1 as usize, c2 as usize, role as usize, 0])
    }
    pub fn rollback(&mut self, saved: PlatformState) {
        let [c1, c2, role, _] = saved.0;
        self.0.write_soc(ROLE, role as u32);
        self.0.write_soc(CLOCK2, c2 as u32);
        self.0.write_soc(CLOCK1, c1 as u32);
    }
    pub fn telemetry(&self) -> PlatformTelemetry {
        PlatformTelemetry {
            clock_enable_1: self.0.read_soc(CLOCK1),
            clock_enable_2: self.0.read_soc(CLOCK2),
            role_override: self.0.read_soc(ROLE),
            phy_utmi_control: self.0.read_phy(UTMI),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap, vec::Vec};
    #[derive(Debug, Eq, PartialEq)]
    enum Event {
        Soc(usize, u32),
        Phy(u32),
        Delay(u64),
    }
    struct Fake {
        soc: RefCell<BTreeMap<usize, u32>>,
        phy: RefCell<u32>,
        events: RefCell<Vec<Event>>,
    }
    impl Registers for Fake {
        fn read_soc(&self, o: usize) -> u32 {
            *self.soc.borrow().get(&o).unwrap()
        }
        fn write_soc(&self, o: usize, v: u32) {
            self.soc.borrow_mut().insert(o, v);
            self.events.borrow_mut().push(Event::Soc(o, v));
        }
        fn read_phy(&self, o: usize) -> u32 {
            assert_eq!(o, UTMI);
            *self.phy.borrow()
        }
        fn write_phy(&self, o: usize, v: u32) {
            assert_eq!(o, UTMI);
            *self.phy.borrow_mut() = v;
            self.events.borrow_mut().push(Event::Phy(v));
        }
        fn delay_us(&self, v: u64) {
            self.events.borrow_mut().push(Event::Delay(v));
        }
    }
    // Register/order test only; this cannot establish physical UTMI timing.
    #[test]
    fn prepare_and_rollback_preserve_original_clock_role_and_utmi_state() {
        let mut usb = Usb(Fake {
            soc: RefCell::new(BTreeMap::from([
                (CLOCK1, 0x1234),
                (CLOCK2, 0xa0),
                (ROLE, 0x185),
            ])),
            phy: RefCell::new(0x123),
            events: RefCell::new(Vec::new()),
        });
        for _ in 0..2 {
            usb.0.events.borrow_mut().clear();
            let saved = usb.prepare();
            assert_eq!(
                usb.telemetry(),
                PlatformTelemetry {
                    clock_enable_1: 0xf0001234,
                    clock_enable_2: 0xa1,
                    role_override: 0x147,
                    phy_utmi_control: 0x123
                }
            );
            usb.rollback(saved);
            assert_eq!(
                *usb.0.events.borrow(),
                [
                    Event::Soc(CLOCK1, 0xf0001234),
                    Event::Soc(CLOCK2, 0xa1),
                    Event::Soc(ROLE, 0x147),
                    Event::Phy(0x18b),
                    Event::Phy(0x123),
                    Event::Delay(100),
                    Event::Soc(ROLE, 0x185),
                    Event::Soc(CLOCK2, 0xa0),
                    Event::Soc(CLOCK1, 0x1234)
                ]
            );
            assert_eq!(
                usb.telemetry(),
                PlatformTelemetry {
                    clock_enable_1: 0x1234,
                    clock_enable_2: 0xa0,
                    role_override: 0x185,
                    phy_utmi_control: 0x123
                }
            );
        }
    }
    #[test]
    fn invalid_apertures_are_rejected_before_access() {
        for (soc, phy, hz) in [
            (AddressRange::new(1, 0x3001), AddressRange::new(0, 0x18), 1),
            (AddressRange::new(0, 0x2008), AddressRange::new(0, 0x18), 1),
            (AddressRange::new(0, 0x200c), AddressRange::new(0, 0x14), 1),
            (AddressRange::new(0, 0x200c), AddressRange::new(0, 0x18), 0),
        ] {
            assert!(unsafe { Mmio::new(soc, phy, hz, || 0) }.is_err());
        }
    }
    #[test]
    fn delay_preserves_minimum_tick_and_handles_timer_wrap() {
        use core::sync::atomic::{AtomicU64, Ordering::SeqCst};
        static TIME: AtomicU64 = AtomicU64::new(0);
        fn time() -> u64 {
            TIME.fetch_add(1, SeqCst)
        }
        let mmio = unsafe {
            Mmio::new(
                AddressRange::new(0, 0x200c),
                AddressRange::new(0, 0x18),
                1_000_000,
                time,
            )
        }
        .unwrap();
        for us in [0u64, 100] {
            let start = u64::MAX - 3;
            TIME.store(start, SeqCst);
            mmio.delay_us(us);
            assert_eq!(TIME.load(SeqCst), start.wrapping_add(us.max(1) + 1));
        }
    }
}
