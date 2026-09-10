//! CV1800B Ethernet clocks, integrated PHY tuning and eFuse calibration.
use vibeos_hal::{
    network::{Error, PlatformTelemetry},
    AddressRange,
};
pub trait Registers {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&self, offset: usize, value: u32);
    fn efuse32(&self, offset: usize) -> u32;
    fn delay_ms(&self, ms: u64);
}
pub struct Mmio {
    soc: usize,
    efuse: usize,
    hz: u64,
    time: fn() -> u64,
    _not_sync: core::marker::PhantomData<core::cell::Cell<()>>,
}
impl Mmio {
    /// # Safety
    /// Both ranges are mapped CV1800B apertures; the caller exclusively owns
    /// Ethernet clock and PHY changes for the lifetime of these operations.
    pub unsafe fn new(
        soc: AddressRange,
        efuse: AddressRange,
        hz: u64,
        time: fn() -> u64,
    ) -> Result<Self, Error> {
        if soc.start % 4 != 0
            || efuse.start % 4 != 0
            || hz < 1000
            || soc.end.checked_sub(soc.start).is_none_or(|n| n < 0xa000)
            || efuse.end.checked_sub(efuse.start).is_none_or(|n| n < 0x128)
        {
            return Err(Error::InvalidDescription);
        }
        Ok(Self {
            soc: soc.start,
            efuse: efuse.start,
            hz,
            time,
            _not_sync: core::marker::PhantomData,
        })
    }
}
impl Registers for Mmio {
    fn read32(&self, o: usize) -> u32 {
        assert!(o % 4 == 0 && o <= 0x9ffc);
        unsafe { ((self.soc + o) as *const u32).read_volatile() }
    }
    fn write32(&self, o: usize, v: u32) {
        assert!(o % 4 == 0 && o <= 0x9ffc);
        unsafe { ((self.soc + o) as *mut u32).write_volatile(v) }
    }
    fn efuse32(&self, o: usize) -> u32 {
        assert!(o == 0x120 || o == 0x124);
        unsafe { ((self.efuse + o) as *const u32).read_volatile() }
    }
    fn delay_ms(&self, ms: u64) {
        let start = (self.time)();
        let ticks = ms.saturating_mul(self.hz) / 1000;
        while (self.time)().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }
}
pub struct Ethernet<R: Registers>(pub R);
// CV1800B EPHY page 10 link-pulse tuning. The alternate values shipped next
// to the original Milk-V settings explicitly fix a latched link-up indication
// after the cable is removed.
const EPHY_LINK_PULSE: &[(usize, u32)] = &[
    (0x40, 0x2000),
    (0x44, 0x3832),
    (0x48, 0x3132),
    (0x4c, 0x2d2f),
    (0x50, 0x2c2d),
    (0x54, 0x1b2b),
    (0x58, 0x94a0),
    (0x5c, 0x8990),
    (0x60, 0x8788),
    (0x64, 0x8485),
    (0x68, 0x8283),
    (0x6c, 0x8182),
    (0x70, 0x0081),
];

impl<R: Registers> Ethernet<R> {
    pub fn prepare(&mut self) {
        let clk = 0x2000;
        self.0.write32(
            clk,
            self.0.read32(clk) | ((1 << 11) | (1 << 25) | (1 << 26)),
        );
        self.0
            .write32(clk + 0x30, self.0.read32(clk + 0x30) & !(1 << 9));
        self.0.write32(
            clk + 0x8c,
            (self.0.read32(clk + 0x8c) & !(0xf << 16)) | (3 << 16) | (1 << 3),
        );
        self.prepare_ephy();
        let _ = self.0.read32(clk);
    }
    fn prepare_ephy(&self) {
        let base = 0x9000;
        let top = base + 0x800;
        self.0.write32(top + 4, 1);
        self.0.write32(top, 0x0900);
        self.0.write32(top, 0x0904);
        self.0.delay_ms(10);
        self.page(base, 5);
        self.ew(base, 0x40, 0x0c7e);
        self.0.delay_ms(1);
        self.0.write32(top, 0x0906);
        self.page(base, 0);
        let e20 = self.0.efuse32(0x120);
        let e24 = self.0.efuse32(0x124);
        self.ew(
            base,
            0x64,
            if e20 & 0x200 != 0 {
                (e24 >> 24 & 0xff) | (e24 >> 8 & 0xff00)
            } else {
                0x5a5a
            },
        );
        self.ew(base, 0x54, if e20 & 0x100 != 0 { e24 & 0xff00 } else { 0 });
        let term = if e20 & 0x800 != 0 {
            ((e20 >> 24) & 0xf0) | ((e20 >> 16) & 0xf00)
        } else {
            0xbb0
        };
        self.ew(base, 0x58, (self.er(base, 0x58) & !0xff0) | term);
        self.ew(base, 0x5c, 0xc10);
        self.ew(base, 0x68, 3);
        self.ew(base, 0x54, 0);
        self.table(
            base,
            16,
            &[
                (0x68, 0x1000),
                (0x6c, 0x3020),
                (0x70, 0x5040),
                (0x74, 0x7060),
                (0x58, 0x1708),
                (0x5c, 0x3827),
                (0x60, 0x5748),
                (0x64, 0x7867),
            ],
        );
        self.table(
            base,
            17,
            &[
                (0x40, 0x9080),
                (0x44, 0xb0a0),
                (0x48, 0xd0c0),
                (0x4c, 0xf0e0),
                (0x50, 0x9788),
                (0x54, 0xb8a7),
                (0x58, 0xd7c8),
                (0x5c, 0xf8e7),
            ],
        );
        self.page(base, 5);
        self.ew(base, 0x40, self.er(base, 0x40) | 1);
        self.ew(base, 0x4c, self.er(base, 0x4c) | 0x820);
        self.table(base, 10, EPHY_LINK_PULSE);
        self.table(
            base,
            11,
            &[
                (0x40, 0x5252),
                (0x44, 0x5252),
                (0x48, 0x4b52),
                (0x4c, 0x3d47),
                (0x50, 0xaa99),
                (0x54, 0x989e),
                (0x58, 0x9395),
                (0x5c, 0x9091),
                (0x60, 0x8e8f),
                (0x64, 0x8d8e),
                (0x68, 0x8c8c),
                (0x6c, 0x8b8b),
                (0x70, 0x8a),
            ],
        );
        self.table(
            base,
            13,
            &[
                (0x40, 0x1e0a),
                (0x44, 0x3862),
                (0x48, 0x1e62),
                (0x4c, 0x2a08),
                (0x50, 0x244c),
                (0x54, 0x1a44),
                (0x58, 0x61c),
            ],
        );
        self.table(
            base,
            14,
            &[
                (0x40, 0x2d30),
                (0x44, 0x3470),
                (0x48, 0x648),
                (0x4c, 0x261c),
                (0x50, 0x3160),
                (0x54, 0x2d5e),
            ],
        );
        self.table(
            base,
            15,
            &[
                (0x40, 0x2922),
                (0x44, 0x366e),
                (0x48, 0x752),
                (0x4c, 0x2556),
                (0x50, 0x2348),
                (0x54, 0xc30),
            ],
        );
        self.table(
            base,
            16,
            &[
                (0x40, 0x1e08),
                (0x44, 0x3868),
                (0x48, 0x1462),
                (0x4c, 0x1a0e),
                (0x50, 0x305e),
                (0x54, 0x2f62),
            ],
        );
        self.page(base, 1);
        self.ew(base, 0x68, self.er(base, 0x68) & !0xf00);
        self.table(base, 19, &[(0x58, 0x12), (0x5c, 0x6848)]);
        self.table(
            base,
            18,
            &[
                (0x48, 0x801),
                (0x4c, 0x1717),
                (0x5c, 0x108),
                (0x50, 0x3afc),
                (0x54, 0x8d3),
                (0x60, 0xfb),
            ],
        );
        self.page(base, 0);
        self.0.write32(top, 0x090e);
        self.ew(base, 0, self.er(base, 0) | 0x100);
        self.0.write32(top + 4, 0);
    }
    fn table(&self, base: usize, p: u32, v: &[(usize, u32)]) {
        self.page(base, p);
        for &(o, x) in v {
            self.ew(base, o, x)
        }
    }
    fn page(&self, base: usize, p: u32) {
        self.0.write32(base + 0x7c, p << 8)
    }
    fn er(&self, base: usize, o: usize) -> u32 {
        self.0.read32(base + o)
    }
    fn ew(&self, base: usize, o: usize, v: u32) {
        self.0.write32(base + o, v)
    }
    pub fn telemetry(&self) -> PlatformTelemetry {
        PlatformTelemetry {
            clock_enable: self.0.read32(0x2000),
            clock_bypass: self.0.read32(0x2030),
            clock_divider: self.0.read32(0x208c),
            ephy_control: self.0.read32(0x9800),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{cell::RefCell, collections::BTreeMap, vec::Vec};
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Write(usize, u32),
        Delay(u64),
    }
    struct Fake {
        registers: RefCell<BTreeMap<usize, u32>>,
        events: RefCell<Vec<Event>>,
        fuse: [u32; 2],
    }
    impl Registers for Fake {
        fn read32(&self, o: usize) -> u32 {
            *self.registers.borrow().get(&o).unwrap_or(&0)
        }
        fn write32(&self, o: usize, v: u32) {
            self.registers.borrow_mut().insert(o, v);
            self.events.borrow_mut().push(Event::Write(o, v));
        }
        fn efuse32(&self, o: usize) -> u32 {
            self.fuse[(o - 0x120) / 4]
        }
        fn delay_ms(&self, ms: u64) {
            self.events.borrow_mut().push(Event::Delay(ms));
        }
    }
    // This verifies the register sequence, not physical PHY/link behavior.
    #[test]
    fn clock_phy_sequence_preserves_calibration_and_link_removal_tuning() {
        use std::fmt::Write;
        let mut trace = std::string::String::new();
        for fuse in [[0, 0], [0xabc0_0b00, 0x1234_5678]] {
            let mut eth = Ethernet(Fake {
                registers: RefCell::new(BTreeMap::from([
                    (0x2000, 1),
                    (0x2030, 0x601),
                    (0x208c, 0xf0000),
                ])),
                events: RefCell::new(Vec::new()),
                fuse,
            });
            eth.prepare();
            let events = eth.0.events.borrow();
            assert_eq!(
                &events[..8],
                &[
                    Event::Write(0x2000, 1 | (1 << 11) | (1 << 25) | (1 << 26)),
                    Event::Write(0x2030, 0x401),
                    Event::Write(0x208c, 0x30008),
                    Event::Write(0x9804, 1),
                    Event::Write(0x9800, 0x900),
                    Event::Write(0x9800, 0x904),
                    Event::Delay(10),
                    Event::Write(0x907c, 5 << 8)
                ]
            );
            assert!(events.windows(3).any(|e| e
                == [
                    Event::Write(0x9040, 0xc7e),
                    Event::Delay(1),
                    Event::Write(0x9800, 0x906)
                ]));
            let calibration = if fuse[0] == 0 {
                0x5a5a
            } else {
                (fuse[1] >> 24 & 0xff) | (fuse[1] >> 8 & 0xff00)
            };
            assert!(events.contains(&Event::Write(0x9064, calibration)));
            let term = if fuse[0] == 0 {
                0xbb0
            } else {
                ((fuse[0] >> 24) & 0xf0) | ((fuse[0] >> 16) & 0xf00)
            };
            assert!(events.contains(&Event::Write(0x9058, term)));
            let page10 = events
                .iter()
                .position(|e| *e == Event::Write(0x907c, 10 << 8))
                .unwrap();
            assert_eq!(events[page10 + 1], Event::Write(0x9040, 0x2000));
            assert_eq!(events[page10 + 7], Event::Write(0x9058, 0x94a0));
            assert_eq!(events[page10 + 13], Event::Write(0x9070, 0x81));
            assert_eq!(
                &events[events.len() - 4..],
                &[
                    Event::Write(0x907c, 0),
                    Event::Write(0x9800, 0x90e),
                    Event::Write(0x9000, 0x100),
                    Event::Write(0x9804, 0)
                ]
            );
            assert_eq!(eth.telemetry().ephy_control, 0x90e);
            writeln!(trace, "F {:08x} {:08x}", fuse[0], fuse[1]).unwrap();
            for event in events.iter() {
                match event {
                    Event::Write(a, v) => writeln!(trace, "W {a:04x} {v:08x}").unwrap(),
                    Event::Delay(ms) => writeln!(trace, "D {ms}").unwrap(),
                }
            }
        }
        // Captured from e831630's unmodified register algorithm using mocked
        // MMIO and delays; the fixture covers every write in both fuse paths.
        assert_eq!(trace, include_str!("../tests/ethernet-sequence.txt"));
    }
    #[test]
    fn rejects_invalid_resources_before_register_access() {
        for (soc, efuse, hz) in [
            (
                AddressRange::new(0x1001, 0xb001),
                AddressRange::new(0, 0x128),
                1000,
            ),
            (
                AddressRange::new(0, 0x999c),
                AddressRange::new(0, 0x128),
                1000,
            ),
            (
                AddressRange::new(0, 0xa000),
                AddressRange::new(0, 0x124),
                1000,
            ),
            (AddressRange::new(0, 0xa000), AddressRange::new(0, 0x128), 0),
        ] {
            assert!(unsafe { Mmio::new(soc, efuse, hz, || 0) }.is_err());
        }
    }
}
