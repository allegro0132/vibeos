//! Register-model checks do not model clocks, pins, reset synchronizers or media.
use std::collections::BTreeMap;
use vibeos_platform_jh7110::sd::{clock_plan, prepare, Bank, Error, Pins, Prepared};
const PINS: Pins = Pins([10, 9, 11, 12, 7, 8]);
const RESET: usize = 0x300;
const STATUS: usize = 0x310;
const CARD: usize = 0x178;
const GATE: u32 = 1 << 31;
struct Model {
    words: BTreeMap<(u8, usize), u32>,
    writes: Vec<(Bank, usize, u32, u64)>,
    now: u64,
    stall_assert: bool,
    stall_release: bool,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: BTreeMap::new(),
            writes: vec![],
            now: 0,
            stall_assert: false,
            stall_release: false,
        };
        for offset in (0..0x2b4).step_by(4) {
            m.set(Bank::Pins, offset, 0xa5a5a5a5);
        }
        for (offset, value) in [
            (0x14, 1 << 24),
            (0x1c, 3),
            (0x20, 2),
            (0x24, GATE),
            (0x170, 0x1234),
            (CARD, 0x4000010b),
            (RESET, 0xdeadbeed),
            (STATUS, 0xffffffff),
        ] {
            m.set(Bank::Crg, offset, value);
        }
        for (offset, value) in [(0x2c, (3 << 15) | (99 << 17)), (0x30, 0), (0x34, 2)] {
            m.set(Bank::Syscon, offset, value);
        }
        m
    }
    fn set(&mut self, b: Bank, o: usize, v: u32) {
        self.words.insert((b as u8, o), v);
    }
    fn get(&self, b: Bank, o: usize) -> u32 {
        self.words.get(&(b as u8, o)).copied().unwrap_or(0)
    }
}
impl vibeos_platform_jh7110::sd::Registers for Model {
    fn read(&mut self, b: Bank, o: usize) -> u32 {
        self.get(b, o)
    }
    fn write(&mut self, b: Bank, o: usize, v: u32) {
        self.writes.push((b, o, v, self.now));
        self.set(b, o, v);
        if b == Bank::Crg && o == RESET {
            let assert = v & 2 != 0;
            if !(assert && self.stall_assert || !assert && self.stall_release) {
                self.set(
                    b,
                    STATUS,
                    (self.get(b, STATUS) & !2) | if assert { 0 } else { 2 },
                );
            }
        }
    }
    fn ticks(&mut self) -> u64 {
        self.now = self.now.wrapping_add(10_000);
        self.now
    }
}
#[test]
fn actual_rate_is_derived_without_nominal_frequency_fallback() {
    let mut m = Model::new();
    assert_eq!(
        clock_plan(&mut m),
        Ok(Prepared {
            parent_hz: 396_000_000,
            source_hz: 49_500_000,
            divider: 8
        })
    );
    assert!(m.writes.is_empty());
    m.set(Bank::Syscon, 0x2c, (3 << 15) | (768 << 17));
    m.set(Bank::Syscon, 0x34, 15);
    assert_eq!(clock_plan(&mut m).unwrap().source_hz, 45_511_111);
    m.set(Bank::Crg, 0x14, 0);
    m.set(Bank::Crg, 0x1c, 1);
    assert_eq!(
        clock_plan(&mut m),
        Ok(Prepared {
            parent_hz: 24_000_000,
            source_hz: 24_000_000,
            divider: 1
        })
    );
}
#[test]
fn invalid_clock_or_wiring_never_changes_hardware() {
    for (bank, offset, value) in [
        (Bank::Syscon, 0x2c, 99 << 17),
        (Bank::Syscon, 0x30, 1 << 27),
        (Bank::Syscon, 0x34, 0),
        (Bank::Crg, 0x1c, 0),
        (Bank::Crg, 0x20, 0),
        (Bank::Crg, 0x24, 0),
    ] {
        let mut m = Model::new();
        m.set(bank, offset, value);
        assert_eq!(
            prepare(&mut m, PINS, 4_000_000, 200),
            Err(Error::UnsupportedClock)
        );
        assert!(m.writes.is_empty());
    }
    for pins in [Pins([10, 9, 11, 12, 7, 7]), Pins([10, 9, 11, 12, 7, 64])] {
        let mut m = Model::new();
        assert_eq!(
            prepare(&mut m, pins, 4_000_000, 200),
            Err(Error::InvalidPins)
        );
        assert!(m.writes.is_empty());
    }
    for hz in [0, u64::MAX] {
        let mut m = Model::new();
        assert_eq!(prepare(&mut m, PINS, hz, 200), Err(Error::InvalidResources));
        assert!(m.writes.is_empty());
    }
}
#[test]
fn sdk_pad_fields_and_unrelated_register_bits_are_preserved() {
    let mut m = Model::new();
    let before = m.words.clone();
    assert_eq!(
        prepare(&mut m, PINS, 4_000_000, 200).unwrap().source_hz,
        49_500_000
    );
    // Independently listed board DTS routes: GPIO, DOUT, DOEN, optional DIN.
    for (gpio, dout, doen, din, pad) in [
        (10, 55, 0, None, 0x2d),
        (9, 57, 19, Some(44), 0x0b),
        (11, 58, 20, Some(45), 0x0b),
        (12, 59, 21, Some(46), 0x0b),
        (7, 60, 22, Some(47), 0x0b),
        (8, 61, 23, Some(48), 0x0b),
    ] {
        let shift = (gpio % 4) * 8;
        let group = (gpio / 4) * 4;
        assert_eq!((m.get(Bank::Pins, 0x40 + group) >> shift) & 0x7f, dout);
        assert_eq!((m.get(Bank::Pins, group) >> shift) & 0x3f, doen);
        assert_eq!(m.get(Bank::Pins, 0x120 + gpio * 4), 0xa5a5a500 | pad);
        if let Some(din) = din {
            assert_eq!(
                (m.get(Bank::Pins, 0x80 + (din / 4) * 4) >> ((din % 4) * 8)) & 0x7f,
                (gpio + 2) as u32
            );
        }
    }
    for group in [4, 8, 12] {
        assert_eq!(
            m.get(Bank::Pins, 0x40 + group) & 0x80808080,
            0xa5a5a5a5 & 0x80808080
        );
        assert_eq!(
            m.get(Bank::Pins, group) & 0xc0c0c0c0,
            0xa5a5a5a5 & 0xc0c0c0c0
        );
    }
    for offset in [0xac, 0xb0] {
        assert_eq!(
            m.get(Bank::Pins, offset) & 0x80808080,
            0xa5a5a5a5 & 0x80808080
        );
    }
    assert_eq!(m.get(Bank::Pins, 0x29c), 0xa5a5a5a5 & !0x7fc);
    assert_eq!(m.get(Bank::Pins, 0x2b0), 0xa5a5a5a5 & !0x7fc);
    assert_eq!(m.get(Bank::Crg, 0x170), 0x80001234);
    assert_eq!(m.get(Bank::Crg, CARD), 0xc0000108);
    assert_eq!(m.get(Bank::Crg, RESET), 0xdeadbeed & !2);
    for (&(bank, offset), &old) in &before {
        if !m
            .writes
            .iter()
            .any(|&(b, o, _, _)| b as u8 == bank && o == offset)
        {
            assert_eq!(
                m.words[&(bank, offset)],
                old,
                "unowned register {bank}:{offset:x}"
            );
        }
    }
    assert!(!m.writes.iter().any(|&(b, _, _, _)| b == Bank::Syscon));
    assert!(!m
        .writes
        .iter()
        .any(|&(b, o, _, _)| b == Bank::Crg && ![0x170, CARD, RESET].contains(&o)));
}
#[test]
fn reset_and_clock_sequence_precedes_settling_delay_and_supports_wrap() {
    let mut m = Model::new();
    m.now = u64::MAX - 100_000;
    prepare(&mut m, PINS, 4_000_000, 200).unwrap();
    let reset = m
        .writes
        .iter()
        .position(|&(b, o, v, _)| b == Bank::Crg && o == RESET && v & 2 != 0)
        .unwrap();
    let off = m
        .writes
        .iter()
        .position(|&(b, o, v, _)| b == Bank::Crg && o == CARD && v & GATE == 0)
        .unwrap();
    let first_pad = m
        .writes
        .iter()
        .position(|&(b, _, _, _)| b == Bank::Pins)
        .unwrap();
    let on = m
        .writes
        .iter()
        .position(|&(b, o, v, _)| b == Bank::Crg && o == CARD && v & GATE != 0)
        .unwrap();
    let release = m
        .writes
        .iter()
        .position(|&(b, o, v, _)| b == Bank::Crg && o == RESET && v & 2 == 0)
        .unwrap();
    assert!(reset < off && off < first_pad && first_pad < on && on < release);
    assert!(m.now.wrapping_sub(m.writes[release].3) >= 800_000);
}
#[test]
fn reset_timeouts_request_reset_and_allow_explicit_retry() {
    for stall_assert in [true, false] {
        let mut m = Model::new();
        m.stall_assert = stall_assert;
        m.stall_release = !stall_assert;
        assert_eq!(prepare(&mut m, PINS, 4_000_000, 200), Err(Error::TimedOut));
        assert_ne!(m.get(Bank::Crg, RESET) & 2, 0);
        assert_eq!(m.get(Bank::Crg, CARD) & GATE, 0);
        if stall_assert {
            assert!(!m.writes.iter().any(|&(b, _, _, _)| b == Bank::Pins));
        }
        m.stall_assert = false;
        m.stall_release = false;
        assert!(prepare(&mut m, PINS, 4_000_000, 200).is_ok());
    }
}

#[test]
fn mmio_constructor_rejects_short_misaligned_and_overlapping_resources() {
    use vibeos_hal::AddressRange;
    use vibeos_platform_jh7110::sd::Mmio;
    let crg = [0u32; 197];
    let syscon = [0u32; 14];
    let pins = [0u32; 173];
    let range = |words: &[u32]| {
        AddressRange::new(
            words.as_ptr() as usize,
            words.as_ptr() as usize + words.len() * 4,
        )
    };
    let c = range(&crg);
    let s = range(&syscon);
    let p = range(&pins);
    // Real allocated host storage, never accessed through the MMIO methods.
    assert!(unsafe { Mmio::new(c, s, p, || 0) }.is_ok());
    for bad in [
        AddressRange::new(c.start + 1, c.end),
        AddressRange::new(c.start, c.end - 4),
        AddressRange::new(c.end, c.start),
    ] {
        assert!(matches!(
            unsafe { Mmio::new(bad, s, p, || 0) },
            Err(Error::InvalidResources)
        ));
    }
    assert!(matches!(
        unsafe { Mmio::new(c, s, c, || 0) },
        Err(Error::InvalidResources)
    ));
}
