use std::collections::BTreeMap;
use vibeos_platform_jh7110::ethernet::{self as eth, Bank, Error, Registers};
const GATE: u32 = 1 << 31;
struct Model {
    words: BTreeMap<(u8, usize), u32>,
    writes: Vec<(Bank, usize, u32)>,
    now: u64,
    frozen: bool,
    stall_assert: bool,
    stall_release: bool,
    ignore: Option<(Bank, usize)>,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: BTreeMap::new(),
            writes: vec![],
            now: 0,
            frozen: false,
            stall_assert: false,
            stall_release: false,
            ignore: None,
        };
        for (b, o, v) in [
            (Bank::Syscon, 0x18, 3 << 24),
            (Bank::Syscon, 0x1c, 125),
            (Bank::Syscon, 0x20, 0),
            (Bank::Syscon, 0x24, 2),
            (Bank::Syscon, 0x2c, (3 << 15) | (99 << 17)),
            (Bank::Syscon, 0x30, 0),
            (Bank::Syscon, 0x34, 2),
            (Bank::SysCrg, 0x14, 1 << 24),
            (Bank::SysCrg, 0x1c, 3),
            (Bank::SysCrg, 0x20, 2),
            (Bank::SysCrg, 99 * 4, 5),
            (Bank::SysCrg, 108 * 4, 0x40000008),
            (Bank::AonCrg, 0x38, 0xfffffff8),
            (Bank::AonCrg, 0x3c, u32::MAX),
            (Bank::AonSyscon, 0x0c, 0xaa00bb00),
        ] {
            m.set(b, o, v);
        }
        for o in [0x78, 0x7c, 0x80, 0x84, 0x88] {
            m.set(Bank::AonPins, o, 0xa5a5a5a7);
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
impl Registers for Model {
    fn read(&mut self, b: Bank, o: usize) -> u32 {
        self.get(b, o)
    }
    fn write(&mut self, b: Bank, o: usize, v: u32) {
        self.writes.push((b, o, v));
        if self.ignore == Some((b, o)) {
            return;
        }
        self.set(b, o, v);
        if b == Bank::AonCrg && o == 0x38 {
            let assert = v & 3 != 0;
            if !(assert && self.stall_assert || !assert && self.stall_release) {
                self.set(b, 0x3c, (self.get(b, 0x3c) & !3) | (!v & 3));
            }
        }
    }
    fn ticks(&mut self) -> u64 {
        if !self.frozen {
            self.now = self.now.wrapping_add(10000);
        }
        self.now
    }
}
#[test]
fn actual_pll_and_bus_frequencies_are_distinct_from_gtx() {
    let mut m = Model::new();
    let p = eth::clock_plan(&mut m).unwrap();
    assert_eq!(
        (p.csr_hz, p.gtx_hz, p.ptp_hz),
        (198_000_000, 125_000_000, 100_000_000)
    );
    assert_eq!((p.gtx_divider, p.ptp_divider), (12, 3));
    assert!(m.writes.is_empty());
    m.set(Bank::SysCrg, 0x14, 0);
    m.set(Bank::SysCrg, 0x1c, 1);
    m.set(Bank::SysCrg, 0x20, 1);
    assert_eq!(eth::clock_plan(&mut m).unwrap().csr_hz, 24_000_000);
}
#[test]
fn malformed_roots_and_configuration_make_no_writes() {
    for (b, o, v) in [
        (Bank::Syscon, 0x18, 1 << 24),
        (Bank::Syscon, 0x20, 1 << 27),
        (Bank::Syscon, 0x24, 0),
        (Bank::Syscon, 0x1c, 124),
        (Bank::Syscon, 0x2c, 0),
        (Bank::SysCrg, 0x1c, 0),
        (Bank::SysCrg, 0x20, 3),
        (Bank::SysCrg, 99 * 4, 0),
    ] {
        let mut m = Model::new();
        m.set(b, o, v);
        assert_eq!(
            eth::prepare(&mut m, 1, 4_000_000),
            Err(Error::UnsupportedClock)
        );
        assert!(m.writes.is_empty());
    }
    let mut m = Model::new();
    assert_eq!(
        eth::prepare(&mut m, 4, 4_000_000),
        Err(Error::InvalidResources)
    );
    assert_eq!(eth::prepare(&mut m, 1, 0), Err(Error::InvalidResources));
    assert!(m.writes.is_empty());
}
#[test]
fn shared_aon_pin_reset_is_never_released_as_a_side_effect() {
    let mut m = Model::new();
    m.set(Bank::AonCrg, 0x38, 4);
    assert_eq!(
        eth::prepare(&mut m, 1, 4_000_000),
        Err(Error::InvalidResources)
    );
    assert!(m.writes.is_empty());
    m.set(Bank::AonCrg, 0x38, 0);
    m.set(Bank::AonCrg, 0x3c, 3);
    assert_eq!(
        eth::prepare(&mut m, 1, 4_000_000),
        Err(Error::InvalidResources)
    );
    assert!(m.writes.is_empty());
}
#[test]
fn reset_brackets_owned_clock_and_pin_changes_only() {
    let mut m = Model::new();
    let before = m.words.clone();
    eth::prepare(&mut m, 1, 4_000_000).unwrap();
    assert_eq!(m.get(Bank::SysCrg, 108 * 4), 0xc000000c);
    assert_eq!(m.get(Bank::SysCrg, 109 * 4), GATE | 3);
    assert_eq!(m.get(Bank::SysCrg, 111 * 4), GATE);
    assert_eq!(m.get(Bank::AonCrg, 0x10), 1);
    assert_eq!(m.get(Bank::AonCrg, 0x14), GATE | (1 << 24));
    assert_eq!(
        m.get(Bank::AonSyscon, 0x0c),
        (0xaa00bb00 & !(7 << 18)) | (1 << 18)
    );
    for o in [0x78, 0x7c, 0x80, 0x84, 0x88] {
        assert_eq!(m.get(Bank::AonPins, o), 0xa5a5a5a5);
    }
    let assert_at = m
        .writes
        .iter()
        .position(|&(b, o, v)| b == Bank::AonCrg && o == 0x38 && v & 3 == 3)
        .unwrap();
    let release_at = m
        .writes
        .iter()
        .position(|&(b, o, v)| b == Bank::AonCrg && o == 0x38 && v & 3 == 0)
        .unwrap();
    for (i, &(b, o, _)) in m.writes.iter().enumerate() {
        assert_ne!(b, Bank::Syscon);
        if b == Bank::SysCrg {
            assert!([108 * 4, 109 * 4, 111 * 4].contains(&o));
        }
        if b == Bank::AonPins {
            assert!(i > assert_at && i < release_at);
        }
    }
    for (&(b, o), &v) in &before {
        if b == Bank::Syscon as u8 || b == Bank::SysCrg as u8 && o < 108 * 4 {
            assert_eq!(m.words[&(b, o)], v);
        }
    }
    assert_eq!(m.get(Bank::AonCrg, 0x38) & !3, 0xfffffff8);
}
fn assert_closed(m: &Model) {
    assert_eq!(m.get(Bank::AonCrg, 0x38) & 3, 3);
    assert_eq!(m.get(Bank::AonCrg, 0x14) & GATE, 0);
    for o in [108 * 4, 109 * 4, 111 * 4] {
        assert_eq!(m.get(Bank::SysCrg, o) & GATE, 0);
    }
}
#[test]
fn failed_reset_ack_never_releases_or_configures_pins() {
    let mut m = Model::new();
    m.stall_assert = true;
    assert_eq!(eth::prepare(&mut m, 1, 4_000_000), Err(Error::TimedOut));
    assert_closed(&m);
    assert!(!m.writes.iter().any(|&(b, _, _)| b == Bank::AonPins));
    assert!(!m
        .writes
        .iter()
        .any(|&(b, o, v)| b == Bank::AonCrg && o == 0x38 && v & 3 == 0));
}
#[test]
fn release_failure_and_ignored_writes_request_reset_and_gate_tx() {
    let mut m = Model::new();
    m.stall_release = true;
    assert_eq!(eth::prepare(&mut m, 1, 4_000_000), Err(Error::TimedOut));
    assert_closed(&m);
    let mut m = Model::new();
    m.ignore = Some((Bank::AonSyscon, 0x0c));
    assert_eq!(eth::prepare(&mut m, 1, 4_000_000), Err(Error::Readback));
    assert_closed(&m);
}
#[test]
fn frozen_and_wrapping_counters_cannot_hang_reset_polling() {
    for frozen in [false, true] {
        let mut m = Model::new();
        m.now = u64::MAX - 20000;
        m.frozen = frozen;
        m.stall_assert = true;
        assert_eq!(eth::prepare(&mut m, 1, 4_000_000), Err(Error::TimedOut));
        assert_closed(&m);
    }
}
#[test]
fn mmio_constructor_rejects_substituted_banks_without_access() {
    use vibeos_hal::AddressRange;
    let mut ranges = [
        AddressRange::new(0x13020000, 0x13030000),
        AddressRange::new(0x13030000, 0x13031000),
        AddressRange::new(0x17000000, 0x17010000),
        AddressRange::new(0x17010000, 0x17011000),
        AddressRange::new(0x17020000, 0x17030000),
    ];
    assert!(unsafe { eth::Mmio::new(ranges, || 0) }.is_ok());
    ranges.swap(0, 2);
    assert!(unsafe { eth::Mmio::new(ranges, || 0) }.is_err());
}
