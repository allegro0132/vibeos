//! Actual platform preparation on RV64, with modeled clock/reset registers.
use vibeos_platform_jh7110::ethernet::{self as eth, Bank, Error, Registers};
struct Model {
    words: [[u32; 128]; 5],
    now: u64,
    stall: bool,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: [[0; 128]; 5],
            now: 0,
            stall: false,
        };
        for (b, o, v) in [
            (Bank::Syscon, 0x18, 3 << 24),
            (Bank::Syscon, 0x1c, 125),
            (Bank::Syscon, 0x24, 2),
            (Bank::Syscon, 0x2c, (3 << 15) | (99 << 17)),
            (Bank::Syscon, 0x34, 2),
            (Bank::SysCrg, 0x14, 1 << 24),
            (Bank::SysCrg, 0x1c, 3),
            (Bank::SysCrg, 0x20, 2),
            (Bank::SysCrg, 99 * 4, 5),
            (Bank::AonCrg, 0x3c, u32::MAX),
        ] {
            m.words[b as usize][o / 4] = v;
        }
        m
    }
}
impl Registers for Model {
    fn read(&mut self, b: Bank, o: usize) -> u32 {
        self.words[b as usize][o / 4]
    }
    fn write(&mut self, b: Bank, o: usize, v: u32) {
        assert_ne!(b, Bank::Syscon, "shared PLL must be read-only");
        self.words[b as usize][o / 4] = v;
        if b == Bank::AonCrg && o == 0x38 && !self.stall {
            self.words[b as usize][0x3c / 4] = (self.words[b as usize][0x3c / 4] & !3) | (!v & 3);
        }
    }
    fn ticks(&mut self) -> u64 {
        self.now = self.now.wrapping_add(10000);
        self.now
    }
}
pub fn run() -> u64 {
    let mut m = Model::new();
    let p = eth::prepare(&mut m, 1, 4_000_000).unwrap();
    assert_eq!(p.csr_hz, 198_000_000);
    assert_eq!(p.gtx_divider, 12);
    assert_eq!(m.read(Bank::AonCrg, 0x14), 0x81000000);
    assert_eq!(m.read(Bank::AonCrg, 0x10), 1);
    assert_eq!(m.read(Bank::AonSyscon, 0x0c) & (7 << 18), 1 << 18);
    m.stall = true;
    assert_eq!(eth::prepare(&mut m, 1, 4_000_000), Err(Error::TimedOut));
    assert_eq!(m.read(Bank::AonCrg, 0x38) & 3, 3);
    assert_eq!(m.read(Bank::AonCrg, 0x14) & (1 << 31), 0);
    u64::from(p.csr_hz)
}
