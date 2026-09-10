//! Target-side register model. This executes platform logic on RV64; it does
//! not access JH7110 hardware or qualify its clock/reset/pin electrical timing.
use vibeos_platform_jh7110::sd::{prepare, Bank, Error, Pins, Registers};
struct Model {
    words: [[u32; 197]; 3],
    tick: u64,
    stall_release: bool,
}
impl Model {
    fn new() -> Self {
        let mut m = Self {
            words: [[0; 197]; 3],
            tick: 0,
            stall_release: false,
        };
        m.words[0][5] = 1 << 24;
        m.words[0][7] = 3;
        m.words[0][8] = 2;
        m.words[0][9] = 1 << 31;
        m.words[0][0x310 / 4] = 2;
        m.words[1][0x2c / 4] = (3 << 15) | (99 << 17);
        m.words[1][0x34 / 4] = 2;
        m
    }
}
impl Registers for Model {
    fn read(&mut self, b: Bank, o: usize) -> u32 {
        self.words[b as usize][o / 4]
    }
    fn write(&mut self, b: Bank, o: usize, v: u32) {
        self.words[b as usize][o / 4] = v;
        if b == Bank::Crg && o == 0x300 && !(self.stall_release && v & 2 == 0) {
            self.words[0][0x310 / 4] = if v & 2 != 0 { 0 } else { 2 };
        }
    }
    fn ticks(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(10_000);
        self.tick
    }
}
pub fn run() {
    let pins = Pins([10, 9, 11, 12, 7, 8]);
    let mut m = Model::new();
    let actual = prepare(&mut m, pins, 4_000_000, 200).unwrap();
    assert_eq!(actual.source_hz, 49_500_000);
    assert_eq!(m.words[0][0x178 / 4], 0x80000008);
    assert_eq!(m.words[2][0x148 / 4], 0x2d);
    assert!(m.tick >= 800_000);
    m.stall_release = true;
    assert_eq!(prepare(&mut m, pins, 4_000_000, 200), Err(Error::TimedOut));
    assert_ne!(m.words[0][0x300 / 4] & 2, 0);
    assert_eq!(m.words[0][0x178 / 4] & (1 << 31), 0);
}
