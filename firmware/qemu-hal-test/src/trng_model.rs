//! RV64 protocol execution only; registers/noise are modeled, not physical.
use vibeos_starfive_trng::{Error, Registers, Trng};
struct Model {
    words: [u32; 26],
    failed: bool,
    stuck: bool,
    tick: u64,
}
impl Model {
    fn new(failed: bool, stuck: bool) -> Self {
        let mut words = [0; 26];
        words[1] = 256;
        words[3] = 256;
        Self {
            words,
            failed,
            stuck,
            tick: u64::MAX - 3999,
        }
    }
}
impl Registers for Model {
    fn read(&mut self, o: usize) -> u32 {
        if o == 60 && self.failed {
            self.words[5] |= 16;
        }
        self.words[o / 4]
    }
    fn write(&mut self, o: usize, v: u32) {
        match o {
            8 => {
                self.words[2] = v;
                self.words[1] |= v & 8;
            }
            20 => self.words[5] &= !v,
            0 => {
                assert_eq!(self.words[5], 0);
                assert_eq!(self.words[1] & (3 << 30), 0);
                if self.stuck {
                    self.words[1] |= 1 << 31;
                    return;
                }
                self.words[1] |= 512;
                self.words[5] = v;
                if v == 1 {
                    for i in 8..16 {
                        self.words[i] += 0x1020304;
                    }
                }
            }
            _ => self.words[o / 4] = v,
        }
    }
    fn ticks(&mut self) -> u64 {
        let now = self.tick;
        self.tick = self.tick.wrapping_add(4000);
        now
    }
}
pub fn run() {
    let mut trng = Trng::new(Model::new(false, false), 4_000_000, 4).unwrap();
    trng.initialize().unwrap();
    let first = trng.read_block().unwrap();
    assert_eq!(&first[..4], &[4, 3, 2, 1]);
    assert_ne!(first, trng.read_block().unwrap());
    let mut trng = Trng::new(Model::new(true, false), 4_000_000, 4).unwrap();
    trng.initialize().unwrap();
    assert_eq!(trng.read_block(), Err(Error::Lockup));
    assert_eq!(trng.read_block(), Err(Error::NotReady));
    let mut trng = Trng::new(Model::new(false, true), 4_000_000, 4).unwrap();
    assert_eq!(trng.initialize(), Err(Error::TimedOut));
    assert_eq!(trng.initialize(), Err(Error::NotReady));
}
