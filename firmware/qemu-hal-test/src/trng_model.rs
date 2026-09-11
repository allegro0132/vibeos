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
    mmio_lane();
    platform_model();
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

// RAM-backed access test: executes the production volatile/fence lane on RV64,
// but does not simulate TRNG side effects or establish physical entropy quality.
#[inline(never)]
fn mmio_lane() {
    use vibeos_starfive_trng::Mmio;
    let mut words = [0xa5a5a5a5u32; 28];
    let mut lane = unsafe {
        Mmio::new(words.as_mut_ptr().add(1) as usize, 104, || 77).unwrap()
    };
    lane.write(100, 0x12345678);
    lane.write(16, 0);
    assert_eq!(lane.read(100), 0x12345678);
    assert_eq!(lane.read(16), 0);
    for offset in (32..64).step_by(4) {
        assert_eq!(lane.read(offset), 0xa5a5a5a5);
    }
    assert_eq!(lane.ticks(), 77);
    assert_eq!(words[0], 0xa5a5a5a5);
    assert_eq!(words[27], 0xa5a5a5a5);
}

fn platform_model() {
    use vibeos_platform_jh7110::security::{Domain, Registers as PlatformRegisters};
    struct Crg {
        gates: [u32; 2],
        reset: u32,
    }
    impl PlatformRegisters for Crg {
        fn read(&mut self, o: usize) -> u32 {
            match o {
                0x3c => self.gates[0],
                0x40 => self.gates[1],
                0x74 => self.reset,
                0x78 => !self.reset,
                _ => panic!("STG read"),
            }
        }
        fn write(&mut self, o: usize, v: u32) {
            match o {
                0x3c | 0x40 => {
                    if v & (1 << 31) == 0 {
                        assert_ne!(self.reset & 8, 0);
                    }
                    self.gates[(o - 0x3c) / 4] = v;
                }
                0x74 => {
                    assert!(self.gates.iter().all(|g| g & (1 << 31) != 0));
                    assert_eq!(v & !8, 0x50);
                    self.reset = v;
                }
                _ => panic!("STG write"),
            }
        }
        fn ticks(&mut self) -> u64 {
            0
        }
    }
    let mut domain = unsafe {
        Domain::new_exclusive(
            Crg {
                gates: [0; 2],
                reset: 0x50,
            },
            4_000_000,
        )
        .unwrap()
    };
    domain.prepare().unwrap();
    assert!(domain.ready());
    unsafe {
        domain.stop().unwrap();
    }
    assert!(!domain.ready());
    domain.prepare().unwrap();
    unsafe {
        domain.stop().unwrap();
    }
}
