//! Register effects only; cannot assess noise, entropy, clocks or reset wiring.
use std::{cell::RefCell, rc::Rc};
use vibeos_starfive_trng::{Error, Registers, Trng};

struct State {
    words: [u32; 26],
    writes: Vec<(usize, u32)>,
    reads: usize,
    status_reads: usize,
    ignored_write: Option<usize>,
    status_fault: u32,
    clock: u64,
    step: u64,
    stuck: bool,
    ignore_clear: bool,
    wrong_event: bool,
    repeat: bool,
    lock_at: Option<usize>,
}
#[derive(Clone)]
struct Model(Rc<RefCell<State>>);
impl Model {
    fn new() -> Self {
        let mut words = [0; 26];
        words[1] = 1 << 8;
        words[3] = 1 << 8;
        Self(Rc::new(RefCell::new(State {
            words,
            writes: Vec::new(),
            reads: 0,
            status_reads: 0,
            ignored_write: None,
            status_fault: 0,
            clock: 0,
            step: 0,
            stuck: false,
            ignore_clear: false,
            wrong_event: false,
            repeat: false,
            lock_at: None,
        })))
    }
}
impl Registers for Model {
    fn read(&mut self, offset: usize) -> u32 {
        let mut s = self.0.borrow_mut();
        if offset == 4 {
            s.status_reads += 1;
        }
        if (32..64).contains(&offset) {
            s.reads += 1;
            if s.lock_at == Some(s.reads) {
                s.words[5] |= 16;
            }
            if offset == 60 {
                s.words[1] ^= s.status_fault;
            }
        }
        s.words[offset / 4]
    }
    fn write(&mut self, offset: usize, value: u32) {
        let mut s = self.0.borrow_mut();
        s.writes.push((offset, value));
        if s.ignored_write == Some(offset) {
            return;
        }
        match offset {
            20 => {
                if !s.ignore_clear {
                    s.words[5] &= !value;
                }
            }
            8 => {
                s.words[2] = value;
                s.words[1] = (s.words[1] & !8) | (value & 8);
            }
            0 => {
                assert_eq!(s.words[1] & (3 << 30), 0, "command while busy");
                assert_eq!(s.words[5], 0, "stale event not cleared");
                assert!(value == 1 || value == 2);
                if s.stuck {
                    s.words[1] |= 1 << 30;
                    return;
                }
                s.words[5] |= if s.wrong_event { 3 ^ value } else { value };
                s.words[1] |= 1 << 9;
                if value == 1 && !s.repeat {
                    for i in 8..16 {
                        s.words[i] = s.words[i].wrapping_add(0x1020304 + i as u32);
                    }
                }
            }
            _ => s.words[offset / 4] = value,
        }
    }
    fn ticks(&mut self) -> u64 {
        let mut s = self.0.borrow_mut();
        let v = s.clock;
        s.clock = v.wrapping_add(s.step);
        v
    }
}

#[test]
fn mode_seed_or_busy_drift_during_copy_never_returns_a_block() {
    for bit in [4, 8, 256, 512, 1 << 30] {
        let (mut t, m) = ready();
        m.0.borrow_mut().status_fault = bit;
        assert_eq!(t.read_block(), Err(Error::Mode));
        assert_eq!(t.read_block(), Err(Error::NotReady));
    }
}
fn ready() -> (Trng<Model>, Model) {
    let m = Model::new();
    let mut t = Trng::new(m.clone(), 4_000_000, 4).unwrap();
    t.initialize().unwrap();
    (t, m)
}

#[test]
fn reseeds_each_block_and_reads_little_endian_words_only_after_completion() {
    let (mut t, m) = ready();
    let first = t.read_block().unwrap();
    assert_eq!(&first[..4], &0x0102030cu32.to_le_bytes());
    assert_ne!(first, t.read_block().unwrap());
    let s = m.0.borrow();
    assert_eq!(
        s.writes
            .iter()
            .filter(|&&(o, _)| o == 0)
            .copied()
            .collect::<Vec<_>>(),
        [(0, 2), (0, 2), (0, 1), (0, 2), (0, 1)]
    );
    assert_eq!(s.reads, 16);
    assert_eq!(s.words[5], 0);
}
#[test]
fn invalid_budget_and_uninitialized_state_never_issue_commands() {
    let m = Model::new();
    for (hz, polls) in [
        (0, 1),
        (999, 1),
        (1_000_000_001, 1),
        (4000000, 0),
        (4000000, 1_000_001),
    ] {
        assert!(matches!(
            Trng::new(m.clone(), hz, polls),
            Err(Error::InvalidBudget)
        ));
    }
    let mut t = Trng::new(m.clone(), 4_000_000, 1).unwrap();
    assert_eq!(t.read_block(), Err(Error::NotReady));
    assert!(m.0.borrow().writes.is_empty());
}
#[test]
fn nonce_or_nonmission_mode_is_rejected_before_reseed() {
    for smode in [0, 4, 260] {
        let m = Model::new();
        m.0.borrow_mut().words[3] = smode;
        let mut t = Trng::new(m.clone(), 4_000_000, 4).unwrap();
        assert_eq!(t.initialize(), Err(Error::Mode));
        assert!(!m.0.borrow().writes.iter().any(|&(o, _)| o == 0));
        assert_eq!(t.initialize(), Err(Error::NotReady));
    }
}
#[test]
fn busy_and_stale_event_cannot_be_mistaken_for_new_completion() {
    let m = Model::new();
    m.0.borrow_mut().words[1] |= 1 << 31;
    let mut t = Trng::new(m.clone(), 4_000_000, 4).unwrap();
    assert_eq!(t.initialize(), Err(Error::TimedOut));
    assert!(!m.0.borrow().writes.iter().any(|&(o, _)| o == 0));
    let (mut t, m) = ready();
    {
        let mut s = m.0.borrow_mut();
        s.words[5] = 1;
        s.ignore_clear = true;
    }
    assert_eq!(t.read_block(), Err(Error::Protocol));
    assert_eq!(m.0.borrow().reads, 0);
}
#[test]
fn missing_or_wrong_completion_faults_without_output_and_without_retry() {
    for stuck in [true, false] {
        let (mut t, m) = ready();
        {
            let mut s = m.0.borrow_mut();
            s.stuck = stuck;
            s.wrong_event = !stuck;
        }
        assert_eq!(
            t.read_block(),
            Err(if stuck {
                Error::TimedOut
            } else {
                Error::Protocol
            })
        );
        let n = m.0.borrow().writes.len();
        assert_eq!(t.read_block(), Err(Error::NotReady));
        assert_eq!(t.initialize(), Err(Error::NotReady));
        let s = m.0.borrow();
        assert_eq!(s.writes.len(), n);
        assert_eq!(s.reads, 0);
        assert_eq!(s.words[4], 0);
    }
}
#[test]
fn timer_wrap_and_poll_budget_both_terminate_stalled_hardware() {
    for step in [0, 4000] {
        let (mut t, m) = ready();
        let before = m.0.borrow().status_reads;
        {
            let mut s = m.0.borrow_mut();
            s.stuck = true;
            s.clock = u64::MAX - 3999;
            s.step = step;
        }
        assert_eq!(t.read_block(), Err(Error::TimedOut));
        assert_eq!(m.0.borrow().reads, 0);
        assert_eq!(
            m.0.borrow().status_reads - before,
            if step == 0 { 5 } else { 2 }
        );
    }
}

#[test]
fn rejected_configuration_readback_never_reseeds() {
    for offset in [8, 16, 96, 100] {
        let m = Model::new();
        {
            let mut s = m.0.borrow_mut();
            s.ignored_write = Some(offset);
            if offset >= 96 {
                s.words[offset / 4] = 7;
            }
        }
        let mut t = Trng::new(m.clone(), 4_000_000, 4).unwrap();
        assert_eq!(t.initialize(), Err(Error::Protocol));
        assert!(!m.0.borrow().writes.iter().any(|&(o, _)| o == 0));
    }
}
#[test]
fn lockup_before_or_during_copy_invalidates_entire_block() {
    for at in [0, 1, 8] {
        let (mut t, m) = ready();
        if at == 0 {
            m.0.borrow_mut().words[5] = 16;
        } else {
            m.0.borrow_mut().lock_at = Some(at);
        }
        assert_eq!(t.read_block(), Err(Error::Lockup));
        assert_eq!(t.read_block(), Err(Error::NotReady));
        assert_eq!(m.0.borrow().words[4], 0);
    }
}
#[test]
fn stuck_output_rejected_across_reseeds() {
    let (mut t, m) = ready();
    t.read_block().unwrap();
    m.0.borrow_mut().repeat = true;
    assert_eq!(t.read_block(), Err(Error::RepeatedOutput));
    for word in [0, u32::MAX] {
        let (mut t, m) = ready();
        {
            let mut s = m.0.borrow_mut();
            s.repeat = true;
            s.words[8..16].fill(word);
        }
        assert_eq!(t.read_block(), Err(Error::RepeatedOutput));
    }
}
