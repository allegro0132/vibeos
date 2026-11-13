//! Side-effect models do not prove hardware reset or clock acknowledgements.
use std::{cell::RefCell, rc::Rc};
use vibeos_platform_jh7110::security::{Domain, Error, Registers};
struct State {
    gates: [u32; 2],
    reset: u32,
    status: u32,
    writes: Vec<(usize, u32)>,
    stuck: bool,
    stuck_release: bool,
    ignored: Option<usize>,
    ticks: u64,
    step: u64,
    status_reads: usize,
}
#[derive(Clone)]
struct Model(Rc<RefCell<State>>);
impl Model {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(State {
            gates: [0x12345, 0x6789],
            reset: 0x50,
            status: !0x50,
            writes: Vec::new(),
            stuck: false,
            stuck_release: false,
            ignored: None,
            ticks: u64::MAX - 3999,
            step: 4000,
            status_reads: 0,
        })))
    }
}
impl Registers for Model {
    fn read(&mut self, o: usize) -> u32 {
        let mut s = self.0.borrow_mut();
        match o {
            0x3c => s.gates[0],
            0x40 => s.gates[1],
            0x74 => s.reset,
            0x78 => {
                s.status_reads += 1;
                s.status
            }
            _ => panic!("wrong STG register"),
        }
    }
    fn write(&mut self, o: usize, v: u32) {
        let mut s = self.0.borrow_mut();
        s.writes.push((o, v));
        if s.ignored == Some(o) {
            return;
        }
        match o {
            0x3c | 0x40 => {
                if v & (1 << 31) == 0 {
                    assert_eq!(s.status & 8, 0, "gated before reset proof");
                }
                s.gates[(o - 0x3c) / 4] = v;
            }
            0x74 => {
                assert!(s.gates.iter().all(|v| v & (1 << 31) != 0));
                assert_eq!(v & !8, 0x50, "unrelated reset bits changed");
                s.reset = v;
                if !s.stuck && !(s.stuck_release && v & 8 == 0) {
                    s.status = !v;
                }
            }
            _ => panic!("unexpected write"),
        }
    }
    fn ticks(&mut self) -> u64 {
        let mut s = self.0.borrow_mut();
        let t = s.ticks;
        s.ticks = t.wrapping_add(s.step);
        t
    }
}

#[test]
fn deassertion_timeout_never_publishes_ready() {
    let m = Model::new();
    m.0.borrow_mut().stuck_release = true;
    let mut d = domain(&m);
    assert_eq!(d.prepare(), Err(Error::TimedOut));
    assert!(!d.ready());
    assert!(m.0.borrow().gates.iter().all(|v| v & (1 << 31) != 0));
    unsafe { d.stop().unwrap() };
    assert_eq!(m.0.borrow().gates, [0x12345, 0x6789]);
}

#[test]
fn mmio_rejects_sys_crg_and_trng_apertures_before_access() {
    use vibeos_hal::AddressRange;
    use vibeos_platform_jh7110::security::Mmio;
    for range in [
        AddressRange::new(0x13020000, 0x13030000),
        AddressRange::new(0x1600c000, 0x16010000),
        AddressRange::new(0x10230000, 0x10230100),
    ] {
        assert!(matches!(
            unsafe { Mmio::new(range, || 0) },
            Err(Error::InvalidResources)
        ));
    }
}
fn domain(m: &Model) -> Domain<Model> {
    unsafe { Domain::new_exclusive(m.clone(), 4_000_000).unwrap() }
}
#[test]
fn exact_gate_reset_order_preserves_other_bits() {
    let m = Model::new();
    let mut d = domain(&m);
    d.prepare().unwrap();
    assert!(d.ready());
    assert_eq!(d.prepare(), Err(Error::NotReady));
    assert_eq!(
        m.0.borrow().writes,
        [
            (0x3c, 0x80012345),
            (0x40, 0x80006789),
            (0x74, 0x58),
            (0x74, 0x50)
        ]
    );
    unsafe { d.stop().unwrap() };
    assert!(!d.ready());
    let s = m.0.borrow();
    assert_eq!(s.gates, [0x12345, 0x6789]);
    assert_eq!(s.reset, 0x58);
    drop(s);
    d.prepare().unwrap();
    assert!(d.ready());
}
#[test]
fn failed_reset_quarantines_without_gating_then_explicit_stop_can_recover() {
    let m = Model::new();
    let mut d = domain(&m);
    m.0.borrow_mut().stuck = true;
    assert_eq!(d.prepare(), Err(Error::TimedOut));
    assert!(!d.ready());
    let n = m.0.borrow().writes.len();
    assert_eq!(d.prepare(), Err(Error::NotReady));
    assert_eq!(m.0.borrow().writes.len(), n);
    assert_eq!(unsafe { d.stop() }, Err(Error::TimedOut));
    assert!(m.0.borrow().gates.iter().all(|v| v & (1 << 31) != 0));
    m.0.borrow_mut().stuck = false;
    unsafe { d.stop().unwrap() };
    d.prepare().unwrap();
}
#[test]
fn clock_and_reset_write_failures_do_not_publish_ready() {
    for offset in [0x3c, 0x40, 0x74] {
        let m = Model::new();
        m.0.borrow_mut().ignored = Some(offset);
        let mut d = domain(&m);
        assert_eq!(d.prepare(), Err(Error::Readback));
        assert!(!d.ready());
        assert_eq!(d.prepare(), Err(Error::NotReady));
    }
}
#[test]
fn deadline_and_frozen_timer_poll_limit_are_independent() {
    for step in [0, 4000] {
        let m = Model::new();
        {
            let mut s = m.0.borrow_mut();
            s.stuck = true;
            s.step = step;
        }
        assert_eq!(domain(&m).prepare(), Err(Error::TimedOut));
        assert_eq!(
            m.0.borrow().status_reads,
            if step == 0 { 100000 } else { 1 }
        );
    }
}
#[test]
fn invalid_timebase_has_no_io_and_stopped_domain_is_idempotent() {
    let m = Model::new();
    assert!(matches!(
        unsafe { Domain::new_exclusive(m.clone(), 0) },
        Err(Error::InvalidTimebase)
    ));
    assert!(m.0.borrow().writes.is_empty());
    let mut d = domain(&m);
    unsafe { d.stop().unwrap() };
    let n = m.0.borrow().writes.len();
    unsafe { d.stop().unwrap() };
    assert_eq!(n, m.0.borrow().writes.len());
}
