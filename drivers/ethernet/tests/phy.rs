use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    rc::Rc,
};
use vibeos_ethernet::{
    phy::{self, Error, Link, Speed, Tuning, Yt8531},
    MdioPort,
};
const ADDRESS: u8 = 7;
const TUNING: Tuning = Tuning {
    drive: [0, 3, 6],
    rxc_delay_enabled: false,
    rx_delay: 10,
    tx_delay_fe: 5,
    tx_delay: 10,
    tx_inverted: [true, false, true],
};
struct State {
    regs: [[u16; 32]; 32],
    ext: BTreeMap<u16, u16>,
    selected: u16,
    data: u16,
    log: Vec<(bool, u8, u8, u16)>,
    stuck: bool,
    fail_at: usize,
    reset_stuck: bool,
    ignore_ext: bool,
    statuses: VecDeque<u16>,
}
#[derive(Clone)]
struct Port(Rc<RefCell<State>>);
impl Port {
    fn new() -> Self {
        let mut regs = [[u16::MAX; 32]; 32];
        regs[7] = [0; 32];
        regs[7][2] = 0x4f51;
        regs[7][3] = 0xe91b;
        Self(Rc::new(RefCell::new(State {
            regs,
            ext: [(0xa001, 0x0135), (0xa010, 0x0fcc), (0xa003, 0x8100)].into(),
            selected: 0,
            data: 0,
            log: vec![],
            stuck: false,
            fail_at: usize::MAX,
            reset_stuck: false,
            ignore_ext: false,
            statuses: VecDeque::new(),
        })))
    }
    fn phy(&self) -> Yt8531<Self> {
        Yt8531::probe(self.clone(), u32::MAX, 4).unwrap()
    }
    fn link(&self, status: u16) {
        let mut s = self.0.borrow_mut();
        s.regs[7][1] = 0x24;
        s.regs[7][17] = status;
    }
}
impl MdioPort for Port {
    fn busy(&mut self) -> bool {
        self.0.borrow().stuck
    }
    fn start_read(&mut self, phy: u8, reg: u8) {
        let mut s = self.0.borrow_mut();
        s.log.push((false, phy, reg, 0));
        if s.log.len() == s.fail_at {
            s.stuck = true;
        }
        s.data = if phy == ADDRESS && reg == 31 {
            *s.ext.get(&s.selected).unwrap_or(&0)
        } else if phy == ADDRESS && reg == 17 {
            s.statuses.pop_front().unwrap_or(s.regs[7][17])
        } else {
            s.regs[phy as usize][reg as usize]
        };
    }
    fn start_write(&mut self, phy: u8, reg: u8, value: u16) {
        let mut s = self.0.borrow_mut();
        s.log.push((true, phy, reg, value));
        if s.log.len() == s.fail_at {
            s.stuck = true;
        }
        assert_eq!(phy, ADDRESS, "no writes to unverified PHY addresses");
        match reg {
            30 => s.selected = value,
            31 => {
                if !s.ignore_ext {
                    let selected = s.selected;
                    s.ext.insert(selected, value);
                }
            }
            0 if value & 0x8000 != 0 && !s.reset_stuck => s.regs[7][0] = 0,
            _ => s.regs[7][reg as usize] = value,
        }
    }
    fn data(&mut self) -> u16 {
        self.0.borrow().data
    }
}
#[test]
fn discovery_is_read_only_and_does_not_assume_address_zero() {
    let p = Port::new();
    let phy = p.phy();
    assert_eq!(phy.identity().address, 7);
    assert_eq!(phy.identity().id, 0x4f51e91b);
    assert_eq!(p.0.borrow().log.len(), 64);
    assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
    assert_eq!(phy::discover(&mut p.clone(), 1, 4), Err(Error::NoDevice));
    assert_eq!(
        phy::discover(&mut p.clone(), 0, 4),
        Err(Error::InvalidConfig)
    );
    p.0.borrow_mut().regs[3][2] = 0x1234;
    assert!(matches!(
        Yt8531::probe(p.clone(), u32::MAX, 4),
        Err(Error::Ambiguous)
    ));
    p.0.borrow_mut().regs[7][3] = 0xe91a;
    assert!(matches!(
        Yt8531::probe(p.clone(), 1 << 7, 4),
        Err(Error::Unsupported)
    ));
    assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
}
#[test]
fn reset_tuning_and_advertisement_preserve_unrelated_vendor_bits() {
    let p = Port::new();
    let mut phy = p.phy();
    phy.initialize(TUNING, 4).unwrap();
    let s = p.0.borrow();
    assert_eq!(s.ext[&0xa001], 0x0035);
    assert_eq!(s.ext[&0xa010], 0xcffc);
    assert_eq!(s.ext[&0xa003], 0xa95a);
    assert_eq!(s.regs[7][4], 0x0141);
    assert_eq!(s.regs[7][9], 0x0200);
    assert_eq!(s.regs[7][0], 0x1200);
    assert_eq!(
        s.log
            .iter()
            .filter(|&&(w, _, r, v)| w && r == 0 && v == 0x8000)
            .count(),
        1
    );
}
#[test]
fn invalid_tuning_has_no_hardware_effects_and_wrong_identity_is_never_written() {
    let p = Port::new();
    let mut phy = p.phy();
    p.0.borrow_mut().log.clear();
    let mut bad = TUNING;
    bad.drive[2] = 8;
    assert_eq!(phy.initialize(bad, 4), Err(Error::InvalidConfig));
    assert!(p.0.borrow().log.is_empty());
    assert_eq!(phy.initialize(TUNING, 0), Err(Error::InvalidConfig));
    p.0.borrow_mut().regs[7][3] = 0xe91a;
    assert_eq!(phy.initialize(TUNING, 4), Err(Error::Unsupported));
    assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
}
#[test]
fn reset_and_readback_failures_cannot_publish_ready_state() {
    let p = Port::new();
    let mut phy = p.phy();
    p.0.borrow_mut().reset_stuck = true;
    p.0.borrow_mut().log.clear();
    assert_eq!(phy.initialize(TUNING, 3), Err(Error::ResetTimedOut));
    assert_eq!(
        p.0.borrow()
            .log
            .iter()
            .filter(|&&(w, _, r, _)| !w && r == 0)
            .count(),
        3
    );
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
    p.0.borrow_mut().reset_stuck = false;
    p.0.borrow_mut().ignore_ext = true;
    assert_eq!(phy.initialize(TUNING, 3), Err(Error::Readback));
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
    p.0.borrow_mut().ignore_ext = false;
    phy.initialize(TUNING, 3).unwrap();
    assert_eq!(phy.poll_link(), Ok(None));
}
#[test]
fn every_initialization_transaction_failure_stops_without_replay() {
    let baseline = Port::new();
    let mut phy = baseline.phy();
    baseline.0.borrow_mut().log.clear();
    phy.initialize(TUNING, 3).unwrap();
    let count = baseline.0.borrow().log.len();
    for fail in 1..=count {
        let p = Port::new();
        let mut phy = p.phy();
        p.0.borrow_mut().log.clear();
        p.0.borrow_mut().fail_at = fail;
        assert!(phy.initialize(TUNING, 3).is_err(), "transaction {fail}");
        assert_eq!(p.0.borrow().log.len(), fail);
        assert_eq!(phy.poll_link(), Err(Error::NotReady));
        assert_eq!(p.0.borrow().log.len(), fail);
    }
}
#[test]
fn link_resolution_updates_inversion_once_and_tracks_disconnect() {
    let p = Port::new();
    let mut phy = p.phy();
    phy.initialize(TUNING, 3).unwrap();
    for (status, speed, inverted) in [
        (0x2c00, Speed::Mbps10, true),
        (0x6c00, Speed::Mbps100, false),
        (0xac00, Speed::Mbps1000, true),
    ] {
        p.link(status);
        p.0.borrow_mut().log.clear();
        assert_eq!(
            phy.poll_link(),
            Ok(Some(Link {
                speed,
                full_duplex: true
            }))
        );
        assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
        assert!(phy
            .configure_link(Link {
                speed,
                full_duplex: true
            })
            .unwrap());
        assert_eq!(p.0.borrow().ext[&0xa003] & (1 << 14) != 0, inverted);
        p.0.borrow_mut().log.clear();
        phy.poll_link().unwrap();
        assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
    }
    p.0.borrow_mut().regs[7][1] = 0;
    assert_eq!(phy.poll_link(), Ok(None));
    p.link(0xac00);
    assert!(phy.poll_link().unwrap().is_some());
}
#[test]
fn unresolved_or_changing_status_is_not_a_link_and_invalid_speed_faults() {
    let p = Port::new();
    let mut phy = p.phy();
    phy.initialize(TUNING, 3).unwrap();
    p.link(0xa400);
    assert_eq!(phy.poll_link(), Ok(None));
    p.link(0xac00);
    p.0.borrow_mut().statuses.extend([0xac00, 0x6c00]);
    assert_eq!(phy.poll_link(), Ok(None));
    p.link(0xec00);
    assert_eq!(phy.poll_link(), Err(Error::Unsupported));
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
}
#[test]
fn link_write_timeout_quarantines_until_fresh_initialization() {
    let p = Port::new();
    let mut phy = p.phy();
    phy.initialize(TUNING, 3).unwrap();
    p.link(0xac00);
    {
        let mut s = p.0.borrow_mut();
        s.log.clear();
        s.fail_at = 9; // six observation reads, address/read/data-write
    }
    assert!(phy
        .configure_link(Link {
            speed: Speed::Mbps1000,
            full_duplex: true
        })
        .is_err());
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
    {
        let mut s = p.0.borrow_mut();
        s.stuck = false;
        s.fail_at = usize::MAX;
    }
    phy.initialize(TUNING, 3).unwrap();
    assert!(phy.poll_link().unwrap().is_some());
}

#[test]
fn board_mask_excludes_zero_alias_but_keeps_real_collisions_fatal() {
    let p = Port::new();
    {
        let mut s = p.0.borrow_mut();
        s.regs[0][2] = 0x4f51;
        s.regs[0][3] = 0xe91b;
    }
    assert_eq!(phy::discover(&mut p.clone(), u32::MAX, 4), Err(Error::Ambiguous));
    let mask = u32::MAX & !1;
    assert_eq!(phy::discover(&mut p.clone(), mask, 4).unwrap().address, ADDRESS);
    {
        let mut s = p.0.borrow_mut();
        s.regs[3][2] = 0x4f51;
        s.regs[3][3] = 0xe91b;
    }
    assert_eq!(phy::discover(&mut p.clone(), mask, 4), Err(Error::Ambiguous));
    assert!(p.0.borrow().log.iter().all(|entry| !entry.0));
}
