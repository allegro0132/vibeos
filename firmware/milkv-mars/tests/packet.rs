#![cfg(feature = "ethernet")]
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use vibeos_eqos_net::{
    backend::{Backend, Memory},
    controller::{Config, Controller, Io, Speed},
    mdio::Registers,
    ring::{Direction, Layout},
};
use vibeos_ethernet::{
    phy::{Tuning, Yt8531},
    MdioPort,
};
use vibeos_firmware_milkv_mars::packet::{Engine, Error};
struct State {
    csr: BTreeMap<usize, u32>,
    phy: [u16; 32],
    ext: BTreeMap<u16, u16>,
    selected: u16,
    data: u16,
    reset_stuck: bool,
    mdio_stuck: bool,
    phase_writes: usize,
    tx_copies: usize,
    status_reads: usize,
    change_at: usize,
}
#[derive(Clone)]
struct Model(Rc<RefCell<State>>);
fn layout() -> Layout {
    Layout {
        tx_descriptors: 0x42000000,
        rx_descriptors: 0x42001000,
        tx_buffers: 0x42002000,
        rx_buffers: 0x42004000,
        count: 2,
        axi_bytes: 8,
    }
}
impl Registers for Model {
    fn read(&mut self, o: usize) -> u32 {
        self.0.borrow().csr.get(&o).copied().unwrap_or(0)
    }
    fn write(&mut self, o: usize, v: u32) {
        let mut s = self.0.borrow_mut();
        let v = if o == 0x1000 && v & 1 != 0 && !s.reset_stuck {
            v & !1
        } else {
            v
        };
        s.csr.insert(o, v);
    }
}
unsafe impl Io for Model {
    fn ticks(&mut self) -> u64 {
        0
    }
}
unsafe impl Memory for Model {
    fn admit(&self, l: Layout) -> bool {
        l == layout()
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        Registers::read(self, a as usize + w * 4)
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        Registers::write(self, a as usize + w * 4, v)
    }
    fn copy_tx(&mut self, _: u64, _: &[u8]) {
        self.0.borrow_mut().tx_copies += 1;
    }
    fn copy_rx(&mut self, _: u64, out: &mut [u8]) {
        out.fill(0x5a);
    }
    fn for_device(&mut self, a: u64, n: usize, _: Direction) {
        assert_eq!(a % 64, 0);
        assert_eq!(n % 64, 0);
    }
    fn for_cpu(&mut self, a: u64, n: usize, _: Direction) {
        assert_eq!(a % 64, 0);
        assert_eq!(n % 64, 0);
    }
    fn barrier(&mut self) {}
}
impl MdioPort for Model {
    fn busy(&mut self) -> bool {
        self.0.borrow().mdio_stuck
    }
    fn start_read(&mut self, p: u8, r: u8) {
        let mut s = self.0.borrow_mut();
        if r == 17 {
            s.status_reads += 1;
            if s.status_reads == s.change_at {
                s.phy[17] = 0x6c00;
            }
        }
        s.data = if p != 7 {
            0xffff
        } else if r == 31 {
            *s.ext.get(&s.selected).unwrap_or(&0)
        } else {
            s.phy[r as usize]
        };
    }
    fn start_write(&mut self, p: u8, r: u8, v: u16) {
        assert_eq!(p, 7);
        let mut s = self.0.borrow_mut();
        if r == 31 {
            assert_eq!(
                s.csr.get(&0x1104).copied().unwrap_or(0) & 1,
                0,
                "PHY phase changed with TX DMA running"
            );
            assert_eq!(
                s.csr.get(&0x1108).copied().unwrap_or(0) & 1,
                0,
                "PHY phase changed with RX DMA running"
            );
            let selected = s.selected;
            s.ext.insert(selected, v);
            s.phase_writes += 1;
        } else if r == 30 {
            s.selected = v;
        } else {
            s.phy[r as usize] = if r == 0 && v & 0x8000 != 0 { 0 } else { v };
        }
    }
    fn data(&mut self) -> u16 {
        self.0.borrow().data
    }
}
type E = Engine<Model, Model, Model>;
fn engine() -> (E, Model) {
    let mut phy = [0; 32];
    phy[2] = 0x4f51;
    phy[3] = 0xe91b;
    let m = Model(Rc::new(RefCell::new(State {
        csr: [(0x120, 5 << 6 | 5)].into(),
        phy,
        ext: BTreeMap::new(),
        selected: 0,
        data: 0,
        reset_stuck: false,
        mdio_stuck: false,
        phase_writes: 0,
        tx_copies: 0,
        status_reads: 0,
        change_at: usize::MAX,
    })));
    let mut phy = Yt8531::probe(m.clone(), u32::MAX, 4).unwrap();
    phy.initialize(
        Tuning {
            drive: [0, 3, 6],
            rxc_delay_enabled: false,
            rx_delay: 10,
            tx_delay_fe: 5,
            tx_delay: 10,
            tx_inverted: [true, false, true],
        },
        3,
    )
    .unwrap();
    let c = Controller::new(
        m.clone(),
        Config {
            mac: [2, 0, 0, 0, 0, 1],
            speed: Speed::Mbps1000,
            full_duplex: true,
            csr_hz: 198_000_000,
            timebase_hz: 4_000_000,
            max_polls: 4,
        },
    )
    .unwrap();
    let memory = Box::leak(Box::new(m.clone()));
    let backend = Box::leak(Box::new(Backend::new(c, memory)));
    (Engine::new(backend, layout(), phy).unwrap(), m)
}
fn link(m: &Model, status: u16) {
    let mut s = m.0.borrow_mut();
    s.phy[1] = 0x24;
    s.phy[17] = status;
}
#[test]
fn link_down_backpressures_then_transfers_and_reconnects_without_replaying_tx() {
    let (mut e, m) = engine();
    e.poll_link().unwrap();
    assert_eq!(e.link(), None);
    assert!(!e.tx_owned().unwrap());
    assert!(e.transmit(&[0; 60]).is_err());
    link(&m, 0xac00);
    e.poll_link().unwrap();
    assert_eq!(e.link().unwrap().speed, Speed::Mbps1000);
    e.transmit(&[0; 60]).unwrap();
    assert!(e.tx_owned().unwrap());
    m.0.borrow_mut().csr.insert(0x4200100c, 0x30000040);
    let mut out = [0; 64];
    assert_eq!(e.receive(&mut out), Ok(Some(60)));
    assert_eq!(&out[..60], &[0x5a; 60]);
    m.0.borrow_mut().phy[1] = 0;
    e.poll_link().unwrap();
    assert!(!e.tx_owned().unwrap());
    assert_eq!(m.0.borrow().csr[&0x1104] & 1, 0);
    link(&m, 0x6c00);
    e.poll_link().unwrap();
    assert_eq!(e.link().unwrap().speed, Speed::Mbps100);
    assert_eq!(m.0.borrow().csr[&0] & 0xe000, 0xe000);
    assert_eq!(m.0.borrow().tx_copies, 1);
    assert_eq!((e.tx_packets, e.rx_packets), (1, 1));
    let writes = m.0.borrow().phase_writes;
    e.poll_link().unwrap();
    assert_eq!(m.0.borrow().phase_writes, writes);
}
#[test]
fn failed_stop_retains_ownership_and_never_changes_phy_phase() {
    let (mut e, m) = engine();
    link(&m, 0xac00);
    e.poll_link().unwrap();
    let writes = m.0.borrow().phase_writes;
    m.0.borrow_mut().reset_stuck = true;
    link(&m, 0x6c00);
    assert!(e.poll_link().is_err());
    assert_eq!(e.link(), None);
    assert_eq!(e.tx_owned(), Err(Error::Faulted));
    assert_eq!(m.0.borrow().phase_writes, writes);
    assert!(!e.shutdown());
    m.0.borrow_mut().reset_stuck = false;
    assert!(e.shutdown());
    assert_eq!(e.poll_link(), Err(Error::Faulted));
}
#[test]
fn phy_io_failure_cannot_resume_retired_engine() {
    let (mut e, m) = engine();
    link(&m, 0xac00);
    e.poll_link().unwrap();
    m.0.borrow_mut().mdio_stuck = true;
    assert!(e.poll_link().is_err());
    assert_eq!(e.link(), None);
    assert!(e.shutdown());
    m.0.borrow_mut().mdio_stuck = false;
    assert_eq!(e.poll_link(), Err(Error::Faulted));
}
#[test]
fn failed_controller_configuration_never_publishes_a_link() {
    let (mut e, m) = engine();
    m.0.borrow_mut().csr.insert(0x120, 0);
    link(&m, 0xac00);
    assert!(e.poll_link().is_err());
    assert_eq!(e.link(), None);
    assert!(e.shutdown());
    assert!(!m.0.borrow().csr.keys().any(|&a| a >= 0x42000000));
}
#[test]
fn changed_candidate_is_observed_again_before_starting_dma() {
    let (mut e, m) = engine();
    link(&m, 0xac00);
    m.0.borrow_mut().change_at = 3;
    e.poll_link().unwrap();
    assert_eq!(e.link(), None);
    assert_eq!(m.0.borrow().csr.get(&0x1104), None);
    e.poll_link().unwrap();
    assert_eq!(e.link().unwrap().speed, Speed::Mbps100);
}
#[test]
fn malformed_rx_is_rearmed_without_faulting_the_link() {
    let (mut e, m) = engine();
    link(&m, 0xac00);
    e.poll_link().unwrap();
    m.0.borrow_mut().csr.insert(0x4200100c, 0x30008040);
    assert_eq!(e.receive(&mut [0; 64]), Ok(None));
    assert!(e.link().is_some());
    assert_ne!(m.0.borrow().csr[&0x4200100c] & (1 << 31), 0);
}
