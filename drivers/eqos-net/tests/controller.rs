//! Register model tests; no physical clock/reset/DMA qualification.
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use vibeos_eqos_net::{
    backend::{Backend, Memory},
    ring::{Direction, Ring},
};
use vibeos_eqos_net::{controller::*, mdio::Registers, ring::Layout};

struct Pool {
    state: Rc<RefCell<State>>,
    admit: bool,
}

#[test]
fn link_reconfiguration_requires_stop_and_invalidates_old_configuration() {
    let (mut c, s) = model();
    c.reset().unwrap();
    c.configure(layout()).unwrap();
    c.set_link(Speed::Mbps10, true).unwrap();
    assert_eq!(c.start(), Err(Error::NotReady));
    c.configure(layout()).unwrap();
    c.start().unwrap();
    let count = s.borrow().writes.len();
    assert_eq!(c.set_link(Speed::Mbps100, true), Err(Error::NotReady));
    assert_eq!(s.borrow().writes.len(), count);
    c.stop().unwrap();
    c.set_link(Speed::Mbps100, true).unwrap();
    assert_eq!(c.start(), Err(Error::NotReady));
    c.configure(layout()).unwrap();
    c.start().unwrap();
    assert_eq!(s.borrow().registers[&0] & 0xe000, 0xe000);
}

#[test]
fn running_or_failed_stop_keeps_backend_and_successful_stop_allows_reuse() {
    let (c, s) = model();
    let pool = Box::leak(Box::new(Pool {
        state: s.clone(),
        admit: true,
    }));
    let b = Box::leak(Box::new(Backend::new(c, pool)));
    let mut ring = Ring::new(b, layout()).unwrap();
    ring.initialize().unwrap();
    let mut ring = match ring.into_stopped_backend() {
        Err(r) => r,
        Ok(_) => panic!("released live DMA"),
    };
    s.borrow_mut().reset_stuck = true;
    assert!(!ring.shutdown());
    let mut ring = match ring.into_stopped_backend() {
        Err(r) => r,
        Ok(_) => panic!("released quarantined DMA"),
    };
    s.borrow_mut().reset_stuck = false;
    assert!(ring.shutdown());
    let b = ring.into_stopped_backend().ok().unwrap();
    b.set_link(Speed::Mbps10, true).unwrap();
    let mut ring = Ring::new(b, layout()).unwrap();
    ring.initialize().unwrap();
    assert_eq!(s.borrow().registers[&0] & 0xe000, 0xa000);
}
unsafe impl Memory for Pool {
    fn admit(&self, l: Layout) -> bool {
        self.admit && l == layout()
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        self.state.borrow().registers[&(a as usize + w * 4)]
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        self.state
            .borrow_mut()
            .registers
            .insert(a as usize + w * 4, v);
    }
    fn copy_tx(&mut self, a: u64, p: &[u8]) {
        assert_eq!(a, layout().tx_buffers);
        assert_eq!(p.len(), 60);
    }
    fn copy_rx(&mut self, a: u64, p: &mut [u8]) {
        assert_eq!(a, layout().rx_buffers);
        p.fill(0x33);
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

#[test]
fn actual_controller_backend_runs_ring_and_quarantines_on_reset_timeout() {
    let (c, s) = model();
    let pool = Box::leak(Box::new(Pool {
        state: s.clone(),
        admit: true,
    }));
    let backend = Box::leak(Box::new(Backend::new(c, pool)));
    let mut ring = Ring::new(backend, layout()).unwrap();
    ring.initialize().unwrap();
    ring.transmit(&[0; 60]).unwrap();
    assert_eq!(s.borrow().registers[&0x1120], 0x42000040);
    s.borrow_mut().registers.insert(0x4200000c, 0x30000000);
    assert_eq!(ring.reap(), Ok(1));
    s.borrow_mut().registers.insert(0x4200100c, 0x30000040);
    let mut output = [0; 64];
    assert_eq!(ring.receive(&mut output), Ok(Some(60)));
    assert_eq!(&output[..60], &[0x33; 60]);
    assert_eq!(s.borrow().registers[&0x1128], 0x42001000);
    s.borrow_mut().reset_stuck = true;
    assert!(!ring.shutdown());
    assert!(ring.quarantined());
    let memory: Vec<_> = s
        .borrow()
        .registers
        .iter()
        .filter(|(a, _)| **a >= 0x42000000)
        .map(|(a, v)| (*a, *v))
        .collect();
    assert!(ring.initialize().is_err());
    let after: Vec<_> = s
        .borrow()
        .registers
        .iter()
        .filter(|(a, _)| **a >= 0x42000000)
        .map(|(a, v)| (*a, *v))
        .collect();
    assert_eq!(memory, after);
    s.borrow_mut().reset_stuck = false;
    ring.initialize().unwrap();
    assert_eq!(ring.pending(), 0);
}

#[test]
fn backend_rejects_unowned_pool_before_dma_programming() {
    let (c, s) = model();
    let pool = Box::leak(Box::new(Pool {
        state: s.clone(),
        admit: false,
    }));
    let backend = Box::leak(Box::new(Backend::new(c, pool)));
    let mut ring = Ring::new(backend, layout()).unwrap();
    assert!(ring.initialize().is_err());
    assert!(ring.quarantined());
    assert!(!s.borrow().registers.contains_key(&0x1114));
    assert!(!s.borrow().registers.keys().any(|a| *a >= 0x42000000));
}
#[derive(Default)]
struct State {
    registers: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    reset_stuck: bool,
    sticky_enable: bool,
    drop_start: bool,
    ticks: u64,
    step: u64,
    mode_reads: usize,
}
struct Model(Rc<RefCell<State>>);
impl Registers for Model {
    fn read(&mut self, a: usize) -> u32 {
        let mut s = self.0.borrow_mut();
        if a == 0x1000 {
            s.mode_reads += 1;
        }
        if a == 0x1104 && s.sticky_enable {
            return 1;
        }
        *s.registers.get(&a).unwrap_or(&0)
    }
    fn write(&mut self, a: usize, v: u32) {
        let mut s = self.0.borrow_mut();
        s.writes.push((a, v));
        let value = if a == 0x1000 && !s.reset_stuck {
            0
        } else if s.drop_start && a == 0x1104 {
            v & !1
        } else {
            v
        };
        s.registers.insert(a, value);
    }
}
unsafe impl Io for Model {
    fn ticks(&mut self) -> u64 {
        let mut s = self.0.borrow_mut();
        let t = s.ticks;
        s.ticks = s.ticks.wrapping_add(s.step);
        t
    }
}
fn config() -> Config {
    Config {
        mac: [2, 3, 4, 5, 6, 7],
        speed: Speed::Mbps1000,
        full_duplex: true,
        csr_hz: 125_000_000,
        timebase_hz: 4_000_000,
        max_polls: 4,
    }
}
fn layout() -> Layout {
    Layout {
        tx_descriptors: 0x42000000,
        rx_descriptors: 0x42001000,
        tx_buffers: 0x42002000,
        rx_buffers: 0x42004000,
        count: 4,
        axi_bytes: 8,
    }
}
fn model() -> (Controller<Model>, Rc<RefCell<State>>) {
    let s = Rc::new(RefCell::new(State::default()));
    s.borrow_mut().registers.insert(0x120, 5 << 6 | 5);
    (Controller::new(Model(s.clone()), config()).unwrap(), s)
}

#[test]
fn configuration_matches_ring_contract_and_does_not_start_dma() {
    let (mut c, s) = model();
    c.reset().unwrap();
    s.borrow_mut().writes.clear();
    c.configure(layout()).unwrap();
    let s = s.borrow();
    let r = &s.registers;
    assert_eq!(r[&0xd00], 15 << 16 | 10);
    assert_eq!(r[&0xd30], 15 << 20 | 32);
    assert_eq!(r[&0x1100], 6 << 18);
    assert_eq!(r[&0x1104], 8 << 16 | 16);
    assert_eq!(r[&0x1108], 8 << 16 | 1536 << 1);
    assert_eq!(r[&0x1114], 0x42000000);
    assert_eq!(r[&0x111c], 0x42001000);
    assert_eq!(r[&0x1110], 0);
    assert_eq!(r[&0x1118], 0);
    assert_eq!(r[&0x112c], 3);
    assert_eq!(r[&0x1130], 3);
    assert_eq!(r[&0], 1 << 13);
    assert_eq!(r[&0x300], 0x80000706);
    assert_eq!(r[&0x304], 0x05040302);
    assert_eq!(r[&0xdc], 124);
    assert_eq!(r[&8], 0);
    assert_eq!(r[&0x1134], 0);
    assert_eq!(r[&0x1004] & (1 << 11), 0); // No extended address mode.
}

#[test]
fn reset_is_bounded_with_frozen_clock_and_never_retries_swr() {
    let (mut c, s) = model();
    s.borrow_mut().reset_stuck = true;
    assert_eq!(c.reset(), Err(Error::TimedOut));
    assert_eq!(s.borrow().mode_reads, 4);
    assert_eq!(
        s.borrow()
            .writes
            .iter()
            .filter(|p| **p == (0x1000, 1))
            .count(),
        1
    );
    let n = s.borrow().writes.len();
    assert_eq!(c.configure(layout()), Err(Error::NotReady));
    assert_eq!(s.borrow().writes.len(), n);
}

#[test]
fn reset_deadline_works_across_counter_wrap() {
    let (mut c, s) = model();
    {
        let mut s = s.borrow_mut();
        s.reset_stuck = true;
        s.ticks = u64::MAX - 200000;
        s.step = 400000;
    }
    assert_eq!(c.reset(), Err(Error::TimedOut));
    assert_eq!(s.borrow().mode_reads, 1);
}

#[test]
fn swr_clear_without_disabled_channel_does_not_prove_reset() {
    let (mut c, s) = model();
    s.borrow_mut().sticky_enable = true;
    assert_eq!(c.reset(), Err(Error::ResetFailed));
    assert_eq!(c.configure(layout()), Err(Error::NotReady));
}

#[test]
fn rejects_fifo_geometry_and_layout_before_configuration_writes() {
    for feature in [0, 3 << 6 | 5, 11 << 6 | 5, 5 << 6 | 12, u32::MAX] {
        let (mut c, s) = model();
        c.reset().unwrap();
        {
            let mut s = s.borrow_mut();
            s.registers.insert(0x120, feature);
            s.writes.clear();
        }
        assert_eq!(c.configure(layout()), Err(Error::UnsupportedFifo));
        assert!(s.borrow().writes.is_empty());
    }
    let (mut c, s) = model();
    c.reset().unwrap();
    s.borrow_mut().writes.clear();
    assert_eq!(
        c.configure(Layout {
            count: 0,
            ..layout()
        }),
        Err(Error::InvalidLayout)
    );
    assert!(s.borrow().writes.is_empty());
}

#[test]
fn start_requires_config_and_readback_stop_requires_new_reset() {
    let (mut c, s) = model();
    assert_eq!(c.start(), Err(Error::NotReady));
    c.reset().unwrap();
    c.configure(layout()).unwrap();
    c.start().unwrap();
    assert_eq!(s.borrow().registers[&0] & 3, 3);
    assert_eq!(c.configure(layout()), Err(Error::NotReady));
    s.borrow_mut().reset_stuck = true;
    assert_eq!(c.stop(), Err(Error::TimedOut));
    assert_eq!(c.start(), Err(Error::NotReady));
    s.borrow_mut().reset_stuck = false;
    c.reset().unwrap();
    c.configure(layout()).unwrap();
    s.borrow_mut().drop_start = true;
    assert_eq!(c.start(), Err(Error::StartFailed));
    assert_eq!(c.configure(layout()), Err(Error::NotReady));
}

#[test]
fn tails_are_validated_in_the_admitted_descriptor_ring() {
    let (mut c, s) = model();
    assert_eq!(c.tail(false, 0x42000000), Err(Error::NotReady));
    c.reset().unwrap();
    c.configure(layout()).unwrap();
    s.borrow_mut().writes.clear();
    for a in [0x41ffffff, 0x42000001, 0x42000100, 0x100000000] {
        assert_eq!(c.tail(false, a), Err(Error::InvalidLayout));
    }
    assert!(s.borrow().writes.is_empty());
    c.tail(false, 0x420000c0).unwrap();
    c.tail(true, 0x420010c0).unwrap();
    assert_eq!(
        s.borrow().writes,
        [(0x1120, 0x420000c0), (0x1128, 0x420010c0)]
    );
}

#[test]
fn invalid_configuration_and_mmio_window_are_rejected_without_io() {
    for bad in [
        Config {
            mac: [0; 6],
            ..config()
        },
        Config {
            mac: [1; 6],
            ..config()
        },
        Config {
            timebase_hz: 0,
            ..config()
        },
        Config {
            csr_hz: 0,
            ..config()
        },
        Config {
            max_polls: 0,
            ..config()
        },
        Config {
            max_polls: 1_000_001,
            ..config()
        },
    ] {
        let s = Rc::new(RefCell::new(State::default()));
        assert!(Controller::new(Model(s.clone()), bad).is_err());
        assert!(s.borrow().writes.is_empty());
    }
    unsafe {
        assert!(Mmio::new(1, 0x1164, || 0).is_err());
        assert!(Mmio::new(0x1000, 0x1160, || 0).is_err());
        assert!(Mmio::new(usize::MAX - 3, 0x1164, || 0).is_err());
    }
}

#[test]
fn mmio_adapter_uses_the_checked_window_and_firmware_clock() {
    use vibeos_eqos_net::controller::Io;
    let mut words = [0u32; 0x1164 / 4];
    let mut io = unsafe {
        Mmio::new(
            words.as_mut_ptr() as usize,
            core::mem::size_of_val(&words),
            || 123,
        )
        .unwrap()
    };
    io.write(0x1160, 0x12345678);
    io.write(0x200, 0xabcdef01);
    assert_eq!(words[0x1160 / 4], 0x12345678);
    assert_eq!(words[0x200 / 4], 0xabcdef01);
    assert_eq!(io.read(0x1160), 0x12345678);
    assert_eq!(io.ticks(), 123);
}

#[test]
fn speed_modes_keep_fcs_and_checksum_disabled() {
    for (speed, expected) in [
        (Speed::Mbps10, 1 << 15),
        (Speed::Mbps100, 3 << 14),
        (Speed::Mbps1000, 0),
    ] {
        let s = Rc::new(RefCell::new(State::default()));
        s.borrow_mut().registers.insert(0x120, 4 << 6 | 4);
        let mut c = Controller::new(
            Model(s.clone()),
            Config {
                speed,
                full_duplex: false,
                ..config()
            },
        )
        .unwrap();
        c.reset().unwrap();
        c.configure(layout()).unwrap();
        assert_eq!(s.borrow().registers[&0], expected);
    }
}
