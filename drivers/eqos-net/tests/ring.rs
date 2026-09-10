//! Software DMA model. It validates sequencing, never cache instructions/MMIO.
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use vibeos_eqos_net::{descriptor, ring::*};

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Reset,
    Configure,
    Start,
    Stop,
    Barrier,
    Word(u64, usize, u32),
    Read(u64, usize),
    Device(u64, usize, Direction),
    Cpu(u64, usize, Direction),
    Tx(u64, usize),
    Rx(u64, usize),
    Tail(bool, u64),
}
struct State {
    events: Vec<Event>,
    words: BTreeMap<(u64, usize), u32>,
    reset: bool,
    stop: bool,
    start: bool,
    configure: bool,
}
struct Model(Rc<RefCell<State>>);
unsafe impl Backend for Model {
    fn reset(&mut self) -> bool {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Reset);
        s.reset
    }
    fn configure(&mut self, _: Layout) -> bool {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Configure);
        s.configure
    }
    fn start(&mut self) -> bool {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Start);
        s.start
    }
    fn stop(&mut self) -> bool {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Stop);
        s.stop
    }
    fn read_word(&mut self, a: u64, w: usize) -> u32 {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Read(a, w));
        *s.words.get(&(a, w)).unwrap_or(&0)
    }
    fn write_word(&mut self, a: u64, w: usize, v: u32) {
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Word(a, w, v));
        s.words.insert((a, w), v);
    }
    fn copy_tx(&mut self, a: u64, p: &[u8]) {
        self.0.borrow_mut().events.push(Event::Tx(a, p.len()));
    }
    fn copy_rx(&mut self, a: u64, p: &mut [u8]) {
        self.0.borrow_mut().events.push(Event::Rx(a, p.len()));
        p.fill(0x5a);
    }
    fn for_device(&mut self, a: u64, n: usize, d: Direction) {
        self.0.borrow_mut().events.push(Event::Device(a, n, d));
    }
    fn for_cpu(&mut self, a: u64, n: usize, d: Direction) {
        self.0.borrow_mut().events.push(Event::Cpu(a, n, d));
    }
    fn barrier(&mut self) {
        self.0.borrow_mut().events.push(Event::Barrier);
    }
    fn tail(&mut self, rx: bool, a: u64) {
        self.0.borrow_mut().events.push(Event::Tail(rx, a));
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
fn model() -> (Ring<Model>, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State {
        events: vec![],
        words: BTreeMap::new(),
        reset: true,
        stop: true,
        start: true,
        configure: true,
    }));
    let backend = Box::leak(Box::new(Model(state.clone())));
    (Ring::new(backend, layout()).unwrap(), state)
}
fn started() -> (Ring<Model>, Rc<RefCell<State>>) {
    let (mut r, s) = model();
    r.initialize().unwrap();
    s.borrow_mut().events.clear();
    (r, s)
}

#[test]
fn backend_must_admit_pool_before_any_descriptor_or_buffer_access() {
    let (mut r, s) = model();
    s.borrow_mut().configure = false;
    assert_eq!(r.initialize(), Err(Error::Controller));
    assert!(r.quarantined());
    assert_eq!(s.borrow().events, vec![Event::Reset, Event::Configure]);
}

#[test]
fn both_rings_wrap_repeatedly_without_changing_slot_to_buffer_mapping() {
    let (mut r, s) = started();
    for cycle in 0..12 {
        let slot = cycle % 4;
        let tx = layout().tx_descriptors + (slot * 64) as u64;
        let rx = layout().rx_descriptors + (slot * 64) as u64;
        s.borrow_mut().events.clear();
        r.transmit(&[0; 60]).unwrap();
        assert!(s
            .borrow()
            .events
            .contains(&Event::Tx(layout().tx_buffers + (slot * 1536) as u64, 60)));
        assert_eq!(
            s.borrow().events.last(),
            Some(&Event::Tail(
                false,
                layout().tx_descriptors + (((slot + 1) % 4) * 64) as u64
            ))
        );
        s.borrow_mut().words.insert((tx, 3), 0x30000000);
        assert_eq!(r.reap(), Ok(1));
        s.borrow_mut().words.insert((rx, 3), 0x30000040);
        assert_eq!(r.receive(&mut [0; 64]), Ok(Some(60)));
        assert!(s
            .borrow()
            .events
            .contains(&Event::Rx(layout().rx_buffers + (slot * 1536) as u64, 60)));
        assert_eq!(s.borrow().events.last(), Some(&Event::Tail(true, rx)));
        assert_eq!(r.pending(), 0);
    }
}

#[test]
fn validate_all_spans_and_cache_line_isolation() {
    assert_eq!(layout().validate(), Ok(()));
    for bad in [
        Layout {
            count: 0,
            ..layout()
        },
        Layout {
            count: 1025,
            ..layout()
        },
        Layout {
            tx_buffers: 0xffff_ffc0,
            ..layout()
        },
        Layout {
            rx_buffers: u64::MAX,
            ..layout()
        },
        Layout {
            rx_descriptors: 0x42000040,
            ..layout()
        },
        Layout {
            tx_buffers: 0x42001000,
            ..layout()
        },
        Layout {
            rx_buffers: 0x42002040,
            ..layout()
        },
        Layout {
            tx_descriptors: 0x42000001,
            ..layout()
        },
        Layout {
            axi_bytes: 4,
            ..layout()
        },
    ] {
        assert_eq!(bad.validate(), Err(Error::Layout));
    }
}

#[test]
fn transmit_orders_copy_cache_words_own_cache_tail() {
    let (mut r, s) = started();
    r.transmit(&[7; 60]).unwrap();
    let d = layout().tx_descriptors;
    let b = layout().tx_buffers;
    assert_eq!(
        s.borrow().events,
        vec![
            Event::Tx(b, 60),
            Event::Device(b, 1536, Direction::ToDevice),
            Event::Word(d, 0, b as u32),
            Event::Word(d, 1, 0),
            Event::Word(d, 2, 60),
            Event::Word(d, 3, 0x3000003c),
            Event::Device(d, 64, Direction::Bidirectional),
            Event::Barrier,
            Event::Word(d, 3, 0xb000003c),
            Event::Device(d, 64, Direction::Bidirectional),
            Event::Barrier,
            Event::Tail(false, d + 64)
        ]
    );
}

#[test]
fn no_copy_when_busy_full_or_invalid_and_fifo_reap_wraps() {
    let (mut r, s) = started();
    assert_eq!(r.transmit(&[0; 1519]), Err(Error::Packet));
    assert!(s.borrow().events.is_empty());
    for _ in 0..3 {
        r.transmit(&[0; 60]).unwrap();
    }
    assert_eq!(r.pending(), 3);
    s.borrow_mut().events.clear();
    assert_eq!(r.transmit(&[0; 60]), Err(Error::Full));
    assert!(!s
        .borrow()
        .events
        .iter()
        .any(|e| matches!(e, Event::Tx(..) | Event::Word(..) | Event::Tail(..))));
    s.borrow_mut()
        .words
        .insert((layout().tx_descriptors, 3), 0x30000000);
    assert_eq!(r.reap(), Ok(1));
    r.transmit(&[0; 60]).unwrap();
    assert_eq!(r.pending(), 3);
    assert_eq!(
        s.borrow().events.last(),
        Some(&Event::Tail(false, layout().tx_descriptors))
    );
}

#[test]
fn receive_uses_private_buffer_mapping_and_rearms_after_copy() {
    let (mut r, s) = started();
    let d = layout().rx_descriptors;
    let b = layout().rx_buffers;
    {
        let mut s = s.borrow_mut();
        s.words.insert((d, 0), 0xdeadbeef);
        s.words.insert((d, 3), 0x30000040);
    }
    let mut output = [0; 64];
    assert_eq!(r.receive(&mut output), Ok(Some(60)));
    assert_eq!(&output[..60], &[0x5a; 60]);
    assert_eq!(&output[60..], &[0; 4]);
    let events = &s.borrow().events;
    assert_eq!(
        &events[..5],
        &[
            Event::Cpu(d, 64, Direction::Bidirectional),
            Event::Barrier,
            Event::Read(d, 3),
            Event::Cpu(b, 1536, Direction::FromDevice),
            Event::Rx(b, 60)
        ]
    );
    assert_eq!(events.last(), Some(&Event::Tail(true, d)));
    assert_eq!(s.borrow().words[&(d, 3)], descriptor::OWN | (1 << 24));
}

#[test]
fn malformed_and_small_output_drop_without_copy_then_advance() {
    let (mut r, s) = started();
    let d = layout().rx_descriptors;
    s.borrow_mut().words.insert((d, 3), 0x30008040);
    assert_eq!(
        r.receive(&mut [0; 64]),
        Err(Error::Descriptor(descriptor::Error::Hardware))
    );
    s.borrow_mut().words.insert((d + 64, 3), 0x30000040);
    assert_eq!(r.receive(&mut [0; 59]), Err(Error::OutputTooSmall));
    assert!(!s.borrow().events.iter().any(|e| matches!(e, Event::Rx(..))));
    assert_eq!(s.borrow().events.last(), Some(&Event::Tail(true, d + 64)));
    s.borrow_mut().events.clear();
    assert_eq!(r.receive(&mut [0; 64]), Ok(None));
    assert!(!s.borrow().events.iter().any(|e| matches!(
        e,
        Event::Device(..) | Event::Word(..) | Event::Rx(..) | Event::Tail(..)
    )));
}

#[test]
fn failed_stop_quarantines_and_failed_reset_cannot_touch_old_dma() {
    let (mut r, s) = started();
    r.transmit(&[0; 60]).unwrap();
    s.borrow_mut().stop = false;
    assert!(!r.shutdown());
    assert!(r.quarantined());
    s.borrow_mut().events.clear();
    assert_eq!(r.transmit(&[0; 60]), Err(Error::Offline));
    assert_eq!(r.receive(&mut [0; 64]), Err(Error::Offline));
    assert!(s.borrow().events.is_empty());
    s.borrow_mut().reset = false;
    assert_eq!(r.initialize(), Err(Error::Controller));
    assert_eq!(s.borrow().events, vec![Event::Reset]);
    assert_eq!(r.pending(), 1);
    {
        let mut s = s.borrow_mut();
        s.reset = true;
        s.events.clear();
    }
    r.initialize().unwrap();
    assert_eq!(r.pending(), 0);
    assert!(!r.quarantined());
    assert_eq!(&s.borrow().events[..2], &[Event::Reset, Event::Configure]);
    assert!(!s.borrow().events.iter().any(|e| matches!(e, Event::Tx(..))));
}

#[test]
fn completion_error_or_external_timeout_quarantines_without_retry() {
    let (mut r, s) = started();
    r.transmit(&[0; 60]).unwrap();
    s.borrow_mut()
        .words
        .insert((layout().tx_descriptors, 3), 0x30008000);
    assert_eq!(
        r.reap(),
        Err(Error::Descriptor(descriptor::Error::Hardware))
    );
    assert!(r.quarantined());
    assert_eq!(r.pending(), 1);
    r.initialize().unwrap();
    r.transmit(&[0; 60]).unwrap();
    r.fault();
    assert_eq!(r.reap(), Err(Error::Offline));
    assert!(r.shutdown());
    assert_eq!(r.pending(), 0);
}

#[test]
fn failed_start_never_admits_packets_and_live_initialize_is_rejected() {
    let (mut r, s) = model();
    s.borrow_mut().start = false;
    assert_eq!(r.initialize(), Err(Error::Controller));
    assert!(r.quarantined());
    assert_eq!(r.transmit(&[0; 60]), Err(Error::Offline));
    s.borrow_mut().start = true;
    r.initialize().unwrap();
    s.borrow_mut().events.clear();
    assert_eq!(r.initialize(), Err(Error::Controller));
    assert!(s.borrow().events.is_empty());
}
