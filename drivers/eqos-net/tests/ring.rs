//! Software DMA model. It validates sequencing, never cache instructions/MMIO.
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use vibeos_eqos_net::{descriptor, ring::*};

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Recycle(u64, usize),
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
    fast_recycle: bool,
    tx_checksum: bool,
    tx_data: Vec<u8>,
    tx_source: usize,
}
struct Model(Rc<RefCell<State>>);
unsafe impl Backend for Model {
    fn tx_checksum_capable(&self) -> bool { self.0.borrow().tx_checksum }
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
        let mut s = self.0.borrow_mut();
        s.events.push(Event::Tx(a, p.len()));
        s.tx_data = p.to_vec();
        s.tx_source = p.as_ptr() as usize;
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
    unsafe fn recycle_rx(&mut self, a: u64, n: usize) {
        if self.0.borrow().fast_recycle {
            self.0.borrow_mut().events.push(Event::Recycle(a, n));
            self.barrier();
        } else {
            self.for_device(a, n, Direction::FromDevice);
        }
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
        fast_recycle: false,
        tx_checksum: false,
        tx_data: Vec::new(),
        tx_source: 0,
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
        s.borrow_mut().words.insert((tx, 3), 0x10000000);
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
            Event::Device(b, 64, Direction::ToDevice),
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
            Event::Cpu(b, 64, Direction::FromDevice),
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

#[test]
fn small_packets_sync_only_complete_cache_lines() {
    for length in [60usize, 65, 1514] {
        let (mut r, s) = started();
        r.transmit(&vec![0; length]).unwrap();
        let span = length.div_ceil(STRIDE) * STRIDE;
        assert!(s.borrow().events.contains(&Event::Device(layout().tx_buffers, span, Direction::ToDevice)));
        s.borrow_mut().words.insert((layout().rx_descriptors, 3), 0x30000000 | (length as u32 + 4));
        r.receive(&mut [0; BUFFER]).unwrap();
        assert!(s.borrow().events.contains(&Event::Cpu(layout().rx_buffers, span, Direction::FromDevice)));
        // Full RX buffer remains prepared before returning ownership to DMA.
        assert!(s.borrow().events.contains(&Event::Device(layout().rx_buffers, BUFFER, Direction::FromDevice)));
    }
}

#[test]
fn checksum_request_respects_hardware_and_own_publication() {
    for hardware in [false, true] {
        let (mut r, s) = started();s.borrow_mut().tx_checksum = hardware;
        let mut f = [0u8;54];f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14]=0x45;f[16..18].copy_from_slice(&40u16.to_be_bytes());f[23]=6;f[46]=0x50;
        let before = f;
        r.transmit_checksum(&f).unwrap();
        assert_eq!(f, before);
        assert_eq!(s.borrow().tx_source == f.as_ptr() as usize, hardware);
        let words=&s.borrow().words;
        let status=words[&(layout().tx_descriptors,3)];
        assert_eq!((status>>16)&3, if hardware {3} else {0});
        assert_ne!(status & descriptor::OWN,0);
        assert_eq!(s.borrow().tx_data[24..26]==[0,0],hardware);
        assert_eq!(s.borrow().tx_data[50..52]==[0,0],hardware);
        assert_eq!(s.borrow().events.last(),Some(&Event::Tail(false,layout().tx_descriptors+STRIDE as u64)));
    }
}

#[test]
fn checksum_request_rejection_never_publishes_and_fallback_preserves_caller() {
    let (mut r, s) = started();
    s.borrow_mut().tx_checksum = true;
    let mut f = [0u8;54]; f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    f[14]=0x45; f[16..18].copy_from_slice(&40u16.to_be_bytes()); f[23]=6; f[46]=0x50;
    for (at, value) in [(14,0x44), (20,0x20), (21,1), (46,0x10)] {
        let mut invalid=f;invalid[at]=value;
        s.borrow_mut().events.clear();
        assert_eq!(r.transmit_checksum(&invalid),Err(Error::Packet));
        assert!(s.borrow().events.is_empty());
    }
    f[24]=0xaa;f[50]=0xbb;
    let before=f;r.transmit_checksum(&f).unwrap();
    assert_eq!(f,before);
    assert_ne!(s.borrow().tx_source,f.as_ptr() as usize);
    assert_eq!(&s.borrow().tx_data[24..26],&[0,0]);
    assert_eq!(&s.borrow().tx_data[50..52],&[0,0]);
    assert_eq!((s.borrow().words[&(layout().tx_descriptors,3)]>>16)&3,3);
}

#[test]
fn rx_status_is_read_only_after_completion_and_before_slot_rearm() {
    use vibeos_eqos_net::descriptor::RxChecksum as C;
    let (mut r, s) = started();
    let desc=layout().rx_descriptors;
    let complete=(1<<29)|(1<<28)|(1<<26)|64;
    s.borrow_mut().events.clear();
    s.borrow_mut().words.insert((desc,1),0x12);
    s.borrow_mut().words.insert((desc,3),complete|descriptor::OWN);
    assert_eq!(r.receive_with_status(&mut [0;BUFFER]).unwrap(),None);
    assert!(!s.borrow().events.contains(&Event::Read(desc,1)));
    s.borrow_mut().words.insert((desc,3),complete);
    s.borrow_mut().events.clear();
    let mut output=[0;BUFFER];
    let frame=r.receive_with_status(&mut output).unwrap().unwrap();
    assert_eq!(frame.bytes,60);assert_eq!(frame.checksum,C::Ipv4 { payload_type:2 });
    assert_eq!(&output[..60],&[0x5a;60]);
    let state=s.borrow();let events=&state.events;
    let status=events.iter().position(|e| *e==Event::Read(desc,3)).unwrap();
    let detail=events.iter().position(|e| *e==Event::Read(desc,1)).unwrap();
    let rearm=events.iter().position(|e| matches!(e,Event::Word(a,_,_) if *a==desc)).unwrap();
    assert!(status<detail && detail<rearm);
    drop(state);
    // The next slot has no valid metadata: stale word 1 must not be observed.
    let next=desc+STRIDE as u64;
    s.borrow_mut().words.insert((next,1),0x12);
    s.borrow_mut().words.insert((next,3),complete & !(1<<26));
    s.borrow_mut().events.clear();
    assert_eq!(r.receive_with_status(&mut output).unwrap().unwrap().checksum,C::Unavailable);
    assert!(!s.borrow().events.contains(&Event::Read(next,1)));
}

#[test]
fn rejected_rx_keeps_error_evidence_without_copying_payload() {
    let (mut r,s)=started();
    let desc=layout().rx_descriptors;
    let status=(1<<29)|(1<<28)|(1<<26)|(1<<15)|64;
    s.borrow_mut().words.insert((desc,1),0x92);
    s.borrow_mut().words.insert((desc,3),status|descriptor::OWN);
    assert_eq!(r.receive_with_status(&mut [0;BUFFER]).unwrap(),None);
    assert_eq!(r.rx_diagnostics().rejected,0);
    s.borrow_mut().words.insert((desc,3),status);
    s.borrow_mut().events.clear();
    assert_eq!(r.receive_with_status(&mut [0;BUFFER]),Err(Error::Descriptor(descriptor::Error::Hardware)));
    assert_eq!(r.rx_diagnostics(),RxDiagnostics { rejected:1,last_status:status,last_word1:0x92 });
    assert!(!s.borrow().events.iter().any(|e| matches!(e,Event::Rx(..))));
    assert!(s.borrow().events.contains(&Event::Read(desc,1)));
    assert_eq!(s.borrow().words[&(desc,3)] & descriptor::OWN,descriptor::OWN);
    let next=desc+STRIDE as u64;
    s.borrow_mut().words.insert((next,1),0x92);
    s.borrow_mut().words.insert((next,3),status & !(1<<26));
    s.borrow_mut().events.clear();
    assert!(r.receive_with_status(&mut [0;BUFFER]).is_err());
    assert_eq!(r.rx_diagnostics().rejected,2);
    assert_eq!(r.rx_diagnostics().last_word1,0);
    assert!(!s.borrow().events.contains(&Event::Read(next,1)));
}

#[test]
fn readonly_recycle_is_after_completion_before_own_and_never_initialization() {
    let (mut r, state) = model();
    state.borrow_mut().fast_recycle = true;
    r.initialize().unwrap();
    assert!(!state.borrow().events.iter().any(|e| matches!(e, Event::Recycle(..))));
    assert_eq!(state.borrow().events.iter().filter(|e| matches!(e,
        Event::Device(_, BUFFER, Direction::FromDevice))).count(), layout().count);
    for (slot, status, output_len) in [(0, 0x30000040, 64), (1, 0x30008040, 64), (2, 0x30000040, 59)] {
        let d = layout().rx_descriptors + slot * STRIDE as u64;
        let b = layout().rx_buffers + slot * BUFFER as u64;
        state.borrow_mut().events.clear();
        state.borrow_mut().words.insert((d, 3), status);
        let _ = r.receive(&mut vec![0; output_len]);
        let s = state.borrow();
        let recycle = s.events.iter().position(|e| *e == Event::Recycle(b, BUFFER)).unwrap();
        let own = s.events.iter().position(|e| matches!(e, Event::Word(a, 3, v) if *a == d && v & descriptor::OWN != 0)).unwrap();
        assert!(recycle < own);
        assert!(!s.events.iter().any(|e| matches!(e, Event::Device(_, _, Direction::FromDevice))));
        if slot == 0 {
            assert!(s.events.iter().position(|e| *e == Event::Rx(b, 60)).unwrap() < recycle);
        } else {
            assert!(!s.events.iter().any(|e| matches!(e, Event::Rx(..))));
        }
    }
    assert!(r.shutdown());
    state.borrow_mut().events.clear();
    r.initialize().unwrap();
    assert!(!state.borrow().events.iter().any(|e| matches!(e, Event::Recycle(..))));
    assert_eq!(state.borrow().events.iter().filter(|e| matches!(e,
        Event::Device(_, BUFFER, Direction::FromDevice))).count(), layout().count);
}

#[test]
fn single_tx_sync_orders_payload_fields_own_flush_and_tail() {
    let (mut r, s) = model();
    r.set_single_tx_sync(true).unwrap();
    r.initialize().unwrap();
    assert_eq!(r.set_single_tx_sync(false), Err(Error::Controller));
    s.borrow_mut().events.clear();
    r.transmit(&[7; 60]).unwrap();
    let d = layout().tx_descriptors;
    let b = layout().tx_buffers;
    assert_eq!(s.borrow().events, vec![
        Event::Tx(b, 60), Event::Device(b, 64, Direction::ToDevice),
        Event::Word(d, 0, b as u32), Event::Word(d, 1, 0),
        Event::Word(d, 2, 60), Event::Word(d, 3, 0x3000003c),
        Event::Barrier, Event::Word(d, 3, 0xb000003c),
        Event::Device(d, 64, Direction::Bidirectional), Event::Barrier,
        Event::Tail(false, d + 64),
    ]);
    // A still-owned TX slot cannot be overwritten, even in the faster mode.
    for _ in 0..2 { r.transmit(&[8;60]).unwrap(); }
    s.borrow_mut().events.clear();
    assert_eq!(r.transmit(&[9;60]), Err(Error::Full));
    assert!(!s.borrow().events.iter().any(|e| matches!(e, Event::Tx(..) | Event::Word(..))));
    // RX retains its conservative two descriptor visibility operations.
    let rx = layout().rx_descriptors;
    s.borrow_mut().words.insert((rx, 3), 0x30000040);
    s.borrow_mut().events.clear();
    assert_eq!(r.receive(&mut [0;64]), Ok(Some(60)));
    assert_eq!(s.borrow().events.iter().filter(|e| **e == Event::Device(rx,64,Direction::Bidirectional)).count(),2);
    r.fault();
    assert_eq!(r.set_single_tx_sync(false), Err(Error::Controller));
    assert!(r.shutdown());
    r.set_single_tx_sync(false).unwrap();
}
