//! Cache command model: no physical L1/L2 coherence or MMIO timing is tested.
use std::{cell::RefCell, rc::Rc};
use vibeos_hal::memory::{DmaCache, DmaDirection, DmaRegion};
use vibeos_platform_jh7110::cache::*;
#[derive(Clone, Debug, PartialEq)]
enum Event {
    Read(usize),
    Write(usize, u64),
    Barrier,
}
struct Model {
    events: Rc<RefCell<Vec<Event>>>,
    config: u32,
    ways: u32,
}
unsafe impl Registers for Model {
    fn read32(&mut self, o: usize) -> u32 {
        self.events.borrow_mut().push(Event::Read(o));
        match o {
            0 => self.config,
            8 => self.ways,
            _ => panic!("unexpected register"),
        }
    }
    fn write64(&mut self, o: usize, v: u64) {
        self.events.borrow_mut().push(Event::Write(o, v));
    }
    fn barrier(&mut self) {
        self.events.borrow_mut().push(Event::Barrier);
    }
}
fn cache() -> (Cache<Model>, Rc<RefCell<Vec<Event>>>) {
    let events = Rc::new(RefCell::new(vec![]));
    let c = Cache::new(Model {
        events: events.clone(),
        config: 0x060b1001,
        ways: 15,
    })
    .unwrap();
    events.borrow_mut().clear();
    (c, events)
}
#[test]
fn every_line_uses_full_physical_address_and_following_barrier() {
    let (mut c, e) = cache();
    c.flush(DmaRegion {
        physical: 0x100000000,
        bytes: 128,
    })
    .unwrap();
    assert_eq!(
        *e.borrow(),
        [
            Event::Barrier,
            Event::Write(0x200, 0x100000000),
            Event::Barrier,
            Event::Write(0x200, 0x100000040),
            Event::Barrier
        ]
    );
}
#[test]
fn every_direction_uses_sdk_clean_invalidate_sequence() {
    let (mut c, e) = cache();
    let r = DmaRegion {
        physical: 0x42000000,
        bytes: 64,
    };
    for d in [
        DmaDirection::ToDevice,
        DmaDirection::FromDevice,
        DmaDirection::Bidirectional,
    ] {
        c.for_device(r, d);
        c.for_cpu(r, d);
    }
    assert_eq!(e.borrow().len(), 18);
    for chunk in e.borrow().chunks(3) {
        assert_eq!(
            chunk,
            [
                Event::Barrier,
                Event::Write(0x200, 0x42000000),
                Event::Barrier
            ]
        );
    }
}
#[test]
fn invalid_span_does_not_round_into_unowned_lines_or_touch_hardware() {
    let (mut c, e) = cache();
    for (physical, bytes) in [
        (0x42000000, 0),
        (0x42000001, 64),
        (0x42000000, 65),
        (0x40000000, 64),
        (0x13fffffc0, 128),
        (0x140000000, 64),
        (u64::MAX - 63, 128),
    ] {
        assert!(c.flush(DmaRegion { physical, bytes }).is_err());
        assert!(e.borrow().is_empty());
    }
    c.flush(DmaRegion {
        physical: 0x13fffffc0,
        bytes: 64,
    })
    .unwrap();
    assert_eq!(e.borrow()[1], Event::Write(0x200, 0x13fffffc0));
}
#[test]
fn reject_wrong_line_geometry_and_disabled_way_range() {
    for (config, ways) in [
        (0, 0),
        (0x070b1001, 15),
        (0x060b0001, 0),
        (0x060b1000, 0),
        (0x060b1001, 16),
        (0x060b2101, 0),
    ] {
        let e = Rc::new(RefCell::new(vec![]));
        assert!(Cache::new(Model {
            events: e.clone(),
            config,
            ways
        })
        .is_err());
        assert_eq!(*e.borrow(), [Event::Read(0), Event::Read(8)]);
    }
}
#[test]
fn mmio_resource_geometry_is_exact() {
    unsafe {
        assert!(Mmio::new(vibeos_hal::AddressRange::new(0x2010000, 0x2011000)).is_err());
        assert!(Mmio::new(vibeos_hal::AddressRange::new(0x2010004, 0x2014000)).is_err());
        assert!(Mmio::new(CONTROL).is_ok());
    }
}
