//! Ordinary RAM models the CPU view; physical addresses are intentionally different.
use std::{cell::RefCell, rc::Rc};
use vibeos_eqos_net::{
    backend::Memory,
    pool::*,
    ring::{Direction, Layout},
};
use vibeos_hal::memory::*;
#[derive(Clone, Debug, PartialEq)]
enum Event {
    Validate(DmaRegion),
    Device(DmaRegion, DmaDirection),
    Cpu(DmaRegion, DmaDirection),
    Barrier,
}
struct Cache {
    events: Rc<RefCell<Vec<Event>>>,
    reject: u64,
}
unsafe impl DmaCache for Cache {
    fn validate(&self, r: DmaRegion) -> Result<(), MemoryError> {
        self.events.borrow_mut().push(Event::Validate(r));
        if r.physical == self.reject {
            Err(MemoryError::NotAddressable)
        } else {
            Ok(())
        }
    }
    fn for_device(&mut self, r: DmaRegion, d: DmaDirection) {
        self.events.borrow_mut().push(Event::Device(r, d));
    }
    fn for_cpu(&mut self, r: DmaRegion, d: DmaDirection) {
        self.events.borrow_mut().push(Event::Cpu(r, d));
    }
    fn barrier(&mut self) {
        self.events.borrow_mut().push(Event::Barrier);
    }
}
fn pool() -> (Pool<Cache, 4>, usize, Rc<RefCell<Vec<Event>>>) {
    let storage = Box::leak(Box::new(Storage::<4>::new()));
    let cpu = storage as *mut _ as usize;
    let events = Rc::new(RefCell::new(vec![]));
    let cache = Cache {
        events: events.clone(),
        reject: u64::MAX,
    };
    let pool = unsafe { Pool::new(storage, 0x42000000, cache, 8).unwrap() };
    (pool, cpu, events)
}
#[test]
fn layout_matches_storage_and_validates_every_slot() {
    let (p, cpu, e) = pool();
    assert_eq!(cpu % 64, 0);
    assert_eq!(core::mem::size_of::<Storage<4>>(), 12800);
    assert_eq!(
        p.layout(),
        Layout {
            tx_descriptors: 0x42000000,
            rx_descriptors: 0x42000100,
            tx_buffers: 0x42000200,
            rx_buffers: 0x42001a00,
            count: 4,
            axi_bytes: 8
        }
    );
    assert_eq!(e.borrow().len(), 16);
    assert!(p.admit(p.layout()));
    assert!(!p.admit(Layout {
        count: 3,
        ..p.layout()
    }));
}
#[test]
fn cpu_access_translates_from_physical_and_observes_dma_writeback() {
    let (mut p, cpu, _) = pool();
    let l = p.layout();
    p.write_word(l.tx_descriptors, 0, 0x12345678);
    assert_eq!(p.read_word(l.tx_descriptors, 0), 0x12345678);
    assert_eq!(
        unsafe { core::ptr::read_volatile(cpu as *const u32) },
        0x12345678u32.to_le()
    );
    p.copy_tx(l.tx_buffers, &[0xab; 60]);
    assert_eq!(
        unsafe { core::slice::from_raw_parts((cpu + 512) as *const u8, 60) },
        &[0xab; 60]
    );
    // Emulate external DMA, not a second CPU owner in production.
    unsafe {
        core::ptr::write_bytes((cpu + 6656) as *mut u8, 0x5a, 60);
    }
    let mut output = [0; 64];
    p.copy_rx(l.rx_buffers, &mut output[..60]);
    assert_eq!(&output[..60], &[0x5a; 60]);
    assert_eq!(&output[60..], &[0; 4]);
}
#[test]
fn synchronization_uses_physical_addresses_and_exact_direction() {
    let (mut p, _, e) = pool();
    e.borrow_mut().clear();
    let l = p.layout();
    p.for_device(l.tx_buffers, 1536, Direction::ToDevice);
    p.for_cpu(l.rx_buffers, 1536, Direction::FromDevice);
    p.barrier();
    assert_eq!(
        *e.borrow(),
        [
            Event::Device(
                DmaRegion {
                    physical: l.tx_buffers,
                    bytes: 1536
                },
                DmaDirection::ToDevice
            ),
            Event::Cpu(
                DmaRegion {
                    physical: l.rx_buffers,
                    bytes: 1536
                },
                DmaDirection::FromDevice
            ),
            Event::Barrier
        ]
    );
}
#[test]
fn wide_unaligned_and_partially_unflushable_pools_are_rejected() {
    for physical in [0x42000001, 0xfffff000, 0x100000000, u64::MAX] {
        let e = Rc::new(RefCell::new(vec![]));
        let storage = Box::leak(Box::new(Storage::<4>::new()));
        assert!(unsafe {
            Pool::new(
                storage,
                physical,
                Cache {
                    events: e.clone(),
                    reject: u64::MAX,
                },
                8,
            )
        }
        .is_err());
        assert!(e.borrow().is_empty());
    }
    let e = Rc::new(RefCell::new(vec![]));
    let storage = Box::leak(Box::new(Storage::<4>::new()));
    assert!(unsafe {
        Pool::new(
            storage,
            0x42000000,
            Cache {
                events: e,
                reject: 0x42000040,
            },
            8,
        )
    }
    .is_err());
}
#[test]
fn invalid_raw_callbacks_cannot_escape_the_admitted_storage() {
    for which in 0..5 {
        let (mut p, _, _) = pool();
        let l = p.layout();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match which {
            0 => p.write_word(l.tx_descriptors, 4, 0),
            1 => p.write_word(l.rx_buffers, 0, 0),
            2 => p.copy_tx(l.rx_buffers, &[0; 60]),
            3 => p.copy_rx(l.rx_buffers + 1536 * 4, &mut [0; 64]),
            _ => p.for_device(l.tx_descriptors, 12864, Direction::Bidirectional),
        }));
        assert!(result.is_err());
    }
}

#[test]
fn partial_sync_stays_within_one_buffer_and_whole_cache_lines() {
    let (mut p, _, _) = pool();
    let l = p.layout();
    p.for_device(l.tx_buffers, 64, Direction::ToDevice);
    p.for_cpu(l.rx_buffers, 128, Direction::FromDevice);
    for length in [0, 1, 63, 65, 1600] {
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            p.for_device(l.tx_buffers, length, Direction::ToDevice))).is_err());
    }
}

#[test]
fn larger_rx_pool_validates_all_spares_without_expanding_descriptor_rings() {
    let storage = Box::leak(Box::new(Storage::<4, 9>::new()));
    let events = Rc::new(RefCell::new(vec![]));
    let cache = Cache { events: events.clone(), reject: u64::MAX };
    let mut pool = unsafe { Pool::new(storage, 0x42000000, cache, 8).unwrap() };
    let layout = pool.layout();
    assert_eq!(layout.count, 4);
    assert_eq!(core::mem::size_of::<Storage<4, 9>>(), 12800 + 5 * 1536);
    assert!(pool.admit_rx_buffers(layout, 9)); assert!(!pool.admit_rx_buffers(layout, 8));
    let last = layout.rx_buffers + 8 * 1536;
    assert!(events.borrow().contains(&Event::Validate(DmaRegion { physical: last, bytes: 1536 })));
    pool.for_device(last, 1536, Direction::FromDevice);
    pool.for_cpu(last, 64, Direction::FromDevice);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        pool.for_cpu(last + 1536, 64, Direction::FromDevice))).is_err());
}

#[test]
fn detached_read_view_uses_original_bytes_and_does_not_borrow_the_engine() {
    let storage = Box::leak(Box::new(Storage::<4, 8>::new()));
    let cpu = storage as *mut Storage<4, 8> as *mut u8;
    let cache = Cache { events: Rc::new(RefCell::new(vec![])), reject: u64::MAX };
    let mut pool = unsafe { Pool::new(storage, 0x42000000, cache, 8).unwrap() };
    let layout = pool.layout();
    let offset = (layout.rx_buffers - 0x42000000) as usize + 6 * 1536;
    // Simulate completed DMA before taking an immutable read borrow.
    unsafe { core::ptr::write_bytes(cpu.add(offset), 0x6b, 60); }
    pool.for_cpu(layout.rx_buffers + 6 * 1536, 64, Direction::FromDevice);
    let view = pool.rx_view();
    let same_address = unsafe { view.read(6, 60, |data| {
        assert_eq!(data, &[0x6b; 60]);
        // Concurrent controller/descriptor work touches a disjoint region.
        pool.write_word(layout.tx_descriptors, 0, 123);
        data.as_ptr() == cpu.add(offset).cast_const()
    }).unwrap() };
    assert!(same_address, "read must expose the detached DMA bytes, not scratch storage");
    assert_eq!(unsafe { view.read(8, 60, |_| ()) }, Err(Error::Layout));
    assert_eq!(unsafe { view.read(6, 1537, |_| ()) }, Err(Error::Layout));
}

#[test]
fn raw_reattach_preserves_a_detached_read_without_a_whole_storage_mutable_borrow() {
    let storage = Box::leak(Box::new(Storage::<4, 8>::new()));
    let raw = storage as *mut Storage<4, 8>;
    let make_cache = || Cache { events: Rc::new(RefCell::new(vec![])), reject: u64::MAX };
    let pool = unsafe { Pool::new(storage, 0x42000000, make_cache(), 8).unwrap() };
    let layout = pool.layout(); let offset = (layout.rx_buffers - 0x42000000) as usize + 7 * 1536;
    unsafe { core::ptr::write_bytes(raw.cast::<u8>().add(offset), 0x39, 64); }
    let view = pool.rx_view();
    drop(pool); // The previous engine is quiescent; the permanent bytes remain.
    unsafe { view.read(7, 64, |data| {
        let mut next = Pool::from_raw(raw, 0x42000000, make_cache(), 8).unwrap();
        next.write_word(layout.rx_descriptors, 0, 0x1234);
        assert_eq!(data, &[0x39; 64]);
    }).unwrap(); }
}
