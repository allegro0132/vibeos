use std::sync::Arc;

use vibeos_core::interrupt::{
    plic_enable_location, AtomicIrqHandlerSlot, IrqHandlerPublication, SpscByteRing, PLIC_MAX_IRQ,
};

#[test]
fn source_zero_is_reserved() {
    assert_eq!(plic_enable_location(0), None);
}

#[test]
fn enable_words_cross_the_31_32_boundary() {
    assert_eq!(plic_enable_location(31), Some((0, 31)));
    assert_eq!(plic_enable_location(32), Some((1, 0)));
}

#[test]
fn highest_qemu_source_uses_the_last_word() {
    assert_eq!(PLIC_MAX_IRQ, 1023);
    assert_eq!(plic_enable_location(PLIC_MAX_IRQ), Some((31, 31)));
}

#[test]
fn sources_beyond_the_context_are_rejected() {
    assert_eq!(plic_enable_location(PLIC_MAX_IRQ + 1), None);
    assert_eq!(plic_enable_location(u32::MAX), None);
}

#[test]
fn atomic_handler_slot_publishes_and_revokes_complete_records() {
    let slot = AtomicIrqHandlerSlot::new();
    assert_eq!(slot.try_snapshot(), Ok(None));

    let record = IrqHandlerPublication {
        irq: 10,
        callback: 0x1111,
        context: 0xaaaa,
    };
    unsafe { slot.publish_exclusive(Some(record)) };
    assert_eq!(slot.try_snapshot(), Ok(Some(record)));

    unsafe { slot.publish_exclusive(None) };
    assert_eq!(slot.try_snapshot(), Ok(None));
}

#[test]
fn atomic_handler_slot_never_returns_a_torn_callback_context_pair() {
    const WRITES: usize = 100_000;
    const A: IrqHandlerPublication = IrqHandlerPublication {
        irq: 1,
        callback: 0x1111,
        context: 0xaaaa,
    };
    const B: IrqHandlerPublication = IrqHandlerPublication {
        irq: 2,
        callback: 0x2222,
        context: 0xbbbb,
    };

    let slot = Arc::new(AtomicIrqHandlerSlot::new());
    unsafe { slot.publish_exclusive(Some(A)) };
    let writer_slot = slot.clone();
    let writer = std::thread::spawn(move || {
        for index in 0..WRITES {
            unsafe {
                writer_slot.publish_exclusive(Some(if index & 1 == 0 { B } else { A }));
            }
        }
    });

    for _ in 0..WRITES {
        match slot.try_snapshot() {
            Ok(Some(record)) => assert!(record == A || record == B),
            Err(_) => {} // A bounded IRQ read deliberately declines overlap.
            Ok(None) => panic!("a published handler unexpectedly disappeared"),
        }
    }
    writer.join().unwrap();
}

#[test]
fn spsc_ring_wraps_and_counts_newest_byte_overflow() {
    let ring = SpscByteRing::<4>::new();
    assert_eq!(ring.capacity(), 3);
    unsafe {
        assert!(ring.push_from_producer(1));
        assert!(ring.push_from_producer(2));
        assert!(ring.push_from_producer(3));
        assert!(!ring.push_from_producer(4));
        assert_eq!(ring.pop_from_consumer(), Some(1));
        assert!(ring.push_from_producer(5));
        assert_eq!(ring.pop_from_consumer(), Some(2));
        assert_eq!(ring.pop_from_consumer(), Some(3));
        assert_eq!(ring.pop_from_consumer(), Some(5));
        assert_eq!(ring.pop_from_consumer(), None);
    }
    assert_eq!(ring.dropped(), 1);
}

#[test]
fn spsc_ring_release_acquire_handoff_preserves_byte_order() {
    const BYTES: usize = 100_000;
    let ring = Arc::new(SpscByteRing::<64>::new());
    let producer_ring = ring.clone();
    let producer = std::thread::spawn(move || {
        for index in 0..BYTES {
            let byte = index as u8;
            loop {
                if unsafe { producer_ring.push_from_producer(byte) } {
                    break;
                }
                std::hint::spin_loop();
            }
        }
    });

    for index in 0..BYTES {
        let expected = index as u8;
        loop {
            if let Some(observed) = unsafe { ring.pop_from_consumer() } {
                assert_eq!(observed, expected);
                break;
            }
            std::hint::spin_loop();
        }
    }
    producer.join().unwrap();
}

#[test]
fn irq_handoff_cells_keep_fixed_bounded_layouts() {
    assert!(core::mem::size_of::<AtomicIrqHandlerSlot>() <= 4 * core::mem::size_of::<usize>());
    assert!(core::mem::size_of::<SpscByteRing<256>>() <= 320);
}
