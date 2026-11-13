//! Metadata model only: these unsafe transitions simulate proven DMA/CPU
//! quiescence. They do not test real cache operations or descriptor publication.
use vibeos_eqos_net::rx_buffers::{Buffers, Error, Ticket};
fn ready<const D: usize, const N: usize>(p: &mut Buffers<D, N>, descriptor: usize) -> Ticket {
    let exchange = unsafe { p.prepare(descriptor).unwrap() };
    unsafe { p.publish(exchange).unwrap() }
}
#[test]
fn replacement_is_reserved_before_a_frame_can_be_published() {
    let mut p = Buffers::<2, 4>::new().unwrap();
    let original = p.attach(0).unwrap();
    p.attach(1).unwrap();
    let exchange = unsafe { p.prepare(0).unwrap() };
    assert_ne!(exchange.replacement(), original);
    assert_eq!(p.descriptor_buffer(0), Some(exchange.replacement()));
    assert_eq!(p.stats().detached, 1);
    assert_eq!(p.stats().ready, 0);
    assert_eq!(unsafe { p.prepare(0) }.err(), Some(Error::Pending));
    let ticket = unsafe { p.publish(exchange).unwrap() };
    assert_eq!(ticket.index(), original);
    assert_eq!(p.stats().ready, 1);
    let borrow = p.borrow(ticket, 7).unwrap();
    assert_eq!(borrow.index(), original);
    assert_eq!(p.discard(ticket), Err(Error::Busy));
    assert_eq!(p.borrow(ticket, 8).err(), Some(Error::Busy));
    p.release(borrow).unwrap();
    assert_eq!(p.stats().free, 2);
    assert_eq!(p.discard(ticket), Err(Error::Stale));
}
#[test]
fn full_pool_preserves_descriptor_and_live_borrow() {
    let mut p = Buffers::<2, 3>::new().unwrap();
    p.attach(0).unwrap();
    p.attach(1).unwrap();
    let ticket = ready(&mut p, 0);
    let borrow = p.borrow(ticket, 1).unwrap();
    let mapping = p.descriptor_buffer(1);
    let stats = p.stats();
    assert_eq!(unsafe { p.prepare(1) }.err(), Some(Error::Full));
    assert_eq!(p.descriptor_buffer(1), mapping);
    assert_eq!(p.stats(), stats);
    p.release(borrow).unwrap();
    let next = ready(&mut p, 1);
    p.discard(next).unwrap();
    assert_eq!(p.stats().free, 1);
}
#[test]
fn reset_retires_queued_tickets_but_never_reuses_a_live_byte_borrow() {
    let mut p = Buffers::<2, 5>::new().unwrap();
    p.attach(0).unwrap();
    p.attach(1).unwrap();
    let ticket = ready(&mut p, 0);
    let borrow = p.borrow(ticket, 9).unwrap();
    let queued = ready(&mut p, 1);
    unsafe {
        p.reset_after_dma_stop();
    }
    assert_eq!(p.stats().borrowed, 1);
    assert_eq!(p.stats().free, 4);
    assert_eq!(p.discard(queued), Err(Error::Stale));
    assert_ne!(p.attach(0).unwrap(), borrow.index());
    assert_ne!(p.attach(1).unwrap(), borrow.index());
    p.release(borrow).unwrap();
    for _ in 0..20 {
        let t = ready(&mut p, 0);
        p.discard(t).unwrap();
    }
    assert_eq!(p.borrow(ticket, 9).err(), Some(Error::Stale));
    assert_eq!(p.discard(queued), Err(Error::Stale));
}
#[test]
fn reset_recovers_an_abandoned_exchange_without_publishing_it() {
    let mut p = Buffers::<2, 4>::new().unwrap();
    p.attach(0).unwrap();
    let exchange = unsafe { p.prepare(0).unwrap() };
    unsafe {
        p.reset_after_dma_stop();
    }
    assert_eq!(p.stats().free, 4);
    p.attach(0).unwrap();
    assert_eq!(unsafe { p.publish(exchange) }, Err(Error::Stale));
    let ticket = ready(&mut p, 0);
    p.discard(ticket).unwrap();
}
#[test]
fn foreign_pool_and_zero_owner_do_not_change_ownership() {
    let mut a = Buffers::<2, 4>::new().unwrap();
    let mut b = Buffers::<2, 4>::new().unwrap();
    a.attach(0).unwrap();
    b.attach(0).unwrap();
    let ticket = ready(&mut a, 0);
    let before = a.stats();
    assert_eq!(b.discard(ticket), Err(Error::Stale));
    assert_eq!(a.borrow(ticket, 0).err(), Some(Error::Owner));
    assert_eq!(a.stats(), before);
    a.discard(ticket).unwrap();
}
#[test]
fn borrower_fault_recovery_requires_the_exact_owner_and_rejects_old_release() {
    let mut p = Buffers::<2, 5>::new().unwrap();
    p.attach(0).unwrap();
    p.attach(1).unwrap();
    let t1 = ready(&mut p, 0);
    let b1 = p.borrow(t1, 11).unwrap();
    let t2 = ready(&mut p, 1);
    let b2 = p.borrow(t2, 12).unwrap();
    assert_eq!(unsafe { p.recover_borrower(0) }, 0);
    assert_eq!(unsafe { p.recover_borrower(11) }, 1);
    assert_eq!(p.stats().borrowed, 1);
    let next = ready(&mut p, 0);
    assert_eq!(p.release(b1), Err(Error::Stale));
    p.discard(next).unwrap();
    p.release(b2).unwrap();
    assert_eq!(p.stats().free, 3);
}
#[test]
fn repeated_ring_wraps_preserve_disjoint_hardware_and_consumer_slots() {
    let mut p = Buffers::<4, 8>::new().unwrap();
    for d in 0..4 {
        p.attach(d).unwrap();
    }
    for i in 0..10000 {
        let ticket = ready(&mut p, i % 4);
        let borrow = p.borrow(ticket, 1).unwrap();
        for d in 0..4 {
            assert_ne!(p.descriptor_buffer(d), Some(borrow.index()));
        }
        p.release(borrow).unwrap();
        assert_eq!(p.stats().free, 4);
        assert_eq!(p.stats().dma, 4);
    }
}

#[test]
fn recovery_distinguishes_both_halves_of_full_borrower_identity() {
    let mut p = Buffers::<2, 6>::new().unwrap();
    p.attach(0).unwrap(); p.attach(1).unwrap();
    let keys = [(7u128 << 64) | 11, (8u128 << 64) | 11, (7u128 << 64) | 12];
    let mut borrows = Vec::new();
    for (index, key) in keys.into_iter().enumerate() {
        let ticket = ready(&mut p, index % 2);
        borrows.push(p.borrow(ticket, key).unwrap());
    }
    // An invalid zero incarnation cannot alias a valid owner with the same
    // high word. Neither may a zero high word alias a valid low word alone.
    assert_eq!(unsafe { p.recover_borrower(7u128 << 64) }, 0);
    assert_eq!(unsafe { p.recover_borrower(11) }, 0);
    assert_eq!(unsafe { p.recover_borrower(keys[0]) }, 1);
    assert_eq!(p.stats().borrowed, 2);
    let recovered = borrows.remove(0);
    assert_eq!(p.release(recovered), Err(Error::Stale));
    for borrow in borrows { p.release(borrow).unwrap(); }
    assert_eq!(p.stats().borrowed, 0);
    assert_eq!(p.stats().free, 4);
}
