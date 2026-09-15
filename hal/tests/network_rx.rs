use std::sync::atomic::{AtomicUsize, Ordering};
use vibeos_hal::network_rx::*;
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static BYTES: [u8; 64] = [0x39; 64];
unsafe fn release(borrow: Borrow) {
    assert_eq!(borrow.ticket(), Ticket::from_parts(1, 2, 3));
    assert_eq!(borrow.owner(), Owner::new(4, 5).unwrap());
    RELEASED.fetch_add(1, Ordering::SeqCst);
}
#[test]
fn loan_preserves_original_bytes_and_releases_exactly_once() {
    let borrow = unsafe { Borrow::from_owned(Ticket::from_parts(1, 2, 3), Owner::new(4, 5).unwrap()) };
    let loan = unsafe { Loan::new(borrow, BYTES.as_ptr(), BYTES.len(), release).unwrap() };
    assert_eq!(loan.as_bytes().as_ptr(), BYTES.as_ptr());
    assert_eq!(loan.as_bytes(), &BYTES);
    assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
    drop(loan); assert_eq!(RELEASED.load(Ordering::SeqCst), 1);
}
#[test]
fn invalid_pointer_or_length_returns_the_unique_ownership_token() {
    for (pointer, length) in [(core::ptr::null(), 64), (BYTES.as_ptr(), 0), (BYTES.as_ptr(), 1515)] {
        let ticket = Ticket::from_parts(7, 1, 9);
        let borrow = unsafe { Borrow::from_owned(ticket, Owner::new(1, 2).unwrap()) };
        let returned = unsafe { Loan::new(borrow, pointer, length, |_| panic!("not admitted")) }.err().unwrap();
        assert_eq!(returned.ticket(), ticket);
    }
    assert!(Owner::new(1, 0).is_none());
    assert_ne!(Owner::new(1, 7).unwrap().key(), Owner::new(2, 7).unwrap().key());
}
