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

#[cfg(feature = "rx-batch-release")]
mod batch {
    use super::*;
    use std::sync::Mutex;
    static EVENTS: Mutex<Vec<(usize, Vec<usize>)>> = Mutex::new(Vec::new());
    unsafe fn scalar(b: Borrow) { EVENTS.lock().unwrap().push((0, vec![b.index()])); }
    unsafe fn scalar_other(b: Borrow) { EVENTS.lock().unwrap().push((3, vec![b.index()])); }
    unsafe fn bulk(bs: &mut [Option<Borrow>]) {
        EVENTS.lock().unwrap().push((1, bs.iter_mut().filter_map(Option::take).map(|b| b.index()).collect()));
    }
    unsafe fn other(bs: &mut [Option<Borrow>]) {
        EVENTS.lock().unwrap().push((2, bs.iter_mut().filter_map(Option::take).map(|b| b.index()).collect()));
    }
    fn loan(index: usize, callback: Option<unsafe fn(&mut [Option<Borrow>])>) -> Loan {
        unsafe {
            let b = Borrow::from_owned(Ticket::from_parts(10,index,1),Owner::new(2,3).unwrap());
            let l = Loan::new(b,BYTES.as_ptr(),64,scalar).unwrap();
            match callback { Some(c) => l.with_batch_release(c), None => l }
        }
    }
    #[test]
    fn bounded_bulk_cleanup_falls_back_for_mixed_providers_and_unwinds() {
        drop(ReleaseBatch::<0>::new()); assert!(EVENTS.lock().unwrap().is_empty());
        let mut group = ReleaseBatch::<2>::new();
        assert!(group.push(loan(0,Some(bulk))).is_ok());
        assert!(group.push(loan(1,Some(bulk))).is_ok());
        let extra = group.push(loan(2,Some(bulk))).err().unwrap();
        assert_eq!(extra.as_bytes(), &BYTES); drop(extra);
        assert_eq!(*EVENTS.lock().unwrap(), vec![(0,vec![2])]);
        drop(group); assert_eq!(EVENTS.lock().unwrap().pop(),Some((1,vec![0,1])));
        EVENTS.lock().unwrap().clear();
        for callbacks in [[Some(bulk as unsafe fn(&mut [Option<Borrow>])),Some(other)], [Some(bulk),None]] {
            let mut group=ReleaseBatch::<2>::new();
            for (i,c) in callbacks.into_iter().enumerate() { assert!(group.push(loan(i,c)).is_ok()); }
            drop(group); assert_eq!(*EVENTS.lock().unwrap(),vec![(0,vec![0]),(0,vec![1])]);
            EVENTS.lock().unwrap().clear();
        }
        // A scalar-only first entry must keep later bulk-capable entries on
        // their individual provider callbacks, including distinct providers.
        let mut group = ReleaseBatch::<2>::new();
        let first = unsafe {
            Loan::new(Borrow::from_owned(Ticket::from_parts(11,7,1), Owner::new(5,6).unwrap()),
                BYTES.as_ptr(), 64, scalar_other).unwrap()
        };
        assert!(group.push(first).is_ok());
        assert!(group.push(loan(8, Some(bulk))).is_ok());
        assert!(EVENTS.lock().unwrap().is_empty());
        drop(group);
        assert_eq!(*EVENTS.lock().unwrap(), vec![(3,vec![7]),(0,vec![8])]);
        EVENTS.lock().unwrap().clear();
        let result=std::panic::catch_unwind(|| {
            let mut group=ReleaseBatch::<2>::new();assert!(group.push(loan(4,Some(bulk))).is_ok());
            panic!("caller unwinds after consuming bytes");
        });
        assert!(result.is_err());assert_eq!(*EVENTS.lock().unwrap(),vec![(1,vec![4])]);
    }
}
