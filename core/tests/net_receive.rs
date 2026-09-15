use std::{collections::BTreeMap, sync::{Mutex, OnceLock, atomic::{AtomicU64, Ordering}}};
use vibeos_core::{cap::{CSpace, Rights}, heap::{AllocationDomain, OwnerId, ArenaId},
    net::PacketStamp, net_receive::*};
use vibeos_hal::{network::Error as HardwareError, network_rx::Borrow};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State { Ready, Borrowed(Owner), Released }
struct Record { bytes: &'static [u8], state: State }
static NEXT: AtomicU64 = AtomicU64::new(1);
fn records() -> &'static Mutex<BTreeMap<u64, Record>> {
    static RECORDS: OnceLock<Mutex<BTreeMap<u64, Record>>> = OnceLock::new();
    RECORDS.get_or_init(|| Mutex::new(BTreeMap::new()))
}
unsafe fn release(b: Borrow) {
    let mut map = records().lock().unwrap(); let record = map.get_mut(&b.ticket().pool()).unwrap();
    assert_eq!(record.state, State::Borrowed(b.owner())); record.state = State::Released;
}
static OPS: Operations = Operations {
        stats: Default::default,
    poll: || Ok(None),
    acquire: |ticket, owner| {
        let mut map = records().lock().unwrap();
        let r = map.get_mut(&ticket.pool()).ok_or(HardwareError::InvalidDescription)?;
        if ticket.generation() != 1 || ticket.index() != 0 || r.state != State::Ready {
            return Err(HardwareError::Busy);
        }
        r.state = State::Borrowed(owner);
        let b = unsafe { Borrow::from_owned(ticket, owner) };
        Ok(unsafe { Loan::new(b, r.bytes.as_ptr(), r.bytes.len(), release).unwrap() })
    },
    discard: |ticket| {
        let mut map = records().lock().unwrap();
        let Some(r) = map.get_mut(&ticket.pool()) else { return false; };
        if ticket.index() != 0 || ticket.generation() != 1 || r.state != State::Ready { return false; }
        r.state = State::Released; true
    },
    recover: |owner| {
        let mut count = 0;
        for r in records().lock().unwrap().values_mut() {
            if r.state == State::Borrowed(owner) { r.state = State::Released; count += 1; }
        }
        count
    },
};
fn frame(stamp: PacketStamp) -> Stamped {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    records().lock().unwrap().insert(id, Record { bytes: Box::leak(Box::new([0x39; 64])), state: State::Ready });
    Stamped::new(Ticket::from_parts(id, 0, 1), stamp)
}
fn stamp() -> PacketStamp { PacketStamp::new(1, 1).unwrap() }
fn domain(n: u64) -> AllocationDomain { AllocationDomain::new(OwnerId::new(n), ArenaId::new(n)) }
#[test]
fn queue_backpressure_preserves_ticket_and_acquisition_reads_original_storage() {
    let q = unsafe { ReceiveEndpoint::new("rx", 1, &OPS).unwrap() };
    let a = frame(stamp()); let b = frame(stamp());
    q.try_send(a).unwrap(); assert_eq!(q.try_send(b), Err(b));
    let loan = q.try_receive(stamp(), domain(1)).unwrap().unwrap();
    let original = records().lock().unwrap()[&a.ticket().pool()].bytes.as_ptr();
    assert_eq!(loan.as_bytes().as_ptr(), original);
    assert!(!q.discard(a)); drop(loan);
    assert_eq!(records().lock().unwrap()[&a.ticket().pool()].state, State::Released);
    q.try_send(b).unwrap(); drop(q.try_receive(stamp(), domain(1)).unwrap().unwrap());
}
#[test]
fn stale_session_is_discarded_and_untracked_owner_does_not_dequeue() {
    let q = unsafe { ReceiveEndpoint::new("rx", 2, &OPS).unwrap() };
    let a = frame(stamp()); q.try_send(a).unwrap();
    assert!(matches!(q.try_receive(stamp(), AllocationDomain::SYSTEM), Err(Error::UntrackedOwner)));
    assert!(q.has_message());
    assert!(matches!(q.try_receive(stamp().next_stack_generation().unwrap(), domain(2)), Err(Error::Session(_))));
    assert_eq!(records().lock().unwrap()[&a.ticket().pool()].state, State::Released);
    assert!(!q.has_message());
}
#[test]
fn revocation_blocks_new_access_but_existing_loan_survives_and_releases() {
    let q = unsafe { ReceiveEndpoint::new("rx", 2, &OPS).unwrap() };
    let mut cs = CSpace::new("rx"); let cap = cs.mint(q.clone(), Rights::ALL);
    let authority = cs.lookup_revocable::<ReceiveEndpoint>(cap, Rights::RECV).unwrap();
    let a = frame(stamp()); q.try_send(a).unwrap();
    let loan = authority.try_with(|q| q.try_receive(stamp(), domain(3))).unwrap().unwrap().unwrap();
    cs.revoke(cap).unwrap();
    assert!(authority.try_with(|q| q.try_receive(stamp(), domain(3))).is_err());
    assert_eq!(loan.as_bytes(), &[0x39; 64]); drop(loan);
    assert_eq!(records().lock().unwrap()[&a.ticket().pool()].state, State::Released);
}
#[test]
fn queue_retirement_preserves_loans_and_fault_cleanup_matches_incarnation() {
    let q = unsafe { ReceiveEndpoint::new("rx", 2, &OPS).unwrap() };
    let a = frame(stamp()); q.try_send(a).unwrap();
    let loan = q.try_receive(stamp(), domain(4)).unwrap().unwrap();
    q.try_send(frame(stamp())).unwrap(); assert_eq!(q.retire_queued(), 1);
    assert_eq!(loan.as_bytes(), &[0x39; 64]);
    let another = AllocationDomain::new(OwnerId::new(4), ArenaId::new(400));
    assert_eq!(unsafe { q.recover(another) }, 0);
    // Simulate a task fault after its byte references are dead; no normal drop.
    std::mem::forget(loan);
    assert_eq!(unsafe { q.recover(domain(4)) }, 1);
    assert_eq!(unsafe { q.recover(domain(4)) }, 0);
}
