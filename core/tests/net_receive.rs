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
        #[cfg(feature = "rx-admission-batch")]
        acquire_batch: None,
        poll_batch: None,
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
fn external_input_hint_closes_wait_races_without_publishing_a_ticket() {
    use std::{future::Future, pin::pin, task::{Context, Waker}};
    let q = unsafe { ReceiveEndpoint::new("irq-rx", 2, &OPS).unwrap() };
    let event = q.message_event();
    let mut before_registration = pin!(event.wait());
    q.notify_input();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(before_registration.as_mut().poll(&mut cx).is_ready());
    assert!(!q.has_message());
    assert!(q.try_receive(stamp(), domain(90)).unwrap().is_none());
    let mut after_registration = pin!(event.wait());
    assert!(after_registration.as_mut().poll(&mut cx).is_pending());
    q.notify_input();
    assert!(after_registration.as_mut().poll(&mut cx).is_ready());
    assert!(!q.has_message());
    let mut next = pin!(event.wait());
    assert!(next.as_mut().poll(&mut cx).is_pending());
}
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

#[test]
fn pending_batch_keeps_original_generation_through_queue_pressure_and_rebinding() {
    let q = unsafe { ReceiveEndpoint::new("batch-rx", 1, &OPS).unwrap() };
    let old = stamp();
    let new = old.next_stack_generation().unwrap();
    let frames = [frame(old), frame(old), frame(old)];
    let mut tickets = [None; vibeos_hal::network_rx::BATCH_SIZE];
    tickets[0] = Some(frames[0].ticket());
    tickets[2] = Some(frames[1].ticket());
    tickets[7] = Some(frames[2].ticket());
    let mut batch = StampedBatch::new(tickets, old);
    q.try_send(batch.pop().unwrap()).unwrap();
    let blocked = q.try_send(batch.pop().unwrap()).unwrap_err();
    let loan = q.try_receive(old, domain(12)).unwrap().unwrap();
    // Rebinding cannot relabel either the blocked head or the unqueued tail.
    assert_eq!(blocked.stamp(), old);
    q.try_send(blocked).unwrap();
    assert!(matches!(q.try_receive(new, domain(13)), Err(Error::Session(_))));
    let tail = batch.pop().unwrap();
    assert_eq!(tail, frames[2]);
    q.try_send(tail).unwrap();
    assert!(matches!(q.try_receive(new, domain(13)), Err(Error::Session(_))));
    assert!(batch.pop().is_none());
    assert_eq!(loan.as_bytes(), &[0x39; 64]);
    drop(loan);
    for frame in frames {
        assert_eq!(records().lock().unwrap()[&frame.ticket().pool()].state, State::Released);
    }
}

#[test]
#[cfg(feature = "rx-publish-batch")]
fn batch_partial_publication_retains_order_and_old_stamp_across_rebind() {
    let q=unsafe {ReceiveEndpoint::new("rx-batch",1,&OPS).unwrap()};
    let old=stamp();let new=old.next_stack_generation().unwrap();
    let frames=[frame(old),frame(old),frame(old)];
    let mut tickets=[None;vibeos_hal::network_rx::BATCH_SIZE];
    for (slot,f) in [0,2,7].into_iter().zip(frames) {tickets[slot]=Some(f.ticket());}
    let mut batch=StampedBatch::new(tickets,old);
    assert_eq!(batch.remaining(),3);assert_eq!(q.try_send_batch(&mut batch,0),0);
    assert_eq!(q.try_send_batch(&mut batch,2),1);assert_eq!(batch.remaining(),2);
    assert_eq!(q.try_send_batch(&mut batch,2),0);
    let loan=q.try_receive(old,domain(50)).unwrap().unwrap();
    assert_eq!(q.try_send_batch(&mut batch,1),1);assert_eq!(batch.remaining(),1);
    assert!(matches!(q.try_receive(new,domain(51)),Err(Error::Session(_))));
    assert_eq!(batch.stamp(),Some(old));assert_eq!(batch.pop(),Some(frames[2]));
    assert!(q.discard(frames[2]));assert_eq!(batch.remaining(),0);assert_eq!(q.try_send_batch(&mut batch,32),0);
    assert_eq!(loan.as_bytes(),&[0x39;64]);drop(loan);
    for f in frames {assert_eq!(records().lock().unwrap()[&f.ticket().pool()].state,State::Released);}
}

#[test]
#[cfg(feature = "rx-publish-batch")]
fn revoked_batch_sender_cannot_move_pending_tickets() {
    let q=unsafe {ReceiveEndpoint::new("rx-revoked-batch",2,&OPS).unwrap()};
    let mut space=CSpace::new("batch");let root=space.mint(q.clone(),Rights::SEND.union(Rights::REVOKE));
    let authority=space.lookup_revocable::<ReceiveEndpoint>(root,Rights::SEND).unwrap();
    let f=frame(stamp());let mut tickets=[None;vibeos_hal::network_rx::BATCH_SIZE];tickets[0]=Some(f.ticket());
    let mut batch=StampedBatch::new(tickets,stamp());space.revoke(root).unwrap();
    assert!(authority.try_with(|q|q.try_send_batch(&mut batch,32)).is_err());
    assert_eq!(batch.remaining(),1);assert!(!q.has_message());
    assert_eq!(batch.pop(),Some(f));assert!(q.discard(f));
}

#[cfg(feature = "rx-admission-batch")]
#[test]
fn inplace_refill_preserves_live_destination_and_tracks_reused_storage() {
    let q = unsafe { ReceiveEndpoint::new("inplace-rx", 4, &OPS).unwrap() };
    let a = frame(stamp()); let b = frame(stamp());
    let stale = frame(stamp().next_stack_generation().unwrap()); let c = frame(stamp());
    for f in [a, b, stale, c] { q.try_send(f).unwrap(); }
    let owner = domain(880);
    let mut batch = LoanBatch::empty();
    assert_eq!(q.try_receive_batch_into(stamp(), owner, 1, &mut batch), Ok(1));
    assert_eq!(q.try_receive_batch_into(stamp(), owner, 4, &mut batch), Err(Error::Capacity));
    assert_eq!(q.try_receive_batch_into(stamp(), AllocationDomain::SYSTEM, 4, &mut batch), Err(Error::UntrackedOwner));
    assert_eq!(batch.len(), 1);
    let first = batch.pop().unwrap().unwrap();
    assert_eq!(first.as_bytes().as_ptr(), records().lock().unwrap()[&a.ticket().pool()].bytes.as_ptr());
    assert_eq!(q.try_receive_batch_into(stamp(), owner, 0, &mut batch), Ok(0));
    assert!(q.has_message());
    assert_eq!(q.try_receive_batch_into(stamp(), owner, 2, &mut batch), Ok(2));
    let second = batch.pop().unwrap().unwrap();
    assert_eq!(second.as_bytes().as_ptr(), records().lock().unwrap()[&b.ticket().pool()].bytes.as_ptr());
    assert!(matches!(batch.pop(), Some(Err(Error::Session(_)))));
    drop(second);
    assert_eq!(q.try_receive_batch_into(stamp(), owner, 8, &mut batch), Ok(1));
    assert!(!q.has_message());
    // Simulate permanent domain quiescence with loans in both popped and
    // refilled storage. Recovery must see both under the original incarnation.
    std::mem::forget(first); std::mem::forget(batch);
    assert_eq!(unsafe { q.recover(domain(881)) }, 0);
    assert_eq!(unsafe { q.recover(owner) }, 2);
    for f in [a, b, stale, c] {
        assert_eq!(records().lock().unwrap()[&f.ticket().pool()].state, State::Released);
    }
}

#[cfg(feature = "rx-admission-batch")]
#[test]
fn admitted_batch_preserves_order_budget_and_per_frame_rejection() {
    let q = unsafe { ReceiveEndpoint::new("rx-batch", 8, &OPS).unwrap() };
    let a = frame(stamp());
    let stale = frame(stamp().next_stack_generation().unwrap());
    let b = frame(stamp());
    for f in [a, stale, b] { q.try_send(f).unwrap(); }
    assert!(matches!(q.try_receive_batch(stamp(), AllocationDomain::SYSTEM, 8), Err(Error::UntrackedOwner)));
    assert_eq!(q.try_receive_batch(stamp(), domain(800), 0).unwrap().len(), 0);
    let mut batch = q.try_receive_batch(stamp(), domain(800), 2).unwrap();
    assert_eq!(batch.len(), 2); assert!(q.has_message());
    let loan = batch.pop().unwrap().unwrap();
    assert_eq!(loan.as_bytes().as_ptr(), records().lock().unwrap()[&a.ticket().pool()].bytes.as_ptr());
    assert!(matches!(batch.pop(), Some(Err(Error::Session(_)))));
    assert!(batch.pop().is_none());
    assert_eq!(records().lock().unwrap()[&stale.ticket().pool()].state, State::Released);
    drop(loan);
    let remaining = q.try_receive_batch(stamp(), domain(800), 8).unwrap();
    assert_eq!(remaining.len(), 1); assert!(!q.has_message()); drop(remaining);
    assert_eq!(records().lock().unwrap()[&b.ticket().pool()].state, State::Released);
}

#[cfg(feature = "rx-admission-batch")]
#[test]
fn batched_duplicate_cannot_release_a_live_loan_and_fault_reclaims_all() {
    let q = unsafe { ReceiveEndpoint::new("rx-batch-fault", 8, &OPS).unwrap() };
    let a = frame(stamp()); let b = frame(stamp());
    for f in [a, a, b] { q.try_send(f).unwrap(); }
    let mut batch = q.try_receive_batch(stamp(), domain(801), 8).unwrap();
    let loan = batch.pop().unwrap().unwrap();
    assert!(matches!(batch.pop(), Some(Err(Error::Device(_)))));
    assert_eq!(loan.as_bytes(), &[0x39; 64]);
    let other = AllocationDomain::new(OwnerId::new(801), ArenaId::new(802));
    assert_eq!(unsafe { q.recover(other) }, 0);
    // No references may survive recovery of this permanently stopped owner.
    std::mem::forget(loan); std::mem::forget(batch);
    assert_eq!(unsafe { q.recover(domain(801)) }, 2);
    assert_eq!(unsafe { q.recover(domain(801)) }, 0);
    assert_eq!(records().lock().unwrap()[&a.ticket().pool()].state, State::Released);
    assert_eq!(records().lock().unwrap()[&b.ticket().pool()].state, State::Released);
}

#[cfg(feature = "rx-admission-batch")]
#[test]
fn bulk_operation_is_invoked_once_and_never_acquires_wrong_session() {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static BULK: Operations = Operations {
        stats: OPS.stats, poll: OPS.poll, poll_batch: None,
        acquire: OPS.acquire, discard: OPS.discard, recover: OPS.recover,
        acquire_batch: Some(|tickets, owner| {
            CALLS.fetch_add(1, Ordering::Relaxed);
            core::array::from_fn(|i| tickets[i].map(|ticket| unsafe { (OPS.acquire)(ticket, owner) }))
        }),
    };
    let q = unsafe { ReceiveEndpoint::new("bulk-operation", 8, &BULK).unwrap() };
    let a = frame(stamp()); let b = frame(stamp().next_stack_generation().unwrap());
    let c = frame(stamp());
    for f in [a, b, c] { q.try_send(f).unwrap(); }
    let mut batch = q.try_receive_batch(stamp(), domain(803), 8).unwrap();
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(batch.len(), 3);
    assert!(batch.pop().unwrap().is_ok());
    assert!(matches!(batch.pop(), Some(Err(Error::Session(_)))));
    assert!(batch.pop().unwrap().is_ok());
    assert_eq!(records().lock().unwrap()[&b.ticket().pool()].state, State::Released);
}
