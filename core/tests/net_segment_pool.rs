use vibeos_core::{heap::{AllocationDomain, ArenaId, OwnerId}, net::PacketStamp,
    net_segment_pool::{SegmentPool, Error}};
fn stamp() -> PacketStamp { PacketStamp::new(2,3).unwrap() }
fn domain(n:u64) -> AllocationDomain { AllocationDomain::new(OwnerId::new(17),ArenaId::new(n)) }
fn fill(p: &mut [u8]) {
    p[12..14].copy_from_slice(&[8,0]); p[14]=0x45;
    let len=(p.len()-14) as u16; p[16..18].copy_from_slice(&len.to_be_bytes());
    p[20]=0x40;p[23]=6;p[46]=0x50;p[47]=0x18;
    for (i,b) in p[54..].iter_mut().enumerate(){*b=(i%251) as u8;}
}
#[test]
fn capacity_retry_and_reuse_are_bounded_and_generation_checked() {
    let p=SegmentPool::new(1).unwrap();let t=p.reserve(stamp(),domain(1)).unwrap();
    assert_eq!(p.reserve(stamp(),domain(1)),Err(Error::Full));
    assert_eq!(p.try_consume(t,stamp(),|_|Ok::<_,()>(())),Err(Error::NotReady));
    p.write(t,stamp(),32768,1460,fill).unwrap();
    for _ in 0..3 {assert_eq!(p.try_consume(t,stamp(),|r| {
        assert_eq!(r.bytes().len(),32768);assert_eq!(r.bytes()[100],46);Err::<(),_>("full")
    }),Ok(Err("full")));}
    assert_eq!(p.in_use(),1);
    assert_eq!(p.try_consume(t,stamp(),|r| Ok::<_,()>(r.wire_segments())),Ok(Ok(23)));
    let next=p.reserve(stamp(),domain(1)).unwrap();
    assert_eq!(p.cancel(t,stamp()),Err(Error::Stale));
    assert_eq!(p.in_use(),1);p.cancel(next,stamp()).unwrap();
}
#[test]
fn tickets_do_not_cross_pool_or_session_boundaries() {
    let p=SegmentPool::new(1).unwrap();let q=SegmentPool::new(1).unwrap();
    let t=p.reserve(stamp(),domain(1)).unwrap();let u=q.reserve(stamp(),domain(1)).unwrap();
    p.write(t,stamp(),2000,1460,fill).unwrap();
    assert_eq!(q.cancel(t,stamp()),Err(Error::Stale));
    assert_eq!(p.cancel(t,stamp().next_stack_generation().unwrap()),Err(Error::Stale));
    assert_eq!(p.cancel(t,stamp().next_device_epoch().unwrap()),Err(Error::Stale));
    assert_eq!(p.in_use(),1);assert_eq!(q.in_use(),1);
    p.cancel(t,stamp()).unwrap();q.cancel(u,stamp()).unwrap();
}
#[test]
fn restart_invalidates_only_exact_incarnation_including_queued_tickets() {
    let p=SegmentPool::new(3).unwrap();
    let reserved=p.reserve(stamp(),domain(1)).unwrap();
    let queued=p.reserve(stamp(),domain(1)).unwrap();
    let other=p.reserve(stamp(),domain(2)).unwrap();
    p.write(queued,stamp(),2000,1460,fill).unwrap();
    assert_eq!(p.invalidate_domain(domain(1)),2);
    assert_eq!(p.cancel(reserved,stamp()),Err(Error::Stale));
    assert_eq!(p.try_consume(queued,stamp(),|_|Ok::<_,()>(())),Err(Error::Stale));
    assert_eq!(p.in_use(),1);
    p.write(other,stamp(),2000,1460,fill).unwrap();
    assert_eq!(p.try_consume(other,stamp(),|_|Ok::<_,()>(())),Ok(Ok(())));
}
#[test]
fn invalid_serialization_releases_capacity_without_publishing() {
    assert!(matches!(SegmentPool::new(0),Err(Error::Capacity)));
    let p=SegmentPool::new(1).unwrap();
    assert_eq!(p.reserve(stamp(),AllocationDomain::SYSTEM),Err(Error::UntrackedDomain));
    let t=p.reserve(stamp(),domain(1)).unwrap();
    assert_eq!(p.write(t,stamp(),2000,1460,|_|()),Err(Error::InvalidPacket));
    assert_eq!(p.in_use(),0);
    assert_eq!(p.try_consume(t,stamp(),|_|Ok::<_,()>(())),Err(Error::Stale));
}

#[test]
fn serialization_fault_never_publishes_partial_bytes() {
    let p=SegmentPool::new(1).unwrap();let t=p.reserve(stamp(),domain(1)).unwrap();
    let fault=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _=p.write(t,stamp(),2000,1460,|out| {out[0]=0x42;panic!("producer fault");});
    }));
    assert!(fault.is_err());
    assert_eq!(p.try_consume(t,stamp(),|_|Ok::<_,()>(())),Err(Error::NotReady));
    assert_eq!(p.invalidate_domain(domain(1)),1);
    assert_eq!(p.in_use(),0);
}

#[test]
fn consumer_fault_retires_its_slot_even_when_producer_is_alive() {
    let p=SegmentPool::new(2).unwrap();
    let t=p.reserve(stamp(),domain(1)).unwrap();let other=p.reserve(stamp(),domain(1)).unwrap();
    p.write(t,stamp(),2000,1460,fill).unwrap();
    let consumer=vibeos_core::heap::current_domain();
    let fault=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _:Result<Result<(),()>,_>=p.try_consume(t,stamp(),|_|panic!("consumer fault"));
    }));
    assert!(fault.is_err());
    // Host unwinding releases the guard; target longjmp additionally requires
    // recover_faulted_domain to reclaim the abandoned synchronization token.
    assert_eq!(p.invalidate_domain(consumer),1);
    assert_eq!(p.in_use(),1);
    assert_eq!(p.cancel(t,stamp()),Err(Error::Stale));
    p.cancel(other,stamp()).unwrap();
}

#[test]
fn consumer_and_producer_can_access_different_slots_without_a_pool_lock() {
    let p=SegmentPool::new(2).unwrap();
    let a=p.reserve(stamp(),domain(1)).unwrap();let b=p.reserve(stamp(),domain(1)).unwrap();
    p.write(a,stamp(),2000,1460,fill).unwrap();
    assert_eq!(p.try_consume(a,stamp(),|request| {
        // This deadlocks with a single pool-wide lock. Per-slot ownership
        // permits producer serialization while a different buffer is consumed.
        p.write(b,stamp(),2000,1460,fill).unwrap();
        assert_eq!(request.bytes()[100],46);
        Ok::<_,()>(())
    }),Ok(Ok(())));
    p.cancel(b,stamp()).unwrap();assert_eq!(p.in_use(),0);
}

#[test]
fn binding_retirement_releases_all_domains_and_invalidates_old_tickets() {
    let p=SegmentPool::new(2).unwrap();
    let a=p.reserve(stamp(),domain(1)).unwrap();let b=p.reserve(stamp(),domain(2)).unwrap();
    p.write(a,stamp(),2000,1460,fill).unwrap();
    assert_eq!(p.invalidate_all(),2);
    assert_eq!(p.cancel(a,stamp()),Err(Error::Stale));
    assert_eq!(p.cancel(b,stamp()),Err(Error::Stale));
    let next_stamp=stamp().next_device_epoch().unwrap();
    let fresh=p.reserve(next_stamp,domain(3)).unwrap();
    p.write(fresh,next_stamp,2000,1460,fill).unwrap();
    assert_eq!(p.try_consume(fresh,next_stamp,|_|Ok::<_,()>(())),Ok(Ok(())));
    assert_eq!(p.in_use(),0);
}
