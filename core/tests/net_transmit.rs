use vibeos_core::{net::{PacketStamp,StampedPacket},net_transmit::{Transmit,TransmitEndpoint},
    net_segment_pool::Error,heap::{AllocationDomain,OwnerId,ArenaId}};
fn stamp()->PacketStamp { PacketStamp::new(1,1).unwrap() }
fn domain(n:u64)->AllocationDomain {AllocationDomain::new(OwnerId::new(12),ArenaId::new(n))}
fn frame(n:u8)->Transmit {Transmit::Frame(StampedPacket::copy_from(&[n;60],stamp()).unwrap())}
fn fill(p:&mut [u8]){
 p[12..14].copy_from_slice(&[8,0]);p[14]=0x45;
 let n=(p.len()-14) as u16;p[16..18].copy_from_slice(&n.to_be_bytes());
 p[20]=0x40;p[23]=6;p[46]=0x50;p[47]=0x18;p[54..].fill(0xa5);
}
#[test]
fn raw_and_large_requests_share_one_fifo_and_full_preserves_ticket(){
 let q=TransmitEndpoint::new("tx-order",1,1).unwrap();
 q.try_send(frame(1)).unwrap();
 let t=q.pool().reserve(stamp(),domain(1)).unwrap();q.pool().write(t,stamp(),2000,1460,fill).unwrap();
 assert_eq!(q.publish(t,stamp()),Ok(Err(t)));
 match q.try_recv().unwrap(){Transmit::Frame(p)=>assert_eq!(p.into_packet(stamp()).unwrap().as_bytes()[0],1),_=>panic!("reordered")}
 assert_eq!(q.publish(t,stamp()),Ok(Ok(())));
 let c=q.try_send(frame(3)).unwrap_err();
 let Transmit::Segments(got)=q.try_recv().unwrap() else {panic!("not a large send")};assert_eq!(got,t);
 assert_eq!(q.pool().try_consume(got,stamp(),|_|Err::<(),_>("full")),Ok(Err("full")));
 assert_eq!(q.pool().try_consume(got,stamp(),|r|Ok::<_,()>(r.bytes().len())),Ok(Ok(2000)));
 q.try_send(c).unwrap();
 assert!(matches!(q.try_recv(),Some(Transmit::Frame(_))));
 assert_eq!(q.pool().in_use(),0);
}
#[test]
fn queued_old_ticket_cannot_read_reused_buffer_after_restart(){
 let q=TransmitEndpoint::new("tx-restart",2,1).unwrap();
 let old=q.pool().reserve(stamp(),domain(1)).unwrap();q.pool().write(old,stamp(),2000,1460,fill).unwrap();
 q.publish(old,stamp()).unwrap().unwrap();
 assert_eq!(q.pool().invalidate_domain(domain(1)),1);
 let new=q.pool().reserve(stamp(),domain(2)).unwrap();q.pool().write(new,stamp(),2000,1460,fill).unwrap();
 q.publish(new,stamp()).unwrap().unwrap();
 let Transmit::Segments(stale)=q.try_recv().unwrap() else {panic!()};
 assert_eq!(q.pool().try_consume(stale,stamp(),|_|Ok::<_,()>(())),Err(Error::Stale));
 let Transmit::Segments(fresh)=q.try_recv().unwrap() else {panic!()};
 assert_eq!(fresh,new);
 assert_eq!(q.pool().try_consume(fresh,stamp(),|_|Ok::<_,()>(())),Ok(Ok(())));
}
