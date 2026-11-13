use vibeos_core::{net::PacketStamp,net_segmentation::*};
fn packet()->Vec<u8>{
    let mut p=vec![0;2054];p[12..14].copy_from_slice(&[8,0]);p[14]=0x45;
    p[16..18].copy_from_slice(&2040u16.to_be_bytes());p[20]=0x40;p[23]=6;
    p[46]=0x50;p[47]=0x18;p[54..].fill(0xa5);p
}
#[test]
fn owns_bytes_and_rechecks_device_and_stack_session_on_retry(){
    let stamp=PacketStamp::new(7,11).unwrap();let mut bytes=packet();
    let msg=StampedSegments::copy_from(&bytes,1460,stamp).unwrap();bytes[54]=0;
    assert_eq!(msg.request(stamp).unwrap().bytes()[54],0xa5);
    for other in [stamp.next_device_epoch().unwrap(),stamp.next_stack_generation().unwrap()]{
        let error=msg.request(other).unwrap_err();assert_eq!(error.expected,other);assert_eq!(error.observed,stamp);
    }
    let mut pending=SoftwareTransmit::new(msg);let mut first=[0;1514];let mut retry=[0;1514];
    let req=pending.request(stamp).unwrap();req.write_segment(pending.next_segment(),&mut first).unwrap();
    // Simulate QueueFull: no accepted() call and no lost/duplicated progress.
    req.write_segment(pending.next_segment(),&mut retry).unwrap();assert_eq!(first,retry);
    pending.accepted().unwrap();assert_eq!(pending.next_segment(),1);assert!(!pending.is_complete());
    assert!(pending.request(stamp.next_stack_generation().unwrap()).is_err());
    assert_eq!(pending.request(stamp).unwrap().write_segment(1,&mut retry).unwrap(),594);
    pending.accepted().unwrap();assert!(pending.is_complete());assert_eq!(pending.accepted(),Err(Error::SegmentIndex));
}
#[test]
fn builder_validates_before_exposing_owned_request(){
    let stamp=PacketStamp::new(1,1).unwrap();let bytes=packet();
    let (msg,result)=StampedSegments::write_with(bytes.len(),1460,stamp,|out|{out.copy_from_slice(&bytes);42}).unwrap();
    assert_eq!(result,42);assert_eq!(msg.request(stamp).unwrap().bytes(),bytes);
    assert!(StampedSegments::write_with(MAX_LOGICAL_PACKET+1,1460,stamp,|_|panic!("oversized allocation")).is_err());
    assert!(StampedSegments::copy_from(&bytes,1461,stamp).is_err());
}
