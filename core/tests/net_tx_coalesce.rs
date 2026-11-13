use vibeos_core::{net::PacketStamp, net_tx_coalesce::TxCoalescer};
use vibeos_hal::tcp_segmentation::TcpSegments;
fn stamp() -> PacketStamp { PacketStamp::new(1, 1).unwrap() }
fn frame(seq: u32, n: usize, flags: u8) -> Vec<u8> {
    let mut p = vec![0; 54 + n];
    p[0] = 2; p[6] = 2; p[12..14].copy_from_slice(&[8,0]);
    p[14] = 0x45; p[16..18].copy_from_slice(&((40 + n) as u16).to_be_bytes());
    p[20] = 0x40; p[22] = 64; p[23] = 6; p[26] = 10; p[30] = 11;
    p[34..38].copy_from_slice(&[1,2,3,4]); p[38..42].copy_from_slice(&seq.to_be_bytes());
    p[46] = 0x50; p[47] = flags; p[48] = 0x7f;
    for (i, b) in p[54..].iter_mut().enumerate() { *b = seq.wrapping_add(i as u32) as u8; }
    let mut wire = vec![0; p.len()];
    TcpSegments::new(&p,n).unwrap().write_segment(0,&mut wire).unwrap(); wire
}
#[test]
fn reconstructs_packet_boundaries_and_payload_across_sequence_wrap() {
    let mut batch = TxCoalescer::new(); let mut seq = u32::MAX - 1000;
    let mut originals = Vec::new();
    for (n,flags) in [(1460,0x10),(1460,0x10),(17,0x18)] {
        let p = frame(seq,n,flags); assert!(batch.push(&p,stamp())); originals.push(p);
        seq = seq.wrapping_add(n as u32);
    }
    assert_eq!(batch.frames(),3);
    assert!(!batch.push(&frame(seq,1460,0x10),stamp()));
    let request = batch.request(stamp()).unwrap(); assert_eq!(request.wire_segments(),3);
    for (i,p) in originals.iter().enumerate() {
        let mut out = [0;1514]; let n=request.write_segment(i,&mut out).unwrap();
        assert_eq!(n,p.len()); assert_eq!(&out[26..50],&p[26..50]);
        assert_eq!(&out[52..n],&p[52..]);
        assert_eq!(u16::from_be_bytes([out[18],out[19]]),i as u16);
    }
}
#[test]
fn incompatibility_and_session_changes_never_mutate_pending_batch() {
    let mut batch=TxCoalescer::new(); let first=frame(100,1460,0x10);
    assert!(batch.push(&first,stamp()));
    for offset in [0,6,15,22,26,30,34,36,42,44,48] {
        let mut next=frame(1560,1460,0x10);next[offset]^=1;
        assert!(!batch.push(&next,stamp()),"offset {offset}");
        assert_eq!(batch.request(stamp()).unwrap().bytes(),first);
    }
    assert!(!batch.push(&frame(1559,1460,0x10),stamp()));
    let newer=stamp().next_stack_generation().unwrap();
    assert!(!batch.push(&frame(1560,1460,0x10),newer));
    assert!(batch.request(newer).is_err());
    assert!(batch.request(stamp().next_device_epoch().unwrap()).is_err());
    // QueueFull causes no clear/advance; retry reads identical bytes.
    assert_eq!(batch.request(stamp()).unwrap().bytes(),first);
    batch.clear(); assert!(batch.push(&frame(1560,1460,0x10),newer));
}
#[test]
fn bounds_psh_and_short_packet_flush() {
    let mut batch=TxCoalescer::new();
    for i in 0..16 {assert!(batch.push(&frame(i*1460,1460,0x10),stamp()));}
    assert!(!batch.push(&frame(16*1460,1460,0x10),stamp()));
    assert_eq!(batch.frames(),16); batch.clear();
    assert!(!batch.push(&frame(0,63,0x10),stamp()));
    assert!(batch.push(&frame(0,1460,0x18),stamp()));
    assert!(!batch.push(&frame(1460,1460,0x10),stamp())); batch.clear();
    assert!(batch.push(&frame(0,1000,0x10),stamp()));
    assert!(!batch.push(&frame(1000,1460,0x10),stamp()));
    assert!(batch.push(&frame(1000,1,0x10),stamp()));
    assert!(!batch.push(&frame(1001,1000,0x10),stamp()));
}
