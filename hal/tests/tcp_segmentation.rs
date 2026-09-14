use vibeos_hal::tcp_segmentation::{TcpSegments,Error,MAX_LOGICAL_PACKET};
fn packet(n:usize)->Vec<u8>{
    let mut p=vec![0;n];p[..14].copy_from_slice(&[2,0,0,0,0,1,2,0,0,0,0,2,8,0]);
    p[14]=0x45;p[16..18].copy_from_slice(&((n-14) as u16).to_be_bytes());
    p[18..20].copy_from_slice(&65535u16.to_be_bytes());p[20]=0x40;p[22]=64;p[23]=6;
    p[26..34].copy_from_slice(&[192,0,2,1,192,0,2,2]);
    p[34..38].copy_from_slice(&[0x14,0xb4,0xc0,0]);
    p[38..42].copy_from_slice(&(u32::MAX-10).to_be_bytes());
    p[46]=0x80;p[47]=0x18;p[48]=0x7f;
    p[54..66].copy_from_slice(&[1,1,8,10,0,0,0,5,0,0,0,4]);
    for (i,b) in p[66..].iter_mut().enumerate(){*b=((i*19+i/251)%253) as u8;}p
}
fn valid_checksum(parts:&[&[u8]])->bool{
    let bytes:Vec<_>=parts.iter().flat_map(|s|s.iter().copied()).collect();
    let mut n=bytes.iter().enumerate().fold(0u64,|sum,(i,b)|sum+((*b as u64)<<if i%2==0{8}else{0}));
    while n>65535{n=(n&65535)+(n>>16);}n==65535
}
#[test]
fn segmentation_preserves_payload_mtu_options_sequence_and_valid_checksums(){
    for n in [67,1515,4097,MAX_LOGICAL_PACKET] {
        let p=packet(n);let original=p.clone();let req=TcpSegments::new(&p,1448).unwrap();
        let mut received=Vec::new();
        for i in 0..req.wire_segments(){
            let mut b=[0u8;1514];let len=req.write_segment(i,&mut b).unwrap();let b=&b[..len];
            assert!(len<=1514);assert_eq!(&b[54..66],&p[54..66]);
            assert_eq!(u16::from_be_bytes([b[16],b[17]]) as usize,len-14);
            assert_eq!(u16::from_be_bytes([b[18],b[19]]),65535u16.wrapping_add(i as u16));
            assert_eq!(u32::from_be_bytes(b[38..42].try_into().unwrap()),(u32::MAX-10).wrapping_add((i*1448) as u32));
            assert_eq!(b[47],if i+1==req.wire_segments(){0x18}else{0x10});
            assert!(valid_checksum(&[&b[14..34]]));
            let len=((len-34) as u16).to_be_bytes();
            assert!(valid_checksum(&[&b[26..34],&[0,6],&len,&b[34..]]));
            received.extend_from_slice(&b[66..]);
        }
        assert_eq!(received,&p[66..]);assert_eq!(p,original);
    }
}
#[test]
fn retries_are_identical_and_invalid_calls_do_not_mutate_output(){
    let p=packet(4097);let q=TcpSegments::new(&p,1448).unwrap();
    let mut a=[0xa5;1514];let mut b=[0xa5;1514];
    assert_eq!(q.write_segment(1,&mut a),q.write_segment(1,&mut b));assert_eq!(a,b);
    let mut small=[0xa5;10];assert_eq!(q.write_segment(0,&mut small),Err(Error::OutputTooSmall));assert_eq!(small,[0xa5;10]);
    assert_eq!(q.write_segment(usize::MAX,&mut a),Err(Error::SegmentIndex));assert_eq!(a,b);
    assert!(TcpSegments::new(&p,1).is_ok()); // Generic software fallback can serve small MSS.
    for mss in [0,1449,usize::MAX]{assert!(TcpSegments::new(&p,mss).is_err());}
    for end in 0..p.len(){assert!(TcpSegments::new(&p[..end],1448).is_err());}
}
