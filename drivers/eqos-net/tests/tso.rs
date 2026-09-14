use vibeos_eqos_net::tso::{Request,MAX_PACKET};
fn packet(n:usize)->Vec<u8>{
    let mut p=vec![0;n];p[12..14].copy_from_slice(&[8,0]);p[14]=0x45;
    p[16..18].copy_from_slice(&((n-14) as u16).to_be_bytes());
    p[20]=0x40;p[23]=6;p[46]=0x80;p[47]=0x10;p
}
#[test]
fn logical_request_keeps_wire_mtu_and_borrows_without_modification(){
    let p=packet(MAX_PACKET);let before=p.clone();let r=Request::new(&p,1448).unwrap();
    assert_eq!(r.header_bytes(),66);assert_eq!(r.payload_bytes(),32702);
    assert_eq!(r.wire_segments(),23);assert_eq!(r.bytes().as_ptr(),p.as_ptr());assert_eq!(p,before);
    assert!(Request::new(&p,1449).is_err());
    assert!(Request::new(&packet(67),1448).is_ok());
    assert!(Request::new(&packet(66),1448).is_err());
    assert!(Request::new(&packet(MAX_PACKET+1),1448).is_err());
}
#[test]
fn malformed_or_control_packets_never_enter_tso(){
    let p=packet(4096);
    for i in [12,14,16,20,21,23,46,47,52] {
        let mut bad=p.clone();bad[i]^=1;assert!(Request::new(&bad,1448).is_err(),"offset {i}");
    }
    for flags in [0,1,2,4,0x11,0x12,0x30,0x50,0x90] {
        let mut bad=p.clone();bad[47]=flags;assert!(Request::new(&bad,1448).is_err());
    }
    for n in 0..p.len() { assert!(Request::new(&p[..n],1448).is_err()); }
}
