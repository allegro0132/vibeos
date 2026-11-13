//! Logical TCP transmit contract, independent of a controller descriptor format.
//! Wire IP MTU stays 1500. The caller retains the borrowed bytes until return;
//! asynchronous queues must own their backing storage and session identity.
pub const MAX_LOGICAL_PACKET: usize = 32 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Format, Length, Mss, OutputTooSmall, SegmentIndex }
#[derive(Clone, Copy, Debug)]
pub struct TcpSegments<'a> { packet: &'a [u8], header: usize, mss: usize }
impl<'a> TcpSegments<'a> {
    /// Admit Ethernet/IPv4 without VLAN/IP options, DF, non-ECN TCP ACK data
    /// with optional final PSH. Control/fragment packets retain the raw path.
    /// Input checksum fields are placeholders; software segmentation rebuilds
    /// them and a hardware backend must prepare its own checksum convention.
    pub fn new(packet: &'a [u8], mss: usize) -> Result<Self, Error> {
        if !(55..=MAX_LOGICAL_PACKET).contains(&packet.len()) {return Err(Error::Length);}
        if packet[12..14]!=[8,0] || packet[14]!=0x45 || packet[23]!=6
            || packet[20..22]!=[0x40,0] || packet[15]&3!=0
            || packet[46]&15!=0 || !matches!(packet[47],0x10|0x18)
            || packet[52..54]!=[0,0] {return Err(Error::Format);}
        if u16::from_be_bytes([packet[16],packet[17]]) as usize!=packet.len()-14 {
            return Err(Error::Length);
        }
        let tcp=(packet[46]>>4) as usize*4;
        if !(20..=60).contains(&tcp) {return Err(Error::Format);}
        let header=34+tcp;
        if header>=packet.len(){return Err(Error::Length);}
        if mss==0 || mss>1500-20-tcp{return Err(Error::Mss);}
        Ok(Self{packet,header,mss})
    }
    pub fn bytes(self)-> &'a [u8]{self.packet}
    pub fn header_bytes(self)->usize{self.header}
    pub fn payload_bytes(self)->usize{self.packet.len()-self.header}
    pub fn mss(self)->usize{self.mss}
    pub fn wire_segments(self)->usize{self.payload_bytes().div_ceil(self.mss)}
    /// Stateless retry: the same index always yields the same frame. QueueFull
    /// must leave the caller's index unchanged, so no segment is lost/repeated.
    pub fn write_segment(self,index:usize,out:&mut [u8])->Result<usize,Error>{
        if index>=self.wire_segments(){return Err(Error::SegmentIndex);}
        let offset=index*self.mss;
        let payload=(self.payload_bytes()-offset).min(self.mss);
        let length=self.header+payload;
        if out.len()<length{return Err(Error::OutputTooSmall);}
        let b=&mut out[..length];b[..self.header].copy_from_slice(&self.packet[..self.header]);
        b[self.header..].copy_from_slice(&self.packet[self.header+offset..self.header+offset+payload]);
        b[16..18].copy_from_slice(&((length-14) as u16).to_be_bytes());
        let id=u16::from_be_bytes([self.packet[18],self.packet[19]]).wrapping_add(index as u16);
        b[18..20].copy_from_slice(&id.to_be_bytes());
        let seq=u32::from_be_bytes(self.packet[38..42].try_into().unwrap()).wrapping_add(offset as u32);
        b[38..42].copy_from_slice(&seq.to_be_bytes());
        if index+1!=self.wire_segments(){b[47]&=!8;}
        b[24..26].fill(0);b[50..52].fill(0);
        let ip=checksum(sum(&b[14..34]));b[24..26].copy_from_slice(&ip.to_be_bytes());
        let tcp=checksum(sum(&b[26..34])+6+(length-34) as u32+sum(&b[34..]));
        b[50..52].copy_from_slice(&tcp.to_be_bytes());Ok(length)
    }
}
fn sum(b:&[u8])->u32{
    let mut words=b.chunks_exact(2);
    let mut sum=words.by_ref().map(|w|u16::from_be_bytes([w[0],w[1]]) as u32).sum::<u32>();
    if let Some(last)=words.remainder().first(){sum+=(*last as u32)<<8;}sum
}
fn checksum(mut value:u32)->u16{
    while value>0xffff{value=(value&0xffff)+(value>>16);}!(value as u16)
}
