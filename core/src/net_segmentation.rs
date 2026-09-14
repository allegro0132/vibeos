//! Owned logical TCP messages for a separate capability queue. The existing
//! Packet/StampedPacket representation and raw Ethernet endpoint stay intact.
extern crate alloc;
use alloc::{boxed::Box,vec};
use crate::net::{PacketStamp,PacketStampMismatch};
pub use vibeos_hal::tcp_segmentation::{TcpSegments,Error,MAX_LOGICAL_PACKET};
pub struct StampedSegments { bytes:Box<[u8]>,mss:usize,stamp:PacketStamp }
impl StampedSegments {
    pub fn copy_from(bytes:&[u8],mss:usize,stamp:PacketStamp)->Result<Self,Error>{
        TcpSegments::new(bytes,mss)?;
        Ok(Self{bytes:bytes.into(),mss,stamp})
    }
    pub fn write_with<R>(length:usize,mss:usize,stamp:PacketStamp,
        fill:impl FnOnce(&mut [u8])->R)->Result<(Self,R),Error>{
        if !(55..=MAX_LOGICAL_PACKET).contains(&length){return Err(Error::Length);}
        let mut bytes=vec![0;length].into_boxed_slice();let result=fill(&mut bytes);
        TcpSegments::new(&bytes,mss)?;Ok((Self{bytes,mss,stamp},result))
    }
    /// Recheck the full session identity on every attempt, including fallback
    /// retries; revocation of queue authority is separately enforced by policy.
    pub fn request(&self,expected:PacketStamp)->Result<TcpSegments<'_>,PacketStampMismatch>{
        if expected!=self.stamp{return Err(PacketStampMismatch{expected,observed:self.stamp});}
        Ok(TcpSegments::new(&self.bytes,self.mss).expect("immutable validated TCP message"))
    }
}
/// Progress for one software-fallback send. QueueFull does not call `accepted`.
/// Callers must finish this message before admitting its successor on the queue.
pub struct SoftwareTransmit { message:StampedSegments,next:usize,total:usize }
impl SoftwareTransmit {
    pub fn new(message:StampedSegments)->Self{
        let total=message.request(message.stamp).unwrap().wire_segments();
        Self{message,next:0,total}
    }
    pub fn request(&self,expected:PacketStamp)->Result<TcpSegments<'_>,PacketStampMismatch>{self.message.request(expected)}
    pub fn next_segment(&self)->usize{self.next}
    pub fn is_complete(&self)->bool{self.next==self.total}
    pub fn accepted(&mut self)->Result<(),Error>{
        if self.is_complete(){return Err(Error::SegmentIndex);}
        self.next+=1;Ok(())
    }
}
