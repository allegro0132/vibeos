//! EQoS admission on top of the portable logical TCP contract.
pub use vibeos_hal::tcp_segmentation::MAX_LOGICAL_PACKET as MAX_PACKET;
use crate::descriptor;
#[derive(Clone, Copy)]
pub struct Request<'a>(vibeos_hal::tcp_segmentation::TcpSegments<'a>);
impl<'a> Request<'a> {
    pub fn new(packet: &'a [u8], mss: usize) -> Result<Self,descriptor::Error> {
        let request=vibeos_hal::tcp_segmentation::TcpSegments::new(packet,mss)
            .map_err(|_|descriptor::Error::InvalidLayout)?;
        Self::from_segments(request)
    }
    pub fn from_segments(request: vibeos_hal::tcp_segmentation::TcpSegments<'a>)
        ->Result<Self,descriptor::Error> {
        descriptor::tso_mss(request.mss(),request.header_bytes()-34)?;
        Ok(Self(request))
    }
    pub fn bytes(self)-> &'a [u8]{self.0.bytes()}
    pub fn header_bytes(self)->usize{self.0.header_bytes()}
    pub fn payload_bytes(self)->usize{self.0.payload_bytes()}
    pub fn mss(self)->usize{self.0.mss()}
    pub fn wire_segments(self)->usize{self.0.wire_segments()}
}
