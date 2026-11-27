use alloc::vec::Vec;

pub struct Packet {
    pub bytes: Vec<u8>,
    pub mss: Option<u16>,
    pub payload_sums: Option<Vec<u16>>,
}
impl From<Vec<u8>> for Packet {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mss: None,
            payload_sums: None,
        }
    }
}
impl core::ops::Deref for Packet {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
