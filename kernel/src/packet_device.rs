//! Invocation token for the statically composed packet controller.
use vibeos_hal::network::{device, Error};
pub struct Engine;
impl Engine {
    /// # Safety
    /// The caller retains exclusive device/DMA capabilities for this session.
    pub unsafe fn claim(mac: [u8; 6], time: fn() -> u64, hz: u64) -> Result<Self, Error> {
        (device().claim)(mac, time, hz)?;
        Ok(Self)
    }
    pub fn irq(&self) -> u32 {
        device().irq
    }
    pub fn tx_checksum_offload(&self) -> bool {
        unsafe { (device().telemetry)().tx_checksum_offload }
    }
    pub fn rx_checksum_offload(&self) -> bool {
        unsafe { (device().telemetry)().rx_checksum_offload }
    }
    pub fn tx_owned(&mut self) -> bool {
        unsafe { (device().tx_owned)() }
    }
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        unsafe { (device().transmit)(packet) }
    }
    pub fn receive(&mut self, output: &mut [u8]) -> Option<usize> {
        unsafe { (device().receive)(output) }
    }
    pub fn poll_link(&mut self) {
        unsafe { (device().poll_link)() }
    }
    pub fn shutdown(self) -> bool {
        unsafe { (device().shutdown)() }
    }
}
