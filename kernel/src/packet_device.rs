//! Invocation token for the statically composed packet controller.
use vibeos_hal::network::{device, Error};
pub struct Engine;
impl Engine {
    /// # Safety
    /// The caller retains exclusive device/DMA capabilities for this session.
    pub unsafe fn claim(mac: [u8; 6], time: fn() -> u64, hz: u64) -> Result<Self, Error> {
        if !device().present { return Err(Error::InvalidDescription); }
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
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Completion);
        unsafe { (device().tx_owned)() }
    }
    pub fn transmit(&mut self, packet: &[u8]) -> Result<(), Error> {
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Tx);
        unsafe { (device().transmit)(packet) }
    }
    pub fn segmentation_limits(&self) -> Option<(usize,usize)> {
        device().segmentation.as_ref().map(|s|(s.max_packet_bytes,s.min_mss))
    }
    pub fn transmit_segments(&mut self, request: vibeos_hal::tcp_segmentation::TcpSegments<'_>) -> Result<(),Error> {
        let operation=device().segmentation.as_ref().ok_or(Error::InvalidDescription)?;
        if request.bytes().len()>operation.max_packet_bytes || request.mss()<operation.min_mss {
            return Err(Error::InvalidDescription);
        }
        let _scope=vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Tx);
        unsafe {(operation.transmit)(request)}
    }
    #[cfg(feature = "pooled-rx")]
    pub fn receive_ticket(&mut self) -> Result<Option<vibeos_hal::network_rx::Ticket>, Error> {
        let operations = device().receive_buffers.as_ref().ok_or(Error::InvalidDescription)?;
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Rx);
        unsafe { (operations.poll)() }
    }
    #[cfg(feature = "pooled-rx")]
    pub fn receive_batch(&mut self) -> Result<vibeos_hal::network_rx::TicketBatch, Error> {
        let operations = device().receive_buffers.as_ref().ok_or(Error::InvalidDescription)?;
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Rx);
        if let Some(poll) = operations.poll_batch { unsafe { poll() } }
        else {
            let mut batch = [None; vibeos_hal::network_rx::BATCH_SIZE];
            batch[0] = unsafe { (operations.poll)()? };
            Ok(batch)
        }
    }
    #[cfg(feature = "pooled-rx")]
    pub fn discard_ticket(&mut self, ticket: vibeos_hal::network_rx::Ticket) {
        if let Some(operations) = &device().receive_buffers { unsafe { (operations.discard)(ticket); } }
    }
    pub fn receive(&mut self, output: &mut [u8]) -> Option<usize> {
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Rx);
        unsafe { (device().receive)(output) }
    }
    pub fn poll_link(&mut self) {
        unsafe { (device().poll_link)() }
    }
    pub fn shutdown(self) -> bool {
        unsafe { (device().shutdown)() }
    }
}
