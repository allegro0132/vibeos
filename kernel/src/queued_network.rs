//! Local incarnation token prevents repeated shutdown from reaching a replacement.
use crate::virtio_mmio::MmioTransport;
use vibeos_hal::queued_network::{device, Info, ReceivedFrame};
pub use vibeos_hal::queued_network::{Error as HardwareError, ResetReason};
pub struct Engine {
    transport: MmioTransport,
    released: Option<bool>,
    cached: Info,
}
impl Engine {
    pub fn attach(transport: MmioTransport, epoch: u64) -> Result<Self, HardwareError> {
        // Kernel AUTHORITY serializes attach and excludes previous users.
        unsafe {
            (device().attach)(transport.slot(), transport.base(), epoch)?;
        }
        Ok(Self {
            transport,
            released: None,
            cached: unsafe { (device().info)() },
        })
    }
    fn active(&self) -> Result<(), HardwareError> {
        if self.released.is_some() {
            Err(HardwareError::Offline)
        } else {
            Ok(())
        }
    }
    pub fn transport(&self) -> MmioTransport {
        self.transport
    }
    pub fn info(&self) -> Info {
        if self.released.is_some() {
            self.cached
        } else {
            unsafe { (device().info)() }
        }
    }
    pub fn start(&self) -> Result<(), HardwareError> {
        self.active()?;
        unsafe { (device().start)() }
    }
    pub fn service_device_events(&mut self, causes: u32) -> Result<bool, HardwareError> {
        self.active()?;
        unsafe { (device().service_events)(causes) }
    }
    pub fn drain_transmit_completions(&mut self) -> Result<u8, HardwareError> {
        self.active()?;
        unsafe { (device().drain_tx)() }
    }
    pub fn receive(&mut self) -> Result<Option<ReceivedFrame>, HardwareError> {
        self.active()?;
        unsafe { (device().receive)() }
    }
    pub fn submit_transmit(&mut self, frame: &[u8], deadline: u64) -> Result<(), HardwareError> {
        self.active()?;
        unsafe { (device().transmit)(frame, deadline) }
    }
    pub fn check_timeout(&mut self, now: u64) -> Result<bool, HardwareError> {
        self.active()?;
        unsafe { (device().check_timeout)(now) }
    }
    pub fn reset_and_reinitialize(&mut self, reason: ResetReason) -> Result<u64, HardwareError> {
        self.active()?;
        unsafe { (device().reset)(reason) }
    }
    pub fn shutdown(&mut self, reason: ResetReason) -> bool {
        if let Some(reset) = self.released {
            return reset;
        }
        self.cached = self.info();
        let reset = unsafe { (device().shutdown)(reason) };
        self.cached.rx_inflight = 0;
        self.cached.tx_inflight = 0;
        self.cached.quarantined = !reset;
        self.released = Some(reset);
        reset
    }
    pub fn force_quarantine(&mut self) {
        if self.released.is_some() {
            return;
        }
        self.cached = self.info();
        unsafe {
            (device().force_quarantine)();
        }
        self.cached.quarantined = true;
        self.released = Some(false);
    }
}
pub fn dma_base() -> usize {
    (device().dma_base)()
}
pub fn dma_size() -> usize {
    device().dma_size
}
pub fn dma_quarantined() -> bool {
    (device().dma_quarantined)()
}
pub fn quarantine_before_attach(t: MmioTransport) {
    unsafe {
        (device().quarantine_before_attach)(t.slot(), t.base());
    }
}
pub unsafe fn recover_faulted_transport(t: MmioTransport) -> bool {
    (device().recover)(t.slot(), t.base())
}
pub unsafe fn acknowledge_irq_at_base(base: usize) -> u32 {
    (device().acknowledge)(base)
}
impl Drop for Engine {
    fn drop(&mut self) { let _ = self.shutdown(ResetReason::Cancelled); }
}
