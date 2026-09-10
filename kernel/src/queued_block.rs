//! Invocation adapter for the firmware's queued block controller.
use crate::{
    virtio::{BlockOperation, UsedElement},
    virtio_mmio::MmioTransport,
};
use vibeos_hal::queued_block::{device, Completion, Info, Operation};
pub use vibeos_hal::queued_block::{Error as HardwareError, Submission};
pub struct BlockEngine {
    transport: MmioTransport,
}
impl BlockEngine {
    pub fn attach(transport: MmioTransport, epoch: u64) -> Result<Self, HardwareError> {
        // The kernel AUTHORITY barrier serializes attach and excludes prior
        // owners; the driver additionally atomically claims its DMA pool.
        unsafe {
            (device().attach)(transport.slot(), transport.base(), epoch)?;
        }
        Ok(Self { transport })
    }
    pub fn transport(&self) -> MmioTransport {
        self.transport
    }
    pub fn info(&self) -> Info {
        unsafe { (device().info)() }
    }
    pub fn mark_ready(&self) {
        unsafe { (device().mark_ready)() }
    }
    pub fn device_needs_reset(&self) -> bool {
        unsafe { (device().needs_reset)() }
    }
    pub fn refresh_capacity(&mut self) -> Result<u64, HardwareError> {
        unsafe { (device().refresh_capacity)() }
    }
    pub fn require_device_reset(&mut self) {
        unsafe { (device().require_reset)() }
    }
    pub fn submit_tracked(
        &mut self,
        op: BlockOperation,
        data: &[u8],
        published: impl FnOnce(),
    ) -> Result<Submission, HardwareError> {
        let operation = if op.is_read() {
            Operation::Read {
                sector: op.sector(),
                blocks: op.block_count(),
            }
        } else if op.is_write() {
            Operation::Write {
                sector: op.sector(),
                blocks: op.block_count(),
            }
        } else {
            Operation::Flush
        };
        let mut published = Some(published);
        unsafe {
            (device().submit)(operation, data, &mut || {
                if let Some(hook) = published.take() {
                    hook();
                }
            })
        }
    }
    pub fn notify(&self) {
        unsafe { (device().notify)() }
    }
    pub fn used_index(&self) -> u16 {
        unsafe { (device().used_index)() }
    }
    pub fn used_element(&self, previous: u16) -> UsedElement {
        let completion = unsafe { (device().used_element)(previous) };
        UsedElement {
            id: completion.id,
            length: completion.length,
        }
    }
    pub fn complete(
        &mut self,
        token: Submission,
        index: u16,
        used: UsedElement,
        out: &mut [u8],
    ) -> Result<(), HardwareError> {
        unsafe {
            (device().complete)(
                token,
                index,
                Completion {
                    id: used.id,
                    length: used.length,
                },
                out,
            )
        }
    }
    pub fn timeout(&mut self, token: Submission) -> Result<(), HardwareError> {
        unsafe { (device().timeout)(token) }
    }
    pub fn reset_and_reinitialize(&mut self) -> Result<(), HardwareError> {
        unsafe { (device().reset)() }
    }
    pub fn shutdown(self) -> Result<(), HardwareError> {
        unsafe { (device().shutdown)() }
    }
}
pub fn dma_base() -> usize {
    (device().dma_base)()
}
pub fn dma_bytes() -> usize {
    device().dma_bytes
}
pub unsafe fn recover_after_fault(t: MmioTransport) -> Result<(), HardwareError> {
    (device().recover)(t.slot(), t.base())
}
pub unsafe fn acknowledge_interrupt_at(base: usize) -> u32 {
    (device().acknowledge)(base)
}
