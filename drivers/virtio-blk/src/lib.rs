//! Supervision-independent Virtio block hardware engine.
//!
//! This crate owns the device-visible split queue and the protocol state that
//! makes it safe to reuse.  Interrupt routing, scheduling, capabilities and
//! fault-domain recovery deliberately remain with the kernel adapter.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use vibeos_driver_virtio_core as virtio;
use vibeos_driver_virtio_core::{
    AvailableRing, BlockDmaAddresses, BlockOperation, BlockRequestHeader, BlockStatus, Descriptor,
    ModernInit, NegotiatedFeatures, QueueError, ResetReason, SplitQueueModel, Submission,
    UsedElement, UsedRing, BLOCK_HEADER_DESCRIPTOR, BLOCK_SECTOR_SIZE, SPLIT_QUEUE_SIZE,
    STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER_OK,
};
use vibeos_driver_virtio_mmio::MmioTransport;

pub const RESET_POLL_BUDGET: usize = 100_000;
pub const DMA_BYTES: usize = core::mem::size_of::<DmaSlab>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareError {
    AlreadyClaimed,
    QueueFull,
    ReadOnly,
    FlushUnsupported,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    RestartRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineInfo {
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub read_only: bool,
    pub supports_flush: bool,
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSubmission {
    protocol: Submission,
    operation: BlockOperation,
    previous_used_index: u16,
}

impl PendingSubmission {
    pub const fn previous_used_index(self) -> u16 {
        self.previous_used_index
    }
}

#[repr(C, align(4096))]
struct DmaSlab {
    descriptors: [Descriptor; SPLIT_QUEUE_SIZE as usize],
    available: AvailableRing,
    used: UsedRing,
    header: BlockRequestHeader,
    data: [u8; BLOCK_SECTOR_SIZE as usize],
    status: u8,
}

impl DmaSlab {
    const ZERO: Self = Self {
        descriptors: [Descriptor::new(0, 0, 0, 0); SPLIT_QUEUE_SIZE as usize],
        available: AvailableRing {
            flags: 0,
            index: 0,
            ring: [0; SPLIT_QUEUE_SIZE as usize],
        },
        used: UsedRing {
            flags: 0,
            index: 0,
            ring: [UsedElement::new(0, 0); SPLIT_QUEUE_SIZE as usize],
        },
        header: BlockRequestHeader {
            request_type: 0,
            reserved: 0,
            sector: 0,
        },
        data: [0; BLOCK_SECTOR_SIZE as usize],
        status: 0,
    };
}

struct StableDma(UnsafeCell<DmaSlab>);

// Safety: CPU access is serialized by DMA_CLAIMED and BlockEngine permits a
// single in-flight request. The device only receives addresses in this slab.
unsafe impl Sync for StableDma {}

#[cfg_attr(target_os = "none", link_section = ".dma")]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));
static DMA_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Exclusive ownership of one initialized block transport and the global,
/// physically stable DMA slab.
pub struct BlockEngine {
    transport: MmioTransport,
    model: SplitQueueModel,
    features: NegotiatedFeatures,
    capacity: u64,
    quarantined: bool,
}

impl BlockEngine {
    /// Claim the stable DMA slab and negotiate queue zero. DRIVER_OK is left
    /// clear until the kernel has installed and enabled the IRQ route.
    pub fn attach(transport: MmioTransport, epoch: u64) -> Result<Self, HardwareError> {
        if epoch == 0 {
            return Err(HardwareError::Protocol);
        }
        if DMA_CLAIMED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(HardwareError::AlreadyClaimed);
        }
        clear_dma();
        match initialize(transport) {
            Ok((features, capacity)) => Ok(Self {
                transport,
                model: SplitQueueModel::at_epoch(features, epoch)
                    .expect("the epoch was validated as non-zero"),
                features,
                capacity,
                quarantined: false,
            }),
            Err(error) => {
                if transport.reset(RESET_POLL_BUDGET) {
                    clear_dma();
                    DMA_CLAIMED.store(false, Ordering::Release);
                    Err(error)
                } else {
                    // The failed initialization may already have published
                    // queue addresses. Preserve the claim until a future
                    // platform recovery can prove the device is quiescent.
                    Err(HardwareError::Quarantined)
                }
            }
        }
    }

    pub const fn transport(&self) -> MmioTransport {
        self.transport
    }

    pub const fn info(&self) -> EngineInfo {
        EngineInfo {
            capacity_sectors: self.capacity,
            queue_size: SPLIT_QUEUE_SIZE,
            read_only: self.features.read_only(),
            supports_flush: self.features.supports_flush(),
            epoch: self.model.epoch(),
        }
    }

    pub fn mark_ready(&self) {
        self.transport.add_status(STATUS_DRIVER_OK);
    }

    pub fn device_needs_reset(&self) -> bool {
        self.transport.status() & STATUS_DEVICE_NEEDS_RESET != 0
    }

    pub fn refresh_capacity(&mut self) -> Result<u64, HardwareError> {
        let capacity = self.transport.block_capacity().ok_or_else(|| {
            self.model.require_reset(ResetReason::DeviceNeedsReset);
            HardwareError::Protocol
        })?;
        self.capacity = capacity;
        Ok(capacity)
    }

    pub fn require_device_reset(&mut self) {
        self.model.require_reset(ResetReason::DeviceNeedsReset);
    }

    pub fn submit(
        &mut self,
        operation: BlockOperation,
        data: [u8; 512],
    ) -> Result<PendingSubmission, HardwareError> {
        let previous_used_index = self.model.used_index();
        let protocol = self.model.submit(operation).map_err(map_queue_error)?;
        publish_request(operation, data, protocol.available_slot)?;
        Ok(PendingSubmission {
            protocol,
            operation,
            previous_used_index,
        })
    }

    pub fn notify(&self) {
        self.transport.notify_queue(0);
    }

    pub fn used_index(&self) -> u16 {
        read_used_index()
    }

    pub fn used_element(&self, previous_used_index: u16) -> UsedElement {
        read_used_element(virtio::ring_slot(previous_used_index) as usize)
    }

    pub fn complete(
        &mut self,
        submission: PendingSubmission,
        observed_used_index: u16,
        used: UsedElement,
    ) -> Result<[u8; 512], HardwareError> {
        let status = unsafe { core::ptr::addr_of!((*DMA.0.get()).status).read_volatile() };
        let completion = self
            .model
            .complete(submission.protocol, observed_used_index, used, status)
            .map_err(|_| HardwareError::Protocol)?;
        match completion.block_status {
            BlockStatus::Ok if matches!(submission.operation, BlockOperation::Read { .. }) => {
                Ok(read_dma_data())
            }
            BlockStatus::Ok => Ok([0; 512]),
            BlockStatus::IoError => Err(HardwareError::DeviceIo),
            BlockStatus::Unsupported => Err(HardwareError::Unsupported),
        }
    }

    pub fn timeout(&mut self, submission: PendingSubmission) -> Result<(), HardwareError> {
        self.model
            .timeout(submission.protocol)
            .map_err(|_| HardwareError::Protocol)
    }

    /// Confirm status zero, then renegotiate without releasing the DMA claim.
    /// The caller must first disable the transport interrupt.
    pub fn reset_and_reinitialize(&mut self) -> Result<(), HardwareError> {
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.quarantined = true;
            return Err(HardwareError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        self.model
            .confirm_reset(0)
            .map_err(|_| HardwareError::Protocol)?;
        clear_dma();
        let (features, capacity) = initialize(self.transport)?;
        self.model = SplitQueueModel::at_epoch(features, self.model.epoch())
            .ok_or(HardwareError::Protocol)?;
        self.features = features;
        self.capacity = capacity;
        Ok(())
    }

    /// Reset and relinquish the stable slab. Failure quarantines the DMA
    /// addresses permanently and intentionally leaves the claim set.
    pub fn shutdown(mut self) -> Result<(), HardwareError> {
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.quarantined = true;
            return Err(HardwareError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        clear_dma();
        DMA_CLAIMED.store(false, Ordering::Release);
        Ok(())
    }
}

/// Fault-recovery path for an engine whose owning future can no longer run.
/// Reset confirmation is the only authority needed to release its static DMA.
///
/// # Safety
/// The owner of the previous `BlockEngine` must be permanently unable to run.
pub unsafe fn recover_after_fault(transport: MmioTransport) -> Result<(), HardwareError> {
    if !transport.reset(RESET_POLL_BUDGET) {
        return Err(HardwareError::Quarantined);
    }
    let _ = transport.acknowledge_interrupt();
    clear_dma();
    DMA_CLAIMED.store(false, Ordering::Release);
    Ok(())
}

/// Minimal IRQ-safe acknowledgement using a transport base previously
/// validated by `MmioTransport`. No engine or task-owned pointer is touched.
///
/// # Safety
/// `transport_base` must remain mapped to a modern Virtio MMIO window.
pub unsafe fn acknowledge_interrupt_at(transport_base: usize) -> u32 {
    use vibeos_driver_virtio_core::{
        InterruptCauses, MMIO_INTERRUPT_ACK_OFFSET, MMIO_INTERRUPT_STATUS_OFFSET,
    };
    let raw =
        unsafe { ((transport_base + MMIO_INTERRUPT_STATUS_OFFSET) as *const u32).read_volatile() };
    dma_fence();
    let causes = InterruptCauses::from_status(raw).ack_bits();
    if causes != 0 {
        dma_fence();
        unsafe {
            ((transport_base + MMIO_INTERRUPT_ACK_OFFSET) as *mut u32).write_volatile(causes)
        };
        dma_fence();
    }
    causes
}

fn initialize(transport: MmioTransport) -> Result<(NegotiatedFeatures, u64), HardwareError> {
    if !transport.reset(RESET_POLL_BUDGET) {
        return Err(HardwareError::Quarantined);
    }
    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| HardwareError::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| HardwareError::Protocol)?);
    let features = init
        .select_features(transport.device_features())
        .map_err(|_| HardwareError::Unsupported)?;
    transport.set_driver_features(features.accepted());
    transport.set_status(
        init.set_features_ok()
            .map_err(|_| HardwareError::Protocol)?,
    );
    init.confirm_features(transport.status())
        .map_err(|_| HardwareError::Unsupported)?;
    transport.select_queue(0);
    if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
        return Err(HardwareError::Unsupported);
    }
    let (descriptors, available, used) = dma_addresses();
    transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    let capacity = transport.block_capacity().ok_or(HardwareError::Protocol)?;
    Ok((features, capacity))
}

pub fn dma_base() -> usize {
    DMA.0.get() as usize
}

fn publish_request(
    operation: BlockOperation,
    data: [u8; 512],
    available_slot: u16,
) -> Result<(), HardwareError> {
    let addresses = unsafe {
        let slab = DMA.0.get();
        BlockDmaAddresses {
            header: core::ptr::addr_of!((*slab).header) as u64,
            data: core::ptr::addr_of!((*slab).data) as u64,
            status: core::ptr::addr_of!((*slab).status) as u64,
        }
    };
    let chain =
        virtio::build_block_chain(operation, addresses).map_err(|_| HardwareError::Protocol)?;
    unsafe {
        let slab = DMA.0.get();
        core::ptr::addr_of_mut!((*slab).header).write_volatile(BlockRequestHeader::new(operation));
        core::ptr::addr_of_mut!((*slab).status).write_volatile(0xff);
        if matches!(operation, BlockOperation::Write { .. }) {
            let destination = core::ptr::addr_of_mut!((*slab).data) as *mut u8;
            for (index, byte) in data.iter().copied().enumerate() {
                destination.add(index).write_volatile(byte);
            }
        }
        for (index, descriptor) in chain.descriptors.iter().copied().enumerate() {
            core::ptr::addr_of_mut!((*slab).descriptors[index]).write_volatile(descriptor);
        }
        let ring = core::ptr::addr_of_mut!((*slab).available.ring) as *mut u16;
        ring.add(available_slot as usize)
            .write_volatile(BLOCK_HEADER_DESCRIPTOR.to_le());
        dma_fence();
        let index = core::ptr::addr_of_mut!((*slab).available.index);
        let next = u16::from_le(index.read_volatile()).wrapping_add(1);
        index.write_volatile(next.to_le());
        dma_fence();
    }
    Ok(())
}

fn dma_addresses() -> (u64, u64, u64) {
    unsafe {
        let slab = DMA.0.get();
        (
            core::ptr::addr_of!((*slab).descriptors) as u64,
            core::ptr::addr_of!((*slab).available) as u64,
            core::ptr::addr_of!((*slab).used) as u64,
        )
    }
}

fn clear_dma() {
    unsafe {
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, DMA_BYTES);
        dma_fence();
    }
}

fn read_used_index() -> u16 {
    dma_fence();
    unsafe { u16::from_le(core::ptr::addr_of!((*DMA.0.get()).used.index).read_volatile()) }
}

fn read_used_element(slot: usize) -> UsedElement {
    dma_fence();
    unsafe { core::ptr::addr_of!((*DMA.0.get()).used.ring[slot]).read_volatile() }
}

fn read_dma_data() -> [u8; 512] {
    let mut data = [0; 512];
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).data) as *const u8;
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
    data
}

fn map_queue_error(error: QueueError) -> HardwareError {
    match error {
        QueueError::Busy => HardwareError::QueueFull,
        QueueError::ReadOnly => HardwareError::ReadOnly,
        QueueError::FlushUnsupported => HardwareError::FlushUnsupported,
        _ => HardwareError::Protocol,
    }
}

#[inline]
fn dma_fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use vibeos_driver_virtio_core::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_F_VERSION_1};

    #[test]
    fn dma_layout_is_stable_and_queue_aligned() {
        assert_eq!(dma_base() % 4096, 0);
        assert!(DMA_BYTES >= 512);
        assert_eq!(core::mem::align_of::<DmaSlab>(), 4096);
    }

    #[test]
    fn queue_errors_keep_hardware_meaning() {
        assert_eq!(map_queue_error(QueueError::Busy), HardwareError::QueueFull);
        assert_eq!(
            map_queue_error(QueueError::ReadOnly),
            HardwareError::ReadOnly
        );
        assert_eq!(
            map_queue_error(QueueError::FlushUnsupported),
            HardwareError::FlushUnsupported
        );
    }

    #[test]
    fn engine_info_reflects_negotiated_block_features() {
        let features = virtio::negotiate_block_features(
            VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH,
        )
        .unwrap();
        let model = SplitQueueModel::at_epoch(features, 9).unwrap();
        let info = EngineInfo {
            capacity_sectors: 123,
            queue_size: SPLIT_QUEUE_SIZE,
            read_only: features.read_only(),
            supports_flush: features.supports_flush(),
            epoch: model.epoch(),
        };
        assert_eq!(info.capacity_sectors, 123);
        assert!(info.read_only);
        assert!(info.supports_flush);
        assert_eq!(info.epoch, 9);
    }

    #[test]
    fn shutdown_consumes_the_engine_owner() {
        // This function-pointer type is a compile-time assertion that shutdown
        // takes BlockEngine by value. Safe code therefore cannot touch DMA via
        // the old owner after the method returns, including on reset failure.
        let _: fn(BlockEngine) -> Result<(), HardwareError> = BlockEngine::shutdown;
    }
}
