//! Synchronous VirtIO RNG hardware engine.
//!
//! The engine owns the fixed DMA slab and enforces the split-ring protocol.
//! Scheduling, interrupt routing, deadlines and capability policy deliberately
//! remain with the kernel adapter.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;

use vibeos_driver_virtio_core as virtio;
use vibeos_driver_virtio_core::{
    AvailableRing, Descriptor, ModernInit, UsedElement, UsedRing, DESC_F_WRITE, SPLIT_QUEUE_SIZE,
};
use vibeos_driver_virtio_mmio::MmioTransport;

pub const MAX_RANDOM_BYTES: usize = 64;
const ENTROPY_QUEUE: u16 = 0;
const ENTROPY_DESCRIPTOR: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    Busy,
    Protocol,
    Unsupported,
    DriverRestarted,
    IdentityExhausted,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    epoch: u64,
    requested: u16,
    available_slot: u16,
    expected_used_index: u16,
}

impl Submission {
    pub const fn requested(self) -> usize {
        self.requested as usize
    }
    pub const fn previous_used_index(self) -> u16 {
        self.expected_used_index.wrapping_sub(1)
    }
}

struct QueueModel {
    epoch: u64,
    available_index: u16,
    used_index: u16,
    active: Option<Submission>,
    reset_required: bool,
}

impl QueueModel {
    fn new(epoch: u64) -> Result<Self, Error> {
        if epoch == 0 {
            return Err(Error::IdentityExhausted);
        }
        Ok(Self {
            epoch,
            available_index: 0,
            used_index: 0,
            active: None,
            reset_required: false,
        })
    }

    fn submit(&mut self, requested: usize) -> Result<Submission, Error> {
        if self.reset_required {
            return Err(Error::DriverRestarted);
        }
        if self.active.is_some() {
            return Err(Error::Busy);
        }
        if !(1..=MAX_RANDOM_BYTES).contains(&requested) {
            return Err(Error::InvalidLength);
        }
        let old = self.available_index;
        self.available_index = old.wrapping_add(1);
        let submission = Submission {
            epoch: self.epoch,
            requested: requested as u16,
            available_slot: virtio::ring_slot(old),
            expected_used_index: self.used_index.wrapping_add(1),
        };
        self.active = Some(submission);
        Ok(submission)
    }

    fn complete(
        &mut self,
        submission: Submission,
        observed: u16,
        used: UsedElement,
    ) -> Result<usize, Error> {
        let valid = submission.epoch == self.epoch
            && self.active == Some(submission)
            && observed == submission.expected_used_index
            && used.id() == u32::from(ENTROPY_DESCRIPTOR)
            && used.length() != 0
            && used.length() as usize <= submission.requested as usize;
        if !valid {
            self.reset_required = true;
            return Err(Error::Protocol);
        }
        self.used_index = observed;
        self.active = None;
        Ok(used.length() as usize)
    }
}

#[repr(C, align(4096))]
struct DmaSlab {
    descriptors: [Descriptor; SPLIT_QUEUE_SIZE as usize],
    available: AvailableRing,
    used: UsedRing,
    data: [u8; MAX_RANDOM_BYTES],
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
        data: [0; MAX_RANDOM_BYTES],
    };
}

struct StableDma(UnsafeCell<DmaSlab>);
unsafe impl Sync for StableDma {}

#[cfg_attr(target_os = "none", link_section = ".dma")]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));

pub const DMA_BYTES: usize = core::mem::size_of::<DmaSlab>();

pub struct Engine {
    transport: MmioTransport,
    model: QueueModel,
    accepted_features: u64,
    ready_status: u32,
    quarantined: bool,
}

impl Engine {
    /// Reset, negotiate the modern entropy profile, and configure queue zero.
    ///
    /// # Safety
    ///
    /// The caller must exclusively own both `transport` and this crate's
    /// process-wide DMA slab. It must serialize every engine access for the
    /// complete lifetime of the returned value; creating concurrent engines
    /// would alias the fixed DMA memory.
    pub unsafe fn prepare(
        transport: MmioTransport,
        epoch: u64,
        reset_budget: usize,
    ) -> Result<Self, Error> {
        let (accepted_features, ready_status) = initialize_transport(transport, reset_budget)?;
        Ok(Self {
            transport,
            model: QueueModel::new(epoch)?,
            accepted_features,
            ready_status,
            quarantined: false,
        })
    }

    pub const fn accepted_features(&self) -> u64 {
        self.accepted_features
    }
    pub const fn epoch(&self) -> u64 {
        self.model.epoch
    }
    pub const fn used_index(&self) -> u16 {
        self.model.used_index
    }
    pub const fn quarantined(&self) -> bool {
        self.quarantined
    }

    pub fn start(&self) -> Result<(), Error> {
        self.transport.set_status(self.ready_status);
        if self.operational() {
            Ok(())
        } else {
            Err(Error::DriverRestarted)
        }
    }

    pub fn operational(&self) -> bool {
        operational_status(self.transport.status())
    }

    /// Publish one writable descriptor and notify queue zero.
    pub fn submit(&mut self, requested: usize) -> Result<Submission, Error> {
        let submission = self.model.submit(requested)?;
        publish_request(submission)?;
        self.transport.notify_queue(ENTROPY_QUEUE);
        Ok(submission)
    }

    pub fn completion(&self, submission: Submission) -> Option<(u16, UsedElement)> {
        let used_index = read_used_index();
        if used_index == submission.previous_used_index() {
            return None;
        }
        let slot = virtio::ring_slot(submission.previous_used_index()) as usize;
        Some((used_index, read_used_element(slot)))
    }

    /// Validate a completion and copy only the initialized prefix from DMA.
    pub fn finish(&mut self, submission: Submission, output: &mut [u8]) -> Result<usize, Error> {
        let Some((observed, used)) = self.completion(submission) else {
            return Err(Error::Busy);
        };
        let length = self.model.complete(submission, observed, used)?;
        if output.len() < length {
            self.model.reset_required = true;
            return Err(Error::Protocol);
        }
        read_dma_data(&mut output[..length]);
        zero_dma_data();
        Ok(length)
    }

    pub fn require_reset(&mut self) {
        self.model.reset_required = true;
    }

    /// Confirm reset before reusing DMA, then negotiate a fresh queue epoch.
    pub fn reset_and_prepare(&mut self, epoch: u64, reset_budget: usize) -> Result<(), Error> {
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        if !self.transport.reset(reset_budget) {
            self.quarantined = true;
            return Err(Error::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        clear_dma();
        let (accepted_features, ready_status) =
            match initialize_transport(self.transport, reset_budget) {
                Ok(initialized) => initialized,
                Err(Error::Quarantined) => {
                    self.quarantined = true;
                    return Err(Error::Quarantined);
                }
                Err(error) => return Err(error),
            };
        self.model = QueueModel::new(epoch)?;
        self.accepted_features = accepted_features;
        self.ready_status = ready_status;
        Ok(())
    }

    /// A failed confirmation permanently quarantines the engine and its DMA.
    pub fn shutdown(&mut self, reset_budget: usize) -> Result<(), Error> {
        if self.quarantined {
            return Err(Error::Quarantined);
        }
        if !self.transport.reset(reset_budget) {
            self.quarantined = true;
            return Err(Error::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        clear_dma();
        Ok(())
    }
}

fn initialize_transport(
    transport: MmioTransport,
    reset_budget: usize,
) -> Result<(u64, u32), Error> {
    if transport.device_id() != virtio::DEVICE_ID_ENTROPY {
        return Err(Error::Unsupported);
    }
    if !transport.reset(reset_budget) {
        return Err(Error::Quarantined);
    }
    // No DMA byte may be reused until status-zero has been observed.
    clear_dma();
    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| Error::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| Error::Protocol)?);
    let features = init
        .select_entropy_features(transport.device_features())
        .map_err(|_| Error::Unsupported)?;
    transport.set_driver_features(features.accepted());
    transport.set_status(init.set_features_ok().map_err(|_| Error::Protocol)?);
    init.confirm_features(transport.status())
        .map_err(|_| Error::Unsupported)?;
    transport.select_queue(ENTROPY_QUEUE);
    if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
        return Err(Error::Unsupported);
    }
    let (descriptors, available, used) = dma_addresses();
    transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    let ready = init.set_driver_ok().map_err(|_| Error::Protocol)?;
    Ok((features.accepted(), ready))
}

pub fn operational_status(status: u32) -> bool {
    let expected = virtio::STATUS_ACKNOWLEDGE
        | virtio::STATUS_DRIVER
        | virtio::STATUS_FEATURES_OK
        | virtio::STATUS_DRIVER_OK;
    status & (virtio::STATUS_FAILED | virtio::STATUS_DEVICE_NEEDS_RESET) == 0
        && status & expected == expected
}

pub fn dma_base() -> usize {
    DMA.0.get() as usize
}
fn clear_dma() {
    unsafe {
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, DMA_BYTES);
        dma_fence();
    }
}

/// Confirm that the device released DMA before clearing the shared slab.
///
/// # Safety
///
/// The caller must exclusively own `transport` and the process-wide DMA slab,
/// and must guarantee that no engine or CPU context accesses the slab during
/// this operation.
pub unsafe fn confirmed_reset(transport: MmioTransport, reset_budget: usize) -> bool {
    if !transport.reset(reset_budget) {
        return false;
    }
    let _ = transport.acknowledge_interrupt();
    clear_dma();
    true
}

/// Minimal IRQ-safe acknowledgement using a transport base previously
/// validated and exclusively assigned to this entropy device.
///
/// # Safety
///
/// `transport_base` must remain mapped as a live modern VirtIO MMIO transport
/// for the duration of this call and must not be reassigned to a different
/// device. Concurrent acknowledgements of the same fixed transport are
/// permitted: the acknowledged cause bits are write-one-to-clear.
pub unsafe fn acknowledge_interrupt_at(transport_base: usize) -> u32 {
    let raw = unsafe {
        ((transport_base + virtio::MMIO_INTERRUPT_STATUS_OFFSET) as *const u32).read_volatile()
    };
    irq_fence();
    let causes = virtio::InterruptCauses::from_status(raw).ack_bits();
    if causes != 0 {
        irq_fence();
        unsafe {
            ((transport_base + virtio::MMIO_INTERRUPT_ACK_OFFSET) as *mut u32)
                .write_volatile(causes)
        };
        irq_fence();
    }
    causes
}

#[inline]
fn irq_fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags))
    };

    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn zero_dma_data() {
    unsafe {
        let data = core::ptr::addr_of_mut!((*DMA.0.get()).data) as *mut u8;
        for index in 0..MAX_RANDOM_BYTES {
            data.add(index).write_volatile(0);
        }
        dma_fence();
    }
}

fn publish_request(submission: Submission) -> Result<(), Error> {
    if submission.requested == 0 || submission.requested as usize > MAX_RANDOM_BYTES {
        return Err(Error::InvalidLength);
    }
    zero_dma_data();
    let address = unsafe { core::ptr::addr_of!((*DMA.0.get()).data) as u64 };
    let descriptor = Descriptor::new(address, u32::from(submission.requested), DESC_F_WRITE, 0);
    unsafe {
        let slab = DMA.0.get();
        core::ptr::addr_of_mut!((*slab).descriptors[ENTROPY_DESCRIPTOR as usize])
            .write_volatile(descriptor);
        let ring = core::ptr::addr_of_mut!((*slab).available.ring) as *mut u16;
        ring.add(submission.available_slot as usize)
            .write_volatile(ENTROPY_DESCRIPTOR.to_le());
        dma_fence();
        core::ptr::addr_of_mut!((*slab).available.index)
            .write_volatile(submission.expected_used_index.to_le());
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
fn read_used_index() -> u16 {
    dma_fence();
    unsafe { u16::from_le(core::ptr::addr_of!((*DMA.0.get()).used.index).read_volatile()) }
}
fn read_used_element(slot: usize) -> UsedElement {
    dma_fence();
    unsafe { core::ptr::addr_of!((*DMA.0.get()).used.ring[slot]).read_volatile() }
}
fn read_dma_data(output: &mut [u8]) {
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).data) as *const u8;
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
}

#[inline]
fn dma_fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_rejects_zero_and_parallel_work() {
        let mut queue = QueueModel::new(1).unwrap();
        assert_eq!(queue.submit(0), Err(Error::InvalidLength));
        queue.submit(8).unwrap();
        assert_eq!(queue.submit(8), Err(Error::Busy));
    }

    #[test]
    fn partial_completion_is_valid_but_zero_is_not() {
        let mut queue = QueueModel::new(7).unwrap();
        let submission = queue.submit(16).unwrap();
        assert_eq!(queue.complete(submission, 1, UsedElement::new(0, 5)), Ok(5));
        let submission = queue.submit(16).unwrap();
        assert_eq!(
            queue.complete(submission, 2, UsedElement::new(0, 0)),
            Err(Error::Protocol)
        );
    }

    #[test]
    fn stale_epoch_and_bad_descriptor_force_reset() {
        let mut queue = QueueModel::new(2).unwrap();
        let mut submission = queue.submit(4).unwrap();
        submission.epoch = 1;
        assert_eq!(
            queue.complete(submission, 1, UsedElement::new(0, 4)),
            Err(Error::Protocol)
        );
        assert_eq!(queue.submit(4), Err(Error::DriverRestarted));
    }
}
