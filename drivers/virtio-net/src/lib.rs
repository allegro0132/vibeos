//! Allocation-free VirtIO network hardware engine.
//!
//! This crate owns the fixed DMA slab, split-ring protocol, feature handshake,
//! completion validation, timeout bookkeeping, and reset/quarantine boundary.
//! Kernel composition remains responsible for capabilities, packet-session
//! identity, interrupt routing, scheduling, and supervisor policy.

#![cfg_attr(not(test), no_std)]

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use vibeos_core::net::MAX_PACKET_LEN;
use vibeos_driver_virtio_core as virtio;
use vibeos_driver_virtio_core::{
    AvailableRing, Descriptor, ModernInit, NegotiatedFeatures, NetDeviceModel, NetDeviceState,
    NetOperation, NetQueue, NetResetReason, NetSubmission, UsedElement, UsedRing, VirtioNetHeader,
    NET_HEADER_SIZE, NET_RECEIVE_QUEUE, NET_TRANSMIT_QUEUE, SPLIT_QUEUE_SIZE, VIRTIO_F_VERSION_1,
};
use vibeos_driver_virtio_mmio::MmioTransport;

const _: () = assert!(MAX_PACKET_LEN as u32 == virtio::NET_MAX_FRAME_SIZE);

pub const RESET_POLL_BUDGET: usize = 100_000;
pub const QUEUE_SLOTS: usize = SPLIT_QUEUE_SIZE as usize;
const HEADER_BYTES: usize = NET_HEADER_SIZE as usize;
const INTERRUPT_STATUS_OFFSET: usize = 0x060;
const INTERRUPT_ACK_OFFSET: usize = 0x064;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareError {
    Offline,
    QueueFull,
    TimedOut,
    Protocol,
    Quarantined,
    IdentityExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetReason {
    Device,
    Protocol,
    Timeout,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedFrame {
    bytes: [u8; MAX_PACKET_LEN],
    len: u16,
}

impl ReceivedFrame {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineInfo {
    pub accepted_features: u64,
    pub epoch: u64,
    pub rx_inflight: u8,
    pub tx_inflight: u8,
    pub quarantined: bool,
}

#[repr(C)]
struct NetBuffer {
    header: [u8; HEADER_BYTES],
    frame: [u8; MAX_PACKET_LEN],
}

impl NetBuffer {
    const ZERO: Self = Self {
        header: [0; HEADER_BYTES],
        frame: [0; MAX_PACKET_LEN],
    };
}

#[repr(C, align(4096))]
struct QueueDma {
    descriptors: [Descriptor; QUEUE_SLOTS],
    available: AvailableRing,
    used: UsedRing,
}

impl QueueDma {
    const ZERO: Self = Self {
        descriptors: [Descriptor::new(0, 0, 0, 0); QUEUE_SLOTS],
        available: AvailableRing {
            flags: 0,
            index: 0,
            ring: [0; QUEUE_SLOTS],
        },
        used: UsedRing {
            flags: 0,
            index: 0,
            ring: [UsedElement::new(0, 0); QUEUE_SLOTS],
        },
    };
}

#[repr(C, align(4096))]
struct DmaSlab {
    receive: QueueDma,
    transmit: QueueDma,
    receive_buffers: [NetBuffer; QUEUE_SLOTS],
    transmit_buffers: [NetBuffer; QUEUE_SLOTS],
}

impl DmaSlab {
    const ZERO: Self = Self {
        receive: QueueDma::ZERO,
        transmit: QueueDma::ZERO,
        receive_buffers: [const { NetBuffer::ZERO }; QUEUE_SLOTS],
        transmit_buffers: [const { NetBuffer::ZERO }; QUEUE_SLOTS],
    };
}

struct StableDma(UnsafeCell<DmaSlab>);

// Safety: CLAIMED serializes CPU ownership. A failed reset deliberately keeps
// the claim forever, so a device can never DMA into memory reused by an owner.
unsafe impl Sync for StableDma {}

#[cfg_attr(target_os = "none", link_section = ".dma")]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));
static CLAIMED: AtomicBool = AtomicBool::new(false);
static QUARANTINED: AtomicBool = AtomicBool::new(false);

pub const fn dma_size() -> usize {
    core::mem::size_of::<DmaSlab>()
}

pub fn dma_base() -> usize {
    DMA.0.get() as usize
}

pub fn dma_quarantined() -> bool {
    QUARANTINED.load(Ordering::Acquire)
}

/// Recover a transport whose task incarnation was abandoned by its executor.
///
/// # Safety
///
/// The engine incarnation that owned the global DMA claim must have been
/// detached permanently and must never run or be dropped after this call.
/// Interrupt delivery for `transport` must already be detached. These
/// conditions make it sound to clear the slab and release `CLAIMED` after the
/// device confirms reset.
pub unsafe fn recover_faulted_transport(transport: MmioTransport) -> bool {
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    if reset {
        clear_dma();
        CLAIMED.store(false, Ordering::Release);
    } else {
        QUARANTINED.store(true, Ordering::Release);
    }
    reset
}

/// Fail closed when packet-session identity is exhausted before an engine has
/// acquired the DMA slab. This path never clears DMA or releases a claim: even
/// an accidental concurrent call cannot make live engine memory reusable.
pub fn quarantine_before_attach(transport: MmioTransport) {
    let _ = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    QUARANTINED.store(true, Ordering::Release);
    CLAIMED.store(true, Ordering::Release);
}

/// Allocation-free IRQ top-half operation for an already validated transport.
/// The kernel may retain only the base address in its interrupt routing table;
/// this helper keeps device register semantics in the hardware crate.
///
/// # Safety
///
/// `transport_base` must name a mapped modern VirtIO MMIO register window that
/// remains live for the entire interrupt callback.
pub unsafe fn acknowledge_irq_at_base(transport_base: usize) -> u32 {
    let raw = unsafe { ((transport_base + INTERRUPT_STATUS_OFFSET) as *const u32).read_volatile() };
    dma_fence();
    let causes = virtio::InterruptCauses::from_status(raw).ack_bits();
    if causes != 0 {
        dma_fence();
        unsafe { ((transport_base + INTERRUPT_ACK_OFFSET) as *mut u32).write_volatile(causes) };
        dma_fence();
    }
    causes
}

/// One exclusive incarnation of the hardware engine.
pub struct Engine {
    transport: MmioTransport,
    model: NetDeviceModel,
    features: NegotiatedFeatures,
    tx_deadlines: [u64; QUEUE_SLOTS],
    armed: bool,
}

impl Engine {
    pub fn attach(transport: MmioTransport, epoch: u64) -> Result<Self, HardwareError> {
        if QUARANTINED.load(Ordering::Acquire)
            || CLAIMED
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return Err(HardwareError::Quarantined);
        }
        clear_dma();
        let features = match initialize_transport(transport) {
            Ok(features) => features,
            Err(error) => {
                release_after_failed_attach(transport);
                return Err(error);
            }
        };
        let Some(model) = NetDeviceModel::at_epoch(epoch) else {
            release_after_failed_attach(transport);
            return Err(HardwareError::IdentityExhausted);
        };
        let mut engine = Self {
            transport,
            model,
            features,
            tx_deadlines: [0; QUEUE_SLOTS],
            armed: true,
        };
        if let Err(error) = engine.post_all_receives() {
            engine.shutdown(ResetReason::Protocol);
            return Err(error);
        }
        Ok(engine)
    }

    pub const fn transport(&self) -> MmioTransport {
        self.transport
    }

    pub fn info(&self) -> EngineInfo {
        EngineInfo {
            accepted_features: self.features.accepted(),
            epoch: self.model.epoch(),
            rx_inflight: self.model.inflight(NetQueue::Receive),
            tx_inflight: self.model.inflight(NetQueue::Transmit),
            quarantined: matches!(self.model.state(), NetDeviceState::Quarantined { .. }),
        }
    }

    pub fn start(&self) -> Result<(), HardwareError> {
        self.ensure_armed()?;
        self.transport.add_status(virtio::STATUS_DRIVER_OK);
        self.transport.notify_queue(NET_RECEIVE_QUEUE);
        Ok(())
    }

    pub fn service_device_events(&mut self, raw_causes: u32) -> Result<bool, HardwareError> {
        self.ensure_armed()?;
        let causes = virtio::InterruptCauses::from_status(raw_causes);
        let status = self.transport.status();
        let expected = virtio::STATUS_ACKNOWLEDGE
            | virtio::STATUS_DRIVER
            | virtio::STATUS_FEATURES_OK
            | virtio::STATUS_DRIVER_OK;
        if status & (virtio::STATUS_DEVICE_NEEDS_RESET | virtio::STATUS_FAILED) != 0
            || status & expected != expected
        {
            self.model.require_reset(NetResetReason::DeviceNeedsReset);
            return Err(HardwareError::Offline);
        }
        Ok(!causes.is_empty())
    }

    pub fn drain_transmit_completions(&mut self) -> Result<u8, HardwareError> {
        self.ensure_armed()?;
        let observed = read_used_index(NetQueue::Transmit);
        let mut completed = 0u8;
        let mut budget = QUEUE_SLOTS;
        while self.model.used_index(NetQueue::Transmit) != observed && budget != 0 {
            let slot = virtio::ring_slot(self.model.used_index(NetQueue::Transmit)) as usize;
            let used = read_used_element(NetQueue::Transmit, slot);
            match self.model.complete_transmit(observed, used) {
                Ok(completion) => {
                    self.tx_deadlines[completion.submission.token.head as usize] = 0;
                    completed += 1;
                }
                Err(_) => {
                    self.model
                        .require_reset(NetResetReason::MalformedCompletion);
                    return Err(HardwareError::Protocol);
                }
            }
            budget -= 1;
        }
        if self.model.used_index(NetQueue::Transmit) != observed {
            self.model
                .require_reset(NetResetReason::MalformedCompletion);
            return Err(HardwareError::Protocol);
        }
        Ok(completed)
    }

    /// Consume at most one receive completion and immediately repost its slot.
    pub fn receive(&mut self) -> Result<Option<ReceivedFrame>, HardwareError> {
        self.ensure_armed()?;
        let observed = read_used_index(NetQueue::Receive);
        if self.model.used_index(NetQueue::Receive) == observed {
            return Ok(None);
        }
        let slot = virtio::ring_slot(self.model.used_index(NetQueue::Receive)) as usize;
        let used = read_used_element(NetQueue::Receive, slot);
        let frame_length = virtio::validate_net_receive_length(used.length()).map_err(|_| {
            self.model
                .require_reset(NetResetReason::MalformedCompletion);
            HardwareError::Protocol
        })? as usize;
        let head = used.id();
        let header = if head < u32::from(SPLIT_QUEUE_SIZE) {
            VirtioNetHeader::from_bytes(read_receive_header(head as usize))
        } else {
            VirtioNetHeader::transmit()
        };
        let completion = self
            .model
            .complete_receive(observed, used, header)
            .map_err(|_| HardwareError::Protocol)?;
        if completion.frame_length as usize != frame_length || frame_length == 0 {
            self.model
                .require_reset(NetResetReason::MalformedCompletion);
            return Err(HardwareError::Protocol);
        }
        let bytes = read_receive_frame(completion.submission.token.head as usize, frame_length);
        let submission = self
            .model
            .post_receive()
            .map_err(|_| HardwareError::Protocol)?;
        publish_receive(submission)?;
        self.transport.notify_queue(NET_RECEIVE_QUEUE);
        Ok(Some(ReceivedFrame {
            bytes,
            len: frame_length as u16,
        }))
    }

    pub fn submit_transmit(&mut self, frame: &[u8], deadline: u64) -> Result<(), HardwareError> {
        self.ensure_armed()?;
        let submission = self
            .model
            .submit_transmit(frame.len())
            .map_err(|_| HardwareError::QueueFull)?;
        publish_transmit(submission, frame)?;
        self.tx_deadlines[submission.token.head as usize] = deadline;
        self.transport.notify_queue(NET_TRANSMIT_QUEUE);
        Ok(())
    }

    pub fn check_timeout(&mut self, now: u64) -> Result<bool, HardwareError> {
        self.ensure_armed()?;
        for head in 0..QUEUE_SLOTS {
            let deadline = self.tx_deadlines[head];
            if deadline == 0 || now < deadline {
                continue;
            }
            let Some(submission) = self
                .model
                .active_submission(NetQueue::Transmit, head as u16)
            else {
                self.tx_deadlines[head] = 0;
                continue;
            };
            self.model
                .timeout(submission.token)
                .map_err(|_| HardwareError::Protocol)?;
            return Err(HardwareError::TimedOut);
        }
        Ok(false)
    }

    pub fn reset_and_reinitialize(&mut self, reason: ResetReason) -> Result<u64, HardwareError> {
        self.ensure_armed()?;
        if !matches!(self.model.state(), NetDeviceState::ResetRequired { .. }) {
            self.model.require_reset(match reason {
                ResetReason::Device => NetResetReason::DeviceNeedsReset,
                ResetReason::Protocol => NetResetReason::MalformedCompletion,
                ResetReason::Timeout => NetResetReason::Timeout,
                ResetReason::Cancelled => NetResetReason::Cancelled,
            });
        }
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.model.quarantine(NetResetReason::ResetFailed);
            self.quarantine();
            return Err(HardwareError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        if self.model.confirm_reset(0).is_err() {
            self.model.quarantine(NetResetReason::IdentityExhausted);
            self.quarantine();
            return Err(HardwareError::IdentityExhausted);
        }
        clear_dma();
        self.features = initialize_transport(self.transport)?;
        self.model
            .reinitialize()
            .map_err(|_| HardwareError::Protocol)?;
        self.tx_deadlines = [0; QUEUE_SLOTS];
        self.post_all_receives()?;
        self.start()?;
        Ok(self.model.epoch())
    }

    pub fn shutdown(&mut self, reason: ResetReason) -> bool {
        if !self.armed {
            return !QUARANTINED.load(Ordering::Acquire);
        }
        self.model.require_reset(match reason {
            ResetReason::Device => NetResetReason::DeviceNeedsReset,
            ResetReason::Protocol => NetResetReason::MalformedCompletion,
            ResetReason::Timeout => NetResetReason::Timeout,
            ResetReason::Cancelled => NetResetReason::Cancelled,
        });
        let reset = self.transport.reset(RESET_POLL_BUDGET);
        let _ = self.transport.acknowledge_interrupt();
        self.armed = false;
        if reset {
            clear_dma();
            CLAIMED.store(false, Ordering::Release);
        } else {
            self.model.quarantine(NetResetReason::ResetFailed);
            QUARANTINED.store(true, Ordering::Release);
        }
        reset
    }

    pub fn force_quarantine(&mut self) {
        if self.ensure_armed().is_err() {
            return;
        }
        self.model.quarantine(NetResetReason::IdentityExhausted);
        let _ = self.transport.reset(RESET_POLL_BUDGET);
        let _ = self.transport.acknowledge_interrupt();
        self.quarantine();
    }

    fn quarantine(&mut self) {
        self.armed = false;
        QUARANTINED.store(true, Ordering::Release);
        // CLAIMED remains set: every address in DMA stays permanently owned.
    }

    /// Runtime typestate boundary for the retained `Engine` value. Once an
    /// incarnation releases or permanently quarantines its claim, no safe
    /// method may touch the shared DMA slab again.
    fn ensure_armed(&self) -> Result<(), HardwareError> {
        require_armed(self.armed)
    }

    fn post_all_receives(&mut self) -> Result<(), HardwareError> {
        self.ensure_armed()?;
        for _ in 0..QUEUE_SLOTS {
            let submission = self
                .model
                .post_receive()
                .map_err(|_| HardwareError::Protocol)?;
            publish_receive(submission)?;
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.shutdown(ResetReason::Cancelled);
    }
}

fn release_after_failed_attach(transport: MmioTransport) {
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    if reset {
        clear_dma();
        CLAIMED.store(false, Ordering::Release);
    } else {
        QUARANTINED.store(true, Ordering::Release);
    }
}

fn require_armed(armed: bool) -> Result<(), HardwareError> {
    if armed {
        Ok(())
    } else {
        Err(HardwareError::Offline)
    }
}

fn initialize_transport(transport: MmioTransport) -> Result<NegotiatedFeatures, HardwareError> {
    if !transport.reset(RESET_POLL_BUDGET) {
        QUARANTINED.store(true, Ordering::Release);
        return Err(HardwareError::Quarantined);
    }
    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| HardwareError::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| HardwareError::Protocol)?);
    let features = init
        .select_net_features(transport.device_features())
        .map_err(|_| HardwareError::Protocol)?;
    if features.accepted() != VIRTIO_F_VERSION_1 {
        return Err(HardwareError::Protocol);
    }
    transport.set_driver_features(features.accepted());
    transport.set_status(
        init.set_features_ok()
            .map_err(|_| HardwareError::Protocol)?,
    );
    init.confirm_features(transport.status())
        .map_err(|_| HardwareError::Protocol)?;
    for queue in [NetQueue::Receive, NetQueue::Transmit] {
        transport.select_queue(queue.index());
        if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
            return Err(HardwareError::Protocol);
        }
        let (descriptors, available, used) = queue_dma_addresses(queue);
        transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    }
    Ok(features)
}

fn publish_receive(submission: NetSubmission) -> Result<(), HardwareError> {
    debug_assert_eq!(submission.operation, NetOperation::Receive);
    let head = submission.token.head as usize;
    if head >= QUEUE_SLOTS {
        return Err(HardwareError::Protocol);
    }
    clear_receive_buffer(head);
    prime_receive_header(head);
    let descriptor =
        virtio::build_net_descriptor(submission.operation, receive_buffer_address(head))
            .map_err(|_| HardwareError::Protocol)?;
    publish_descriptor(NetQueue::Receive, submission, descriptor);
    Ok(())
}

fn publish_transmit(submission: NetSubmission, frame: &[u8]) -> Result<(), HardwareError> {
    let head = submission.token.head as usize;
    if head >= QUEUE_SLOTS || frame.is_empty() || frame.len() > MAX_PACKET_LEN {
        return Err(HardwareError::Protocol);
    }
    write_transmit_buffer(head, frame);
    let descriptor =
        virtio::build_net_descriptor(submission.operation, transmit_buffer_address(head))
            .map_err(|_| HardwareError::Protocol)?;
    publish_descriptor(NetQueue::Transmit, submission, descriptor);
    Ok(())
}

fn publish_descriptor(queue: NetQueue, submission: NetSubmission, descriptor: Descriptor) {
    unsafe {
        let queue_dma = queue_dma_ptr(queue);
        core::ptr::addr_of_mut!((*queue_dma).descriptors[submission.token.head as usize])
            .write_volatile(descriptor);
        let ring = core::ptr::addr_of_mut!((*queue_dma).available.ring) as *mut u16;
        ring.add(submission.available_slot as usize)
            .write_volatile(submission.token.head.to_le());
        dma_fence();
        core::ptr::addr_of_mut!((*queue_dma).available.index)
            .write_volatile(submission.available_index.to_le());
        dma_fence();
    }
}

fn clear_receive_buffer(head: usize) {
    unsafe {
        let buffer = core::ptr::addr_of_mut!((*DMA.0.get()).receive_buffers[head]);
        core::ptr::write_bytes(buffer.cast::<u8>(), 0, core::mem::size_of::<NetBuffer>());
        dma_fence();
    }
}

fn prime_receive_header(head: usize) {
    let header = VirtioNetHeader::received_without_offload().to_bytes();
    unsafe {
        let destination =
            core::ptr::addr_of_mut!((*DMA.0.get()).receive_buffers[head].header) as *mut u8;
        for (index, byte) in header.iter().copied().enumerate() {
            destination.add(index).write_volatile(byte);
        }
        dma_fence();
    }
}

fn write_transmit_buffer(head: usize, frame: &[u8]) {
    unsafe {
        let buffer = core::ptr::addr_of_mut!((*DMA.0.get()).transmit_buffers[head]);
        core::ptr::write_bytes(buffer.cast::<u8>(), 0, core::mem::size_of::<NetBuffer>());
        let header = VirtioNetHeader::transmit().to_bytes();
        let header_dst = core::ptr::addr_of_mut!((*buffer).header) as *mut u8;
        for (index, byte) in header.iter().copied().enumerate() {
            header_dst.add(index).write_volatile(byte);
        }
        let frame_dst = core::ptr::addr_of_mut!((*buffer).frame) as *mut u8;
        for (index, byte) in frame.iter().copied().enumerate() {
            frame_dst.add(index).write_volatile(byte);
        }
        dma_fence();
    }
}

fn read_receive_header(head: usize) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    dma_fence();
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).receive_buffers[head].header) as *const u8;
        for (index, byte) in header.iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
    header
}

fn read_receive_frame(head: usize, length: usize) -> [u8; MAX_PACKET_LEN] {
    let mut frame = [0; MAX_PACKET_LEN];
    dma_fence();
    unsafe {
        let source = core::ptr::addr_of!((*DMA.0.get()).receive_buffers[head].frame) as *const u8;
        for (index, byte) in frame[..length].iter_mut().enumerate() {
            *byte = source.add(index).read_volatile();
        }
    }
    frame
}

fn queue_dma_addresses(queue: NetQueue) -> (u64, u64, u64) {
    unsafe {
        let queue = queue_dma_ptr(queue);
        (
            core::ptr::addr_of!((*queue).descriptors) as u64,
            core::ptr::addr_of!((*queue).available) as u64,
            core::ptr::addr_of!((*queue).used) as u64,
        )
    }
}

fn receive_buffer_address(head: usize) -> u64 {
    unsafe { core::ptr::addr_of!((*DMA.0.get()).receive_buffers[head]) as u64 }
}
fn transmit_buffer_address(head: usize) -> u64 {
    unsafe { core::ptr::addr_of!((*DMA.0.get()).transmit_buffers[head]) as u64 }
}

unsafe fn queue_dma_ptr(queue: NetQueue) -> *mut QueueDma {
    match queue {
        NetQueue::Receive => unsafe { core::ptr::addr_of_mut!((*DMA.0.get()).receive) },
        NetQueue::Transmit => unsafe { core::ptr::addr_of_mut!((*DMA.0.get()).transmit) },
    }
}

fn read_used_index(queue: NetQueue) -> u16 {
    dma_fence();
    unsafe { u16::from_le(core::ptr::addr_of!((*queue_dma_ptr(queue)).used.index).read_volatile()) }
}

fn read_used_element(queue: NetQueue, slot: usize) -> UsedElement {
    dma_fence();
    unsafe { core::ptr::addr_of!((*queue_dma_ptr(queue)).used.ring[slot]).read_volatile() }
}

fn clear_dma() {
    unsafe {
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, dma_size());
        dma_fence();
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

    #[test]
    fn dma_layout_is_page_aligned_and_fixed() {
        assert_eq!(dma_base() % 4096, 0);
        assert!(dma_size() >= 2 * 4096);
        assert_eq!(QUEUE_SLOTS, 8);
    }

    #[test]
    fn received_frame_exposes_only_initialized_prefix() {
        let mut bytes = [0; MAX_PACKET_LEN];
        bytes[..4].copy_from_slice(b"vibe");
        let frame = ReceivedFrame { bytes, len: 4 };
        assert_eq!(frame.as_bytes(), b"vibe");
    }

    #[test]
    fn inactive_incarnation_cannot_enter_dma_operations() {
        assert_eq!(require_armed(false), Err(HardwareError::Offline));
        assert_eq!(require_armed(true), Ok(()));
    }
}
