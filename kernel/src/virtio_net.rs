//! Supervised modern virtio-net component.
//!
//! The device sees only a fixed, page-aligned SYSTEM-owned DMA slab. Packets
//! cross the component boundary by value through two bounded typed endpoints;
//! neither queue descriptor can ever contain a client-provided pointer.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::cell::UnsafeCell;
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Poll;

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::exec::{self, WaitQueue};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{Endpoint, Packet, MAX_PACKET_LEN};
use crate::plic;
use crate::sync::SpinLock;
use crate::virtio::{
    self, AvailableRing, Descriptor, ModernInit, NegotiatedFeatures, NetDeviceModel,
    NetDeviceState, NetOperation, NetQueue, NetResetReason, NetSubmission, UsedElement, UsedRing,
    VirtioNetHeader, NET_HEADER_SIZE, NET_RECEIVE_QUEUE, NET_TRANSMIT_QUEUE, SPLIT_QUEUE_SIZE,
    VIRTIO_F_VERSION_1,
};
use crate::virtio_mmio::MmioTransport;
use crate::world::Space;

const RESET_POLL_BUDGET: usize = 100_000;
const TX_TIMEOUT_MS: u64 = 2_000;
const IDLE_POLL_MS: u64 = 1;
const QUEUE_SLOTS: usize = SPLIT_QUEUE_SIZE as usize;
const HEADER_BYTES: usize = NET_HEADER_SIZE as usize;
const DMA_BYTES: usize = core::mem::size_of::<DmaSlab>();
const INTERRUPT_STATUS_OFFSET: usize = 0x060;
const INTERRUPT_ACK_OFFSET: usize = 0x064;

pub const HANDSHAKE_FRAME_LEN: usize = 60;
pub const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
pub const HANDSHAKE_ETHERTYPE: u16 = 0x88b5;
const HELLO_PAYLOAD: &[u8] = b"VIBEOS-NET-HELLO-v1";
const CHALLENGE_PAYLOAD: &[u8] = b"VIBEOS-NET-CHALLENGE-v1";
const ACK_PAYLOAD: &[u8] = b"VIBEOS-NET-ACK-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    Offline,
    QueueFull,
    TimedOut,
    DriverCancelled,
    DriverFault,
    Protocol,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "network device is offline",
            Self::QueueFull => "network transmit queue is full",
            Self::TimedOut => "network transmit timed out",
            Self::DriverCancelled => "network driver was cancelled",
            Self::DriverFault => "network driver faulted",
            Self::Protocol => "network device returned a malformed completion",
            Self::Quarantined => "network DMA is quarantined after an unconfirmed reset",
            Self::AuthorityRevoked => "network capability is absent or revoked",
            Self::PermissionDenied => "network capability lacks the required right",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetInfo {
    pub online: bool,
    pub quarantined: bool,
    pub queue_size: u16,
    pub header_size: u32,
    pub accepted_features: u64,
    pub session_epoch: u64,
    pub irq: u32,
    pub used_interrupts: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub resets: u64,
    pub timeouts: u64,
    pub rx_inflight: u8,
    pub tx_inflight: u8,
}

/// Capability naming exactly one discovered 4 KiB MMIO transport window.
pub struct MmioWindow {
    transport: MmioTransport,
}

impl MmioWindow {
    fn new(transport: MmioTransport) -> Arc<Self> {
        Arc::new(Self { transport })
    }
}

impl Resource for MmioWindow {
    fn kind(&self) -> &'static str {
        "virtio-mmio"
    }

    fn describe(&self) -> String {
        format!(
            "modern network transport slot {} @ {:#x}, IRQ {}, vendor {:#x}",
            self.transport.slot(),
            self.transport.base(),
            self.transport.irq(),
            self.transport.vendor_id()
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Capability naming the one stable dual-queue DMA slab.
pub struct DmaRegion;

impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "dma-region"
    }

    fn describe(&self) -> String {
        format!(
            "SYSTEM stable net slab @ {:#x}, {} bytes, page aligned",
            dma_base(),
            DMA_BYTES
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Client-visible control and status authority. Packet transfer itself uses
/// the two directional `Endpoint<Packet>` capabilities.
pub struct NetDevice;

impl NetDevice {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }

    fn info(&self) -> NetInfo {
        let control = CONTROL.lock();
        NetInfo {
            online: control.online,
            quarantined: control.quarantined,
            queue_size: SPLIT_QUEUE_SIZE,
            header_size: NET_HEADER_SIZE,
            accepted_features: control.features.map_or(0, |features| features.accepted()),
            session_epoch: control.epoch,
            irq: control.transport.map_or(0, MmioTransport::irq),
            used_interrupts: USED_INTERRUPT_COUNT.load(Ordering::Acquire),
            rx_packets: RX_PACKET_COUNT.load(Ordering::Acquire),
            tx_packets: TX_PACKET_COUNT.load(Ordering::Acquire),
            resets: RESET_COUNT.load(Ordering::Acquire),
            timeouts: TIMEOUT_COUNT.load(Ordering::Acquire),
            rx_inflight: control.rx_inflight,
            tx_inflight: control.tx_inflight,
        }
    }
}

impl Resource for NetDevice {
    fn kind(&self) -> &'static str {
        "network-device"
    }

    fn describe(&self) -> String {
        let info = self.info();
        if info.quarantined {
            return String::from("virtio-net quarantined");
        }
        if !info.online {
            return String::from("virtio-net offline");
        }
        format!(
            "virtio-net [rx {}, tx {}, queue {}, epoch {}]",
            info.rx_packets, info.tx_packets, info.queue_size, info.session_epoch
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn info_with(lease: &InvocationLease<NetDevice>) -> Result<NetInfo, NetError> {
    if !lease.authorizes(Rights::READ) {
        return Err(NetError::PermissionDenied);
    }
    Ok(lease.with(NetDevice::info))
}

pub fn inject_fault_with(lease: &InvocationLease<NetDevice>) -> Result<(), NetError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(NetError::PermissionDenied);
    }
    lease.with(|_| FAULT_AFTER_PUBLISH.store(true, Ordering::Release));
    Ok(())
}

pub struct NetResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub control: Arc<NetDevice>,
}

/// Empty modern MMIO slots are not errors. No component or network caps are
/// created unless device ID 1 is present.
pub fn discover() -> Option<NetResources> {
    let transport = MmioTransport::scan_network()?;
    Some(NetResources {
        mmio: MmioWindow::new(transport),
        dma: Arc::new(DmaRegion),
        control: NetDevice::new(),
    })
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

// Safety: DMA_CLAIMED serializes CPU access. A device retains addresses only
// while the claim is held, and failure to confirm reset permanently retains it.
unsafe impl Sync for StableDma {}

#[link_section = ".dma"]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));
static DMA_CLAIMED: AtomicBool = AtomicBool::new(false);

struct DriverControl {
    transport: Option<MmioTransport>,
    features: Option<NegotiatedFeatures>,
    epoch: u64,
    online: bool,
    quarantined: bool,
    rx_inflight: u8,
    tx_inflight: u8,
}

struct DriverAuthority {
    mmio: Revocable<MmioWindow>,
    dma: Revocable<DmaRegion>,
    outbound: Revocable<Endpoint<Packet>>,
    inbound: Revocable<Endpoint<Packet>>,
    control: Revocable<NetDevice>,
}

static CONTROL: SpinLock<DriverControl> = SpinLock::new_recoverable(DriverControl {
    transport: None,
    features: None,
    epoch: 0,
    online: false,
    quarantined: false,
    rx_inflight: 0,
    tx_inflight: 0,
});
static AUTHORITY: SpinLock<Option<DriverAuthority>> = SpinLock::new_recoverable(None);
static IRQ_WAIT: WaitQueue = WaitQueue::new();
static IRQ_CAUSES: AtomicU32 = AtomicU32::new(0);
static USED_INTERRUPT_COUNT: AtomicU64 = AtomicU64::new(0);
static RX_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
static TX_PACKET_COUNT: AtomicU64 = AtomicU64::new(0);
static RESET_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());
static FAULT_AFTER_PUBLISH: AtomicBool = AtomicBool::new(false);

/// Run one network-driver incarnation after resolving all five explicit
/// grants. Each endpoint operation and every new hardware operation rechecks
/// the complete derivation, so revocation is effective at the next boundary.
pub async fn driver_task(
    space: &'static Space,
    mmio_cap: Cap,
    dma_cap: Cap,
    outbound_cap: Cap,
    inbound_cap: Cap,
    control_cap: Cap,
) {
    let authority = {
        let cspace = space.0.lock();
        match (
            cspace.lookup_revocable::<MmioWindow>(mmio_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<DmaRegion>(dma_cap, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<Endpoint<Packet>>(outbound_cap, Rights::RECV),
            cspace.lookup_revocable::<Endpoint<Packet>>(inbound_cap, Rights::SEND),
            cspace.lookup_revocable::<NetDevice>(control_cap, Rights::READ),
        ) {
            (Ok(mmio), Ok(dma), Ok(outbound), Ok(inbound), Ok(control)) => Some(DriverAuthority {
                mmio,
                dma,
                outbound,
                inbound,
                control,
            }),
            _ => None,
        }
    };
    let Some(authority) = authority else {
        return;
    };
    let Ok(transport) = authority.mmio.try_with(|window| window.transport) else {
        return;
    };
    let Some(mut session) = DriverSession::attach(transport, authority) else {
        return;
    };

    loop {
        match session.step() {
            Ok(true) => {}
            Ok(false) => wait_for_work().await,
            Err(NetError::AuthorityRevoked | NetError::Quarantined | NetError::Offline) => return,
            Err(_) => return,
        }
    }
}

struct DriverSession {
    transport: MmioTransport,
    model: NetDeviceModel,
    tx_deadlines: [u64; QUEUE_SLOTS],
    armed: bool,
}

impl DriverSession {
    fn attach(transport: MmioTransport, authority: DriverAuthority) -> Option<Self> {
        if CONTROL.lock().quarantined {
            return None;
        }
        if DMA_CLAIMED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        {
            let mut installed = AUTHORITY.lock();
            if installed.is_some() {
                DMA_CLAIMED.store(false, Ordering::Release);
                return None;
            }
            *installed = Some(authority);
        }

        let domain = crate::heap::current_domain();
        DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
        DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);
        clear_dma();

        let features = match initialize_transport(transport) {
            Ok(features) => features,
            Err(_) => {
                shutdown(transport, NetError::Offline);
                return None;
            }
        };
        let epoch = {
            let mut control = CONTROL.lock();
            let Some(epoch) = control.epoch.checked_add(1) else {
                drop(control);
                quarantine_identity_exhausted(transport);
                return None;
            };
            control.epoch = epoch;
            control.transport = Some(transport);
            control.features = Some(features);
            control.online = false;
            control.epoch
        };
        let mut session = Self {
            transport,
            model: NetDeviceModel::at_epoch(epoch).expect("driver epochs are non-zero"),
            tx_deadlines: [0; QUEUE_SLOTS],
            armed: true,
        };
        if session.post_all_receives().is_err() {
            shutdown(transport, NetError::Protocol);
            session.armed = false;
            return None;
        }

        let _ = plic::unregister(transport.irq());
        // Publish the probed base in the PLIC's atomic callback record. The
        // IRQ top half never locks CONTROL or a second transport snapshot.
        if plic::register(transport.irq(), irq_top_half, transport.base()).is_err()
            || plic::enable(transport.irq()).is_err()
        {
            shutdown(transport, NetError::DriverCancelled);
            session.armed = false;
            return None;
        }
        transport.add_status(virtio::STATUS_DRIVER_OK);
        transport.notify_queue(NET_RECEIVE_QUEUE);
        {
            let mut control = CONTROL.lock();
            control.online = true;
            control.rx_inflight = session.model.inflight(NetQueue::Receive);
            control.tx_inflight = session.model.inflight(NetQueue::Transmit);
        }
        Some(session)
    }

    fn step(&mut self) -> Result<bool, NetError> {
        let mut progressed = self.service_device_events()?;
        progressed |= self.drain_transmit_completions()?;
        progressed |= self.drain_receive_completions()?;
        progressed |= self.check_transmit_timeout()?;
        progressed |= self.publish_transmits()?;
        self.sync_control();
        Ok(progressed)
    }

    fn service_device_events(&mut self) -> Result<bool, NetError> {
        if !authority_live(self.transport) {
            return Err(NetError::AuthorityRevoked);
        }
        let causes = virtio::InterruptCauses::from_status(IRQ_CAUSES.swap(0, Ordering::AcqRel));
        let status = self.transport.status();
        let expected = virtio::STATUS_ACKNOWLEDGE
            | virtio::STATUS_DRIVER
            | virtio::STATUS_FEATURES_OK
            | virtio::STATUS_DRIVER_OK;
        if status & (virtio::STATUS_DEVICE_NEEDS_RESET | virtio::STATUS_FAILED) != 0
            || status & expected != expected
        {
            self.model.require_reset(NetResetReason::DeviceNeedsReset);
            self.reset_required_transport()?;
            return Ok(true);
        }
        Ok(!causes.is_empty())
    }

    fn drain_transmit_completions(&mut self) -> Result<bool, NetError> {
        let observed = read_used_index(NetQueue::Transmit);
        let mut progressed = false;
        let mut budget = QUEUE_SLOTS;
        while self.model.used_index(NetQueue::Transmit) != observed && budget != 0 {
            let slot = virtio::ring_slot(self.model.used_index(NetQueue::Transmit)) as usize;
            let used = read_used_element(NetQueue::Transmit, slot);
            match self.model.complete_transmit(observed, used) {
                Ok(completion) => {
                    self.tx_deadlines[completion.submission.token.head as usize] = 0;
                    TX_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
                    progressed = true;
                }
                Err(_) => {
                    self.reset_after_protocol_error()?;
                    return Ok(true);
                }
            }
            budget -= 1;
        }
        if self.model.used_index(NetQueue::Transmit) != observed {
            self.model
                .require_reset(NetResetReason::MalformedCompletion);
            self.reset_required_transport()?;
            return Ok(true);
        }
        Ok(progressed)
    }

    fn drain_receive_completions(&mut self) -> Result<bool, NetError> {
        let observed = read_used_index(NetQueue::Receive);
        let mut progressed = false;
        let mut reposted = false;
        let mut budget = QUEUE_SLOTS;
        while self.model.used_index(NetQueue::Receive) != observed && budget != 0 {
            if !inbound_has_space()? {
                break;
            }
            let slot = virtio::ring_slot(self.model.used_index(NetQueue::Receive)) as usize;
            let used = read_used_element(NetQueue::Receive, slot);
            let frame_length = match virtio::validate_net_receive_length(used.length()) {
                Ok(length) => length as usize,
                Err(_) => {
                    self.model
                        .require_reset(NetResetReason::MalformedCompletion);
                    self.reset_required_transport()?;
                    return Ok(true);
                }
            };
            let head = used.id();
            let header = if head < SPLIT_QUEUE_SIZE as u32 {
                VirtioNetHeader::from_bytes(read_receive_header(head as usize))
            } else {
                // The model rejects the ID before consulting this placeholder;
                // never use an untrusted ID for a DMA address calculation.
                VirtioNetHeader::transmit()
            };
            let completion = match self.model.complete_receive(observed, used, header) {
                Ok(completion) => completion,
                Err(_) => {
                    self.reset_required_transport()?;
                    return Ok(true);
                }
            };
            if completion.frame_length as usize != frame_length || frame_length == 0 {
                self.model
                    .require_reset(NetResetReason::MalformedCompletion);
                self.reset_required_transport()?;
                return Ok(true);
            }
            let frame = read_receive_frame(completion.submission.token.head as usize, frame_length);
            let packet =
                Packet::copy_from(&frame[..frame_length]).map_err(|_| NetError::Protocol)?;
            match send_inbound(packet) {
                Ok(()) => {
                    RX_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                Err(NetError::AuthorityRevoked) => return Err(NetError::AuthorityRevoked),
                // The sole producer checked capacity immediately above. If a
                // future policy adds another producer, bounded backpressure
                // may race this send; drop this already-consumed frame without
                // misclassifying ordinary pressure as a device protocol fault.
                Err(NetError::QueueFull) => {}
                Err(error) => return Err(error),
            }
            let submission = self.model.post_receive().map_err(|_| NetError::Protocol)?;
            publish_receive(submission)?;
            reposted = true;
            progressed = true;
            budget -= 1;
        }
        if reposted {
            self.transport.notify_queue(NET_RECEIVE_QUEUE);
        }
        Ok(progressed)
    }

    fn check_transmit_timeout(&mut self) -> Result<bool, NetError> {
        let now = crate::sbi::time();
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
                .map_err(|_| NetError::Protocol)?;
            TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
            self.reset_required_transport()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn publish_transmits(&mut self) -> Result<bool, NetError> {
        let mut published = false;
        while self.model.inflight(NetQueue::Transmit) < SPLIT_QUEUE_SIZE as u8 {
            let Some(packet) = take_outbound()? else {
                break;
            };
            let submission = self
                .model
                .submit_transmit(packet.len())
                .map_err(|_| NetError::QueueFull)?;
            publish_transmit(submission, &packet)?;
            self.tx_deadlines[submission.token.head as usize] = crate::sbi::time()
                .saturating_add(TX_TIMEOUT_MS.saturating_mul(exec::timebase_hz() / 1_000));
            published = true;
        }
        if published {
            self.transport.notify_queue(NET_TRANSMIT_QUEUE);
            if FAULT_AFTER_PUBLISH.swap(false, Ordering::AcqRel) {
                panic!("injected virtio-net fault after DMA publication");
            }
        }
        Ok(published)
    }

    fn post_all_receives(&mut self) -> Result<(), NetError> {
        for _ in 0..QUEUE_SLOTS {
            let submission = self.model.post_receive().map_err(|_| NetError::Protocol)?;
            publish_receive(submission)?;
        }
        Ok(())
    }

    fn reset_after_protocol_error(&mut self) -> Result<(), NetError> {
        if !matches!(self.model.state(), NetDeviceState::ResetRequired { .. }) {
            self.model
                .require_reset(NetResetReason::MalformedCompletion);
        }
        self.reset_required_transport()
    }

    fn reset_required_transport(&mut self) -> Result<(), NetError> {
        CONTROL.lock().online = false;
        let _ = plic::disable(self.transport.irq());
        if !self.transport.reset(RESET_POLL_BUDGET) {
            self.model.quarantine(NetResetReason::ResetFailed);
            self.quarantine();
            return Err(NetError::Quarantined);
        }
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        self.model
            .confirm_reset(0)
            .map_err(|_| NetError::Protocol)?;
        RESET_COUNT.fetch_add(1, Ordering::Relaxed);
        self.reinitialize_after_reset()
    }

    fn reinitialize_after_reset(&mut self) -> Result<(), NetError> {
        clear_dma();
        let initialized = initialize_transport(self.transport);
        if let Ok(features) = initialized {
            self.model.reinitialize().map_err(|_| NetError::Protocol)?;
            self.tx_deadlines = [0; QUEUE_SLOTS];
            self.post_all_receives()?;
            if plic::enable(self.transport.irq()).is_ok() {
                self.transport.add_status(virtio::STATUS_DRIVER_OK);
                self.transport.notify_queue(NET_RECEIVE_QUEUE);
                let mut control = CONTROL.lock();
                control.features = Some(features);
                control.epoch = self.model.epoch();
                control.online = true;
                control.rx_inflight = self.model.inflight(NetQueue::Receive);
                control.tx_inflight = 0;
                return Ok(());
            }
        }

        let _ = plic::disable(self.transport.irq());
        let reset = self.transport.reset(RESET_POLL_BUDGET);
        let _ = self.transport.acknowledge_interrupt();
        let _ = plic::unregister(self.transport.irq());
        IRQ_CAUSES.store(0, Ordering::Release);
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.rx_inflight = 0;
            control.tx_inflight = 0;
            if !reset {
                control.quarantined = true;
            }
        }
        *AUTHORITY.lock() = None;
        self.armed = false;
        if reset {
            clear_dma();
            DMA_CLAIMED.store(false, Ordering::Release);
            clear_driver_domain();
            Err(NetError::Offline)
        } else {
            Err(NetError::Quarantined)
        }
    }

    fn quarantine(&mut self) {
        let _ = plic::disable(self.transport.irq());
        let _ = plic::unregister(self.transport.irq());
        let _ = self.transport.acknowledge_interrupt();
        IRQ_CAUSES.store(0, Ordering::Release);
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.quarantined = true;
            control.rx_inflight = self.model.inflight(NetQueue::Receive);
            control.tx_inflight = self.model.inflight(NetQueue::Transmit);
        }
        *AUTHORITY.lock() = None;
        self.armed = false;
        // DMA_CLAIMED intentionally remains true after an unconfirmed reset.
    }

    fn sync_control(&self) {
        let mut control = CONTROL.lock();
        control.epoch = self.model.epoch();
        control.rx_inflight = self.model.inflight(NetQueue::Receive);
        control.tx_inflight = self.model.inflight(NetQueue::Transmit);
    }
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        if self.armed {
            self.model.require_reset(NetResetReason::Cancelled);
            shutdown(self.transport, NetError::DriverCancelled);
            self.armed = false;
        }
    }
}

fn initialize_transport(transport: MmioTransport) -> Result<NegotiatedFeatures, NetError> {
    if !transport.reset(RESET_POLL_BUDGET) {
        return Err(NetError::Quarantined);
    }
    let mut init = ModernInit::new();
    transport.set_status(init.acknowledge().map_err(|_| NetError::Protocol)?);
    transport.set_status(init.declare_driver().map_err(|_| NetError::Protocol)?);
    let features = init
        .select_net_features(transport.device_features())
        .map_err(|_| NetError::Protocol)?;
    if features.accepted() != VIRTIO_F_VERSION_1 {
        return Err(NetError::Protocol);
    }
    transport.set_driver_features(features.accepted());
    transport.set_status(init.set_features_ok().map_err(|_| NetError::Protocol)?);
    init.confirm_features(transport.status())
        .map_err(|_| NetError::Protocol)?;

    for queue in [NetQueue::Receive, NetQueue::Transmit] {
        transport.select_queue(queue.index());
        if transport.queue_ready() || transport.queue_num_max() < SPLIT_QUEUE_SIZE {
            return Err(NetError::Protocol);
        }
        let (descriptors, available, used) = queue_dma_addresses(queue);
        transport.configure_queue(SPLIT_QUEUE_SIZE, descriptors, available, used);
    }
    Ok(features)
}

fn shutdown(transport: MmioTransport, _reason: NetError) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    {
        let mut control = CONTROL.lock();
        control.online = false;
        control.rx_inflight = 0;
        control.tx_inflight = 0;
        if !reset {
            control.quarantined = true;
        }
    }
    *AUTHORITY.lock() = None;
    if reset {
        clear_dma();
        DMA_CLAIMED.store(false, Ordering::Release);
        clear_driver_domain();
    }
}

/// Token identity exhaustion is terminal even when status zero is confirmed:
/// no later incarnation can mint a distinct epoch, so retain the DMA claim as
/// an explicit fail-closed quarantine instead of wrapping or panicking.
fn quarantine_identity_exhausted(transport: MmioTransport) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    let reset = transport.reset(RESET_POLL_BUDGET);
    let _ = transport.acknowledge_interrupt();
    IRQ_CAUSES.store(0, Ordering::Release);
    if reset {
        clear_dma();
    }
    {
        let mut control = CONTROL.lock();
        control.online = false;
        control.quarantined = true;
        control.features = None;
        control.rx_inflight = 0;
        control.tx_inflight = 0;
    }
    *AUTHORITY.lock() = None;
    clear_driver_domain();
    // DMA_CLAIMED deliberately remains set forever for this exhausted device.
}

fn clear_driver_domain() {
    DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
    DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
}

fn authority_live(transport: MmioTransport) -> bool {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return false;
    };
    authority
        .mmio
        .try_with(|window| window.transport == transport)
        .is_ok_and(|same| same)
        && authority.dma.try_with(|_| ()).is_ok()
        && authority.outbound.try_with(|_| ()).is_ok()
        && authority.inbound.try_with(|_| ()).is_ok()
        && authority.control.try_with(|_| ()).is_ok()
}

fn take_outbound() -> Result<Option<Packet>, NetError> {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    authority
        .outbound
        .try_with(Endpoint::try_recv)
        .map_err(|_| NetError::AuthorityRevoked)
}

fn inbound_has_space() -> Result<bool, NetError> {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    authority
        .inbound
        .try_with(|endpoint| endpoint.stats().2 < QUEUE_SLOTS)
        .map_err(|_| NetError::AuthorityRevoked)
}

fn send_inbound(packet: Packet) -> Result<(), NetError> {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    authority
        .inbound
        .try_with(|endpoint| endpoint.try_send(packet))
        .map_err(|_| NetError::AuthorityRevoked)?
        .map_err(|_| NetError::QueueFull)
}

async fn wait_for_work() {
    let irq = IRQ_WAIT.wait();
    let timer = exec::sleep_ms(IDLE_POLL_MS);
    let mut irq = pin!(irq);
    let mut timer = pin!(timer);
    poll_fn(|cx| {
        if irq.as_mut().poll(cx).is_ready() || timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}

fn irq_top_half(transport_base: usize, _irq_entry: u64) {
    let causes = acknowledge_irq_transport(transport_base);
    if causes != 0 {
        if virtio::InterruptCauses::from_status(causes).used_buffer() {
            USED_INTERRUPT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        IRQ_CAUSES.fetch_or(causes, Ordering::Release);
        IRQ_WAIT.wake_all();
    }
}

/// Acknowledge the two architected virtio-mmio causes using the validated
/// transport base captured atomically alongside this callback in the PLIC.
/// No revocable task-owned object is touched by the IRQ top half.
fn acknowledge_irq_transport(transport_base: usize) -> u32 {
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

fn publish_receive(submission: NetSubmission) -> Result<(), NetError> {
    debug_assert_eq!(submission.operation, NetOperation::Receive);
    let head = submission.token.head as usize;
    if head >= QUEUE_SLOTS {
        return Err(NetError::Protocol);
    }
    clear_receive_buffer(head);
    prime_receive_header(head);
    let descriptor =
        virtio::build_net_descriptor(submission.operation, receive_buffer_address(head))
            .map_err(|_| NetError::Protocol)?;
    publish_descriptor(NetQueue::Receive, submission, descriptor);
    Ok(())
}

fn publish_transmit(submission: NetSubmission, packet: &Packet) -> Result<(), NetError> {
    let head = submission.token.head as usize;
    if head >= QUEUE_SLOTS {
        return Err(NetError::Protocol);
    }
    write_transmit_buffer(head, packet);
    let descriptor =
        virtio::build_net_descriptor(submission.operation, transmit_buffer_address(head))
            .map_err(|_| NetError::Protocol)?;
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
    // QEMU 11 keeps a 12-byte modern receive prefix even without MRG_RXBUF,
    // but its non-MRG path writes only the first 10 metadata bytes. Seed the
    // architected single-buffer value before publication so the untouched
    // `num_buffers` field remains canonical. The model still requires exactly
    // one buffer and rejects every nonzero offload flag after used.len has
    // proved that the complete 12-byte prefix belongs to this completion.
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

fn write_transmit_buffer(head: usize, packet: &Packet) {
    unsafe {
        let buffer = core::ptr::addr_of_mut!((*DMA.0.get()).transmit_buffers[head]);
        core::ptr::write_bytes(buffer.cast::<u8>(), 0, core::mem::size_of::<NetBuffer>());
        let header = VirtioNetHeader::transmit().to_bytes();
        let header_dst = core::ptr::addr_of_mut!((*buffer).header) as *mut u8;
        for (index, byte) in header.iter().copied().enumerate() {
            header_dst.add(index).write_volatile(byte);
        }
        let frame_dst = core::ptr::addr_of_mut!((*buffer).frame) as *mut u8;
        for (index, byte) in packet.as_bytes().iter().copied().enumerate() {
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

fn dma_base() -> usize {
    DMA.0.get() as usize
}

fn clear_dma() {
    unsafe {
        core::ptr::write_bytes(DMA.0.get().cast::<u8>(), 0, DMA_BYTES);
        dma_fence();
    }
}

#[inline]
fn dma_fence() {
    unsafe { core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags)) };
}

pub fn hello_packet() -> Packet {
    handshake_packet(PEER_MAC, GUEST_MAC, HELLO_PAYLOAD)
}

pub fn challenge_packet() -> Packet {
    handshake_packet(GUEST_MAC, PEER_MAC, CHALLENGE_PAYLOAD)
}

pub fn ack_packet() -> Packet {
    handshake_packet(PEER_MAC, GUEST_MAC, ACK_PAYLOAD)
}

pub fn is_challenge(packet: &Packet) -> bool {
    packet == &challenge_packet()
}

fn handshake_packet(destination: [u8; 6], source: [u8; 6], payload: &[u8]) -> Packet {
    let mut frame = [0u8; HANDSHAKE_FRAME_LEN];
    frame[..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&source);
    frame[12..14].copy_from_slice(&HANDSHAKE_ETHERTYPE.to_be_bytes());
    frame[14..14 + payload.len()].copy_from_slice(payload);
    Packet::copy_from(&frame).expect("the fixed handshake frame is valid")
}

/// Device-specific half of raw fault recovery. It runs before the generic
/// component arena is reclaimed and performs no allocation. Released handles
/// are SYSTEM-rooted and remain owned by the policy CSpace.
///
/// # Safety
/// The executor guarantees that every task in `domain` is detached forever.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    if DRIVER_OWNER.load(Ordering::Acquire) != domain.owner.get()
        || DRIVER_ARENA.load(Ordering::Acquire) != domain.arena.get()
    {
        return;
    }

    let _ = unsafe { CONTROL.recover_after_fault(domain) };
    let _ = unsafe { AUTHORITY.recover_after_fault(domain) };
    let transport = CONTROL.lock().transport;
    if let Some(transport) = transport {
        shutdown(transport, NetError::DriverFault);
    }
}

#[allow(dead_code)]
pub fn debug_waiter_count() -> usize {
    IRQ_WAIT.waiter_count()
}
