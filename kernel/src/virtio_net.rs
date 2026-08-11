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
use core::future::{poll_fn, Future};
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Poll;

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::exec::{self, WaitQueue};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{
    Endpoint, Packet, PacketSessionError, PacketSessionFence, PacketStamp, StampedPacket,
};
use crate::plic;
use crate::sync::SpinLock;
use crate::virtio::{self, NegotiatedFeatures, NET_HEADER_SIZE, SPLIT_QUEUE_SIZE};
use crate::virtio_mmio::MmioTransport;
use crate::world::Space;
use vibeos_driver_virtio_net::{Engine, HardwareError, ResetReason};

const TX_TIMEOUT_MS: u64 = 2_000;
const IDLE_POLL_MS: u64 = 1;
const QUEUE_SLOTS: usize = SPLIT_QUEUE_SIZE as usize;

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
    SessionBusy,
    SessionInactive,
    IdentityExhausted,
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
            Self::SessionBusy => "the previous packet session still has transmit work in flight",
            Self::SessionInactive => "no packet stack is bound to this device incarnation",
            Self::IdentityExhausted => "network packet-session identity space is exhausted",
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
    pub stack_generation: u64,
    pub irq: u32,
    pub used_interrupts: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub stale_ingress_drops: u64,
    pub stale_egress_drops: u64,
    pub stale_egress_device_epoch_drops: u64,
    pub stale_egress_stack_generation_drops: u64,
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
            vibeos_driver_virtio_net::dma_base(),
            vibeos_driver_virtio_net::dma_size()
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Client-visible control and status authority. Packet transfer itself uses
/// the two directional `Endpoint<StampedPacket>` capabilities.
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
            session_epoch: control.sessions.device_epoch(),
            stack_generation: control
                .sessions
                .active_stamp()
                .map_or(0, PacketStamp::stack_generation),
            irq: control.transport.map_or(0, MmioTransport::irq),
            used_interrupts: USED_INTERRUPT_COUNT.load(Ordering::Acquire),
            rx_packets: RX_PACKET_COUNT.load(Ordering::Acquire),
            tx_packets: TX_PACKET_COUNT.load(Ordering::Acquire),
            stale_ingress_drops: STALE_INGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_drops: STALE_EGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_device_epoch_drops: STALE_EGRESS_DEVICE_EPOCH_DROPS
                .load(Ordering::Acquire),
            stale_egress_stack_generation_drops: STALE_EGRESS_STACK_GENERATION_DROPS
                .load(Ordering::Acquire),
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

/// Establish a fresh packet-stack generation after all previously admitted
/// transmit work has completed. The caller needs explicit control INVOKE
/// authority; packet SEND/RECV alone cannot retarget the device session, and
/// INVOKE does not grant the diagnostic WRITE operation used to fault a driver.
pub fn bind_stack_with(lease: &InvocationLease<NetDevice>) -> Result<PacketStamp, NetError> {
    if !lease.authorizes(Rights::INVOKE) {
        return Err(NetError::PermissionDenied);
    }
    lease.with(|_| {
        let mut control = CONTROL.lock();
        if control.quarantined {
            return Err(NetError::Quarantined);
        }
        if !control.online {
            return Err(NetError::Offline);
        }
        let tx_inflight = usize::from(control.tx_inflight);
        control.active_stack_domain = None;
        match control.sessions.bind_stack(tx_inflight) {
            Ok(stamp) => {
                control.active_stack_domain = Some(crate::heap::current_domain());
                Ok(stamp)
            }
            Err(PacketSessionError::TransmitBusy { .. }) => Err(NetError::SessionBusy),
            Err(PacketSessionError::Inactive) => Err(NetError::SessionInactive),
            Err(
                PacketSessionError::DeviceEpochExhausted
                | PacketSessionError::StackGenerationExhausted,
            ) => {
                control.online = false;
                control.quarantined = true;
                Err(NetError::IdentityExhausted)
            }
            Err(PacketSessionError::StampMismatch(_)) => unreachable!(),
        }
    })
}

/// Capture two packets under the current stamp without publishing them. The
/// recovery test releases them only after a replacement device or stack binds,
/// making both stale-ingress and stale-egress rejection deterministic.
#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn stage_stale_packets_for_test() -> Result<(), NetError> {
    let control = CONTROL.lock();
    let stamp = control
        .sessions
        .active_stamp()
        .ok_or(NetError::SessionInactive)?;
    let packet = hello_packet();
    let mut staged = STAGED_FAULT_PACKETS.lock();
    if staged.is_some() {
        return Err(NetError::SessionBusy);
    }
    *staged = Some(StagedFaultPackets {
        inbound: Some(StampedPacket::new(packet.clone(), stamp)),
        outbound: Some(StampedPacket::new(packet, stamp)),
    });
    Ok(())
}

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn release_stale_packets_for_test() -> Result<bool, NetError> {
    let control = CONTROL.lock();
    let active = control
        .sessions
        .active_stamp()
        .ok_or(NetError::SessionInactive)?;
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    let mut staged = STAGED_FAULT_PACKETS.lock();
    let packets = staged.as_mut().ok_or(NetError::SessionInactive)?;
    let old_stamp = packets
        .inbound
        .as_ref()
        .or(packets.outbound.as_ref())
        .expect("an installed stale-packet probe retains at least one frame")
        .stamp();
    if active == old_stamp {
        return Err(NetError::SessionBusy);
    }

    let mut progressed = false;
    if let Some(packet) = packets.inbound.as_ref() {
        match authority
            .inbound
            .try_with(|endpoint| endpoint.try_send(packet.clone()))
            .map_err(|_| NetError::AuthorityRevoked)?
        {
            Ok(()) => {
                packets.inbound = None;
                progressed = true;
            }
            Err(_) => {}
        }
    }
    if let Some(packet) = packets.outbound.as_ref() {
        match authority
            .outbound
            .try_with(|endpoint| endpoint.try_send(packet.clone()))
            .map_err(|_| NetError::AuthorityRevoked)?
        {
            Ok(()) => {
                packets.outbound = None;
                progressed = true;
            }
            Err(_) => {}
        }
    }

    let complete = packets.inbound.is_none() && packets.outbound.is_none();
    if complete {
        *staged = None;
        Ok(true)
    } else if progressed {
        Ok(false)
    } else {
        Err(NetError::QueueFull)
    }
}

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn packet_session_test_info() -> (u64, u64, u64, u64) {
    let control = CONTROL.lock();
    (
        control.sessions.device_epoch(),
        control
            .sessions
            .active_stamp()
            .map_or(0, PacketStamp::stack_generation),
        STALE_EGRESS_DEVICE_EPOCH_DROPS.load(Ordering::Acquire),
        STALE_EGRESS_STACK_GENERATION_DROPS.load(Ordering::Acquire),
    )
}

#[cfg(feature = "tcp-echo-recovery-test")]
pub(crate) fn request_driver_fault_for_test() {
    DRIVER_FAULT_REQUESTED.store(true, Ordering::Release);
}

pub struct NetResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub control: Arc<NetDevice>,
}

/// Empty modern MMIO slots are not errors. No component or network caps are
/// created unless device ID 1 is present.
pub fn discover() -> Option<NetResources> {
    // Safety: the selected BSP maps this trusted VirtIO MMIO aperture into
    // the kernel's identity address space before device discovery begins.
    let transport = unsafe { MmioTransport::scan_network(crate::platform::VIRTIO_MMIO) }?;
    Some(NetResources {
        mmio: MmioWindow::new(transport),
        dma: Arc::new(DmaRegion),
        control: NetDevice::new(),
    })
}

struct DriverControl {
    transport: Option<MmioTransport>,
    features: Option<NegotiatedFeatures>,
    sessions: PacketSessionFence,
    active_stack_domain: Option<AllocationDomain>,
    online: bool,
    quarantined: bool,
    rx_inflight: u8,
    tx_inflight: u8,
}

struct DriverAuthority {
    mmio: Revocable<MmioWindow>,
    dma: Revocable<DmaRegion>,
    outbound: Revocable<Endpoint<StampedPacket>>,
    inbound: Revocable<Endpoint<StampedPacket>>,
    control: Revocable<NetDevice>,
}

static CONTROL: SpinLock<DriverControl> = SpinLock::new_recoverable(DriverControl {
    transport: None,
    features: None,
    sessions: PacketSessionFence::new(),
    active_stack_domain: None,
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
static STALE_INGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DEVICE_EPOCH_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_STACK_GENERATION_DROPS: AtomicU64 = AtomicU64::new(0);
static RESET_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_COUNT: AtomicU64 = AtomicU64::new(0);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());
static FAULT_AFTER_PUBLISH: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tcp-echo-recovery-test")]
static DRIVER_FAULT_REQUESTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "tcp-echo-recovery-test")]
struct StagedFaultPackets {
    inbound: Option<StampedPacket>,
    outbound: Option<StampedPacket>,
}
#[cfg(feature = "tcp-echo-recovery-test")]
static STAGED_FAULT_PACKETS: SpinLock<Option<StagedFaultPackets>> = SpinLock::new(None);

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
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(outbound_cap, Rights::RECV),
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(inbound_cap, Rights::SEND),
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
        #[cfg(feature = "tcp-echo-recovery-test")]
        if DRIVER_FAULT_REQUESTED.swap(false, Ordering::AcqRel) {
            panic!("injected virtio-net fault with a live TCP stream");
        }
        match session.step() {
            Ok(true) => {}
            Ok(false) => wait_for_work().await,
            Err(NetError::AuthorityRevoked | NetError::Quarantined | NetError::Offline) => return,
            Err(_) => return,
        }
    }
}

struct DriverSession {
    engine: Engine,
}

impl DriverSession {
    fn attach(transport: MmioTransport, authority: DriverAuthority) -> Option<Self> {
        if CONTROL.lock().quarantined || vibeos_driver_virtio_net::dma_quarantined() {
            return None;
        }
        {
            let mut installed = AUTHORITY.lock();
            if installed.is_some() {
                return None;
            }
            *installed = Some(authority);
        }

        let domain = crate::heap::current_domain();
        DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
        DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);
        let epoch = {
            let mut control = CONTROL.lock();
            let epoch = match control.sessions.attach_device() {
                Ok(epoch) => epoch,
                Err(_) => {
                    drop(control);
                    quarantine_identity_exhausted(transport);
                    return None;
                }
            };
            control.active_stack_domain = None;
            control.transport = Some(transport);
            control.online = false;
            epoch
        };
        let engine = match Engine::attach(transport, epoch) {
            Ok(engine) => engine,
            Err(_) => {
                let mut control = CONTROL.lock();
                control.sessions.detach_device();
                control.quarantined = vibeos_driver_virtio_net::dma_quarantined();
                *AUTHORITY.lock() = None;
                clear_driver_domain();
                return None;
            }
        };
        let mut session = Self { engine };

        let _ = plic::unregister(transport.irq());
        // Publish the probed base in the PLIC's atomic callback record. The
        // IRQ top half never locks CONTROL or a task-owned driver object.
        if plic::register(transport.irq(), irq_top_half, transport.base()).is_err()
            || plic::enable(transport.irq()).is_err()
        {
            session.shutdown(NetError::DriverCancelled);
            return None;
        }
        if session.engine.start().is_err() {
            session.shutdown(NetError::DriverCancelled);
            return None;
        }
        {
            let info = session.engine.info();
            let mut control = CONTROL.lock();
            control.features = Some(session.engine_features());
            control.online = true;
            control.rx_inflight = info.rx_inflight;
            control.tx_inflight = info.tx_inflight;
        }
        Some(session)
    }

    fn engine_features(&self) -> NegotiatedFeatures {
        // The core feature token is intentionally opaque to policy. Re-run
        // the pure negotiation over the engine's accepted bitset.
        virtio::negotiate_net_features(self.engine.info().accepted_features)
            .expect("an attached engine negotiated VERSION_1")
    }

    fn step(&mut self) -> Result<bool, NetError> {
        if !authority_live(self.engine.transport()) {
            return Err(NetError::AuthorityRevoked);
        }
        let causes = IRQ_CAUSES.swap(0, Ordering::AcqRel);
        let mut progressed = match self.engine.service_device_events(causes) {
            Ok(progressed) => progressed,
            Err(error) => {
                self.reset(map_reset_reason(error))?;
                return Ok(true);
            }
        };
        match self.engine.drain_transmit_completions() {
            Ok(count) => {
                if count != 0 {
                    TX_PACKET_COUNT.fetch_add(u64::from(count), Ordering::Relaxed);
                    progressed = true;
                }
            }
            Err(error) => {
                self.reset(map_reset_reason(error))?;
                return Ok(true);
            }
        }
        progressed |= self.drain_receive_completions()?;
        if let Err(error) = self.engine.check_timeout(crate::sbi::time()) {
            TIMEOUT_COUNT.fetch_add(1, Ordering::Relaxed);
            self.reset(map_reset_reason(error))?;
            return Ok(true);
        }
        progressed |= self.publish_transmits()?;
        self.sync_control();
        Ok(progressed)
    }

    fn drain_receive_completions(&mut self) -> Result<bool, NetError> {
        // CONTROL remains the rebind barrier across hardware completion,
        // packet stamping, and endpoint publication.
        let control = CONTROL.lock();
        let mut progressed = false;
        for _ in 0..QUEUE_SLOTS {
            if !inbound_has_space()? {
                break;
            }
            let frame = match self.engine.receive() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(error) => {
                    drop(control);
                    self.reset(map_reset_reason(error))?;
                    return Ok(true);
                }
            };
            let packet = Packet::copy_from(frame.as_bytes()).map_err(|_| NetError::Protocol)?;
            match send_inbound(&control, packet) {
                Ok(true) => {
                    RX_PACKET_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                Ok(false) => {}
                Err(NetError::AuthorityRevoked) => return Err(NetError::AuthorityRevoked),
                Err(NetError::QueueFull) => {}
                Err(error) => return Err(error),
            }
            progressed = true;
        }
        Ok(progressed)
    }

    fn publish_transmits(&mut self) -> Result<bool, NetError> {
        let mut published = false;
        let mut control = CONTROL.lock();
        while self.engine.info().tx_inflight < SPLIT_QUEUE_SIZE as u8 {
            let Some(packet) = take_admitted_outbound(&mut control)? else {
                break;
            };
            let deadline = crate::sbi::time()
                .saturating_add(TX_TIMEOUT_MS.saturating_mul(exec::timebase_hz() / 1_000));
            self.engine
                .submit_transmit(packet.as_bytes(), deadline)
                .map_err(map_hardware_error)?;
            control.tx_inflight = self.engine.info().tx_inflight;
            published = true;
        }
        drop(control);
        if published && FAULT_AFTER_PUBLISH.swap(false, Ordering::AcqRel) {
            panic!("injected virtio-net fault after DMA publication");
        }
        Ok(published)
    }

    fn reset(&mut self, reason: ResetReason) -> Result<(), NetError> {
        let transport = self.engine.transport();
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.sessions.detach_device();
            control.active_stack_domain = None;
        }
        let _ = plic::disable(transport.irq());
        IRQ_CAUSES.store(0, Ordering::Release);
        let epoch = match self.engine.reset_and_reinitialize(reason) {
            Ok(epoch) => epoch,
            Err(HardwareError::Quarantined | HardwareError::IdentityExhausted) => {
                self.quarantine();
                return Err(NetError::Quarantined);
            }
            Err(error) => return Err(map_hardware_error(error)),
        };
        RESET_COUNT.fetch_add(1, Ordering::Relaxed);
        if plic::enable(transport.irq()).is_err() {
            self.shutdown(NetError::DriverCancelled);
            return Err(NetError::Offline);
        }
        let mut control = CONTROL.lock();
        let session_epoch = control.sessions.attach_device().map_err(|_| {
            self.engine.force_quarantine();
            control.quarantined = true;
            NetError::IdentityExhausted
        })?;
        control.active_stack_domain = None;
        if session_epoch != epoch {
            control.sessions.detach_device();
            self.engine.force_quarantine();
            control.quarantined = true;
            return Err(NetError::Protocol);
        }
        let info = self.engine.info();
        control.features = Some(self.engine_features());
        control.online = true;
        control.rx_inflight = info.rx_inflight;
        control.tx_inflight = info.tx_inflight;
        Ok(())
    }

    fn quarantine(&mut self) {
        let transport = self.engine.transport();
        let _ = plic::disable(transport.irq());
        let _ = plic::unregister(transport.irq());
        IRQ_CAUSES.store(0, Ordering::Release);
        self.engine.force_quarantine();
        let info = self.engine.info();
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.quarantined = true;
            control.sessions.detach_device();
            control.active_stack_domain = None;
            control.rx_inflight = info.rx_inflight;
            control.tx_inflight = info.tx_inflight;
        }
        *AUTHORITY.lock() = None;
    }

    fn shutdown(&mut self, _reason: NetError) {
        let transport = self.engine.transport();
        let _ = plic::disable(transport.irq());
        let _ = plic::unregister(transport.irq());
        let reset = self.engine.shutdown(ResetReason::Cancelled);
        IRQ_CAUSES.store(0, Ordering::Release);
        {
            let mut control = CONTROL.lock();
            control.online = false;
            control.sessions.detach_device();
            control.active_stack_domain = None;
            control.rx_inflight = 0;
            control.tx_inflight = 0;
            if !reset {
                control.quarantined = true;
            }
        }
        *AUTHORITY.lock() = None;
        if reset {
            clear_driver_domain();
        }
    }

    fn sync_control(&self) {
        let info = self.engine.info();
        let mut control = CONTROL.lock();
        control.rx_inflight = info.rx_inflight;
        control.tx_inflight = info.tx_inflight;
    }
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        self.shutdown(NetError::DriverCancelled);
    }
}

fn map_hardware_error(error: HardwareError) -> NetError {
    match error {
        HardwareError::Offline => NetError::Offline,
        HardwareError::QueueFull => NetError::QueueFull,
        HardwareError::TimedOut => NetError::TimedOut,
        HardwareError::Protocol => NetError::Protocol,
        HardwareError::Quarantined => NetError::Quarantined,
        HardwareError::IdentityExhausted => NetError::IdentityExhausted,
    }
}

fn map_reset_reason(error: HardwareError) -> ResetReason {
    match error {
        HardwareError::TimedOut => ResetReason::Timeout,
        HardwareError::Protocol | HardwareError::QueueFull => ResetReason::Protocol,
        HardwareError::Offline => ResetReason::Device,
        HardwareError::Quarantined | HardwareError::IdentityExhausted => ResetReason::Cancelled,
    }
}

fn quarantine_identity_exhausted(transport: MmioTransport) {
    let _ = plic::disable(transport.irq());
    let _ = plic::unregister(transport.irq());
    vibeos_driver_virtio_net::quarantine_before_attach(transport);
    IRQ_CAUSES.store(0, Ordering::Release);
    {
        let mut control = CONTROL.lock();
        control.online = false;
        control.quarantined = true;
        control.sessions.detach_device();
        control.active_stack_domain = None;
        control.features = None;
        control.rx_inflight = 0;
        control.tx_inflight = 0;
    }
    *AUTHORITY.lock() = None;
    clear_driver_domain();
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

fn take_outbound() -> Result<Option<StampedPacket>, NetError> {
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    authority
        .outbound
        .try_with(Endpoint::try_recv)
        .map_err(|_| NetError::AuthorityRevoked)
}

fn take_admitted_outbound(control: &mut DriverControl) -> Result<Option<Packet>, NetError> {
    for _ in 0..QUEUE_SLOTS {
        let Some(packet) = take_outbound()? else {
            return Ok(None);
        };
        match control.sessions.accept_egress(packet) {
            Ok(packet) => return Ok(Some(packet)),
            Err(PacketSessionError::Inactive) => {
                STALE_EGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
            }
            Err(PacketSessionError::StampMismatch(mismatch)) => {
                STALE_EGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
                if mismatch.device_epoch_changed() {
                    STALE_EGRESS_DEVICE_EPOCH_DROPS.fetch_add(1, Ordering::Relaxed);
                } else if mismatch.stack_generation_changed() {
                    STALE_EGRESS_STACK_GENERATION_DROPS.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(
                PacketSessionError::DeviceEpochExhausted
                | PacketSessionError::StackGenerationExhausted
                | PacketSessionError::TransmitBusy { .. },
            ) => unreachable!(),
        }
    }
    Ok(None)
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

fn send_inbound(control: &DriverControl, packet: Packet) -> Result<bool, NetError> {
    let packet = match control.sessions.stamp_ingress(packet) {
        Ok(packet) => packet,
        Err(PacketSessionError::Inactive) => {
            STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        Err(_) => unreachable!(),
    };
    let authority = AUTHORITY.lock();
    let Some(authority) = authority.as_ref() else {
        return Err(NetError::AuthorityRevoked);
    };
    authority
        .inbound
        .try_with(|endpoint| endpoint.try_send(packet))
        .map_err(|_| NetError::AuthorityRevoked)?
        .map_err(|_| NetError::QueueFull)?;
    // Keep CONTROL held through endpoint publication so a successful rebind
    // cannot be followed by a late frame stamped for the retired session.
    Ok(true)
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
    // Safety: PLIC registration captures the base from a successfully probed
    // transport and unregisters the callback before transport retirement.
    unsafe { vibeos_driver_virtio_net::acknowledge_irq_at_base(transport_base) }
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
    // A stack client may fault while it owns the stable control lock. Recover
    // only an exact abandoned guard, then retire its packet route before the
    // executor publishes Faulted or a supervisor can start a replacement.
    let _ = unsafe { CONTROL.recover_after_fault(domain) };
    {
        let mut control = CONTROL.lock();
        if control.active_stack_domain == Some(domain) {
            control.sessions.unbind_stack();
            control.active_stack_domain = None;
        }
    }
    if DRIVER_OWNER.load(Ordering::Acquire) != domain.owner.get()
        || DRIVER_ARENA.load(Ordering::Acquire) != domain.arena.get()
    {
        return;
    }

    let _ = unsafe { AUTHORITY.recover_after_fault(domain) };
    let transport = CONTROL.lock().transport;
    if let Some(transport) = transport {
        let _ = plic::disable(transport.irq());
        let _ = plic::unregister(transport.irq());
        // Safety: the executor contract above permanently detaches every task
        // in this exact owner/arena incarnation. PLIC delivery is detached
        // before the hardware crate clears DMA or releases its global claim;
        // the abandoned DriverSession can therefore never run or Drop later.
        let reset = unsafe { vibeos_driver_virtio_net::recover_faulted_transport(transport) };
        IRQ_CAUSES.store(0, Ordering::Release);
        let mut control = CONTROL.lock();
        control.online = false;
        control.sessions.detach_device();
        control.active_stack_domain = None;
        control.rx_inflight = 0;
        control.tx_inflight = 0;
        control.quarantined = !reset;
        *AUTHORITY.lock() = None;
        if reset {
            clear_driver_domain();
        }
    }
}

#[allow(dead_code)]
pub fn debug_waiter_count() -> usize {
    IRQ_WAIT.waiter_count()
}
