//! Polling CV1800B DWMAC backend for the Milk-V Duo Ethernet IO Board.
//!
//! The minimal profile uses one normal RX descriptor and one normal TX
//! descriptor. Each descriptor occupies its own non-coherent cache line even
//! though the device consumes only the first four words. Packet transport
//! remains the same bounded, capability-addressed raw-L2 interface used by the
//! QEMU virtio-net backend.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use vibeos_driver_dwmac_net::{Engine, Error as HardwareError};

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{
    Endpoint, MAX_PACKET_LEN, Packet, PacketSessionError, PacketSessionFence, PacketStamp,
    StampedPacket,
};
use crate::sync::SpinLock;
use crate::world::Space;

const TX_TIMEOUT_MS: u64 = 2_000;

const DWMAC: vibeos_hal::DwmacDescription = crate::platform::DWMAC;
const IRQ: u32 = DWMAC.irq;

pub const HANDSHAKE_FRAME_LEN: usize = 60;
pub const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const PEER_DESTINATION_MAC: [u8; 6] = [0xff; 6];
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
            Self::Offline => "Ethernet device is offline",
            Self::QueueFull => "Ethernet packet queue is full",
            Self::TimedOut => "Ethernet operation timed out",
            Self::DriverCancelled => "Ethernet driver was cancelled",
            Self::DriverFault => "Ethernet driver faulted",
            Self::Protocol => "Ethernet descriptor was malformed",
            Self::Quarantined => "Ethernet DMA is quarantined",
            Self::AuthorityRevoked => "Ethernet capability is absent or revoked",
            Self::PermissionDenied => "Ethernet capability lacks the required right",
            Self::SessionBusy => "the previous packet session still has transmit work in flight",
            Self::SessionInactive => "no packet stack is bound to this Ethernet incarnation",
            Self::IdentityExhausted => "Ethernet packet-session identity space is exhausted",
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
    pub phy_link_up: bool,
    pub tx_descriptor_status: u32,
    pub dma_status: u32,
    pub clock_enable: u32,
    pub clock_bypass: u32,
    pub clock_divider: u32,
    pub ephy_control: u32,
}

pub struct MmioWindow;
impl Resource for MmioWindow {
    fn kind(&self) -> &'static str {
        "cv1800b-dwmac-mmio"
    }
    fn describe(&self) -> String {
        format!(
            "CV1800B DWMAC @ {:#x}, IRQ {IRQ}, RMII",
            DWMAC.registers.start
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct DmaRegion;
impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "dma-region"
    }
    fn describe(&self) -> String {
        format!(
            "DWMAC stable cache-isolated two-descriptor slab @ {:#x}",
            vibeos_driver_dwmac_net::dma_region_base()
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct NetDevice;
impl NetDevice {
    fn info(&self) -> NetInfo {
        let state = CONTROL.lock();
        // SAFETY: the Milk-V BSP maps all DWMAC, clock, ePHY, and eFuse
        // apertures for the firmware lifetime. CONTROL serializes this
        // diagnostic snapshot with kernel packet-engine operations; the
        // selected status registers are non-destructive reads.
        let hardware = unsafe { vibeos_driver_dwmac_net::telemetry(DWMAC) };
        NetInfo {
            online: state.online,
            quarantined: state.quarantined,
            queue_size: 1,
            header_size: 0,
            accepted_features: 0,
            session_epoch: state.sessions.device_epoch(),
            stack_generation: state
                .sessions
                .active_stamp()
                .map_or(0, PacketStamp::stack_generation),
            irq: IRQ,
            used_interrupts: 0,
            rx_packets: hardware.rx_packets,
            tx_packets: hardware.tx_packets,
            stale_ingress_drops: STALE_INGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_drops: STALE_EGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_device_epoch_drops: STALE_EGRESS_DEVICE_EPOCH_DROPS
                .load(Ordering::Acquire),
            stale_egress_stack_generation_drops: STALE_EGRESS_STACK_GENERATION_DROPS
                .load(Ordering::Acquire),
            resets: hardware.resets,
            timeouts: TIMEOUTS.load(Ordering::Acquire),
            rx_inflight: u8::from(state.online),
            tx_inflight: u8::from(state.tx_inflight),
            phy_link_up: hardware.phy_link_up,
            tx_descriptor_status: hardware.tx_descriptor_status,
            dma_status: hardware.dma_status,
            clock_enable: hardware.clock_enable,
            clock_bypass: hardware.clock_bypass,
            clock_divider: hardware.clock_divider,
            ephy_control: hardware.ephy_control,
        }
    }
}
impl Resource for NetDevice {
    fn kind(&self) -> &'static str {
        "network-device"
    }
    fn describe(&self) -> String {
        let info = self.info();
        format!(
            "CV1800B DWMAC [online {}, rx {}, tx {}, epoch {}]",
            info.online, info.rx_packets, info.tx_packets, info.session_epoch
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct NetResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub control: Arc<NetDevice>,
}

pub fn discover() -> Option<NetResources> {
    Some(NetResources {
        mmio: Arc::new(MmioWindow),
        dma: Arc::new(DmaRegion),
        control: Arc::new(NetDevice),
    })
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
    lease.with(|_| FAULT.store(true, Ordering::Release));
    Ok(())
}

pub fn bind_stack_with(lease: &InvocationLease<NetDevice>) -> Result<PacketStamp, NetError> {
    if !lease.authorizes(Rights::INVOKE) {
        return Err(NetError::PermissionDenied);
    }
    lease.with(|_| {
        let mut state = CONTROL.lock();
        if state.quarantined {
            return Err(NetError::Quarantined);
        }
        if !state.online {
            return Err(NetError::Offline);
        }
        let tx_inflight = usize::from(state.tx_inflight);
        state.active_stack_domain = None;
        match state.sessions.bind_stack(tx_inflight) {
            Ok(stamp) => {
                state.active_stack_domain = Some(crate::heap::current_domain());
                Ok(stamp)
            }
            Err(PacketSessionError::TransmitBusy { .. }) => Err(NetError::SessionBusy),
            Err(PacketSessionError::Inactive) => Err(NetError::SessionInactive),
            Err(
                PacketSessionError::DeviceEpochExhausted
                | PacketSessionError::StackGenerationExhausted,
            ) => {
                state.online = false;
                state.quarantined = true;
                Err(NetError::IdentityExhausted)
            }
            Err(PacketSessionError::StampMismatch(_)) => unreachable!(),
        }
    })
}

struct Control {
    online: bool,
    quarantined: bool,
    sessions: PacketSessionFence,
    active_stack_domain: Option<AllocationDomain>,
    tx_inflight: bool,
}
static CONTROL: SpinLock<Control> = SpinLock::new_recoverable(Control {
    online: false,
    quarantined: false,
    sessions: PacketSessionFence::new(),
    active_stack_domain: None,
    tx_inflight: false,
});
static STALE_INGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DEVICE_EPOCH_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_STACK_GENERATION_DROPS: AtomicU64 = AtomicU64::new(0);
static TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static FAULT: AtomicBool = AtomicBool::new(false);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());

pub async fn driver_task(
    space: &'static Space,
    mmio: Cap,
    dma: Cap,
    outbound: Cap,
    inbound: Cap,
    control: Cap,
) {
    let authority = {
        let cspace = space.0.lock();
        (
            cspace.lookup_revocable::<MmioWindow>(mmio, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<DmaRegion>(dma, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::RECV),
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::SEND),
            cspace.lookup_revocable::<NetDevice>(control, Rights::READ),
        )
    };
    let (Ok(mmio), Ok(dma), Ok(outbound), Ok(inbound), Ok(control)) = authority else {
        return;
    };

    let domain = crate::heap::current_domain();
    DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
    DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);

    let engine = match with_device_authority(&mmio, &dma, &control, || {
        // SAFETY: the retained and currently live capabilities authorize the
        // identity-mapped BSP apertures and crate-owned `.dma` slab. The
        // firmware linker keeps that slab physically contiguous and below the
        // board's 32-bit DMA limit for this engine's lifetime.
        unsafe {
            Engine::claim(
                DWMAC,
                GUEST_MAC,
                crate::sbi::time,
                crate::exec::timebase_hz(),
            )
        }
        .map_err(|_| NetError::DriverFault)
    }) {
        Ok(engine) => engine,
        Err(_) => {
            shutdown_driver_policy(false);
            return;
        }
    };

    if with_device_authority(&mmio, &dma, &control, || {
        let mut state = CONTROL.lock();
        if state.sessions.attach_device().is_err() {
            state.online = false;
            state.quarantined = true;
            return Err(NetError::IdentityExhausted);
        }
        state.active_stack_domain = None;
        state.tx_inflight = false;
        state.online = true;
        state.quarantined = false;
        Ok(())
    })
    .is_err()
    {
        let reset = engine.shutdown();
        shutdown_driver_policy(reset);
        return;
    }
    let mut session = DriverSession {
        engine: Some(engine),
    };

    let mut pending_tx = None;
    let mut tx_deadline = 0;
    let mut link_poll = 0u16;
    loop {
        if FAULT.swap(false, Ordering::AcqRel) {
            panic!("injected CV1800B DWMAC fault");
        }
        if with_device_authority(&mmio, &dma, &control, || {
            driver_turn(
                session.engine_mut(),
                &outbound,
                &inbound,
                &mut pending_tx,
                &mut tx_deadline,
                &mut link_poll,
            )
        })
        .is_err()
        {
            return;
        }
        crate::exec::sleep_ms(1).await;
    }
}

struct DriverSession {
    engine: Option<Engine>,
}

impl DriverSession {
    fn engine_mut(&mut self) -> &mut Engine {
        self.engine.as_mut().expect("live DWMAC driver session")
    }
}

impl Drop for DriverSession {
    fn drop(&mut self) {
        let reset = self
            .engine
            .take()
            .map_or(true, vibeos_driver_dwmac_net::Engine::shutdown);
        shutdown_driver_policy(reset);
    }
}

fn with_device_authority<R>(
    mmio: &Revocable<MmioWindow>,
    dma: &Revocable<DmaRegion>,
    control: &Revocable<NetDevice>,
    operation: impl FnOnce() -> Result<R, NetError>,
) -> Result<R, NetError> {
    match mmio.try_with(|_| dma.try_with(|_| control.try_with(|_| operation()))) {
        Ok(Ok(Ok(result))) => result,
        _ => Err(NetError::AuthorityRevoked),
    }
}

fn driver_turn(
    engine: &mut Engine,
    outbound: &Revocable<Endpoint<StampedPacket>>,
    inbound: &Revocable<Endpoint<StampedPacket>>,
    pending_tx: &mut Option<Packet>,
    tx_deadline: &mut u64,
    link_poll: &mut u16,
) -> Result<(), NetError> {
    // Once a packet leaves the bounded endpoint, this task owns it until the
    // sole TX descriptor accepts it. Descriptor ownership is ordinary
    // backpressure until the bounded hardware deadline: retain the packet and
    // do not dequeue a second one while DMA is using the descriptor.
    {
        // Binding and DMA publication share CONTROL. Marking the pending/raw
        // descriptor reservation before releasing this guard prevents a new
        // generation from becoming active between stamp validation and OWN.
        let mut state = CONTROL.lock();
        let now = crate::sbi::time();
        let descriptor_busy = engine.tx_owned();
        state.tx_inflight = descriptor_busy || pending_tx.is_some();
        if descriptor_busy {
            // The deadline covers DMA ownership after publication as well as
            // software waiting to publish. A corrupted or stalled OWN bit must
            // restart the supervised driver instead of wedging TX forever.
            if *tx_deadline == 0 {
                *tx_deadline = now.saturating_add(tx_timeout_ticks());
            } else if now >= *tx_deadline {
                TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                panic!("CV1800B DWMAC TX descriptor timed out");
            }
        } else if pending_tx.is_none() {
            *tx_deadline = 0;
            if let Some(packet) = take_admitted_outbound(outbound, &state.sessions)? {
                *pending_tx = Some(packet);
                *tx_deadline = now.saturating_add(tx_timeout_ticks());
                state.tx_inflight = true;
            }
        }
        if let Some(packet) = pending_tx.as_ref() {
            match engine.transmit(packet.as_bytes()) {
                Ok(()) => {
                    *pending_tx = None;
                    state.tx_inflight = true;
                }
                Err(HardwareError::QueueFull) if now < *tx_deadline => {}
                Err(HardwareError::QueueFull) => {
                    TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                    panic!("CV1800B DWMAC TX descriptor timed out");
                }
                Err(HardwareError::PacketTooLarge) => {
                    // A safely constructed Packet always fits the DMA buffer.
                    state.online = false;
                    return Err(NetError::Protocol);
                }
                Err(_) => return Err(NetError::DriverFault),
            }
        }

        // Keep the same rebind barrier from descriptor consumption through
        // exact session stamping, endpoint publication, and RX rearm. A stack
        // restart cannot relabel a raw frame after the driver consumes it.
        let mut frame = [0u8; MAX_PACKET_LEN];
        if let Some(length) = engine.receive(&mut frame) {
            let packet = Packet::copy_from(&frame[..length]).expect("DWMAC bounded receive");
            match send_inbound(inbound, &state.sessions, packet) {
                Ok(()) => {}
                // RX has already consumed and rearmed its sole descriptor, so
                // bounded client pressure drops this one frame.
                Err(NetError::QueueFull) => {}
                Err(error) => return Err(error),
            }
        }
    }
    *link_poll = link_poll.wrapping_add(1);
    if *link_poll >= 1_000 {
        *link_poll = 0;
        engine.poll_link();
    }
    Ok(())
}

fn tx_timeout_ticks() -> u64 {
    TX_TIMEOUT_MS.saturating_mul(crate::exec::timebase_hz()) / 1_000
}

fn take_outbound(
    outbound: &Revocable<Endpoint<StampedPacket>>,
) -> Result<Option<StampedPacket>, NetError> {
    outbound
        .try_with(Endpoint::try_recv)
        .map_err(|_| NetError::AuthorityRevoked)
}

fn take_admitted_outbound(
    outbound: &Revocable<Endpoint<StampedPacket>>,
    sessions: &PacketSessionFence,
) -> Result<Option<Packet>, NetError> {
    for _ in 0..crate::net_device::FRONTEND_QUEUE_DEPTH {
        let Some(packet) = take_outbound(outbound)? else {
            return Ok(None);
        };
        match sessions.accept_egress(packet) {
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
            Err(_) => unreachable!(),
        }
    }
    Ok(None)
}

fn send_inbound(
    inbound: &Revocable<Endpoint<StampedPacket>>,
    sessions: &PacketSessionFence,
    packet: Packet,
) -> Result<(), NetError> {
    let packet = match sessions.stamp_ingress(packet) {
        Ok(packet) => packet,
        Err(PacketSessionError::Inactive) => {
            STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        Err(_) => unreachable!(),
    };
    inbound
        .try_with(|endpoint| endpoint.try_send(packet))
        .map_err(|_| NetError::AuthorityRevoked)?
        .map_err(|_| NetError::QueueFull)
}

pub fn hello_packet() -> Packet {
    handshake_packet(PEER_DESTINATION_MAC, GUEST_MAC, HELLO_PAYLOAD)
}
pub fn challenge_packet() -> Packet {
    handshake_packet(GUEST_MAC, PEER_MAC, CHALLENGE_PAYLOAD)
}
pub fn ack_packet() -> Packet {
    handshake_packet(PEER_DESTINATION_MAC, GUEST_MAC, ACK_PAYLOAD)
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
    Packet::copy_from(&frame).expect("fixed handshake packet is valid")
}

fn shutdown_driver_policy(reset: bool) {
    let mut state = CONTROL.lock();
    state.online = false;
    state.quarantined |= !reset;
    state.sessions.detach_device();
    state.active_stack_domain = None;
    state.tx_inflight = false;
    DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
    DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
}

/// # Safety
/// The executor guarantees that the faulting domain can never resume.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    let _ = unsafe { CONTROL.recover_after_fault(domain) };
    {
        let mut state = CONTROL.lock();
        if state.active_stack_domain == Some(domain) {
            state.sessions.unbind_stack();
            state.active_stack_domain = None;
        }
    }
    if DRIVER_OWNER.load(Ordering::Acquire) != domain.owner.get()
        || DRIVER_ARENA.load(Ordering::Acquire) != domain.arena.get()
    {
        return;
    }
    let reset = unsafe { vibeos_driver_dwmac_net::recover_faulted(DWMAC) };
    shutdown_driver_policy(reset);
}

#[allow(dead_code)]
pub fn debug_waiter_count() -> usize {
    0
}
