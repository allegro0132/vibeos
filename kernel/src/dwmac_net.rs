//! Capability/session policy for a firmware-owned packet device. The historical
//! module and resource names remain compatible; hardware descriptors, PHY,
//! clocks and DMA synchronization are supplied by the firmware HAL instance.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::packet_device::Engine;
use vibeos_hal::network::{device, Error as HardwareError};

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{
    flush_pending_ingress, submit_ingress, IngressDelivery, Endpoint, Packet, PacketSessionError, PacketSessionFence, PacketStamp, StampedPacket,
};
use crate::sync::SpinLock;
use crate::world::Space;

#[cfg(all(feature = "network-inline-rx", feature = "network-tso-coalesce"))]
compile_error!("inline RX does not admit task-arena TX coalescer storage");

#[cfg(feature = "direct-tcp-segmentation")]
type OutboundResource = vibeos_core::net_transmit::TransmitEndpoint;
#[cfg(not(feature = "direct-tcp-segmentation"))]
type OutboundResource = Endpoint<StampedPacket>;
#[cfg(not(feature = "direct-tcp-segmentation"))]
type PendingTx = Packet;
#[cfg(feature = "direct-tcp-segmentation")]
enum PendingTx { Frame(Packet), Segments(vibeos_core::net_segment_pool::Ticket) }
#[cfg(feature = "direct-tcp-segmentation")]
impl PendingTx {
    fn as_bytes(&self) -> &[u8] {
        match self { Self::Frame(packet) => packet.as_bytes(), Self::Segments(_) => unreachable!("large send handled first") }
    }
}

#[cfg(feature = "pooled-rx")]
type InboundResource = vibeos_core::net_receive::ReceiveEndpoint;
#[cfg(not(feature = "pooled-rx"))]
type InboundResource = Endpoint<StampedPacket>;
#[cfg(feature = "pooled-rx")]
type PendingRx = vibeos_core::net_receive::Stamped;
#[cfg(not(feature = "pooled-rx"))]
type PendingRx = StampedPacket;

const TX_TIMEOUT_MS: u64 = 2_000;
const DRIVER_BATCH_PACKETS: usize = 32;

#[cfg(any(feature = "network-tso-coalesce", feature = "direct-tcp-segmentation"))]
static TSO_GROUPS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(feature = "network-tso-coalesce", feature = "direct-tcp-segmentation"))]
static TSO_FRAMES: AtomicU64 = AtomicU64::new(0);
#[cfg(any(feature = "network-tso-coalesce", feature = "direct-tcp-segmentation"))]
pub fn tso_counts() -> (u64,u64) {
    (TSO_GROUPS.load(Ordering::Relaxed), TSO_FRAMES.load(Ordering::Relaxed))
}

fn description() -> &'static vibeos_hal::network::Device { device() }

pub const HANDSHAKE_FRAME_LEN: usize = 60;
pub const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
pub const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
const PEER_DESTINATION_MAC: [u8; 6] = [0xff; 6];
pub const HANDSHAKE_ETHERTYPE: u16 = 0x88b5;
const HELLO_PAYLOAD: &[u8] = b"VIBEOS-NET-HELLO-v1";
const CHALLENGE_PAYLOAD: &[u8] = b"VIBEOS-NET-CHALLENGE-v1";
const ACK_PAYLOAD: &[u8] = b"VIBEOS-NET-ACK-v1";

#[cfg(not(feature = "universal"))]
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

#[cfg(not(feature = "universal"))]
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

#[cfg(not(feature = "universal"))]
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
    pub tx_checksum_offload: bool,
    pub rx_checksum_offload: bool,
    pub stale_ingress_drops: u64,
    pub stale_egress_drops: u64,
    pub stale_egress_device_epoch_drops: u64,
    pub stale_egress_stack_generation_drops: u64,
    pub resets: u64,
    pub timeouts: u64,
    pub rx_inflight: u8,
    pub tx_inflight: u8,
    pub ethernet_address: [u8; 6],
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
            "CV1800B DWMAC @ {:#x}, IRQ {}, RMII",
            description().registers.start, description().irq
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct DmaRegion {
    device: &'static vibeos_hal::network::Device,
}

impl DmaRegion {
    fn device(&self) -> &'static vibeos_hal::network::Device {
        self.device
    }
}
impl Resource for DmaRegion {
    fn kind(&self) -> &'static str {
        "dma-region"
    }
    fn describe(&self) -> String {
        format!(
            "DWMAC stable cache-isolated descriptor-ring slab @ {:#x}",
            (self.device.dma_base)()
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(not(feature = "universal"))]
pub struct NetDevice;
#[cfg(not(feature = "universal"))]
impl NetDevice {
    fn info(&self) -> NetInfo {
        let state = CONTROL.lock();
        // SAFETY: the Milk-V BSP maps all DWMAC, clock, ePHY, and eFuse
        // apertures for the firmware lifetime. CONTROL serializes this
        // diagnostic snapshot with kernel packet-engine operations; the
        // selected status registers are non-destructive reads.
        let hardware = unsafe { (device().telemetry)() };
        NetInfo {
            online: state.online,
            quarantined: state.quarantined,
            queue_size: u16::try_from(device().rx_queue_size)
                .expect("DWMAC ring size fits telemetry"),
            header_size: 0,
            accepted_features: 0,
            session_epoch: state.sessions.device_epoch(),
            stack_generation: state
                .sessions
                .active_stamp()
                .map_or(0, PacketStamp::stack_generation),
            irq: description().irq,
            used_interrupts: 0,
            rx_packets: hardware.rx_packets,
            tx_packets: hardware.tx_packets,
            tx_checksum_offload: hardware.tx_checksum_offload,
            rx_checksum_offload: hardware.rx_checksum_offload,
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
            ethernet_address: GUEST_MAC,
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
#[cfg(feature = "universal")]
pub(crate) fn universal_info() -> NetInfo {
        let state = CONTROL.lock();
        // SAFETY: the Milk-V BSP maps all DWMAC, clock, ePHY, and eFuse
        // apertures for the firmware lifetime. CONTROL serializes this
        // diagnostic snapshot with kernel packet-engine operations; the
        // selected status registers are non-destructive reads.
        let hardware = unsafe { (device().telemetry)() };
        NetInfo {
            online: state.online,
            quarantined: state.quarantined,
            queue_size: u16::try_from(device().rx_queue_size)
                .expect("DWMAC ring size fits telemetry"),
            header_size: 0,
            accepted_features: 0,
            session_epoch: state.sessions.device_epoch(),
            stack_generation: state
                .sessions
                .active_stamp()
                .map_or(0, PacketStamp::stack_generation),
            irq: description().irq,
            used_interrupts: 0,
            rx_packets: hardware.rx_packets,
            tx_packets: hardware.tx_packets,
            tx_checksum_offload: hardware.tx_checksum_offload,
            rx_checksum_offload: hardware.rx_checksum_offload,
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
            ethernet_address: GUEST_MAC,
            phy_link_up: hardware.phy_link_up,
            tx_descriptor_status: hardware.tx_descriptor_status,
            dma_status: hardware.dma_status,
            clock_enable: hardware.clock_enable,
            clock_bypass: hardware.clock_bypass,
            clock_divider: hardware.clock_divider,
            ephy_control: hardware.ephy_control,
        }
    }
#[cfg(not(feature = "universal"))]
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
    pub location: crate::net_device::NetworkLocation,
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub control: Arc<NetDevice>,
}

pub fn discover() -> Option<NetResources> {
    if !device().present { return None; }
    Some(NetResources {
        location: crate::net_device::NetworkLocation::Mmio {
            base: description().registers.start,
        },
        mmio: Arc::new(MmioWindow),
        dma: Arc::new(DmaRegion { device: device() }),
        control: Arc::new(NetDevice),
    })
}

pub fn info_with(lease: &InvocationLease<NetDevice>) -> Result<NetInfo, NetError> {
    if !lease.authorizes(Rights::READ) {
        return Err(NetError::PermissionDenied);
    }
    Ok(lease.with(NetDevice::info))
}

// Admission policy is published separately from the DMA batch lock. Hardware
// telemetry uses the HAL's explicitly concurrent-safe operation contract.
#[cfg(all(feature = "network-status-snapshot", not(feature = "universal")))]
pub(crate) fn runtime_info_with(lease: &InvocationLease<NetDevice>) -> Result<crate::net_device::RuntimeInfo, NetError> {
    if !lease.authorizes(Rights::READ) { return Err(NetError::PermissionDenied); }
    Ok(lease.with(|_| {
        let (online, quarantined, session_epoch) = *RUNTIME_INFO.lock();
        // SAFETY: Device::telemetry must permit concurrent engine operations;
        // it may not borrow mutable engine state. The invocation remains pinned.
        let hardware = unsafe { (device().telemetry)() };
        crate::net_device::RuntimeInfo {
            online, quarantined, session_epoch,
            phy_link_up: hardware.phy_link_up,
            ethernet_address: GUEST_MAC,
            tx_checksum_offload: hardware.tx_checksum_offload,
            rx_checksum_offload: hardware.rx_checksum_offload,
        }
    }))
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
        #[cfg(feature = "direct-tcp-segmentation")]
        if let Some(old) = state.active_stack_domain { crate::segmented_tx::retire(old); }
        state.active_stack_domain = None;
        let result = match state.sessions.bind_stack(tx_inflight) {
            Ok(stamp) => {
                #[cfg(feature = "pooled-rx")]
                crate::detached_rx::retire_queued();
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
        };
        publish_runtime_info(&state);
        result
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
#[cfg(feature = "network-profile")]
pub fn profile_control_address() -> usize { &CONTROL as *const _ as usize }
#[cfg(all(feature = "network-profile", feature = "network-status-snapshot", not(feature = "universal")))]
pub fn profile_runtime_info_address() -> usize { &RUNTIME_INFO as *const _ as usize }


#[cfg(all(feature = "network-status-snapshot", not(feature = "universal")))]
static RUNTIME_INFO: SpinLock<(bool, bool, u64)> = SpinLock::new_recoverable((false, false, 0));

// Writers hold CONTROL and publish before lifecycle operations complete.
// Only policy fields live here; no timeout, cached counters, link sampling,
// or packet-admission decision is moved into this reader snapshot.
#[cfg(all(feature = "network-status-snapshot", not(feature = "universal")))]
fn publish_runtime_info(state: &Control) {
    *RUNTIME_INFO.lock() = (state.online, state.quarantined, state.sessions.device_epoch());
}
#[cfg(not(all(feature = "network-status-snapshot", not(feature = "universal"))))]
#[inline(always)]
fn publish_runtime_info(_: &Control) {}

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
            cspace.lookup_revocable::<OutboundResource>(outbound, Rights::RECV),
            cspace.lookup_revocable::<InboundResource>(inbound, Rights::SEND),
            cspace.lookup_revocable::<NetDevice>(control, Rights::READ),
        )
    };
    let (Ok(mmio), Ok(dma), Ok(outbound), Ok(inbound), Ok(control)) = authority else {
        crate::println!("  dwmac net driver capability lookup failed");
        return;
    };

    let domain = crate::heap::current_domain();
    DRIVER_OWNER.store(domain.owner.get(), Ordering::Release);
    DRIVER_ARENA.store(domain.arena.get(), Ordering::Release);

    let _device = match dma.try_with(DmaRegion::device) {
        Ok(storage) => storage,
        Err(_) => return,
    };
    let engine = match with_device_authority(&mmio, &dma, &control, || {
        // SAFETY: the retained and currently live capabilities authorize the
        // identity-mapped BSP apertures and this resource's `.dma` storage. The
        // firmware linker keeps that slab physically contiguous and below the
        // board's 32-bit DMA limit for this engine's lifetime.
        unsafe {
            Engine::claim(
                GUEST_MAC,
                crate::sbi::time,
                crate::exec::timebase_hz(),
            )
        }
        .map_err(|_| NetError::DriverFault)
    }) {
        Ok(engine) => engine,
        Err(_) => {
            crate::println!("  dwmac net driver claim failed");
            shutdown_driver_policy(false);
            return;
        }
    };

    if with_device_authority(&mmio, &dma, &control, || {
        let mut state = CONTROL.lock();
        if state.sessions.attach_device().is_err() {
            state.online = false;
            state.quarantined = true;
            publish_runtime_info(&state);
            return Err(NetError::IdentityExhausted);
        }
        state.active_stack_domain = None;
        state.tx_inflight = false;
        state.online = true;
        state.quarantined = false;
        publish_runtime_info(&state);
        Ok(())
    })
    .is_err()
    {
        crate::println!("  dwmac net driver device attach failed");
        let reset = engine.shutdown();
        shutdown_driver_policy(reset);
        return;
    }
    crate::println!(
        "  dwmac net online, IRQ {}, DMA {:#x}, epoch {}, tx-csum {}, rx-csum {}",
        engine.irq(),
        (_device.dma_base)(),
        CONTROL.lock().sessions.device_epoch(),
        engine.tx_checksum_offload(),
        engine.rx_checksum_offload(),
    );
    #[cfg(not(feature = "network-inline-rx"))]
    let mut work = DriverWork::new(engine);
    #[cfg(feature = "network-inline-rx")]
    let _registration = InlineRegistration::install(InlineService {
        owner: domain, caller: None, work: DriverWork::new(engine),
        mmio: mmio.clone(), dma: dma.clone(), control: control.clone(),
        outbound: outbound.clone(), inbound: inbound.clone(),
    });
    #[cfg(feature = "rx-interrupt-poll")]
    if device().rx_interrupts.is_some() {
        if !crate::plic::is_dispatch_hart()
            || crate::plic::register(device().irq, rx_top_half, 0).is_err()
            {
            crate::println!("RX IRQ admission failed (requires dispatch-hart affinity)");
            return;
        }
        RX_REGISTERED.store(true, Ordering::Release);
        RX_IRQ_FAULT.store(false, Ordering::Release);
        if crate::plic::enable(device().irq).is_err() { return; }
    }
    #[cfg(feature = "driver-stage-profile")]
    let mut stage_turn = 0u64;
    let mut poll_budget = vibeos_core::poll_budget::PollBudget::new(crate::exec::timebase_hz() / 1000, 64);
    loop {
        #[cfg(feature = "rx-interrupt-poll")]
        if RX_IRQ_FAULT.swap(false, Ordering::AcqRel) {
            crate::println!("RX IRQ fatal controller fault");
            return;
        }
        if FAULT.swap(false, Ordering::AcqRel) {
            panic!("injected CV1800B DWMAC fault");
        }
        #[cfg(feature = "network-inline-rx")]
        {
            if INLINE_SERVICE.lock().as_ref().is_none_or(|s| s.owner != domain) { return; }
            // Once bound, the protocol task drives each controller turn. This
            // lifecycle task retains independent cancellation/restart authority.
            let bound = with_device_authority(&mmio, &dma, &control, ||
                Ok(CONTROL.lock().active_stack_domain.is_some()));
            match bound {
                Ok(true) => {
                    // Bounded fallback also drains TX if a stack retires
                    // normally before a replacement can bind its session.
                    if inline_turn(false, false).is_err() { return; }
                    crate::exec::sleep_ms(1).await;
                    continue;
                }
                Ok(false) => {}
                Err(_) => return,
            }
        }
        #[cfg(feature = "driver-stage-profile")]
        let sample_stage = { stage_turn = stage_turn.wrapping_add(1); stage_turn & 63 == 0 };
        #[cfg(not(feature = "network-inline-rx"))]
        let turn = with_device_authority(&mmio, &dma, &control, || {
            driver_turn(
                &mut work,
                true,
                #[cfg(feature = "driver-stage-profile")]
                sample_stage,
                &outbound,
                &inbound,
            )
        });
        #[cfg(feature = "network-inline-rx")]
        let turn = inline_turn(false, true);
        match turn {
            Ok(worked) => {
                #[cfg(feature = "rx-interrupt-poll")]
                if device().rx_interrupts.is_some() {
                    vibeos_core::net_profile::poll_decision(worked, worked);
                    if worked {
                        crate::exec::yield_now().await;
                    } else if wait_rx_work(&mmio, &dma, &control, &outbound).await.is_err() {
                        return;
                    }
                    continue;
                }
                if poll_budget.runnable(crate::sbi::time(), worked) {
                    crate::exec::yield_now().await;
                } else {
                    crate::exec::sleep_ms(1).await;
                }
            }
            Err(error) => {
                crate::println!("  dwmac net driver stopped: {error:?}");
                return;
            }
        }
    }
}

#[cfg(feature = "rx-interrupt-poll")]
static RX_REGISTERED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rx-interrupt-poll")]
static RX_IRQ_FAULT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rx-interrupt-poll")]
static RX_WAIT: crate::exec::WaitQueue = crate::exec::WaitQueue::new();
#[cfg(feature = "rx-interrupt-poll")]
static RX_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rx-interrupt-poll")]
static RX_ARMS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rx-interrupt-poll")]
static RX_BUSY_RECHECKS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rx-interrupt-poll")]
static RX_TIMERS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rx-interrupt-poll")]
static RX_TX_WAKES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "rx-interrupt-poll")]
pub fn rx_irq_stats() -> [u64; 5] {
    [&RX_INTERRUPTS, &RX_ARMS, &RX_BUSY_RECHECKS, &RX_TIMERS, &RX_TX_WAKES]
        .map(|v| v.load(Ordering::Relaxed))
}
#[cfg(feature = "rx-interrupt-poll")]
fn rx_top_half(_: usize, _: u64) {
    if let Some(irq) = &device().rx_interrupts {
        // Firmware provides a static register-only operation, never ENGINE.
        if !unsafe { (irq.acknowledge)() } {
            RX_IRQ_FAULT.store(true, Ordering::Release);
        }
        RX_INTERRUPTS.fetch_add(1, Ordering::Relaxed);
        RX_WAIT.wake_all();
        #[cfg(feature = "network-inline-rx")]
        crate::detached_rx::notify_input();
    }
}
#[cfg(feature = "rx-interrupt-poll")]
fn stop_rx_interrupts() {
    if let Some(irq) = &device().rx_interrupts {
        unsafe { (irq.mask)(); }
        if RX_REGISTERED.swap(false, Ordering::AcqRel) {
            crate::plic::unregister(device().irq);
        }
    }
}
#[cfg(feature = "rx-interrupt-poll")]
async fn wait_rx_work(
    mmio: &Revocable<MmioWindow>, dma: &Revocable<DmaRegion>,
    control: &Revocable<NetDevice>, outbound: &Revocable<OutboundResource>,
) -> Result<(), NetError> {
    use core::{future::{poll_fn, Future}, pin::pin, task::Poll};
    let irq = device().rx_interrupts.as_ref().expect("admitted RX interrupts");
    // Capturing the wait-queue epoch precedes every condition check. Register
    // the waiter before arming; an ISR in either gap remains observable.
    let tx_notification = outbound.try_with(|q| q.message_event())
        .map_err(|_| NetError::AuthorityRevoked)?;
    let mut tx_event = pin!(tx_notification.wait());
    let mut event = pin!(RX_WAIT.wait());
    let mut timer = pin!(crate::exec::sleep_ms(1));
    poll_fn(|cx| {
        let event_ready = event.as_mut().poll(cx).is_ready();
        let tx_ready = tx_event.as_mut().poll(cx).is_ready();
        let timer_ready = timer.as_mut().poll(cx).is_ready();
        if event_ready || tx_ready || timer_ready {
            unsafe { (irq.mask)(); }
            if timer_ready { RX_TIMERS.fetch_add(1, Ordering::Relaxed); }
            if tx_ready { RX_TX_WAKES.fetch_add(1, Ordering::Relaxed); }
            return Poll::Ready(Ok(()));
        }
        let result = with_device_authority(mmio, dma, control, || {
            // Driver runs on the PLIC dispatch hart. This IRQ-masking guard
            // serializes register writers against its top half and pins policy.
            let _state = CONTROL.lock();
            if outbound.try_with(|q| q.has_message()).map_err(|_| NetError::AuthorityRevoked)? {
                unsafe { (irq.mask)(); }
                RX_TX_WAKES.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            }
            // Clear causes accumulated while polling with interrupts masked.
            // The subsequent OWN recheck catches arrivals covered by this ACK.
            if !unsafe { (irq.acknowledge)() } { return Err(NetError::DriverFault); }
            RX_ARMS.fetch_add(1, Ordering::Relaxed);
            let idle = unsafe { (irq.arm)() && !(irq.pending)() };
            if !idle {
                unsafe { (irq.mask)(); }
                RX_BUSY_RECHECKS.fetch_add(1, Ordering::Relaxed);
            }
            Ok(idle)
        });
        match result {
            Ok(true) => Poll::Pending,
            Ok(false) => Poll::Ready(Ok(())),
            Err(e) => { unsafe { (irq.mask)(); } Poll::Ready(Err(e)) }
        }
    }).await
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
        let Some(engine) = self.engine.take() else { return; };
        #[cfg(feature = "rx-interrupt-poll")]
        stop_rx_interrupts();
        let reset = engine.shutdown();
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

/// Exclusive state of one bounded controller service turn. It is independent
/// of the async scheduling loop so a future receive/protocol pump can drive the
/// same state synchronously without inventing a second Engine owner. This
/// context never awaits; callers retain live device capabilities for each turn.
/// Keep the session last: pending software state is dropped before reset.
struct DriverWork {
    pending_tx: Option<PendingTx>,
    #[cfg(feature = "network-tso-coalesce")]
    tx_batch: vibeos_core::net_tx_coalesce::TxCoalescer,
    pending_rx: Option<PendingRx>,
    #[cfg(feature = "pooled-rx")]
    pending_rx_batch: vibeos_core::net_receive::StampedBatch,
    tx_deadline: u64,
    link_poll: Option<u64>,
    session: DriverSession,
}
impl DriverWork {
    fn new(engine: Engine) -> Self {
        Self {
            pending_tx: None,
            #[cfg(feature = "network-tso-coalesce")]
            tx_batch: vibeos_core::net_tx_coalesce::TxCoalescer::new(),
            pending_rx: None,
            #[cfg(feature = "pooled-rx")]
            pending_rx_batch: vibeos_core::net_receive::StampedBatch::empty(),
            tx_deadline: 0, link_poll: None,
            session: DriverSession { engine: Some(engine) },
        }
    }
}

// Permanent kernel policy storage, never a pointer into either task's arena.
// The gate covers every use of the sole Engine, including removal/reset. All
// pending data in the admitted configuration is fixed storage or pool tickets.
#[cfg(feature = "network-inline-rx")]
struct InlineService {
    owner: AllocationDomain,
    caller: Option<AllocationDomain>,
    work: DriverWork,
    mmio: Revocable<MmioWindow>,
    dma: Revocable<DmaRegion>,
    control: Revocable<NetDevice>,
    outbound: Revocable<OutboundResource>,
    inbound: Revocable<InboundResource>,
}
#[cfg(feature = "network-inline-rx")]
static INLINE_SERVICE: SpinLock<Option<InlineService>> = SpinLock::new_recoverable(None);
#[cfg(feature = "network-inline-rx")]
struct InlineRegistration(AllocationDomain);
#[cfg(feature = "network-inline-rx")]
impl InlineRegistration {
    fn install(service: InlineService) -> Self {
        let mut slot = INLINE_SERVICE.lock();
        assert!(slot.is_none(), "exclusive packet service already installed");
        let owner = service.owner;
        *slot = Some(service);
        Self(owner)
    }
}
#[cfg(feature = "network-inline-rx")]
impl Drop for InlineRegistration {
    fn drop(&mut self) {
        let mut slot = INLINE_SERVICE.lock();
        if slot.as_ref().is_some_and(|s| s.owner == self.0) {
            // Keep the gate through shutdown: a new claim must not overlap it.
            drop(slot.take());
        }
    }
}
#[cfg(feature = "network-inline-rx")]
pub(crate) fn service_inline_with(lease: &InvocationLease<NetDevice>, receive: bool) -> Result<bool, NetError> {
    if !lease.authorizes(Rights::INVOKE) { return Err(NetError::PermissionDenied); }
    lease.with(|_| inline_turn(true, receive))
}
#[cfg(feature = "network-inline-rx")]
fn inline_turn(protocol: bool, receive: bool) -> Result<bool, NetError> {
    // Synchronous device work now runs inside the stack task. Give it its own
    // nested stage so protocol attribution does not absorb controller policy,
    // capability checks and gate waits. Compiles out without network-profile.
    let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Driver);
    if !crate::plic::is_dispatch_hart() { return Err(NetError::PermissionDenied); }
    let mut slot = INLINE_SERVICE.lock();
    let Some(s) = slot.as_mut() else { return Ok(false); };
    let domain = crate::heap::current_domain();
    // The stack gets invocation authority, never the driver's capabilities or
    // Engine. Validate its exact active incarnation at each synchronous call.
    if protocol && CONTROL.lock().active_stack_domain != Some(domain) { return Ok(false); }
    if !protocol && s.owner != domain { return Err(NetError::PermissionDenied); }
    s.caller = Some(domain);
    let result = with_device_authority(&s.mmio, &s.dma, &s.control, || {
        if let Some(irq) = &device().rx_interrupts { unsafe { (irq.mask)(); } }
        let worked = driver_turn(&mut s.work, receive,
            #[cfg(feature = "driver-stage-profile")] false,
            &s.outbound, &s.inbound)?;
        if !worked && (protocol || !receive) {
            // Receiver registers its notification before repeating its full
            // input check. Arm and OWN recheck share the dispatch-hart guard.
            let _state = CONTROL.lock();
            let irq = device().rx_interrupts.as_ref().ok_or(NetError::DriverFault)?;
            if !unsafe { (irq.acknowledge)() } { return Err(NetError::DriverFault); }
            RX_ARMS.fetch_add(1, Ordering::Relaxed);
            let idle = unsafe { (irq.arm)() && !(irq.pending)() };
            if !idle {
                unsafe { (irq.mask)(); }
                RX_BUSY_RECHECKS.fetch_add(1, Ordering::Relaxed);
                return Ok(true);
            }
        }
        Ok(worked)
    });
    s.caller = None;
    result
}

fn driver_turn(
    work: &mut DriverWork,
    receive: bool,
    #[cfg(feature = "driver-stage-profile")] sample_stage: bool,
    outbound: &Revocable<OutboundResource>,
    inbound: &Revocable<InboundResource>,
) -> Result<bool, NetError> {
    let DriverWork { pending_tx,
        #[cfg(feature = "network-tso-coalesce")] tx_batch,
        pending_rx,
        #[cfg(feature = "pooled-rx")] pending_rx_batch,
        tx_deadline, link_poll, session } = work;
    let engine = session.engine_mut();
    #[cfg(feature = "tx-wait-profile")]
    let turn_started = crate::sbi::time();
    // Observe cable/negotiation changes even when a queued DHCP packet is
    // waiting for the first link, or sustained traffic keeps the turn busy.
    if crate::network_poll::due(link_poll, crate::sbi::time(), crate::exec::timebase_hz()) {
        engine.poll_link();
    }
    #[cfg(feature = "driver-stage-profile")]
    let stage_started = if sample_stage { crate::sbi::time() } else { 0 };
    #[cfg(feature = "driver-stage-profile")]
    let mut stage = [0u64; 8];
    let mut immediate_work = false;
    let tx_dma_pending;
    // Once a packet leaves the bounded endpoint, this task owns it until a TX
    // descriptor accepts it. Ring pressure is ordinary backpressure until the
    // bounded hardware deadline; retain the one packet that did not fit.
    {
        // Binding and DMA publication share CONTROL. Marking the pending/raw
        // descriptor reservation before releasing this guard prevents a new
        // generation from becoming active between stamp validation and OWN.
        let mut state = CONTROL.lock();
        let now = crate::sbi::time();
        let was_busy = engine.tx_owned();
        if was_busy && *tx_deadline != 0 && now >= *tx_deadline {
            TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            panic!("CV1800B DWMAC TX descriptor ring timed out");
        }
        #[cfg(feature = "network-tso-coalesce")]
        let mut dequeues_left = DRIVER_BATCH_PACKETS;
        #[cfg(feature = "direct-tcp-segmentation")]
        let mut wire_budget = DRIVER_BATCH_PACKETS;
        for _ in 0..DRIVER_BATCH_PACKETS {
            #[cfg(feature = "direct-tcp-segmentation")]
            if wire_budget == 0 { break; }
            #[cfg(feature = "network-tso-coalesce")]
            if tx_batch.frames() != 0 {
                // Preserve the group on QueueFull: successors cannot overtake it.
                let stamp = state.sessions.active_stamp().ok_or(NetError::Protocol)?;
                let request = tx_batch.request(stamp).map_err(|_| NetError::Protocol)?;
                let result = outbound.try_with(|_| {
                    if tx_batch.frames() == 1 { engine.transmit(request.bytes()) }
                    else { engine.transmit_segments(request) }
                }).map_err(|_| NetError::AuthorityRevoked)?;
                match result {
                    Ok(()) => {
                        #[cfg(feature = "network-tx-audit")]
                        {
                            let mut wire = [0; vibeos_core::net::MAX_PACKET_LEN];
                            for index in 0..request.wire_segments() {
                                let length = request.write_segment(index, &mut wire).unwrap();
                                vibeos_core::net_tx_audit::record(1, &wire[..length]);
                            }
                        }
                        if tx_batch.frames() > 1 {
                            TSO_GROUPS.fetch_add(1, Ordering::Relaxed);
                            TSO_FRAMES.fetch_add(tx_batch.frames() as u64, Ordering::Relaxed);
                        }
                        tx_batch.clear();
                        *tx_deadline = now.saturating_add(tx_timeout_ticks());
                        immediate_work = true;
                    }
                    Err(HardwareError::QueueFull) => break,
                    Err(_) => return Err(NetError::DriverFault),
                }
            }
            if pending_tx.is_none() {
                #[cfg(feature = "network-tso-coalesce")]
                {
                    if dequeues_left == 0 { break; }
                    dequeues_left -= 1;
                }
                *pending_tx = take_admitted_outbound(outbound, &state.sessions)?;
            }
            #[cfg(feature = "direct-tcp-segmentation")]
            if let Some(PendingTx::Segments(ticket)) = pending_tx.as_ref() {
                let ticket = *ticket;
                let expected = state.sessions.active_stamp();
                if expected != Some(ticket.stamp()) {
                    let _ = outbound.try_with(|q| q.pool().cancel(ticket, ticket.stamp()));
                    *pending_tx = None;
                    STALE_EGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let result = outbound.try_with(|q| q.pool().try_consume(ticket, ticket.stamp(), |request| {
                    let frames = request.wire_segments();
                    // Bound a turn by wire work, not 32 large requests. Permit
                    // one oversized group for small-MSS peers to make progress.
                    if frames > wire_budget && wire_budget != DRIVER_BATCH_PACKETS {
                        return Err(HardwareError::QueueFull);
                    }
                    let result = engine.transmit_segments(request);
                    if result.is_ok() { vibeos_core::net_tx_audit::record_segments(1, request); }
                    result.map(|()| frames)
                })).map_err(|_| NetError::AuthorityRevoked)?;
                match result {
                    Ok(Ok(frames)) => {
                        wire_budget = wire_budget.saturating_sub(frames);
                        TSO_GROUPS.fetch_add(1, Ordering::Relaxed);
                        TSO_FRAMES.fetch_add(frames as u64, Ordering::Relaxed);
                        *pending_tx = None;
                        *tx_deadline = now.saturating_add(tx_timeout_ticks());
                        immediate_work = true;
                    }
                    Ok(Err(HardwareError::QueueFull)) => break,
                    Ok(Err(_)) => return Err(NetError::DriverFault),
                    Err(vibeos_core::net_segment_pool::Error::Stale) => {
                        *pending_tx = None;
                        STALE_EGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => return Err(NetError::Protocol),
                }
                continue;
            }
            let Some(packet) = pending_tx.as_ref() else {
                break;
            };
            #[cfg(feature = "network-tso-coalesce")]
            if engine.segmentation_limits().is_some_and(|(max, min)| max >= 32768 && min <= 64) {
                let stamp = state.sessions.active_stamp().ok_or(NetError::Protocol)?;
                if tx_batch.push(packet.as_bytes(), stamp) {
                    *pending_tx = None;
                    while dequeues_left != 0 && tx_batch.frames() < 16 {
                        dequeues_left -= 1;
                        *pending_tx = take_admitted_outbound(outbound, &state.sessions)?;
                        let Some(next) = pending_tx.as_ref() else { break; };
                        if !tx_batch.push(next.as_bytes(), stamp) { break; }
                        *pending_tx = None;
                    }
                    // Flush without waiting for future packets. A lone frame
                    // keeps the ordinary transmit path.
                    immediate_work = true;
                    continue;
                }
            }
            match engine.transmit(packet.as_bytes()) {
                Ok(()) => {
                    vibeos_core::net_tx_audit::record(1, packet.as_bytes());
                    #[cfg(feature = "direct-tcp-segmentation")]
                    { wire_budget = wire_budget.saturating_sub(1); }
                    *pending_tx = None;
                    *tx_deadline = now.saturating_add(tx_timeout_ticks());
                    immediate_work = true;
                }
                Err(HardwareError::QueueFull) => {
                    break;
                }
                Err(HardwareError::PacketTooLarge) => {
                    // A safely constructed Packet always fits the DMA buffer.
                    state.online = false;
                    publish_runtime_info(&state);
                    return Err(NetError::Protocol);
                }
                Err(_) => return Err(NetError::DriverFault),
            }
        }
        let descriptor_busy = engine.tx_owned();
        state.tx_inflight = descriptor_busy || pending_tx.is_some();
        #[cfg(feature = "network-tso-coalesce")]
        { state.tx_inflight |= tx_batch.frames() != 0; }
        tx_dma_pending = descriptor_busy;
        if state.tx_inflight && *tx_deadline == 0 {
            *tx_deadline = now.saturating_add(tx_timeout_ticks());
        } else if !state.tx_inflight {
            *tx_deadline = 0;
        }

    }

    #[cfg(feature = "driver-stage-profile")]
    let rx_started = if sample_stage {
        let now = crate::sbi::time();
        stage[0] = 1;
        stage[1] = now.wrapping_sub(stage_started);
        now
    } else { 0 };

    let rx_budget = if receive { DRIVER_BATCH_PACKETS } else { 0 };
    #[cfg(feature = "rx-publish-batch")]
    {
        let mut budget = rx_budget;
        while budget != 0 {
            let state = CONTROL.lock();
            if pending_rx_batch.remaining() == 0 {
                #[cfg(feature = "driver-stage-profile")]
                let hw_started = if sample_stage { crate::sbi::time() } else { 0 };
                let tickets = engine.receive_batch().map_err(|_| NetError::DriverFault)?;
                let count = tickets.iter().flatten().count();
                #[cfg(feature = "driver-stage-profile")]
                if sample_stage {
                    stage[3] += crate::sbi::time().wrapping_sub(hw_started);
                    stage[4] += count as u64;
                    if count == 0 { stage[7] += 1; }
                }
                if count == 0 { break; }
                immediate_work = true;
                let Some(stamp) = state.sessions.active_stamp() else {
                    for ticket in tickets.into_iter().flatten() { engine.discard_ticket(ticket); }
                    STALE_INGRESS_DROPS.fetch_add(count as u64, Ordering::Relaxed);
                    budget = budget.saturating_sub(count); continue;
                };
                *pending_rx_batch = vibeos_core::net_receive::StampedBatch::new(tickets, stamp);
            }
            if pending_rx_batch.stamp() != state.sessions.active_stamp() {
                while budget != 0 {
                    let Some(frame) = pending_rx_batch.pop() else { break; };
                    engine.discard_ticket(frame.ticket());
                    STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed); budget -= 1;
                }
                continue;
            }
            let wanted = pending_rx_batch.remaining().min(budget);
            let sent = match inbound.try_with(|q| q.try_send_batch(pending_rx_batch, budget)) {
                Ok(sent) => sent,
                Err(_) => {
                    while let Some(frame) = pending_rx_batch.pop() { engine.discard_ticket(frame.ticket()); }
                    return Err(NetError::AuthorityRevoked);
                }
            };
            budget -= sent; immediate_work = true;
            #[cfg(feature = "driver-stage-profile")]
            if sample_stage { stage[5] += sent as u64; }
            if sent < wanted {
                #[cfg(feature = "driver-stage-profile")]
                if sample_stage { stage[6] += 1; }
                break;
            }
        }
    }
    #[cfg(all(feature = "pooled-rx", not(feature = "rx-publish-batch")))]
    for _ in 0..rx_budget {
        let state = CONTROL.lock();
        let frame = if let Some(frame) = pending_rx.take().or_else(|| pending_rx_batch.pop()) {
            frame
        } else {
            #[cfg(feature = "driver-stage-profile")]
            let hw_started = if sample_stage { crate::sbi::time() } else { 0 };
            let tickets = engine.receive_batch().map_err(|_| NetError::DriverFault)?;
            let count = tickets.iter().flatten().count();
            #[cfg(feature = "driver-stage-profile")]
            if sample_stage {
                stage[3] += crate::sbi::time().wrapping_sub(hw_started);
                stage[4] += count as u64;
                if count == 0 { stage[7] += 1; }
            }
            if count == 0 { break; }
            immediate_work = true;
            let Some(stamp) = state.sessions.active_stamp() else {
                for ticket in tickets.into_iter().flatten() { engine.discard_ticket(ticket); }
                STALE_INGRESS_DROPS.fetch_add(count as u64, Ordering::Relaxed);
                continue;
            };
            // Entire returned batch is stamped before CONTROL is released.
            // Queue pressure retains this stamp; no firmware-prefetched ticket
            // can later acquire a new device/stack generation.
            *pending_rx_batch = vibeos_core::net_receive::StampedBatch::new(tickets, stamp);
            pending_rx_batch.pop().expect("nonempty admitted RX batch")
        };
        if state.sessions.active_stamp() != Some(frame.stamp()) {
            engine.discard_ticket(frame.ticket());
            STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        match inbound.try_with(|q| q.try_send(frame)) {
            Ok(Ok(())) => {
                immediate_work = true;
                #[cfg(feature = "driver-stage-profile")]
                if sample_stage { stage[5] += 1; }
            },
            Ok(Err(frame)) => {
                #[cfg(feature = "driver-stage-profile")]
                if sample_stage { stage[6] += 1; }
                *pending_rx = Some(frame); immediate_work = true; break;
            }
            Err(_) => { engine.discard_ticket(frame.ticket()); return Err(NetError::AuthorityRevoked); }
        }
    }
    #[cfg(not(feature = "pooled-rx"))]
    for _ in 0..rx_budget {
        // Consume, stamp, publish and rearm one RX frame under the same
        // barrier. Rebinding between frames cannot relabel a consumed frame.
        let state = CONTROL.lock();
        // Never consume another DMA frame while one awaits queue space.
        // Its immutable stamp survives retries; a rebind retires it instead
        // of relabeling it for the new stack. TX remains serviced each turn.
        let delivery = if pending_rx.is_some() {
            flush_pending_ingress(pending_rx, &state.sessions, inbound)
        } else {
            let Some(packet) = Packet::receive_with(|frame| engine.receive(frame))
                .map_err(|_| NetError::Protocol)? else { break; };
            immediate_work = true;
            let packet = match state.sessions.stamp_ingress(packet) {
                Ok(packet) => packet,
                Err(PacketSessionError::Inactive) => {
                    STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(_) => unreachable!(),
            };
            submit_ingress(packet, pending_rx, &state.sessions, inbound)
        }.map_err(|_| NetError::AuthorityRevoked)?;
        immediate_work = true;
        match delivery {
            IngressDelivery::Backpressured => break,
            IngressDelivery::Stale => { STALE_INGRESS_DROPS.fetch_add(1, Ordering::Relaxed); }
            IngressDelivery::Delivered | IngressDelivery::Empty => {}
        }
    }
    #[cfg(feature = "driver-stage-profile")]
    if sample_stage {
        stage[2] = crate::sbi::time().wrapping_sub(rx_started);
        for (counter, value) in DRIVER_STAGES.iter().zip(stage) {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }
    #[cfg(feature = "tx-wait-profile")]
    {
        // Do not call the first bucket productive: queue backpressure also
        // requests another turn. TX-only means no other runnable flag was set.
        let bucket = if immediate_work { 0 } else if tx_dma_pending { 1 } else { 2 };
        let elapsed = crate::sbi::time().wrapping_sub(turn_started);
        TX_WAIT_TURNS[bucket * 2].fetch_add(1, Ordering::Relaxed);
        TX_WAIT_TURNS[bucket * 2 + 1].fetch_add(elapsed, Ordering::Relaxed);
    }
    Ok(immediate_work || tx_dma_pending)
}

// Opt-in turn attribution, separate from low-overhead WFI residency counters.
// Buckets are [other runnable work, TX ownership only, idle], each count/ticks.
// Elapsed scopes include lock wait, preemption, link checks and reclamation;
// they are not CPU cycles or a measure of hardware DMA latency.
#[cfg(feature = "tx-wait-profile")]
static TX_WAIT_TURNS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
#[cfg(feature = "tx-wait-profile")]
pub fn tx_wait_stats() -> [u64; 6] {
    TX_WAIT_TURNS.each_ref().map(|v| v.load(Ordering::Relaxed))
}

// Systematic 1/64 turn sampling limits hot-path perturbation. Do not scale
// these scopes into CPU usage: workload periodicity may bias the sample.
#[cfg(feature = "driver-stage-profile")]
static DRIVER_STAGES: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
#[cfg(feature = "driver-stage-profile")]
pub fn driver_stage_stats() -> [u64; 8] {
    DRIVER_STAGES.each_ref().map(|v| v.load(Ordering::Relaxed))
}

fn tx_timeout_ticks() -> u64 {
    TX_TIMEOUT_MS.saturating_mul(crate::exec::timebase_hz()) / 1_000
}

#[cfg(not(feature = "direct-tcp-segmentation"))]
fn take_outbound(
    outbound: &Revocable<OutboundResource>,
) -> Result<Option<StampedPacket>, NetError> {
    outbound
        .try_with(Endpoint::try_recv)
        .map_err(|_| NetError::AuthorityRevoked)
}

#[cfg(not(feature = "direct-tcp-segmentation"))]
fn take_admitted_outbound(
    outbound: &Revocable<OutboundResource>,
    sessions: &PacketSessionFence,
) -> Result<Option<Packet>, NetError> {
    let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::PacketQueue);
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

#[cfg(feature = "direct-tcp-segmentation")]
fn take_admitted_outbound(outbound: &Revocable<OutboundResource>, sessions: &PacketSessionFence)
    -> Result<Option<PendingTx>, NetError> {
    use vibeos_core::net_transmit::Transmit;
    for _ in 0..crate::net_device::FRONTEND_QUEUE_DEPTH {
        let Some(message) = outbound.try_with(|q| q.try_recv()).map_err(|_|NetError::AuthorityRevoked)? else { return Ok(None); };
        match message {
            Transmit::Frame(frame) => if let Ok(packet) = sessions.accept_egress(frame) { return Ok(Some(PendingTx::Frame(packet))); },
            Transmit::Segments(ticket) => {
                if sessions.active_stamp() == Some(ticket.stamp()) { return Ok(Some(PendingTx::Segments(ticket))); }
                let _ = outbound.try_with(|q| q.pool().cancel(ticket, ticket.stamp()));
            }
        }
        STALE_EGRESS_DROPS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(None)
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
    #[cfg(feature = "pooled-rx")]
    crate::detached_rx::retire_queued();
    #[cfg(feature = "direct-tcp-segmentation")]
    crate::segmented_tx::retire_all();
    state.active_stack_domain = None;
    state.tx_inflight = false;
    publish_runtime_info(&state);
    DRIVER_OWNER.store(OwnerId::SYSTEM.get(), Ordering::Release);
    DRIVER_ARENA.store(ArenaId::UNTRACKED.get(), Ordering::Release);
}

/// # Safety
/// The executor guarantees that the faulting domain can never resume.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    // Release any abandoned pool guard before waiting on CONTROL: another hart
    // can hold CONTROL while waiting for that same slot.
    #[cfg(feature = "pooled-rx")]
    unsafe { crate::detached_rx::recover(domain); }
    #[cfg(feature = "direct-tcp-segmentation")]
    unsafe { crate::segmented_tx::recover(domain); }
    #[cfg(all(feature = "network-status-snapshot", not(feature = "universal")))]
    let _ = unsafe { RUNTIME_INFO.recover_after_fault(domain) };
    let _ = unsafe { CONTROL.recover_after_fault(domain) };
    #[cfg(feature = "network-inline-rx")]
    {
        let _ = unsafe { INLINE_SERVICE.recover_after_fault(domain) };
        let mut slot = INLINE_SERVICE.lock();
        if slot.as_ref().is_some_and(|s| s.owner == domain || s.caller == Some(domain)) {
            let mut abandoned = slot.take().unwrap();
            // A fault may have interrupted a controller operation. Retire the
            // token without normal shutdown, then use the firmware's hard-fault
            // recovery contract while every other invocation remains excluded.
            let _ = abandoned.work.session.engine.take();
            stop_rx_interrupts();
            let reset = unsafe { (device().recover)() };
            shutdown_driver_policy(reset);
            drop(abandoned);
        }
    }
    {
        let mut state = CONTROL.lock();
        if state.active_stack_domain == Some(domain) {
            state.sessions.unbind_stack();
            #[cfg(feature = "pooled-rx")]
            crate::detached_rx::retire_queued();
            state.active_stack_domain = None;
            publish_runtime_info(&state);
        }
    }
    if DRIVER_OWNER.load(Ordering::Acquire) != domain.owner.get()
        || DRIVER_ARENA.load(Ordering::Acquire) != domain.arena.get()
    {
        return;
    }
    #[cfg(feature = "rx-interrupt-poll")]
    stop_rx_interrupts();
    let reset = unsafe { (device().recover)() };
    shutdown_driver_policy(reset);
}

#[allow(dead_code)]
pub fn debug_waiter_count() -> usize {
    0
}

#[cfg(feature = "universal")]
pub use crate::universal_net::{NetError, NetInfo, NetDevice};
