//! Polling CV1800B DWMAC backend for the Milk-V Duo Ethernet IO Board.
//!
//! The first revision uses one enhanced RX descriptor and one enhanced TX
//! descriptor. Packet transport remains the same bounded, capability-addressed
//! raw-L2 interface used by the QEMU virtio-net backend.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{
    Endpoint, Packet, PacketSessionError, PacketSessionFence, PacketStamp, StampedPacket,
    MAX_PACKET_LEN,
};
use crate::sync::SpinLock;
use crate::world::Space;

const BASE: usize = crate::platform::ETHERNET_BASE;
const IRQ: u32 = crate::platform::ETHERNET_IRQ;
const DMA_BUFFER_LEN: usize = 1_536;
const RESET_BUDGET: usize = 2_000_000;
const TX_TIMEOUT_MS: u64 = 2_000;

const GMAC_CONTROL: usize = 0x0000;
const GMAC_FRAME_FILTER: usize = 0x0004;
const GMAC_MII_ADDR: usize = 0x0010;
const GMAC_MII_DATA: usize = 0x0014;
const GMAC_ADDR_HIGH: usize = 0x0040;
const GMAC_ADDR_LOW: usize = 0x0044;
const DMA_BUS_MODE: usize = 0x1000;
const DMA_TX_POLL: usize = 0x1004;
const DMA_RX_POLL: usize = 0x1008;
const DMA_RX_DESC: usize = 0x100c;
const DMA_TX_DESC: usize = 0x1010;
const DMA_STATUS: usize = 0x1014;
const DMA_CONTROL: usize = 0x1018;
const DMA_INT_ENABLE: usize = 0x101c;
const DMA_AXI_BUS_MODE: usize = 0x1028;

const DMA_SOFT_RESET: u32 = 1;
const DMA_ATDS: u32 = 1 << 7;
const DMA_AAL: u32 = 1 << 25;
const DMA_START_RX: u32 = 1 << 1;
const DMA_START_TX: u32 = 1 << 13;
const DMA_RX_STORE_FORWARD: u32 = 1 << 25;
const DMA_TX_STORE_FORWARD: u32 = 1 << 21;
const DMA_FLUSH_TX: u32 = 1 << 20;
const MAC_RX_ENABLE: u32 = 1 << 2;
const MAC_TX_ENABLE: u32 = 1 << 3;
const MAC_ACS: u32 = 1 << 7;
const MAC_DUPLEX: u32 = 1 << 11;
const MAC_FAST_ETHERNET: u32 = 1 << 14;
const MAC_MII_PORT: u32 = 1 << 15;
const MII_BUSY: u32 = 1;
const MII_CLOCK_RANGE_250MHZ: u32 = 5 << 2;
const PHY_ADDRESS: u32 = 0;

const DESC_OWN: u32 = 1 << 31;
const RX_LAST: u32 = 1 << 8;
const RX_FIRST: u32 = 1 << 9;
const RX_ERROR: u32 = 1 << 15;
const RX_END_RING: u32 = 1 << 15;
const TX_END_RING: u32 = 1 << 21;
const TX_FIRST: u32 = 1 << 28;
const TX_LAST: u32 = 1 << 29;

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
}

pub struct MmioWindow;
impl Resource for MmioWindow {
    fn kind(&self) -> &'static str {
        "cv1800b-dwmac-mmio"
    }
    fn describe(&self) -> String {
        format!("CV1800B DWMAC @ {BASE:#x}, IRQ {IRQ}, RMII")
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
        format!("DWMAC stable two-descriptor slab @ {:#x}", dma_base())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct NetDevice;
impl NetDevice {
    fn info(&self) -> NetInfo {
        let state = CONTROL.lock();
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
            rx_packets: RX_PACKETS.load(Ordering::Acquire),
            tx_packets: TX_PACKETS.load(Ordering::Acquire),
            stale_ingress_drops: STALE_INGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_drops: STALE_EGRESS_DROPS.load(Ordering::Acquire),
            stale_egress_device_epoch_drops: STALE_EGRESS_DEVICE_EPOCH_DROPS
                .load(Ordering::Acquire),
            stale_egress_stack_generation_drops: STALE_EGRESS_STACK_GENERATION_DROPS
                .load(Ordering::Acquire),
            resets: RESETS.load(Ordering::Acquire),
            timeouts: TIMEOUTS.load(Ordering::Acquire),
            rx_inflight: u8::from(state.online),
            tx_inflight: u8::from(state.tx_inflight),
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
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);
static TX_PACKETS: AtomicU64 = AtomicU64::new(0);
static STALE_INGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_DEVICE_EPOCH_DROPS: AtomicU64 = AtomicU64::new(0);
static STALE_EGRESS_STACK_GENERATION_DROPS: AtomicU64 = AtomicU64::new(0);
static RESETS: AtomicU64 = AtomicU64::new(0);
static TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static FAULT: AtomicBool = AtomicBool::new(false);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());

#[repr(C, align(64))]
struct DmaSlab {
    rx_desc: [u32; 8],
    tx_desc: [u32; 8],
    rx: [u8; DMA_BUFFER_LEN],
    tx: [u8; DMA_BUFFER_LEN],
}
impl DmaSlab {
    const ZERO: Self = Self {
        rx_desc: [0; 8],
        tx_desc: [0; 8],
        rx: [0; DMA_BUFFER_LEN],
        tx: [0; DMA_BUFFER_LEN],
    };
}
struct StableDma(UnsafeCell<DmaSlab>);
unsafe impl Sync for StableDma {}
#[link_section = ".dma"]
static DMA: StableDma = StableDma(UnsafeCell::new(DmaSlab::ZERO));

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

    if with_device_authority(&mmio, &dma, &control, || {
        initialize()?;
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
        shutdown_driver();
        return;
    }
    let _session = DriverSession;

    let mut pending_tx = None;
    let mut tx_deadline = 0;
    let mut link_poll = 0u16;
    loop {
        if FAULT.swap(false, Ordering::AcqRel) {
            panic!("injected CV1800B DWMAC fault");
        }
        if with_device_authority(&mmio, &dma, &control, || {
            driver_turn(
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

struct DriverSession;

impl Drop for DriverSession {
    fn drop(&mut self) {
        shutdown_driver();
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
        let descriptor_busy = tx_owned();
        state.tx_inflight = descriptor_busy || pending_tx.is_some();
        if pending_tx.is_none() && !descriptor_busy {
            if let Some(packet) = take_admitted_outbound(outbound, &state.sessions)? {
                *pending_tx = Some(packet);
                *tx_deadline = crate::sbi::time().saturating_add(tx_timeout_ticks());
                state.tx_inflight = true;
            }
        }
        if let Some(packet) = pending_tx.as_ref() {
            match transmit(packet) {
                Ok(()) => {
                    *pending_tx = None;
                    *tx_deadline = 0;
                    state.tx_inflight = true;
                }
                Err(NetError::QueueFull) if crate::sbi::time() < *tx_deadline => {}
                Err(NetError::QueueFull) => {
                    TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                    panic!("CV1800B DWMAC TX descriptor timed out");
                }
                Err(NetError::Protocol) => {
                    // A safely constructed Packet always fits the DMA buffer.
                    state.online = false;
                    return Err(NetError::Protocol);
                }
                Err(error) => return Err(error),
            }
        }

        // Keep the same rebind barrier from descriptor consumption through
        // exact session stamping, endpoint publication, and RX rearm. A stack
        // restart cannot relabel a raw frame after the driver consumes it.
        if let Some(packet) = receive() {
            match send_inbound(inbound, &state.sessions, packet) {
                Ok(()) => {
                    RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                }
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
        update_phy_link();
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
    for _ in 0..crate::virtio::SPLIT_QUEUE_SIZE {
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

fn initialize() -> Result<(), NetError> {
    write32(DMA_BUS_MODE, read32(DMA_BUS_MODE) | DMA_SOFT_RESET);
    for _ in 0..RESET_BUDGET {
        if read32(DMA_BUS_MODE) & DMA_SOFT_RESET == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    if read32(DMA_BUS_MODE) & DMA_SOFT_RESET != 0 {
        return Err(NetError::TimedOut);
    }
    RESETS.fetch_add(1, Ordering::Relaxed);

    let dma = unsafe { &mut *DMA.0.get() };
    *dma = DmaSlab::ZERO;
    dma.rx_desc[0] = DESC_OWN;
    dma.rx_desc[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
    dma.rx_desc[2] = buffer_address(&dma.rx) as u32;
    dma.tx_desc[0] = TX_END_RING;
    dma.tx_desc[2] = buffer_address(&dma.tx) as u32;
    clean_range(dma_base(), core::mem::size_of::<DmaSlab>());

    write32(DMA_BUS_MODE, DMA_ATDS | DMA_AAL | (8 << 8) | (8 << 17));
    write32(DMA_AXI_BUS_MODE, (1 << 12) | (1 << 1) | (1 << 2) | (1 << 3));
    write32(DMA_RX_DESC, descriptor_address(&dma.rx_desc) as u32);
    write32(DMA_TX_DESC, descriptor_address(&dma.tx_desc) as u32);
    write32(DMA_STATUS, 0xffff_ffff);
    write32(DMA_INT_ENABLE, 0);
    write32(
        GMAC_ADDR_HIGH,
        u32::from(GUEST_MAC[4]) | u32::from(GUEST_MAC[5]) << 8,
    );
    write32(
        GMAC_ADDR_LOW,
        u32::from_le_bytes([GUEST_MAC[0], GUEST_MAC[1], GUEST_MAC[2], GUEST_MAC[3]]),
    );
    write32(GMAC_FRAME_FILTER, 0);
    // The IO Board PHY negotiates 100/full in the normal case. MDIO remains
    // available for later link-change handling; start with the validated RMII
    // mode used by the vendor device tree.
    write32(
        GMAC_CONTROL,
        MAC_MII_PORT | MAC_FAST_ETHERNET | MAC_DUPLEX | MAC_ACS | MAC_RX_ENABLE | MAC_TX_ENABLE,
    );
    write32(
        DMA_CONTROL,
        DMA_FLUSH_TX | DMA_RX_STORE_FORWARD | DMA_TX_STORE_FORWARD | DMA_START_RX | DMA_START_TX,
    );
    write32(DMA_RX_POLL, 1);
    update_phy_link();
    let _ = read32(GMAC_MII_ADDR); // serialize the final MAC/DMA writes
    Ok(())
}

fn update_phy_link() {
    // Clause-22 registers are sufficient for the integrated 10/100 PHY. Read
    // BMSR twice because its link bit is latch-low, then select the best common
    // advertised mode. If no cable is present, retain the safe 100/full MAC
    // default and retry periodically without taking the interface offline.
    let Some(_) = mdio_read(1) else { return };
    let Some(status) = mdio_read(1) else { return };
    if status & (1 << 2) == 0 {
        return;
    }
    let control = mdio_read(0).unwrap_or(0);
    let (fast, full) = if control & (1 << 12) != 0 && status & (1 << 5) != 0 {
        let partner = mdio_read(5).unwrap_or(0);
        if partner & (1 << 8) != 0 {
            (true, true)
        } else if partner & (1 << 7) != 0 {
            (true, false)
        } else if partner & (1 << 6) != 0 {
            (false, true)
        } else {
            (false, false)
        }
    } else {
        (control & (1 << 13) != 0, control & (1 << 8) != 0)
    };
    let mut mac = read32(GMAC_CONTROL) & !(MAC_FAST_ETHERNET | MAC_DUPLEX);
    if fast {
        mac |= MAC_FAST_ETHERNET;
    }
    if full {
        mac |= MAC_DUPLEX;
    }
    write32(GMAC_CONTROL, mac);
}

fn mdio_read(register: u32) -> Option<u16> {
    for _ in 0..10_000 {
        if read32(GMAC_MII_ADDR) & MII_BUSY == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    if read32(GMAC_MII_ADDR) & MII_BUSY != 0 {
        return None;
    }
    write32(
        GMAC_MII_ADDR,
        PHY_ADDRESS << 11 | (register & 0x1f) << 6 | MII_CLOCK_RANGE_250MHZ | MII_BUSY,
    );
    for _ in 0..10_000 {
        if read32(GMAC_MII_ADDR) & MII_BUSY == 0 {
            return Some(read32(GMAC_MII_DATA) as u16);
        }
        core::hint::spin_loop();
    }
    None
}

fn transmit(packet: &Packet) -> Result<(), NetError> {
    let dma = unsafe { &mut *DMA.0.get() };
    invalidate_range(
        descriptor_address(&dma.tx_desc),
        core::mem::size_of_val(&dma.tx_desc),
    );
    if dma.tx_desc[0] & DESC_OWN != 0 {
        return Err(NetError::QueueFull);
    }
    let len = packet.len();
    if len > DMA_BUFFER_LEN {
        return Err(NetError::Protocol);
    }
    dma.tx[..len].copy_from_slice(packet.as_bytes());
    dma.tx_desc[1] = len as u32;
    dma.tx_desc[0] = TX_END_RING | TX_FIRST | TX_LAST | DESC_OWN;
    clean_range(buffer_address(&dma.tx), len);
    clean_range(
        descriptor_address(&dma.tx_desc),
        core::mem::size_of_val(&dma.tx_desc),
    );
    write32(DMA_TX_POLL, 1);
    TX_PACKETS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn receive() -> Option<Packet> {
    let dma = unsafe { &mut *DMA.0.get() };
    invalidate_range(
        descriptor_address(&dma.rx_desc),
        core::mem::size_of_val(&dma.rx_desc),
    );
    let status = dma.rx_desc[0];
    if status & DESC_OWN != 0 {
        return None;
    }
    let length_with_fcs = ((status >> 16) & 0x3fff) as usize;
    let valid = status & (RX_FIRST | RX_LAST) == RX_FIRST | RX_LAST && status & RX_ERROR == 0;
    let length = length_with_fcs.saturating_sub(4);
    let packet = if valid && (1..=MAX_PACKET_LEN).contains(&length) {
        invalidate_range(buffer_address(&dma.rx), length_with_fcs.min(DMA_BUFFER_LEN));
        Packet::copy_from(&dma.rx[..length]).ok()
    } else {
        None
    };
    dma.rx_desc[0] = DESC_OWN;
    dma.rx_desc[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
    clean_range(
        descriptor_address(&dma.rx_desc),
        core::mem::size_of_val(&dma.rx_desc),
    );
    write32(DMA_RX_POLL, 1);
    packet
}

fn tx_owned() -> bool {
    let dma = unsafe { &*DMA.0.get() };
    invalidate_range(
        descriptor_address(&dma.tx_desc),
        core::mem::size_of_val(&dma.tx_desc),
    );
    dma.tx_desc[0] & DESC_OWN != 0
}

fn dma_base() -> usize {
    DMA.0.get() as usize
}
fn descriptor_address(value: &[u32; 8]) -> usize {
    value.as_ptr() as usize
}
fn buffer_address(value: &[u8; DMA_BUFFER_LEN]) -> usize {
    value.as_ptr() as usize
}

fn clean_range(start: usize, size: usize) {
    cache_range(start, size, 0x0295_000b);
}
fn invalidate_range(start: usize, size: usize) {
    cache_range(start, size, 0x02b5_000b);
}
fn cache_range(start: usize, size: usize, instruction: u32) {
    let mut line = start & !63;
    let end = start.saturating_add(size).saturating_add(63) & !63;
    while line < end {
        // T-Head C9xx cache operations encode the address in a0. Use the raw
        // instruction words documented by Milk-V's pinned FSBL source.
        unsafe {
            if instruction == 0x0295_000b {
                core::arch::asm!(".long 0x0295000b", in("a0") line, options(nostack));
            } else {
                core::arch::asm!(".long 0x02b5000b", in("a0") line, options(nostack));
            }
        }
        line += 64;
    }
    unsafe {
        core::arch::asm!(".long 0x0190000b", options(nostack));
    }
}

#[inline]
fn read32(offset: usize) -> u32 {
    unsafe { ((BASE + offset) as *const u32).read_volatile() }
}
#[inline]
fn write32(offset: usize, value: u32) {
    unsafe { ((BASE + offset) as *mut u32).write_volatile(value) }
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

fn shutdown_driver() {
    write32(DMA_INT_ENABLE, 0);
    write32(DMA_CONTROL, 0);
    write32(
        GMAC_CONTROL,
        read32(GMAC_CONTROL) & !(MAC_RX_ENABLE | MAC_TX_ENABLE),
    );
    write32(DMA_BUS_MODE, read32(DMA_BUS_MODE) | DMA_SOFT_RESET);
    let mut reset = false;
    for _ in 0..RESET_BUDGET {
        if read32(DMA_BUS_MODE) & DMA_SOFT_RESET == 0 {
            reset = true;
            break;
        }
        core::hint::spin_loop();
    }
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
    shutdown_driver();
}

#[allow(dead_code)]
pub fn debug_waiter_count() -> usize {
    0
}
