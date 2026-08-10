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
const DMA_CACHE_LINE_BYTES: usize = 64;
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
const RX_END_RING: u32 = 1 << 25;
const TX_END_RING: u32 = 1 << 25;
const TX_FIRST: u32 = 1 << 29;
const TX_LAST: u32 = 1 << 30;

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
        format!(
            "DWMAC stable cache-isolated two-descriptor slab @ {:#x}",
            dma_base()
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
            phy_link_up: PHY_LINK_UP.load(Ordering::Acquire),
            tx_descriptor_status: tx_status(),
            dma_status: read32(DMA_STATUS),
            clock_enable: soc_read32(CLK_ENABLE_0),
            clock_bypass: soc_read32(CLK_BYPASS_0),
            clock_divider: soc_read32(CLK_DIV_500M_ETH0),
            ephy_control: soc_read32(EPHY_TOP_WRAP),
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
static PHY_LINK_UP: AtomicBool = AtomicBool::new(false);
static DRIVER_OWNER: AtomicU64 = AtomicU64::new(OwnerId::SYSTEM.get());
static DRIVER_ARENA: AtomicU64 = AtomicU64::new(ArenaId::UNTRACKED.get());

#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct DmaDescriptorSlot {
    // CV1800B uses the legacy normal four-word descriptor format. The explicit
    // 64-byte slot prevents a cache operation for one DMA direction from
    // writing back stale ownership state for the other direction.
    words: [u32; 16],
}
impl DmaDescriptorSlot {
    const ZERO: Self = Self { words: [0; 16] };
}

#[repr(C, align(64))]
struct DmaSlab {
    rx_desc: DmaDescriptorSlot,
    tx_desc: DmaDescriptorSlot,
    rx: [u8; DMA_BUFFER_LEN],
    tx: [u8; DMA_BUFFER_LEN],
}
impl DmaSlab {
    const ZERO: Self = Self {
        rx_desc: DmaDescriptorSlot::ZERO,
        tx_desc: DmaDescriptorSlot::ZERO,
        rx: [0; DMA_BUFFER_LEN],
        tx: [0; DMA_BUFFER_LEN],
    };
}

const _: () = {
    assert!(core::mem::size_of::<DmaDescriptorSlot>() == DMA_CACHE_LINE_BYTES);
    assert!(core::mem::align_of::<DmaDescriptorSlot>() == DMA_CACHE_LINE_BYTES);
    assert!(core::mem::offset_of!(DmaSlab, rx_desc) % DMA_CACHE_LINE_BYTES == 0);
    assert!(core::mem::offset_of!(DmaSlab, tx_desc) % DMA_CACHE_LINE_BYTES == 0);
    assert!(core::mem::offset_of!(DmaSlab, rx) % DMA_CACHE_LINE_BYTES == 0);
    assert!(core::mem::offset_of!(DmaSlab, tx) % DMA_CACHE_LINE_BYTES == 0);
};
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
        let now = crate::sbi::time();
        let descriptor_busy = tx_owned();
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
            match transmit(packet) {
                Ok(()) => {
                    *pending_tx = None;
                    state.tx_inflight = true;
                }
                Err(NetError::QueueFull) if now < *tx_deadline => {}
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
    prepare_soc_hardware();
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
    dma.rx_desc.words[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
    dma.rx_desc.words[2] = buffer_address(&dma.rx) as u32;
    dma.rx_desc.words[0] = DESC_OWN;
    dma.tx_desc.words[1] = TX_END_RING;
    dma.tx_desc.words[2] = buffer_address(&dma.tx) as u32;
    clean_range(dma_base(), core::mem::size_of::<DmaSlab>());

    // The Duo device tree uses the DWMAC normal four-word descriptor format;
    // it does not opt into snps,enh-desc. Keep ATDS clear and place TX frame
    // control in descriptor word 1 exactly like the pinned stmmac driver.
    write32(DMA_BUS_MODE, DMA_AAL | (8 << 8) | (8 << 17));
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
    let Some(_) = mdio_read(1) else {
        PHY_LINK_UP.store(false, Ordering::Release);
        return;
    };
    let Some(status) = mdio_read(1) else {
        PHY_LINK_UP.store(false, Ordering::Release);
        return;
    };
    if status & (1 << 2) == 0 {
        PHY_LINK_UP.store(false, Ordering::Release);
        return;
    }
    PHY_LINK_UP.store(true, Ordering::Release);
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
    if dma.tx_desc.words[0] & DESC_OWN != 0 {
        return Err(NetError::QueueFull);
    }
    let len = packet.len();
    if len > DMA_BUFFER_LEN {
        return Err(NetError::Protocol);
    }
    dma.tx[..len].copy_from_slice(packet.as_bytes());
    dma.tx_desc.words[1] = len as u32 | TX_END_RING | TX_FIRST | TX_LAST;
    dma.tx_desc.words[0] = DESC_OWN;
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
    let status = dma.rx_desc.words[0];
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
    dma.rx_desc.words[1] = DMA_BUFFER_LEN as u32 | RX_END_RING;
    dma.rx_desc.words[0] = DESC_OWN;
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
    dma.tx_desc.words[0] & DESC_OWN != 0
}

fn tx_status() -> u32 {
    let dma = unsafe { &*DMA.0.get() };
    invalidate_range(
        descriptor_address(&dma.tx_desc),
        core::mem::size_of_val(&dma.tx_desc),
    );
    dma.tx_desc.words[0]
}

const CLKGEN_BASE: usize = crate::platform::SOC_CONTROL_BASE + 0x2000;
const CLK_ENABLE_0: usize = CLKGEN_BASE;
const CLK_BYPASS_0: usize = CLKGEN_BASE + 0x30;
const CLK_DIV_500M_ETH0: usize = CLKGEN_BASE + 0x8c;
const EPHY_BASE: usize = crate::platform::SOC_CONTROL_BASE + 0x9000;
const EPHY_TOP_WRAP: usize = EPHY_BASE + 0x800;
const EPHY_PAGE: usize = EPHY_BASE + 0x7c;
const EFUSE_SHADOW: usize = crate::platform::EFUSE_BASE + 0x100;
const ETH0_CLOCKS: u32 = (1 << 11) | (1 << 25) | (1 << 26);

fn prepare_soc_hardware() {
    // The pinned CV1800B clock driver marks ETH0's 500 MHz MAC clock and
    // AXI4 clock critical. U-Boot does not instantiate Ethernet for this
    // image, so take ownership explicitly instead of depending on reset
    // defaults left by an earlier firmware stage.
    soc_write32(CLK_ENABLE_0, soc_read32(CLK_ENABLE_0) | ETH0_CLOCKS);
    soc_write32(CLK_BYPASS_0, soc_read32(CLK_BYPASS_0) & !(1 << 9));
    // Bit 3 is the vendor clock driver's divider-update strobe.
    soc_write32(
        CLK_DIV_500M_ETH0,
        (soc_read32(CLK_DIV_500M_ETH0) & !(0xf << 16)) | (3 << 16) | (1 << 3),
    );
    prepare_ephy();
    let _ = soc_read32(CLK_ENABLE_0);
}

fn prepare_ephy() {
    // The CV1800B PHY is integrated but its analogue wave-shaping tables are
    // not reset defaults. Linux installs this sequence in cvitek.c when the
    // PHY is bound; a bare-metal boot must do the same before MAC traffic.
    soc_write32(EPHY_TOP_WRAP + 4, 1); // direct APB access
    soc_write32(EPHY_TOP_WRAP, 0x0900); // release shutdown
    soc_write32(EPHY_TOP_WRAP, 0x0904); // release digital reset
    delay_ms(10);
    ephy_page(5);
    ephy_write(0x40, 0x0c7e); // release analogue power-down and enables
    delay_ms(1);
    soc_write32(EPHY_TOP_WRAP, 0x0906); // release analogue reset

    ephy_page(0);
    let efuse20 = soc_read32(EFUSE_SHADOW + 0x20);
    let efuse24 = soc_read32(EFUSE_SHADOW + 0x24);
    let tx_tune = if efuse20 & 0x0000_0200 != 0 {
        (efuse24 >> 24 & 0xff) | (efuse24 >> 8 & 0xff00)
    } else {
        0x5a5a
    };
    ephy_write(0x64, tx_tune);
    let echo_current = if efuse20 & 0x0000_0100 != 0 {
        efuse24 & 0x0000_ff00
    } else {
        0
    };
    ephy_write(0x54, echo_current);
    let termination = if efuse20 & 0x0000_0800 != 0 {
        ((efuse20 >> 24) & 0xf0) | ((efuse20 >> 16) & 0x0f00)
    } else {
        0x0bb0
    };
    ephy_write(0x58, (ephy_read(0x58) & !0x0ff0) | termination);
    ephy_write(0x5c, 0x0c10);
    ephy_write(0x68, 0x0003);
    ephy_write(0x54, 0x0000);

    ephy_write_page(
        16,
        &[
            (0x68, 0x1000),
            (0x6c, 0x3020),
            (0x70, 0x5040),
            (0x74, 0x7060),
            (0x58, 0x1708),
            (0x5c, 0x3827),
            (0x60, 0x5748),
            (0x64, 0x7867),
        ],
    );
    ephy_write_page(
        17,
        &[
            (0x40, 0x9080),
            (0x44, 0xb0a0),
            (0x48, 0xd0c0),
            (0x4c, 0xf0e0),
            (0x50, 0x9788),
            (0x54, 0xb8a7),
            (0x58, 0xd7c8),
            (0x5c, 0xf8e7),
        ],
    );
    ephy_page(5);
    ephy_write(0x40, ephy_read(0x40) | 0x0001);
    ephy_write(0x4c, ephy_read(0x4c) | 0x0820);
    ephy_write_page(
        10,
        &[
            (0x40, 0x3e00),
            (0x44, 0x7864),
            (0x48, 0x6470),
            (0x4c, 0x5f62),
            (0x50, 0x5a5a),
            (0x54, 0x5458),
            (0x58, 0xb23a),
            (0x5c, 0x94a0),
            (0x60, 0x9092),
            (0x64, 0x8a8e),
            (0x68, 0x8688),
            (0x6c, 0x8484),
            (0x70, 0x0082),
        ],
    );
    ephy_write_page(
        11,
        &[
            (0x40, 0x5252),
            (0x44, 0x5252),
            (0x48, 0x4b52),
            (0x4c, 0x3d47),
            (0x50, 0xaa99),
            (0x54, 0x989e),
            (0x58, 0x9395),
            (0x5c, 0x9091),
            (0x60, 0x8e8f),
            (0x64, 0x8d8e),
            (0x68, 0x8c8c),
            (0x6c, 0x8b8b),
            (0x70, 0x008a),
        ],
    );
    ephy_write_page(
        13,
        &[
            (0x40, 0x1e0a),
            (0x44, 0x3862),
            (0x48, 0x1e62),
            (0x4c, 0x2a08),
            (0x50, 0x244c),
            (0x54, 0x1a44),
            (0x58, 0x061c),
        ],
    );
    ephy_write_page(
        14,
        &[
            (0x40, 0x2d30),
            (0x44, 0x3470),
            (0x48, 0x0648),
            (0x4c, 0x261c),
            (0x50, 0x3160),
            (0x54, 0x2d5e),
        ],
    );
    ephy_write_page(
        15,
        &[
            (0x40, 0x2922),
            (0x44, 0x366e),
            (0x48, 0x0752),
            (0x4c, 0x2556),
            (0x50, 0x2348),
            (0x54, 0x0c30),
        ],
    );
    ephy_write_page(
        16,
        &[
            (0x40, 0x1e08),
            (0x44, 0x3868),
            (0x48, 0x1462),
            (0x4c, 0x1a0e),
            (0x50, 0x305e),
            (0x54, 0x2f62),
        ],
    );
    ephy_page(1);
    ephy_write(0x68, ephy_read(0x68) & !0x0f00);
    ephy_write_page(19, &[(0x58, 0x0012), (0x5c, 0x6848)]);
    ephy_write_page(
        18,
        &[
            (0x48, 0x0801),
            (0x4c, 0x1717),
            (0x5c, 0x0108),
            (0x50, 0x3afc),
            (0x54, 0x08d3),
            (0x60, 0x00fb),
        ],
    );
    ephy_page(0);
    soc_write32(EPHY_TOP_WRAP, 0x090e); // start auto-negotiation
    ephy_write(0, ephy_read(0) | 0x0100); // force full-duplex reset default
    soc_write32(EPHY_TOP_WRAP + 4, 0); // return MII registers to MAC MDIO
}

fn ephy_write_page(page: u32, values: &[(usize, u32)]) {
    ephy_page(page);
    for &(offset, value) in values {
        ephy_write(offset, value);
    }
}

fn ephy_page(page: u32) {
    soc_write32(EPHY_PAGE, page << 8);
}

fn ephy_read(offset: usize) -> u32 {
    soc_read32(EPHY_BASE + offset)
}

fn ephy_write(offset: usize, value: u32) {
    soc_write32(EPHY_BASE + offset, value);
}

fn delay_ms(milliseconds: u64) {
    let ticks = milliseconds.saturating_mul(crate::platform::TIMEBASE_HZ) / 1_000;
    let deadline = crate::sbi::time().saturating_add(ticks);
    while crate::sbi::time() < deadline {
        core::hint::spin_loop();
    }
}

#[inline]
fn soc_read32(address: usize) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}

#[inline]
fn soc_write32(address: usize, value: u32) {
    unsafe { (address as *mut u32).write_volatile(value) }
}

fn dma_base() -> usize {
    DMA.0.get() as usize
}
fn descriptor_address(value: &DmaDescriptorSlot) -> usize {
    value.words.as_ptr() as usize
}
fn buffer_address(value: &[u8; DMA_BUFFER_LEN]) -> usize {
    value.as_ptr() as usize
}

fn clean_range(start: usize, size: usize) {
    cache_range(start, size, true);
}
fn invalidate_range(start: usize, size: usize) {
    cache_range(start, size, false);
}
fn cache_range(start: usize, size: usize, clean: bool) {
    let mut line = start & !(DMA_CACHE_LINE_BYTES - 1);
    let end = start
        .saturating_add(size)
        .saturating_add(DMA_CACHE_LINE_BYTES - 1)
        & !(DMA_CACHE_LINE_BYTES - 1);
    while line < end {
        // T-Head C9xx cache operations encode the address in a0. Use the raw
        // instruction words documented by Milk-V's pinned FSBL source. DMA
        // reads require dcache.cpa (clean); DMA writes require dcache.ipa
        // (invalidate). dcache.cipa (0x02b5000b) is deliberately not used for
        // device-written state because its clean phase can restore stale OWN.
        unsafe {
            if clean {
                core::arch::asm!(".long 0x0295000b", in("a0") line, options(nostack));
            } else {
                core::arch::asm!(".long 0x02a5000b", in("a0") line, options(nostack));
            }
        }
        line += DMA_CACHE_LINE_BYTES;
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
    PHY_LINK_UP.store(false, Ordering::Release);
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
