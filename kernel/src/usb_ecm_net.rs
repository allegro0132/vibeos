//! Independent CDC-ECM network component over the shared Milk-V DWC2 host.
//!
//! DWC2 retains controller DMA, topology and IRQ ownership. This component
//! owns only one ECM packet session, its bounded endpoints and its recovery
//! state, so it can run concurrently with the native DWMAC component.

extern crate alloc;

use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{Cap, InvocationLease, Resource, Revocable, Rights};
use crate::heap::{AllocationDomain, ArenaId, OwnerId};
use crate::net::{
    Endpoint, Packet, PacketSessionError, PacketSessionFence, PacketStamp, StampedPacket,
    MAX_PACKET_LEN,
};
use crate::sync::SpinLock;
use crate::world::Space;

const TX_TIMEOUT_MS: u64 = 2_000;
pub const FALLBACK_MAC: [u8; 6] = [0x02, 0, 0, 0, 1, 1];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    Offline,
    QueueFull,
    TimedOut,
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
            Self::Offline => "USB Ethernet device is offline",
            Self::QueueFull => "USB Ethernet packet queue is full",
            Self::TimedOut => "USB Ethernet transmit timed out",
            Self::DriverFault => "USB Ethernet driver faulted",
            Self::Protocol => "USB Ethernet frame was malformed",
            Self::Quarantined => "USB Ethernet interface is quarantined",
            Self::AuthorityRevoked => "USB Ethernet capability is absent or revoked",
            Self::PermissionDenied => "USB Ethernet capability lacks the required right",
            Self::SessionBusy => "the previous USB packet session still has transmit work",
            Self::SessionInactive => "no packet stack is bound to this USB interface",
            Self::IdentityExhausted => "USB packet-session identity space is exhausted",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetInfo {
    pub online: bool,
    pub carrier_up: bool,
    pub quarantined: bool,
    pub session_epoch: u64,
    pub stack_generation: u64,
    pub ethernet_address: [u8; 6],
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub stale_ingress_drops: u64,
    pub stale_egress_drops: u64,
    pub timeouts: u64,
    pub tx_inflight: bool,
}

/// Narrow authority for ECM class transactions. It does not expose DWC2 MMIO,
/// the controller DMA buffer, hub topology or other USB functions.
pub struct EcmTransport;

impl Resource for EcmTransport {
    fn kind(&self) -> &'static str {
        "usb-cdc-ecm-transport"
    }

    fn describe(&self) -> String {
        String::from("CDC-ECM class transport through the supervised DWC2 host")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct Control {
    sessions: PacketSessionFence,
    active_stack_domain: Option<AllocationDomain>,
    online: bool,
    carrier_up: bool,
    quarantined: bool,
    ethernet_address: [u8; 6],
    tx_inflight: bool,
}

/// Instance-owned network session and telemetry. Unlike the former DWMAC/USB
/// mux, none of this state is shared with the native MAC.
pub struct NetDevice {
    control: SpinLock<Control>,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    stale_ingress_drops: AtomicU64,
    stale_egress_drops: AtomicU64,
    timeouts: AtomicU64,
    fault_requested: AtomicBool,
    driver_owner: AtomicU64,
    driver_arena: AtomicU64,
}

impl NetDevice {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            control: SpinLock::new_recoverable(Control {
                sessions: PacketSessionFence::new(),
                active_stack_domain: None,
                online: false,
                carrier_up: false,
                quarantined: false,
                ethernet_address: FALLBACK_MAC,
                tx_inflight: false,
            }),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            stale_ingress_drops: AtomicU64::new(0),
            stale_egress_drops: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            fault_requested: AtomicBool::new(false),
            driver_owner: AtomicU64::new(OwnerId::SYSTEM.get()),
            driver_arena: AtomicU64::new(ArenaId::UNTRACKED.get()),
        })
    }

    fn info(&self) -> NetInfo {
        let control = self.control.lock();
        NetInfo {
            online: control.online,
            carrier_up: control.carrier_up,
            quarantined: control.quarantined,
            session_epoch: control.sessions.device_epoch(),
            stack_generation: control
                .sessions
                .active_stamp()
                .map_or(0, PacketStamp::stack_generation),
            ethernet_address: control.ethernet_address,
            rx_packets: self.rx_packets.load(Ordering::Acquire),
            tx_packets: self.tx_packets.load(Ordering::Acquire),
            stale_ingress_drops: self.stale_ingress_drops.load(Ordering::Acquire),
            stale_egress_drops: self.stale_egress_drops.load(Ordering::Acquire),
            timeouts: self.timeouts.load(Ordering::Acquire),
            tx_inflight: control.tx_inflight,
        }
    }

    fn detach(&self) {
        let _ = self.link_down();
        self.driver_owner
            .store(OwnerId::SYSTEM.get(), Ordering::Release);
        self.driver_arena
            .store(ArenaId::UNTRACKED.get(), Ordering::Release);
    }

    fn link_down(&self) -> bool {
        let mut control = self.control.lock();
        let was_online = control.online;
        control.online = false;
        control.carrier_up = false;
        control.sessions.detach_device();
        control.active_stack_domain = None;
        control.tx_inflight = false;
        was_online
    }
}

impl Resource for NetDevice {
    fn kind(&self) -> &'static str {
        "usb-network-device"
    }

    fn describe(&self) -> String {
        let info = self.info();
        format!(
            "USB CDC-ECM [online {}, rx {}, tx {}, epoch {}]",
            info.online, info.rx_packets, info.tx_packets, info.session_epoch,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct NetResources {
    pub location: crate::net_device::NetworkLocation,
    pub transport: Arc<EcmTransport>,
    pub control: Arc<NetDevice>,
}

pub fn discover() -> Option<NetResources> {
    let path = crate::dwc2_host::network_bus_path()?;
    let mut ports = [0; 8];
    ports[..path.ports.len()].copy_from_slice(&path.ports);
    Some(NetResources {
        location: crate::net_device::NetworkLocation::Usb {
            controller: crate::platform::DWC2.registers.start,
            ports,
            depth: path.depth,
        },
        transport: Arc::new(EcmTransport),
        control: NetDevice::new(),
    })
}

pub fn info_with(lease: &InvocationLease<NetDevice>) -> Result<NetInfo, NetError> {
    if !lease.authorizes(Rights::READ) {
        return Err(NetError::PermissionDenied);
    }
    Ok(lease.with(NetDevice::info))
}

pub fn bind_stack_with(lease: &InvocationLease<NetDevice>) -> Result<PacketStamp, NetError> {
    if !lease.authorizes(Rights::INVOKE) {
        return Err(NetError::PermissionDenied);
    }
    lease.with(|device| {
        let mut control = device.control.lock();
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

pub fn inject_fault_with(lease: &InvocationLease<NetDevice>) -> Result<(), NetError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(NetError::PermissionDenied);
    }
    lease.with(|device| device.fault_requested.store(true, Ordering::Release));
    Ok(())
}

static ACTIVE_DEVICE: SpinLock<Option<Revocable<NetDevice>>> = SpinLock::new(None);

pub async fn driver_task(
    space: &'static Space,
    transport: Cap,
    outbound: Cap,
    inbound: Cap,
    control: Cap,
) {
    let authority = {
        let cspace = space.0.lock();
        (
            cspace.lookup_revocable::<EcmTransport>(transport, Rights::READ.union(Rights::WRITE)),
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(outbound, Rights::RECV),
            cspace.lookup_revocable::<Endpoint<StampedPacket>>(inbound, Rights::SEND),
            cspace.lookup_revocable::<NetDevice>(control, Rights::READ),
        )
    };
    let (Ok(transport), Ok(outbound), Ok(inbound), Ok(control)) = authority else {
        crate::println!("  usb net   driver capability lookup failed");
        return;
    };

    let domain = crate::heap::current_domain();
    if control
        .try_with(|device| {
            device
                .driver_owner
                .store(domain.owner.get(), Ordering::Release);
            device
                .driver_arena
                .store(domain.arena.get(), Ordering::Release);
        })
        .is_err()
    {
        return;
    }
    *ACTIVE_DEVICE.lock() = Some(control.clone());
    let _guard = DriverGuard {
        control: control.clone(),
    };
    let mut pending_tx = None;
    let mut tx_deadline = 0;
    let mut next_carrier_poll = 0;
    let mut carrier_observed = false;

    loop {
        let turn = transport.try_with(|_| {
            control.try_with(|device| {
                if device.fault_requested.swap(false, Ordering::AcqRel) {
                    panic!("injected USB CDC-ECM network fault");
                }
                driver_turn(
                    device,
                    &outbound,
                    &inbound,
                    &mut pending_tx,
                    &mut tx_deadline,
                    &mut next_carrier_poll,
                    &mut carrier_observed,
                )
            })
        });
        match turn {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(NetError::Offline))) => {
                if matches!(control.try_with(NetDevice::link_down), Ok(true)) {
                    crate::println!("  usb net   CDC-ECM offline");
                }
                pending_tx = None;
                tx_deadline = 0;
                next_carrier_poll = 0;
                carrier_observed = false;
            }
            Ok(Ok(Err(error))) => {
                crate::println!("  usb net   driver stopped: {error:?}");
                return;
            }
            _ => return,
        }
        crate::exec::sleep_ms(1).await;
    }
}

struct DriverGuard {
    control: Revocable<NetDevice>,
}

impl Drop for DriverGuard {
    fn drop(&mut self) {
        let _ = self.control.try_with(NetDevice::detach);
    }
}

fn driver_turn(
    device: &NetDevice,
    outbound: &Revocable<Endpoint<StampedPacket>>,
    inbound: &Revocable<Endpoint<StampedPacket>>,
    pending_tx: &mut Option<Packet>,
    tx_deadline: &mut u64,
    next_carrier_poll: &mut u64,
    carrier_observed: &mut bool,
) -> Result<(), NetError> {
    let ecm = crate::dwc2_host::snapshot().and_then(|snapshot| snapshot.cdc_ecm);
    let Some(ecm) = ecm else {
        *pending_tx = None;
        *tx_deadline = 0;
        return Err(NetError::Offline);
    };

    let mut control = device.control.lock();
    if !control.online {
        if control.sessions.attach_device().is_err() {
            control.online = false;
            control.quarantined = true;
            return Err(NetError::IdentityExhausted);
        }
        control.active_stack_domain = None;
        control.ethernet_address = ecm.mac_address.unwrap_or(FALLBACK_MAC);
        control.online = true;
        control.carrier_up = false;
        control.quarantined = false;
        control.tx_inflight = false;
        crate::println!(
            "  usb net   CDC-ECM online, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, epoch {}",
            control.ethernet_address[0],
            control.ethernet_address[1],
            control.ethernet_address[2],
            control.ethernet_address[3],
            control.ethernet_address[4],
            control.ethernet_address[5],
            control.sessions.device_epoch(),
        );
    }

    let now = crate::sbi::time();
    if now >= *next_carrier_poll {
        *next_carrier_poll = now.saturating_add(
            u64::from(ecm.status_interval_ms).saturating_mul(crate::exec::timebase_hz()) / 1_000,
        );
        match crate::dwc2_host::poll_cdc_ecm_carrier() {
            Ok(status) if status.link_up.is_some() => {
                let carrier_up = status.link_up.expect("matched present carrier status");
                if !*carrier_observed || carrier_up != control.carrier_up {
                    if let Some(raw) = status.rtl815x_phystatus {
                        crate::println!(
                            "  usb net   RTL815x carrier {}, PHYSTATUS {:#06x}",
                            if carrier_up { "up" } else { "down" },
                            raw,
                        );
                    } else {
                        crate::println!(
                            "  usb net   CDC-ECM carrier {}",
                            if carrier_up { "up" } else { "down" }
                        );
                    }
                }
                *carrier_observed = true;
                control.carrier_up = carrier_up;
            }
            Ok(_) => {}
            Err(vibeos_driver_dwc2_host::Error::NoDevice) => return Err(NetError::Offline),
            Err(vibeos_driver_dwc2_host::Error::InvalidDescriptor)
                if ecm.status_endpoint.is_none() => {}
            Err(_) => return Err(NetError::DriverFault),
        }
    }

    if !control.carrier_up {
        *pending_tx = None;
        *tx_deadline = 0;
        control.tx_inflight = false;
        return Ok(());
    }

    if pending_tx.is_none() {
        if let Some(packet) = take_admitted_outbound(device, outbound, &control.sessions)? {
            *pending_tx = Some(packet);
            *tx_deadline = now.saturating_add(tx_timeout_ticks());
        }
    }
    control.tx_inflight = pending_tx.is_some();
    if let Some(packet) = pending_tx.as_ref() {
        match crate::dwc2_host::transmit_cdc_ecm(packet.as_bytes()) {
            Ok(()) => {
                *pending_tx = None;
                *tx_deadline = 0;
                control.tx_inflight = false;
                device.tx_packets.fetch_add(1, Ordering::Relaxed);
            }
            Err(vibeos_driver_dwc2_host::Error::Nak) if now < *tx_deadline => {}
            Err(vibeos_driver_dwc2_host::Error::Nak) => {
                device.timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(NetError::TimedOut);
            }
            Err(vibeos_driver_dwc2_host::Error::NoDevice) => return Err(NetError::Offline),
            Err(_) => return Err(NetError::DriverFault),
        }
    }

    let mut frame = [0; MAX_PACKET_LEN];
    match crate::dwc2_host::receive_cdc_ecm(&mut frame) {
        Ok(length) => {
            let packet = Packet::copy_from(&frame[..length]).map_err(|_| NetError::Protocol)?;
            if send_inbound(device, inbound, &control.sessions, packet)? {
                device.rx_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(
            vibeos_driver_dwc2_host::Error::Nak | vibeos_driver_dwc2_host::Error::TransferTimedOut,
        ) => {}
        Err(vibeos_driver_dwc2_host::Error::NoDevice) => return Err(NetError::Offline),
        Err(_) => return Err(NetError::DriverFault),
    }
    Ok(())
}

fn take_admitted_outbound(
    device: &NetDevice,
    outbound: &Revocable<Endpoint<StampedPacket>>,
    sessions: &PacketSessionFence,
) -> Result<Option<Packet>, NetError> {
    for _ in 0..crate::net_device::FRONTEND_QUEUE_DEPTH {
        let packet = outbound
            .try_with(Endpoint::try_recv)
            .map_err(|_| NetError::AuthorityRevoked)?;
        let Some(packet) = packet else {
            return Ok(None);
        };
        match sessions.accept_egress(packet) {
            Ok(packet) => return Ok(Some(packet)),
            Err(PacketSessionError::Inactive | PacketSessionError::StampMismatch(_)) => {
                device.stale_egress_drops.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => unreachable!(),
        }
    }
    Ok(None)
}

fn send_inbound(
    device: &NetDevice,
    inbound: &Revocable<Endpoint<StampedPacket>>,
    sessions: &PacketSessionFence,
    packet: Packet,
) -> Result<bool, NetError> {
    let packet = match sessions.stamp_ingress(packet) {
        Ok(packet) => packet,
        Err(PacketSessionError::Inactive) => {
            device.stale_ingress_drops.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        Err(_) => unreachable!(),
    };
    match inbound
        .try_with(|endpoint| endpoint.try_send(packet))
        .map_err(|_| NetError::AuthorityRevoked)?
    {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn tx_timeout_ticks() -> u64 {
    TX_TIMEOUT_MS.saturating_mul(crate::exec::timebase_hz()) / 1_000
}

/// # Safety
/// The executor guarantees that the faulting domain can never resume.
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) {
    let active = ACTIVE_DEVICE.lock().clone();
    let Some(active) = active else {
        return;
    };
    let _ = active.try_with(|device| {
        let _ = unsafe { device.control.recover_after_fault(domain) };
        let mut control = device.control.lock();
        if control.active_stack_domain == Some(domain) {
            control.sessions.unbind_stack();
            control.active_stack_domain = None;
        }
        if device.driver_owner.load(Ordering::Acquire) == domain.owner.get()
            && device.driver_arena.load(Ordering::Acquire) == domain.arena.get()
        {
            control.online = false;
            control.sessions.detach_device();
            control.tx_inflight = false;
            device
                .driver_owner
                .store(OwnerId::SYSTEM.get(), Ordering::Release);
            device
                .driver_arena
                .store(ArenaId::UNTRACKED.get(), Ordering::Release);
        }
    });
}
