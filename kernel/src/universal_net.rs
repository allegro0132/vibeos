//! One admitted network backend, with a shared control-capability type.
use crate::net::{Packet, PacketStamp};
use crate::{
    cap::{Cap, InvocationLease, Resource},
    heap::AllocationDomain,
    world::Space,
};
use alloc::{format, string::String, sync::Arc};
use core::any::Any;
use vibeos_hal::runtime_platform::{get, NetworkBackend};
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

pub struct NetDevice;
impl NetDevice {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self)
    }
    pub(crate) fn info(&self) -> NetInfo {
        match get().network_backend {
            NetworkBackend::Packet => crate::dwmac_net::universal_info(),
            NetworkBackend::Queued => crate::virtio_net::universal_info(),
            NetworkBackend::None => NetInfo::default(),
        }
    }
}
impl Resource for NetDevice {
    fn kind(&self) -> &'static str {
        "network-device"
    }
    fn describe(&self) -> String {
        let i = self.info();
        format!(
            "{} [online {}, epoch {}]",
            get().platform.network_driver_name,
            i.online,
            i.session_epoch
        )
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
pub type MmioWindow = dyn Resource;
pub type DmaRegion = dyn Resource;
pub struct NetResources {
    pub location: crate::net_device::NetworkLocation,
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub control: Arc<NetDevice>,
}
pub fn discover() -> Option<NetResources> {
    match get().network_backend {
        NetworkBackend::Packet => {
            let r = crate::dwmac_net::discover()?;
            Some(NetResources {
                location: r.location,
                mmio: r.mmio,
                dma: r.dma,
                control: r.control,
            })
        }
        NetworkBackend::Queued => {
            let r = crate::virtio_net::discover()?;
            Some(NetResources {
                location: r.location,
                mmio: r.mmio,
                dma: r.dma,
                control: r.control,
            })
        }
        NetworkBackend::None => None,
    }
}
#[allow(unused_imports)]
pub use crate::virtio_net::{GUEST_MAC, HANDSHAKE_ETHERTYPE, HANDSHAKE_FRAME_LEN, PEER_MAC};
pub fn carrier_up(i: &NetInfo) -> bool {
    i.phy_link_up
}
pub fn tx_checksum_offload(i: &NetInfo) -> bool {
    i.tx_checksum_offload
}
pub fn rx_checksum_offload(i: &NetInfo) -> bool {
    i.rx_checksum_offload
}
pub fn info_with(lease: &InvocationLease<NetDevice>) -> Result<NetInfo, NetError> {
    match get().network_backend {
        NetworkBackend::Packet => crate::dwmac_net::info_with(lease),
        NetworkBackend::Queued => crate::virtio_net::info_with(lease),
        NetworkBackend::None => Err(NetError::Offline),
    }
}
pub fn inject_fault_with(lease: &InvocationLease<NetDevice>) -> Result<(), NetError> {
    match get().network_backend {
        NetworkBackend::Packet => crate::dwmac_net::inject_fault_with(lease),
        NetworkBackend::Queued => crate::virtio_net::inject_fault_with(lease),
        NetworkBackend::None => Err(NetError::Offline),
    }
}
pub fn bind_stack_with(lease: &InvocationLease<NetDevice>) -> Result<PacketStamp, NetError> {
    match get().network_backend {
        NetworkBackend::Packet => crate::dwmac_net::bind_stack_with(lease),
        NetworkBackend::Queued => crate::virtio_net::bind_stack_with(lease),
        NetworkBackend::None => Err(NetError::Offline),
    }
}
pub async fn driver_task(
    space: &'static Space,
    mmio: Cap,
    dma: Cap,
    outbound: Cap,
    inbound: Cap,
    control: Cap,
) -> () {
    match get().network_backend {
        NetworkBackend::Packet => {
            crate::dwmac_net::driver_task(space, mmio, dma, outbound, inbound, control).await
        }
        NetworkBackend::Queued => {
            crate::virtio_net::driver_task(space, mmio, dma, outbound, inbound, control).await
        }
        NetworkBackend::None => (),
    }
}
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) -> () {
    match get().network_backend {
        NetworkBackend::Packet => crate::dwmac_net::recover_faulted_domain(domain),
        NetworkBackend::Queued => crate::virtio_net::recover_faulted_domain(domain),
        NetworkBackend::None => (),
    }
}
pub fn debug_waiter_count() -> usize {
    match get().network_backend {
        NetworkBackend::Packet => crate::dwmac_net::debug_waiter_count(),
        NetworkBackend::Queued => crate::virtio_net::debug_waiter_count(),
        NetworkBackend::None => 0,
    }
}
pub fn hello_packet() -> Packet {
    if get().network_backend == NetworkBackend::Queued {
        crate::virtio_net::hello_packet()
    } else {
        crate::dwmac_net::hello_packet()
    }
}
pub fn challenge_packet() -> Packet {
    if get().network_backend == NetworkBackend::Queued {
        crate::virtio_net::challenge_packet()
    } else {
        crate::dwmac_net::challenge_packet()
    }
}
pub fn ack_packet() -> Packet {
    if get().network_backend == NetworkBackend::Queued {
        crate::virtio_net::ack_packet()
    } else {
        crate::dwmac_net::ack_packet()
    }
}
pub fn is_challenge(packet: &Packet) -> bool {
    crate::virtio_net::is_challenge(packet)
}
