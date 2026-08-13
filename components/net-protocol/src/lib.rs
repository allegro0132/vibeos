//! Portable configurable-IPv4 networking over VibeOS packet endpoints.
//!
//! This module is the first protocol layer above the raw Ethernet contract in
//! [`vibeos_core::net`]. It deliberately exposes neither file descriptors nor an
//! ambient NIC. A supervisor resolves two directional packet capabilities as
//! operation-time [`Revocable`] tokens and hands them to
//! [`StaticIpv4TcpStack`]. Calling [`StaticIpv4TcpStack::poll_network`] with a
//! monotonic millisecond timestamp advances ARP, IPv4, and one passive TCP
//! connection by a bounded amount. Application byte-stream work is explicit
//! and separately bounded through [`StaticIpv4TcpStack::try_recv`] and
//! [`StaticIpv4TcpStack::try_send`]. [`StaticIpv4EchoStack`] remains as the N1
//! acceptance adapter over that byte-stream API.

#![no_std]

extern crate alloc;

pub mod command;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;

use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
    SocketSet,
};
use smoltcp::phy::{self, Checksum, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

use vibeos_core::cap::Revocable;
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{Packet, PacketStamp, StampedPacket, MAX_PACKET_LEN};
use vibeos_net_api::{TcpCloseRequest, TcpFrontendError, TcpListener};
pub use vibeos_net_api::{TcpIoResult, TcpStreamState, TcpStreamStatus};

/// Static IPv4 address and optional default route shared by network services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticIpv4Address {
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub default_gateway: Option<[u8; 4]>,
}

impl StaticIpv4Address {
    pub const fn new(address: [u8; 4], prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
            default_gateway: None,
        }
    }

    pub const fn with_default_gateway(mut self, gateway: [u8; 4]) -> Self {
        self.default_gateway = Some(gateway);
        self
    }
}

/// Runtime address state published by the bounded IPv4 stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4RuntimeStatus {
    Unconfigured,
    Static(StaticIpv4Address),
    DhcpDiscovering,
    DhcpBound(StaticIpv4Address),
}

/// Bytes reserved in each direction of the single TCP connection.
pub const TCP_BUFFER_BYTES: usize = 32 * 1024;
/// At most this many ingress frames are consumed by one cooperative poll.
pub const MAX_INGRESS_FRAMES_PER_POLL: usize = 32;
/// At most this many bounded egress passes are made by one cooperative poll.
pub const MAX_EGRESS_PASSES_PER_POLL: usize = 32;
/// Bound application work independently from packet parsing work.
pub const MAX_ECHO_CHUNKS_PER_POLL: usize = 4;
/// At most this many application bytes are copied by one stream I/O call.
pub const MAX_TCP_STREAM_BYTES_PER_CALL: usize = 32 * 1024;
const ECHO_CHUNK_BYTES: usize = MAX_TCP_STREAM_BYTES_PER_CALL;
const TCP_IDLE_TIMEOUT_SECS: u64 = 30;

/// Static policy for the first IPv4/TCP service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticIpv4Config {
    pub ethernet_address: [u8; 6],
    pub ipv4_address: [u8; 4],
    pub prefix_len: u8,
    pub default_gateway: Option<[u8; 4]>,
    pub listen_port: u16,
    /// Seeds TCP initial sequence numbers. It is not an SSH entropy source.
    pub tcp_random_seed: u64,
}

impl StaticIpv4Config {
    pub const fn new(
        ethernet_address: [u8; 6],
        ipv4_address: [u8; 4],
        prefix_len: u8,
        listen_port: u16,
        tcp_random_seed: u64,
    ) -> Self {
        Self {
            ethernet_address,
            ipv4_address,
            prefix_len,
            default_gateway: None,
            listen_port,
            tcp_random_seed,
        }
    }

    pub const fn with_default_gateway(mut self, gateway: [u8; 4]) -> Self {
        self.default_gateway = Some(gateway);
        self
    }
}

/// Interface-wide configuration owned by one shared network stack.
///
/// TCP ports deliberately do not appear here. They are separately allocated
/// as [`TcpListenerHandle`] values so multiple services can share this one IP
/// interface without gaining authority over one another's listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4StackConfig {
    pub ethernet_address: [u8; 6],
    pub ipv4_address: [u8; 4],
    pub prefix_len: u8,
    pub default_gateway: Option<[u8; 4]>,
    /// Seeds TCP initial sequence numbers. It is not application entropy.
    pub tcp_random_seed: u64,
    /// The physical egress backend generates IPv4 and TCP/UDP checksums.
    pub tx_checksum_offload: bool,
    /// The physical ingress backend verifies IPv4 and TCP/UDP checksums and
    /// discards frames for which the descriptor reports an error.
    pub rx_checksum_offload: bool,
}

impl Ipv4StackConfig {
    pub const fn new(
        ethernet_address: [u8; 6],
        ipv4_address: [u8; 4],
        prefix_len: u8,
        tcp_random_seed: u64,
    ) -> Self {
        Self {
            ethernet_address,
            ipv4_address,
            prefix_len,
            default_gateway: None,
            tcp_random_seed,
            tx_checksum_offload: false,
            rx_checksum_offload: false,
        }
    }

    pub const fn with_default_gateway(mut self, gateway: [u8; 4]) -> Self {
        self.default_gateway = Some(gateway);
        self
    }

    pub const fn with_tx_checksum_offload(mut self, enabled: bool) -> Self {
        self.tx_checksum_offload = enabled;
        self
    }

    pub const fn with_rx_checksum_offload(mut self, enabled: bool) -> Self {
        self.rx_checksum_offload = enabled;
        self
    }
}

impl From<StaticIpv4Config> for Ipv4StackConfig {
    fn from(config: StaticIpv4Config) -> Self {
        Self {
            ethernet_address: config.ethernet_address,
            ipv4_address: config.ipv4_address,
            prefix_len: config.prefix_len,
            default_gateway: config.default_gateway,
            tcp_random_seed: config.tcp_random_seed,
            tx_checksum_offload: false,
            rx_checksum_offload: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    InvalidEthernetAddress,
    InvalidIpv4Address,
    InvalidPrefixLength,
    InvalidDefaultGateway,
    InvalidListenPort,
    ListenPortInUse,
    TcpListenerLimitReached,
    InvalidTcpListener,
    RouteTableFull,
    /// One of the directional packet capabilities was revoked.
    AuthorityRevoked,
    ClockWentBackwards {
        previous_ms: u64,
        now_ms: u64,
    },
    ClockOutOfRange {
        now_ms: u64,
    },
}

impl fmt::Display for StackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEthernetAddress => f.write_str("Ethernet address must be unicast"),
            Self::InvalidIpv4Address => f.write_str("IPv4 address must be unicast"),
            Self::InvalidPrefixLength => f.write_str("IPv4 prefix length exceeds 32"),
            Self::InvalidDefaultGateway => f.write_str("default gateway must be unicast"),
            Self::InvalidListenPort => f.write_str("TCP listen port must be non-zero"),
            Self::ListenPortInUse => f.write_str("TCP listen port is already allocated"),
            Self::TcpListenerLimitReached => {
                f.write_str("shared TCP listener limit has been reached")
            }
            Self::InvalidTcpListener => f.write_str("TCP listener handle is stale or invalid"),
            Self::RouteTableFull => f.write_str("IPv4 route table is full"),
            Self::AuthorityRevoked => f.write_str("network endpoint authority was revoked"),
            Self::ClockWentBackwards {
                previous_ms,
                now_ms,
            } => write!(
                f,
                "network clock moved backwards from {previous_ms} ms to {now_ms} ms"
            ),
            Self::ClockOutOfRange { now_ms } => {
                write!(f, "network clock {now_ms} ms exceeds smoltcp range")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketDeviceStats {
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub rejected_ingress_frames: u64,
    pub rejected_device_epoch_frames: u64,
    pub rejected_stack_generation_frames: u64,
    pub tx_backpressure_events: u64,
    pub pending_egress: bool,
}

/// A lossless-at-the-endpoint-boundary smoltcp device adapter.
///
/// smoltcp's transmit token cannot return `WouldBlock`. If the bounded VibeOS
/// outbound endpoint fills between token creation and consumption, the adapter
/// retains exactly one packet and stops admitting additional ingress/egress
/// until that packet is accepted. This preserves TCP retransmission semantics
/// without growing an unbounded second queue.
pub struct PacketDevice {
    stamp: PacketStamp,
    inbound: Revocable<Endpoint<StampedPacket>>,
    outbound: Revocable<Endpoint<StampedPacket>>,
    pending_egress: Option<StampedPacket>,
    stats: PacketDeviceStats,
    authority_revoked: bool,
    tx_checksum_offload: bool,
    rx_checksum_offload: bool,
}

impl PacketDevice {
    pub fn new(
        stamp: PacketStamp,
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Self {
        Self {
            stamp,
            inbound,
            outbound,
            pending_egress: None,
            stats: PacketDeviceStats::default(),
            authority_revoked: false,
            tx_checksum_offload: false,
            rx_checksum_offload: false,
        }
    }

    pub const fn set_tx_checksum_offload(&mut self, enabled: bool) {
        self.tx_checksum_offload = enabled;
    }

    pub const fn set_rx_checksum_offload(&mut self, enabled: bool) {
        self.rx_checksum_offload = enabled;
    }

    pub const fn stamp(&self) -> PacketStamp {
        self.stamp
    }

    /// Revalidate both directional authorities at a cooperative-call boundary.
    pub fn revalidate_authority(&mut self) -> Result<(), StackError> {
        if self.authority_revoked
            || self.inbound.try_with(|_| ()).is_err()
            || self.outbound.try_with(|_| ()).is_err()
        {
            self.authority_revoked = true;
            return Err(StackError::AuthorityRevoked);
        }
        self.authority_result()
    }

    /// Try once to publish a frame retained after endpoint backpressure.
    pub fn flush_egress(&mut self) -> Result<bool, StackError> {
        self.authority_result()?;
        let Some(packet) = self.pending_egress.take() else {
            self.stats.pending_egress = false;
            return Ok(true);
        };
        match self.outbound.try_with(|endpoint| endpoint.try_send(packet)) {
            Ok(Ok(())) => {
                self.stats.tx_frames = self.stats.tx_frames.saturating_add(1);
                self.stats.pending_egress = false;
                Ok(true)
            }
            Ok(Err(packet)) => {
                self.pending_egress = Some(packet);
                self.stats.tx_backpressure_events =
                    self.stats.tx_backpressure_events.saturating_add(1);
                self.stats.pending_egress = true;
                Ok(false)
            }
            Err(_) => {
                self.authority_revoked = true;
                self.stats.pending_egress = false;
                Err(StackError::AuthorityRevoked)
            }
        }
    }

    pub fn has_immediate_work(&mut self) -> Result<bool, StackError> {
        self.authority_result()?;
        if self.pending_egress.is_some() {
            return Ok(true);
        }
        match self.inbound.try_with(|endpoint| endpoint.stats().2 != 0) {
            Ok(has_ingress) => Ok(has_ingress),
            Err(_) => {
                self.authority_revoked = true;
                Err(StackError::AuthorityRevoked)
            }
        }
    }

    pub fn stats(&self) -> PacketDeviceStats {
        let mut stats = self.stats;
        stats.pending_egress = self.pending_egress.is_some();
        stats
    }

    fn authority_result(&self) -> Result<(), StackError> {
        if self.authority_revoked {
            Err(StackError::AuthorityRevoked)
        } else {
            Ok(())
        }
    }
}

/// An owned receive token; it never borrows the DMA or endpoint queue.
pub struct PacketRxToken(Packet);

impl phy::RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.0.as_bytes())
    }
}

/// A transmit token borrowing only the adapter's one-packet pending slot.
pub struct PacketTxToken<'a> {
    stamp: PacketStamp,
    outbound: Revocable<Endpoint<StampedPacket>>,
    pending_egress: &'a mut Option<StampedPacket>,
    stats: &'a mut PacketDeviceStats,
    authority_revoked: &'a mut bool,
}

impl phy::TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        assert!(
            len <= MAX_PACKET_LEN,
            "smoltcp emitted a frame larger than the advertised Ethernet MTU"
        );
        debug_assert!(self.pending_egress.is_none());

        let mut frame = [0u8; MAX_PACKET_LEN];
        let result = f(&mut frame[..len]);
        let packet = StampedPacket::new(
            Packet::copy_from(&frame[..len])
                .expect("smoltcp emitted an empty or oversized Ethernet frame"),
            self.stamp,
        );
        match self.outbound.try_with(|endpoint| endpoint.try_send(packet)) {
            Ok(Ok(())) => {
                self.stats.tx_frames = self.stats.tx_frames.saturating_add(1);
            }
            Ok(Err(packet)) => {
                *self.pending_egress = Some(packet);
                self.stats.tx_backpressure_events =
                    self.stats.tx_backpressure_events.saturating_add(1);
                self.stats.pending_egress = true;
            }
            Err(_) => {
                *self.authority_revoked = true;
                self.stats.pending_egress = false;
            }
        }
        result
    }
}

impl phy::Device for PacketDevice {
    type RxToken<'a>
        = PacketRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.flush_egress() != Ok(true) {
            return None;
        }
        let packet = match self.inbound.try_with(|endpoint| endpoint.try_recv()) {
            Ok(packet) => packet?,
            Err(_) => {
                self.authority_revoked = true;
                return None;
            }
        };
        let packet = match packet.into_packet(self.stamp) {
            Ok(packet) => packet,
            Err(mismatch) => {
                self.stats.rejected_ingress_frames =
                    self.stats.rejected_ingress_frames.saturating_add(1);
                if mismatch.device_epoch_changed() {
                    self.stats.rejected_device_epoch_frames =
                        self.stats.rejected_device_epoch_frames.saturating_add(1);
                } else if mismatch.stack_generation_changed() {
                    self.stats.rejected_stack_generation_frames = self
                        .stats
                        .rejected_stack_generation_frames
                        .saturating_add(1);
                }
                return None;
            }
        };
        self.stats.rx_frames = self.stats.rx_frames.saturating_add(1);
        Some((
            PacketRxToken(packet),
            PacketTxToken {
                stamp: self.stamp,
                outbound: self.outbound.clone(),
                pending_egress: &mut self.pending_egress,
                stats: &mut self.stats,
                authority_revoked: &mut self.authority_revoked,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.flush_egress() != Ok(true) {
            return None;
        }
        Some(PacketTxToken {
            stamp: self.stamp,
            outbound: self.outbound.clone(),
            pending_egress: &mut self.pending_egress,
            stats: &mut self.stats,
            authority_revoked: &mut self.authority_revoked,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = MAX_PACKET_LEN;
        // Bound the advertised TCP window to the number of frames the physical
        // DWMAC RX ring can absorb before software runs again. The image packet
        // endpoints use the same or greater depth, and QEMU can safely honor
        // this conservative hardware-derived burst contract as well.
        capabilities.max_burst_size = Some(32);
        let checksum = match (self.rx_checksum_offload, self.tx_checksum_offload) {
            (false, false) => Checksum::Both,
            (false, true) => Checksum::Rx,
            (true, false) => Checksum::Tx,
            (true, true) => Checksum::None,
        };
        capabilities.checksum.ipv4 = checksum;
        capabilities.checksum.tcp = checksum;
        capabilities.checksum.udp = checksum;
        capabilities
    }
}

/// Report from one bounded network-only protocol turn.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpPollReport {
    pub ingress_frames: usize,
    pub connection_started: bool,
    pub connection_ended: bool,
    /// More packet/timer work is immediately runnable. Application readability
    /// and writability are reported separately by [`TcpStreamStatus`].
    pub more_work: bool,
    /// Advisory delay before the next timer-driven poll. Incoming packets should
    /// always trigger an earlier poll.
    pub next_poll_delay_ms: Option<u64>,
}

struct NetworkPollWork {
    ingress_frames: usize,
    application_bytes: usize,
    connection_started: bool,
    connection_ended: bool,
    more_network_work: bool,
    next_poll_delay_ms: Option<u64>,
}

/// Maximum number of independently authorized passive TCP sockets sharing one
/// IPv4 interface. Every socket reserves both fixed-size byte buffers up front.
pub const MAX_TCP_LISTENERS: usize = 8;
/// Bound application/frontend copies independently from packet processing.
pub const MAX_FRONTEND_CHUNKS_PER_DRIVE: usize = 4;

/// Stack-local identity of one passive TCP socket.
///
/// The fields remain private so safe application code cannot forge another
/// listener. The capability frontend wraps this identity in a `Resource`;
/// keeping a generation here also prevents slot-reuse ABA inside the stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpListenerHandle {
    slot: u8,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpListenerPollReport {
    pub connection_started: bool,
    pub connection_ended: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SharedTcpPollReport {
    pub ingress_frames: usize,
    pub more_work: bool,
    pub next_poll_delay_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFrontendDriveReport {
    pub received_bytes: usize,
    pub transmitted_bytes: usize,
    pub close_applied: Option<TcpCloseRequest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpFrontendDriveError {
    Stack(StackError),
    Frontend(TcpFrontendError),
    QueueInvariant,
}

impl From<StackError> for TcpFrontendDriveError {
    fn from(error: StackError) -> Self {
        Self::Stack(error)
    }
}

impl From<TcpFrontendError> for TcpFrontendDriveError {
    fn from(error: TcpFrontendError) -> Self {
        Self::Frontend(error)
    }
}

struct TcpListenerEntry {
    socket: SocketHandle,
    port: u16,
    port_group: Option<u64>,
    generation: u64,
    connection_active: bool,
    reset_requested: bool,
    last_poll: TcpListenerPollReport,
}

struct SharedNetworkPollWork {
    ingress_frames: usize,
    application_bytes: usize,
    more_network_work: bool,
    next_poll_delay_ms: Option<u64>,
}

/// One dynamically configurable IPv4 interface with a bounded TCP socket set.
///
/// This is the shared protocol core: it owns the sole smoltcp [`Interface`]
/// and [`SocketSet`] for this packet session. Applications identify only a
/// listener allocated for them and never receive the interface, packet device,
/// DHCP socket, route table, or another service's TCP socket.
pub struct SharedIpv4TcpStack {
    config: Ipv4StackConfig,
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    listeners: Vec<TcpListenerEntry>,
    dhcp_handle: Option<SocketHandle>,
    ipv4_status: Ipv4RuntimeStatus,
    last_now_ms: u64,
    next_listener_generation: u64,
}

impl SharedIpv4TcpStack {
    pub fn new(
        config: Ipv4StackConfig,
        stamp: PacketStamp,
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Result<Self, StackError> {
        validate_stack_config(config)?;

        let mut device = PacketDevice::new(stamp, inbound, outbound);
        device.set_tx_checksum_offload(config.tx_checksum_offload);
        device.set_rx_checksum_offload(config.rx_checksum_offload);
        device.revalidate_authority()?;
        let ethernet_address = EthernetAddress(config.ethernet_address);
        let mut interface_config = InterfaceConfig::new(ethernet_address.into());
        interface_config.random_seed = config.tcp_random_seed;
        let mut interface = Interface::new(interface_config, &mut device, Instant::ZERO);
        let address = Ipv4Addr::from(config.ipv4_address);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(address), config.prefix_len))
                .expect("a fresh smoltcp interface has room for one IPv4 address");
        });
        if let Some(gateway) = config.default_gateway {
            interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(gateway))
                .map_err(|_| StackError::RouteTableFull)?;
        }

        Ok(Self {
            config,
            device,
            interface,
            sockets: SocketSet::new(Vec::new()),
            listeners: Vec::new(),
            dhcp_handle: None,
            ipv4_status: Ipv4RuntimeStatus::Static(StaticIpv4Address {
                address: config.ipv4_address,
                prefix_len: config.prefix_len,
                default_gateway: config.default_gateway,
            }),
            last_now_ms: 0,
            next_listener_generation: 1,
        })
    }

    pub const fn config(&self) -> Ipv4StackConfig {
        self.config
    }

    pub const fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        self.ipv4_status
    }

    /// Allocate one exclusive passive port from this shared stack.
    pub fn add_tcp_listener(&mut self, port: u16) -> Result<TcpListenerHandle, StackError> {
        self.add_tcp_listener_with_group(port, None)
    }

    /// Allocate another passive socket in an explicitly shared port group.
    ///
    /// All sockets on a repeated port must carry the same non-zero group id.
    /// This keeps ordinary service ports exclusive while supporting protocols
    /// whose control and data connections intentionally share one port.
    pub fn add_shared_tcp_listener(
        &mut self,
        port: u16,
        port_group: u64,
    ) -> Result<TcpListenerHandle, StackError> {
        if port_group == 0 {
            return Err(StackError::ListenPortInUse);
        }
        self.add_tcp_listener_with_group(port, Some(port_group))
    }

    fn add_tcp_listener_with_group(
        &mut self,
        port: u16,
        port_group: Option<u64>,
    ) -> Result<TcpListenerHandle, StackError> {
        self.device.revalidate_authority()?;
        if port == 0 {
            return Err(StackError::InvalidListenPort);
        }
        if self
            .listeners
            .iter()
            .any(|listener| listener.port == port && listener.port_group != port_group)
        {
            return Err(StackError::ListenPortInUse);
        }
        if port_group.is_none() && self.listeners.iter().any(|listener| listener.port == port) {
            return Err(StackError::ListenPortInUse);
        }
        if self.listeners.len() >= MAX_TCP_LISTENERS {
            return Err(StackError::TcpListenerLimitReached);
        }

        let receive = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
        let transmit = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
        let mut socket = tcp::Socket::new(receive, transmit);
        socket.set_congestion_control(tcp::CongestionControl::Reno);
        socket.set_nagle_enabled(false);
        // The packet backends are polled and currently cannot wake this task
        // when a frame arrives.  smoltcp's default 10 ms delayed ACK would
        // therefore be observed only on a later protocol poll.  On the Duo's
        // one-descriptor DWMAC receive path that turns TCP into stop-and-wait:
        // one MSS followed by roughly 20 ms of silence.  ACK immediately so
        // the peer can refill the deliberately bounded receive window.
        socket.set_ack_delay(None);
        socket.set_timeout(Some(Duration::from_secs(TCP_IDLE_TIMEOUT_SECS)));
        socket
            .listen(port)
            .expect("validated non-zero TCP port must be listenable");

        let socket = self.sockets.add(socket);
        let generation = self.next_listener_generation;
        self.next_listener_generation = self
            .next_listener_generation
            .checked_add(1)
            .ok_or(StackError::TcpListenerLimitReached)?;
        let slot = u8::try_from(self.listeners.len())
            .expect("the bounded TCP listener table fits in a u8");
        self.listeners.push(TcpListenerEntry {
            socket,
            port,
            port_group,
            generation,
            connection_active: false,
            reset_requested: false,
            last_poll: TcpListenerPollReport::default(),
        });
        Ok(TcpListenerHandle { slot, generation })
    }

    pub fn tcp_listener_port(&self, listener: TcpListenerHandle) -> Result<u16, StackError> {
        Ok(self.listener(listener)?.port)
    }

    pub fn tcp_listener_poll_report(
        &self,
        listener: TcpListenerHandle,
    ) -> Result<TcpListenerPollReport, StackError> {
        Ok(self.listener(listener)?.last_poll)
    }

    pub fn tcp_is_listening(&self, listener: TcpListenerHandle) -> Result<bool, StackError> {
        let socket = self.listener(listener)?.socket;
        Ok(self.sockets.get::<tcp::Socket>(socket).is_listening())
    }

    pub fn tcp_connection_active(&self, listener: TcpListenerHandle) -> Result<bool, StackError> {
        let socket = self.listener(listener)?.socket;
        Ok(self.sockets.get::<tcp::Socket>(socket).is_active())
    }

    pub fn tcp_stream_status(
        &self,
        listener: TcpListenerHandle,
    ) -> Result<TcpStreamStatus, StackError> {
        let entry = self.listener(listener)?;
        let socket = self.sockets.get::<tcp::Socket>(entry.socket);
        if entry.reset_requested {
            return Ok(TcpStreamStatus {
                state: TcpStreamState::Reset,
                readable_bytes: 0,
                queued_send_bytes: 0,
                writable_bytes: 0,
            });
        }

        Ok(TcpStreamStatus {
            state: stream_state(socket.state()),
            readable_bytes: socket.recv_queue(),
            queued_send_bytes: socket.send_queue(),
            writable_bytes: if socket.may_send() {
                socket.send_capacity().saturating_sub(socket.send_queue())
            } else {
                0
            },
        })
    }

    pub fn tcp_try_recv(
        &mut self,
        listener: TcpListenerHandle,
        output: &mut [u8],
    ) -> Result<TcpIoResult, StackError> {
        self.device.revalidate_authority()?;
        let entry = self.listener(listener)?;
        if entry.reset_requested {
            return Ok(TcpIoResult::Closed);
        }
        if output.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }

        let socket = entry.socket;
        let length = output.len().min(MAX_TCP_STREAM_BYTES_PER_CALL);
        match self
            .sockets
            .get_mut::<tcp::Socket>(socket)
            .recv_slice(&mut output[..length])
        {
            Ok(0) => Ok(TcpIoResult::WouldBlock),
            Ok(received) => Ok(TcpIoResult::Progress(received)),
            Err(tcp::RecvError::Finished | tcp::RecvError::InvalidState) => Ok(TcpIoResult::Closed),
        }
    }

    pub fn tcp_try_send(
        &mut self,
        listener: TcpListenerHandle,
        input: &[u8],
    ) -> Result<TcpIoResult, StackError> {
        self.device.revalidate_authority()?;
        let entry = self.listener(listener)?;
        if entry.reset_requested {
            return Ok(TcpIoResult::Closed);
        }
        if input.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }

        let socket = entry.socket;
        let length = input.len().min(MAX_TCP_STREAM_BYTES_PER_CALL);
        match self
            .sockets
            .get_mut::<tcp::Socket>(socket)
            .send_slice(&input[..length])
        {
            Ok(0) => Ok(TcpIoResult::WouldBlock),
            Ok(sent) => Ok(TcpIoResult::Progress(sent)),
            Err(tcp::SendError::InvalidState) => Ok(TcpIoResult::Closed),
        }
    }

    pub fn tcp_close(&mut self, listener: TcpListenerHandle) -> Result<TcpStreamState, StackError> {
        self.device.revalidate_authority()?;
        let index = self.listener_index(listener)?;
        self.listeners[index].reset_requested = false;
        let socket = self.listeners[index].socket;
        self.sockets.get_mut::<tcp::Socket>(socket).close();
        Ok(self.tcp_stream_status(listener)?.state)
    }

    pub fn tcp_reset(&mut self, listener: TcpListenerHandle) -> Result<TcpStreamState, StackError> {
        self.device.revalidate_authority()?;
        let index = self.listener_index(listener)?;
        let socket = self.listeners[index].socket;
        self.sockets.get_mut::<tcp::Socket>(socket).abort();
        self.listeners[index].reset_requested = true;
        Ok(TcpStreamState::Reset)
    }

    /// Reconcile one capability frontend with its private smoltcp socket.
    ///
    /// This function never polls the interface. The owning netstack task calls
    /// it before or after [`Self::poll_network`] so packet progress remains
    /// serialized through the sole interface owner.
    pub fn drive_tcp_frontend(
        &mut self,
        listener: TcpListenerHandle,
        frontend: &TcpListener,
    ) -> Result<TcpFrontendDriveReport, TcpFrontendDriveError> {
        if self.tcp_listener_port(listener)? != frontend.port() {
            return Err(TcpFrontendDriveError::QueueInvariant);
        }

        let mut report = TcpFrontendDriveReport::default();
        frontend.network_update_state(self.tcp_stream_status(listener)?.state)?;
        let mut scratch = [0u8; MAX_TCP_STREAM_BYTES_PER_CALL];

        for _ in 0..MAX_FRONTEND_CHUNKS_PER_DRIVE {
            let capacity = frontend.network_receive_capacity().min(scratch.len());
            if capacity == 0 {
                break;
            }
            match self.tcp_try_recv(listener, &mut scratch[..capacity])? {
                TcpIoResult::Progress(0) | TcpIoResult::WouldBlock | TcpIoResult::Closed => break,
                TcpIoResult::Progress(length) => {
                    if frontend.network_receive(&scratch[..length]) != length {
                        return Err(TcpFrontendDriveError::QueueInvariant);
                    }
                    report.received_bytes += length;
                }
            }
        }

        for _ in 0..MAX_FRONTEND_CHUNKS_PER_DRIVE {
            let writable = self
                .tcp_stream_status(listener)?
                .writable_bytes
                .min(scratch.len());
            if writable == 0 {
                break;
            }
            let queued = frontend.network_copy_transmit(&mut scratch[..writable]);
            if queued == 0 {
                break;
            }
            match self.tcp_try_send(listener, &scratch[..queued])? {
                TcpIoResult::Progress(sent) => {
                    frontend.network_consume_transmit(sent);
                    report.transmitted_bytes += sent;
                    if sent != queued {
                        break;
                    }
                }
                TcpIoResult::WouldBlock => break,
                TcpIoResult::Closed => return Err(TcpFrontendDriveError::QueueInvariant),
            }
        }

        if let Some(request) = frontend.close_request() {
            match request {
                TcpCloseRequest::Close => {
                    self.tcp_close(listener)?;
                }
                TcpCloseRequest::Reset => {
                    self.tcp_reset(listener)?;
                }
            }
            frontend.clear_close_request(request);
            report.close_applied = Some(request);
            frontend.network_update_state(self.tcp_stream_status(listener)?.state)?;
        }

        Ok(report)
    }

    /// Atomically replace the interface address and route. Every active TCP
    /// tuple is aborted before the old address disappears.
    pub fn configure_static_ipv4(&mut self, address: StaticIpv4Address) -> Result<(), StackError> {
        validate_ipv4_address(address.address, address.prefix_len, address.default_gateway)?;
        self.device.revalidate_authority()?;
        self.remove_dhcp_socket();
        self.abort_for_reconfiguration();
        self.install_ipv4_address(address)?;
        self.config.ipv4_address = address.address;
        self.config.prefix_len = address.prefix_len;
        self.config.default_gateway = address.default_gateway;
        self.ipv4_status = Ipv4RuntimeStatus::Static(address);
        Ok(())
    }

    /// Remove every IPv4 address and route and stop an active DHCP client.
    pub fn clear_ipv4(&mut self) -> Result<(), StackError> {
        self.device.revalidate_authority()?;
        self.remove_dhcp_socket();
        self.abort_for_reconfiguration();
        self.clear_interface_ipv4();
        self.ipv4_status = Ipv4RuntimeStatus::Unconfigured;
        Ok(())
    }

    /// Clear static configuration and begin bounded DHCPv4 discovery.
    pub fn start_dhcp(&mut self) -> Result<(), StackError> {
        self.device.revalidate_authority()?;
        self.remove_dhcp_socket();
        self.abort_for_reconfiguration();
        self.clear_interface_ipv4();
        self.dhcp_handle = Some(self.sockets.add(dhcpv4::Socket::new()));
        self.ipv4_status = Ipv4RuntimeStatus::DhcpDiscovering;
        Ok(())
    }

    pub fn device_stats(&self) -> PacketDeviceStats {
        self.device.stats()
    }

    pub fn poll_network(&mut self, now_ms: u64) -> Result<SharedTcpPollReport, StackError> {
        let work = self.poll_with_application(now_ms, |_, _| 0)?;
        Ok(SharedTcpPollReport {
            ingress_frames: work.ingress_frames,
            more_work: work.more_network_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }

    fn poll_with_application(
        &mut self,
        now_ms: u64,
        mut service: impl FnMut(TcpListenerHandle, &mut tcp::Socket<'static>) -> usize,
    ) -> Result<SharedNetworkPollWork, StackError> {
        let now = checked_instant(self.last_now_ms, now_ms)?;
        self.device.revalidate_authority()?;
        self.last_now_ms = now_ms;
        let mut was_active = [false; MAX_TCP_LISTENERS];
        for (index, listener) in self.listeners.iter().enumerate() {
            was_active[index] = listener.connection_active;
        }
        let mut ingress_frames = 0;
        let mut application_bytes = 0;
        let mut ingress_budget_exhausted = true;
        let mut egress_budget_exhausted = true;

        self.interface.poll_maintenance(now);
        self.ensure_listening(false);

        for _ in 0..MAX_INGRESS_FRAMES_PER_POLL {
            let ingress_result =
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets);
            self.device.authority_result()?;
            match ingress_result {
                PollIngressSingleResult::None => {
                    ingress_budget_exhausted = false;
                    break;
                }
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => {
                    ingress_frames += 1;
                    application_bytes += self.service_listeners(&mut service);
                    // Preserve the boundary between old and new users of every
                    // reusable passive socket. Any queued SYN remains in the
                    // packet endpoint until the end-of-turn rearm completes.
                    if self.listeners.iter().enumerate().any(|(index, listener)| {
                        was_active[index]
                            && !self.sockets.get::<tcp::Socket>(listener.socket).is_active()
                    }) {
                        break;
                    }
                }
            }
        }

        self.apply_dhcp_event()?;

        application_bytes += self.service_listeners(&mut service);
        for _ in 0..MAX_EGRESS_PASSES_PER_POLL {
            let egress_result =
                self.interface
                    .poll_egress(now, &mut self.device, &mut self.sockets);
            self.device.authority_result()?;
            if egress_result == PollResult::None {
                egress_budget_exhausted = false;
                break;
            }
        }
        let _ = self.device.flush_egress()?;
        self.ensure_listening(true);

        for (index, listener) in self.listeners.iter_mut().enumerate() {
            let active = self.sockets.get::<tcp::Socket>(listener.socket).is_active();
            listener.last_poll = TcpListenerPollReport {
                connection_started: !was_active[index] && active,
                connection_ended: was_active[index] && !active,
            };
            listener.connection_active = active;
        }
        let more_network_work = ingress_budget_exhausted
            || egress_budget_exhausted
            || self.device.has_immediate_work()?;
        let next_poll_delay_ms = if more_network_work {
            Some(0)
        } else {
            self.interface
                .poll_delay(now, &self.sockets)
                .map(|delay| delay.total_millis())
        };

        Ok(SharedNetworkPollWork {
            ingress_frames,
            application_bytes,
            more_network_work,
            next_poll_delay_ms,
        })
    }

    fn service_listeners(
        &mut self,
        service: &mut impl FnMut(TcpListenerHandle, &mut tcp::Socket<'static>) -> usize,
    ) -> usize {
        let mut application_bytes = 0;
        for (index, listener) in self.listeners.iter().enumerate() {
            let handle = TcpListenerHandle {
                slot: u8::try_from(index).expect("the bounded listener table fits in a u8"),
                generation: listener.generation,
            };
            application_bytes += service(handle, self.sockets.get_mut(listener.socket));
        }
        application_bytes
    }

    fn ensure_listening(&mut self, rearm_resets: bool) {
        for listener in &mut self.listeners {
            if listener.reset_requested && !rearm_resets {
                continue;
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(listener.socket);
            // `is_open()` is also false in TIME-WAIT. Re-listening there would
            // reset delayed-ACK/close state. Only CLOSED is safe to reuse.
            if socket.state() == tcp::State::Closed {
                socket
                    .listen(listener.port)
                    .expect("an allocated TCP port must remain listenable");
                listener.reset_requested = false;
            }
        }
    }

    fn abort_for_reconfiguration(&mut self) {
        for listener in &mut self.listeners {
            self.sockets.get_mut::<tcp::Socket>(listener.socket).abort();
            listener.connection_active = false;
            listener.reset_requested = false;
            listener.last_poll = TcpListenerPollReport::default();
        }
    }

    fn remove_dhcp_socket(&mut self) {
        if let Some(handle) = self.dhcp_handle.take() {
            let _ = self.sockets.remove(handle);
        }
    }

    fn clear_interface_ipv4(&mut self) {
        self.interface
            .update_ip_addrs(|addresses| addresses.clear());
        self.interface.routes_mut().remove_default_ipv4_route();
    }

    fn install_ipv4_address(&mut self, address: StaticIpv4Address) -> Result<(), StackError> {
        self.clear_interface_ipv4();
        let ipv4 = Ipv4Addr::from(address.address);
        self.interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(ipv4), address.prefix_len))
                .expect("the interface retains room for one IPv4 address");
        });
        if let Some(gateway) = address.default_gateway {
            self.interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from(gateway))
                .map_err(|_| StackError::RouteTableFull)?;
        }
        Ok(())
    }

    fn apply_dhcp_event(&mut self) -> Result<(), StackError> {
        enum OwnedEvent {
            Configured(StaticIpv4Address),
            Deconfigured,
        }

        let Some(handle) = self.dhcp_handle else {
            return Ok(());
        };
        let event =
            self.sockets
                .get_mut::<dhcpv4::Socket>(handle)
                .poll()
                .map(|event| match event {
                    dhcpv4::Event::Configured(config) => {
                        OwnedEvent::Configured(StaticIpv4Address {
                            address: config.address.address().octets(),
                            prefix_len: config.address.prefix_len(),
                            default_gateway: config.router.map(|router| router.octets()),
                        })
                    }
                    dhcpv4::Event::Deconfigured => OwnedEvent::Deconfigured,
                });
        match event {
            Some(OwnedEvent::Configured(address)) => {
                validate_ipv4_address(
                    address.address,
                    address.prefix_len,
                    address.default_gateway,
                )?;
                // A normal lease renewal reports Configured again. Preserve
                // established TCP state when the effective address and route
                // did not change.
                if self.ipv4_status != Ipv4RuntimeStatus::DhcpBound(address) {
                    self.abort_for_reconfiguration();
                    self.install_ipv4_address(address)?;
                }
                self.ipv4_status = Ipv4RuntimeStatus::DhcpBound(address);
            }
            Some(OwnedEvent::Deconfigured) => {
                self.abort_for_reconfiguration();
                self.clear_interface_ipv4();
                self.ipv4_status = Ipv4RuntimeStatus::DhcpDiscovering;
            }
            None => {}
        }
        Ok(())
    }

    fn listener(&self, listener: TcpListenerHandle) -> Result<&TcpListenerEntry, StackError> {
        self.listeners
            .get(usize::from(listener.slot))
            .filter(|entry| entry.generation == listener.generation)
            .ok_or(StackError::InvalidTcpListener)
    }

    fn listener_index(&self, listener: TcpListenerHandle) -> Result<usize, StackError> {
        self.listener(listener)?;
        Ok(usize::from(listener.slot))
    }
}

/// Compatibility adapter retaining the original one-listener API while the
/// netstack and SSH components migrate to explicit listener capabilities.
pub struct StaticIpv4TcpStack {
    config: StaticIpv4Config,
    shared: SharedIpv4TcpStack,
    listener: TcpListenerHandle,
}

impl StaticIpv4TcpStack {
    pub fn new(
        config: StaticIpv4Config,
        stamp: PacketStamp,
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Result<Self, StackError> {
        validate_config(config)?;
        let mut shared = SharedIpv4TcpStack::new(config.into(), stamp, inbound, outbound)?;
        let listener = shared.add_tcp_listener(config.listen_port)?;
        Ok(Self {
            config,
            shared,
            listener,
        })
    }

    pub const fn config(&self) -> StaticIpv4Config {
        self.config
    }

    pub const fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        self.shared.ipv4_status()
    }

    pub fn configure_static_ipv4(&mut self, address: StaticIpv4Address) -> Result<(), StackError> {
        self.shared.configure_static_ipv4(address)?;
        self.config.ipv4_address = address.address;
        self.config.prefix_len = address.prefix_len;
        self.config.default_gateway = address.default_gateway;
        Ok(())
    }

    pub fn clear_ipv4(&mut self) -> Result<(), StackError> {
        self.shared.clear_ipv4()
    }

    pub fn start_dhcp(&mut self) -> Result<(), StackError> {
        self.shared.start_dhcp()
    }

    pub fn device_stats(&self) -> PacketDeviceStats {
        self.shared.device_stats()
    }

    pub fn is_listening(&self) -> bool {
        self.shared
            .tcp_is_listening(self.listener)
            .expect("the compatibility listener remains allocated")
    }

    pub fn connection_active(&self) -> bool {
        self.shared
            .tcp_connection_active(self.listener)
            .expect("the compatibility listener remains allocated")
    }

    pub fn stream_status(&self) -> TcpStreamStatus {
        self.shared
            .tcp_stream_status(self.listener)
            .expect("the compatibility listener remains allocated")
    }

    pub fn try_recv(&mut self, output: &mut [u8]) -> Result<TcpIoResult, StackError> {
        self.shared.tcp_try_recv(self.listener, output)
    }

    pub fn try_send(&mut self, input: &[u8]) -> Result<TcpIoResult, StackError> {
        self.shared.tcp_try_send(self.listener, input)
    }

    pub fn close(&mut self) -> Result<TcpStreamState, StackError> {
        self.shared.tcp_close(self.listener)
    }

    pub fn reset(&mut self) -> Result<TcpStreamState, StackError> {
        self.shared.tcp_reset(self.listener)
    }

    pub fn poll_network(&mut self, now_ms: u64) -> Result<TcpPollReport, StackError> {
        let work = self.poll_with_application(now_ms, |_| 0)?;
        Ok(TcpPollReport {
            ingress_frames: work.ingress_frames,
            connection_started: work.connection_started,
            connection_ended: work.connection_ended,
            more_work: work.more_network_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }

    fn poll_with_application(
        &mut self,
        now_ms: u64,
        mut service: impl FnMut(&mut tcp::Socket<'static>) -> usize,
    ) -> Result<NetworkPollWork, StackError> {
        let listener = self.listener;
        let work = self
            .shared
            .poll_with_application(now_ms, |candidate, socket| {
                if candidate == listener {
                    service(socket)
                } else {
                    0
                }
            })?;
        let listener = self.shared.tcp_listener_poll_report(listener)?;
        Ok(NetworkPollWork {
            ingress_frames: work.ingress_frames,
            application_bytes: work.application_bytes,
            connection_started: listener.connection_started,
            connection_ended: listener.connection_ended,
            more_network_work: work.more_network_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }

    fn echo_has_immediate_work(&self) -> bool {
        let socket = self
            .shared
            .listener(self.listener)
            .expect("the compatibility listener remains allocated")
            .socket;
        echo_has_immediate_work(self.shared.sockets.get::<tcp::Socket>(socket))
    }
}

fn stream_state(state: tcp::State) -> TcpStreamState {
    match state {
        tcp::State::Listen => TcpStreamState::Listening,
        tcp::State::SynSent | tcp::State::SynReceived => TcpStreamState::Handshake,
        tcp::State::Established => TcpStreamState::Established,
        tcp::State::CloseWait => TcpStreamState::PeerClosed,
        tcp::State::FinWait1
        | tcp::State::FinWait2
        | tcp::State::Closing
        | tcp::State::LastAck
        | tcp::State::TimeWait => TcpStreamState::Closing,
        tcp::State::Closed => TcpStreamState::Closed,
    }
}

fn echo_has_immediate_work(socket: &tcp::Socket<'_>) -> bool {
    socket.can_recv()
        && socket.can_send()
        && socket.recv_queue() != 0
        && socket.send_queue() < socket.send_capacity()
}

fn service_echo(socket: &mut tcp::Socket<'_>) -> usize {
    let mut echoed = 0;
    let mut scratch = [0u8; ECHO_CHUNK_BYTES];

    for _ in 0..MAX_ECHO_CHUNKS_PER_POLL {
        let free = socket.send_capacity().saturating_sub(socket.send_queue());
        let available = socket.recv_queue();
        let length = free.min(available).min(scratch.len());
        if length == 0 || !socket.can_recv() || !socket.can_send() {
            break;
        }
        let received = socket
            .recv_slice(&mut scratch[..length])
            .expect("can_recv guaranteed a readable TCP socket");
        let sent = socket
            .send_slice(&scratch[..received])
            .expect("reserved transmit capacity guaranteed a writable TCP socket");
        debug_assert_eq!(sent, received);
        echoed += sent;
    }

    if !socket.may_recv() && socket.may_send() {
        socket.close();
    }
    echoed
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollReport {
    pub ingress_frames: usize,
    pub echoed_bytes: usize,
    pub connection_started: bool,
    pub connection_ended: bool,
    pub more_work: bool,
    /// Advisory delay before the next timer-driven poll. Incoming packets should
    /// always trigger an earlier poll.
    pub next_poll_delay_ms: Option<u64>,
}

/// Compatibility echo service implemented over [`StaticIpv4TcpStack`].
pub struct StaticIpv4EchoStack {
    tcp: StaticIpv4TcpStack,
}

impl StaticIpv4EchoStack {
    pub fn new(
        config: StaticIpv4Config,
        stamp: PacketStamp,
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Result<Self, StackError> {
        Ok(Self {
            tcp: StaticIpv4TcpStack::new(config, stamp, inbound, outbound)?,
        })
    }

    pub const fn config(&self) -> StaticIpv4Config {
        self.tcp.config()
    }

    pub const fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        self.tcp.ipv4_status()
    }

    pub fn configure_static_ipv4(&mut self, address: StaticIpv4Address) -> Result<(), StackError> {
        self.tcp.configure_static_ipv4(address)
    }

    pub fn clear_ipv4(&mut self) -> Result<(), StackError> {
        self.tcp.clear_ipv4()
    }

    pub fn start_dhcp(&mut self) -> Result<(), StackError> {
        self.tcp.start_dhcp()
    }

    pub fn device_stats(&self) -> PacketDeviceStats {
        self.tcp.device_stats()
    }

    pub fn is_listening(&self) -> bool {
        self.tcp.is_listening()
    }

    pub fn connection_active(&self) -> bool {
        self.tcp.connection_active()
    }

    /// Advance ARP, IPv4, TCP, and the compatibility echo application.
    pub fn poll(&mut self, now_ms: u64) -> Result<PollReport, StackError> {
        let work = self.tcp.poll_with_application(now_ms, service_echo)?;
        let echo_ready = self.tcp.echo_has_immediate_work();
        let more_work = work.more_network_work || echo_ready;
        Ok(PollReport {
            ingress_frames: work.ingress_frames,
            echoed_bytes: work.application_bytes,
            connection_started: work.connection_started,
            connection_ended: work.connection_ended,
            more_work,
            next_poll_delay_ms: if more_work {
                Some(0)
            } else {
                work.next_poll_delay_ms
            },
        })
    }

    /// Kernel-facing spelling for one bounded state-machine turn.
    pub fn step(&mut self, now_ms: u64) -> Result<PollReport, StackError> {
        self.poll(now_ms)
    }
}

fn checked_instant(previous_ms: u64, now_ms: u64) -> Result<Instant, StackError> {
    if now_ms < previous_ms {
        return Err(StackError::ClockWentBackwards {
            previous_ms,
            now_ms,
        });
    }
    let millis = i64::try_from(now_ms).map_err(|_| StackError::ClockOutOfRange { now_ms })?;
    Ok(Instant::from_millis(millis))
}

fn validate_config(config: StaticIpv4Config) -> Result<(), StackError> {
    validate_stack_config(config.into())?;
    if config.listen_port == 0 {
        return Err(StackError::InvalidListenPort);
    }
    Ok(())
}

fn validate_stack_config(config: Ipv4StackConfig) -> Result<(), StackError> {
    let ethernet = EthernetAddress(config.ethernet_address);
    if !ethernet.is_unicast() || config.ethernet_address == [0; 6] {
        return Err(StackError::InvalidEthernetAddress);
    }
    validate_ipv4_address(
        config.ipv4_address,
        config.prefix_len,
        config.default_gateway,
    )?;
    Ok(())
}

fn validate_ipv4_address(
    address: [u8; 4],
    prefix_len: u8,
    default_gateway: Option<[u8; 4]>,
) -> Result<(), StackError> {
    if !is_unicast_ipv4(address) {
        return Err(StackError::InvalidIpv4Address);
    }
    if prefix_len > 32 {
        return Err(StackError::InvalidPrefixLength);
    }
    if default_gateway.is_some_and(|gateway| !is_unicast_ipv4(gateway)) {
        return Err(StackError::InvalidDefaultGateway);
    }
    Ok(())
}

fn is_unicast_ipv4(octets: [u8; 4]) -> bool {
    let address = Ipv4Addr::from(octets);
    !address.is_unspecified() && !address.is_multicast() && octets != [255; 4] && octets[0] != 0
}
