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

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::net::Ipv4Addr;

use smoltcp::iface::{
    Config as InterfaceConfig, Interface, PollIngressSingleResult, PollResult, SocketHandle,
    SocketSet,
};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

use vibeos_core::cap::Revocable;
use vibeos_core::chan::Endpoint;
use vibeos_core::net::{Packet, PacketStamp, StampedPacket, MAX_PACKET_LEN};

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
pub const TCP_BUFFER_BYTES: usize = 4 * 1024;
/// At most this many ingress frames are consumed by one cooperative poll.
pub const MAX_INGRESS_FRAMES_PER_POLL: usize = 8;
/// At most this many bounded egress passes are made by one cooperative poll.
pub const MAX_EGRESS_PASSES_PER_POLL: usize = 8;
/// Bound application work independently from packet parsing work.
pub const MAX_ECHO_CHUNKS_PER_POLL: usize = 4;
/// At most this many application bytes are copied by one stream I/O call.
pub const MAX_TCP_STREAM_BYTES_PER_CALL: usize = 1_024;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    InvalidEthernetAddress,
    InvalidIpv4Address,
    InvalidPrefixLength,
    InvalidDefaultGateway,
    InvalidListenPort,
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
        }
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
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

/// Coarse state of the one reusable passive TCP stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpStreamState {
    /// No connection is active and the socket is accepting one peer.
    Listening,
    /// A TCP handshake is in progress.
    Handshake,
    /// Both halves of the byte stream are open.
    Established,
    /// The peer sent FIN; buffered receive bytes remain readable and the local
    /// transmit half may still be writable.
    PeerClosed,
    /// A graceful local close is progressing through the TCP state machine.
    Closing,
    /// [`StaticIpv4TcpStack::reset`] discarded the current stream. The next
    /// network poll rearms the listener after emitting any required reset.
    Reset,
    /// The socket is closed between a terminal transition and listener rearm.
    Closed,
}

/// Result of one non-blocking, bounded byte-stream operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpIoResult {
    /// Bytes were copied. Empty input or output slices yield `Progress(0)`.
    Progress(usize),
    /// The stream half is open, but its bounded buffer cannot currently make progress.
    WouldBlock,
    /// The requested stream half is closed or there is no active connection.
    Closed,
}

/// Snapshot of bounded application-facing TCP queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpStreamStatus {
    pub state: TcpStreamState,
    pub readable_bytes: usize,
    pub queued_send_bytes: usize,
    pub writable_bytes: usize,
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

/// One dynamically configurable IPv4 interface and one reusable passive TCP byte stream.
///
/// The object is intentionally neither a socket table nor a file-descriptor
/// namespace. It owns exactly one listener and accepts at most one connection.
/// Network progress happens only in [`Self::poll_network`]; application calls
/// copy at most [`MAX_TCP_STREAM_BYTES_PER_CALL`] bytes and never poll packets.
pub struct StaticIpv4TcpStack {
    config: StaticIpv4Config,
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
    dhcp_handle: Option<SocketHandle>,
    ipv4_status: Ipv4RuntimeStatus,
    last_now_ms: u64,
    connection_active: bool,
    reset_requested: bool,
}

impl StaticIpv4TcpStack {
    pub fn new(
        config: StaticIpv4Config,
        stamp: PacketStamp,
        inbound: Revocable<Endpoint<StampedPacket>>,
        outbound: Revocable<Endpoint<StampedPacket>>,
    ) -> Result<Self, StackError> {
        validate_config(config)?;

        let mut device = PacketDevice::new(stamp, inbound, outbound);
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

        let receive = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
        let transmit = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
        let mut socket = tcp::Socket::new(receive, transmit);
        socket.set_congestion_control(tcp::CongestionControl::Reno);
        socket.set_nagle_enabled(false);
        socket.set_timeout(Some(Duration::from_secs(TCP_IDLE_TIMEOUT_SECS)));
        socket
            .listen(config.listen_port)
            .expect("validated non-zero TCP port must be listenable");

        let mut sockets = SocketSet::new(Vec::new());
        let tcp_handle = sockets.add(socket);
        Ok(Self {
            config,
            device,
            interface,
            sockets,
            tcp_handle,
            dhcp_handle: None,
            ipv4_status: Ipv4RuntimeStatus::Static(StaticIpv4Address {
                address: config.ipv4_address,
                prefix_len: config.prefix_len,
                default_gateway: config.default_gateway,
            }),
            last_now_ms: 0,
            connection_active: false,
            reset_requested: false,
        })
    }

    pub const fn config(&self) -> StaticIpv4Config {
        self.config
    }

    pub const fn ipv4_status(&self) -> Ipv4RuntimeStatus {
        self.ipv4_status
    }

    /// Atomically replace the one IPv4 address and optional default route.
    /// Any active TCP tuple is aborted before the old address disappears.
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

    pub fn is_listening(&self) -> bool {
        self.sockets
            .get::<tcp::Socket>(self.tcp_handle)
            .is_listening()
    }

    pub fn connection_active(&self) -> bool {
        self.sockets.get::<tcp::Socket>(self.tcp_handle).is_active()
    }

    /// Describe the application-visible stream without advancing the network.
    pub fn stream_status(&self) -> TcpStreamStatus {
        let socket = self.sockets.get::<tcp::Socket>(self.tcp_handle);
        if self.reset_requested {
            return TcpStreamStatus {
                state: TcpStreamState::Reset,
                readable_bytes: 0,
                queued_send_bytes: 0,
                writable_bytes: 0,
            };
        }

        TcpStreamStatus {
            state: stream_state(socket.state()),
            readable_bytes: socket.recv_queue(),
            queued_send_bytes: socket.send_queue(),
            writable_bytes: if socket.may_send() {
                socket.send_capacity().saturating_sub(socket.send_queue())
            } else {
                0
            },
        }
    }

    /// Copy one bounded receive fragment without polling the network.
    pub fn try_recv(&mut self, output: &mut [u8]) -> Result<TcpIoResult, StackError> {
        self.device.revalidate_authority()?;
        if self.reset_requested {
            return Ok(TcpIoResult::Closed);
        }
        if output.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }

        let length = output.len().min(MAX_TCP_STREAM_BYTES_PER_CALL);
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        match socket.recv_slice(&mut output[..length]) {
            Ok(0) => Ok(TcpIoResult::WouldBlock),
            Ok(received) => Ok(TcpIoResult::Progress(received)),
            Err(tcp::RecvError::Finished | tcp::RecvError::InvalidState) => Ok(TcpIoResult::Closed),
        }
    }

    /// Copy one bounded transmit fragment without polling the network.
    pub fn try_send(&mut self, input: &[u8]) -> Result<TcpIoResult, StackError> {
        self.device.revalidate_authority()?;
        if self.reset_requested {
            return Ok(TcpIoResult::Closed);
        }
        if input.is_empty() {
            return Ok(TcpIoResult::Progress(0));
        }

        let length = input.len().min(MAX_TCP_STREAM_BYTES_PER_CALL);
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        match socket.send_slice(&input[..length]) {
            Ok(0) => Ok(TcpIoResult::WouldBlock),
            Ok(sent) => Ok(TcpIoResult::Progress(sent)),
            Err(tcp::SendError::InvalidState) => Ok(TcpIoResult::Closed),
        }
    }

    /// Gracefully close the transmit half without polling the network.
    pub fn close(&mut self) -> Result<TcpStreamState, StackError> {
        self.device.revalidate_authority()?;
        self.reset_requested = false;
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).close();
        Ok(self.stream_status().state)
    }

    /// Abort the current connection and discard its application buffers.
    ///
    /// smoltcp emits the reset during the next network poll; until then the
    /// synthetic [`TcpStreamState::Reset`] prevents stale buffered data from
    /// being exposed through the application API.
    pub fn reset(&mut self) -> Result<TcpStreamState, StackError> {
        self.device.revalidate_authority()?;
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).abort();
        self.reset_requested = true;
        Ok(TcpStreamState::Reset)
    }

    /// Advance only ARP, IPv4, and TCP by a bounded amount.
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
        let now = checked_instant(self.last_now_ms, now_ms)?;
        self.device.revalidate_authority()?;
        self.last_now_ms = now_ms;
        let was_active = self.connection_active;
        let mut ingress_frames = 0;
        let mut echoed_bytes = 0;
        let mut ingress_budget_exhausted = true;
        let mut egress_budget_exhausted = true;

        self.interface.poll_maintenance(now);
        // A locally requested abort must remain CLOSED for one dispatch pass so
        // smoltcp can emit its RST before `listen()` clears the old tuple.
        if !self.reset_requested {
            self.ensure_listening();
        }

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
                    echoed_bytes += service(self.sockets.get_mut::<tcp::Socket>(self.tcp_handle));
                    // Preserve the boundary between two users of the single
                    // passive socket. If this frame ended the old active
                    // tuple, leave any already-queued SYN for the next poll;
                    // the end-of-turn rearm below will install LISTEN first.
                    if was_active && !self.connection_active() {
                        break;
                    }
                }
            }
        }

        self.apply_dhcp_event()?;

        echoed_bytes += service(self.sockets.get_mut::<tcp::Socket>(self.tcp_handle));
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
        self.ensure_listening();

        let active = self.connection_active();
        self.connection_active = active;
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

        Ok(NetworkPollWork {
            ingress_frames,
            application_bytes: echoed_bytes,
            connection_started: !was_active && active,
            connection_ended: was_active && !active,
            more_network_work,
            next_poll_delay_ms,
        })
    }

    fn ensure_listening(&mut self) {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        // `is_open()` is also false in TIME-WAIT. Re-listening there would
        // reset smoltcp's delayed-ACK/close timer and can strand a peer whose
        // final payload and FIN arrived together. Only CLOSED has finished
        // the old tuple and is safe to reuse as the passive listener.
        if socket.state() == tcp::State::Closed {
            socket
                .listen(self.config.listen_port)
                .expect("validated non-zero TCP port must remain listenable");
            self.reset_requested = false;
        }
    }

    fn abort_for_reconfiguration(&mut self) {
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).abort();
        self.connection_active = false;
        self.reset_requested = false;
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
        let echo_ready =
            echo_has_immediate_work(self.tcp.sockets.get::<tcp::Socket>(self.tcp.tcp_handle));
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
    let ethernet = EthernetAddress(config.ethernet_address);
    if !ethernet.is_unicast() || config.ethernet_address == [0; 6] {
        return Err(StackError::InvalidEthernetAddress);
    }
    validate_ipv4_address(
        config.ipv4_address,
        config.prefix_len,
        config.default_gateway,
    )?;
    if config.listen_port == 0 {
        return Err(StackError::InvalidListenPort);
    }
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
