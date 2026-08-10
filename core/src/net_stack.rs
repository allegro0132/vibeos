//! Portable static-IPv4 networking over VibeOS packet endpoints.
//!
//! This module is the first protocol layer above the raw Ethernet contract in
//! [`crate::net`].  It deliberately exposes neither file descriptors nor an
//! ambient NIC. A supervisor resolves two directional packet capabilities as
//! operation-time [`Revocable`] tokens and hands them to
//! [`StaticIpv4EchoStack`]. Calling
//! [`StaticIpv4EchoStack::poll`] with a monotonic millisecond timestamp then
//! advances ARP, IPv4, and one passive TCP connection by a bounded amount.

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
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

use crate::cap::Revocable;
use crate::chan::Endpoint;
use crate::net::{Packet, PacketStamp, StampedPacket, MAX_PACKET_LEN};

/// Bytes reserved in each direction of the single TCP connection.
pub const TCP_BUFFER_BYTES: usize = 4 * 1024;
/// At most this many ingress frames are consumed by one cooperative poll.
pub const MAX_INGRESS_FRAMES_PER_POLL: usize = 8;
/// At most this many bounded egress passes are made by one cooperative poll.
pub const MAX_EGRESS_PASSES_PER_POLL: usize = 8;
/// Bound application work independently from packet parsing work.
pub const MAX_ECHO_CHUNKS_PER_POLL: usize = 4;
const ECHO_CHUNK_BYTES: usize = 1_024;
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

/// One static IPv4 interface and one reusable passive TCP echo socket.
pub struct StaticIpv4EchoStack {
    config: StaticIpv4Config,
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp_handle: SocketHandle,
    last_now_ms: u64,
    connection_active: bool,
}

impl StaticIpv4EchoStack {
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
            last_now_ms: 0,
            connection_active: false,
        })
    }

    pub const fn config(&self) -> StaticIpv4Config {
        self.config
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

    /// Advance ARP, IPv4, TCP, and the echo application by bounded work.
    pub fn poll(&mut self, now_ms: u64) -> Result<PollReport, StackError> {
        let now = checked_instant(self.last_now_ms, now_ms)?;
        self.device.revalidate_authority()?;
        self.last_now_ms = now_ms;
        let was_active = self.connection_active;
        let mut ingress_frames = 0;
        let mut echoed_bytes = 0;
        let mut ingress_budget_exhausted = true;
        let mut egress_budget_exhausted = true;

        self.interface.poll_maintenance(now);
        self.ensure_listening();

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
                    echoed_bytes += self.service_echo();
                }
            }
        }

        echoed_bytes += self.service_echo();
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
        let more_work = ingress_budget_exhausted
            || egress_budget_exhausted
            || self.echo_has_immediate_work()
            || self.device.has_immediate_work()?;
        let next_poll_delay_ms = if more_work {
            Some(0)
        } else {
            self.interface
                .poll_delay(now, &self.sockets)
                .map(|delay| delay.total_millis())
        };

        Ok(PollReport {
            ingress_frames,
            echoed_bytes,
            connection_started: !was_active && active,
            connection_ended: was_active && !active,
            more_work,
            next_poll_delay_ms,
        })
    }

    /// Kernel-facing spelling for one bounded state-machine turn.
    pub fn step(&mut self, now_ms: u64) -> Result<PollReport, StackError> {
        self.poll(now_ms)
    }

    fn ensure_listening(&mut self) {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
        if !socket.is_open() {
            socket
                .listen(self.config.listen_port)
                .expect("validated non-zero TCP port must remain listenable");
        }
    }

    fn echo_has_immediate_work(&self) -> bool {
        let socket = self.sockets.get::<tcp::Socket>(self.tcp_handle);
        socket.can_recv()
            && socket.can_send()
            && socket.recv_queue() != 0
            && socket.send_queue() < socket.send_capacity()
    }

    fn service_echo(&mut self) -> usize {
        let socket = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
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
    if !is_unicast_ipv4(config.ipv4_address) {
        return Err(StackError::InvalidIpv4Address);
    }
    if config.prefix_len > 32 {
        return Err(StackError::InvalidPrefixLength);
    }
    if config
        .default_gateway
        .is_some_and(|gateway| !is_unicast_ipv4(gateway))
    {
        return Err(StackError::InvalidDefaultGateway);
    }
    if config.listen_port == 0 {
        return Err(StackError::InvalidListenPort);
    }
    Ok(())
}

fn is_unicast_ipv4(octets: [u8; 4]) -> bool {
    let address = Ipv4Addr::from(octets);
    !address.is_unspecified() && !address.is_multicast() && octets != [255; 4] && octets[0] != 0
}
