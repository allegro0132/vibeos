//! Portable configurable-IPv4 networking over VibeOS packet endpoints.
//!
//! This module is the first protocol layer above the raw Ethernet contract in
//! [`vibeos_core::net`]. It deliberately exposes neither file descriptors nor an
//! ambient NIC. A supervisor resolves two directional packet capabilities as
//! operation-time [`vibeos_core::cap::Revocable`] tokens and hands them to
//! [`StaticIpv4TcpStack`]. Calling [`StaticIpv4TcpStack::poll_network`] with a
//! monotonic millisecond timestamp advances ARP, IPv4, and one passive TCP
//! connection by a bounded amount. Application byte-stream work is explicit
//! and separately bounded through [`StaticIpv4TcpStack::try_recv`] and
//! [`StaticIpv4TcpStack::try_send`]. [`StaticIpv4EchoStack`] remains as the N1
//! acceptance adapter over that byte-stream API.

#![no_std]

extern crate alloc;

pub mod command;
#[cfg(feature = "receive-buffer-exchange")]
pub mod receive_exchange;
mod transmit;
mod receive;
pub use receive::PacketReceive;
pub use transmit::PacketTransmit;
#[cfg(feature = "bounded-gro")]
mod gro;
#[cfg(feature = "gro-checked")]
mod checked_gro;

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
#[cfg(not(feature = "tcp-large-window"))]
pub const TCP_BUFFER_BYTES: usize = 32 * 1024;
#[cfg(feature = "tcp-large-window")]
pub const TCP_BUFFER_BYTES: usize = 256 * 1024;
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
    #[cfg(feature = "rx-admission-batch")]
    pub rx_admission_sizes: [u64; 9],
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub tx_segmented_requests: u64,
    pub rejected_ingress_frames: u64,
    pub rejected_device_epoch_frames: u64,
    pub rejected_stack_generation_frames: u64,
    pub tx_backpressure_events: u64,
    pub pending_egress: bool,
    pub gro_merged_segments: u64,
    pub gro_aggregates: u64,
    #[cfg(feature = "gro-end-profile")]
    pub gro_end_profile: [u64; 31],
}

/// A lossless-at-the-endpoint-boundary smoltcp device adapter.
///
/// smoltcp's transmit token cannot return `WouldBlock`. If the bounded VibeOS
/// outbound endpoint fills between token creation and consumption, the adapter
/// retains exactly one packet and stops admitting additional ingress/egress
/// until that packet is accepted. This preserves TCP retransmission semantics
/// without growing an unbounded second queue.
pub struct PacketDevice {
    #[cfg(feature = "gro-checked")]
    checked_rx: checked_gro::Window,
    #[cfg(feature = "rx-admission-batch")]
    rx_batch: vibeos_core::net_receive::LoanBatch,
    stamp: PacketStamp,
    inbound: PacketReceive,
    rx_packet: Option<Packet>,
    #[cfg(feature = "pooled-rx")]
    rx_loan: Option<vibeos_core::net_receive::Loan>,
    #[cfg(feature = "gro-scatter")]
    gro_loans: [Option<vibeos_core::net_receive::Loan>; gro::MAX_SEGMENTS - 1],
    #[cfg(feature = "gro-scatter")]
    gro_loan_count: usize,
    #[cfg(all(feature = "pooled-rx", feature = "bounded-gro"))]
    pending_rx_loan: Option<vibeos_core::net_receive::Loan>,
    outbound: PacketTransmit,
    pending_egress: Option<StampedPacket>,
    #[cfg(feature = "native-tcp-segmentation")]
    pending_segments: Option<vibeos_core::net_segmentation::SoftwareTransmit>,
    #[cfg(feature = "native-tcp-segmentation")]
    pending_pooled: Option<transmit::Reservation>,
    stats: PacketDeviceStats,
    authority_revoked: bool,
    tx_checksum_offload: bool,
    rx_checksum_offload: bool,
    #[cfg(feature = "bounded-gro")]
    gro: gro::Buffer,
    #[cfg(feature = "gro-end-profile")]
    gro_last_none: gro::NoInput,
    #[cfg(feature = "bounded-gro")]
    pending_ingress: Option<Packet>,
    #[cfg(feature = "bounded-gro")]
    ingress_remaining: usize,
}

impl PacketDevice {
    pub fn new(
        stamp: PacketStamp,
        inbound: impl Into<PacketReceive>,
        outbound: impl Into<PacketTransmit>,
    ) -> Self {
        Self {
            stamp,
            #[cfg(feature = "gro-checked")]
            checked_rx: checked_gro::Window::new(),
            #[cfg(feature = "rx-admission-batch")]
            rx_batch: vibeos_core::net_receive::LoanBatch::empty(),
            inbound: inbound.into(),
            rx_packet: None,
            #[cfg(feature = "pooled-rx")]
            rx_loan: None,
            #[cfg(feature = "gro-scatter")]
            gro_loans: core::array::from_fn(|_| None),
            #[cfg(feature = "gro-scatter")]
            gro_loan_count: 0,
            #[cfg(all(feature = "pooled-rx", feature = "bounded-gro"))]
            pending_rx_loan: None,
            outbound: outbound.into(),
            pending_egress: None,
            #[cfg(feature = "native-tcp-segmentation")]
            pending_segments: None,
            #[cfg(feature = "native-tcp-segmentation")]
            pending_pooled: None,
            stats: PacketDeviceStats::default(),
            authority_revoked: false,
            tx_checksum_offload: false,
            rx_checksum_offload: false,
            #[cfg(feature = "bounded-gro")]
            gro: gro::Buffer::new(),
            #[cfg(feature = "gro-end-profile")]
            gro_last_none: gro::NoInput::Unsupported,
            #[cfg(feature = "bounded-gro")]
            pending_ingress: None,
            #[cfg(feature = "bounded-gro")]
            ingress_remaining: usize::MAX,
        }
    }

    pub const fn set_tx_checksum_offload(&mut self, enabled: bool) {
        self.tx_checksum_offload = enabled;
    }

    #[cfg(feature = "gro-scatter")]
    fn clear_gro_loans(&mut self) {
        let mut releases = vibeos_core::net_receive::ReleaseBatch::<{ gro::MAX_SEGMENTS }>::new();
        for slot in &mut self.gro_loans[..self.gro_loan_count] {
            if let Some(loan) = slot.take() {
                if let Err(loan) = releases.push(loan) { drop(loan); }
            }
        }
        self.gro_loan_count = 0;
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
            || self.inbound.revalidate().is_err()
            || self.outbound.revalidate().is_err()
        {
            self.authority_revoked = true;
            return Err(StackError::AuthorityRevoked);
        }
        self.authority_result()
    }

    /// Try once to publish a frame retained after endpoint backpressure.
    pub fn flush_egress(&mut self) -> Result<bool, StackError> {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::TxFlush);
        self.authority_result()?;
        #[cfg(feature = "native-tcp-segmentation")]
        if let Some(pending) = self.pending_pooled.as_mut() {
            match pending.publish() {
                Ok(true) => {
                    self.stats.tx_frames = self.stats.tx_frames.saturating_add(pending.frames);
                    self.pending_pooled = None;
                    self.stats.pending_egress = false;
                    return Ok(true);
                }
                Ok(false) => {
                    self.stats.tx_backpressure_events = self.stats.tx_backpressure_events.saturating_add(1);
                    return Ok(false);
                }
                Err(_) => {
                    self.pending_pooled = None;
                    self.authority_revoked = true;
                    return Err(StackError::AuthorityRevoked);
                }
            }
        }
        #[cfg(feature = "native-tcp-segmentation")]
        if self.pending_segments.is_some() {
            // One logical request owns its bytes until every software segment
            // has entered the existing queue. No successor may overtake it.
            for _ in 0..32 {
                let pending = self.pending_segments.as_mut().unwrap();
                let request = pending.request(self.stamp).expect("immutable adapter session");
                let index = pending.next_segment();
                let length = request.header_bytes()
                    + (request.payload_bytes() - index * request.mss()).min(request.mss());
                let (frame, _) = Packet::write_with(length, |out| request.write_segment(index, out).unwrap())
                    .expect("bounded software segment");
                let packet = StampedPacket::new(frame, self.stamp);
                match self.outbound.send_frame(packet) {
                    Ok(Ok(())) => {
                        pending.accepted().unwrap();
                        self.stats.tx_frames = self.stats.tx_frames.saturating_add(1);
                        if pending.is_complete() {
                            self.pending_segments = None;
                            self.stats.pending_egress = false;
                            return Ok(true);
                        }
                    }
                    Ok(Err(_)) => {
                        self.stats.tx_backpressure_events = self.stats.tx_backpressure_events.saturating_add(1);
                        self.stats.pending_egress = true;
                        return Ok(false);
                    }
                    Err(_) => {
                        self.pending_segments = None;
                        self.authority_revoked = true;
                        self.stats.pending_egress = false;
                        return Err(StackError::AuthorityRevoked);
                    }
                }
            }
            return Ok(false);
        }
        let Some(packet) = self.pending_egress.take() else {
            self.stats.pending_egress = false;
            return Ok(true);
        };
        match self.outbound.send_frame(packet) {
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
        #[cfg(feature = "rx-admission-batch")]
        if self.rx_batch.len() != 0 { return Ok(true); }
        if self.pending_egress.is_some() {
            return Ok(true);
        }
        #[cfg(feature = "native-tcp-segmentation")]
        if self.pending_segments.is_some() || self.pending_pooled.is_some() { return Ok(true); }
        #[cfg(feature = "bounded-gro")]
        if self.pending_ingress.is_some() { return Ok(true); }
        #[cfg(feature = "gro-checked")]
        if self.checked_rx.has_pending() { return Ok(true); }
        #[cfg(all(feature = "pooled-rx", feature = "bounded-gro"))]
        if self.pending_rx_loan.is_some() { return Ok(true); }
        match self.inbound.has_message() {
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
        #[cfg(feature = "native-tcp-segmentation")]
        { stats.pending_egress |= self.pending_segments.is_some() || self.pending_pooled.is_some(); }
        #[cfg(feature = "bounded-gro")]
        {
            stats.gro_merged_segments = self.gro.merged_segments;
            stats.gro_aggregates = self.gro.aggregates;
            #[cfg(feature = "gro-end-profile")]
            { stats.gro_end_profile = self.gro.profile; }
        }
        stats
    }

    #[cfg(feature = "native-tcp-segmentation")]
    fn reserve_transmit(&mut self) -> Option<Option<transmit::Reservation>> {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::TxReserve);
        match self.outbound.reserve(self.stamp) {
            Ok(reservation) => Some(reservation),
            Err(transmit::ReserveError::Pool(vibeos_core::net_segment_pool::Error::Full)) => {
                self.stats.tx_backpressure_events = self.stats.tx_backpressure_events.saturating_add(1);
                None
            }
            Err(_) => { self.authority_revoked = true; None }
        }
    }

    #[cfg(feature = "pooled-rx")]
    fn receive_pooled(&mut self) -> Option<vibeos_core::net_receive::Loan> {
        let _scope = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::RxLoan);
        #[cfg(feature = "bounded-gro")]
        if self.ingress_remaining == 0 {
            #[cfg(feature = "gro-end-profile")]
            { self.gro_last_none = gro::NoInput::IngressBudget; }
            return None;
        }
        #[cfg(feature = "rx-admission-batch")]
        let received = if self.rx_batch.len() != 0 {
            Some(Ok(self.rx_batch.pop().unwrap().map(Some)))
        } else {
            self.inbound.receive_batch_into(self.stamp, self.ingress_remaining.min(8), &mut self.rx_batch).map(|result| match result {
                Ok(Ok(count)) => {
                    self.stats.rx_admission_sizes[count] += 1;
                    Ok(self.rx_batch.pop().map_or(Ok(None), |r| r.map(Some)))
                },
                Ok(Err(error)) => Ok(Err(error)),
                Err(error) => Err(error),
            })
        };
        #[cfg(not(feature = "rx-admission-batch"))]
        let received = self.inbound.receive_loan(self.stamp);
        let Some(result) = received else {
            #[cfg(feature = "gro-end-profile")]
            { self.gro_last_none = gro::NoInput::Unsupported; }
            return None;
        };
        if !matches!(&result, Ok(Ok(None)) | Err(_)) {
            #[cfg(feature = "bounded-gro")]
            { self.ingress_remaining -= 1; }
        }
        match result {
            Ok(Ok(loan)) => {
                if loan.is_some() { self.stats.rx_frames = self.stats.rx_frames.saturating_add(1); }
                #[cfg(feature = "gro-end-profile")]
                if loan.is_none() { self.gro_last_none = gro::NoInput::EmptyEndpoint; }
                loan
            }
            Err(_) => {
                #[cfg(feature = "gro-end-profile")]
                { self.gro_last_none = gro::NoInput::Authority; }
                self.authority_revoked = true; None
            }
            Ok(Err(error)) => {
                #[cfg(feature = "gro-end-profile")]
                { self.gro_last_none = gro::NoInput::Rejected; }
                self.stats.rejected_ingress_frames = self.stats.rejected_ingress_frames.saturating_add(1);
                if let vibeos_core::net_receive::Error::Session(mismatch) = error {
                    if mismatch.device_epoch_changed() {
                        self.stats.rejected_device_epoch_frames = self.stats.rejected_device_epoch_frames.saturating_add(1);
                    } else {
                        self.stats.rejected_stack_generation_frames = self.stats.rejected_stack_generation_frames.saturating_add(1);
                    }
                }
                None
            }
        }
    }

    fn receive_packet(&mut self) -> Option<Packet> {
        #[cfg(feature = "bounded-gro")]
        if self.ingress_remaining == 0 {
            #[cfg(feature = "gro-end-profile")]
            { self.gro_last_none = gro::NoInput::IngressBudget; }
            return None;
        }
        let packet = match self.inbound.raw_receive() {
            Ok(Some(packet)) => packet,
            Ok(None) => {
                #[cfg(feature = "gro-end-profile")]
                { self.gro_last_none = gro::NoInput::EmptyEndpoint; }
                return None;
            },
            Err(_) => {
                #[cfg(feature = "gro-end-profile")]
                { self.gro_last_none = gro::NoInput::Authority; }
                self.authority_revoked = true;
                return None;
            }
        };
        #[cfg(feature = "bounded-gro")]
        { self.ingress_remaining -= 1; }
        let packet = match packet.into_packet(self.stamp) {
            Ok(packet) => packet,
            Err(mismatch) => {
                #[cfg(feature = "gro-end-profile")]
                { self.gro_last_none = gro::NoInput::Rejected; }
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
        Some(packet)
    }

    fn authority_result(&self) -> Result<(), StackError> {
        if self.authority_revoked {
            Err(StackError::AuthorityRevoked)
        } else {
            Ok(())
        }
    }
}

/// Pooled builds borrow pinned storage; legacy builds retain the original
/// owning token so moving into a second inline frame does not add a packet copy.
#[cfg(feature = "pooled-rx")]
type RxBytes<'a> = &'a [u8];
#[cfg(not(feature = "pooled-rx"))]
enum RxBytes<'a> {
    Single(Packet, core::marker::PhantomData<&'a ()>),
    #[cfg(feature = "bounded-gro")]
    Coalesced(&'a [u8]),
}
#[inline]
fn single_rx(packet: Packet, storage: &mut Option<Packet>) -> RxBytes<'_> {
    #[cfg(feature = "pooled-rx")]
    { *storage = Some(packet); storage.as_ref().unwrap().as_bytes() }
    #[cfg(not(feature = "pooled-rx"))]
    { let _ = storage; RxBytes::Single(packet, core::marker::PhantomData) }
}
#[cfg(feature = "bounded-gro")]
#[inline]
fn coalesced_rx(bytes: &[u8]) -> RxBytes<'_> {
    #[cfg(feature = "pooled-rx")]
    { bytes }
    #[cfg(not(feature = "pooled-rx"))]
    { RxBytes::Coalesced(bytes) }
}
pub struct PacketRxToken<'a>(RxBytes<'a>,
    #[cfg(feature = "gro-scatter")] Option<&'a [Option<vibeos_core::net_receive::Loan>]>,
    #[cfg(feature = "gro-checked")] Option<checked_gro::Token<'a>>);
impl phy::RxToken for PacketRxToken<'_> {
    #[cfg(feature = "gro-checked")]
    fn consume_gro_checked<R, F>(mut self, caps: &phy::ChecksumCapabilities, f: F) -> R
    where F: FnOnce(phy::TcpGroRx<'_>) -> R {
        if let Some(token) = self.2.take() {
            return token.consume(caps, |received, _| f(received));
        }
        self.consume_gro(|frames| match frames {
            [frame] => f(phy::TcpGroRx::Frame(frame)),
            _ => f(match phy::TcpGro::new(frames, caps) {
                Some(group) => phy::TcpGroRx::Group(group),
                None => phy::TcpGroRx::Invalid,
            }),
        })
    }
    #[cfg(feature = "gro-scatter")]
    #[allow(unused_mut)]
    fn consume_gro<R, F>(mut self, f: F) -> R where F: FnOnce(&[&[u8]]) -> R {
        #[cfg(feature = "gro-checked")]
        if let Some(token) = self.2.take() {
            let caps = token.caps.clone();
            return token.consume(&caps, |_, frames| f(frames));
        }
        let mut frames = [&[][..]; gro::MAX_SEGMENTS];
        frames[0] = self.0;
        let mut count = 1;
        if let Some(loans) = self.1 {
            for loan in loans {
                frames[count] = loan.as_ref().expect("admitted GRO loan").as_bytes();
                count += 1;
            }
        }
        f(&frames[..count])
    }
    #[allow(unused_mut)]
    fn consume<R, F>(mut self, f: F) -> R where F: FnOnce(&[u8]) -> R {
        #[cfg(feature = "gro-checked")]
        if let Some(token) = self.2.take() {
            let caps = token.caps.clone();
            return token.consume(&caps, |received, _| match received {
                phy::TcpGroRx::Frame(frame) => f(frame),
                phy::TcpGroRx::Group(group) => f(&group.materialize()),
                phy::TcpGroRx::Invalid => f(&[]),
            });
        }
        #[cfg(feature = "gro-scatter")]
        if self.1.is_some() {
            return self.consume_gro(|frames| {
                match phy::TcpGro::new(frames, &phy::ChecksumCapabilities::ignored()) {
                    Some(gro) => f(&gro.materialize()),
                    None => f(&[]),
                }
            });
        }
        #[cfg(feature = "pooled-rx")]
        { f(self.0) }
        #[cfg(not(feature = "pooled-rx"))]
        { match self.0 {
            RxBytes::Single(packet, _) => f(packet.as_bytes()),
            #[cfg(feature = "bounded-gro")]
            RxBytes::Coalesced(bytes) => f(bytes),
        } }
    }
}

/// A transmit token borrowing the adapter's authority and pending slots.
/// The device borrow already bounds its lifetime; cloning authority per token
/// would add reference-count traffic without extending useful ownership.
pub struct PacketTxToken<'a> {
    stamp: PacketStamp,
    outbound: &'a PacketTransmit,
    pending_egress: &'a mut Option<StampedPacket>,
    #[cfg(feature = "native-tcp-segmentation")]
    pending_segments: &'a mut Option<vibeos_core::net_segmentation::SoftwareTransmit>,
    #[cfg(feature = "native-tcp-segmentation")]
    segment_size: Option<u16>,
    #[cfg(feature = "native-tcp-segmentation")]
    reservation: Option<transmit::Reservation>,
    #[cfg(feature = "native-tcp-segmentation")]
    pending_pooled: &'a mut Option<transmit::Reservation>,
    stats: &'a mut PacketDeviceStats,
    authority_revoked: &'a mut bool,
}

impl phy::TxToken for PacketTxToken<'_> {
    #[cfg(feature = "native-tcp-segmentation")]
    fn set_meta(&mut self, meta: phy::PacketMeta) { self.segment_size = meta.tcp_segment_size; }
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        #[cfg(feature = "native-tcp-segmentation")]
        if let Some(mss) = self.segment_size {
            if let Some(mut reservation) = self.reservation {
                let ticket = reservation.ticket.unwrap();
                let mut fill = Some(f);
                let written = reservation.authority.try_with(|q| {
                    q.pool().write(ticket, self.stamp, len, mss as usize, fill.take().unwrap())
                        .expect("valid native TCP serialization")
                });
                let result = match written {
                    Ok(result) => result,
                    Err(_) => {
                        // TxToken requires the serializer's return value even
                        // after revocation. Use task-local scratch only here.
                        assert!(len <= vibeos_core::net_segmentation::MAX_LOGICAL_PACKET);
                        let mut scratch = vec![0; len];
                        *self.authority_revoked = true;
                        return fill.take().unwrap()(&mut scratch);
                    }
                };
                #[cfg(feature = "network-tx-audit")]
                let _ = reservation.authority.try_with(|q| q.pool().try_consume(ticket, self.stamp, |request| {
                    vibeos_core::net_tx_audit::record_segments(0, request);
                    Err::<(), ()>(()) // Inspection does not release the pending request.
                }));
                reservation.frames = (len - 54).div_ceil(mss as usize) as u64;
                self.stats.tx_segmented_requests = self.stats.tx_segmented_requests.saturating_add(1);
                match reservation.publish() {
                    Ok(true) => self.stats.tx_frames = self.stats.tx_frames.saturating_add(reservation.frames),
                    Ok(false) => { *self.pending_pooled = Some(reservation); self.stats.pending_egress = true; }
                    Err(_) => { *self.authority_revoked = true; }
                }
                return result;
            }
            use vibeos_core::net_segmentation::{StampedSegments, SoftwareTransmit};
            assert!(self.pending_egress.is_none() && self.pending_segments.is_none());
            let (message, result) = StampedSegments::write_with(len, mss as usize, self.stamp, f)
                .expect("stack supplied a supported TCP segmentation request");
            vibeos_core::net_tx_audit::record_segments(0, message.request(self.stamp).unwrap());
            if self.outbound.revalidate().is_err() {
                *self.authority_revoked = true;
                self.stats.pending_egress = false;
            } else {
                *self.pending_segments = Some(SoftwareTransmit::new(message));
                self.stats.tx_segmented_requests = self.stats.tx_segmented_requests.saturating_add(1);
                self.stats.pending_egress = true;
            }
            return result;
        }
        #[cfg(feature = "native-tcp-segmentation")]
        drop(self.reservation);
        assert!(
            len <= MAX_PACKET_LEN,
            "smoltcp emitted a frame larger than the advertised Ethernet MTU"
        );
        debug_assert!(self.pending_egress.is_none());

        let (frame, result) = Packet::write_with(len, f)
            .expect("smoltcp emitted an empty or oversized Ethernet frame");
        vibeos_core::net_tx_audit::record(0, frame.as_bytes());
        let packet = StampedPacket::new(frame, self.stamp);
        match self.outbound.send_frame(packet) {
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
        = PacketRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Include pooled loans and GRO, not only the legacy copied queue path.
        // The guard ends before token consumption, leaving TCP/IP work in its
        // parent protocol scope. TX reservation/flush inside receive is included.
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::PacketQueue);
        #[cfg(feature = "gro-scatter")]
        self.clear_gro_loans();
        #[cfg(feature = "gro-checked")]
        self.checked_rx.retire();
        // Previous tokens cannot coexist with this mutable device invocation.
        // Dropping an admitted loan releases storage even after revocation.
        #[cfg(feature = "pooled-rx")]
        { self.rx_loan = None; }
        #[cfg(feature = "bounded-gro")]
        if self.revalidate_authority().is_err() {
            #[cfg(feature = "gro-checked")]
            self.checked_rx.clear();
            #[cfg(feature = "pooled-rx")]
            { self.pending_rx_loan = None; }
            #[cfg(feature = "rx-admission-batch")]
            { self.rx_batch = vibeos_core::net_receive::LoanBatch::empty(); }
            return None;
        }
        if self.flush_egress() != Ok(true) {
            return None;
        }
        #[cfg(feature = "native-tcp-segmentation")]
        let reservation = self.reserve_transmit()?;
        #[cfg(feature = "gro-checked")]
        if matches!(&self.inbound, PacketReceive::Pooled { .. }) {
            while self.checked_rx.len() < gro::MAX_SEGMENTS {
                let Some(loan) = self.receive_pooled() else { break; };
                self.checked_rx.push(loan);
            }
            if self.authority_revoked || self.revalidate_authority().is_err() {
                self.checked_rx.clear();
                #[cfg(feature = "rx-admission-batch")]
                { self.rx_batch = vibeos_core::net_receive::LoanBatch::empty(); }
                return None;
            }
            if self.checked_rx.len() == 0 { return None; }
            let caps = self.capabilities().checksum;
            return Some((
                PacketRxToken(&[], None, Some(checked_gro::Token {
                    window: &mut self.checked_rx,
                    stats: &mut self.gro,
                    caps,
                    #[cfg(feature = "gro-end-profile")]
                    no_input: self.gro_last_none,
                })),
                PacketTxToken {
                    stamp: self.stamp,
                    outbound: &self.outbound,
                    pending_egress: &mut self.pending_egress,
                    #[cfg(feature = "native-tcp-segmentation")]
                    pending_segments: &mut self.pending_segments,
                    #[cfg(feature = "native-tcp-segmentation")]
                    segment_size: None,
                    #[cfg(feature = "native-tcp-segmentation")]
                    reservation,
                    #[cfg(feature = "native-tcp-segmentation")]
                    pending_pooled: &mut self.pending_pooled,
                    stats: &mut self.stats,
                    authority_revoked: &mut self.authority_revoked,
                },
            ));
        }
        #[cfg(feature = "pooled-rx")]
        if matches!(&self.inbound, PacketReceive::Pooled { .. }) {
            #[cfg(feature = "bounded-gro")]
            let loan = self.pending_rx_loan.take().or_else(|| self.receive_pooled())?;
            #[cfg(not(feature = "bounded-gro"))]
            let loan = self.receive_pooled()?;
            #[cfg(feature = "gro-scatter")]
            let began = self.gro.begin_scattered(loan.as_bytes(), self.rx_checksum_offload);
            #[cfg(all(feature = "bounded-gro", not(feature = "gro-scatter")))]
            let began = self.gro.begin(loan.as_bytes(), self.rx_checksum_offload);
            #[cfg(feature = "bounded-gro")]
            if began {
                #[cfg(all(feature = "gro-batch-release", not(feature = "gro-scatter")))]
                let mut releases = vibeos_core::net_receive::ReleaseBatch::<{ gro::MAX_SEGMENTS }>::new();
                for _ in 1..gro::MAX_SEGMENTS {
                    if self.gro.finished() { break; }
                    let Some(next) = self.receive_pooled() else {
                        #[cfg(feature = "gro-end-profile")]
                        self.gro.profile_no_input(self.gro_last_none);
                        break;
                    };
                    if !self.gro.append(loan.as_bytes(), next.as_bytes(), self.rx_checksum_offload) {
                        self.pending_rx_loan = Some(next);
                        break;
                    }
                    // Copied GRO can release followers now. Scatter GRO retains
                    // each original loan through synchronous token consumption;
                    // the next receive or device destruction releases it.
                    #[cfg(feature = "gro-scatter")]
                    {
                        self.gro_loans[self.gro_loan_count] = Some(next);
                        self.gro_loan_count += 1;
                    }
                    #[cfg(all(feature = "gro-batch-release", not(feature = "gro-scatter")))]
                    if let Err(loan) = releases.push(next) { drop(loan); }
                }
            }
            #[cfg(feature = "gro-end-profile")]
            self.gro.profile_record();
            #[cfg(feature = "bounded-gro")]
            if self.authority_revoked || self.revalidate_authority().is_err() {
                #[cfg(feature = "gro-scatter")]
                self.clear_gro_loans();
                self.pending_rx_loan = None;
                #[cfg(feature = "rx-admission-batch")]
                { self.rx_batch = vibeos_core::net_receive::LoanBatch::empty(); }
                return None;
            }
            self.rx_loan = Some(loan);
            #[cfg(feature = "bounded-gro")]
            let bytes = if self.gro.has_aggregate() {
                self.gro.finish(self.rx_checksum_offload);
                #[cfg(feature = "gro-scatter")]
                { self.rx_loan.as_ref()?.as_bytes() }
                #[cfg(not(feature = "gro-scatter"))]
                { self.gro.bytes() }
            } else { self.rx_loan.as_ref()?.as_bytes() };
            #[cfg(not(feature = "bounded-gro"))]
            let bytes = self.rx_loan.as_ref()?.as_bytes();
            return Some((
                PacketRxToken(bytes,
                    #[cfg(feature = "gro-scatter")]
                    if self.gro_loan_count == 0 { None } else { Some(&self.gro_loans[..self.gro_loan_count]) },
                    #[cfg(feature = "gro-checked")] None),
                PacketTxToken {
                    stamp: self.stamp,
                    outbound: &self.outbound,
                    pending_egress: &mut self.pending_egress,
                    #[cfg(feature = "native-tcp-segmentation")]
                    pending_segments: &mut self.pending_segments,
                    #[cfg(feature = "native-tcp-segmentation")]
                    segment_size: None,
                    #[cfg(feature = "native-tcp-segmentation")]
                    reservation,
                    #[cfg(feature = "native-tcp-segmentation")]
                    pending_pooled: &mut self.pending_pooled,
                    stats: &mut self.stats,
                    authority_revoked: &mut self.authority_revoked,
                },
            ));
        }
        #[cfg(feature = "bounded-gro")]
        let packet = self.pending_ingress.take().or_else(|| self.receive_packet())?;
        #[cfg(not(feature = "bounded-gro"))]
        let packet = self.receive_packet()?;
        #[cfg(feature = "bounded-gro")]
        let bytes = if self.gro.begin(packet.as_bytes(), self.rx_checksum_offload) {
            for _ in 1..gro::MAX_SEGMENTS {
                if self.gro.finished() { break; }
                let Some(next) = self.receive_packet() else {
                        #[cfg(feature = "gro-end-profile")]
                        self.gro.profile_no_input(self.gro_last_none);
                        break;
                    };
                if !self.gro.append(packet.as_bytes(), next.as_bytes(), self.rx_checksum_offload) {
                    self.pending_ingress = Some(next);
                    break;
                }
            }
            #[cfg(feature = "gro-end-profile")]
            self.gro.profile_record();
            // Revocation observed while gathering invalidates the whole token.
            if self.authority_revoked { return None; }
            if self.gro.has_aggregate() {
                self.gro.finish(self.rx_checksum_offload);
                coalesced_rx(self.gro.bytes())
            } else {
                single_rx(packet, &mut self.rx_packet)
            }
        } else {
            #[cfg(feature = "gro-end-profile")]
            self.gro.profile_record();
            single_rx(packet, &mut self.rx_packet)
        };
        #[cfg(not(feature = "bounded-gro"))]
        let bytes = { single_rx(packet, &mut self.rx_packet) };
        Some((
            PacketRxToken(bytes, #[cfg(feature = "gro-scatter")] None,
                #[cfg(feature = "gro-checked")] None),
            PacketTxToken {
                stamp: self.stamp,
                outbound: &self.outbound,
                pending_egress: &mut self.pending_egress,
                #[cfg(feature = "native-tcp-segmentation")]
                pending_segments: &mut self.pending_segments,
                #[cfg(feature = "native-tcp-segmentation")]
                segment_size: None,
                #[cfg(feature = "native-tcp-segmentation")]
                reservation,
                #[cfg(feature = "native-tcp-segmentation")]
                pending_pooled: &mut self.pending_pooled,
                stats: &mut self.stats,
                authority_revoked: &mut self.authority_revoked,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.flush_egress() != Ok(true) {
            return None;
        }
        #[cfg(feature = "native-tcp-segmentation")]
        let reservation = self.reserve_transmit()?;
        Some(PacketTxToken {
            stamp: self.stamp,
            outbound: &self.outbound,
            pending_egress: &mut self.pending_egress,
            #[cfg(feature = "native-tcp-segmentation")]
            pending_segments: &mut self.pending_segments,
            #[cfg(feature = "native-tcp-segmentation")]
            segment_size: None,
            #[cfg(feature = "native-tcp-segmentation")]
            reservation,
            #[cfg(feature = "native-tcp-segmentation")]
            pending_pooled: &mut self.pending_pooled,
            stats: &mut self.stats,
            authority_revoked: &mut self.authority_revoked,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = MAX_PACKET_LEN;
        #[cfg(feature = "native-tcp-segmentation")]
        { capabilities.tcp_max_segmented_len = Some(vibeos_core::net_segmentation::MAX_LOGICAL_PACKET); }
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
    #[cfg(feature = "receive-buffer-exchange")]
    pub exchanged_bytes: usize,
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

#[cfg(feature = "receive-buffer-exchange")]
enum ExchangeFrontend {
    Assembled(alloc::sync::Arc<TcpListener>),
    Capability(vibeos_core::cap::Revocable<TcpListener>),
}
#[cfg(feature = "receive-buffer-exchange")]
impl ExchangeFrontend {
    fn matches(&self, frontend: &TcpListener) -> bool {
        match self {
            Self::Assembled(value) => core::ptr::eq(value.as_ref(), frontend),
            Self::Capability(value) => value.try_with(|value| core::ptr::eq(value, frontend)).unwrap_or(false),
        }
    }
}

#[cfg(feature = "receive-buffer-exchange")]
struct ExchangeSockets {
    failed: bool,
    frontend: ExchangeFrontend,
    owner: vibeos_net_api::receive_ownership::Owner,
    bindings: Vec<(SocketHandle, receive_exchange::Binding<{ vibeos_net_api::RECEIVE_POOL_SLOTS }>)>,
}

struct TcpListenerEntry {
    #[cfg(feature = "receive-buffer-exchange")]
    exchange: Option<ExchangeSockets>,
    socket: SocketHandle,
    // One bounded pending connection for exclusive service ports. Shared port
    // groups already allocate their own parallel connection sockets.
    pending: Option<SocketHandle>,
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

// Normal destruction is distinct from supervisor hard-fault retirement. Remove
// every socket reference before releasing only the writers owned by this stack.
// Published frontend ranges and other stacks using the same task are untouched.
#[cfg(feature = "receive-buffer-exchange")]
impl Drop for SharedIpv4TcpStack {
    fn drop(&mut self) {
        let sockets = core::mem::replace(&mut self.sockets, SocketSet::new(Vec::new()));
        drop(sockets);
        for listener in &mut self.listeners {
            if let Some(exchange) = listener.exchange.take() {
                for (_, binding) in exchange.bindings {
                    // The private SocketSet was the sole holder of each
                    // binding's current mutable buffer; it has now been dropped.
                    // Invalid metadata remains quarantined rather than freeing
                    // an unverified slot. Hard-fault lock recovery is separate.
                    let _ = unsafe { binding.release_writer() };
                }
            }
        }
    }
}

impl SharedIpv4TcpStack {
    pub fn new(
        config: Ipv4StackConfig,
        stamp: PacketStamp,
        inbound: impl Into<PacketReceive>,
        outbound: impl Into<PacketTransmit>,
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

        let socket = self.sockets.add(passive_socket(port));
        let pending = port_group.is_none().then(|| self.sockets.add(passive_socket(port)));
        let generation = self.next_listener_generation;
        self.next_listener_generation = self
            .next_listener_generation
            .checked_add(1)
            .ok_or(StackError::TcpListenerLimitReached)?;
        let slot = u8::try_from(self.listeners.len())
            .expect("the bounded TCP listener table fits in a u8");
        self.listeners.push(TcpListenerEntry {
            #[cfg(feature = "receive-buffer-exchange")]
            exchange: None,
            socket,
            pending,
            port,
            port_group,
            generation,
            connection_active: false,
            reset_requested: false,
            last_poll: TcpListenerPollReport::default(),
        });
        Ok(TcpListenerHandle { slot, generation })
    }

    /// Attach permanent RX storage before any network poll or connection activity.
    /// Both the active and pending sockets retain their original handles, so
    /// pending-connection promotion does not change buffer/binding identity.
    ///
    /// # Safety
    /// The stack must remain exclusively owned by `owner` until it is dropped.
    /// No retirement of that owner's pool slots is allowed before all stack
    /// socket references are dead. Hard-fault recovery is not implemented here;
    /// image assembly must not enable this without a supervisor protocol.
    #[cfg(feature = "receive-buffer-exchange")]
    pub unsafe fn enable_receive_exchange(&mut self, listener: TcpListenerHandle,
        frontend: alloc::sync::Arc<TcpListener>, owner: vibeos_net_api::receive_ownership::Owner,
    ) -> Result<(), TcpFrontendDriveError> {
        let retained = ExchangeFrontend::Assembled(frontend.clone());
        unsafe { self.install_receive_exchange(listener, frontend.as_ref(), retained, owner) }
    }

    /// Capability-preserving variant for the netstack service. No bare Arc or
    /// resource reference is extracted from the resolved authority.
    ///
    /// # Safety
    /// The same producer ownership and quiescence requirements as
    /// enable_receive_exchange apply for the full stack lifetime.
    #[cfg(feature = "receive-buffer-exchange")]
    pub unsafe fn enable_receive_exchange_capability(&mut self, listener: TcpListenerHandle,
        frontend: vibeos_core::cap::Revocable<TcpListener>, owner: vibeos_net_api::receive_ownership::Owner,
    ) -> Result<(), TcpFrontendDriveError> {
        let retained = ExchangeFrontend::Capability(frontend.clone());
        frontend.try_with(|value| unsafe { self.install_receive_exchange(listener, value, retained, owner) })
            .map_err(|_| TcpFrontendDriveError::QueueInvariant)?
    }

    /// Resolve producer identity from the executing task rather than policy
    /// input. Pool setup is a cold path; reads retain their lighter provenance.
    ///
    /// # Safety
    /// The stack must remain on this producer task until destruction, and the
    /// lifetime/quiescence contract of enable_receive_exchange still applies.
    #[cfg(feature = "receive-buffer-exchange")]
    pub unsafe fn enable_receive_exchange_current_task(&mut self, listener: TcpListenerHandle,
        frontend: vibeos_core::cap::Revocable<TcpListener>,
    ) -> Result<(), TcpFrontendDriveError> {
        let owner = vibeos_net_api::receive_ownership::Owner::current_producer()
            .ok_or(TcpFrontendDriveError::QueueInvariant)?;
        unsafe { self.enable_receive_exchange_capability(listener, frontend, owner) }
    }

    #[cfg(feature = "receive-buffer-exchange")]
    unsafe fn install_receive_exchange(&mut self, listener: TcpListenerHandle,
        frontend: &TcpListener, retained: ExchangeFrontend, owner: vibeos_net_api::receive_ownership::Owner,
    ) -> Result<(), TcpFrontendDriveError> {
        self.device.revalidate_authority()?;
        let index = self.listener_index(listener)?;
        let entry = &self.listeners[index];
        if entry.exchange.is_some() || entry.connection_active || self.last_now_ms != 0
            || frontend.port() != entry.port || frontend.port_group().map(|g| g.get()) != entry.port_group {
            return Err(TcpFrontendDriveError::QueueInvariant);
        }
        let pool = frontend.receive_storage().ok_or(TcpFrontendDriveError::QueueInvariant)?;
        let handles = [Some(entry.socket), entry.pending];
        if handles.into_iter().flatten().any(|handle| self.sockets.get::<tcp::Socket>(handle).state() != tcp::State::Listen)
            || frontend.snapshot().state != TcpStreamState::Listening {
            return Err(TcpFrontendDriveError::QueueInvariant);
        }
        let mut prepared = Vec::with_capacity(2);
        for handle in handles.into_iter().flatten() {
            match receive_exchange::Binding::new(pool, owner) {
                Ok((binding, buffer)) => prepared.push((handle, binding, buffer)),
                Err(_) => {
                    for (_, binding, buffer) in prepared {
                        drop(buffer);
                        unsafe { binding.release_writer() }.map_err(|_| TcpFrontendDriveError::QueueInvariant)?;
                    }
                    return Err(TcpFrontendDriveError::QueueInvariant);
                }
            }
        }
        let mut bindings = Vec::with_capacity(prepared.len());
        for (handle, binding, buffer) in prepared {
            *self.sockets.get_mut::<tcp::Socket>(handle) = passive_socket_with_receive(entry.port, buffer);
            bindings.push((handle, binding));
        }
        self.listeners[index].exchange = Some(ExchangeSockets { failed: false, frontend: retained, owner, bindings });
        Ok(())
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
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::Frontend);
        let phase = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::FrontendStatus);
        if self.tcp_listener_port(listener)? != frontend.port() {
            return Err(TcpFrontendDriveError::QueueInvariant);
        }

        // Empty directions must still reject revoked device authority.
        self.device.revalidate_authority()?;
        let mut report = TcpFrontendDriveReport::default();
        #[cfg(feature = "receive-buffer-exchange")]
        if let Some(exchange) = &self.listener(listener)?.exchange {
            if exchange.failed || !exchange.frontend.matches(frontend) {
                return Err(TcpFrontendDriveError::QueueInvariant);
            }
        }
        let transport = self.tcp_stream_status(listener)?;
        #[cfg(all(feature = "frontend-rx-batch", not(feature = "receive-buffer-exchange")))]
        let drive = {
            let entry = self.listener(listener)?;
            let socket = entry.socket;
            let reset_requested = entry.reset_requested;
            let (drive, result) = frontend.network_receive_drive(transport.state, |drive, batch| {
                let _phase = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::FrontendRx);
                let mut budget = drive.receive_capacity.min(transport.readable_bytes);
                for _ in 0..MAX_FRONTEND_CHUNKS_PER_DRIVE {
                    let capacity = budget.min(MAX_TCP_STREAM_BYTES_PER_CALL);
                    if capacity == 0 || reset_requested { break; }
                    self.device.revalidate_authority()?;
                    match self.sockets.get_mut::<tcp::Socket>(socket).recv(|input| {
                        let length = batch.receive(&input[..input.len().min(capacity)]);
                        (length, length)
                    }) {
                        Ok(0) | Err(tcp::RecvError::Finished | tcp::RecvError::InvalidState) => break,
                        Ok(length) => {
                            report.received_bytes += length;
                            budget -= length;
                        }
                    }
                }
                Ok::<(), TcpFrontendDriveError>(())
            })?;
            result?;
            drive
        };
        #[cfg(any(not(feature = "frontend-rx-batch"), feature = "receive-buffer-exchange"))]
        let drive = frontend.network_begin_drive(transport.state)?;
        drop(phase);
        // Conservative turn-local budgets. Concurrent application progress may
        // add work, but cannot cause over-consumption; next drive rechecks it.
        #[cfg(all(feature = "frontend-rx-batch", not(feature = "receive-buffer-exchange")))]
        let mut receive_budget: usize = 0;
        #[cfg(any(not(feature = "frontend-rx-batch"), feature = "receive-buffer-exchange"))]
        let mut receive_budget = drive.receive_capacity.min(transport.readable_bytes);
        let mut transmit_budget = drive.queued_send_bytes;
        // Borrow transport storage only for the synchronous copy. No socket
        // buffer escapes into the frontend, and each turn retains its byte and
        // chunk limits even when either ring wraps. This avoids clearing and
        // copying through a 32 KiB scratch buffer on every frontend poll.
        let phase = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::FrontendRx);
        #[cfg(feature = "receive-buffer-exchange")]
        if receive_budget != 0 {
            let index = self.listener_index(listener)?;
            let entry = &mut self.listeners[index];
            if let Some(exchange) = &mut entry.exchange {
                if !entry.reset_requested {
                    let generation = frontend.network_exchange_generation()
                        .ok_or(TcpFrontendDriveError::QueueInvariant)?;
                    let (_, binding) = exchange.bindings.iter_mut().find(|(handle, _)| *handle == entry.socket)
                        .ok_or(TcpFrontendDriveError::QueueInvariant)?;
                    // enable_receive_exchange's owner/lifetime contract and the
                    // private handle table preserve exclusive socket ownership.
                    let transfer = match unsafe { binding.exchange(self.sockets.get_mut::<tcp::Socket>(entry.socket), generation, receive_budget) } {
                        Ok(transfer) => transfer,
                        Err(_) => {
                            self.fail_receive_exchange(index, frontend);
                            return Err(TcpFrontendDriveError::QueueInvariant);
                        }
                    };
                    if let Some(transfer) = transfer {
                        let length = match frontend.network_publish_exchange(transfer.ticket, exchange.owner, generation) {
                            Ok(length) => length,
                            Err(error) => {
                                let cleanup = binding.discard_unpublished(transfer);
                                self.fail_receive_exchange(index, frontend);
                                cleanup.map_err(|_| TcpFrontendDriveError::QueueInvariant)?;
                                return Err(error.into());
                            }
                        };
                        report.exchanged_bytes += length;
                        report.received_bytes += length;
                        receive_budget -= length;
                    }
                }
            }
        }
        for _ in 0..MAX_FRONTEND_CHUNKS_PER_DRIVE {
            let capacity = receive_budget.min(MAX_TCP_STREAM_BYTES_PER_CALL);
            if capacity == 0 {
                break;
            }
            self.device.revalidate_authority()?;
            let entry = self.listener(listener)?;
            if entry.reset_requested {
                break;
            }
            let socket = entry.socket;
            match self.sockets.get_mut::<tcp::Socket>(socket).recv(|input| {
                let length = frontend.network_receive(&input[..input.len().min(capacity)]);
                (length, length)
            }) {
                Ok(0) | Err(tcp::RecvError::Finished | tcp::RecvError::InvalidState) => break,
                Ok(length) => {
                    report.received_bytes += length;
                    receive_budget -= length;
                }
            }
        }

        drop(phase);
        let phase = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::FrontendTx);
        for _ in 0..MAX_FRONTEND_CHUNKS_PER_DRIVE {
            if transmit_budget == 0 || self.tcp_stream_status(listener)?.writable_bytes == 0 {
                break;
            }
            self.device.revalidate_authority()?;
            let entry = self.listener(listener)?;
            if entry.reset_requested {
                break;
            }
            let socket = entry.socket;
            match self.sockets.get_mut::<tcp::Socket>(socket).send(|output| {
                let capacity = output.len().min(MAX_TCP_STREAM_BYTES_PER_CALL).min(transmit_budget);
                let length = frontend.network_copy_transmit(&mut output[..capacity]);
                (length, length)
            }) {
                Ok(0) => break,
                Ok(sent) => {
                    // Commit only bytes actually enqueued by the transport.
                    frontend.network_consume_transmit(sent);
                    report.transmitted_bytes += sent;
                    transmit_budget -= sent;
                }
                Err(tcp::SendError::InvalidState) => {
                    return Err(TcpFrontendDriveError::QueueInvariant);
                }
            }
        }

        drop(phase);
        let _phase = vibeos_core::net_profile::Scope::sampled(vibeos_core::net_profile::Stage::FrontendClose);
        if let Some(request) = frontend.close_request() {
            match request {
                TcpCloseRequest::Close => {
                    // A socket close drains only its own TX ring. The capability
                    // frontend can still hold bytes behind transport backpressure.
                    if frontend.snapshot().queued_send_bytes != 0 {
                        return Ok(report);
                    }
                    self.tcp_close(listener)?;
                }
                TcpCloseRequest::Reset => {
                    self.tcp_reset(listener)?;
                }
            }
            // Publish the non-writable state before lifting the pending-close
            // barrier, so another hart cannot append bytes in that interval.
            frontend.network_update_state(self.tcp_stream_status(listener)?.state)?;
            frontend.clear_close_request(request);
            report.close_applied = Some(request);
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
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::ProtocolPoll);
        let work = self.poll_with_application::<{ !cfg!(feature = "skip-empty-service") }>(now_ms, |_, _| 0)?;
        Ok(SharedTcpPollReport {
            ingress_frames: work.ingress_frames,
            more_work: work.more_network_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }

    fn poll_with_application<const SERVICE: bool>(
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

        #[cfg(feature = "bounded-gro")]
        { self.device.ingress_remaining = MAX_INGRESS_FRAMES_PER_POLL; }
        for _ in 0..MAX_INGRESS_FRAMES_PER_POLL {
            let ingress_result =
                self.interface
                    .poll_ingress_single(now, &mut self.device, &mut self.sockets);
            self.device.authority_result()?;
            match ingress_result {
                PollIngressSingleResult::None => {
                    ingress_budget_exhausted = false;
                    #[cfg(feature = "bounded-gro")]
                    { ingress_budget_exhausted = self.device.ingress_remaining == 0; }
                    break;
                }
                PollIngressSingleResult::PacketProcessed
                | PollIngressSingleResult::SocketStateChanged => {
                    ingress_frames += 1;
                    if SERVICE { application_bytes += self.service_listeners(&mut service); }
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

        if SERVICE { application_bytes += self.service_listeners(&mut service); }
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

    #[cfg(feature = "receive-buffer-exchange")]
    fn fail_receive_exchange(&mut self, index: usize, frontend: &TcpListener) {
        let entry = &mut self.listeners[index];
        if let Some(exchange) = &mut entry.exchange { exchange.failed = true; }
        self.sockets.get_mut::<tcp::Socket>(entry.socket).abort();
        if let Some(pending) = entry.pending { self.sockets.get_mut::<tcp::Socket>(pending).abort(); }
        entry.reset_requested = true;
        // Bytes removed from TCP but rejected by the frontend must never be
        // followed by later bytes on the same stream. Normal errors retire the
        // listener until stack rebuild; a caller cannot silently retry it.
        let _ = frontend.network_update_state(TcpStreamState::Reset);
    }

    fn ensure_listening(&mut self, rearm_resets: bool) {
        for listener in &mut self.listeners {
            #[cfg(feature = "receive-buffer-exchange")]
            if listener.exchange.as_ref().is_some_and(|exchange| exchange.failed) { continue; }
            if listener.reset_requested && !rearm_resets {
                continue;
            }
            if let Some(pending) = listener.pending {
                // Promote only at the START of a later turn. The prior turn
                // must publish the old connection's inactive edge so queued
                // capability bytes and close requests cannot cross generations.
                if !rearm_resets
                    && self.sockets.get::<tcp::Socket>(listener.socket).state() == tcp::State::Listen
                    && self.sockets.get::<tcp::Socket>(pending).is_active()
                {
                    let old = core::mem::replace(&mut listener.socket, pending);
                    listener.pending = Some(old);
                }
                let pending = self.sockets.get_mut::<tcp::Socket>(listener.pending.unwrap());
                if pending.state() == tcp::State::Closed {
                    pending.listen(listener.port).expect("validated pending port");
                }
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
            if let Some(pending) = listener.pending {
                self.sockets.get_mut::<tcp::Socket>(pending).abort();
            }
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
        inbound: impl Into<PacketReceive>,
        outbound: impl Into<PacketTransmit>,
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
        let _scope = vibeos_core::net_profile::Scope::enter(vibeos_core::net_profile::Stage::ProtocolPoll);
        let work = self.poll_with_application::<{ !cfg!(feature = "skip-empty-service") }>(now_ms, |_| 0)?;
        Ok(TcpPollReport {
            ingress_frames: work.ingress_frames,
            connection_started: work.connection_started,
            connection_ended: work.connection_ended,
            more_work: work.more_network_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }

    fn poll_with_application<const SERVICE: bool>(
        &mut self,
        now_ms: u64,
        mut service: impl FnMut(&mut tcp::Socket<'static>) -> usize,
    ) -> Result<NetworkPollWork, StackError> {
        let listener = self.listener;
        let work = self
            .shared
            .poll_with_application::<SERVICE>(now_ms, |candidate, socket| {
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
        inbound: impl Into<PacketReceive>,
        outbound: impl Into<PacketTransmit>,
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
        let work = self.tcp.poll_with_application::<true>(now_ms, service_echo)?;
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

fn passive_socket(port: u16) -> tcp::Socket<'static> {
    let receive = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_BYTES]);
    passive_socket_with_receive(port, receive)
}

fn passive_socket_with_receive(port: u16, receive: tcp::SocketBuffer<'static>) -> tcp::Socket<'static> {
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
    // A control connection may carry no application data while its separate
    // data connection is busy (e.g. a 60-second iperf test). Probe reachability
    // before the unchanged dead-peer timeout instead of expiring healthy peers.
    socket.set_keep_alive(Some(Duration::from_secs(TCP_IDLE_TIMEOUT_SECS / 3)));
    socket.set_timeout(Some(Duration::from_secs(TCP_IDLE_TIMEOUT_SECS)));
    socket
        .listen(port)
        .expect("validated non-zero TCP port must be listenable");

    socket
}
