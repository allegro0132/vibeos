//! Bounded, single-owner NAT44 mapping and return-flow policy.
//!
//! Mapping keys exclude the remote endpoint (endpoint-independent mapping).
//! Permissions include the remote IP/port. Lookups use at most eight probes;
//! collisions/full tables fail closed without evicting live flows. No allocation
//! occurs during forwarding. A transition into TCP closing/closed scans the
//! bounded flow table to release the historical established mapping deadline.
//! This is an initial LAN-originated policy, not an
//! endpoint TCP stack: established segments are checked against a bounded
//! observed sequence/window envelope, not reassembled or PAWS-validated.
//! Explicit TCP offload handoff instead retains connection/flag policy for
//! that connection, since hardware-forwarded sequence progress is unobserved.
//! Simultaneous open, hairpinning, port forwards and fragments remain unsupported.
//! Received ICMP errors use the separate quoted-flow authorization path.
use crate::ipv4::{self, Egress, Packet, PortRewrite, Translation, Transport};

use core::sync::atomic::{AtomicU64, Ordering};

pub mod tcp_offload;
pub use tcp_offload::{TcpForwardCache, TcpPermit, TcpPermitPair, TcpSoftwareFallback, TcpTuple};

// Distinguish receipts from different/recreated NAT owners, even with identical
// configuration, seed, slot indices and per-mapping generations. Never wrap.
static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);

const PORT_BASE: u16 = 49152;
const PROBES: usize = 8;
const UDP_MS: u64 = 120_000;
const ECHO_MS: u64 = 60_000;
const TCP_TRANSITORY_MS: u64 = 240_000;
const TCP_ESTABLISHED_MS: u64 = 7_440_000;
const TCP_CLOSED_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    LanToWan,
    WanToLan,
}
/// Exact UDP tuple; no wildcard remote authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpTuple {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
}
/// Receipt from a successfully committed software UDP forward. Private fields
/// prevent constructing authority from unvalidated packet hints. Copies retain
/// their original deadline; traffic or a newer receipt cannot extend them.
///
/// This is not a self-validating hardware capability: the same NAT owner must
/// revalidate it immediately before publication. Hardware must enforce ingress
/// direction and revoke before configuration/neighbor changes or this deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpPermit {
    identity: u64,
    direction: Direction,
    mapping: usize,
    flow: usize,
    generation: u64,
    internal: Internal,
    remote: Remote,
    wan: [u8; 4],
    issued: u64,
    until: u64,
}
/// Bounded hints from committed forwards, never independent authorization.
/// Callers must revalidate NAT, configuration and neighbor authority on use.
pub struct UdpForwardCache<const N: usize> {
    entries: [Option<(UdpPermit, Egress)>; N],
    next: usize,
}
impl<const N: usize> UdpForwardCache<N> {
    pub const fn new() -> Self { Self { entries: [None; N], next: 0 } }
    pub fn clear(&mut self) { self.entries.fill(None); self.next = 0; }
    pub fn forget(&mut self, direction: Direction, tuple: UdpTuple) {
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|(permit, _)| permit.direction() == direction && permit.original() == tuple) {
                *entry = None;
            }
        }
    }
    pub fn remember(&mut self, permit: UdpPermit, link: Egress) {
        let mut vacant = None;
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if entry.as_ref().is_some_and(|(old, _)| old.direction() == permit.direction()
                && old.original() == permit.original()) {
                *entry = Some((permit, link));
                return;
            }
            // A later slot may already hold this key: record the hole but
            // finish looking for an update before consuming any capacity.
            if entry.is_none() && vacant.is_none() { vacant = Some(index); }
        }
        if N != 0 {
            let index = vacant.unwrap_or(self.next);
            self.entries[index] = Some((permit, link));
            self.next = (index + 1) % N;
        }
    }
    pub fn lookup(&self, direction: Direction, tuple: UdpTuple) -> Option<(UdpPermit, Egress)> {
        self.entries.iter().flatten().find(|(permit, _)|
            permit.direction() == direction && permit.original() == tuple).copied()
    }
}
impl UdpPermit {
    pub fn direction(self) -> Direction {
        self.direction
    }
    pub fn expires_at(self) -> u64 {
        self.until
    }
    pub fn original(self) -> UdpTuple {
        let external = PORT_BASE + self.mapping as u16;
        match self.direction {
            Direction::LanToWan => UdpTuple {
                source: self.internal.ip,
                destination: self.remote.ip,
                source_port: self.internal.port,
                destination_port: self.remote.port,
            },
            Direction::WanToLan => UdpTuple {
                source: self.remote.ip,
                destination: self.wan,
                source_port: self.remote.port,
                destination_port: external,
            },
        }
    }
    pub fn translated(self) -> UdpTuple {
        let external = PORT_BASE + self.mapping as u16;
        match self.direction {
            Direction::LanToWan => UdpTuple {
                source: self.wan,
                source_port: external,
                ..self.original()
            },
            Direction::WanToLan => UdpTuple {
                destination: self.internal.ip,
                destination_port: self.internal.port,
                ..self.original()
            },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Clock,
    Denied,
    MappingCapacity,
    FlowCapacity,
    GenerationExhausted,
    Packet(ipv4::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub wan_ip: [u8; 4],
    pub lan_ip: [u8; 4],
    pub lan_prefix: u8,
}
impl Config {
    fn mask(self) -> u32 {
        u32::MAX << (32 - self.lan_prefix)
    }
    fn on_lan(self, ip: [u8; 4]) -> bool {
        u32::from_be_bytes(ip) & self.mask() == u32::from_be_bytes(self.lan_ip) & self.mask()
    }
    fn lan_host(self, ip: [u8; 4]) -> bool {
        let host = u32::from_be_bytes(ip) & !self.mask();
        unicast(ip) && self.on_lan(ip) && host != 0 && host != !self.mask() && ip != self.lan_ip
    }
    fn valid(self) -> bool {
        if !(1..=30).contains(&self.lan_prefix) || !unicast(self.lan_ip) || !unicast(self.wan_ip) {
            return false;
        }
        let host = u32::from_be_bytes(self.lan_ip) & !self.mask();
        host != 0 && host != !self.mask() && !self.on_lan(self.wan_ip)
    }
    fn remote(self, ip: [u8; 4]) -> bool {
        unicast(ip) && !self.on_lan(ip) && ip != self.wan_ip
    }
}
fn unicast(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Internal {
    ip: [u8; 4],
    port: u16,
    protocol: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mapping {
    key: Internal,
    generation: u64,
    until: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Remote {
    ip: [u8; 4],
    port: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Datagram,
    SynSent { client_next: u32 },
    SynReceived { client_next: u32, server_next: u32 },
    Established { client_next: u32, server_next: u32 },
    Closing,
    Closed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flow {
    tcp_incarnation: u64,
    tcp_offloaded: bool,
    window: Option<crate::tcp_window::Tracker>,
    mapping: usize,
    generation: u64,
    remote: Remote,
    until: u64,
    state: State,
}
use crate::tcp_window::Segment;

/// Coarse connection phase for display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowState {
    /// UDP or ICMP echo: no connection phases.
    Datagram,
    Opening,
    Established,
    Closing,
}
/// One tracked flow as shown to an operator. `protocol` is the IP protocol
/// number; for ICMP echo the ports hold the identifier and `remote_port` is 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowInfo {
    pub protocol: u8,
    pub internal: [u8; 4],
    pub internal_port: u16,
    pub external_port: u16,
    pub remote: [u8; 4],
    pub remote_port: u16,
    pub state: FlowState,
    pub expires_at: u64,
    /// The TCP connection was handed to hardware forwarding at some point.
    pub offloaded: bool,
}

/// `M` mapping slots reserve ports 49152..49152+M in TCP/UDP and echo IDs.
/// The image must keep this range out of its local listeners/port forwards.
/// `seed` distributes keys; this mixer is not a cryptographic hash. Probe bounds
/// cap collision work, but production entropy/hash-flood resistance is separate.
pub struct Table<const M: usize, const F: usize> {
    identity: u64,
    tcp_sequence: u64,
    config: Config,
    mappings: [Option<Mapping>; M],
    flows: [Option<Flow>; F],
    generation: u64,
    last_now: u64,
    seed: u64,
}
impl<const M: usize, const F: usize> Table<M, F> {
    pub fn new(config: Config, seed: u64) -> Result<Self, Error> {
        if M == 0 || M > 16384 || F == 0 || !config.valid() {
            return Err(Error::Configuration);
        }
        let identity = NEXT_IDENTITY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::GenerationExhausted)?;
        Ok(Self {
            identity,
            tcp_sequence: 0,
            config,
            mappings: [None; M],
            flows: [None; F],
            generation: 0,
            last_now: 0,
            seed,
        })
    }
    /// Heap-constructed table for capacities too large to build on a kernel
    /// stack and move. Every slot is written in place; behavior is otherwise
    /// identical to [`Table::new`].
    pub fn new_boxed(config: Config, seed: u64) -> Result<alloc::boxed::Box<Self>, Error> {
        if M == 0 || M > 16384 || F == 0 || !config.valid() {
            return Err(Error::Configuration);
        }
        let identity = NEXT_IDENTITY
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::GenerationExhausted)?;
        let mut table = alloc::boxed::Box::<Self>::new_uninit();
        let raw = table.as_mut_ptr();
        // Safety: `raw` is valid, exclusively owned, properly aligned storage
        // for `Self`. Each field is initialized exactly once below, the arrays
        // element by element, before `assume_init`. No field is read first.
        unsafe {
            use core::ptr::addr_of_mut;
            addr_of_mut!((*raw).identity).write(identity);
            addr_of_mut!((*raw).tcp_sequence).write(0);
            addr_of_mut!((*raw).config).write(config);
            let mappings = addr_of_mut!((*raw).mappings).cast::<Option<Mapping>>();
            for i in 0..M {
                mappings.add(i).write(None);
            }
            let flows = addr_of_mut!((*raw).flows).cast::<Option<Flow>>();
            for i in 0..F {
                flows.add(i).write(None);
            }
            addr_of_mut!((*raw).generation).write(0);
            addr_of_mut!((*raw).last_now).write(0);
            addr_of_mut!((*raw).seed).write(seed);
            Ok(table.assume_init())
        }
    }
    /// Table capacity as (mapping slots, flow slots).
    pub const fn capacity(&self) -> (usize, usize) {
        (M, F)
    }
    /// WAN lease or LAN/policy changes revoke all mappings and permissions.
    /// Validation precedes clearing, so an invalid update preserves old state.
    pub fn reconfigure(&mut self, config: Config) -> Result<(), Error> {
        if !config.valid() {
            return Err(Error::Configuration);
        }
        self.config = config;
        self.mappings.fill(None);
        self.flows.fill(None);
        Ok(())
    }
    /// Constant-work revalidation of a committed UDP receipt. No allocation,
    /// expiry refresh or mutation. A receipt cannot authorize the other ingress
    /// direction, a different NAT owner, or a reused mapping/remote flow slot.
    /// `now` must come from the routing owner's monotonic clock; this read-only
    /// check does not advance the table clock or schedule hardware revocation.
    pub fn validate_udp_permit(&self, permit: &UdpPermit, direction: Direction, now: u64) -> bool {
        if permit.identity != self.identity
            || permit.direction != direction
            || now < self.last_now
            || now < permit.issued
            || now >= permit.until
            || self.config.wan_ip != permit.wan
        {
            return false;
        }
        let Some(mapping) = self.mappings.get(permit.mapping).copied().flatten() else {
            return false;
        };
        let Some(flow) = self.flows.get(permit.flow).copied().flatten() else {
            return false;
        };
        mapping.key.protocol == 17
            && mapping.key == permit.internal
            && mapping.generation == permit.generation
            && mapping.until >= permit.until
            && flow.mapping == permit.mapping
            && flow.generation == permit.generation
            && flow.remote == permit.remote
            && flow.state == State::Datagram
            && flow.until >= permit.until
    }
    /// Forward an exact previously committed UDP flow without mutating NAT
    /// mappings, remote permissions, expiry or the table clock. No new receipt
    /// is issued and repeated packets cannot extend the supplied authority.
    ///
    /// The owner supplies monotonic time and must independently validate route,
    /// neighbor, MTU and ingress provenance, reserve TX capacity, and preserve
    /// ordering against any hardware/in-flight packets of this same flow.
    /// On error, the packet remains unchanged for normal control-path handling.
    pub fn forward_permitted_udp(
        &self,
        permit: &UdpPermit,
        direction: Direction,
        packet: Packet<'_>,
        egress: Egress,
        now: u64,
    ) -> Result<usize, Error> {
        if !self.validate_udp_permit(permit, direction, now) {
            return Err(Error::Denied);
        }
        let original = permit.original();
        if packet.source() != original.source || packet.destination() != original.destination
            || packet.transport() != (Transport::Udp {
                source: original.source_port, destination: original.destination_port,
            }) {
            return Err(Error::Denied);
        }
        let translated = permit.translated();
        packet.forward(egress, Some(ipv4::Translation {
            source: translated.source,
            destination: translated.destination,
            ports: ipv4::PortRewrite::Ports {
                source: translated.source_port, destination: translated.destination_port,
            },
        })).map_err(Error::Packet)
    }

    /// Diagnostic listing of live flows for operator display. A full scan:
    /// never call it per packet. Read-only; no expiry is refreshed.
    pub fn flows(&self, now: u64) -> impl Iterator<Item = FlowInfo> + '_ {
        self.flows.iter().flatten().filter(move |f| self.live_flow(**f, now)).map(|f| {
            let key = self.mappings[f.mapping].expect("live flow has a mapping").key;
            FlowInfo {
                protocol: key.protocol,
                internal: key.ip,
                internal_port: key.port,
                external_port: PORT_BASE + f.mapping as u16,
                remote: f.remote.ip,
                remote_port: f.remote.port,
                state: match f.state {
                    State::Datagram => FlowState::Datagram,
                    State::SynSent { .. } | State::SynReceived { .. } => FlowState::Opening,
                    State::Established { .. } => FlowState::Established,
                    State::Closing | State::Closed => FlowState::Closing,
                },
                expires_at: f.until,
                offloaded: f.tcp_offloaded,
            }
        })
    }
    /// Diagnostic count scan; ordinary established forwarding uses hash probes.
    pub fn active_counts(&self, now: u64) -> (usize, usize) {
        (
            self.mappings
                .iter()
                .flatten()
                .filter(|m| m.until > now)
                .count(),
            self.flows
                .iter()
                .flatten()
                .filter(|f| self.live_flow(**f, now))
                .count(),
        )
    }
    fn live_flow(&self, flow: Flow, now: u64) -> bool {
        flow.until > now
            && self.mappings[flow.mapping]
                .is_some_and(|m| m.until > now && m.generation == flow.generation)
    }
    fn mapping_slot(&self, key: Internal, now: u64) -> Result<(usize, bool), Error> {
        let hash = mix(self.seed
            ^ u32::from_be_bytes(key.ip) as u64
            ^ ((key.port as u64) << 32)
            ^ ((key.protocol as u64) << 48));
        let start = (hash % M as u64) as usize;
        let mut free = None;
        for probe in 0..PROBES.min(M) {
            let i = (start + probe) % M;
            match self.mappings[i] {
                Some(m) if m.until > now => {
                    if m.key == key {
                        return Ok((i, false));
                    }
                }
                _ => {
                    if free.is_none() {
                        free = Some(i);
                    }
                }
            }
        }
        free.map(|i| (i, true)).ok_or(Error::MappingCapacity)
    }
    fn flow_slot(
        &self,
        mapping: usize,
        generation: u64,
        remote: Remote,
        now: u64,
    ) -> Result<(usize, bool), Error> {
        let hash = mix(self.seed
            ^ generation.rotate_left(19)
            ^ mapping as u64
            ^ u32::from_be_bytes(remote.ip) as u64
            ^ ((remote.port as u64) << 32));
        let start = (hash % F as u64) as usize;
        let mut free = None;
        for probe in 0..PROBES.min(F) {
            let i = (start + probe) % F;
            match self.flows[i] {
                Some(f) if self.live_flow(f, now) => {
                    if f.mapping == mapping && f.generation == generation && f.remote == remote {
                        return Ok((i, false));
                    }
                }
                _ => {
                    if free.is_none() {
                        free = Some(i);
                    }
                }
            }
        }
        free.map(|i| (i, true)).ok_or(Error::FlowCapacity)
    }

    /// Convenience operation when the egress neighbor is already known.
    pub fn forward(
        &mut self,
        direction: Direction,
        packet: Packet<'_>,
        egress: Egress,
        now: u64,
    ) -> Result<usize, Error> {
        self.prepare(direction, packet, now)?.forward(egress)
    }

    /// Authorize a quoted error against an existing mapping AND remote flow.
    /// ICMP errors neither create state nor refresh its expiry (RFC 5508).
    /// A remote intermediate router may originate it; the quoted remote tuple,
    /// not the outer source address, selects the permission.
    pub fn prepare_error<'t, 'p>(
        &'t mut self,
        direction: Direction,
        packet: crate::icmp_nat::Packet<'p>,
        now: u64,
    ) -> Result<PreparedError<'t, 'p, M, F>, Error> {
        use crate::icmp_nat::{Quoted, Rewrite};
        if now < self.last_now {
            return Err(Error::Clock);
        }
        let (protocol, source_port, destination_port) = match packet.quoted() {
            Quoted::Tcp {
                source,
                destination,
            } => (6, source, destination),
            Quoted::Udp {
                source,
                destination,
            } => (17, source, destination),
            Quoted::Echo { identifier, reply } => {
                if reply != (direction == Direction::LanToWan) {
                    return Err(Error::Denied);
                }
                (1, identifier, identifier)
            }
        };
        let (slot, mapping, remote) = match direction {
            Direction::WanToLan => {
                if packet.destination() != self.config.wan_ip
                    || packet.quoted_source() != self.config.wan_ip
                    || !self.config.remote(packet.source())
                    || !self.config.remote(packet.quoted_destination())
                {
                    return Err(Error::Denied);
                }
                let slot = source_port.checked_sub(PORT_BASE).ok_or(Error::Denied)? as usize;
                let mapping = self
                    .mappings
                    .get(slot)
                    .copied()
                    .flatten()
                    .filter(|m| m.until > now && m.key.protocol == protocol)
                    .ok_or(Error::Denied)?;
                (
                    slot,
                    mapping,
                    Remote {
                        ip: packet.quoted_destination(),
                        port: if protocol == 1 { 0 } else { destination_port },
                    },
                )
            }
            Direction::LanToWan => {
                if !self.config.lan_host(packet.source())
                    || !self.config.lan_host(packet.quoted_destination())
                    || !self.config.remote(packet.destination())
                    || packet.destination() != packet.quoted_source()
                {
                    return Err(Error::Denied);
                }
                let key = Internal {
                    ip: packet.quoted_destination(),
                    port: destination_port,
                    protocol,
                };
                let (slot, fresh) = self.mapping_slot(key, now)?;
                if fresh {
                    return Err(Error::Denied);
                }
                (
                    slot,
                    self.mappings[slot].unwrap(),
                    Remote {
                        ip: packet.quoted_source(),
                        port: if protocol == 1 { 0 } else { source_port },
                    },
                )
            }
        };
        let (_, fresh) = self.flow_slot(slot, mapping.generation, remote, now)?;
        if fresh {
            return Err(Error::Denied);
        }
        let external = PORT_BASE + slot as u16;
        let rewrite = match direction {
            Direction::WanToLan => Rewrite {
                source: packet.source(),
                destination: mapping.key.ip,
                quoted: Translation {
                    source: mapping.key.ip,
                    destination: packet.quoted_destination(),
                    ports: if protocol == 1 {
                        PortRewrite::EchoIdentifier(mapping.key.port)
                    } else {
                        PortRewrite::Ports {
                            source: mapping.key.port,
                            destination: destination_port,
                        }
                    },
                },
            },
            Direction::LanToWan => Rewrite {
                source: self.config.wan_ip,
                destination: packet.destination(),
                quoted: Translation {
                    source: packet.quoted_source(),
                    destination: self.config.wan_ip,
                    ports: if protocol == 1 {
                        PortRewrite::EchoIdentifier(external)
                    } else {
                        PortRewrite::Ports {
                            source: source_port,
                            destination: external,
                        }
                    },
                },
            },
        };
        Ok(PreparedError {
            table: self,
            packet,
            rewrite,
            now,
        })
    }

    /// Authorize without mutation and expose the translated destination for
    /// route/neighbor lookup. Drop the preparation on an unresolved neighbor;
    /// never hold an RX descriptor while waiting for an ARP response behind it.
    /// A successful forward commits the packet and both tables together.
    pub fn prepare<'t, 'p>(
        &'t mut self,
        direction: Direction,
        packet: Packet<'p>,
        now: u64,
    ) -> Result<Prepared<'t, 'p, M, F>, Error> {
        if now < self.last_now {
            return Err(Error::Clock);
        }
        let source = packet.source();
        let destination = packet.destination();
        let (protocol, source_port, destination_port, segment) = match packet.transport() {
            Transport::Tcp {
                source,
                destination,
                ..
            } => (
                6,
                source,
                destination,
                packet.tcp_details().map_err(Error::Packet)?,
            ),
            Transport::Udp {
                source,
                destination,
            } => (17, source, destination, None),
            Transport::Echo { identifier, reply } => {
                if reply != (direction == Direction::WanToLan) {
                    return Err(Error::Denied);
                }
                (1, identifier, identifier, None)
            }
        };
        let (mapping_slot, fresh, key, generation, remote) = match direction {
            Direction::LanToWan => {
                if !self.config.lan_host(source) || !self.config.remote(destination) {
                    return Err(Error::Denied);
                }
                let key = Internal {
                    ip: source,
                    port: source_port,
                    protocol,
                };
                let (i, fresh) = self.mapping_slot(key, now)?;
                let generation = if fresh {
                    self.generation
                        .checked_add(1)
                        .ok_or(Error::GenerationExhausted)?
                } else {
                    self.mappings[i].unwrap().generation
                };
                (
                    i,
                    fresh,
                    key,
                    generation,
                    Remote {
                        ip: destination,
                        port: if protocol == 1 { 0 } else { destination_port },
                    },
                )
            }
            Direction::WanToLan => {
                if destination != self.config.wan_ip || !self.config.remote(source) {
                    return Err(Error::Denied);
                }
                let i = destination_port
                    .checked_sub(PORT_BASE)
                    .ok_or(Error::Denied)? as usize;
                let m = self
                    .mappings
                    .get(i)
                    .copied()
                    .flatten()
                    .filter(|m| m.until > now && m.key.protocol == protocol)
                    .ok_or(Error::Denied)?;
                (
                    i,
                    false,
                    m.key,
                    m.generation,
                    Remote {
                        ip: source,
                        port: if protocol == 1 { 0 } else { source_port },
                    },
                )
            }
        };
        let (flow_slot, fresh_flow) = self.flow_slot(mapping_slot, generation, remote, now)?;
        if fresh_flow && direction == Direction::WanToLan {
            return Err(Error::Denied);
        }
        let old = if fresh_flow {
            None
        } else {
            Some(self.flows[flow_slot].unwrap().state)
        };
        let state = if let Some(segment) = segment {
            tcp_transition(old, direction, segment)?
        } else {
            State::Datagram
        };
        let new_tcp = protocol == 6 && (fresh_flow || matches!(old, Some(State::Closed)));
        let tcp_incarnation = if new_tcp {
            self.tcp_sequence
                .checked_add(1)
                .ok_or(Error::GenerationExhausted)?
        } else if protocol == 6 {
            self.flows[flow_slot].unwrap().tcp_incarnation
        } else {
            0
        };
        let tcp_offloaded =
            protocol == 6 && !new_tcp && self.flows[flow_slot].unwrap().tcp_offloaded;
        let window = if tcp_offloaded {
            // Hardware may have advanced both sequence spaces. Reusing the
            // stale envelope would reject legitimate FIN/RST and fallback data.
            // The explicit handoff changes only this connection's policy.
            None
        } else if let Some(segment) = segment {
            let previous = if fresh_flow || matches!(old, Some(State::Closed)) {
                None
            } else {
                self.flows[flow_slot].unwrap().window
            };
            Some(
                crate::tcp_window::Tracker::advance(
                    previous,
                    direction == Direction::LanToWan,
                    segment,
                )
                .map_err(|_| Error::Denied)?,
            )
        } else {
            None
        };
        let timeout = match state {
            State::Datagram => {
                if protocol == 1 {
                    ECHO_MS
                } else {
                    UDP_MS
                }
            }
            State::Established { .. } => TCP_ESTABLISHED_MS,
            State::Closed => TCP_CLOSED_MS,
            _ => TCP_TRANSITORY_MS,
        };
        let until = now.checked_add(timeout).ok_or(Error::Clock)?;
        let map_until = if fresh {
            until
        } else if matches!(state, State::Closing | State::Closed) && old != Some(state) {
            // An established connection may shorten its own deadline on FIN
            // or RST, but an endpoint-independent mapping may still serve
            // other remote peers. Recompute only on teardown phase changes;
            // ordinary established packets retain bounded hash-probe work.
            // This remains a proposed value until Prepared::forward commits.
            self.flows
                .iter()
                .enumerate()
                .filter_map(|(i, f)| {
                    f.filter(|f| {
                        i != flow_slot
                            && f.mapping == mapping_slot
                            && f.generation == generation
                            && f.until > now
                    })
                    .map(|f| f.until)
                })
                .fold(until, u64::max)
        } else {
            self.mappings[mapping_slot].unwrap().until.max(until)
        };
        let external = PORT_BASE + mapping_slot as u16;
        let translation = match direction {
            Direction::LanToWan => Translation {
                source: self.config.wan_ip,
                destination,
                ports: if protocol == 1 {
                    PortRewrite::EchoIdentifier(external)
                } else {
                    PortRewrite::Ports {
                        source: external,
                        destination: destination_port,
                    }
                },
            },
            Direction::WanToLan => Translation {
                source,
                destination: key.ip,
                ports: if protocol == 1 {
                    PortRewrite::EchoIdentifier(key.port)
                } else {
                    PortRewrite::Ports {
                        source: source_port,
                        destination: key.port,
                    }
                },
            },
        };
        Ok(Prepared {
            direction,
            table: self,
            packet,
            translation,
            mapping_slot,
            flow_slot,
            mapping: Mapping {
                key,
                generation,
                until: map_until,
            },
            flow: Flow {
                tcp_incarnation,
                tcp_offloaded,
                window,
                mapping: mapping_slot,
                generation,
                remote,
                until,
                state,
            },
            fresh,
            now,
        })
    }
}

/// Exclusive table and packet borrow makes authorization valid until commit.
/// Dropping this value neither changes bytes nor allocates/refreshes a flow.
pub struct Prepared<'t, 'p, const M: usize, const F: usize> {
    direction: Direction,
    table: &'t mut Table<M, F>,
    packet: Packet<'p>,
    translation: Translation,
    mapping_slot: usize,
    flow_slot: usize,
    mapping: Mapping,
    flow: Flow,
    fresh: bool,
    now: u64,
}
impl<const M: usize, const F: usize> Prepared<'_, '_, M, F> {
    pub fn destination(&self) -> [u8; 4] {
        self.translation.destination
    }
    /// Reserve DMA TX capacity before this operation. No fallible operation
    /// follows the packet rewrite; table updates are fixed indexed assignments.
    pub fn forward(self, egress: Egress) -> Result<usize, Error> {
        self.forward_inner::<false>(egress)
            .map(|(length, _)| length)
    }
    /// Same atomic packet/table commit, additionally returning a UDP-only
    /// receipt. Reserve TX capacity first, as for `forward`. Failed forwarding,
    /// TCP and ICMP cannot produce a UDP permit. This does not prove TX delivery.
    pub fn forward_with_udp_permit(
        self,
        egress: Egress,
    ) -> Result<(usize, Option<UdpPermit>), Error> {
        self.forward_inner::<true>(egress)
    }
    fn forward_inner<const PERMIT: bool>(
        self,
        egress: Egress,
    ) -> Result<(usize, Option<UdpPermit>), Error> {
        let length = self
            .packet
            .forward(egress, Some(self.translation))
            .map_err(Error::Packet)?;
        self.table.mappings[self.mapping_slot] = Some(self.mapping);
        self.table.flows[self.flow_slot] = Some(self.flow);
        self.table.tcp_sequence = self.table.tcp_sequence.max(self.flow.tcp_incarnation);
        if self.fresh {
            self.table.generation = self.mapping.generation;
        }
        self.table.last_now = self.now;
        let permit = if PERMIT && self.mapping.key.protocol == 17 {
            Some(UdpPermit {
                identity: self.table.identity,
                direction: self.direction,
                mapping: self.mapping_slot,
                flow: self.flow_slot,
                generation: self.mapping.generation,
                internal: self.mapping.key,
                remote: self.flow.remote,
                wan: self.table.config.wan_ip,
                issued: self.now,
                until: self.flow.until.min(self.mapping.until),
            })
        } else {
            None
        };
        Ok((length, permit))
    }
}

/// Exclusive authorization lease for an ICMP error; no mapping/flow mutation.
pub struct PreparedError<'t, 'p, const M: usize, const F: usize> {
    table: &'t mut Table<M, F>,
    packet: crate::icmp_nat::Packet<'p>,
    rewrite: crate::icmp_nat::Rewrite,
    now: u64,
}
impl<const M: usize, const F: usize> PreparedError<'_, '_, M, F> {
    pub fn destination(&self) -> [u8; 4] {
        self.rewrite.destination
    }
    pub fn forward(self, egress: Egress) -> Result<usize, Error> {
        let length = self
            .packet
            .forward(egress, self.rewrite)
            .map_err(Error::Packet)?;
        self.table.last_now = self.now;
        Ok(length)
    }
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}
fn tcp_transition(old: Option<State>, dir: Direction, s: Segment) -> Result<State, Error> {
    const FIN: u8 = 1;
    const SYN: u8 = 2;
    const RST: u8 = 4;
    const ACK: u8 = 16;
    let lan = dir == Direction::LanToWan;
    let control = s.flags & (FIN | SYN | RST | ACK);
    if s.flags & SYN != 0 && s.flags & (FIN | RST) != 0 {
        return Err(Error::Denied);
    }
    let initial = control == SYN && s.payload == 0;
    let retransmit = |client_next: u32| initial && s.seq.wrapping_add(1) == client_next;
    match old {
        None | Some(State::Closed) if lan && initial => Ok(State::SynSent {
            client_next: s.seq.wrapping_add(1),
        }),
        Some(State::SynSent { client_next }) => {
            if lan && retransmit(client_next) {
                return Ok(State::SynSent { client_next });
            }
            if !lan && s.ack == client_next {
                if control == (SYN | ACK) && s.payload == 0 {
                    return Ok(State::SynReceived {
                        client_next,
                        server_next: s.seq.wrapping_add(1),
                    });
                }
                if control == (RST | ACK) {
                    return Ok(State::Closed);
                }
            }
            Err(Error::Denied)
        }
        Some(State::SynReceived {
            client_next,
            server_next,
        }) => {
            if lan && retransmit(client_next)
                || !lan
                    && control == (SYN | ACK)
                    && s.payload == 0
                    && s.seq.wrapping_add(1) == server_next
                    && s.ack == client_next
            {
                return Ok(State::SynReceived {
                    client_next,
                    server_next,
                });
            }
            if !lan && control == (RST | ACK) && s.seq == server_next && s.ack == client_next {
                return Ok(State::Closed);
            }
            if lan
                && s.seq == client_next
                && s.ack == server_next
                && s.flags & ACK != 0
                && s.flags & SYN == 0
            {
                return Ok(if s.flags & RST != 0 {
                    State::Closed
                } else if s.flags & FIN != 0 {
                    State::Closing
                } else {
                    State::Established {
                        client_next,
                        server_next,
                    }
                });
            }
            Err(Error::Denied)
        }
        Some(State::Established {
            client_next,
            server_next,
        }) => {
            if !lan
                && control == (SYN | ACK)
                && s.payload == 0
                && s.seq.wrapping_add(1) == server_next
                && s.ack == client_next
            {
                return Ok(State::Established {
                    client_next,
                    server_next,
                });
            }
            if s.flags & SYN != 0 || s.flags & (ACK | RST) == 0 {
                return Err(Error::Denied);
            }
            Ok(if s.flags & RST != 0 {
                State::Closed
            } else if s.flags & FIN != 0 {
                State::Closing
            } else {
                State::Established {
                    client_next,
                    server_next,
                }
            })
        }
        Some(State::Closing) => {
            if s.flags & SYN != 0 || s.flags & (ACK | RST) == 0 {
                return Err(Error::Denied);
            }
            Ok(if s.flags & RST != 0 {
                State::Closed
            } else {
                State::Closing
            })
        }
        _ => Err(Error::Denied),
    }
}

#[cfg(test)]
mod tests;
