//! Bounded WAN DHCP control plane, separate from allocation-free NAT traffic.
//! The NIC owner must call `receive` only for frames from its trusted WAN port.
//! A lease transition is a request: the owner must apply/revoke NAT and neighbor
//! state before forwarding. This module does not itself own the routing path.
use crate::{
    neighbor, router_config, Ipv4RuntimeStatus, Ipv4StackConfig, SharedIpv4TcpStack, StackError,
};
use alloc::sync::Arc;
use vibeos_core::{
    cap::{CSpace, Rights},
    chan::Endpoint,
    net::{Packet, PacketStamp, StampedPacket},
};

const CAPACITY: usize = 4;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ingress {
    Ignored,
    Queued,
    Full,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Some(Some(config)): install; Some(None): revoke; None: no change.
    /// The first discovering poll explicitly requests revocation.
    pub transition: Option<Option<router_config::Config>>,
    pub rejected_lease: bool,
    pub more_work: bool,
    pub next_poll_delay_ms: Option<u64>,
}
pub struct Client {
    stack: SharedIpv4TcpStack,
    _authority: CSpace,
    inbound: Arc<Endpoint<StampedPacket>>,
    outbound: Arc<Endpoint<StampedPacket>>,
    stamp: PacketStamp,
    pending: Option<Packet>,
    wan_mac: [u8; 6],
    lan: neighbor::Interface,
    published: Option<Option<router_config::Config>>,
    forwarding_window: Option<(u64, u64)>,
}
impl Client {
    pub fn new(initial: router_config::Config, seed: u64) -> Result<Self, StackError> {
        let [wan, lan] = initial.interfaces;
        let inbound = Endpoint::new("router-dhcp-in", CAPACITY);
        let outbound = Endpoint::new("router-dhcp-out", CAPACITY);
        let mut authority = CSpace::new("router-dhcp");
        let rx = authority.mint(inbound.clone(), Rights::RECV);
        let tx = authority.mint(outbound.clone(), Rights::SEND);
        let stamp = PacketStamp::new(1, 1).unwrap();
        // No listeners are created. start_dhcp clears this bootstrap address
        // before any poll can emit or accept traffic.
        let mut stack = SharedIpv4TcpStack::new(
            Ipv4StackConfig::new(wan.mac, wan.ip, wan.prefix, seed),
            stamp,
            authority.lookup_revocable(rx, Rights::RECV).unwrap(),
            authority.lookup_revocable(tx, Rights::SEND).unwrap(),
        )?;
        stack.start_dhcp()?;
        Ok(Self {
            stack,
            _authority: authority,
            inbound,
            outbound,
            stamp,
            pending: None,
            wan_mac: wan.mac,
            lan,
            published: None,
            forwarding_window: None,
        })
    }
    pub fn receive(&mut self, frame: &[u8]) -> Ingress {
        if frame.len() > 1514 || !control_frame(frame, self.wan_mac, true) {
            return Ingress::Ignored;
        }
        // Even a full control queue cannot preserve an earlier proof.
        self.forwarding_window = None;
        let Ok(packet) = StampedPacket::copy_from(frame, self.stamp) else {
            return Ingress::Ignored;
        };
        if self.inbound.try_send(packet).is_ok() {
            Ingress::Queued
        } else {
            Ingress::Full
        }
    }
    pub fn poll(&mut self, now_ms: u64) -> Result<Report, StackError> {
        // Invalidate before any fallible work.
        self.forwarding_window = None;
        // A caller must fail closed on Err; errors are not a retained-lease proof.
        let work = self.stack.poll_network(now_ms)?;
        let (desired, rejected_lease) = match self.stack.ipv4_status() {
            Ipv4RuntimeStatus::DhcpBound(address) => {
                let config = router_config::Config::new([
                    neighbor::Interface {
                        mac: self.wan_mac,
                        ip: address.address,
                        prefix: address.prefix_len,
                        gateway: address.default_gateway,
                    },
                    self.lan,
                ]);
                (config.ok(), config.is_err())
            }
            _ => (None, false),
        };
        let transition = if self.published == Some(desired) {
            None
        } else {
            self.published = Some(desired);
            Some(desired)
        };
        if desired.is_some() && !work.more_work {
            self.forwarding_window = work
                .next_poll_delay_ms
                .and_then(|delay| now_ms.checked_add(delay))
                .filter(|deadline| *deadline > now_ms)
                .map(|deadline| (now_ms, deadline));
        }
        Ok(Report {
            transition,
            rejected_lease,
            more_work: work.more_work,
            next_poll_delay_ms: work.next_poll_delay_ms,
        })
    }
    /// A conservative bound for unchanged DHCP forwarding authority, never a
    /// lease extension. The stack's next poll includes renewal/rebind/expiry;
    /// the bound is unavailable if that deadline is unknown or already due.
    ///
    /// The owner must already have applied `config`, retain exclusive access,
    /// and arrange its own cutoff no later than the returned deadline. This
    /// does not authorize NAT tuples, neighbors, hardware tables or new ingress.
    pub fn forwarding_until(&self, config: router_config::Config, now_ms: u64) -> Option<u64> {
        let (observed, deadline) = self.forwarding_window?;
        if now_ms < observed
            || now_ms >= deadline
            || self.published != Some(Some(config))
            || self.pending.is_some()
            || self.inbound.stats().2 != 0
            || self.outbound.stats().2 != 0
        {
            return None;
        }
        Some(deadline)
    }

    /// At most one frame per call. `false` retains the exact packet under NIC
    /// backpressure; `true` acknowledges transfer of its bytes to the NIC.
    /// The owner must arrange a TX-completion/timer wake when returning false.
    pub fn transmit(&mut self, send: impl FnOnce(&[u8]) -> bool) -> bool {
        if self.pending.is_none() {
            self.pending = self
                .outbound
                .try_recv()
                .and_then(|p| p.into_packet(self.stamp).ok());
        }
        let Some(packet) = &self.pending else {
            return false;
        };
        // Defense in depth: never expose a general service from this stack.
        if !control_frame(packet.as_bytes(), self.wan_mac, false) {
            self.pending = None;
            return false;
        }
        if send(packet.as_bytes()) {
            self.pending = None;
            true
        } else {
            false
        }
    }
}

fn control_frame(frame: &[u8], mac: [u8; 6], inbound: bool) -> bool {
    if frame.len() < 42 {
        return false;
    }
    if inbound {
        if frame[..6] != mac && frame[..6] != [255; 6] {
            return false;
        }
    } else if frame[6..12] != mac {
        return false;
    }
    if frame[12..14] == [8, 6] {
        // Feed replies only: router owns replies to requests for its WAN IP.
        return frame[14..20] == [0, 1, 8, 0, 6, 4]
            && if inbound {
                frame[20..22] == [0, 2]
            } else {
                frame[20..22] == [0, 1]
            };
    }
    if frame[12..14] != [8, 0]
        || frame[14] != 0x45
        || frame[23] != 17
        || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0
    {
        return false;
    }
    let ip_len = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let udp_len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
    ip_len >= 28
        && ip_len <= frame.len() - 14
        && udp_len == ip_len - 20
        && frame[34..38]
            == if inbound {
                [0, 67, 0, 68]
            } else {
                [0, 68, 0, 67]
            }
    // Checksums, BOOTP identity, transaction/server IDs and options are checked
    // by the existing DHCP stack. This is only traffic admission, not parsing.
}
