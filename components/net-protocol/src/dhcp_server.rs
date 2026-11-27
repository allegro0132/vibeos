//! Bounded LAN DHCPv4 server working directly on Ethernet frames.
//!
//! The router's NIC owner passes every LAN broadcast/unicast UDP 68->67 frame
//! to [`Server::handle`], which either ignores it or writes exactly one reply
//! frame. No sockets, allocation or timers: leases are a fixed table keyed by
//! client hardware address and expire lazily against the caller's monotonic
//! clock. The table is volatile; after a restart, clients renewing or
//! rebooting with a free in-pool address get it back, anything else is NAKed.
//!
//! Relay agents (giaddr), BOOTP without a message type, and option overload
//! are not served.

/// Longest client host name kept for display.
pub const NAME_BYTES: usize = 32;
/// A reply always fits: 14 + 20 + 8 + 300-byte minimum BOOTP payload.
pub const REPLY_BYTES: usize = 342;
const OFFER_HOLD_MS: u64 = 60_000;
const DECLINE_HOLD_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub prefix: u8,
    /// Inclusive pool bounds, both inside the interface subnet.
    pub first: [u8; 4],
    pub last: [u8; 4],
    pub lease_seconds: u32,
    /// Resolvers advertised to clients; `None` entries are skipped.
    pub dns: [Option<[u8; 4]>; 2],
}
impl Config {
    fn mask(self) -> u32 {
        u32::MAX << (32 - u32::from(self.prefix))
    }
    fn valid(self) -> bool {
        if !(8..=30).contains(&self.prefix) || !(60..=7 * 86_400).contains(&self.lease_seconds) {
            return false;
        }
        let (ip, first, last) = (
            u32::from_be_bytes(self.ip),
            u32::from_be_bytes(self.first),
            u32::from_be_bytes(self.last),
        );
        let (net, host_mask) = (ip & self.mask(), !self.mask());
        first <= last
            && first & self.mask() == net
            && last & self.mask() == net
            && first & host_mask != 0
            && last & host_mask != host_mask
    }
    /// Pool for an interface: the upper part of the subnet, leaving the low
    /// addresses for static hosts (`.100-.249` in a /24).
    pub fn default_pool(ip: [u8; 4], prefix: u8) -> ([u8; 4], [u8; 4]) {
        let mask = u32::MAX << (32 - u32::from(prefix.clamp(8, 30)));
        let net = u32::from_be_bytes(ip) & mask;
        let hosts = !mask - 1; // usable host numbers 1..=hosts
        let (first, last) = if hosts >= 254 {
            (100, 249)
        } else {
            ((hosts / 2 + 1).max(2).min(hosts), hosts)
        };
        ((net + first).to_be_bytes(), (net + last).to_be_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState {
    Offered,
    Bound,
    /// A client reported the address in use; withheld until expiry.
    Declined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub expires_ms: u64,
    pub state: LeaseState,
    name: [u8; NAME_BYTES],
    name_len: u8,
}
impl Lease {
    /// Printable ASCII host name supplied by the client, if any.
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..usize::from(self.name_len)]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handled {
    /// Not a DHCP client message for this server; continue normal processing.
    NotDhcp,
    /// Consumed without a reply.
    Silent,
    /// Consumed; transmit `out[..length]` on the LAN.
    Reply(usize),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub discovers: u64,
    pub offers: u64,
    pub acks: u64,
    pub naks: u64,
    pub exhausted: u64,
}

pub struct Server<const N: usize> {
    config: Config,
    leases: [Option<Lease>; N],
    /// Operator-assigned addresses: these clients always get theirs (even
    /// outside the pool) and nobody else ever does.
    reservations: alloc::vec::Vec<([u8; 6], [u8; 4])>,
    pub counters: Counters,
}

struct Request<'a> {
    kind: u8,
    xid: &'a [u8],
    flags: &'a [u8],
    ciaddr: [u8; 4],
    chaddr: [u8; 6],
    requested: Option<[u8; 4]>,
    server: Option<[u8; 4]>,
    name: &'a [u8],
}

fn parse<'a>(frame: &'a [u8], config: &Config) -> Option<Request<'a>> {
    if frame.len() < 14 + 20 + 8 + 240 || frame[12..14] != [8, 0] || frame[14] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(frame[14] & 15) * 4;
    if ihl < 20 || frame[23] != 17 || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    let udp = 14 + ihl;
    if total < ihl + 8 + 240 || 14 + total > frame.len() || frame[udp..udp + 4] != [0, 68, 0, 67] {
        return None;
    }
    let destination: [u8; 4] = frame[30..34].try_into().unwrap();
    let broadcast = (u32::from_be_bytes(config.ip) | !config.mask()).to_be_bytes();
    if destination != [255; 4] && destination != config.ip && destination != broadcast {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
    if udp_len < 8 + 240 || udp_len > total - ihl {
        return None;
    }
    let bootp = &frame[udp + 8..udp + udp_len];
    // BOOTREQUEST, Ethernet, no relay agent, magic cookie.
    if bootp[0] != 1 || bootp[1] != 1 || bootp[2] != 6 || bootp[24..28] != [0; 4] {
        return None;
    }
    if bootp[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let chaddr: [u8; 6] = bootp[28..34].try_into().unwrap();
    if chaddr[0] & 1 != 0 || chaddr == [0; 6] || chaddr == config.mac {
        return None;
    }
    let mut request = Request {
        kind: 0,
        xid: &bootp[4..8],
        flags: &bootp[10..12],
        ciaddr: bootp[12..16].try_into().unwrap(),
        chaddr,
        requested: None,
        server: None,
        name: &[],
    };
    let mut options = &bootp[240..];
    while let [code, rest @ ..] = options {
        match *code {
            0 => {
                options = rest;
                continue;
            }
            255 => break,
            _ => {}
        }
        let [length, rest @ ..] = rest else { return None };
        let length = usize::from(*length);
        if rest.len() < length {
            return None;
        }
        let (value, rest) = rest.split_at(length);
        match (*code, length) {
            (53, 1) => request.kind = value[0],
            (50, 4) => request.requested = Some(value.try_into().unwrap()),
            (54, 4) => request.server = Some(value.try_into().unwrap()),
            (12, 1..) => request.name = value,
            _ => {}
        }
        options = rest;
    }
    (request.kind != 0).then_some(request)
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for pair in part.chunks(2) {
            sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl<const N: usize> Server<N> {
    pub fn new(config: Config) -> Option<Self> {
        (N != 0 && config.valid()).then_some(Self {
            config,
            leases: [None; N],
            reservations: alloc::vec::Vec::new(),
            counters: Counters::default(),
        })
    }
    pub fn config(&self) -> Config {
        self.config
    }
    /// Replace addressing policy. Leases that no longer fit the pool are
    /// dropped; the rest survive (e.g. a resolver or lease-time change).
    pub fn reconfigure(&mut self, config: Config) -> bool {
        if !config.valid() {
            return false;
        }
        self.config = config;
        for index in 0..N {
            if self.leases[index].is_some_and(|lease| !self.in_pool(lease.ip) && self.reserved_for(lease.mac) != Some(lease.ip)) {
                self.leases[index] = None;
            }
        }
        true
    }
    /// Replace the static assignments. Leases they contradict (a reserved
    /// address held by someone else, or a reserved client elsewhere) end now.
    pub fn set_reservations(&mut self, reservations: &[([u8; 6], [u8; 4])]) {
        self.reservations = reservations.to_vec();
        for index in 0..N {
            if self.leases[index].is_some_and(|lease| {
                reservations.iter().any(|(mac, ip)| (lease.mac == *mac) != (lease.ip == *ip))
            }) {
                self.leases[index] = None;
            }
        }
    }
    fn reserved_for(&self, mac: [u8; 6]) -> Option<[u8; 4]> {
        self.reservations.iter().find(|(m, _)| *m == mac).map(|(_, ip)| *ip)
    }
    fn subnet_host(&self, ip: [u8; 4]) -> bool {
        let (ip, mask) = (u32::from_be_bytes(ip), self.config.mask());
        ip & mask == u32::from_be_bytes(self.config.ip) & mask && ip != u32::from_be_bytes(self.config.ip)
    }
    /// Unexpired offers, bindings and declined holds.
    pub fn leases(&self, now_ms: u64) -> impl Iterator<Item = &Lease> {
        self.leases
            .iter()
            .flatten()
            .filter(move |lease| lease.expires_ms > now_ms)
    }
    /// Addresses in the pool, for capacity display.
    pub fn pool_size(&self) -> u32 {
        u32::from_be_bytes(self.config.last) - u32::from_be_bytes(self.config.first) + 1
    }

    fn in_pool(&self, ip: [u8; 4]) -> bool {
        let ip = u32::from_be_bytes(ip);
        (u32::from_be_bytes(self.config.first)..=u32::from_be_bytes(self.config.last)).contains(&ip)
            && ip != u32::from_be_bytes(self.config.ip)
    }
    fn slot_of(&self, mac: [u8; 6], now: u64) -> Option<usize> {
        self.leases.iter().position(|slot| {
            slot.is_some_and(|l| l.mac == mac && l.expires_ms > now && l.state != LeaseState::Declined)
        })
    }
    fn holder(&self, ip: [u8; 4], now: u64) -> Option<[u8; 6]> {
        self.leases
            .iter()
            .flatten()
            .find(|l| l.ip == ip && l.expires_ms > now)
            .map(|l| l.mac)
    }
    /// A slot to (re)use for `mac`: its own, an empty one, or the entry
    /// expired longest ago. Live leases are never evicted.
    fn store(&mut self, lease: Lease, now: u64) -> bool {
        let index = self
            .leases
            .iter()
            .position(|slot| slot.is_some_and(|l| l.mac == lease.mac && l.state != LeaseState::Declined))
            .or_else(|| self.leases.iter().position(Option::is_none))
            .or_else(|| {
                self.leases
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| slot.is_some_and(|l| l.expires_ms <= now))
                    .min_by_key(|(_, slot)| slot.unwrap().expires_ms)
                    .map(|(index, _)| index)
            });
        match index {
            Some(index) => {
                self.leases[index] = Some(lease);
                true
            }
            None => false,
        }
    }
    fn free_for(&self, ip: [u8; 4], mac: [u8; 6], now: u64, occupied: &impl Fn([u8; 4]) -> Option<[u8; 6]>) -> bool {
        // A reservation decides alone: its owner may use it wherever it lies
        // in the subnet, and it is never free for anyone else.
        if let Some((owner, _)) = self.reservations.iter().find(|(_, reserved)| *reserved == ip) {
            return *owner == mac && self.subnet_host(ip);
        }
        if self.reserved_for(mac).is_some() {
            return false;
        }
        self.in_pool(ip)
            && self.holder(ip, now).is_none_or(|holder| holder == mac)
            && occupied(ip).is_none_or(|seen| seen == mac)
    }
    fn choose(&self, request: &Request, now: u64, occupied: &impl Fn([u8; 4]) -> Option<[u8; 6]>) -> Option<[u8; 4]> {
        if let Some(reserved) = self.reserved_for(request.chaddr) {
            return Some(reserved);
        }
        // Prefer continuity: the current record (even expired), then the
        // client's own suggestion, then any free address.
        let previous = self
            .leases
            .iter()
            .flatten()
            .find(|l| l.mac == request.chaddr && l.state != LeaseState::Declined)
            .map(|l| l.ip);
        for candidate in [previous, request.requested, Some(request.ciaddr)].into_iter().flatten() {
            if self.free_for(candidate, request.chaddr, now, occupied) {
                return Some(candidate);
            }
        }
        // Start at a per-client offset so restarts do not always hand the
        // first address to whichever client asks first.
        let size = self.pool_size();
        let seed = u32::from_be_bytes(request.chaddr[2..6].try_into().unwrap()).wrapping_mul(0x9e37_79b9);
        let first = u32::from_be_bytes(self.config.first);
        let never_used = |ip: [u8; 4]| !self.leases.iter().flatten().any(|l| l.ip == ip);
        for fresh_only in [true, false] {
            for step in 0..size {
                let ip = (first + (seed % size + step) % size).to_be_bytes();
                if self.free_for(ip, request.chaddr, now, occupied) && (!fresh_only || never_used(ip)) {
                    return Some(ip);
                }
            }
        }
        None
    }

    /// Process one LAN frame at monotonic time `now_ms`. `occupied` reports the
    /// hardware address the router has recently observed using an IP (from its
    /// neighbor table), so an address already taken by a static host is not
    /// handed to someone else.
    pub fn handle(
        &mut self,
        frame: &[u8],
        now_ms: u64,
        occupied: impl Fn([u8; 4]) -> Option<[u8; 6]>,
        out: &mut [u8; REPLY_BYTES],
    ) -> Handled {
        let Some(request) = parse(frame, &self.config) else {
            return Handled::NotDhcp;
        };
        let mut name = [0; NAME_BYTES];
        let mut name_len = 0;
        for byte in request.name.iter().take(NAME_BYTES) {
            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
                break;
            }
            name[name_len] = *byte;
            name_len += 1;
        }
        let lease = |ip, state, ttl: u64| Lease {
            mac: request.chaddr,
            ip,
            expires_ms: now_ms.saturating_add(ttl),
            state,
            name,
            name_len: name_len as u8,
        };
        let lease_ms = u64::from(self.config.lease_seconds) * 1000;
        let (kind, yiaddr) = match request.kind {
            1 => {
                self.counters.discovers += 1;
                let Some(ip) = self.choose(&request, now_ms, &occupied) else {
                    self.counters.exhausted += 1;
                    return Handled::Silent;
                };
                // Keep an existing binding's lifetime; only fresh offers are short.
                let bound = self
                    .slot_of(request.chaddr, now_ms)
                    .and_then(|i| self.leases[i])
                    .filter(|l| l.state == LeaseState::Bound && l.ip == ip);
                if bound.is_none() && !self.store(lease(ip, LeaseState::Offered, OFFER_HOLD_MS), now_ms) {
                    self.counters.exhausted += 1;
                    return Handled::Silent;
                }
                self.counters.offers += 1;
                (2, ip)
            }
            3 => {
                if request.server.is_some_and(|server| server != self.config.ip) {
                    // The client selected another server: withdraw our offer.
                    if let Some(i) = self.slot_of(request.chaddr, now_ms) {
                        if self.leases[i].unwrap().state == LeaseState::Offered {
                            self.leases[i] = None;
                        }
                    }
                    return Handled::Silent;
                }
                let wanted = request.requested.unwrap_or(request.ciaddr);
                let ours = self.slot_of(request.chaddr, now_ms).map(|i| self.leases[i].unwrap().ip);
                // Selecting must match our offer. Renewing/rebooting clients may
                // also reclaim any free pool address (the table is volatile).
                let grant = wanted != [0; 4]
                    && if request.server.is_some() {
                        ours == Some(wanted)
                    } else {
                        ours == Some(wanted) || (ours.is_none() && self.free_for(wanted, request.chaddr, now_ms, &occupied))
                    };
                if grant && self.store(lease(wanted, LeaseState::Bound, lease_ms), now_ms) {
                    self.counters.acks += 1;
                    (5, wanted)
                } else {
                    // Authoritative for this LAN (RFC 2131 4.3.2): a wrong
                    // network or an unavailable address is corrected at once.
                    self.counters.naks += 1;
                    (6, [0; 4])
                }
            }
            4 => {
                if let Some(ip) = request.requested.filter(|ip| self.in_pool(*ip)) {
                    if let Some(i) = self.slot_of(request.chaddr, now_ms) {
                        self.leases[i] = None;
                    }
                    let mut hold = lease(ip, LeaseState::Declined, DECLINE_HOLD_MS);
                    hold.mac = [0; 6];
                    self.store(hold, now_ms);
                }
                return Handled::Silent;
            }
            7 => {
                if let Some(i) = self.slot_of(request.chaddr, now_ms) {
                    if self.leases[i].unwrap().ip == request.ciaddr {
                        self.leases[i] = None;
                    }
                }
                return Handled::Silent;
            }
            8 if request.ciaddr != [0; 4] => (5, [0; 4]),
            _ => return Handled::Silent,
        };
        Handled::Reply(self.reply(&request, kind, yiaddr, out))
    }

    fn reply(&self, request: &Request, kind: u8, yiaddr: [u8; 4], out: &mut [u8; REPLY_BYTES]) -> usize {
        out.fill(0);
        let inform = kind == 5 && yiaddr == [0; 4];
        // RFC 2131 4.1: NAK and broadcast-flagged replies are broadcast;
        // renewals go to ciaddr; otherwise unicast to the new address.
        let (destination_mac, destination_ip) = if kind == 6 || (request.ciaddr == [0; 4] && request.flags[0] & 0x80 != 0) {
            ([255; 6], [255; 4])
        } else if request.ciaddr != [0; 4] {
            (request.chaddr, request.ciaddr)
        } else {
            (request.chaddr, yiaddr)
        };
        out[..6].copy_from_slice(&destination_mac);
        out[6..12].copy_from_slice(&self.config.mac);
        out[12..14].copy_from_slice(&[8, 0]);
        let bootp = 42;
        out[bootp] = 2;
        out[bootp + 1] = 1;
        out[bootp + 2] = 6;
        out[bootp + 4..bootp + 8].copy_from_slice(request.xid);
        out[bootp + 10..bootp + 12].copy_from_slice(request.flags);
        if kind != 6 {
            out[bootp + 12..bootp + 16].copy_from_slice(&request.ciaddr);
            out[bootp + 16..bootp + 20].copy_from_slice(&yiaddr);
            out[bootp + 20..bootp + 24].copy_from_slice(&self.config.ip);
        }
        out[bootp + 28..bootp + 34].copy_from_slice(&request.chaddr);
        out[bootp + 236..bootp + 240].copy_from_slice(&[99, 130, 83, 99]);
        let mut at = bootp + 240;
        let mut option = |code: u8, value: &[u8]| {
            out[at] = code;
            out[at + 1] = value.len() as u8;
            out[at + 2..at + 2 + value.len()].copy_from_slice(value);
            at += 2 + value.len();
        };
        option(53, &[kind]);
        option(54, &self.config.ip);
        if kind != 6 {
            if !inform {
                let seconds = self.config.lease_seconds;
                option(51, &seconds.to_be_bytes());
                option(58, &(seconds / 2).to_be_bytes());
                option(59, &(seconds / 8 * 7).to_be_bytes());
            }
            option(1, &self.config.mask().to_be_bytes());
            option(28, &(u32::from_be_bytes(self.config.ip) | !self.config.mask()).to_be_bytes());
            option(3, &self.config.ip);
            let mut dns = [0; 8];
            let mut count = 0;
            for server in self.config.dns.into_iter().flatten() {
                dns[count * 4..count * 4 + 4].copy_from_slice(&server);
                count += 1;
            }
            if count != 0 {
                option(6, &dns[..count * 4]);
            }
        }
        out[at] = 255;
        let length = REPLY_BYTES; // BOOTP minimum; options above stay below it.
        debug_assert!(at < length);
        out[14] = 0x45;
        out[16..18].copy_from_slice(&((length - 14) as u16).to_be_bytes());
        out[22] = 64;
        out[23] = 17;
        out[26..30].copy_from_slice(&self.config.ip);
        out[30..34].copy_from_slice(&destination_ip);
        let ip_sum = checksum(&[&out[14..34]]);
        out[24..26].copy_from_slice(&ip_sum.to_be_bytes());
        out[34..38].copy_from_slice(&[0, 67, 0, 68]);
        let udp_len = ((length - 34) as u16).to_be_bytes();
        out[38..40].copy_from_slice(&udp_len);
        let sum = checksum(&[&out[26..34], &[0, 17], &udp_len, &out[34..length]]);
        out[40..42].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
        length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    const ROUTER: [u8; 6] = [2, 0x42, 0x70, 4, 0, 2];
    fn config() -> Config {
        Config {
            mac: ROUTER,
            ip: [192, 168, 10, 1],
            prefix: 24,
            first: [192, 168, 10, 100],
            last: [192, 168, 10, 103],
            lease_seconds: 600,
            dns: [Some([192, 168, 10, 1]), None],
        }
    }
    fn mac(n: u8) -> [u8; 6] {
        [2, 0, 0, 0, 0, n]
    }
    #[derive(Default)]
    struct Message {
        ciaddr: [u8; 4],
        requested: Option<[u8; 4]>,
        server: Option<[u8; 4]>,
        broadcast: bool,
        name: &'static [u8],
        giaddr: [u8; 4],
    }
    fn message(client: [u8; 6], kind: u8, m: Message) -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[..3].copy_from_slice(&[1, 1, 6]);
        b[4..8].copy_from_slice(&[0xde, 0xad, client[5], kind]);
        b[10] = if m.broadcast { 0x80 } else { 0 };
        b[12..16].copy_from_slice(&m.ciaddr);
        b[24..28].copy_from_slice(&m.giaddr);
        b[28..34].copy_from_slice(&client);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend_from_slice(&[53, 1, kind]);
        if let Some(ip) = m.requested {
            b.extend_from_slice(&[50, 4]);
            b.extend_from_slice(&ip);
        }
        if let Some(ip) = m.server {
            b.extend_from_slice(&[54, 4]);
            b.extend_from_slice(&ip);
        }
        if !m.name.is_empty() {
            b.extend_from_slice(&[12, m.name.len() as u8]);
            b.extend_from_slice(m.name);
        }
        b.extend_from_slice(&[55, 3, 1, 3, 6, 255]);
        let mut f = vec![0u8; 42];
        f[..6].fill(255);
        f[6..12].copy_from_slice(&client);
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((28 + b.len()) as u16).to_be_bytes());
        f[23] = 17;
        f[26..30].copy_from_slice(&m.ciaddr);
        f[30..34].fill(255);
        f[34..38].copy_from_slice(&[0, 68, 0, 67]);
        f[38..40].copy_from_slice(&((8 + b.len()) as u16).to_be_bytes());
        f.extend_from_slice(&b);
        f
    }
    struct Reply {
        frame: Vec<u8>,
    }
    impl Reply {
        fn kind(&self) -> u8 {
            self.option(53).unwrap()[0]
        }
        fn yiaddr(&self) -> [u8; 4] {
            self.frame[58..62].try_into().unwrap()
        }
        fn option(&self, code: u8) -> Option<&[u8]> {
            let mut o = &self.frame[282..];
            while o[0] != 255 {
                let n = usize::from(o[1]);
                if o[0] == code {
                    return Some(&o[2..2 + n]);
                }
                o = &o[2 + n..];
            }
            None
        }
    }
    fn exchange<const N: usize>(s: &mut Server<N>, frame: &[u8], now: u64) -> Option<Reply> {
        exchange_seen(s, frame, now, |_| None)
    }
    fn exchange_seen<const N: usize>(
        s: &mut Server<N>,
        frame: &[u8],
        now: u64,
        occupied: impl Fn([u8; 4]) -> Option<[u8; 6]>,
    ) -> Option<Reply> {
        let mut out = [0; REPLY_BYTES];
        match s.handle(frame, now, occupied, &mut out) {
            Handled::Reply(n) => {
                assert_eq!(n, REPLY_BYTES);
                assert_eq!(checksum(&[&out[14..34]]), 0, "IPv4 header checksum");
                let udp_len = [out[38], out[39]];
                assert_eq!(checksum(&[&out[26..34], &[0, 17], &udp_len, &out[34..n]]), 0, "UDP checksum");
                assert_eq!(&out[6..12], &ROUTER);
                Some(Reply { frame: out[..n].to_vec() })
            }
            Handled::Silent => None,
            Handled::NotDhcp => panic!("frame was not recognised as DHCP"),
        }
    }
    fn acquire<const N: usize>(s: &mut Server<N>, client: [u8; 6], now: u64) -> [u8; 4] {
        let offer = exchange(s, &message(client, 1, Message::default()), now).unwrap();
        assert_eq!(offer.kind(), 2);
        let ip = offer.yiaddr();
        let ack = exchange(
            s,
            &message(client, 3, Message { requested: Some(ip), server: Some([192, 168, 10, 1]), ..Default::default() }),
            now + 1,
        )
        .unwrap();
        assert_eq!((ack.kind(), ack.yiaddr()), (5, ip));
        ip
    }

    #[test]
    fn full_exchange_carries_router_mask_resolver_and_timers() {
        let mut s = Server::<8>::new(config()).unwrap();
        let offer = exchange(&mut s, &message(mac(1), 1, Message { name: b"laptop", ..Default::default() }), 0).unwrap();
        assert_eq!(offer.kind(), 2);
        let ip = offer.yiaddr();
        assert!((100..=103).contains(&ip[3]));
        // Unicast to the offered address at the client's hardware address.
        assert_eq!((&offer.frame[..6], &offer.frame[30..34]), (&mac(1)[..], &ip[..]));
        assert_eq!(offer.option(54), Some(&[192, 168, 10, 1][..]));
        assert_eq!(offer.option(1), Some(&[255, 255, 255, 0][..]));
        assert_eq!(offer.option(3), Some(&[192, 168, 10, 1][..]));
        assert_eq!(offer.option(6), Some(&[192, 168, 10, 1][..]));
        assert_eq!(offer.option(28), Some(&[192, 168, 10, 255][..]));
        assert_eq!(offer.option(51), Some(&600u32.to_be_bytes()[..]));
        assert_eq!(offer.option(58), Some(&300u32.to_be_bytes()[..]));
        assert_eq!(offer.option(59), Some(&525u32.to_be_bytes()[..]));
        let request = message(mac(1), 3, Message { requested: Some(ip), server: Some([192, 168, 10, 1]), name: b"laptop", ..Default::default() });
        assert_eq!(exchange(&mut s, &request, 5).unwrap().kind(), 5);
        let lease = *s.leases(6).next().unwrap();
        assert_eq!((lease.mac, lease.ip, lease.state, lease.name()), (mac(1), ip, LeaseState::Bound, "laptop"));
        assert_eq!(lease.expires_ms, 600_005);
        assert_eq!(s.counters, Counters { discovers: 1, offers: 1, acks: 1, naks: 0, exhausted: 0 });
    }

    #[test]
    fn broadcast_flag_and_renewal_select_reply_addressing() {
        let mut s = Server::<8>::new(config()).unwrap();
        let offer = exchange(&mut s, &message(mac(1), 1, Message { broadcast: true, ..Default::default() }), 0).unwrap();
        assert_eq!((&offer.frame[..6], &offer.frame[30..34]), (&[255u8; 6][..], &[255u8; 4][..]));
        let ip = acquire(&mut s, mac(1), 1);
        let renew = exchange(&mut s, &message(mac(1), 3, Message { ciaddr: ip, ..Default::default() }), 300_000).unwrap();
        assert_eq!((renew.kind(), &renew.frame[..6], &renew.frame[30..34]), (5, &mac(1)[..], &ip[..]));
        assert_eq!(s.leases(300_001).next().unwrap().expires_ms, 900_000);
    }

    #[test]
    fn clients_keep_distinct_addresses_until_the_pool_is_exhausted() {
        let mut s = Server::<8>::new(config()).unwrap();
        let mut seen = Vec::new();
        for n in 1..=4 {
            let ip = acquire(&mut s, mac(n), u64::from(n) * 10);
            assert!(!seen.contains(&ip));
            seen.push(ip);
            // Asking again returns the same address and does not shorten it.
            assert_eq!(exchange(&mut s, &message(mac(n), 1, Message::default()), 100).unwrap().yiaddr(), ip);
        }
        assert!(exchange(&mut s, &message(mac(9), 1, Message::default()), 200).is_none());
        assert_eq!(s.counters.exhausted, 1);
        assert_eq!(s.leases(200).filter(|l| l.state == LeaseState::Bound).count(), 4);
        // After expiry the address is reusable, but the old owner is preferred.
        assert_eq!(exchange(&mut s, &message(mac(2), 1, Message::default()), 700_000).unwrap().yiaddr(), seen[1]);
        assert!(exchange(&mut s, &message(mac(9), 1, Message::default()), 700_000).is_some());
    }

    #[test]
    fn requests_for_foreign_or_taken_addresses_are_refused() {
        let mut s = Server::<8>::new(config()).unwrap();
        let ip = acquire(&mut s, mac(1), 0);
        // Another client cannot take a bound address by INIT-REBOOT or renewal.
        for m in [Message { requested: Some(ip), ..Default::default() }, Message { ciaddr: ip, ..Default::default() }] {
            assert_eq!(exchange(&mut s, &message(mac(2), 3, m), 10).unwrap().kind(), 6);
        }
        // A request selecting a different server withdraws our pending offer.
        let offered = exchange(&mut s, &message(mac(3), 1, Message::default()), 20).unwrap().yiaddr();
        let other = Message { requested: Some(offered), server: Some([192, 168, 10, 2]), ..Default::default() };
        assert!(exchange(&mut s, &message(mac(3), 3, other), 21).is_none());
        assert_eq!(s.leases(22).count(), 1);
        // Selecting us for an address we never offered is NAKed by broadcast.
        let wrong = Message { requested: Some([192, 168, 10, 50]), server: Some([192, 168, 10, 1]), ..Default::default() };
        let nak = exchange(&mut s, &message(mac(3), 3, wrong), 23).unwrap();
        assert_eq!((nak.kind(), &nak.frame[..6], nak.yiaddr()), (6, &[255u8; 6][..], [0; 4]));
        assert_eq!(nak.option(51), None);
    }

    #[test]
    fn volatile_table_readmits_rebooting_clients_with_free_pool_addresses() {
        let mut s = Server::<8>::new(config()).unwrap();
        let reboot = Message { requested: Some([192, 168, 10, 102]), ..Default::default() };
        let ack = exchange(&mut s, &message(mac(1), 3, reboot), 0).unwrap();
        assert_eq!((ack.kind(), ack.yiaddr()), (5, [192, 168, 10, 102]));
        let renew = Message { ciaddr: [192, 168, 10, 101], ..Default::default() };
        assert_eq!(exchange(&mut s, &message(mac(2), 3, renew), 0).unwrap().kind(), 5);
        // Outside the pool (static range or another network) is not granted.
        for ip in [[192, 168, 10, 5], [10, 0, 0, 7]] {
            let m = Message { requested: Some(ip), ..Default::default() };
            assert_eq!(exchange(&mut s, &message(mac(3), 3, m), 1).unwrap().kind(), 6);
        }
    }

    #[test]
    fn decline_release_inform_and_observed_static_hosts() {
        let mut s = Server::<8>::new(config()).unwrap();
        let ip = acquire(&mut s, mac(1), 0);
        let decline = Message { requested: Some(ip), server: Some([192, 168, 10, 1]), ..Default::default() };
        assert!(exchange(&mut s, &message(mac(1), 4, decline), 10).is_none());
        let next = acquire(&mut s, mac(1), 20);
        assert_ne!(next, ip);
        assert!(s.leases(30).any(|l| l.ip == ip && l.state == LeaseState::Declined));
        assert!(exchange(&mut s, &message(mac(1), 7, Message { ciaddr: next, ..Default::default() }), 40).is_none());
        assert!(!s.leases(41).any(|l| l.ip == next));
        let inform = exchange(&mut s, &message(mac(5), 8, Message { ciaddr: [192, 168, 10, 9], ..Default::default() }), 50).unwrap();
        assert_eq!((inform.kind(), inform.yiaddr(), inform.option(51)), (5, [0; 4], None));
        assert_eq!(inform.option(6), Some(&[192, 168, 10, 1][..]));
        // An address the router sees in use by another host is skipped.
        let mut s = Server::<8>::new(Config { last: [192, 168, 10, 101], ..config() }).unwrap();
        let squatter = |ip: [u8; 4]| (ip == [192, 168, 10, 100]).then_some(mac(7));
        for n in 1..=2 {
            let offer = exchange_seen(&mut s, &message(mac(n), 1, Message::default()), 0, squatter);
            assert_eq!(offer.map(|o| o.yiaddr()), (n == 1).then_some([192, 168, 10, 101]));
        }
    }

    #[test]
    fn static_leases_are_exclusive_and_may_lie_outside_the_pool() {
        let mut s = Server::<8>::new(config()).unwrap();
        let squatter = acquire(&mut s, mac(1), 0);
        assert_eq!(squatter, [192, 168, 10, 100 + (squatter[3] - 100)]);
        // Reserve the address mac(1) currently holds for mac(2), and a
        // low static address for mac(3).
        s.set_reservations(&[(mac(2), squatter), (mac(3), [192, 168, 10, 20])]);
        assert!(!s.leases(1).any(|l| l.ip == squatter), "contradicted lease ends");
        assert_eq!(acquire(&mut s, mac(2), 10), squatter);
        assert_eq!(acquire(&mut s, mac(3), 10), [192, 168, 10, 20]);
        let moved = acquire(&mut s, mac(1), 20);
        assert!(moved != squatter && moved[3] >= 100);
        // Nobody else can claim a reserved address, by any route.
        for m in [Message { requested: Some(squatter), ..Default::default() }, Message { ciaddr: [192, 168, 10, 20], ..Default::default() }] {
            assert_eq!(exchange(&mut s, &message(mac(4), 3, m), 30).unwrap().kind(), 6);
        }
        // The reserved client is NAKed off any other address and re-offered its own.
        let other = Message { requested: Some([192, 168, 10, 103]), ..Default::default() };
        assert_eq!(exchange(&mut s, &message(mac(3), 3, other), 40).unwrap().kind(), 6);
        assert_eq!(exchange(&mut s, &message(mac(3), 1, Message::default()), 41).unwrap().yiaddr(), [192, 168, 10, 20]);
        // Reconfiguring the pool keeps a reserved lease that lies outside it.
        assert!(s.reconfigure(config()));
        assert!(s.leases(42).any(|l| l.ip == [192, 168, 10, 20]));
    }

    #[test]
    fn unrelated_malformed_and_relayed_frames_are_not_served() {
        let mut s = Server::<8>::new(config()).unwrap();
        let mut out = [0; REPLY_BYTES];
        let good = message(mac(1), 1, Message::default());
        let mut cases: Vec<Vec<u8>> = vec![good[..200].to_vec(), message(mac(1), 1, Message { giaddr: [10, 0, 0, 1], ..Default::default() })];
        for (offset, value) in [(12, 0x86), (23, 6), (37, 68), (42, 2), (278, 0), (20, 0x20)] {
            let mut bad = good.clone();
            bad[offset] = value;
            cases.push(bad);
        }
        let mut own = good.clone();
        own[70..76].copy_from_slice(&ROUTER);
        cases.push(own);
        let mut truncated = good.clone();
        let length = truncated.len() - 5;
        truncated[length] = 200; // option length runs past the datagram
        cases.push(truncated);
        for case in cases {
            assert_eq!(s.handle(&case, 0, |_| None, &mut out), Handled::NotDhcp);
        }
        assert_eq!(s.leases(0).count(), 0);
        assert!(Server::<8>::new(Config { first: [192, 168, 11, 100], ..config() }).is_none());
        assert!(Server::<8>::new(Config { last: [192, 168, 10, 255], ..config() }).is_none());
        assert!(Server::<8>::new(Config { lease_seconds: 5, ..config() }).is_none());
    }

    #[test]
    fn reconfiguration_keeps_only_leases_inside_the_new_pool() {
        let mut s = Server::<8>::new(Config { last: [192, 168, 10, 110], ..config() }).unwrap();
        let ips: Vec<_> = (1..=6).map(|n| acquire(&mut s, mac(n), 0)).collect();
        assert!(s.reconfigure(Config { last: [192, 168, 10, 104], dns: [Some([9, 9, 9, 9]), None], ..config() }));
        let kept: Vec<_> = s.leases(1).map(|l| l.ip).collect();
        assert_eq!(kept.len(), ips.iter().filter(|ip| ip[3] <= 104).count());
        assert!(!s.reconfigure(Config { prefix: 31, ..config() }));
        assert_eq!(Config::default_pool([192, 168, 10, 1], 24), ([192, 168, 10, 100], [192, 168, 10, 249]));
        assert_eq!(Config::default_pool([10, 0, 0, 1], 28), ([10, 0, 0, 8], [10, 0, 0, 14]));
        let (first, last) = Config::default_pool([10, 0, 0, 1], 30);
        assert!(Config { first, last, ..config() }.first == [10, 0, 0, 2] && last == [10, 0, 0, 2]);
    }
}
