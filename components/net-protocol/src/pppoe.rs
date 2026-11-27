//! PPPoE client for a single Ethernet uplink. The board owns link detection,
//! VLAN insertion, transmit backpressure and publication of IPCP/IPv6CP state.
use alloc::string::String;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Pppoe {
    pub username: String,
    pub password: String,
    pub service: String,
}
impl core::fmt::Debug for Pppoe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pppoe").field("service", &self.service).finish_non_exhaustive()
    }
}

use alloc::{collections::VecDeque, vec, vec::Vec};
use md5::{Digest, Md5};

pub const MAX_MTU: u16 = 1492;
const DISCOVERY: u16 = 0x8863;
const SESSION: u16 = 0x8864;
const LCP: u16 = 0xc021;
const PAP: u16 = 0xc023;
const CHAP: u16 = 0xc223;
const IPCP: u16 = 0x8021;
const IPV4: u16 = 0x0021;
const IPV6CP: u16 = 0x8057;
const IPV6: u16 = 0x0057;
const PADI: u8 = 0x09;
const PADO: u8 = 0x07;
const PADR: u8 = 0x19;
const PADS: u8 = 0x65;
const PADT: u8 = 0xa7;
const HEADER: usize = 20;
const OVERHEAD: usize = 8;
const MAX_PENDING: usize = 8;
const RETRY: u64 = 3_000;
const KEEPALIVE: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wire {
    pub local: [u8; 6],
    pub peer: [u8; 6],
    id: u16,
    mru: u16,
    pub mtu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub wire: Wire,
    pub address: [u8; 4],
    pub gateway: Option<[u8; 4]>,
    pub dns: [Option<[u8; 4]>; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Link {
    pub wire: Wire,
    pub local: [u8; 16],
    pub peer: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Discover,
    Request,
    Link,
    Auth,
    Network,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Auth {
    None,
    Pap,
    Chap,
}

struct Exchange {
    id: u8,
    request: Vec<u8>,
    acked: bool,
    peer_request: Option<(u8, Vec<u8>)>,
}
impl Exchange {
    fn new(id: u8, request: Vec<u8>) -> Self {
        Self {
            id,
            request,
            acked: false,
            peer_request: None,
        }
    }
    fn open(&self) -> bool {
        self.acked && self.peer_request.is_some()
    }
    fn repeated(&self, id: u8, options: &[u8]) -> bool {
        self.peer_request
            .as_ref()
            .is_some_and(|(old_id, old)| *old_id == id && *old == options)
    }
}

/// Each NCP can open or stop independently of the other family.
struct Network {
    exchange: Exchange,
    retry_at: Option<u64>,
    attempts: u8,
}
impl Network {
    fn new(id: u8, options: Vec<u8>, now: Option<u64>) -> Self {
        Self {
            exchange: Exchange::new(id, options),
            retry_at: now,
            attempts: 0,
        }
    }
    fn retry(&mut self, now: u64) -> Option<(u8, Vec<u8>)> {
        if self.retry_at.is_none_or(|at| at > now) {
            return None;
        }
        if self.attempts >= 8 {
            self.retry_at = None;
            return None;
        }
        self.attempts += 1;
        self.retry_at = Some(now + RETRY);
        // The peer may have acknowledged our request before sending its own.
        // Keep probing until both directions are open.
        self.exchange.acked = false;
        Some((self.exchange.id, self.exchange.request.clone()))
    }
}

pub struct Client {
    pub settings: Pppoe,
    mac: [u8; 6],
    limit: u16,
    nonce: u64,
    phase: Phase,
    deadline: u64,
    attempts: u8,
    id: u8,
    offer: Vec<u8>,
    service: Vec<u8>,
    peer: [u8; 6],
    session: u16,
    auth: Auth,
    auth_id: Option<u8>,
    mru: u16,
    peer_mru: u16,
    magic: u32,
    link: Exchange,
    network: Network,
    ipv6_enabled: bool,
    ipv6: Option<Network>,
    peer_address: Option<[u8; 4]>,
    lease: Option<Lease>,
    /// Outstanding LCP identifier and next retry within the same keepalive interval.
    echo: Option<(u8, u64)>,
    error: Option<&'static str>,
    tx: VecDeque<Vec<u8>>,
}

fn word(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub fn unicast(ip: [u8; 4]) -> bool {
    !matches!(ip[0], 0 | 127 | 224..=255)
}

fn tag(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn header(
    out: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    kind: u16,
    code: u8,
    session: u16,
    len: usize,
) {
    out[..6].copy_from_slice(&dst);
    out[6..12].copy_from_slice(&src);
    out[12..14].copy_from_slice(&kind.to_be_bytes());
    out[14] = 0x11;
    out[15] = code;
    out[16..18].copy_from_slice(&session.to_be_bytes());
    out[18..20].copy_from_slice(&(len as u16).to_be_bytes());
}

fn payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < HEADER || frame[14] != 0x11 {
        return None;
    }
    let len = usize::from(word(&frame[18..20]));
    (len <= 1500 - 6)
        .then(|| frame.get(HEADER..HEADER + len))
        .flatten()
}

fn options(mut bytes: &[u8]) -> Option<Vec<&[u8]>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(*bytes.get(1)?);
        if len < 2 {
            return None;
        }
        result.push(bytes.get(..len)?);
        bytes = &bytes[len..];
    }
    Some(result)
}

fn tags(mut bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let head = bytes.get(..4)?;
        let kind = word(head);
        let len = usize::from(word(&head[2..]));
        let value = bytes.get(4..4 + len)?;
        if kind == 0 {
            return (len == 0).then_some(result);
        }
        result.push((kind, value));
        bytes = &bytes[4 + len..];
    }
    Some(result)
}

fn ip_option(request: &[u8], kind: u8) -> Option<[u8; 4]> {
    options(request)?.into_iter().find_map(|opt| {
        if opt[0] != kind {
            return None;
        }
        let ip: [u8; 4] = opt[2..].try_into().ok()?;
        unicast(ip).then_some(ip)
    })
}

impl Client {
    pub fn new(settings: Pppoe, mac: [u8; 6], mtu: u16, nonce: u64, now: u64) -> Self {
        let limit = mtu.min(MAX_MTU);
        Self {
            settings,
            mac,
            limit,
            nonce,
            phase: Phase::Discover,
            deadline: now,
            attempts: 0,
            id: nonce as u8,
            offer: Vec::new(),
            service: Vec::new(),
            peer: [0; 6],
            session: 0,
            auth: Auth::None,
            auth_id: None,
            mru: limit,
            peer_mru: MAX_MTU,
            magic: 0,
            link: Exchange::new(0, Vec::new()),
            network: Network::new(0, Vec::new(), None),
            ipv6_enabled: false,
            ipv6: None,
            peer_address: None,
            lease: None,
            echo: None,
            error: None,
            tx: VecDeque::new(),
        }
    }
    pub fn state(&self) -> &'static str {
        self.error.unwrap_or(match self.phase {
            Phase::Discover | Phase::Request => "discovering",
            Phase::Link => "negotiating",
            Phase::Auth => "authenticating",
            Phase::Network if self.lease.is_some() => "bound",
            Phase::Network => "configuring",
        })
    }
    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }
    pub fn enable_ipv6(mut self, enabled: bool) -> Self {
        self.ipv6_enabled = enabled;
        self
    }
    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6_enabled
    }
    pub fn ipv6_state(&self) -> &'static str {
        if !self.ipv6_enabled {
            "disabled"
        } else if self.phase != Phase::Network {
            "waiting-ppp"
        } else if self.ipv6_link().is_some() {
            "open"
        } else if self.wire().mtu < 1280 || self.mru < 1280 {
            "mtu-too-small"
        } else if self.ipv6.as_ref().is_some_and(|cp| cp.retry_at.is_some()) {
            "negotiating"
        } else {
            "closed"
        }
    }
    pub fn reject_ipv4_address(&mut self, now: u64) {
        if self.ipv6_enabled {
            self.close_ipcp();
            let id = self.next_id();
            self.control(IPCP, 5, id, &[]);
            self.error = Some("address-conflict");
        } else {
            self.restart(now, "address-conflict");
        }
    }
    pub fn ipv6_link(&self) -> Option<Ipv6Link> {
        let cp = &self.ipv6.as_ref()?.exchange;
        if self.phase != Phase::Network || !cp.open() {
            return None;
        }
        let (_, peer) = cp.peer_request.as_ref()?;
        Some(Ipv6Link {
            wire: self.wire(),
            local: ipv6_link_local(iid(&cp.request)?),
            peer: ipv6_link_local(iid(peer)?),
        })
    }
    fn wire(&self) -> Wire {
        Wire {
            local: self.mac,
            peer: self.peer,
            id: self.session,
            mru: self.mru,
            mtu: self.limit.min(self.peer_mru),
        }
    }
    /// A validated network-layer return on this session proves peer activity
    /// even when a congested peer drops individual LCP Echo-Replies.
    pub fn accepted_return(&mut self, wire: Wire) {
        if self.echo.is_some() && self.phase == Phase::Network && self.wire() == wire {
            self.attempts = 0;
            self.echo = None;
        }
    }
    pub fn deadline(&self) -> u64 {
        self.network
            .retry_at
            .into_iter()
            .chain(self.ipv6.as_ref().and_then(|n| n.retry_at))
            .chain(self.echo.map(|(_, retry)| retry))
            .fold(self.deadline, u64::min)
    }
    pub fn egress(&self) -> Option<&[u8]> {
        self.tx.front().map(Vec::as_slice)
    }
    pub fn sent(&mut self) {
        self.tx.pop_front();
    }
    fn enqueue(&mut self, frame: Vec<u8>) {
        if self.tx.len() < MAX_PENDING {
            self.tx.push_back(frame);
        }
    }
    fn next_id(&mut self) -> u8 {
        self.id = self.id.wrapping_add(1);
        self.id
    }
    fn discovery_frame(&self, code: u8, dest: [u8; 6], session: u16, tags: &[u8]) -> Vec<u8> {
        let mut frame = vec![0; HEADER];
        header(
            &mut frame,
            dest,
            self.mac,
            DISCOVERY,
            code,
            session,
            tags.len(),
        );
        frame.extend_from_slice(tags);
        frame
    }
    pub fn terminate(&self) -> Option<Vec<u8>> {
        (self.session != 0).then(|| self.discovery_frame(PADT, self.peer, self.session, &[]))
    }
    pub fn restart(&mut self, now: u64, error: &'static str) {
        let padt = self.terminate();
        self.tx.clear();
        self.tx.extend(padt);
        self.session = 0;
        self.nonce = self.nonce.wrapping_add(1);
        self.enter(Phase::Discover, now + 5_000);
        self.error = Some(error);
        self.offer.clear();
        self.service.clear();
    }
    fn control(&mut self, proto: u16, code: u8, id: u8, data: &[u8]) {
        let mut frame = vec![0; HEADER];
        header(
            &mut frame,
            self.peer,
            self.mac,
            SESSION,
            0,
            self.session,
            6 + data.len(),
        );
        frame.extend_from_slice(&proto.to_be_bytes());
        frame.extend_from_slice(&[code, id]);
        frame.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        frame.extend_from_slice(data);
        self.enqueue(frame);
    }
    fn peer_terminate(&mut self, proto: u16, id: u8, now: u64) {
        let session = self.session;
        self.restart(now, "peer-terminated");
        // The old session remains usable for Terminate-Ack until PADT leaves.
        self.session = session;
        self.control(proto, 6, id, &[]);
        self.session = 0;
        self.tx.rotate_right(1);
    }
    fn enter(&mut self, phase: Phase, now: u64) {
        self.phase = phase;
        self.lease = None;
        self.network.retry_at = None;
        self.ipv6 = None;
        self.echo = None;
        self.attempts = 0;
        self.deadline = now;
        self.error = None;
    }
    fn start_link(&mut self, now: u64) {
        self.auth = Auth::None;
        self.auth_id = None;
        self.mru = self.limit;
        self.peer_mru = MAX_MTU;
        self.magic = ((self.nonce ^ (self.nonce >> 32)) as u32).max(1);
        let mut req = vec![1, 4];
        req.extend_from_slice(&self.mru.to_be_bytes());
        req.extend_from_slice(&[5, 6]);
        req.extend_from_slice(&self.magic.to_be_bytes());
        self.link = Exchange::new(self.next_id(), req);
        self.enter(Phase::Link, now);
    }
    fn start_network(&mut self, now: u64) {
        self.peer_address = None;
        self.enter(Phase::Network, now + KEEPALIVE);
        self.network = Network::new(
            self.next_id(),
            vec![3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0],
            Some(now),
        );
        if self.ipv6_enabled && self.wire().mtu >= 1280 && self.mru >= 1280 {
            let local = self.mac;
            let request = vec![
                1,
                10,
                local[0] & !2,
                local[1],
                local[2],
                0xff,
                0xfe,
                local[3],
                local[4],
                local[5],
            ];
            self.ipv6 = Some(Network::new(self.next_id(), request, Some(now)));
        }
    }
    pub fn poll(&mut self, now: u64) {
        if !self.tx.is_empty() {
            return;
        }
        if self.phase == Phase::Network {
            if let Some((id, request)) = self.network.retry(now) {
                self.control(IPCP, 1, id, &request);
            }
            if let Some((id, request)) = self.ipv6.as_mut().and_then(|cp| cp.retry(now)) {
                self.control(IPV6CP, 1, id, &request);
            }
            if self.lease.is_none()
                && self.ipv6_link().is_none()
                && self.network.retry_at.is_none()
                && self.ipv6.as_ref().is_none_or(|cp| cp.retry_at.is_none())
            {
                self.restart(now, "dial-timeout");
            } else if now >= self.deadline {
                if self.attempts >= 3 {
                    self.restart(now, "peer-timeout");
                    return;
                }
                let id = self.next_id();
                self.echo = Some((id, now + KEEPALIVE / 4));
                self.control(LCP, 9, id, &self.magic.to_be_bytes());
                self.attempts += 1;
                self.deadline = now + KEEPALIVE;
            } else if let Some((id, retry)) = self.echo {
                if now >= retry {
                    self.control(LCP, 9, id, &self.magic.to_be_bytes());
                    self.echo = Some((id, (now + KEEPALIVE / 4).min(self.deadline)));
                }
            }
            return;
        }
        if now < self.deadline {
            return;
        }
        if self.attempts >= 8 {
            self.restart(now, "dial-timeout");
            return;
        }
        self.attempts += 1;
        self.deadline = now + RETRY;
        match self.phase {
            Phase::Discover => {
                let mut data = Vec::new();
                tag(&mut data, 0x0101, self.settings.service.as_bytes());
                tag(&mut data, 0x0103, &self.nonce.to_be_bytes());
                self.enqueue(self.discovery_frame(PADI, [0xff; 6], 0, &data));
            }
            Phase::Request => self.enqueue(self.discovery_frame(PADR, self.peer, 0, &self.offer)),
            Phase::Link if !self.link.acked => {
                self.control(LCP, 1, self.link.id, &self.link.request.clone())
            }
            Phase::Auth if self.auth == Auth::Pap => {
                let user = self.settings.username.as_bytes();
                let password = self.settings.password.as_bytes();
                let mut data = vec![user.len() as u8];
                data.extend_from_slice(user);
                data.push(password.len() as u8);
                data.extend_from_slice(password);
                let id = self.auth_id.unwrap_or_else(|| self.next_id());
                self.auth_id = Some(id);
                self.control(PAP, 1, id, &data);
            }
            _ => {}
        }
    }

    pub fn receive(&mut self, frame: &[u8], now: u64) {
        let Some(data) = payload(frame) else {
            return;
        };
        let source: [u8; 6] = frame[6..12].try_into().unwrap();
        if frame[..6] != self.mac || source[0] & 1 != 0 || source == [0; 6] || source == self.mac {
            return;
        }
        let session = word(&frame[16..18]);
        match (word(&frame[12..14]), frame[15]) {
            (DISCOVERY, PADO | PADS) => self.discover(frame[15], source, session, data, now),
            (DISCOVERY, PADT)
                if self.session != 0 && session == self.session && source == self.peer =>
            {
                self.session = 0;
                self.restart(now, "peer-terminated");
            }
            (SESSION, 0) if self.session != 0 && session == self.session && source == self.peer => {
                self.session_input(data, now);
            }
            _ => {}
        }
    }

    fn discover(&mut self, code: u8, source: [u8; 6], session: u16, data: &[u8], now: u64) {
        if !matches!(
            (code, self.phase),
            (PADO, Phase::Discover) | (PADS, Phase::Request)
        ) {
            return;
        }
        let Some(tags) = tags(data) else {
            return;
        };
        if !tags
            .iter()
            .any(|(kind, value)| *kind == 0x0103 && *value == self.nonce.to_be_bytes())
        {
            return;
        }
        if code == PADS && source != self.peer {
            return;
        }
        if tags.iter().any(|(kind, _)| matches!(kind, 0x0201..=0x0203)) {
            if code == PADS {
                self.restart(now, "discovery-rejected");
            }
            return;
        }
        let service = if code == PADO {
            self.settings.service.as_bytes()
        } else {
            &self.service
        };
        let Some((_, offered)) = tags.iter().find(|(kind, value)| {
            *kind == 0x0101 && (*value == service || (code == PADO && service.is_empty()))
        }) else {
            return;
        };
        if code == PADS && session != 0 && session != u16::MAX {
            self.tx.clear();
            self.session = session;
            self.start_link(now);
        } else if code == PADO && session == 0 && tags.iter().any(|(kind, _)| *kind == 0x0102) {
            let mut offer = Vec::new();
            tag(&mut offer, 0x0101, offered);
            tag(&mut offer, 0x0103, &self.nonce.to_be_bytes());
            for kind in [0x0104, 0x0110] {
                if let Some((_, value)) = tags.iter().find(|(key, _)| *key == kind) {
                    tag(&mut offer, kind, value);
                }
            }
            if offer.len() <= 1494 {
                self.tx.clear();
                self.service = offered.to_vec();
                self.offer = offer;
                self.peer = source;
                self.enter(Phase::Request, now);
            }
        }
    }

    fn session_input(&mut self, data: &[u8], now: u64) {
        if data.len() < 2 {
            return;
        }
        let proto = word(data);
        if !matches!(proto, LCP | PAP | CHAP | IPCP | IPV4 | IPV6)
            && !(proto == IPV6CP && self.ipv6_enabled)
            && self.link.open()
        {
            let id = self.next_id();
            let len = data.len().min(usize::from(self.peer_mru) - 4);
            self.control(LCP, 8, id, &data[..len]);
            return;
        }
        if matches!(proto, IPV4 | IPV6) || data.len() < 6 {
            return;
        }
        let size = usize::from(word(&data[4..6]));
        if size < 4 || size > usize::from(self.mru) {
            return;
        }
        let Some(body) = data.get(6..2 + size) else {
            return;
        };
        let (code, id) = (data[2], data[3]);
        match proto {
            LCP => self.lcp(code, id, body, now),
            PAP if self.phase == Phase::Auth
                && self.auth == Auth::Pap
                && self.auth_id == Some(id)
                && body
                    .first()
                    .is_some_and(|len| usize::from(*len) == body.len() - 1) =>
            {
                match code {
                    2 => self.start_network(now),
                    3 => self.restart(now, "authentication-failed"),
                    _ => {}
                }
            }
            CHAP if self.auth == Auth::Chap
                && matches!(self.phase, Phase::Auth | Phase::Network) =>
            {
                self.chap(code, id, body, now);
            }
            IPCP if self.phase == Phase::Network => self.ipcp(code, id, body, now),
            IPV6CP if self.phase == Phase::Network && self.ipv6.is_some() => {
                self.ipv6cp(code, id, body, now)
            }
            _ => {}
        }
    }

    fn lcp(&mut self, code: u8, id: u8, body: &[u8], now: u64) {
        match code {
            1 => self.link_request(id, body, now),
            2 if self.phase == Phase::Link && id == self.link.id && body == self.link.request => {
                self.link.acked = true;
            }
            3 | 4 if self.phase == Phase::Link && id == self.link.id && !self.link.acked => {
                if let Some(request) =
                    revised(&self.link.request, code, body, |old, new| match old[0] {
                        1 => new.len() == 4 && (576..=word(&old[2..])).contains(&word(&new[2..])),
                        5 => new.len() == 6 && new[2..] != old[2..] && new[2..] != [0; 4],
                        _ => false,
                    })
                {
                    self.mru = options(&request)
                        .unwrap()
                        .into_iter()
                        .find(|opt| opt[0] == 1)
                        .map_or(self.limit, |opt| word(&opt[2..]));
                    self.magic = options(&request)
                        .unwrap()
                        .into_iter()
                        .find(|opt| opt[0] == 5)
                        .map_or(0, |opt| u32::from_be_bytes(opt[2..].try_into().unwrap()));
                    self.link.id = self.next_id();
                    self.link.request = request;
                    self.deadline = now;
                }
            }
            5 => self.peer_terminate(LCP, id, now),
            8 if self.phase == Phase::Network && body.len() >= 2 => match word(body) {
                IPV6CP | IPV6 => self.ipv6 = None,
                IPCP | IPV4 => self.close_ipcp(),
                _ => {}
            },
            9 if self.link.open() && body.len() >= 4 => {
                let mut reply = body[..body.len().min(usize::from(self.peer_mru) - 4)].to_vec();
                reply[..4].copy_from_slice(&self.magic.to_be_bytes());
                self.control(LCP, 10, id, &reply);
            }
            10 if self.phase == Phase::Network
                && body.len() >= 4
                && self.echo.is_some_and(|(pending, _)| pending == id)
                && (self.magic == 0 || body[..4] != self.magic.to_be_bytes()) =>
            {
                self.echo = None;
                self.attempts = 0;
            }
            _ => {}
        }
        if self.phase == Phase::Link && self.link.open() {
            if self.auth == Auth::None {
                self.start_network(now);
            } else {
                self.enter(Phase::Auth, now);
            }
        }
    }

    fn link_request(&mut self, id: u8, body: &[u8], now: u64) {
        if self.link.repeated(id, body) {
            self.control(LCP, 2, id, body);
            return;
        }
        let Some(opts) = options(body) else {
            return;
        };
        if self.phase != Phase::Link {
            self.tx.clear();
            self.start_link(now);
        }
        self.link.peer_request = None;
        let mut reject = Vec::new();
        let mut nak = Vec::new();
        let mut mru = MAX_MTU;
        let mut auth = Auth::None;
        let mut seen = [false; 6];
        for opt in opts {
            let kind = usize::from(opt[0]);
            if seen.get(kind).copied().unwrap_or(false) {
                reject.extend_from_slice(opt);
                continue;
            }
            if let Some(slot) = seen.get_mut(kind) {
                *slot = true;
            }
            match opt {
                [1, 4, high, low] => {
                    mru = u16::from_be_bytes([*high, *low]);
                    if !(576..=MAX_MTU).contains(&mru) {
                        nak.extend_from_slice(&[1, 4]);
                        nak.extend_from_slice(&mru.clamp(576, MAX_MTU).to_be_bytes());
                    }
                }
                [3, 4, 0xc0, 0x23] => auth = Auth::Pap,
                [3, 5, 0xc2, 0x23, 5] => auth = Auth::Chap,
                [3, ..] if opt.len() >= 4 => nak.extend_from_slice(&[3, 5, 0xc2, 0x23, 5]),
                [5, 6, rest @ ..] => {
                    if self.magic != 0 && rest == self.magic.to_be_bytes() {
                        nak.extend_from_slice(&[5, 6]);
                        nak.extend_from_slice(&self.magic.wrapping_add(1).max(1).to_be_bytes());
                    }
                }
                _ => reject.extend_from_slice(opt),
            }
        }
        if !reject.is_empty() {
            self.control(LCP, 4, id, &reject);
        } else if !nak.is_empty() {
            self.control(LCP, 3, id, &nak);
        } else {
            self.link.peer_request = Some((id, body.to_vec()));
            self.peer_mru = mru;
            self.auth = auth;
            self.control(LCP, 2, id, body);
        }
    }

    fn chap(&mut self, code: u8, id: u8, body: &[u8], now: u64) {
        match code {
            1 => {
                let Some(challenge) = body
                    .first()
                    .filter(|len| **len != 0)
                    .and_then(|len| body.get(1..1 + usize::from(*len)))
                else {
                    return;
                };
                let mut md5 = Md5::new();
                md5.update([id]);
                md5.update(self.settings.password.as_bytes());
                md5.update(challenge);
                let mut response = vec![16];
                response.extend_from_slice(&md5.finalize());
                response.extend_from_slice(self.settings.username.as_bytes());
                self.auth_id = Some(id);
                self.control(CHAP, 2, id, &response);
            }
            3 if self.auth_id == Some(id) => {
                self.auth_id = None;
                if self.phase == Phase::Auth {
                    self.start_network(now);
                }
            }
            4 if self.auth_id == Some(id) => self.restart(now, "authentication-failed"),
            _ => {}
        }
    }

    fn close_ipcp(&mut self) {
        self.lease = None;
        self.network.exchange.acked = false;
        self.network.exchange.peer_request = None;
        self.network.retry_at = None;
    }

    fn ipcp(&mut self, code: u8, id: u8, body: &[u8], now: u64) {
        match code {
            1 => {
                if self.network.exchange.repeated(id, body) {
                    self.control(IPCP, 2, id, body);
                    return;
                }
                let Some(opts) = options(body) else {
                    return;
                };
                if self.lease.is_some() || self.network.retry_at.is_none() {
                    self.lease = None;
                    let request = self.network.exchange.request.clone();
                    self.network = Network::new(self.next_id(), request, Some(now));
                }
                self.network.exchange.peer_request = None;
                let mut reject = Vec::new();
                let mut peer = None;
                for opt in opts {
                    if opt.len() == 6 && opt[0] == 3 && peer.is_none() {
                        let ip = opt[2..].try_into().unwrap();
                        if unicast(ip) {
                            peer = Some(ip);
                            continue;
                        }
                    }
                    reject.extend_from_slice(opt);
                }
                if reject.is_empty() {
                    self.peer_address = peer;
                    self.network.exchange.peer_request = Some((id, body.to_vec()));
                    self.control(IPCP, 2, id, body);
                } else {
                    self.control(IPCP, 4, id, &reject);
                }
            }
            2 if self.network.retry_at.is_some()
                && id == self.network.exchange.id
                && body == self.network.exchange.request =>
            {
                self.network.exchange.acked = true
            }
            3 | 4
                if self.network.retry_at.is_some()
                    && id == self.network.exchange.id
                    && !self.network.exchange.acked =>
            {
                if let Some(request) =
                    revised(&self.network.exchange.request, code, body, |_, new| {
                        new.len() == 6
                            && (unicast(new[2..].try_into().unwrap())
                                || (new[0] != 3 && new[2..] == [0; 4]))
                    })
                {
                    if options(&request).unwrap().iter().all(|opt| opt[0] != 3) {
                        self.close_ipcp();
                        return;
                    }
                    self.network.exchange.id = self.next_id();
                    self.network.exchange.request = request;
                    self.network.retry_at = Some(now);
                }
            }
            5 => {
                self.close_ipcp();
                self.control(IPCP, 6, id, &[]);
            }
            _ => {}
        }
        if self.lease.is_none() && self.network.exchange.open() {
            self.network.retry_at = None;
            if let Some(address) = ip_option(&self.network.exchange.request, 3) {
                self.error = None;
                self.lease = Some(Lease {
                    wire: self.wire(),
                    address,
                    gateway: self.peer_address,
                    dns: [
                        ip_option(&self.network.exchange.request, 129),
                        ip_option(&self.network.exchange.request, 131),
                    ],
                });
            }
        }
    }

    fn ipv6cp(&mut self, code: u8, id: u8, body: &[u8], now: u64) {
        let mut cp = self.ipv6.take().unwrap();
        let local = iid(&cp.exchange.request).unwrap();
        match code {
            1 if cp.exchange.repeated(id, body) => self.control(IPV6CP, 2, id, body),
            1 => {
                let Some(opts) = options(body) else {
                    self.ipv6 = Some(cp);
                    return;
                };
                if cp.retry_at.is_none() {
                    cp = Network::new(self.next_id(), cp.exchange.request, Some(now));
                }
                cp.exchange.peer_request = None;
                let mut remote = None;
                let mut reject = Vec::new();
                for opt in opts {
                    if let Some(candidate) = iid(opt).filter(|_| remote.is_none()) {
                        remote = Some(candidate);
                    } else {
                        reject.extend_from_slice(opt);
                    }
                }
                if !reject.is_empty() {
                    self.control(IPV6CP, 4, id, &reject);
                } else if remote.is_some_and(|remote| remote != [0; 8] && remote != local) {
                    cp.exchange.peer_request = Some((id, body.to_vec()));
                    self.control(IPV6CP, 2, id, body);
                } else {
                    let suggestion = if u64::from_be_bytes(local) == 1 {
                        2u64
                    } else {
                        1u64
                    }
                    .to_be_bytes();
                    let mut nak = [1; 10];
                    nak[1] = 10;
                    nak[2..].copy_from_slice(&suggestion);
                    self.control(IPV6CP, 3, id, &nak);
                }
            }
            2 if cp.retry_at.is_some() && id == cp.exchange.id && body == cp.exchange.request => {
                cp.exchange.acked = true;
            }
            3 if cp.retry_at.is_some() && id == cp.exchange.id && !cp.exchange.acked => {
                if iid(body).is_some_and(|suggestion| {
                    suggestion != [0; 8]
                        && suggestion != local
                        && cp
                            .exchange
                            .peer_request
                            .as_ref()
                            .and_then(|(_, peer)| iid(peer))
                            != Some(suggestion)
                }) {
                    cp.exchange.id = self.next_id();
                    cp.exchange.request = body.to_vec();
                    cp.retry_at = Some(now);
                }
            }
            4 if cp.retry_at.is_some() && id == cp.exchange.id && body == cp.exchange.request => {
                return;
            }
            5 => {
                cp.exchange.acked = false;
                cp.exchange.peer_request = None;
                cp.retry_at = None;
                self.control(IPV6CP, 6, id, &[]);
            }
            7 if matches!(body.first(), Some(1..=4)) => return,
            2..=7 => {}
            _ => {
                let mut rejected = vec![code, id];
                rejected.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
                rejected.extend_from_slice(&body[..body.len().min(usize::from(self.peer_mru) - 8)]);
                let reject_id = self.next_id();
                self.control(IPV6CP, 7, reject_id, &rejected);
            }
        }
        if cp.exchange.open() {
            cp.retry_at = None;
        }
        self.ipv6 = Some(cp);
    }
}

fn iid(option: &[u8]) -> Option<[u8; 8]> {
    let [1, 10, value @ ..] = option else {
        return None;
    };
    value.try_into().ok()
}

fn ipv6_link_local(id: [u8; 8]) -> [u8; 16] {
    let mut address = [0; 16];
    address[..2].copy_from_slice(&[0xfe, 0x80]);
    address[8..].copy_from_slice(&id);
    address
}

/// Accept only replies that refer to the outstanding request.
fn revised(
    request: &[u8],
    code: u8,
    reply: &[u8],
    valid_nak: impl Fn(&[u8], &[u8]) -> bool,
) -> Option<Vec<u8>> {
    let old = options(request)?;
    let changed = options(reply)?;
    if changed.is_empty()
        || changed.iter().enumerate().any(|(i, opt)| {
            changed[..i].iter().any(|prior| prior[0] == opt[0])
                || !old.iter().any(|prior| {
                    prior[0] == opt[0]
                        && if code == 4 {
                            prior == opt
                        } else {
                            valid_nak(prior, opt)
                        }
                })
        })
    {
        return None;
    }
    let mut next = Vec::new();
    for opt in old {
        match changed.iter().find(|new| new[0] == opt[0]) {
            Some(new) if code == 3 => next.extend_from_slice(new),
            Some(_) => {}
            None => next.extend_from_slice(opt),
        }
    }
    (next != request).then_some(next)
}

impl Wire {
    pub fn session_id(self) -> u16 {
        self.id
    }

    pub fn decapsulate(self, frame: &mut [u8]) -> Option<(usize, usize)> {
        self.decapsulate_ip(frame, IPV4)
    }

    pub fn decapsulate_ipv6(self, frame: &mut [u8]) -> Option<(usize, usize)> {
        self.decapsulate_ip(frame, IPV6)
    }

    /// Validate the peer, session and MRU before inspecting any inner bytes.
    fn session_datagram<'a>(self, frame: &'a [u8], protocol: u16) -> Option<&'a [u8]> {
        let data = payload(frame)?;
        if frame[..6] != self.local
            || frame[6..12] != self.peer
            || frame[12..16] != [0x88, 0x64, 0x11, 0]
            || word(&frame[16..18]) != self.id
            || data.len() < 22
            || word(data) != protocol
            || data.len() - 2 > usize::from(self.mru)
        {
            return None;
        }
        Some(&data[2..])
    }

    /// Validate an IPv4 return without modifying the descriptor on a miss.
    pub fn inspect_ipv4_return(self, frame: &[u8]) -> Option<crate::ipv4::Inspected> {
        let data = self.session_datagram(frame, IPV4)?;
        if [self.local, self.peer].iter().any(|mac| *mac == [0; 6] || mac[0] & 1 != 0) { return None; }
        let ip = crate::ipv4::inspect_datagram(data).ok()?;
        (ip.ip_length == data.len()).then_some(ip)
    }

    pub fn ipv6_return<'a>(self, frame: &'a [u8]) -> Option<crate::ipv6::Packet<'a>> {
        let ip = self.session_datagram(frame, IPV6)?;
        let payload = ip.get(40..)?;
        if ip[0] >> 4 != 6 || usize::from(word(&ip[4..6])) != payload.len() { return None; }
        Some(crate::ipv6::Packet {
            source: ip[8..24].try_into().ok()?,
            destination: ip[24..40].try_into().ok()?,
            next: ip[6], hop: ip[7], payload, length: 14 + ip.len(),
        })
    }

    /// Install the Ethernet header in the space freed by PPPoE decapsulation.
    /// The caller has checked this exact datagram and its forwarding authority.
    pub fn write_ipv4_return_header(self, frame: &mut [u8]) -> usize {
        self.write_return_header(frame, [8, 0])
    }
    pub fn write_ipv6_return_header(self, frame: &mut [u8]) -> usize {
        self.write_return_header(frame, [0x86, 0xdd])
    }
    fn write_return_header(self, frame: &mut [u8], kind: [u8; 2]) -> usize {
        frame[OVERHEAD..OVERHEAD + 6].copy_from_slice(&self.local);
        frame[OVERHEAD + 6..OVERHEAD + 12].copy_from_slice(&self.peer);
        frame[OVERHEAD + 12..OVERHEAD + 14].copy_from_slice(&kind);
        OVERHEAD
    }

    /// Use bytes already occupied by PPPoE to present the packet to the
    /// router's Ethernet-facing IPv4 or IPv6 path.
    fn decapsulate_ip(self, frame: &mut [u8], protocol: u16) -> Option<(usize, usize)> {
        let ip = self.session_datagram(frame, protocol)?;
        let (total, kind) = match protocol {
            IPV4 if ip[0] >> 4 == 4 => {
                let total = usize::from(word(&ip[2..4]));
                if total < 20 {
                    return None;
                }
                (total, [8, 0])
            }
            IPV6 if ip.len() >= 40 && ip[0] >> 4 == 6 => {
                (40 + usize::from(word(&ip[4..6])), [0x86, 0xdd])
            }
            _ => return None,
        };
        if total != ip.len() {
            return None;
        }
        let frame = &mut frame[OVERHEAD..OVERHEAD + 14 + total];
        frame[..6].copy_from_slice(&self.local);
        frame[6..12].copy_from_slice(&self.peer);
        frame[12..14].copy_from_slice(&kind);
        clamp_mss(&mut frame[14..], protocol, self.mtu);
        Some((OVERHEAD, 14 + total))
    }

    pub fn encapsulate(
        self,
        buffer: &mut [u8],
        offset: usize,
        length: usize,
        headroom: bool,
    ) -> Option<(usize, usize)> {
        self.encapsulate_ip(buffer, offset, length, headroom, IPV4)
    }

    pub fn encapsulate_ipv6(
        self,
        buffer: &mut [u8],
        offset: usize,
        length: usize,
        headroom: bool,
    ) -> Option<(usize, usize)> {
        self.encapsulate_ip(buffer, offset, length, headroom, IPV6)
    }

    fn encapsulate_ip(
        self,
        buffer: &mut [u8],
        offset: usize,
        length: usize,
        headroom: bool,
        protocol: u16,
    ) -> Option<(usize, usize)> {
        let end = offset.checked_add(length)?;
        let frame = buffer.get(offset..end)?;
        let (minimum, kind) = if protocol == IPV4 {
            (34, [8, 0])
        } else {
            (54, [0x86, 0xdd])
        };
        if length < minimum || length - 14 > usize::from(self.mtu) || frame[12..14] != kind {
            return None;
        }
        let length = length + OVERHEAD;
        let start = if headroom && offset >= OVERHEAD {
            offset - OVERHEAD
        } else {
            if end.checked_add(OVERHEAD)? > buffer.len() {
                return None;
            }
            buffer.copy_within(offset + 14..end, offset + HEADER + 2);
            offset
        };
        let frame = &mut buffer[start..start + length];
        header(
            frame,
            self.peer,
            self.local,
            SESSION,
            0,
            self.id,
            length - HEADER,
        );
        frame[HEADER..HEADER + 2].copy_from_slice(&protocol.to_be_bytes());
        clamp_mss(&mut frame[HEADER + 2..], protocol, self.mru.min(self.mtu));
        Some((start, length))
    }
}

/// Clamp advertised MSS on SYN and SYN-ACK. Update the checksum in place,
/// including options whose two-byte value straddles checksum words.
fn clamp_mss(ip: &mut [u8], protocol: u16, mtu: u16) {
    let (offset, overhead) = match protocol {
        IPV4 if ip.len() >= 20 && ip[0] >> 4 == 4 && ip[9] == 6 && word(&ip[6..8]) & 0x3fff == 0 => {
            let ihl = usize::from(ip[0] & 15) * 4;
            if ihl < 20 { return; }
            (ihl, 40)
        }
        IPV6 if ip.len() >= 40 && ip[0] >> 4 == 6 && ip[6] == 6
            && usize::from(word(&ip[4..6])) == ip.len() - 40 => (40, 60),
        _ => return,
    };
    let Some(tcp) = ip.get_mut(offset..).filter(|tcp| tcp.len() >= 20) else {return;};
    let end = usize::from(tcp[12] >> 4) * 4;
    if tcp[13] & 2 == 0 || end < 20 || end > tcp.len() {
        return;
    }
    let Some(max) = mtu.checked_sub(overhead) else {return;};
    let mut at = 20;
    while at < end {
        let kind = tcp[at];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            at += 1;
            continue;
        }
        let Some(&len) = tcp.get(at + 1).filter(|_| at + 1 < end) else {
            return;
        };
        let len = usize::from(len);
        if len < 2 || at + len > end {
            return;
        }
        if kind == 2 && len == 4 && word(&tcp[at + 2..at + 4]) > max {
            let start = (at + 2) & !1;
            let stop = (at + 5) & !1;
            let mut sum = u32::from(!word(&tcp[16..18]));
            sum += tcp[start..stop]
                .chunks_exact(2)
                .map(|old| u32::from(!word(old)))
                .sum::<u32>();
            tcp[at + 2..at + 4].copy_from_slice(&max.to_be_bytes());
            sum += tcp[start..stop]
                .chunks_exact(2)
                .map(|new| u32::from(word(new)))
                .sum::<u32>();
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            tcp[16..18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        }
        at += len;
    }
}

#[cfg(any(test, feature = "pppoe-test-fixtures"))]
pub mod fixtures {
    use super::*;
    pub const LOCAL: [u8; 6] = [2, 0, 0, 0, 0, 1];
    pub const PEER: [u8; 6] = [2, 0, 0, 0, 0, 2];
    pub(super) const NONCE: u64 = 1234;
    pub(super) const SESSION_ID: u16 = 13;
    #[cfg(test)]
    pub(super) const ADDRESS: [u8; 4] = [198, 51, 100, 0];
    #[cfg(test)]
    pub(super) const GATEWAY: [u8; 4] = [203, 0, 113, 1];

    pub(super) fn peer_frame(kind: u16, code: u8, session: u16, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0; HEADER];
        header(&mut frame, LOCAL, PEER, kind, code, session, data.len());
        frame.extend_from_slice(data);
        frame
    }

    pub(super) fn peer_control(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
        let mut payload = proto.to_be_bytes().to_vec();
        payload.extend_from_slice(&[code, id]);
        payload.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
        payload.extend_from_slice(data);
        peer_frame(SESSION, 0, SESSION_ID, &payload)
    }

    pub(super) fn tx(client: &mut Client) -> Vec<u8> {
        let frame = client.egress().unwrap().to_vec();
        client.sent();
        frame
    }

    pub(super) fn discover() -> Client {
        let config = Pppoe {
            username: "isp-user".into(),
            password: "isp-password".into(),
            service: "internet".into(),
        };
        let mut client = Client::new(config, LOCAL, 1500, NONCE, 0);
        client.poll(0);
        let padi = tx(&mut client);
        assert_eq!(&padi[..6], &[0xff; 6]);
        assert_eq!(&padi[12..18], &[0x88, 0x63, 0x11, 9, 0, 0]);
        let offered = |host: u64, offer: bool| {
            let mut data = Vec::new();
            tag(&mut data, 0x0101, b"internet");
            tag(&mut data, 0x0103, &host.to_be_bytes());
            if offer {
                tag(&mut data, 0x0102, b"access-concentrator");
                tag(&mut data, 0x0104, b"cookie");
                tag(&mut data, 0x0110, b"relay");
            }
            data
        };
        client.receive(
            &peer_frame(DISCOVERY, PADO, 0, &offered(NONCE + 1, true)),
            1,
        );
        assert_eq!(client.deadline(), RETRY);
        client.receive(&peer_frame(DISCOVERY, PADO, 0, &offered(NONCE, true)), 1);
        client.poll(1);
        let padr = tx(&mut client);
        assert_eq!(&padr[..6], &PEER);
        assert_eq!(padr[15], PADR);
        let tags = tags(payload(&padr).unwrap()).unwrap();
        assert!(tags.contains(&(0x0104, b"cookie")));
        assert!(tags.contains(&(0x0110, b"relay")));
        let mut wrong_peer = peer_frame(DISCOVERY, PADS, SESSION_ID, &offered(NONCE, false));
        wrong_peer[11] ^= 4;
        client.receive(&wrong_peer, 2);
        assert_eq!(client.session, 0);
        client.receive(
            &peer_frame(DISCOVERY, PADS, SESSION_ID, &offered(NONCE, false)),
            2,
        );
        assert_eq!(client.session, SESSION_ID);
        assert_eq!(client.lease(), None);
        client
    }

    pub(super) fn lcp(mut client: Client, auth: &[u8]) -> Client {
        client.poll(2);
        let request = tx(&mut client);
        assert_eq!(&request[20..23], &[0xc0, 0x21, 1]);
        let mut peer = vec![1, 4, 5, 120]; // MRU 1400
        peer.extend_from_slice(auth);
        peer.extend_from_slice(&[5, 6, 0x01, 0x02, 0x03, 0x04]);
        client.receive(&peer_control(LCP, 1, 12, &peer), 3);
        assert_eq!(
            &tx(&mut client)[20..],
            &peer_control(LCP, 2, 12, &peer)[20..]
        );
        let mut bad_ack = peer_control(LCP, 2, request[23], &request[26..]);
        bad_ack[29] ^= 1;
        client.receive(&bad_ack, 4);
        assert_eq!(client.state(), "negotiating");
        client.receive(&peer_control(LCP, 2, request[23], &request[26..]), 4);
        client
    }

    pub(super) fn open_ipv6(client: &mut Client, request: &[u8], now: u64) -> Ipv6Link {
        let peer = [1, 10, 0, 0, 0, 0, 0, 0, 0, 3];
        client.receive(&peer_control(IPV6CP, 1, 19, &request[26..]), now);
        assert_eq!(tx(client)[22], 3); // Conflicting interface identifiers are NAKed.
        client.receive(&peer_control(IPV6CP, 1, 20, &peer), now);
        assert_eq!(&tx(client)[20..], &peer_control(IPV6CP, 2, 20, &peer)[20..]);
        assert!(client.ipv6_link().is_none());
        let assigned = [1, 10, 0, 0, 0, 0, 0, 0, 0, 42];
        client.receive(&peer_control(IPV6CP, 3, request[23], &assigned), now);
        client.receive(&peer_control(IPV6CP, 2, request[23], &request[26..]), now);
        assert!(client.ipv6_link().is_none()); // ACK of the obsolete identifier.
        client.poll(now);
        let request = tx(client);
        assert_eq!(&request[26..], &assigned);
        client.receive(&peer_control(IPV6CP, 2, request[23], &assigned), now);
        let link = client.ipv6_link().unwrap();
        assert_eq!(link.local, v6_addr("fe80::2a"));
        assert_eq!(link.peer, v6_addr("fe80::3"));
        assert_eq!(client.ipv6_state(), "open");
        link
    }

    pub fn v6_addr(s: &str) -> [u8; 16] {
        s.parse::<core::net::Ipv6Addr>().unwrap().octets()
    }

    pub fn ipv6_only() -> (Client, Ipv6Link) {
        let mut client = lcp(discover().enable_ipv6(true), &[]);
        client.poll(4);
        tx(&mut client); // No IPv4 negotiation succeeds on this access link.
        let request = tx(&mut client);
        let link = open_ipv6(&mut client, &request, 5);
        client.receive(&peer_control(LCP, 8, 31, &IPCP.to_be_bytes()), 6);
        assert_eq!(client.lease(), None);
        assert_eq!(client.ipv6_link(), Some(link));
        (client, link)
    }
    pub fn terminate_ipv6() -> Vec<u8> { peer_control(IPV6CP, 5, 41, &[]) }
    pub fn reverse(wire: Wire) -> Wire { Wire { local: wire.peer, peer: wire.local, ..wire } }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn ipcp(client: &mut Client, now: u64) -> Lease {
        client.poll(now);
        let request = tx(client);
        assert_eq!(&request[20..23], &[0x80, 0x21, 1]);
        let peer_addr = [3, 6, GATEWAY[0], GATEWAY[1], GATEWAY[2], GATEWAY[3]];
        client.receive(&peer_control(IPCP, 1, 32, &peer_addr), now + 1);
        assert_eq!(tx(client)[22], 2);
        let assigned = [
            3, 6, ADDRESS[0], ADDRESS[1], ADDRESS[2], ADDRESS[3], 129, 6, 1, 1, 1, 1, 131, 6, 9, 9,
            9, 9,
        ];
        client.receive(&peer_control(IPCP, 3, request[23], &assigned), now + 2);
        client.poll(now + 2);
        let request = tx(client);
        assert_eq!(&request[26..], &assigned);
        assert_eq!(client.lease(), None);
        client.receive(&peer_control(IPCP, 2, request[23], &assigned), now + 3);
        let lease = client.lease().unwrap();
        assert_eq!(lease.address, ADDRESS);
        assert_eq!(lease.gateway, Some(GATEWAY));
        assert_eq!(lease.dns, [Some([1, 1, 1, 1]), Some([9, 9, 9, 9])]);
        assert_eq!(lease.wire.mtu, 1400);
        lease
    }

    #[test]
    fn pap_to_ipcp_and_remote_padt_then_redials() {
        let mut client = lcp(discover(), &[3, 4, 0xc0, 0x23]);
        assert_eq!(client.state(), "authenticating");
        client.poll(4);
        let pap = tx(&mut client);
        assert_eq!(&pap[20..23], &[0xc0, 0x23, 1]);
        assert_eq!(&pap[26..], b"\x08isp-user\x0cisp-password");
        client.receive(&peer_control(PAP, 2, pap[23].wrapping_add(1), &[0]), 5);
        assert_eq!(client.state(), "authenticating");
        client.receive(&peer_control(PAP, 2, pap[23], &[0]), 6);
        ipcp(&mut client, 6);
        client.receive(&peer_frame(DISCOVERY, PADT, SESSION_ID + 1, &[]), 10);
        assert!(client.lease().is_some());
        client.receive(&peer_frame(DISCOVERY, PADT, SESSION_ID, &[]), 11);
        assert_eq!(client.lease(), None);
        assert_eq!(client.state(), "peer-terminated");
        assert!(client.egress().is_none());
        client.poll(5011);
        let retry = tx(&mut client);
        assert_eq!(retry[15], PADI);
        assert!(tags(payload(&retry).unwrap())
            .unwrap()
            .contains(&(0x0103, &(NONCE + 1).to_be_bytes())));
    }

    #[test]
    fn chap_md5_challenge_and_failed_reauthentication_withdraw_lease() {
        let mut client = lcp(discover(), &[3, 5, 0xc2, 0x23, 5]);
        client.receive(&peer_control(CHAP, 1, 71, b"\x04\x01\x02\x03\x04ac"), 5);
        let response = tx(&mut client);
        assert_eq!(&response[20..24], &[0xc2, 0x23, 2, 71]);
        assert_eq!(
            &response[26..43],
            &[16, 250, 121, 109, 226, 208, 214, 22, 27, 189, 168, 153, 49, 104, 252, 48, 145]
        );
        assert_eq!(&response[43..], b"isp-user");
        client.receive(&peer_control(CHAP, 3, 71, b"OK"), 6);
        ipcp(&mut client, 6);
        client.receive(&peer_control(CHAP, 1, 72, b"\x01\x02ac"), 10);
        assert_eq!(tx(&mut client)[23], 72);
        client.receive(&peer_control(CHAP, 4, 72, b"FAIL"), 11);
        assert_eq!(client.state(), "authentication-failed");
        assert_eq!(client.lease(), None);
        assert_eq!(tx(&mut client)[15], PADT);
    }

    #[test]
    fn lcp_echo_loss_expires_forwarding() {
        let mut client = lcp(discover(), &[]);
        ipcp(&mut client, 4);
        let first = client.deadline();
        for interval in 0..3 {
            client.poll(first + interval * KEEPALIVE);
            let request = tx(&mut client);
            assert_eq!(&request[20..23], &[0xc0, 0x21, 9]);
            for _ in 0..3 {
                client.poll(client.deadline());
                assert_eq!(tx(&mut client), request);
            }
            assert!(client.lease().is_some());
        }
        assert_eq!(client.deadline(), first + 3 * KEEPALIVE);
        client.poll(client.deadline());
        assert_eq!(client.state(), "peer-timeout");
        assert_eq!(client.lease(), None);
        assert_eq!(tx(&mut client)[15], PADT);
    }

    #[test]
    fn matching_echo_reply_after_retry_cancels_remaining_retries() {
        let mut client = lcp(discover(), &[]);
        ipcp(&mut client, 4);
        let now = client.deadline();
        client.poll(now);
        let request = tx(&mut client);
        client.poll(client.deadline());
        assert_eq!(tx(&mut client), request);
        client.receive(&peer_control(LCP, 10, request[23], &[1, 2, 3, 4]), now + KEEPALIVE / 4 + 1);
        assert_eq!(client.deadline(), now + KEEPALIVE);
        assert!(client.lease().is_some());
    }

    #[test]
    fn only_the_current_session_can_satisfy_an_outstanding_probe() {
        let mut client = lcp(discover(), &[]);
        ipcp(&mut client, 4);
        let mut wire = client.lease().unwrap().wire;
        let start = client.deadline();
        for round in 0..5 {
            let now = start + round * KEEPALIVE;
            client.poll(now);
            assert_eq!(tx(&mut client)[22], 9);
            wire.id ^= 1;
            client.accepted_return(wire);
            assert_eq!(client.deadline(), now + KEEPALIVE / 4);
            wire.id ^= 1;
            client.accepted_return(wire);
            assert_eq!(client.deadline(), now + KEEPALIVE);
            assert_eq!(client.state(), "bound");
        }
        for _ in 0..3 {
            client.poll(client.deadline);
            assert_eq!(tx(&mut client)[22], 9);
        }
        client.poll(client.deadline);
        assert_eq!(client.state(), "peer-timeout");
    }

    fn checksum(initial: u32, bytes: &[u8]) -> u16 {
        let mut sum = initial
            + bytes
                .chunks_exact(2)
                .map(|p| u32::from(word(p)))
                .sum::<u32>();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn assert_rejects_foreign_session(
        session: Wire,
        encapsulated: &[u8],
        decapsulate: fn(Wire, &mut [u8]) -> Option<(usize, usize)>,
    ) {
        let mut accepted = encapsulated.to_vec();
        let (offset, length) = decapsulate(session, &mut accepted).expect("active session");
        let native = &accepted[offset..offset + length];
        let mut plain = native.to_vec();
        assert_eq!(decapsulate(session, &mut plain), None);
        assert_eq!(plain, native);

        // Keep the inner tuple identical while changing only PPPoE session
        // identity or the Ethernet stations that identify the session.
        for (index, field) in [(17, "session ID"), (11, "peer MAC"), (5, "local MAC")] {
            let mut frame = encapsulated.to_vec();
            frame[index] ^= 0x04;
            let original = frame.clone();
            assert_eq!(decapsulate(session, &mut frame), None, "{field}");
            assert_eq!(frame, original, "{field}");
        }
    }

    #[test]
    fn ipv6_pppoe_clamps_syn_in_both_directions_and_preserves_checksum() {
        use crate::ipv6 as ip;
        let wire = Wire {local: LOCAL, peer: PEER, id: SESSION_ID, mtu: 1492, mru: 1492};
        let reverse = Wire {local: PEER, peer: LOCAL, ..wire};
        let from = [0x20; 16];
        let to = [0x24; 16];
        for (flags, advertised, expected) in [(2, 1440, 1432), (18, 1440, 1432), (2, 1300, 1300), (16, 1440, 1440)] {
            let mut tcp = [0u8; 28];
            tcp[12..14].copy_from_slice(&[0x70, flags]);
            tcp[20..28].copy_from_slice(&[1, 2, 4, 0, 0, 1, 1, 0]);
            tcp[23..25].copy_from_slice(&u16::to_be_bytes(advertised));
            let check = ip::checksum(from, to, 6, &tcp);
            tcp[16..18].copy_from_slice(&check.to_be_bytes());
            let frame = ip::frame(LOCAL, PEER, from, to, 6, 64, &tcp);
            let mut buffer = vec![0; OVERHEAD];
            buffer.extend_from_slice(&frame);
            let (_, len) = wire.encapsulate_ipv6(&mut buffer, OVERHEAD, frame.len(), true).unwrap();
            let data = &buffer[HEADER + 2 + 40..len];
            assert_eq!(word(&data[23..25]), expected);
            assert_eq!(ip::checksum(from, to, 6, data), 0);
            // An upstream peer can advertise its own larger MSS independently.
            buffer[HEADER + 2 + 40..len].copy_from_slice(&tcp);
            let (skip, n) = reverse.decapsulate_ipv6(&mut buffer).unwrap();
            let packet = ip::Packet::parse(&buffer[skip..skip+n]).unwrap();
            assert_eq!(word(&packet.payload[23..25]), expected);
            assert!(packet.checksum_valid());
        }
    }

    #[test]
    fn encapsulation_uses_headroom_and_clamps_odd_aligned_mss() {
        let wire = Wire {
            local: LOCAL,
            peer: PEER,
            id: SESSION_ID,
            mru: MAX_MTU,
            mtu: 1400,
        };
        let mut buffer = [0; 120];
        let frame = &mut buffer[8..70];
        frame[..6].copy_from_slice(&PEER);
        frame[6..12].copy_from_slice(&LOCAL);
        frame[12..14].copy_from_slice(&[8, 0]);
        let ip = &mut frame[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&48u16.to_be_bytes());
        ip[8..10].copy_from_slice(&[64, 6]);
        ip[12..16].copy_from_slice(&ADDRESS);
        ip[16..20].copy_from_slice(&GATEWAY);
        let ip_sum = checksum(0, &ip[..20]);
        ip[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let pseudo: u32 = ip[12..20]
            .chunks_exact(2)
            .map(|p| u32::from(word(p)))
            .sum::<u32>()
            + 6
            + 28;
        let tcp = &mut ip[20..];
        tcp[..4].copy_from_slice(&[0xc0, 0, 0, 80]);
        tcp[12..14].copy_from_slice(&[0x70, 2]);
        tcp[20..28].copy_from_slice(&[1, 2, 4, 5, 180, 1, 0, 0]);
        let tcp_sum = checksum(pseudo, tcp);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());

        let mut queued = [0; 120];
        queued[..62].copy_from_slice(frame);
        assert_eq!(wire.encapsulate(&mut queued, 0, 62, false), Some((0, 70)));
        assert_eq!(wire.encapsulate(&mut buffer, 8, 62, true), Some((0, 70)));
        assert_eq!(buffer[..70], queued[..70]);
        assert_eq!(&buffer[12..22], &[0x88, 0x64, 0x11, 0, 0, 13, 0, 50, 0, 33]);
        assert_eq!(word(&buffer[65..67]), 1360);
        assert_eq!(checksum(pseudo, &buffer[42..70]), 0);

        let inbound = Wire {
            local: PEER,
            peer: LOCAL,
            ..wire
        };
        assert_rejects_foreign_session(inbound, &buffer[..70], Wire::decapsulate);
        let inspected = inbound.inspect_ipv4_return(&buffer[..80]).unwrap();
        assert_eq!(inspected.ip_length, 48);
        assert!(wire.inspect_ipv4_return(&buffer[..70]).is_none());
        assert!(inbound.inspect_ipv4_return(&buffer[..69]).is_none());
        let mut damaged = buffer;
        damaged[69] ^= 1;
        assert!(inbound.inspect_ipv4_return(&damaged[..70]).is_none());
        let skip = inbound.write_ipv4_return_header(&mut damaged);
        assert_eq!(&damaged[skip..skip + 14], &[PEER.as_slice(), LOCAL.as_slice(), &[8, 0]].concat());

        assert_eq!(wire.decapsulate(&mut buffer[..70]), None);
        assert_eq!(inbound.decapsulate(&mut buffer[..69]), None);
        assert_eq!(inbound.decapsulate(&mut buffer[..80]), Some((8, 62)));
        assert!(crate::ipv4::Packet::parse(&mut buffer[8..70], PEER).is_ok());
    }

    #[test]
    fn ipv6_return_requires_the_negotiated_pppoe_envelope() {
        let wire = Wire { local: LOCAL, peer: PEER, id: SESSION_ID, mru: MAX_MTU, mtu: MAX_MTU };
        let packet = crate::ipv6::udp(
            PEER, LOCAL, v6_addr("2001:db8:1::2"), v6_addr("2001:db8:2::2"),
            (443, 40000), b"return",
        );
        let mut payload = IPV6.to_be_bytes().to_vec();
        payload.extend_from_slice(&packet[14..]);
        let frame = peer_frame(SESSION, 0, SESSION_ID, &payload);
        assert_rejects_foreign_session(wire, &frame, Wire::decapsulate_ipv6);
    }

    #[test]
    fn ipv6cp_close_and_peer_rejection_preserve_ipcp() {
        let mut client = lcp(discover().enable_ipv6(true), &[]);
        client.poll(4);
        let v4 = tx(&mut client);
        let v6 = tx(&mut client);
        assert_eq!(&v4[20..23], &[0x80, 0x21, 1]);
        assert_eq!(&v6[20..23], &[0x80, 0x57, 1]);
        let peer = [3, 6, 203, 0, 113, 1];
        client.receive(&peer_control(IPCP, 1, 6, &peer), 5);
        tx(&mut client);
        let assigned = [
            3, 6, 198, 51, 100, 1, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0,
        ];
        client.receive(&peer_control(IPCP, 3, v4[23], &assigned), 6);
        client.poll(6);
        let request = tx(&mut client);
        client.receive(&peer_control(IPCP, 2, request[23], &assigned), 7);
        let lease = client.lease().unwrap();

        open_ipv6(&mut client, &v6, 8);
        client.receive(&peer_control(IPV6CP, 5, 30, &[]), 9);
        assert_eq!(&tx(&mut client)[20..24], &[0x80, 0x57, 6, 30]);
        assert_eq!(client.ipv6_state(), "closed");
        assert_eq!(client.lease(), Some(lease));
        client.receive(&peer_control(LCP, 8, 31, &IPV6CP.to_be_bytes()), 10);
        assert_eq!(client.lease(), Some(lease));
    }

}
