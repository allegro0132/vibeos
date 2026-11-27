//! Stateless-looking DNS forwarding built on the router's own NAT.
//!
//! LAN clients are told to use the router as their resolver. A UDP query to
//! the router's LAN address port 53 is re-addressed to the upstream resolver
//! *before* NAT, so it travels as an ordinary client flow. The matching reply
//! is re-sourced from the router's LAN address *after* NAT restored the client
//! tuple. Only the two addresses and the affected checksums change; payloads
//! are never parsed, cached or generated here.
//!
//! The table only remembers which client sockets were redirected and where,
//! so replies from a resolver the client addressed directly stay untouched.
//! It is bounded; when full, the oldest redirect is replaced.

const TTL_MS: u64 = 30_000;

#[derive(Clone, Copy)]
struct Entry {
    client: [u8; 4],
    port: u16,
    upstream: [u8; 4],
    until: u64,
}
pub struct Relay<const N: usize> {
    entries: [Option<Entry>; N],
    pub queries: u64,
    pub replies: u64,
}

/// UDP header offset when `frame` is an unfragmented IPv4/UDP Ethernet frame.
fn udp_offset(frame: &[u8]) -> Option<usize> {
    if frame.len() < 42 || frame[12..14] != [8, 0] || frame[14] >> 4 != 4 || frame[23] != 17 {
        return None;
    }
    let ihl = usize::from(frame[14] & 15) * 4;
    if ihl < 20 || frame.len() < 14 + ihl + 8 || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0 {
        return None;
    }
    Some(14 + ihl)
}
/// RFC 1624 incremental update of a ones-complement checksum field.
fn adjust(field: &mut [u8], old: [u8; 4], new: [u8; 4]) {
    let mut sum = u32::from(!u16::from_be_bytes([field[0], field[1]]));
    for pair in old.chunks(2) {
        sum += u32::from(!u16::from_be_bytes([pair[0], pair[1]]));
    }
    for pair in new.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    field.copy_from_slice(&(!(sum as u16)).to_be_bytes());
}
fn readdress(frame: &mut [u8], udp: usize, address: usize, new: [u8; 4]) {
    let old: [u8; 4] = frame[address..address + 4].try_into().unwrap();
    frame[address..address + 4].copy_from_slice(&new);
    adjust(&mut frame[24..26], old, new);
    // A zero UDP checksum means "not computed" and must stay zero.
    if frame[udp + 6..udp + 8] != [0, 0] {
        adjust(&mut frame[udp + 6..udp + 8], old, new);
        if frame[udp + 6..udp + 8] == [0, 0] {
            frame[udp + 6..udp + 8].copy_from_slice(&[0xff, 0xff]);
        }
    }
}

impl<const N: usize> Relay<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N], queries: 0, replies: 0 }
    }
    pub fn clear(&mut self) {
        self.entries = [None; N];
    }
    /// True for UDP traffic of a resolver port in either direction. Such flows
    /// may be redirected here and must stay on the software path.
    pub fn is_dns(frame: &[u8]) -> bool {
        udp_offset(frame).is_some_and(|udp| frame[udp..udp + 2] == [0, 53] || frame[udp + 2..udp + 4] == [0, 53])
    }
    /// LAN ingress, before NAT. Redirects a query addressed to `router` and
    /// returns true; the frame then continues through normal routing.
    pub fn outbound(&mut self, frame: &mut [u8], router: [u8; 4], upstream: [u8; 4], now: u64) -> bool {
        let Some(udp) = udp_offset(frame) else { return false };
        if frame[30..34] != router || frame[udp + 2..udp + 4] != [0, 53] {
            return false;
        }
        let client: [u8; 4] = frame[26..30].try_into().unwrap();
        let port = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
        let entry = Entry { client, port, upstream, until: now.saturating_add(TTL_MS) };
        let slot = self
            .entries
            .iter()
            .position(|e| e.is_some_and(|e| e.client == client && e.port == port))
            .or_else(|| self.entries.iter().position(|e| e.is_none_or(|e| e.until <= now)))
            .or_else(|| (0..N).min_by_key(|i| self.entries[*i].unwrap().until));
        let Some(slot) = slot else { return false };
        self.entries[slot] = Some(entry);
        readdress(frame, udp, 30, upstream);
        self.queries += 1;
        true
    }
    /// LAN egress, after NAT restored the client destination. Re-sources a
    /// reply to a redirected query from `router`; other frames are untouched.
    pub fn inbound(&mut self, frame: &mut [u8], router: [u8; 4], now: u64) -> bool {
        let Some(udp) = udp_offset(frame) else { return false };
        if frame[udp..udp + 2] != [0, 53] {
            return false;
        }
        let client: [u8; 4] = frame[30..34].try_into().unwrap();
        let port = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
        let source: [u8; 4] = frame[26..30].try_into().unwrap();
        if !self.entries.iter().flatten().any(|e| {
            e.client == client && e.port == port && e.upstream == source && e.until > now
        }) {
            return false;
        }
        readdress(frame, udp, 26, router);
        self.replies += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    const ROUTER: [u8; 4] = [192, 168, 10, 1];
    const CLIENT: [u8; 4] = [192, 168, 10, 100];
    const UPSTREAM: [u8; 4] = [203, 0, 113, 53];
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
    fn udp(source: [u8; 4], destination: [u8; 4], sport: u16, dport: u16, payload: &[u8], summed: bool) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12..14].copy_from_slice(&[8, 0]);
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        f[22] = 64;
        f[23] = 17;
        f[26..30].copy_from_slice(&source);
        f[30..34].copy_from_slice(&destination);
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(payload);
        let ip = checksum(&[&f[14..34]]);
        f[24..26].copy_from_slice(&ip.to_be_bytes());
        if summed {
            let length = [f[38], f[39]];
            let sum = checksum(&[&f[26..34], &[0, 17], &length, &f[34..]]);
            f[40..42].copy_from_slice(&sum.to_be_bytes());
        }
        f
    }
    fn valid(f: &[u8]) -> bool {
        let length = [f[38], f[39]];
        checksum(&[&f[14..34]]) == 0
            && (f[40..42] == [0, 0] || checksum(&[&f[26..34], &[0, 17], &length, &f[34..]]) == 0)
    }

    #[test]
    fn query_and_reply_are_readdressed_with_valid_checksums() {
        for summed in [true, false] {
            let mut relay = Relay::<4>::new();
            let mut query = udp(CLIENT, ROUTER, 40000, 53, b"query-bytes", summed);
            assert!(Relay::<4>::is_dns(&query));
            assert!(relay.outbound(&mut query, ROUTER, UPSTREAM, 0));
            assert_eq!((&query[26..30], &query[30..34]), (&CLIENT[..], &UPSTREAM[..]));
            assert_eq!(&query[42..], b"query-bytes");
            assert!(valid(&query));
            assert_eq!(query[40..42] == [0, 0], !summed);
            let mut reply = udp(UPSTREAM, CLIENT, 53, 40000, b"an-odd-reply!", summed);
            assert!(relay.inbound(&mut reply, ROUTER, 10));
            assert_eq!((&reply[26..30], &reply[30..34]), (&ROUTER[..], &CLIENT[..]));
            assert!(valid(&reply));
            assert_eq!((relay.queries, relay.replies), (1, 1));
        }
    }

    #[test]
    fn only_redirected_sockets_and_their_upstream_are_resourced() {
        let mut relay = Relay::<4>::new();
        // A client using a public resolver directly is not a relay flow.
        let mut direct = udp(CLIENT, [9, 9, 9, 9], 40001, 53, b"q", true);
        let before = direct.clone();
        assert!(!relay.outbound(&mut direct, ROUTER, UPSTREAM, 0));
        assert_eq!(direct, before);
        let mut reply = udp([9, 9, 9, 9], CLIENT, 53, 40001, b"r", true);
        assert!(!relay.inbound(&mut reply, ROUTER, 1));
        let mut query = udp(CLIENT, ROUTER, 40000, 53, b"q", true);
        assert!(relay.outbound(&mut query, ROUTER, UPSTREAM, 0));
        for (source, port, now) in [([9, 9, 9, 9], 40000, 1), (UPSTREAM, 40002, 1), (UPSTREAM, 40000, 30_000)] {
            let mut other = udp(source, CLIENT, 53, port, b"r", true);
            let before = other.clone();
            assert!(!relay.inbound(&mut other, ROUTER, now), "{source:?} {port} {now}");
            assert_eq!(other, before);
        }
        // Other protocols, ports, fragments and short frames pass untouched.
        let mut tcp = udp(CLIENT, ROUTER, 40000, 53, b"q", true);
        tcp[23] = 6;
        let mut fragment = udp(CLIENT, ROUTER, 40000, 53, b"q", true);
        fragment[20] = 0x20;
        let mut web = udp(CLIENT, ROUTER, 40000, 80, b"q", true);
        for frame in [&mut tcp, &mut fragment, &mut web, &mut vec![0u8; 20]] {
            assert!(!relay.outbound(frame, ROUTER, UPSTREAM, 0));
            assert!(!Relay::<4>::is_dns(frame));
        }
    }

    #[test]
    fn table_is_bounded_and_replaces_the_oldest_redirect() {
        let mut relay = Relay::<2>::new();
        for (i, port) in [40000u16, 40001, 40002].into_iter().enumerate() {
            let mut query = udp(CLIENT, ROUTER, port, 53, b"q", true);
            assert!(relay.outbound(&mut query, ROUTER, UPSTREAM, i as u64));
        }
        let mut answer = |port| relay.inbound(&mut udp(UPSTREAM, CLIENT, 53, port, b"r", true), ROUTER, 5);
        assert_eq!([answer(40000), answer(40001), answer(40002)], [false, true, true]);
        // A retransmission refreshes its own slot rather than taking another.
        let mut again = udp(CLIENT, ROUTER, 40001, 53, b"q", true);
        assert!(relay.outbound(&mut again, ROUTER, [1, 1, 1, 1], 6));
        assert!(relay.inbound(&mut udp([1, 1, 1, 1], CLIENT, 53, 40001, b"r", true), ROUTER, 7));
        assert!(relay.inbound(&mut udp(UPSTREAM, CLIENT, 53, 40002, b"r", true), ROUTER, 7));
        relay.clear();
        assert!(!relay.inbound(&mut udp(UPSTREAM, CLIENT, 53, 40002, b"r", true), ROUTER, 7));
    }
}
