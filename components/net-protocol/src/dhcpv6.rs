//! Bounded DHCPv6 prefix-delegation client (Rapid Commit or four-message exchange,
//! Renew/Rebind). No IA_NA is needed to route a delegated prefix over link-local.
use super::ipv6::{self, Address};
use alloc::vec::Vec;
pub const SERVERS: Address = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];
const IAID: u32 = 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub prefix: Address,
    pub length: u8,
    pub preferred_until: u64,
    pub valid_until: u64,
    pub renew_at: u64,
    pub rebind_at: u64,
    pub dns: Option<Address>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Solicit,
    Request,
    Bound,
    Renew,
    Rebind,
}
pub struct Client {
    duid: [u8; 10],
    transaction: u32,
    server: Vec<u8>,
    offer: Option<(Address, u8)>,
    lease: Option<Lease>,
    state: State,
    next: u64,
    started: u64,
    interval: u64,
    attempts: u8,
}
fn options(mut bytes: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let n = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        out.push((code, bytes.get(4..4 + n)?));
        bytes = &bytes[4 + n..];
    }
    Some(out)
}
fn one<'a>(options: &[(u16, &'a [u8])], code: u16) -> Option<&'a [u8]> {
    let mut items = options.iter().filter(|o| o.0 == code);
    let value = items.next()?.1;
    if items.next().is_some() {
        None
    } else {
        Some(value)
    }
}
fn success(opts: &[(u16, &[u8])]) -> bool {
    opts.iter()
        .filter(|o| o.0 == 13)
        .all(|o| o.1.len() >= 2 && o.1[..2] == [0, 0])
}
fn put(out: &mut Vec<u8>, code: u16, data: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}
fn word(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn deadline(now: u64, seconds: u32) -> u64 {
    now.saturating_add(u64::from(seconds) * 1000)
}
impl Client {
    pub fn new(mac: [u8; 6], seed: u32, now: u64) -> Self {
        let mut duid = [0; 10];
        duid[..4].copy_from_slice(&[0, 3, 0, 1]);
        duid[4..].copy_from_slice(&mac);
        Self {
            duid,
            transaction: seed & 0xffffff,
            server: Vec::new(),
            offer: None,
            lease: None,
            state: State::Solicit,
            next: now + u64::from(seed % 1000),
            started: now,
            interval: 1000,
            attempts: 0,
        }
    }
    pub fn lease(&self) -> Option<Lease> {
        self.lease
    }
    pub fn state(&self) -> State {
        self.state
    }
    fn transition(&mut self, state: State, now: u64) {
        self.state = state;
        self.transaction = self.transaction.wrapping_add(1) & 0xffffff;
        self.next = now;
        self.started = now;
        self.interval = 1000;
        self.attempts = 0;
    }
    /// Advance lifetimes before accepting/advertising any authority.
    pub fn tick(&mut self, now: u64) {
        if let Some(lease) = self.lease {
            if now >= lease.valid_until {
                self.lease = None;
                self.server.clear();
                self.offer = None;
                self.transition(State::Solicit, now);
            } else if now >= lease.rebind_at && self.state != State::Rebind {
                self.transition(State::Rebind, now);
            } else if now >= lease.renew_at && self.state == State::Bound {
                self.transition(State::Renew, now);
            }
        }
        if self.state == State::Request && self.attempts >= 10 && now >= self.next {
            self.server.clear();
            self.offer = None;
            self.transition(State::Solicit, now);
        }
    }
    pub fn transmit(&mut self, now: u64) -> Option<Vec<u8>> {
        self.tick(now);
        if self.state == State::Bound || now < self.next {
            return None;
        }
        let kind = match self.state {
            State::Solicit => 1,
            State::Request => 3,
            State::Renew => 5,
            State::Rebind => 6,
            State::Bound => return None,
        };
        let mut out = alloc::vec![
            kind,
            (self.transaction >> 16) as u8,
            (self.transaction >> 8) as u8,
            self.transaction as u8
        ];
        put(&mut out, 1, &self.duid);
        if self.state == State::Solicit {
            put(&mut out, 14, &[]); // Rapid Commit; Advertise remains a supported fallback.
        }
        if matches!(self.state, State::Request | State::Renew) {
            put(&mut out, 2, &self.server);
        }
        put(
            &mut out,
            8,
            &((now.saturating_sub(self.started) / 10).min(65535) as u16).to_be_bytes(),
        );
        put(&mut out, 6, &[0, 23]);
        let mut ia = alloc::vec![0;12];
        ia[..4].copy_from_slice(&IAID.to_be_bytes());
        let (prefix, length) = self
            .lease
            .map(|l| (l.prefix, l.length))
            .or(self.offer)
            .unwrap_or(([0; 16], 56));
        let mut hint = [0; 25];
        hint[8] = length;
        hint[9..].copy_from_slice(&prefix);
        put(&mut ia, 26, &hint);
        put(&mut out, 25, &ia);
        self.attempts = self.attempts.saturating_add(1);
        // Deterministic per-client +/-10% jitter, independently seeded per exchange.
        let jitter = u64::from(
            self.transaction
                .wrapping_mul(1103515245)
                .wrapping_add(u32::from(self.attempts) * 12345)
                % 201,
        );
        self.next = now.saturating_add(self.interval * (900 + jitter) / 1000);
        self.interval = (self.interval * 2).min(120_000);
        Some(out)
    }
    pub fn receive(&mut self, bytes: &[u8], now: u64) -> bool {
        self.tick(now);
        if bytes.len() < 4
            || bytes.len() > 1400
            || bytes[1..4] != self.transaction.to_be_bytes()[1..]
        {
            return false;
        }
        let expected = if self.state == State::Solicit { 2 } else { 7 };
        let rapid_commit = self.state == State::Solicit && bytes[0] == 7;
        if self.state == State::Bound || bytes[0] != expected && !rapid_commit {
            return false;
        }
        let Some(opts) = options(&bytes[4..]) else {
            return false;
        };
        // A direct Reply is authoritative only when the server explicitly
        // commits the lease in response to our Rapid Commit Solicit.
        if rapid_commit && one(&opts, 14) != Some(&[][..]) {
            return false;
        }
        if one(&opts, 1) != Some(&self.duid[..]) || !success(&opts) {
            return false;
        }
        let Some(server) = one(&opts, 2).filter(|s| s.len() >= 2 && s.len() <= 128) else {
            return false;
        };
        if matches!(self.state, State::Request | State::Renew) && server != self.server {
            return false;
        }
        let Some(ia) = one(&opts, 25).filter(|ia| ia.len() >= 12 && word(ia, 0) == IAID) else {
            return false;
        };
        let Some(sub) = options(&ia[12..]) else {
            return false;
        };
        if !success(&sub) {
            return false;
        }
        let Some(p) = one(&sub, 26).filter(|p| p.len() >= 25) else {
            return false;
        };
        let Some(prefix_options) = options(&p[25..]) else {
            return false;
        };
        if !success(&prefix_options) {
            return false;
        }
        let prefix: Address = p[9..25].try_into().unwrap();
        let length = p[8];
        let preferred = word(p, 0);
        let valid = word(p, 4);
        if !(1..=64).contains(&length)
            || !ipv6::global(prefix)
            || ipv6::network(prefix, length) != Some(prefix)
            || preferred > valid
        {
            return false;
        }
        let (mut t1, mut t2) = (word(ia, 4), word(ia, 8));
        if t1 != 0 && t2 != 0 && t1 > t2 {
            return false;
        }
        if valid == 0 {
            if bytes[0] != 7
                || self
                    .lease
                    .is_none_or(|l| l.prefix != prefix || l.length != length)
            {
                return false;
            }
            self.lease = None;
            self.offer = None;
            self.server.clear();
            self.transition(State::Solicit, now);
            return true;
        }
        if valid < 3 {
            return false;
        }
        if t1 == 0 {
            t1 = (valid / 2).max(1)
        }
        if t2 == 0 {
            t2 = (valid / 5 * 4).max(t1 + 1)
        }
        if t1 >= t2 || t2 >= valid {
            return false;
        }
        if bytes[0] == 2 {
            self.server = server.to_vec();
            self.offer = Some((prefix, length));
            self.transition(State::Request, now);
            return true;
        }
        let dns = one(&opts, 23)
            .filter(|d| !d.is_empty() && d.len() % 16 == 0)
            .and_then(|d| {
                d.chunks_exact(16)
                    .map(|a| Address::try_from(a).unwrap())
                    .find(|a| ipv6::global(*a))
            });
        self.lease = Some(Lease {
            prefix,
            length,
            preferred_until: deadline(now, preferred),
            valid_until: deadline(now, valid),
            renew_at: deadline(now, t1),
            rebind_at: deadline(now, t2),
            dns,
        });
        self.server = server.to_vec();
        self.offer = None;
        self.state = State::Bound;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn response(c: &Client, kind: u8, valid: u32) -> Vec<u8> {
        let mut b = alloc::vec![
            kind,
            (c.transaction >> 16) as u8,
            (c.transaction >> 8) as u8,
            c.transaction as u8
        ];
        put(&mut b, 1, &c.duid);
        put(&mut b, 2, b"server");
        let mut ia = alloc::vec![0;12];
        ia[..4].copy_from_slice(&IAID.to_be_bytes());
        let mut p = [0; 25];
        p[..4].copy_from_slice(&(valid / 2).to_be_bytes());
        p[4..8].copy_from_slice(&valid.to_be_bytes());
        p[8] = 56;
        p[9] = 0x20;
        p[10] = 1;
        p[11] = 0x0d;
        p[12] = 0xb8;
        put(&mut ia, 26, &p);
        put(&mut b, 25, &ia);
        b
    }
    #[test]
    fn rapid_commit_requires_explicit_unique_empty_option() {
        let mut c = Client::new([2; 6], 7, 0);
        let query = c.transmit(1000).unwrap();
        assert_eq!(one(&options(&query[4..]).unwrap(), 14), Some(&[][..]));
        let plain = response(&c, 7, 100);
        assert!(!c.receive(&plain, 1000));
        let mut malformed = plain.clone();
        put(&mut malformed, 14, &[0]);
        assert!(!c.receive(&malformed, 1000));
        let mut committed = plain.clone();
        put(&mut committed, 14, &[]);
        let mut duplicate = committed.clone();
        put(&mut duplicate, 14, &[]);
        assert!(!c.receive(&duplicate, 1000));
        assert!(c.receive(&committed, 1000));
        assert_eq!(c.state(), State::Bound);
        assert!(c.lease().is_some());
        let renew = c.transmit(51_000).unwrap();
        assert_eq!(renew[0], 5);
        assert_eq!(one(&options(&renew[4..]).unwrap(), 14), None);
    }
    #[test]
    fn acquisition_renew_rebind_expiry() {
        let mut c = Client::new([2; 6], 7, 0);
        assert_eq!(c.transmit(1000).unwrap()[0], 1);
        assert!(c.receive(&response(&c, 2, 100), 1000));
        assert_eq!(c.transmit(1000).unwrap()[0], 3);
        assert!(c.receive(&response(&c, 7, 100), 1000));
        assert_eq!(c.state(), State::Bound);
        assert_eq!(c.transmit(51_000).unwrap()[0], 5);
        assert_eq!(c.transmit(81_000).unwrap()[0], 6);
        c.tick(101_000);
        assert!(c.lease().is_none());
        assert_eq!(c.state(), State::Solicit);
    }
    #[test]
    fn rejects_wrong_transaction_and_truncations() {
        let mut c = Client::new([2; 6], 7, 0);
        let good = response(&c, 2, 100);
        for n in 0..good.len() {
            assert!(!c.receive(&good[..n], 0));
        }
        let mut bad = good.clone();
        bad[3] ^= 1;
        assert!(!c.receive(&bad, 0));
        assert!(c.receive(&good, 0));
        assert!(!c.receive(&response(&c, 7, 1), 0));
        assert!(c.lease().is_none());
    }
    #[test]
    fn revoke_and_server_identity() {
        let mut c = Client::new([2; 6], 7, 0);
        c.receive(&response(&c, 2, 100), 0);
        let mut bad = response(&c, 7, 100);
        let at = bad.windows(6).position(|b| b == b"server").unwrap();
        bad[at] ^= 1;
        assert!(!c.receive(&bad, 0));
        assert!(c.receive(&response(&c, 7, 100), 0));
        c.tick(50_000);
        assert!(c.receive(&response(&c, 7, 0), 50_000));
        assert!(c.lease().is_none());
    }
}
