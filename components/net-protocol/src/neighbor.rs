//! Per-interface IPv4 next-hop and bounded ARP resolution.
//!
//! No packet buffers are retained here. A caller may queue a bounded copy on a
//! miss, then release the DMA RX descriptor so the ARP reply can be received.
//! ARP is not authenticated; strict validation limits accidental/unsolicited
//! updates, not a malicious peer able to spoof a solicited response.

const PROBES: usize = 8;
const RETRY_MS: u64 = 1000;
const PACE_MS: u64 = 100;
const PENDING_MS: u64 = 5000;
const COOLDOWN_MS: u64 = 10_000;
const REACHABLE_MS: u64 = 30_000;
const REFRESH_MS: u64 = 5000;
const ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    Address,
    Local,
    NoRoute,
    Capacity,
    Clock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Reachable([u8; 6]),
    Pending,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interface {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gateway: Option<[u8; 4]>,
}
fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
fn unicast_ip(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}
impl Interface {
    fn mask(self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }
    fn same_subnet(self, ip: [u8; 4]) -> bool {
        u32::from_be_bytes(ip) & self.mask() == u32::from_be_bytes(self.ip) & self.mask()
    }
    fn host(self, ip: [u8; 4]) -> bool {
        let host = u32::from_be_bytes(ip) & !self.mask();
        unicast_ip(ip) && self.same_subnet(ip) && host != 0 && host != !self.mask()
    }
    fn valid(self) -> bool {
        (1..=30).contains(&self.prefix)
            && unicast_mac(self.mac)
            && self.host(self.ip)
            && self.gateway.is_none_or(|g| self.host(g) && g != self.ip)
    }
    /// Static connected route, then optional default gateway. Broadcast and
    /// local destinations never become neighbor-resolution requests.
    pub fn next_hop(self, destination: [u8; 4]) -> Result<[u8; 4], Error> {
        if !self.valid() {
            return Err(Error::Configuration);
        }
        if !unicast_ip(destination) {
            return Err(Error::Address);
        }
        if destination == self.ip {
            return Err(Error::Local);
        }
        if self.same_subnet(destination) {
            return if self.host(destination) {
                Ok(destination)
            } else {
                Err(Error::Address)
            };
        }
        self.gateway.ok_or(Error::NoRoute)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refresh {
    attempts: u8,
    next_at: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Pending {
        attempts: u8,
        next_at: u64,
        deadline: u64,
        reusable: u64,
    },
    Reachable {
        mac: [u8; 6],
        until: u64,
        refresh: Option<Refresh>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    ip: [u8; 4],
    state: State,
}
impl Entry {
    fn probe_schedule(self) -> Option<(u8, u64, u64)> {
        match self.state {
            State::Pending {
                attempts,
                next_at,
                deadline,
                ..
            } => Some((attempts, next_at, deadline)),
            State::Reachable {
                until,
                refresh: Some(r),
                ..
            } => Some((r.attempts, r.next_at, until)),
            State::Reachable { refresh: None, .. } => None,
        }
    }
    fn reusable(self, now: u64) -> bool {
        match self.state {
            State::Pending { reusable, .. } => now >= reusable,
            State::Reachable { until, .. } => now >= until,
        }
    }
}

/// The hardware ingress selects the table, never an address in a received frame.
/// Resolve/lookup takes at most eight probes. Polling control work may scan N.
pub struct Table<const N: usize> {
    interface: Interface,
    entries: [Option<Entry>; N],
    last_now: u64,
    next_send: u64,
    cursor: usize,
}
impl<const N: usize> Table<N> {
    pub fn new(interface: Interface) -> Result<Self, Error> {
        if N == 0 || !interface.valid() {
            return Err(Error::Configuration);
        }
        Ok(Self {
            interface,
            entries: [None; N],
            last_now: 0,
            next_send: 0,
            cursor: 0,
        })
    }
    pub fn reconfigure(&mut self, interface: Interface) -> Result<(), Error> {
        if !interface.valid() {
            return Err(Error::Configuration);
        }
        self.interface = interface;
        self.entries.fill(None);
        // Preserve pacing and monotonic-time guards across reconfiguration.
        Ok(())
    }
    fn locate(&self, ip: [u8; 4], now: u64) -> Result<(usize, bool), Error> {
        let hash = (u32::from_be_bytes(ip).wrapping_mul(0x9e3779b9)).rotate_left(13);
        let start = hash as usize % N;
        let mut free = None;
        for probe in 0..PROBES.min(N) {
            let i = (start + probe) % N;
            if let Some(e) = self.entries[i] {
                if e.ip == ip {
                    return Ok((i, true));
                }
                if e.reusable(now) && free.is_none() {
                    free = Some(i);
                }
            } else if free.is_none() {
                free = Some(i);
            }
        }
        free.map(|i| (i, false)).ok_or(Error::Capacity)
    }
    fn clock(&self, now: u64) -> Result<(), Error> {
        if now < self.last_now || now.checked_add(REACHABLE_MS).is_none() {
            Err(Error::Clock)
        } else {
            Ok(())
        }
    }
    /// `ip` must be an on-link next hop, not the off-link final destination.
    /// A miss schedules resolution; repeated misses do not restart its budget.
    pub fn resolve(&mut self, ip: [u8; 4], now: u64) -> Result<Resolution, Error> {
        self.clock(now)?;
        if ip == self.interface.ip || !self.interface.host(ip) {
            return Err(Error::Address);
        }
        let (i, found) = self.locate(ip, now)?;
        if found {
            if let State::Reachable { until, refresh, .. } =
                &mut self.entries[i].as_mut().unwrap().state
            {
                // Traffic requests a refresh while the old binding is still
                // valid. Neither lookup nor failed probes extend its lifetime.
                if now < *until && now >= until.saturating_sub(REFRESH_MS) && refresh.is_none() {
                    *refresh = Some(Refresh {
                        attempts: 0,
                        next_at: now,
                    });
                }
            }
        }
        let result = if found && !self.entries[i].unwrap().reusable(now) {
            match self.entries[i].unwrap().state {
                State::Reachable { mac, .. } => Resolution::Reachable(mac),
                State::Pending { deadline, .. } => {
                    if now < deadline {
                        Resolution::Pending
                    } else {
                        Resolution::Failed
                    }
                }
            }
        } else {
            self.entries[i] = Some(Entry {
                ip,
                state: State::Pending {
                    attempts: 0,
                    next_at: now,
                    deadline: now + PENDING_MS,
                    reusable: now + PENDING_MS + COOLDOWN_MS,
                },
            });
            Resolution::Pending
        };
        self.last_now = now;
        Ok(result)
    }
    /// Start refreshing a reachable binding ahead of the traffic-driven window.
    /// For an owner whose packets no longer pass `resolve` (hardware
    /// forwarding) and who must keep the binding valid beyond its own margin.
    /// Only schedules probes: unknown, pending and already refreshing entries
    /// are left alone, and nothing but a received reply extends a lifetime.
    pub fn request_refresh(&mut self, ip: [u8; 4], now: u64) -> Result<bool, Error> {
        self.clock(now)?;
        if ip == self.interface.ip || !self.interface.host(ip) {
            return Err(Error::Address);
        }
        let (slot, found) = self.locate(ip, now)?;
        if found {
            if let State::Reachable { until, refresh, .. } = &mut self.entries[slot].as_mut().unwrap().state {
                if now < *until && refresh.is_none() {
                    *refresh = Some(Refresh { attempts: 0, next_at: now });
                    self.last_now = now;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Read-only, bounded next-hop authority for offload publication. Does not
    /// schedule probes or extend reachability. Caller must withdraw hardware
    /// before the returned absolute deadline or any neighbor/config change.
    pub fn reachable_until(&self, ip: [u8; 4], now: u64) -> Result<Option<([u8; 6], u64)>, Error> {
        self.clock(now)?;
        if ip == self.interface.ip || !self.interface.host(ip) {
            return Err(Error::Address);
        }
        let (slot, found) = self.locate(ip, now)?;
        if found {
            if let State::Reachable { mac, until, .. } = self.entries[slot].unwrap().state {
                if now < until {
                    return Ok(Some((mac, until)));
                }
            }
        }
        Ok(None)
    }
    /// Answer only an already-reachable peer's unchanged local ARP query.
    /// Does not learn, refresh, advance time or alter any offload authority.
    /// A miss leaves the frame unchanged for the owner's normal control path.
    pub fn reply_known_request(&self, frame: &mut [u8], now: u64) -> Option<usize> {
        if frame.len() < 42
            || (frame[32..38] != [0; 6] && frame[32..38] != self.interface.mac) {
            return None;
        }
        let ip = frame[28..32].try_into().ok()?;
        let (mac, _) = self.reachable_until(ip, now).ok()??;
        if frame[22..28] != mac { return None; }
        crate::arp::reply_in_place(frame, self.interface.mac, self.interface.ip)
    }

    /// Absolute monotonic deadline for control work. The caller also tracks its
    /// own pending-packet expiry and TX-completion wakeups under backpressure.
    pub fn next_deadline(&self, now: u64) -> Result<Option<u64>, Error> {
        self.clock(now)?;
        let mut earliest = None;
        for e in self.entries.iter().flatten() {
            if let Some((attempts, next_at, deadline)) = e.probe_schedule() {
                if now >= deadline {
                    continue;
                }
                let due = if attempts < ATTEMPTS {
                    next_at.max(self.next_send).min(deadline)
                } else {
                    deadline
                };
                earliest = Some(earliest.map_or(due.max(now), |old: u64| old.min(due.max(now))));
            }
        }
        Ok(earliest)
    }
    /// Produces one request without consuming its retry/pacing budget. Drop on
    /// DMA Busy; call `sent` only after successful TX. The exclusive borrow
    /// prevents stale acknowledgements or reconfiguration while a probe exists.
    pub fn probe(&mut self, now: u64) -> Result<Option<Probe<'_, N>>, Error> {
        self.clock(now)?;
        if now < self.next_send {
            return Ok(None);
        }
        for offset in 0..N {
            let i = (self.cursor + offset) % N;
            if let Some((attempts, next_at, deadline)) =
                self.entries[i].and_then(Entry::probe_schedule)
            {
                if attempts < ATTEMPTS && now >= next_at && now < deadline {
                    return Ok(Some(Probe {
                        table: self,
                        slot: i,
                        now,
                    }));
                }
            }
        }
        Ok(None)
    }
    /// Learn only an already-requested neighbor from a valid targeted ARP.
    /// Replies require at least one actually transmitted request. Requests for
    /// our IP can resolve an existing pending entry. Existing MACs may refresh,
    /// but a different MAC waits for expiry/re-resolution. Gratuitous or unknown
    /// senders never allocate entries. Returns true only for an accepted update.
    pub fn observe(&mut self, frame: &[u8], now: u64) -> Result<bool, Error> {
        self.clock(now)?;
        if frame.len() < 42 || frame[12..20] != [8, 6, 0, 1, 8, 0, 6, 4] || frame[20] != 0 {
            return Ok(false);
        }
        let op = frame[21];
        let mac: [u8; 6] = frame[22..28].try_into().unwrap();
        let ip: [u8; 4] = frame[28..32].try_into().unwrap();
        if !unicast_mac(mac)
            || mac == self.interface.mac
            || frame[6..12] != mac
            || !self.interface.host(ip)
            || ip == self.interface.ip
            || frame[38..42] != self.interface.ip
        {
            return Ok(false);
        }
        match op {
            1 if (frame[..6] == self.interface.mac || frame[..6] == [0xff; 6])
                && (frame[32..38] == self.interface.mac || frame[32..38] == [0; 6]) => {}
            2 if frame[..6] == self.interface.mac && frame[32..38] == self.interface.mac => {}
            _ => return Ok(false),
        }
        let (i, found) = match self.locate(ip, now) {
            Ok(v) => v,
            Err(_) => return Ok(false),
        };
        if !found {
            return Ok(false);
        }
        let permitted = match self.entries[i].unwrap().state {
            State::Pending {
                attempts, deadline, ..
            } => now < deadline && (op == 1 || attempts != 0),
            State::Reachable {
                mac: old,
                until,
                refresh,
            } => now < until && mac == old && (op == 1 || refresh.is_some_and(|r| r.attempts != 0)),
        };
        if !permitted {
            return Ok(false);
        }
        self.entries[i] = Some(Entry {
            ip,
            state: State::Reachable {
                mac,
                until: now + REACHABLE_MS,
                refresh: None,
            },
        });
        self.last_now = now;
        Ok(true)
    }
}

pub struct Probe<'a, const N: usize> {
    table: &'a mut Table<N>,
    slot: usize,
    now: u64,
}
impl<const N: usize> Probe<'_, N> {
    /// Unpadded Ethernet/ARP request. The driver must zero Ethernet padding.
    pub fn frame(&self) -> [u8; 42] {
        let mut f = [0; 42];
        let interface = self.table.interface;
        f[..6].fill(0xff);
        f[6..12].copy_from_slice(&interface.mac);
        f[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        f[22..28].copy_from_slice(&interface.mac);
        f[28..32].copy_from_slice(&interface.ip);
        f[38..42].copy_from_slice(&self.table.entries[self.slot].unwrap().ip);
        f
    }
    pub fn sent(self) {
        let e = self.table.entries[self.slot].as_mut().unwrap();
        match &mut e.state {
            State::Pending {
                attempts, next_at, ..
            } => {
                *attempts += 1;
                *next_at = self.now + RETRY_MS;
            }
            State::Reachable {
                refresh: Some(r), ..
            } => {
                r.attempts += 1;
                r.next_at = self.now + RETRY_MS;
            }
            State::Reachable { refresh: None, .. } => unreachable!("probe owns scheduled entry"),
        }
        self.table.next_send = self.now + PACE_MS;
        self.table.cursor = (self.slot + 1) % N;
        self.table.last_now = self.now;
    }
}

#[cfg(test)]
mod tests;
