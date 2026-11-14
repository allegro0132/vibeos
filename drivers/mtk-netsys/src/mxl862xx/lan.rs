//! Reversible four-copper LAN bridge. The caller owns switch configuration and
//! must quiesce CPU-port TX while applying/restoring. No PHY/CTP reset is issued.
mod product;
pub use product::ProductLanBridge;

use super::{Bridge, DomainPolicy, Error, FdbEntry, FloodMode, Io, Learning, Mailbox};
use crate::{mxl_tag::Port, mxl_vlan::Rule};

const PORTS: [u16; 8] = [1, 2, 3, 4, 17, 18, 19, 20];
const COPPER: [Port; 4] = [Port::Copper0, Port::Copper1, Port::Copper2, Port::Copper3];
type Allocation = [u8; 4];
fn block(a: Allocation) -> u16 {
    u16::from_le_bytes([a[2], a[3]])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snapshot {
    bridge: Bridge,
    learning: Learning,
    vlan_key: [u8; 7],
}

// Typed hardware boundary also permits fault injection at every operation in
// the sequencing tests. The real adapter below verifies every persistent write.
trait Backend {
    fn fdb_find(&mut self, id: u16, mac: [u8; 6]) -> Result<Option<FdbEntry>, Error>;
    fn fdb_add(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error>;
    fn fdb_remove(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error>;
    fn qualify(&mut self) -> Result<(), Error>;
    fn read(&mut self, port: u16) -> Result<Snapshot, Error>;
    fn domain_alloc(&mut self) -> Result<u16, Error>;
    fn domain_set(&mut self, id: u16) -> Result<(), Error>;
    fn domain_free(&mut self, id: u16) -> Result<(), Error>;
    fn alloc(&mut self, count: u16) -> Result<Allocation, Error>;
    fn rule(&mut self, id: u16, index: u16, rule: Rule) -> Result<(), Error>;
    fn free(&mut self, allocation: Allocation) -> Result<(), Error>;
    fn map(&mut self, port: u16, map: [u16; 8]) -> Result<(), Error>;
    fn identity(
        &mut self,
        port: u16,
        id: u16,
        lookup_off: bool,
        learn_off: bool,
        key: [u8; 7],
    ) -> Result<(), Error>;
    fn binding(&mut self, port: u16, ingress: bool, value: (bool, u16, u16)) -> Result<(), Error>;
}

#[derive(Debug)]
pub struct LanBridgeLease {
    before: [Option<Snapshot>; 8],
    inherited: [Option<Snapshot>; 3], // CPU 9, excluded SFP 13 and CPU alias 29
    domain: Option<u16>,
    router_mac: [u8; 6],
    untagged_only: bool,
    fdb_may_exist: bool,
    allocations: [Option<Allocation>; 5], // four ingress + one shared egress
    started: bool,
    changed: bool,
    free_attempted: bool,
    active: bool,
    released: bool,
}
impl LanBridgeLease {
    pub const fn new(router_mac: [u8; 6]) -> Self {
        Self {
            before: [None; 8],
            inherited: [None; 3],
            domain: None,
            router_mac,
            untagged_only: false,
            fdb_may_exist: false,
            allocations: [None; 5],
            started: false,
            changed: false,
            free_attempted: false,
            active: false,
            released: false,
        }
    }
    /// Copper access ports accept untagged traffic; recognized single/double tags are
    /// discarded before CPU-tag insertion. Rules are verified before binding.
    pub const fn new_untagged(router_mac: [u8; 6]) -> Self {
        let mut lease = Self::new(router_mac);
        lease.untagged_only = true;
        lease
    }
    pub fn untagged_only(&self) -> bool { self.active && self.untagged_only }
    pub fn domain(&self) -> Option<u16> {
        self.domain
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn released(&self) -> bool {
        self.released
    }

    fn acquire<B: Backend>(&mut self, hw: &mut B) -> Result<(), Error> {
        if self.started {
            return Err(Error::InvalidState);
        }
        self.started = true;
        if self.router_mac == [0; 6] || self.router_mac[0] & 1 != 0 {
            return Err(Error::InvalidState);
        }
        hw.qualify()?;
        for (i, port) in PORTS.into_iter().enumerate() {
            self.before[i] = Some(hw.read(port)?);
        }
        for (i, port) in [9, 13, 29].into_iter().enumerate() {
            self.inherited[i] = Some(hw.read(port)?);
        }
        for i in 0..4 {
            let p = self.before[i].unwrap().bridge;
            let cpu = self.before[i + 4].unwrap().bridge;
            if p.destination != i as u8 + 1
                || p.map != map(0x200)
                || !p.ingress_vlan.0
                || !p.egress_vlan.0
                || cpu.destination != 9
                || cpu.id != p.id
                || cpu.map != map(1 << (i + 1))
            {
                return Err(Error::InvalidResponse);
            }
        }
        let id = hw.domain_alloc()?;
        if id == 0 || id == u16::MAX || self.snapshots().any(|s| s.bridge.id == id) {
            return Err(Error::InvalidResponse);
        }
        self.domain = Some(id);
        hw.domain_set(id)?;
        for slot in 0..5 {
            let count = if slot == 4 { 10 } else { 3 };
            let allocation = hw.alloc(count)?;
            let bid = block(allocation);
            if bid == u16::MAX
                || self.snapshots().any(|s| {
                    s.bridge.ingress_vlan.0 && s.bridge.ingress_vlan.1 == bid
                        || s.bridge.egress_vlan.0 && s.bridge.egress_vlan.1 == bid
                })
                || self.allocations.iter().flatten().any(|a| block(*a) == bid)
            {
                // A corrupt ID never grants authority to free an existing block.
                return Err(Error::InvalidResponse);
            }
            self.allocations[slot] = Some(allocation);
            if u16::from_le_bytes([allocation[0], allocation[1]]) < count {
                return Err(Error::InvalidResponse);
            }
            if slot < 4 {
                let p = COPPER[slot];
                for (i, rule) in [
                    Rule::PushUntagged(p),
                    if self.untagged_only { Rule::DropAnyDoubleTagged } else { Rule::PushSingleTagged(p) },
                    if self.untagged_only { Rule::DropAnySingleTagged } else { Rule::PushDoubleTagged(p) },
                ]
                .into_iter()
                .enumerate()
                {
                    hw.rule(bid, i as u16, rule)?;
                }
            } else {
                for (i, p) in COPPER.into_iter().enumerate() {
                    hw.rule(bid, i as u16 * 2, Rule::PopOuter(p))?;
                    hw.rule(bid, i as u16 * 2 + 1, Rule::PopOuterTagged(p))?;
                }
                hw.rule(bid, 8, Rule::DropDoubleTagged)?;
                hw.rule(bid, 9, Rule::DropSingleTagged)?;
            }
        }
        // A fresh FID is required, but still prove this exact key absent before
        // claiming it. Existing entries are never overwritten or later removed.
        if hw.fdb_find(id, self.router_mac)?.is_some() {
            return Err(Error::InvalidState);
        }
        self.fdb_may_exist = true; // ADD may apply even if completion is lost
        hw.fdb_add(id, self.router_mac)?;
        // Every domain/rule is ready before the first live-port write.
        self.changed = true; // set BEFORE submission: timeout is ambiguous
        for port in PORTS {
            hw.map(port, map(0))?;
        }
        for (i, port) in PORTS.into_iter().enumerate() {
            // Alias 17 is the common CPU-to-LAN bridge injection point.
            // It uses the FDB and hardware flooding; other aliases stay directed.
            hw.identity(port, id, i > 4, i >= 4, [0; 7])?;
            if i < 4 {
                hw.binding(port, true, (true, block(self.allocations[i].unwrap()), 3))?;
                hw.binding(port, false, (true, block(self.allocations[4].unwrap()), 10))?;
            }
        }
        for (i, port) in PORTS.into_iter().enumerate() {
            // One CPU flood destination, no SFP and no self reflection.
            let bits = if i < 4 {
                0x21e & !(1 << port)
            } else if i == 4 {
                0x1e
            } else {
                1 << (port - 16)
            };
            hw.map(port, map(bits))?;
        }
        self.active = true;
        Ok(())
    }
    fn snapshots(&self) -> impl Iterator<Item = &Snapshot> {
        self.before.iter().chain(self.inherited.iter()).flatten()
    }
    fn restore<B: Backend>(&mut self, hw: &mut B) -> Result<(), Error> {
        if !self.started || self.released || self.free_attempted {
            return Err(Error::InvalidState);
        }
        if self.changed {
            self.active = false;
            for port in PORTS {
                hw.map(port, map(0))?;
            }
            // Do not reopen ANY map until ALL old bindings/identities read back.
            for (i, port) in PORTS.into_iter().enumerate() {
                let old = self.before[i].ok_or(Error::InvalidState)?;
                if i < 4 {
                    hw.binding(port, true, old.bridge.ingress_vlan)?;
                    hw.binding(port, false, old.bridge.egress_vlan)?;
                }
                hw.identity(
                    port,
                    old.bridge.id,
                    old.learning.destination_lookup_disabled,
                    old.learning.source_learning_disabled,
                    old.vlan_key,
                )?;
            }
            for (i, port) in PORTS.into_iter().enumerate() {
                hw.map(port, self.before[i].unwrap().bridge.map)?;
            }
            self.changed = false;
        }
        if self.fdb_may_exist {
            let id = self.domain.ok_or(Error::InvalidState)?;
            if let Some(entry) = hw.fdb_find(id, self.router_mac)? {
                // Ownership follows the previously absent key, even if ADD readback
                // normalized the destination unexpectedly. Never delete another
                // filter/TCI variant when recovering from a failed verification.
                if entry.fid != id
                    || entry.mac != self.router_mac
                    || entry.filter != 0
                    || entry.tci != 0
                {
                    return Err(Error::ReadbackMismatch);
                }
                hw.fdb_remove(id, self.router_mac)?;
            }
            self.fdb_may_exist = false;
        }
        // No binding can reference owned resources now. FREE ambiguity is
        // terminal for this lease: never resend a possibly completed release.
        for allocation in self.allocations.into_iter().flatten() {
            self.free_attempted = true;
            hw.free(allocation)?;
        }
        if let Some(id) = self.domain {
            self.free_attempted = true;
            hw.domain_free(id)?;
        }
        self.released = true;
        Ok(())
    }
}
fn map(bits: u16) -> [u16; 8] {
    [bits, 0, 0, 0, 0, 0, 0, 0]
}

impl<I: Io> Mailbox<'_, I> {
    /// Retain the lease even on error and explicitly restore before reboot.
    pub fn own_lan_bridge(&mut self, lease: &mut LanBridgeLease) -> Result<(), Error> {
        lease.acquire(self)
    }
    pub fn restore_lan_bridge(&mut self, lease: &mut LanBridgeLease) -> Result<(), Error> {
        lease.restore(self)
    }
    /// Turn a switch that is in its hardware-reset defaults into one plain
    /// learning bridge of the four copper ports and the CPU port, with
    /// untagged frames on the CPU port and no VLAN rules.
    ///
    /// For a product that resets the switch itself at start-up and therefore
    /// needs neither a lease nor a restore: the next start resets again. The
    /// state is verified first (default bridge 0, no VLAN bindings); anything
    /// else is refused, not adopted. Forwarding is closed on every port
    /// before the first new map opens, and each write is read back.
    pub fn raw_lan_bridge(&mut self) -> Result<(), Error> {
        const MEMBERS: [u16; 5] = [1, 2, 3, 4, 9];
        for port in MEMBERS {
            let bridge = self.bridge(port)?;
            if bridge.id != 0 || bridge.destination != port as u8 || bridge.ingress_vlan.0 || bridge.egress_vlan.0 {
                return Err(Error::InvalidState);
            }
        }
        for port in MEMBERS {
            Backend::map(self, port, map(0))?;
        }
        for port in 1..=4u16 {
            self.set_port_data(port)?;
            // The other copper ports and the CPU; never back out the ingress port.
            Backend::map(self, port, map(0x21e & !(1 << port)))?;
        }
        Backend::map(self, 9, map(0x1e))
    }
}
impl<I: Io> Backend for Mailbox<'_, I> {
    fn fdb_find(&mut self, id: u16, mac: [u8; 6]) -> Result<Option<FdbEntry>, Error> {
        self.find_fdb(id, mac)
    }
    fn fdb_add(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error> {
        self.add_gateway_fdb(id, mac)
    }
    fn fdb_remove(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error> {
        self.remove_gateway_fdb(id, mac)
    }

    fn qualify(&mut self) -> Result<(), Error> {
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        for p in COPPER {
            if !self.verify_port_path(p)? {
                return Err(Error::InvalidResponse);
            }
        }
        Ok(())
    }
    fn read(&mut self, port: u16) -> Result<Snapshot, Error> {
        let bridge = self.bridge(port)?;
        let learning = self.port_learning(port)?;
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x100000u32.to_le_bytes());
        self.query(0x0403, &mut b)?;
        if b[..2] != port.to_le_bytes() || b[177..183].iter().any(|v| *v > 1) {
            return Err(Error::InvalidResponse);
        }
        Ok(Snapshot {
            bridge,
            learning,
            vlan_key: b[176..183].try_into().unwrap(),
        })
    }
    fn domain_alloc(&mut self) -> Result<u16, Error> {
        let mut b = [0; 2];
        self.query(0x0301, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn domain_set(&mut self, id: u16) -> Result<(), Error> {
        let policy = DomainPolicy {
            learning_limit: Some(254),
            flood: [FloodMode::Members; 4],
        };
        self.execute(0x0302, &mut policy.request(id)?, false)?;
        if self.domain_policy(id)? != policy {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn domain_free(&mut self, id: u16) -> Result<(), Error> {
        self.execute(0x0304, &mut id.to_le_bytes(), false)
    }
    fn alloc(&mut self, count: u16) -> Result<Allocation, Error> {
        let mut b = [0; 4];
        b[..2].copy_from_slice(&count.to_le_bytes());
        self.query(0x0b01, &mut b)?;
        Ok(b)
    }
    fn rule(&mut self, id: u16, index: u16, rule: Rule) -> Result<(), Error> {
        self.execute(0x0b02, &mut rule.encode(id, index), false)?;
        if !rule.matches(&self.vlan_rule(id, index)?) {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn free(&mut self, mut a: Allocation) -> Result<(), Error> {
        self.execute(0x0b04, &mut a, false)
    }
    fn map(&mut self, port: u16, map: [u16; 8]) -> Result<(), Error> {
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        for (i, v) in map.into_iter().enumerate() {
            b[131 + i * 2..133 + i * 2].copy_from_slice(&v.to_le_bytes());
        }
        self.execute(0x0402, &mut b, false)?;
        if self.bridge(port)?.map != map {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn identity(
        &mut self,
        port: u16,
        id: u16,
        lookup_off: bool,
        learn_off: bool,
        key: [u8; 7],
    ) -> Result<(), Error> {
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x101801u32.to_le_bytes());
        b[6..8].copy_from_slice(&id.to_le_bytes());
        b[149] = lookup_off as u8;
        b[150] = learn_off as u8;
        b[176..183].copy_from_slice(&key);
        self.execute(0x0402, &mut b, false)?;
        let got = self.read(port)?;
        if got.bridge.id != id
            || got.learning.destination_lookup_disabled != lookup_off
            || got.learning.source_learning_disabled != learn_off
            || got.vlan_key != key
        {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn binding(&mut self, port: u16, ingress: bool, value: (bool, u16, u16)) -> Result<(), Error> {
        self.set_binding(port, ingress, value)
    }
}

#[cfg(test)]
mod tests;
