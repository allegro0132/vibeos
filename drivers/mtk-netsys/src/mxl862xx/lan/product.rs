//! Product-owned tagged LAN initialized after hardware reset, not adopted from
//! Linux. Resources live until the next switch reset. A failed setup keeps the
//! ownership record inactive and closes data gates; uncertain allocations are
//! never freed/retried while hardware might still reference them.
use super::*;
const PHYSICAL: [u16; 6] = [1, 2, 3, 4, 9, 13];

/// What a copper port is used for. LAN ports share one learning bridge with
/// the CPU. A `Wan` port is isolated: it is outside that bridge's domain and
/// can only exchange frames with the CPU, whatever the CPU then uses it for
/// (the uplink, or a network of its own); any number of ports may be. An
/// unused port forwards nothing in either direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRole {
    Lan,
    Wan,
    Off,
}

/// The VLANs an isolated port exchanges with the CPU: whether untagged
/// frames pass, and which VLAN IDs do (0: an empty place). Every other
/// frame is dropped at the port. A tagged frame reaches the CPU with the
/// port's CPU tag in front of its own, and is sent the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortVlans {
    pub untagged: bool,
    pub vids: [u16; 5],
}
impl PortVlans {
    /// Untagged frames only.
    pub const PLAIN: Self = Self { untagged: true, vids: [0; 5] };
    fn count(&self) -> u16 {
        self.vids.iter().filter(|vid| **vid != 0).count() as u16
    }
    fn valid(&self) -> bool {
        self.vids.iter().enumerate().all(|(i, vid)| *vid == 0
            || ((1..=4094).contains(vid) && !(0xc00..=0xc0f).contains(vid) && !self.vids[..i].contains(vid)))
    }
}

pub struct ProductLanBridge {
    router_mac: [u8; 6],
    roles: [PortRole; 4],
    vlans: [PortVlans; 4],
    wan_domain: Option<u16>,
    sfp: Option<PortVlans>,
    stage: &'static str,
    started: bool,
    active: bool,
    domain: Option<u16>,
    blocks: [Option<Allocation>; 8],
}
impl ProductLanBridge {
    pub const fn new(router_mac: [u8; 6]) -> Self {
        Self::with_roles(router_mac, [PortRole::Lan; 4])
    }
    /// `roles[n]` is the use of copper port n (DT index).
    pub const fn with_roles(router_mac: [u8; 6], roles: [PortRole; 4]) -> Self {
        Self {
            router_mac,
            roles,
            vlans: [PortVlans::PLAIN; 4],
            wan_domain: None,
            sfp: None,
            stage: "new",
            started: false,
            active: false,
            domain: None,
            blocks: [None; 8],
        }
    }
    /// Give isolated ports VLANs. A port of the LAN bridge takes none: the
    /// switch's own bridge forwards untagged frames only.
    pub const fn with_vlans(mut self, vlans: [PortVlans; 4]) -> Self {
        self.vlans = vlans;
        self
    }
    /// SFP is isolated from copper; software bridges its configured networks.
    pub const fn with_sfp(mut self, vlans: Option<PortVlans>) -> Self { self.sfp = vlans; self }
    pub fn vlans(&self) -> [PortVlans; 4] {
        self.vlans
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn domain(&self) -> Option<u16> {
        self.domain
    }
    pub fn roles(&self) -> [PortRole; 4] {
        self.roles
    }
    /// Copper index whose CPU tag (`Port::vid`) enters the LAN bridge with
    /// address lookup and flooding instead of leaving through that one port.
    /// Index 0 unless that port is the WAN, then the first LAN port. None
    /// without LAN ports. Every other tag is directed at its own port.
    pub fn injection(&self) -> Option<u8> {
        if !self.roles.contains(&PortRole::Lan) {
            None
        } else if self.roles[0] != PortRole::Wan {
            Some(0)
        } else {
            self.roles.iter().position(|r| *r == PortRole::Lan).map(|i| i as u8)
        }
    }
    fn acquire(&mut self, hw: &mut impl ProductBackend) -> Result<(), Error> {
        if self.started || self.router_mac == [0; 6] || self.router_mac[0] & 1 != 0 {
            return Err(Error::InvalidState);
        }
        if (0..4).any(|c| !self.vlans[c].valid() || (self.vlans[c] != PortVlans::PLAIN && self.roles[c] != PortRole::Wan)) {
            return Err(Error::InvalidState);
        }
        if self.sfp.is_some_and(|v| !v.valid()) { return Err(Error::InvalidState); }
        self.started = true;
        // Even a failed qualification must not open a data path.
        let result = self.configure(hw);
        if result.is_err() {
            let _ = hw.data(false);
        }
        self.active = result.is_ok();
        result
    }
    fn configure(&mut self, hw: &mut impl ProductBackend) -> Result<(), Error> {
        self.stage = "qualify";
        hw.reset_qualify()?;
        self.stage = "close-gates";
        hw.data(false)?;
        self.stage = "reset-state";
        for p in PHYSICAL {
            let b = hw.read(p)?.bridge;
            if b.id != 0 || b.destination != p as u8 || b.ingress_vlan.0 || b.egress_vlan.0 {
                return Err(Error::InvalidState);
            }
        }
        self.stage = "close-maps";
        for p in PHYSICAL {
            hw.map(p, map(0))?;
        }
        self.stage = "aliases";
        for p in 17..=20 {
            hw.alias(p)?;
            hw.map(p, map(0))?;
        }
        self.stage = "domain-allocate";
        let id = hw.domain_alloc()?;
        if id == 0 || id == u16::MAX {
            return Err(Error::InvalidResponse);
        }
        self.domain = Some(id);
        self.stage = "domain-policy";
        hw.domain_set(id)?;
        // Isolated ports never share an address table with the LAN. They may
        // share one among themselves: none learns, and none's map reaches another.
        let mut wan_id = id;
        if self.roles.contains(&PortRole::Wan) || self.sfp.is_some() {
            self.stage = "wan-domain-allocate";
            wan_id = hw.domain_alloc()?;
            if wan_id == 0 || wan_id == u16::MAX || wan_id == id {
                return Err(Error::InvalidResponse);
            }
            self.wan_domain = Some(wan_id);
            self.stage = "wan-domain-policy";
            hw.domain_set(wan_id)?;
        }
        for slot in 0..6 {
            let tagged_ports = self.vlans.iter().filter(|v| v.count() != 0).count() as u16;
            let count = match slot {
                0..=3 => 3 + self.vlans[slot].count(),
                4 => 10,
                _ => 7 + tagged_ports + self.sfp.map_or(0, |v| 1 + u16::from(v.count() != 0)),
            };
            self.stage = "vlan-allocate";
            let allocation = hw.alloc(count)?;
            let bid = block(allocation);
            if bid == u16::MAX || self.blocks.iter().flatten().any(|a| block(*a) == bid) {
                return Err(Error::InvalidResponse);
            }
            self.blocks[slot] = Some(allocation);
            if u16::from_le_bytes([allocation[0], allocation[1]]) < count {
                return Err(Error::InvalidResponse);
            }
            self.stage = "vlan-rules";
            if slot < 4 {
                // Untagged frames and each listed VLAN get the CPU tag;
                // everything else is dropped here. A rule that names a VLAN
                // comes before the ones for any tag.
                let vlans = self.vlans[slot];
                let first = if vlans.untagged { Rule::PushUntagged(COPPER[slot]) } else { Rule::DropUntagged };
                let listed = vlans.vids.into_iter().filter(|vid| *vid != 0).map(|vid| Rule::PushTagged(COPPER[slot], vid));
                for (i, rule) in core::iter::once(first).chain(listed).chain([Rule::DropAnyDoubleTagged, Rule::DropAnySingleTagged]).enumerate() {
                    hw.rule(bid, i as u16, rule)?;
                }
            } else if slot == 4 {
                for (i, p) in COPPER.into_iter().enumerate() {
                    hw.rule(bid, i as u16 * 2, Rule::PopOuter(p))?;
                    hw.rule(bid, i as u16 * 2 + 1, Rule::PopOuterTagged(p))?;
                }
                hw.rule(bid, 8, Rule::DropDoubleTagged)?;
                hw.rule(bid, 9, Rule::DropSingleTagged)?;
            } else {
                // The CPU reaches a port with that port's tag; a second tag
                // behind it only towards a port that has VLANs.
                let tagged = COPPER.into_iter().enumerate().filter(|(c, _)| self.vlans[*c].count() != 0).map(|(_, p)| Rule::ClassifyCpuTagged(p));
                let sfp_rules = self.sfp.into_iter().flat_map(|v| core::iter::once(Rule::ClassifyCpu(Port::Sfp)).chain((v.count() != 0).then_some(Rule::ClassifyCpuTagged(Port::Sfp))));
                let rules = COPPER.into_iter().map(Rule::ClassifyCpu).chain(tagged).chain(sfp_rules)
                    .chain([Rule::DropAnyDoubleTagged, Rule::DropAnySingleTagged, Rule::DropUntagged]);
                for (i, rule) in rules.enumerate() {
                    hw.rule(bid, i as u16, rule)?;
                }
            }
        }
        self.stage = "fdb-find";
        if hw.fdb_find(id, self.router_mac)?.is_some() {
            return Err(Error::InvalidState);
        }
        self.stage = "fdb-add";
        hw.fdb_add(id, self.router_mac)?;
        self.stage = "port-config";
        let injection = self.injection().map(usize::from);
        for (i, p) in PORTS.into_iter().enumerate() {
            let (role, alias) = (self.roles[i % 4], i >= 4);
            hw.destination(p, if i < 4 { p as u8 } else { 9 })?;
            // Only the injection alias consults the address table; only LAN
            // copper ports learn. The WAN port floods everything to the CPU.
            hw.identity(
                p,
                if role == PortRole::Wan { wan_id } else { id },
                alias && injection != Some(i % 4),
                alias || role != PortRole::Lan,
                [0; 7],
            )?;
            if i < 4 {
                hw.binding(p, true, (true, block(self.blocks[i].unwrap()), 3 + self.vlans[i].count()))?;
                hw.binding(p, false, (true, block(self.blocks[4].unwrap()), 10))?;
            }
        }
        // CPU ingress classifies tags to aliases 17..20; CPU egress is
        // transparent. Unclassified CPU traffic cannot use bridge 9's map.
        self.stage = "cpu-path";
        hw.cpu_path(block(self.blocks[5].unwrap()), 7 + self.vlans.iter().filter(|v| v.count() != 0).count() as u16 + self.sfp.map_or(0, |v| 1 + u16::from(v.count() != 0)))?;
        self.stage = "open-maps";
        let members = (0..4).filter(|c| self.roles[*c] == PortRole::Lan).fold(0u16, |bits, c| bits | 2 << c);
        for (i, p) in PORTS.into_iter().enumerate() {
            let bits = match (i >= 4, self.roles[i % 4]) {
                // The other members and the CPU; never back out the ingress port.
                (false, PortRole::Lan) => (members | 0x200) & !(1 << p),
                (false, PortRole::Wan) => 0x200,
                (true, _) if injection == Some(i % 4) => members,
                (_, PortRole::Off) => 0,
                (true, _) => 1 << (p - 16),
            };
            hw.map(p, map(bits))?;
        }
        if let Some(vlans) = self.sfp {
            self.stage = "sfp-serdes";
            hw.sfp_10g()?;
            self.stage = "sfp-alias";
            hw.alias(29)?;
            hw.map(29, map(0))?;
            for slot in 6..8 {
                let count = if slot == 6 { 3 + vlans.count() } else { 4 };
                let allocation = hw.alloc(count)?;
                let bid = block(allocation);
                if bid == u16::MAX || self.blocks.iter().flatten().any(|a| block(*a) == bid) { return Err(Error::InvalidResponse); }
                self.blocks[slot] = Some(allocation);
                if u16::from_le_bytes([allocation[0], allocation[1]]) < count { return Err(Error::InvalidResponse); }
                if slot == 6 {
                    let first = if vlans.untagged { Rule::PushUntagged(Port::Sfp) } else { Rule::DropUntagged };
                    let listed = vlans.vids.into_iter().filter(|v| *v != 0).map(|v| Rule::PushTagged(Port::Sfp, v));
                    for (i, rule) in core::iter::once(first).chain(listed).chain([Rule::DropAnyDoubleTagged, Rule::DropAnySingleTagged]).enumerate() {
                        hw.rule(bid, i as u16, rule)?;
                    }
                } else {
                    for (i, rule) in [Rule::PopOuter(Port::Sfp), Rule::PopOuterTagged(Port::Sfp), Rule::DropDoubleTagged, Rule::DropSingleTagged].into_iter().enumerate() {
                        hw.rule(bid, i as u16, rule)?;
                    }
                }
            }
            for (port, dest) in [(13, 13), (29, 9)] {
                hw.destination(port, dest)?;
                hw.identity(port, wan_id, true, true, [0; 7])?;
            }
            hw.binding(13, true, (true, block(self.blocks[6].unwrap()), 3 + vlans.count()))?;
            hw.binding(13, false, (true, block(self.blocks[7].unwrap()), 4))?;
            hw.map(13, map(1 << 9))?;
            hw.map(29, map(1 << 13))?;
        }
        self.stage = "open-gates";
        hw.data(true)?;
        self.stage = "ready";
        Ok(())
    }
}
trait ProductBackend: Backend {
    fn sfp_10g(&mut self) -> Result<(), Error>;
    fn reset_qualify(&mut self) -> Result<(), Error>;
    fn data(&mut self, enable: bool) -> Result<(), Error>;
    fn alias(&mut self, id: u16) -> Result<(), Error>;
    fn destination(&mut self, port: u16, destination: u8) -> Result<(), Error>;
    fn cpu_path(&mut self, block: u16, count: u16) -> Result<(), Error>;
}
impl<I: Io> Mailbox<'_, I> {
    /// Caller has reset the switch, owns all its configuration and keeps SoC
    /// RX/TX disabled. Retain `owner` on success or failure until next reset.
    pub fn initialize_product_lan(&mut self, owner: &mut ProductLanBridge) -> Result<(), Error> {
        owner.acquire(self)
    }
}
impl<I: Io> ProductBackend for Mailbox<'_, I> {
    fn sfp_10g(&mut self) -> Result<(), Error> {
        // Vendor SYS_MISC_SFP: SerDes 1 (physical port 13), fixed 10G XFI.
        self.execute(0x190e, &mut [1, 1, 2, 0], false)?;
        let mut got = [1, 0, 0, 0];
        self.query(0x190d, &mut got)?;
        if got[..3] != [1, 1, 2] { return Err(Error::ReadbackMismatch); }
        Ok(())
    }
    fn reset_qualify(&mut self) -> Result<(), Error> {
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        Ok(())
    }
    fn data(&mut self, enable: bool) -> Result<(), Error> {
        // On failure, still attempt every remaining gate. No enabling retry.
        let mut first = None;
        for p in PHYSICAL {
            for address in [0x0bc0 + p * 6, 0x0a80 + p * 6] {
                let result = (|| {
                    let [lo, hi] = address.to_le_bytes();
                    let mut before = [lo, hi, 0, 0];
                    self.query(0x0101, &mut before)?;
                    let old = u16::from_le_bytes([before[2], before[3]]);
                    self.execute(0x0111, &mut [lo, hi, u8::from(enable), 0, 1, 0], false)?;
                    let mut after = [lo, hi, 0, 0];
                    self.query(0x0101, &mut after)?;
                    if u16::from_le_bytes([after[2], after[3]]) != ((old & !1) | u16::from(enable))
                    {
                        return Err(Error::ReadbackMismatch);
                    }
                    Ok(())
                })();
                if let Err(e) = result {
                    if first.is_none() {
                        first = Some(e);
                    }
                }
            }
        }
        first.map_or(Ok(()), Err)
    }
    fn alias(&mut self, id: u16) -> Result<(), Error> {
        let mut b = id.to_le_bytes();
        self.query(0x0401, &mut b)?;
        if u16::from_le_bytes(b) != id {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
    fn destination(&mut self, port: u16, destination: u8) -> Result<(), Error> {
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x80u32.to_le_bytes());
        b[47] = destination;
        self.execute(0x0402, &mut b, false)?;
        if self.bridge(port)?.destination != destination {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn cpu_path(&mut self, block: u16, count: u16) -> Result<(), Error> {
        // Same 802.1Q CPU transport as mxl862_configure_tag_proto(enable=false).
        let tag = [9, 3, 1, 3, 0, 0];
        self.execute(0x1602, &mut tag.clone(), false)?;
        let mut got = [9, 3, 0, 0, 0, 0];
        self.query(0x1601, &mut got)?;
        if got[..4] != tag[..4] {
            return Err(Error::ReadbackMismatch);
        }
        let mut assignment = [0; 11];
        assignment[0] = 9;
        assignment[1..3].copy_from_slice(&9u16.to_le_bytes());
        assignment[3..5].copy_from_slice(&1u16.to_le_bytes());
        assignment[5..9].copy_from_slice(&2u32.to_le_bytes());
        self.execute(0x0503, &mut assignment.clone(), false)?;
        let mut got = [0; 11];
        got[0] = 9;
        self.query(0x0504, &mut got)?;
        if got[..9] != assignment[..9] {
            return Err(Error::ReadbackMismatch);
        }
        let mut ctp = [0; 151];
        ctp[0] = 9;
        ctp[3..7].copy_from_slice(&0x15u32.to_le_bytes());
        ctp[7..9].copy_from_slice(&9u16.to_le_bytes());
        ctp[11] = 1;
        ctp[12..14].copy_from_slice(&block.to_le_bytes());
        ctp[14..16].copy_from_slice(&count.to_le_bytes());
        self.execute(0x0505, &mut ctp.clone(), false)?;
        let mut got = [0; 151];
        got[0] = 9;
        got[3..7].copy_from_slice(&0x15u32.to_le_bytes());
        self.query(0x0506, &mut got)?;
        if got[..3] != ctp[..3]
            || got[7..9] != ctp[7..9]
            || got[11..16] != ctp[11..16]
            || got[21] != 0
        {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{collections::BTreeMap, vec::Vec};
    struct Model {
        ports: BTreeMap<u16, Snapshot>,
        blocks: BTreeMap<u16, Vec<Rule>>,
        enabled: bool,
        cpu: bool,
        gateway: bool,
        next: u16,
        calls: usize,
        fail_at: usize,
        duplicate: bool,
        roles: [PortRole; 4],
        vlans: [PortVlans; 4],
        domains: u16,
        same_domain: bool,
        sfp: Option<PortVlans>,
    }
    impl Model {
        fn new() -> Self {
            let ports = PHYSICAL
                .into_iter()
                .map(|p| {
                    (
                        p,
                        Snapshot {
                            bridge: Bridge {
                                id: 0,
                                destination: p as u8,
                                map: map(0x21e),
                                ingress_vlan: (false, 0, 0),
                                egress_vlan: (false, 0, 0),
                            },
                            learning: Learning {
                                destination_lookup_disabled: false,
                                source_learning_disabled: false,
                                limit: None,
                                learned: 0,
                            },
                            vlan_key: [0; 7],
                        },
                    )
                })
                .collect();
            Self {
                ports,
                blocks: BTreeMap::new(),
                enabled: false,
                cpu: false,
                gateway: false,
                next: 100,
                calls: 0,
                fail_at: usize::MAX,
                duplicate: false,
                roles: [PortRole::Lan; 4],
                vlans: [PortVlans::PLAIN; 4],
                domains: 0,
                same_domain: false,
                sfp: None,
            }
        }
        fn done<T>(&mut self, value: T) -> Result<T, Error> {
            self.calls += 1;
            if self.calls == self.fail_at {
                Err(Error::CompletionTimeout)
            } else {
                Ok(value)
            }
        }
        fn ready(&self) {
            assert!(self.cpu && self.gateway);
            // Stated independently of the driver: per role, who may reach whom.
            let lan: std::vec::Vec<u16> = (1..=4).filter(|p| self.roles[*p as usize - 1] == PortRole::Lan).collect();
            let all = lan.iter().fold(0u16, |bits, p| bits | 1 << p);
            let entry = if self.roles[0] == PortRole::Wan { lan.first().copied() } else { lan.first().map(|_| 1) };
            assert_eq!(self.domains, if self.roles.contains(&PortRole::Wan) || self.sfp.is_some() { 2 } else { 1 });
            for (i, p) in PORTS.into_iter().enumerate() {
                let s = self.ports[&p];
                let physical = if i < 4 { p } else { p - 16 };
                let role = self.roles[physical as usize - 1];
                let entry_alias = i >= 4 && entry == Some(physical);
                assert_eq!(s.bridge.id, if role == PortRole::Wan { 7 } else { 6 }, "port {p}");
                assert_eq!(s.bridge.destination, if i < 4 { p as u8 } else { 9 });
                let expected = match role {
                    _ if entry_alias => all,
                    PortRole::Off => 0,
                    PortRole::Lan if i < 4 => (all | 0x200) & !(1 << p),
                    PortRole::Wan if i < 4 => 0x200,
                    _ => 1 << physical,
                };
                assert_eq!(s.bridge.map, map(expected), "port {p}");
                // A map reaches another copper port only from the LAN to the LAN,
                // or from an isolated port's own CPU alias to that port.
                for q in 1..=4u16 {
                    let other = self.roles[q as usize - 1];
                    if expected & 1 << q != 0 {
                        assert!(other != PortRole::Off, "port {p} reaches unused {q}");
                        assert!(if other == PortRole::Wan { i >= 4 && q == physical } else { role == PortRole::Lan || entry_alias }, "port {p} reaches {q}");
                    }
                }
                assert_eq!(s.learning.source_learning_disabled, i >= 4 || role != PortRole::Lan, "port {p}");
                assert_eq!(s.learning.destination_lookup_disabled, i >= 4 && !entry_alias, "port {p}");
                if i < 4 {
                    // Stated independently: untagged frames pass unless the
                    // port is tagged-only, then exactly its VLANs, then nothing.
                    let r = &self.blocks[&s.bridge.ingress_vlan.1];
                    let vlans = self.vlans[i];
                    let listed: Vec<u16> = vlans.vids.into_iter().filter(|v| *v != 0).collect();
                    assert_eq!((s.bridge.ingress_vlan.0, s.bridge.ingress_vlan.2 as usize), (true, r.len()));
                    assert_eq!(r.len(), 3 + listed.len(), "port {p}");
                    assert!(if vlans.untagged { matches!(r[0], Rule::PushUntagged(q) if q.dt_index() == i as u8) } else { matches!(r[0], Rule::DropUntagged) }, "port {p}");
                    for (n, vid) in listed.iter().enumerate() {
                        assert!(matches!(r[1 + n], Rule::PushTagged(q, v) if q.dt_index() == i as u8 && v == *vid), "port {p}");
                    }
                    assert!(matches!(r[1 + listed.len()..], [Rule::DropAnyDoubleTagged, Rule::DropAnySingleTagged]), "port {p}");
                    assert!(listed.is_empty() || role == PortRole::Wan, "only an isolated port has VLANs");
                    assert_eq!(self.blocks[&s.bridge.egress_vlan.1].len(), 10);
                }
            }
            assert_eq!(self.ports[&9].bridge.map, map(0));
            if let Some(vlans) = self.sfp {
                let physical = self.ports[&13].bridge;
                let alias = self.ports[&29].bridge;
                assert_eq!(physical.map, map(1 << 9));
                assert_eq!(alias.map, map(1 << 13));
                assert_eq!((physical.destination, alias.destination), (13, 9));
                assert_ne!(physical.id, 6);
                assert_eq!(physical.id, alias.id);
                assert_eq!(physical.ingress_vlan.2, 3 + vlans.count());
                assert!(matches!(self.blocks[&physical.egress_vlan.1][0], Rule::PopOuter(Port::Sfp)));
                for p in PORTS { assert_eq!(self.ports[&p].bridge.map[0] & (1 << 13), 0); }
            } else { assert_eq!(self.ports[&13].bridge.map, map(0)); }
        }
    }
    impl Backend for Model {
        fn qualify(&mut self) -> Result<(), Error> {
            panic!("must not qualify inherited Linux layout")
        }
        fn read(&mut self, p: u16) -> Result<Snapshot, Error> {
            self.done(self.ports[&p])
        }
        fn map(&mut self, p: u16, m: [u16; 8]) -> Result<(), Error> {
            assert!(!self.enabled);
            self.ports.get_mut(&p).unwrap().bridge.map = m;
            self.done(())
        }
        fn domain_alloc(&mut self) -> Result<u16, Error> {
            self.domains += 1;
            assert!(self.domains <= 2);
            self.done(if self.same_domain { 6 } else { 5 + self.domains })
        }
        fn domain_set(&mut self, id: u16) -> Result<(), Error> {
            assert_eq!(id, 5 + self.domains);
            self.done(())
        }
        fn domain_free(&mut self, _: u16) -> Result<(), Error> {
            panic!("resources live until reset")
        }
        fn alloc(&mut self, count: u16) -> Result<Allocation, Error> {
            let id = if self.duplicate { 100 } else { self.next };
            self.next += 1;
            self.blocks.entry(id).or_default();
            let [a, b] = count.to_le_bytes();
            let [c, d] = id.to_le_bytes();
            self.done([a, b, c, d])
        }
        fn rule(&mut self, id: u16, index: u16, r: Rule) -> Result<(), Error> {
            let rules = self.blocks.get_mut(&id).unwrap();
            assert_eq!(rules.len(), index as usize);
            rules.push(r);
            self.done(())
        }
        fn free(&mut self, _: Allocation) -> Result<(), Error> {
            panic!("resources live until reset")
        }
        fn fdb_find(&mut self, _: u16, _: [u8; 6]) -> Result<Option<FdbEntry>, Error> {
            self.done(None)
        }
        fn fdb_add(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error> {
            assert_eq!(id, 6);
            assert_eq!(mac, [2, 0x42, 0x70, 4, 0, 2]);
            self.gateway = true;
            self.done(())
        }
        fn fdb_remove(&mut self, _: u16, _: [u8; 6]) -> Result<(), Error> {
            panic!("resources live until reset")
        }
        fn identity(
            &mut self,
            p: u16,
            id: u16,
            lookup: bool,
            learn: bool,
            key: [u8; 7],
        ) -> Result<(), Error> {
            assert!(!self.enabled);
            let s = self.ports.get_mut(&p).unwrap();
            assert!(id == 6 || id == 7 && self.domains == 2);
            s.bridge.id = id;
            s.learning.destination_lookup_disabled = lookup;
            s.learning.source_learning_disabled = learn;
            s.vlan_key = key;
            self.done(())
        }
        fn binding(&mut self, p: u16, ingress: bool, b: (bool, u16, u16)) -> Result<(), Error> {
            assert!(!self.enabled);
            let s = &mut self.ports.get_mut(&p).unwrap().bridge;
            if ingress {
                s.ingress_vlan = b;
            } else {
                s.egress_vlan = b;
            }
            self.done(())
        }
    }
    impl ProductBackend for Model {
        fn sfp_10g(&mut self) -> Result<(), Error> { self.done(()) }
        fn reset_qualify(&mut self) -> Result<(), Error> {
            self.done(())
        }
        fn data(&mut self, on: bool) -> Result<(), Error> {
            if on {
                self.ready();
            }
            self.enabled = on;
            self.done(())
        }
        fn alias(&mut self, id: u16) -> Result<(), Error> {
            assert!(!self.enabled && !self.ports.contains_key(&id));
            let mut s = self.ports[&9];
            s.bridge.destination = 0;
            self.ports.insert(id, s);
            self.done(())
        }
        fn destination(&mut self, p: u16, d: u8) -> Result<(), Error> {
            assert!(!self.enabled);
            self.ports.get_mut(&p).unwrap().bridge.destination = d;
            self.done(())
        }
        fn cpu_path(&mut self, block: u16, count: u16) -> Result<(), Error> {
            let rules = &self.blocks[&block];
            assert_eq!(count as usize, rules.len());
            for (i, r) in rules[..4].iter().enumerate() {
                assert!(matches!(r,Rule::ClassifyCpu(p) if p.dt_index()==i as u8));
            }
            // A second tag behind the CPU tag only towards ports with VLANs.
            let tagged: Vec<u8> = (0..4u8).filter(|c| self.vlans[*c as usize].vids.iter().any(|v| *v != 0)).collect();
            let sfp_count = self.sfp.map_or(0, |v| 1 + usize::from(v.count() != 0));
            assert_eq!(rules.len(), 7 + tagged.len() + sfp_count);
            for (r, c) in rules[4..].iter().zip(&tagged) {
                assert!(matches!(r, Rule::ClassifyCpuTagged(p) if p.dt_index() == *c));
            }
            assert!(matches!(
                &rules[4 + tagged.len() + sfp_count..],
                [
                    Rule::DropAnyDoubleTagged,
                    Rule::DropAnySingleTagged,
                    Rule::DropUntagged
                ]
            ));
            self.cpu = true;
            self.done(())
        }
    }
    fn owner() -> ProductLanBridge {
        ProductLanBridge::new([2, 0x42, 0x70, 4, 0, 2])
    }
    #[test]
    fn builds_complete_tagged_bridge_from_reset_without_inherited_aliases() {
        let mut m = Model::new();
        let mut o = owner();
        o.acquire(&mut m).unwrap();
        assert!(o.active() && m.enabled);
        m.ready();
        assert_eq!(o.domain(), Some(6));
        let calls = m.calls;
        assert!(o.acquire(&mut m).is_err());
        assert_eq!(m.calls, calls);
    }
    #[test]
    fn every_ambiguous_setup_failure_closes_data_and_never_grants_authority() {
        let mut good = Model::new();
        owner().acquire(&mut good).unwrap();
        for fail in 1..=good.calls {
            let mut m = Model::new();
            m.fail_at = fail;
            let mut o = owner();
            assert!(o.acquire(&mut m).is_err(), "call {fail}");
            assert!(!o.active() && !m.enabled, "call {fail}");
            let calls = m.calls;
            assert!(o.acquire(&mut m).is_err());
            assert_eq!(m.calls, calls);
        }
    }
    #[test]
    fn every_role_assignment_isolates_wan_from_lan_and_fails_closed() {
        use PortRole::*;
        let mut layouts = 0;
        for code in 0..81usize {
            let roles: [PortRole; 4] = core::array::from_fn(|i| [Lan, Wan, Off][code / 3usize.pow(i as u32) % 3]);
            let mut m = Model::new();
            m.roles = roles;
            let mut o = ProductLanBridge::with_roles([2, 0x42, 0x70, 4, 0, 2], roles);
            layouts += 1;
            o.acquire(&mut m).unwrap_or_else(|e| panic!("{roles:?}: {e:?} at {}", o.stage()));
            assert!(o.active() && m.enabled);
            m.ready();
            let lan = roles.iter().position(|r| *r == Lan).map(|i| i as u8);
            assert_eq!(o.injection(), if roles[0] == Wan { lan } else { lan.map(|_| 0) });
            for fail in 1..=m.calls {
                let mut broken = Model::new();
                broken.roles = roles;
                broken.fail_at = fail;
                let mut o = ProductLanBridge::with_roles([2, 0x42, 0x70, 4, 0, 2], roles);
                assert!(o.acquire(&mut broken).is_err(), "{roles:?} call {fail}");
                assert!(!o.active() && !broken.enabled, "{roles:?} call {fail}");
            }
        }
        assert_eq!(layouts, 81);
        // A WAN domain that is not distinct from the LAN's is refused.
        let mut m = Model::new();
        m.roles = [Lan, Lan, Lan, Wan];
        m.same_domain = true;
        let mut o = ProductLanBridge::with_roles([2, 0x42, 0x70, 4, 0, 2], m.roles);
        assert!(o.acquire(&mut m).is_err());
        assert!(!o.active() && !m.enabled);
    }
    #[test]
    fn isolated_ports_take_listed_vlans_and_nothing_else() {
        use PortRole::*;
        let mac = [2, 0x42, 0x70, 4, 0, 2];
        let trunk = PortVlans { untagged: true, vids: [20, 30, 0, 0, 0] };
        let only = PortVlans { untagged: false, vids: [0, 7, 0, 0, 4094] };
        for (roles, vlans) in [
            ([Wan, Lan, Lan, Lan], [trunk, PortVlans::PLAIN, PortVlans::PLAIN, PortVlans::PLAIN]),
            ([Lan, Wan, Off, Wan], [PortVlans::PLAIN, only, PortVlans::PLAIN, trunk]),
            ([Wan, Wan, Wan, Wan], [trunk, only, PortVlans::PLAIN, PortVlans { untagged: false, vids: [1, 2, 3, 4, 5] }]),
        ] {
            let mut m = Model::new();
            (m.roles, m.vlans) = (roles, vlans);
            let mut o = ProductLanBridge::with_roles(mac, roles).with_vlans(vlans);
            o.acquire(&mut m).unwrap_or_else(|e| panic!("{roles:?}: {e:?} at {}", o.stage()));
            assert!(o.active() && m.enabled && o.vlans() == vlans);
            m.ready();
            for fail in 1..=m.calls {
                let mut broken = Model::new();
                (broken.roles, broken.vlans, broken.fail_at) = (roles, vlans, fail);
                let mut o = ProductLanBridge::with_roles(mac, roles).with_vlans(vlans);
                assert!(o.acquire(&mut broken).is_err(), "{roles:?} call {fail}");
                assert!(!o.active() && !broken.enabled, "{roles:?} call {fail}");
            }
        }
        // Refused before anything is touched: VLANs on a port of the LAN
        // bridge or on an unused one, an ID out of range, one of the CPU
        // tags' own, the same ID twice.
        for (roles, bad) in [
            ([Lan, Lan, Lan, Lan], trunk),
            ([Off, Lan, Lan, Lan], trunk),
            ([Lan, Lan, Lan, Lan], PortVlans { untagged: false, vids: [0; 5] }),
            ([Wan, Lan, Lan, Lan], PortVlans { untagged: true, vids: [4095, 0, 0, 0, 0] }),
            ([Wan, Lan, Lan, Lan], PortVlans { untagged: true, vids: [0xc02, 0, 0, 0, 0] }),
            ([Wan, Lan, Lan, Lan], PortVlans { untagged: true, vids: [9, 0, 9, 0, 0] }),
        ] {
            let mut m = Model::new();
            let mut o = ProductLanBridge::with_roles(mac, roles).with_vlans([bad, PortVlans::PLAIN, PortVlans::PLAIN, PortVlans::PLAIN]);
            assert!(o.acquire(&mut m).is_err(), "{roles:?} {bad:?}");
            assert!(!o.active() && !m.enabled && m.calls == 0 && m.blocks.is_empty());
        }
    }
    #[test]
    fn refuses_inherited_configuration_and_aliased_vlan_allocations() {
        for p in PHYSICAL {
            let mut m = Model::new();
            m.ports.get_mut(&p).unwrap().bridge.ingress_vlan.0 = true;
            let mut o = owner();
            assert!(o.acquire(&mut m).is_err());
            assert!(!o.active() && !m.enabled);
            assert!(m.blocks.is_empty());
        }
        let mut m = Model::new();
        m.duplicate = true;
        let mut o = owner();
        assert!(o.acquire(&mut m).is_err());
        assert!(!o.active() && !m.enabled);
    }
    #[test]
    fn sfp_is_cpu_only_and_every_setup_failure_closes_gates() {
        for vlans in [PortVlans::PLAIN, PortVlans { untagged: false, vids: [100, 200, 0, 0, 0] }] {
            let mut model = Model::new(); model.sfp = Some(vlans);
            let mut bridge = owner().with_sfp(Some(vlans));
            bridge.acquire(&mut model).unwrap();
            model.ready();
            for fail in 1..=model.calls {
                let mut broken = Model::new(); broken.sfp = Some(vlans); broken.fail_at = fail;
                let mut bridge = owner().with_sfp(Some(vlans));
                assert!(bridge.acquire(&mut broken).is_err(), "failure {fail}");
                assert!(!bridge.active() && !broken.enabled);
            }
        }
    }

}
