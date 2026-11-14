//! Product-owned tagged LAN initialized after hardware reset, not adopted from
//! Linux. Resources live until the next switch reset. A failed setup keeps the
//! ownership record inactive and closes data gates; uncertain allocations are
//! never freed/retried while hardware might still reference them.
use super::*;
const PHYSICAL: [u16; 5] = [1, 2, 3, 4, 9];

pub struct ProductLanBridge {
    router_mac: [u8; 6],
    stage: &'static str,
    started: bool,
    active: bool,
    domain: Option<u16>,
    blocks: [Option<Allocation>; 6],
}
impl ProductLanBridge {
    pub const fn new(router_mac: [u8; 6]) -> Self {
        Self {
            router_mac,
            stage: "new",
            started: false,
            active: false,
            domain: None,
            blocks: [None; 6],
        }
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
    fn acquire(&mut self, hw: &mut impl ProductBackend) -> Result<(), Error> {
        if self.started || self.router_mac == [0; 6] || self.router_mac[0] & 1 != 0 {
            return Err(Error::InvalidState);
        }
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
        for slot in 0..6 {
            let count = match slot {
                0..=3 => 3,
                4 => 10,
                _ => 7,
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
                for (i, rule) in [
                    Rule::PushUntagged(COPPER[slot]),
                    Rule::DropAnyDoubleTagged,
                    Rule::DropAnySingleTagged,
                ]
                .into_iter()
                .enumerate()
                {
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
                for (i, p) in COPPER.into_iter().enumerate() {
                    hw.rule(bid, i as u16, Rule::ClassifyCpu(p))?;
                }
                hw.rule(bid, 4, Rule::DropAnyDoubleTagged)?;
                hw.rule(bid, 5, Rule::DropAnySingleTagged)?;
                hw.rule(bid, 6, Rule::DropUntagged)?;
            }
        }
        self.stage = "fdb-find";
        if hw.fdb_find(id, self.router_mac)?.is_some() {
            return Err(Error::InvalidState);
        }
        self.stage = "fdb-add";
        hw.fdb_add(id, self.router_mac)?;
        self.stage = "port-config";
        for (i, p) in PORTS.into_iter().enumerate() {
            hw.destination(p, if i < 4 { p as u8 } else { 9 })?;
            hw.identity(p, id, i > 4, i >= 4, [0; 7])?;
            if i < 4 {
                hw.binding(p, true, (true, block(self.blocks[i].unwrap()), 3))?;
                hw.binding(p, false, (true, block(self.blocks[4].unwrap()), 10))?;
            }
        }
        // CPU ingress classifies tags to aliases 17..20; CPU egress is
        // transparent. Unclassified CPU traffic cannot use bridge 9's map.
        self.stage = "cpu-path";
        hw.cpu_path(block(self.blocks[5].unwrap()), 7)?;
        self.stage = "open-maps";
        for (i, p) in PORTS.into_iter().enumerate() {
            let bits = if i < 4 {
                0x21e & !(1 << p)
            } else if i == 4 {
                0x1e
            } else {
                1 << (p - 16)
            };
            hw.map(p, map(bits))?;
        }
        self.stage = "open-gates";
        hw.data(true)?;
        self.stage = "ready";
        Ok(())
    }
}
trait ProductBackend: Backend {
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
            for (i, p) in PORTS.into_iter().enumerate() {
                let s = self.ports[&p];
                assert_eq!(s.bridge.id, 6);
                assert_eq!(s.bridge.destination, if i < 4 { p as u8 } else { 9 });
                assert_eq!(
                    s.bridge.map,
                    map(if i < 4 {
                        0x21e & !(1 << p)
                    } else if i == 4 {
                        0x1e
                    } else {
                        1 << (p - 16)
                    })
                );
                assert_eq!(s.learning.source_learning_disabled, i >= 4);
                assert_eq!(s.learning.destination_lookup_disabled, i > 4);
                if i < 4 {
                    let r = &self.blocks[&s.bridge.ingress_vlan.1];
                    assert!(matches!(
                        r.as_slice(),
                        [
                            Rule::PushUntagged(_),
                            Rule::DropAnyDoubleTagged,
                            Rule::DropAnySingleTagged
                        ]
                    ));
                    assert_eq!(self.blocks[&s.bridge.egress_vlan.1].len(), 10);
                }
            }
            assert_eq!(self.ports[&9].bridge.map, map(0));
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
            self.done(6)
        }
        fn domain_set(&mut self, id: u16) -> Result<(), Error> {
            assert_eq!(id, 6);
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
            assert_eq!(count, 7);
            for (i, r) in rules[..4].iter().enumerate() {
                assert!(matches!(r,Rule::ClassifyCpu(p) if p.dt_index()==i as u8));
            }
            assert!(matches!(
                &rules[4..],
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
}
