extern crate std;
use super::*;
use std::collections::BTreeMap;

struct Model {
    ports: BTreeMap<u16, Snapshot>,
    original: BTreeMap<u16, Snapshot>,
    domains: std::vec::Vec<u16>,
    fdb: Option<FdbEntry>,
    blocks: BTreeMap<u16, (u16, std::vec::Vec<Rule>)>,
    next: u16,
    calls: usize,
    fail_at: usize,
    frees: usize,
}
impl Model {
    fn new() -> Self {
        let mut ports = BTreeMap::new();
        for p in [1, 2, 3, 4, 9, 13, 17, 18, 19, 20, 29] {
            let physical = if p > 16 { p - 16 } else { p };
            let alias = p > 16;
            ports.insert(
                p,
                Snapshot {
                    bridge: Bridge {
                        id: if p == 9 { 0 } else { physical + 1 },
                        destination: if alias { 9 } else { p as u8 },
                        map: if alias {
                            map(1 << physical)
                        } else {
                            map(0x200)
                        },
                        ingress_vlan: (!alias, p * 10, 3),
                        egress_vlan: (!alias, p * 10 + 3, 4),
                    },
                    learning: Learning {
                        destination_lookup_disabled: false,
                        source_learning_disabled: true,
                        limit: None,
                        learned: 0,
                    },
                    vlan_key: [1, 1, 0, 1, 0, 1, 0],
                },
            );
        }
        Self {
            original: ports.clone(),
            ports,
            domains: std::vec::Vec::new(),
            fdb: None,
            blocks: BTreeMap::new(),
            next: 1000,
            calls: 0,
            fail_at: usize::MAX,
            frees: 0,
        }
    }
    // Fail AFTER applying a write: the worst case of ambiguous completion.
    fn done<T>(&mut self, v: T) -> Result<T, Error> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(Error::CompletionTimeout)
        } else {
            Ok(v)
        }
    }
    fn quarantined(&self) {
        for p in PORTS {
            assert_eq!(self.ports[&p].bridge.map, map(0));
        }
    }
    fn ready_to_open(&self) {
        let old = PORTS.iter().all(|p| {
            let mut a = self.ports[p];
            let mut b = self.original[p];
            a.bridge.map = map(0);
            b.bridge.map = map(0);
            a == b
        });
        if old {
            return;
        }
        assert!(self.fdb.unwrap().gateway(6, [2, 0x42, 0x70, 4, 0, 2]));
        for (i, p) in PORTS.into_iter().enumerate() {
            let s = self.ports[&p];
            assert_eq!(s.bridge.id, 6);
            assert_eq!(s.learning.source_learning_disabled, i >= 4);
            assert_eq!(s.learning.destination_lookup_disabled, i > 4);
            assert_eq!(s.vlan_key, [0; 7]);
            if i < 4 {
                let a = s.bridge.ingress_vlan;
                let b = s.bridge.egress_vlan;
                assert_eq!((a.0, a.2, b.0, b.2), (true, 3, true, 10));
                assert_eq!(self.blocks[&a.1].1.len(), 3);
                assert_eq!(self.blocks[&b.1].1.len(), 10);
            }
        }
    }
    fn restored(&self) {
        assert_eq!(self.ports, self.original);
    }
}
impl Backend for Model {
    fn fdb_find(&mut self, _id: u16, _mac: [u8; 6]) -> Result<Option<FdbEntry>, Error> {
        self.done(self.fdb)
    }
    fn fdb_add(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error> {
        assert!(self.fdb.is_none());
        self.fdb = Some(FdbEntry {
            fid: id,
            port: 9,
            map: [0x200, 0, 0, 0, 0, 0, 0, 0],
            mac,
            static_entry: true,
            sub_interface: 0,
            filter: 0,
            igmp: false,
            associated: [0; 6],
            tci: 0,
        });
        self.done(())
    }
    fn fdb_remove(&mut self, id: u16, mac: [u8; 6]) -> Result<(), Error> {
        assert!(self.fdb.unwrap().gateway(id, mac));
        assert!(self.ports.values().all(|p| p.bridge.id != id));
        self.fdb = None;
        self.done(())
    }

    fn qualify(&mut self) -> Result<(), Error> {
        self.done(())
    }
    fn read(&mut self, p: u16) -> Result<Snapshot, Error> {
        self.done(self.ports[&p])
    }
    fn domain_alloc(&mut self) -> Result<u16, Error> {
        self.domains.push(6);
        self.done(6)
    }
    fn domain_set(&mut self, id: u16) -> Result<(), Error> {
        assert_eq!(id, 6);
        self.done(())
    }
    fn domain_free(&mut self, id: u16) -> Result<(), Error> {
        assert!(self.ports.values().all(|p| p.bridge.id != id));
        assert!(self.fdb.is_none());
        assert_eq!(self.domains.pop(), Some(id));
        self.frees += 1;
        self.done(())
    }
    fn alloc(&mut self, count: u16) -> Result<Allocation, Error> {
        let id = self.next;
        self.next += 16;
        assert!(self
            .blocks
            .insert(id, (count, std::vec::Vec::new()))
            .is_none());
        let c = count.to_le_bytes();
        let b = id.to_le_bytes();
        self.done([c[0], c[1], b[0], b[1]])
    }
    fn rule(&mut self, id: u16, index: u16, r: Rule) -> Result<(), Error> {
        let (count, rules) = self.blocks.get_mut(&id).unwrap();
        assert_eq!(rules.len(), index as usize);
        assert!(index < *count);
        rules.push(r);
        self.done(())
    }
    fn free(&mut self, a: Allocation) -> Result<(), Error> {
        let id = block(a);
        assert!(self
            .ports
            .values()
            .all(|p| p.bridge.ingress_vlan.1 != id && p.bridge.egress_vlan.1 != id));
        assert!(self.blocks.remove(&id).is_some());
        self.frees += 1;
        self.done(())
    }
    fn map(&mut self, p: u16, m: [u16; 8]) -> Result<(), Error> {
        if m != map(0) {
            self.ready_to_open();
        }
        assert!(PORTS.contains(&p));
        self.ports.get_mut(&p).unwrap().bridge.map = m;
        self.done(())
    }
    fn identity(
        &mut self,
        p: u16,
        id: u16,
        lookup: bool,
        learn: bool,
        key: [u8; 7],
    ) -> Result<(), Error> {
        self.quarantined();
        let s = self.ports.get_mut(&p).unwrap();
        s.bridge.id = id;
        s.learning.destination_lookup_disabled = lookup;
        s.learning.source_learning_disabled = learn;
        s.vlan_key = key;
        self.done(())
    }
    fn binding(&mut self, p: u16, ingress: bool, value: (bool, u16, u16)) -> Result<(), Error> {
        self.quarantined();
        let s = self.ports.get_mut(&p).unwrap();
        if ingress {
            s.bridge.ingress_vlan = value;
        } else {
            s.bridge.egress_vlan = value;
        }
        self.done(())
    }
}

#[test]
fn common_domain_learning_maps_and_complete_restore() {
    let mut hw = Model::new();
    let mut lease = LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2]);
    lease.acquire(&mut hw).unwrap();
    assert!(lease.active());
    assert_eq!(lease.domain(), Some(6));
    for p in 1..=4 {
        assert_eq!(hw.ports[&p].bridge.map, map(0x21e & !(1 << p)));
    }
    assert_eq!(hw.ports[&17].bridge.map, map(0x1e));
    for p in 18..=20 {
        assert_eq!(hw.ports[&p].bridge.map, map(1 << (p - 16)));
    }
    for p in [9, 13, 29] {
        assert_eq!(hw.ports[&p], hw.original[&p]);
    }
    assert_eq!(lease.acquire(&mut hw), Err(Error::InvalidState));
    lease.restore(&mut hw).unwrap();
    hw.restored();
    assert!(lease.released() && !lease.active());
    assert!(hw.blocks.is_empty() && hw.domains.is_empty());
    assert_eq!(hw.frees, 6);
    assert_eq!(lease.restore(&mut hw), Err(Error::InvalidState));
}

#[test]
fn every_acquire_failure_retains_authority_to_restore_without_freeing_references() {
    let mut complete = Model::new();
    LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2])
        .acquire(&mut complete)
        .unwrap();
    for fault in 1..=complete.calls {
        let mut hw = Model::new();
        hw.fail_at = fault;
        let mut lease = LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2]);
        assert_eq!(
            lease.acquire(&mut hw),
            Err(Error::CompletionTimeout),
            "fault {fault}"
        );
        assert!(!lease.active());
        hw.fail_at = usize::MAX;
        lease.restore(&mut hw).unwrap();
        hw.restored();
        // A timed-out allocation can leave one unknown UNBOUND resource.
        assert!(hw.blocks.len() + hw.domains.len() <= 1);
    }
}

#[test]
fn every_restore_failure_keeps_resources_until_detached_and_never_retries_free() {
    let mut complete = Model::new();
    let mut lease = LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2]);
    lease.acquire(&mut complete).unwrap();
    let begin = complete.calls;
    lease.restore(&mut complete).unwrap();
    let operations = complete.calls - begin;
    for offset in 1..=operations {
        let mut hw = Model::new();
        let mut lease = LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2]);
        lease.acquire(&mut hw).unwrap();
        hw.fail_at = hw.calls + offset;
        assert_eq!(lease.restore(&mut hw), Err(Error::CompletionTimeout));
        hw.fail_at = usize::MAX;
        if lease.free_attempted {
            hw.restored();
            let freed = hw.frees;
            assert_eq!(lease.restore(&mut hw), Err(Error::InvalidState));
            assert_eq!(hw.frees, freed);
        } else {
            assert_eq!(hw.frees, 0);
            lease.restore(&mut hw).unwrap();
            hw.restored();
            assert!(hw.blocks.is_empty());
        }
    }
}

#[test]
fn shared_egress_accepts_each_real_copper_source_but_not_sfp_or_other_vids() {
    let mut hw = Model::new();
    let mut lease = LanBridgeLease::new([2, 0x42, 0x70, 4, 0, 2]);
    lease.acquire(&mut hw).unwrap();
    let rules = &hw.blocks[&block(lease.allocations[4].unwrap())].1;
    for vid in [0xc00u16, 0xc01, 0xc02, 0xc03, 0xc0c, 1, 0xfff] {
        for tagged in [false, true] {
            let expected_filter = if tagged { 1u32 } else { 3u32 };
            let matched = rules
                .iter()
                .find(|r| {
                    let b = r.encode(0, 0);
                    let word = |o| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
                    word(31) == expected_filter
                        && (word(9) == 2 || b[18] == 1 && word(19) == vid as u32)
                })
                .unwrap()
                .encode(0, 0);
            assert_eq!(
                matched[57],
                if (0xc00..=0xc03).contains(&vid) { 1 } else { 3 }
            );
        }
    }
}

#[test]
fn invalid_gateway_mac_never_reaches_hardware() {
    for mac in [[0; 6], [0xff; 6], [1, 0, 0, 0, 0, 1]] {
        let mut hw = Model::new();
        let mut lease = LanBridgeLease::new(mac);
        assert_eq!(lease.acquire(&mut hw), Err(Error::InvalidState));
        assert_eq!(hw.calls, 0);
        lease.restore(&mut hw).unwrap();
        assert!(lease.released());
        assert_eq!(hw.calls, 0);
    }
}

#[test]
fn untagged_access_profile_keeps_bridge_maps_and_restores_all_bindings() {
    let mut hw = Model::new();
    let mut lease = LanBridgeLease::new_untagged([2, 0x42, 0x70, 4, 0, 2]);
    assert!(!lease.untagged_only());
    lease.acquire(&mut hw).unwrap();
    assert!(lease.untagged_only());
    for p in 1..=4 {
        let state = hw.ports[&p];
        assert_eq!(state.bridge.map, map(0x21e & !(1 << p)));
        let rules = &hw.blocks[&state.bridge.ingress_vlan.1].1;
        assert!(matches!(rules[0], Rule::PushUntagged(_)));
        assert!(matches!(rules[1], Rule::DropAnyDoubleTagged));
        assert!(matches!(rules[2], Rule::DropAnySingleTagged));
    }
    lease.restore(&mut hw).unwrap();
    assert!(!lease.untagged_only());
    hw.restored();
    assert!(hw.blocks.is_empty() && hw.domains.is_empty());
}

#[test]
fn untagged_access_acquisition_faults_restore_before_free() {
    let mut complete = Model::new();
    LanBridgeLease::new_untagged([2, 0x42, 0x70, 4, 0, 2])
        .acquire(&mut complete).unwrap();
    for fault in 1..=complete.calls {
        let mut hw = Model::new();
        hw.fail_at = fault;
        let mut lease = LanBridgeLease::new_untagged([2, 0x42, 0x70, 4, 0, 2]);
        assert_eq!(lease.acquire(&mut hw), Err(Error::CompletionTimeout), "fault {fault}");
        assert!(!lease.untagged_only());
        hw.fail_at = usize::MAX;
        lease.restore(&mut hw).unwrap();
        hw.restored();
        assert!(hw.blocks.len() + hw.domains.len() <= 1);
    }
}
