//! Build the tagged CPU paths from the observed untagged reset configuration.
//! No switch/PHY reset, CTP reassignment or firmware reload is performed.
use super::{Bridge, BridgePortLease, Error, Io, Mailbox};
use crate::{mxl_tag::Port, mxl_vlan::Rule};
const PHYSICAL: [u16; 6] = [1, 2, 3, 4, 9, 13];
const COUNTS: [u16; 7] = [3, 3, 3, 3, 10, 11, 3];
#[derive(Debug)]
pub struct ColdLanLease {
    started: bool,
    changed: bool,
    active: bool,
    released: bool,
    free_attempted: bool,
    ambiguous_allocation: bool,
    previous: [Option<Bridge>; 6],
    aliases: [BridgePortLease; 13],
    blocks: [Option<[u8; 4]>; 7],
}
impl ColdLanLease {
    pub fn new() -> Self {
        Self {
            started: false,
            changed: false,
            active: false,
            released: false,
            free_attempted: false,
            ambiguous_allocation: false,
            previous: [None; 6],
            aliases: core::array::from_fn(|_| BridgePortLease::new()),
            blocks: [None; 7],
        }
    }
    pub fn active(&self) -> bool {
        self.active
    }
    pub fn released(&self) -> bool {
        self.released
    }
    fn block(&self, i: usize) -> u16 {
        let b = self.blocks[i].unwrap();
        u16::from_le_bytes([b[2], b[3]])
    }
}
impl Default for ColdLanLease {
    fn default() -> Self {
        Self::new()
    }
}
impl<I: Io> Mailbox<'_, I> {
    fn cold_map(&mut self, port: u16, map: [u16; 8]) -> Result<(), Error> {
        let mut b = [0; 186];
        b[..2].copy_from_slice(&port.to_le_bytes());
        b[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        for (i, v) in map.iter().enumerate() {
            b[131 + i * 2..133 + i * 2].copy_from_slice(&v.to_le_bytes());
        }
        self.execute(0x402, &mut b, false)?;
        self.query(0x403, &mut b)?;
        if b[..2] != port.to_le_bytes()
            || (0..8).any(|i| u16::from_le_bytes([b[131 + i * 2], b[132 + i * 2]]) != map[i])
        {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    fn cold_rule(&mut self, block: u16, index: u16, rule: Rule) -> Result<(), Error> {
        self.execute(0xb02, &mut rule.encode(block, index), false)?;
        if !rule.matches(&self.vlan_rule(block, index)?) {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    /// The caller must retain the lease even on failure and keep GMAC3 TX
    /// disabled until this bootstrap AND the LAN bridge owner are active.
    pub fn initialize_cold_lan(&mut self, l: &mut ColdLanLease) -> Result<(), Error> {
        if l.started {
            return Err(Error::InvalidState);
        }
        l.started = true;
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        for (i, p) in PHYSICAL.iter().enumerate() {
            let old = self.bridge(*p)?;
            if old.destination != *p as u8
                || old.id != 0
                || old.ingress_vlan.0
                || old.egress_vlan.0
                || old.map[1..].iter().any(|x| *x != 0)
            {
                return Err(Error::InvalidState);
            }
            l.previous[i] = Some(old);
        }
        // CPU logical port already exists in the reset configuration. Preserve
        // its CTP assignment; only bridge/VLAN state is changed below.
        for (i, a) in l.aliases.iter_mut().enumerate() {
            let id = match self.allocate_bridge_port(a) {
                Ok(id) => id,
                Err(e) => {
                    l.ambiguous_allocation |= a.uncertain_allocation();
                    return Err(e);
                }
            };
            if id != 17 + i as u16 {
                // Unexpected allocation identity cannot authorize rollback frees.
                l.free_attempted = true;
                return Err(Error::InvalidResponse);
            }
        }
        for (i, count) in COUNTS.iter().enumerate() {
            let mut b = [0; 4];
            b[..2].copy_from_slice(&count.to_le_bytes());
            if let Err(e) = self.query(0xb01, &mut b) {
                l.ambiguous_allocation = true;
                return Err(e);
            }
            let id = u16::from_le_bytes([b[2], b[3]]);
            if id == u16::MAX || l.blocks.iter().flatten().any(|a| a[2..] == b[2..]) {
                return Err(Error::InvalidResponse);
            }
            l.blocks[i] = Some(b);
            if u16::from_le_bytes([b[0], b[1]]) < *count {
                return Err(Error::InvalidResponse);
            }
        }
        for i in 0..4 {
            let p = Port::from_dt(i as u8).unwrap();
            for (j, r) in [
                Rule::PushUntagged(p),
                Rule::PushSingleTagged(p),
                Rule::PushDoubleTagged(p),
            ]
            .into_iter()
            .enumerate()
            {
                self.cold_rule(l.block(i), j as u16, r)?;
            }
            self.cold_rule(l.block(4), i as u16 * 2, Rule::PopOuter(p))?;
            self.cold_rule(l.block(4), i as u16 * 2 + 1, Rule::PopOuterTagged(p))?;
            self.cold_rule(l.block(5), i as u16 * 2, Rule::ClassifyCpuTagged(p))?;
            self.cold_rule(l.block(5), i as u16 * 2 + 1, Rule::ClassifyCpu(p))?;
        }
        for (i, r) in [Rule::DropDoubleTagged, Rule::DropSingleTagged]
            .into_iter()
            .enumerate()
        {
            self.cold_rule(l.block(4), 8 + i as u16, r)?;
            self.cold_rule(l.block(5), 8 + i as u16, r)?;
        }
        self.cold_rule(l.block(5), 10, Rule::DropUntagged)?;
        for (i, r) in [
            Rule::KeepDoubleTagged,
            Rule::KeepSingleTagged,
            Rule::DropUntagged,
        ]
        .into_iter()
        .enumerate()
        {
            self.cold_rule(l.block(6), i as u16, r)?;
        }
        // All resources are prepared before publishing a single binding.
        l.changed = true;
        for p in PHYSICAL {
            self.cold_map(p, [0; 8])?;
        }
        for p in [17u16, 18, 19, 20, 29] {
            let mut b = [0; 186];
            b[..2].copy_from_slice(&p.to_le_bytes());
            b[2..6].copy_from_slice(&0x1881u32.to_le_bytes());
            b[47] = 9;
            b[149] = 1;
            b[150] = 1;
            self.execute(0x402, &mut b, false)?;
            let got = self.bridge(p)?;
            let learning = self.port_learning(p)?;
            if got.id != 0
                || got.destination != 9
                || got.map != [0; 8]
                || !learning.destination_lookup_disabled
                || !learning.source_learning_disabled
            {
                return Err(Error::ReadbackMismatch);
            }
        }
        for i in 0..4 {
            self.set_binding(i as u16 + 1, true, (true, l.block(i), 3))?;
            self.set_binding(i as u16 + 1, false, (true, l.block(4), 10))?;
        }
        self.set_binding(9, true, (true, l.block(5), 11))?;
        self.set_binding(9, false, (true, l.block(6), 3))?;
        for i in 0..4 {
            self.cold_map(i + 1, bits(0x200))?;
            self.cold_map(i + 17, bits(1 << (i + 1)))?;
        }
        self.cold_map(9, bits(0x1e))?;
        for i in 0..4 {
            if !self.verify_port_path(Port::from_dt(i).unwrap())? {
                return Err(Error::ReadbackMismatch);
            }
        }
        l.active = true;
        Ok(())
    }
    /// Invoke only after the later LAN owner has detached/restored its lease.
    /// Restore all original bindings before releasing aliases or VLAN blocks.
    pub fn restore_cold_lan(&mut self, l: &mut ColdLanLease) -> Result<(), Error> {
        if !l.started || l.released || l.free_attempted {
            return Err(Error::InvalidState);
        }
        l.active = false;
        if l.changed {
            for p in PHYSICAL {
                self.cold_map(p, [0; 8])?;
            }
            for a in &l.aliases {
                if let Some(id) = a.id() {
                    self.cold_map(id, [0; 8])?;
                }
            }
            for (i, p) in PHYSICAL.iter().enumerate() {
                let old = l.previous[i].ok_or(Error::InvalidState)?;
                self.set_binding(*p, true, old.ingress_vlan)?;
                self.set_binding(*p, false, old.egress_vlan)?;
            }
            for (i, p) in PHYSICAL.iter().enumerate() {
                self.cold_map(*p, l.previous[i].unwrap().map)?;
            }
        }
        // Never retry any resource release after an ambiguous completion.
        l.free_attempted = true;
        for b in l.blocks.iter_mut().rev() {
            if let Some(mut allocation) = *b {
                self.execute(0xb04, &mut allocation, false)?;
                *b = None;
            }
        }
        for a in l.aliases.iter_mut().rev() {
            if a.id().is_some() {
                self.release_bridge_port(a)?;
            }
        }
        if l.ambiguous_allocation {
            return Err(Error::InvalidState);
        }
        l.released = true;
        Ok(())
    }
}
fn bits(v: u16) -> [u16; 8] {
    [v, 0, 0, 0, 0, 0, 0, 0]
}
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    struct Model {
        regs: [u16; 96],
        staged: [u8; 188],
        reply: [u8; 564],
        ports: BTreeMap<u16, [u8; 186]>,
        blocks: BTreeMap<u16, u16>,
        rules: BTreeMap<(u16, u16), [u8; 193]>,
        next_alias: u16,
        next_block: u16,
        calls: usize,
        fail: Option<usize>,
        after_write: bool,
        trace: std::vec::Vec<u16>,
    }
    impl Model {
        fn new() -> Self {
            let mut m = Self {
                regs: [0; 96],
                staged: [0; 188],
                reply: [0; 564],
                ports: BTreeMap::new(),
                blocks: BTreeMap::new(),
                rules: BTreeMap::new(),
                next_alias: 17,
                next_block: 100,
                calls: 0,
                fail: None,
                after_write: false,
                trace: std::vec::Vec::new(),
            };
            for p in PHYSICAL {
                let mut b = [0; 186];
                b[..2].copy_from_slice(&p.to_le_bytes());
                b[47] = p as u8;
                b[131..133].copy_from_slice(&(if p == 9 { 2u16 } else { 0x200u16 }).to_le_bytes());
                m.ports.insert(p, b);
            }
            m
        }
        fn window(&self) -> [u8; 188] {
            let mut b = [0; 188];
            for (i, r) in self.regs[2..].iter().enumerate() {
                b[i * 2..i * 2 + 2].copy_from_slice(&r.to_le_bytes());
            }
            b
        }
        fn response(&mut self, off: usize) {
            for i in 0..94 {
                self.regs[2 + i] =
                    u16::from_le_bytes([self.reply[off + i * 2], self.reply[off + i * 2 + 1]]);
            }
        }
    }
    impl Io for Model {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, r: u16) -> Result<u16, crate::mdio::Error> {
            Ok(self.regs[r as usize])
        }
        fn write(&mut self, r: u16, v: u16) -> Result<(), crate::mdio::Error> {
            self.regs[r as usize] = v;
            if r != 0 || v & 0x8000 == 0 {
                return Ok(());
            }
            let cmd = v & 0x7fff;
            let size = self.regs[1] as usize;
            self.regs[0] = cmd;
            self.regs[1] = 0;
            if cmd == 2 {
                self.staged = self.window();
                return Ok(());
            }
            if cmd == 6 {
                self.response(188);
                return Ok(());
            }
            self.calls += 1;
            self.trace.push(cmd);
            let failing = self.fail == Some(self.calls);
            if failing && !self.after_write {
                self.regs[1] = 65535;
                return Ok(());
            }
            let mut b = [0; 564];
            let window = self.window();
            if size > 188 {
                b[..188].copy_from_slice(&self.staged);
                b[188..size].copy_from_slice(&window[..size - 188]);
            } else {
                b[..size].copy_from_slice(&window[..size]);
            }
            let id = u16::from_le_bytes([b[0], b[1]]);
            match cmd {
                0x1902 => b[..8].copy_from_slice(&[1, 0, 70, 0, 70, 0, 0, 0]),
                0x401 => {
                    let id = self.next_alias;
                    self.next_alias += 1;
                    let mut p = [0; 186];
                    p[..2].copy_from_slice(&id.to_le_bytes());
                    self.ports.insert(id, p);
                    b[..2].copy_from_slice(&id.to_le_bytes());
                }
                0x402 => {
                    let mask = u32::from_le_bytes(b[2..6].try_into().unwrap());
                    let p = self.ports.get_mut(&id).unwrap();
                    for (bit, range) in [
                        (1, 6..8),
                        (2, 8..13),
                        (4, 13..18),
                        (0x80, 47..50),
                        (0x100, 131..147),
                        (0x1800, 149..151),
                    ] {
                        if mask & bit != 0 {
                            p[range.clone()].copy_from_slice(&b[range]);
                        }
                    }
                }
                0x403 => b[..186].copy_from_slice(self.ports.get(&id).unwrap()),
                0x404 => {
                    assert!(
                        self.ports.values().all(|p| p[8] == 0 && p[13] == 0),
                        "free alias before detaching VLAN references"
                    );
                    assert!(id >= 17);
                    self.ports.remove(&id).unwrap();
                }
                0xb01 => {
                    let block = self.next_block;
                    self.next_block += 1;
                    self.blocks.insert(block, id);
                    b[2..4].copy_from_slice(&block.to_le_bytes());
                }
                0xb02 => {
                    let index = u16::from_le_bytes([b[2], b[3]]);
                    assert!(index < self.blocks[&id]);
                    self.rules.insert((id, index), b[..193].try_into().unwrap());
                }
                0xb03 => {
                    let index = u16::from_le_bytes([b[2], b[3]]);
                    b[..193].copy_from_slice(&self.rules[&(id, index)]);
                }
                0xb04 => {
                    let block = u16::from_le_bytes([b[2], b[3]]);
                    for p in self.ports.values() {
                        for off in [8, 13] {
                            assert!(
                                p[off] == 0
                                    || u16::from_le_bytes([p[off + 1], p[off + 2]]) != block,
                                "free referenced VLAN block"
                            );
                        }
                    }
                    self.blocks.remove(&block).unwrap();
                    self.rules.retain(|(bid, _), _| *bid != block);
                }
                _ => panic!("unexpected command {cmd:x}"),
            }
            self.reply = b;
            self.response(0);
            if failing {
                self.regs[1] = 65535;
            }
            Ok(())
        }
    }
    #[test]
    fn cold_setup_and_reverse_restore_preserve_reset_state() {
        let mut m = Model::new();
        let before = m.ports.clone();
        let mut l = ColdLanLease::new();
        Mailbox::new(&mut m, 10)
            .initialize_cold_lan(&mut l)
            .unwrap();
        assert!(l.active());
        assert_eq!(m.ports.len(), 19);
        assert_eq!(m.blocks.len(), 7);
        Mailbox::new(&mut m, 10).restore_cold_lan(&mut l).unwrap();
        assert!(l.released());
        assert_eq!(m.ports, before);
        assert!(m.blocks.is_empty());
    }
    #[test]
    fn every_acquire_error_retains_cleanup_authority() {
        let mut good = Model::new();
        let mut l = ColdLanLease::new();
        Mailbox::new(&mut good, 10)
            .initialize_cold_lan(&mut l)
            .unwrap();
        for fail in 1..=good.calls {
            let mut m = Model::new();
            let before = m.ports.clone();
            m.fail = Some(fail);
            let mut l = ColdLanLease::new();
            assert!(
                Mailbox::new(&mut m, 10)
                    .initialize_cold_lan(&mut l)
                    .is_err(),
                "{fail}"
            );
            m.fail = None;
            let restored = Mailbox::new(&mut m, 10).restore_cold_lan(&mut l);
            if l.ambiguous_allocation {
                assert_eq!(restored, Err(Error::InvalidState));
                assert!(!l.released());
            } else {
                restored.unwrap();
            }
            assert_eq!(m.ports, before, "failure {fail}");
            assert!(m.blocks.is_empty());
        }
    }
    #[test]
    fn unexpected_reset_state_is_not_overwritten() {
        for (offset, value) in [(8, 1), (13, 1), (6, 1), (133, 2), (47, 7)] {
            let mut m = Model::new();
            m.ports.get_mut(&1).unwrap()[offset] = value;
            let before = m.ports.clone();
            let mut l = ColdLanLease::new();
            assert_eq!(
                Mailbox::new(&mut m, 10).initialize_cold_lan(&mut l),
                Err(Error::InvalidState)
            );
            Mailbox::new(&mut m, 10).restore_cold_lan(&mut l).unwrap();
            assert_eq!(m.ports, before);
            assert!(m.blocks.is_empty());
        }
    }
    #[test]
    fn applied_write_failures_are_detached_before_free() {
        let mut good = Model::new();
        let mut l = ColdLanLease::new();
        Mailbox::new(&mut good, 10)
            .initialize_cold_lan(&mut l)
            .unwrap();
        for (i, cmd) in good
            .trace
            .iter()
            .enumerate()
            .filter(|(_, cmd)| matches!(cmd, 0x402 | 0xb02))
        {
            let mut m = Model::new();
            let before = m.ports.clone();
            m.fail = Some(i + 1);
            m.after_write = true;
            let mut l = ColdLanLease::new();
            assert!(
                Mailbox::new(&mut m, 10)
                    .initialize_cold_lan(&mut l)
                    .is_err(),
                "{i} {cmd:x}"
            );
            m.fail = None;
            Mailbox::new(&mut m, 10).restore_cold_lan(&mut l).unwrap();
            assert_eq!(m.ports, before);
            assert!(m.blocks.is_empty());
        }
    }
    #[test]
    fn every_restore_failure_keeps_referenced_resources_and_fences_ambiguous_frees() {
        let mut good = Model::new();
        let mut l = ColdLanLease::new();
        Mailbox::new(&mut good, 10)
            .initialize_cold_lan(&mut l)
            .unwrap();
        let base = good.calls;
        Mailbox::new(&mut good, 10)
            .restore_cold_lan(&mut l)
            .unwrap();
        let end = good.calls;
        for fail in base + 1..=end {
            let mut m = Model::new();
            let before = m.ports.clone();
            let mut l = ColdLanLease::new();
            Mailbox::new(&mut m, 10)
                .initialize_cold_lan(&mut l)
                .unwrap();
            m.fail = Some(fail);
            assert!(Mailbox::new(&mut m, 10).restore_cold_lan(&mut l).is_err());
            assert!(!l.active());
            assert!(!l.released());
            m.fail = None;
            if l.free_attempted {
                assert_eq!(
                    Mailbox::new(&mut m, 10).restore_cold_lan(&mut l),
                    Err(Error::InvalidState)
                );
            } else {
                Mailbox::new(&mut m, 10).restore_cold_lan(&mut l).unwrap();
                assert_eq!(m.ports, before);
                assert!(m.blocks.is_empty());
            }
        }
    }
    #[test]
    fn unexpected_alias_number_requires_reboot_without_freeing_guessed_ids() {
        let mut m = Model::new();
        m.next_alias = 18;
        let mut l = ColdLanLease::new();
        assert_eq!(
            Mailbox::new(&mut m, 10).initialize_cold_lan(&mut l),
            Err(Error::InvalidResponse)
        );
        assert_eq!(
            Mailbox::new(&mut m, 10).restore_cold_lan(&mut l),
            Err(Error::InvalidState)
        );
        assert!(m.ports.contains_key(&18));
    }
    #[test]
    fn lost_allocation_reply_does_not_claim_complete_cleanup() {
        let mut good = Model::new();
        let mut l = ColdLanLease::new();
        Mailbox::new(&mut good, 10)
            .initialize_cold_lan(&mut l)
            .unwrap();
        for (i, _) in good
            .trace
            .iter()
            .enumerate()
            .filter(|(_, cmd)| matches!(cmd, 0x401 | 0xb01))
        {
            let mut m = Model::new();
            let mut l = ColdLanLease::new();
            m.fail = Some(i + 1);
            m.after_write = true;
            assert!(Mailbox::new(&mut m, 10)
                .initialize_cold_lan(&mut l)
                .is_err());
            m.fail = None;
            // Model retains the unknown resource. Known unattached resources
            // are reclaimed, but the lost ID must require reset, not guessing.
            let result = Mailbox::new(&mut m, 10).restore_cold_lan(&mut l);
            assert_eq!(result, Err(Error::InvalidState));
            assert!(!l.released());
        }
    }
}
