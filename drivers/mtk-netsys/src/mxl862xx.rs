//! MxL862xx diagnostics and constrained isolation, C45 address 16, MMD 30.
//! Wire ABI: MaxLinear/Linux mxl862xx-host.c, -api.h and -cmd.h,
//! BPI-Router-Linux ccaea3d9c05167978e003fbfaf3ac4a5a65e4ad9.
//! Exclusive ownership spans the whole mailbox transaction, not each MDIO op.
use crate::mdio;
mod alias;
pub use alias::BridgePortLease;
mod binding;
mod domain;
mod fdb;
pub use fdb::FdbEntry;
mod lan;
pub use binding::PortVlanLease;
pub use domain::{DomainPolicy, DomainProbe, FloodMode, Learning};
pub use lan::LanBridgeLease;

pub trait Io {
    fn read(&mut self, reg: u16) -> Result<u16, mdio::Error>;
    fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error>;
    fn now(&self) -> u64;
}

fn cpu_classifies_port(rule: &VlanRule, port: crate::mxl_tag::Port, single: bool) -> bool {
    !rule.original_packet
        && rule.outer_filter == 0
        && rule.match_vid_enabled
        && rule.match_vid == port.vid() as u32
        && matches!(rule.filter_tpid, 0 | 1)
        && (if single {
            rule.inner_filter == 3
        } else {
            matches!(rule.inner_filter, 0 | 1)
        })
        && rule.reassign_bridge
        && rule.bridge_port == port.dt_index() as u16 + 17
        && rule.remove == 0
        && !rule.add_outer
        && !rule.extra_actions
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    struct Mock {
        words: [u16; 96],
        writes: std::vec::Vec<(u16, u16)>,
        ticks: Cell<u64>,
        stuck: bool,
        fail_write: Option<u16>,
        status: i16,
        reply: [u8; 30],
    }
    impl Mock {
        fn new() -> Self {
            let mut reply = [0; 30];
            reply[..8].copy_from_slice(&[1, 0, 70, 0, 70, 0, 0, 0]);
            Self {
                words: [0; 96],
                writes: std::vec::Vec::new(),
                ticks: Cell::new(0),
                stuck: false,
                fail_write: None,
                status: 0,
                reply,
            }
        }
    }
    impl Io for Mock {
        fn now(&self) -> u64 {
            let t = self.ticks.get();
            self.ticks.set(t.wrapping_add(1));
            t
        }
        fn read(&mut self, reg: u16) -> Result<u16, mdio::Error> {
            Ok(self.words[reg as usize])
        }
        fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error> {
            self.writes.push((reg, value));
            if self.fail_write == Some(reg) {
                return Err(mdio::Error::CompletionTimeout);
            }
            self.words[reg as usize] = value;
            if reg == 0 && !self.stuck {
                self.words[0] &= 0x7fff;
                self.words[1] = self.status as u16;
                for (i, p) in self.reply.chunks_exact(2).enumerate() {
                    self.words[2 + i] = u16::from_le_bytes([p[0], p[1]]);
                }
            }
            Ok(())
        }
    }
    #[test]
    fn version_wire_bytes_and_single_submission() {
        let mut io = Mock::new();
        let v = Mailbox::new(&mut io, 10).version().unwrap();
        assert_eq!(
            v,
            Version {
                major: 1,
                minor: 0,
                revision: 70,
                build: 70
            }
        );
        assert_eq!(
            io.writes,
            [(2, 0), (3, 0), (4, 0), (5, 0), (1, 8), (0, 0x9902)]
        );
    }
    #[test]
    fn failures_stop_before_submission_or_do_not_retry() {
        let mut io = Mock::new();
        io.words[0] = 0x8000;
        io.ticks.set(u64::MAX - 4);
        assert_eq!(Mailbox::new(&mut io, 10).version(), Err(Error::BusyTimeout));
        assert!(io.writes.is_empty());
        io.words[0] = 0;
        io.fail_write = Some(3);
        assert_eq!(
            Mailbox::new(&mut io, 10).version(),
            Err(Error::Mdio(mdio::Error::CompletionTimeout))
        );
        assert_eq!(io.writes, [(2, 0), (3, 0)]);
        io.writes.clear();
        io.fail_write = None;
        io.stuck = true;
        assert_eq!(
            Mailbox::new(&mut io, 10).version(),
            Err(Error::CompletionTimeout)
        );
        assert_eq!(io.writes.iter().filter(|(r, _)| *r == 0).count(), 1);
    }
    #[test]
    fn firmware_failure_and_empty_reply_are_not_versions() {
        let mut io = Mock::new();
        io.status = -5;
        assert_eq!(
            Mailbox::new(&mut io, 10).version(),
            Err(Error::Firmware(-5))
        );
        io.status = 0;
        io.reply.fill(0);
        assert_eq!(
            Mailbox::new(&mut io, 10).version(),
            Err(Error::InvalidResponse)
        );
    }
    #[test]
    fn packed_unaligned_port_fields_and_address_validation() {
        let mut io = Mock::new();
        io.reply.fill(0);
        io.reply[0] = 9;
        io.reply[8] = 6;
        let mut m = Mailbox::new(&mut io, 10);
        assert_eq!(
            m.link(9),
            Ok(Link {
                state: 0,
                duplex: 0,
                speed_mbps: Some(10000)
            })
        );
        assert_eq!(io.writes[0], (2, 9));
        assert_eq!(io.writes[15], (1, 30));
        io.writes.clear();
        assert_eq!(Mailbox::new(&mut io, 10).link(0), Err(Error::InvalidPort));
        assert!(io.writes.is_empty());
        io.reply[13] = 255;
        assert_eq!(
            Mailbox::new(&mut io, 10).link(9),
            Err(Error::InvalidResponse)
        );
    }

    struct VlanMock {
        regs: [u16; 96],
        scratch: [u8; 564],
        page: usize,
        rules: [[[u8; 193]; 4]; 2],
        live: [bool; 2],
        egress: (bool, u16, u16),
        allocated: bool,
        released: bool,
        commands: std::vec::Vec<u16>,
        fail_set: Option<usize>,
        sets: usize,
        fail_free: bool,
        bad_readback: bool,
        ingress: (bool, u16, u16),
        map: u16,
        binding_sets: usize,
        ignore_binding_set: Option<usize>,
    }
    impl VlanMock {
        fn new() -> Self {
            Self {
                regs: [0; 96],
                scratch: [0; 564],
                page: 0,
                rules: [[[0; 193]; 4]; 2],
                live: [false; 2],
                egress: (true, 162, 75),
                allocated: false,
                released: false,
                commands: std::vec::Vec::new(),
                fail_set: None,
                sets: 0,
                fail_free: false,
                bad_readback: false,
                ingress: (true, 85, 77),
                map: 0x200,
                binding_sets: 0,
                ignore_binding_set: None,
            }
        }
        fn capture(&mut self) {
            for i in 0..94 {
                self.scratch[self.page * 188 + i * 2..self.page * 188 + i * 2 + 2]
                    .copy_from_slice(&self.regs[2 + i].to_le_bytes());
            }
        }
        fn respond(&mut self, page: usize) {
            for i in 0..94 {
                let off = page * 188 + i * 2;
                self.regs[2 + i] = u16::from_le_bytes([self.scratch[off], self.scratch[off + 1]]);
            }
        }
    }
    impl Io for VlanMock {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, r: u16) -> Result<u16, mdio::Error> {
            Ok(self.regs[r as usize])
        }
        fn write(&mut self, r: u16, v: u16) -> Result<(), mdio::Error> {
            self.regs[r as usize] = v;
            if r != 0 {
                return Ok(());
            }
            let cmd = v & 0x7fff;
            self.commands.push(cmd);
            let mut status = 0;
            match cmd {
                2 => {
                    self.capture();
                    self.page = 1;
                }
                6 => self.respond(1),
                0x1902 => {
                    self.scratch.fill(0);
                    self.scratch[..8].copy_from_slice(&[1, 0, 70, 0, 70, 0, 0, 0]);
                    self.respond(0);
                }
                0x0b01 => {
                    let slot = self
                        .live
                        .iter()
                        .position(|v| !*v)
                        .expect("allocation slots");
                    self.live[slot] = true;
                    assert_eq!(self.regs[1], 4);
                    assert!(matches!(self.regs[2], 3 | 4));
                    self.allocated = true;
                    self.regs[3] = 900 + slot as u16 * 4;
                }
                0x0b02 | 0x0b03 => {
                    assert!(self.allocated);
                    assert_eq!(self.regs[1], 193);
                    self.capture();
                    self.page = 0;
                    let block = u16::from_le_bytes([self.scratch[0], self.scratch[1]]);
                    assert!(matches!(block, 900 | 904));
                    let slot = ((block - 900) / 4) as usize;
                    assert!(self.live[slot]);
                    let index = u16::from_le_bytes([self.scratch[2], self.scratch[3]]) as usize;
                    assert!(index < 4);
                    if cmd == 0x0b02 {
                        self.sets += 1;
                        if self.fail_set == Some(self.sets) {
                            status = 0xfffb;
                        } else {
                            self.rules[slot][index].copy_from_slice(&self.scratch[..193]);
                        }
                    } else {
                        self.scratch[..193].copy_from_slice(&self.rules[slot][index]);
                        if self.bad_readback {
                            self.scratch[65] ^= 1;
                        }
                        self.respond(0);
                    }
                }
                0x0402 => {
                    assert_eq!(self.regs[1], 186);
                    self.capture();
                    assert_eq!(self.scratch[0], 1);
                    let mask = u32::from_le_bytes(self.scratch[2..6].try_into().unwrap());
                    match mask {
                        0x100 => {
                            self.map = u16::from_le_bytes([self.scratch[131], self.scratch[132]]);
                        }
                        2 | 4 => {
                            assert_eq!(self.map, 0, "binding changes require quarantine");
                            self.binding_sets += 1;
                            if self.ignore_binding_set != Some(self.binding_sets) {
                                let off = if mask == 2 { 8 } else { 13 };
                                let binding = (
                                    self.scratch[off] != 0,
                                    u16::from_le_bytes([
                                        self.scratch[off + 1],
                                        self.scratch[off + 2],
                                    ]),
                                    u16::from_le_bytes([
                                        self.scratch[off + 3],
                                        self.scratch[off + 4],
                                    ]),
                                );
                                if mask == 2 {
                                    self.ingress = binding;
                                } else {
                                    self.egress = binding;
                                }
                            }
                        }
                        _ => panic!("unexpected binding mask"),
                    }
                }
                0x0403 => {
                    assert_eq!(self.regs[2], 1);
                    self.scratch.fill(0);
                    self.scratch[0] = 1;
                    self.scratch[6] = 2;
                    self.scratch[47] = 1;
                    self.scratch[8] = u8::from(self.ingress.0);
                    self.scratch[9..11].copy_from_slice(&self.ingress.1.to_le_bytes());
                    self.scratch[11..13].copy_from_slice(&self.ingress.2.to_le_bytes());
                    self.scratch[13] = u8::from(self.egress.0);
                    self.scratch[14..16].copy_from_slice(&self.egress.1.to_le_bytes());
                    self.scratch[16..18].copy_from_slice(&self.egress.2.to_le_bytes());
                    self.scratch[131..133].copy_from_slice(&self.map.to_le_bytes());
                    self.respond(0);
                }
                0x0b04 => {
                    let block = self.regs[3];
                    let slot = ((block - 900) / 4) as usize;
                    assert!(matches!(block, 900 | 904) && self.live[slot]);
                    assert_ne!(self.ingress.1, block, "never free a referenced block");
                    assert_ne!(self.egress.1, block, "never free a referenced block");
                    assert!(self.allocated);
                    assert_eq!(self.regs[1], 4);
                    if self.fail_free {
                        status = 0xfff9;
                    } else {
                        self.live[slot] = false;
                        self.allocated = self.live.iter().any(|v| *v);
                        self.released = !self.allocated;
                    }
                }
                _ => panic!("unexpected command (must never attach a probe block): {cmd:x}"),
            }
            self.regs[0] = cmd;
            self.regs[1] = status;
            Ok(())
        }
    }
    #[test]
    fn unattached_vlan_probe_verifies_four_rules_and_releases() {
        let mut io = VlanMock::new();
        let r = Mailbox::new(&mut io, 10).probe_vlan_rules().unwrap();
        assert_eq!(
            (r.block, r.verified, r.failure, r.cleanup_error),
            (900, 4, None, None)
        );
        assert!(io.released && !io.allocated);
        assert_eq!(io.commands.iter().filter(|c| **c == 0x0b04).count(), 1);
    }
    #[test]
    fn vlan_probe_stops_on_failure_and_reports_cleanup_failure_separately() {
        for failed in 1..=4 {
            let mut io = VlanMock::new();
            io.fail_set = Some(failed);
            let r = Mailbox::new(&mut io, 10).probe_vlan_rules().unwrap();
            assert_eq!(r.failure, Some(Error::Firmware(-5)));
            assert_eq!(r.verified, failed as u8 - 1);
            assert!(io.released);
            assert_eq!(io.sets, failed);
        }
        let mut io = VlanMock::new();
        io.bad_readback = true;
        io.fail_free = true;
        let r = Mailbox::new(&mut io, 10).probe_vlan_rules().unwrap();
        assert_eq!(r.failure, Some(Error::ReadbackMismatch));
        assert_eq!(r.cleanup_error, Some(Error::Firmware(-7)));
        assert_eq!(r.verified, 0);
        assert!(io.allocated && !io.released);
        assert_eq!(io.commands.iter().filter(|c| **c == 0x0b04).count(), 1);
    }

    #[test]
    fn owned_ingress_stays_bound_until_explicit_restore() {
        let mut io = VlanMock::new();
        let mut lease = PortVlanLease::new(crate::mxl_tag::Port::Copper0);
        Mailbox::new(&mut io, 10)
            .own_port_vlans(&mut lease)
            .unwrap();
        assert!(lease.active());
        assert_eq!(lease.block(), Some(900));
        assert_eq!(io.ingress, (true, 900, 3));
        assert_eq!(io.map, 0x200);
        assert!(io.allocated);
        Mailbox::new(&mut io, 10)
            .restore_port_vlans(&mut lease)
            .unwrap();
        assert!(lease.released() && !lease.active());
        assert!(io.released);
        assert_eq!(io.ingress, (true, 85, 77));
        assert_eq!(io.map, 0x200);
    }
    #[test]
    fn failed_binding_and_restore_never_free_referenced_resources() {
        let mut io = VlanMock::new();
        io.ignore_binding_set = Some(1);
        let mut lease = PortVlanLease::new(crate::mxl_tag::Port::Copper0);
        assert_eq!(
            Mailbox::new(&mut io, 10).own_port_vlans(&mut lease),
            Err(Error::ReadbackMismatch)
        );
        assert_eq!(io.map, 0);
        assert!(io.allocated && !io.released);
        Mailbox::new(&mut io, 10)
            .restore_port_vlans(&mut lease)
            .unwrap();
        assert!(io.released);
        let mut io = VlanMock::new();
        let mut lease = PortVlanLease::new(crate::mxl_tag::Port::Copper0);
        Mailbox::new(&mut io, 10)
            .own_port_vlans(&mut lease)
            .unwrap();
        io.ignore_binding_set = Some(3);
        assert_eq!(
            Mailbox::new(&mut io, 10).restore_port_vlans(&mut lease),
            Err(Error::ReadbackMismatch)
        );
        assert!(io.allocated && !io.released);
        assert_eq!(io.map, 0);
        assert_eq!(io.ingress.1, 900);
        Mailbox::new(&mut io, 10)
            .restore_port_vlans(&mut lease)
            .unwrap();
        assert!(io.released);
    }
    #[test]
    fn failed_rule_programming_can_release_without_changing_binding() {
        for failure in 1..=7 {
            let mut io = VlanMock::new();
            io.fail_set = Some(failure);
            let mut lease = PortVlanLease::new(crate::mxl_tag::Port::Copper0);
            assert_eq!(
                Mailbox::new(&mut io, 10).own_port_vlans(&mut lease),
                Err(Error::Firmware(-5))
            );
            assert_eq!(io.ingress, (true, 85, 77));
            assert_eq!(io.map, 0x200);
            Mailbox::new(&mut io, 10)
                .restore_port_vlans(&mut lease)
                .unwrap();
            assert!(io.released);
        }
        let mut io = VlanMock::new();
        let mut lease = PortVlanLease::new(crate::mxl_tag::Port::Copper0);
        Mailbox::new(&mut io, 10)
            .own_port_vlans(&mut lease)
            .unwrap();
        io.fail_free = true;
        assert_eq!(
            Mailbox::new(&mut io, 10).restore_port_vlans(&mut lease),
            Err(Error::Firmware(-7))
        );
        assert_eq!(
            Mailbox::new(&mut io, 10).restore_port_vlans(&mut lease),
            Err(Error::InvalidState)
        );
        assert_eq!(io.commands.iter().filter(|c| **c == 0x0b04).count(), 1);
    }

    struct RelayMock {
        regs: [u16; 96],
        values: [u16; 4],
        writes: std::vec::Vec<[u16; 3]>,
    }
    impl Io for RelayMock {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, r: u16) -> Result<u16, mdio::Error> {
            Ok(self.regs[r as usize])
        }
        fn write(&mut self, r: u16, v: u16) -> Result<(), mdio::Error> {
            self.regs[r as usize] = v;
            if r == 0 {
                let cmd = v & 0x7fff;
                assert_eq!(self.regs[1], 6);
                assert!(self.regs[3] < 4);
                match cmd {
                    0x1801 => {
                        self.regs[2] = match self.regs[4] {
                            2 => self.values[0],
                            3 => self.values[1],
                            0 => self.values[2],
                            1 => self.values[3],
                            _ => panic!("register"),
                        };
                    }
                    0x1802 => {
                        assert_eq!(self.regs[4], 0);
                        self.writes.push([self.regs[2], self.regs[3], self.regs[4]]);
                        self.values[2] = self.regs[2] & !0x200;
                    }
                    _ => panic!("command"),
                }
                self.regs[0] = cmd;
                self.regs[1] = 0;
            }
            Ok(())
        }
    }
    #[test]
    fn copper_powerup_is_identity_gated_and_preserves_speed_bits() {
        let mut io = RelayMock {
            regs: [0; 96],
            values: [0xc133, 0x5528, 0x3a40, 0x7949],
            writes: std::vec::Vec::new(),
        };
        assert_eq!(Mailbox::new(&mut io, 10).wake_copper(0).unwrap()[2], 0x3040);
        assert_eq!(io.writes, [[0x3240, 0, 0]]);
        Mailbox::new(&mut io, 10).wake_copper(0).unwrap();
        assert_eq!(io.writes.len(), 1);
        io.values[0] = 0;
        assert_eq!(
            Mailbox::new(&mut io, 10).wake_copper(0),
            Err(Error::InvalidResponse)
        );
        assert_eq!(
            Mailbox::new(&mut io, 10).wake_copper(4),
            Err(Error::InvalidPort)
        );
        assert_eq!(io.writes.len(), 1);
    }

    struct IsolationMock {
        regs: [u16; 96],
        maps: [[u16; 8]; 14],
        writes: std::vec::Vec<(u16, u16)>,
        ignore_set: Option<usize>,
        version: u16,
        gates: [u16; 2],
        gate_writes: usize,
        ignore_gate_write: bool,
    }
    impl IsolationMock {
        fn new() -> Self {
            Self {
                regs: [0; 96],
                maps: [[0xffff; 8]; 14],
                writes: std::vec::Vec::new(),
                ignore_set: None,
                version: 1,
                gates: [0x120, 0x340],
                gate_writes: 0,
                ignore_gate_write: false,
            }
        }
    }
    impl Io for IsolationMock {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, reg: u16) -> Result<u16, mdio::Error> {
            assert!(
                !(self.regs[0] == 0x402 && reg >= 2),
                "write command must not fetch a reply payload"
            );
            Ok(self.regs[reg as usize])
        }
        fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error> {
            self.regs[reg as usize] = value;
            if reg != 0 {
                return Ok(());
            }
            let command = value & 0x7fff;
            let mut bytes = [0; 188];
            for (i, pair) in bytes.chunks_exact_mut(2).enumerate() {
                pair.copy_from_slice(&self.regs[2 + i].to_le_bytes());
            }
            let port = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
            match command {
                0x101 | 0x111 => {
                    let index = match port {
                        0xbc6 => 0,
                        0xa86 => 1,
                        _ => panic!("gate address"),
                    };
                    if command == 0x111 {
                        assert_eq!(self.regs[1], 6);
                        assert_eq!(&bytes[2..6], &[1, 0, 1, 0]);
                        self.gate_writes += 1;
                        if !self.ignore_gate_write {
                            self.gates[index] |= 1;
                        }
                    } else {
                        assert_eq!(self.regs[1], 4);
                        bytes[2..4].copy_from_slice(&self.gates[index].to_le_bytes());
                    }
                }
                0x1902 => {
                    bytes.fill(0);
                    bytes[..2].copy_from_slice(&self.version.to_le_bytes());
                    bytes[2] = 70;
                    bytes[4] = 70;
                }
                0x402 => {
                    assert_eq!(self.regs[1], 186);
                    assert_eq!(u32::from_le_bytes(bytes[2..6].try_into().unwrap()), 0x100);
                    let map = u16::from_le_bytes([bytes[131], bytes[132]]);
                    assert!(matches!(port, 1..=4 | 13));
                    assert!(matches!(map, 0 | 0x200));
                    let mut expected = [0; 188];
                    expected[..6].copy_from_slice(&bytes[..6]);
                    expected[131..133].copy_from_slice(&bytes[131..133]);
                    assert_eq!(bytes, expected, "no field other than the map may change");
                    self.writes.push((port as u16, map));
                    if self.ignore_set != Some(self.writes.len()) {
                        self.maps[port] = [map, 0, 0, 0, 0, 0, 0, 0];
                    }
                }
                0x403 => {
                    bytes.fill(0);
                    bytes[..2].copy_from_slice(&(port as u16).to_le_bytes());
                    bytes[47] = port as u8;
                    for (i, map) in self.maps[port].iter().enumerate() {
                        bytes[131 + i * 2..133 + i * 2].copy_from_slice(&map.to_le_bytes());
                    }
                }
                _ => panic!("unexpected command"),
            }
            for (i, pair) in bytes.chunks_exact(2).enumerate() {
                self.regs[2 + i] = u16::from_le_bytes([pair[0], pair[1]]);
            }
            self.regs[0] = command;
            self.regs[1] = 0;
            Ok(())
        }
    }
    #[test]
    fn data_gates_require_isolation_preserve_bits_and_check_readback() {
        use crate::mxl_tag::Port;
        let mut io = IsolationMock::new();
        assert_eq!(
            Mailbox::new(&mut io, 10).enable_port_data(Port::Copper0),
            Err(Error::InvalidState)
        );
        assert_eq!(io.gate_writes, 0);
        io.maps[1] = [0x200, 0, 0, 0, 0, 0, 0, 0];
        Mailbox::new(&mut io, 10)
            .enable_port_data(Port::Copper0)
            .unwrap();
        assert_eq!(io.gates, [0x121, 0x341]);
        assert_eq!(io.gate_writes, 2);
        Mailbox::new(&mut io, 10)
            .enable_port_data(Port::Copper0)
            .unwrap();
        assert_eq!(io.gate_writes, 2);
        io.gates[0] &= !1;
        io.ignore_gate_write = true;
        assert_eq!(
            Mailbox::new(&mut io, 10).enable_port_data(Port::Copper0),
            Err(Error::ReadbackMismatch)
        );
        assert_eq!(io.gate_writes, 3);
    }

    #[test]
    fn isolation_quarantines_all_ports_before_allowing_cpu_only() {
        let mut io = IsolationMock::new();
        Mailbox::new(&mut io, 10).isolate_user_ports().unwrap();
        assert_eq!(
            io.writes,
            [
                (1, 0),
                (2, 0),
                (3, 0),
                (4, 0),
                (13, 0),
                (1, 0x200),
                (2, 0x200),
                (3, 0x200),
                (4, 0x200),
                (13, 0x200)
            ]
        );
        assert_eq!(
            io.maps[9], [0xffff; 8],
            "CPU bridge configuration must be untouched"
        );
    }
    #[test]
    fn isolation_stops_on_every_readback_failure_and_rejects_other_firmware() {
        for failed in 1..=10 {
            let mut io = IsolationMock::new();
            io.ignore_set = Some(failed);
            assert_eq!(
                Mailbox::new(&mut io, 10).isolate_user_ports(),
                Err(Error::ReadbackMismatch)
            );
            assert_eq!(
                io.writes.len(),
                failed,
                "no later write after failed verification"
            );
            if failed <= 5 {
                assert!(io.writes.iter().all(|(_, map)| *map == 0));
            }
        }
        let mut io = IsolationMock::new();
        io.version = 2;
        assert_eq!(
            Mailbox::new(&mut io, 10).isolate_user_ports(),
            Err(Error::UnsupportedFirmware)
        );
        assert!(io.writes.is_empty());
    }

    struct WindowMock {
        regs: [u16; 96],
        request: [u8; 564],
        response: [u8; 564],
        page: usize,
        commands: std::vec::Vec<u16>,
        fail_command: Option<u16>,
    }
    impl WindowMock {
        fn new() -> Self {
            Self {
                regs: [0; 96],
                request: [0; 564],
                response: core::array::from_fn(|i| (i * 7) as u8),
                page: 0,
                commands: std::vec::Vec::new(),
                fail_command: None,
            }
        }
        fn capture(&mut self) {
            for i in 0..94 {
                self.request[self.page * 188 + i * 2..self.page * 188 + i * 2 + 2]
                    .copy_from_slice(&self.regs[2 + i].to_le_bytes());
            }
        }
        fn respond(&mut self, page: usize) {
            for i in 0..94 {
                let off = page * 188 + i * 2;
                self.regs[2 + i] = u16::from_le_bytes([self.response[off], self.response[off + 1]]);
            }
        }
    }
    impl Io for WindowMock {
        fn now(&self) -> u64 {
            0
        }
        fn read(&mut self, reg: u16) -> Result<u16, mdio::Error> {
            Ok(self.regs[reg as usize])
        }
        fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error> {
            self.regs[reg as usize] = value;
            if reg == 0 {
                let command = value & 0x7fff;
                self.commands.push(command);
                if self.fail_command == Some(command) {
                    return Err(mdio::Error::CompletionTimeout);
                }
                match command {
                    2 | 3 => {
                        self.capture();
                        self.page += 1;
                    }
                    6 | 7 => self.respond((command - 5) as usize),
                    0x0b03 | 0x1703 => {
                        self.capture();
                        self.respond(0);
                        self.regs[1] = 0;
                    }
                    _ => panic!("unexpected command"),
                }
                self.regs[0] = command;
            }
            Ok(())
        }
    }
    #[test]
    fn cpu_classifier_rejects_other_ports_and_side_effects() {
        use crate::{mxl_tag::Port, mxl_vlan::Rule};
        for index in 0..4 {
            let port = Port::from_dt(index).unwrap();
            let mut io = WindowMock::new();
            io.response[..193].copy_from_slice(&Rule::ClassifyCpu(port).encode(0, 0));
            let rule = Mailbox::new(&mut io, 10).vlan_rule(0, 0).unwrap();
            assert!(cpu_classifies_port(&rule, port, true));
            assert!(!cpu_classifies_port(
                &rule,
                Port::from_dt((index + 1) % 4).unwrap(),
                true
            ));
            for field in 0..7 {
                let mut invalid = rule;
                match field {
                    0 => invalid.bridge_port += 1,
                    1 => invalid.match_vid_enabled = false,
                    2 => invalid.extra_actions = true,
                    3 => invalid.remove = 1,
                    4 => invalid.add_outer = true,
                    5 => invalid.filter_tpid = 2,
                    _ => invalid.original_packet = true,
                }
                assert!(!cpu_classifies_port(&invalid, port, true));
            }
            let mut tagged = rule;
            tagged.inner_filter = 1;
            assert!(cpu_classifies_port(&tagged, port, false));
            assert!(!cpu_classifies_port(&tagged, port, true));
        }
    }

    #[test]
    fn vlan_readback_checks_packet_stage_for_every_treatment() {
        use crate::{mxl_tag::Port, mxl_vlan::Rule};
        for treatment in [
            Rule::PushUntagged(Port::Copper0),
            Rule::PushSingleTagged(Port::Copper0),
            Rule::PushDoubleTagged(Port::Copper0),
            Rule::PopOuter(Port::Copper0),
            Rule::PopOuterTagged(Port::Copper0),
            Rule::ClassifyCpu(Port::Copper0),
            Rule::DropSingleTagged,
            Rule::DropDoubleTagged,
            Rule::DropAnySingleTagged,
            Rule::DropAnyDoubleTagged,
        ] {
            for stage in 0..=2 {
                let mut io = WindowMock::new();
                io.response[..193].copy_from_slice(&treatment.encode(0, 0));
                io.response[4] = stage;
                let result = Mailbox::new(&mut io, 10).vlan_rule(0, 0);
                if stage == 2 {
                    assert!(matches!(result, Err(Error::InvalidResponse)));
                } else {
                    let rule = result.unwrap();
                    assert_eq!(rule.original_packet, stage == 1);
                    assert_eq!(treatment.matches(&rule), stage == 0);
                }
            }
        }
    }

    #[test]
    fn physical_mac_counters_decode_unaligned_u64_and_validate_identity() {
        let mut io = WindowMock::new();
        io.response[0] = 9;
        for i in 0..17 {
            io.response[1 + i * 8..9 + i * 8]
                .copy_from_slice(&(0x1234567800000000u64 + i as u64).to_le_bytes());
        }
        let result = Mailbox::new(&mut io, 10).mac_counters(9).unwrap();
        assert_eq!(
            result,
            core::array::from_fn(|i| 0x1234567800000000u64 + i as u64)
        );
        assert_eq!(io.commands, [0x1703]);
        assert_eq!(io.request[0], 9);
        assert_eq!(&io.request[1..138], &[0; 137]);
        io.response[0] = 1;
        assert_eq!(
            Mailbox::new(&mut io, 10).mac_counters(9),
            Err(Error::InvalidResponse)
        );
        let calls = io.commands.len();
        assert_eq!(
            Mailbox::new(&mut io, 10).mac_counters(8),
            Err(Error::InvalidPort)
        );
        assert_eq!(io.commands.len(), calls);
        for port in 1..=4 {
            let mut io = WindowMock::new();
            io.response[0] = port;
            io.response[1..9].copy_from_slice(&(u64::from(port) << 40).to_le_bytes());
            let counts = Mailbox::new(&mut io, 10).mac_counters(port).unwrap();
            assert_eq!(counts[0], u64::from(port) << 40);
            assert_eq!(io.request[0], port);
            assert_eq!(io.commands, [0x1703]);
        }
    }

    #[test]
    fn mailbox_window_boundaries_and_odd_tail() {
        for size in [1, 187, 188, 189, 193, 376, 377, 564] {
            let mut io = WindowMock::new();
            let mut bytes: std::vec::Vec<u8> = (0..size).map(|i| (i * 11 + 3) as u8).collect();
            let request = bytes.clone();
            let expected = io.response[..size].to_vec();
            Mailbox::new(&mut io, 10).query(0x0b03, &mut bytes).unwrap();
            assert_eq!(bytes, expected, "response size={size}");
            assert_eq!(
                &io.request[..size],
                request.as_slice(),
                "request size={size}"
            );
            if size % 2 != 0 {
                assert_eq!(io.request[size], 0);
            }
            let pages = (size + 187) / 188;
            let commands: std::vec::Vec<u16> = (1..pages)
                .map(|p| 1 + p as u16)
                .chain(core::iter::once(0x0b03))
                .chain((1..pages).map(|p| 5 + p as u16))
                .collect();
            assert_eq!(io.commands, commands);
        }
    }
    #[test]
    fn failed_page_transfer_stops_before_following_commands() {
        for command in [2, 3, 0x0b03, 6, 7] {
            let mut io = WindowMock::new();
            io.fail_command = Some(command);
            assert_eq!(
                Mailbox::new(&mut io, 10).query(0x0b03, &mut [0; 564]),
                Err(Error::Mdio(mdio::Error::CompletionTimeout))
            );
            let all = [2, 3, 0x0b03, 6, 7];
            assert_eq!(
                io.commands,
                &all[..=all.iter().position(|c| *c == command).unwrap()]
            );
        }
    }
}
impl<I: mdio::Io> Io for mdio::Mdio<I> {
    fn read(&mut self, reg: u16) -> Result<u16, mdio::Error> {
        self.read_c45(16, 30, reg)
    }
    fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error> {
        self.write_c45(16, 30, reg, value)
    }
    fn now(&self) -> u64 {
        self.now()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Mdio(mdio::Error),
    BusyTimeout,
    CompletionTimeout,
    Firmware(i16),
    InvalidResponse,
    InvalidPort,
    UnsupportedFirmware,
    ReadbackMismatch,
    InvalidState,
}
impl From<mdio::Error> for Error {
    fn from(e: mdio::Error) -> Self {
        Self::Mdio(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub build: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    /// Firmware enum: 0 up, 1 down, 2 auto. A down link's speed is not negotiated.
    pub state: u32,
    pub speed_mbps: Option<u32>,
    /// Firmware enum: 0 full, 1 half, 2 auto.
    pub duplex: u32,
}

/// Port-map bit numbers are firmware bridge-port IDs, not board DT ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bridge {
    pub id: u16,
    pub destination: u8,
    pub map: [u16; 8],
    /// (enabled, block ID, block size)
    pub ingress_vlan: (bool, u16, u16),
    pub egress_vlan: (bool, u16, u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanRule {
    /// Match the original frame rather than the intermediate packet.
    pub original_packet: bool,
    pub outer_filter: u32,
    pub inner_filter: u32,
    pub match_vid: u32,
    pub match_vid_enabled: bool,
    pub filter_tpid: u32,
    pub outer_vid_mode: u32,
    pub outer_tpid: u32,
    pub outer_dei: u32,
    /// Actions outside the narrow rule builder (inner rewrite, DSCP/class/
    /// meter rewrite, loopback, MAC swap or mirroring) must stay disabled.
    pub extra_actions: bool,
    pub remove: u32,
    pub add_outer: bool,
    pub outer_vid: u32,
    pub reassign_bridge: bool,
    pub bridge_port: u16,
}

/// Allocation is never attached to a port by this probe. A failed cleanup
/// reports its block ID for diagnosis; success does not imply datapath proof.
#[derive(Debug)]
pub struct VlanProbe {
    pub block: u16,
    pub verified: u8,
    pub failure: Option<Error>,
    pub cleanup_error: Option<Error>,
}

pub struct Mailbox<'a, I: Io> {
    io: &'a mut I,
    timeout: u64,
}
impl<'a, I: Io> Mailbox<'a, I> {
    pub fn new(io: &'a mut I, timeout_ticks: u64) -> Self {
        assert!(timeout_ticks != 0);
        Self {
            io,
            timeout: timeout_ticks,
        }
    }
    fn wait(&mut self, error: Error) -> Result<u16, Error> {
        let start = self.io.now();
        loop {
            let ctrl = self.io.read(0)?;
            if ctrl & 0x8000 == 0 {
                return Ok(ctrl);
            }
            if self.io.now().wrapping_sub(start) >= self.timeout {
                return Err(error);
            }
            core::hint::spin_loop();
        }
    }
    fn submit(&mut self, command: u16, size: usize) -> Result<(), Error> {
        self.io.write(1, size as u16)?;
        self.io.write(0, command | 0x8000)?;
        if self.wait(Error::CompletionTimeout)? != command {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
    // At most three 188-byte windows. Odd payloads use a zero high byte in
    // the final request word; the response's unused high byte is discarded.
    // Scratch/page failure stops immediately. No command is auto-retried.
    fn query(&mut self, command: u16, bytes: &mut [u8]) -> Result<(), Error> {
        self.execute(command, bytes, true)
    }
    fn execute(&mut self, command: u16, bytes: &mut [u8], read_reply: bool) -> Result<(), Error> {
        assert!(!bytes.is_empty() && bytes.len() <= 564);
        self.wait(Error::BusyTimeout)?;
        for (page, chunk) in bytes.chunks(188).enumerate() {
            if page != 0 {
                self.submit(1 + page as u16, 188)?;
            }
            for (i, pair) in chunk.chunks(2).enumerate() {
                self.io.write(
                    2 + i as u16,
                    u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]),
                )?;
            }
        }
        self.submit(command, bytes.len())?;
        let status = self.io.read(1)? as i16;
        if status != 0 {
            return Err(Error::Firmware(status));
        }
        if !read_reply {
            return Ok(());
        }
        for (page, chunk) in bytes.chunks_mut(188).enumerate() {
            if page != 0 {
                self.submit(5 + page as u16, 188)?;
            }
            for (i, pair) in chunk.chunks_mut(2).enumerate() {
                let word = self.io.read(2 + i as u16)?.to_le_bytes();
                pair.copy_from_slice(&word[..pair.len()]);
            }
        }
        Ok(())
    }
    /// Take ownership of user-port bridge maps: quarantine all five first,
    /// then allow only CPU bridge port 9. Does not alter VLAN/CTP/PHY state.
    /// On any failure stop without retrying; callers must keep GMAC3 disabled.
    /// A failed operation may have changed hardware: never report atomicity.
    pub fn isolate_user_ports(&mut self) -> Result<(), Error> {
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        for enable in [false, true] {
            for port in [1, 2, 3, 4, 13] {
                self.set_user_map(port, enable)?;
            }
        }
        Ok(())
    }
    fn set_user_map(&mut self, port: u16, cpu_only: bool) -> Result<(), Error> {
        if !matches!(port, 1..=4 | 13) {
            return Err(Error::InvalidPort);
        }
        let mut bytes = [0; 186];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        // BRIDGE_PORT_MAP mask only. Zero fields outside the mask are ignored.
        bytes[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        let map = if cpu_only { 0x200u16 } else { 0 };
        bytes[131..133].copy_from_slice(&map.to_le_bytes());
        self.execute(0x0402, &mut bytes, false)?;
        if self.bridge(port)?.map != [map, 0, 0, 0, 0, 0, 0, 0] {
            return Err(Error::ReadbackMismatch);
        }
        Ok(())
    }
    /// Verify the inherited bidirectional path for one copper test port.
    /// This validates routing/tag identity, not ownership or cold initialization.
    pub fn verify_port_path(&mut self, port: crate::mxl_tag::Port) -> Result<bool, Error> {
        let index = port.dt_index();
        if index > 3 {
            return Err(Error::InvalidPort);
        }
        let physical = index as u16 + 1;
        let bridge = self.bridge(physical)?;
        let cpu = self.bridge(9)?;
        let virtual_cpu = self.bridge(physical + 16)?;
        if bridge.destination != physical as u8
            || bridge.map != [0x200, 0, 0, 0, 0, 0, 0, 0]
            || !bridge.ingress_vlan.0
            || bridge.ingress_vlan.2 < 3
            || !bridge.egress_vlan.0
            || cpu.destination != 9
            || cpu.map[0] & (1 << physical) == 0
            || !cpu.ingress_vlan.0
            || cpu.ingress_vlan.2 <= index as u16 * 2 + 1
            || !cpu.egress_vlan.0
            || virtual_cpu.id != bridge.id
            || virtual_cpu.destination != 9
            || virtual_cpu.map != [1 << physical, 0, 0, 0, 0, 0, 0, 0]
        {
            return Ok(false);
        }
        let ingress = self.vlan_rule(bridge.ingress_vlan.1, bridge.ingress_vlan.2 - 3)?;
        if !ingress.add_outer
            || ingress.outer_vid != port.vid() as u32
            || ingress.outer_vid_mode != 0
            || ingress.outer_tpid != 3
        {
            return Ok(false);
        }
        for i in 0..2 {
            let rule = self.vlan_rule(cpu.ingress_vlan.1, index as u16 * 2 + i)?;
            if !cpu_classifies_port(&rule, port, i == 1) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Read the bridge mapping and VLAN blocks needed to plan isolation.
    pub fn bridge(&mut self, port: u16) -> Result<Bridge, Error> {
        if !matches!(port, 1..=4 | 9 | 13 | 17..=20 | 29) {
            return Err(Error::InvalidPort);
        }
        let mut bytes = [0; 186];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        // Only ID, ingress/egress VLAN, destination and forwarding map fields.
        bytes[2..6].copy_from_slice(&0x187u32.to_le_bytes());
        self.query(0x0403, &mut bytes)?;
        let word = |off| u16::from_le_bytes([bytes[off], bytes[off + 1]]);
        if word(0) != port || bytes[8] > 1 || bytes[13] > 1 {
            return Err(Error::InvalidResponse);
        }
        let mut map = [0; 8];
        for (i, v) in map.iter_mut().enumerate() {
            *v = word(131 + i * 2);
        }
        Ok(Bridge {
            id: word(6),
            destination: bytes[47],
            map,
            ingress_vlan: (bytes[8] != 0, word(9), word(11)),
            egress_vlan: (bytes[13] != 0, word(14), word(16)),
        })
    }
    /// Fixed-size extended VLAN read, spanning two windows (193 bytes).
    pub fn vlan_rule(&mut self, block: u16, index: u16) -> Result<VlanRule, Error> {
        let mut bytes = [0; 193];
        bytes[..2].copy_from_slice(&block.to_le_bytes());
        bytes[2..4].copy_from_slice(&index.to_le_bytes());
        self.query(0x0b03, &mut bytes)?;
        let word = |off| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if bytes[..2] != block.to_le_bytes()
            || bytes[2..4] != index.to_le_bytes()
            || bytes[4] > 1
            || bytes[18] > 1
            || bytes[65] > 1
            || bytes[115] > 1
        {
            return Err(Error::InvalidResponse);
        }
        Ok(VlanRule {
            original_packet: bytes[4] != 0,
            outer_filter: word(9),
            inner_filter: word(31),
            match_vid: word(19),
            match_vid_enabled: bytes[18] != 0,
            filter_tpid: word(23),
            outer_vid_mode: word(74),
            outer_tpid: word(82),
            outer_dei: word(86),
            extra_actions: [90, 118, 121, 123, 190, 191, 192]
                .into_iter()
                .any(|i| bytes[i] != 0),
            remove: word(57),
            add_outer: bytes[65] != 0,
            outer_vid: word(78),
            reassign_bridge: bytes[115] != 0,
            bridge_port: u16::from_le_bytes([bytes[116], bytes[117]]),
        })
    }
    /// Exercise resource allocation, all required treatment families, two-window
    /// writes/readback and release without attaching the temporary block.
    /// Allocation timeout may leak an unknown block; it is never retried.
    pub fn probe_vlan_rules(&mut self) -> Result<VlanProbe, Error> {
        use crate::{mxl_tag::Port, mxl_vlan::Rule};
        let v = self.version()?;
        if (v.major, v.minor, v.revision, v.build) != (1, 0, 70, 70) {
            return Err(Error::UnsupportedFirmware);
        }
        let mut allocation = [4, 0, 0, 0];
        self.query(0x0b01, &mut allocation)?;
        let count = u16::from_le_bytes([allocation[0], allocation[1]]);
        let block = u16::from_le_bytes([allocation[2], allocation[3]]);
        if block == u16::MAX {
            return Err(Error::InvalidResponse);
        }
        let mut report = VlanProbe {
            block,
            verified: 0,
            failure: None,
            cleanup_error: None,
        };
        if count < 4 {
            report.failure = Some(Error::InvalidResponse);
        } else {
            let rules = [
                Rule::PushUntagged(Port::Copper0),
                Rule::PopOuter(Port::Copper0),
                Rule::ClassifyCpu(Port::Copper0),
                Rule::DropSingleTagged,
            ];
            for (index, rule) in rules.into_iter().enumerate() {
                let result = (|| {
                    self.execute(0x0b02, &mut rule.encode(block, index as u16), false)?;
                    if !rule.matches(&self.vlan_rule(block, index as u16)?) {
                        return Err(Error::ReadbackMismatch);
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    report.failure = Some(error);
                    break;
                }
                report.verified += 1;
            }
        }
        // FREE uses the same 4-byte allocation struct. The block was never
        // referenced by a bridge or CTP, even if SET completion was ambiguous.
        report.cleanup_error = self.execute(0x0b04, &mut allocation, false).err();
        Ok(report)
    }
    /// MxL internal PHY relay uses zero-based PHY index and MMD 0 for C22.
    pub fn copper_phy(&mut self, index: u8) -> Result<[u16; 4], Error> {
        if index > 3 {
            return Err(Error::InvalidPort);
        }
        let mut values = [0; 4];
        for (i, reg) in [2u16, 3, 0, 1, 1].into_iter().enumerate() {
            let mut data = [0, 0, index, 0, reg as u8, 0];
            self.query(0x1801, &mut data)?;
            values[i.min(3)] = u16::from_le_bytes([data[0], data[1]]);
        }
        Ok(values)
    }
    /// Power up only the attached board's identified copper PHY, preserving
    /// analog calibration and speed advertisement. Never assert PHY reset.
    pub fn wake_copper(&mut self, index: u8) -> Result<[u16; 4], Error> {
        let values = self.copper_phy(index)?;
        if values[..2] != [0xc133, 0x5528] {
            return Err(Error::InvalidResponse);
        }
        if values[2] & 0x1c00 != 0x1000 {
            let control = (values[2] & !0x0c00) | 0x1200;
            let [lo, hi] = control.to_le_bytes();
            self.execute(0x1802, &mut [lo, hi, index, 0, 0, 0], false)?;
            let after = self.copper_phy(index)?;
            if after[2] & 0x1c00 != 0x1000 {
                return Err(Error::ReadbackMismatch);
            }
            return Ok(after);
        }
        Ok(values)
    }
    /// Own the two per-port switch DMA enable bits; preserve all other bits.
    pub fn enable_port_data(&mut self, port: crate::mxl_tag::Port) -> Result<(), Error> {
        let physical = port.dt_index() as u16 + 1;
        if self.bridge(physical)?.map != [0x200, 0, 0, 0, 0, 0, 0, 0] {
            return Err(Error::InvalidState);
        }
        for address in [0x0bc0 + physical * 6, 0x0a80 + physical * 6] {
            let [lo, hi] = address.to_le_bytes();
            let mut before = [lo, hi, 0, 0];
            self.query(0x0101, &mut before)?;
            let old = u16::from_le_bytes([before[2], before[3]]);
            if old & 1 == 0 {
                self.execute(0x0111, &mut [lo, hi, 1, 0, 1, 0], false)?;
            }
            let mut after = [lo, hi, 0, 0];
            self.query(0x0101, &mut after)?;
            if u16::from_le_bytes([after[2], after[3]]) != old | 1 {
                return Err(Error::ReadbackMismatch);
            }
        }
        Ok(())
    }
    /// Read the SDK's packed physical-MAC counters. This optional command may
    /// be unsupported by older firmware; never substitutes for wire capture.
    pub fn mac_counters(&mut self, index: u8) -> Result<[u64; 17], Error> {
        if !matches!(index, 1..=4 | 9) {
            return Err(Error::InvalidPort);
        }
        let mut bytes = [0; 137];
        bytes[0] = index;
        self.query(0x1703, &mut bytes)?;
        if bytes[0] != index {
            return Err(Error::InvalidResponse);
        }
        let mut result = [0; 17];
        for (out, chunk) in result.iter_mut().zip(bytes[1..].chunks_exact(8)) {
            *out = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Ok(result)
    }
    /// CPU-port classifier inputs, read-only: assignment, special-tag mode,
    /// and selected CTP VLAN/bridge fields (packed firmware ABI).
    pub fn cpu_path(&mut self) -> Result<([u8; 11], [u8; 6], [u8; 31]), Error> {
        let mut assignment = [0; 11];
        assignment[0] = 9;
        self.query(0x0504, &mut assignment)?;
        let mut tag = [9, 15, 0, 0, 0, 0];
        self.query(0x1601, &mut tag)?;
        let mut ctp = [0; 151];
        ctp[0] = 9;
        ctp[3..7].copy_from_slice(&0x15u32.to_le_bytes());
        self.query(0x0506, &mut ctp)?;
        Ok((assignment, tag, ctp[..31].try_into().unwrap()))
    }
    /// Read data-path gates without changing port configuration.
    pub fn path_gates(&mut self, port: u16) -> Result<[u32; 3], Error> {
        if !matches!(port, 1 | 9) {
            return Err(Error::InvalidPort);
        }
        let mut result = [0; 3];
        for (i, address) in [0x0bc0 + port * 6, 0x0a80 + port * 6]
            .into_iter()
            .enumerate()
        {
            let mut bytes = [0; 4];
            bytes[..2].copy_from_slice(&address.to_le_bytes());
            self.query(0x0101, &mut bytes)?;
            result[i] = u16::from_le_bytes([bytes[2], bytes[3]]) as u32;
        }
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        self.query(0x0f01, &mut bytes)?;
        result[2] = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        Ok(result)
    }
    /// Non-clearing RMON diagnostic: [RX good, TX good, VLAN drop, filtered,
    /// RX dropped, TX dropped, RX FCS error], packed 242-byte ABI.
    /// Hardware currently returns zero: counting behavior is not qualified.
    pub fn counters(&mut self, port: u16, kind: u32) -> Result<[u32; 7], Error> {
        if !matches!(port, 1 | 9 | 17) || kind > 3 {
            return Err(Error::InvalidPort);
        }
        let mut bytes = [0; 242];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        bytes[2..6].copy_from_slice(&kind.to_le_bytes());
        self.query(0x0801, &mut bytes)?;
        if bytes[..2] != port.to_le_bytes() || bytes[2..6] != kind.to_le_bytes() {
            return Err(Error::InvalidResponse);
        }
        Ok([22, 94, 6, 66, 166, 158, 38]
            .map(|off| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())))
    }
    pub fn version(&mut self) -> Result<Version, Error> {
        let mut bytes = [0; 8];
        self.query(0x1902, &mut bytes)?;
        if bytes == [0; 8] || bytes == [255; 8] {
            return Err(Error::InvalidResponse);
        }
        Ok(Version {
            major: bytes[0],
            minor: bytes[1],
            revision: u16::from_le_bytes([bytes[2], bytes[3]]),
            build: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        })
    }
    /// Board DT ports 0..3, 8, 12 map to firmware ports 1..4, 9, 13.
    pub fn link(&mut self, port: u16) -> Result<Link, Error> {
        if !matches!(port, 1..=4 | 9 | 13) {
            return Err(Error::InvalidPort);
        }
        // Packed Linux ABI: u16, u8, enum32, u8, enum32, u8,
        // enum32 link, enum32 MII mode/type/clock, u8 LPI = 30 bytes.
        let mut bytes = [0; 30];
        bytes[..2].copy_from_slice(&port.to_le_bytes());
        self.query(0x0105, &mut bytes)?;
        let word = |off| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let duplex = word(3);
        let speed = word(8);
        let state = word(13);
        if u16::from_le_bytes([bytes[0], bytes[1]]) != port || duplex > 2 || speed > 7 || state > 2
        {
            return Err(Error::InvalidResponse);
        }
        Ok(Link {
            state,
            duplex,
            speed_mbps: [
                Some(10),
                Some(100),
                Some(200),
                Some(1000),
                Some(2500),
                Some(5000),
                Some(10000),
                None,
            ][speed as usize],
        })
    }
}
