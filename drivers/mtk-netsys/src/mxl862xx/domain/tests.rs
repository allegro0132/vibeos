extern crate std;
use super::*;
use crate::mdio;

struct Mock {
    regs: [u16; 96],
    policy: [u8; 49],
    commands: std::vec::Vec<u16>,
    allocated: bool,
    allocation: u16,
    fail: Option<u16>,
    ignore_set: bool,
    bad_reply: bool,
    learning: [u8; 186],
}
impl Mock {
    fn new() -> Self {
        Self {
            regs: [0; 96],
            policy: DomainPolicy {
                learning_limit: None,
                flood: [FloodMode::Members; 4],
            }
            .request(7)
            .unwrap(),
            commands: std::vec::Vec::new(),
            allocated: false,
            allocation: 7,
            fail: None,
            ignore_set: false,
            bad_reply: false,
            learning: [0; 186],
        }
    }
    fn reply(&mut self, b: &[u8]) {
        for (i, pair) in b.chunks(2).enumerate() {
            self.regs[2 + i] = u16::from_le_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        }
    }
}
impl Io for Mock {
    fn now(&self) -> u64 {
        0
    }
    fn read(&mut self, reg: u16) -> Result<u16, mdio::Error> {
        Ok(self.regs[reg as usize])
    }
    fn write(&mut self, reg: u16, value: u16) -> Result<(), mdio::Error> {
        self.regs[reg as usize] = value;
        if reg != 0 {
            return Ok(());
        }
        let cmd = value & 0x7fff;
        self.commands.push(cmd);
        self.regs[0] = cmd;
        if self.fail == Some(cmd) {
            self.regs[1] = (-7i16) as u16;
            return Ok(());
        }
        let len = self.regs[1] as usize;
        let mut b = [0; 188];
        for i in 0..len {
            b[i] = self.regs[2 + i / 2].to_le_bytes()[i % 2];
        }
        self.regs[1] = 0;
        match cmd {
            0x1902 => self.reply(&[1, 0, 70, 0, 70, 0, 0, 0]),
            0x0403 => {
                assert_eq!(len, 186);
                let port = u16::from_le_bytes([b[0], b[1]]);
                assert!(PORTS.contains(&port));
                let mask = u32::from_le_bytes(b[2..6].try_into().unwrap());
                if mask == 0x19800 {
                    b[..186].copy_from_slice(&self.learning);
                } else {
                    assert_eq!(mask, 0x187);
                    b.fill(0);
                    b[6] = 2;
                }
                b[..2].copy_from_slice(&port.to_le_bytes());
                self.reply(&b[..186]);
            }
            0x0301 => {
                assert_eq!(len, 2);
                assert!(!self.allocated);
                self.allocated = true;
                self.reply(&self.allocation.to_le_bytes());
            }
            0x0302 | 0x0303 => {
                assert!(self.allocated);
                assert_eq!(len, 49);
                assert_eq!(&b[..6], &[7, 0, 17, 0, 0, 0]);
                if cmd == 0x0302 {
                    // All unmasked fields and odd-byte padding stay zero.
                    assert!(b[9..33].iter().all(|v| *v == 0));
                    assert_eq!(self.regs[26] >> 8, 0);
                    if !self.ignore_set {
                        self.policy.copy_from_slice(&b[..49]);
                    }
                } else {
                    let mut reply = self.policy;
                    if self.bad_reply {
                        reply[33] = 3;
                    }
                    self.reply(&reply);
                }
            }
            0x0304 => {
                assert_eq!(len, 2);
                assert_eq!(&b[..2], &[7, 0]);
                assert!(self.allocated);
                self.allocated = false;
            }
            _ => panic!("probe must not write a live port: {cmd:x}"),
        }
        Ok(())
    }
}

#[test]
fn allocation_policy_readback_and_single_release_without_port_writes() {
    let mut io = Mock::new();
    let report = Mailbox::new(&mut io, 10).probe_bridge_domain().unwrap();
    assert_eq!(
        (
            report.id,
            report.verified,
            report.failure,
            report.cleanup_error
        ),
        (7, 2, None, None)
    );
    assert!(!io.allocated);
    assert_eq!(io.commands.iter().filter(|c| **c == 0x0304).count(), 1);
    assert_eq!(
        DomainPolicy::decode(7, &io.policy).unwrap(),
        DomainPolicy {
            learning_limit: Some(254),
            flood: [FloodMode::Members; 4]
        }
    );
}

#[test]
fn never_touch_reserved_or_inherited_allocation_ids() {
    for id in [0, 2, u16::MAX] {
        let mut io = Mock::new();
        io.allocation = id;
        assert!(matches!(
            Mailbox::new(&mut io, 10).probe_bridge_domain(),
            Err(Error::InvalidResponse)
        ));
        assert!(!io
            .commands
            .iter()
            .any(|c| matches!(c, 0x0302 | 0x0303 | 0x0304)));
    }
    let mut io = Mock::new();
    io.fail = Some(0x0301);
    assert!(matches!(
        Mailbox::new(&mut io, 10).probe_bridge_domain(),
        Err(Error::Firmware(-7))
    ));
    assert_eq!(io.commands.iter().filter(|c| **c == 0x0301).count(), 1);
    assert!(!io.commands.contains(&0x0304));
}

#[test]
fn failures_stop_exercise_and_report_cleanup_separately() {
    for command in [0x0302, 0x0303, 0x0304] {
        let mut io = Mock::new();
        io.fail = Some(command);
        let report = Mailbox::new(&mut io, 10).probe_bridge_domain().unwrap();
        if command == 0x0304 {
            assert_eq!(report.cleanup_error, Some(Error::Firmware(-7)));
            assert!(io.allocated);
        } else {
            assert_eq!(report.failure, Some(Error::Firmware(-7)));
            assert_eq!(report.verified, 0);
            assert!(!io.allocated);
        }
        assert_eq!(io.commands.iter().filter(|c| **c == command).count(), 1);
    }
    for bad_decode in [false, true] {
        let mut io = Mock::new();
        io.ignore_set = !bad_decode;
        io.bad_reply = bad_decode;
        let report = Mailbox::new(&mut io, 10).probe_bridge_domain().unwrap();
        assert_eq!(
            report.failure,
            Some(if bad_decode {
                Error::InvalidResponse
            } else {
                Error::ReadbackMismatch
            })
        );
        assert!(!io.allocated);
    }
}

#[test]
fn learning_offsets_and_invalid_flags() {
    let mut io = Mock::new();
    io.learning[149] = 1;
    io.learning[150] = 1;
    io.learning[153] = 1;
    io.learning[154..156].copy_from_slice(&1024u16.to_le_bytes());
    io.learning[158..160].copy_from_slice(&513u16.to_le_bytes());
    assert_eq!(
        Mailbox::new(&mut io, 10).port_learning(17).unwrap(),
        Learning {
            destination_lookup_disabled: true,
            source_learning_disabled: true,
            limit: Some(1024),
            learned: 513
        }
    );
    io.learning[150] = 2;
    assert_eq!(
        Mailbox::new(&mut io, 10).port_learning(1),
        Err(Error::InvalidResponse)
    );
    assert_eq!(
        Mailbox::new(&mut io, 10).port_learning(8),
        Err(Error::InvalidPort)
    );
}

#[test]
fn reject_learning_limit_truncation_before_wire_encoding() {
    let policy = DomainPolicy {
        learning_limit: Some(1024),
        flood: [FloodMode::Members; 4],
    };
    assert_eq!(policy.request(7), Err(Error::InvalidState));
    assert_eq!(
        DomainPolicy {
            learning_limit: Some(255),
            ..policy
        }
        .request(7),
        Err(Error::InvalidState)
    );
    let encoded = DomainPolicy {
        learning_limit: Some(254),
        ..policy
    }
    .request(7)
    .unwrap();
    assert_eq!(&encoded[7..9], &[0xfe, 0]);
}
