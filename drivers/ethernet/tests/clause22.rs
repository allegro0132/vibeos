//! Host transaction models cannot qualify live MDIO timing or PHY wiring.
use std::collections::VecDeque;
use vibeos_ethernet::{read, status, write, Error, MdioPort};

#[derive(Default)]
struct Port {
    busy: VecDeque<bool>,
    data: VecDeque<u16>,
    commands: Vec<(u8, u8, Option<u16>)>,
    polls: usize,
}
impl MdioPort for Port {
    fn busy(&mut self) -> bool {
        self.polls += 1;
        self.busy.pop_front().unwrap_or(false)
    }
    fn start_read(&mut self, phy: u8, reg: u8) {
        self.commands.push((phy, reg, None));
    }
    fn start_write(&mut self, phy: u8, reg: u8, val: u16) {
        self.commands.push((phy, reg, Some(val)));
    }
    fn data(&mut self) -> u16 {
        self.data.pop_front().expect("unexpected data read")
    }
}

#[test]
fn clears_latched_status_and_rejects_floating_bus() {
    let mut p = Port {
        data: [0, 0x24, 0x24, 0xffff].into(),
        ..Port::default()
    };
    let s = status(&mut p, 3, 2).unwrap();
    assert!(s.link_up() && s.autoneg_complete());
    assert_eq!(status(&mut p, 3, 2), Err(Error::InvalidResponse));
    assert_eq!(p.commands, vec![(3, 1, None); 4]);
}

#[test]
fn timeout_before_command_does_not_publish() {
    let mut p = Port {
        busy: [true; 3].into(),
        ..Port::default()
    };
    assert_eq!(write(&mut p, 0, 2, 99, 3), Err(Error::TimedOut));
    assert_eq!(p.polls, 3);
    assert!(p.commands.is_empty());
}

#[test]
fn timeout_after_write_does_not_retry_or_read_data() {
    let mut p = Port {
        busy: [false, true, true, true].into(),
        ..Port::default()
    };
    assert_eq!(write(&mut p, 31, 31, 0x1234, 3), Err(Error::TimedOut));
    assert_eq!(p.commands, [(31, 31, Some(0x1234))]);
    assert_eq!(p.polls, 4);
}

#[test]
fn last_poll_can_complete_but_never_reads_data_while_busy() {
    let mut p = Port {
        busy: [true, false, true, false].into(),
        data: [0xbeef].into(),
        ..Port::default()
    };
    assert_eq!(read(&mut p, 1, 2, 2), Ok(0xbeef));
    assert_eq!(p.commands, [(1, 2, None)]);
    assert_eq!(p.polls, 4);
}

#[test]
fn invalid_parameters_do_not_touch_hardware() {
    let mut p = Port::default();
    assert_eq!(read(&mut p, 32, 0, 2), Err(Error::InvalidAddress));
    assert_eq!(write(&mut p, 0, 32, 0, 2), Err(Error::InvalidAddress));
    assert_eq!(read(&mut p, 0, 0, 0), Err(Error::InvalidBudget));
    assert_eq!(p.polls, 0);
    assert!(p.commands.is_empty());
}
