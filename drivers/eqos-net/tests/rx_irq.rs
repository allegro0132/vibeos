use vibeos_eqos_net::{mdio::Registers, rx_irq::*};
#[derive(Default)]
struct Model {
    enabled: u32,
    status: u32,
    arrive_on_arm: bool,
    acks: Vec<u32>,
}
impl Registers for Model {
    fn read(&mut self, offset: usize) -> u32 {
        match offset {
            ENABLE => self.enabled,
            STATUS => self.status,
            _ => panic!("unknown register"),
        }
    }
    fn write(&mut self, offset: usize, value: u32) {
        match offset {
            ENABLE => {
                self.enabled = value;
                if self.arrive_on_arm && value & (1 << 6) != 0 {
                    self.status |= 1 << 6;
                }
            }
            STATUS => {
                self.acks.push(value);
                self.status &= !value;
            }
            _ => panic!("unknown register"),
        }
    }
}
#[test]
fn watchdog_interval_is_rounded_up_without_overflow_or_clamping() {
    assert_eq!(watchdog_ticks(198_000_000, 100), Some(78));
    assert_eq!(watchdog_ticks(198_000_000, 1), Some(1));
    assert_eq!(watchdog_ticks(198_000_000, 0), Some(0));
    assert_eq!(watchdog_ticks(198_000_000, 330), None);
    assert_eq!(watchdog_ticks(0, 1), None);
    assert_eq!(watchdog_ticks(u64::MAX, u32::MAX), None);
}
#[test]
fn arrival_during_arm_retains_event_and_keeps_polling() {
    let mut io = Model {
        enabled: 1,
        arrive_on_arm: true,
        ..Default::default()
    };
    assert!(!arm_and_check(&mut io, Revision::Gmac410OrLater));
    assert_eq!(io.enabled & 1, 1);
    assert_eq!(io.enabled & (1 << 6), 0);
    assert_eq!(io.status, 1 << 6);
    assert!(io.acks.is_empty());
}
#[test]
fn acknowledging_rx_preserves_tx_and_fatal_fault_evidence() {
    let tx_and_fatal = 1 | (1 << 2) | (1 << 12) | (1 << 14);
    let rx = (1 << 6) | (1 << 7) | (1 << 15);
    let mut io = Model {
        enabled: 1 | (1 << 6) | (1 << 15),
        status: tx_and_fatal | rx,
        ..Default::default()
    };
    assert_eq!(mask_and_acknowledge(&mut io), tx_and_fatal | rx);
    assert_eq!(io.status, tx_and_fatal);
    assert_eq!(io.enabled, 1 | (1 << 15));
    assert!(!arm_and_check(&mut io, Revision::Gmac410OrLater));
    assert_eq!(io.status, tx_and_fatal);
}
#[test]
fn summary_enable_encoding_depends_on_core_revision() {
    for (revision, summary) in [
        (Revision::Gmac400, 1 << 16),
        (Revision::Gmac410OrLater, 1 << 15),
    ] {
        let mut io = Model::default();
        assert!(arm_and_check(&mut io, revision));
        assert_eq!(io.enabled, summary | (1 << 6));
    }
}
