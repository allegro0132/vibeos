//! Real Clause 22, EQoS transport and YT8531 code with register side effects
//! modeled on RV64. This is not a PHY timing or physical link qualification.
use vibeos_eqos_net::mdio::{Port, Registers};
use vibeos_ethernet::phy::{Error, Speed, Tuning, Yt8531};
pub(super) struct Model {
    registers: [u16; 32],
    extended: [u16; 3],
    selected: u16,
    data: u32,
    reset_stuck: bool,
    live: bool,
}
impl Model {
    fn new() -> Self {
        let mut registers = [0; 32];
        registers[2] = 0x4f51;
        registers[3] = 0xe91b;
        registers[1] = 0x24;
        registers[17] = 0xac00;
        Self {
            registers,
            extended: [0x0135, 0x0fcc, 0x8100],
            selected: 0,
            data: 0,
            reset_stuck: false,
            live: false,
        }
    }
    fn ext_index(&self) -> usize {
        match self.selected {
            0xa001 => 0,
            0xa010 => 1,
            0xa003 => 2,
            _ => panic!("unexpected PHY extended address"),
        }
    }
}
impl Registers for Model {
    fn read(&mut self, offset: usize) -> u32 {
        match offset {
            0x200 => 0,
            0x204 => self.data,
            _ => panic!("unexpected MDIO offset"),
        }
    }
    fn write(&mut self, offset: usize, value: u32) {
        if offset == 0x204 {
            self.data = value;
            return;
        }
        assert_eq!(offset, 0x200);
        assert_eq!((value >> 8) & 15, 4); // actual 198 MHz CSR selects divisor 102
        assert_eq!(value & 1, 1);
        let phy = (value >> 21) & 31;
        let reg = ((value >> 16) & 31) as usize;
        match (value >> 2) & 3 {
            3 => {
                self.data = if phy != 17 {
                    0xffff
                } else if self.live && reg == 1 {
                    if STATUS.load(core::sync::atomic::Ordering::Relaxed) == 0 {
                        0
                    } else {
                        0x24
                    }
                } else if self.live && reg == 17 {
                    STATUS.load(core::sync::atomic::Ordering::Relaxed)
                } else if reg == 31 {
                    u32::from(self.extended[self.ext_index()])
                } else {
                    u32::from(self.registers[reg])
                }
            }
            1 => {
                assert_eq!(phy, 17);
                let v = self.data as u16;
                match reg {
                    30 => self.selected = v,
                    31 => self.extended[self.ext_index()] = v,
                    0 if v & 0x8000 != 0 && !self.reset_stuck => self.registers[0] = 0,
                    _ => self.registers[reg] = v,
                }
            }
            _ => panic!("unexpected Clause 22 operation"),
        }
    }
}
static STATUS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "mars-ethernet-test")]
pub(super) fn link(status: u32) {
    STATUS.store(status, core::sync::atomic::Ordering::Relaxed);
}
#[cfg(feature = "mars-ethernet-test")]
pub(super) fn initialized() -> Yt8531<Port<Model>> {
    let mut model = Model::new();
    model.live = true;
    let mut phy = Yt8531::probe(Port::new(model, 198_000_000).unwrap(), u32::MAX, 4).unwrap();
    phy.initialize(
        Tuning {
            drive: [0, 3, 6],
            rxc_delay_enabled: false,
            rx_delay: 10,
            tx_delay_fe: 5,
            tx_delay: 10,
            tx_inverted: [true; 3],
        },
        3,
    )
    .unwrap();
    phy
}
pub fn run(csr_hz: u64) {
    let tuning = Tuning {
        drive: [0, 3, 6],
        rxc_delay_enabled: false,
        rx_delay: 10,
        tx_delay_fe: 5,
        tx_delay: 10,
        tx_inverted: [true; 3],
    };
    let mut phy = Yt8531::probe(Port::new(Model::new(), csr_hz).unwrap(), u32::MAX, 4).unwrap();
    assert_eq!(phy.identity().address, 17);
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
    phy.initialize(tuning, 3).unwrap();
    let link = phy.poll_link().unwrap().unwrap();
    assert_eq!(link.speed, Speed::Mbps1000);
    assert!(phy.configure_link(link).unwrap());
    let mut model = phy.into_port().into_inner();
    assert_eq!(model.extended, [0x0035, 0xcffc, 0xe95a]);
    assert_eq!(model.registers[4], 0x0141);
    assert_eq!(model.registers[9], 0x0200);
    model.reset_stuck = true;
    let mut phy = Yt8531::probe(Port::new(model, csr_hz).unwrap(), u32::MAX, 4).unwrap();
    assert_eq!(phy.initialize(tuning, 3), Err(Error::ResetTimedOut));
    assert_eq!(phy.poll_link(), Err(Error::NotReady));
}
