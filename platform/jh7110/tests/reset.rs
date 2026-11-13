use vibeos_platform_jh7110::reset::{self, Registers, I2C5_APB};
struct Model { word: u32, reset: u32, writes: Vec<(usize, u32)>, ignore: bool, stuck: bool }
impl Registers for Model {
    fn read(&mut self, o: usize) -> u32 {
        match o { I2C5_APB => self.word, 0x300 => self.reset,
            0x310 => if self.stuck { 0 } else { !self.reset },
            _ => panic!("unexpected clock/reset offset {o:x}") }
    }
    fn write(&mut self, o: usize, v: u32) {
        self.writes.push((o,v));
        match o { I2C5_APB => if !self.ignore { self.word=v; },
            0x300 => self.reset=v, _ => panic!("invalid offset") }
    }
}
fn model() -> Model { Model { word:0x40000123, reset:0xffe7afcc, writes:vec![], ignore:false, stuck:false } }
#[test]
fn restores_gate_and_reset_preserving_unrelated_bits() {
    let mut r=model();
    assert!(reset::prepare(&mut r));
    assert_eq!(r.writes,[(0x23c,0xc0000123),(0x300,0xffe5afcc)]);
}
#[test]
fn refuses_failed_gate_without_touching_reset() {
    let mut r=model();r.ignore=true;
    assert!(!reset::prepare(&mut r));
    assert_eq!(r.writes.len(),1);
}
#[test]
fn refuses_stuck_reset() {
    let mut r=model();r.stuck=true;
    assert!(!reset::prepare(&mut r));
}
