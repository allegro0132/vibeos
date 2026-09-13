use vibeos_driver_dw_i2c::{prepare, Registers, StandardTiming};
struct Model { words: [u32;64], writes: Vec<usize>, stuck: bool }
impl Registers for Model {
    fn read(&mut self, o: usize) -> u32 { self.words[o/4] }
    fn write(&mut self, o: usize, v: u32) {
        self.writes.push(o); self.words[o/4]=v;
        if o==0x6c && !self.stuck { self.words[0x9c/4]=v & 1; }
    }
}
fn model() -> Model {
    let mut m=Model { words:[0;64],writes:vec![],stuck:false };
    m.words[0xfc/4]=0x44570140;m.words[0x9c/4]=1;m
}
fn timing() -> StandardTiming { StandardTiming {high_count:32,low_count:176,sda_hold:8} }
#[test]
fn prepares_reset_controller_without_any_bus_transaction() {
    let mut m=model();assert!(prepare(&mut m,timing()));
    assert_eq!(m.words[0],0x63);assert_eq!(m.words[0x6c/4],0);
    assert_eq!(m.words[0x14/4],32);assert_eq!(m.words[0x18/4],176);
    assert!(!m.writes.contains(&0x04));assert!(!m.writes.contains(&0x10));
}
#[test]
fn stuck_enable_cannot_reconfigure_live_controller() {
    let mut m=model();m.stuck=true;assert!(!prepare(&mut m,timing()));
    assert_eq!(m.writes,[0x6c]);
}
#[test]
fn wrong_hardware_is_not_written() {
    let mut m=model();m.words[0xfc/4]=0;assert!(!prepare(&mut m,timing()));
    assert!(m.writes.is_empty());
}
