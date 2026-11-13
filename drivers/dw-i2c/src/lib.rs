#![no_std]
//! Bounded preparation of a DesignWare I2C controller for a firmware owner.
//! No bus transactions are issued; the caller transfers ownership after success.
pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
}
#[derive(Clone, Copy)]
pub struct StandardTiming {
    pub high_count: u16,
    pub low_count: u16,
    pub sda_hold: u16,
}
/// Disable, configure a 7-bit polling master, and leave it disabled for takeover.
/// Caller exclusively owns the controller and supplies timings for its clock.
pub fn prepare(r: &mut impl Registers, t: StandardTiming) -> bool {
    if t.high_count < 6 || t.low_count < 8 || t.sda_hold == 0
        || u32::from(t.sda_hold) + 2 >= u32::from(t.low_count)
        || r.read(0xfc) != 0x44570140 {
        return false;
    }
    r.write(0x6c, 0);
    let mut disabled = false;
    for _ in 0..100_000 {
        if r.read(0x9c) & 1 == 0 { disabled = true; break; }
        core::hint::spin_loop();
    }
    if !disabled { return false; }
    for (offset, value) in [
        (0x00, 0x63), // master, standard speed, restart, slave disabled
        (0x14, u32::from(t.high_count)), (0x18, u32::from(t.low_count)),
        (0x7c, u32::from(t.sda_hold)), (0x30, 0), (0x38, 0), (0x3c, 0),
    ] {
        r.write(offset, value);
        if r.read(offset) != value { return false; }
    }
    let _ = r.read(0x40); // clear pending interrupts, including stale aborts
    true
}
struct Mmio(usize);
impl Registers for Mmio {
    fn read(&mut self, offset: usize) -> u32 {
        unsafe { ((self.0 + offset) as *const u32).read_volatile() }
    }
    fn write(&mut self, offset: usize, value: u32) {
        unsafe { ((self.0 + offset) as *mut u32).write_volatile(value) };
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("fence iorw, iorw", options(nostack)) };
    }
}
/// # Safety
/// `base` maps at least 0x100 bytes of an exclusively owned, clocked and released
/// controller. The caller must prevent concurrent access until ownership passes.
pub unsafe fn prepare_mmio(base: usize, timing: StandardTiming) -> bool {
    if base & 3 != 0 { return false; }
    prepare(&mut Mmio(base), timing)
}
