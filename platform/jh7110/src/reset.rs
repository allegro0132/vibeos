//! PMIC transport preparation for the vendor OpenSBI reset service.
//! Only the I2C5 APB gate is a real JH7110 clock register. The vendor's
//! synthetic CORE ID 298 must not be interpreted as a SYS CRG MMIO offset.
//! Upstream jh7110.dtsi and clk-starfive-jh7110-sys.c describe only I2C5_APB.
//! OpenSBI's `if (!val)` misses a disabled gate with other bits still set.
use vibeos_hal::AddressRange;
pub const I2C5_APB: usize = 143 * 4;
const ENABLE: u32 = 1 << 31;
pub trait Registers {
    fn read(&mut self, offset: usize) -> u32;
    fn write(&mut self, offset: usize, value: u32);
}
/// Preserve dividers and unrelated bits. Never enter an SBI service which may
/// hang if the transport clock failed to enable. No I2C transaction or PMIC
/// write is performed here; those remain owned by M-mode firmware.
pub fn prepare(r: &mut impl Registers) -> bool {
    for offset in [I2C5_APB] {
        let previous = r.read(offset);
        r.write(offset, previous | ENABLE);
        if r.read(offset) & ENABLE == 0 {
            return false;
        }
    }
    // Reset ID 81: ASSERT2 bit 17, STATUS2 bit 17. U-Boot's device
    // removal asserts this reset before handing control to the payload.
    let reset = r.read(0x300);
    r.write(0x300, reset & !(1 << 17));
    for _ in 0..100_000 {
        if r.read(0x310) & (1 << 17) != 0 { return true; }
        core::hint::spin_loop();
    }
    false
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
/// Caller supplies the mapped, owned JH7110 SYS CRG bank and serializes reset
/// preparation with clock management. Board wiring must put its PMIC on I2C5.
pub unsafe fn prepare_mmio(sys_crg: AddressRange) -> bool {
    if sys_crg != AddressRange::new(0x13020000, 0x13030000) {
        return false;
    }
    prepare(&mut Mmio(sys_crg.start))
}
