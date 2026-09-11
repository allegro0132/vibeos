//! Ordered register lane. Address translation and platform ownership belong
//! to the firmware; this driver does not select a board or map physical RAM.
use super::{Registers, AGE, CTRL, IE, ISTAT, MODE, RANDOM, REQUESTS, SMODE, STAT};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAperture;

pub struct Mmio {
    base: *mut u32,
    time: fn() -> u64,
}
impl Mmio {
    /// Construct without touching hardware.
    ///
    /// # Safety
    /// `base..base+bytes` must be a live, device-mapped TRNG aperture for the
    /// entire lifetime of this object. The caller exclusively owns register
    /// access, including ISTAT, and keeps the PLIC source masked on every hart.
    /// The platform must hold its clocks and shared SEC reset domain; it may
    /// not reset or gate that domain while this lane can be invoked. This view
    /// does not confer reset authority or establish any entropy quality.
    pub unsafe fn new(
        base: usize,
        bytes: usize,
        time: fn() -> u64,
    ) -> Result<Self, InvalidAperture> {
        if base == 0 || base % 4 != 0 || bytes < AGE + 4 || base.checked_add(bytes).is_none() {
            return Err(InvalidAperture);
        }
        Ok(Self {
            base: base as *mut u32,
            time,
        })
    }
    fn address(&self, offset: usize, write: bool) -> *mut u32 {
        let allowed = if write {
            matches!(offset, CTRL | MODE | IE | ISTAT | REQUESTS | AGE)
        } else {
            matches!(
                offset,
                CTRL | STAT | MODE | SMODE | IE | ISTAT | REQUESTS | AGE
            ) || ((RANDOM..RANDOM + 32).contains(&offset) && offset % 4 == 0)
        };
        assert!(allowed, "unsupported TRNG register access");
        // The allowlist and constructor prove the complete u32 is in range.
        unsafe { self.base.add(offset / 4) }
    }
}
#[inline]
fn fence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
impl Registers for Mmio {
    fn read(&mut self, offset: usize) -> u32 {
        let address = self.address(offset, false);
        fence();
        let value = unsafe { address.read_volatile() };
        fence();
        value
    }
    fn write(&mut self, offset: usize, value: u32) {
        let address = self.address(offset, true);
        fence();
        unsafe { address.write_volatile(value) };
        fence();
    }
    fn ticks(&mut self) -> u64 {
        (self.time)()
    }
}
