//! Minimal SBI v0.2 calls into the M-mode firmware (OpenSBI) below us.

use core::arch::asm;

#[inline(always)]
fn ecall(eid: usize, fid: usize, a0: usize, a1: usize) -> (isize, usize) {
    let (err, val): (isize, usize);
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => err,
            inlateout("a1") a1 => val,
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    (err, val)
}

/// Legacy console putchar — always present, and we only use it before the
/// UART driver is live (panics, early boot).
pub fn legacy_putchar(c: u8) {
    ecall(0x01, 0, c as usize, 0);
}

/// Program the next timer interrupt (TIME extension).
pub fn set_timer(stime: u64) {
    ecall(0x54494D45, 0, stime as usize, 0);
}

/// System Reset extension: shut the machine down.
pub fn shutdown(failure: bool) -> ! {
    ecall(0x53525354, 0, 0, if failure { 1 } else { 0 });
    loop {
        unsafe { asm!("wfi") };
    }
}

#[inline]
pub fn time() -> u64 {
    let t: u64;
    unsafe { asm!("rdtime {}", out(reg) t) };
    t
}
