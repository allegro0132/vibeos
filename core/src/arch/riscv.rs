//! riscv64 implementation, plus the SBI calls the runtime needs.

use core::arch::asm;

const SSTATUS_SIE: usize = 1 << 1;

/// Disable S-mode interrupts; returns whether they were previously enabled.
#[inline]
pub fn irq_save() -> bool {
    let sstatus: usize;
    unsafe { asm!("csrrc {}, sstatus, {}", out(reg) sstatus, in(reg) SSTATUS_SIE) };
    sstatus & SSTATUS_SIE != 0
}

#[inline]
pub fn irq_restore(was_on: bool) {
    if was_on {
        unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SIE) };
    }
}

#[inline]
pub fn enable_interrupts() {
    unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SIE) };
}

#[inline]
pub fn wait_for_interrupt() {
    unsafe { asm!("wfi") };
}

#[inline]
pub fn time() -> u64 {
    let t: u64;
    unsafe { asm!("rdtime {}", out(reg) t) };
    t
}

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

/// Program the next timer interrupt (SBI TIME extension).
pub fn set_timer(stime: u64) {
    ecall(0x54494D45, 0, stime as usize, 0);
}

/// Legacy console putchar. Only used before the UART driver is live, and on
/// the panic path where the driver's lock may already be held.
pub fn legacy_putchar(c: u8) {
    ecall(0x01, 0, c as usize, 0);
}

/// SBI System Reset.
pub fn shutdown(failure: bool) -> ! {
    ecall(0x53525354, 0, 0, if failure { 1 } else { 0 });
    loop {
        wait_for_interrupt();
    }
}
