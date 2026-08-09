//! riscv64 implementation, plus the SBI calls the runtime needs.

use core::arch::asm;

use super::IpiError;

const SSTATUS_SIE: usize = 1 << 1;
const SIP_SSIP: usize = 1 << 1;
const SBI_EXT_IPI: usize = 0x735049;
const SBI_EXT_IPI_SEND: usize = 0;

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

/// Hart identity installed in `tp` by the kernel's assembly entry path.
///
/// `mhartid` is not accessible from S-mode. Keeping the firmware-provided
/// `a0` value in `tp` also gives M5.4 a register-local identity without
/// touching shared memory.
#[inline]
pub fn current_hart_id() -> usize {
    let hart: usize;
    unsafe { asm!("mv {}, tp", out(reg) hart, options(nostack, nomem)) };
    hart
}

/// Logical scheduler identity cached in this hart's supervisor scratch CSR.
///
/// Zero means unregistered; logical ids are stored as `index + 1`. OpenSBI
/// does not own `sscratch` after entering S-mode, and the kernel clears it in
/// `_start` before any Rust code runs.
#[inline(always)]
pub fn cached_logical_hart_index() -> Option<usize> {
    let encoded: usize;
    unsafe { asm!("csrr {}, sscratch", out(reg) encoded, options(nostack, nomem)) };
    encoded.checked_sub(1)
}

/// Install the current hart's already-validated logical scheduler identity.
#[inline(always)]
pub(crate) unsafe fn cache_logical_hart_index(index: usize) {
    let encoded = index
        .checked_add(1)
        .expect("logical hart cache encoding overflowed");
    unsafe { asm!("csrw sscratch, {}", in(reg) encoded, options(nostack, nomem)) };
}

/// Clear the receiving hart's supervisor-software pending bit.
#[inline]
pub fn clear_software_interrupt() {
    unsafe { asm!("csrc sip, {}", in(reg) SIP_SSIP, options(nostack)) };
}

/// Order mailbox memory and the SSIP/SBI device-visible boundary.
#[inline]
pub fn fence_ipi() {
    unsafe { asm!("fence iorw, iorw", options(nostack)) };
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

/// Send one supervisor IPI through the standardized SBI v0.2 IPI extension.
///
/// A single target is encoded as `hart_mask = 1, hart_mask_base = hart`, as
/// required by the standardized hart-mask encoding. We deliberately do not
/// guess a legacy EID 0x04 bit-vector length: that ABI requires one word per
/// platform hart-range and VibeOS does not parse the topology until M5.5.
pub fn send_ipi(hart: usize) -> Result<(), IpiError> {
    let (error, _) = ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND, 1, hart);
    if error == 0 {
        Ok(())
    } else {
        Err(IpiError::from_sbi(error))
    }
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
