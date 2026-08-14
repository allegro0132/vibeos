//! riscv64 implementation, plus the SBI calls the runtime needs.

use core::arch::asm;

use crate::mapping::{hart_state_from_sbi, ipi_error_from_sbi};
use crate::{HartState, IpiError};

const SSTATUS_SIE: usize = 1 << 1;
const SSTATUS_MXR: usize = 1 << 19;
const SIP_SSIP: usize = 1 << 1;
const SBI_EXT_BASE: usize = 0x10;
const SBI_EXT_BASE_PROBE: usize = 3;
const SBI_EXT_IPI: usize = 0x735049;
const SBI_EXT_IPI_SEND: usize = 0;
const SBI_EXT_HSM: usize = 0x48534D;
const SBI_EXT_HSM_HART_START: usize = 0;
const SBI_EXT_HSM_HART_STATUS: usize = 2;
const SBI_EXT_SRST: usize = 0x5352_5354;
const SBI_EXT_SRST_SYSTEM_RESET: usize = 0;
const SBI_SRST_RESET_TYPE_SHUTDOWN: usize = 0;
const SBI_SRST_RESET_TYPE_COLD_REBOOT: usize = 1;
const SBI_SRST_RESET_REASON_NONE: usize = 0;
const SBI_SRST_RESET_REASON_SYSTEM_FAILURE: usize = 1;
pub const RFENCE_EXTENSION_ID: usize = 0x52464E43;
const SBI_EXT_RFENCE_REMOTE_FENCE_I: usize = 0;
const SBI_EXT_RFENCE_REMOTE_SFENCE_VMA: usize = 1;
const PAGE_SIZE: usize = 4096;

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
///
/// # Safety
///
/// `index` must be the logical scheduler identity already validated for the
/// current physical hart, and this must run on that hart.
#[inline(always)]
pub unsafe fn cache_logical_hart_index(index: usize) {
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

/// Invalidate local address translations covering one virtual range.
///
/// `(0, 0)` and `size == usize::MAX` retain the standardized SBI meaning of
/// the complete address space. Other ranges are walked in base-page steps;
/// the MMU owns alignment and overflow validation before reaching this seam.
pub fn local_sfence_vma(start: usize, size: usize) {
    if (start == 0 && size == 0) || size == usize::MAX {
        unsafe { asm!("sfence.vma x0, x0", options(nostack)) };
        return;
    }

    let end = start
        .checked_add(size)
        .expect("local SFENCE.VMA range overflowed");
    let mut address = start;
    while address < end {
        unsafe {
            asm!(
                "sfence.vma {address}, x0",
                address = in(reg) address,
                options(nostack),
            )
        };
        address = address
            .checked_add(PAGE_SIZE)
            .expect("local SFENCE.VMA page walk overflowed");
    }
}

/// Synchronize earlier data writes with subsequent local instruction fetches.
#[inline]
pub fn local_fence_i() {
    unsafe { asm!("fence.i", options(nostack)) };
}

/// Clear `sstatus.MXR` so execute-only pages cannot also be read by S-mode.
#[inline]
pub fn clear_mxr() {
    unsafe { asm!("csrc sstatus, {}", in(reg) SSTATUS_MXR, options(nostack)) };
}

/// Read the current hart's `sstatus.MXR` bit.
#[inline]
pub fn mxr_enabled() -> bool {
    let sstatus: usize;
    unsafe { asm!("csrr {}, sstatus", out(reg) sstatus, options(nostack, nomem)) };
    sstatus & SSTATUS_MXR != 0
}

#[inline]
pub fn time() -> u64 {
    let t: u64;
    unsafe { asm!("rdtime {}", out(reg) t) };
    t
}

#[inline(always)]
fn ecall(eid: usize, fid: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> (isize, usize) {
    let (err, val): (isize, usize);
    unsafe {
        asm!(
            "ecall",
            inlateout("a0") a0 => err,
            inlateout("a1") a1 => val,
            in("a2") a2,
            in("a3") a3,
            in("a6") fid,
            in("a7") eid,
            options(nostack),
        );
    }
    (err, val)
}

/// Probe one standardized SBI extension through the mandatory Base extension.
pub fn probe_extension(extension_id: usize) -> bool {
    let (error, value) = ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE, extension_id, 0, 0, 0);
    error == 0 && value != 0
}

/// Ask selected physical harts to synchronize their instruction streams.
pub fn remote_fence_i(hart_mask: usize, hart_mask_base: usize) -> Result<(), IpiError> {
    let (error, _) = ecall(
        RFENCE_EXTENSION_ID,
        SBI_EXT_RFENCE_REMOTE_FENCE_I,
        hart_mask,
        hart_mask_base,
        0,
        0,
    );
    if error == 0 {
        Ok(())
    } else {
        Err(ipi_error_from_sbi(error))
    }
}

/// Ask selected physical harts to invalidate translations for one range.
pub fn remote_sfence_vma(
    hart_mask: usize,
    hart_mask_base: usize,
    start: usize,
    size: usize,
) -> Result<(), IpiError> {
    let (error, _) = ecall(
        RFENCE_EXTENSION_ID,
        SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
        hart_mask,
        hart_mask_base,
        start,
        size,
    );
    if error == 0 {
        Ok(())
    } else {
        Err(ipi_error_from_sbi(error))
    }
}

/// Send one supervisor IPI through the standardized SBI v0.2 IPI extension.
///
/// A single target is encoded as `hart_mask = 1, hart_mask_base = hart`, as
/// required by the standardized hart-mask encoding. We deliberately do not
/// guess a legacy EID 0x04 bit-vector length: that ABI requires one word per
/// platform hart-range and VibeOS does not parse the topology until M5.5.
pub fn send_ipi(hart: usize) -> Result<(), IpiError> {
    let (error, _) = ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND, 1, hart, 0, 0);
    if error == 0 {
        Ok(())
    } else {
        Err(ipi_error_from_sbi(error))
    }
}

/// Ask SBI HSM to start `hart` at the physical `start_addr`.
///
/// Per the HSM ABI, firmware enters the new S-mode context with `satp = 0`,
/// interrupts disabled, `a0 = hart`, and `a1 = opaque`. The operation is
/// asynchronous: success means the transition was accepted, not that the hart
/// has completed VibeOS-local initialization.
pub fn hart_start(hart: usize, start_addr: usize, opaque: usize) -> Result<(), IpiError> {
    let (error, _) = ecall(
        SBI_EXT_HSM,
        SBI_EXT_HSM_HART_START,
        hart,
        start_addr,
        opaque,
        0,
    );
    if error == 0 {
        Ok(())
    } else {
        Err(ipi_error_from_sbi(error))
    }
}

/// Return the target hart's momentary SBI HSM state.
///
/// Firmware may transition the hart concurrently immediately after this
/// snapshot. VibeOS therefore uses secondary self-registration, not this
/// status value, as the completion side of its startup handshake.
pub fn hart_status(hart: usize) -> Result<HartState, IpiError> {
    let (error, value) = ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS, hart, 0, 0, 0);
    if error == 0 {
        Ok(hart_state_from_sbi(value))
    } else {
        Err(ipi_error_from_sbi(error))
    }
}

/// Program the next timer interrupt (SBI TIME extension).
pub fn set_timer(stime: u64) {
    ecall(0x54494D45, 0, stime as usize, 0, 0, 0);
}

/// Legacy console putchar. Only used before the UART driver is live, and on
/// the panic path where the driver's lock may already be held.
pub fn legacy_putchar(c: u8) {
    ecall(0x01, 0, c as usize, 0, 0, 0);
}

/// SBI System Reset.
pub fn shutdown(failure: bool) -> ! {
    ecall(
        SBI_EXT_SRST,
        SBI_EXT_SRST_SYSTEM_RESET,
        SBI_SRST_RESET_TYPE_SHUTDOWN,
        if failure {
            SBI_SRST_RESET_REASON_SYSTEM_FAILURE
        } else {
            SBI_SRST_RESET_REASON_NONE
        },
        0,
        0,
    );
    loop {
        wait_for_interrupt();
    }
}

/// Ask the platform to perform a full cold reboot.
pub fn reboot() -> ! {
    ecall(
        SBI_EXT_SRST,
        SBI_EXT_SRST_SYSTEM_RESET,
        SBI_SRST_RESET_TYPE_COLD_REBOOT,
        SBI_SRST_RESET_REASON_NONE,
        0,
        0,
    );
    loop {
        wait_for_interrupt();
    }
}
