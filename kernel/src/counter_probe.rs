//! Diagnostic CSR probes. Only the two exact S-mode illegal-instruction sites
//! below may resume; unrelated faults retain the normal trap policy.

#[repr(C)]
pub struct Reading { pub value: u64, pub available: usize }

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(r#"
.pushsection .text.counter_probe,"ax"
.option push
.option norvc
.balign 4
.global __vibe_read_cycle
.type __vibe_read_cycle,@function
__vibe_read_cycle:
    li a1, 1
.global __vibe_cycle_probe_site
__vibe_cycle_probe_site:
    csrr a0, cycle
    ret
.size __vibe_read_cycle, .-__vibe_read_cycle
.balign 4
.global __vibe_read_instret
.type __vibe_read_instret,@function
__vibe_read_instret:
    li a1, 1
.global __vibe_instret_probe_site
__vibe_instret_probe_site:
    csrr a0, instret
    ret
.size __vibe_read_instret, .-__vibe_read_instret
.option pop
.popsection
"#);

#[cfg(target_arch = "riscv64")]
extern "C" {
    fn __vibe_read_cycle() -> Reading;
    fn __vibe_read_instret() -> Reading;
    fn __vibe_cycle_probe_site();
    fn __vibe_instret_probe_site();
}

fn resume_pc(cause: usize, pc: usize, supervisor: bool, sites: [usize; 2]) -> Option<usize> {
    if cause != 2 || !supervisor || pc == 0 || pc & 3 != 0 || !sites.contains(&pc) { return None; }
    pc.checked_add(4)
}

/// # Safety
/// Run only after the trap vector and this module's recovery hook are installed.
#[cfg(target_arch = "riscv64")]
pub unsafe fn read() -> (Reading, Reading) {
    (__vibe_read_cycle(), __vibe_read_instret())
}

/// # Safety
/// `frame` is the current trap entry's complete saved register frame. Its a0/a1
/// slots are offsets 64/72; neither another hart nor a resumed task may use it.
#[cfg(target_arch = "riscv64")]
pub unsafe fn recover(cause: usize, pc: usize, frame: usize) -> bool {
    // Ordinary IRQs must not read extra CSRs or inspect the saved frame.
    if cause != 2 { return false; }
    let sites = [__vibe_cycle_probe_site as *const () as usize,
        __vibe_instret_probe_site as *const () as usize];
    if !sites.contains(&pc) { return false; }
    let status: usize;
    core::arch::asm!("csrr {}, sstatus", out(reg) status, options(nostack));
    let Some(next) = resume_pc(cause, pc, status & (1 << 8) != 0, sites) else { return false; };
    // Return { value: 0, available: 0 }; never represent an unavailable counter
    // as a valid zero measurement. CSR reads are fixed-width via norvc above.
    (frame as *mut usize).add(8).write(0);
    (frame as *mut usize).add(9).write(0);
    core::arch::asm!("csrw sepc, {}", in(reg) next, options(nostack));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resumes_only_exact_supervisor_illegal_sites() {
        let sites = [0x1000, 0x2000];
        assert_eq!(resume_pc(2, 0x1000, true, sites), Some(0x1004));
        assert_eq!(resume_pc(2, 0x2000, true, sites), Some(0x2004));
        for cause in [0, 1, 3, 5, 12, 13, 15, (1usize << (usize::BITS - 1)) | 2] {
            assert_eq!(resume_pc(cause, 0x1000, true, sites), None);
        }
        assert_eq!(resume_pc(2, 0x1000, false, sites), None);
        assert_eq!(resume_pc(2, 0x1004, true, sites), None);
        assert_eq!(resume_pc(2, 0x1002, true, [0x1002, 0x2000]), None);
        assert_eq!(resume_pc(2, 0, true, [0, 0]), None);
        assert_eq!(resume_pc(2, usize::MAX - 3, true, [usize::MAX - 3, 0]), None);
    }
}
