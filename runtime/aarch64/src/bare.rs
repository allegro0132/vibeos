//! EL1 primitives for an integer-only, single-CPU bootstrap.
use core::arch::asm;

pub fn counter() -> u64 {
    let value;
    unsafe {
        asm!("isb", "mrs {}, cntpct_el0", out(reg) value, options(nomem, nostack));
    }
    value
}
pub fn counter_frequency() -> u64 {
    let value;
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack));
    }
    value
}
pub fn irq_save() -> bool {
    let value: u64;
    // No nomem: this is also a compiler barrier for IRQ-shared memory.
    unsafe {
        asm!("mrs {}, daif", "msr daifset, #2", out(reg) value, options(nostack));
    }
    value & (1 << 7) == 0
}
pub fn irq_restore(enabled: bool) {
    if enabled {
        enable_interrupts();
    }
}
pub fn enable_interrupts() {
    unsafe {
        asm!("msr daifclr, #2", options(nostack));
    }
}
pub fn set_timer(deadline: u64) {
    unsafe {
        asm!("msr cntp_cval_el0, {0}", "msr cntp_ctl_el0, {1}", "isb",
        in(reg) deadline, in(reg) 1u64, options(nostack));
    }
}
pub fn disable_timer() {
    unsafe {
        asm!("msr cntp_ctl_el0, xzr", "isb", options(nostack));
    }
}
pub fn mpidr() -> u64 {
    let value;
    unsafe {
        asm!("mrs {}, mpidr_el1", out(reg) value, options(nomem, nostack));
    }
    value
}

/// Activate the bootstrap's 39-bit identity map and caches.
///
/// # Safety
/// Caller runs at EL1, IRQs masked, MMU and data cache off. `root` points to
/// permanent identity-mapped tables whose memory is never moved after this
/// call. Later changes must obey the serialized `mmu::protect_data_page`
/// contract; ordinary mutable references must not be used while active. All current code, stack, data and required MMIO must be mapped.
/// The loader must have cleaned/invalidated stale cache lines before entry.
pub unsafe fn enable_mmu(root: usize) {
    let old: u64;
    let features: u64;
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) old, options(nomem, nostack));
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) features, options(nomem, nostack));
    }
    assert_eq!(old & 5, 0, "MMU/cache must be off before map installation");
    assert!(features & 15 >= 2, "40-bit physical addresses required");
    assert_eq!((features >> 28) & 15, 0, "4 KiB granule required");
    assert_eq!(root & 4095, 0);
    assert!(root < (1usize << 40));
    // T0SZ=25, WBWA inner/outer, inner-shareable, 4 KiB, TTBR1 disabled,
    // IPS=40 bits. MAIR[0]=normal WBWA; MAIR[1]=Device-nGnRnE; MAIR[2]=Normal NC.
    const TCR: u64 = 25 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (2 << 32);
    unsafe {
        asm!("dsb sy", "msr mair_el1, {mair}", "msr tcr_el1, {tcr}",
            "msr ttbr0_el1, {root}", "msr ttbr1_el1, xzr", "isb",
            "tlbi vmalle1", "dsb sy", "ic iallu", "dsb sy", "isb",
            "msr sctlr_el1, {control}", "isb",
            mair = in(reg) (0xffu64 | (0x44 << 16)), tcr = in(reg) TCR, root = in(reg) root,
            control = in(reg) (old | 1 | (1 << 2) | (1 << 12) | (1 << 19)),
            options(nostack));
    }
}

/// CPU-local scheduler slot; firmware clears TPIDR_EL1 before any Rust entry.
pub fn cached_logical_hart_index() -> Option<usize> {
    let encoded: usize;
    unsafe {
        asm!("mrs {}, tpidr_el1", out(reg) encoded, options(nomem, nostack));
    }
    encoded.checked_sub(1)
}
/// # Safety
/// The caller must have validated this logical slot for the current CPU.
pub unsafe fn cache_logical_hart_index(index: usize) {
    let encoded = index.checked_add(1).expect("logical CPU token overflow");
    unsafe {
        asm!("msr tpidr_el1, {}", in(reg) encoded, options(nomem, nostack));
    }
}
pub fn current_hart_id() -> usize {
    (mpidr() & 0xff00_ffffff) as usize
}
pub fn wait_for_interrupt() {
    unsafe {
        asm!("dsb sy", "wfi", options(nostack));
    }
}
pub fn fence_ipi() {
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}
/// No SGI delivery is admitted by the current single-CPU runtime.
pub fn send_ipi(_hart: usize) -> Result<(), vibeos_hal::arch::IpiError> {
    Err(vibeos_hal::arch::IpiError::NotSupported)
}
pub fn clear_software_interrupt() {
    panic!("SGI handling is not installed on the single-CPU ARM runtime");
}
pub fn reboot() -> ! {
    system_reset(0x8400_0009)
}
pub fn shutdown(_failure: bool) -> ! {
    system_reset(0x8400_0008)
}
fn system_reset(function: u64) -> ! {
    irq_save();
    unsafe {
        asm!("smc #0", inout("x0") function => _, inout("x1") 0u64 => _,
            inout("x2") 0u64 => _, inout("x3") 0u64 => _, clobber_abi("C"), options(nostack));
    }
    loop {
        wait_for_interrupt();
    }
}
