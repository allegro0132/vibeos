//! SiFive PLIC as wired up by the QEMU `virt` machine, hart 0 / S-mode context.

pub const PLIC_BASE: usize = 0x0c00_0000;

const PRIORITY: usize = PLIC_BASE;
const ENABLE_S: usize = PLIC_BASE + 0x2080; // hart 0, S-mode
const THRESHOLD_S: usize = PLIC_BASE + 0x20_1000;
const CLAIM_S: usize = PLIC_BASE + 0x20_1004;

pub fn init(irqs: &[u32]) {
    unsafe {
        (THRESHOLD_S as *mut u32).write_volatile(0);
        for &irq in irqs {
            ((PRIORITY + irq as usize * 4) as *mut u32).write_volatile(1);
            let cur = (ENABLE_S as *mut u32).read_volatile();
            (ENABLE_S as *mut u32).write_volatile(cur | (1 << irq));
        }
    }
}

pub fn claim() -> Option<u32> {
    let irq = unsafe { (CLAIM_S as *mut u32).read_volatile() };
    (irq != 0).then_some(irq)
}

pub fn complete(irq: u32) {
    unsafe { (CLAIM_S as *mut u32).write_volatile(irq) };
}
