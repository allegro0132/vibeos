//! Pure interrupt-controller address helpers.

/// QEMU `virt` exposes 32 enable words per PLIC context.
pub const PLIC_ENABLE_WORDS: usize = 32;
pub const PLIC_MAX_IRQ: u32 = (PLIC_ENABLE_WORDS * u32::BITS as usize - 1) as u32;

/// Map a non-zero PLIC source ID to its enable-register word and bit.
pub const fn plic_enable_location(irq: u32) -> Option<(usize, u32)> {
    if irq == 0 || irq > PLIC_MAX_IRQ {
        None
    } else {
        Some(((irq / u32::BITS) as usize, irq % u32::BITS))
    }
}
