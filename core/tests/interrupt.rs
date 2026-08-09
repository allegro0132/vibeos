use vibeos_core::interrupt::{plic_enable_location, PLIC_MAX_IRQ};

#[test]
fn source_zero_is_reserved() {
    assert_eq!(plic_enable_location(0), None);
}

#[test]
fn enable_words_cross_the_31_32_boundary() {
    assert_eq!(plic_enable_location(31), Some((0, 31)));
    assert_eq!(plic_enable_location(32), Some((1, 0)));
}

#[test]
fn highest_qemu_source_uses_the_last_word() {
    assert_eq!(PLIC_MAX_IRQ, 1023);
    assert_eq!(plic_enable_location(PLIC_MAX_IRQ), Some((31, 31)));
}

#[test]
fn sources_beyond_the_context_are_rejected() {
    assert_eq!(plic_enable_location(PLIC_MAX_IRQ + 1), None);
    assert_eq!(plic_enable_location(u32::MAX), None);
}
