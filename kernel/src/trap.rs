//! S-mode trap entry.
//!
//! Interrupt handlers in VibeOS do exactly one thing: turn a hardware event
//! into a `Waker::wake()`. All real work happens back on the executor, so the
//! handler is short, allocation-free, and never blocks.

use core::arch::{asm, global_asm};

use crate::{exec, plic, sbi, uart};

const SIE_STIE: usize = 1 << 5; // supervisor timer
const SIE_SEIE: usize = 1 << 9; // supervisor external
const SSTATUS_SIE: usize = 1 << 1;

global_asm!(
    r#"
.option norvc
.section .text
.align 4
.global __trap_entry
__trap_entry:
    addi sp, sp, -256
    sd ra,   0(sp)
    sd t0,   8(sp)
    sd t1,  16(sp)
    sd t2,  24(sp)
    sd t3,  32(sp)
    sd t4,  40(sp)
    sd t5,  48(sp)
    sd t6,  56(sp)
    sd a0,  64(sp)
    sd a1,  72(sp)
    sd a2,  80(sp)
    sd a3,  88(sp)
    sd a4,  96(sp)
    sd a5, 104(sp)
    sd a6, 112(sp)
    sd a7, 120(sp)
    sd s0, 128(sp)
    sd s1, 136(sp)
    sd s2, 144(sp)
    sd s3, 152(sp)
    sd s4, 160(sp)
    sd s5, 168(sp)
    sd s6, 176(sp)
    sd s7, 184(sp)
    sd s8, 192(sp)
    sd s9, 200(sp)
    sd s10,208(sp)
    sd s11,216(sp)
    sd tp, 224(sp)
    sd gp, 232(sp)

    call __trap_handler

    ld ra,   0(sp)
    ld t0,   8(sp)
    ld t1,  16(sp)
    ld t2,  24(sp)
    ld t3,  32(sp)
    ld t4,  40(sp)
    ld t5,  48(sp)
    ld t6,  56(sp)
    ld a0,  64(sp)
    ld a1,  72(sp)
    ld a2,  80(sp)
    ld a3,  88(sp)
    ld a4,  96(sp)
    ld a5, 104(sp)
    ld a6, 112(sp)
    ld a7, 120(sp)
    ld s0, 128(sp)
    ld s1, 136(sp)
    ld s2, 144(sp)
    ld s3, 152(sp)
    ld s4, 160(sp)
    ld s5, 168(sp)
    ld s6, 176(sp)
    ld s7, 184(sp)
    ld s8, 192(sp)
    ld s9, 200(sp)
    ld s10,208(sp)
    ld s11,216(sp)
    ld tp, 224(sp)
    ld gp, 232(sp)
    addi sp, sp, 256
    sret
"#
);

extern "C" {
    fn __trap_entry();
}

pub fn init() {
    unsafe {
        asm!("csrw stvec, {}", in(reg) __trap_entry as *const () as usize);
        asm!("csrs sie, {}", in(reg) SIE_STIE | SIE_SEIE);
    }
    plic::init(&[uart::UART_IRQ]);
    exec::init_timer();
}

pub fn enable_interrupts() {
    unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SIE) };
}

#[no_mangle]
extern "C" fn __trap_handler() {
    let scause: usize;
    let stval: usize;
    let sepc: usize;
    unsafe {
        asm!("csrr {}, scause", out(reg) scause);
        asm!("csrr {}, stval", out(reg) stval);
        asm!("csrr {}, sepc", out(reg) sepc);
    }

    let is_interrupt = scause >> 63 == 1;
    let code = scause & !(1usize << 63);

    if !is_interrupt {
        crate::println!(
            "\n[!] fatal trap: cause={} stval={:#x} sepc={:#x} ({})",
            code,
            stval,
            sepc,
            exception_name(code)
        );
        sbi::shutdown(true);
    }

    match code {
        5 => exec::timer_tick(),
        9 => {
            while let Some(irq) = plic::claim() {
                if irq == uart::UART_IRQ {
                    uart::handle_irq();
                }
                plic::complete(irq);
            }
        }
        _ => {}
    }
}

fn exception_name(code: usize) -> &'static str {
    match code {
        0 => "instruction address misaligned",
        1 => "instruction access fault",
        2 => "illegal instruction",
        3 => "breakpoint",
        5 => "load access fault",
        7 => "store access fault",
        8 => "ecall from U-mode",
        12 => "instruction page fault",
        13 => "load page fault",
        15 => "store page fault",
        _ => "unknown",
    }
}
