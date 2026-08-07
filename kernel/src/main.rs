//! VibeOS — a capability-secure, single-address-space, async-first kernel.
//!
//! Three bets, all visible in this ~1800-line v0.1:
//!
//!   1. Authority is a *capability*, never a name. No paths, no uids, no root.
//!   2. Isolation is a *type system*, not a page table. Components share one
//!      address space; the compiler, not the MMU, is the enforcement boundary.
//!   3. Concurrency is a *future*, not a thread. Nothing blocks, nothing gets
//!      preempted, and an interrupt costs a queue push instead of a context
//!      switch.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

mod cap;
mod chan;
mod dev;
mod exec;
mod heap;
mod plic;
mod rustc;
mod sbi;
mod shell;
mod sync;
mod trap;
mod uart;
mod world;

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
.option norvc
.section .text.boot
.global _start
_start:
    csrw sie, zero
    csrw sip, zero

    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    // Only hart 0 boots; anything else parks.
    bnez a0, .Lpark

    la sp, __stack_top

    // Zero .bss before any Rust runs.
    la t0, __bss_start
    la t1, __bss_end
.Lbss:
    bgeu t0, t1, .Ldone
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lbss
.Ldone:
    j kmain

.Lpark:
    wfi
    j .Lpark
"#
);

extern "C" {
    static __heap_start: u8;
    static __heap_end: u8;
}

const BANNER: &str = r#"
   __   __ __  _           ____  ____
   \ \ / /(_)| |__   ___  / __ \/ ___|
    \ V / | || '_ \ / _ \| |  | \___ \
     \_/  |_||_.__/ \___/ \____/|____/   v0.1
"#;

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    let boot_time = sbi::time();

    uart::init();
    println!("{}", BANNER);

    let (hs, he) = (
        core::ptr::addr_of!(__heap_start) as usize,
        core::ptr::addr_of!(__heap_end) as usize,
    );
    unsafe { heap::HEAP.init(hs, he) };
    println!("  heap      {:#x}..{:#x}  ({} KiB)", hs, he, (he - hs) / 1024);

    trap::init();
    println!("  traps     stvec armed, PLIC ctx S/hart0, IRQ {} enabled", uart::UART_IRQ);

    world::build();
    println!("  world     5 capability spaces, 1 typed channel, 3 components");

    exec::spawn("shell", shell::shell_task(boot_time));
    println!("  sched     async executor, no threads, no preemption");

    trap::enable_interrupts();
    exec::run()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Deliberately bypasses the UART driver: a panic may already hold its lock.
    for b in "\n\n[!] kernel panic: ".bytes() {
        sbi::legacy_putchar(b);
    }
    let mut w = SbiWriter;
    let _ = core::fmt::write(&mut w, format_args!("{}\n", info));
    sbi::shutdown(true);
}

struct SbiWriter;
impl core::fmt::Write for SbiWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                sbi::legacy_putchar(b'\r');
            }
            sbi::legacy_putchar(b);
        }
        Ok(())
    }
}

#[alloc_error_handler]
fn oom(layout: core::alloc::Layout) -> ! {
    panic!("out of kernel heap: {:?}", layout)
}
