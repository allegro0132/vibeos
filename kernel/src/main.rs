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

// The portable half of the kernel lives in `vibeos-core` so it can be tested on
// the host. Re-exported under the names the rest of the tree already uses.
pub use vibeos_core::arch as sbi;
pub use vibeos_core::{cap, chan, durable, exec, heap, interrupt, sync, virtio};

mod bench;
mod dev;
mod plic;
mod rustc;
mod selftest;
mod shell;
mod trampoline;
mod trap;
mod tty;
mod uart;
mod virtio_blk;
mod virtio_mmio;
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
    static __stack_bottom: u8;
}

/// Lowest address a compiled program's stack may reach. The linker puts the
/// kernel stack directly above `.bss`, so without this a deep recursion in
/// generated code would corrupt kernel state instead of faulting.
pub fn stack_floor() -> usize {
    // Leave a band so the abort path itself has room to run.
    core::ptr::addr_of!(__stack_bottom) as usize + 8192
}

#[global_allocator]
pub static HEAP: heap::Heap = heap::Heap::new();

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
    unsafe { HEAP.init(hs, he) };
    println!(
        "  heap      {:#x}..{:#x}  ({} KiB)",
        hs,
        he,
        (he - hs) / 1024
    );

    trap::init();
    println!(
        "  traps     stvec armed, PLIC ctx S/hart0, IRQ {} enabled",
        uart::UART_IRQ
    );

    // Install the complete fault boundary before World admits any reclaimable
    // component task. A tracked arena must never run without both hooks.
    exec::set_fault_guard(trampoline::guard_task);
    exec::set_fault_reclaimer(reclaim_faulted_component);

    world::build();

    let world = world::world();
    world::start_block_supervisor();
    world.spawn_component(
        "shell",
        world.spaces["init"].clone(),
        world::SHELL_MEMORY_BUDGET,
        shell::shell_task(boot_time),
    );
    println!(
        "  world     {} capability spaces, 1 typed channel, {} components",
        world.spaces.len(),
        world.components().len()
    );
    println!("  sched     async executor, no threads, no preemption");

    trap::enable_interrupts();
    exec::run()
}

/// Executor callback after every task and external registration in a tracked
/// incarnation has been detached. The sealed World templates prove that no
/// arena-backed pointer escaped, so raw reclamation is sound and runs no Drop.
unsafe fn reclaim_faulted_component(domain: heap::AllocationDomain) {
    unsafe {
        // Repair component-stable synchronization state while the exact
        // faulting incarnation is still identifiable and before Faulted is
        // visible to safe lifecycle callers.
        virtio_blk::recover_faulted_domain(domain);
        world::world().recover_faulted_domain(domain);
        HEAP.reclaim_faulted_arena(domain.arena)
            .expect("a faulted audited arena must reclaim atomically");
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Deliberately bypasses the UART driver: a panic may already hold its lock.
    let mut w = SbiWriter;
    let _ = core::fmt::write(&mut w, format_args!("\n[!] panic: {}\n", info));

    // An IRQ may preempt a guarded task, but its panic belongs to the kernel.
    // Longjmp from here would skip the saved trap frame and corrupt interrupt
    // state, so interrupt faults are deliberately fatal.
    if trap::in_interrupt() {
        let _ = core::fmt::write(&mut w, format_args!("[!] panic in interrupt; halting\n"));
        sbi::shutdown(true);
    }

    // If a compiled program is running, or a task is being polled behind the
    // fault guard, unwind to that landing pad instead of taking the machine
    // down. Innermost first.
    rustc::unwind_running_program();
    trampoline::unwind_faulted_task();

    let _ = core::fmt::write(&mut w, format_args!("[!] no landing pad; halting\n"));
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
    match HEAP.take_last_failure() {
        Some(heap::AllocationFailure::QuotaExceeded { owner, .. })
            if owner != heap::OwnerId::SYSTEM =>
        {
            // Keep the panic text deterministic; the account snapshot carries
            // exact live/peak/request evidence for diagnostics and tests.
            panic!("component allocation quota exceeded")
        }
        failure => {
            // A global allocator failure is kernel state, even if it happened
            // while a task guard was armed. Bypass panic/longjmp so it cannot be
            // misattributed to the interrupted component.
            let mut w = SbiWriter;
            let _ = core::fmt::write(
                &mut w,
                format_args!(
                    "\n[!] fatal allocator failure: {:?}, layout {:?}\n",
                    failure, layout
                ),
            );
            sbi::shutdown(true)
        }
    }
}
