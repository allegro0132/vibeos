//! S-mode trap entry.
//!
//! Interrupt handlers in VibeOS do exactly one thing: turn a hardware event
//! into a `Waker::wake()`. All real work happens back on the executor, so the
//! handler is short, allocation-free, and never blocks.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::heap::OwnerId;
use crate::{exec, heap, ipi, plic, sbi, uart};

const SIE_SSIE: usize = 1 << 1; // supervisor software / SBI IPI
const SIE_STIE: usize = 1 << 5; // supervisor timer
const SIE_SEIE: usize = 1 << 9; // supervisor external
const SSTATUS_SIE: usize = 1 << 1;

// A task fault landing pad is still armed when an interrupt preempts its poll.
// Panicking from that interrupt must not longjmp into the interrupted task: it
// would abandon the trap frame and falsely blame the component. The panic path
// reads this flag before considering task-local recovery.
static IN_INTERRUPT: [AtomicBool; exec::MAX_HARTS] =
    [const { AtomicBool::new(false) }; exec::MAX_HARTS];

fn current_hart_index() -> Option<usize> {
    ipi::current_logical_hart().map(exec::HartId::index)
}

global_asm!(
    r#"
.option norvc
.section .text
.align 4
.global __trap_entry
__trap_entry:
    addi sp, sp, -256
    // Capture the IRQ-side benchmark endpoint before the full register save.
    // t0 is the first scratch register saved, so using it after this store
    // preserves the interrupted context. Offset 240 is otherwise unused.
    sd t0,   8(sp)
    rdtime t0
    sd t0, 240(sp)
    sd ra,   0(sp)
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

    ld a0, 240(sp)
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

fn install_local(enabled: usize) {
    unsafe {
        asm!("csrw stvec, {}", in(reg) __trap_entry as *const () as usize);
        // Entry assembly cleared SIE. Writing the exact local mask keeps
        // secondary harts away from the boot hart's sole PLIC context.
        asm!("csrw sie, {}", in(reg) enabled);
    }
}

/// Initialize the boot hart's local trap CSRs and the one global PLIC setup.
pub fn init_boot() {
    install_local(SIE_SSIE | SIE_STIE | SIE_SEIE);
    plic::init(sbi::current_hart_id());
    plic::register(uart::UART_IRQ, uart_irq, 0)
        .expect("UART IRQ must fit in the PLIC handler registry");
    plic::enable(uart::UART_IRQ).expect("UART IRQ must be a valid PLIC source");
    exec::init_timer();
}

/// Install a secondary's trap vector before publishing it ONLINE.
///
/// Global SIE is still clear, so a concurrently published SSIP may become
/// pending but cannot enter Rust until the complete local init is ready.
pub fn prepare_secondary() {
    install_local(SIE_SSIE | SIE_STIE);
}

/// Finish secondary-local initialization after logical self-registration.
pub fn finish_secondary() {
    exec::init_timer();
}

fn uart_irq(_context: usize, _irq_entry: u64) {
    uart::handle_irq();
}

pub fn enable_interrupts() {
    unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SIE) };
}

pub fn in_interrupt() -> bool {
    // An unknown physical hart has no safe task/program landing pad. Treat it
    // as interrupt context so the panic path fails stop instead of jumping
    // through another hart's saved stack.
    current_hart_index()
        .map(|hart| IN_INTERRUPT[hart].load(Ordering::Acquire))
        .unwrap_or(true)
}

#[no_mangle]
extern "C" fn __trap_handler(irq_entry: u64) {
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
        if let Some(hart) = crate::mmu::stack_guard_hart(stval) {
            crate::println!(
                "[!] stack guard: hart{} blocked {}",
                hart,
                exception_name(code)
            );
        }
        if crate::mmu::code_pool_contains(stval) {
            crate::println!("[!] W^X code pool blocked {}", exception_name(code));
        }
        if crate::mmu::rodata_contains(stval) {
            crate::println!("[!] read-only .rodata blocked {}", exception_name(code));
        }
        if crate::cap_table_pool::contains(stval) {
            crate::println!(
                "[!] read-only capability table blocked {}",
                exception_name(code)
            );
        }
        sbi::shutdown(true);
    }

    let Some(hart) = current_hart_index() else {
        // Trap-local state cannot be addressed safely until firmware identity
        // has been bound to one logical scheduler hart.
        sbi::shutdown(true);
    };

    // IRQ work belongs to the kernel, never to the component it interrupted.
    // This also protects future handler changes from accidentally consuming a
    // component quota. Deallocation remains owner-correct because heap headers
    // carry the allocation owner independently of this ambient scope.
    IN_INTERRUPT[hart].store(true, Ordering::Release);

    #[cfg(feature = "wasm-c84-profile-irq-overlay")]
    let profile_irq = crate::wasm_aot_profile_slot::profile_irq_enter(irq_entry);

    if code == 1 {
        // SBI IPIs arrive as SSIP. Acknowledge the CSR before consuming the
        // Release-published reason; doing it in the opposite order can clear a
        // concurrent publisher's fresh doorbell. No scheduler lock or poll is
        // entered from this path.
        let _ = ipi::acknowledge_current();
        #[cfg(any(
            feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
            feature = "wasm-c84-profile-child-delegation-qemu-acceptance",
            feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance"
        ))]
        {
            let applied = crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq, sbi::time());
            crate::wasm_aot_profile_slot::profile_irq_acceptance_note_ssip(applied);
        }
        #[cfg(all(
            feature = "wasm-c84-profile-irq-overlay",
            not(any(
                feature = "wasm-c84-profile-irq-overlay-qemu-acceptance",
                feature = "wasm-c84-profile-child-delegation-qemu-acceptance",
                feature = "wasm-c84-ssh-managed-child-irq-overlay-qemu-acceptance"
            ))
        ))]
        let _ = crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq, sbi::time());
        IN_INTERRUPT[hart].store(false, Ordering::Release);
        return;
    }

    let mut system_owner = heap::enter_owner(OwnerId::SYSTEM);

    match code {
        5 => exec::timer_tick_at(irq_entry),
        9 => {
            while let Some(irq) = plic::claim() {
                if !plic::dispatch(irq, irq_entry) {
                    // A level-triggered source without a handler would
                    // otherwise immediately retrigger forever. Mask it before
                    // returning ownership to the PLIC.
                    let _ = plic::disable(irq);
                }
                plic::complete(irq);
            }
        }
        _ => {}
    }

    system_owner.restore();
    #[cfg(feature = "wasm-c84-profile-irq-overlay")]
    let _ = crate::wasm_aot_profile_slot::profile_irq_exit(profile_irq, sbi::time());
    IN_INTERRUPT[hart].store(false, Ordering::Release);
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
