//! A non-local exit out of running generated code.
//!
//! Three of the confinement holes in BLUEPRINT §6.4 — stack overflow, runaway
//! loops, and division by zero — are the same hole: a compiled program can get
//! into a state it must not continue from, and there is no way to stop it.
//! Everything else in M2 is built on this.
//!
//! A small catch/longjmp pair rather than unwinding, because `panic = "abort"`
//! and there are no landing pads in emitted code. Rust only calls
//! [`vibe_catch`], which returns exactly once: the returns-twice control flow is
//! contained entirely in assembly so LLVM never has to model it.
//!
//! ## Register contract with generated code
//!
//! `enter` hands the program two values in callee-saved registers, which is
//! what lets the emitted checks be pure register compares — no memory access,
//! so the confinement audit still holds:
//!
//! | reg | holds | why it survives |
//! |-----|-------|-----------------|
//! | `s1` | lowest permitted `sp` | callee-saved, so the Rust runtime hooks preserve it |
//! | `s2` | remaining fuel | likewise; generated functions only ever save `ra`/`s0` |
//! | `s3` | base of the granted memory region | likewise |
//! | `s4` | that region's length, in elements | likewise |

use core::arch::global_asm;

/// `ra`, `sp`, `s0`–`s11`, the entry `sstatus.SIE` bit, and one reserved word.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct JmpBuf {
    regs: [u64; 14],
    sie: u64,
    reserved: u64,
}

impl JmpBuf {
    pub const ZERO: JmpBuf = JmpBuf {
        regs: [0; 14],
        sie: 0,
        reserved: 0,
    };
}

/// Opaque work invoked inside an assembly catch boundary.
pub type CatchThunk = unsafe extern "C" fn(*mut ());

global_asm!(
    r#"
.option norvc
.section .text
.align 4

// i64 vibe_catch(JmpBuf *a0, CatchThunk a1, void *a2)
//
// The call returns zero after the thunk returns normally. vibe_longjmp restores
// this call's entry state and makes the same call return a non-zero status.
// Unlike setjmp, no initial result is ever returned to Rust before the thunk
// has finished, so the Rust/LLVM boundary is single-return.
.global vibe_catch
vibe_catch:
    sd ra,    0(a0)
    sd sp,    8(a0)
    sd s0,   16(a0)
    sd s1,   24(a0)
    sd s2,   32(a0)
    sd s3,   40(a0)
    sd s4,   48(a0)
    sd s5,   56(a0)
    sd s6,   64(a0)
    sd s7,   72(a0)
    sd s8,   80(a0)
    sd s9,   88(a0)
    sd s10,  96(a0)
    sd s11, 104(a0)
    csrr t0, sstatus
    andi t0, t0, 2
    sd t0,  112(a0)

    // s0 is callee-saved, so it keeps the buffer address across the thunk.
    // The incoming stack is already 16-byte aligned at this C ABI boundary.
    mv s0, a0
    mv t0, a1
    mv a0, a2
    jalr ra, t0, 0

    // Restore with interrupts masked. If they were enabled at entry, enable
    // them only after every saved register and the exact stack are back.
    mv t0, s0
    csrci sstatus, 2
    ld t1,  112(t0)
    ld ra,    0(t0)
    ld s0,   16(t0)
    ld s1,   24(t0)
    ld s2,   32(t0)
    ld s3,   40(t0)
    ld s4,   48(t0)
    ld s5,   56(t0)
    ld s6,   64(t0)
    ld s7,   72(t0)
    ld s8,   80(t0)
    ld s9,   88(t0)
    ld s10,  96(t0)
    ld s11, 104(t0)
    ld sp,    8(t0)
    li a0, 0
    beqz t1, .Lvibe_catch_return
    csrsi sstatus, 2
.Lvibe_catch_return:
    ret

// void vibe_longjmp(JmpBuf *a0, i64 value_a1)
.global vibe_longjmp
vibe_longjmp:
    // As with C longjmp, zero is mapped to one so it cannot be confused with
    // the normal vibe_catch return.
    bnez a1, .Lvibe_longjmp_nonzero
    li a1, 1
.Lvibe_longjmp_nonzero:
    csrci sstatus, 2
    ld t0,  112(a0)
    ld ra,    0(a0)
    ld s0,   16(a0)
    ld s1,   24(a0)
    ld s2,   32(a0)
    ld s3,   40(a0)
    ld s4,   48(a0)
    ld s5,   56(a0)
    ld s6,   64(a0)
    ld s7,   72(a0)
    ld s8,   80(a0)
    ld s9,   88(a0)
    ld s10,  96(a0)
    ld s11, 104(a0)
    ld sp,    8(a0)
    mv a0, a1
    beqz t0, .Lvibe_longjmp_return
    csrsi sstatus, 2
.Lvibe_longjmp_return:
    ret

// i64 vibe_enter(entry a0, stack_limit a1, fuel a2, region a3, region_len a4)
//
// Establishes the register contract above, then calls the program. On a normal
// return the saved registers come back; on an abort we never get here, because
// the longjmp makes the enclosing vibe_catch call return an error status.
.global vibe_enter
vibe_enter:
    addi sp, sp, -48
    sd ra,  0(sp)
    sd s1,  8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s4, 32(sp)
    mv s1, a1
    mv s2, a2
    mv s3, a3
    mv s4, a4
    jalr ra, a0, 0
    ld ra,  0(sp)
    ld s1,  8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s4, 32(sp)
    addi sp, sp, 48
    ret

// usize vibe_catch_abi_probe(buf a0, thunk a1, ctx a2, expected_status a3)
//
// Target self-test helper. It installs distinct values in every callee-saved
// integer register, brackets its frame with canaries, and returns the number
// of mismatches observed after vibe_catch returns.
.global vibe_catch_abi_probe
vibe_catch_abi_probe:
    addi sp, sp, -144
    sd ra,    0(sp)
    sd s0,    8(sp)
    sd s1,   16(sp)
    sd s2,   24(sp)
    sd s3,   32(sp)
    sd s4,   40(sp)
    sd s5,   48(sp)
    sd s6,   56(sp)
    sd s7,   64(sp)
    sd s8,   72(sp)
    sd s9,   80(sp)
    sd s10,  88(sp)
    sd s11,  96(sp)
    li t0, 0x5a5
    sd t0, 104(sp)
    li t0, 0x2a5
    sd t0, 112(sp)
    sd a3, 120(sp)
    sd sp, 128(sp)

    li s0,  0x101
    li s1,  0x112
    li s2,  0x123
    li s3,  0x134
    li s4,  0x145
    li s5,  0x156
    li s6,  0x167
    li s7,  0x178
    li s8,  0x189
    li s9,  0x19a
    li s10, 0x1ab
    li s11, 0x1bc
    call vibe_catch

    li t6, 0
    ld t0, 120(sp)
    xor t0, t0, a0
    snez t0, t0
    add t6, t6, t0
    ld t0, 128(sp)
    xor t0, t0, sp
    snez t0, t0
    add t6, t6, t0

    li t1, 0x101
    xor t0, s0, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x112
    xor t0, s1, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x123
    xor t0, s2, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x134
    xor t0, s3, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x145
    xor t0, s4, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x156
    xor t0, s5, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x167
    xor t0, s6, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x178
    xor t0, s7, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x189
    xor t0, s8, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x19a
    xor t0, s9, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x1ab
    xor t0, s10, t1
    snez t0, t0
    add t6, t6, t0
    li t1, 0x1bc
    xor t0, s11, t1
    snez t0, t0
    add t6, t6, t0

    ld t0, 104(sp)
    xori t0, t0, 0x5a5
    snez t0, t0
    add t6, t6, t0
    ld t0, 112(sp)
    xori t0, t0, 0x2a5
    snez t0, t0
    add t6, t6, t0

    mv a0, t6
    ld ra,    0(sp)
    ld s0,    8(sp)
    ld s1,   16(sp)
    ld s2,   24(sp)
    ld s3,   32(sp)
    ld s4,   40(sp)
    ld s5,   48(sp)
    ld s6,   56(sp)
    ld s7,   64(sp)
    ld s8,   72(sp)
    ld s9,   80(sp)
    ld s10,  88(sp)
    ld s11,  96(sp)
    addi sp, sp, 144
    ret

// Test thunk context: {{ JmpBuf *buf; i64 status; }}. Deliberately dirties all
// callee-saved registers and abandons an extra stack frame before longjmp.
.global vibe_catch_test_jump
vibe_catch_test_jump:
    ld t0, 0(a0)
    ld t1, 8(a0)
    addi sp, sp, -64
    li s0,  -1
    li s1,  -2
    li s2,  -3
    li s3,  -4
    li s4,  -5
    li s5,  -6
    li s6,  -7
    li s7,  -8
    li s8,  -9
    li s9,  -10
    li s10, -11
    li s11, -12
    mv a0, t0
    mv a1, t1
    tail vibe_longjmp
"#
);

extern "C" {
    pub fn vibe_catch(buf: *mut JmpBuf, thunk: CatchThunk, ctx: *mut ()) -> i64;
    pub fn vibe_longjmp(buf: *mut JmpBuf, value: i64) -> !;
    pub fn vibe_enter(
        entry: usize,
        stack_limit: usize,
        fuel: i64,
        region: usize,
        region_len: usize,
    ) -> i64;
    pub fn vibe_catch_abi_probe(
        buf: *mut JmpBuf,
        thunk: CatchThunk,
        ctx: *mut (),
        expected_status: i64,
    ) -> usize;
    pub fn vibe_catch_test_jump(ctx: *mut ());
}

/// Abort reasons. The numbers are baked into emitted code, so they are part of
/// the ABI between the code generator and this module.
pub mod abort {
    pub const STACK_OVERFLOW: u8 = 1;
    pub const DIVIDE_BY_ZERO: u8 = 2;
    pub const REMAINDER_BY_ZERO: u8 = 3;
    pub const OUT_OF_FUEL: u8 = 4;
    pub const ARITHMETIC_OVERFLOW: u8 = 5;
    pub const DIVIDE_OVERFLOW: u8 = 6;
    pub const INDEX_OUT_OF_BOUNDS: u8 = 7;
    pub const OUT_OF_MEMORY: u8 = 8;

    /// What real rustc prints for the same condition, where there is one.
    pub fn describe(code: i64) -> &'static str {
        match code as u8 {
            STACK_OVERFLOW => "stack overflow",
            DIVIDE_BY_ZERO => "attempt to divide by zero",
            REMAINDER_BY_ZERO => "attempt to calculate the remainder with a divisor of zero",
            OUT_OF_FUEL => "exceeded execution budget",
            ARITHMETIC_OVERFLOW => "attempt to perform arithmetic that overflowed",
            DIVIDE_OVERFLOW => "attempt to divide with overflow",
            INDEX_OUT_OF_BOUNDS => "index out of bounds",
            OUT_OF_MEMORY => "the granted memory region is too small for this program",
            _ => "aborted",
        }
    }
}

// --- Task fault isolation (ROADMAP 2.8) ---

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_TASK_GUARDS: usize = 8;
static mut TASK_JMPS: [[JmpBuf; MAX_TASK_GUARDS]; crate::exec::MAX_HARTS] =
    [[JmpBuf::ZERO; MAX_TASK_GUARDS]; crate::exec::MAX_HARTS];
static TASK_GUARD_DEPTH: [AtomicUsize; crate::exec::MAX_HARTS] =
    [const { AtomicUsize::new(0) }; crate::exec::MAX_HARTS];

fn current_task_hart() -> Option<usize> {
    crate::ipi::current_logical_hart().map(crate::exec::HartId::index)
}

struct TaskCatch<'a> {
    f: &'a mut dyn FnMut(),
    hart: usize,
    depth: usize,
    hart_mismatch: bool,
}

unsafe extern "C" fn poll_task(ctx: *mut ()) {
    // Safety: guard_task keeps this context alive for the complete catch call.
    let catch = unsafe { &mut *ctx.cast::<TaskCatch<'_>>() };
    if current_task_hart() != Some(catch.hart) {
        catch.hart_mismatch = true;
        return;
    }
    // Advertise the landing pad only after vibe_catch has saved it completely.
    TASK_GUARD_DEPTH[catch.hart].store(catch.depth + 1, Ordering::SeqCst);
    (catch.f)();
}

/// Poll a task with a landing pad installed. Returns true if it panicked.
///
/// The returns-twice machinery lives wholly inside `vibe_catch`; this Rust call
/// returns once with either zero (normal) or a fault status (non-local exit).
#[inline(never)]
pub fn guard_task(f: &mut dyn FnMut()) -> bool {
    let Some(hart) = current_task_hart() else {
        // Without a logical identity there is no safe per-hart jump target.
        return true;
    };
    let depth = TASK_GUARD_DEPTH[hart].load(Ordering::SeqCst);
    // Panicking here would be caught by the *outer* landing pad and longjmp
    // across the caller that owns this operation's terminal claim. Report a
    // synthetic fault instead so that caller can still reclaim/publish its
    // task before returning to the outer component.
    if depth >= MAX_TASK_GUARDS {
        return true;
    }
    let mut catch = TaskCatch {
        f,
        hart,
        depth,
        hart_mismatch: false,
    };
    let status = unsafe {
        vibe_catch(
            addr_of_mut!(TASK_JMPS[hart][depth]),
            poll_task,
            (&mut catch as *mut TaskCatch<'_>).cast(),
        )
    };
    // Both the normal callback return and a non-local exit converge here. The
    // outer landing pad therefore remains armed throughout nested supervision.
    TASK_GUARD_DEPTH[hart].store(depth, Ordering::SeqCst);
    status != 0 || catch.hart_mismatch || current_task_hart() != Some(hart)
}

/// Called from the panic handler. Returns only if there is no pad to jump to.
pub fn unwind_faulted_task() {
    let Some(hart) = current_task_hart() else {
        return;
    };
    let depth = TASK_GUARD_DEPTH[hart].load(Ordering::SeqCst);
    if depth == 0 {
        return;
    }
    let target = depth - 1;
    unsafe { vibe_longjmp(addr_of_mut!(TASK_JMPS[hart][target]), 1) }
}
