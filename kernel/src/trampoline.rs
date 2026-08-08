//! A non-local exit out of running generated code.
//!
//! Three of the confinement holes in BLUEPRINT §6.4 — stack overflow, runaway
//! loops, and division by zero — are the same hole: a compiled program can get
//! into a state it must not continue from, and there is no way to stop it.
//! Everything else in M2 is built on this.
//!
//! `setjmp`/`longjmp` rather than unwinding, because `panic = "abort"` and
//! there are no landing pads in emitted code.
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

/// `ra`, `sp`, and `s0`–`s11`.
#[repr(C)]
pub struct JmpBuf {
    regs: [u64; 14],
}

impl JmpBuf {
    pub const ZERO: JmpBuf = JmpBuf { regs: [0; 14] };
}

global_asm!(
    r#"
.option norvc
.section .text
.align 4

// i64 vibe_setjmp(JmpBuf *a0)   -- returns 0 when saving, non-zero on longjmp
.global vibe_setjmp
vibe_setjmp:
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
    li a0, 0
    ret

// void vibe_longjmp(JmpBuf *a0, i64 value_a1)
.global vibe_longjmp
vibe_longjmp:
    ld ra,    0(a0)
    ld sp,    8(a0)
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
    mv a0, a1
    ret

// i64 vibe_enter(entry a0, stack_limit a1, fuel a2, region a3, region_len a4)
//
// Establishes the register contract above, then calls the program. On a normal
// return the saved registers come back; on an abort we never get here, because
// the longjmp lands back in the Rust frame that called vibe_setjmp.
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
"#
);

extern "C" {
    pub fn vibe_setjmp(buf: *mut JmpBuf) -> i64;
    pub fn vibe_longjmp(buf: *mut JmpBuf, value: i64) -> !;
    pub fn vibe_enter(
        entry: usize,
        stack_limit: usize,
        fuel: i64,
        region: usize,
        region_len: usize,
    ) -> i64;
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
use core::sync::atomic::{AtomicBool, Ordering};

static mut TASK_JMP: JmpBuf = JmpBuf::ZERO;
static TASK_ARMED: AtomicBool = AtomicBool::new(false);

/// Poll a task with a landing pad installed. Returns true if it panicked.
///
/// `setjmp` lives in *this* function rather than in the caller on purpose: a
/// `longjmp` restores this frame and then returns normally, so the caller's
/// frame and locals are never disturbed and stay safe to use afterwards.
#[inline(never)]
pub fn guard_task(f: &mut dyn FnMut()) -> bool {
    unsafe {
        if vibe_setjmp(addr_of_mut!(TASK_JMP)) != 0 {
            TASK_ARMED.store(false, Ordering::SeqCst);
            return true;
        }
    }
    TASK_ARMED.store(true, Ordering::SeqCst);
    f();
    TASK_ARMED.store(false, Ordering::SeqCst);
    false
}

/// Called from the panic handler. Returns only if there is no pad to jump to.
pub fn unwind_faulted_task() {
    if !TASK_ARMED.swap(false, Ordering::SeqCst) {
        return;
    }
    unsafe { vibe_longjmp(addr_of_mut!(TASK_JMP), 1) }
}
