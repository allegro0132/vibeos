//! An in-kernel compiler for a subset of Rust, emitting native RV64 machine
//! code that VibeOS then executes in place.
//!
//! Supported: `fn` with `i64` params and return, `let`/`let mut`, assignment,
//! `if`/`else` as an expression, `while`, `return`, recursion, the usual
//! arithmetic/comparison/logical operators with short-circuiting, and
//! `print!`/`println!` with `{}` holes.
//!
//! The interesting part is not the code generator — it is where the generated
//! code's authority comes from. Emitted programs cannot touch hardware. At the
//! start of each invocation, `run` resolves the `prog` space's console and
//! memory capabilities; runtime hooks use those invocation-scoped objects.
//! Revoking before the next run denies them. Whether revoke-during-run should
//! invalidate an active invocation lease is ROADMAP 3.16.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub use vibeos_rustc::samples::{
    BENCHMARK as BENCH_SRC, CONFORMANCE as CONFORM_SRC, DEMO as DEMO_SRC, HELLO as HELLO_SRC,
};

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};

use crate::cap::Rights;
use crate::dev::{ConsoleDev, MemoryRegion};
use crate::sbi;
use crate::sync::SpinLock;
use crate::trampoline::{self, abort, vibe_enter, vibe_longjmp, vibe_setjmp, JmpBuf};
use crate::world::world;

/// Where a compiled program's authority lives while it runs. `None` means no
/// program is executing and the runtime hooks refuse everything.
static PROG_OUT: SpinLock<Option<Arc<ConsoleDev>>> = SpinLock::new(None);
static DENIED: SpinLock<bool> = SpinLock::new(false);

/// Called by generated code. Not `pub` to the language — the compiler emits the
/// address directly, so a program cannot name it, forge it, or call anything else.
extern "C" fn rt_print_str(ptr: *const u8, len: usize) {
    let Some(console) = PROG_OUT.lock().clone() else {
        *DENIED.lock() = true;
        return;
    };
    // Safety: the pointer and length come from the compiler's own string table,
    // which outlives the call.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(bytes) {
        console.write(s);
    }
}

/// Where a failed safety check lands, and the state it needs.
///
/// All of this lives in statics rather than locals because a `longjmp` returns
/// into the middle of `run`, and a local held in a callee-saved register across
/// that boundary is not reliable.
static mut JMP: JmpBuf = JmpBuf::ZERO;
static ARMED: AtomicBool = AtomicBool::new(false);
static ABORT_CODE: AtomicI64 = AtomicI64::new(0);
static ENTRY: AtomicUsize = AtomicUsize::new(0);
static STARTED_AT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// How many calls and loop iterations a program may execute.
///
/// Fuel rather than a clock, because reading the timer needs a CSR access and
/// generated code is not permitted a SYSTEM instruction — see the confinement
/// audit in the compiler's tests.
pub const FUEL: i64 = 20_000_000;

/// Called from the panic handler: if a compiled program is on the stack, treat
/// the panic as an abort of that program. Returns if none is running.
pub fn unwind_running_program() {
    if !ARMED.swap(false, Ordering::SeqCst) {
        return;
    }
    ABORT_CODE.store(RUNTIME_PANICKED, Ordering::SeqCst);
    unsafe { vibe_longjmp(addr_of_mut!(JMP), 1) }
}

/// Reason code for "the kernel panicked while this program was running". Above
/// the codes the code generator emits.
const RUNTIME_PANICKED: i64 = 64;

/// Called by generated code when an emitted check fails. Never returns.
extern "C" fn rt_abort(code: i64) -> ! {
    if !ARMED.load(Ordering::SeqCst) {
        panic!("generated code aborted with no landing pad: {}", abort::describe(code));
    }
    ABORT_CODE.store(code, Ordering::SeqCst);
    ARMED.store(false, Ordering::SeqCst);
    unsafe { vibe_longjmp(addr_of_mut!(JMP), 1) }
}

extern "C" fn rt_print_int(v: i64) {
    let Some(console) = PROG_OUT.lock().clone() else {
        *DENIED.lock() = true;
        return;
    };
    console.write(&format!("{}", v));
}

/// `Display for bool` prints `true`/`false`, and the subset must agree with
/// Rust here or the differential oracle stops being one.
extern "C" fn rt_print_bool(v: i64) {
    let Some(console) = PROG_OUT.lock().clone() else {
        *DENIED.lock() = true;
        return;
    };
    console.write(if v == 0 { "false" } else { "true" });
}

pub struct Compiled {
    /// Kept alive because generated code holds absolute pointers into it.
    _data: Vec<u8>,
    code: Vec<u32>,
    pub funcs: usize,
    pub bytes: usize,
    pub data_bytes: usize,
}

pub fn compile(src: &str) -> Result<Compiled, String> {
    let rt = vibeos_rustc::Runtime {
        print_str: rt_print_str as *const () as u64,
        print_int: rt_print_int as *const () as u64,
        print_bool: rt_print_bool as *const () as u64,
        abort: rt_abort as *const () as u64,
    };

    // Sizing pass: instruction counts never depend on addresses, so the length
    // measured at base 0 is the length we will need at the real base. The data
    // buffer it produces is also final, since only its *address* was a guess.
    let sized = vibeos_rustc::compile_at(src, 0, 0, &rt)?;
    let mut data = sized.data;
    let mut code = vec![0u32; sized.code.len()];

    let real = vibeos_rustc::compile_at(
        src,
        data.as_ptr() as u64,
        code.as_ptr() as u64,
        &rt,
    )?;
    if real.code.len() != code.len() || real.data.len() != data.len() {
        return Err("internal error: code layout was not stable across passes".to_string());
    }
    data.copy_from_slice(&real.data);
    code.copy_from_slice(&real.code);

    Ok(Compiled {
        funcs: real.funcs,
        bytes: code.len() * 4,
        data_bytes: data.len(),
        _data: data,
        code,
    })
}

pub struct RunOutcome {
    pub value: i64,
    /// Raw `rdtime` delta. Benchmark consumers use ticks rather than the
    /// rounded human-readable microsecond value.
    pub ticks: u64,
    pub micros: u64,
    pub denied: bool,
    /// Set when an emitted safety check stopped the program.
    pub aborted: Option<&'static str>,
}

/// Execute compiled code, having first resolved the console capability the
/// program will run with. A denial here is not an error path bolted on — it is
/// what happens when `prog`'s cap is gone.
pub fn run(prog: &Compiled) -> RunOutcome {
    let w = world();
    let space = w.spaces["prog"].clone();
    let console = space.0.lock().lookup_as::<ConsoleDev>(w.prog_console, Rights::WRITE).ok();

    // Memory is resolved through the capability on every run, exactly like the
    // console. Without it a program simply has a zero-length region, and its
    // first array allocation aborts.
    let region = space
        .0
        .lock()
        .lookup_as::<MemoryRegion>(w.prog_memory, Rights::READ.union(Rights::WRITE))
        .ok();
    let (region_base, region_len) = match &region {
        Some(r) => {
            r.clear();
            r.extent()
        }
        None => (0, 0),
    };

    *PROG_OUT.lock() = console;
    *DENIED.lock() = false;
    ABORT_CODE.store(0, Ordering::SeqCst);
    ENTRY.store(prog.code.as_ptr() as usize, Ordering::SeqCst);
    STARTED_AT.store(sbi::time(), Ordering::SeqCst);

    // Safety: `entry` points at freshly written RV64 whose first instruction is
    // `main`'s prologue. `fence.i` makes those writes visible to instruction
    // fetch. `vibe_setjmp` returns 0 on the way in and 1 if a safety check
    // aborted; on that second return only statics may be read.
    let value = unsafe {
        core::arch::asm!("fence.i");
        ARMED.store(true, Ordering::SeqCst);
        if vibe_setjmp(addr_of_mut!(JMP)) == 0 {
            let v = vibe_enter(
                ENTRY.load(Ordering::SeqCst),
                crate::stack_floor(),
                FUEL,
                region_base,
                region_len,
            );
            ARMED.store(false, Ordering::SeqCst);
            v
        } else {
            -1
        }
    };

    let ticks = sbi::time() - STARTED_AT.load(Ordering::SeqCst);
    let micros = ticks / (crate::exec::TIMEBASE_HZ / 1_000_000);
    let code = ABORT_CODE.load(Ordering::SeqCst);

    *PROG_OUT.lock() = None;
    RunOutcome {
        value,
        ticks,
        micros,
        denied: *DENIED.lock(),
        aborted: (code != 0).then(|| match code {
            RUNTIME_PANICKED => "the runtime panicked while the program was running",
            other => trampoline::abort::describe(other),
        }),
    }
}
