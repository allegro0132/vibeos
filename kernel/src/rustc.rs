//! An in-kernel compiler for a subset of Rust, emitting native RV64 machine
//! code that VibeOS then executes in place.
//!
//! Supported: `fn` with `i64` params and return, `let`/`let mut`, assignment,
//! `if`/`else` as an expression, `while`, `return`, recursion, the usual
//! arithmetic/comparison/logical operators with short-circuiting, and
//! `print!`/`println!` with `{}` holes.
//!
//! The interesting part is not the code generator — it is where the generated
//! code's authority comes from. Emitted programs cannot touch hardware. Their
//! only exit is a call into `rt_print_*`, which resolves the `prog` space's
//! console capability *on every call*. Revoke it and the next `println!` in
//! already-compiled, already-running machine code stops working.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub use vibeos_rustc::samples::{CONFORMANCE as CONFORM_SRC, DEMO as DEMO_SRC, HELLO as HELLO_SRC};

use crate::cap::Rights;
use crate::dev::ConsoleDev;
use crate::sbi;
use crate::sync::SpinLock;
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

extern "C" fn rt_print_int(v: i64) {
    let Some(console) = PROG_OUT.lock().clone() else {
        *DENIED.lock() = true;
        return;
    };
    console.write(&format!("{}", v));
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
    pub micros: u64,
    pub denied: bool,
}

/// Execute compiled code, having first resolved the console capability the
/// program will run with. A denial here is not an error path bolted on — it is
/// what happens when `prog`'s cap is gone.
pub fn run(prog: &Compiled) -> RunOutcome {
    let w = world();
    let space = w.spaces["prog"].clone();
    let console = space.0.lock().lookup_as::<ConsoleDev>(w.prog_console, Rights::WRITE).ok();

    *PROG_OUT.lock() = console;
    *DENIED.lock() = false;

    let entry = prog.code.as_ptr() as usize;
    // Safety: `entry` points at freshly written RV64 whose first instruction is
    // `main`'s prologue. `fence.i` makes the writes visible to instruction fetch.
    let f: extern "C" fn() -> i64 = unsafe {
        core::arch::asm!("fence.i");
        core::mem::transmute(entry)
    };

    let start = sbi::time();
    let value = f();
    let micros = (sbi::time() - start) / (crate::exec::TIMEBASE_HZ / 1_000_000);

    *PROG_OUT.lock() = None;
    RunOutcome { value, micros, denied: *DENIED.lock() }
}
