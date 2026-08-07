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

pub mod ast;
pub mod codegen;
pub mod lex;
pub mod parse;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::cap::Rights;
use crate::dev::ConsoleDev;
use crate::sbi;
use crate::sync::SpinLock;
use crate::world::world;

pub const HELLO_SRC: &str = r#"fn main() {
    println!("Hello, world!");
}
"#;

pub const DEMO_SRC: &str = r#"// Compiled to RV64 by VibeOS, in VibeOS.
fn fib(n: i64) -> i64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}

fn gcd(a: i64, b: i64) -> i64 {
    let mut x = a;
    let mut y = b;
    while y != 0 {
        let t = x % y;
        x = y;
        y = t;
    }
    return x;
}

fn main() {
    println!("Hello, world!");
    let mut i = 0;
    while i < 10 {
        print!("fib({}) = {}  ", i, fib(i));
        i = i + 1;
    }
    println!("");
    println!("gcd(1071, 462) = {}", gcd(1071, 462));
    let n = 30;
    if n % 2 == 0 && n > 10 {
        println!("{} is even and greater than ten", n);
    }
}
"#;

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
    let toks = lex::lex(src)?;
    let prog = parse::Parser::new(toks).program()?;

    // Lay the string table out first: generated code refers to literals by
    // absolute address, so those addresses must be settled before codegen.
    let literals = codegen::collect_strings(&prog, "\n");
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for s in &literals {
        offsets.push(data.len());
        data.extend_from_slice(s.as_bytes());
    }
    let data_base = data.as_ptr() as u64;
    let str_addr: BTreeMap<String, u64> = literals
        .iter()
        .zip(&offsets)
        .map(|(s, off)| (s.clone(), data_base + *off as u64))
        .collect();

    let rt = codegen::Runtime {
        print_str: rt_print_str as *const () as u64,
        print_int: rt_print_int as *const () as u64,
    };

    // Sizing pass: instruction counts never depend on addresses, so the length
    // measured at base 0 is the length we will need at the real base.
    let sized = codegen::compile(&prog, 0, str_addr.clone(), &rt)?;
    let mut code = vec![0u32; sized.len()];
    let code_base = code.as_ptr() as u64;
    let real = codegen::compile(&prog, code_base, str_addr, &rt)?;
    if real.len() != sized.len() {
        return Err("internal error: code layout was not stable across passes".to_string());
    }
    code.copy_from_slice(&real);

    Ok(Compiled {
        funcs: prog.funcs.len(),
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
