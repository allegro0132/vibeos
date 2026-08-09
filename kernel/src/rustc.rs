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
//! memory capabilities. Console operations revalidate their token every time;
//! raw memory remains covered by one non-cloneable invocation lease until the
//! catcher returns. Revocation is therefore immediate for later console writes
//! while an already-started memory invocation is allowed to finish.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

pub use vibeos_rustc::samples::{
    BENCHMARK as BENCH_SRC, CONFORMANCE as CONFORM_SRC, DEMO as DEMO_SRC, HELLO as HELLO_SRC,
};

/// Fixed M3.16 demonstration: memory is claimed before the first console
/// operation and used again after the second operation revokes `prog`.
pub const LEASE_SRC: &str = r#"fn main() -> i64 {
    let mut values = [0; 2];
    values[0] = 40;
    print!("lease-visible\n");
    print!("lease-hidden\n");
    values[1] = 2;
    values[0] + values[1]
}
"#;

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::cap::{Cap, Revocable, Rights};
use crate::dev::{ConsoleDev, MemoryInvocation, MemoryRegion};
use crate::sbi;
use crate::sync::SpinLock;
use crate::trampoline::{self, abort, vibe_catch, vibe_enter, vibe_longjmp, JmpBuf};
use crate::world::{world, Space};

/// Where a compiled program's authority lives while it runs. `None` means no
/// program is executing and the runtime hooks refuse everything.
static PROG_OUT: SpinLock<Option<Revocable<ConsoleDev>>> = SpinLock::new(None);
static DENIED: AtomicBool = AtomicBool::new(false);

/// Deterministic M3.16 test hook. Zero means disarmed; `usize::MAX` is the
/// short arm transition. The target is cleared before revocation, so the hook
/// is one-shot even if revocation itself causes more output attempts.
static REVOKE_BEFORE_CONSOLE: AtomicUsize = AtomicUsize::new(0);
static CONSOLE_OPERATIONS: AtomicUsize = AtomicUsize::new(0);
static HOOK_REVOKED_CAPS: AtomicUsize = AtomicUsize::new(0);

/// Arm a one-shot revocation immediately before the selected generated-code
/// console operation. The hook is reset by `run` on every return path.
pub fn arm_console_revoke_hook(operation: usize) -> bool {
    if operation == 0
        || operation == usize::MAX
        || REVOKE_BEFORE_CONSOLE
            .compare_exchange(0, usize::MAX, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return false;
    }
    CONSOLE_OPERATIONS.store(0, Ordering::SeqCst);
    HOOK_REVOKED_CAPS.store(0, Ordering::SeqCst);
    REVOKE_BEFORE_CONSOLE.store(operation, Ordering::SeqCst);
    true
}

fn finish_console_revoke_hook() -> usize {
    REVOKE_BEFORE_CONSOLE.store(0, Ordering::SeqCst);
    CONSOLE_OPERATIONS.store(0, Ordering::SeqCst);
    HOOK_REVOKED_CAPS.swap(0, Ordering::SeqCst)
}

fn before_console_operation() {
    let target = REVOKE_BEFORE_CONSOLE.load(Ordering::SeqCst);
    if target == 0 || target == usize::MAX {
        return;
    }
    let operation = CONSOLE_OPERATIONS.fetch_add(1, Ordering::SeqCst) + 1;
    if operation != target
        || REVOKE_BEFORE_CONSOLE
            .compare_exchange(target, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return;
    }

    // This lock is released before the revocable token is copied and before
    // any device operation. The hook never nests a CSpace, hook, or PROG_OUT
    // lock around a console call.
    let revoked = world().spaces["prog"].0.lock().revoke_all();
    HOOK_REVOKED_CAPS.store(revoked, Ordering::SeqCst);
}

fn console_token() -> Option<Revocable<ConsoleDev>> {
    let token = PROG_OUT.lock().clone();
    token
}

fn deny_console() {
    DENIED.store(true, Ordering::SeqCst);
}

/// Called by generated code. Not `pub` to the language — the compiler emits the
/// address directly, so a program cannot name it, forge it, or call anything else.
extern "C" fn rt_print_str(ptr: *const u8, len: usize) {
    before_console_operation();
    let Some(console) = console_token() else {
        deny_console();
        return;
    };
    // Safety: the pointer and length come from the compiler's own string table,
    // which outlives the call.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    if let Ok(s) = core::str::from_utf8(bytes) {
        if console.try_with(|device| device.write(s)).is_err() {
            deny_console();
        }
    }
}

/// Where a failed safety check lands. The buffer is static because runtime
/// hooks need its address; invocation inputs and results remain ordinary
/// locals now that Rust only sees the single-return `vibe_catch` boundary.
static mut JMP: JmpBuf = JmpBuf::ZERO;
static ARMED: AtomicBool = AtomicBool::new(false);

struct ProgramCatch {
    entry: usize,
    stack_limit: usize,
    fuel: i64,
    region: usize,
    region_len: usize,
    value: i64,
}

unsafe extern "C" fn enter_program(ctx: *mut ()) {
    // Safety: run keeps this context alive for the complete catch call, and
    // entry points at the freshly emitted main function.
    let catch = unsafe { &mut *ctx.cast::<ProgramCatch>() };
    // Do not advertise the global jump target until vibe_catch has populated
    // it. This closes the stale-buffer window present in a direct setjmp call.
    ARMED.store(true, Ordering::SeqCst);
    catch.value = unsafe {
        vibe_enter(
            catch.entry,
            catch.stack_limit,
            catch.fuel,
            catch.region,
            catch.region_len,
        )
    };
    ARMED.store(false, Ordering::SeqCst);
}

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
    unsafe { vibe_longjmp(addr_of_mut!(JMP), RUNTIME_PANICKED) }
}

/// Reason code for "the kernel panicked while this program was running". Above
/// the codes the code generator emits.
const RUNTIME_PANICKED: i64 = 64;

/// Called by generated code when an emitted check fails. Never returns.
extern "C" fn rt_abort(code: i64) -> ! {
    if !ARMED.swap(false, Ordering::SeqCst) {
        panic!(
            "generated code aborted with no landing pad: {}",
            abort::describe(code)
        );
    }
    unsafe { vibe_longjmp(addr_of_mut!(JMP), code) }
}

extern "C" fn rt_print_int(v: i64) {
    before_console_operation();
    let Some(console) = console_token() else {
        deny_console();
        return;
    };
    let text = format!("{}", v);
    if console.try_with(|device| device.write(&text)).is_err() {
        deny_console();
    }
}

/// `Display for bool` prints `true`/`false`, and the subset must agree with
/// Rust here or the differential oracle stops being one.
extern "C" fn rt_print_bool(v: i64) {
    before_console_operation();
    let Some(console) = console_token() else {
        deny_console();
        return;
    };
    let text = if v == 0 { "false" } else { "true" };
    if console.try_with(|device| device.write(text)).is_err() {
        deny_console();
    }
}

pub struct Compiled {
    /// Kept alive because generated code holds absolute pointers into it.
    _data: Vec<u8>,
    code: Vec<u32>,
    pub funcs: usize,
    pub bytes: usize,
    pub data_bytes: usize,
}

fn runtime() -> vibeos_rustc::Runtime {
    vibeos_rustc::Runtime {
        print_str: rt_print_str as *const () as u64,
        print_int: rt_print_int as *const () as u64,
        print_bool: rt_print_bool as *const () as u64,
        abort: rt_abort as *const () as u64,
    }
}

fn link_relocatable(image: &vibeos_rustc::RelocatableImage) -> Result<Compiled, String> {
    let rt = runtime();

    // Allocate the exact final buffers before linking. The linker emits another
    // owned Image, whose bytes are copied into these stable-address buffers;
    // generated absolute references therefore name the storage retained by
    // `Compiled`, never a temporary linker allocation.
    let mut data = image.data().to_vec();
    let mut code = vec![0u32; image.code_template().len()];

    let linked = image.link_with_runtime(
        data.as_ptr() as u64,
        code.as_ptr() as u64,
        &rt,
    )?;
    if linked.code.len() != code.len() || linked.data.len() != data.len() {
        return Err("internal error: executable layout changed while linking".to_string());
    }
    data.copy_from_slice(&linked.data);
    code.copy_from_slice(&linked.code);

    Ok(Compiled {
        funcs: linked.funcs,
        bytes: code.len() * 4,
        data_bytes: data.len(),
        _data: data,
        code,
    })
}

pub fn compile(src: &str) -> Result<Compiled, String> {
    let image = vibeos_rustc::compile_relocatable(src)?;
    link_relocatable(&image)
}

/// Produce the canonical address-independent VIBEEXE stored inside a durable
/// ProgramArtifact.
pub fn compile_persistable(src: &str) -> Result<Vec<u8>, String> {
    Ok(vibeos_rustc::compile_relocatable(src)?.encode())
}

/// Admit persisted native code only after the current trusted compiler emits
/// the identical canonical VIBEEXE for the persisted source. The durable CRCs
/// are corruption checks, not authority to introduce arbitrary machine code.
pub fn compile_verified(src: &str, executable: &[u8]) -> Result<Compiled, String> {
    let persisted = vibeos_rustc::RelocatableImage::decode(executable)?;
    let current = vibeos_rustc::compile_relocatable(src)?;
    if current.encode().as_slice() != executable {
        return Err("persisted VIBEEXE does not match the current compiler output".to_string());
    }
    link_relocatable(&persisted)
}

pub struct RunOutcome {
    pub value: i64,
    /// Raw `rdtime` delta. Benchmark consumers use ticks rather than the
    /// rounded human-readable microsecond value.
    pub ticks: u64,
    pub micros: u64,
    pub denied: bool,
    /// Number of `prog` caps revoked by the deterministic operation hook.
    pub revoked_caps: usize,
    /// Set when an emitted safety check stopped the program.
    pub aborted: Option<&'static str>,
}

/// Execute compiled code, having first resolved the console capability the
/// program will run with. A denial here is not an error path bolted on — it is
/// what happens when `prog`'s cap is gone.
pub fn run(prog: &Compiled) -> RunOutcome {
    let w = world();
    let space = w.spaces["prog"].clone();
    run_with_authority(prog, &space, w.prog_console, w.prog_memory)
}

/// Execute with one explicit CSpace and its exact capability handles. Saved
/// programs use this entry point so the legacy boot-local `prog` grants cannot
/// accidentally become ambient authority after recovery.
pub fn run_with_authority(
    prog: &Compiled,
    space: &Arc<Space>,
    console_cap: Cap,
    memory_cap: Cap,
) -> RunOutcome {
    let (console, memory_lease) = {
        let cspace = space.0.lock();
        (
            cspace
                .lookup_revocable::<ConsoleDev>(console_cap, Rights::WRITE)
                .ok(),
            cspace.lookup_lease::<MemoryRegion>(
                memory_cap,
                Rights::READ.union(Rights::WRITE),
            ),
        )
    };

    // The non-Clone lease stays in `memory` across the complete `vibe_catch`.
    // Revocation can prevent the next lookup but cannot invalidate this active
    // raw extent. An exclusive claim prevents two invocations aliasing it. The
    // two tokens are resolved under one local CSpace guard so `revoke_all`
    // cannot split this launch; a concurrent ancestor revoke would still
    // linearize independently at each capability's acquisition point.
    let memory = memory_lease
        .ok()
        .and_then(|lease| MemoryInvocation::claim(lease).ok());
    let (region_base, region_len) = match &memory {
        Some(invocation) => invocation.extent(),
        None => (0, 0),
    };

    *PROG_OUT.lock() = console;
    DENIED.store(false, Ordering::SeqCst);
    let started_at = sbi::time();
    let mut catch = ProgramCatch {
        entry: prog.code.as_ptr() as usize,
        stack_limit: crate::stack_floor(),
        fuel: FUEL,
        region: region_base,
        region_len,
        value: -1,
    };

    // Safety: `entry` points at freshly written RV64 whose first instruction is
    // `main`'s prologue. `fence.i` makes those writes visible to instruction
    // fetch. `vibe_catch` itself returns exactly once, with zero after a normal
    // callback or the non-zero reason supplied by a safety check. The short TCB
    // path from `MemoryInvocation::claim` to this boundary must not non-locally
    // fault: once the catcher is established, normal and abort returns converge
    // below and explicitly drop the claim.
    let code = unsafe {
        core::arch::asm!("fence.i");
        vibe_catch(
            addr_of_mut!(JMP),
            enter_program,
            (&mut catch as *mut ProgramCatch).cast(),
        )
    };
    // Normal and non-local paths converge here. Clear defensively even though
    // the thunk and every abort path already perform their exact transition.
    ARMED.store(false, Ordering::SeqCst);
    let value = if code == 0 { catch.value } else { -1 };
    drop(memory);

    let ticks = sbi::time() - started_at;
    let micros = ticks / (crate::exec::TIMEBASE_HZ / 1_000_000);

    *PROG_OUT.lock() = None;
    let denied = DENIED.load(Ordering::SeqCst);
    let revoked_caps = finish_console_revoke_hook();
    RunOutcome {
        value,
        ticks,
        micros,
        denied,
        revoked_caps,
        aborted: (code != 0).then(|| match code {
            RUNTIME_PANICKED => "the runtime panicked while the program was running",
            other => trampoline::abort::describe(other),
        }),
    }
}
