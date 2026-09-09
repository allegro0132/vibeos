//! Optional Wasmtime native trap adapter. Unknown/host exceptions remain fatal.
use core::{
    arch::asm,
    sync::atomic::{AtomicUsize, Ordering},
};
use vibeos_wasmtime_runtime::wasmtime::{self, Engine, Instance, Module, Store, Trap};
type Handler = extern "C" fn(usize, usize, bool, usize);
static HANDLER: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static MEMORY_FAULTS: AtomicUsize = AtomicUsize::new(0);
const CONTROL: usize = (1 << 1) | (1 << 5) | (1 << 8); // SIE, SPIE, SPP
#[no_mangle]
extern "C" fn wasmtime_init_traps(handler: Handler) -> i32 {
    let ptr = handler as usize;
    match HANDLER.compare_exchange(0, ptr, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => 0,
        Err(old) if old == ptr => 0,
        Err(_) => 22,
    }
}
/// Safety: called only for a real synchronous exception with the interrupted
/// PC/frame pointer, before the handler has acquired any kernel locks.
pub unsafe fn dispatch(cause: usize, pc: usize, fp: usize, address: usize) {
    if !matches!(cause, 2 | 3 | 5 | 7 | 12 | 13 | 15) {
        return;
    }
    let ptr = HANDLER.load(Ordering::Acquire);
    if ptr == 0 {
        return;
    }
    let handler: Handler = unsafe { core::mem::transmute(ptr) };
    let memory = matches!(cause, 5 | 7 | 12 | 13 | 15);
    HANDLED.fetch_add(1, Ordering::Relaxed);
    if memory {
        MEMORY_FAULTS.fetch_add(1, Ordering::Relaxed);
    }
    handler(pc, fp, memory, address);
    // Only an unrecognized trap returns. A recognized one resumes the
    // Wasmtime entry handler and bypasses this Rust frame and kernel sret.
    HANDLED.fetch_sub(1, Ordering::Relaxed);
    if memory {
        MEMORY_FAULTS.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(super) struct CallState {
    control: usize,
    fcsr: usize,
    #[cfg(feature = "wasmtime-async")]
    recovery: Option<usize>,
}
impl CallState {
    pub(super) fn enter() -> Self {
        let status: usize;
        let fcsr: usize;
        unsafe {
            asm!("csrr {}, sstatus",out(reg) status,options(nomem,nostack));
            asm!("frcsr {}",out(reg) fcsr,options(nomem,nostack));
        }
        Self {
            control: status & CONTROL,
            fcsr,
            #[cfg(feature = "wasmtime-async")]
            recovery: super::call_recovery::enter(),
        }
    }
}
impl Drop for CallState {
    fn drop(&mut self) {
        #[cfg(feature = "wasmtime-async")]
        super::call_recovery::leave(self.recovery);
        // Do not re-enable interrupts until the floating-point environment
        // and trap-control fields have been restored. Other sstatus fields
        // (including FS dirty state) must retain their current values.
        unsafe {
            asm!("csrci sstatus, 2", options(nostack));
            asm!("fscsr {}",in(reg) self.fcsr,options(nomem,nostack));
            let status: usize;
            asm!("csrr {}, sstatus",out(reg) status,options(nomem,nostack));
            asm!("csrw sstatus, {}",in(reg) ((status & !CONTROL)|self.control),options(nostack));
        }
    }
}
fn status() -> usize {
    let s: usize;
    unsafe {
        asm!("csrr {}, sstatus",out(reg)s,options(nomem,nostack));
    }
    s & CONTROL
}
fn fcsr() -> usize {
    let s: usize;
    unsafe {
        asm!("frcsr {}",out(reg)s,options(nomem,nostack));
    }
    s
}
pub(super) fn selftest(engine: &Engine) -> wasmtime::Result<()> {
    // (func (export "run") unreachable): an actual illegal instruction when
    // native traps are enabled, not a Rust host-error shortcut.
    let bytes=b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x07\x07\x01\x03run\0\0\x0a\x05\x01\x03\0\0\x0b";
    let module = Module::new(engine, bytes)?;
    let mut store = Store::new(engine, ());
    store.set_fuel(10_000)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let run = instance.get_typed_func::<(), ()>(&mut store, "run")?;
    let before = HANDLED.load(Ordering::Relaxed);
    let original = fcsr();
    for _ in 0..100 {
        unsafe {
            asm!("fscsr {}",in(reg)0x60usize,options(nomem,nostack));
        }
        let saved = status();
        let error = super::call(&run, &mut store, ()).unwrap_err();
        assert_eq!(status(), saved);
        assert_eq!(fcsr(), 0x60);
        assert_eq!(
            error.downcast_ref::<Trap>(),
            Some(&Trap::UnreachableCodeReached)
        );
    }
    unsafe {
        asm!("fscsr {}",in(reg)original,options(nomem,nostack));
    }
    assert_eq!(HANDLED.load(Ordering::Relaxed) - before, 100);
    let mut context = FpContext {
        run: &run,
        store: &mut store,
    };
    crate::trap::__vibe_fp_irq_probe_active.store(true, Ordering::SeqCst);
    let mismatch = unsafe {
        wasmtime_native_fp_probe((&mut context as *mut FpContext<'_>).cast(), fp_callback)
    };
    crate::trap::__vibe_fp_irq_probe_active.store(false, Ordering::SeqCst);
    assert_eq!(mismatch, 0, "callee-saved FP registers across native trap");
    assert_eq!(HANDLED.load(Ordering::Relaxed) - before, 101);
    // No active Wasmtime call: an unknown site must return to the kernel.
    unsafe {
        dispatch(2, 0, 0, 0);
    }
    assert_eq!(HANDLED.load(Ordering::Relaxed) - before, 101);
    // Exercise a real software interrupt after all native trap returns.
    assert_eq!(unsafe { crate::trampoline::vibe_fp_irq_probe() }, 0);
    crate::println!(
        "  WASMTIME HARDWARE TRAPS PASS illegal=101 control_restored=1 fcsr_restored=1 fp_callee=12 irq_after=1 unknown_declined=1"
    );
    Ok(())
}

pub(super) fn report() {
    crate::println!(
        "  WASMTIME HARDWARE COUNTS total={} memory_faults={}",
        HANDLED.load(Ordering::Relaxed),
        MEMORY_FAULTS.load(Ordering::Relaxed)
    );
}
struct FpContext<'a> {
    run: &'a wasmtime::TypedFunc<(), ()>,
    store: &'a mut Store<()>,
}
extern "C" fn fp_callback(opaque: *mut ()) -> usize {
    // Only the assembly probe calls back synchronously with this stack record.
    let context = unsafe { &mut *opaque.cast::<FpContext<'_>>() };
    let result = super::call(context.run, context.store, ());
    usize::from(
        !result.is_err_and(|e| e.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached)),
    )
}
extern "C" {
    fn wasmtime_native_fp_probe(
        opaque: *mut (),
        callback: extern "C" fn(*mut ()) -> usize,
    ) -> usize;
}

core::arch::global_asm!(
    r#"
.option push
.option arch, +f, +d
.section .text
.balign 4
.global wasmtime_native_fp_probe
wasmtime_native_fp_probe:
    addi sp, sp, -128
    sd ra, 0(sp)
    .set __wasmtime_fp_slot, 8
    .irp r,8,9,18,19,20,21,22,23,24,25,26,27
    fsd f\r, __wasmtime_fp_slot(sp)
    .set __wasmtime_fp_slot, __wasmtime_fp_slot+8
    .endr
    frcsr t0
    sd t0, 104(sp)
    .irp r,8,9,18,19,20,21,22,23,24,25,26,27
    li t0, (5000+\r)
    fmv.d.x f\r, t0
    .endr
    li t0, 0x60
    fscsr t0
    // a0 remains the opaque context; a1 is the callback address.
    jalr ra, 0(a1)
    bnez a0, .Lwasmtime_fp_restore
    frcsr t0
    li t2, 64
    li t1, 0x60
    bne t0, t1, .Lwasmtime_fp_fail
    .irp r,8,9,18,19,20,21,22,23,24,25,26,27
    fmv.x.d t0, f\r
    li t2, \r
    li t1, (5000+\r)
    bne t0, t1, .Lwasmtime_fp_fail
    .endr
    j .Lwasmtime_fp_restore
.Lwasmtime_fp_fail:
    slli a0, t2, 32
    slli t0, t0, 32
    srli t0, t0, 32
    or a0, a0, t0
.Lwasmtime_fp_restore:
    .set __wasmtime_fp_slot, 8
    .irp r,8,9,18,19,20,21,22,23,24,25,26,27
    fld f\r, __wasmtime_fp_slot(sp)
    .set __wasmtime_fp_slot, __wasmtime_fp_slot+8
    .endr
    ld t0, 104(sp)
    fscsr t0
    ld ra, 0(sp)
    addi sp, sp, 128
    ret
.option pop
"#
);
