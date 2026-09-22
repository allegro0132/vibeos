//! Normal-return native ABI entry. No fault jump, cancellation jump or arena recovery.
use alloc::alloc::{alloc_zeroed, dealloc};
use core::{alloc::Layout, arch::{asm, global_asm}, sync::atomic::{AtomicBool, Ordering}};

const PAGE: usize = 4096;
const SIZE: usize = 256 * 1024;
const BASE: usize = crate::mmu::NATIVE_FIBER_BASE + PAGE;
static BUSY: AtomicBool = AtomicBool::new(false);

// LP64D callee-saved FP registers plus FCSR and the host TLS pointer survive
// this boundary. C++ code returns normally through its own destructors.
#[cfg(target_feature = "d")]
global_asm!(r#"
.option push
.option arch, +f, +d
.section .text
.balign 4
.global __vibe_native_call
__vibe_native_call:
    addi sp, sp, -128
    sd ra, 0(sp)
    sd s0, 8(sp)
    sd tp, 16(sp)
    frcsr t0
    sd t0, 24(sp)
    fsd fs0, 32(sp)
    fsd fs1, 40(sp)
    fsd fs2, 48(sp)
    fsd fs3, 56(sp)
    fsd fs4, 64(sp)
    fsd fs5, 72(sp)
    fsd fs6, 80(sp)
    fsd fs7, 88(sp)
    fsd fs8, 96(sp)
    fsd fs9, 104(sp)
    fsd fs10, 112(sp)
    fsd fs11, 120(sp)
    mv s0, sp
    mv sp, a0
    mv tp, a1
    fscsr zero
    mv a0, a3
    jalr a2
    mv sp, s0
    fld fs0, 32(sp)
    fld fs1, 40(sp)
    fld fs2, 48(sp)
    fld fs3, 56(sp)
    fld fs4, 64(sp)
    fld fs5, 72(sp)
    fld fs6, 80(sp)
    fld fs7, 88(sp)
    fld fs8, 96(sp)
    fld fs9, 104(sp)
    fld fs10, 112(sp)
    fld fs11, 120(sp)
    ld t0, 24(sp)
    fscsr t0
    ld tp, 16(sp)
    ld s0, 8(sp)
    ld ra, 0(sp)
    addi sp, sp, 128
    ret
.option pop
"#);
unsafe extern "C" {
    fn __vibe_native_call(top: usize, tls: usize,
                          entry: extern "C" fn(usize) -> usize, arg: usize) -> usize;
}

struct Stack { physical: usize, layout: Layout }
impl Stack {
    fn allocate() -> Option<Self> {
        if BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return None;
        }
        let layout = Layout::from_size_align(SIZE, PAGE).unwrap();
        let physical = unsafe { alloc_zeroed(layout) } as usize;
        if physical == 0 {
            BUSY.store(false, Ordering::Release);
            return None;
        }
        unsafe { crate::mmu::replace_native_fiber(0, 0, 0, physical, SIZE); }
        Some(Self { physical, layout })
    }
}
impl Drop for Stack {
    fn drop(&mut self) {
        // Only reached after native frames returned; never invoked by a fault
        // recovery hook while C++ objects still occupy the stack.
        unsafe {
            crate::mmu::replace_native_fiber(0, self.physical, SIZE, 0, 0);
            dealloc(self.physical as *mut u8, self.layout);
        }
        BUSY.store(false, Ordering::Release);
    }
}

pub(super) fn probe() {
    extern "C" fn entry(expected_hart: usize) -> usize {
        let sp: usize;
        let tls: usize;
        unsafe { asm!("mv {}, sp", out(reg) sp, options(nomem, nostack)); }
        unsafe { asm!("mv {}, tp", out(reg) tls, options(nomem, nostack)); }
        assert!((BASE..BASE + SIZE).contains(&sp));
        assert_eq!(tls, 0x1234_5000);
        assert_eq!(crate::sbi::current_hart_id(), expected_hart);
        assert!(crate::mmu::mapping(BASE - PAGE).is_none());
        assert!(crate::mmu::mapping(BASE + SIZE).is_none());
        let mapping = crate::mmu::mapping(sp).unwrap();
        use vibeos_core::mmu::PagePermissions as P;
        assert!(mapping.permissions.contains(P::READ.union(P::WRITE)));
        assert!(!mapping.permissions.contains(P::EXECUTE));
        let a = core::hint::black_box(1.5f64);
        let b = core::hint::black_box(2.25f64);
        assert_eq!(a + b, 3.75);
        // Deliberately change the callee's floating-point environment.
        unsafe { asm!("fscsr {}", in(reg) 0x20usize, options(nostack)); }
        42
    }
    let old_tp: usize;
    let old_fcsr: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) old_tp, options(nomem, nostack));
        asm!("frcsr {}", out(reg) old_fcsr, options(nomem, nostack));
    }
    for _ in 0..4 {
        let stack = Stack::allocate().expect("native probe stack allocation");
        let result = unsafe { __vibe_native_call(BASE + SIZE, 0x1234_5000, entry,
                                                crate::sbi::current_hart_id()) };
        assert_eq!(result, 42);
        let tp: usize;
        let fcsr: usize;
        unsafe {
            asm!("mv {}, tp", out(reg) tp, options(nomem, nostack));
            asm!("frcsr {}", out(reg) fcsr, options(nomem, nostack));
        }
        assert_eq!(tp, old_tp);
        assert_eq!(fcsr, old_fcsr);
        drop(stack);
        assert!(!BUSY.load(Ordering::Acquire));
        for offset in (0..SIZE + 2 * PAGE).step_by(PAGE) {
            assert!(crate::mmu::mapping(BASE - PAGE + offset).is_none());
        }
    }
    crate::println!("NATIVE CALL PASS runs=4 stack=262144 guard=1 nx=1 tls=1 fp=1 returned=1 unmapped=1");
}

// This context contains only LP64D nonvolatile state. Call-clobbered registers
// belong to the call boundary, as with an ordinary extern C function call.
#[repr(C, align(16))]
struct Context { words: [usize; 28] }
impl Context { const fn zero() -> Self { Self { words: [0; 28] } } }
const _: () = assert!(core::mem::size_of::<Context>() == 224);

#[cfg(target_feature = "d")]
global_asm!(r#"
.option push
.option arch, +f, +d
.section .text
.balign 4
.global __vibe_native_swap
__vibe_native_swap:
    sd ra, 0(a0)
    sd sp, 8(a0)
    sd s0, 16(a0)
    sd s1, 24(a0)
    sd s2, 32(a0)
    sd s3, 40(a0)
    sd s4, 48(a0)
    sd s5, 56(a0)
    sd s6, 64(a0)
    sd s7, 72(a0)
    sd s8, 80(a0)
    sd s9, 88(a0)
    sd s10, 96(a0)
    sd s11, 104(a0)
    sd tp, 112(a0)
    frcsr t0
    sd t0, 120(a0)
    fsd fs0, 128(a0)
    fsd fs1, 136(a0)
    fsd fs2, 144(a0)
    fsd fs3, 152(a0)
    fsd fs4, 160(a0)
    fsd fs5, 168(a0)
    fsd fs6, 176(a0)
    fsd fs7, 184(a0)
    fsd fs8, 192(a0)
    fsd fs9, 200(a0)
    fsd fs10, 208(a0)
    fsd fs11, 216(a0)
.Lnative_restore:
    ld ra, 0(a1)
    ld sp, 8(a1)
    ld s0, 16(a1)
    ld s1, 24(a1)
    ld s2, 32(a1)
    ld s3, 40(a1)
    ld s4, 48(a1)
    ld s5, 56(a1)
    ld s6, 64(a1)
    ld s7, 72(a1)
    ld s8, 80(a1)
    ld s9, 88(a1)
    ld s10, 96(a1)
    ld s11, 104(a1)
    ld tp, 112(a1)
    ld t0, 120(a1)
    fscsr t0
    fld fs0, 128(a1)
    fld fs1, 136(a1)
    fld fs2, 144(a1)
    fld fs3, 152(a1)
    fld fs4, 160(a1)
    fld fs5, 168(a1)
    fld fs6, 176(a1)
    fld fs7, 184(a1)
    fld fs8, 192(a1)
    fld fs9, 200(a1)
    fld fs10, 208(a1)
    fld fs11, 216(a1)
    ret
.balign 4
.global __vibe_native_probe_start
__vibe_native_probe_start:
    mv a0, s0
    call {start}
    // The entry returned normally; only this assembly frame remains. Do not
    // save a resumable continuation for a completed native invocation.
    mv a1, s0
    j .Lnative_restore
.option pop
"#, start = sym switch_probe_entry);
unsafe extern "C" {
    fn __vibe_native_swap(from: *mut Context, to: *const Context);
    fn __vibe_native_probe_start();
}

// Context addresses stay pinned in a Box while the native stack is suspended.
// Interior mutability avoids holding an exclusive Rust reference across a
// switch into another frame that accesses the same control block.
#[repr(C)]
struct SwitchProbe {
    caller: core::cell::UnsafeCell<Context>,
    native: core::cell::UnsafeCell<Context>,
    yields: core::cell::Cell<usize>,
    drops: core::cell::Cell<usize>,
    cpp_drops: core::cell::Cell<usize>,
    tls_constructors: core::cell::Cell<usize>,
    tls_destructors: core::cell::Cell<usize>,
    finished: core::cell::Cell<bool>,
    hart: usize,
    #[cfg(feature = "native-cxx-probe")]
    tls: crate::native_tls::NativeTls,
}
impl SwitchProbe {
    fn tls_pointer(&self) -> usize {
        #[cfg(feature = "native-cxx-probe")]
        { self.tls.pointer() }
        #[cfg(not(feature = "native-cxx-probe"))]
        { 0x1234_6000 }
    }
}

extern "C" fn switch_probe_yield(pointer: *const SwitchProbe, step: usize) {
    let state = unsafe { &*pointer };
    unsafe { asm!("fscsr {}", in(reg) 0x20usize, options(nostack)); }
    state.yields.set(step);
    unsafe { __vibe_native_swap(state.native.get(), state.caller.get()); }
    let tls: usize;
    let fcsr: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) tls, options(nostack, nomem));
        asm!("frcsr {}", out(reg) fcsr, options(nostack, nomem));
    }
    assert_eq!(tls, state.tls_pointer());
    assert_eq!(fcsr, 0x20);
    assert_eq!(crate::sbi::current_hart_id(), state.hart);
    assert_eq!(state.drops.get(), 0);
    assert_eq!(state.cpp_drops.get(), 0);
    assert_eq!(state.tls_destructors.get(), 0);
}

#[cfg(feature = "native-cxx-probe")]
unsafe extern "C" {
    fn vibeos_native_cxx_probe(context: *const core::ffi::c_void,
        suspend: extern "C" fn(*const core::ffi::c_void, usize),
        drop: extern "C" fn(*const core::ffi::c_void),
        event: extern "C" fn(*const core::ffi::c_void, usize)) -> usize;
}
#[cfg(feature = "native-cxx-probe")]
extern "C" fn switch_probe_tls_event(pointer: *const core::ffi::c_void, event: usize) {
    let state = unsafe { &*pointer.cast::<SwitchProbe>() };
    if event <= 2 {
        assert_eq!(event, state.tls_constructors.get() + 1);
        state.tls_constructors.set(event);
    } else {
        assert_eq!(state.cpp_drops.get(), 1);
        let expected = if state.tls_destructors.get() == 0 { 102 } else { 101 };
        assert_eq!(event, expected);
        state.tls_destructors.set(state.tls_destructors.get() * 10 + event - 100);
    }
}
#[cfg(feature = "native-cxx-probe")]
extern "C" fn switch_probe_cxx_yield(pointer: *const core::ffi::c_void, step: usize) {
    switch_probe_yield(pointer.cast(), step);
}
#[cfg(feature = "native-cxx-probe")]
extern "C" fn switch_probe_cpp_drop(pointer: *const core::ffi::c_void) {
    let state = unsafe { &*pointer.cast::<SwitchProbe>() };
    state.cpp_drops.set(state.cpp_drops.get() + 1);
}

extern "C" fn switch_probe_entry(pointer: *const SwitchProbe) {
    let state = unsafe { &*pointer };
    struct Guard<'a>(&'a core::cell::Cell<usize>);
    impl Drop for Guard<'_> { fn drop(&mut self) { self.0.set(self.0.get() + 1); } }
    {
        let _guard = Guard(&state.drops);
        #[cfg(not(feature = "native-cxx-probe"))]
        {
            let mut value = core::hint::black_box(1.5f64);
            for step in 1..=3 {
                switch_probe_yield(pointer, step);
                value *= core::hint::black_box(2.0);
            }
            assert_eq!(value, 12.0);
        }
        #[cfg(feature = "native-cxx-probe")]
        {
            let result = unsafe {
                vibeos_native_cxx_probe(pointer.cast(), switch_probe_cxx_yield, switch_probe_cpp_drop, switch_probe_tls_event)
            };
            assert_eq!(result, 42);
            assert_eq!(state.cpp_drops.get(), 1);
            assert_eq!(state.tls_constructors.get(), 2);
            assert_eq!(state.tls_destructors.get(), 0);
            assert_eq!(crate::native_tls::finish_current(), 2);
            assert_eq!(state.tls_destructors.get(), 21);
        }
    }
    state.finished.set(true);
    // Return through Rust's ordinary epilogue before the assembly trampoline
    // restores the caller. No suspended high-level frame survives completion.
}

const _: () = assert!(core::mem::offset_of!(SwitchProbe, caller) == 0);

pub(super) fn suspend_probe() {
    #[cfg(feature = "native-cxx-probe")]
    tls_image_probe();
    use alloc::boxed::Box;
    use core::cell::{Cell, UnsafeCell};
    let stack = Stack::allocate().expect("native suspend probe stack");
    let state = Box::pin(SwitchProbe {
        caller: UnsafeCell::new(Context::zero()), native: UnsafeCell::new(Context::zero()),
        yields: Cell::new(0), drops: Cell::new(0), cpp_drops: Cell::new(0),
        tls_constructors: Cell::new(0), tls_destructors: Cell::new(0), finished: Cell::new(false),
        hart: crate::sbi::current_hart_id(),
        #[cfg(feature = "native-cxx-probe")]
        tls: crate::native_tls::NativeTls::new(BASE, BASE + SIZE, 1024 * 1024),
    });
    let pointer = &*state as *const SwitchProbe;
    unsafe {
        let initial = &mut *state.native.get();
        initial.words[0] = __vibe_native_probe_start as *const () as usize;
        initial.words[1] = BASE + SIZE;
        initial.words[2] = pointer as usize;
        initial.words[14] = state.tls_pointer();
    }
    let host_tls: usize;
    let host_fcsr: usize;
    unsafe {
        asm!("mv {}, tp", out(reg) host_tls, options(nostack, nomem));
        asm!("frcsr {}", out(reg) host_fcsr, options(nostack, nomem));
    }
    for resume in 1..=4 {
        assert!(!state.finished.get());
        #[cfg(feature = "native-cxx-probe")]
        let active = unsafe { state.tls.activate() };
        unsafe { __vibe_native_swap(state.caller.get(), state.native.get()); }
        let tls: usize;
        let fcsr: usize;
        unsafe {
            asm!("mv {}, tp", out(reg) tls, options(nostack, nomem));
            asm!("frcsr {}", out(reg) fcsr, options(nostack, nomem));
        }
        assert_eq!(tls, host_tls);
        assert_eq!(fcsr, host_fcsr);
        #[cfg(feature = "native-cxx-probe")]
        drop(active);
        assert_eq!(state.yields.get(), resume.min(3));
        assert_eq!(state.finished.get(), resume == 4);
        assert_eq!(state.drops.get(), usize::from(resume == 4));
        #[cfg(feature = "native-cxx-probe")]
        assert_eq!(state.cpp_drops.get(), usize::from(resume == 4));
        assert!(crate::mmu::mapping(BASE).is_some());
    }
    drop(state);
    drop(stack);
    assert!(!BUSY.load(Ordering::Acquire));
    for offset in (0..SIZE + 2 * PAGE).step_by(PAGE) {
        assert!(crate::mmu::mapping(BASE - PAGE + offset).is_none());
    }
    #[cfg(feature = "native-cxx-probe")]
    crate::println!("NATIVE CXX PASS yields=3 cpp_drops=1 rust_drops=1 returned=1");
    crate::println!("NATIVE SUSPEND PASS yields=3 resumes=4 drops=1 tls=1 fcsr=1 local_fp=1 unmapped=1");
}

#[cfg(feature = "native-cxx-probe")]
fn tls_image_probe() {
    unsafe extern "C" { fn vibeos_native_cxx_tls_probe(expected: usize) -> usize; }
    extern "C" fn entry(expected: usize) -> usize {
        unsafe { vibeos_native_cxx_tls_probe(expected) }
    }
    let a = crate::native_tls::NativeTls::new(BASE, BASE + SIZE, 1024 * 1024);
    let b = crate::native_tls::NativeTls::new(BASE, BASE + SIZE, 1024 * 1024);
    assert_ne!(a.pointer(), b.pointer());
    assert!(a.id() > 0 && b.id() > 0);
    assert_ne!(a.id(), b.id());
    let stack = Stack::allocate().expect("TLS probe stack");
    let caller_tp: usize;
    unsafe { asm!("mv {}, tp", out(reg) caller_tp, options(nostack, nomem)); }
    for (tls, expected) in [(&a, 0), (&a, 1), (&b, 0), (&a, 2), (&b, 1)] {
        let active = unsafe { tls.activate() };
        assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, tls.pointer(), entry, expected) }, 42);
        let restored: usize;
        unsafe { asm!("mv {}, tp", out(reg) restored, options(nostack, nomem)); }
        assert_eq!(restored, caller_tp);
        drop(active);
    }
    unsafe extern "C" {
        fn vibeos_native_semaphore_create(count: i32) -> *mut core::ffi::c_void;
        fn vibeos_native_semaphore_signal(handle: *mut core::ffi::c_void) -> i32;
        fn vibeos_native_semaphore_destroy(handle: *mut core::ffi::c_void);
        fn vibeos_native_pages_allocate(hint: *mut u8, size: usize, alignment: usize, permission: i32) -> *mut u8;
        fn vibeos_native_pages_protect(address: *mut u8, size: usize, permission: i32) -> i32;
    }
    extern "C" fn create_semaphore(_: usize) -> usize {
        unsafe { vibeos_native_semaphore_create(0) as usize }
    }
    extern "C" fn post_semaphore(handle: usize) -> usize {
        unsafe { vibeos_native_semaphore_signal(handle as *mut core::ffi::c_void) as usize }
    }
    extern "C" fn destroy_semaphore(handle: usize) -> usize {
        unsafe { vibeos_native_semaphore_destroy(handle as *mut core::ffi::c_void); }
        42
    }
    extern "C" fn allocate_page(_: usize) -> usize {
        unsafe { vibeos_native_pages_allocate(core::ptr::null_mut(), 4096, 4096, 2) as usize }
    }
    extern "C" fn protect_page(address: usize) -> usize {
        unsafe { vibeos_native_pages_protect(address as *mut u8, 4096, 1) as usize }
    }
    let active = unsafe { a.activate() };
    #[cfg(not(feature = "node-runtime"))]
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), crate::native_memory::flag_probe, 0) }, 42);
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), crate::native_libc_heap::probe, 0) }, 42);
    let owned = unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), allocate_page, 0) };
    assert_ne!(owned, 0);
    let semaphore = unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), create_semaphore, 0) };
    assert_ne!(semaphore, 0);
    drop(active);
    let active = unsafe { b.activate() };
    assert_ne!(unsafe { __vibe_native_call(BASE + SIZE, b.pointer(), protect_page, owned) }, 0);
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, b.pointer(), post_semaphore, semaphore) }, usize::MAX);
    drop(active);
    let active = unsafe { a.activate() };
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), protect_page, owned) }, 0);
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), post_semaphore, semaphore) }, 0);
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), destroy_semaphore, semaphore) }, 42);
    drop(active);
    a.revoke_memory();
    let active = unsafe { a.activate() };
    assert_ne!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), protect_page, owned) }, 0);
    assert_eq!(unsafe { __vibe_native_call(BASE + SIZE, a.pointer(), allocate_page, 0) }, 0);
    drop(active);
    drop(stack);
    drop((a, b)); // Revoked backing is still reclaimed and owner counters checked.
    crate::println!("NATIVE MEMORY ABI PASS isolated=2 revoked=1 reclaimed=1");
    crate::println!("NATIVE SEMAPHORE OWNER PASS foreign_denied=1 owner_post=1 destroyed=1");
    crate::println!("NATIVE CXX TLS PASS initialized=1 zero=1 aligned=1 isolated=2 restored=1");
}

// Executor fixture only: this entry is known to make at most three yields.
// It is NOT a general V8 cancellation strategy. If the future is dropped,
// drive this bounded fixture to ordinary return before releasing its stack.
#[cfg(feature = "native-cxx-probe")]
struct ParkProbe {
    state: core::pin::Pin<alloc::boxed::Box<SwitchProbe>>,
    stack: Option<Stack>,
    resumes: core::cell::Cell<usize>,
}
#[cfg(feature = "native-cxx-probe")]
impl ParkProbe {
    fn new() -> Self {
        use alloc::boxed::Box;
        use core::cell::{Cell, UnsafeCell};
        let stack = Stack::allocate().expect("native parking probe stack");
        let state = Box::pin(SwitchProbe {
            caller: UnsafeCell::new(Context::zero()), native: UnsafeCell::new(Context::zero()),
            yields: Cell::new(0), drops: Cell::new(0), cpp_drops: Cell::new(0),
        tls_constructors: Cell::new(0), tls_destructors: Cell::new(0),
            finished: Cell::new(false), hart: crate::sbi::current_hart_id(),
            tls: crate::native_tls::NativeTls::new(BASE, BASE + SIZE, 1024 * 1024),
        });
        unsafe {
            let initial = &mut *state.native.get();
            initial.words[0] = __vibe_native_probe_start as *const () as usize;
            initial.words[1] = BASE + SIZE;
            initial.words[2] = (&*state as *const SwitchProbe) as usize;
            initial.words[14] = state.tls_pointer();
        }
        Self { state, stack: Some(stack), resumes: Cell::new(0) }
    }
    fn resume(&self) -> bool {
        assert_eq!(crate::sbi::current_hart_id(), self.state.hart);
        assert!(!self.state.finished.get());
        assert!(self.resumes.get() < 4);
        let active = unsafe { self.state.tls.activate() };
        let tls: usize;
        let fcsr: usize;
        unsafe {
            asm!("mv {}, tp", out(reg) tls, options(nostack, nomem));
            asm!("frcsr {}", out(reg) fcsr, options(nostack, nomem));
            __vibe_native_swap(self.state.caller.get(), self.state.native.get());
        }
        let restored_tls: usize;
        let restored_fcsr: usize;
        unsafe {
            asm!("mv {}, tp", out(reg) restored_tls, options(nostack, nomem));
            asm!("frcsr {}", out(reg) restored_fcsr, options(nostack, nomem));
        }
        assert_eq!((restored_tls, restored_fcsr), (tls, fcsr));
        drop(active);
        let resumes = self.resumes.get() + 1;
        self.resumes.set(resumes);
        assert_eq!(self.state.yields.get(), resumes.min(3));
        assert_eq!(self.state.finished.get(), resumes == 4);
        assert_eq!(self.state.drops.get(), usize::from(resumes == 4));
        assert_eq!(self.state.cpp_drops.get(), usize::from(resumes == 4));
        self.state.finished.get()
    }
}
#[cfg(feature = "native-cxx-probe")]
impl Drop for ParkProbe {
    fn drop(&mut self) {
        if self.resumes.get() != 0 {
            while !self.state.finished.get() { self.resume(); }
        }
        drop(self.stack.take());
    }
}

#[cfg(feature = "native-cxx-probe")]
static PARK_DONE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "native-cxx-probe")]
static PARK_PEER_BEATS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "native-cxx-probe")]
pub(super) async fn parking_probe() {
    use crate::exec;
    crate::native_pages::probe();
    crate::native_page_pool::probe();
    crate::native_notify::probe().await;
    let peer = exec::spawn_pinned_on(exec::HartId::BOOT, "native-park-peer", async {
        while !PARK_DONE.load(Ordering::Acquire) {
            exec::sleep_ms(1).await;
            PARK_PEER_BEATS.fetch_add(1, Ordering::Release);
        }
    });
    native_async_wait_probe().await;
    native_stdio_probe().await;
    native_unlink_probe().await;
    native_open_probe().await;
    #[cfg(feature = "queued-entropy")]
    native_entropy_probe().await;
    let run = ParkProbe::new();
    let fences_before = crate::mmu::wx_sync_stats().remote_fence_i;
    let mut waits = 0;
    while !run.resume() {
        let before = PARK_PEER_BEATS.load(Ordering::Acquire);
        exec::sleep_ms(10).await;
        assert!(PARK_PEER_BEATS.load(Ordering::Acquire) > before,
                "same-hart peer must run while native frames are parked");
        assert_eq!(run.state.cpp_drops.get(), 0);
        waits += 1;
    }
    assert_eq!(waits, 3);
    assert_eq!(run.state.cpp_drops.get(), 1);
    assert_eq!(run.state.tls_constructors.get(), 2);
    assert_eq!(run.state.tls_destructors.get(), 21);
    crate::println!("NATIVE TLS DTOR PASS constructors=2 once=1 lifo=21 tls_access=1 stack_bounds=1");
    assert!(crate::mmu::wx_sync_stats().remote_fence_i > fences_before,
            "C++ cache bridge must complete a remote instruction fence");
    crate::println!("NATIVE CACHE PASS c_abi=1 remote_fence=1");
    drop(run);
    crate::native_tcb_pages::assert_reclaimed();
    assert!(!BUSY.load(Ordering::Acquire));
    assert!(crate::mmu::mapping(BASE).is_none());
    PARK_DONE.store(true, Ordering::Release);
    let _ = peer.join().await;
    crate::println!("NATIVE PARK PASS waits=3 peer_progress=1 cpp_drops=1 returned=1 unmapped=1 cxx_tls=1");
    #[cfg(feature = "native-exit-probe")]
    {
        extern "C" fn fatal(_: usize) -> usize { crate::native_process::vibeos_native_fatal_exit(42) }
        let _ = NativeAsync::new(fatal).run().await;
        panic!("fatal native exit returned");
    }
}

// Initial async runner: normal completion only. Cancellation must be integrated
// with cooperative V8 termination before exposing this runner to VSH jobs.
#[cfg(feature = "native-cxx-probe")]
#[repr(C)]
struct NativeAsyncState {
    caller: core::cell::UnsafeCell<Context>,
    native: core::cell::UnsafeCell<Context>,
    tls: crate::native_tls::NativeTls,
    entry: extern "C" fn(usize) -> usize,
    result: core::cell::Cell<usize>,
    finished: core::cell::Cell<bool>,
    pending: core::cell::Cell<Option<(usize, crate::native_tls::PendingPoll)>>,
    parks: core::cell::Cell<usize>,
    hart: usize,
}
#[cfg(feature = "native-cxx-probe")]
global_asm!(r#"
.section .text
.balign 4
.global __vibe_native_async_start
__vibe_native_async_start:
    mv a0, s0
    call {entry}
    mv a1, s0
    j .Lnative_restore
"#, entry = sym native_async_entry);
#[cfg(feature = "native-cxx-probe")]
extern "C" fn native_async_entry(pointer: *const NativeAsyncState) {
    let state = unsafe { &*pointer };
    state.result.set((state.entry)(0));
    crate::native_tls::finish_current();
    state.finished.set(true);
}
#[cfg(feature = "native-cxx-probe")]
unsafe fn native_async_park(pointer: usize, data: usize, poll: crate::native_tls::PendingPoll) -> bool {
    let state = unsafe { &*(pointer as *const NativeAsyncState) };
    assert!(state.pending.replace(Some((data, poll))).is_none());
    state.parks.set(state.parks.get() + 1);
    unsafe { __vibe_native_swap(state.native.get(), state.caller.get()); }
    assert!(state.pending.get().is_none());
    true
}
#[cfg(feature = "native-cxx-probe")]
struct NativeAsync {
    state: core::pin::Pin<alloc::boxed::Box<NativeAsyncState>>,
    _stack: Stack,
    started: bool,
}
#[cfg(feature = "native-cxx-probe")]
impl NativeAsync {
    fn new(entry: extern "C" fn(usize) -> usize) -> Self {
        Self::with_capacity(entry, 1024 * 1024)
    }
    fn with_capacity(entry: extern "C" fn(usize) -> usize, capacity: usize) -> Self {
        use core::cell::{Cell, UnsafeCell};
        let stack = Stack::allocate().expect("native async stack");
        let state = alloc::boxed::Box::pin(NativeAsyncState {
            caller: UnsafeCell::new(Context::zero()), native: UnsafeCell::new(Context::zero()),
            tls: crate::native_tls::NativeTls::new(BASE, BASE + SIZE, capacity),
            entry, result: Cell::new(0), finished: Cell::new(false), pending: Cell::new(None),
            parks: Cell::new(0), hart: crate::sbi::current_hart_id(),
        });
        unsafe extern "C" { fn __vibe_native_async_start(); }
        unsafe {
            let initial = &mut *state.native.get();
            initial.words[0] = __vibe_native_async_start as *const () as usize;
            initial.words[1] = BASE + SIZE;
            initial.words[2] = (&*state as *const NativeAsyncState) as usize;
            initial.words[14] = state.tls.pointer();
            state.tls.set_park_hook(crate::native_tls::ParkHook {
                context: (&*state as *const NativeAsyncState) as usize, call: native_async_park,
            });
        }
        Self { state, _stack: stack, started: false }
    }
    async fn run(mut self) -> (usize, usize) {
        loop {
            assert_eq!(crate::sbi::current_hart_id(), self.state.hart);
            self.started = true;
            let active = unsafe { self.state.tls.activate() };
            unsafe { __vibe_native_swap(self.state.caller.get(), self.state.native.get()); }
            drop(active);
            if self.state.finished.get() {
                assert!(self.state.pending.get().is_none());
                return (self.state.result.get(), self.state.parks.get());
            }
            let (data, poll) = self.state.pending.get().expect("native task suspended without a request");
            // This future remains pinned on the retained native stack. Poll
            // ends before the native task resumes or that future is destroyed.
            core::future::poll_fn(|cx| unsafe { poll(data, cx) }).await;
            self.state.pending.set(None);
        }
    }
}
#[cfg(feature = "native-cxx-probe")]
impl Drop for NativeAsync {
    fn drop(&mut self) {
        // Panic is fatal in this firmware: never reclaim live C++ frames as if
        // an unsupported cancellation had safely unwound them.
        assert!(!self.started || self.state.finished.get(),
                "native async cancellation requires cooperative termination");
    }
}
#[cfg(feature = "native-cxx-probe")]
async fn native_async_wait_probe() {
    unsafe extern "C" { fn vibeos_native_cxx_wait_probe() -> usize; }
    extern "C" fn entry(_: usize) -> usize { unsafe { vibeos_native_cxx_wait_probe() } }
    let before = PARK_PEER_BEATS.load(Ordering::Acquire);
    let (result, parks) = NativeAsync::new(entry).run().await;
    assert_eq!(result, 42);
    assert_eq!(parks, 4);
    assert!(PARK_PEER_BEATS.load(Ordering::Acquire) > before);
    crate::println!("NATIVE WAIT ABI PASS timeouts=2 immediate=1 cpp_return=1 peer_progress=1");
    crate::println!("NATIVE SEMAPHORE PASS permits=1 timeout=1 stale=1 overflow=1 destroyed=1");
    crate::println!("NATIVE SEMAPHORE WAKE PASS parked=1 backend_post=1 consumed_once=1");
}

#[cfg(all(feature = "native-cxx-probe", feature = "queued-entropy"))]
async fn native_entropy_probe() {
    extern "C" fn denied(_: usize) -> usize {
        let mut output = [0xa5; 32];
        assert_eq!(unsafe { crate::native_entropy::vibeos_native_entropy(output.as_mut_ptr(), output.len()) }, -1);
        assert_eq!(output, [0xa5; 32]);
        42
    }
    let (result, parks) = NativeAsync::new(denied).run().await;
    assert_eq!((result, parks), (42, 0));
    crate::println!("NATIVE ENTROPY DENY PASS no_grant=1 unchanged=1");
    let Some(grant) = crate::world::world().native_entropy_probe_grant() else { return; };
    extern "C" fn granted(_: usize) -> usize {
        let mut output = [0u8; 32];
        assert_eq!(unsafe { crate::native_entropy::vibeos_native_entropy(output.as_mut_ptr(), output.len()) }, 0);
        assert!(output.iter().any(|byte| *byte != 0));
        42
    }
    let run = NativeAsync::new(granted);
    run.state.tls.set_entropy(grant);
    let (result, parks) = run.run().await;
    assert_eq!(result, 42);
    assert_eq!(parks, 1);
    crate::println!("NATIVE ENTROPY PASS granted=1 device=1 parked=1 bytes=32");
}

#[cfg(feature = "native-cxx-probe")]
async fn native_stdio_probe() {
    use crate::native_stdio::{StdioGrant, vibeos_native_read, vibeos_native_write, vibeos_native_fd_kind, vibeos_native_close};
    use alloc::sync::Arc;
    use core::future::poll_fn;
    use vibeos_wasi_command::CommandIo;
    extern "C" fn denied(_: usize) -> usize {
        let mut byte = 0xa5;
        assert_eq!(unsafe { vibeos_native_read(0, &mut byte, 1) }, -3);
        assert_eq!(unsafe { vibeos_native_write(1, &byte, 1) }, -3);
        assert_eq!(byte, 0xa5);
        42
    }
    assert_eq!(NativeAsync::new(denied).run().await, (42, 0));
    let io = Arc::new(CommandIo::new());
    let backend = io.clone();
    let peer = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "native-stdio-peer", async move {
        while backend.pending_waiters() == 0 { crate::exec::sleep_ms(1).await; }
        assert_eq!(backend.pending_waiters(), 1, "native writer must park on full pipe");
        let mut byte = [0];
        for expected in 0..9 {
            assert_eq!(poll_fn(|cx| backend.stdout.read(cx, &mut byte)).await.unwrap(), 1);
            assert_eq!(byte[0], expected);
        }
        assert_eq!(poll_fn(|cx| backend.stdin.write(cx, b"R")).await.unwrap(), 1);
        backend.stdin.close();
    });
    extern "C" fn granted(_: usize) -> usize {
        for byte in 0..9u8 { assert_eq!(unsafe { vibeos_native_write(1, &byte, 1) }, 1); }
        let mut byte = 0;
        assert_eq!(unsafe { vibeos_native_read(0, &mut byte, 1) }, 1);
        assert_eq!(byte, b'R');
        assert_eq!(unsafe { vibeos_native_read(0, &mut byte, 1) }, 0);
        assert_eq!(unsafe { vibeos_native_write(0, &byte, 1) }, -1);
        assert_eq!(vibeos_native_fd_kind(-1), -1);
        assert_eq!(vibeos_native_close(3), -1);
        for fd in 0..=2 {
            assert_eq!(vibeos_native_fd_kind(fd), 1);
            assert_eq!(vibeos_native_close(fd), 0);
            assert_eq!(vibeos_native_fd_kind(fd), -1);
            assert_eq!(vibeos_native_close(fd), -1);
        }
        assert_eq!(unsafe { vibeos_native_read(0, &mut byte, 1) }, -1);
        assert_eq!(unsafe { vibeos_native_write(1, &byte, 1) }, -1);
        assert_eq!(unsafe { vibeos_native_write(2, &byte, 1) }, -1);
        42
    }
    let run = NativeAsync::new(granted);
    run.state.tls.set_stdio(StdioGrant::new(io.clone()));
    let (result, parks) = run.run().await;
    assert_eq!((result, parks), (42, 11));
    let _ = peer.join().await;
    assert_eq!(io.pending_waiters(), 0);
    assert!(io.stdout.drained() && io.stderr.drained() && io.stdin.drained());
    let revoked = Arc::new(CommandIo::new());
    let backend = revoked.clone();
    let peer = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "native-stdio-revoke", async move {
        while backend.pending_waiters() == 0 { crate::exec::sleep_ms(1).await; }
        assert_eq!(backend.pending_waiters(), 1, "native reader must park before revocation");
        backend.deny();
    });
    extern "C" fn blocked(_: usize) -> usize {
        let mut byte = 0xa5;
        assert_eq!(unsafe { vibeos_native_read(0, &mut byte, 1) }, -3);
        assert_eq!(byte, 0xa5);
        assert_eq!(unsafe { vibeos_native_write(2, &byte, 1) }, -3);
        assert_eq!(vibeos_native_fd_kind(2), -3);
        assert_eq!(vibeos_native_close(2), 0);
        assert_eq!(vibeos_native_close(2), -1);
        42
    }
    let run = NativeAsync::new(blocked);
    run.state.tls.set_stdio(StdioGrant::new(revoked.clone()));
    assert_eq!(run.run().await, (42, 2));
    let _ = peer.join().await;
    assert_eq!(revoked.pending_waiters(), 0);
    crate::println!("NATIVE FD PASS pipe=1 close=1 stale=1 revoked_cleanup=1 drained=1");
    crate::println!("NATIVE STDIO PASS no_grant=1 backpressure=1 ordered=1 read=1 eof=1 revoked=1 waiters=0");
}

#[cfg(feature = "native-cxx-probe")]
async fn native_unlink_probe() {
    use crate::{native_files::{FileGrant, vibeos_native_unlink}, cap::Rights};
    use alloc::sync::Arc;
    use vibeos_file_store::{FileTreeRoot, RelPath, FileError};
    extern "C" fn denied(_: usize) -> usize {
        assert_eq!(unsafe { vibeos_native_unlink(b"victim".as_ptr(), 6) }, -3);
        42
    }
    assert_eq!(NativeAsync::new(denied).run().await, (42, 0));
    let root = Arc::new(FileTreeRoot::new_empty(0x6e61746976656673).unwrap());
    let path = RelPath::parse("victim").unwrap();
    let mut tx = root.begin().unwrap();
    tx.write_chunks(&path, [b"contents"], false).unwrap();
    tx.mkdir(&RelPath::parse("dir").unwrap(), false).unwrap();
    tx.commit().unwrap();
    let space = crate::world::Space::new("native-file-probe");
    let readonly = space.0.lock().mint(root.clone(), Rights::READ);
    let writable = space.0.lock().mint(root.clone(), Rights::ALL);
    let run = NativeAsync::new(denied);
    run.state.tls.set_files(FileGrant::new(space.clone(), readonly).unwrap());
    assert_eq!(run.run().await, (42, 0));
    assert!(root.snapshot().stat(&path, false).is_ok());
    extern "C" fn granted(_: usize) -> usize {
        assert_eq!(unsafe { vibeos_native_unlink(b"../victim".as_ptr(), 9) }, -3);
        assert_eq!(unsafe { vibeos_native_unlink(b"/dir".as_ptr(), 4) }, -7);
        assert_eq!(unsafe { vibeos_native_unlink(b"/victim".as_ptr(), 7) }, 0);
        assert_eq!(unsafe { vibeos_native_unlink(b"victim".as_ptr(), 6) }, -6);
        42
    }
    let grant = FileGrant::new(space.clone(), writable).unwrap();
    let run = NativeAsync::new(granted);
    run.state.tls.set_files(grant.clone());
    assert_eq!(run.run().await, (42, 1));
    assert_eq!(root.snapshot().stat(&path, false), Err(FileError::NotFound));
    space.0.lock().revoke(writable).unwrap();
    let run = NativeAsync::new(denied);
    run.state.tls.set_files(grant);
    assert_eq!(run.run().await, (42, 0));
    assert!(root.snapshot().stat(&RelPath::parse("dir").unwrap(), false).is_ok());
    crate::println!("NATIVE UNLINK PASS no_grant=1 readonly=1 escape=1 directory=1 removed=1 revoked=1");
}

#[cfg(feature = "native-cxx-probe")]
async fn native_open_probe() {
    use crate::{native_files::*, native_stdio::*, cap::Rights};
    use alloc::sync::Arc;
    use vibeos_file_store::{FileTreeRoot, RelPath};
    let root = Arc::new(FileTreeRoot::new_empty(0x6e61746976656f70).unwrap());
    let content: alloc::vec::Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    let mut tx = root.begin().unwrap();
    tx.write_chunks(&RelPath::parse("source").unwrap(), [&content], false).unwrap();
    tx.commit().unwrap();
    let space = crate::world::Space::new("native-open-probe");
    let cap = space.0.lock().mint(root, Rights::ALL);
    extern "C" fn entry(_: usize) -> usize {
        assert_eq!(unsafe { vibeos_native_open(b"../source".as_ptr(), 9, 0) }, -3);
        assert_eq!(unsafe { vibeos_native_open(b"source".as_ptr(), 6, 1) }, -13);
        let fd = unsafe { vibeos_native_open(b"/source".as_ptr(), 7, 0) };
        assert!(fd >= 3);
        assert_eq!(vibeos_native_fd_kind(fd), 2);
        assert_eq!(vibeos_native_file_size(fd), 5000);
        let mut bytes = [0xa5; 32];
        assert_eq!(unsafe { vibeos_native_read(fd, bytes.as_mut_ptr(), bytes.len()) }, 32);
        for (index, byte) in bytes.iter().enumerate() { assert_eq!(*byte, index as u8); }
        assert_eq!(vibeos_native_file_seek(fd, 4090, 0), 4090);
        assert_eq!(unsafe { vibeos_native_read(fd, bytes.as_mut_ptr(), 16) }, 6);
        for i in 0..6 { assert_eq!(bytes[i], ((4090 + i) % 251) as u8); }
        assert_eq!(unsafe { vibeos_native_read(fd, bytes.as_mut_ptr(), 16) }, 16);
        for i in 0..16 { assert_eq!(bytes[i], ((4096 + i) % 251) as u8); }
        assert_eq!(vibeos_native_file_seek(fd, -1, 0), -9);
        assert_eq!(vibeos_native_file_seek(fd, 0, 1), 4112);
        assert_eq!(vibeos_native_file_seek(fd, 0, 2), 5000);
        assert_eq!(unsafe { vibeos_native_read(fd, bytes.as_mut_ptr(), 16) }, 0);
        assert_eq!(unsafe { vibeos_native_write(fd, bytes.as_ptr(), 1) }, -1);
        assert_eq!(vibeos_native_close(fd), 0);
        assert_eq!(unsafe { vibeos_native_read(fd, bytes.as_mut_ptr(), 1) }, -1);
        let fresh = unsafe { vibeos_native_open(b"source".as_ptr(), 6, 0) };
        assert!(fresh > fd);
        revoke_probe_grant();
        bytes.fill(0xa5);
        assert_eq!(unsafe { vibeos_native_read(fresh, bytes.as_mut_ptr(), 1) }, -3);
        assert_eq!(bytes, [0xa5; 32]);
        assert_eq!(vibeos_native_file_size(fresh), -3);
        assert_eq!(vibeos_native_file_seek(fresh, 0, 0), -3);
        assert_eq!(vibeos_native_close(fresh), 0);
        42
    }
    let run = NativeAsync::new(entry);
    run.state.tls.set_files(FileGrant::new(space, cap).unwrap());
    assert_eq!(run.run().await, (42, 3));
    crate::println!("NATIVE OPEN PASS read=1 seek=1 chunks=1 eof=1 close=1 revoked=1 readonly=1");
}

#[cfg(feature = "node-runtime")]
pub(super) async fn v8_gate() {
    use alloc::sync::Arc;
    use core::future::poll_fn;
    use vibeos_wasi_command::CommandIo;
    let io = Arc::new(CommandIo::new());
    io.stdin.close();
    let stdout = io.clone();
    let out = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "v8-stdout", async move {
        let mut bytes = [0u8; 1024];
        loop {
            let count = poll_fn(|cx| stdout.stdout.read(cx, &mut bytes)).await.unwrap();
            if count == 0 { break; }
            crate::print!("{}", core::str::from_utf8(&bytes[..count]).unwrap_or("[invalid utf8]"));
        }
    });
    let stderr = io.clone();
    let err = crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "v8-stderr", async move {
        let mut bytes = [0u8; 1024];
        loop {
            let count = poll_fn(|cx| stderr.stderr.read(cx, &mut bytes)).await.unwrap();
            if count == 0 { break; }
            crate::print!("{}", core::str::from_utf8(&bytes[..count]).unwrap_or("[invalid utf8]"));
        }
    });
    extern "C" fn entry(_: usize) -> usize {
        unsafe extern "C" { fn vibeos_v8_smoke() -> i32; }
        crate::println!("V8 GATE native_entry ram=1GiB stack=256KiB");
        unsafe { vibeos_v8_smoke() as usize }
    }
    let run = NativeAsync::with_capacity(entry, 128 * 1024 * 1024);
    run.state.tls.set_stdio(crate::native_stdio::StdioGrant::new(io.clone()));
    let grant = crate::world::world().native_entropy_probe_grant().expect("V8 gate entropy grant");
    run.state.tls.set_entropy(grant);
    let (live_before, _, _) = crate::HEAP.stats();
    let (result, parks) = run.run().await;
    io.stdout.close(); io.stderr.close();
    let _ = out.join().await; let _ = err.join().await;
    let (live_after, global_peak, bump_remaining) = crate::HEAP.stats();
    crate::println!("V8 GATE memory global_live_before={} global_live_after={} global_peak={} bump_remaining={}",
                    live_before, live_after, global_peak, bump_remaining);
    crate::println!("V8 GATE returned={} parks={} waiters={}", result, parks, io.pending_waiters());
    crate::sbi::shutdown(result != 0);
}
