//! GCC 14 emulated TLS, scoped to one admitted native execution context.
//! Compiler-generated dynamic initialization and explicit normal-exit cleanup.
use alloc::{alloc::{alloc_zeroed, dealloc}, boxed::Box, vec::Vec};
use core::{alloc::Layout, cell::{Cell, RefCell}, arch::asm, sync::atomic::{AtomicUsize, Ordering}};

// GCC libgcc/emutls.c: word-sized size/alignment, location union, template.
// The descriptor is shared static compiler data; never store instance values
// in its location union (the threadless libgcc fallback does exactly that).
#[repr(C)]
struct Descriptor { size: usize, alignment: usize, location: usize, template: *const u8 }
struct Slot { descriptor: usize, pointer: usize, layout: Layout }
impl Drop for Slot {
    fn drop(&mut self) { unsafe { dealloc(self.pointer as *mut u8, self.layout); } }
}
struct Destructor { callback: unsafe extern "C" fn(*mut core::ffi::c_void), object: usize }
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct StackBounds { low: usize, high: usize }
pub(super) type PendingPoll = unsafe fn(usize, &mut core::task::Context<'_>) -> core::task::Poll<()>;
#[derive(Clone, Copy)]
pub(super) struct ParkHook {
    pub context: usize,
    pub call: unsafe fn(usize, usize, PendingPoll) -> bool,
}
struct State {
    file_table: RefCell<crate::native_files::FileTable>,
    files: RefCell<Option<crate::native_files::FileGrant>>,
    stdio: RefCell<Option<crate::native_stdio::StdioGrant>>,
    #[cfg(feature = "queued-entropy")]
    entropy: RefCell<Option<crate::native_entropy::EntropyGrant>>,
    park: Cell<Option<ParkHook>>,
    semaphores: RefCell<crate::native_semaphore::Semaphores>,
    notify: alloc::sync::Arc<crate::native_notify::NativeNotify>,
    wait_key: Cell<Option<usize>>,
    id: i32,
    memory: RefCell<crate::native_memory::NativeMemory>,
    stack: StackBounds,
    slots: RefCell<Vec<Slot>>,
    destructors: RefCell<Vec<Destructor>>,
    phase: Cell<u8>, // 0: live, 1: finalizing, 2: finalized
}
// All native code is statically linked into this image; dlopen is unsupported.
#[no_mangle]
static __dso_handle: usize = 0;
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub(super) struct NativeTls { state: Box<State> }
pub(super) struct ActiveTls<'a>(&'a NativeTls);
impl NativeTls {
    pub(super) fn new(stack_low: usize, stack_high: usize, page_capacity: usize) -> Self {
        assert!(stack_low != 0 && stack_low < stack_high);
        assert_eq!((stack_low | stack_high) % 16, 0);
        let id = NEXT_ID.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |next| (next <= i32::MAX as usize).then_some(next + 1))
            .expect("native execution identity space exhausted") as i32;
        Self { state: Box::new(State {
            file_table: RefCell::new(crate::native_files::FileTable::new()),
            files: RefCell::new(None),
            stdio: RefCell::new(None),
            #[cfg(feature = "queued-entropy")]
            entropy: RefCell::new(None),
            semaphores: RefCell::new(crate::native_semaphore::Semaphores::new()), park: Cell::new(None), notify: crate::native_notify::NativeNotify::new(), wait_key: Cell::new(None), id, memory: RefCell::new(crate::native_memory::NativeMemory::new(page_capacity)), stack: StackBounds { low: stack_low, high: stack_high }, slots: RefCell::new(Vec::new()),
            destructors: RefCell::new(Vec::new()), phase: Cell::new(0) }) }
    }
    /// The pinned runner must outlive all native frames using this hook.
    pub(super) unsafe fn set_park_hook(&self, hook: ParkHook) { self.state.park.set(Some(hook)); }
    #[cfg(feature = "queued-entropy")]
    pub(super) fn set_entropy(&self, grant: crate::native_entropy::EntropyGrant) {
        assert_ne!(ACTIVE.load(Ordering::Acquire), self.pointer());
        *self.state.entropy.borrow_mut() = Some(grant);
    }
    pub(super) fn set_files(&self, grant: crate::native_files::FileGrant) {
        assert_ne!(ACTIVE.load(Ordering::Acquire), self.pointer());
        *self.state.files.borrow_mut() = Some(grant);
    }
    pub(super) fn set_stdio(&self, grant: crate::native_stdio::StdioGrant) {
        assert_ne!(ACTIVE.load(Ordering::Acquire), self.pointer());
        *self.state.stdio.borrow_mut() = Some(grant);
    }
    pub(super) fn revoke_memory(&self) { self.state.memory.borrow_mut().revoke(); }
    pub(super) fn id(&self) -> i32 { self.state.id }
    pub(super) fn pointer(&self) -> usize { (&*self.state as *const State) as usize }
    /// The caller must restore tp and stop executing native frames before
    /// dropping the guard. Suspended frames must retain their NativeTls owner
    /// until normal completion. Only one context may execute at a time.
    pub(super) unsafe fn activate(&self) -> ActiveTls<'_> {
        assert!(ACTIVE.compare_exchange(0, self.pointer(), Ordering::AcqRel,
                                        Ordering::Acquire).is_ok());
        ActiveTls(self)
    }
}
impl Drop for NativeTls {
    fn drop(&mut self) {
        assert_ne!(ACTIVE.load(Ordering::Acquire), self.pointer());
        assert!(self.state.destructors.borrow().is_empty(),
                "TLS destructors must finish on the native stack before release");
    }
}

// Called only on the protected native stack, after user/native frames returned.
// A callback may register further cleanup, which is consumed in LIFO order.
pub(super) fn finish_current() -> usize {
    let state = unsafe { current_state() };
    assert_eq!(state.phase.replace(1), 0, "recursive or repeated TLS finalization");
    let mut count = 0;
    loop {
        let next = state.destructors.borrow_mut().pop();
        let Some(next) = next else { break; };
        unsafe { (next.callback)(next.object as *mut core::ffi::c_void); }
        count += 1;
    }
    state.phase.set(2);
    count
}

#[no_mangle]
unsafe extern "C" fn __cxa_thread_atexit(
    callback: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>,
    object: *mut core::ffi::c_void, dso: *mut core::ffi::c_void,
) -> i32 {
    assert_eq!(dso as usize, core::ptr::addr_of!(__dso_handle) as usize,
               "TLS cleanup requires the statically linked image");
    let state = unsafe { current_state() };
    let mut destructors = state.destructors.borrow_mut();
    destructors.try_reserve(1).expect("TLS destructor registration failed");
    destructors.push(Destructor { callback: callback.expect("null TLS destructor"),
                                  object: object as usize });
    0
}

impl Drop for ActiveTls<'_> {
    fn drop(&mut self) {
        assert_eq!(ACTIVE.swap(0, Ordering::AcqRel), self.0.pointer());
    }
}

// The returned borrow is confined to a native callback while ACTIVE's guard
// retains the owner. No reference may survive a switch back to the scheduler.
unsafe fn current_state() -> &'static State {
    let active = ACTIVE.load(Ordering::Acquire);
    let tp: usize;
    unsafe { asm!("mv {}, tp", out(reg) tp, options(nomem, nostack)); }
    assert!(active != 0 && active == tp, "TLS access outside admitted native context");
    let state = unsafe { &*(active as *const State) };
    assert_ne!(state.phase.get(), 2, "TLS access after finalization");
    state
}

#[no_mangle]
extern "C" fn vibeos_native_thread_id() -> i32 {
    unsafe { current_state() }.id
}

pub(super) fn with_memory<R>(f: impl FnOnce(&mut crate::native_memory::NativeMemory) -> R) -> R {
    let state = unsafe { current_state() };
    f(&mut state.memory.borrow_mut())
}

pub(super) fn require_current() {
    let _ = unsafe { current_state() };
}

#[no_mangle]
extern "C" fn vibeos_native_stack_bounds() -> StackBounds {
    let state = unsafe { current_state() };
    let sp: usize;
    unsafe { asm!("mv {}, sp", out(reg) sp, options(nomem, nostack)); }
    assert!((state.stack.low..state.stack.high).contains(&sp),
            "native stack metadata does not describe the executing stack");
    state.stack
}

#[no_mangle]
unsafe extern "C" fn __emutls_get_address(descriptor: *const Descriptor) -> *mut u8 {
    let state = unsafe { current_state() };
    assert!(!descriptor.is_null());
    let mut slots = state.slots.borrow_mut();
    if let Some(slot) = slots.iter().find(|slot| slot.descriptor == descriptor as usize) {
        return slot.pointer as *mut u8;
    }
    let desc = unsafe { &*descriptor };
    assert!(desc.size > 0);
    let layout = Layout::from_size_align(desc.size, desc.alignment).expect("invalid GCC TLS descriptor");
    slots.try_reserve(1).expect("TLS slot allocation failed");
    let pointer = unsafe { alloc_zeroed(layout) };
    assert!(!pointer.is_null(), "TLS value allocation failed");
    if !desc.template.is_null() {
        unsafe { core::ptr::copy_nonoverlapping(desc.template, pointer, desc.size); }
    }
    slots.push(Slot { descriptor: descriptor as usize, pointer: pointer as usize, layout });
    pointer
}

pub(super) fn park(future: impl core::future::Future<Output = ()>) -> bool {
    let Some(hook) = (unsafe { current_state() }).park.get() else { return false; };
    unsafe fn poll<F: core::future::Future<Output = ()>>(data: usize, cx: &mut core::task::Context<'_>) -> core::task::Poll<()> {
        unsafe { core::pin::Pin::new_unchecked(&mut *(data as *mut F)) }.poll(cx)
    }
    fn run<F: core::future::Future<Output = ()>>(future: F, hook: ParkHook) -> bool {
        let mut future = core::pin::pin!(future);
        let data = unsafe { future.as_mut().get_unchecked_mut() as *mut F } as usize;
        // The runner may poll this address only while this C++/Rust stack is
        // parked. The hook must stop polling before returning here.
        unsafe { (hook.call)(hook.context, data, poll::<F>) }
    }
    run(future, hook)
}
pub(super) struct WaitAdmission {
    state: &'static State,
    pub notify: alloc::sync::Arc<crate::native_notify::NativeNotify>,
}
pub(super) fn admit_wait(key: usize) -> Option<WaitAdmission> {
    let state = unsafe { current_state() };
    if state.wait_key.get().is_some() { return None; }
    state.wait_key.set(Some(key));
    Some(WaitAdmission { state, notify: state.notify.clone() })
}
impl Drop for WaitAdmission {
    fn drop(&mut self) { self.state.wait_key.set(None); }
}
pub(super) fn wake_key(key: usize) {
    let state = unsafe { current_state() };
    if state.wait_key.get() == Some(key) { state.notify.signal(); }
}

pub(super) fn notification() -> alloc::sync::Arc<crate::native_notify::NativeNotify> {
    unsafe { current_state() }.notify.clone()
}
pub(super) fn with_semaphores<R>(f: impl FnOnce(&mut crate::native_semaphore::Semaphores) -> R) -> R {
    let state = unsafe { current_state() };
    f(&mut state.semaphores.borrow_mut())
}

#[cfg(feature = "queued-entropy")]
pub(super) fn entropy_grant() -> Option<crate::native_entropy::EntropyGrant> {
    unsafe { current_state() }.entropy.borrow().clone()
}

pub(super) fn stdio_grant() -> Option<crate::native_stdio::StdioGrant> {
    unsafe { current_state() }.stdio.borrow().clone()
}

pub(super) fn file_grant() -> Option<crate::native_files::FileGrant> {
    unsafe { current_state() }.files.borrow().clone()
}

pub(super) fn with_file_table<R>(f: impl FnOnce(&mut crate::native_files::FileTable) -> R) -> R {
    f(&mut unsafe { current_state() }.file_table.borrow_mut())
}
