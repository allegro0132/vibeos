//! Invocation-local opaque handles. Handle values are never dereferenced.
use alloc::{sync::Arc, vec::Vec};
use core::{ffi::c_void, sync::atomic::{AtomicUsize, AtomicU32, Ordering}};
use crate::native_notify::NativeNotify;
static NEXT_HANDLE: AtomicUsize = AtomicUsize::new(1);
pub(super) struct Semaphore { permits: AtomicU32, notify: Arc<NativeNotify> }
impl Semaphore {
    pub(super) fn signal(&self) -> bool {
        if self.permits.fetch_update(Ordering::Release, Ordering::Relaxed,
            |n| (n < i32::MAX as u32).then_some(n + 1)).is_err() { return false; }
        self.notify.signal();
        true
    }
    fn acquire(&self) -> bool {
        self.permits.fetch_update(Ordering::Acquire, Ordering::Relaxed,
            |n| n.checked_sub(1)).is_ok()
    }
}
pub(super) struct Semaphores { entries: Vec<(usize, Arc<Semaphore>)> }
impl Semaphores {
    pub(super) fn new() -> Self { Self { entries: Vec::new() } }
    fn create(&mut self, count: i32, notify: Arc<NativeNotify>) -> *mut c_void {
        if count < 0 || self.entries.len() >= 256 || self.entries.try_reserve(1).is_err() {
            return core::ptr::null_mut();
        }
        let Ok(id) = NEXT_HANDLE.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |next| next.checked_add(1)) else { return core::ptr::null_mut(); };
        self.entries.push((id, Arc::new(Semaphore { permits: AtomicU32::new(count as u32), notify })));
        id as *mut c_void
    }
    fn get(&self, handle: usize) -> Option<Arc<Semaphore>> {
        self.entries.iter().find(|(id, _)| *id == handle).map(|(_, sem)| sem.clone())
    }
    fn destroy(&mut self, handle: usize) {
        let index = self.entries.iter().position(|(id, _)| *id == handle)
            .expect("foreign or stale native semaphore destruction");
        assert_eq!(Arc::strong_count(&self.entries[index].1), 1,
                   "native semaphore destroyed while in use");
        self.entries.swap_remove(index);
    }
}
impl Drop for Semaphores {
    fn drop(&mut self) {
        assert!(self.entries.iter().all(|(_, sem)| Arc::strong_count(sem) == 1),
                "native semaphore users outlived invocation");
    }
}
#[no_mangle]
extern "C" fn vibeos_native_semaphore_create(count: i32) -> *mut c_void {
    let notify = crate::native_tls::notification();
    crate::native_tls::with_semaphores(|table| table.create(count, notify))
}
#[no_mangle]
extern "C" fn vibeos_native_semaphore_destroy(handle: *mut c_void) {
    crate::native_tls::with_semaphores(|table| table.destroy(handle as usize));
}
#[no_mangle]
extern "C" fn vibeos_native_semaphore_signal(handle: *mut c_void) -> i32 {
    let sem = crate::native_tls::with_semaphores(|table| table.get(handle as usize));
    if sem.is_some_and(|sem| sem.signal()) { 0 } else { -1 }
}
unsafe extern "C" fn acquire(context: *mut c_void) -> i32 {
    i32::from(unsafe { &*context.cast::<Semaphore>() }.acquire())
}
#[no_mangle]
extern "C" fn vibeos_native_semaphore_wait(handle: *mut c_void, timeout_us: i64) -> i32 {
    let Some(sem) = crate::native_tls::with_semaphores(|table| table.get(handle as usize)) else { return -1; };
    // Keep the semaphore alive on the native stack while the runner parks;
    // no registry borrow crosses a context switch.
    unsafe { crate::native_wait::vibeos_native_wait_until_context(
        handle, Some(acquire), Arc::as_ptr(&sem) as *mut c_void, timeout_us) }
}

// A trusted backend receives a posting right while the owner is admitted; it
// cannot fabricate authority from a raw handle after switching contexts.
pub(super) struct PostPermit(Arc<Semaphore>);
impl PostPermit {
    pub(super) fn post(self) -> bool { self.0.signal() }
}
pub(super) fn grant_post(handle: usize) -> Option<PostPermit> {
    crate::native_tls::with_semaphores(|table| table.get(handle)).map(PostPermit)
}

// Probe-only backend: deliver a posted completion after native suspension.
#[no_mangle]
extern "C" fn vibeos_native_probe_schedule_post(handle: *mut c_void) -> i32 {
    let Some(permit) = grant_post(handle as usize) else { return -1; };
    crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "native-sem-post", async move {
        crate::exec::sleep_ms(2).await;
        assert!(permit.post());
    });
    0
}
