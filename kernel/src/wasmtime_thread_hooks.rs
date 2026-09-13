//! Scheduler hooks for wasi-threads: identify the running guest thread, wake a
//! suspended sibling through its SYSTEM-owned poll signal, and time out waits
//! with the executor's timers. Tokens are copy-only scalars.
use alloc::boxed::Box;
use core::{future::Future, pin::Pin, sync::atomic::{AtomicUsize, Ordering}};
use vibeos_wasmtime_runtime::wasmtime::ThreadHooks;
/// The job record address and thread index polling a fiber on each hart.
/// Zero means no guest thread is running there.
static CURRENT_JOB: [AtomicUsize; crate::exec::MAX_HARTS] = [const { AtomicUsize::new(0) }; crate::exec::MAX_HARTS];
static CURRENT_THREAD: [AtomicUsize; crate::exec::MAX_HARTS] = [const { AtomicUsize::new(0) }; crate::exec::MAX_HARTS];
/// Called by a thread task on its hart before polling its fiber.
pub(crate) fn enter(job: usize, thread: usize) {
    let hart = super::hart();
    CURRENT_JOB[hart].store(job, Ordering::Relaxed);
    CURRENT_THREAD[hart].store(thread, Ordering::Relaxed);
}
pub(crate) fn leave() { enter(0, 0); }
/// Raw fault recovery: no hart may keep naming a job whose arena is gone.
pub(crate) fn clear_job(job: usize) {
    for hart in 0..crate::exec::MAX_HARTS {
        if CURRENT_JOB[hart].load(Ordering::Relaxed) == job {
            CURRENT_JOB[hart].store(0, Ordering::Relaxed);
            CURRENT_THREAD[hart].store(0, Ordering::Relaxed);
        }
    }
}
pub(crate) struct KernelThreadHooks;
impl ThreadHooks for KernelThreadHooks {
    fn current(&self) -> [usize; 2] {
        let hart = super::hart();
        [CURRENT_JOB[hart].load(Ordering::Relaxed), CURRENT_THREAD[hart].load(Ordering::Relaxed)]
    }
    fn wake(&self, token: [usize; 2]) {
        // A zero job is a probe driving its stores directly; it re-polls.
        if token[0] != 0 {
            #[cfg(feature = "wasmtime-command")]
            crate::wasi::wasmtime_backend::wake_thread(token[0], token[1]);
        }
    }
    fn sleep(&self, nanoseconds: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(crate::exec::sleep_ms(nanoseconds.div_ceil(1_000_000).max(1)))
    }
}
