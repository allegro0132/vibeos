//! Embedder hooks for the no_std `threads` implementation.
//!
//! Without `std` there is no OS thread to park, so `memory.atomic.wait*`
//! suspends the current async fiber instead. The embedder identifies the
//! executing guest thread with a copy-only token, wakes a token when another
//! thread notifies it, and supplies a timer future for bounded waits.

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

/// Scheduler integration for guest threads sharing one linear memory.
///
/// All methods may be called from any guest thread. `wake` may be called
/// while another thread is suspended in `wait`; it must not allocate, block or
/// re-enter the runtime. `sleep` is only called on a fiber and its future is
/// polled with the same `Context` that drives the guest's async call.
pub trait ThreadHooks: Send + Sync + 'static {
    /// Copy-only identity of the currently executing guest thread.
    fn current(&self) -> [usize; 2];
    /// Make the thread identified by `token` poll its guest call again.
    fn wake(&self, token: [usize; 2]);
    /// A future that completes after at least `nanoseconds`.
    fn sleep(&self, nanoseconds: u64) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}
