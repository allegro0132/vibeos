#[cfg(feature = "std")]
pub use std::sync::Mutex;
#[cfg(not(feature = "std"))]
#[derive(Default)]
pub struct Mutex<T>(spin::Mutex<T>);
#[cfg(not(feature = "std"))]
impl<T> Mutex<T> {
    // The kernel uses aborting panics, so there is no poisoned-lock state.
    pub fn lock(&self) -> Result<spin::MutexGuard<'_, T>, core::convert::Infallible> {
        Ok(self.0.lock())
    }
}
