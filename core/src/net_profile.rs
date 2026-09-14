//! Diagnostic-only bounded network timeline. Units are elapsed timer ticks,
//! not CPU cycles. Scopes must not cross await points. No sampling-time output,
//! allocation, locks, or reset; one capture window is permitted per boot.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage { Executor, Driver, Stack, Application, Other, Rx, Tx, Frontend }
pub const NAMES: [&str; 8] = ["executor", "driver", "stack", "application", "other", "rx", "tx", "frontend"];

#[cfg(feature = "network-profile")]
mod enabled;
#[cfg(feature = "network-profile")]
pub use enabled::*;

#[cfg(not(feature = "network-profile"))]
pub struct Scope;
#[cfg(not(feature = "network-profile"))]
impl Scope {
    #[inline(always)] pub fn enter(_: Stage) -> Self { Self }
    #[inline(always)] pub fn task(_: &str) -> Self { Self }
}
#[cfg(not(feature = "network-profile"))]
#[inline(always)] pub fn queue(_: &str, _: usize, _: bool) {}
