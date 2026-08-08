//! Host stand-in, used only when compiling for `cargo test`.
//!
//! Interrupts are a no-op: host tests exercise scheduler *logic*, never
//! interrupt ordering. Ordering bugs are the kind this shim cannot reproduce,
//! which is exactly why the in-kernel self-test exists alongside it.
//!
//! Time is a counter the test drives by hand, so timer tests are deterministic
//! rather than racy.

use core::sync::atomic::{AtomicU64, Ordering};

static NOW: AtomicU64 = AtomicU64::new(0);
static NEXT_TIMER: AtomicU64 = AtomicU64::new(u64::MAX);

pub fn irq_save() -> bool {
    false
}
pub fn irq_restore(_was_on: bool) {}
pub fn enable_interrupts() {}
pub fn wait_for_interrupt() {}

pub fn time() -> u64 {
    NOW.load(Ordering::SeqCst)
}

pub fn set_timer(stime: u64) {
    NEXT_TIMER.store(stime, Ordering::SeqCst);
}

// --- test controls ---

/// Move the simulated clock forward.
pub fn advance_time(ticks: u64) {
    NOW.fetch_add(ticks, Ordering::SeqCst);
}

/// Reset the clock. Call at the start of any test that inspects time.
pub fn reset_time() {
    NOW.store(0, Ordering::SeqCst);
    NEXT_TIMER.store(u64::MAX, Ordering::SeqCst);
}

/// The deadline most recently handed to `set_timer`.
pub fn armed_timer() -> u64 {
    NEXT_TIMER.load(Ordering::SeqCst)
}
