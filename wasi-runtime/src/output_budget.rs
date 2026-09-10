//! Whole-invocation output ceiling shared by every guest thread of a command.
//!
//! Threads on several harts write the same stdout/stderr pipes. Each write
//! first reserves its bytes here, so two writers that observe the same
//! remaining count cannot both spend it; the counter never wraps.
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct OutputBudget(AtomicUsize);

impl OutputBudget {
    pub const fn new(bytes: usize) -> Self {
        Self(AtomicUsize::new(bytes))
    }
    /// Reserve up to `want` bytes. The grant never exceeds what is left, so
    /// concurrent reservations cannot overdraw the ceiling.
    pub fn reserve(&self, want: usize) -> usize {
        let mut left = self.0.load(Ordering::Acquire);
        loop {
            let granted = left.min(want);
            match self.0.compare_exchange_weak(left, left - granted, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return granted,
                Err(current) => left = current,
            }
        }
    }
    /// Return the unused part of an earlier reservation.
    pub fn release(&self, unused: usize) {
        self.0.fetch_add(unused, Ordering::AcqRel);
    }
    pub fn remaining(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::OutputBudget;
    #[test]
    fn reservations_never_overdraw_or_wrap() {
        let budget = OutputBudget::new(100);
        assert_eq!(budget.reserve(60), 60);
        // A second writer that raced the first is clamped to what is left.
        assert_eq!(budget.reserve(60), 40);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.reserve(1), 0);
        assert_eq!(budget.remaining(), 0, "an exhausted budget must not wrap");
        budget.release(15);
        assert_eq!(budget.reserve(usize::MAX), 15);
        assert_eq!(budget.reserve(0), 0);
    }
}
