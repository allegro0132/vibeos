//! Short cooperative polling grace after progress on a polling-only transport.
//! Callers must yield between attempts; this never spins inside a task poll.
pub struct PollBudget {
    window: u64,
    limit: usize,
    last: Option<u64>,
    remaining: usize,
}
impl PollBudget {
    /// `now` passed to `runnable` uses the same units as `window`.
    pub const fn new(window: u64, attempts: usize) -> Self {
        Self { window, limit: attempts, last: None, remaining: 0 }
    }
    /// Actual progress renews grace. Empty polls cannot extend it, and the
    /// attempt cap bounds work even if the clock is unavailable or stops.
    pub fn runnable(&mut self, now: u64, progress: bool) -> bool {
        let runnable = self.decide(now, progress);
        crate::net_profile::poll_decision(progress, runnable);
        runnable
    }
    fn decide(&mut self, now: u64, progress: bool) -> bool {
        if progress {
            self.last = Some(now);
            self.remaining = self.limit;
            return true;
        }
        if self.remaining != 0 && self.last.is_some_and(|last| now.wrapping_sub(last) < self.window) {
            self.remaining -= 1;
            return true;
        }
        self.last = None;
        self.remaining = 0;
        false
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_has_no_grace_and_empty_polls_do_not_renew_it() {
        let mut b = PollBudget::new(4, 64);
        assert!(!b.runnable(100, false));
        assert!(b.runnable(100, true));
        assert!(b.runnable(103, false));
        assert!(!b.runnable(104, false));
        assert!(!b.runnable(105, false));
    }
    #[test]
    fn stopped_clock_is_bounded_and_progress_rearms() {
        let mut b = PollBudget::new(4, 2);
        assert!(b.runnable(0, true));
        assert!(b.runnable(0, false));
        assert!(b.runnable(0, false));
        assert!(!b.runnable(0, false));
        assert!(b.runnable(1, true));
        assert!(b.runnable(1, false));
    }
    #[test]
    fn wrapping_clock_preserves_bounded_elapsed_time() {
        let mut b = PollBudget::new(3, 64);
        assert!(b.runnable(u64::MAX - 1, true));
        assert!(b.runnable(0, false));
        assert!(!b.runnable(1, false));
    }
}
