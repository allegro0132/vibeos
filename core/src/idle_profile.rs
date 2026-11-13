//! Single-writer, per-hart WFI interval accounting. Interrupts are
//! masked at WFI entry/exit; readers use bounded retries and include current residency.
//! No reset, allocation, locks, or packet/lock hot-path instrumentation.
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub active: bool,
    pub since: u64,
    pub now: u64,
    pub idle: u64,
    pub sleeps: u64,
}

#[repr(align(64))]
pub(crate) struct Counter {
    sequence: AtomicU64,
    active: AtomicBool,
    since: AtomicU64,
    asleep: AtomicBool,
    entered: AtomicU64,
    completed: AtomicU64,
    sleeps: AtomicU64,
}

impl Counter {
    pub const fn new() -> Self {
        Self { sequence: AtomicU64::new(0), active: AtomicBool::new(false),
            since: AtomicU64::new(0), asleep: AtomicBool::new(false),
            entered: AtomicU64::new(0), completed: AtomicU64::new(0),
            sleeps: AtomicU64::new(0) }
    }
    // Only the owning hart calls these methods. The sequence is even during
    // WFI itself; it is odd only while publishing entry/exit bookkeeping.
    pub fn activate(&self, now: u64) {
        self.sequence.fetch_add(1, SeqCst);
        self.since.store(now, SeqCst);
        self.active.store(true, SeqCst);
        self.sequence.fetch_add(1, SeqCst);
    }
    pub fn enter(&self, now: u64) {
        self.sequence.fetch_add(1, SeqCst);
        self.entered.store(now, SeqCst);
        self.asleep.store(true, SeqCst);
        self.sleeps.fetch_add(1, SeqCst);
        self.sequence.fetch_add(1, SeqCst);
    }
    pub fn leave(&self, now: u64) {
        self.sequence.fetch_add(1, SeqCst);
        let elapsed = now.wrapping_sub(self.entered.load(SeqCst));
        self.completed.fetch_add(elapsed, SeqCst);
        self.asleep.store(false, SeqCst);
        self.sequence.fetch_add(1, SeqCst);
    }
    pub fn snapshot(&self, mut clock: impl FnMut() -> u64) -> Option<Snapshot> {
        for _ in 0..64 {
            let sequence = self.sequence.load(SeqCst);
            if sequence & 1 != 0 { continue; }
            let active = self.active.load(SeqCst);
            let since = self.since.load(SeqCst);
            let asleep = self.asleep.load(SeqCst);
            let entered = self.entered.load(SeqCst);
            let completed = self.completed.load(SeqCst);
            let sleeps = self.sleeps.load(SeqCst);
            let now = clock();
            if self.sequence.load(SeqCst) != sequence { continue; }
            let idle = completed.wrapping_add(if asleep { now.wrapping_sub(entered) } else { 0 });
            return Some(Snapshot { active, since, now, idle, sleeps });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ongoing_intervals_and_busy_time_are_distinct() {
        let c = Counter::new();
        assert!(!c.snapshot(|| 5).unwrap().active);
        c.activate(10);
        c.enter(20);
        assert_eq!(c.snapshot(|| 35).unwrap().idle, 15);
        c.leave(40);
        assert_eq!(c.snapshot(|| 90).unwrap().idle, 20);
        c.enter(100);
        let s = c.snapshot(|| 110).unwrap();
        assert_eq!((s.idle, s.sleeps, s.since), (30, 2, 10));
    }
    #[test]
    fn reader_retries_concurrent_exit_without_double_counting() {
        let c = Counter::new(); c.activate(1); c.enter(10);
        let mut first = true;
        let s = c.snapshot(|| {
            if first { first = false; c.leave(30); }
            40
        }).unwrap();
        assert_eq!(s.idle, 20);
        c.sequence.store(3, SeqCst);
        assert!(c.snapshot(|| 50).is_none());
    }
    #[test]
    fn timer_wrap_and_zero_length_wfi_are_supported() {
        let c = Counter::new(); c.activate(u64::MAX - 10); c.enter(u64::MAX - 2);
        assert_eq!(c.snapshot(|| 2).unwrap().idle, 5);
        c.leave(3);
        c.enter(4); c.leave(4);
        assert_eq!(c.snapshot(|| 8).unwrap().idle, 6);
    }
}
