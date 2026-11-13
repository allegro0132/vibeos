//! Bounded timer-PC diagnostics. IRQ-masked execution is underrepresented:
//! delayed interrupts often land at irq_restore, and RA is not a stack trace.
//! One writer per logical hart (non-nested timer traps), one capture per boot.
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

const ARMED: usize = 2;
const FROZEN: usize = 3;
pub const CAPACITY: usize = 4096;
pub static RECORDER: Recorder<CAPACITY> = Recorder::new();

struct Entry {
    time: AtomicU64,
    due: AtomicU64,
    pc: AtomicUsize,
    ra: AtomicUsize,
}
impl Entry {
    const fn new() -> Self {
        Self {
            time: AtomicU64::new(0),
            due: AtomicU64::new(0),
            pc: AtomicUsize::new(0),
            ra: AtomicUsize::new(0),
        }
    }
}
#[repr(align(64))]
struct Hart<const N: usize> {
    busy: AtomicBool,
    next: AtomicU64,
    count: AtomicUsize,
    dropped: AtomicUsize,
    entries: [Entry; N],
}
impl<const N: usize> Hart<N> {
    const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            next: AtomicU64::new(0),
            count: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            entries: [const { Entry::new() }; N],
        }
    }
}
pub struct Recorder<const N: usize> {
    state: AtomicUsize,
    start: AtomicU64,
    end: AtomicU64,
    period: AtomicU64,
    harts: [Hart<N>; crate::runqueue::MAX_HARTS],
}
impl<const N: usize> Recorder<N> {
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            period: AtomicU64::new(0),
            harts: [const { Hart::new() }; crate::runqueue::MAX_HARTS],
        }
    }
    pub fn start(&self, now: u64, hz: u64, seconds: u64) -> bool {
        // 2 ms, at most 5 s: the buffer accommodates every scheduled sample.
        if !(1..=5).contains(&seconds) || hz < 500 {
            return false;
        }
        let Some(end) = hz.checked_mul(seconds).and_then(|d| now.checked_add(d)) else {
            return false;
        };
        if self.state.compare_exchange(0, 1, SeqCst, SeqCst).is_err() {
            return false;
        }
        let period = hz / 500 + u64::from(hz % 500 != 0);
        self.start.store(now, SeqCst);
        self.end.store(end, SeqCst);
        self.period.store(period, SeqCst);
        for h in &self.harts {
            h.next.store(now + period, SeqCst);
        }
        self.state.store(ARMED, SeqCst);
        true
    }
    /// Compose with the scheduler's existing deadline; never postpone it.
    pub fn deadline(&self, hart: usize, now: u64, scheduled: u64) -> u64 {
        if self.state.load(SeqCst) != ARMED || now >= self.end.load(SeqCst) {
            return scheduled;
        }
        self.harts
            .get(hart)
            .map_or(scheduled, |h| scheduled.min(h.next.load(SeqCst)))
    }
    pub fn record(&self, hart: usize, now: u64, pc: usize, ra: usize) {
        if self.state.load(SeqCst) != ARMED {
            return;
        }
        let Some(h) = self.harts.get(hart) else {
            return;
        };
        h.busy.store(true, SeqCst);
        // Freeze can race entry. The second state check and busy handshake
        // guarantee a successful freeze cannot precede an unpublished write.
        if self.state.load(SeqCst) == ARMED && now < self.end.load(SeqCst) {
            let due = h.next.load(SeqCst);
            if now >= due {
                // Skip missed periods, retaining lateness; no catch-up IRQ storm.
                let period = self.period.load(SeqCst);
                h.next.store(now.saturating_add(period), SeqCst);
                let n = h.count.load(SeqCst);
                if let Some(e) = h.entries.get(n) {
                    e.time.store(now, SeqCst);
                    e.due.store(due, SeqCst);
                    e.pc.store(pc, SeqCst);
                    e.ra.store(ra, SeqCst);
                    h.count.store(n + 1, SeqCst);
                } else {
                    h.dropped.fetch_add(1, SeqCst);
                }
            }
        }
        h.busy.store(false, SeqCst);
    }
    /// No spinning: callers retry if the last IRQ writer has not drained.
    pub fn freeze(&self, now: u64) -> bool {
        if now < self.end.load(SeqCst) {
            return false;
        }
        let state = self.state.load(SeqCst);
        if state != ARMED && state != FROZEN {
            return false;
        }
        self.state.store(FROZEN, SeqCst);
        self.harts.iter().all(|h| !h.busy.load(SeqCst))
    }
    pub fn window(&self) -> (u64, u64, u64) {
        (
            self.start.load(SeqCst),
            self.end.load(SeqCst),
            self.period.load(SeqCst),
        )
    }
    /// Call only after successful freeze. Entries are atomic even on misuse.
    pub fn count(&self, hart: usize) -> (usize, usize) {
        let h = &self.harts[hart];
        (h.count.load(SeqCst), h.dropped.load(SeqCst))
    }
    pub fn sample(&self, hart: usize, index: usize) -> (u64, u64, usize, usize) {
        let e = &self.harts[hart].entries[index];
        (
            e.time.load(SeqCst),
            e.due.load(SeqCst),
            e.pc.load(SeqCst),
            e.ra.load(SeqCst),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deadlines_expiry_and_capacity() {
        let p = Recorder::<2>::new();
        assert!(!p.start(0, 1000, 6));
        assert!(p.start(100, 1000, 1));
        assert!(!p.start(100, 1000, 1));
        assert_eq!(p.deadline(0, 100, 101), 101);
        assert_eq!(p.deadline(0, 100, 10000), 102);
        p.record(0, 101, 1, 2);
        assert_eq!(p.count(0), (0, 0));
        p.record(0, 102, 3, 4);
        p.record(0, 110, 5, 6);
        assert_eq!(p.sample(0, 1), (110, 104, 5, 6));
        assert_eq!(p.deadline(0, 110, 10000), 112);
        p.record(0, 112, 7, 8);
        assert_eq!(p.count(0), (2, 1));
        assert!(!p.freeze(1099));
        p.record(1, 1100, 1, 2);
        assert_eq!(p.count(1), (0, 0));
        assert_eq!(p.deadline(0, 1100, 9999), 9999);
        assert!(p.freeze(1100));
        p.record(0, 113, 9, 10);
        assert_eq!(p.sample(0, 0), (102, 102, 3, 4));
    }
    #[test]
    fn non_divisible_timebase_does_not_exceed_sample_rate() {
        let p = Recorder::<2>::new();
        assert!(p.start(0, 999, 5));
        assert_eq!(p.window(), (0, 4995, 2));
        assert_eq!(p.deadline(0, 0, 9999), 2);
    }

    #[test]
    fn freeze_requires_writer_drain() {
        let p = Recorder::<2>::new();
        assert!(p.start(0, 1000, 1));
        p.harts[0].busy.store(true, SeqCst);
        assert!(!p.freeze(1000));
        p.harts[0].busy.store(false, SeqCst);
        assert!(p.freeze(1000));
        p.record(0, 500, 1, 2);
        assert_eq!(p.count(0), (0, 0));
    }
}
