//! Opt-in memcpy sampling. Times include interrupts and timer-read overhead;
//! this is not an instruction counter. Inline copies and memmove are excluded.
//! One bounded capture per boot; no allocation, payload inspection, or output
//! occurs in the copy path. Reentrant copies on a sampled hart are not sampled.
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

pub const INTERVAL: u64 = 127;
pub const MIN_BYTES: usize = 256;
pub const CAPACITY: usize = 512;
const ARMED: usize = 2;
const FROZEN: usize = 3;
pub static RECORDER: Recorder<CAPACITY> = Recorder::new();

struct Entry {
    caller: AtomicUsize,
    key: AtomicUsize,
    calls: AtomicU64,
    bytes: AtomicU64,
    ticks: AtomicU64,
    max_ticks: AtomicU64,
}
impl Entry {
    const fn new() -> Self {
        Self {
            caller: AtomicUsize::new(0),
            key: AtomicUsize::new(0),
            calls: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            max_ticks: AtomicU64::new(0),
        }
    }
}
#[repr(align(64))]
struct Hart<const N: usize> {
    busy: AtomicBool,
    eligible: AtomicU64,
    dropped: AtomicU64,
    entries: [Entry; N],
}
impl<const N: usize> Hart<N> {
    const fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
            eligible: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            entries: [const { Entry::new() }; N],
        }
    }
}
pub struct Recorder<const N: usize> {
    state: AtomicUsize,
    start: AtomicU64,
    end: AtomicU64,
    harts: [Hart<N>; crate::runqueue::MAX_HARTS],
}
pub struct Sample {
    hart: usize,
    caller: usize,
    key: usize,
    bytes: usize,
    start: u64,
    _not_send: PhantomData<*mut ()>,
}
impl<const N: usize> Recorder<N> {
    pub const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            harts: [const { Hart::new() }; crate::runqueue::MAX_HARTS],
        }
    }
    pub fn start(&self, now: u64, hz: u64, seconds: u64) -> bool {
        if N == 0 || hz == 0 || !(1..=5).contains(&seconds) {
            return false;
        }
        let Some(end) = hz.checked_mul(seconds).and_then(|n| now.checked_add(n)) else {
            return false;
        };
        if self.state.compare_exchange(0, 1, SeqCst, SeqCst).is_err() {
            return false;
        }
        self.start.store(now, SeqCst);
        self.end.store(end, SeqCst);
        self.state.store(ARMED, SeqCst);
        true
    }
    #[inline]
    pub fn armed(&self) -> bool {
        self.state.load(SeqCst) == ARMED
    }
    pub fn window(&self) -> (u64, u64) {
        (self.start.load(SeqCst), self.end.load(SeqCst))
    }
    pub fn begin(
        &self,
        now: u64,
        hart: usize,
        caller: usize,
        src: usize,
        dst: usize,
        bytes: usize,
    ) -> Option<Sample> {
        if !self.armed() || bytes < MIN_BYTES || now >= self.end.load(SeqCst) {
            return None;
        }
        let h = self.harts.get(hart)?;
        if h.busy
            .compare_exchange(false, true, SeqCst, SeqCst)
            .is_err()
        {
            return None;
        }
        // Freeze and writer admission handshake: after FROZEN is visible no
        // new writer can publish, and a previously admitted writer stays busy.
        if !self.armed() || now < self.start.load(SeqCst) {
            h.busy.store(false, SeqCst);
            return None;
        }
        let count = h.eligible.fetch_add(1, SeqCst);
        if count % INTERVAL != 0 {
            h.busy.store(false, SeqCst);
            return None;
        }
        let bin = (usize::BITS - 1 - bytes.leading_zeros())
            .saturating_sub(8)
            .min(7) as usize;
        Some(Sample {
            hart,
            caller,
            key: (src & 7) | ((dst & 7) << 3) | (bin << 6),
            bytes,
            start: now,
            _not_send: PhantomData,
        })
    }
    pub fn finish(&self, sample: Sample, now: u64) {
        let h = &self.harts[sample.hart];
        let hash = (sample.caller >> 2) ^ sample.key.wrapping_mul(37);
        let ticks = now.saturating_sub(sample.start);
        let mut recorded = false;
        for offset in 0..N {
            let e = &h.entries[hash.wrapping_add(offset) % N];
            let calls = e.calls.load(SeqCst);
            if calls == 0
                || (e.caller.load(SeqCst) == sample.caller && e.key.load(SeqCst) == sample.key)
            {
                e.caller.store(sample.caller, SeqCst);
                e.key.store(sample.key, SeqCst);
                e.bytes.fetch_add(sample.bytes as u64, SeqCst);
                e.ticks.fetch_add(ticks, SeqCst);
                e.max_ticks.fetch_max(ticks, SeqCst);
                e.calls.store(calls + 1, SeqCst);
                recorded = true;
                break;
            }
        }
        if !recorded {
            h.dropped.fetch_add(1, SeqCst);
        }
        h.busy.store(false, SeqCst);
    }
    pub fn freeze(&self, now: u64) -> bool {
        let state = self.state.load(SeqCst);
        if state != ARMED && state != FROZEN {
            return false;
        }
        if now < self.end.load(SeqCst) {
            return false;
        }
        self.state.store(FROZEN, SeqCst);
        self.harts.iter().all(|h| !h.busy.load(SeqCst))
    }
    /// Read only after freeze returned true; all fields are POD snapshots.
    pub fn counts(&self, hart: usize) -> (u64, u64) {
        let h = &self.harts[hart];
        (h.eligible.load(SeqCst), h.dropped.load(SeqCst))
    }
    pub fn entry(&self, hart: usize, index: usize) -> (usize, usize, u64, u64, u64, u64) {
        let e = &self.harts[hart].entries[index];
        (
            e.caller.load(SeqCst),
            e.key.load(SeqCst),
            e.calls.load(SeqCst),
            e.bytes.load(SeqCst),
            e.ticks.load(SeqCst),
            e.max_ticks.load(SeqCst),
        )
    }
}

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    r#"
    .section .text.__wrap_memcpy,"ax"
    .global __wrap_memcpy
    .type __wrap_memcpy,@function
__wrap_memcpy:
    mv a3, ra
    tail __vibeos_profile_memcpy
    .size __wrap_memcpy, .-__wrap_memcpy
"#
);
#[cfg(target_arch = "riscv64")]
extern "C" {
    fn __real_memcpy(dst: *mut u8, src: *const u8, bytes: usize) -> *mut u8;
}
#[cfg(target_arch = "riscv64")]
#[no_mangle]
unsafe extern "C" fn __vibeos_profile_memcpy(
    dst: *mut u8,
    src: *const u8,
    bytes: usize,
    caller: usize,
) -> *mut u8 {
    let sample = if bytes >= MIN_BYTES && RECORDER.armed() {
        crate::arch::cached_logical_hart_index().and_then(|hart| {
            RECORDER.begin(
                crate::arch::time(),
                hart,
                caller,
                src as usize,
                dst as usize,
                bytes,
            )
        })
    } else {
        None
    };
    // Begin bookkeeping is deliberately outside the measured interval.
    let sample = sample.map(|mut s| {
        s.start = crate::arch::time();
        s
    });
    let result = unsafe { __real_memcpy(dst, src, bytes) };
    if let Some(sample) = sample {
        RECORDER.finish(sample, crate::arch::time());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_bounds_and_single_use() {
        let r = Recorder::<2>::new();
        assert!(!r.start(0, 1, 0));
        assert!(!r.start(u64::MAX, 1, 1));
        assert!(r.start(10, 100, 1));
        assert!(!r.start(10, 100, 1));
        assert!(r.begin(11, 0, 100, 0, 0, 255).is_none());
        assert!(r.begin(11, usize::MAX, 100, 0, 0, 512).is_none());
        assert!(!r.freeze(109));
        assert!(r.freeze(110));
        assert!(r.begin(110, 0, 100, 0, 0, 512).is_none());
        assert!(!r.start(110, 100, 1));
    }
    #[test]
    fn freeze_waits_for_inflight_copy_without_spinning() {
        let r = Recorder::<2>::new();
        assert!(r.start(0, 100, 1));
        let s = r.begin(99, 0, 100, 2, 4, 1460).unwrap();
        assert!(r.begin(99, 0, 101, 0, 0, 1460).is_none());
        assert!(!r.freeze(100));
        r.finish(s, 102);
        assert!(r.freeze(102));
        assert_eq!(r.counts(0), (1, 0));
        let e = (0..2).map(|i| r.entry(0, i)).find(|e| e.2 > 0).unwrap();
        assert_eq!(e, (100, 2 | 4 << 3 | 2 << 6, 1, 1460, 3, 3));
    }
    #[test]
    fn bounded_table_counts_overflow_and_preserves_records() {
        let r = Recorder::<1>::new();
        assert!(r.start(0, 1000, 1));
        let s = r.begin(1, 0, 100, 0, 0, 512).unwrap();
        r.finish(s, 3);
        for _ in 1..INTERVAL {
            assert!(r.begin(1, 0, 200, 0, 0, 512).is_none());
        }
        let s = r.begin(1, 0, 200, 0, 0, 512).unwrap();
        r.finish(s, 5);
        assert!(r.freeze(1000));
        assert_eq!(r.counts(0), (128, 1));
        assert_eq!(r.entry(0, 0).0, 100);
        assert_eq!(r.entry(0, 0).2, 1);
    }
}
