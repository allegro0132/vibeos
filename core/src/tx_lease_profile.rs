//! Default-off timer sampling for synchronous native TX lease operations.
//! Counts include failed calls; durations include capability checks and lock
//! waits, and are elapsed ticks, not exclusive execution cycles. Never await
//! with a Scope. No allocation, live reset or output on the measured path.
use core::{marker::PhantomData, sync::atomic::{AtomicU64, Ordering::Relaxed}};
use crate::{arch, exec::MAX_HARTS};
pub const INTERVAL: u64 = 127;
pub const NAMES: [&str; 3] = ["reserve", "cancel", "publish"];
#[repr(align(64))]
struct Counters { calls: AtomicU64, samples: AtomicU64, ticks: AtomicU64, max: AtomicU64 }
static DATA: [[Counters; 3]; MAX_HARTS] = [const { [const { Counters {
    calls: AtomicU64::new(0), samples: AtomicU64::new(0),
    ticks: AtomicU64::new(0), max: AtomicU64::new(0),
} }; 3] }; MAX_HARTS];
pub struct Scope { sample: Option<(usize, usize, u64)>, _not_send: PhantomData<*mut ()> }
impl Scope {
    pub fn enter(kind: usize) -> Self {
        #[cfg(target_arch = "riscv64")]
        let hart = arch::cached_logical_hart_index().unwrap_or(MAX_HARTS);
        #[cfg(not(target_arch = "riscv64"))]
        let hart = arch::current_hart_id();
        let sample = DATA.get(hart).and_then(|row| row.get(kind)).and_then(|c| {
            let calls = c.calls.fetch_add(1, Relaxed);
            (calls % INTERVAL == 0).then(|| (hart, kind, arch::time()))
        });
        Self { sample, _not_send: PhantomData }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some((hart, kind, start)) = self.sample {
            let elapsed = arch::time().saturating_sub(start);
            let c = &DATA[hart][kind];
            c.ticks.fetch_add(elapsed, Relaxed);
            c.max.fetch_max(elapsed, Relaxed);
            c.samples.fetch_add(1, Relaxed);
        }
    }
}
/// Cumulative, non-transactional snapshot; callers take before/after deltas
/// outside traffic. Max is boot-wide and must not be subtracted.
pub fn snapshot(hart: usize, kind: usize) -> [u64; 4] {
    let c = &DATA[hart][kind];
    [c.calls.load(Relaxed), c.samples.load(Relaxed), c.ticks.load(Relaxed), c.max.load(Relaxed)]
}
