//! Opt-in RX boundary counters. No output, allocation or locks in the data path.
//! A driver RX turn and its consumer execute on the same logical hart. Histograms
//! distinguish publication budget, zero-ticket polls and endpoint backpressure;
//! zero tickets do not by themselves prove that hardware has no pending frame.
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[repr(align(64))]
struct Counters {
    turns: AtomicU64,
    driver: [[AtomicU64; 33]; 3],
    empty: [[AtomicU64; 33]; 3],
    post: [[AtomicU64; 33]; 2],
    admitted: AtomicU64,
    empty_admitted: AtomicU64,
    empty_ticks: AtomicU64,
    last: AtomicU64,
    end: AtomicU64,
}
static COUNTERS: [Counters; crate::exec::MAX_HARTS] = [const { Counters {
    turns: AtomicU64::new(0),
    driver: [const { [const { AtomicU64::new(0) }; 33] }; 3],
    empty: [const { [const { AtomicU64::new(0) }; 33] }; 3],
    post: [const { [const { AtomicU64::new(0) }; 33] }; 2],
    admitted: AtomicU64::new(0), empty_admitted: AtomicU64::new(0),
    empty_ticks: AtomicU64::new(0), last: AtomicU64::new(0), end: AtomicU64::new(0),
} }; crate::exec::MAX_HARTS];

fn current() -> Option<&'static Counters> {
    Some(&COUNTERS[crate::ipi::current_logical_hart()?.index()])
}

/// reason: 0=publication budget consumed, 1=poll returned zero, 2=queue full.
/// Only RX turns call this; a TX-only service must not replace the association.
pub fn driver(published: usize, reason: usize) {
    let Some(c) = current() else { return; };
    if c.turns.fetch_add(1, Relaxed) % 127 != 0 {
        c.last.store(0, Relaxed);
        return;
    }
    assert!(published <= 32 && reason < 3);
    c.driver[reason][published].fetch_add(1, Relaxed);
    c.last.store(1 + reason as u64 * 33 + published as u64, Relaxed);
    c.admitted.store(0, Relaxed);
    c.end.store(crate::arch::time(), Relaxed);
}

pub fn admission(count: usize) {
    let Some(c) = current() else { return; };
    let last = c.last.load(Relaxed);
    if last == 0 { return; }
    if count != 0 { c.admitted.fetch_add(count as u64, Relaxed); return; }
    let key = (last - 1) as usize;
    c.empty[key / 33][key % 33].fetch_add(1, Relaxed);
    c.empty_admitted.fetch_add(c.admitted.load(Relaxed), Relaxed);
    c.empty_ticks.fetch_add(crate::arch::time().wrapping_sub(c.end.load(Relaxed)), Relaxed);
}

/// Snapshot of descriptor readiness after protocol consumption, not at the
/// earlier empty-endpoint observation. The caller retains device authority.
pub fn is_sampled() -> bool { current().is_some_and(|c| c.last.load(Relaxed) != 0) }

pub fn after_protocol(pending: bool) {
    let Some(c) = current() else { return; };
    let last = c.last.load(Relaxed);
    if last != 0 { c.post[usize::from(pending)][((last - 1) % 33) as usize].fetch_add(1, Relaxed); }
}

pub fn snapshot(hart: usize) -> Option<([[u64; 33]; 3], [[u64; 33]; 3], [[u64; 33]; 2], [u64; 2])> {
    let c = COUNTERS.get(hart)?;
    Some((core::array::from_fn(|r| core::array::from_fn(|n| c.driver[r][n].load(Relaxed))),
        core::array::from_fn(|r| core::array::from_fn(|n| c.empty[r][n].load(Relaxed))),
        core::array::from_fn(|r| core::array::from_fn(|n| c.post[r][n].load(Relaxed))),
        [c.empty_admitted.load(Relaxed), c.empty_ticks.load(Relaxed)]))
}
