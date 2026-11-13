use super::{Stage, STAGE_COUNT, SAMPLE_INTERVAL};
use crate::{arch, exec::MAX_HARTS};
use core::{marker::PhantomData, sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::*}};

pub const BUCKETS: usize = 600;
const OFF: usize = STAGE_COUNT;
static START: AtomicU64 = AtomicU64::new(0);
static END: AtomicU64 = AtomicU64::new(0);
static WIDTH: AtomicU64 = AtomicU64::new(0);
static EXPIRED: AtomicBool = AtomicBool::new(false);
#[repr(align(64))]
struct Local { current: AtomicUsize, accounted: AtomicU64 }
static LOCAL: [Local; MAX_HARTS] = [const { Local {
    current: AtomicUsize::new(OFF), accounted: AtomicU64::new(0),
} }; MAX_HARTS];

#[repr(align(64))]
struct Bucket {
    ticks: [AtomicU64; STAGE_COUNT], wait: [AtomicU64; STAGE_COUNT], calls: [AtomicU64; STAGE_COUNT],
    high: [AtomicU64; 2], full: [AtomicU64; 2],
    dma: [AtomicU64; 3],
}
impl Bucket {
    const fn new() -> Self { Self {
        ticks: [const { AtomicU64::new(0) }; STAGE_COUNT],
        wait: [const { AtomicU64::new(0) }; STAGE_COUNT],
        calls: [const { AtomicU64::new(0) }; STAGE_COUNT],
        high: [const { AtomicU64::new(0) }; 2],
        full: [const { AtomicU64::new(0) }; 2],
        dma: [const { AtomicU64::new(0) }; 3],
    } }
}
static DATA: [[Bucket; BUCKETS]; MAX_HARTS] = [const { [const { Bucket::new() }; BUCKETS] }; MAX_HARTS];

/// One window, up to 60 seconds, in 100 ms buckets. No live-counter reset.
pub fn start(seconds: u64, hz: u64) -> bool {
    if !(1..=60).contains(&seconds) || hz < 10 || hz % 10 != 0 { return false; }
    if START.compare_exchange(0, u64::MAX, AcqRel, Acquire).is_err() { return false; }
    let now = arch::time().max(1);
    WIDTH.store(hz / 10, Relaxed);
    END.store(now.saturating_add(seconds.saturating_mul(hz)), Relaxed);
    START.store(now, Release);
    true
}
pub fn window() -> (u64, u64, u64) {
    (START.load(Acquire), END.load(Relaxed), WIDTH.load(Relaxed))
}
fn bucket(now: u64) -> Option<usize> {
    let (start, end, width) = window();
    if start == 0 || start == u64::MAX || width == 0 || now < start || now >= end { return None; }
    Some(((now-start)/width).min(BUCKETS as u64-1) as usize)
}
fn live_time() -> Option<u64> {
    if START.load(Acquire) == 0 || EXPIRED.load(Relaxed) { return None; }
    let now = arch::time();
    if now >= END.load(Relaxed) && START.load(Acquire) != u64::MAX {
        EXPIRED.store(true, Relaxed);
        return None;
    }
    bucket(now).map(|_| now)
}
pub fn active() -> bool { live_time().is_some() }
pub fn dma_status(dma: u32, mtl: u32) {
    if let Some(i) = live_time().and_then(bucket) {
        let h = hart();
        if h >= MAX_HARTS { return; }
        DATA[h][i].dma[0].fetch_add(1, Relaxed);
        DATA[h][i].dma[1].fetch_or(dma as u64, Relaxed);
        DATA[h][i].dma[2].fetch_or(mtl as u64, Relaxed);
    }
}
fn hart() -> usize {
    #[cfg(target_arch = "riscv64")]
    { arch::cached_logical_hart_index().unwrap_or(MAX_HARTS) }
    #[cfg(not(target_arch = "riscv64"))]
    { arch::current_hart_id() }
}

#[repr(align(64))]
struct SampleCounters([AtomicUsize; STAGE_COUNT]);
static SAMPLES: [SampleCounters; MAX_HARTS] = [const {
    SampleCounters([const { AtomicUsize::new(0) }; STAGE_COUNT])
}; MAX_HARTS];

/// Parent-exclusive accounting: children (including measured contended-lock
/// waits) add to ACCOUNTED before their parent exits. Scopes are hart-affine.
/// Intervals are attributed to the bucket of completion, not split at edges.
pub struct Scope {
    state: Option<(usize, usize, usize, u64, u64)>,
    _not_send: PhantomData<*mut ()>,
}
impl Scope {
    #[inline]
    pub fn enter(stage: Stage) -> Self {
        let now = live_time();
        let h = hart();
        let state = if h < MAX_HARTS && now.is_some() {
            let now = now.unwrap();
            Some((h, stage as usize, LOCAL[h].current.swap(stage as usize, Relaxed),
                  now, LOCAL[h].accounted.load(Relaxed)))
        } else { None };
        Self { state, _not_send: PhantomData }
    }
    /// Record one in SAMPLE_INTERVAL calls per hart and stage. Unselected
    /// time stays in the parent. Never multiply these counters into timeline
    /// totals: selected calls are a diagnostic sample, not exhaustive work.
    #[inline]
    pub fn sampled(stage: Stage) -> Self {
        if START.load(Acquire) != 0 && !EXPIRED.load(Relaxed) {
            let h = hart();
            if h < MAX_HARTS && SAMPLES[h].0[stage as usize]
                .fetch_add(1, Relaxed) % SAMPLE_INTERVAL == 0 {
                return Self::enter(stage);
            }
        }
        Self { state: None, _not_send: PhantomData }
    }
    pub fn task(name: &str) -> Self {
        Self::enter(match name {
            "virtio-net" => Stage::Driver,
            "net-stack" => Stage::Stack,
            "iperf3-server" | "tcp-probe" => Stage::Application,
            _ => Stage::Other,
        })
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let Some((h, stage, parent, start, children_start)) = self.state else { return; };
        assert_eq!(hart(), h, "network profile scope changed hart");
        let end = arch::time().min(END.load(Relaxed));
        let children = LOCAL[h].accounted.load(Relaxed).wrapping_sub(children_start);
        let exclusive = end.saturating_sub(start).saturating_sub(children);
        if let Some(i) = bucket(end.saturating_sub(1)) {
            DATA[h][i].ticks[stage].fetch_add(exclusive, Relaxed);
            DATA[h][i].calls[stage].fetch_add(1, Relaxed);
        }
        LOCAL[h].accounted.fetch_add(exclusive, Relaxed);
        LOCAL[h].current.store(parent, Relaxed);
    }
}

pub fn lock_start() -> Option<(usize, usize, u64)> {
    let h = hart();
    if h >= MAX_HARTS { return None; }
    let stage = LOCAL[h].current.load(Relaxed);
    if stage == OFF { return None; }
    live_time().map(|now| (h, stage, now))
}
pub fn lock_end(start: Option<(usize, usize, u64)>, contended: bool) {
    lock_end_at(start, contended, 0);
}
pub fn lock_end_at(start: Option<(usize, usize, u64)>, contended: bool, address: usize) {
    if !contended { return; }
    let Some((h, stage, start)) = start else { return; };
    let end = arch::time().min(END.load(Relaxed));
    if let Some(i) = bucket(end.saturating_sub(1)) {
        let wait = end.saturating_sub(start);
        DATA[h][i].wait[stage].fetch_add(wait, Relaxed);
        record_lock(h, stage, address, wait);
        LOCAL[h].accounted.fetch_add(wait, Relaxed);
    }
}
pub fn queue(name: &str, depth: usize, full: bool) {
    let direction = match name { "net-inbound" => 0, "net-outbound" => 1, _ => return };
    if let Some(i) = live_time().and_then(bucket) {
        let h = hart();
        if h >= MAX_HARTS { return; }
        DATA[h][i].high[direction].fetch_max(depth as u64, Relaxed);
        if full { DATA[h][i].full[direction].fetch_add(1, Relaxed); }
    }
}
pub struct Snapshot {
    pub ticks: [u64; STAGE_COUNT], pub wait: [u64; STAGE_COUNT], pub calls: [u64; STAGE_COUNT],
    pub high: [u64; 2], pub full: [u64; 2],
    pub dma: [u64; 3],
}
pub fn snapshot(index: usize) -> Snapshot {
    let mut total = empty_snapshot();
    for h in 0..MAX_HARTS { merge(&mut total, read_bucket(&DATA[h][index])); }
    total
}
pub fn snapshot_hart(index: usize) -> Snapshot {
    let mut total = empty_snapshot();
    for b in &DATA[index] { merge(&mut total, read_bucket(b)); }
    total
}
fn empty_snapshot() -> Snapshot {
    Snapshot { ticks: [0; STAGE_COUNT], wait: [0; STAGE_COUNT], calls: [0; STAGE_COUNT], high: [0;2], full: [0;2], dma: [0;3] }
}
fn merge(total: &mut Snapshot, b: Snapshot) {
    for i in 0..STAGE_COUNT { total.ticks[i] += b.ticks[i]; total.wait[i] += b.wait[i]; total.calls[i] += b.calls[i]; }
    for i in 0..2 { total.high[i] = total.high[i].max(b.high[i]); total.full[i] += b.full[i]; }
    total.dma[0] += b.dma[0]; total.dma[1] |= b.dma[1]; total.dma[2] |= b.dma[2];
}
fn read_bucket(b: &Bucket) -> Snapshot {
    Snapshot {
        ticks: core::array::from_fn(|i| b.ticks[i].load(Relaxed)),
        wait: core::array::from_fn(|i| b.wait[i].load(Relaxed)),
        calls: core::array::from_fn(|i| b.calls[i].load(Relaxed)),
        high: core::array::from_fn(|i| b.high[i].load(Relaxed)),
        full: core::array::from_fn(|i| b.full[i].load(Relaxed)),
        dma: core::array::from_fn(|i| b.dma[i].load(Relaxed)),
    }
}

// Diagnostic identities are addresses of the exact SpinLock object, not stack
// caller guesses. Fixed per-hart storage avoids allocation and cross-hart writes.
// Address zero is the explicit overflow/unspecified row. Reused arena addresses
// aggregate by address; do not interpret them as permanent resource identities.
pub const LOCK_SLOTS: usize = 64;
#[repr(align(64))]
struct LockRecord { address: AtomicUsize, wait: [AtomicU64; STAGE_COUNT], calls: [AtomicU64; STAGE_COUNT] }
impl LockRecord { const fn new() -> Self { Self {
    address: AtomicUsize::new(0), wait: [const {AtomicU64::new(0)}; STAGE_COUNT],
    calls: [const {AtomicU64::new(0)}; STAGE_COUNT],
} } }
static LOCKS: [[LockRecord; LOCK_SLOTS + 1]; MAX_HARTS] =
    [const { [const {LockRecord::new()}; LOCK_SLOTS + 1] }; MAX_HARTS];
fn record_lock(h: usize, stage: usize, address: usize, ticks: u64) {
    let mut slot = LOCK_SLOTS;
    if address != 0 {
        for offset in 0..LOCK_SLOTS {
            let index = ((address >> 6) + offset) % LOCK_SLOTS;
            let entry = &LOCKS[h][index];
            let key = entry.address.load(Relaxed);
            if key == address || (key == 0 && entry.address.compare_exchange(0, address, Relaxed, Relaxed).is_ok()) {
                slot = index; break;
            }
        }
    }
    LOCKS[h][slot].wait[stage].fetch_add(ticks, Relaxed);
    LOCKS[h][slot].calls[stage].fetch_add(1, Relaxed);
}
pub fn lock_snapshot(hart: usize, slot: usize) -> (usize, [u64; STAGE_COUNT], [u64; STAGE_COUNT]) {
    let entry = &LOCKS[hart][slot];
    (entry.address.load(Relaxed), core::array::from_fn(|i| entry.wait[i].load(Relaxed)),
     core::array::from_fn(|i| entry.calls[i].load(Relaxed)))
}

/// Decision counters, not time: [work-hint runnable, empty retry, wait attempt,
/// interface turns with ingress, interface turns with frontend progress, packets].
/// Ingress packets are protocol inputs after optional GRO, not wire frames.
/// A work hint may represent pending/backpressured work, not completed I/O.
#[repr(align(64))]
struct PollCounts([[AtomicU64; 6]; STAGE_COUNT]);
static POLL_COUNTS: [PollCounts; MAX_HARTS] = [const { PollCounts(
    [const { [const { AtomicU64::new(0) }; 6] }; STAGE_COUNT]) }; MAX_HARTS];
fn poll_counters() -> Option<&'static [AtomicU64; 6]> {
    live_time()?;
    let h = hart();
    if h >= MAX_HARTS { return None; }
    let stage = LOCAL[h].current.load(Relaxed);
    if stage >= STAGE_COUNT { return None; }
    Some(&POLL_COUNTS[h].0[stage])
}
pub fn poll_decision(work_hint: bool, runnable: bool) {
    if let Some(counters) = poll_counters() {
        let index = if !runnable { 2 } else if work_hint { 0 } else { 1 };
        counters[index].fetch_add(1, Relaxed);
    }
}
pub fn stack_activity(ingress: usize, frontend: bool) {
    if let Some(counters) = poll_counters() {
        counters[3].fetch_add(u64::from(ingress != 0), Relaxed);
        counters[4].fetch_add(u64::from(frontend), Relaxed);
        counters[5].fetch_add(ingress as u64, Relaxed);
    }
}
pub fn poll_snapshot(hart: usize, stage: usize) -> [u64; 6] {
    core::array::from_fn(|i| POLL_COUNTS[hart].0[stage][i].load(Relaxed))
}
