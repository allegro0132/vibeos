//! Bound final RX-descriptor writeback between an observation of OWN and its
//! first observed clear. These bounds include the CE DMA and memory fabric.
use super::{Cipher, CompletedRecord, PostedRecord, DMA_WAIT_TICKS, OWN};
use core::{
    arch::asm,
    fmt::Write,
    sync::atomic::{AtomicU64, AtomicU8, Ordering::Relaxed},
};

// Zero retains the production poll loop. The normal cadence is policy one.
const POLICIES: [(u64, usize); 3] = [(5, 64), (0, 0), (5, 16)];
static POLICY: AtomicU8 = AtomicU8::new(0);
// Records, bytes, OWN reads, first-read completions, last-busy lower bound,
// first-clear upper bound, and the existing submission-to-observation counter.
static TOTALS: [[AtomicU64; 7]; 2] = [const { [const { AtomicU64::new(0) }; 7] }; 2];

pub fn configure(command: u8) -> u8 {
    let index = b"~{};".iter().position(|k| *k == command).unwrap() as u8;
    POLICY.store(index, Relaxed);
    index
}

#[inline]
fn stamp() -> u64 {
    let time;
    unsafe {
        asm!("fence iorw, iorw", "rdtime {}", "fence iorw, iorw", out(reg) time, options(nostack))
    };
    time
}

pub(super) fn wait(
    cipher: &mut Cipher,
    record: &PostedRecord,
) -> Option<Result<CompletedRecord, &'static str>> {
    let policy = POLICY.load(Relaxed);
    if policy == 0 {
        return None;
    }
    let (delay, spins) = POLICIES[usize::from(policy - 1)];
    let before = DMA_WAIT_TICKS.load(Relaxed);
    let mut lower = 0;
    let mut probes = 0;
    while crate::ticks().wrapping_sub(record.started) < delay * record.len as u64 {
        core::hint::spin_loop();
    }
    loop {
        let earliest_read = stamp().wrapping_sub(record.started);
        let owned = super::read(record.descriptor + 12) & OWN != 0;
        probes += 1;
        if !owned {
            let upper = stamp().wrapping_sub(record.started);
            let result = cipher.complete(record);
            if matches!(result, Some(Ok(_))) {
                let elapsed = DMA_WAIT_TICKS.load(Relaxed).wrapping_sub(before);
                let row = &TOTALS[usize::from(record.len >= 1024)];
                for (c, n) in row.iter().zip([
                    1,
                    record.len as u64,
                    probes,
                    u64::from(probes == 1),
                    lower,
                    upper,
                    elapsed,
                ]) {
                    c.fetch_add(n, Relaxed);
                }
            }
            return result;
        }
        lower = earliest_read;
        if lower > 125_000_000 {
            return cipher.complete(record);
        }
        for _ in 0..spins {
            core::hint::spin_loop();
        }
    }
}

pub fn report() {
    for (id, row) in TOTALS.iter().enumerate() {
        let counters = row.each_ref().map(|c| c.load(Relaxed));
        let _ = writeln!(crate::Console, "CE OWN bracket {id} {counters:?}\r");
    }
}
