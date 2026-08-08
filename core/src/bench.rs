//! Small, allocation-free helpers shared by in-kernel benchmarks.
//!
//! Benchmark samples deliberately stay as integer timer ticks. That keeps the
//! result deterministic and avoids pulling floating-point formatting into the
//! kernel merely to report a percentile.

/// A deterministic summary of a non-empty sample set.
///
/// Percentiles use the nearest-rank definition: for `n` sorted observations,
/// percentile `p` selects the 1-based rank `ceil(p * n)`. The integer mean is
/// rounded down after an exact `u128` accumulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Summary {
    pub count: usize,
    pub min: u64,
    pub p50: u64,
    pub p95: u64,
    pub max: u64,
    pub mean: u64,
}

/// Sort `samples` in place and return its min/p50/p95/max/mean summary.
///
/// This function allocates nothing and returns `None` for an empty slice. A
/// `u128` sum cannot overflow for any slice addressable by a 64-bit target:
/// at most `usize::MAX` values of at most `u64::MAX` fit below `u128::MAX`.
pub fn summarize(samples: &mut [u64]) -> Option<Summary> {
    if samples.is_empty() {
        return None;
    }

    samples.sort_unstable();
    let count = samples.len();
    let sum = samples
        .iter()
        .fold(0u128, |total, &sample| total + u128::from(sample));

    Some(Summary {
        count,
        min: samples[0],
        p50: samples[nearest_rank_index(count, 50, 100)],
        p95: samples[nearest_rank_index(count, 95, 100)],
        max: samples[count - 1],
        mean: (sum / count as u128) as u64,
    })
}

/// Zero-based index for the 1-based nearest-rank percentile.
fn nearest_rank_index(count: usize, numerator: u128, denominator: u128) -> usize {
    debug_assert!(count != 0);
    debug_assert!(numerator != 0 && numerator <= denominator);
    // Do the multiply in u128 so a valid 64-bit slice length cannot overflow.
    let rank = ((count as u128 * numerator) + (denominator - 1)) / denominator;
    (rank - 1) as usize
}
