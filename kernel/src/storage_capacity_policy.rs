//! Bounded foreground storage capacity policy, independent of device I/O.

pub(crate) const STORAGE_V2_FOREGROUND_FREE_SEGMENTS: u64 = 10;
/// Extra segments requested beyond the floor whenever foreground growth
/// runs, so one growth transaction serves many subsequent commits.
const STORAGE_V2_GROWTH_HYSTERESIS_SEGMENTS: u64 = 22;

/// Scale the fixed foreground floor and hysteresis to the device: they were
/// tuned on large bench devices, and on a small store (the Milk-V 64 MiB
/// slice is sixteen 4 MiB segments) a 10-segment floor is structurally
/// unreachable once a handful of segments hold live data — growth exhausts
/// immediately and every subsequent commit pays up to eight full GC mark
/// walks of the live object graph. An eighth of the device (clamped to the
/// tuned values) keeps foreground collection an emergency, not a tax.
pub(crate) fn scaled_free_floor(total_segments: u64) -> u64 {
    (total_segments / 8).clamp(2, STORAGE_V2_FOREGROUND_FREE_SEGMENTS)
}

pub(crate) fn scaled_growth_hysteresis(total_segments: u64) -> u64 {
    (total_segments / 4).clamp(2, STORAGE_V2_GROWTH_HYSTERESIS_SEGMENTS)
}

/// Amortize strict growth remounts as the admitted store grows. This only
/// enlarges an already provisioned adjacent suffix, without writing payload
/// pages. Collection keeps its smaller existing hysteresis/pause budget.
pub(crate) fn scaled_admission_hysteresis(total_segments: u64, admitted_segments: u64) -> u64 {
    scaled_growth_hysteresis(total_segments)
        .max(admitted_segments.min(total_segments / 4).min(64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_scales_without_inflating_small_device_or_gc_targets() {
        assert_eq!(scaled_free_floor(16), 2);
        assert_eq!(scaled_growth_hysteresis(16), 4);
        for total in 0..=88 {
            for admitted in 0..=total {
                assert_eq!(scaled_admission_hysteresis(total, admitted),
                    scaled_growth_hysteresis(total));
            }
        }
        assert_eq!(scaled_admission_hysteresis(256, 8), 22);
        assert_eq!(scaled_admission_hysteresis(256, 32), 32);
        assert_eq!(scaled_admission_hysteresis(256, 64), 64);
        assert_eq!(scaled_admission_hysteresis(256, 256), 64);
        assert_eq!(scaled_growth_hysteresis(256), 22);
        for total in [0, 1, 8, 16, 32, 64, 128, 256, 1024, u64::MAX] {
            let mut previous = 0;
            for admitted in [0, 1, 8, 16, 32, 64, 128, u64::MAX] {
                let extra = scaled_admission_hysteresis(total, admitted);
                assert!(extra >= scaled_growth_hysteresis(total));
                assert!(extra >= previous && extra <= 64);
                previous = extra;
            }
        }
    }
}
