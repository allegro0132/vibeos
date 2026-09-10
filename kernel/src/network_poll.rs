//! PHY observation cadence is independent of packet queue pressure.
pub fn due(last: &mut Option<u64>, now: u64, timebase_hz: u64) -> bool {
    if last.is_none_or(|previous| now.wrapping_sub(previous) >= timebase_hz.max(1)) {
        *last = Some(now);
        true
    } else {
        false
    }
}
