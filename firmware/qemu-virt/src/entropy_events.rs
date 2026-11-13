//! VirtIO acknowledgement translation belongs to the firmware adapter.
use vibeos_hal::entropy::Events;
pub const fn from_status(status: u32) -> Events {
    Events {
        completion: status & 1 != 0,
        // Preserve notification for config changes and unexpected status bits;
        // the kernel rechecks operational/completion state before returning data.
        state_changed: status & !1 != 0,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_is_distinct_from_config_or_unknown_causes() {
        assert_eq!(from_status(0), Events::default());
        assert_eq!(from_status(1), Events { completion: true, state_changed: false });
        for bit in 1..32 {
            assert_eq!(from_status(1 << bit), Events { completion: false, state_changed: true });
            assert_eq!(from_status((1 << bit) | 1), Events { completion: true, state_changed: true });
        }
    }
}
