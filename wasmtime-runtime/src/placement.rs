//! Preserve worker parallelism while leaving room for kernel housekeeping.

/// Prefer non-housekeeping harts only when they can accommodate every worker
/// slot. Small/sparse topologies retain all their online harts.
pub fn worker_harts(online: usize, housekeeping: usize, worker_capacity: usize) -> usize {
    let workers = online & !housekeeping;
    if worker_capacity != 0 && workers.count_ones() as usize >= worker_capacity {
        workers
    } else {
        online
    }
}

#[cfg(test)]
mod tests {
    use super::worker_harts;

    #[test]
    fn never_loses_available_worker_parallelism() {
        for online in 0usize..256 {
            for boot in 0..8 {
                for capacity in 1..=8 {
                    let eligible = worker_harts(online, 1 << boot, capacity);
                    assert_eq!(eligible & !online, 0);
                    assert!(eligible.count_ones() as usize >=
                        core::cmp::min(online.count_ones() as usize, capacity));
                }
            }
        }
    }

    #[test]
    fn command_topologies() {
        assert_eq!(worker_harts(0b1, 1, 3), 0b1);
        assert_eq!(worker_harts(0b11, 1, 3), 0b11);
        assert_eq!(worker_harts(0b1101, 1, 3), 0b1101);
        assert_eq!(worker_harts(0b1111, 1, 3), 0b1110);
        assert_eq!(worker_harts(0b1110, 1, 3), 0b1110);
        assert_eq!(worker_harts(0, 1, 3), 0);
        assert_eq!(worker_harts(0b1111, 1, 0), 0b1111);
    }
}
