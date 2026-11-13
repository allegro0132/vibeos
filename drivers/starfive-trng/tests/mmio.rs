use vibeos_starfive_trng::{Mmio, Registers};
fn ticks() -> u64 {
    u64::MAX - 3
}

#[test]
fn invalid_apertures_are_rejected_without_io() {
    for (base, bytes) in [(0, 104), (1, 104), (0x1000, 103), (usize::MAX - 3, 104)] {
        assert!(unsafe { Mmio::new(base, bytes, ticks) }.is_err());
    }
}

#[test]
fn volatile_lane_preserves_neighbors_and_uses_supplied_timer() {
    let mut storage = [0xa5a5a5a5u32; 28];
    let base = unsafe { storage.as_mut_ptr().add(1) } as usize;
    let mut lane = unsafe { Mmio::new(base, 104, ticks) }.unwrap();
    assert_eq!(lane.ticks(), u64::MAX - 3);
    for offset in [0, 8, 16, 20, 96, 100] {
        lane.write(offset, 0x12340000 | offset as u32);
    }
    for offset in [0, 4, 8, 12, 16, 20, 32, 36, 40, 44, 48, 52, 56, 60, 96, 100] {
        let expected = if [0, 8, 16, 20, 96, 100].contains(&offset) {
            0x12340000 | offset as u32
        } else {
            0xa5a5a5a5
        };
        assert_eq!(lane.read(offset), expected);
    }
    for (index, value) in storage.iter().enumerate() {
        let offset = index.wrapping_sub(1).wrapping_mul(4);
        let expected = if (1..27).contains(&index) && [0, 8, 16, 20, 96, 100].contains(&offset) {
            0x12340000 | offset as u32
        } else {
            0xa5a5a5a5
        };
        assert_eq!(*value, expected);
    }
}

#[test]
fn reserved_unaligned_and_read_only_accesses_fail_before_io() {
    let mut storage = [0xababababu32; 26];
    let mut lane = unsafe { Mmio::new(storage.as_mut_ptr() as usize, 104, ticks) }.unwrap();
    for offset in [1, 24, 28, 64, 92, 104, usize::MAX] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lane.read(offset))).is_err()
        );
    }
    for offset in [1, 4, 12, 24, 32, 60, 64, 104, usize::MAX] {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| lane.write(offset, 0)))
                .is_err()
        );
    }
    assert_eq!(storage, [0xabababab; 26]);
}
