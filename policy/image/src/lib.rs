#![no_std]

//! Compile-time logical resource and storage-layout policy selected by final
//! firmware images. Physical hardware descriptions remain in the BSP/HAL.

#[cfg(all(feature = "qemu-default", feature = "milkv-duo-sd"))]
compile_error!("image policies `qemu-default` and `milkv-duo-sd` are mutually exclusive");

#[cfg(not(any(feature = "qemu-default", feature = "milkv-duo-sd")))]
compile_error!("exactly one image policy must be selected");

/// A logical block-device view carved out of a packaged storage image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockSlice {
    pub first_sector: u64,
    pub sector_count: u64,
}

impl BlockSlice {
    pub const fn end_sector(self) -> Option<u64> {
        self.first_sector.checked_add(self.sector_count)
    }
}

/// Resource policy for stable packet frontends shared by network backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkFrontendPolicy {
    pub queue_depth: usize,
}

/// Bounded capacity of each stable packet endpoint. This is independent of a
/// device backend's descriptor-ring size.
pub const NETWORK_FRONTEND: NetworkFrontendPolicy = NetworkFrontendPolicy { queue_depth: 64 };

/// The default QEMU image admits a bounded managed slice. Storage V2 initially
/// formats only its policy range within this slice; unused suffix capacity is
/// not ambient store capacity and may be admitted only by explicit growth.
#[cfg(all(feature = "qemu-default", feature = "storage-bench"))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    // The benchmark harness always provisions a 1 GiB data disk; admit all of
    // it so large-file workloads exercise real growth instead of an
    // artificially small window. The raw-block benchmark range parks in the
    // final 64 MiB.
    sector_count: 2_097_152,
});

#[cfg(all(
    feature = "qemu-default",
    not(feature = "storage-bench"),
    not(feature = "file-tree")
))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    sector_count: 131_072,
});

/// The capability-rooted file-tree acceptance image uses a dedicated 128 MiB
/// managed slice. The initial V2 ABI remains the same 8-segment window; the
/// aligned suffix becomes usable only through the maintenance growth protocol.
#[cfg(all(
    feature = "qemu-default",
    feature = "file-tree",
    not(feature = "storage-bench")
))]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 0,
    sector_count: 262_144,
});

/// The packaged Duo image places raw service data immediately after its
/// 128 MiB FAT boot partition. The slice is 512 MiB: Storage V2's segment
/// granule is 4 MiB and its foreground free-segment policy needs dozens of
/// segments of headroom, so the previous 64 MiB (sixteen segments) forced a
/// full garbage-collection walk on nearly every commit.
#[cfg(feature = "milkv-duo-sd")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 262_145,
    sector_count: 1_048_576,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_queue_is_bounded() {
        assert!(NETWORK_FRONTEND.queue_depth > 0);
    }

    #[cfg(feature = "qemu-default")]
    #[test]
    fn qemu_data_slice_is_exact_and_checked() {
        assert_eq!(
            BLOCK_DATA_SLICE.unwrap().end_sector(),
            Some(if cfg!(feature = "storage-bench") {
                2_097_152
            } else if cfg!(feature = "file-tree") {
                262_144
            } else {
                131_072
            })
        );
    }

    #[cfg(feature = "milkv-duo-sd")]
    #[test]
    fn duo_data_slice_does_not_overflow() {
        assert_eq!(BLOCK_DATA_SLICE.unwrap().end_sector(), Some(1_310_721));
    }
}
