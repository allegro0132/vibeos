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
pub const NETWORK_FRONTEND: NetworkFrontendPolicy = NetworkFrontendPolicy { queue_depth: 8 };

/// The QEMU image exposes its complete emulated block device.
#[cfg(feature = "qemu-default")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = None;

/// The packaged Duo image places raw service data immediately after its
/// 128 MiB FAT boot partition.
#[cfg(feature = "milkv-duo-sd")]
pub const BLOCK_DATA_SLICE: Option<BlockSlice> = Some(BlockSlice {
    first_sector: 262_145,
    sector_count: 8_192,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_queue_is_bounded() {
        assert!(NETWORK_FRONTEND.queue_depth > 0);
    }

    #[cfg(feature = "milkv-duo-sd")]
    #[test]
    fn duo_data_slice_does_not_overflow() {
        assert_eq!(BLOCK_DATA_SLICE.unwrap().end_sector(), Some(270_337));
    }
}
