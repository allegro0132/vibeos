//! Board-selected block-device frontend.
//!
//! Kernel services depend on this module instead of naming a transport or
//! controller driver.  The firmware package still selects exactly one board at
//! compile time, so the re-export remains statically dispatched and adds no
//! runtime indirection.

#[cfg(feature = "milkv-duo")]
#[allow(unused_imports)]
pub use crate::sdhci_blk::{
    BlockDevice, BlockError, BlockInfo, BlockResources, DmaRegion, MmioWindow, debug_waiter_counts,
    discover, driver_task, flush_with, info_with, inject_fault_after_publish, inject_timeout,
    is_online, read_with, recover_faulted_domain, write_with,
};

#[cfg(feature = "qemu-virt")]
#[allow(unused_imports)]
pub use crate::virtio_blk::{
    BlockDevice, BlockError, BlockInfo, BlockResources, DmaRegion, MmioWindow, debug_waiter_counts,
    discover, driver_task, flush_with, info_with, inject_fault_after_publish, inject_timeout,
    is_online, read_with, recover_faulted_domain, write_with,
};
