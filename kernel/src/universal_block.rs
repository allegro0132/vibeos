//! Runtime dispatch preserves each backend's original capability resource types.
use crate::cap::{Cap, Resource};
use crate::heap::AllocationDomain;
use crate::world::Space;
use alloc::sync::Arc;
use vibeos_hal::runtime_platform::{get, BlockBackend};
use vibeos_storage_device::{MutationFailure, MutationResult};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    Offline,
    QueueFull,
    OutOfRange,
    ReadOnly,
    FlushUnsupported,
    TimedOut,
    DriverCancelled,
    DriverFault,
    DriverRestarted,
    DeviceIo,
    Unsupported,
    Protocol,
    Quarantined,
    AuthorityRevoked,
    PermissionDenied,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Offline => "block device is offline",
            Self::QueueFull => "block request queue is full",
            Self::OutOfRange => "sector is outside the device capacity",
            Self::ReadOnly => "block device is read-only",
            Self::FlushUnsupported => "block device does not support flush",
            Self::TimedOut => "block request timed out",
            Self::DriverCancelled => "block driver was cancelled",
            Self::DriverFault => "block driver faulted",
            Self::DriverRestarted => "block driver session restarted",
            Self::DeviceIo => "block device reported an I/O error",
            Self::Unsupported => "block device rejected the operation",
            Self::Protocol => "block device returned a malformed completion",
            Self::Quarantined => "block DMA is quarantined after an unconfirmed reset",
            Self::AuthorityRevoked => "block capability is absent or revoked",
            Self::PermissionDenied => "block capability lacks the required right",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockInfo {
    pub online: bool,
    pub quarantined: bool,
    pub capacity_sectors: u64,
    pub queue_size: u16,
    pub read_only: bool,
    pub supports_flush: bool,
    pub session_epoch: u64,
    pub irq: u32,
    pub used_interrupts: u64,
    pub last_error: Option<BlockError>,
    pub last_command: u8,
    pub interrupt_status: u32,
    pub present_state: u32,
}

pub type MmioWindow = dyn Resource;
pub type DmaRegion = dyn Resource;
pub type BlockDevice = dyn Resource;
pub struct BlockResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub device: Arc<BlockDevice>,
}
impl From<crate::sdhci_blk::BlockError> for BlockError {
    fn from(e: crate::sdhci_blk::BlockError) -> Self {
        match e {
            crate::sdhci_blk::BlockError::Offline => Self::Offline,
            crate::sdhci_blk::BlockError::QueueFull => Self::QueueFull,
            crate::sdhci_blk::BlockError::OutOfRange => Self::OutOfRange,
            crate::sdhci_blk::BlockError::ReadOnly => Self::ReadOnly,
            crate::sdhci_blk::BlockError::FlushUnsupported => Self::FlushUnsupported,
            crate::sdhci_blk::BlockError::TimedOut => Self::TimedOut,
            crate::sdhci_blk::BlockError::DriverCancelled => Self::DriverCancelled,
            crate::sdhci_blk::BlockError::DriverFault => Self::DriverFault,
            crate::sdhci_blk::BlockError::DriverRestarted => Self::DriverRestarted,
            crate::sdhci_blk::BlockError::DeviceIo => Self::DeviceIo,
            crate::sdhci_blk::BlockError::Unsupported => Self::Unsupported,
            crate::sdhci_blk::BlockError::Protocol => Self::Protocol,
            crate::sdhci_blk::BlockError::Quarantined => Self::Quarantined,
            crate::sdhci_blk::BlockError::AuthorityRevoked => Self::AuthorityRevoked,
            crate::sdhci_blk::BlockError::PermissionDenied => Self::PermissionDenied,
        }
    }
}
impl From<crate::virtio_blk::BlockError> for BlockError {
    fn from(e: crate::virtio_blk::BlockError) -> Self {
        match e {
            crate::virtio_blk::BlockError::Offline => Self::Offline,
            crate::virtio_blk::BlockError::QueueFull => Self::QueueFull,
            crate::virtio_blk::BlockError::OutOfRange => Self::OutOfRange,
            crate::virtio_blk::BlockError::ReadOnly => Self::ReadOnly,
            crate::virtio_blk::BlockError::FlushUnsupported => Self::FlushUnsupported,
            crate::virtio_blk::BlockError::TimedOut => Self::TimedOut,
            crate::virtio_blk::BlockError::DriverCancelled => Self::DriverCancelled,
            crate::virtio_blk::BlockError::DriverFault => Self::DriverFault,
            crate::virtio_blk::BlockError::DriverRestarted => Self::DriverRestarted,
            crate::virtio_blk::BlockError::DeviceIo => Self::DeviceIo,
            crate::virtio_blk::BlockError::Unsupported => Self::Unsupported,
            crate::virtio_blk::BlockError::Protocol => Self::Protocol,
            crate::virtio_blk::BlockError::Quarantined => Self::Quarantined,
            crate::virtio_blk::BlockError::AuthorityRevoked => Self::AuthorityRevoked,
            crate::virtio_blk::BlockError::PermissionDenied => Self::PermissionDenied,
        }
    }
}
pub fn discover() -> Option<BlockResources> {
    match get().block_backend {
        BlockBackend::Pio => {
            let r = crate::sdhci_blk::discover()?;
            Some(BlockResources {
                mmio: r.mmio,
                dma: r.dma,
                device: r.device,
            })
        }
        BlockBackend::Queued => {
            let r = crate::virtio_blk::discover()?;
            Some(BlockResources {
                mmio: r.mmio,
                dma: r.dma,
                device: r.device,
            })
        }
        BlockBackend::None => None,
    }
}
pub(crate) fn raw_info() -> BlockInfo {
    match get().block_backend {
        BlockBackend::Pio => {
            let i = crate::sdhci_blk::raw_info();
            BlockInfo {
                online: i.online,
                quarantined: i.quarantined,
                capacity_sectors: i.capacity_sectors,
                queue_size: i.queue_size,
                read_only: i.read_only,
                supports_flush: i.supports_flush,
                session_epoch: i.session_epoch,
                irq: i.irq,
                used_interrupts: i.used_interrupts,
                last_error: i.last_error.map(Into::into),
                last_command: i.last_command,
                interrupt_status: i.interrupt_status,
                present_state: i.present_state,
            }
        }
        BlockBackend::Queued => {
            let i = crate::virtio_blk::raw_info();
            BlockInfo {
                online: i.online,
                quarantined: i.quarantined,
                capacity_sectors: i.capacity_sectors,
                queue_size: i.queue_size,
                read_only: i.read_only,
                supports_flush: i.supports_flush,
                session_epoch: i.session_epoch,
                irq: i.irq,
                used_interrupts: i.used_interrupts,
                ..BlockInfo::default()
            }
        }
        BlockBackend::None => BlockInfo::default(),
    }
}
pub(crate) async fn raw_read_at(expected_epoch: u64, sector: u64) -> Result<[u8; 512], BlockError> {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::raw_read_at(expected_epoch, sector)
            .await
            .map_err(Into::into),
        BlockBackend::Queued => crate::virtio_blk::raw_read_at(expected_epoch, sector)
            .await
            .map_err(Into::into),
        BlockBackend::None => Err(BlockError::Offline),
    }
}
pub(crate) async fn raw_read_blocks_at(
    expected_epoch: u64,
    sector: u64,
    count: u32,
    output: &mut [u8],
) -> Result<(), BlockError> {
    match get().block_backend {
        BlockBackend::Pio => {
            crate::sdhci_blk::raw_read_blocks_at(expected_epoch, sector, count, output)
                .await
                .map_err(Into::into)
        }
        BlockBackend::Queued => {
            crate::virtio_blk::raw_read_blocks_at(expected_epoch, sector, count, output)
                .await
                .map_err(Into::into)
        }
        BlockBackend::None => Err(BlockError::Offline),
    }
}
pub(crate) async fn raw_write_at(
    expected_epoch: u64,
    sector: u64,
    data: [u8; 512],
) -> MutationResult<(), BlockError> {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::raw_write_at(expected_epoch, sector, data)
            .await
            .map_err(|e| e.map(Into::into)),
        BlockBackend::Queued => crate::virtio_blk::raw_write_at(expected_epoch, sector, data)
            .await
            .map_err(|e| e.map(Into::into)),
        BlockBackend::None => Err(MutationFailure::not_submitted(BlockError::Offline)),
    }
}
pub(crate) async fn raw_write_blocks_at(
    expected_epoch: u64,
    sector: u64,
    count: u32,
    data: &[u8],
) -> MutationResult<(), BlockError> {
    match get().block_backend {
        BlockBackend::Pio => {
            crate::sdhci_blk::raw_write_blocks_at(expected_epoch, sector, count, data)
                .await
                .map_err(|e| e.map(Into::into))
        }
        BlockBackend::Queued => {
            crate::virtio_blk::raw_write_blocks_at(expected_epoch, sector, count, data)
                .await
                .map_err(|e| e.map(Into::into))
        }
        BlockBackend::None => Err(MutationFailure::not_submitted(BlockError::Offline)),
    }
}
pub(crate) async fn raw_flush_at(expected_epoch: u64) -> MutationResult<(), BlockError> {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::raw_flush_at(expected_epoch)
            .await
            .map_err(|e| e.map(Into::into)),
        BlockBackend::Queued => crate::virtio_blk::raw_flush_at(expected_epoch)
            .await
            .map_err(|e| e.map(Into::into)),
        BlockBackend::None => Err(MutationFailure::not_submitted(BlockError::Offline)),
    }
}
pub async fn driver_task(space: &'static Space, mmio: Cap, dma: Cap, service: Cap) -> () {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::driver_task(space, mmio, dma, service).await,
        BlockBackend::Queued => crate::virtio_blk::driver_task(space, mmio, dma, service).await,
        BlockBackend::None => (),
    }
}
pub fn debug_waiter_counts() -> (usize, usize, usize) {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::debug_waiter_counts(),
        BlockBackend::Queued => crate::virtio_blk::debug_waiter_counts(),
        BlockBackend::None => (0, 0, 0),
    }
}
pub fn is_online() -> bool {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::is_online(),
        BlockBackend::Queued => crate::virtio_blk::is_online(),
        BlockBackend::None => false,
    }
}
pub fn inject_timeout() -> () {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::inject_timeout(),
        BlockBackend::Queued => crate::virtio_blk::inject_timeout(),
        BlockBackend::None => (),
    }
}
pub fn inject_fault_after_publish() -> () {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::inject_fault_after_publish(),
        BlockBackend::Queued => crate::virtio_blk::inject_fault_after_publish(),
        BlockBackend::None => (),
    }
}
pub unsafe fn recover_faulted_domain(domain: AllocationDomain) -> () {
    match get().block_backend {
        BlockBackend::Pio => crate::sdhci_blk::recover_faulted_domain(domain),
        BlockBackend::Queued => crate::virtio_blk::recover_faulted_domain(domain),
        BlockBackend::None => (),
    }
}
