//! Kernel Block/CSpace adapters for the separately compiled object store.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use vibeos_core::cap::{Cap, Rights};
use vibeos_object_store::{
    BackendError, BackendInfo, Platform, PublicationTarget, StoreService, StoredObject,
};

use crate::virtio_blk::{self, BlockDevice, BlockError};
use crate::world::Space;

struct StorePlatform {
    backend: Arc<Space>,
    block: Cap,
}

impl StorePlatform {
    fn new(backend: Arc<Space>, block: Cap) -> Self {
        Self { backend, block }
    }

    fn lease(
        &self,
        need: Rights,
    ) -> Result<vibeos_core::cap::InvocationLease<BlockDevice>, BackendError> {
        self.backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(self.block, need)
            .map_err(|_| BackendError::AuthorityRevoked)
    }
}

impl Platform for StorePlatform {
    fn info(&self) -> Result<BackendInfo, BackendError> {
        let info = virtio_blk::info_with(&self.lease(Rights::READ)?).map_err(map_block_error)?;
        Ok(BackendInfo {
            capacity_sectors: info.capacity_sectors,
            read_only: info.read_only,
            supports_flush: info.supports_flush,
        })
    }

    fn read_sector(&self, sector: u64) -> vibeos_object_store::BackendFuture<'_, [u8; 512]> {
        Box::pin(async move {
            let lease = self.lease(Rights::READ)?;
            virtio_blk::read_with(lease, sector)
                .await
                .map_err(map_block_error)
        })
    }

    fn write_sector(
        &self,
        sector: u64,
        bytes: [u8; 512],
    ) -> vibeos_object_store::BackendFuture<'_, ()> {
        Box::pin(async move {
            let lease = self.lease(Rights::WRITE)?;
            virtio_blk::write_with(lease, sector, bytes)
                .await
                .map_err(map_block_error)
        })
    }

    fn flush(&self) -> vibeos_object_store::BackendFuture<'_, ()> {
        Box::pin(async move {
            let lease = self.lease(Rights::WRITE)?;
            virtio_blk::flush_with(lease).await.map_err(map_block_error)
        })
    }

    fn has_working_headroom(&self, required: usize) -> bool {
        let domain = vibeos_core::heap::current_domain();
        crate::HEAP
            .account_stats(domain.owner)
            .is_some_and(|stats| stats.quota_bytes.saturating_sub(stats.live_bytes) >= required)
    }
}

impl PublicationTarget for Space {
    fn incarnation(&self) -> u64 {
        self.0.lock().incarnation()
    }

    fn publish(
        &self,
        expected_incarnation: u64,
        object: Arc<StoredObject>,
        rights: Rights,
    ) -> Option<Cap> {
        self.0
            .lock()
            .mint_if_incarnation(expected_incarnation, object, rights)
    }
}

pub fn new_service(backend: Arc<Space>, block: Cap) -> Arc<StoreService> {
    StoreService::new(Arc::new(StorePlatform::new(backend, block)))
}

fn map_block_error(error: BlockError) -> BackendError {
    match error {
        BlockError::Offline => BackendError::Offline,
        BlockError::QueueFull => BackendError::QueueFull,
        BlockError::OutOfRange => BackendError::OutOfRange,
        BlockError::ReadOnly => BackendError::ReadOnly,
        BlockError::FlushUnsupported => BackendError::FlushUnsupported,
        BlockError::TimedOut => BackendError::TimedOut,
        BlockError::DriverCancelled => BackendError::DriverCancelled,
        BlockError::DriverFault => BackendError::DriverFault,
        BlockError::DriverRestarted => BackendError::DriverRestarted,
        BlockError::DeviceIo => BackendError::DeviceIo,
        BlockError::Unsupported => BackendError::Unsupported,
        BlockError::Protocol => BackendError::Protocol,
        BlockError::Quarantined => BackendError::Quarantined,
        BlockError::AuthorityRevoked => BackendError::AuthorityRevoked,
        BlockError::PermissionDenied => BackendError::PermissionDenied,
    }
}
