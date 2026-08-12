//! Kernel Block/CSpace adapters for the separately compiled object store.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;

use vibeos_core::cap::{Cap, Rights};
use vibeos_object_store::{
    BackendError, BackendInfo, BackendMutationFuture, Platform, PublicationTarget, StoreService,
    StoredObject, STORE_END_SECTOR, STORE_FIRST_SECTOR,
};
use vibeos_storage_device::{
    ContractError, DeviceSession, Legacy512Adapter, MutationFailure, WriteDurability,
    LEGACY_BLOCK_SIZE,
};

use crate::block_device::{self, BlockDevice, BlockError};
use crate::world::Space;

struct StorePlatform {
    backend: Arc<Space>,
    block: Cap,
    adapter: Legacy512Adapter,
}

impl StorePlatform {
    fn new(backend: Arc<Space>, block: Cap) -> Self {
        let range = backend
            .0
            .lock()
            .lookup_lease::<BlockDevice>(block, Rights::READ)
            .expect("store backend receives a readable block range")
            .with(BlockDevice::range);
        assert_eq!(range.first_block(), STORE_FIRST_SECTOR);
        assert_eq!(range.end_block(), STORE_END_SECTOR);
        let adapter = Legacy512Adapter::new(range, STORE_FIRST_SECTOR)
            .expect("the exact M4 range has a valid legacy namespace");
        Self {
            backend,
            block,
            adapter,
        }
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
        let info =
            block_device::range_info_with(&self.lease(Rights::READ)?).map_err(map_block_error)?;
        let geometry = info.geometry();
        if geometry.logical_block_size() != LEGACY_BLOCK_SIZE
            || !geometry.supports_flush()
            || self.adapter.range().first_block() != STORE_FIRST_SECTOR
            || self.adapter.legacy_end_sector() != STORE_END_SECTOR
        {
            return Err(BackendError::Unsupported);
        }
        Ok(BackendInfo {
            // Preserve the M4 journal's historical absolute sector namespace.
            // I/O below translates it back to the range-relative API.
            capacity_sectors: self.adapter.legacy_end_sector(),
            read_only: info.read_only(),
            supports_flush: geometry.supports_flush(),
            session: info.session(),
        })
    }

    fn read_sector(
        &self,
        session: DeviceSession,
        sector: u64,
    ) -> vibeos_object_store::BackendFuture<'_, [u8; 512]> {
        Box::pin(async move {
            let relative = self
                .adapter
                .relative_sector(sector)
                .map_err(map_contract_error)?;
            let lease = self.lease(Rights::READ)?;
            let mut output = [0; 512];
            block_device::read_blocks_with_session(&lease, session, relative, 1, &mut output)
                .await
                .map_err(map_block_error)?;
            Ok(output)
        })
    }

    fn write_sector_durable(
        &self,
        expected: DeviceSession,
        sector: u64,
        bytes: [u8; 512],
    ) -> BackendMutationFuture<'_, ()> {
        Box::pin(async move {
            let relative = self
                .adapter
                .relative_sector(sector)
                .map_err(map_contract_error)
                .map_err(MutationFailure::not_submitted)?;
            // Hold this exact invocation lease and mutation session across the
            // data write and its durability barrier. A driver restart between
            // the two is therefore observable instead of silently mixing
            // device incarnations.
            let lease = self
                .lease(Rights::WRITE)
                .map_err(MutationFailure::not_submitted)?;
            let session = block_device::begin_mutation(&lease)
                .map_err(|failure| failure.map(map_block_error))?;
            if session.device_session() != expected {
                return Err(MutationFailure::not_submitted(
                    BackendError::DriverRestarted,
                ));
            }
            let durability = block_device::write_blocks_with_session(
                &lease, session, relative, 1, &bytes, false,
            )
            .await
            .map_err(|failure| failure.map(map_block_error))?;
            if durability == WriteDurability::RequiresFlush {
                let barrier = block_device::flush_with_session(&lease, session)
                    .await
                    .map_err(|failure| failure.map(map_block_error));
                vibeos_object_store::barrier_after_successful_write(barrier)?;
            }
            Ok(())
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

fn map_contract_error(error: ContractError) -> BackendError {
    match error {
        ContractError::OutsideRange | ContractError::ArithmeticOverflow => BackendError::OutOfRange,
        _ => BackendError::Unsupported,
    }
}
