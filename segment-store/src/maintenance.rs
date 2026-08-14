//! Capability-gated Storage V2 maintenance operations.
//!
//! This authority is deliberately distinct from object-store write authority.
//! Safe attenuation can only remove operations; it can never add `grow`,
//! `scrub`, or the catch-all explicit-maintenance right.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use vibeos_segment_format::{
    admitted_pages, payload_sha256, Checkpoint, ExtentKind, RecordBinding, StoreUuid,
    ANCHOR_SEGMENT_NO, PAGE_SIZE, SEGMENT_PAGES,
};
use vibeos_storage_device::BlockRangeCapability;

use crate::allocation_v2::{
    encode_allocation_v2, AllocationV2Error, ALLOCATION_V2_HEADER_LEN, MAX_ALLOCATION_V2_SEGMENTS,
};
use crate::device::GrowablePageDevice;
use crate::gc::{GcError, GcStoreError, SegmentBuilder};
use crate::store::{read_pointer_payload, write_checkpoint, SegmentStore, StoreError, StoreInfo};

const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;

pub(crate) struct MaintenanceDomain {
    state: AtomicUsize,
}

impl MaintenanceDomain {
    const REVOKED: usize = 1_usize << (usize::BITS - 1);
    const ACTIVE_MASK: usize = Self::REVOKED - 1;

    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicUsize::new(0),
        }
    }

    fn is_live(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::REVOKED == 0
    }

    fn try_acquire(self: &Arc<Self>) -> Option<MaintenanceOperationLease> {
        let mut observed = self.state.load(Ordering::Acquire);
        loop {
            if observed & Self::REVOKED != 0 || observed & Self::ACTIVE_MASK == Self::ACTIVE_MASK {
                return None;
            }
            match self.state.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(MaintenanceOperationLease {
                        domain: self.clone(),
                    });
                }
                Err(current) => observed = current,
            }
        }
    }

    fn try_revoke(&self) -> Result<(), MaintenanceAuthorityError> {
        match self
            .state
            .compare_exchange(0, Self::REVOKED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) | Err(Self::REVOKED) => Ok(()),
            Err(_) => Err(MaintenanceAuthorityError::OperationsInFlight),
        }
    }
}

/// Non-cloneable invocation lease. Successful revocation cannot race past a
/// live lease, and an in-flight async operation never blocks a single-hart
/// executor by making the provisioner spin.
pub(crate) struct MaintenanceOperationLease {
    domain: Arc<MaintenanceDomain>,
}

impl Drop for MaintenanceOperationLease {
    fn drop(&mut self) {
        let previous = self.domain.state.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous & MaintenanceDomain::REVOKED == 0);
        debug_assert!(previous & MaintenanceDomain::ACTIVE_MASK > 0);
    }
}

/// One privileged Storage V2 maintenance operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MaintenanceOperation {
    Grow = 1 << 0,
    Scrub = 1 << 1,
    ExplicitMaintenance = 1 << 2,
}

#[allow(dead_code)] // exercised by crate-internal trusted provisioning tests
const ALL_OPERATIONS: u8 = MaintenanceOperation::Grow as u8
    | MaintenanceOperation::Scrub as u8
    | MaintenanceOperation::ExplicitMaintenance as u8;

/// An attenuable authority token for privileged store maintenance.
///
/// The root constructor is crate-sealed; normal object-store read/write
/// authority is insufficient to mint this value.
#[derive(Clone)]
pub struct StoreMaintenance {
    domain: Arc<MaintenanceDomain>,
    store_uuid: StoreUuid,
    device_id: [u8; 16],
    range_first_logical_block: u64,
    range_logical_block_count: u64,
    operations: u8,
}

/// Opaque provisioning authority retained by the trusted store service.
///
/// A provisioner is created together with one [`crate::StoreRuntimeContext`].
/// Constructing another runtime yields a different domain, so possession of a
/// normal store handle or runtime-context clone cannot mint maintenance rights
/// for an existing service.
pub struct StoreMaintenanceProvisioner {
    domain: Arc<MaintenanceDomain>,
}

impl fmt::Debug for StoreMaintenanceProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreMaintenanceProvisioner(<opaque>)")
    }
}

impl StoreMaintenanceProvisioner {
    pub(crate) fn new(domain: Arc<MaintenanceDomain>) -> Self {
        Self { domain }
    }

    pub(crate) fn authorizes(&self, domain: &Arc<MaintenanceDomain>) -> bool {
        Arc::ptr_eq(&self.domain, domain) && self.domain.is_live()
    }

    /// Permanently revoke every root and attenuated child issued by this
    /// runtime domain. A revoked provisioner cannot issue replacement roots;
    /// trusted policy creates a fresh runtime domain when reauthorization is
    /// required.
    pub fn revoke_all(&self) -> Result<(), MaintenanceAuthorityError> {
        self.domain.try_revoke()
    }
}

impl fmt::Debug for StoreMaintenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoreMaintenance(<opaque>)")
    }
}

impl StoreMaintenance {
    #[allow(dead_code)] // trusted image integration point, never public
    pub(crate) fn mint_root(
        domain: Arc<MaintenanceDomain>,
        store_uuid: StoreUuid,
        device_id: [u8; 16],
        range_first_logical_block: u64,
        range_logical_block_count: u64,
    ) -> Self {
        Self {
            domain,
            store_uuid,
            device_id,
            range_first_logical_block,
            range_logical_block_count,
            operations: ALL_OPERATIONS,
        }
    }

    /// Derive a child authority containing exactly the requested subset.
    pub fn attenuate(
        &self,
        operations: &[MaintenanceOperation],
    ) -> Result<Self, MaintenanceAuthorityError> {
        let mut requested = 0_u8;
        for operation in operations {
            requested |= *operation as u8;
        }
        if requested == 0 {
            return Err(MaintenanceAuthorityError::EmptyAuthority);
        }
        if requested & !self.operations != 0 {
            return Err(MaintenanceAuthorityError::AuthorityAmplification);
        }
        Ok(Self {
            domain: self.domain.clone(),
            store_uuid: self.store_uuid,
            device_id: self.device_id,
            range_first_logical_block: self.range_first_logical_block,
            range_logical_block_count: self.range_logical_block_count,
            operations: requested,
        })
    }

    pub(crate) fn acquire(
        &self,
        operation: MaintenanceOperation,
        expected_domain: &Arc<MaintenanceDomain>,
        expected_store_uuid: StoreUuid,
        expected_device_id: [u8; 16],
        expected_range_first_logical_block: u64,
        expected_range_logical_block_count: u64,
    ) -> Option<MaintenanceOperationLease> {
        if Arc::ptr_eq(&self.domain, expected_domain)
            && self.store_uuid == expected_store_uuid
            && self.device_id == expected_device_id
            && self.range_first_logical_block == expected_range_first_logical_block
            && self.range_logical_block_count == expected_range_logical_block_count
            && self.operations & operation as u8 != 0
        {
            self.domain.try_acquire()
        } else {
            None
        }
    }

    /// Acquire the one operation lease that may publish migration-control
    /// state. The controller lives outside the V2 data slice, so the caller
    /// must also present this runtime's private provisioner witness. Together
    /// they bind the exact authority domain, target store UUID, stable device,
    /// and complete V2 block range.
    pub(crate) fn acquire_explicit_migration(
        &self,
        provisioner: &StoreMaintenanceProvisioner,
        expected_store_uuid: StoreUuid,
        expected_device_id: [u8; 16],
        expected_range_first_logical_block: u64,
        expected_range_logical_block_count: u64,
    ) -> Option<MaintenanceOperationLease> {
        if provisioner.authorizes(&self.domain)
            && self.store_uuid == expected_store_uuid
            && self.device_id == expected_device_id
            && self.range_first_logical_block == expected_range_first_logical_block
            && self.range_logical_block_count == expected_range_logical_block_count
            && self.operations & MaintenanceOperation::ExplicitMaintenance as u8 != 0
        {
            self.domain.try_acquire()
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceAuthorityError {
    EmptyAuthority,
    AuthorityAmplification,
    OperationsInFlight,
}

impl fmt::Display for MaintenanceAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyAuthority => "maintenance authority must admit at least one operation",
            Self::AuthorityAmplification => "maintenance attenuation cannot add operations",
            Self::OperationsInFlight => "maintenance operation is already in flight",
        })
    }
}

impl core::error::Error for MaintenanceAuthorityError {}

#[derive(Debug)]
pub enum GrowError<E> {
    Unauthorized,
    WrongDevice,
    NotAdjacent,
    InvalidGeometry,
    ArithmeticOverflow,
    Capacity,
    GcPending,
    Store(StoreError<E>),
    Allocation(AllocationV2Error),
    Builder(GcError),
}

impl<E: fmt::Display> fmt::Display for GrowError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => formatter.write_str("Storage V2 grow authority denied"),
            Self::WrongDevice => formatter.write_str("growth range names a different device"),
            Self::NotAdjacent => {
                formatter.write_str("growth range is not the exact adjacent suffix")
            }
            Self::InvalidGeometry => formatter.write_str("growth range geometry is invalid"),
            Self::ArithmeticOverflow => formatter.write_str("growth range arithmetic overflowed"),
            Self::Capacity => formatter.write_str("growth metadata has no carrier capacity"),
            Self::GcPending => formatter.write_str("growth cannot overlap a pending GC barrier"),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Allocation(error) => write!(formatter, "{error}"),
            Self::Builder(error) => write!(formatter, "{error}"),
        }
    }
}

impl<E> From<StoreError<E>> for GrowError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<AllocationV2Error> for GrowError<E> {
    fn from(value: AllocationV2Error) -> Self {
        Self::Allocation(value)
    }
}

impl<E> From<GcStoreError<E>> for GrowError<E> {
    fn from(value: GcStoreError<E>) -> Self {
        match value {
            GcStoreError::Store(error) => Self::Store(error),
            GcStoreError::Gc(error) => Self::Builder(error),
        }
    }
}

impl<D: GrowablePageDevice> SegmentStore<D> {
    /// Admit one exact adjacent block-range capability and publish its segments
    /// as an all-Free suffix. The allocation payload is staged in the old
    /// admitted range; no byte in the new suffix is allocatable before the
    /// enlarged checkpoint seal is durable and a strict remount succeeds.
    pub async fn grow(
        &mut self,
        maintenance: &StoreMaintenance,
        additional: BlockRangeCapability,
    ) -> Result<StoreInfo, GrowError<D::Error>> {
        // Capability and mounted-store UUID gates precede even device.info().
        let _maintenance_lease = self
            .acquire_maintenance(maintenance, MaintenanceOperation::Grow)
            .ok_or(GrowError::Unauthorized)?;
        let state = self.require_current_generation()?;
        if !state.allocation.retired_segments().is_empty() {
            return Err(GrowError::GcPending);
        }
        let additional_range = additional.range();
        if additional_range.device_id().get().to_le_bytes() != state.superblock.device_id {
            return Err(GrowError::WrongDevice);
        }

        let info = self.device.info();
        if info.device_id != state.superblock.device_id
            || info.range_first_logical_block != state.superblock.range_first_logical_block
            || info.logical_block_size != state.superblock.logical_block_size
            || info.logical_block_size == 0
            || !(PAGE_SIZE as u64).is_multiple_of(u64::from(info.logical_block_size))
        {
            return Err(GrowError::InvalidGeometry);
        }
        let blocks_per_page = PAGE_SIZE as u64 / u64::from(info.logical_block_size);
        let durable_pages = admitted_pages(state.admitted_segments).map_err(StoreError::Format)?;
        let durable_blocks = durable_pages
            .checked_mul(blocks_per_page)
            .ok_or(GrowError::ArithmeticOverflow)?;
        let durable_end = info
            .range_first_logical_block
            .checked_add(durable_blocks)
            .ok_or(GrowError::ArithmeticOverflow)?;
        if additional_range.first_block() != durable_end {
            return Err(GrowError::NotAdjacent);
        }
        if !additional_range
            .block_count()
            .is_multiple_of(blocks_per_page)
        {
            return Err(GrowError::InvalidGeometry);
        }
        let additional_pages = additional_range.block_count() / blocks_per_page;
        if additional_pages == 0 || !additional_pages.is_multiple_of(SEGMENT_PAGES) {
            return Err(GrowError::InvalidGeometry);
        }
        let additional_segments = additional_pages / SEGMENT_PAGES;
        let enlarged_segments = state
            .admitted_segments
            .checked_add(additional_segments)
            .ok_or(GrowError::ArithmeticOverflow)?;
        if enlarged_segments > MAX_ALLOCATION_V2_SEGMENTS as u64 {
            return Err(GrowError::Capacity);
        }
        let enlarged_blocks = durable_blocks
            .checked_add(additional_range.block_count())
            .ok_or(GrowError::ArithmeticOverflow)?;
        let device_end = info
            .range_first_logical_block
            .checked_add(info.logical_block_count)
            .ok_or(GrowError::ArithmeticOverflow)?;
        if (info.logical_block_count != durable_blocks
            && info.logical_block_count != enlarged_blocks)
            || (additional_range.first_block() < device_end
                && additional_range.end_block() > device_end)
        {
            return Err(GrowError::NotAdjacent);
        }
        let expected_pages = info
            .logical_block_count
            .checked_div(blocks_per_page)
            .ok_or(GrowError::InvalidGeometry)?;
        if expected_pages != info.page_count {
            return Err(GrowError::InvalidGeometry);
        }

        // Growth is itself the operation that replenishes the free pool. It
        // may stage its allocation delta in one cleaner-reserve segment: the
        // admitted suffix replaces that free segment atomically in the same
        // checkpoint, so no ordinary foreground writer is granted reserve
        // access and a failed publication leaves the old reserve selected.
        let carrier = state.find_free_run(1, true).ok_or(GrowError::Capacity)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(GrowError::ArithmeticOverflow)?;
        let next_segment_generation = state
            .next_segment_generation
            .checked_add(1)
            .ok_or(GrowError::ArithmeticOverflow)?;

        // Preflight the true heap high-water before allocating any enlarged
        // map. Growth directly constructs one final map (there is no enlarged
        // intermediate). Staging later holds the final map plus both encoded
        // and reread payload buffers. SegmentBuilder owns one single-u64 Vec.
        let state_heap = state
            .resident_heap_bytes()
            .ok_or(GrowError::ArithmeticOverflow)?;
        let enlarged_bitmap = usize::try_from(enlarged_segments.div_ceil(4))
            .map_err(|_| GrowError::ArithmeticOverflow)?;
        let encoded_len = ALLOCATION_V2_HEADER_LEN
            .checked_add(enlarged_bitmap)
            .ok_or(GrowError::ArithmeticOverflow)?;
        let construction_peak = state_heap
            .checked_add(enlarged_bitmap)
            .ok_or(GrowError::ArithmeticOverflow)?;
        let builder_peak = state_heap
            .checked_add(enlarged_bitmap)
            .and_then(|bytes| bytes.checked_add(encoded_len))
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<u64>()))
            .ok_or(GrowError::ArithmeticOverflow)?;
        let verification_peak = state_heap
            .checked_add(enlarged_bitmap)
            .and_then(|bytes| bytes.checked_add(encoded_len.checked_mul(2)?))
            .ok_or(GrowError::ArithmeticOverflow)?;
        let operation_peak = construction_peak.max(builder_peak).max(verification_peak);
        if operation_peak > self.limits.recovery_memory_bytes {
            return Err(GrowError::Store(StoreError::MemoryLimit));
        }

        // The device owns the current session binding and range-root domain.
        // Reject stale or forged sibling capabilities before taking mounted
        // state or changing the addressable device view.
        self.device
            .validate_growth(durable_blocks, additional)
            .map_err(|error| GrowError::Store(StoreError::Device(error)))?;

        let allocation = state.allocation.grow_free_suffix(
            generation,
            next_segment_generation,
            enlarged_segments,
            carrier,
        )?;
        let allocation_bytes = encode_allocation_v2(&allocation)?;

        // Expanding the in-memory device binding grants addressability, not
        // store allocation. Keep the old mounted state installed until this
        // final synchronous device-policy recheck succeeds, so read-only,
        // incarnation, or geometry drift cannot poison an otherwise healthy
        // store. Only the checkpoint below admits the new pages.
        let grown_info = self
            .device
            .admit_growth(durable_blocks, additional)
            .map_err(|error| GrowError::Store(StoreError::Device(error)))?;
        let enlarged_pages = admitted_pages(enlarged_segments).map_err(StoreError::Format)?;
        if grown_info.device_id != info.device_id
            || grown_info.range_first_logical_block != info.range_first_logical_block
            || grown_info.logical_block_size != info.logical_block_size
            || grown_info.logical_block_count != enlarged_blocks
            || grown_info.page_count != enlarged_pages
            || grown_info.logical_block_count / blocks_per_page != grown_info.page_count
        {
            return Err(GrowError::InvalidGeometry);
        }

        // Take ownership without cloning the catalog/CAS/root sets only after
        // every non-mutating precondition has succeeded.
        let state = self
            .mounted
            .take()
            .ok_or(GrowError::Store(StoreError::RecoveryRequired))?;
        self.poisoned = true;

        let mut builder =
            SegmentBuilder::begin(&self.device, &state, generation, vec![carrier]).await?;
        let allocation_root = builder
            .payload(
                &self.device,
                ExtentKind::Allocation,
                METADATA_KIND_ALLOCATION,
                0,
                1,
                allocation_bytes.len() as u64,
                allocation_bytes.len() as u64,
                0,
                payload_sha256(&allocation_bytes),
                &allocation_bytes,
            )
            .await?;
        builder.finish(&self.device).await?;
        let staged = read_pointer_payload(
            &self.device,
            state.superblock.binding.store_uuid,
            enlarged_segments,
            next_segment_generation,
            generation,
            allocation_root,
            ExtentKind::Allocation,
            self.limits.recovery_memory_bytes,
        )
        .await?;
        if staged.bytes != allocation_bytes {
            return Err(GrowError::Store(StoreError::Corrupt));
        }
        drop(staged);
        let slot = ((generation - 1) & 1) as u8;
        let checkpoint = Checkpoint {
            binding: RecordBinding {
                store_uuid: state.superblock.binding.store_uuid,
                generation,
                segment_no: ANCHOR_SEGMENT_NO,
                ordinal: u32::from(slot),
                self_page: 4 + u64::from(slot) * 2,
                target_checkpoint_generation: generation,
            },
            slot,
            previous_generation: state.generation,
            admitted_range_pages: admitted_pages(enlarged_segments).map_err(StoreError::Format)?,
            admitted_segments: enlarged_segments,
            next_segment_generation,
            replay_count: state.replay_count,
            max_replay_records: self.limits.max_replay_records,
            cleaner_reserve_segments: state.cleaner_reserve_segments,
            catalog_root: state.catalog_root,
            authority_root: state.authority_root,
            allocation_root,
            replay_tail: state.replay_tail,
        };
        write_checkpoint(&self.device, &checkpoint, true).await?;
        drop(allocation_bytes);
        drop(allocation);
        drop(state);
        self.mount().await.map_err(GrowError::Store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attenuation_only_removes_operations() {
        let domain = Arc::new(MaintenanceDomain::new());
        let store_uuid = StoreUuid::new([1; 16]).unwrap();
        let device_id = [3; 16];
        let range_first_logical_block = 128;
        let grow = StoreMaintenance::mint_root(
            domain.clone(),
            store_uuid,
            device_id,
            range_first_logical_block,
            256,
        )
        .attenuate(&[MaintenanceOperation::Grow])
        .unwrap();
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                device_id,
                range_first_logical_block,
                256,
            )
            .is_some());
        assert!(grow
            .acquire(
                MaintenanceOperation::Scrub,
                &domain,
                store_uuid,
                device_id,
                range_first_logical_block,
                256,
            )
            .is_none());
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &Arc::new(MaintenanceDomain::new()),
                store_uuid,
                device_id,
                range_first_logical_block,
                256,
            )
            .is_none());
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                StoreUuid::new([2; 16]).unwrap(),
                device_id,
                range_first_logical_block,
                256,
            )
            .is_none());
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                [4; 16],
                range_first_logical_block,
                256,
            )
            .is_none());
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                device_id,
                range_first_logical_block + 1,
                256,
            )
            .is_none());
        assert!(grow
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                device_id,
                range_first_logical_block,
                255,
            )
            .is_none());
        assert!(matches!(
            grow.attenuate(&[MaintenanceOperation::Scrub]),
            Err(MaintenanceAuthorityError::AuthorityAmplification)
        ));
        assert!(matches!(
            grow.attenuate(&[]),
            Err(MaintenanceAuthorityError::EmptyAuthority)
        ));
        assert_eq!(alloc::format!("{grow:?}"), "StoreMaintenance(<opaque>)");
    }

    #[test]
    fn successful_revocation_cannot_cross_an_active_operation_lease() {
        let domain = Arc::new(MaintenanceDomain::new());
        let provisioner = StoreMaintenanceProvisioner::new(domain.clone());
        let store_uuid = StoreUuid::new([1; 16]).unwrap();
        let root = StoreMaintenance::mint_root(domain.clone(), store_uuid, [3; 16], 128, 256);
        let lease = root
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                [3; 16],
                128,
                256,
            )
            .unwrap();
        assert_eq!(
            provisioner.revoke_all(),
            Err(MaintenanceAuthorityError::OperationsInFlight)
        );
        drop(lease);
        assert_eq!(provisioner.revoke_all(), Ok(()));
        assert!(root
            .acquire(
                MaintenanceOperation::Grow,
                &domain,
                store_uuid,
                [3; 16],
                128,
                256,
            )
            .is_none());
    }
}
