//! Capability-scoped logical-block frontend.
//!
//! The selected board backend owns the raw controller service. Clients receive
//! only an attenuable [`BlockDevice`] resource naming one exact logical-block
//! range; every address is validated and translated before reaching the raw
//! backend.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use crate::cap::{InvocationLease, Resource, Rights, ScopedResource};
use vibeos_storage_device::{
    successful_write_durability, validate_flush, validate_request, BlockRange, ContractError,
    DeviceGeometry, DeviceId, DeviceInfo, DeviceSession, MutationFailure, MutationResult,
    Operation, RangeInfo, RangeSession, WriteCache, WriteDurability,
};

#[cfg(feature = "milkv-duo")]
use crate::sdhci_blk as backend;
#[cfg(feature = "qemu-virt")]
use crate::virtio_blk as backend;

#[allow(unused_imports)]
pub use backend::{
    debug_waiter_counts, driver_task, inject_fault_after_publish, inject_timeout, is_online,
    recover_faulted_domain, BlockError, BlockInfo, DmaRegion, MmioWindow,
};

#[cfg(feature = "qemu-virt")]
const MANAGED_DEVICE_ID: DeviceId = match DeviceId::new(0x5649_4245_4f53_0000_0000_0000_0000_0001) {
    Some(id) => id,
    None => panic!("managed block device identity must be non-zero"),
};

#[cfg(feature = "milkv-duo")]
const MANAGED_DEVICE_ID: DeviceId = match DeviceId::new(0x5649_4245_4f53_0000_0000_0000_0000_0002) {
    Some(id) => id,
    None => panic!("managed block device identity must be non-zero"),
};

/// Client-visible authority over one exact range in the managed device's
/// logical namespace. Safe derivation can only shrink this range.
pub struct BlockDevice {
    range: BlockRange,
}

impl BlockDevice {
    fn new(range: BlockRange) -> Arc<Self> {
        Arc::new(Self { range })
    }

    pub const fn range(&self) -> BlockRange {
        self.range
    }
}

impl Resource for BlockDevice {
    fn kind(&self) -> &'static str {
        "block-range"
    }

    fn describe(&self) -> String {
        format!(
            "{} logical blocks [{}..{})",
            self.range.device_id(),
            self.range.first_block(),
            self.range.end_block()
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Safety: attenuation delegates to `BlockRange::attenuate`, which preserves
// DeviceId and admits only a checked non-empty subset of the parent interval.
unsafe impl ScopedResource for BlockDevice {
    type Scope = (u64, u64);

    fn attenuate(&self, (relative_first, block_count): Self::Scope) -> Option<Arc<Self>> {
        self.range
            .attenuate(relative_first, block_count)
            .ok()
            .map(Self::new)
    }
}

/// Bootstrap-only resources. The raw service is intentionally a distinct type
/// from the client-visible range resource and is never minted into init or the
/// store backend.
pub(crate) struct BlockResources {
    pub mmio: Arc<MmioWindow>,
    pub dma: Arc<DmaRegion>,
    pub raw_device: Arc<backend::BlockDevice>,
    pub managed_range: Arc<BlockDevice>,
}

pub(crate) fn discover() -> Option<BlockResources> {
    let resources = backend::discover()?;
    let slice = vibeos_image_policy::BLOCK_DATA_SLICE?;
    // The SDHCI backend already translates its provisioned physical partition
    // into a zero-based managed namespace. QEMU's managed image also starts at
    // logical zero. Partition offsets therefore never enter a client CSpace.
    // SAFETY: image policy is the sole root provisioning authority for the
    // managed device namespace; client CSpaces receive only attenuated ranges.
    let range = unsafe { BlockRange::root(MANAGED_DEVICE_ID, 0, slice.sector_count) }.ok()?;
    Some(BlockResources {
        mmio: resources.mmio,
        dma: resources.dma,
        raw_device: resources.device,
        managed_range: BlockDevice::new(range),
    })
}

/// Geometry and session for the currently attached managed device.
pub fn range_info_with(lease: &InvocationLease<BlockDevice>) -> Result<RangeInfo, BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    let range = lease.with(BlockDevice::range);
    let info = current_device_info()?;
    RangeInfo::new(range, info).map_err(map_contract_error)
}

/// Compatibility diagnostics retain the board-specific status record while
/// requiring a live range capability. Capacity is descriptive, not authority;
/// all I/O is still range-relative and checked below.
pub fn info_with(lease: &InvocationLease<BlockDevice>) -> Result<BlockInfo, BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    lease.with(|_| ());
    Ok(backend::raw_info())
}

/// One mutation sequence pinned to an exact range and device incarnation.
/// Fields stay private so safe clients cannot manufacture a session after a
/// restart or bind it to another device.
#[derive(Clone, Copy)]
pub struct MutationSession {
    binding: RangeSession,
    geometry: DeviceGeometry,
}

impl MutationSession {
    pub const fn device_session(self) -> DeviceSession {
        self.binding.session()
    }
}

pub fn begin_mutation(
    lease: &InvocationLease<BlockDevice>,
) -> MutationResult<MutationSession, BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(MutationFailure::not_submitted(BlockError::PermissionDenied));
    }
    let range = lease.with(BlockDevice::range);
    let current = current_device_info().map_err(MutationFailure::not_submitted)?;
    let binding = RangeSession::bind(range, current)
        .map_err(map_contract_error)
        .map_err(MutationFailure::not_submitted)?;
    Ok(MutationSession {
        binding,
        geometry: current.geometry(),
    })
}

pub async fn read_with(
    lease: InvocationLease<BlockDevice>,
    relative_block: u64,
) -> Result<[u8; 512], BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    let expected = current_device_info()?.session();
    let mut output = [0; 512];
    read_blocks_with_session(&lease, expected, relative_block, 1, &mut output).await?;
    drop(lease);
    Ok(output)
}

/// Bounded range-relative read using one explicitly cached device session.
/// A reset between lookup and dispatch is rejected before raw publication.
pub async fn read_blocks_with_session(
    lease: &InvocationLease<BlockDevice>,
    expected: DeviceSession,
    relative_first: u64,
    block_count: u32,
    output: &mut [u8],
) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::READ) {
        return Err(BlockError::PermissionDenied);
    }
    let range = lease.with(BlockDevice::range);
    let (request, current) = validate_range_request(
        range,
        expected,
        Operation::Read,
        relative_first,
        block_count,
        output.len(),
    )?;
    // Both admitted backends currently truthfully report max_transfer=1 and a
    // 512-byte logical block. The slice API remains stable as those limits grow.
    let data = backend::raw_read_at(
        current.session().incarnation(),
        request.physical_first_block(),
    )
    .await?;
    output.copy_from_slice(&data);
    Ok(())
}

pub async fn write_with(
    lease: InvocationLease<BlockDevice>,
    relative_block: u64,
    data: [u8; 512],
) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    let session = begin_mutation(&lease).map_err(|failure| *failure.error())?;
    write_blocks_with_session(&lease, session, relative_block, 1, &data, false)
        .await
        .map_err(|failure| *failure.error())?;
    drop(lease);
    Ok(())
}

/// Bounded range-relative mutation. Success reports whether the exact write is
/// already durable or still requires a Flush in this same `MutationSession`.
pub async fn write_blocks_with_session(
    lease: &InvocationLease<BlockDevice>,
    session: MutationSession,
    relative_first: u64,
    block_count: u32,
    data: &[u8],
    fua: bool,
) -> MutationResult<WriteDurability, BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(MutationFailure::not_submitted(BlockError::PermissionDenied));
    }
    let range = lease.with(BlockDevice::range);
    if range != session.binding.range() {
        return Err(MutationFailure::not_submitted(BlockError::PermissionDenied));
    }
    let current = current_device_info().map_err(MutationFailure::not_submitted)?;
    session
        .binding
        .validate_current(current)
        .map_err(map_contract_error)
        .map_err(MutationFailure::not_submitted)?;
    let (request, current) = validate_range_request(
        range,
        session.binding.session(),
        Operation::Write { fua },
        relative_first,
        block_count,
        data.len(),
    )
    .map_err(MutationFailure::not_submitted)?;
    let durability = successful_write_durability(session.geometry, fua)
        .map_err(map_contract_error)
        .map_err(MutationFailure::not_submitted)?;
    if request.byte_len() != 512 {
        return Err(MutationFailure::not_submitted(BlockError::Unsupported));
    }
    let mut block = [0; 512];
    block.copy_from_slice(data);
    backend::raw_write_at(
        current.session().incarnation(),
        request.physical_first_block(),
        block,
    )
    .await?;
    Ok(durability)
}

pub async fn flush_with(lease: InvocationLease<BlockDevice>) -> Result<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(BlockError::PermissionDenied);
    }
    let session = begin_mutation(&lease).map_err(|failure| *failure.error())?;
    flush_with_session(&lease, session)
        .await
        .map_err(|failure| *failure.error())?;
    drop(lease);
    Ok(())
}

pub async fn flush_with_session(
    lease: &InvocationLease<BlockDevice>,
    session: MutationSession,
) -> MutationResult<(), BlockError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(MutationFailure::not_submitted(BlockError::PermissionDenied));
    }
    let range = lease.with(BlockDevice::range);
    if range != session.binding.range() {
        return Err(MutationFailure::not_submitted(BlockError::PermissionDenied));
    }
    let current = current_device_info().map_err(MutationFailure::not_submitted)?;
    session
        .binding
        .validate_current(current)
        .map_err(map_contract_error)
        .map_err(MutationFailure::not_submitted)?;
    validate_flush(session.binding, current)
        .map_err(map_contract_error)
        .map_err(MutationFailure::not_submitted)?;
    backend::raw_flush_at(current.session().incarnation()).await
}

fn validate_range_request(
    range: BlockRange,
    expected: DeviceSession,
    operation: Operation,
    relative_first: u64,
    block_count: u32,
    buffer_len: usize,
) -> Result<(vibeos_storage_device::ValidatedRequest, DeviceInfo), BlockError> {
    let current = current_device_info()?;
    require_session(current, expected)?;
    let binding = RangeSession::bind(range, current).map_err(map_contract_error)?;
    let request = validate_request(
        binding,
        current,
        operation,
        relative_first,
        block_count,
        buffer_len,
    )
    .map_err(map_contract_error)?;
    Ok((request, current))
}

fn require_session(info: DeviceInfo, expected: DeviceSession) -> Result<(), BlockError> {
    if info.session() == expected {
        Ok(())
    } else if info.session().device_id() != expected.device_id() {
        Err(BlockError::DriverRestarted)
    } else {
        Err(BlockError::DriverRestarted)
    }
}

fn current_device_info() -> Result<DeviceInfo, BlockError> {
    let raw = backend::raw_info();
    if raw.quarantined {
        return Err(BlockError::Quarantined);
    }
    if !raw.online {
        return Err(BlockError::Offline);
    }
    let session =
        DeviceSession::new(MANAGED_DEVICE_ID, raw.session_epoch).map_err(map_contract_error)?;
    let geometry = DeviceGeometry::new(
        512,
        None,
        1,
        0,
        1,
        None,
        WriteCache::Unknown,
        raw.supports_flush,
        false,
        None,
    )
    .map_err(map_contract_error)?;
    DeviceInfo::new(session, raw.capacity_sectors, raw.read_only, geometry)
        .map_err(map_contract_error)
}

fn map_contract_error(error: ContractError) -> BlockError {
    match error {
        ContractError::OutsideRange | ContractError::ArithmeticOverflow => BlockError::OutOfRange,
        ContractError::ReadOnly => BlockError::ReadOnly,
        ContractError::FlushUnsupported => BlockError::FlushUnsupported,
        ContractError::StaleIncarnation | ContractError::WrongDevice => BlockError::DriverRestarted,
        ContractError::FuaUnsupported
        | ContractError::DiscardUnsupported
        | ContractError::DiscardMisaligned => BlockError::Unsupported,
        ContractError::ZeroIncarnation
        | ContractError::EmptyRange
        | ContractError::EmptyRequest
        | ContractError::OverlappingRange
        | ContractError::InvalidGeometry
        | ContractError::TransferTooLarge
        | ContractError::WrongBufferLength => BlockError::Protocol,
    }
}
