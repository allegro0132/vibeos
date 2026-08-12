//! Capability-scoped logical-block storage contract.
//!
//! This crate performs no I/O and allocates no memory. It validates the stable
//! device identity, boot-local incarnation, geometry, authorized block range,
//! request size, and durability operation before a driver sees an address.

#![no_std]

use core::fmt;
use core::future::Future;

pub const LEGACY_BLOCK_SIZE: u32 = 512;
pub const MAX_LOGICAL_BLOCK_SIZE: u32 = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u128);

impl DeviceId {
    pub const fn new(value: u128) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u128 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "device:{:032x}", self.0)
    }
}

/// One attached incarnation of a stable managed device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceSession {
    device_id: DeviceId,
    incarnation: u64,
}

impl DeviceSession {
    pub const fn new(device_id: DeviceId, incarnation: u64) -> Result<Self, ContractError> {
        if incarnation == 0 {
            return Err(ContractError::ZeroIncarnation);
        }
        Ok(Self {
            device_id,
            incarnation,
        })
    }

    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    pub const fn incarnation(self) -> u64 {
        self.incarnation
    }
}

/// Exact descriptor for a non-empty half-open range of logical blocks.
///
/// Fields are private so safe callers can narrow a received value only through
/// [`BlockRange::attenuate`]. A root descriptor is an unsafe trusted-policy
/// boundary; online-growth APIs additionally require a session-bound
/// [`BlockRangeCapability`] rather than accepting this descriptor alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRange {
    device_id: DeviceId,
    first_block: u64,
    block_count: u64,
}

impl BlockRange {
    /// Mint a root descriptor from trusted discovery/provisioning policy.
    ///
    /// # Safety
    ///
    /// The caller must own the device's root provisioning policy and must
    /// ensure independently minted roots do not alias. Safe code can only
    /// attenuate a root it has already received.
    pub const unsafe fn root(
        device_id: DeviceId,
        first_block: u64,
        block_count: u64,
    ) -> Result<Self, ContractError> {
        if block_count == 0 {
            return Err(ContractError::EmptyRange);
        }
        if first_block.checked_add(block_count).is_none() {
            return Err(ContractError::ArithmeticOverflow);
        }
        Ok(Self {
            device_id,
            first_block,
            block_count,
        })
    }

    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    pub const fn first_block(self) -> u64 {
        self.first_block
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    pub const fn end_block(self) -> u64 {
        // Construction proves this addition cannot overflow.
        self.first_block + self.block_count
    }

    /// Produce a range relative to this authority. It can never widen or move
    /// outside the parent, and retains the exact device identity.
    pub const fn attenuate(
        self,
        relative_first: u64,
        block_count: u64,
    ) -> Result<Self, ContractError> {
        if block_count == 0 {
            return Err(ContractError::EmptyRange);
        }
        let Some(relative_end) = relative_first.checked_add(block_count) else {
            return Err(ContractError::ArithmeticOverflow);
        };
        if relative_end > self.block_count {
            return Err(ContractError::OutsideRange);
        }
        let Some(first_block) = self.first_block.checked_add(relative_first) else {
            return Err(ContractError::ArithmeticOverflow);
        };
        Ok(Self {
            device_id: self.device_id,
            first_block,
            block_count,
        })
    }

    pub const fn contains(self, other: Self) -> bool {
        self.device_id.get() == other.device_id.get()
            && other.first_block >= self.first_block
            && other.end_block() <= self.end_block()
    }

    pub const fn overlaps(self, other: Self) -> bool {
        self.device_id.get() == other.device_id.get()
            && self.first_block < other.end_block()
            && other.first_block < self.end_block()
    }

    /// Translate a range-relative request into the device's logical-block
    /// namespace after checked containment.
    pub const fn translate(
        self,
        relative_first: u64,
        block_count: u64,
    ) -> Result<u64, ContractError> {
        match self.attenuate(relative_first, block_count) {
            Ok(range) => Ok(range.first_block),
            Err(error) => Err(error),
        }
    }

    pub const fn byte_bounds(self, logical_block_size: u32) -> Result<(u64, u64), ContractError> {
        if logical_block_size == 0 {
            return Err(ContractError::InvalidGeometry);
        }
        let size = logical_block_size as u64;
        let Some(first) = self.first_block.checked_mul(size) else {
            return Err(ContractError::ArithmeticOverflow);
        };
        let Some(length) = self.block_count.checked_mul(size) else {
            return Err(ContractError::ArithmeticOverflow);
        };
        Ok((first, length))
    }
}

/// Trusted, non-cloneable issuer for one boot/device-incarnation range tree.
///
/// A provisioner derives sibling range capabilities from one parent without
/// allowing a holder of a child to widen it or manufacture another sibling.
pub struct BlockRangeProvisioner {
    parent: BlockRange,
    session: DeviceSession,
}

impl fmt::Debug for BlockRangeProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockRangeProvisioner(<opaque>)")
    }
}

impl BlockRangeProvisioner {
    /// Establish one root range tree for the current device incarnation.
    ///
    /// # Safety
    ///
    /// The caller must be trusted discovery/provisioning policy and must own
    /// the named root exclusively for this authority domain.
    pub unsafe fn new(
        session: DeviceSession,
        first_block: u64,
        block_count: u64,
    ) -> Result<Self, ContractError> {
        // SAFETY: inherited from this constructor's trusted-policy contract.
        let parent = unsafe { BlockRange::root(session.device_id(), first_block, block_count)? };
        Ok(Self { parent, session })
    }

    /// Derive one exact child. This can only shrink the provisioner's parent.
    pub fn derive(
        &self,
        relative_first: u64,
        block_count: u64,
    ) -> Result<BlockRangeCapability, ContractError> {
        Ok(BlockRangeCapability {
            parent: self.parent,
            range: self.parent.attenuate(relative_first, block_count)?,
            session: self.session,
        })
    }
}

/// Session-bound authority over one exact logical-block range.
///
/// The parent and session fields are private. A holder may copy or attenuate
/// this capability, but cannot widen it or derive a disjoint sibling.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BlockRangeCapability {
    parent: BlockRange,
    range: BlockRange,
    session: DeviceSession,
}

impl fmt::Debug for BlockRangeCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlockRangeCapability(<opaque>)")
    }
}

impl BlockRangeCapability {
    pub const fn range(self) -> BlockRange {
        self.range
    }

    pub const fn session(self) -> DeviceSession {
        self.session
    }

    pub fn attenuate(self, relative_first: u64, block_count: u64) -> Result<Self, ContractError> {
        Ok(Self {
            parent: self.parent,
            range: self.range.attenuate(relative_first, block_count)?,
            session: self.session,
        })
    }

    pub const fn same_authority_domain(self, other: Self) -> bool {
        self.parent.device_id.get() == other.parent.device_id.get()
            && self.parent.first_block == other.parent.first_block
            && self.parent.block_count == other.parent.block_count
            && self.session.device_id.get() == other.session.device_id.get()
            && self.session.incarnation == other.session.incarnation
    }

    /// Join one exact adjacent sibling from the same root/session domain.
    pub const fn join_adjacent(self, sibling: Self) -> Result<Self, ContractError> {
        if !self.same_authority_domain(sibling) {
            return if self.session.device_id.get() != sibling.session.device_id.get() {
                Err(ContractError::WrongDevice)
            } else if self.session.incarnation != sibling.session.incarnation {
                Err(ContractError::StaleIncarnation)
            } else {
                Err(ContractError::OutsideRange)
            };
        }
        if self.range.end_block() != sibling.range.first_block {
            return if self.range.overlaps(sibling.range) {
                Err(ContractError::OverlappingRange)
            } else {
                Err(ContractError::OutsideRange)
            };
        }
        let block_count = match self
            .range
            .block_count
            .checked_add(sibling.range.block_count)
        {
            Some(value) => value,
            None => return Err(ContractError::ArithmeticOverflow),
        };
        let relative_first = match self.range.first_block.checked_sub(self.parent.first_block) {
            Some(value) => value,
            None => return Err(ContractError::OutsideRange),
        };
        Ok(Self {
            parent: self.parent,
            range: match self.parent.attenuate(relative_first, block_count) {
                Ok(value) => value,
                Err(error) => return Err(error),
            },
            session: self.session,
        })
    }
}

/// Reject a newly admitted root grant that aliases an independently admitted
/// range on the same device. Parent/child attenuation is checked separately by
/// [`BlockRange::attenuate`] and is intentionally not passed to this function.
pub fn admit_non_overlapping(
    admitted: &[BlockRange],
    candidate: BlockRange,
) -> Result<(), ContractError> {
    if admitted
        .iter()
        .copied()
        .any(|range| range.overlaps(candidate))
    {
        Err(ContractError::OverlappingRange)
    } else {
        Ok(())
    }
}

/// Validate one complete child-grant plan before capabilities are derived.
/// Every child must be contained by the same parent and siblings must be
/// pairwise disjoint. Adjacent half-open ranges are accepted.
pub fn validate_grant_layout(
    parent: BlockRange,
    children: &[BlockRange],
) -> Result<(), ContractError> {
    for (index, child) in children.iter().copied().enumerate() {
        if child.device_id != parent.device_id {
            return Err(ContractError::WrongDevice);
        }
        if !parent.contains(child) {
            return Err(ContractError::OutsideRange);
        }
        if children[..index]
            .iter()
            .copied()
            .any(|admitted| admitted.overlaps(child))
        {
            return Err(ContractError::OverlappingRange);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteCache {
    WriteThrough,
    Volatile,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscardGeometry {
    granularity_blocks: u32,
    alignment_blocks: u32,
    max_blocks: u32,
}

impl DiscardGeometry {
    pub fn new(
        granularity_blocks: u32,
        alignment_blocks: u32,
        max_blocks: u32,
    ) -> Result<Self, ContractError> {
        if granularity_blocks == 0 || max_blocks == 0 || alignment_blocks >= granularity_blocks {
            return Err(ContractError::InvalidGeometry);
        }
        Ok(Self {
            granularity_blocks,
            alignment_blocks,
            max_blocks,
        })
    }

    pub const fn granularity_blocks(self) -> u32 {
        self.granularity_blocks
    }

    pub const fn alignment_blocks(self) -> u32 {
        self.alignment_blocks
    }

    pub const fn max_blocks(self) -> u32 {
        self.max_blocks
    }
}

/// Truthful device geometry in bytes and logical blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceGeometry {
    logical_block_size: u32,
    physical_block_size: Option<u32>,
    preferred_write_blocks: u32,
    preferred_write_alignment_blocks: u32,
    max_transfer_blocks: u32,
    atomic_write_blocks: Option<u32>,
    write_cache: WriteCache,
    supports_flush: bool,
    supports_fua: bool,
    discard: Option<DiscardGeometry>,
}

impl DeviceGeometry {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        logical_block_size: u32,
        physical_block_size: Option<u32>,
        preferred_write_blocks: u32,
        preferred_write_alignment_blocks: u32,
        max_transfer_blocks: u32,
        atomic_write_blocks: Option<u32>,
        write_cache: WriteCache,
        supports_flush: bool,
        supports_fua: bool,
        discard: Option<DiscardGeometry>,
    ) -> Result<Self, ContractError> {
        let invalid_physical = match physical_block_size {
            Some(size) => {
                logical_block_size == 0
                    || size < logical_block_size
                    || size % logical_block_size != 0
            }
            None => false,
        };
        let invalid_atomic = match atomic_write_blocks {
            Some(blocks) => blocks == 0 || blocks > max_transfer_blocks,
            None => false,
        };
        if logical_block_size < LEGACY_BLOCK_SIZE
            || logical_block_size > MAX_LOGICAL_BLOCK_SIZE
            || !logical_block_size.is_power_of_two()
            || invalid_physical
            || preferred_write_blocks == 0
            || preferred_write_alignment_blocks >= preferred_write_blocks
            || max_transfer_blocks == 0
            || invalid_atomic
        {
            return Err(ContractError::InvalidGeometry);
        }
        Ok(Self {
            logical_block_size,
            physical_block_size,
            preferred_write_blocks,
            preferred_write_alignment_blocks,
            max_transfer_blocks,
            atomic_write_blocks,
            write_cache,
            supports_flush,
            supports_fua,
            discard,
        })
    }

    pub const fn logical_block_size(self) -> u32 {
        self.logical_block_size
    }
    pub const fn physical_block_size(self) -> Option<u32> {
        self.physical_block_size
    }
    pub const fn preferred_write_blocks(self) -> u32 {
        self.preferred_write_blocks
    }
    pub const fn preferred_write_alignment_blocks(self) -> u32 {
        self.preferred_write_alignment_blocks
    }
    pub const fn max_transfer_blocks(self) -> u32 {
        self.max_transfer_blocks
    }
    pub const fn atomic_write_blocks(self) -> Option<u32> {
        self.atomic_write_blocks
    }
    pub const fn write_cache(self) -> WriteCache {
        self.write_cache
    }
    pub const fn supports_flush(self) -> bool {
        self.supports_flush
    }
    pub const fn supports_fua(self) -> bool {
        self.supports_fua
    }
    pub const fn discard(self) -> Option<DiscardGeometry> {
        self.discard
    }
    pub const fn has_ordered_durability(self) -> bool {
        // FUA makes only the exact FUA-tagged write durable; by itself it
        // cannot order an earlier plain write before later metadata.
        self.supports_flush || matches!(self.write_cache, WriteCache::WriteThrough)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    session: DeviceSession,
    capacity_blocks: u64,
    read_only: bool,
    geometry: DeviceGeometry,
}

impl DeviceInfo {
    pub const fn new(
        session: DeviceSession,
        capacity_blocks: u64,
        read_only: bool,
        geometry: DeviceGeometry,
    ) -> Result<Self, ContractError> {
        if capacity_blocks == 0 {
            return Err(ContractError::InvalidGeometry);
        }
        Ok(Self {
            session,
            capacity_blocks,
            read_only,
            geometry,
        })
    }

    pub const fn session(self) -> DeviceSession {
        self.session
    }
    pub const fn capacity_blocks(self) -> u64 {
        self.capacity_blocks
    }
    pub const fn read_only(self) -> bool {
        self.read_only
    }
    pub const fn geometry(self) -> DeviceGeometry {
        self.geometry
    }

    pub const fn admits(self, range: BlockRange) -> Result<(), ContractError> {
        if self.session.device_id().get() != range.device_id().get() {
            return Err(ContractError::WrongDevice);
        }
        if range.end_block() > self.capacity_blocks {
            return Err(ContractError::OutsideRange);
        }
        Ok(())
    }
}

/// Cached range binding. A driver restart invalidates this value even when the
/// stable range capability remains live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeSession {
    range: BlockRange,
    session: DeviceSession,
}

impl RangeSession {
    pub fn bind(range: BlockRange, info: DeviceInfo) -> Result<Self, ContractError> {
        info.admits(range)?;
        Ok(Self {
            range,
            session: info.session,
        })
    }

    pub fn validate_current(self, current: DeviceInfo) -> Result<(), ContractError> {
        if current.session.device_id().get() != self.session.device_id().get() {
            return Err(ContractError::WrongDevice);
        }
        if current.session.incarnation() != self.session.incarnation() {
            return Err(ContractError::StaleIncarnation);
        }
        current.admits(self.range)
    }

    pub const fn range(self) -> BlockRange {
        self.range
    }

    pub const fn session(self) -> DeviceSession {
        self.session
    }
}

/// Device facts scoped to the caller's exact block authority. Capacity is the
/// range length, never the raw device capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeInfo {
    range: BlockRange,
    session: DeviceSession,
    read_only: bool,
    geometry: DeviceGeometry,
}

impl RangeInfo {
    pub fn new(range: BlockRange, info: DeviceInfo) -> Result<Self, ContractError> {
        info.admits(range)?;
        Ok(Self {
            range,
            session: info.session,
            read_only: info.read_only,
            geometry: info.geometry,
        })
    }

    pub const fn range(self) -> BlockRange {
        self.range
    }
    pub const fn session(self) -> DeviceSession {
        self.session
    }
    pub const fn capacity_blocks(self) -> u64 {
        self.range.block_count
    }
    pub const fn read_only(self) -> bool {
        self.read_only
    }
    pub const fn geometry(self) -> DeviceGeometry {
        self.geometry
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Read,
    Write { fua: bool },
    Discard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedRequest {
    session: DeviceSession,
    operation: Operation,
    physical_first_block: u64,
    block_count: u32,
    byte_len: usize,
}

impl ValidatedRequest {
    pub const fn session(self) -> DeviceSession {
        self.session
    }
    pub const fn operation(self) -> Operation {
        self.operation
    }
    pub const fn physical_first_block(self) -> u64 {
        self.physical_first_block
    }
    pub const fn block_count(self) -> u32 {
        self.block_count
    }
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }
}

pub fn validate_request(
    binding: RangeSession,
    current: DeviceInfo,
    operation: Operation,
    relative_first: u64,
    block_count: u32,
    buffer_len: usize,
) -> Result<ValidatedRequest, ContractError> {
    binding.validate_current(current)?;
    if block_count == 0 {
        return Err(ContractError::EmptyRequest);
    }
    let geometry = current.geometry;
    if block_count > geometry.max_transfer_blocks {
        return Err(ContractError::TransferTooLarge);
    }
    let Some(byte_len) = (block_count as usize).checked_mul(geometry.logical_block_size as usize)
    else {
        return Err(ContractError::ArithmeticOverflow);
    };
    let physical_first_block = binding
        .range
        .translate(relative_first, u64::from(block_count))?;
    match operation {
        Operation::Read | Operation::Write { .. } if buffer_len != byte_len => {
            return Err(ContractError::WrongBufferLength);
        }
        Operation::Discard if buffer_len != 0 => return Err(ContractError::WrongBufferLength),
        _ => {}
    }
    match operation {
        Operation::Write { .. } | Operation::Discard if current.read_only => {
            return Err(ContractError::ReadOnly);
        }
        Operation::Write { fua: true } if !geometry.supports_fua => {
            return Err(ContractError::FuaUnsupported);
        }
        Operation::Discard => {
            let Some(discard) = geometry.discard else {
                return Err(ContractError::DiscardUnsupported);
            };
            if block_count > discard.max_blocks
                || physical_first_block % u64::from(discard.granularity_blocks)
                    != u64::from(discard.alignment_blocks)
                || !block_count.is_multiple_of(discard.granularity_blocks)
            {
                return Err(ContractError::DiscardMisaligned);
            }
        }
        _ => {}
    }
    Ok(ValidatedRequest {
        session: current.session,
        operation,
        physical_first_block,
        block_count,
        byte_len,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedFlush {
    session: DeviceSession,
    range: BlockRange,
}

impl ValidatedFlush {
    pub const fn session(self) -> DeviceSession {
        self.session
    }

    pub const fn range(self) -> BlockRange {
        self.range
    }
}

pub fn validate_flush(
    binding: RangeSession,
    current: DeviceInfo,
) -> Result<ValidatedFlush, ContractError> {
    binding.validate_current(current)?;
    if current.read_only {
        return Err(ContractError::ReadOnly);
    }
    if !current.geometry.supports_flush {
        return Err(ContractError::FlushUnsupported);
    }
    Ok(ValidatedFlush {
        session: current.session,
        range: binding.range,
    })
}

/// Resulting durability of a successful write completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDurability {
    /// Bytes were accepted, but a later flush is still required.
    RequiresFlush,
    /// The device contract makes this exact write durable (FUA or no volatile
    /// cache). This never follows merely from request completion plus a CRC.
    Durable,
}

pub fn successful_write_durability(
    geometry: DeviceGeometry,
    fua: bool,
) -> Result<WriteDurability, ContractError> {
    if fua {
        return if geometry.supports_fua {
            Ok(WriteDurability::Durable)
        } else {
            Err(ContractError::FuaUnsupported)
        };
    }
    Ok(
        if matches!(geometry.write_cache, WriteCache::WriteThrough) {
            WriteDurability::Durable
        } else {
            WriteDurability::RequiresFlush
        },
    )
}

/// Whether a failed mutating operation is known not to have reached the
/// device, or must be treated as having possibly completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationCertainty {
    NotSubmitted,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    Offline,
    QueueFull,
    OutOfRange,
    ReadOnly,
    Unsupported,
    TimedOut,
    Cancelled,
    DriverFault,
    DriverRestarted,
    DeviceIo,
    Protocol,
    Quarantined,
    Revoked,
    PermissionDenied,
}

pub type MutationResult<T, E> = Result<T, MutationFailure<E>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationFailure<E = FailureReason> {
    error: E,
    certainty: MutationCertainty,
}

impl<E> MutationFailure<E> {
    pub const fn not_submitted(error: E) -> Self {
        Self {
            error,
            certainty: MutationCertainty::NotSubmitted,
        }
    }

    pub const fn ambiguous(error: E) -> Self {
        Self {
            error,
            certainty: MutationCertainty::Ambiguous,
        }
    }

    pub const fn error(&self) -> &E {
        &self.error
    }

    pub const fn certainty(&self) -> MutationCertainty {
        self.certainty
    }

    pub fn into_parts(self) -> (E, MutationCertainty) {
        (self.error, self.certainty)
    }

    pub fn map<F>(self, map: impl FnOnce(E) -> F) -> MutationFailure<F> {
        MutationFailure {
            error: map(self.error),
            certainty: self.certainty,
        }
    }

    /// Once an earlier mutation has been submitted, a later pre-submission
    /// failure cannot prove that the composite operation had no media effect.
    pub fn force_ambiguous(self) -> Self {
        Self::ambiguous(self.error)
    }
}

impl MutationFailure<FailureReason> {
    pub const fn before_submission(reason: FailureReason) -> Self {
        Self::not_submitted(reason)
    }

    pub const fn after_submission(reason: FailureReason) -> Self {
        Self::ambiguous(reason)
    }

    pub const fn cancelled(submitted: bool) -> Self {
        if submitted {
            Self::after_submission(FailureReason::Cancelled)
        } else {
            Self::before_submission(FailureReason::Cancelled)
        }
    }

    pub const fn reason(&self) -> FailureReason {
        self.error
    }
}

/// Translation shim for the M4 journal's historical absolute 512-byte sector
/// namespace. It does not widen the backing `BlockRange`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Legacy512Adapter {
    range: BlockRange,
    legacy_first_sector: u64,
    legacy_end_sector: u64,
}

impl Legacy512Adapter {
    pub const fn new(range: BlockRange, legacy_first_sector: u64) -> Result<Self, ContractError> {
        let Some(legacy_end_sector) = legacy_first_sector.checked_add(range.block_count) else {
            return Err(ContractError::ArithmeticOverflow);
        };
        Ok(Self {
            range,
            legacy_first_sector,
            legacy_end_sector,
        })
    }

    pub const fn range(self) -> BlockRange {
        self.range
    }

    pub const fn legacy_first_sector(self) -> u64 {
        self.legacy_first_sector
    }

    pub const fn legacy_end_sector(self) -> u64 {
        self.legacy_end_sector
    }

    pub const fn device_block_for_legacy_sector(
        self,
        legacy_sector: u64,
    ) -> Result<u64, ContractError> {
        match self.relative_sector(legacy_sector) {
            Ok(relative) => self.range.translate(relative, 1),
            Err(error) => Err(error),
        }
    }

    /// Translate the historical absolute sector number into the relative
    /// namespace accepted by a capability-scoped block service.
    pub const fn relative_sector(self, legacy_sector: u64) -> Result<u64, ContractError> {
        let Some(relative) = legacy_sector.checked_sub(self.legacy_first_sector) else {
            return Err(ContractError::OutsideRange);
        };
        if relative >= self.range.block_count {
            return Err(ContractError::OutsideRange);
        }
        Ok(relative)
    }
}

/// Generic asynchronous data path. Implementations must still reject a
/// `ValidatedRequest` whose session is no longer current at dispatch.
pub trait BlockIo {
    type Error;
    type ReadFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;
    type WriteFuture<'a>: Future<Output = MutationResult<WriteDurability, Self::Error>>
    where
        Self: 'a;
    type FlushFuture<'a>: Future<Output = MutationResult<(), Self::Error>>
    where
        Self: 'a;

    fn info(&self) -> Result<DeviceInfo, Self::Error>;
    fn read<'a>(&'a self, request: ValidatedRequest, output: &'a mut [u8]) -> Self::ReadFuture<'a>;
    fn write<'a>(&'a self, request: ValidatedRequest, input: &'a [u8]) -> Self::WriteFuture<'a>;
    fn flush(&self, request: ValidatedFlush) -> Self::FlushFuture<'_>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    ZeroIncarnation,
    EmptyRange,
    EmptyRequest,
    ArithmeticOverflow,
    OutsideRange,
    OverlappingRange,
    WrongDevice,
    StaleIncarnation,
    InvalidGeometry,
    TransferTooLarge,
    WrongBufferLength,
    ReadOnly,
    FlushUnsupported,
    FuaUnsupported,
    DiscardUnsupported,
    DiscardMisaligned,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroIncarnation => "device incarnation must be non-zero",
            Self::EmptyRange => "block range must be non-empty",
            Self::EmptyRequest => "block request must be non-empty",
            Self::ArithmeticOverflow => "block address arithmetic overflowed",
            Self::OutsideRange => "block request is outside the authorized range",
            Self::OverlappingRange => "independent block grants overlap",
            Self::WrongDevice => "block range names a different device",
            Self::StaleIncarnation => "block request uses a stale device incarnation",
            Self::InvalidGeometry => "block geometry is invalid",
            Self::TransferTooLarge => "block request exceeds the maximum transfer",
            Self::WrongBufferLength => "buffer length does not match the block request",
            Self::ReadOnly => "block device is read-only",
            Self::FlushUnsupported => "block device does not support flush",
            Self::FuaUnsupported => "block device does not support FUA",
            Self::DiscardUnsupported => "block device does not support discard",
            Self::DiscardMisaligned => "discard request violates device geometry",
        })
    }
}
