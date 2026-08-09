//! Pure Virtio 1.2 protocol helpers used by the supervised block driver.
//!
//! This module deliberately performs no MMIO and owns no DMA memory.  It keeps
//! the wire constants, feature/status state machine, descriptor construction,
//! and the reset-before-reuse invariant independently testable on the host.

use core::mem::size_of;

// Virtio 1.2, section 4.2.2: modern MMIO register layout.
pub const MMIO_MAGIC_VALUE_OFFSET: usize = 0x000;
pub const MMIO_VERSION_OFFSET: usize = 0x004;
pub const MMIO_DEVICE_ID_OFFSET: usize = 0x008;
pub const MMIO_VENDOR_ID_OFFSET: usize = 0x00c;
pub const MMIO_DEVICE_FEATURES_OFFSET: usize = 0x010;
pub const MMIO_DEVICE_FEATURES_SEL_OFFSET: usize = 0x014;
pub const MMIO_DRIVER_FEATURES_OFFSET: usize = 0x020;
pub const MMIO_DRIVER_FEATURES_SEL_OFFSET: usize = 0x024;
pub const MMIO_QUEUE_SEL_OFFSET: usize = 0x030;
pub const MMIO_QUEUE_NUM_MAX_OFFSET: usize = 0x034;
pub const MMIO_QUEUE_NUM_OFFSET: usize = 0x038;
pub const MMIO_QUEUE_READY_OFFSET: usize = 0x044;
pub const MMIO_QUEUE_NOTIFY_OFFSET: usize = 0x050;
pub const MMIO_INTERRUPT_STATUS_OFFSET: usize = 0x060;
pub const MMIO_INTERRUPT_ACK_OFFSET: usize = 0x064;
pub const MMIO_STATUS_OFFSET: usize = 0x070;
pub const MMIO_QUEUE_DESC_LOW_OFFSET: usize = 0x080;
pub const MMIO_QUEUE_DESC_HIGH_OFFSET: usize = 0x084;
pub const MMIO_QUEUE_DRIVER_LOW_OFFSET: usize = 0x090;
pub const MMIO_QUEUE_DRIVER_HIGH_OFFSET: usize = 0x094;
pub const MMIO_QUEUE_DEVICE_LOW_OFFSET: usize = 0x0a0;
pub const MMIO_QUEUE_DEVICE_HIGH_OFFSET: usize = 0x0a4;
pub const MMIO_CONFIG_GENERATION_OFFSET: usize = 0x0fc;
pub const MMIO_CONFIG_OFFSET: usize = 0x100;

pub const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
pub const MMIO_VERSION_MODERN: u32 = 2;
pub const DEVICE_ID_BLOCK: u32 = 2;

pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u32 = 64;
pub const STATUS_FAILED: u32 = 128;

pub const INTERRUPT_USED_BUFFER: u32 = 1;
pub const INTERRUPT_CONFIGURATION_CHANGE: u32 = 2;
pub const INTERRUPT_KNOWN_MASK: u32 = INTERRUPT_USED_BUFFER | INTERRUPT_CONFIGURATION_CHANGE;

pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
pub const VIRTIO_RING_F_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_RING_F_EVENT_IDX: u64 = 1 << 29;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
pub const VIRTIO_F_RING_PACKED: u64 = 1 << 34;

/// Features implemented by the deliberately small M4.1 driver.
pub const BLOCK_DRIVER_FEATURES: u64 = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_FLUSH;

/// Ring/platform modes which must never be acknowledged by this split-ring
/// driver.  A device may offer them; rejecting a feature means leaving its bit
/// clear in `DriverFeatures`, not rejecting the entire device.
pub const BLOCK_DRIVER_REJECTED_FEATURES: u64 = VIRTIO_RING_F_INDIRECT_DESC
    | VIRTIO_RING_F_EVENT_IDX
    | VIRTIO_F_ACCESS_PLATFORM
    | VIRTIO_F_RING_PACKED;

pub const SPLIT_QUEUE_SIZE: u16 = 8;
pub const BLOCK_SECTOR_SIZE: u32 = 512;
pub const BLOCK_HEADER_DESCRIPTOR: u16 = 0;
pub const BLOCK_DATA_DESCRIPTOR: u16 = 1;
pub const BLOCK_STATUS_DESCRIPTOR: u16 = 2;

pub const DESC_F_NEXT: u16 = 1;
pub const DESC_F_WRITE: u16 = 2;
pub const DESC_F_INDIRECT: u16 = 4;

pub const BLOCK_REQUEST_IN: u32 = 0;
pub const BLOCK_REQUEST_OUT: u32 = 1;
pub const BLOCK_REQUEST_FLUSH: u32 = 4;

pub const BLOCK_STATUS_OK: u8 = 0;
pub const BLOCK_STATUS_IOERR: u8 = 1;
pub const BLOCK_STATUS_UNSUPP: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioIdentity {
    pub magic: u32,
    pub version: u32,
    pub device_id: u32,
    pub vendor_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    BadMagic { observed: u32 },
    LegacyTransport { observed: u32 },
    UnsupportedVersion { observed: u32 },
    NotBlockDevice { observed: u32 },
}

/// Accept only the non-legacy block transport described by Virtio 1.2.
pub const fn probe_modern_block(identity: MmioIdentity) -> Result<(), ProbeError> {
    if identity.magic != MMIO_MAGIC_VALUE {
        return Err(ProbeError::BadMagic {
            observed: identity.magic,
        });
    }
    if identity.version == 1 {
        return Err(ProbeError::LegacyTransport {
            observed: identity.version,
        });
    }
    if identity.version != MMIO_VERSION_MODERN {
        return Err(ProbeError::UnsupportedVersion {
            observed: identity.version,
        });
    }
    if identity.device_id != DEVICE_ID_BLOCK {
        return Err(ProbeError::NotBlockDevice {
            observed: identity.device_id,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterruptCauses(u32);

impl InterruptCauses {
    /// Reserved status bits are not acknowledged.  The caller can safely write
    /// `ack_bits()` to `InterruptACK` after recording the causes.
    pub const fn from_status(raw: u32) -> Self {
        Self(raw & INTERRUPT_KNOWN_MASK)
    }

    pub const fn used_buffer(self) -> bool {
        self.0 & INTERRUPT_USED_BUFFER != 0
    }

    pub const fn configuration_change(self) -> bool {
        self.0 & INTERRUPT_CONFIGURATION_CHANGE != 0
    }

    pub const fn ack_bits(self) -> u32 {
        self.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

pub const fn feature_word(features: u64, selector: u32) -> u32 {
    match selector {
        0 => features as u32,
        1 => (features >> 32) as u32,
        _ => 0,
    }
}

pub const fn features_from_words(low: u32, high: u32) -> u64 {
    low as u64 | ((high as u64) << 32)
}

/// One attempt at reading a multiword device configuration value guarded by
/// Virtio's configuration generation byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigU64Sample {
    pub generation_before: u32,
    pub low: u32,
    pub high: u32,
    pub generation_after: u32,
}

/// Return the first generation-consistent 64-bit configuration sample.
///
/// The retry budget is explicit because a malicious or broken device can keep
/// changing its generation forever. Transport code must fail closed instead
/// of spinning indefinitely on a non-preemptive kernel hart.
pub fn consistent_config_u64(
    retry_budget: usize,
    mut sample: impl FnMut() -> ConfigU64Sample,
) -> Option<u64> {
    for _ in 0..retry_budget {
        let sample = sample();
        if sample.generation_before == sample.generation_after {
            return Some(u64::from(sample.low) | (u64::from(sample.high) << 32));
        }
        core::hint::spin_loop();
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureError {
    MissingVersion1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiatedFeatures {
    offered: u64,
    accepted: u64,
    rejected: u64,
}

impl NegotiatedFeatures {
    pub const fn offered(self) -> u64 {
        self.offered
    }

    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    pub const fn rejected(self) -> u64 {
        self.rejected
    }

    pub const fn read_only(self) -> bool {
        self.accepted & VIRTIO_BLK_F_RO != 0
    }

    pub const fn supports_flush(self) -> bool {
        self.accepted & VIRTIO_BLK_F_FLUSH != 0
    }
}

pub const fn negotiate_block_features(offered: u64) -> Result<NegotiatedFeatures, FeatureError> {
    if offered & VIRTIO_F_VERSION_1 == 0 {
        return Err(FeatureError::MissingVersion1);
    }

    Ok(NegotiatedFeatures {
        offered,
        accepted: offered & BLOCK_DRIVER_FEATURES,
        rejected: offered & BLOCK_DRIVER_REJECTED_FEATURES,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitPhase {
    Reset,
    Acknowledged,
    Driver,
    FeaturesSelected,
    FeaturesOkWritten,
    FeaturesAccepted,
    Ready,
    ResetPending,
    ResetRequired,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    InvalidTransition { phase: InitPhase },
    MissingVersion1,
    FeaturesRejected,
    DeviceNeedsReset,
    DeviceFailed,
    StatusRegressed { expected: u32, observed: u32 },
    ResetNotConfirmed { observed: u32 },
}

/// Driver-side model of the cumulative device-status handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModernInit {
    phase: InitPhase,
    status: u32,
    features: Option<NegotiatedFeatures>,
}

impl Default for ModernInit {
    fn default() -> Self {
        Self::new()
    }
}

impl ModernInit {
    pub const fn new() -> Self {
        Self {
            phase: InitPhase::Reset,
            status: 0,
            features: None,
        }
    }

    pub const fn phase(&self) -> InitPhase {
        self.phase
    }

    pub const fn status_to_write(&self) -> u32 {
        self.status
    }

    pub const fn features(&self) -> Option<NegotiatedFeatures> {
        self.features
    }

    pub fn acknowledge(&mut self) -> Result<u32, InitError> {
        self.require_phase(InitPhase::Reset)?;
        self.status = STATUS_ACKNOWLEDGE;
        self.phase = InitPhase::Acknowledged;
        Ok(self.status)
    }

    pub fn declare_driver(&mut self) -> Result<u32, InitError> {
        self.require_phase(InitPhase::Acknowledged)?;
        self.status |= STATUS_DRIVER;
        self.phase = InitPhase::Driver;
        Ok(self.status)
    }

    pub fn select_features(&mut self, offered: u64) -> Result<NegotiatedFeatures, InitError> {
        self.require_phase(InitPhase::Driver)?;
        let features = match negotiate_block_features(offered) {
            Ok(features) => features,
            Err(FeatureError::MissingVersion1) => {
                self.fail();
                return Err(InitError::MissingVersion1);
            }
        };
        self.features = Some(features);
        self.phase = InitPhase::FeaturesSelected;
        Ok(features)
    }

    pub fn set_features_ok(&mut self) -> Result<u32, InitError> {
        self.require_phase(InitPhase::FeaturesSelected)?;
        self.status |= STATUS_FEATURES_OK;
        self.phase = InitPhase::FeaturesOkWritten;
        Ok(self.status)
    }

    /// Verify the status read back after writing `FEATURES_OK`.
    pub fn confirm_features(&mut self, observed: u32) -> Result<(), InitError> {
        self.require_phase(InitPhase::FeaturesOkWritten)?;
        if observed & STATUS_FAILED != 0 {
            self.phase = InitPhase::Failed;
            return Err(InitError::DeviceFailed);
        }
        if observed & STATUS_DEVICE_NEEDS_RESET != 0 {
            self.phase = InitPhase::ResetRequired;
            return Err(InitError::DeviceNeedsReset);
        }
        if observed & self.status != self.status {
            self.fail();
            return Err(InitError::FeaturesRejected);
        }
        self.phase = InitPhase::FeaturesAccepted;
        Ok(())
    }

    pub fn set_driver_ok(&mut self) -> Result<u32, InitError> {
        self.require_phase(InitPhase::FeaturesAccepted)?;
        self.status |= STATUS_DRIVER_OK;
        self.phase = InitPhase::Ready;
        Ok(self.status)
    }

    /// Check an operational status read without accepting status regression.
    pub fn observe(&mut self, observed: u32) -> Result<(), InitError> {
        if observed & STATUS_FAILED != 0 {
            self.phase = InitPhase::Failed;
            return Err(InitError::DeviceFailed);
        }
        if observed & STATUS_DEVICE_NEEDS_RESET != 0 {
            self.phase = InitPhase::ResetRequired;
            return Err(InitError::DeviceNeedsReset);
        }
        if observed & self.status != self.status {
            return Err(InitError::StatusRegressed {
                expected: self.status,
                observed,
            });
        }
        Ok(())
    }

    /// Set `FAILED`; the returned cumulative value must be written to Status.
    pub fn fail(&mut self) -> u32 {
        self.status |= STATUS_FAILED;
        self.phase = InitPhase::Failed;
        self.status
    }

    /// Begin a transport reset.  The returned zero must be written to Status.
    pub fn begin_reset(&mut self) -> u32 {
        self.status = 0;
        self.features = None;
        self.phase = InitPhase::ResetPending;
        0
    }

    /// Reset is complete only after Status reads back as zero.
    pub fn confirm_reset(&mut self, observed: u32) -> Result<(), InitError> {
        self.require_phase(InitPhase::ResetPending)?;
        if observed != 0 {
            return Err(InitError::ResetNotConfirmed { observed });
        }
        *self = Self::new();
        Ok(())
    }

    fn require_phase(&self, expected: InitPhase) -> Result<(), InitError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(InitError::InvalidTransition { phase: self.phase })
        }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    /// Little-endian device-readable physical address.
    pub address: u64,
    /// Little-endian buffer length.
    pub length: u32,
    /// Little-endian `DESC_F_*` bits.
    pub flags: u16,
    /// Little-endian descriptor-table index when `DESC_F_NEXT` is set.
    pub next: u16,
}

impl Descriptor {
    pub const fn new(address: u64, length: u32, flags: u16, next: u16) -> Self {
        Self {
            address: address.to_le(),
            length: length.to_le(),
            flags: flags.to_le(),
            next: next.to_le(),
        }
    }

    pub const fn address(self) -> u64 {
        u64::from_le(self.address)
    }

    pub const fn length(self) -> u32 {
        u32::from_le(self.length)
    }

    pub const fn flags(self) -> u16 {
        u16::from_le(self.flags)
    }

    pub const fn next(self) -> u16 {
        u16::from_le(self.next)
    }

    pub const fn device_writable(self) -> bool {
        self.flags() & DESC_F_WRITE != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsedElement {
    pub id: u32,
    pub length: u32,
}

impl UsedElement {
    pub const fn new(id: u32, length: u32) -> Self {
        Self {
            id: id.to_le(),
            length: length.to_le(),
        }
    }

    pub const fn id(self) -> u32 {
        u32::from_le(self.id)
    }

    pub const fn length(self) -> u32 {
        u32::from_le(self.length)
    }
}

/// Split available ring without the optional EVENT_IDX tail field.
#[repr(C, align(2))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AvailableRing {
    pub flags: u16,
    pub index: u16,
    pub ring: [u16; SPLIT_QUEUE_SIZE as usize],
}

/// Split used ring without the optional EVENT_IDX tail field.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UsedRing {
    pub flags: u16,
    pub index: u16,
    pub ring: [UsedElement; SPLIT_QUEUE_SIZE as usize],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockRequestHeader {
    pub request_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

impl BlockRequestHeader {
    pub const fn new(operation: BlockOperation) -> Self {
        Self {
            request_type: operation.request_type().to_le(),
            reserved: 0,
            sector: operation.sector().to_le(),
        }
    }

    pub const fn request_type(self) -> u32 {
        u32::from_le(self.request_type)
    }

    pub const fn sector(self) -> u64 {
        u64::from_le(self.sector)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOperation {
    Read { sector: u64 },
    Write { sector: u64 },
    Flush,
}

impl BlockOperation {
    pub const fn request_type(self) -> u32 {
        match self {
            Self::Read { .. } => BLOCK_REQUEST_IN,
            Self::Write { .. } => BLOCK_REQUEST_OUT,
            Self::Flush => BLOCK_REQUEST_FLUSH,
        }
    }

    pub const fn sector(self) -> u64 {
        match self {
            Self::Read { sector } | Self::Write { sector } => sector,
            Self::Flush => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDmaAddresses {
    pub header: u64,
    pub data: u64,
    pub status: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    ZeroAddress,
    AddressOverflow,
    OverlappingBuffers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockDescriptorChain {
    pub descriptors: [Descriptor; 3],
    descriptor_count: u16,
}

impl BlockDescriptorChain {
    pub const fn descriptor_count(self) -> u16 {
        self.descriptor_count
    }
}

/// Build the fixed DMA layout.  Read/write use header -> data -> status;
/// flush uses header -> status and leaves descriptor 1 unreachable.
pub fn build_block_chain(
    operation: BlockOperation,
    addresses: BlockDmaAddresses,
) -> Result<BlockDescriptorChain, ChainError> {
    if addresses.header == 0 || addresses.status == 0 {
        return Err(ChainError::ZeroAddress);
    }
    if !matches!(operation, BlockOperation::Flush) && addresses.data == 0 {
        return Err(ChainError::ZeroAddress);
    }

    let header_end = checked_end(addresses.header, size_of::<BlockRequestHeader>() as u32)?;
    let status_end = checked_end(addresses.status, 1)?;
    if overlaps(addresses.header, header_end, addresses.status, status_end) {
        return Err(ChainError::OverlappingBuffers);
    }

    let mut descriptors = [Descriptor::default(); 3];
    descriptors[BLOCK_STATUS_DESCRIPTOR as usize] =
        Descriptor::new(addresses.status, 1, DESC_F_WRITE, 0);

    let descriptor_count = match operation {
        BlockOperation::Read { .. } | BlockOperation::Write { .. } => {
            let data_end = checked_end(addresses.data, BLOCK_SECTOR_SIZE)?;
            if overlaps(addresses.header, header_end, addresses.data, data_end)
                || overlaps(addresses.data, data_end, addresses.status, status_end)
            {
                return Err(ChainError::OverlappingBuffers);
            }
            descriptors[BLOCK_HEADER_DESCRIPTOR as usize] = Descriptor::new(
                addresses.header,
                size_of::<BlockRequestHeader>() as u32,
                DESC_F_NEXT,
                BLOCK_DATA_DESCRIPTOR,
            );
            let data_flags = match operation {
                BlockOperation::Read { .. } => DESC_F_NEXT | DESC_F_WRITE,
                BlockOperation::Write { .. } => DESC_F_NEXT,
                BlockOperation::Flush => unreachable!(),
            };
            descriptors[BLOCK_DATA_DESCRIPTOR as usize] = Descriptor::new(
                addresses.data,
                BLOCK_SECTOR_SIZE,
                data_flags,
                BLOCK_STATUS_DESCRIPTOR,
            );
            3
        }
        BlockOperation::Flush => {
            descriptors[BLOCK_HEADER_DESCRIPTOR as usize] = Descriptor::new(
                addresses.header,
                size_of::<BlockRequestHeader>() as u32,
                DESC_F_NEXT,
                BLOCK_STATUS_DESCRIPTOR,
            );
            2
        }
    };

    Ok(BlockDescriptorChain {
        descriptors,
        descriptor_count,
    })
}

fn checked_end(start: u64, length: u32) -> Result<u64, ChainError> {
    start
        .checked_add(length as u64)
        .ok_or(ChainError::AddressOverflow)
}

const fn overlaps(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

/// Device-writable bytes in this request chain. Virtio permits a device to
/// under-report bytes actually written, but a modern driver may only consume
/// the first `used.len` bytes. Because block status is the final writable byte,
/// this driver requires the complete writable prefix before interpreting it.
pub const fn maximum_used_length(operation: BlockOperation) -> u32 {
    match operation {
        BlockOperation::Read { .. } => BLOCK_SECTOR_SIZE + 1,
        BlockOperation::Write { .. } | BlockOperation::Flush => 1,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Ok,
    IoError,
    Unsupported,
}

impl BlockStatus {
    pub const fn from_wire(raw: u8) -> Option<Self> {
        match raw {
            BLOCK_STATUS_OK => Some(Self::Ok),
            BLOCK_STATUS_IOERR => Some(Self::IoError),
            BLOCK_STATUS_UNSUPP => Some(Self::Unsupported),
            _ => None,
        }
    }
}

pub const fn ring_slot(index: u16) -> u16 {
    index % SPLIT_QUEUE_SIZE
}

pub const fn advance_ring_index(index: u16) -> u16 {
    index.wrapping_add(1)
}

pub const fn used_advanced_once(previous: u16, observed: u16) -> bool {
    observed == advance_ring_index(previous)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub epoch: u64,
    pub head: u16,
    /// Producer index after publishing this head.
    pub available_index: u16,
    pub available_slot: u16,
    pub operation: BlockOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetReason {
    Timeout,
    Cancelled,
    DriverFault,
    DeviceNeedsReset,
    MalformedCompletion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueState {
    Idle,
    InFlight(Submission),
    ResetRequired {
        reason: ResetReason,
        abandoned: Option<Submission>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    Busy,
    ResetRequired,
    ReadOnly,
    FlushUnsupported,
    StaleSession { expected: u64, observed: u64 },
    NotInFlight,
    WrongSubmission,
    UsedIndexDidNotAdvance { expected: u16, observed: u16 },
    UsedIdOutOfRange { observed: u32 },
    WrongUsedId { expected: u16, observed: u32 },
    UsedLengthOutOfRange { maximum: u32, observed: u32 },
    UsedLengthTooShort { minimum: u32, observed: u32 },
    UnknownBlockStatus { observed: u8 },
    ResetNotRequired,
    ResetNotConfirmed { observed_status: u32 },
    EpochExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub submission: Submission,
    pub block_status: BlockStatus,
}

/// Single-in-flight split-queue lifecycle model.
///
/// Timeout, cancellation, device reset, malformed used entries, and driver
/// faults all quarantine the descriptor/DMA slab.  `confirm_reset(0)` is the
/// only transition which releases it, and also changes the session epoch so a
/// stale completion token cannot be mistaken for a later request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitQueueModel {
    features: NegotiatedFeatures,
    epoch: u64,
    available_index: u16,
    used_index: u16,
    state: QueueState,
}

impl SplitQueueModel {
    pub const fn new(features: NegotiatedFeatures) -> Self {
        Self {
            features,
            epoch: 1,
            available_index: 0,
            used_index: 0,
            state: QueueState::Idle,
        }
    }

    /// Construct an idle model at a caller-owned, non-zero session epoch.
    /// Drivers which retain an epoch beside stable DMA memory can use this to
    /// preserve stale-token rejection across a supervised restart.
    pub const fn at_epoch(features: NegotiatedFeatures, epoch: u64) -> Option<Self> {
        if epoch == 0 {
            None
        } else {
            Some(Self {
                features,
                epoch,
                available_index: 0,
                used_index: 0,
                state: QueueState::Idle,
            })
        }
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn state(&self) -> QueueState {
        self.state
    }

    pub const fn available_index(&self) -> u16 {
        self.available_index
    }

    pub const fn used_index(&self) -> u16 {
        self.used_index
    }

    pub const fn dma_reusable(&self) -> bool {
        matches!(self.state, QueueState::Idle)
    }

    pub fn submit(&mut self, operation: BlockOperation) -> Result<Submission, QueueError> {
        match self.state {
            QueueState::Idle => {}
            QueueState::InFlight(_) => return Err(QueueError::Busy),
            QueueState::ResetRequired { .. } => return Err(QueueError::ResetRequired),
        }

        if matches!(operation, BlockOperation::Write { .. }) && self.features.read_only() {
            return Err(QueueError::ReadOnly);
        }
        if matches!(operation, BlockOperation::Flush) && !self.features.supports_flush() {
            return Err(QueueError::FlushUnsupported);
        }

        let previous = self.available_index;
        self.available_index = advance_ring_index(previous);
        let submission = Submission {
            epoch: self.epoch,
            head: BLOCK_HEADER_DESCRIPTOR,
            available_index: self.available_index,
            available_slot: ring_slot(previous),
            operation,
        };
        self.state = QueueState::InFlight(submission);
        Ok(submission)
    }

    pub fn complete(
        &mut self,
        submission: Submission,
        observed_used_index: u16,
        used: UsedElement,
        block_status: u8,
    ) -> Result<Completion, QueueError> {
        if submission.epoch != self.epoch {
            return Err(QueueError::StaleSession {
                expected: self.epoch,
                observed: submission.epoch,
            });
        }
        let active = match self.state {
            QueueState::Idle => return Err(QueueError::NotInFlight),
            QueueState::ResetRequired { .. } => return Err(QueueError::ResetRequired),
            QueueState::InFlight(active) => active,
        };
        if submission != active {
            return Err(QueueError::WrongSubmission);
        }

        let expected_index = advance_ring_index(self.used_index);
        if observed_used_index != expected_index {
            return self.malformed(QueueError::UsedIndexDidNotAdvance {
                expected: expected_index,
                observed: observed_used_index,
            });
        }
        let used_id = used.id();
        if used_id >= SPLIT_QUEUE_SIZE as u32 {
            return self.malformed(QueueError::UsedIdOutOfRange { observed: used_id });
        }
        if used_id != active.head as u32 {
            return self.malformed(QueueError::WrongUsedId {
                expected: active.head,
                observed: used_id,
            });
        }
        let maximum_length = maximum_used_length(active.operation);
        if used.length() > maximum_length {
            return self.malformed(QueueError::UsedLengthOutOfRange {
                maximum: maximum_length,
                observed: used.length(),
            });
        }
        if used.length() < maximum_length {
            return self.malformed(QueueError::UsedLengthTooShort {
                minimum: maximum_length,
                observed: used.length(),
            });
        }
        let Some(block_status) = BlockStatus::from_wire(block_status) else {
            return self.malformed(QueueError::UnknownBlockStatus {
                observed: block_status,
            });
        };
        self.used_index = observed_used_index;
        self.state = QueueState::Idle;
        Ok(Completion {
            submission: active,
            block_status,
        })
    }

    pub fn timeout(&mut self, submission: Submission) -> Result<(), QueueError> {
        self.abandon(submission, ResetReason::Timeout)
    }

    pub fn cancel(&mut self, submission: Submission) -> Result<(), QueueError> {
        self.abandon(submission, ResetReason::Cancelled)
    }

    /// Quarantine the current DMA slab after an external fault/reset signal.
    pub fn require_reset(&mut self, reason: ResetReason) {
        let abandoned = match self.state {
            QueueState::InFlight(submission) => Some(submission),
            QueueState::ResetRequired { abandoned, .. } => abandoned,
            QueueState::Idle => None,
        };
        self.state = QueueState::ResetRequired { reason, abandoned };
    }

    /// Complete the status=0 reset handshake and start a new ring session.
    pub fn confirm_reset(&mut self, observed_status: u32) -> Result<(), QueueError> {
        if !matches!(self.state, QueueState::ResetRequired { .. }) {
            return Err(QueueError::ResetNotRequired);
        }
        if observed_status != 0 {
            return Err(QueueError::ResetNotConfirmed { observed_status });
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            return Err(QueueError::EpochExhausted);
        };
        self.epoch = epoch;
        self.available_index = 0;
        self.used_index = 0;
        self.state = QueueState::Idle;
        Ok(())
    }

    fn abandon(&mut self, submission: Submission, reason: ResetReason) -> Result<(), QueueError> {
        if submission.epoch != self.epoch {
            return Err(QueueError::StaleSession {
                expected: self.epoch,
                observed: submission.epoch,
            });
        }
        match self.state {
            QueueState::Idle => Err(QueueError::NotInFlight),
            QueueState::ResetRequired { .. } => Err(QueueError::ResetRequired),
            QueueState::InFlight(active) if active != submission => {
                Err(QueueError::WrongSubmission)
            }
            QueueState::InFlight(active) => {
                self.state = QueueState::ResetRequired {
                    reason,
                    abandoned: Some(active),
                };
                Ok(())
            }
        }
    }

    fn malformed<T>(&mut self, error: QueueError) -> Result<T, QueueError> {
        let abandoned = match self.state {
            QueueState::InFlight(submission) => Some(submission),
            QueueState::ResetRequired { abandoned, .. } => abandoned,
            QueueState::Idle => None,
        };
        self.state = QueueState::ResetRequired {
            reason: ResetReason::MalformedCompletion,
            abandoned,
        };
        Err(error)
    }
}
