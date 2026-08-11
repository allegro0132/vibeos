//! Pure Virtio 1.2 protocol helpers used by the supervised block and network
//! drivers.
//!
//! This module deliberately performs no MMIO and owns no DMA memory.  It keeps
//! the wire constants, feature/status state machine, descriptor construction,
//! and the reset-before-reuse invariant independently testable on the host.

#![cfg_attr(not(test), no_std)]

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
pub const DEVICE_ID_NETWORK: u32 = 1;
pub const DEVICE_ID_BLOCK: u32 = 2;
pub const DEVICE_ID_ENTROPY: u32 = 4;

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
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
pub const VIRTIO_NET_F_GUEST_ECN: u64 = 1 << 9;
pub const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
pub const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
pub const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
pub const VIRTIO_NET_F_HOST_ECN: u64 = 1 << 13;
pub const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
pub const VIRTIO_NET_F_CTRL_RX: u64 = 1 << 18;
pub const VIRTIO_NET_F_CTRL_VLAN: u64 = 1 << 19;
pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u64 = 1 << 21;
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u64 = 1 << 23;
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

/// The M4.4 network model deliberately implements a single queue pair with no
/// checksum/segmentation offload, merged receive buffers, control queue, MQ,
/// device-supplied MAC, or optional ring/platform mode. Only VERSION_1 is
/// acknowledged; the device may offer any of these bits without becoming
/// unusable, but the driver must leave them clear.
pub const NET_DRIVER_FEATURES: u64 = VIRTIO_F_VERSION_1;
pub const NET_DRIVER_REJECTED_FEATURES: u64 = VIRTIO_NET_F_CSUM
    | VIRTIO_NET_F_GUEST_CSUM
    | VIRTIO_NET_F_MTU
    | VIRTIO_NET_F_MAC
    | VIRTIO_NET_F_GUEST_TSO4
    | VIRTIO_NET_F_GUEST_TSO6
    | VIRTIO_NET_F_GUEST_ECN
    | VIRTIO_NET_F_GUEST_UFO
    | VIRTIO_NET_F_HOST_TSO4
    | VIRTIO_NET_F_HOST_TSO6
    | VIRTIO_NET_F_HOST_ECN
    | VIRTIO_NET_F_HOST_UFO
    | VIRTIO_NET_F_MRG_RXBUF
    | VIRTIO_NET_F_STATUS
    | VIRTIO_NET_F_CTRL_VQ
    | VIRTIO_NET_F_CTRL_RX
    | VIRTIO_NET_F_CTRL_VLAN
    | VIRTIO_NET_F_GUEST_ANNOUNCE
    | VIRTIO_NET_F_MQ
    | VIRTIO_NET_F_CTRL_MAC_ADDR
    | VIRTIO_RING_F_INDIRECT_DESC
    | VIRTIO_RING_F_EVENT_IDX
    | VIRTIO_F_ACCESS_PLATFORM
    | VIRTIO_F_RING_PACKED;

/// Virtio entropy devices define no device-specific feature bits.  This
/// split-ring driver therefore acknowledges only the mandatory modern
/// transport bit and leaves every optional ring/platform mode clear.
pub const ENTROPY_DRIVER_FEATURES: u64 = VIRTIO_F_VERSION_1;
pub const ENTROPY_DRIVER_REJECTED_FEATURES: u64 = VIRTIO_RING_F_INDIRECT_DESC
    | VIRTIO_RING_F_EVENT_IDX
    | VIRTIO_F_ACCESS_PLATFORM
    | VIRTIO_F_RING_PACKED;

pub const SPLIT_QUEUE_SIZE: u16 = 8;
pub const NET_QUEUE_SIZE: u16 = SPLIT_QUEUE_SIZE;
pub const NET_RECEIVE_QUEUE: u16 = 0;
pub const NET_TRANSMIT_QUEUE: u16 = 1;
pub const ENTROPY_QUEUE: u16 = 0;
pub const ENTROPY_MAX_REQUEST: u32 = 256;
pub const NET_HEADER_SIZE: u32 = 12;
/// Maximum untagged Ethernet frame carried by the current network model.
pub const NET_MAX_FRAME_SIZE: u32 = 1_514;
pub const NET_RECEIVE_BUFFER_SIZE: u32 = NET_HEADER_SIZE + NET_MAX_FRAME_SIZE;
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
    NotNetworkDevice { observed: u32 },
    NotEntropyDevice { observed: u32 },
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

/// Accept only a non-legacy Virtio network transport (device ID 1).
pub const fn probe_modern_net(identity: MmioIdentity) -> Result<(), ProbeError> {
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
    if identity.device_id != DEVICE_ID_NETWORK {
        return Err(ProbeError::NotNetworkDevice {
            observed: identity.device_id,
        });
    }
    Ok(())
}

/// Accept only a non-legacy Virtio entropy transport (device ID 4).
pub const fn probe_modern_entropy(identity: MmioIdentity) -> Result<(), ProbeError> {
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
    if identity.device_id != DEVICE_ID_ENTROPY {
        return Err(ProbeError::NotEntropyDevice {
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

/// Negotiate the deliberately feature-minimal modern network profile.
///
/// Optional network features are not prerequisites: frames carry no offload
/// metadata, RX uses exactly one 1,526-byte buffer, and only queue pair 0/1 is
/// configured. Unsupported offered bits stay clear in DriverFeatures.
pub const fn negotiate_net_features(offered: u64) -> Result<NegotiatedFeatures, FeatureError> {
    if offered & VIRTIO_F_VERSION_1 == 0 {
        return Err(FeatureError::MissingVersion1);
    }

    Ok(NegotiatedFeatures {
        offered,
        accepted: offered & NET_DRIVER_FEATURES,
        rejected: offered & NET_DRIVER_REJECTED_FEATURES,
    })
}

/// Negotiate the feature-minimal modern entropy profile.
pub const fn negotiate_entropy_features(offered: u64) -> Result<NegotiatedFeatures, FeatureError> {
    if offered & VIRTIO_F_VERSION_1 == 0 {
        return Err(FeatureError::MissingVersion1);
    }

    Ok(NegotiatedFeatures {
        offered,
        accepted: offered & ENTROPY_DRIVER_FEATURES,
        rejected: offered & ENTROPY_DRIVER_REJECTED_FEATURES,
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

    /// Select the modern network profile instead of the block profile.
    pub fn select_net_features(&mut self, offered: u64) -> Result<NegotiatedFeatures, InitError> {
        self.require_phase(InitPhase::Driver)?;
        let features = match negotiate_net_features(offered) {
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

    /// Select the modern entropy profile instead of the block profile.
    pub fn select_entropy_features(
        &mut self,
        offered: u64,
    ) -> Result<NegotiatedFeatures, InitError> {
        self.require_phase(InitPhase::Driver)?;
        let features = match negotiate_entropy_features(offered) {
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

/// The 12-byte modern `virtio_net_hdr` used before every Ethernet frame.
///
/// M4.4 negotiates no checksum or segmentation offload and no merged receive
/// buffers. TX writes an all-zero header. For RX, the driver preinitializes
/// bytes 10..12 to `num_buffers == 1`: QEMU 11's modern no-MRG path uses the
/// 12-byte prefix but overwrites only the first 10 bytes. Completion still
/// validates the final `num_buffers` value strictly rather than trusting it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub header_length: u16,
    pub gso_size: u16,
    pub checksum_start: u16,
    pub checksum_offset: u16,
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const fn transmit() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            header_length: 0,
            gso_size: 0,
            checksum_start: 0,
            checksum_offset: 0,
            num_buffers: 0,
        }
    }

    /// Canonical header with which the driver preinitializes a no-offload,
    /// no-MRG RX buffer before handing it to the device.
    pub const fn received_without_offload() -> Self {
        Self {
            num_buffers: 1u16.to_le(),
            ..Self::transmit()
        }
    }

    pub const fn header_length(self) -> u16 {
        u16::from_le(self.header_length)
    }

    pub const fn gso_size(self) -> u16 {
        u16::from_le(self.gso_size)
    }

    pub const fn checksum_start(self) -> u16 {
        u16::from_le(self.checksum_start)
    }

    pub const fn checksum_offset(self) -> u16 {
        u16::from_le(self.checksum_offset)
    }

    pub const fn num_buffers(self) -> u16 {
        u16::from_le(self.num_buffers)
    }

    pub const fn to_bytes(self) -> [u8; NET_HEADER_SIZE as usize] {
        let header_length = self.header_length().to_le_bytes();
        let gso_size = self.gso_size().to_le_bytes();
        let checksum_start = self.checksum_start().to_le_bytes();
        let checksum_offset = self.checksum_offset().to_le_bytes();
        let num_buffers = self.num_buffers().to_le_bytes();
        [
            self.flags,
            self.gso_type,
            header_length[0],
            header_length[1],
            gso_size[0],
            gso_size[1],
            checksum_start[0],
            checksum_start[1],
            checksum_offset[0],
            checksum_offset[1],
            num_buffers[0],
            num_buffers[1],
        ]
    }

    pub const fn from_bytes(bytes: [u8; NET_HEADER_SIZE as usize]) -> Self {
        Self {
            flags: bytes[0],
            gso_type: bytes[1],
            header_length: u16::from_le_bytes([bytes[2], bytes[3]]).to_le(),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]).to_le(),
            checksum_start: u16::from_le_bytes([bytes[6], bytes[7]]).to_le(),
            checksum_offset: u16::from_le_bytes([bytes[8], bytes[9]]).to_le(),
            num_buffers: u16::from_le_bytes([bytes[10], bytes[11]]).to_le(),
        }
    }

    pub const fn is_plain_transmit(self) -> bool {
        self.flags == 0
            && self.gso_type == 0
            && self.header_length() == 0
            && self.gso_size() == 0
            && self.checksum_start() == 0
            && self.checksum_offset() == 0
            && self.num_buffers() == 0
    }

    pub const fn is_plain_receive(self) -> bool {
        // Without the corresponding offload features, the four middle u16
        // fields carry no authority and must be ignored rather than treated as
        // trusted metadata or a reason to reset a conforming device.
        self.flags == 0 && self.gso_type == 0 && self.num_buffers() == 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetQueue {
    Receive,
    Transmit,
}

impl NetQueue {
    pub const fn index(self) -> u16 {
        match self {
            Self::Receive => NET_RECEIVE_QUEUE,
            Self::Transmit => NET_TRANSMIT_QUEUE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetOperation {
    Receive,
    Transmit { frame_length: u16 },
}

impl NetOperation {
    pub const fn queue(self) -> NetQueue {
        match self {
            Self::Receive => NetQueue::Receive,
            Self::Transmit { .. } => NetQueue::Transmit,
        }
    }

    pub const fn frame_length(self) -> Option<u16> {
        match self {
            Self::Receive => None,
            Self::Transmit { frame_length } => Some(frame_length),
        }
    }
}

/// Size of one contiguous DMA buffer holding header followed by frame bytes.
pub const fn net_descriptor_length(operation: NetOperation) -> Option<u32> {
    match operation {
        NetOperation::Receive => Some(NET_RECEIVE_BUFFER_SIZE),
        NetOperation::Transmit { frame_length }
            if frame_length != 0 && frame_length as u32 <= NET_MAX_FRAME_SIZE =>
        {
            Some(NET_HEADER_SIZE + frame_length as u32)
        }
        NetOperation::Transmit { .. } => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetReceiveLengthError {
    HeaderIncomplete { minimum: u32, observed: u32 },
    BufferOverrun { maximum: u32, observed: u32 },
}

/// Validate `used.len` before a driver reads even the first header byte from
/// RX DMA. This separate first-stage API prevents an under-reported completion
/// from causing uninitialized header memory to be interpreted merely to call
/// `NetDeviceModel::complete_receive`.
pub const fn validate_net_receive_length(used_length: u32) -> Result<u16, NetReceiveLengthError> {
    if used_length < NET_HEADER_SIZE {
        return Err(NetReceiveLengthError::HeaderIncomplete {
            minimum: NET_HEADER_SIZE,
            observed: used_length,
        });
    }
    if used_length > NET_RECEIVE_BUFFER_SIZE {
        return Err(NetReceiveLengthError::BufferOverrun {
            maximum: NET_RECEIVE_BUFFER_SIZE,
            observed: used_length,
        });
    }
    Ok((used_length - NET_HEADER_SIZE) as u16)
}

/// Build the one-descriptor network buffer required by the minimal profile.
/// RX is wholly device-writable; TX is wholly device-readable. Keeping header
/// and frame contiguous also makes a no-MRG receive packet exactly one Virtio
/// buffer even though callers expose the two logical regions separately.
pub fn build_net_descriptor(
    operation: NetOperation,
    buffer_address: u64,
) -> Result<Descriptor, ChainError> {
    if buffer_address == 0 {
        return Err(ChainError::ZeroAddress);
    }
    let length = net_descriptor_length(operation).ok_or(ChainError::InvalidPacketLength {
        observed: operation.frame_length().unwrap_or(0),
    })?;
    checked_end(buffer_address, length)?;
    let flags = match operation {
        NetOperation::Receive => DESC_F_WRITE,
        NetOperation::Transmit { .. } => 0,
    };
    Ok(Descriptor::new(buffer_address, length, flags, 0))
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
    InvalidPacketLength { observed: u16 },
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

// --- Modern Virtio network device model ----------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetToken {
    pub epoch: u64,
    pub serial: u64,
    pub queue: NetQueue,
    pub head: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetSubmission {
    pub token: NetToken,
    /// Producer index after publishing this head.
    pub available_index: u16,
    pub available_slot: u16,
    pub operation: NetOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetReceiveCompletion {
    pub submission: NetSubmission,
    /// Bytes following the 12-byte Virtio header. A zero-length device frame
    /// is represented here but remains rejected by `net::Packet`.
    pub frame_length: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetTransmitCompletion {
    pub submission: NetSubmission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetResetReason {
    Timeout,
    Cancelled,
    DriverFault,
    DeviceNeedsReset,
    MalformedCompletion,
    ResetFailed,
    IdentityExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetDeviceState {
    Active,
    ResetRequired {
        reason: NetResetReason,
    },
    /// Status read back as zero and all old DMA is reusable, but the driver
    /// must reinstall both virtqueues before publishing new buffers.
    ResetConfirmed,
    /// Terminal for this instance; only constructing a new model after driver
    /// restart may publish DMA again.
    Quarantined {
        reason: NetResetReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetQueueError {
    QueueFull {
        queue: NetQueue,
    },
    InvalidPacketLength {
        observed: usize,
    },
    ResetRequired,
    ReinitializeRequired,
    Quarantined,
    NoUsedCompletion {
        queue: NetQueue,
    },
    UsedIndexAdvancedTooFar {
        queue: NetQueue,
        pending: u16,
        active: u8,
    },
    UsedIdOutOfRange {
        queue: NetQueue,
        observed: u32,
    },
    UsedIdNotActive {
        queue: NetQueue,
        observed: u16,
    },
    UsedLengthOutOfRange {
        maximum: u32,
        observed: u32,
    },
    UsedLengthTooShort {
        minimum: u32,
        observed: u32,
    },
    UnsupportedReceiveHeader {
        observed: VirtioNetHeader,
    },
    StaleSession {
        expected: u64,
        observed: u64,
    },
    WrongToken,
    ResetNotRequired,
    ResetNotConfirmed {
        observed_status: u32,
    },
    ReinitializeNotReady,
    EpochExhausted,
    SerialExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NetQueueBook {
    available_index: u16,
    used_index: u16,
    active: [Option<NetSubmission>; SPLIT_QUEUE_SIZE as usize],
    active_count: u8,
}

impl NetQueueBook {
    const fn new() -> Self {
        Self {
            available_index: 0,
            used_index: 0,
            active: [None; SPLIT_QUEUE_SIZE as usize],
            active_count: 0,
        }
    }

    fn free_head(&self) -> Option<u16> {
        self.active
            .iter()
            .position(Option::is_none)
            .map(|index| index as u16)
    }
}

/// Allocation-free lifecycle model for the minimal modern network device.
///
/// Receive queue 0 and transmit queue 1 each permit eight in-flight buffers.
/// They have independent wrapping ring cursors but share one non-zero epoch
/// and one reset/quarantine boundary, because a status=0 device reset stops
/// both virtqueues. Any malformed completion therefore quarantines every
/// exposed RX and TX DMA buffer until reset is confirmed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetDeviceModel {
    epoch: u64,
    next_serial: u64,
    receive: NetQueueBook,
    transmit: NetQueueBook,
    state: NetDeviceState,
}

impl Default for NetDeviceModel {
    fn default() -> Self {
        Self::new()
    }
}

impl NetDeviceModel {
    pub const fn new() -> Self {
        Self {
            epoch: 1,
            next_serial: 1,
            receive: NetQueueBook::new(),
            transmit: NetQueueBook::new(),
            state: NetDeviceState::Active,
        }
    }

    pub const fn at_epoch(epoch: u64) -> Option<Self> {
        Self::at_epoch_and_serial(epoch, 1)
    }

    /// Test/support constructor for a caller-persisted non-zero identity
    /// cursor. Neither value may be zero.
    pub const fn at_epoch_and_serial(epoch: u64, next_serial: u64) -> Option<Self> {
        if epoch == 0 || next_serial == 0 {
            None
        } else {
            Some(Self {
                epoch,
                next_serial,
                receive: NetQueueBook::new(),
                transmit: NetQueueBook::new(),
                state: NetDeviceState::Active,
            })
        }
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn state(&self) -> NetDeviceState {
        self.state
    }

    pub const fn queue_size(&self) -> u16 {
        SPLIT_QUEUE_SIZE
    }

    pub const fn available_index(&self, queue: NetQueue) -> u16 {
        self.book(queue).available_index
    }

    pub const fn used_index(&self, queue: NetQueue) -> u16 {
        self.book(queue).used_index
    }

    pub const fn inflight(&self, queue: NetQueue) -> u8 {
        self.book(queue).active_count
    }

    pub const fn active_submission(&self, queue: NetQueue, head: u16) -> Option<NetSubmission> {
        if head >= SPLIT_QUEUE_SIZE {
            None
        } else {
            self.book(queue).active[head as usize]
        }
    }

    /// Whether one descriptor/DMA slot is safe to clear or initialize. In
    /// `ResetConfirmed` the old device no longer owns it, but publication is
    /// still forbidden until `reinitialize` returns the model to `Active`.
    pub const fn slot_reusable(&self, queue: NetQueue, head: u16) -> bool {
        if head >= SPLIT_QUEUE_SIZE {
            return false;
        }
        matches!(
            self.state,
            NetDeviceState::Active | NetDeviceState::ResetConfirmed
        ) && self.book(queue).active[head as usize].is_none()
    }

    pub const fn all_dma_reusable(&self) -> bool {
        matches!(
            self.state,
            NetDeviceState::Active | NetDeviceState::ResetConfirmed
        ) && self.receive.active_count == 0
            && self.transmit.active_count == 0
    }

    pub fn post_receive(&mut self) -> Result<NetSubmission, NetQueueError> {
        self.submit(NetOperation::Receive)
    }

    pub fn submit_transmit(&mut self, frame_length: usize) -> Result<NetSubmission, NetQueueError> {
        self.require_active()?;
        if frame_length == 0 || frame_length > NET_MAX_FRAME_SIZE as usize {
            return Err(NetQueueError::InvalidPacketLength {
                observed: frame_length,
            });
        }
        self.submit(NetOperation::Transmit {
            frame_length: frame_length as u16,
        })
    }

    pub fn complete_receive(
        &mut self,
        observed_used_index: u16,
        used: UsedElement,
        header: VirtioNetHeader,
    ) -> Result<NetReceiveCompletion, NetQueueError> {
        let (head, submission) =
            self.validate_used(NetQueue::Receive, observed_used_index, used)?;
        let length = used.length();
        let frame_length = match validate_net_receive_length(length) {
            Ok(frame_length) => frame_length,
            Err(NetReceiveLengthError::BufferOverrun { maximum, observed }) => {
                return self.malformed(NetQueueError::UsedLengthOutOfRange { maximum, observed });
            }
            Err(NetReceiveLengthError::HeaderIncomplete { minimum, observed }) => {
                return self.malformed(NetQueueError::UsedLengthTooShort { minimum, observed });
            }
        };
        if !header.is_plain_receive() {
            return self.malformed(NetQueueError::UnsupportedReceiveHeader { observed: header });
        }
        self.finish(NetQueue::Receive, head, observed_used_index);
        Ok(NetReceiveCompletion {
            submission,
            frame_length,
        })
    }

    pub fn complete_transmit(
        &mut self,
        observed_used_index: u16,
        used: UsedElement,
    ) -> Result<NetTransmitCompletion, NetQueueError> {
        let (head, submission) =
            self.validate_used(NetQueue::Transmit, observed_used_index, used)?;
        // TX exposes no device-writable bytes. Virtio specifies no useful
        // completion length here, and historical devices report either zero or
        // the descriptor length, so the value is deliberately ignored.
        self.finish(NetQueue::Transmit, head, observed_used_index);
        Ok(NetTransmitCompletion { submission })
    }

    pub fn timeout(&mut self, token: NetToken) -> Result<(), NetQueueError> {
        self.abandon(token, NetResetReason::Timeout)
    }

    pub fn cancel(&mut self, token: NetToken) -> Result<(), NetQueueError> {
        self.abandon(token, NetResetReason::Cancelled)
    }

    /// Require one status=0 reset for both queues. Existing active slot records
    /// remain intact so no exposed DMA can be reused early.
    pub fn require_reset(&mut self, reason: NetResetReason) {
        if !matches!(self.state, NetDeviceState::Quarantined { .. }) {
            self.state = NetDeviceState::ResetRequired { reason };
        }
    }

    /// Permanently fail closed after a bounded reset attempt could not confirm
    /// status zero. This instance exposes no recovery transition.
    pub fn quarantine(&mut self, reason: NetResetReason) {
        self.state = NetDeviceState::Quarantined { reason };
    }

    /// Confirm status zero, release both DMA books together, and advance the
    /// shared epoch. Queue publication remains blocked until `reinitialize`.
    pub fn confirm_reset(&mut self, observed_status: u32) -> Result<(), NetQueueError> {
        match self.state {
            NetDeviceState::Quarantined { .. } => return Err(NetQueueError::Quarantined),
            NetDeviceState::ResetRequired { .. } => {}
            _ => return Err(NetQueueError::ResetNotRequired),
        }
        if observed_status != 0 {
            return Err(NetQueueError::ResetNotConfirmed { observed_status });
        }
        let Some(epoch) = self.epoch.checked_add(1) else {
            return Err(NetQueueError::EpochExhausted);
        };
        self.epoch = epoch;
        self.next_serial = 1;
        self.receive = NetQueueBook::new();
        self.transmit = NetQueueBook::new();
        self.state = NetDeviceState::ResetConfirmed;
        Ok(())
    }

    /// Mark both freshly reset queue structures ready for publication.
    pub fn reinitialize(&mut self) -> Result<(), NetQueueError> {
        match self.state {
            NetDeviceState::ResetConfirmed => {
                self.state = NetDeviceState::Active;
                Ok(())
            }
            NetDeviceState::Quarantined { .. } => Err(NetQueueError::Quarantined),
            _ => Err(NetQueueError::ReinitializeNotReady),
        }
    }

    fn submit(&mut self, operation: NetOperation) -> Result<NetSubmission, NetQueueError> {
        self.require_active()?;
        let queue = operation.queue();
        let (head, previous) = {
            let book = self.book(queue);
            let Some(head) = book.free_head() else {
                return Err(NetQueueError::QueueFull { queue });
            };
            (head, book.available_index)
        };
        let Some(serial_after) = self.next_serial.checked_add(1) else {
            self.state = NetDeviceState::Quarantined {
                reason: NetResetReason::IdentityExhausted,
            };
            return Err(NetQueueError::SerialExhausted);
        };
        let serial = self.next_serial;
        let epoch = self.epoch;
        let book = self.book_mut(queue);
        let submission = NetSubmission {
            token: NetToken {
                epoch,
                serial,
                queue,
                head,
            },
            available_index: advance_ring_index(previous),
            available_slot: ring_slot(previous),
            operation,
        };
        book.available_index = submission.available_index;
        book.active[head as usize] = Some(submission);
        book.active_count += 1;
        self.next_serial = serial_after;
        Ok(submission)
    }

    fn validate_used(
        &mut self,
        queue: NetQueue,
        observed_used_index: u16,
        used: UsedElement,
    ) -> Result<(u16, NetSubmission), NetQueueError> {
        self.require_active()?;
        let book = self.book(queue);
        let pending = observed_used_index.wrapping_sub(book.used_index);
        if pending == 0 {
            return Err(NetQueueError::NoUsedCompletion { queue });
        }
        if pending > book.active_count as u16 {
            return self.malformed(NetQueueError::UsedIndexAdvancedTooFar {
                queue,
                pending,
                active: book.active_count,
            });
        }
        let used_id = used.id();
        if used_id >= SPLIT_QUEUE_SIZE as u32 {
            return self.malformed(NetQueueError::UsedIdOutOfRange {
                queue,
                observed: used_id,
            });
        }
        let head = used_id as u16;
        let Some(submission) = book.active[head as usize] else {
            return self.malformed(NetQueueError::UsedIdNotActive {
                queue,
                observed: head,
            });
        };
        Ok((head, submission))
    }

    fn finish(&mut self, queue: NetQueue, head: u16, _observed_used_index: u16) {
        let book = self.book_mut(queue);
        book.active[head as usize] = None;
        book.active_count -= 1;
        // Consume exactly the UsedElement validated by this call. If the
        // device published a batch, subsequent calls retain the same observed
        // device index and drain one ring element at a time.
        book.used_index = advance_ring_index(book.used_index);
    }

    fn abandon(&mut self, token: NetToken, reason: NetResetReason) -> Result<(), NetQueueError> {
        if token.epoch != self.epoch {
            return Err(NetQueueError::StaleSession {
                expected: self.epoch,
                observed: token.epoch,
            });
        }
        self.require_active()?;
        if token.head >= SPLIT_QUEUE_SIZE
            || self.book(token.queue).active[token.head as usize]
                .is_none_or(|submission| submission.token != token)
        {
            return Err(NetQueueError::WrongToken);
        }
        self.state = NetDeviceState::ResetRequired { reason };
        Ok(())
    }

    fn require_active(&self) -> Result<(), NetQueueError> {
        match self.state {
            NetDeviceState::Active => Ok(()),
            NetDeviceState::ResetRequired { .. } => Err(NetQueueError::ResetRequired),
            NetDeviceState::ResetConfirmed => Err(NetQueueError::ReinitializeRequired),
            NetDeviceState::Quarantined { .. } => Err(NetQueueError::Quarantined),
        }
    }

    const fn book(&self, queue: NetQueue) -> &NetQueueBook {
        match queue {
            NetQueue::Receive => &self.receive,
            NetQueue::Transmit => &self.transmit,
        }
    }

    fn book_mut(&mut self, queue: NetQueue) -> &mut NetQueueBook {
        match queue {
            NetQueue::Receive => &mut self.receive,
            NetQueue::Transmit => &mut self.transmit,
        }
    }

    fn malformed<T>(&mut self, error: NetQueueError) -> Result<T, NetQueueError> {
        self.state = NetDeviceState::ResetRequired {
            reason: NetResetReason::MalformedCompletion,
        };
        Err(error)
    }
}
