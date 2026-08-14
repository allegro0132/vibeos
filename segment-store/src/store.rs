//! Append, checkpoint, and bounded recovery state machine.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{fmt, mem};

use vibeos_segment_format::{
    admitted_pages, decode_checkpoint_verified, decode_extent_verified,
    decode_segment_header_verified, decode_segment_seal_verified, decode_segment_summary_verified,
    decode_superblock_verified, descriptor_chain_initial, descriptor_chain_next,
    encode_checkpoint_body, encode_extent_body, encode_record_seal, encode_segment_header_body,
    encode_segment_seal_body, encode_segment_summary_body, encode_superblock_body,
    payload_chain_initial, payload_chain_next, payload_sha256, segment_base_page,
    select_checkpoint_for_superblock, select_superblock, BodyDigest, Checkpoint, DecodeStatus,
    ExtentKind, ExtentRecord, FormatError, FormatGeometry, Page, PhysicalPointer, PointerValue,
    RecordBinding, SegmentHeader, SegmentSeal, SegmentSummary, StoreUuid, Superblock,
    VerifiedRecord, ANCHOR_PAGES, ANCHOR_SEGMENT_NO, DATA_END_PAGE, DATA_FIRST_PAGE,
    MAX_EXTENT_PAYLOAD_PAGES, PAGE_SIZE, SEGMENT_PAGES, SEGMENT_SEAL_BODY_PAGE, SEGMENT_SEAL_PAGE,
    SUMMARY_BODY_PAGE, SUMMARY_SEAL_PAGE,
};
use vibeos_storage_device::{MutationCertainty, MutationFailure};

use crate::allocation_v2::{
    decode_allocation_v2, AllocationV2, SegmentAllocation, ALLOCATION_V2_HEADER_LEN,
    MAX_ALLOCATION_V2_SEGMENTS, RETIRED_SEGMENT_ENTRY_LEN,
};
use crate::authority_snapshot::{
    decode_persistent_authority_snapshot, PersistentAuthoritySnapshot,
    PERSISTENT_AUTHORITY_HEADER_LEN,
};
use crate::cas_codec::{
    decode_blob_manifest, decode_cas_snapshot, BlobManifest, BlobMapping, CasCodecContext,
    ManifestExtent, ObjectMapping, BLOB_MANIFEST_HEADER_LEN, BLOB_MAPPING_LEN,
    CAS_SNAPSHOT_HEADER_LEN, MANIFEST_EXTENT_LEN, OBJECT_MAPPING_LEN,
};
use crate::codec::{
    decode_allocation, decode_catalog, encode_allocation, encode_catalog, AllocationState,
    CatalogEntry, CatalogPayload, CatalogPayloadKind, CodecError, CATALOG_ENTRY_LEN,
    CATALOG_SNAPSHOT_HEADER_LEN,
};
use crate::device::{PageDevice, PageDeviceInfo};
use crate::maintenance::{
    MaintenanceDomain, MaintenanceOperation, MaintenanceOperationLease, StoreMaintenance,
    StoreMaintenanceProvisioner,
};
use crate::pins::{PinRegistry, SharedPinRegistry};
use crate::quota::{
    PrincipalQuotaTable, PrincipalQuotaUsage, QuotaDiagnostics, QuotaError, StoragePrincipal,
    StorageQuotaProvisioner, DEFAULT_MAX_STORAGE_PRINCIPALS,
};
use crate::root_codec::{
    decode_persistent_root_set, PersistentRootEntry, PersistentRootSet, PERSISTENT_ROOT_ENTRY_LEN,
    PERSISTENT_ROOT_SET_HEADER_LEN,
};

const METADATA_KIND_CATALOG: u32 = 0xffff_0001;
const METADATA_KIND_ALLOCATION: u32 = 0xffff_0002;

pub(crate) const ROOT_PIN_SLOTS: usize = 256;
pub(crate) const READER_PIN_SLOTS: usize = 256;
pub(crate) const RESERVED_ROOT_PIN_SLOTS: usize = 8;
pub(crate) const RESERVED_READER_PIN_SLOTS: usize = 8;
pub const MAX_TYPED_REFERENCE_KINDS: usize = 64;
/// One non-cleaner segment is held back so persistent root policy can revoke
/// the last ordinary object before foreground GC needs the cleaner reserve.
pub const ROOT_POLICY_HEADROOM_SEGMENTS: u32 = 1;
pub(crate) type StorePinRegistry = PinRegistry<ROOT_PIN_SLOTS, READER_PIN_SLOTS>;
pub(crate) type SharedStorePinRegistry = SharedPinRegistry<ROOT_PIN_SLOTS, READER_PIN_SLOTS>;

/// Runtime-only root/read pin domain for one mounted store service.
///
/// Keep this value across device-session recovery while in-memory object
/// capabilities remain live. A real process reboot reconstructs durable roots
/// and starts a fresh context because no old in-memory capability survives.
#[derive(Clone)]
pub struct StoreRuntimeContext {
    pub(crate) pins: SharedStorePinRegistry,
    published_generation: alloc::sync::Arc<AtomicU64>,
    typed_reference_kinds: alloc::sync::Arc<Vec<u32>>,
    maintenance_domain: alloc::sync::Arc<MaintenanceDomain>,
    pub(crate) quota: Option<PrincipalQuotaTable>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeContextError {
    TooManyTypedReferenceKinds,
    InvalidTypedReferenceKind,
    AllocationFailed,
    Quota(QuotaError),
}

impl fmt::Display for RuntimeContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyTypedReferenceKinds => "too many typed-reference ObjectKinds",
            Self::InvalidTypedReferenceKind => "typed-reference ObjectKind must be non-zero",
            Self::AllocationFailed => "typed-reference policy allocation failed",
            Self::Quota(error) => return write!(formatter, "{error}"),
        })
    }
}

impl core::error::Error for RuntimeContextError {}

impl From<QuotaError> for RuntimeContextError {
    fn from(value: QuotaError) -> Self {
        Self::Quota(value)
    }
}

impl StoreRuntimeContext {
    pub fn new() -> Self {
        Self::with_typed_reference_kinds(&[])
            .expect("empty Storage V2 typed-reference policy must be valid")
    }

    /// Build one trusted runtime together with its sole maintenance root
    /// provisioner. The provisioner is intentionally non-cloneable and is not
    /// reproduced by [`Self::clone`] or [`SegmentStore::runtime_context`].
    pub fn with_maintenance_provisioner() -> (Self, StoreMaintenanceProvisioner) {
        Self::with_typed_reference_kinds_and_maintenance_provisioner(&[])
            .expect("empty Storage V2 typed-reference policy must be valid")
    }

    /// Trusted-policy variant which also installs the typed-reference parser
    /// allowlist used by GC and scrub.
    pub fn with_typed_reference_kinds_and_maintenance_provisioner(
        kinds: &[u32],
    ) -> Result<(Self, StoreMaintenanceProvisioner), RuntimeContextError> {
        let context = Self::with_typed_reference_kinds(kinds)?;
        let provisioner = StoreMaintenanceProvisioner::new(context.maintenance_domain.clone());
        Ok((context, provisioner))
    }

    /// Constructs one trusted runtime policy for ObjectKinds whose immutable
    /// payloads may be interpreted as `refs-v1`.  The policy is not derived
    /// from media; callers rebuild it from trusted boot configuration.
    pub fn with_typed_reference_kinds(kinds: &[u32]) -> Result<Self, RuntimeContextError> {
        if kinds.len() > MAX_TYPED_REFERENCE_KINDS {
            return Err(RuntimeContextError::TooManyTypedReferenceKinds);
        }
        if kinds.contains(&0) {
            return Err(RuntimeContextError::InvalidTypedReferenceKind);
        }
        let mut typed_reference_kinds = Vec::new();
        typed_reference_kinds
            .try_reserve_exact(kinds.len())
            .map_err(|_| RuntimeContextError::AllocationFailed)?;
        typed_reference_kinds.extend_from_slice(kinds);
        typed_reference_kinds.sort_unstable();
        typed_reference_kinds.dedup();
        let pins = StorePinRegistry::new(RESERVED_ROOT_PIN_SLOTS, RESERVED_READER_PIN_SLOTS)
            .expect("fixed Storage V2 pin-registry configuration")
            .into_shared();
        Ok(Self {
            pins,
            published_generation: alloc::sync::Arc::new(AtomicU64::new(0)),
            typed_reference_kinds: alloc::sync::Arc::new(typed_reference_kinds),
            maintenance_domain: alloc::sync::Arc::new(MaintenanceDomain::new()),
            quota: None,
        })
    }

    /// Build a boot-local governed storage runtime and its sole trusted
    /// principal provisioner. A fresh process reboot creates a fresh domain;
    /// M7.6 intentionally does not persist principal attribution in media.
    pub fn governed() -> Result<(Self, StorageQuotaProvisioner), RuntimeContextError> {
        Self::governed_with_typed_reference_kinds(&[])
    }

    /// Build one governed runtime while returning both trusted provisioners.
    /// This is the production composition point for quota-governed stores
    /// which also expose separately attenuated maintenance resources.
    pub fn governed_with_maintenance_provisioner(
    ) -> Result<(Self, StorageQuotaProvisioner, StoreMaintenanceProvisioner), RuntimeContextError>
    {
        Self::governed_with_typed_reference_kinds_and_maintenance_provisioner(&[])
    }

    pub fn governed_with_typed_reference_kinds(
        kinds: &[u32],
    ) -> Result<(Self, StorageQuotaProvisioner), RuntimeContextError> {
        let mut context = Self::with_typed_reference_kinds(kinds)?;
        let table = PrincipalQuotaTable::new(DEFAULT_MAX_STORAGE_PRINCIPALS)?;
        let provisioner = table.provisioner();
        context.quota = Some(table);
        Ok((context, provisioner))
    }

    pub fn governed_with_typed_reference_kinds_and_maintenance_provisioner(
        kinds: &[u32],
    ) -> Result<(Self, StorageQuotaProvisioner, StoreMaintenanceProvisioner), RuntimeContextError>
    {
        let (context, quota) = Self::governed_with_typed_reference_kinds(kinds)?;
        let maintenance = StoreMaintenanceProvisioner::new(context.maintenance_domain.clone());
        Ok((context, quota, maintenance))
    }

    pub fn admits_typed_reference_kind(&self, object_kind: u32) -> bool {
        self.typed_reference_kinds
            .binary_search(&object_kind)
            .is_ok()
    }
}

impl Default for StoreRuntimeContext {
    fn default() -> Self {
        Self::new()
    }
}

fn publish_runtime_generation(current: &AtomicU64, generation: u64) -> bool {
    current.fetch_max(generation, Ordering::AcqRel) <= generation
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityClass {
    Payload,
    Metadata,
    CleanerReserve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub max_catalog_entries: u32,
    pub max_replay_records: u32,
    pub recovery_memory_bytes: usize,
    pub max_compat_object_bytes: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_catalog_entries: 4096,
            max_replay_records: 32,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: (MAX_EXTENT_PAYLOAD_PAGES as u64) * (PAGE_SIZE as u64),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatOptions {
    pub store_uuid: StoreUuid,
    pub cleaner_reserve_segments: u32,
    pub limits: StoreLimits,
}

const INITIAL_FORMAT_WRITE_ORDER: [u64; 6] = [0, 2, 1, 3, 4, 5];

struct InitialFormatPlan {
    pages: Box<[Page; 6]>,
}

fn initial_format_plan<E>(
    device_info: PageDeviceInfo,
    options: FormatOptions,
) -> Result<InitialFormatPlan, StoreError<E>> {
    validate_limits(options.limits)?;
    let segments = segments_for_page_count(device_info.page_count)?;
    let initial_allocation_bytes = allocation_v2_bitmap_bytes(segments)?;
    let ordinary_floor = u64::from(options.cleaner_reserve_segments)
        .checked_add(u64::from(ROOT_POLICY_HEADROOM_SEGMENTS))
        .ok_or(StoreError::InvalidConfig)?;
    if options.cleaner_reserve_segments < 2
        || ordinary_floor >= segments
        || options.limits.max_replay_records == 0
        || segments > MAX_ALLOCATION_V2_SEGMENTS as u64
        || initial_allocation_bytes > options.limits.recovery_memory_bytes
    {
        return Err(StoreError::InvalidConfig);
    }

    let base_binding = RecordBinding {
        store_uuid: options.store_uuid,
        generation: 1,
        segment_no: ANCHOR_SEGMENT_NO,
        ordinal: 0,
        self_page: 0,
        target_checkpoint_generation: 0,
    };
    let superblock_base = Superblock {
        binding: base_binding,
        copy: 0,
        geometry: FormatGeometry::STORAGE_V2,
        cleaner_reserve_segments: options.cleaner_reserve_segments,
        initial_range_pages: device_info.page_count,
        initial_segments: segments,
        device_id: device_info.device_id,
        range_first_logical_block: device_info.range_first_logical_block,
        initial_block_count: device_info.logical_block_count,
        logical_block_size: device_info.logical_block_size,
        max_replay_records: options.limits.max_replay_records,
    };
    let mut superblocks = [superblock_base; 2];
    superblocks[1].copy = 1;
    superblocks[1].binding.ordinal = 1;
    superblocks[1].binding.self_page = 2;

    let mut pages = Box::new([[0; PAGE_SIZE]; 6]);
    for (index, page) in [0usize, 2].into_iter().enumerate() {
        let digest = encode_superblock_body(&superblocks[index], &mut pages[page])?;
        encode_record_seal(digest, &mut pages[page + 1])?;
    }
    let checkpoint = Checkpoint {
        binding: RecordBinding {
            store_uuid: options.store_uuid,
            generation: 1,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: 0,
            self_page: 4,
            target_checkpoint_generation: 1,
        },
        slot: 0,
        previous_generation: 0,
        admitted_range_pages: device_info.page_count,
        admitted_segments: segments,
        next_segment_generation: 1,
        replay_count: 0,
        max_replay_records: options.limits.max_replay_records,
        cleaner_reserve_segments: options.cleaner_reserve_segments,
        catalog_root: PhysicalPointer::Null,
        authority_root: PhysicalPointer::Null,
        allocation_root: PhysicalPointer::Null,
        replay_tail: PhysicalPointer::Null,
    };
    let digest = encode_checkpoint_body(&checkpoint, &mut pages[4])?;
    encode_record_seal(digest, &mut pages[5])?;
    Ok(InitialFormatPlan { pages })
}

fn is_canonical_block_write_prefix(observed: &Page, expected: &Page) -> bool {
    const FORMAT_BLOCK_SIZE: usize = 512;
    (0..=PAGE_SIZE / FORMAT_BLOCK_SIZE).any(|written| {
        let boundary = written * FORMAT_BLOCK_SIZE;
        observed[..boundary] == expected[..boundary]
            && observed[boundary..].iter().all(|byte| *byte == 0)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    store_uuid: StoreUuid,
    object_id: u128,
    object_kind: u32,
    exact_len: u64,
    commit_generation: u64,
    content_root: [u8; 32],
}

impl ObjectHandle {
    pub const fn object_kind(&self) -> u32 {
        self.object_kind
    }

    pub const fn exact_len(&self) -> u64 {
        self.exact_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreInfo {
    pub generation: u64,
    pub admitted_segments: u64,
    pub allocated_segments: u64,
    pub free_segments: u64,
    pub cleaner_reserved_segments: u32,
    pub object_count: u32,
    pub replay_count: u32,
    pub recovery_peak_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError<E> {
    NotMounted,
    AlreadyFormatted,
    Unformatted,
    InvalidConfig,
    Device(E),
    Mutation(MutationFailure<E>),
    Format(FormatError),
    Corrupt,
    RecoveryRequired,
    GcResumeRequired,
    Capacity(CapacityClass),
    MemoryLimit,
    ObjectTooLarge,
    ObjectUnavailable,
    ObjectMismatch,
    MaintenanceAuthority,
    CatalogMode,
    IdExhausted,
    PrincipalRequired,
    Quota(QuotaError),
    QuotaPersistenceUnavailable,
}

impl<E: fmt::Display> fmt::Display for StoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMounted => f.write_str("Storage V2 store is not mounted"),
            Self::AlreadyFormatted => f.write_str("Storage V2 store is already formatted"),
            Self::Unformatted => f.write_str("Storage V2 store is not formatted"),
            Self::InvalidConfig => f.write_str("Storage V2 configuration is invalid"),
            Self::Device(error) => write!(f, "Storage V2 device read failed: {error}"),
            Self::Mutation(_) => f.write_str("Storage V2 device mutation failed"),
            Self::Format(error) => write!(f, "{error}"),
            Self::Corrupt => f.write_str("Storage V2 media is corrupt"),
            Self::RecoveryRequired => f.write_str("Storage V2 requires cold recovery"),
            Self::GcResumeRequired => {
                f.write_str("Storage V2 must finish the pending GC reuse barrier")
            }
            Self::Capacity(class) => write!(f, "Storage V2 {class:?} capacity exhausted"),
            Self::MemoryLimit => f.write_str("Storage V2 recovery memory ceiling exceeded"),
            Self::ObjectTooLarge => f.write_str("object exceeds the M7.3 compatibility profile"),
            Self::ObjectUnavailable => f.write_str("object is unavailable"),
            Self::ObjectMismatch => f.write_str("object handle does not match this store"),
            Self::MaintenanceAuthority => {
                f.write_str("Storage V2 maintenance provisioner does not match this runtime")
            }
            Self::CatalogMode => {
                f.write_str("operation is incompatible with the mounted catalog mode")
            }
            Self::IdExhausted => f.write_str("object identifier space is exhausted"),
            Self::PrincipalRequired => {
                f.write_str("Storage V2 governed writes require a storage principal")
            }
            Self::Quota(error) => write!(f, "{error}"),
            Self::QuotaPersistenceUnavailable => {
                f.write_str("boot-local quota attribution cannot enter persistent authority")
            }
        }
    }
}

impl<E> From<FormatError> for StoreError<E> {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}

impl<E> From<QuotaError> for StoreError<E> {
    fn from(value: QuotaError) -> Self {
        Self::Quota(value)
    }
}

#[derive(Clone)]
pub(crate) struct CasMountedState {
    pub(crate) objects: Vec<ObjectMapping>,
    pub(crate) blobs: Vec<BlobMapping>,
}

#[derive(Clone)]
pub(crate) struct MountedState {
    pub(crate) superblock: Superblock,
    pub(crate) generation: u64,
    pub(crate) admitted_segments: u64,
    pub(crate) next_physical_segment: u64,
    pub(crate) next_segment_generation: u64,
    pub(crate) next_object_id: u128,
    pub(crate) cleaner_reserve_segments: u32,
    pub(crate) replay_count: u32,
    pub(crate) catalog_root: PhysicalPointer,
    pub(crate) replay_tail: PhysicalPointer,
    pub(crate) authority_root: PhysicalPointer,
    pub(crate) allocation_root: PhysicalPointer,
    pub(crate) allocation: AllocationV2,
    pub(crate) allocation_version: u16,
    pub(crate) persistent_roots: Option<PersistentRootSet>,
    pub(crate) persistent_authority: Option<PersistentAuthoritySnapshot>,
    pub(crate) catalog: Vec<CatalogEntry>,
    pub(crate) cas: Option<CasMountedState>,
    pub(crate) recovery_peak_bytes: usize,
    pub(crate) last_segment: Option<(u64, u64, [u8; 32])>,
    pub(crate) last_segment_previous: Option<(u64, u64, [u8; 32])>,
    pub(crate) last_segment_target_checkpoint_generation: u64,
}

pub(crate) struct CheckpointTransitionWitness {
    store_uuid: StoreUuid,
    generation: u64,
    admitted_segments: u64,
    next_segment_generation: u64,
    cleaner_reserve_segments: u32,
    replay_count: u32,
    catalog_root: PhysicalPointer,
    replay_tail: PhysicalPointer,
    authority_root: PhysicalPointer,
    allocation_root: PhysicalPointer,
    allocation: AllocationV2,
    last_segment: Option<(u64, u64, [u8; 32])>,
}

impl CheckpointTransitionWitness {
    pub(crate) fn from_mounted(state: MountedState) -> Self {
        Self {
            store_uuid: state.superblock.binding.store_uuid,
            generation: state.generation,
            admitted_segments: state.admitted_segments,
            next_segment_generation: state.next_segment_generation,
            cleaner_reserve_segments: state.cleaner_reserve_segments,
            replay_count: state.replay_count,
            catalog_root: state.catalog_root,
            replay_tail: state.replay_tail,
            authority_root: state.authority_root,
            allocation_root: state.allocation_root,
            allocation: state.allocation,
            last_segment: state.last_segment,
        }
    }

    pub(crate) fn resident_bytes(&self) -> Option<usize> {
        self.allocation.allocated_bytes()
    }
}

pub struct SegmentStore<D> {
    pub(crate) device: D,
    pub(crate) limits: StoreLimits,
    pub(crate) mounted: Option<MountedState>,
    pub(crate) poisoned: bool,
    pub(crate) pins: SharedStorePinRegistry,
    pub(crate) published_generation: alloc::sync::Arc<AtomicU64>,
    pub(crate) typed_reference_kinds: alloc::sync::Arc<Vec<u32>>,
    pub(crate) maintenance_domain: alloc::sync::Arc<MaintenanceDomain>,
    pub(crate) quota: Option<PrincipalQuotaTable>,
}

impl<D: PageDevice> SegmentStore<D> {
    pub fn new(device: D, limits: StoreLimits) -> Self {
        Self::new_with_runtime_context(device, limits, StoreRuntimeContext::new())
    }

    pub fn new_with_runtime_context(
        device: D,
        limits: StoreLimits,
        runtime: StoreRuntimeContext,
    ) -> Self {
        Self {
            device,
            limits,
            mounted: None,
            poisoned: false,
            pins: runtime.pins,
            published_generation: runtime.published_generation,
            typed_reference_kinds: runtime.typed_reference_kinds,
            maintenance_domain: runtime.maintenance_domain,
            quota: runtime.quota,
        }
    }

    pub fn runtime_context(&self) -> StoreRuntimeContext {
        StoreRuntimeContext {
            pins: self.pins.clone(),
            published_generation: self.published_generation.clone(),
            typed_reference_kinds: self.typed_reference_kinds.clone(),
            maintenance_domain: self.maintenance_domain.clone(),
            quota: self.quota.clone(),
        }
    }

    pub fn principal_quota_usage(
        &self,
        principal: &StoragePrincipal,
    ) -> Result<PrincipalQuotaUsage, QuotaError> {
        self.quota
            .as_ref()
            .ok_or(QuotaError::UnknownPrincipal)?
            .principal_usage(principal)
    }

    pub fn quota_diagnostics(&self) -> Option<QuotaDiagnostics> {
        self.quota.as_ref().map(PrincipalQuotaTable::diagnostics)
    }

    /// Mint the maintenance root only for trusted policy holding the exact
    /// non-cloneable provisioner created with this runtime. A store handle or
    /// cloned runtime context alone is insufficient.
    pub fn provision_maintenance_root(
        &self,
        provisioner: &StoreMaintenanceProvisioner,
    ) -> Result<StoreMaintenance, StoreError<D::Error>> {
        let state = self.require_current_generation()?;
        if !provisioner.authorizes(&self.maintenance_domain) {
            return Err(StoreError::MaintenanceAuthority);
        }
        Ok(StoreMaintenance::mint_root(
            self.maintenance_domain.clone(),
            state.superblock.binding.store_uuid,
            state.superblock.device_id,
            state.superblock.range_first_logical_block,
            state.superblock.initial_block_count,
        ))
    }

    #[cfg(test)]
    pub(crate) fn mint_maintenance_root(&self) -> Result<StoreMaintenance, StoreError<D::Error>> {
        let state = self.require_current_generation()?;
        Ok(StoreMaintenance::mint_root(
            self.maintenance_domain.clone(),
            state.superblock.binding.store_uuid,
            state.superblock.device_id,
            state.superblock.range_first_logical_block,
            state.superblock.initial_block_count,
        ))
    }

    pub(crate) fn acquire_maintenance(
        &self,
        maintenance: &StoreMaintenance,
        operation: MaintenanceOperation,
    ) -> Option<MaintenanceOperationLease> {
        self.require_current_generation().ok().and_then(|state| {
            maintenance.acquire(
                operation,
                &self.maintenance_domain,
                state.superblock.binding.store_uuid,
                state.superblock.device_id,
                state.superblock.range_first_logical_block,
                state.superblock.initial_block_count,
            )
        })
    }

    pub fn into_device(self) -> D {
        self.device
    }

    pub fn info(&self) -> Result<StoreInfo, StoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        Ok(state.info())
    }

    pub async fn format(
        &mut self,
        options: FormatOptions,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        if self.mounted.is_some() {
            return Err(StoreError::AlreadyFormatted);
        }
        let device_info = self.device.info();
        let plan = initial_format_plan(device_info, options)?;

        // Formatting never guesses whether anchor bytes are disposable.  Data
        // segments are outside the format-identification boundary and may hold
        // bytes from an unrelated earlier use of an explicitly provisioned
        // range; the new superblock/checkpoint initially reference none of them.
        let mut page = Box::new([0; PAGE_SIZE]);
        for page_no in 0..ANCHOR_PAGES {
            self.device
                .read_page(page_no, page.as_mut())
                .await
                .map_err(StoreError::Device)?;
            if page.iter().any(|byte| *byte != 0) {
                return Err(StoreError::AlreadyFormatted);
            }
        }

        self.limits = options.limits;
        self.poisoned = true;
        for page_no in INITIAL_FORMAT_WRITE_ORDER {
            write_page(&self.device, page_no, &plan.pages[page_no as usize]).await?;
            flush(&self.device).await?;
        }
        self.poisoned = false;
        self.mount().await
    }

    /// Resume only an exact crash prefix of this formatter's deterministic
    /// initial anchor image. Arbitrary non-zero, foreign, or reordered anchor
    /// bytes are corruption and are never erased or reformatted.
    pub async fn format_or_resume_canonical(
        &mut self,
        options: FormatOptions,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        if self.mounted.is_some() {
            return Err(StoreError::AlreadyFormatted);
        }
        let device_info = self.device.info();
        if device_info.logical_block_size != 512 {
            return Err(StoreError::InvalidConfig);
        }
        let plan = initial_format_plan(device_info, options)?;
        let mut observed = Box::new([0; PAGE_SIZE]);
        let mut first_incomplete = None;
        for (index, page_no) in INITIAL_FORMAT_WRITE_ORDER.into_iter().enumerate() {
            self.device
                .read_page(page_no, observed.as_mut())
                .await
                .map_err(StoreError::Device)?;
            let expected = &plan.pages[page_no as usize];
            if first_incomplete.is_none() && observed.as_ref() == expected {
                continue;
            }
            if first_incomplete.is_none() && is_canonical_block_write_prefix(&observed, expected) {
                first_incomplete = Some(index);
                continue;
            }
            if observed.iter().any(|byte| *byte != 0) {
                return Err(StoreError::Corrupt);
            }
        }
        for page_no in 6..ANCHOR_PAGES {
            self.device
                .read_page(page_no, observed.as_mut())
                .await
                .map_err(StoreError::Device)?;
            if observed.iter().any(|byte| *byte != 0) {
                return Err(StoreError::Corrupt);
            }
        }

        self.limits = options.limits;
        let next = first_incomplete.unwrap_or(INITIAL_FORMAT_WRITE_ORDER.len());
        if next == INITIAL_FORMAT_WRITE_ORDER.len() {
            return self.mount().await;
        }
        self.poisoned = true;
        // Continue at the first incomplete page. Rewriting an earlier complete
        // page and then crashing part-way through it would leave later complete
        // pages behind a torn predecessor, which is deliberately rejected as
        // a reordered/foreign image on the following boot.
        for page_no in INITIAL_FORMAT_WRITE_ORDER[next..].iter().copied() {
            write_page(&self.device, page_no, &plan.pages[page_no as usize]).await?;
            flush(&self.device).await?;
        }
        self.poisoned = false;
        self.mount().await
    }

    /// Recognize the only formatted-but-authority-missing state admitted by
    /// native provisioning. A merely mountable foreign or previously used V2
    /// store is not an initializer residue.
    pub fn is_canonical_initial_format(
        &self,
        options: FormatOptions,
    ) -> Result<bool, StoreError<D::Error>> {
        let state = self.require_current_generation()?;
        Ok(state.superblock.binding.store_uuid == options.store_uuid
            && state.superblock.cleaner_reserve_segments == options.cleaner_reserve_segments
            && state.superblock.max_replay_records == options.limits.max_replay_records
            && state.generation == 1
            && state.replay_count == 0
            && state.next_segment_generation == 1
            && state.next_physical_segment == 0
            && state.next_object_id == 1
            && state.allocation_version == 1
            && state.last_segment_target_checkpoint_generation == 1
            && state.catalog_root == PhysicalPointer::Null
            && state.replay_tail == PhysicalPointer::Null
            && state.authority_root == PhysicalPointer::Null
            && state.allocation_root == PhysicalPointer::Null
            && state.persistent_roots.is_none()
            && state.persistent_authority.is_none()
            && state.catalog.is_empty()
            && state.cas.is_none()
            && state.last_segment.is_none()
            && state.last_segment_previous.is_none()
            && state
                .allocation
                .counts()
                .map_err(|_| StoreError::Corrupt)?
                .allocated
                == 0
            && state
                .allocation
                .counts()
                .map_err(|_| StoreError::Corrupt)?
                .retired
                == 0)
    }

    pub async fn mount(&mut self) -> Result<StoreInfo, StoreError<D::Error>> {
        self.mounted = None;
        self.poisoned = false;
        validate_limits(self.limits)?;
        let device_info = self.device.info();
        segments_for_page_count(device_info.page_count)?;

        let left = read_superblock(&self.device, 0).await?;
        let right = read_superblock(&self.device, 2).await?;
        let selected = select_superblock(left, right)?.ok_or(StoreError::Unformatted)?;
        let superblock = *selected.value();
        let logical_block_size = u64::from(device_info.logical_block_size);
        if logical_block_size == 0
            || !(PAGE_SIZE as u64).is_multiple_of(logical_block_size)
            || !device_info
                .logical_block_count
                .is_multiple_of(PAGE_SIZE as u64 / logical_block_size)
        {
            return Err(StoreError::Corrupt);
        }
        let blocks_per_page = PAGE_SIZE as u64 / logical_block_size;
        let expected_device_pages = device_info
            .logical_block_count
            .checked_div(blocks_per_page)
            .ok_or(StoreError::Corrupt)?;
        let expected_initial_blocks = superblock
            .initial_range_pages
            .checked_mul(blocks_per_page)
            .ok_or(StoreError::Corrupt)?;
        if superblock.device_id != device_info.device_id
            || superblock.range_first_logical_block != device_info.range_first_logical_block
            || superblock.initial_block_count != expected_initial_blocks
            || superblock.initial_block_count > device_info.logical_block_count
            || superblock.logical_block_size != device_info.logical_block_size
            || superblock.initial_range_pages > device_info.page_count
            || expected_device_pages != device_info.page_count
            || superblock.max_replay_records != self.limits.max_replay_records
        {
            return Err(StoreError::Corrupt);
        }
        let left = read_checkpoint(&self.device, 4).await?;
        let right = read_checkpoint(&self.device, 6).await?;
        let selected =
            select_checkpoint_for_superblock(selected, left, right, device_info.page_count)?
                .ok_or(StoreError::Unformatted)?;
        let selected_generation = selected.value().binding.generation;
        // A complete publication marker is a promise to decode strictly even
        // on the older slot. Recover it first, retain only the allocation-map
        // witness, then recover the newer state under the remaining memory
        // budget. This validates the pair without holding two full catalogs.
        let mut state = match (left, right) {
            (Some(left), Some(right)) => {
                let (older, newer) =
                    if left.value().binding.generation < right.value().binding.generation {
                        (left, right)
                    } else if right.value().binding.generation < left.value().binding.generation {
                        (right, left)
                    } else {
                        return Err(StoreError::Corrupt);
                    };
                if newer.value().binding.generation != selected_generation {
                    return Err(StoreError::Corrupt);
                }
                let older_state =
                    recover_state(&self.device, superblock, older, self.limits).await?;
                let older_peak = older_state.recovery_peak_bytes;
                let witness = CheckpointTransitionWitness::from_mounted(older_state);
                let witness_bytes = witness.resident_bytes().ok_or(StoreError::MemoryLimit)?;
                let remaining = self
                    .limits
                    .recovery_memory_bytes
                    .checked_sub(witness_bytes)
                    .ok_or(StoreError::MemoryLimit)?;
                let newer_limits = StoreLimits {
                    recovery_memory_bytes: remaining,
                    ..self.limits
                };
                let mut newer_state =
                    recover_state(&self.device, superblock, newer, newer_limits).await?;
                validate_checkpoint_transition(&witness, &newer_state)?;
                let pair_peak = witness_bytes
                    .checked_add(newer_state.recovery_peak_bytes)
                    .ok_or(StoreError::MemoryLimit)?;
                newer_state.recovery_peak_bytes = older_peak.max(pair_peak);
                if newer_state.recovery_peak_bytes > self.limits.recovery_memory_bytes {
                    return Err(StoreError::MemoryLimit);
                }
                newer_state
            }
            (Some(candidate), None) | (None, Some(candidate)) => {
                if candidate.value().binding.generation != selected_generation {
                    return Err(StoreError::Corrupt);
                }
                recover_state(&self.device, superblock, candidate, self.limits).await?
            }
            (None, None) => return Err(StoreError::Unformatted),
        };
        state.recovery_peak_bytes = state
            .recovery_peak_bytes
            .max(state.resident_heap_bytes().ok_or(StoreError::MemoryLimit)?);
        if state.recovery_peak_bytes > self.limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
        let info = state.info();
        if !publish_runtime_generation(&self.published_generation, state.generation) {
            self.poisoned = true;
            return Err(StoreError::RecoveryRequired);
        }
        self.mounted = Some(state);
        self.poisoned = false;
        Ok(info)
    }

    /// Install an ordinary commit successor without decoding the already
    /// mounted predecessor from media a second time. The successor itself is
    /// still recovered exclusively from durable bytes, and the resident
    /// predecessor is reduced to the same allocation witness used by mount().
    pub(crate) async fn mount_verified_successor(
        &mut self,
        previous: MountedState,
        expected: Checkpoint,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        self.mounted = None;
        self.poisoned = true;
        validate_limits(self.limits)?;
        let successor_generation = previous
            .generation
            .checked_add(1)
            .ok_or(StoreError::RecoveryRequired)?;
        if self.published_generation.load(Ordering::Acquire) != previous.generation
            || expected.previous_generation != previous.generation
            || expected.binding.generation != successor_generation
        {
            return Err(StoreError::RecoveryRequired);
        }

        let device_info = self.device.info();
        segments_for_page_count(device_info.page_count)?;
        let selected_super = select_superblock(
            read_superblock(&self.device, 0).await?,
            read_superblock(&self.device, 2).await?,
        )?
        .ok_or(StoreError::Unformatted)?;
        if selected_super.value() != &previous.superblock {
            return Err(StoreError::Corrupt);
        }

        let left = read_checkpoint(&self.device, 4).await?;
        let right = read_checkpoint(&self.device, 6).await?;
        let selected =
            select_checkpoint_for_superblock(selected_super, left, right, device_info.page_count)?
                .ok_or(StoreError::Unformatted)?;
        if selected.value() != &expected {
            return Err(StoreError::Corrupt);
        }
        let predecessor =
            if expected.slot == 0 { right } else { left }.ok_or(StoreError::Corrupt)?;
        if !checkpoint_matches_mounted(predecessor.value(), &previous, self.limits) {
            return Err(StoreError::Corrupt);
        }

        let previous_peak = previous.recovery_peak_bytes;
        let witness = CheckpointTransitionWitness::from_mounted(previous);
        let witness_bytes = witness.resident_bytes().ok_or(StoreError::MemoryLimit)?;
        let remaining = self
            .limits
            .recovery_memory_bytes
            .checked_sub(witness_bytes)
            .ok_or(StoreError::MemoryLimit)?;
        let successor_limits = StoreLimits {
            recovery_memory_bytes: remaining,
            ..self.limits
        };
        let mut successor = recover_state(
            &self.device,
            *selected_super.value(),
            selected,
            successor_limits,
        )
        .await?;
        validate_checkpoint_transition(&witness, &successor)?;
        let pair_peak = witness_bytes
            .checked_add(successor.recovery_peak_bytes)
            .ok_or(StoreError::MemoryLimit)?;
        successor.recovery_peak_bytes = previous_peak.max(pair_peak).max(
            successor
                .resident_heap_bytes()
                .ok_or(StoreError::MemoryLimit)?,
        );
        if successor.recovery_peak_bytes > self.limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
        let info = successor.info();
        if !publish_runtime_generation(&self.published_generation, successor.generation) {
            return Err(StoreError::RecoveryRequired);
        }
        self.mounted = Some(successor);
        self.poisoned = false;
        Ok(info)
    }

    pub async fn put(
        &mut self,
        object_kind: u32,
        content_root: [u8; 32],
        bytes: &[u8],
    ) -> Result<ObjectHandle, StoreError<D::Error>> {
        if self.quota.is_some() {
            return Err(StoreError::PrincipalRequired);
        }
        let current = self.require_current_generation()?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| StoreError::ObjectTooLarge)?;
        if byte_len > self.limits.max_compat_object_bytes
            || byte_len > (MAX_EXTENT_PAYLOAD_PAGES as u64) * (PAGE_SIZE as u64)
        {
            return Err(StoreError::Capacity(CapacityClass::Payload));
        }
        if object_kind == 0 || payload_sha256(bytes) != content_root {
            return Err(StoreError::ObjectMismatch);
        }
        if current.cas.is_some() {
            return Err(StoreError::CatalogMode);
        }
        if !current.allocation.retired_segments().is_empty() {
            return Err(StoreError::GcResumeRequired);
        }
        if current.catalog.len() >= self.limits.max_catalog_entries as usize {
            return Err(StoreError::Capacity(CapacityClass::Metadata));
        }
        let prospective_count = current
            .catalog
            .len()
            .checked_add(1)
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        let next_is_snapshot = current.catalog_root == PhysicalPointer::Null
            || current.replay_count + 1 >= self.limits.max_replay_records;
        let snapshot_bytes = CATALOG_SNAPSHOT_HEADER_LEN
            .checked_add(
                prospective_count
                    .checked_mul(CATALOG_ENTRY_LEN)
                    .ok_or(StoreError::Capacity(CapacityClass::Metadata))?,
            )
            .ok_or(StoreError::Capacity(CapacityClass::Metadata))?;
        if (next_is_snapshot && snapshot_bytes > MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE)
            || recovery_memory_upper_bound(prospective_count, snapshot_bytes)
                > self.limits.recovery_memory_bytes
        {
            return Err(StoreError::Capacity(CapacityClass::Metadata));
        }
        if current.next_physical_segment
            >= current.admitted_segments.saturating_sub(
                u64::from(current.cleaner_reserve_segments)
                    .saturating_add(u64::from(ROOT_POLICY_HEADROOM_SEGMENTS)),
            )
        {
            return Err(StoreError::Capacity(CapacityClass::CleanerReserve));
        }

        // Taking the state before the first await makes cancellation invalidate
        // every cached cursor.  Only a complete reread below installs a state.
        let state = self.mounted.take().ok_or(StoreError::NotMounted)?;
        self.poisoned = true;
        let result = append_object(
            &self.device,
            &state,
            self.limits,
            object_kind,
            content_root,
            bytes,
        )
        .await;
        match result {
            Ok((handle, recovered)) => {
                if !publish_runtime_generation(&self.published_generation, recovered.generation) {
                    return Err(StoreError::RecoveryRequired);
                }
                self.mounted = Some(recovered);
                self.poisoned = false;
                Ok(handle)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn require_current_generation(&self) -> Result<&MountedState, StoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        if self.published_generation.load(Ordering::Acquire) != state.generation {
            return Err(StoreError::RecoveryRequired);
        }
        Ok(state)
    }

    pub async fn get(&self, handle: &ObjectHandle) -> Result<Vec<u8>, StoreError<D::Error>> {
        let state = self.mounted.as_ref().ok_or(if self.poisoned {
            StoreError::RecoveryRequired
        } else {
            StoreError::NotMounted
        })?;
        let entry = state
            .catalog
            .iter()
            .find(|entry| entry.object_id == handle.object_id)
            .copied()
            .ok_or(StoreError::ObjectUnavailable)?;
        if handle.store_uuid != state.superblock.binding.store_uuid
            || handle.object_kind != entry.object_kind
            || handle.exact_len != entry.exact_len
            || handle.commit_generation != entry.commit_generation
            || handle.content_root != entry.content_root
        {
            return Err(StoreError::ObjectMismatch);
        }
        if entry.exact_len == 0 {
            if entry.blob != PhysicalPointer::Null {
                return Err(StoreError::Corrupt);
            }
            return Ok(Vec::new());
        }
        let resolved = read_pointer_payload(
            &self.device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            state.next_segment_generation,
            state.generation,
            entry.blob,
            ExtentKind::Blob,
            self.limits.max_compat_object_bytes as usize,
        )
        .await?;
        if resolved.bytes.len() as u64 != entry.exact_len
            || resolved.extent.object_kind != entry.object_kind
            || resolved.extent.binding.target_checkpoint_generation != entry.commit_generation
            || resolved.extent.content_byte_len != entry.exact_len
            || resolved.extent.encoded_blob_len != entry.exact_len
            || resolved.extent.encoded_offset != 0
            || resolved.extent.merkle_root != entry.content_root
            || payload_sha256(&resolved.bytes) != entry.content_root
        {
            return Err(StoreError::Corrupt);
        }
        Ok(resolved.bytes)
    }
}

fn checkpoint_matches_mounted(
    checkpoint: &Checkpoint,
    state: &MountedState,
    limits: StoreLimits,
) -> bool {
    checkpoint.binding.store_uuid == state.superblock.binding.store_uuid
        && checkpoint.binding.generation == state.generation
        && checkpoint.binding.segment_no == ANCHOR_SEGMENT_NO
        && checkpoint.binding.ordinal == u32::from(checkpoint.slot)
        && checkpoint.binding.self_page == 4 + u64::from(checkpoint.slot) * 2
        && checkpoint.binding.target_checkpoint_generation == state.generation
        && checkpoint.slot == ((state.generation - 1) & 1) as u8
        && admitted_pages(state.admitted_segments)
            .is_ok_and(|pages| checkpoint.admitted_range_pages == pages)
        && checkpoint.admitted_segments == state.admitted_segments
        && checkpoint.next_segment_generation == state.next_segment_generation
        && checkpoint.replay_count == state.replay_count
        && checkpoint.max_replay_records == limits.max_replay_records
        && checkpoint.cleaner_reserve_segments == state.cleaner_reserve_segments
        && checkpoint.catalog_root == state.catalog_root
        && checkpoint.authority_root == state.authority_root
        && checkpoint.allocation_root == state.allocation_root
        && checkpoint.replay_tail == state.replay_tail
}

impl MountedState {
    pub(crate) fn resident_heap_bytes(&self) -> Option<usize> {
        let mut bytes = self.allocation.allocated_bytes()?.checked_add(
            self.catalog
                .capacity()
                .checked_mul(mem::size_of::<CatalogEntry>())?,
        )?;
        if let Some(cas) = &self.cas {
            bytes = bytes
                .checked_add(
                    cas.objects
                        .capacity()
                        .checked_mul(mem::size_of::<ObjectMapping>())?,
                )?
                .checked_add(
                    cas.blobs
                        .capacity()
                        .checked_mul(mem::size_of::<BlobMapping>())?,
                )?;
        }
        if let Some(roots) = &self.persistent_roots {
            bytes = bytes.checked_add(roots.allocated_bytes()?)?;
        }
        if let Some(authority) = &self.persistent_authority {
            bytes = bytes.checked_add(authority.allocated_bytes()?)?;
        }
        Some(bytes)
    }

    pub(crate) fn find_free_run(&self, required: u64, may_use_reserve: bool) -> Option<u64> {
        if required == 0 {
            return None;
        }
        let free = self.allocation.counts().ok()?.free;
        let ordinary_floor = u64::from(self.cleaner_reserve_segments)
            .checked_add(u64::from(ROOT_POLICY_HEADROOM_SEGMENTS))?;
        if free < required || (!may_use_reserve && free.checked_sub(required)? < ordinary_floor) {
            return None;
        }
        if self.allocation_version == 1 {
            let end = self.next_physical_segment.checked_add(required)?;
            if end > self.admitted_segments {
                return None;
            }
            return (self.next_physical_segment..end)
                .all(|segment_no| {
                    self.allocation.segment_state(segment_no) == Some(SegmentAllocation::Free)
                })
                .then_some(self.next_physical_segment);
        }
        let mut run_start = 0_u64;
        let mut run_len = 0_u64;
        for segment_no in 0..self.admitted_segments {
            if self.allocation.segment_state(segment_no) == Some(SegmentAllocation::Free) {
                if run_len == 0 {
                    run_start = segment_no;
                }
                run_len += 1;
                if run_len == required {
                    return Some(run_start);
                }
            } else {
                run_len = 0;
            }
        }
        None
    }

    fn info(&self) -> StoreInfo {
        let (allocated_segments, free_segments) = if self.allocation_version == 1 {
            // The legacy prefix allocator quarantines every non-zero final
            // seal through the recovered frontier, including sealed orphans
            // which were never named by a checkpoint.  Report that physical
            // consumption rather than only the committed allocation payload.
            (
                self.next_physical_segment,
                self.admitted_segments
                    .saturating_sub(self.next_physical_segment),
            )
        } else {
            let counts = self
                .allocation
                .counts()
                .expect("mounted allocation map was strictly decoded");
            (counts.allocated.saturating_add(counts.retired), counts.free)
        };
        StoreInfo {
            generation: self.generation,
            admitted_segments: self.admitted_segments,
            allocated_segments,
            free_segments,
            cleaner_reserved_segments: self.cleaner_reserve_segments,
            object_count: self
                .cas
                .as_ref()
                .map_or(self.catalog.len(), |cas| cas.objects.len())
                as u32,
            replay_count: self.replay_count,
            recovery_peak_bytes: self.recovery_peak_bytes,
        }
    }
}

fn allocation_resident_bytes(allocation: &AllocationV2) -> Result<usize, ()> {
    allocation.allocated_bytes().ok_or(())
}

fn cas_resident_bytes(cas: Option<&CasMountedState>) -> Result<usize, ()> {
    cas.map_or(Ok(0), |cas| {
        cas.objects
            .capacity()
            .checked_mul(mem::size_of::<ObjectMapping>())
            .and_then(|bytes| {
                cas.blobs
                    .capacity()
                    .checked_mul(mem::size_of::<BlobMapping>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(())
    })
}

fn root_resident_bytes(roots: Option<&PersistentRootSet>) -> Result<usize, ()> {
    roots.map_or(Ok(0), |roots| roots.allocated_bytes().ok_or(()))
}

fn authority_resident_bytes(authority: Option<&PersistentAuthoritySnapshot>) -> Result<usize, ()> {
    authority.map_or(Ok(0), |value| value.allocated_bytes().ok_or(()))
}

fn recovery_resident_bytes(
    allocation: &AllocationV2,
    catalog: &Vec<CatalogEntry>,
    cas: Option<&CasMountedState>,
    roots: Option<&PersistentRootSet>,
    authority: Option<&PersistentAuthoritySnapshot>,
) -> Result<usize, ()> {
    allocation_resident_bytes(allocation)?
        .checked_add(measured_catalog_bytes(catalog))
        .and_then(|bytes| cas_resident_bytes(cas).ok()?.checked_add(bytes))
        .and_then(|bytes| root_resident_bytes(roots).ok()?.checked_add(bytes))
        .and_then(|bytes| authority_resident_bytes(authority).ok()?.checked_add(bytes))
        .ok_or(())
}

fn validate_limits<E>(limits: StoreLimits) -> Result<(), StoreError<E>> {
    let maximum_catalog_entries = (MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE
        - CATALOG_SNAPSHOT_HEADER_LEN)
        / CATALOG_ENTRY_LEN;
    if limits.max_catalog_entries == 0
        || limits.max_catalog_entries as usize > maximum_catalog_entries
        || limits.max_replay_records == 0
        || limits.recovery_memory_bytes < mem::size_of::<CatalogEntry>()
        || limits.max_compat_object_bytes > (MAX_EXTENT_PAYLOAD_PAGES as u64) * PAGE_SIZE as u64
    {
        Err(StoreError::InvalidConfig)
    } else {
        Ok(())
    }
}

fn recovery_memory_upper_bound(entry_count: usize, largest_snapshot_bytes: usize) -> usize {
    entry_count
        .checked_mul(mem::size_of::<CatalogEntry>())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(largest_snapshot_bytes))
        .unwrap_or(usize::MAX)
}

fn segments_for_page_count<E>(page_count: u64) -> Result<u64, StoreError<E>> {
    let data_pages = page_count
        .checked_sub(ANCHOR_PAGES)
        .ok_or(StoreError::InvalidConfig)?;
    if data_pages == 0 || data_pages % SEGMENT_PAGES != 0 {
        return Err(StoreError::InvalidConfig);
    }
    Ok(data_pages / SEGMENT_PAGES)
}

fn allocation_v2_bitmap_bytes<E>(segments: u64) -> Result<usize, StoreError<E>> {
    usize::try_from(segments.div_ceil(4)).map_err(|_| StoreError::InvalidConfig)
}

async fn write_page<D: PageDevice>(
    device: &D,
    page: u64,
    input: &Page,
) -> Result<(), StoreError<D::Error>> {
    device
        .write_page(page, input)
        .await
        .map_err(StoreError::Mutation)
}

async fn flush<D: PageDevice>(device: &D) -> Result<(), StoreError<D::Error>> {
    device.flush().await.map_err(StoreError::Mutation)
}

async fn read_pair<D: PageDevice>(
    device: &D,
    body_page: u64,
) -> Result<(Box<Page>, Box<Page>), StoreError<D::Error>> {
    let mut body = Box::new([0; PAGE_SIZE]);
    let mut seal = Box::new([0; PAGE_SIZE]);
    device
        .read_page(body_page, body.as_mut())
        .await
        .map_err(StoreError::Device)?;
    device
        .read_page(body_page + 1, seal.as_mut())
        .await
        .map_err(StoreError::Device)?;
    Ok((body, seal))
}

fn optional_verified<T>(status: DecodeStatus<VerifiedRecord<T>>) -> Option<VerifiedRecord<T>> {
    match status {
        DecodeStatus::Sealed(value) => Some(value),
        DecodeStatus::Empty | DecodeStatus::Unsealed => None,
    }
}

pub(crate) async fn read_superblock<D: PageDevice>(
    device: &D,
    page: u64,
) -> Result<Option<VerifiedRecord<Superblock>>, StoreError<D::Error>> {
    let (body, seal) = read_pair(device, page).await?;
    Ok(optional_verified(decode_superblock_verified(&body, &seal)?))
}

pub(crate) async fn read_checkpoint<D: PageDevice>(
    device: &D,
    page: u64,
) -> Result<Option<VerifiedRecord<Checkpoint>>, StoreError<D::Error>> {
    let (body, seal) = read_pair(device, page).await?;
    Ok(optional_verified(decode_checkpoint_verified(&body, &seal)?))
}

pub(crate) async fn write_checkpoint<D: PageDevice>(
    device: &D,
    checkpoint: &Checkpoint,
    clear_first: bool,
) -> Result<VerifiedRecord<Checkpoint>, StoreError<D::Error>> {
    let body_page = 4 + u64::from(checkpoint.slot) * 2;
    if clear_first {
        let zero = Box::new([0; PAGE_SIZE]);
        // Remove the old publication marker before touching its body.  Clearing
        // the body first could leave a durable old seal authenticating zero or
        // torn bytes, which is correctly fatal to the strict decoder.
        write_page(device, body_page + 1, &zero).await?;
        flush(device).await?;
        let mut observed_seal = Box::new([0; PAGE_SIZE]);
        device
            .read_page(body_page + 1, observed_seal.as_mut())
            .await
            .map_err(StoreError::Device)?;
        if observed_seal.iter().any(|byte| *byte != 0) {
            return Err(StoreError::Corrupt);
        }
    }
    let mut body = Box::new([0; PAGE_SIZE]);
    let mut seal = Box::new([0; PAGE_SIZE]);
    let digest = encode_checkpoint_body(checkpoint, body.as_mut())?;
    encode_record_seal(digest, seal.as_mut())?;
    write_page(device, body_page, &body).await?;
    flush(device).await?;
    write_page(device, body_page + 1, &seal).await?;
    flush(device).await?;
    let (observed_body, observed_seal) = read_pair(device, body_page).await?;
    match decode_checkpoint_verified(&observed_body, &observed_seal)? {
        DecodeStatus::Sealed(value) if value.value() == checkpoint => Ok(value),
        _ => Err(StoreError::Corrupt),
    }
}

fn codec_error<E>(error: CodecError) -> StoreError<E> {
    match error {
        CodecError::ArithmeticOverflow => StoreError::Format(FormatError::ArithmeticOverflow),
        CodecError::Format(_) => StoreError::Corrupt,
        _ => StoreError::Corrupt,
    }
}

pub(crate) struct ScannedSegment {
    pub(crate) matched: Option<ExtentRecord>,
    pub(crate) record_count: u32,
    pub(crate) total_payload_bytes: u64,
    pub(crate) segment_seal_body_sha256: [u8; 32],
    pub(crate) previous_segment: (u64, u64, [u8; 32]),
    pub(crate) header_target_checkpoint_generation: u64,
}

pub(crate) async fn scan_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PointerValue,
) -> Result<ScannedSegment, StoreError<D::Error>> {
    if pointer.store_uuid != store_uuid
        || pointer.segment_no >= admitted_segments
        || pointer.segment_generation == 0
        || pointer.segment_generation >= next_segment_generation
    {
        return Err(StoreError::Corrupt);
    }
    let base = segment_base_page(pointer.segment_no)?;
    let (header_body, header_seal) = read_pair(device, base).await?;
    let header = match decode_segment_header_verified(&header_body, &header_seal)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    if header.value().binding.store_uuid != store_uuid
        || header.value().binding.segment_no != pointer.segment_no
        || header.value().binding.generation != pointer.segment_generation
        || header.value().binding.target_checkpoint_generation > checkpoint_generation
    {
        return Err(StoreError::Corrupt);
    }

    let (summary_body, summary_seal_page) =
        read_pair(device, base + u64::from(SUMMARY_BODY_PAGE)).await?;
    let summary = match decode_segment_summary_verified(&summary_body, &summary_seal_page)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    let (segment_seal_body, final_seal_page) =
        read_pair(device, base + u64::from(SEGMENT_SEAL_BODY_PAGE)).await?;
    let segment_seal = match decode_segment_seal_verified(&segment_seal_body, &final_seal_page)? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };

    let mut relative = DATA_FIRST_PAGE;
    let mut descriptor_chain =
        descriptor_chain_initial(store_uuid, pointer.segment_no, pointer.segment_generation);
    let mut payload_chain =
        payload_chain_initial(store_uuid, pointer.segment_no, pointer.segment_generation);
    let mut payload_pages = 0_u32;
    let mut total_bytes = 0_u64;
    let mut kind_counts = [0_u32; 5];
    let mut kind_bytes = [0_u64; 5];
    let mut first_target = 0_u64;
    let mut last_target = 0_u64;
    let mut matched = None;
    for ordinal in 1..=summary.value().record_count {
        let (body, seal) = read_pair(device, base + u64::from(relative)).await?;
        let extent = match decode_extent_verified(&body, &seal)? {
            DecodeStatus::Sealed(value) => value,
            _ => return Err(StoreError::Corrupt),
        };
        let value = *extent.value();
        if value.binding.store_uuid != store_uuid
            || value.binding.segment_no != pointer.segment_no
            || value.binding.generation != pointer.segment_generation
            || value.binding.ordinal != ordinal
            || value.binding.self_page != base + u64::from(relative)
            || value.binding.target_checkpoint_generation > checkpoint_generation
            || value.payload_first_relative_page != relative + 2
            || (last_target != 0 && value.binding.target_checkpoint_generation < last_target)
        {
            return Err(StoreError::Corrupt);
        }
        if first_target == 0 {
            first_target = value.binding.target_checkpoint_generation;
        }
        last_target = value.binding.target_checkpoint_generation;
        descriptor_chain = descriptor_chain_next(
            store_uuid,
            pointer.segment_no,
            pointer.segment_generation,
            descriptor_chain,
            ordinal,
            extent.digest().body_sha256(),
            value.payload_sha256,
        );
        payload_chain = payload_chain_next(
            store_uuid,
            pointer.segment_no,
            pointer.segment_generation,
            payload_chain,
            ordinal,
            value.payload_byte_len,
            value.payload_sha256,
        );
        payload_pages = payload_pages
            .checked_add(value.payload_pages)
            .ok_or(StoreError::Corrupt)?;
        total_bytes = total_bytes
            .checked_add(value.payload_byte_len)
            .ok_or(StoreError::Corrupt)?;
        let kind = extent_kind_index(value.extent_kind);
        kind_counts[kind] = kind_counts[kind]
            .checked_add(1)
            .ok_or(StoreError::Corrupt)?;
        kind_bytes[kind] = kind_bytes[kind]
            .checked_add(value.payload_byte_len)
            .ok_or(StoreError::Corrupt)?;
        if relative == pointer.descriptor_relative_page && ordinal == pointer.ordinal {
            matched = Some(value);
        }
        relative = relative
            .checked_add(value.record_span_pages)
            .ok_or(StoreError::Corrupt)?;
    }
    let summary_value = summary.value();
    let seal_value = segment_seal.value();
    if relative != summary_value.next_free_page
        || payload_pages != summary_value.payload_page_count
        || total_bytes != summary_value.total_payload_bytes
        || first_target != summary_value.first_target_checkpoint_generation
        || last_target != summary_value.last_target_checkpoint_generation
        || header.digest().body_sha256() != summary_value.header_body_sha256
        || descriptor_chain != summary_value.descriptor_chain_sha256
        || payload_chain != summary_value.payload_chain_sha256
        || kind_counts != summary_value.kind_counts
        || kind_bytes != summary_value.kind_bytes
        || segment_seal.value().binding.store_uuid != store_uuid
        || seal_value.binding.segment_no != pointer.segment_no
        || seal_value.binding.generation != pointer.segment_generation
        || seal_value.header_body_sha256 != header.digest().body_sha256()
        || seal_value.summary_body_sha256 != summary.digest().body_sha256()
        || seal_value.final_descriptor_chain_sha256 != descriptor_chain
        || seal_value.final_payload_chain_sha256 != payload_chain
        || seal_value.record_count != summary_value.record_count
        || seal_value.next_free_page != summary_value.next_free_page
        || seal_value.payload_page_count != summary_value.payload_page_count
        || seal_value.total_payload_bytes != summary_value.total_payload_bytes
        || seal_value.target_checkpoint_generation
            != summary_value.last_target_checkpoint_generation
    {
        return Err(StoreError::Corrupt);
    }
    Ok(ScannedSegment {
        matched,
        record_count: summary_value.record_count,
        total_payload_bytes: summary_value.total_payload_bytes,
        segment_seal_body_sha256: segment_seal.digest().body_sha256(),
        previous_segment: (
            header.value().previous_segment_no,
            header.value().previous_segment_generation,
            header.value().previous_segment_seal_body_sha256,
        ),
        header_target_checkpoint_generation: header.value().binding.target_checkpoint_generation,
    })
}

pub(crate) struct ResolvedPayload {
    pub(crate) bytes: Vec<u8>,
    pub(crate) extent: ExtentRecord,
    pub(crate) segment_seal_body_sha256: [u8; 32],
    pub(crate) previous_segment: (u64, u64, [u8; 32]),
    pub(crate) header_target_checkpoint_generation: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_pointer_payload<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    expected_kind: ExtentKind,
    maximum_bytes: usize,
) -> Result<ResolvedPayload, StoreError<D::Error>> {
    let PhysicalPointer::Value(pointer) = pointer else {
        return Err(StoreError::Corrupt);
    };
    if pointer.extent_kind != expected_kind
        || pointer.exact_byte_len > maximum_bytes as u64
        || pointer.exact_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
    {
        return Err(StoreError::Corrupt);
    }
    let scanned = scan_segment(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
    )
    .await?;
    let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
    if extent.extent_kind != pointer.extent_kind
        || extent.payload_first_relative_page != pointer.payload_relative_page
        || extent.payload_pages != pointer.payload_pages
        || extent.payload_byte_len != pointer.exact_byte_len
        || extent.payload_sha256 != pointer.payload_sha256
        || (expected_kind != ExtentKind::Blob
            && (extent.extent_index != 0
                || extent.extent_count != 1
                || extent.content_byte_len != pointer.exact_byte_len
                || extent.encoded_blob_len != pointer.exact_byte_len
                || extent.encoded_offset != 0
                || extent.merkle_root != pointer.payload_sha256))
    {
        return Err(StoreError::Corrupt);
    }
    let exact_len = usize::try_from(pointer.exact_byte_len).map_err(|_| StoreError::Corrupt)?;
    let mut bytes = vec![0; exact_len];
    let base = segment_base_page(pointer.segment_no)?;
    let mut copied = 0;
    for index in 0..pointer.payload_pages {
        let mut page = Box::new([0; PAGE_SIZE]);
        device
            .read_page(
                base + u64::from(pointer.payload_relative_page) + u64::from(index),
                page.as_mut(),
            )
            .await
            .map_err(StoreError::Device)?;
        let remaining = exact_len - copied;
        let take = remaining.min(PAGE_SIZE);
        bytes[copied..copied + take].copy_from_slice(&page[..take]);
        copied += take;
    }
    if copied != exact_len || payload_sha256(&bytes) != pointer.payload_sha256 {
        return Err(StoreError::Corrupt);
    }
    Ok(ResolvedPayload {
        bytes,
        extent,
        segment_seal_body_sha256: scanned.segment_seal_body_sha256,
        previous_segment: scanned.previous_segment,
        header_target_checkpoint_generation: scanned.header_target_checkpoint_generation,
    })
}

fn recovery_remaining<E>(limit: usize, resident: usize) -> Result<usize, StoreError<E>> {
    limit.checked_sub(resident).ok_or(StoreError::MemoryLimit)
}

fn recovery_preflight_decode<E>(
    limit: usize,
    resident: usize,
    encoded_capacity: usize,
    decoded_capacity_upper_bound: usize,
) -> Result<(), StoreError<E>> {
    resident
        .checked_add(encoded_capacity)
        .and_then(|bytes| bytes.checked_add(decoded_capacity_upper_bound))
        .filter(|bytes| *bytes <= limit)
        .map(|_| ())
        .ok_or(StoreError::MemoryLimit)
}

fn recovery_observe<E>(peak: &mut usize, limit: usize, bytes: usize) -> Result<(), StoreError<E>> {
    if bytes > limit {
        return Err(StoreError::MemoryLimit);
    }
    *peak = (*peak).max(bytes);
    Ok(())
}

fn input_u32(input: &[u8], offset: usize) -> Option<u32> {
    let bytes = input.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn allocation_decode_capacity_upper_bound<E>(
    input: &[u8],
    version: u16,
    admitted_segments: u64,
) -> Result<usize, StoreError<E>> {
    let bitmap_bytes =
        allocation_v2_bitmap_bytes::<E>(admitted_segments).map_err(|_| StoreError::Corrupt)?;
    match version {
        1 => Ok(bitmap_bytes),
        2 => {
            let retirement_bytes = input
                .len()
                .checked_sub(ALLOCATION_V2_HEADER_LEN)
                .and_then(|bytes| bytes.checked_sub(bitmap_bytes))
                .filter(|bytes| bytes % RETIRED_SEGMENT_ENTRY_LEN == 0)
                .ok_or(StoreError::Corrupt)?;
            let retired_count = retirement_bytes / RETIRED_SEGMENT_ENTRY_LEN;
            bitmap_bytes
                .checked_add(
                    retired_count
                        .checked_mul(mem::size_of::<crate::allocation_v2::RetiredSegment>())
                        .ok_or(StoreError::MemoryLimit)?,
                )
                .ok_or(StoreError::MemoryLimit)
        }
        _ => Err(StoreError::Corrupt),
    }
}

fn cas_snapshot_decode_capacity_upper_bound<E>(input: &[u8]) -> Result<usize, StoreError<E>> {
    let object_count = input_u32(input, 0x18).ok_or(StoreError::Corrupt)? as usize;
    let blob_count = input_u32(input, 0x1c).ok_or(StoreError::Corrupt)? as usize;
    let expected_len = object_count
        .checked_mul(OBJECT_MAPPING_LEN)
        .and_then(|bytes| bytes.checked_add(CAS_SNAPSHOT_HEADER_LEN))
        .and_then(|bytes| blob_count.checked_mul(BLOB_MAPPING_LEN)?.checked_add(bytes))
        .ok_or(StoreError::Corrupt)?;
    if expected_len != input.len() {
        return Err(StoreError::Corrupt);
    }
    object_count
        .checked_mul(mem::size_of::<ObjectMapping>())
        .and_then(|bytes| {
            blob_count
                .checked_mul(mem::size_of::<BlobMapping>())?
                .checked_add(bytes)
        })
        .ok_or(StoreError::MemoryLimit)
}

fn catalog_decode_capacity_upper_bound<E>(input: &[u8]) -> Result<usize, StoreError<E>> {
    let entry_count = input_u32(input, 0x18).ok_or(StoreError::Corrupt)? as usize;
    entry_count
        .checked_mul(mem::size_of::<CatalogEntry>())
        .ok_or(StoreError::MemoryLimit)
}

fn blob_manifest_decode_capacity_upper_bound<E>(input: &[u8]) -> Result<usize, StoreError<E>> {
    let extent_count = input_u32(input, 0x58).ok_or(StoreError::Corrupt)? as usize;
    let expected_len = extent_count
        .checked_mul(MANIFEST_EXTENT_LEN)
        .and_then(|bytes| bytes.checked_add(BLOB_MANIFEST_HEADER_LEN))
        .ok_or(StoreError::Corrupt)?;
    if expected_len != input.len() {
        return Err(StoreError::Corrupt);
    }
    extent_count
        .checked_mul(mem::size_of::<ManifestExtent>())
        .ok_or(StoreError::MemoryLimit)
}

fn persistent_roots_decode_capacity_upper_bound<E>(input: &[u8]) -> Result<usize, StoreError<E>> {
    let entry_count = input_u32(input, 0x18).ok_or(StoreError::Corrupt)? as usize;
    let expected_len = entry_count
        .checked_mul(PERSISTENT_ROOT_ENTRY_LEN)
        .and_then(|bytes| bytes.checked_add(PERSISTENT_ROOT_SET_HEADER_LEN))
        .ok_or(StoreError::Corrupt)?;
    if expected_len != input.len() {
        return Err(StoreError::Corrupt);
    }
    entry_count
        .checked_mul(mem::size_of::<PersistentRootEntry>())
        .ok_or(StoreError::MemoryLimit)
}

fn persistent_authority_decode_capacity_upper_bound<E>(
    input: &[u8],
) -> Result<usize, StoreError<E>> {
    if input.len() < PERSISTENT_AUTHORITY_HEADER_LEN {
        return Err(StoreError::Corrupt);
    }
    let object_count = input_u32(input, 0x38).ok_or(StoreError::Corrupt)? as usize;
    let principal_count = input_u32(input, 0x3c).ok_or(StoreError::Corrupt)? as usize;
    let record_count = input_u32(input, 0x40).ok_or(StoreError::Corrupt)? as usize;
    object_count
        .checked_mul(core::mem::size_of::<
            crate::authority_snapshot::PersistentObjectBinding,
        >())
        .and_then(|bytes| {
            principal_count
                .checked_mul(core::mem::size_of::<crate::PersistentPrincipalPolicy>())?
                .checked_add(bytes)
        })
        .and_then(|bytes| {
            record_count
                .checked_mul(vibeos_durable_format::RECORD_SIZE)?
                .checked_add(bytes)
        })
        .ok_or(StoreError::MemoryLimit)
}

#[allow(clippy::too_many_arguments)]
async fn read_recovery_pointer_payload<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    expected_kind: ExtentKind,
    memory_limit: usize,
    resident_bytes: usize,
) -> Result<ResolvedPayload, StoreError<D::Error>> {
    let remaining = recovery_remaining(memory_limit, resident_bytes)?;
    if let PhysicalPointer::Value(pointer) = pointer {
        let exact_len = usize::try_from(pointer.exact_byte_len).map_err(|_| StoreError::Corrupt)?;
        if exact_len > MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE {
            return Err(StoreError::Corrupt);
        }
        if exact_len > remaining {
            return Err(StoreError::MemoryLimit);
        }
    }
    read_pointer_payload(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        expected_kind,
        remaining,
    )
    .await
}

pub(crate) async fn recover_state<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    checkpoint: VerifiedRecord<Checkpoint>,
    limits: StoreLimits,
) -> Result<MountedState, StoreError<D::Error>> {
    let checkpoint = *checkpoint.value();
    let mut catalog = Vec::new();
    let mut cas = None;
    let mut recovery_peak = 0_usize;
    let (
        allocation,
        allocation_version,
        last_segment,
        last_segment_previous,
        last_segment_target_checkpoint_generation,
    ) = if checkpoint.allocation_root == PhysicalPointer::Null {
        if checkpoint.binding.generation != 1 {
            return Err(StoreError::Corrupt);
        }
        let bitmap_bytes = allocation_v2_bitmap_bytes::<D::Error>(checkpoint.admitted_segments)
            .map_err(|_| StoreError::Corrupt)?;
        if checkpoint.admitted_segments > MAX_ALLOCATION_V2_SEGMENTS as u64 {
            return Err(StoreError::Corrupt);
        }
        if bitmap_bytes > limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
        let legacy = AllocationState {
            checkpoint_generation: checkpoint.binding.generation,
            admitted_segments: checkpoint.admitted_segments,
            allocated_prefix_segments: 0,
            next_segment_generation: checkpoint.next_segment_generation,
            cleaner_reserve_segments: checkpoint.cleaner_reserve_segments,
        };
        let decoded = AllocationV2::from_v1_prefix(legacy).map_err(|_| StoreError::Corrupt)?;
        recovery_observe(
            &mut recovery_peak,
            limits.recovery_memory_bytes,
            allocation_resident_bytes(&decoded).map_err(|_| StoreError::MemoryLimit)?,
        )?;
        (decoded, 1, None, None, checkpoint.binding.generation)
    } else {
        let payload = read_recovery_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.allocation_root,
            ExtentKind::Allocation,
            limits.recovery_memory_bytes,
            0,
        )
        .await?;
        let allocation_encoded_bytes = payload.bytes.capacity();
        let version = payload
            .bytes
            .get(0x08..0x0a)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .ok_or(StoreError::Corrupt)?;
        let allocation_decoded_upper = allocation_decode_capacity_upper_bound(
            &payload.bytes,
            version,
            checkpoint.admitted_segments,
        )?;
        recovery_preflight_decode(
            limits.recovery_memory_bytes,
            0,
            allocation_encoded_bytes,
            allocation_decoded_upper,
        )?;
        let decoded = match version {
            1 => {
                let legacy = decode_allocation(&payload.bytes).map_err(codec_error)?;
                if legacy.checkpoint_generation != checkpoint.binding.generation
                    || legacy.checkpoint_generation
                        != payload.extent.binding.target_checkpoint_generation
                    || legacy.admitted_segments != checkpoint.admitted_segments
                    || legacy.allocated_prefix_segments == 0
                    || legacy.next_segment_generation != checkpoint.next_segment_generation
                    || legacy.cleaner_reserve_segments != checkpoint.cleaner_reserve_segments
                {
                    return Err(StoreError::Corrupt);
                }
                let PhysicalPointer::Value(root) = checkpoint.allocation_root else {
                    return Err(StoreError::Corrupt);
                };
                if root.segment_no.checked_add(1) != Some(legacy.allocated_prefix_segments) {
                    return Err(StoreError::Corrupt);
                }
                AllocationV2::from_v1_prefix(legacy).map_err(|_| StoreError::Corrupt)?
            }
            2 => {
                let current =
                    decode_allocation_v2(&payload.bytes).map_err(|_| StoreError::Corrupt)?;
                if current.checkpoint_generation != checkpoint.binding.generation
                    || current.checkpoint_generation
                        != payload.extent.binding.target_checkpoint_generation
                    || current.admitted_segments != checkpoint.admitted_segments
                    || current.next_segment_generation != checkpoint.next_segment_generation
                    || current.cleaner_reserve_segments != checkpoint.cleaner_reserve_segments
                {
                    return Err(StoreError::Corrupt);
                }
                current
            }
            _ => return Err(StoreError::Corrupt),
        };
        let PhysicalPointer::Value(root) = checkpoint.allocation_root else {
            return Err(StoreError::Corrupt);
        };
        if decoded.segment_state(root.segment_no) != Some(SegmentAllocation::Allocated) {
            return Err(StoreError::Corrupt);
        }
        let allocation_decoded_bytes =
            allocation_resident_bytes(&decoded).map_err(|_| StoreError::MemoryLimit)?;
        recovery_observe(
            &mut recovery_peak,
            limits.recovery_memory_bytes,
            allocation_encoded_bytes
                .checked_add(allocation_decoded_bytes)
                .ok_or(StoreError::MemoryLimit)?,
        )?;
        (
            decoded,
            version,
            Some((
                root.segment_no,
                root.segment_generation,
                payload.segment_seal_body_sha256,
            )),
            Some(payload.previous_segment),
            payload.header_target_checkpoint_generation,
        )
    };
    for pointer in [
        checkpoint.catalog_root,
        checkpoint.authority_root,
        checkpoint.allocation_root,
        checkpoint.replay_tail,
    ] {
        require_allocated_pointer(&allocation, pointer)?;
    }
    if checkpoint.catalog_root != PhysicalPointer::Null {
        let allocation_bytes =
            allocation_resident_bytes(&allocation).map_err(|_| StoreError::MemoryLimit)?;
        let snapshot = read_recovery_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.catalog_root,
            ExtentKind::Catalog,
            limits.recovery_memory_bytes,
            allocation_bytes,
        )
        .await?;
        if snapshot.bytes.starts_with(b"VIBECAS2") {
            if checkpoint.replay_count != 0 || checkpoint.replay_tail != PhysicalPointer::Null {
                return Err(StoreError::Corrupt);
            }
            let context = CasCodecContext::new(
                superblock.binding.store_uuid,
                checkpoint.admitted_segments,
                checkpoint.next_segment_generation,
            )
            .map_err(|_| StoreError::Corrupt)?;
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                allocation_bytes,
                snapshot.bytes.capacity(),
                cas_snapshot_decode_capacity_upper_bound(&snapshot.bytes)?,
            )?;
            let decoded =
                decode_cas_snapshot(&snapshot.bytes, context).map_err(|_| StoreError::Corrupt)?;
            if decoded.checkpoint_generation > checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != snapshot.extent.binding.target_checkpoint_generation
                || decoded.objects.len() > limits.max_catalog_entries as usize
                || decoded.blobs.len() > limits.max_catalog_entries as usize
            {
                return Err(StoreError::Corrupt);
            }
            let cas_bytes = decoded
                .objects
                .capacity()
                .checked_mul(mem::size_of::<ObjectMapping>())
                .and_then(|bytes| {
                    decoded
                        .blobs
                        .capacity()
                        .checked_mul(mem::size_of::<BlobMapping>())
                        .and_then(|more| bytes.checked_add(more))
                })
                .ok_or(StoreError::MemoryLimit)?;
            let snapshot_capacity = snapshot.bytes.capacity();
            recovery_observe(
                &mut recovery_peak,
                limits.recovery_memory_bytes,
                allocation_bytes
                    .checked_add(cas_bytes)
                    .and_then(|bytes| bytes.checked_add(snapshot_capacity))
                    .ok_or(StoreError::MemoryLimit)?,
            )?;
            // The decoded tables own their data; release the encoded snapshot
            // before reading a manifest so the measured recovery peak is also
            // the actual live-memory bound.
            drop(snapshot);
            for blob in &decoded.blobs {
                let PhysicalPointer::Value(_manifest_pointer) = blob.manifest else {
                    return Err(StoreError::Corrupt);
                };
                require_allocated_pointer(&allocation, blob.manifest)?;
                let manifest = read_recovery_pointer_payload(
                    device,
                    superblock.binding.store_uuid,
                    checkpoint.admitted_segments,
                    checkpoint.next_segment_generation,
                    checkpoint.binding.generation,
                    blob.manifest,
                    ExtentKind::Catalog,
                    limits.recovery_memory_bytes,
                    allocation_bytes
                        .checked_add(cas_bytes)
                        .ok_or(StoreError::MemoryLimit)?,
                )
                .await?;
                recovery_preflight_decode(
                    limits.recovery_memory_bytes,
                    allocation_bytes
                        .checked_add(cas_bytes)
                        .ok_or(StoreError::MemoryLimit)?,
                    manifest.bytes.capacity(),
                    blob_manifest_decode_capacity_upper_bound(&manifest.bytes)?,
                )?;
                let decoded_manifest = decode_blob_manifest(&manifest.bytes, context)
                    .map_err(|_| StoreError::Corrupt)?;
                if decoded_manifest.blob_key != blob.blob_key {
                    return Err(StoreError::Corrupt);
                }
                for declared in &decoded_manifest.extents {
                    let PhysicalPointer::Value(_pointer) = declared.pointer else {
                        return Err(StoreError::Corrupt);
                    };
                    require_allocated_pointer(&allocation, declared.pointer)?;
                }
                validate_cas_blob_descriptors(
                    device,
                    superblock.binding.store_uuid,
                    checkpoint.admitted_segments,
                    checkpoint.next_segment_generation,
                    checkpoint.binding.generation,
                    &decoded_manifest,
                )
                .await?;
                recovery_observe(
                    &mut recovery_peak,
                    limits.recovery_memory_bytes,
                    allocation_bytes
                        .checked_add(cas_bytes)
                        .and_then(|bytes| bytes.checked_add(manifest.bytes.capacity()))
                        .and_then(|bytes| {
                            bytes.checked_add(
                                decoded_manifest
                                    .extents
                                    .capacity()
                                    .checked_mul(mem::size_of::<ManifestExtent>())?,
                            )
                        })
                        .ok_or(StoreError::MemoryLimit)?,
                )?;
            }
            cas = Some(CasMountedState {
                objects: decoded.objects,
                blobs: decoded.blobs,
            });
        } else {
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                allocation_bytes,
                snapshot.bytes.capacity(),
                catalog_decode_capacity_upper_bound(&snapshot.bytes)?,
            )?;
            let decoded = decode_catalog(&snapshot.bytes, superblock.binding.store_uuid)
                .map_err(codec_error)?;
            if decoded.kind != CatalogPayloadKind::Snapshot
                || decoded.checkpoint_generation > checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != snapshot.extent.binding.target_checkpoint_generation
                || decoded.chain_count != decoded.entries.len() as u64
                || decoded.previous_delta != PhysicalPointer::Null
            {
                return Err(StoreError::Corrupt);
            }
            if decoded.entries.len() > limits.max_catalog_entries as usize {
                return Err(StoreError::MemoryLimit);
            }
            catalog = decoded.entries;
            recovery_observe(
                &mut recovery_peak,
                limits.recovery_memory_bytes,
                allocation_bytes
                    .checked_add(measured_catalog_bytes(&catalog))
                    .and_then(|bytes| bytes.checked_add(snapshot.bytes.capacity()))
                    .ok_or(StoreError::MemoryLimit)?,
            )?;
        }
    }

    let mut persistent_roots = None;
    let mut persistent_authority = None;
    if checkpoint.authority_root != PhysicalPointer::Null {
        let resident_before_roots =
            recovery_resident_bytes(&allocation, &catalog, cas.as_ref(), None, None)
                .map_err(|_| StoreError::MemoryLimit)?;
        let authority = read_recovery_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.authority_root,
            ExtentKind::Authority,
            limits.recovery_memory_bytes,
            resident_before_roots,
        )
        .await?;
        // A freshly formatted V2 store has a null catalog root. Installing an
        // explicit empty authority snapshot is still valid: there are no
        // bindings which would require CAS resolution yet.
        let cas_objects: &[ObjectMapping] =
            cas.as_ref().map_or(&[], |state| state.objects.as_slice());
        let (decoded_roots, decoded_authority) = if authority.bytes.starts_with(b"VIBEAUT2") {
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                resident_before_roots,
                authority.bytes.capacity(),
                persistent_authority_decode_capacity_upper_bound(&authority.bytes)?,
            )?;
            let decoded = decode_persistent_authority_snapshot(&authority.bytes)
                .map_err(|_| StoreError::Corrupt)?;
            if decoded.checkpoint_generation()
                != authority.extent.binding.target_checkpoint_generation
            {
                return Err(StoreError::Corrupt);
            }
            let mut entries: Vec<PersistentRootEntry> = decoded
                .objects
                .iter()
                .map(|binding| PersistentRootEntry {
                    object_id: binding.v2_object_id,
                    commit_generation: binding.commit_generation,
                    object_kind: binding.object_kind,
                })
                .collect();
            entries.extend_from_slice(decoded.external_roots());
            entries.sort_unstable_by_key(|entry| entry.object_id);
            let roots = PersistentRootSet::new(decoded.checkpoint_generation(), entries)
                .map_err(|_| StoreError::Corrupt)?;
            (roots, Some(decoded))
        } else {
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                resident_before_roots,
                authority.bytes.capacity(),
                persistent_roots_decode_capacity_upper_bound(&authority.bytes)?,
            )?;
            let decoded =
                decode_persistent_root_set(&authority.bytes).map_err(|_| StoreError::Corrupt)?;
            if decoded.checkpoint_generation > checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != authority.extent.binding.target_checkpoint_generation
            {
                return Err(StoreError::Corrupt);
            }
            (decoded, None)
        };
        for root in decoded_roots.entries() {
            let object = cas_objects
                .binary_search_by_key(&root.object_id, |object| object.object_id)
                .ok()
                .map(|index| cas_objects[index])
                .ok_or(StoreError::Corrupt)?;
            if object.commit_generation != root.commit_generation
                || object.blob_key.object_kind() != root.object_kind
            {
                return Err(StoreError::Corrupt);
            }
        }
        recovery_observe(
            &mut recovery_peak,
            limits.recovery_memory_bytes,
            resident_before_roots
                .checked_add(authority.bytes.capacity())
                .and_then(|bytes| bytes.checked_add(decoded_roots.allocated_bytes()?))
                .and_then(|bytes| {
                    bytes.checked_add(
                        decoded_authority
                            .as_ref()
                            .map_or(0, |value| value.allocated_bytes().unwrap_or(usize::MAX)),
                    )
                })
                .ok_or(StoreError::MemoryLimit)?,
        )?;
        persistent_roots = Some(decoded_roots);
        persistent_authority = decoded_authority;
    }

    let mut reverse_deltas = Vec::new();
    let replay_capacity_bytes = usize::try_from(checkpoint.replay_count)
        .ok()
        .and_then(|count| count.checked_mul(mem::size_of::<CatalogEntry>()))
        .ok_or(StoreError::MemoryLimit)?;
    let resident_bytes = recovery_resident_bytes(
        &allocation,
        &catalog,
        cas.as_ref(),
        persistent_roots.as_ref(),
        persistent_authority.as_ref(),
    )
    .map_err(|_| StoreError::MemoryLimit)?;
    let replay_allocation_peak = resident_bytes
        .checked_add(replay_capacity_bytes)
        .ok_or(StoreError::MemoryLimit)?;
    if replay_allocation_peak > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit);
    }
    reverse_deltas
        .try_reserve_exact(checkpoint.replay_count as usize)
        .map_err(|_| StoreError::MemoryLimit)?;
    recovery_observe(
        &mut recovery_peak,
        limits.recovery_memory_bytes,
        resident_bytes
            .checked_add(reverse_deltas.capacity() * mem::size_of::<CatalogEntry>())
            .ok_or(StoreError::MemoryLimit)?,
    )?;
    let mut pointer = checkpoint.replay_tail;
    let mut expected_depth = u64::from(checkpoint.replay_count);
    while expected_depth != 0 {
        let replay_resident = resident_bytes
            .checked_add(
                reverse_deltas
                    .capacity()
                    .checked_mul(mem::size_of::<CatalogEntry>())
                    .ok_or(StoreError::MemoryLimit)?,
            )
            .ok_or(StoreError::MemoryLimit)?;
        let delta = read_recovery_pointer_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            pointer,
            ExtentKind::CatalogDelta,
            limits.recovery_memory_bytes,
            replay_resident,
        )
        .await?;
        recovery_preflight_decode(
            limits.recovery_memory_bytes,
            replay_resident,
            delta.bytes.capacity(),
            catalog_decode_capacity_upper_bound(&delta.bytes)?,
        )?;
        let decoded =
            decode_catalog(&delta.bytes, superblock.binding.store_uuid).map_err(codec_error)?;
        if decoded.kind != CatalogPayloadKind::Delta
            || decoded.entries.len() != 1
            || decoded.chain_count != expected_depth
            || decoded.checkpoint_generation > checkpoint.binding.generation
            || decoded.checkpoint_generation != delta.extent.binding.target_checkpoint_generation
        {
            return Err(StoreError::Corrupt);
        }
        reverse_deltas.push(decoded.entries[0]);
        pointer = decoded.previous_delta;
        expected_depth -= 1;
        let peak = replay_resident
            .checked_add(delta.bytes.capacity())
            .and_then(|value| value.checked_add(measured_catalog_bytes(&decoded.entries)))
            .ok_or(StoreError::MemoryLimit)?;
        recovery_observe(&mut recovery_peak, limits.recovery_memory_bytes, peak)?;
    }
    if pointer != PhysicalPointer::Null {
        return Err(StoreError::Corrupt);
    }
    let final_catalog_len = catalog
        .len()
        .checked_add(reverse_deltas.len())
        .ok_or(StoreError::MemoryLimit)?;
    if final_catalog_len > limits.max_catalog_entries as usize {
        return Err(StoreError::MemoryLimit);
    }
    let catalog_additional = final_catalog_len - catalog.len();
    let catalog_growth_bytes = final_catalog_len
        .saturating_sub(catalog.capacity())
        .checked_mul(mem::size_of::<CatalogEntry>())
        .ok_or(StoreError::MemoryLimit)?;
    let merge_preflight = resident_bytes
        .checked_add(
            reverse_deltas
                .capacity()
                .checked_mul(mem::size_of::<CatalogEntry>())
                .ok_or(StoreError::MemoryLimit)?,
        )
        .and_then(|bytes| bytes.checked_add(catalog_growth_bytes))
        .ok_or(StoreError::MemoryLimit)?;
    recovery_observe(
        &mut recovery_peak,
        limits.recovery_memory_bytes,
        merge_preflight,
    )?;
    catalog
        .try_reserve_exact(catalog_additional)
        .map_err(|_| StoreError::MemoryLimit)?;
    let merge_peak = allocation_resident_bytes(&allocation)
        .map_err(|_| StoreError::MemoryLimit)?
        .checked_add(cas_resident_bytes(cas.as_ref()).map_err(|_| StoreError::MemoryLimit)?)
        .and_then(|bytes| {
            root_resident_bytes(persistent_roots.as_ref())
                .ok()?
                .checked_add(bytes)
        })
        .and_then(|bytes| bytes.checked_add(measured_catalog_bytes(&catalog)))
        .and_then(|bytes| {
            reverse_deltas
                .capacity()
                .checked_mul(mem::size_of::<CatalogEntry>())?
                .checked_add(bytes)
        })
        .ok_or(StoreError::MemoryLimit)?;
    recovery_observe(&mut recovery_peak, limits.recovery_memory_bytes, merge_peak)?;
    for entry in reverse_deltas.iter().rev() {
        catalog.push(*entry);
    }
    drop(reverse_deltas);
    if cas.is_none() {
        validate_catalog(
            &catalog,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            limits,
        )?;
    }
    recovery_peak = recovery_peak.max(
        recovery_resident_bytes(
            &allocation,
            &catalog,
            cas.as_ref(),
            persistent_roots.as_ref(),
            persistent_authority.as_ref(),
        )
        .map_err(|_| StoreError::MemoryLimit)?,
    );
    if recovery_peak > limits.recovery_memory_bytes {
        return Err(StoreError::MemoryLimit);
    }
    if checkpoint.allocation_root == PhysicalPointer::Null && (!catalog.is_empty() || cas.is_some())
    {
        return Err(StoreError::Corrupt);
    }
    for entry in &catalog {
        if let PhysicalPointer::Value(pointer) = entry.blob {
            require_allocated_pointer(&allocation, entry.blob)?;
            validate_blob_descriptor(
                device,
                superblock.binding.store_uuid,
                checkpoint.admitted_segments,
                checkpoint.next_segment_generation,
                checkpoint.binding.generation,
                entry,
                pointer,
            )
            .await?;
        }
    }

    // Never overwrite a published tail. M7.3 quarantines through the last
    // non-zero final-seal page after the committed frontier. Internal bytes
    // behind an exact-zero publication page are safe to replace only through
    // the explicit zero/flush/reread gate in append_object.
    let first_free = (0..checkpoint.admitted_segments)
        .find(|segment_no| allocation.segment_state(*segment_no) == Some(SegmentAllocation::Free))
        .unwrap_or(checkpoint.admitted_segments);
    let mut next_physical_segment = first_free;
    for segment_no in first_free..checkpoint.admitted_segments {
        if allocation_version == 2
            && allocation.segment_state(segment_no) != Some(SegmentAllocation::Free)
        {
            continue;
        }
        let base = segment_base_page(segment_no)?;
        let mut final_seal = [0; PAGE_SIZE];
        device
            .read_page(base + u64::from(SEGMENT_SEAL_PAGE), &mut final_seal)
            .await
            .map_err(StoreError::Device)?;
        if allocation_version == 1 && final_seal.iter().any(|byte| *byte != 0) {
            next_physical_segment = segment_no.checked_add(1).ok_or(StoreError::Corrupt)?;
        }
    }
    let media_next_object_id = cas
        .as_ref()
        .and_then(|cas| cas.objects.last().map(|entry| entry.object_id))
        .or_else(|| catalog.last().map(|entry| entry.object_id))
        .map(|object_id| object_id.checked_add(1).ok_or(StoreError::IdExhausted))
        .transpose()?
        .unwrap_or(1);
    // Checkpoint generation is the durable ObjectId high-water floor. Every
    // production commit consumes at most one ObjectId and advances generation;
    // GC advances generation without consuming an ID. Taking the maximum also
    // mounts older/externally produced catalogs without colliding with a live
    // mapping. GC separately refuses to discard such a catalog if its media
    // high-water exceeds the generation-backed floor.
    let next_object_id = media_next_object_id.max(u128::from(checkpoint.binding.generation));
    Ok(MountedState {
        superblock,
        generation: checkpoint.binding.generation,
        admitted_segments: checkpoint.admitted_segments,
        next_physical_segment,
        next_segment_generation: checkpoint.next_segment_generation,
        next_object_id,
        cleaner_reserve_segments: checkpoint.cleaner_reserve_segments,
        replay_count: checkpoint.replay_count,
        catalog_root: checkpoint.catalog_root,
        replay_tail: checkpoint.replay_tail,
        authority_root: checkpoint.authority_root,
        allocation_root: checkpoint.allocation_root,
        allocation,
        allocation_version,
        persistent_roots,
        persistent_authority,
        catalog,
        cas,
        recovery_peak_bytes: recovery_peak,
        last_segment,
        last_segment_previous,
        last_segment_target_checkpoint_generation,
    })
}

fn require_allocated_pointer<E>(
    allocation: &AllocationV2,
    pointer: PhysicalPointer,
) -> Result<(), StoreError<E>> {
    if let PhysicalPointer::Value(pointer) = pointer {
        if allocation.segment_state(pointer.segment_no) != Some(SegmentAllocation::Allocated) {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

pub(crate) fn validate_checkpoint_transition<E>(
    older: &CheckpointTransitionWitness,
    newer: &MountedState,
) -> Result<(), StoreError<E>> {
    if older
        .generation
        .checked_add(1)
        .is_none_or(|generation| generation != newer.generation)
        || older.store_uuid != newer.superblock.binding.store_uuid
        || older.cleaner_reserve_segments != newer.cleaner_reserve_segments
    {
        return Err(StoreError::Corrupt);
    }

    if newer.admitted_segments > older.admitted_segments {
        return validate_growth_checkpoint_transition(older, newer);
    }
    if older.admitted_segments != newer.admitted_segments {
        return Err(StoreError::Corrupt);
    }

    validate_allocation_checkpoint_transition(
        &older.allocation,
        &newer.allocation,
        older.generation,
        newer.generation,
        older.next_segment_generation,
        newer.next_segment_generation,
        newer.allocation_version,
    )
}

fn validate_growth_checkpoint_transition<E>(
    older: &CheckpointTransitionWitness,
    newer: &MountedState,
) -> Result<(), StoreError<E>> {
    if newer.allocation_version != 2
        || newer.allocation.admitted_segments != newer.admitted_segments
        || !older.allocation.retired_segments().is_empty()
        || !newer.allocation.retired_segments().is_empty()
        || older.replay_count != newer.replay_count
        || older.catalog_root != newer.catalog_root
        || older.replay_tail != newer.replay_tail
        || older.authority_root != newer.authority_root
    {
        return Err(StoreError::Corrupt);
    }

    let counts = newer.allocation.counts().map_err(|_| StoreError::Corrupt)?;
    let protected_free = u64::from(newer.cleaner_reserve_segments)
        .checked_add(u64::from(ROOT_POLICY_HEADROOM_SEGMENTS))
        .ok_or(StoreError::Corrupt)?;
    if counts.free < protected_free {
        return Err(StoreError::Corrupt);
    }

    let mut allocated_carrier = None;
    for segment_no in 0..older.admitted_segments {
        match (
            older.allocation.segment_state(segment_no),
            newer.allocation.segment_state(segment_no),
        ) {
            (Some(before), Some(after)) if before == after => {}
            (Some(SegmentAllocation::Free), Some(SegmentAllocation::Allocated)) => {
                if allocated_carrier.replace(segment_no).is_some() {
                    return Err(StoreError::Corrupt);
                }
            }
            _ => return Err(StoreError::Corrupt),
        }
    }
    let carrier = allocated_carrier.ok_or(StoreError::Corrupt)?;
    let PhysicalPointer::Value(allocation_root) = newer.allocation_root else {
        return Err(StoreError::Corrupt);
    };
    let expected_previous = older
        .last_segment
        .unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
    if newer.allocation_root == older.allocation_root
        || allocation_root.segment_no != carrier
        || allocation_root.segment_generation != older.next_segment_generation
        || allocation_root.extent_kind != ExtentKind::Allocation
        || newer
            .last_segment
            .is_none_or(|last| last.0 != carrier || last.1 != older.next_segment_generation)
        || newer.last_segment_previous != Some(expected_previous)
        || newer.last_segment_target_checkpoint_generation != newer.generation
        || (older.admitted_segments..newer.admitted_segments).any(|segment_no| {
            newer.allocation.segment_state(segment_no) != Some(SegmentAllocation::Free)
        })
        || newer.next_segment_generation
            != older
                .next_segment_generation
                .checked_add(1)
                .ok_or(StoreError::Corrupt)?
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_allocation_checkpoint_transition<E>(
    older: &AllocationV2,
    newer: &AllocationV2,
    older_generation: u64,
    newer_generation: u64,
    older_next_segment_generation: u64,
    newer_next_segment_generation: u64,
    newer_allocation_version: u16,
) -> Result<(), StoreError<E>> {
    if older.admitted_segments != newer.admitted_segments
        || older.cleaner_reserve_segments != newer.cleaner_reserve_segments
    {
        return Err(StoreError::Corrupt);
    }

    let mut free_to_allocated = 0_u64;
    let mut allocated_to_retired = 0_u64;
    let mut retired_to_free = 0_u64;
    for segment_no in 0..older.admitted_segments {
        let before = older.segment_state(segment_no).ok_or(StoreError::Corrupt)?;
        let after = newer.segment_state(segment_no).ok_or(StoreError::Corrupt)?;
        match (before, after) {
            (SegmentAllocation::Free, SegmentAllocation::Free)
            | (SegmentAllocation::Allocated, SegmentAllocation::Allocated)
            | (SegmentAllocation::Retired, SegmentAllocation::Retired) => {}
            (SegmentAllocation::Free, SegmentAllocation::Allocated) => {
                free_to_allocated = free_to_allocated
                    .checked_add(1)
                    .ok_or(StoreError::Corrupt)?;
            }
            (SegmentAllocation::Allocated, SegmentAllocation::Retired) => {
                if newer.retire_generation(segment_no) != Some(newer_generation) {
                    return Err(StoreError::Corrupt);
                }
                allocated_to_retired = allocated_to_retired
                    .checked_add(1)
                    .ok_or(StoreError::Corrupt)?;
            }
            (SegmentAllocation::Retired, SegmentAllocation::Free) => {
                retired_to_free = retired_to_free.checked_add(1).ok_or(StoreError::Corrupt)?;
            }
            _ => return Err(StoreError::Corrupt),
        }
    }

    let older_counts = older.counts().map_err(|_| StoreError::Corrupt)?;
    if allocated_to_retired != 0 {
        // G -> G+1 relocation: a non-empty strict subset or the complete old
        // Allocated set becomes Retired at exactly G+1. Unselected Allocated
        // segments remain current and no earlier retired cycle may overlap it.
        if retired_to_free != 0
            || older_counts.retired != 0
            || allocated_to_retired > older_counts.allocated
            || free_to_allocated == 0
        {
            return Err(StoreError::Corrupt);
        }
    } else if retired_to_free != 0 {
        // G+1 -> G+2 reuse barrier: reclaim the complete retired set and
        // allocate exactly one distinct segment for the new allocation root.
        if retired_to_free != older_counts.retired
            || older
                .retired_segments()
                .iter()
                .any(|entry| entry.retire_generation != older_generation)
            || newer.counts().map_err(|_| StoreError::Corrupt)?.retired != 0
            || free_to_allocated != 1
        {
            return Err(StoreError::Corrupt);
        }
    } else if older_counts.retired != 0 {
        // No ordinary checkpoint may advance while a reuse barrier is pending.
        return Err(StoreError::Corrupt);
    }

    if newer_allocation_version == 2 {
        let assigned = newer_next_segment_generation
            .checked_sub(older_next_segment_generation)
            .ok_or(StoreError::Corrupt)?;
        if assigned != free_to_allocated {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn validate_blob_descriptor<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    entry: &CatalogEntry,
    pointer: PointerValue,
) -> Result<(), StoreError<D::Error>> {
    let scanned = scan_segment(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
    )
    .await?;
    let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
    if extent.extent_kind != ExtentKind::Blob
        || extent.binding.target_checkpoint_generation != entry.commit_generation
        || extent.object_kind != entry.object_kind
        || extent.extent_index != 0
        || extent.extent_count != 1
        || extent.content_byte_len != entry.exact_len
        || extent.encoded_blob_len != entry.exact_len
        || extent.encoded_offset != 0
        || extent.payload_byte_len != entry.exact_len
        || extent.payload_first_relative_page != pointer.payload_relative_page
        || extent.payload_pages != pointer.payload_pages
        || extent.merkle_root != entry.content_root
        || extent.payload_sha256 != entry.content_root
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn validate_cas_blob_descriptors<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    manifest: &BlobManifest,
) -> Result<(), StoreError<D::Error>> {
    for declared in &manifest.extents {
        let PhysicalPointer::Value(pointer) = declared.pointer else {
            return Err(StoreError::Corrupt);
        };
        let scanned = scan_segment(
            device,
            store_uuid,
            admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            pointer,
        )
        .await?;
        let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
        if extent.extent_kind != ExtentKind::Blob
            || extent.object_kind != manifest.blob_key.object_kind()
            || extent.extent_index != declared.extent_index
            || extent.extent_count != declared.extent_count
            || extent.content_byte_len != manifest.blob_key.exact_len()
            || extent.encoded_blob_len != manifest.encoded_blob_len
            || extent.encoded_offset != declared.encoded_offset
            || extent.payload_byte_len != declared.payload_byte_len
            || extent.merkle_root != manifest.blob_key.merkle_root()
            || extent.payload_first_relative_page != pointer.payload_relative_page
            || extent.payload_pages != pointer.payload_pages
            || extent.payload_sha256 != pointer.payload_sha256
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

fn measured_catalog_bytes(catalog: &Vec<CatalogEntry>) -> usize {
    catalog.capacity() * mem::size_of::<CatalogEntry>()
}

fn validate_catalog<E>(
    catalog: &[CatalogEntry],
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    limits: StoreLimits,
) -> Result<(), StoreError<E>> {
    if catalog.len() > limits.max_catalog_entries as usize {
        return Err(StoreError::MemoryLimit);
    }
    let mut previous = 0_u128;
    for entry in catalog {
        if entry.object_id == 0
            || entry.object_id <= previous
            || entry.object_kind == 0
            || entry.commit_generation == 0
            || entry.commit_generation > checkpoint_generation
            || (entry.exact_len == 0) != (entry.blob == PhysicalPointer::Null)
        {
            return Err(StoreError::Corrupt);
        }
        if let PhysicalPointer::Value(pointer) = entry.blob {
            if pointer.store_uuid != store_uuid
                || pointer.extent_kind != ExtentKind::Blob
                || pointer.segment_no >= admitted_segments
                || pointer.segment_generation >= next_segment_generation
                || pointer.exact_byte_len != entry.exact_len
                || pointer.payload_sha256 != entry.content_root
            {
                return Err(StoreError::Corrupt);
            }
        }
        previous = entry.object_id;
    }
    Ok(())
}

struct BuiltExtent<'a> {
    value: ExtentRecord,
    digest: BodyDigest,
    body: Page,
    seal: Page,
    payload: &'a [u8],
}

impl BuiltExtent<'_> {
    fn pointer(&self) -> PhysicalPointer {
        PhysicalPointer::Value(PointerValue {
            store_uuid: self.value.binding.store_uuid,
            segment_no: self.value.binding.segment_no,
            segment_generation: self.value.binding.generation,
            descriptor_relative_page: self.value.payload_first_relative_page - 2,
            payload_relative_page: self.value.payload_first_relative_page,
            payload_pages: self.value.payload_pages,
            ordinal: self.value.binding.ordinal,
            exact_byte_len: self.value.payload_byte_len,
            extent_kind: self.value.extent_kind,
            payload_sha256: self.value.payload_sha256,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn build_extent<'a>(
    store_uuid: StoreUuid,
    segment_no: u64,
    segment_generation: u64,
    checkpoint_generation: u64,
    ordinal: u32,
    relative_page: u32,
    kind: ExtentKind,
    object_kind: u32,
    content_len: u64,
    content_root: [u8; 32],
    payload: &'a [u8],
) -> Result<BuiltExtent<'a>, FormatError> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| FormatError::ArithmeticOverflow)?;
    if payload_len == 0 {
        return Err(FormatError::InvalidPayloadLength);
    }
    let payload_pages = u32::try_from(payload.len().div_ceil(PAGE_SIZE))
        .map_err(|_| FormatError::ArithmeticOverflow)?;
    let record_span_pages = payload_pages
        .checked_add(2)
        .ok_or(FormatError::ArithmeticOverflow)?;
    let base = segment_base_page(segment_no)?;
    let value = ExtentRecord {
        binding: RecordBinding {
            store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal,
            self_page: base + u64::from(relative_page),
            target_checkpoint_generation: checkpoint_generation,
        },
        extent_kind: kind,
        object_kind,
        extent_index: 0,
        extent_count: 1,
        payload_pages,
        content_byte_len: content_len,
        encoded_blob_len: payload_len,
        encoded_offset: 0,
        payload_byte_len: payload_len,
        payload_first_relative_page: relative_page + 2,
        record_span_pages,
        merkle_root: content_root,
        payload_sha256: payload_sha256(payload),
    };
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_extent_body(&value, &mut body)?;
    encode_record_seal(digest, &mut seal)?;
    Ok(BuiltExtent {
        value,
        digest,
        body,
        seal,
        payload,
    })
}

async fn write_extent<D: PageDevice>(
    device: &D,
    base: u64,
    extent: &BuiltExtent<'_>,
) -> Result<(), StoreError<D::Error>> {
    let relative = extent.value.binding.self_page - base;
    let mut copied = 0;
    let mut page_index = 0_u32;
    while page_index < extent.value.payload_pages {
        let batch_pages = (extent.value.payload_pages - page_index).min(32) as usize;
        let mut pages = vec![[0; PAGE_SIZE]; batch_pages];
        for page in &mut pages {
            let remaining = extent.payload.len() - copied;
            let take = remaining.min(PAGE_SIZE);
            page[..take].copy_from_slice(&extent.payload[copied..copied + take]);
            copied += take;
        }
        device
            .write_pages(
                base + u64::from(extent.value.payload_first_relative_page + page_index),
                &pages,
            )
            .await
            .map_err(StoreError::Mutation)?;
        page_index += batch_pages as u32;
    }
    flush(device).await?;
    write_page(device, base + relative, &extent.body).await?;
    flush(device).await?;
    write_page(device, base + relative + 1, &extent.seal).await?;
    flush(device).await?;
    Ok(())
}

async fn append_object<D: PageDevice>(
    device: &D,
    state: &MountedState,
    limits: StoreLimits,
    object_kind: u32,
    content_root: [u8; 32],
    bytes: &[u8],
) -> Result<(ObjectHandle, MountedState), StoreError<D::Error>> {
    let checkpoint_generation = state
        .generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let segment_no = state.next_physical_segment;
    let segment_generation = state.next_segment_generation;
    let next_segment_generation = segment_generation
        .checked_add(1)
        .ok_or(StoreError::IdExhausted)?;
    let base = segment_base_page(segment_no)?;
    // Reuse is allowed only when the publication page is durably cleared and
    // rereads as exact zero.  M7.3 never treats discard as this proof.
    let zero = [0; PAGE_SIZE];
    write_page(device, base + u64::from(SEGMENT_SEAL_PAGE), &zero).await?;
    flush(device).await?;
    let mut observed_final_seal = [0; PAGE_SIZE];
    device
        .read_page(
            base + u64::from(SEGMENT_SEAL_PAGE),
            &mut observed_final_seal,
        )
        .await
        .map_err(StoreError::Device)?;
    if observed_final_seal.iter().any(|byte| *byte != 0) {
        return Err(StoreError::Corrupt);
    }
    let (previous_segment_no, previous_segment_generation, previous_hash) = state
        .last_segment
        .unwrap_or((ANCHOR_SEGMENT_NO, 0, [0; 32]));
    let header = SegmentHeader {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: 0,
            self_page: base,
            target_checkpoint_generation: checkpoint_generation,
        },
        base_page: base,
        previous_segment_no,
        previous_segment_generation,
        previous_segment_seal_body_sha256: previous_hash,
    };
    let mut header_body = [0; PAGE_SIZE];
    let mut header_seal = [0; PAGE_SIZE];
    let header_digest = encode_segment_header_body(&header, &mut header_body)?;
    encode_record_seal(header_digest, &mut header_seal)?;

    let mut ordinal = 1_u32;
    let mut relative = DATA_FIRST_PAGE;
    let blob = if bytes.is_empty() {
        None
    } else {
        let value = build_extent(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            checkpoint_generation,
            ordinal,
            relative,
            ExtentKind::Blob,
            object_kind,
            bytes.len() as u64,
            content_root,
            bytes,
        )?;
        ordinal += 1;
        relative += value.value.record_span_pages;
        Some(value)
    };
    let blob_pointer = blob
        .as_ref()
        .map_or(PhysicalPointer::Null, BuiltExtent::pointer);
    let entry = CatalogEntry {
        object_id: state.next_object_id,
        object_kind,
        exact_len: bytes.len() as u64,
        commit_generation: checkpoint_generation,
        content_root,
        blob: blob_pointer,
    };

    let make_snapshot = state.catalog_root == PhysicalPointer::Null
        || state.replay_count + 1 >= limits.max_replay_records;
    let mut snapshot_entries = Vec::new();
    let (catalog_kind, previous_delta, replay_count) = if make_snapshot {
        snapshot_entries
            .try_reserve_exact(state.catalog.len() + 1)
            .map_err(|_| StoreError::Capacity(CapacityClass::Metadata))?;
        snapshot_entries.extend_from_slice(&state.catalog);
        snapshot_entries.push(entry);
        (CatalogPayloadKind::Snapshot, PhysicalPointer::Null, 0)
    } else {
        (
            CatalogPayloadKind::Delta,
            state.replay_tail,
            state.replay_count + 1,
        )
    };
    let catalog_payload = CatalogPayload {
        kind: catalog_kind,
        checkpoint_generation,
        chain_count: if make_snapshot {
            snapshot_entries.len() as u64
        } else {
            u64::from(replay_count)
        },
        previous_delta,
        entries: if make_snapshot {
            snapshot_entries
        } else {
            vec![entry]
        },
    };
    let catalog_bytes = encode_catalog(&catalog_payload, state.superblock.binding.store_uuid)
        .map_err(codec_error)?;
    if catalog_bytes.len() > MAX_EXTENT_PAYLOAD_PAGES as usize * PAGE_SIZE {
        return Err(StoreError::Capacity(CapacityClass::Metadata));
    }
    let catalog_extent_kind = if make_snapshot {
        ExtentKind::Catalog
    } else {
        ExtentKind::CatalogDelta
    };
    let catalog_extent = build_extent(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
        checkpoint_generation,
        ordinal,
        relative,
        catalog_extent_kind,
        METADATA_KIND_CATALOG,
        catalog_bytes.len() as u64,
        payload_sha256(&catalog_bytes),
        &catalog_bytes,
    )?;
    ordinal += 1;
    relative += catalog_extent.value.record_span_pages;
    let catalog_pointer = catalog_extent.pointer();

    let allocation = AllocationState {
        checkpoint_generation,
        admitted_segments: state.admitted_segments,
        allocated_prefix_segments: segment_no + 1,
        next_segment_generation,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
    };
    let allocation_bytes = encode_allocation(allocation).map_err(codec_error)?;
    let allocation_extent = build_extent(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
        checkpoint_generation,
        ordinal,
        relative,
        ExtentKind::Allocation,
        METADATA_KIND_ALLOCATION,
        allocation_bytes.len() as u64,
        payload_sha256(&allocation_bytes),
        &allocation_bytes,
    )?;
    relative += allocation_extent.value.record_span_pages;
    if relative > DATA_END_PAGE {
        return Err(StoreError::Capacity(if bytes.is_empty() {
            CapacityClass::Metadata
        } else {
            CapacityClass::Payload
        }));
    }

    let mut descriptor_chain = descriptor_chain_initial(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
    );
    let mut payload_chain = payload_chain_initial(
        state.superblock.binding.store_uuid,
        segment_no,
        segment_generation,
    );
    let mut kind_counts = [0_u32; 5];
    let mut kind_bytes = [0_u64; 5];
    let mut payload_page_count = 0_u32;
    let mut total_payload_bytes = 0_u64;
    let mut record_count = 0_u32;
    for extent in blob
        .iter()
        .chain(core::iter::once(&catalog_extent))
        .chain(core::iter::once(&allocation_extent))
    {
        descriptor_chain = descriptor_chain_next(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            descriptor_chain,
            extent.value.binding.ordinal,
            extent.digest.body_sha256(),
            extent.value.payload_sha256,
        );
        payload_chain = payload_chain_next(
            state.superblock.binding.store_uuid,
            segment_no,
            segment_generation,
            payload_chain,
            extent.value.binding.ordinal,
            extent.value.payload_byte_len,
            extent.value.payload_sha256,
        );
        let kind = extent_kind_index(extent.value.extent_kind);
        kind_counts[kind] += 1;
        kind_bytes[kind] += extent.value.payload_byte_len;
        payload_page_count += extent.value.payload_pages;
        total_payload_bytes += extent.value.payload_byte_len;
        record_count += 1;
    }
    let summary = SegmentSummary {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: record_count + 1,
            self_page: base + u64::from(SUMMARY_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        record_count,
        next_free_page: relative,
        payload_page_count,
        total_payload_bytes,
        first_target_checkpoint_generation: checkpoint_generation,
        last_target_checkpoint_generation: checkpoint_generation,
        header_body_sha256: header_digest.body_sha256(),
        descriptor_chain_sha256: descriptor_chain,
        payload_chain_sha256: payload_chain,
        kind_counts,
        kind_bytes,
    };
    let mut summary_body = [0; PAGE_SIZE];
    let mut summary_seal = [0; PAGE_SIZE];
    let summary_digest = encode_segment_summary_body(&summary, &mut summary_body)?;
    encode_record_seal(summary_digest, &mut summary_seal)?;
    let segment_seal = SegmentSeal {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: segment_generation,
            segment_no,
            ordinal: record_count + 2,
            self_page: base + u64::from(SEGMENT_SEAL_BODY_PAGE),
            target_checkpoint_generation: checkpoint_generation,
        },
        header_body_sha256: header_digest.body_sha256(),
        summary_body_sha256: summary_digest.body_sha256(),
        final_descriptor_chain_sha256: descriptor_chain,
        final_payload_chain_sha256: payload_chain,
        record_count,
        next_free_page: relative,
        payload_page_count,
        total_payload_bytes,
        target_checkpoint_generation: checkpoint_generation,
    };
    let mut segment_seal_body = [0; PAGE_SIZE];
    let mut final_segment_seal = [0; PAGE_SIZE];
    let segment_seal_digest = encode_segment_seal_body(&segment_seal, &mut segment_seal_body)?;
    encode_record_seal(segment_seal_digest, &mut final_segment_seal)?;

    // Every structural pair and extent follows the frozen M7.2 dependency
    // order.  The extra flushes are intentional until a device-specific FUA
    // proof can replace an exact boundary.
    write_page(device, base, &header_body).await?;
    flush(device).await?;
    write_page(device, base + 1, &header_seal).await?;
    flush(device).await?;
    if let Some(blob) = blob.as_ref() {
        write_extent(device, base, blob).await?;
    }
    write_extent(device, base, &catalog_extent).await?;
    write_extent(device, base, &allocation_extent).await?;
    write_page(device, base + u64::from(SUMMARY_BODY_PAGE), &summary_body).await?;
    flush(device).await?;
    write_page(device, base + u64::from(SUMMARY_SEAL_PAGE), &summary_seal).await?;
    flush(device).await?;
    write_page(
        device,
        base + u64::from(SEGMENT_SEAL_BODY_PAGE),
        &segment_seal_body,
    )
    .await?;
    flush(device).await?;
    // Final segment publication.
    write_page(
        device,
        base + u64::from(SEGMENT_SEAL_PAGE),
        &final_segment_seal,
    )
    .await?;
    flush(device).await?;

    let allocation_pointer = allocation_extent.pointer();
    // A checkpoint can name the segment only after a powered-on verification
    // of every exact payload and the complete structural seal chain.
    if let Some(blob) = blob.as_ref() {
        let verified = read_pointer_payload(
            device,
            state.superblock.binding.store_uuid,
            state.admitted_segments,
            next_segment_generation,
            checkpoint_generation,
            blob.pointer(),
            ExtentKind::Blob,
            limits.max_compat_object_bytes as usize,
        )
        .await?;
        if verified.bytes.as_slice() != bytes {
            return Err(StoreError::Corrupt);
        }
    }
    let verified_catalog = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        catalog_pointer,
        catalog_extent_kind,
        limits.recovery_memory_bytes,
    )
    .await?;
    if verified_catalog.bytes != catalog_bytes {
        return Err(StoreError::Corrupt);
    }
    let verified_allocation = read_pointer_payload(
        device,
        state.superblock.binding.store_uuid,
        state.admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        allocation_pointer,
        ExtentKind::Allocation,
        limits.recovery_memory_bytes,
    )
    .await?;
    if verified_allocation.bytes.as_slice() != allocation_bytes {
        return Err(StoreError::Corrupt);
    }
    let (catalog_root, replay_tail) = if make_snapshot {
        (catalog_pointer, PhysicalPointer::Null)
    } else {
        (state.catalog_root, catalog_pointer)
    };
    let slot = ((checkpoint_generation - 1) & 1) as u8;
    let checkpoint = Checkpoint {
        binding: RecordBinding {
            store_uuid: state.superblock.binding.store_uuid,
            generation: checkpoint_generation,
            segment_no: ANCHOR_SEGMENT_NO,
            ordinal: u32::from(slot),
            self_page: 4 + u64::from(slot) * 2,
            target_checkpoint_generation: checkpoint_generation,
        },
        slot,
        previous_generation: state.generation,
        admitted_range_pages: admitted_pages(state.admitted_segments)?,
        admitted_segments: state.admitted_segments,
        next_segment_generation,
        replay_count,
        max_replay_records: limits.max_replay_records,
        cleaner_reserve_segments: state.cleaner_reserve_segments,
        catalog_root,
        authority_root: PhysicalPointer::Null,
        allocation_root: allocation_pointer,
        replay_tail,
    };
    write_checkpoint(device, &checkpoint, true).await?;
    let selected_super = select_superblock(
        read_superblock(device, 0).await?,
        read_superblock(device, 2).await?,
    )?
    .ok_or(StoreError::Corrupt)?;
    if selected_super.value() != &state.superblock {
        return Err(StoreError::Corrupt);
    }
    let left = read_checkpoint(device, 4).await?;
    let right = read_checkpoint(device, 6).await?;
    let selected =
        select_checkpoint_for_superblock(selected_super, left, right, device.info().page_count)?
            .ok_or(StoreError::Corrupt)?;
    if selected.value() != &checkpoint {
        return Err(StoreError::Corrupt);
    }
    for candidate in [left, right].into_iter().flatten() {
        recover_state(device, state.superblock, candidate, limits).await?;
    }
    let recovered = recover_state(device, state.superblock, selected, limits).await?;
    let handle = ObjectHandle {
        store_uuid: state.superblock.binding.store_uuid,
        object_id: entry.object_id,
        object_kind,
        exact_len: bytes.len() as u64,
        commit_generation: checkpoint_generation,
        content_root,
    };
    Ok((handle, recovered))
}

fn extent_kind_index(kind: ExtentKind) -> usize {
    match kind {
        ExtentKind::Blob => 0,
        ExtentKind::Catalog => 1,
        ExtentKind::Authority => 2,
        ExtentKind::Allocation => 3,
        ExtentKind::CatalogDelta => 4,
    }
}

#[allow(dead_code)]
fn _mutation_is_ambiguous<E>(failure: &MutationFailure<E>) -> bool {
    failure.certainty() == MutationCertainty::Ambiguous
}

const _: () = {
    assert!(CATALOG_ENTRY_LEN <= PAGE_SIZE);
};

#[cfg(test)]
mod transition_tests {
    use super::*;
    use crate::allocation_v2::RetiredSegment;

    #[test]
    fn recovery_decode_preflight_enforces_the_aggregate_ceiling() {
        recovery_preflight_decode::<()>(100, 40, 30, 30).unwrap();
        assert_eq!(
            recovery_preflight_decode::<()>(100, 40, 30, 31),
            Err(StoreError::MemoryLimit)
        );
        assert_eq!(
            recovery_remaining::<()>(100, 101),
            Err(StoreError::MemoryLimit)
        );
    }

    fn map(
        generation: u64,
        next_segment_generation: u64,
        states: &[SegmentAllocation],
        retired: &[RetiredSegment],
    ) -> AllocationV2 {
        AllocationV2::new(generation, next_segment_generation, 1, states, retired).unwrap()
    }

    #[test]
    fn checkpoint_pair_rejects_allocated_to_free_without_retirement_barrier() {
        let older = map(
            9,
            20,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        );
        let forged = map(
            10,
            21,
            &[
                SegmentAllocation::Free,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[],
        );
        assert_eq!(
            validate_allocation_checkpoint_transition::<()>(&older, &forged, 9, 10, 20, 21, 2,),
            Err(StoreError::Corrupt)
        );
    }

    #[test]
    fn checkpoint_pair_accepts_exact_relocation_and_reuse_transitions() {
        let older = map(
            9,
            20,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        );
        let relocated = map(
            10,
            21,
            &[
                SegmentAllocation::Retired,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 0,
                retire_generation: 10,
            }],
        );
        let reused = map(
            11,
            22,
            &[
                SegmentAllocation::Free,
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
            ],
            &[],
        );
        validate_allocation_checkpoint_transition::<()>(&older, &relocated, 9, 10, 20, 21, 2)
            .unwrap();
        validate_allocation_checkpoint_transition::<()>(&relocated, &reused, 10, 11, 21, 22, 2)
            .unwrap();
    }

    #[test]
    fn checkpoint_pair_accepts_one_ordinary_allocation() {
        let older = map(
            9,
            20,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        );
        let newer = map(
            10,
            21,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[],
        );
        validate_allocation_checkpoint_transition::<()>(&older, &newer, 9, 10, 20, 21, 2).unwrap();
    }

    #[test]
    fn checkpoint_pair_accepts_partial_low_live_relocation() {
        let older = map(
            9,
            20,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        );
        let forged = map(
            10,
            21,
            &[
                SegmentAllocation::Retired,
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 0,
                retire_generation: 10,
            }],
        );
        validate_allocation_checkpoint_transition::<()>(&older, &forged, 9, 10, 20, 21, 2).unwrap();
    }

    #[test]
    fn checkpoint_pair_rejects_partial_reclaim() {
        let older = map(
            10,
            20,
            &[
                SegmentAllocation::Retired,
                SegmentAllocation::Retired,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[
                RetiredSegment {
                    segment_no: 0,
                    retire_generation: 10,
                },
                RetiredSegment {
                    segment_no: 1,
                    retire_generation: 10,
                },
            ],
        );
        let forged = map(
            11,
            21,
            &[
                SegmentAllocation::Free,
                SegmentAllocation::Retired,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 1,
                retire_generation: 10,
            }],
        );
        assert_eq!(
            validate_allocation_checkpoint_transition::<()>(&older, &forged, 10, 11, 20, 21, 2,),
            Err(StoreError::Corrupt)
        );
    }

    #[test]
    fn checkpoint_pair_rejects_segment_generation_delta_mismatch() {
        let older = map(
            9,
            20,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[],
        );
        let forged = map(
            10,
            22,
            &[
                SegmentAllocation::Allocated,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[],
        );
        assert_eq!(
            validate_allocation_checkpoint_transition::<()>(&older, &forged, 9, 10, 20, 22, 2,),
            Err(StoreError::Corrupt)
        );
    }

    #[test]
    fn checkpoint_pair_rejects_reclaim_of_stale_retirement_generation() {
        let older = map(
            10,
            20,
            &[
                SegmentAllocation::Retired,
                SegmentAllocation::Free,
                SegmentAllocation::Free,
            ],
            &[RetiredSegment {
                segment_no: 0,
                retire_generation: 9,
            }],
        );
        let forged = map(
            11,
            21,
            &[
                SegmentAllocation::Free,
                SegmentAllocation::Allocated,
                SegmentAllocation::Free,
            ],
            &[],
        );
        assert_eq!(
            validate_allocation_checkpoint_transition::<()>(&older, &forged, 10, 11, 20, 21, 2,),
            Err(StoreError::Corrupt)
        );
    }
}
