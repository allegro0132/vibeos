//! Append, checkpoint, and bounded recovery state machine.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
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
    decode_persistent_authority_snapshot_bounded, PersistentAuthoritySnapshot,
    PERSISTENT_AUTHORITY_HEADER_LEN,
};
use crate::cas_codec::{
    decode_blob_manifest, decode_cas_delta, decode_cas_snapshot, BlobManifest, BlobMapping,
    CasSnapshot,
    CasDelta,
    CasCodecContext, ManifestExtent, ObjectMapping, BLOB_MANIFEST_HEADER_LEN, BLOB_MAPPING_LEN,
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

/// Every persistent file held open by a namespace pins its stream tail, so
/// this bounds how many files an open file tree can carry, not merely how
/// many reads are in flight. 2048 admits a thousand-file batch plus its
/// tree nodes and transaction-scoped pins without changing reserve semantics.
pub(crate) const ROOT_PIN_SLOTS: usize = 2048;
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
    #[cfg(feature = "experimental-authority-delta")]
    pub(crate) recovered_authority_depth: Option<u32>,
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
    /// Free segments whose final publication seal page is known to be
    /// durably zero: this generation's own publication wrote the zero and
    /// the checkpoint barrier that installed this state flushed it. A writer
    /// claiming one of them skips the zero-write + flush + read-back that
    /// otherwise precedes every scratch segment (one flush per checkpoint).
    /// Runtime knowledge only; every cold mount starts empty.
    pub(crate) durably_cleared_seals: alloc::collections::BTreeSet<u64>,
}

pub(crate) struct CheckpointTransitionWitness {
    superblock: Superblock,
    recovery_peak_bytes: usize,
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
    /// Move only the predecessor allocation into the transition proof; the
    /// unchanged catalogs and authority stay owned by the growth successor.
    pub(crate) fn replace_growth_allocation(state: &mut MountedState, allocation: AllocationV2) -> Self {
        Self {
            superblock: state.superblock,
            recovery_peak_bytes: state.recovery_peak_bytes,
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
            allocation: mem::replace(&mut state.allocation, allocation),
            last_segment: state.last_segment,
        }
    }

    pub(crate) fn from_mounted(state: MountedState) -> Self {
        Self {
            superblock: state.superblock,
            recovery_peak_bytes: state.recovery_peak_bytes,
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
    /// Runtime-only proof that every CAS payload/tree in this exact mounted
    /// generation passed a complete scrub or an equivalent verified successor.
    /// It is never reconstructed from checkpoint metadata alone.
    pub(crate) verified_cas_generation: AtomicU64,
    pub(crate) typed_reference_kinds: alloc::sync::Arc<Vec<u32>>,
    pub(crate) maintenance_domain: alloc::sync::Arc<MaintenanceDomain>,
    pub(crate) quota: Option<PrincipalQuotaTable>,
    /// Runtime cache of CAS blob keys whose payloads were verified against
    /// the logical record stream during a promotion readback. Entries are
    /// content-addressed and refer to immutable sealed segments, so the cache
    /// remains valid across in-process GC mounts and prevents the steady-state
    /// append path from re-verifying every historical object on each commit.
    pub(crate) promotion_verified: alloc::collections::BTreeSet<crate::cas_codec::BlobKey>,
    /// Runtime cache of CAS blob keys whose existing on-media manifest was
    /// fully compare-verified against freshly recomputed content hashes by a
    /// deduplicating commit. Sealed segments are immutable and a mismatch is
    /// already the fatal hash-collision path, so one verification per key per
    /// process carries the same guarantee as re-scanning on every duplicate.
    pub(crate) dedup_verified: alloc::collections::BTreeSet<crate::cas_codec::BlobKey>,
    /// Runtime cache of logical-object Merkle roots keyed by stable M4
    /// ObjectId with the (kind, exact length) they were computed for. A valid
    /// record stream never redefines an ObjectId's content, and every
    /// non-successor authority installation clears this cache, so an append
    /// does not re-hash the whole logical history on every commit.
    pub(crate) logical_roots:
        alloc::collections::BTreeMap<u128, (u32, u64, vibeos_blob_format::Hash)>,
    /// The committed M4 ObjectId set of the exact installed authority
    /// generation, captured at installation so a strict-successor append does
    /// not re-decode the whole predecessor stream to learn it.
    #[cfg(any(test, feature = "experimental-authority-delta"))]
    pub(crate) experimental_authority_base: Option<crate::authority_delta::VerifiedBaseForTest>,
    #[cfg(any(test, feature = "experimental-authority-delta"))]
    pub(crate) experimental_fused_authority_delta: bool,
    pub(crate) committed_ids_cache: Option<(u64, alloc::collections::BTreeSet<u128>)>,
    /// Promotion claims computed by the last live authority append, keyed by
    /// the exact logical stream they were computed against. A strict stream
    /// extension reuses them for still-unbound objects instead of re-running
    /// promotion over the whole committed set.
    pub(crate) promotion_claims_cache: Option<crate::persistent_authority::PromotionClaims>,
    /// Decoded successor trees of the last fused file transaction, keyed by
    /// the exact root they belong to.
    pub(crate) fs_tree_cache: Option<crate::fs_api::FsTreeCache>,
    /// See [`crate::fs_api::FsRootMemo`].
    pub(crate) fs_root_memo: Option<crate::fs_api::FsRootMemo>,
    /// When set, commits skip the publication-time read-back verification of
    /// the pages they just wrote. See [`SegmentStore::set_deferred_commit_readback`].
    pub(crate) defer_commit_readback: bool,
    /// Platform hot-content cache admission bound; zero disables eager proofs.
    pub(crate) hot_content_proof_max_bytes: u64,
    /// See [`SegmentStore::set_catalog_delta_policy`].
    pub(crate) catalog_delta_policy: crate::cas::CatalogDeltaPolicy,
    /// See [`VerifiedSegmentScans`]: chain-authentication memo for sealed
    /// segments, cleared around every collection round.
    pub(crate) verified_scans: VerifiedSegmentScans,
    /// See [`crate::gc::TypedEdgeCache`]: authenticated typed edges reused by
    /// later collection rounds in this process.
    pub(crate) typed_edge_cache: crate::gc::TypedEdgeCache,
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
            verified_cas_generation: AtomicU64::new(0),
            typed_reference_kinds: runtime.typed_reference_kinds,
            maintenance_domain: runtime.maintenance_domain,
            quota: runtime.quota,
            promotion_verified: alloc::collections::BTreeSet::new(),
            dedup_verified: alloc::collections::BTreeSet::new(),
            logical_roots: alloc::collections::BTreeMap::new(),
            committed_ids_cache: None,
            #[cfg(any(test, feature = "experimental-authority-delta"))]
            experimental_authority_base: None,
            #[cfg(any(test, feature = "experimental-authority-delta"))]
            experimental_fused_authority_delta: false,
            promotion_claims_cache: None,
            fs_tree_cache: None,
            fs_root_memo: None,
            defer_commit_readback: false,
            hot_content_proof_max_bytes: 0,
            catalog_delta_policy: crate::cas::CatalogDeltaPolicy::Auto,
            verified_scans: VerifiedSegmentScans::new(),
            typed_edge_cache: crate::gc::TypedEdgeCache::new(),
        }
    }

    /// Opt into experimental fused authority writes for this store instance.
    /// Requires an initialized authority snapshot. This research format is not
    /// readable by default builds; full publication-memory admission is pending.
    /// Merely compiling the feature enables reading, not writing, delta media.
    #[cfg(feature = "experimental-authority-delta")]
    pub fn enable_experimental_authority_delta(&mut self) -> Result<(), StoreError<D::Error>> {
        if self.require_current_generation()?.persistent_authority.is_none() {
            return Err(StoreError::Corrupt);
        }
        self.experimental_fused_authority_delta = true;
        Ok(())
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

    /// True when the store's continuable state is gone (a staged transaction
    /// failed or is still in flight) and only a fresh mount can proceed.
    /// Callers use this to distinguish a cleanly declined operation, which
    /// leaves the store serviceable, from an interrupted one.
    pub fn needs_remount(&self) -> bool {
        self.poisoned || self.mounted.is_none()
    }

    /// Select the commit-time verification profile. The default profile
    /// re-reads and verifies every page a commit just wrote before the
    /// successor mounts, failing the commit on any device write that was
    /// acknowledged but damaged. The deferred profile skips that read-back:
    /// every read path still fails closed on the content's Merkle identity
    /// and cold recovery re-verifies checkpoint state, so damaged data is
    /// never served as valid — it is simply detected at the first read or
    /// scrub instead of at the commit that wrote it.
    pub fn set_deferred_commit_readback(&mut self, deferred: bool) {
        self.defer_commit_readback = deferred;
    }

    /// Preverify new packed segments for objects admitted by an upper-layer
    /// content cache, whose hits may bypass CAS reads until collection. This
    /// is a performance policy only: normal scan validation is always used.
    /// Zero (the default) disables it; the bound includes the exact object size.
    pub fn set_hot_content_proof_max_bytes(&mut self, max_bytes: u64) {
        self.hot_content_proof_max_bytes = max_bytes;
    }

    /// Choose how commits publish catalog changes: complete snapshots or the
    /// frozen bounded-replay delta chain (see
    /// [`crate::cas::CatalogDeltaPolicy`]). `Auto` writes deltas only when
    /// they cost fewer pages than the snapshot they would replace, which is
    /// the case for every small transaction against a populated catalog.
    pub fn set_catalog_delta_policy(&mut self, policy: crate::cas::CatalogDeltaPolicy) {
        self.catalog_delta_policy = policy;
    }

    /// Diagnostics: `(cached objects, mark-walk hits, misses)` of the typed
    /// edge memo collection rounds reuse in this process.
    pub fn typed_edge_cache_stats(&self) -> (usize, u64, u64) {
        self.typed_edge_cache.stats()
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
        self.verified_cas_generation.store(0, Ordering::Release);
        // A fresh mount may observe different media; runtime verification
        // caches must not outlive the mounted state they were built against.
        self.promotion_verified.clear();
        self.dedup_verified.clear();
        self.logical_roots.clear();
        self.committed_ids_cache = None;
        #[cfg(any(test, feature = "experimental-authority-delta"))]
        { self.experimental_authority_base = None; }
        self.promotion_claims_cache = None;
        self.fs_tree_cache = None;
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
        // Reserve the entire optional memo before recovering either slot.
        // Retry without it on MemoryLimit so caching cannot reduce admission.
        const RECOVERY_MEMO_BYTES: usize = 64 * 1024;
        let memo = VerifiedSegmentScans::with_budget(RECOVERY_MEMO_BYTES, 32);
        let mut state = if let Some(remaining) = self.limits.recovery_memory_bytes.checked_sub(RECOVERY_MEMO_BYTES) {
            let cached_limits = StoreLimits { recovery_memory_bytes: remaining, ..self.limits };
            match recover_checkpoint_pair(&self.device, superblock, left, right,
                selected_generation, cached_limits, Some(&memo)).await {
                Ok(mut state) => {
                    debug_assert!(memo.allocated_bytes() <= RECOVERY_MEMO_BYTES);
                    state.recovery_peak_bytes = state.recovery_peak_bytes
                        .checked_add(RECOVERY_MEMO_BYTES).ok_or(StoreError::MemoryLimit)?;
                    drop(memo);
                    state
                }
                Err(StoreError::MemoryLimit) => {
                    drop(memo);
                    let mut state = recover_checkpoint_pair(&self.device, superblock, left, right,
                        selected_generation, self.limits, None).await?;
                    // The discarded attempt was independently bounded by this
                    // limit; retain that conservative peak across the retry.
                    state.recovery_peak_bytes = self.limits.recovery_memory_bytes;
                    state
                }
                Err(error) => return Err(error),
            }
        } else {
            drop(memo);
            recover_checkpoint_pair(&self.device, superblock, left, right,
                selected_generation, self.limits, None).await?
        };
        state.recovery_peak_bytes = state
            .recovery_peak_bytes
            .max(state.resident_heap_bytes().ok_or(StoreError::MemoryLimit)?);
        if state.recovery_peak_bytes > self.limits.recovery_memory_bytes {
            return Err(StoreError::MemoryLimit);
        }
        // Retain only bounded, fixed-size provenance from this successful
        // cold replay. Cache admission is optional and cannot reject a mount.
        #[cfg(feature = "experimental-authority-delta")]
        let recovered_witness = if let Some(depth) = state.recovered_authority_depth.take()
            .filter(|_| state.persistent_authority.as_ref()
                .is_some_and(|snapshot| snapshot.checkpoint_generation() == state.generation))
        {
            let resident = state.resident_heap_bytes().ok_or(StoreError::MemoryLimit)?;
            let workspace = self.limits.recovery_memory_bytes.checked_sub(resident).ok_or(StoreError::MemoryLimit)?;
            match crate::authority_delta::PreparedBaseForTest::prepare_with_peak(
                state.persistent_authority.as_ref().ok_or(StoreError::Corrupt)?, workspace) {
                Ok((prepared, peak)) => {
                    state.recovery_peak_bytes = state.recovery_peak_bytes.max(
                        resident.checked_add(peak).ok_or(StoreError::MemoryLimit)?);
                    Some(prepared.bind(&state, depth)?)
                }
                Err(StoreError::MemoryLimit) => {
                    state.recovery_peak_bytes = self.limits.recovery_memory_bytes;
                    None
                }
                Err(error) => return Err(error),
            }
        } else { None };
        let info = state.info();
        if !publish_runtime_generation(&self.published_generation, state.generation) {
            self.poisoned = true;
            return Err(StoreError::RecoveryRequired);
        }
        self.mounted = Some(state);
        #[cfg(feature = "experimental-authority-delta")]
        { self.experimental_authority_base = recovered_witness; }
        self.poisoned = false;
        Ok(info)
    }

    /// Install an ordinary commit successor without decoding the already
    /// mounted predecessor from media a second time. The successor is built
    /// only from the transaction bytes that were durably read back before its
    /// checkpoint was published; this method re-reads the publication pair and
    /// reduces the predecessor to the same allocation witness used by mount().
    pub(crate) async fn mount_verified_successor(
        &mut self,
        previous: MountedState,
        expected: Checkpoint,
        successor: MountedState,
        verifies_all_cas: bool,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        self.mount_verified_successor_witness(
            CheckpointTransitionWitness::from_mounted(previous), expected, successor, verifies_all_cas, 0,
        ).await
    }

    pub(crate) async fn mount_verified_successor_witness(
        &mut self,
        previous: CheckpointTransitionWitness,
        expected: Checkpoint,
        mut successor: MountedState,
        verifies_all_cas: bool,
        operation_peak: usize,
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
        // One batched read serves both superblock pairs and both checkpoint
        // slots; the decode path below is unchanged.
        let anchor = crate::cas::SpanSnapshotDevice::capture(&self.device, &[(0, 8)]).await?;
        let selected_super = select_superblock(
            read_superblock(&anchor, 0).await?,
            read_superblock(&anchor, 2).await?,
        )?
        .ok_or(StoreError::Unformatted)?;
        if selected_super.value() != &previous.superblock {
            return Err(StoreError::Corrupt);
        }

        let left = read_checkpoint(&anchor, 4).await?;
        let right = read_checkpoint(&anchor, 6).await?;
        let selected =
            select_checkpoint_for_superblock(selected_super, left, right, device_info.page_count)?
                .ok_or(StoreError::Unformatted)?;
        if selected.value() != &expected {
            return Err(StoreError::Corrupt);
        }
        let predecessor =
            if expected.slot == 0 { right } else { left }.ok_or(StoreError::Corrupt)?;
        if !checkpoint_matches_witness(predecessor.value(), &previous, self.limits) {
            return Err(StoreError::Corrupt);
        }
        if !checkpoint_matches_mounted(&expected, &successor, self.limits) {
            return Err(StoreError::Corrupt);
        }

        let predecessor_cas_verified =
            self.verified_cas_generation.load(Ordering::Acquire) == previous.generation;
        let previous_peak = previous.recovery_peak_bytes;
        let witness = previous;
        let witness_bytes = witness.resident_bytes().ok_or(StoreError::MemoryLimit)?;
        validate_checkpoint_transition(&witness, &successor)?;
        let pair_peak = witness_bytes
            .checked_add(successor.recovery_peak_bytes)
            .ok_or(StoreError::MemoryLimit)?;
        successor.recovery_peak_bytes = previous_peak.max(pair_peak).max(operation_peak).max(
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
        self.verified_cas_generation.store(
            if predecessor_cas_verified && verifies_all_cas {
                expected.binding.generation
            } else {
                0
            },
            Ordering::Release,
        );
        self.poisoned = false;
        Ok(info)
    }

    pub(crate) fn cas_payloads_verified(&self, generation: u64) -> bool {
        self.verified_cas_generation.load(Ordering::Acquire) == generation
    }

    pub fn current_cas_payloads_verified(&self) -> bool {
        self.mounted
            .as_ref()
            .is_some_and(|state| self.cas_payloads_verified(state.generation))
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
            None,
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

fn checkpoint_matches_witness(
    checkpoint: &Checkpoint,
    state: &CheckpointTransitionWitness,
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
        self.find_free_run_with_headroom(required, 0, may_use_reserve)
    }

    /// Reserve extra free capacity without requiring adjacency to the run.
    pub(crate) fn find_free_run_with_headroom(
        &self,
        required: u64,
        extra: u64,
        may_use_reserve: bool,
    ) -> Option<u64> {
        self.find_free_run_in(&self.allocation, self.next_physical_segment, required, extra, may_use_reserve)
    }

    // Share the exact placement policy with a provisional allocation without
    // cloning unrelated authority/catalog state merely to substitute two fields.
    pub(crate) fn find_free_run_in(
        &self,
        allocation: &AllocationV2,
        next_physical_segment: u64,
        required: u64,
        extra: u64,
        may_use_reserve: bool,
    ) -> Option<u64> {
        if required == 0 {
            return None;
        }
        let reserved = required.checked_add(extra)?;
        let free = allocation.counts().ok()?.free;
        let ordinary_floor = u64::from(self.cleaner_reserve_segments)
            .checked_add(u64::from(ROOT_POLICY_HEADROOM_SEGMENTS))?;
        if free < reserved || (!may_use_reserve && free.checked_sub(reserved)? < ordinary_floor) {
            return None;
        }
        if self.allocation_version == 1 {
            let end = next_physical_segment.checked_add(required)?;
            if end > self.admitted_segments {
                return None;
            }
            return (next_physical_segment..end)
                .all(|segment_no| {
                    allocation.segment_state(segment_no) == Some(SegmentAllocation::Free)
                })
                .then_some(next_physical_segment);
        }
        let mut run_start = 0_u64;
        let mut run_len = 0_u64;
        for segment_no in 0..self.admitted_segments {
            if allocation.segment_state(segment_no) == Some(SegmentAllocation::Free) {
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
) -> Result<Box<[Page; 2]>, StoreError<D::Error>> {
    let mut pages = alloc::vec![[0; PAGE_SIZE]; 2].into_boxed_slice();
    device
        .read_pages(body_page, &mut pages)
        .await
        .map_err(StoreError::Device)?;
    pages.try_into().map_err(|_| StoreError::Corrupt)
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
    let pages = read_pair(device, page).await?;
    Ok(optional_verified(decode_superblock_verified(
        &pages[0], &pages[1],
    )?))
}

pub(crate) async fn read_checkpoint<D: PageDevice>(
    device: &D,
    page: u64,
) -> Result<Option<VerifiedRecord<Checkpoint>>, StoreError<D::Error>> {
    let pages = read_pair(device, page).await?;
    Ok(optional_verified(decode_checkpoint_verified(
        &pages[0], &pages[1],
    )?))
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
    let observed = read_pair(device, body_page).await?;
    match decode_checkpoint_verified(&observed[0], &observed[1])? {
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
    additional_matches: Vec<ExtentRecord>,
    authority_siblings: Vec<ExtentRecord>,
    descriptor_peak_bytes: usize,
    pub(crate) record_count: u32,
    pub(crate) total_payload_bytes: u64,
    pub(crate) segment_seal_body_sha256: [u8; 32],
    pub(crate) previous_segment: (u64, u64, [u8; 32]),
    pub(crate) header_target_checkpoint_generation: u64,
}

/// Session-scoped memo of segments whose complete descriptor/summary/seal
/// chain [`scan_segment_with_matches`] has already authenticated. A sealed
/// segment is immutable for its exact `(segment_no, generation)` key, so —
/// exactly like the promotion/dedup verification caches on `SegmentStore` —
/// one chain authentication per process carries the same guarantee as
/// re-walking the whole chain on every pointer dereference, which measures
/// as the dominant read amplification of small-store commits. Collection is
/// the only path that retires and eventually reuses segment numbers, so the
/// memo drops retired/freed segments around GC; cold scrub and migration
/// passes never consult it.
pub(crate) struct VerifiedSegmentScans {
    entries: ScanMemoCell,
    byte_budget: usize,
    entry_limit: usize,
}

struct ScanMemoCell(core::cell::RefCell<alloc::collections::VecDeque<ScanMemoEntry>>);

// Safety: the memo lives inside `SegmentStore`, whose every operation runs
// through `&mut self`, and shared kernel handles serialize all store access
// behind one active-operation claim (the same argument as the kernel's
// `StableSegmentStore`). Every borrow below is taken and released within one
// synchronous call — none is held across an await point.
unsafe impl Sync for ScanMemoCell {}
unsafe impl Send for ScanMemoCell {}

/// Everything a chain walk proves about one sealed segment, independent of
/// which extent the caller asked for.
struct VerifiedSegment {
    extents: Vec<ExtentRecord>,
    record_count: u32,
    total_payload_bytes: u64,
    segment_seal_body_sha256: [u8; 32],
    previous_segment: (u64, u64, [u8; 32]),
    header_target_checkpoint_generation: u64,
    last_target_checkpoint_generation: u64,
}

/// Bounded so a large store cannot grow the memo without limit; eviction is
/// least-recently-used and only costs a re-walk on the next access.
const VERIFIED_SEGMENT_SCAN_CAPACITY: usize = 256;
// Bounds requested resident allocation bytes, including queue capacity and
// all extent Vec capacities. Allocator bookkeeping/rounding is platform-owned.
const VERIFIED_SEGMENT_SCAN_BYTE_BUDGET: usize = 320 * 1024;

type ScanMemoEntry = ((u64, u64), VerifiedSegment);

fn scan_extent_bytes(verified: &VerifiedSegment) -> usize {
    verified.extents.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
        .unwrap_or(usize::MAX)
}

impl VerifiedSegmentScans {
    pub(crate) fn new() -> Self {
        Self::with_budget(VERIFIED_SEGMENT_SCAN_BYTE_BUDGET, VERIFIED_SEGMENT_SCAN_CAPACITY)
    }

    /// A recovery-local memo can use a smaller fixed reservation than the
    /// session cache. An undersized budget disables caching, not validation.
    pub(crate) fn with_budget(byte_budget: usize, entry_limit: usize) -> Self {
        let entry_limit = entry_limit.min(VERIFIED_SEGMENT_SCAN_CAPACITY)
            .min(byte_budget / core::mem::size_of::<ScanMemoEntry>());
        Self {
            entries: ScanMemoCell(core::cell::RefCell::new(alloc::collections::VecDeque::new())),
            byte_budget: byte_budget.min(VERIFIED_SEGMENT_SCAN_BYTE_BUDGET),
            entry_limit,
        }
    }

    /// Reserve the complete memo allowance across reads, including later growth.
    #[cfg(any(test, feature = "experimental-authority-delta"))]
    pub(crate) fn reservation_bytes(&self) -> usize {
        self.byte_budget
    }

    pub(crate) fn allocated_bytes(&self) -> usize {
        let entries = self.entries.0.borrow();
        entries.capacity().saturating_mul(core::mem::size_of::<ScanMemoEntry>())
            .saturating_add(entries.iter().map(|(_, proof)| scan_extent_bytes(proof)).sum::<usize>())
    }

    pub(crate) fn clear(&self) {
        self.entries.0.borrow_mut().clear();
    }

    /// Run `interpret` against the cached proof for this exact sealed
    /// segment, if present and provable at the caller's checkpoint horizon.
    fn with_verified<T>(
        &self,
        segment_no: u64,
        segment_generation: u64,
        checkpoint_generation: u64,
        interpret: impl FnOnce(&VerifiedSegment) -> T,
    ) -> Option<T> {
        let mut entries = self.entries.0.borrow_mut();
        let position = entries.iter().position(|(key, _)| *key == (segment_no, segment_generation))?;
        let cached = &entries[position].1;
        if cached.header_target_checkpoint_generation > checkpoint_generation
            || cached.last_target_checkpoint_generation > checkpoint_generation
        {
            return None;
        }
        let entry = entries.remove(position).expect("located cached segment");
        entries.push_back(entry);
        Some(interpret(&entries.back().expect("promoted cached segment").1))
    }

    /// Drop every entry whose segment is no longer Allocated: only such
    /// segments can be handed back to a writer and later re-sealed under a
    /// fresh generation, so proofs for them must not outlive the round that
    /// freed them. Allocated sealed segments remain immutable and provable.
    pub(crate) fn retain_allocated(&self, allocation: &crate::allocation_v2::AllocationV2) {
        self.entries.0.borrow_mut().retain(|((segment_no, _), _)| {
            matches!(
                allocation.segment_state(*segment_no),
                Some(crate::allocation_v2::SegmentAllocation::Allocated)
            )
        });
    }

    fn insert(&self, segment_no: u64, segment_generation: u64, verified: VerifiedSegment) {
        if self.entry_limit == 0 { return; }
        let mut entries = self.entries.0.borrow_mut();
        let key = (segment_no, segment_generation);
        if let Some(position) = entries.iter().position(|(cached, _)| *cached == key) {
            entries.remove(position);
        }
        let incoming = scan_extent_bytes(&verified);
        let minimum_queue = self.entry_limit * core::mem::size_of::<ScanMemoEntry>();
        if incoming > self.byte_budget.saturating_sub(minimum_queue) {
            return; // A proof too large to memoize remains valid for this read.
        }
        if entries.capacity() == 0
            && entries.try_reserve_exact(self.entry_limit).is_err()
        {
            return; // Optional memo allocation must not fail a verified read.
        }
        let queue_bytes = entries.capacity().checked_mul(core::mem::size_of::<ScanMemoEntry>())
            .unwrap_or(usize::MAX);
        if queue_bytes > self.byte_budget {
            *entries = alloc::collections::VecDeque::new();
            return;
        }
        let available = self.byte_budget - queue_bytes;
        if incoming > available { return; }
        let mut resident = entries.iter().fold(0usize, |bytes, (_, proof)| {
            bytes.saturating_add(scan_extent_bytes(proof))
        });
        while entries.len() >= self.entry_limit || resident > available - incoming {
            let (_, evicted) = entries.pop_front().expect("memo eviction candidate");
            resident = resident.saturating_sub(scan_extent_bytes(&evicted));
        }
        entries.push_back((key, verified));
    }
}

#[cfg(test)]
mod scan_memo_tests {
    use super::*;

    #[test]
    fn scan_result_budget_includes_retained_table_and_reallocation() {
        let item = core::mem::size_of::<ExtentRecord>();
        let retained = 7 * item;
        let mut result = Vec::new();
        assert!(matches!(reserve_scan_results::<()>(&mut result, 2, retained, retained + 2 * item - 1),
            Err(StoreError::MemoryLimit)));
        assert_eq!(result.capacity(), 0);
        reserve_scan_results::<()>(&mut result, 2, retained, retained + 2 * item).unwrap();
        let old = result.capacity() * item;
        // The vector need not be populated to force growth beyond its capacity.
        let more = result.capacity() + 1;
        let peak = retained + old + more * item;
        assert!(matches!(reserve_scan_results::<()>(&mut result, more, retained, peak - 1),
            Err(StoreError::MemoryLimit)));
        assert_eq!(result.capacity() * item, old);
        reserve_scan_results::<()>(&mut result, more, retained, peak).unwrap();
        assert_eq!(result.capacity(), more);
        assert!(matches!(reserve_scan_results::<()>(&mut result, 0, retained, retained),
            Err(StoreError::MemoryLimit)), "existing spare capacity must still be charged");
    }


    #[test]
    fn scan_descriptor_budget_rejects_before_reservation() {
        let exact = 3 * core::mem::size_of::<ExtentRecord>();
        let mut table = Vec::new();
        assert!(matches!(reserve_scan_descriptors::<()>(&mut table, 3, exact - 1),
            Err(StoreError::MemoryLimit)));
        assert_eq!(table.capacity(), 0);
        assert!(matches!(reserve_scan_descriptors::<()>(&mut table, usize::MAX, usize::MAX),
            Err(StoreError::MemoryLimit)));
        assert_eq!(table.capacity(), 0);
        reserve_scan_descriptors::<()>(&mut table, 3, exact).unwrap();
        assert_eq!(table.capacity() * core::mem::size_of::<ExtentRecord>(), exact);
    }


    fn proof_with_capacity(capacity: usize) -> VerifiedSegment {
        VerifiedSegment {
            extents: Vec::with_capacity(capacity),
            record_count: 0,
            total_payload_bytes: 0,
            segment_seal_body_sha256: [0; 32],
            previous_segment: (0, 0, [0; 32]),
            header_target_checkpoint_generation: 1,
            last_target_checkpoint_generation: 2,
        }
    }

    fn resident_bytes(memo: &VerifiedSegmentScans) -> usize {
        let entries = memo.entries.0.borrow();
        entries.capacity() * core::mem::size_of::<ScanMemoEntry>()
            + entries.iter().map(|(_, p)| scan_extent_bytes(p)).sum::<usize>()
    }

    #[test]
    fn scan_peak_reports_retained_capacity_without_matches() {
        let verified = proof_with_capacity(7);
        let bytes = scan_extent_bytes(&verified);
        let pointer = PointerValue {
            store_uuid: StoreUuid::new([7;16]).unwrap(), segment_no: 0, segment_generation: 1,
            descriptor_relative_page: 0, payload_relative_page: 0, payload_pages: 1,
            ordinal: 0, exact_byte_len: 1, extent_kind: ExtentKind::Authority,
            payload_sha256: [0;32],
        };
        let scanned = interpret_verified_extents::<()>(&verified, 0, pointer, &[], false, None, bytes).unwrap();
        assert_eq!(scanned.descriptor_peak_bytes, bytes);
        assert!(scanned.authority_siblings.is_empty());
        assert!(matches!(interpret_verified_extents::<()>(&verified, 0, pointer, &[], false, None, bytes - 1),
            Err(StoreError::MemoryLimit)));
    }

    #[test]
    fn recovery_memo_small_budget_and_checkpoint_horizon() {
        let disabled = VerifiedSegmentScans::with_budget(0, 32);
        disabled.insert(0, 1, proof_with_capacity(1));
        assert_eq!(disabled.allocated_bytes(), 0);
        assert!(disabled.with_verified(0, 1, 2, |_| ()).is_none());
        let limit = 8 * 1024;
        let memo = VerifiedSegmentScans::with_budget(limit, 8);
        assert_eq!(memo.allocated_bytes(), 0);
        assert_eq!(memo.reservation_bytes(), limit, "empty memo still needs its growth allowance");
        for segment in 0..64 {
            memo.insert(segment, 1, proof_with_capacity(4));
            assert!(memo.allocated_bytes() <= limit);
            assert_eq!(memo.reservation_bytes(), limit);
        }
        assert!(memo.with_verified(63, 1, 1, |_| ()).is_none(), "future proof must miss");
        assert!(memo.with_verified(63, 2, 2, |_| ()).is_none(), "different seal generation must miss");
        assert!(memo.with_verified(63, 1, 2, |_| ()).is_some());
        assert!(memo.with_verified(0, 1, 2, |_| ()).is_none(), "old proof must be evicted");
        memo.insert(65, 1, proof_with_capacity(1024));
        assert!(memo.allocated_bytes() <= limit);
        assert!(memo.with_verified(65, 1, 2, |_| ()).is_none(), "oversized proof is optional");
    }

    #[test]
    fn scan_memo_budget_charges_capacity_and_evicts_lru() {
        let memo = VerifiedSegmentScans::new();
        memo.insert(0, 1, proof_with_capacity(0));
        let queue = resident_bytes(&memo);
        memo.clear();
        assert_eq!(resident_bytes(&memo), queue);
        let available = VERIFIED_SEGMENT_SCAN_BYTE_BUDGET - queue;
        let extent_size = core::mem::size_of::<ExtentRecord>();
        let half = available / 2 / extent_size;
        memo.insert(1, 1, proof_with_capacity(half));
        memo.insert(2, 1, proof_with_capacity(half));
        assert_eq!(memo.with_verified(1, 1, 2, |_| ()), Some(()));
        let extra = (available - 2 * half * extent_size) / extent_size + 1;
        memo.insert(3, 1, proof_with_capacity(extra));
        assert_eq!(memo.with_verified(2, 1, 2, |_| ()), None);
        assert_eq!(memo.with_verified(1, 1, 2, |_| ()), Some(()));
        assert_eq!(memo.with_verified(3, 1, 2, |_| ()), Some(()));
        assert!(resident_bytes(&memo) <= VERIFIED_SEGMENT_SCAN_BYTE_BUDGET);
        // Empty vectors with reserved capacity consume the full byte budget.
        assert!(memo.entries.0.borrow().iter().all(|(_, p)| p.extents.is_empty()));
        memo.insert(1, 1, proof_with_capacity(0));
        memo.insert(4, 1, proof_with_capacity(half));
        assert_eq!(memo.with_verified(3, 1, 2, |_| ()), Some(()));
        assert!(resident_bytes(&memo) <= VERIFIED_SEGMENT_SCAN_BYTE_BUDGET);
        use crate::allocation_v2::{AllocationV2, SegmentAllocation};
        let states = [SegmentAllocation::Free, SegmentAllocation::Allocated,
            SegmentAllocation::Free, SegmentAllocation::Free, SegmentAllocation::Free];
        memo.retain_allocated(&AllocationV2::new(2, 10, 2, &states, &[]).unwrap());
        assert_eq!(memo.entries.0.borrow().len(), 1);
        memo.insert(5, 1, proof_with_capacity(available / extent_size));
        assert_eq!(memo.with_verified(1, 1, 2, |_| ()), Some(()));
        assert!(resident_bytes(&memo) <= VERIFIED_SEGMENT_SCAN_BYTE_BUDGET);
    }

    #[test]
    fn oversized_scan_proof_is_not_retained() {
        let memo = VerifiedSegmentScans::new();
        let oversized = VERIFIED_SEGMENT_SCAN_BYTE_BUDGET / core::mem::size_of::<ExtentRecord>() + 1;
        memo.insert(1, 1, proof_with_capacity(oversized));
        assert_eq!(resident_bytes(&memo), 0);
        memo.insert(1, 1, proof_with_capacity(0));
        memo.insert(2, 1, proof_with_capacity(1));
        memo.insert(1, 1, proof_with_capacity(oversized));
        assert_eq!(memo.with_verified(1, 1, 2, |_| ()), None);
        assert_eq!(memo.with_verified(2, 1, 2, |_| ()), Some(()));
        assert!(resident_bytes(&memo) <= VERIFIED_SEGMENT_SCAN_BYTE_BUDGET);
    }

    #[test]
    fn scan_memo_evicts_unused_entries_and_preserves_proof_identity() {
        let memo = VerifiedSegmentScans::new();
        let verified = || VerifiedSegment {
            extents: Vec::new(),
            record_count: 0,
            total_payload_bytes: 0,
            segment_seal_body_sha256: [0; 32],
            previous_segment: (0, 0, [0; 32]),
            header_target_checkpoint_generation: 1,
            last_target_checkpoint_generation: 2,
        };
        for segment in 0..VERIFIED_SEGMENT_SCAN_CAPACITY as u64 {
            memo.insert(segment, 1, verified());
        }
        assert_eq!(memo.with_verified(0, 2, 2, |_| ()), None);
        assert_eq!(memo.with_verified(0, 1, 1, |_| ()), None);
        assert_eq!(memo.with_verified(0, 1, 2, |_| ()), Some(()));
        let next = VERIFIED_SEGMENT_SCAN_CAPACITY as u64;
        memo.insert(next, 1, verified());
        assert_eq!(memo.with_verified(1, 1, 2, |_| ()), None);
        assert_eq!(memo.with_verified(0, 1, 2, |_| ()), Some(()));
        // Replacing a cached key must not evict an unrelated proof.
        memo.insert(next, 1, verified());
        assert_eq!(memo.entries.0.borrow().len(), VERIFIED_SEGMENT_SCAN_CAPACITY);
        assert_eq!(memo.with_verified(2, 1, 2, |_| ()), Some(()));
        use crate::allocation_v2::{AllocationV2, RetiredSegment, SegmentAllocation};
        let mut states = [SegmentAllocation::Free; VERIFIED_SEGMENT_SCAN_CAPACITY];
        states[0] = SegmentAllocation::Allocated;
        states[2] = SegmentAllocation::Retired;
        let allocation = AllocationV2::new(2, 50, 6, &states,
            &[RetiredSegment { segment_no: 2, retire_generation: 2 }]).unwrap();
        memo.retain_allocated(&allocation);
        assert_eq!(memo.entries.0.borrow().len(), 1);
        assert_eq!(memo.with_verified(0, 1, 2, |_| ()), Some(()));
        assert_eq!(memo.with_verified(2, 1, 2, |_| ()), None);
        assert_eq!(memo.with_verified(next, 1, 2, |_| ()), None);
        memo.clear();
        assert_eq!(memo.with_verified(0, 1, 2, |_| ()), None);
    }
}

// Uncached ordinal-zero probes with no match/sibling requests retain no
// descriptor table. Their two four-page I/O windows are the heap workspace.
pub(crate) const SEGMENT_PROBE_PAGE_WORKSPACE_BYTES: usize = 8 * PAGE_SIZE;

pub(crate) async fn scan_segment<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PointerValue,
    memo: Option<&VerifiedSegmentScans>,
) -> Result<ScannedSegment, StoreError<D::Error>> {
    scan_segment_with_matches(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        &[],
        false,
        None,
        memo,
        false,
        usize::MAX,
    )
    .await
}

// Full media verification never consumes or populates a metadata-only memo.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_segment_for_scrub<D: PageDevice>(
    device: &D, store_uuid: StoreUuid, admitted_segments: u64,
    next_segment_generation: u64, checkpoint_generation: u64, segment_no: u64,
) -> Result<ScannedSegment, StoreError<D::Error>> {
    // Scrub discovers the generation from the same authenticated header that
    // starts the full scan, rather than issuing a separate header-pair read.
    let pointer = PointerValue {
        store_uuid, segment_no, segment_generation: 0,
        descriptor_relative_page: 0, payload_relative_page: 0, payload_pages: 1,
        ordinal: 0, exact_byte_len: 1, extent_kind: ExtentKind::Blob,
        payload_sha256: [0; 32],
    };
    scan_segment_with_matches(device, store_uuid, admitted_segments,
        next_segment_generation, checkpoint_generation, pointer, &[], false, None, None, true, usize::MAX).await
}

pub(crate) async fn verify_payload_and_zero_padding<D: PageDevice>(
    device: &D,
    first_page: u64,
    payload_pages: u32,
    exact_byte_len: u64,
    expected_sha256: [u8; 32],
) -> Result<(), StoreError<D::Error>> {
    use sha2::{Digest, Sha256};
    if exact_byte_len == 0 || u64::from(payload_pages) != exact_byte_len.div_ceil(PAGE_SIZE as u64)
    {
        return Err(StoreError::Corrupt);
    }
    let mut remaining = exact_byte_len;
    let mut hasher = Sha256::new();
    // Keep the batch within scrub's existing two-page streaming workspace.
    // The final read is shortened so it never crosses this extent's payload.
    let mut pages = Box::new([[0; PAGE_SIZE]; 2]);
    let mut page_index = 0_u64;
    while page_index < u64::from(payload_pages) {
        let count = (u64::from(payload_pages) - page_index).min(pages.len() as u64) as usize;
        device.read_pages(
            first_page.checked_add(page_index).ok_or(StoreError::Corrupt)?,
            &mut pages[..count],
        ).await.map_err(StoreError::Device)?;
        for page in &pages[..count] {
            let take = usize::try_from(remaining.min(PAGE_SIZE as u64)).map_err(|_| StoreError::Corrupt)?;
            hasher.update(&page[..take]);
            if page[take..].iter().any(|byte| *byte != 0) {
                return Err(StoreError::Corrupt);
            }
            remaining -= take as u64;
        }
        page_index += count as u64;
    }
    let observed: [u8; 32] = hasher.finalize().into();
    if remaining != 0 || observed != expected_sha256 {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

// Even an individually sealed summary must describe a physically possible
// extent population before its count is allowed to size an allocation.
fn validate_scan_summary_geometry<E>(summary: &SegmentSummary) -> Result<(), StoreError<E>> {
    let occupied = summary.next_free_page.checked_sub(DATA_FIRST_PAGE).ok_or(StoreError::Corrupt)?;
    let described = summary.record_count.checked_mul(2)
        .and_then(|pages| pages.checked_add(summary.payload_page_count)).ok_or(StoreError::Corrupt)?;
    if summary.next_free_page > DATA_END_PAGE
        || summary.payload_page_count < summary.record_count
        || described != occupied
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

// Bound the retained scan table before allocation. Summary geometry is
// validated by the caller; allocator capacity is checked again afterwards.
fn reserve_scan_descriptors<E>(table: &mut Vec<ExtentRecord>, count: usize, limit: usize)
    -> Result<(), StoreError<E>> {
    let size = core::mem::size_of::<ExtentRecord>();
    let requested = count.checked_mul(size).ok_or(StoreError::MemoryLimit)?;
    if requested > limit { return Err(StoreError::MemoryLimit); }
    table.try_reserve_exact(count).map_err(|_| StoreError::MemoryLimit)?;
    if table.capacity().checked_mul(size).is_none_or(|bytes| bytes > limit) {
        return Err(StoreError::MemoryLimit);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn scan_segment_with_matches<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    mut pointer: PointerValue,
    additional: &[PointerValue],
    collect_authority_siblings: bool,
    authority_generation: Option<(u64, usize)>,
    memo: Option<&VerifiedSegmentScans>,
    verify_payloads: bool,
    descriptor_limit: usize,
) -> Result<ScannedSegment, StoreError<D::Error>> {
    if verify_payloads && (memo.is_some() || pointer.ordinal != 0
        || !additional.is_empty() || collect_authority_siblings || authority_generation.is_some())
    {
        return Err(StoreError::Corrupt);
    }
    if pointer.store_uuid != store_uuid
        || pointer.segment_no >= admitted_segments
        || (!verify_payloads && (pointer.segment_generation == 0
            || pointer.segment_generation >= next_segment_generation))
    {
        return Err(StoreError::Corrupt);
    }
    let base = segment_base_page(pointer.segment_no)?;
    if let Some(memo) = memo {
        if let Some(interpreted) = memo.with_verified(
            pointer.segment_no,
            pointer.segment_generation,
            checkpoint_generation,
            |verified| {
                interpret_verified_extents(
                    verified,
                    base,
                    pointer,
                    additional,
                    collect_authority_siblings,
                    authority_generation,
                    descriptor_limit,
                )
            },
        ) {
            return interpreted;
        }
    }
    // Every referenced segment starts with a header pair followed by its
    // first descriptor pair. Reuse the latter half for subsequent descriptors.
    const _: () = assert!(DATA_FIRST_PAGE == 2);
    let mut header_pages = alloc::vec![[0; PAGE_SIZE]; 4].into_boxed_slice();
    device.read_pages(base, &mut header_pages).await.map_err(StoreError::Device)?;
    let header = match decode_segment_header_verified(&header_pages[0], &header_pages[1])? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    if verify_payloads {
        let generation = header.value().binding.generation;
        if generation == 0 || generation >= next_segment_generation {
            return Err(StoreError::Corrupt);
        }
        pointer.segment_generation = generation;
    }
    if header.value().binding.store_uuid != store_uuid
        || header.value().binding.segment_no != pointer.segment_no
        || header.value().binding.generation != pointer.segment_generation
        || header.value().binding.target_checkpoint_generation > checkpoint_generation
    {
        return Err(StoreError::Corrupt);
    }

    // Summary and final seal are adjacent immutable pairs. Fetch their four
    // pages together while still authenticating each body/seal independently.
    const _: () = assert!(SEGMENT_SEAL_BODY_PAGE == SUMMARY_BODY_PAGE + 2);
    let mut trailer = alloc::vec![[0; PAGE_SIZE]; 4].into_boxed_slice();
    device
        .read_pages(base + u64::from(SUMMARY_BODY_PAGE), &mut trailer)
        .await
        .map_err(StoreError::Device)?;
    let summary = match decode_segment_summary_verified(&trailer[0], &trailer[1])? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    let segment_seal =
        match decode_segment_seal_verified(&trailer[2], &trailer[3])? {
            DecodeStatus::Sealed(value) => value,
            _ => return Err(StoreError::Corrupt),
        };
    // VerifiedRecord owns both decoded fields and digests. Raw trailer pages
    // are no longer needed while accumulating the extent proof vector.
    drop(trailer);

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
    validate_scan_summary_geometry(summary.value())?;
    // Ordinal zero is a metadata-only segment probe, never an extent. With
    // no requested matches/siblings and no cache to populate, stream every
    // descriptor into the chain checks without retaining a duplicate table.
    let retain_extents = memo.is_some() || pointer.ordinal != 0
        || !additional.is_empty() || collect_authority_siblings || authority_generation.is_some();
    let mut extents = Vec::new();
    if retain_extents {
        reserve_scan_descriptors(&mut extents, summary.value().record_count as usize, descriptor_limit)?;
    }
    for ordinal in 1..=summary.value().record_count {
        if ordinal != 1 {
            device
                .read_pages(base + u64::from(relative), &mut header_pages[2..])
                .await
                .map_err(StoreError::Device)?;
        }
        let extent = match decode_extent_verified(&header_pages[2], &header_pages[3])? {
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
        let next_relative = relative.checked_add(value.record_span_pages)
            .filter(|next| *next <= summary.value().next_free_page && *next <= DATA_END_PAGE)
            .ok_or(StoreError::Corrupt)?;
        if verify_payloads {
            verify_payload_and_zero_padding(device,
                base.checked_add(u64::from(value.payload_first_relative_page)).ok_or(StoreError::Corrupt)?,
                value.payload_pages, value.payload_byte_len, value.payload_sha256).await?;
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
        if retain_extents { extents.push(value); }
        relative = next_relative;
    }
    // Descriptor pairs have been decoded and accumulated; release their
    // page window before interpreting matches or inserting the final proof.
    drop(header_pages);
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
    let verified = VerifiedSegment {
        extents,
        record_count: summary_value.record_count,
        total_payload_bytes: summary_value.total_payload_bytes,
        segment_seal_body_sha256: segment_seal.digest().body_sha256(),
        previous_segment: (
            header.value().previous_segment_no,
            header.value().previous_segment_generation,
            header.value().previous_segment_seal_body_sha256,
        ),
        header_target_checkpoint_generation: header.value().binding.target_checkpoint_generation,
        last_target_checkpoint_generation: last_target,
    };
    let interpreted = interpret_verified_extents(
        &verified,
        base,
        pointer,
        additional,
        collect_authority_siblings,
        authority_generation,
        descriptor_limit,
    );
    if let Some(memo) = memo {
        memo.insert(pointer.segment_no, pointer.segment_generation, verified);
    }
    interpreted
}

// Include existing result capacity and possible old/new allocation overlap.
// `retained` is the independently live scan table plus other result vectors.
fn reserve_scan_results<E>(result: &mut Vec<ExtentRecord>, additional: usize,
    retained: usize, limit: usize) -> Result<usize, StoreError<E>> {
    let item = core::mem::size_of::<ExtentRecord>();
    let needed = result.len().checked_add(additional).ok_or(StoreError::MemoryLimit)?;
    let old = result.capacity().checked_mul(item).ok_or(StoreError::MemoryLimit)?;
    let resident = retained.checked_add(old).ok_or(StoreError::MemoryLimit)?;
    if resident > limit { return Err(StoreError::MemoryLimit); }
    if needed <= result.capacity() { return Ok(resident); }
    let requested = needed.checked_mul(item).ok_or(StoreError::MemoryLimit)?;
    if resident.checked_add(requested).is_none_or(|bytes| bytes > limit) {
        return Err(StoreError::MemoryLimit);
    }
    result.try_reserve_exact(additional).map_err(|_| StoreError::MemoryLimit)?;
    let actual = result.capacity().checked_mul(item).ok_or(StoreError::MemoryLimit)?;
    if resident.checked_add(actual).is_none_or(|bytes| bytes > limit) {
        return Err(StoreError::MemoryLimit);
    }
    Ok(resident + actual)
}

/// Resolve one scan request against a segment's already-authenticated extent
/// list. Every check here is a pure function of the extent values and the
/// request, so the walk path and the memoized path share it verbatim.
fn interpret_verified_extents<E>(
    verified: &VerifiedSegment,
    base: u64,
    pointer: PointerValue,
    additional: &[PointerValue],
    collect_authority_siblings: bool,
    authority_generation: Option<(u64, usize)>,
    descriptor_limit: usize,
) -> Result<ScannedSegment, StoreError<E>> {
    let mut matched = None;
    let mut additional_matches = Vec::new();
    let table_bytes = verified.extents.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
        .ok_or(StoreError::MemoryLimit)?;
    let mut descriptor_peak = reserve_scan_results(&mut additional_matches, additional.len(), table_bytes, descriptor_limit)?;
    let retained = additional_matches.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
        .and_then(|bytes| bytes.checked_add(table_bytes)).ok_or(StoreError::MemoryLimit)?;
    let mut authority_siblings = Vec::new();
    for value in &verified.extents {
        let value = *value;
        let ordinal = value.binding.ordinal;
        let relative = u32::try_from(value.binding.self_page.saturating_sub(base))
            .map_err(|_| StoreError::Corrupt)?;
        if relative == pointer.descriptor_relative_page && ordinal == pointer.ordinal {
            matched = Some(value);
        }
        if let Some((generation, maximum)) = authority_generation {
            if value.extent_kind == ExtentKind::Authority
                && value.binding.target_checkpoint_generation == generation
            {
                if authority_siblings.len() >= maximum { return Err(StoreError::Corrupt); }
                descriptor_peak = descriptor_peak.max(reserve_scan_results(&mut authority_siblings, 1, retained, descriptor_limit)?);
            }
            collect_requested_authority(&mut authority_siblings, value, generation, maximum)?;
        }
        if collect_authority_siblings && ordinal > pointer.ordinal {
            let still_collecting = matched.as_ref().is_some_and(|first| {
                authority_siblings.len() as u32 + 1 < first.extent_count
            });
            if still_collecting {
                let first = matched.as_ref().expect("collecting implies matched");
                let expected_index = authority_siblings.len() as u32 + 1;
                if value.extent_kind != ExtentKind::Authority
                    || value.binding.target_checkpoint_generation
                        != first.binding.target_checkpoint_generation
                    || value.extent_index != expected_index
                    || value.extent_count != first.extent_count
                    || value.object_kind != first.object_kind
                    || value.content_byte_len != first.content_byte_len
                    || value.encoded_blob_len != first.encoded_blob_len
                    || value.encoded_offset
                        != first
                            .payload_byte_len
                            .checked_mul(u64::from(expected_index))
                            .ok_or(StoreError::Corrupt)?
                    || value.merkle_root != first.merkle_root
                    || value.payload_byte_len
                        > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
                {
                    return Err(StoreError::Corrupt);
                }
                if authority_siblings.is_empty() {
                    // Leave one slot for extent zero so the authority reader
                    // can take this allocation without allocating a copy.
                    // Bound the reservation by authenticated segment geometry,
                    // never just the extent count declared by this record.
                    let available = verified.extents.len()
                        .saturating_sub(pointer.ordinal.saturating_sub(1) as usize);
                    descriptor_peak = descriptor_peak.max(reserve_scan_results(&mut authority_siblings,
                        (first.extent_count as usize).min(available), retained, descriptor_limit)?);
                }
                descriptor_peak = descriptor_peak.max(reserve_scan_results(&mut authority_siblings, 1, retained, descriptor_limit)?);
                authority_siblings.push(value);
            }
        }
        for wanted in additional {
            if relative == wanted.descriptor_relative_page && ordinal == wanted.ordinal {
                additional_matches.push(value);
            }
        }
    }
    if additional_matches.len() != additional.len() {
        return Err(StoreError::Corrupt);
    }
    if collect_authority_siblings {
        let first = matched.ok_or(StoreError::Corrupt)?;
        if first.extent_kind != ExtentKind::Authority
            || first.extent_index != 0
            || first.extent_count == 0
            || first.encoded_offset != 0
            || first.payload_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
            || authority_siblings.len() as u32 + 1 > first.extent_count
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(ScannedSegment {
        matched,
        additional_matches,
        authority_siblings,
        descriptor_peak_bytes: descriptor_peak,
        record_count: verified.record_count,
        total_payload_bytes: verified.total_payload_bytes,
        segment_seal_body_sha256: verified.segment_seal_body_sha256,
        previous_segment: verified.previous_segment,
        header_target_checkpoint_generation: verified.header_target_checkpoint_generation,
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
/// Validate the semantic chain of one multi-extent authority payload.
/// Extent 0 carries extent_count and the whole-payload merkle root; every
/// sibling must continue the ascending index/offset sequence with identical
/// logical shape. Binding shape is authenticated separately by the scan.
fn validate_authority_extent_chain<E>(extents: &[ExtentRecord]) -> Result<(), StoreError<E>> {
    let Some(first) = extents.first() else {
        return Ok(());
    };
    if first.extent_index != 0
        || first.extent_count == 0
        || first.encoded_offset != 0
        || first.payload_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
        || extents.len() as u32 != first.extent_count
    {
        return Err(StoreError::Corrupt);
    }
    for (index, extent) in extents.iter().enumerate().skip(1) {
        let expected_offset = first
            .payload_byte_len
            .checked_mul(index as u64)
            .ok_or(StoreError::Corrupt)?;
        if extent.extent_index != index as u32
            || extent.extent_count != first.extent_count
            || extent.object_kind != first.object_kind
            || extent.content_byte_len != first.content_byte_len
            || extent.encoded_blob_len != first.encoded_blob_len
            || extent.encoded_offset != expected_offset
            || extent.merkle_root != first.merkle_root
            || extent.binding.target_checkpoint_generation
                != first.binding.target_checkpoint_generation
            || extent.payload_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

pub(crate) fn read_pointer_payload<'a, D: PageDevice>(
    device: &'a D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    expected_kind: ExtentKind,
    maximum_bytes: usize,
    memo: Option<&'a VerifiedSegmentScans>,
) -> impl core::future::Future<Output = Result<ResolvedPayload, StoreError<D::Error>>> + 'a {
    read_pointer_payload_with_read_capacity(device, store_uuid, admitted_segments,
        next_segment_generation, checkpoint_generation, pointer, expected_kind,
        maximum_bytes, memo, 0)
}

pub(crate) async fn read_pointer_payload_with_read_capacity<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    expected_kind: ExtentKind,
    maximum_bytes: usize,
    memo: Option<&VerifiedSegmentScans>,
    read_capacity_limit: usize,
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
        memo,
    )
    .await?;
    let extent = scanned.matched.ok_or(StoreError::Corrupt)?;
    read_pointer_payload_after_scan(
        device,
        pointer,
        expected_kind,
        checkpoint_generation,
        extent,
        &scanned,
        read_capacity_limit,
    )
    .await
}

/// Resolve several pointers from one immutable sealed segment while paying
/// for its descriptor-chain authentication only once. Every requested
/// descriptor seal and payload is still read back and checked independently.
pub(crate) async fn read_pointer_payloads<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    requests: &[(PhysicalPointer, ExtentKind, usize)],
    memo: Option<&VerifiedSegmentScans>,
) -> Result<Vec<ResolvedPayload>, StoreError<D::Error>> {
    let Some((PhysicalPointer::Value(first), _, _)) = requests.first().copied() else {
        return if requests.is_empty() {
            Ok(Vec::new())
        } else {
            Err(StoreError::Corrupt)
        };
    };
    if requests.len() == 1 {
        let (pointer, kind, maximum_bytes) = requests[0];
        let resolved = vec![
            read_pointer_payload(
                device,
                store_uuid,
                admitted_segments,
                next_segment_generation,
                checkpoint_generation,
                pointer,
                kind,
                maximum_bytes,
                memo,
            )
            .await?,
        ];
        validate_resolved_authority_chains(&resolved)?;
        return Ok(resolved);
    }
    let one_segment = requests.iter().all(|(pointer, _, _)| {
        matches!(
            pointer,
            PhysicalPointer::Value(value)
                if value.store_uuid == first.store_uuid
                    && value.segment_no == first.segment_no
                    && value.segment_generation == first.segment_generation
        )
    });
    if !one_segment {
        let mut resolved = Vec::new();
        resolved
            .try_reserve_exact(requests.len())
            .map_err(|_| StoreError::MemoryLimit)?;
        for (pointer, kind, maximum_bytes) in requests.iter().copied() {
            resolved.push(
                read_pointer_payload(
                    device,
                    store_uuid,
                    admitted_segments,
                    next_segment_generation,
                    checkpoint_generation,
                    pointer,
                    kind,
                    maximum_bytes,
                    memo,
                )
                .await?,
            );
        }
        return Ok(resolved);
    }
    let mut additional = Vec::new();
    additional
        .try_reserve_exact(requests.len().saturating_sub(1))
        .map_err(|_| StoreError::MemoryLimit)?;
    for (pointer, _, _) in &requests[1..] {
        let PhysicalPointer::Value(pointer) = pointer else {
            return Err(StoreError::Corrupt);
        };
        additional.push(*pointer);
    }
    let scanned = scan_segment_with_matches(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        first,
        &additional,
        false,
        None,
        memo,
        false,
        usize::MAX,
    )
    .await?;
    let base = segment_base_page(first.segment_no)?;
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(requests.len())
        .map_err(|_| StoreError::MemoryLimit)?;
    for (request_index, (physical, kind, maximum_bytes)) in requests.iter().copied().enumerate() {
        let PhysicalPointer::Value(pointer) = physical else {
            return Err(StoreError::Corrupt);
        };
        if pointer.store_uuid != first.store_uuid
            || pointer.segment_no != first.segment_no
            || pointer.segment_generation != first.segment_generation
            || pointer.extent_kind != kind
            || pointer.exact_byte_len > maximum_bytes as u64
            || pointer.exact_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
            || pointer.ordinal == 0
            || pointer.ordinal > scanned.record_count
        {
            return Err(StoreError::Corrupt);
        }
        let extent = if request_index == 0 {
            scanned.matched.ok_or(StoreError::Corrupt)?
        } else {
            scanned
                .additional_matches
                .iter()
                .copied()
                .find(|extent| {
                    extent.binding.ordinal == pointer.ordinal
                        && extent.binding.self_page
                            == base + u64::from(pointer.descriptor_relative_page)
                })
                .ok_or(StoreError::Corrupt)?
        };
        resolved.push(
            read_pointer_payload_after_scan(
                device,
                pointer,
                kind,
                checkpoint_generation,
                extent,
                &scanned,
                0,
            )
            .await?,
        );
    }
    validate_resolved_authority_chains(&resolved)?;
    Ok(resolved)
}

fn validate_resolved_authority_chains<E>(resolved: &[ResolvedPayload]) -> Result<(), StoreError<E>> {
    let mut extents = Vec::new();
    extents
        .try_reserve_exact(resolved.len())
        .map_err(|_| StoreError::MemoryLimit)?;
    extents.extend(
        resolved
            .iter()
            .filter(|payload| payload.extent.extent_kind == ExtentKind::Authority)
            .map(|payload| payload.extent),
    );
    validate_authority_extent_chain(&extents)
}

async fn read_pointer_payload_after_scan<D: PageDevice>(
    device: &D,
    pointer: PointerValue,
    expected_kind: ExtentKind,
    checkpoint_generation: u64,
    extent: ExtentRecord,
    scanned: &ScannedSegment,
    read_capacity_limit: usize,
) -> Result<ResolvedPayload, StoreError<D::Error>> {
    let base = segment_base_page(pointer.segment_no)?;
    if pointer.payload_relative_page
        != pointer
            .descriptor_relative_page
            .checked_add(2)
            .ok_or(StoreError::Corrupt)?
        || extent.binding.store_uuid != pointer.store_uuid
        || extent.binding.segment_no != pointer.segment_no
        || extent.binding.generation != pointer.segment_generation
        || extent.binding.ordinal != pointer.ordinal
        || extent.binding.self_page != base + u64::from(pointer.descriptor_relative_page)
        || extent.binding.target_checkpoint_generation > checkpoint_generation
        || extent.extent_kind != pointer.extent_kind
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
                || extent.merkle_root != pointer.payload_sha256)
            && expected_kind != ExtentKind::Authority)
        || (expected_kind == ExtentKind::Authority
            && (extent.extent_count == 0 || extent.extent_index >= extent.extent_count))
    {
        return Err(StoreError::Corrupt);
    }
    let exact_len = usize::try_from(pointer.exact_byte_len).map_err(|_| StoreError::Corrupt)?;
    if exact_len.div_ceil(PAGE_SIZE) != pointer.payload_pages as usize {
        return Err(StoreError::Corrupt);
    }
    let bytes = read_payload_owned(device, base + u64::from(pointer.payload_relative_page),
        exact_len, read_capacity_limit).await?;
    if payload_sha256(&bytes) != pointer.payload_sha256 {
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

// Opt-in only: recovery callers retain exact allocation and tail-scratch behavior.
// A single small blob may use its explicit envelope budget to include the tail
// in one device request. No request exceeds the existing 32-page maximum.
async fn read_payload_owned<D: PageDevice>(
    device: &D, first: u64, exact_len: usize, capacity_limit: usize,
) -> Result<Vec<u8>, StoreError<D::Error>> {
    let rounded = exact_len.checked_next_multiple_of(PAGE_SIZE).ok_or(StoreError::MemoryLimit)?;
    let coalesce = exact_len > PAGE_SIZE && exact_len % PAGE_SIZE != 0
        && rounded <= 32 * PAGE_SIZE && rounded <= capacity_limit;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(if coalesce { rounded } else { exact_len })
        .map_err(|_| StoreError::MemoryLimit)?;
    if coalesce && bytes.capacity() > capacity_limit {
        return Err(StoreError::MemoryLimit);
    }
    bytes.resize(if coalesce { rounded } else { exact_len }, 0);
    read_payload_into(device, first, &mut bytes).await?;
    bytes.truncate(exact_len);
    Ok(bytes)
}

async fn read_payload_into<D: PageDevice>(
    device: &D,
    payload_first: u64,
    bytes: &mut [u8],
) -> Result<(), StoreError<D::Error>> {
    // Read full pages directly into the final payload allocation. This keeps
    // the recovery memory bound unchanged while issuing up to 128 KiB per
    // request instead of allocating/copying one temporary page per read.
    let (pages, tail) = bytes.as_chunks_mut::<PAGE_SIZE>();
    let full_pages = pages.len();
    for (index, chunk) in pages.chunks_mut(32).enumerate() {
        device.read_pages(payload_first + (index * 32) as u64, chunk)
            .await.map_err(StoreError::Device)?;
    }
    if !tail.is_empty() {
        let mut page = Box::new([0; PAGE_SIZE]);
        device
            .read_page(payload_first + full_pages as u64, page.as_mut())
            .await
            .map_err(StoreError::Device)?;
        tail.copy_from_slice(&page[..tail.len()]);
    }
    Ok(())
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
    // V1 reserves this field as zero; V2 uses it for the external-root table.
    // Full snapshot decoding still validates the version and reserved fields.
    let external_root_count = input_u32(input, 0x70).ok_or(StoreError::Corrupt)? as usize;
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
            external_root_count
                .checked_mul(core::mem::size_of::<PersistentRootEntry>())?
                .checked_add(bytes)
        })
        .and_then(|bytes| {
            record_count
                .checked_mul(vibeos_durable_format::RECORD_SIZE)?
                .checked_add(bytes)
        })
        .ok_or(StoreError::MemoryLimit)
}


fn persistent_authority_recovery_capacity_upper_bound<E>(input: &[u8]) -> Result<usize, StoreError<E>> {
    let decoded = persistent_authority_decode_capacity_upper_bound(input)?;
    let objects = input_u32(input, 0x38).ok_or(StoreError::Corrupt)? as usize;
    let external = input_u32(input, 0x70).ok_or(StoreError::Corrupt)? as usize;
    objects.checked_add(external)
        .and_then(|count| count.checked_mul(mem::size_of::<PersistentRootEntry>()))
        .and_then(|roots| decoded.checked_add(roots))
        .ok_or(StoreError::MemoryLimit)
}

fn authority_roots_from_snapshot<E>(decoded: &PersistentAuthoritySnapshot) -> Result<PersistentRootSet, StoreError<E>> {
    let count = decoded.objects.len().checked_add(decoded.external_roots().len())
        .ok_or(StoreError::MemoryLimit)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|_| StoreError::MemoryLimit)?;
    entries.extend(decoded.objects.iter().map(|binding| PersistentRootEntry {
        object_id: binding.v2_object_id,
        commit_generation: binding.commit_generation,
        object_kind: binding.object_kind,
    }));
    entries.extend_from_slice(decoded.external_roots());
    entries.sort_unstable_by_key(|entry| entry.object_id);
    PersistentRootSet::new(decoded.checkpoint_generation(), entries).map_err(|_| StoreError::Corrupt)
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
    memo: Option<&VerifiedSegmentScans>,
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
        memo,
    )
    .await
}

/// Scan one allocated segment and return Authority records of the requested
/// generation, bounded before allocation and authenticated by the segment's full descriptor/summary/seal
/// chain. Used to reassemble authority chains whose extents span segments.
pub(crate) async fn scan_segment_authority_records<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    segment_no: u64,
    maximum: usize,
    target_generation: u64,
    memo: Option<&VerifiedSegmentScans>,
    descriptor_limit: usize,
) -> Result<(Vec<ExtentRecord>, usize), StoreError<D::Error>> {
    let base = segment_base_page(segment_no)?;
    let header_pages = read_pair(device, base).await?;
    let header = match decode_segment_header_verified(&header_pages[0], &header_pages[1])? {
        DecodeStatus::Sealed(value) => value,
        _ => return Err(StoreError::Corrupt),
    };
    let generation = header.value().binding.generation;
    if header.value().binding.store_uuid != store_uuid
        || header.value().binding.segment_no != segment_no
    {
        return Err(StoreError::Corrupt);
    }
    // The verified header owns its decoded fields. Release the discovery
    // pair before the full scan allocates its header/trailer page windows;
    // otherwise this source path exceeds the eight-page probe workspace.
    drop(header_pages);
    let pointer = PointerValue {
        store_uuid,
        segment_no,
        segment_generation: generation,
        descriptor_relative_page: DATA_FIRST_PAGE,
        payload_relative_page: DATA_FIRST_PAGE + 2,
        payload_pages: 0,
        ordinal: 0,
        exact_byte_len: 0,
        extent_kind: ExtentKind::Authority,
        payload_sha256: [0; 32],
    };
    let scanned = scan_segment_with_matches(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        &[],
        false,
        Some((target_generation, maximum)),
        memo,
        false,
        descriptor_limit,
    )
    .await?;
    Ok((scanned.authority_siblings, scanned.descriptor_peak_bytes))
}

// Filter before reserving: historical authority generations must neither grow
// the result Vec nor consume the selected chain's descriptor count budget.
fn collect_requested_authority<E>(
    records: &mut Vec<ExtentRecord>,
    extent: ExtentRecord,
    generation: u64,
    maximum: usize,
) -> Result<(), StoreError<E>> {
    if extent.extent_kind != ExtentKind::Authority
        || extent.binding.target_checkpoint_generation != generation
    {
        return Ok(());
    }
    if records.len() >= maximum {
        return Err(StoreError::Corrupt);
    }
    records.try_reserve_exact(1).map_err(|_| StoreError::MemoryLimit)?;
    records.push(extent);
    Ok(())
}

// Siblings are authenticated by the scan. Keep their allocation where useful,
// charging any growth overlap; otherwise charge the old list while allocating
// the exact-size replacement. Leave one slot for the caller to add extent zero.
fn prepare_authority_chain_storage<E>(siblings: Vec<ExtentRecord>, first: &ExtentRecord,
    limit: usize) -> Result<(Vec<ExtentRecord>, usize), StoreError<E>> {
    let mut peak = 0;
    let count = first.extent_count as usize;
    let mut records = if siblings.capacity() <= count {
        siblings
    } else {
        let retained = siblings.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
            .ok_or(StoreError::MemoryLimit)?;
        let mut records = Vec::new();
        peak = reserve_scan_results(&mut records, count, retained, limit)?;
        collect_authority_generation(&mut records, siblings, first)?;
        records
    };
    if records.len() >= count { return Err(StoreError::Corrupt); }
    let additional = count - records.len();
    peak = peak.max(reserve_scan_results(&mut records, additional, 0, limit)?);
    Ok((records, peak))
}

// Retain only the selected generation while scanning historical segments. The
// caller reserves the chain's declared count once; unrelated history must not
// grow that allocation, and excess matching records are corruption.
fn collect_authority_generation<E>(
    records: &mut Vec<ExtentRecord>,
    candidates: impl IntoIterator<Item = ExtentRecord>,
    first: &ExtentRecord,
) -> Result<(), StoreError<E>> {
    for extent in candidates {
        if extent.binding.target_checkpoint_generation != first.binding.target_checkpoint_generation {
            continue;
        }
        if records.len() >= first.extent_count as usize {
            return Err(StoreError::Corrupt);
        }
        records.push(extent);
    }
    Ok(())
}

// Bound the declared chain before reserving its descriptor array or scanning
// other segments. Authority chunks have a fixed stride and a nonempty tail.
fn validate_authority_payload_bound<E>(first: &ExtentRecord, maximum: usize) -> Result<(), StoreError<E>> {
    if first.extent_index != 0 || first.encoded_offset != 0 || first.extent_count == 0
        || first.payload_byte_len == 0
        || first.payload_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
        || first.content_byte_len != first.encoded_blob_len
    {
        return Err(StoreError::Corrupt);
    }
    let stride = first.payload_byte_len;
    let minimum = stride.checked_mul(u64::from(first.extent_count - 1))
        .and_then(|n| n.checked_add(1)).ok_or(StoreError::Corrupt)?;
    let upper = stride.checked_mul(u64::from(first.extent_count)).ok_or(StoreError::Corrupt)?;
    if first.encoded_blob_len < minimum || first.encoded_blob_len > upper {
        return Err(StoreError::Corrupt);
    }
    if first.encoded_blob_len > maximum as u64 {
        return Err(StoreError::MemoryLimit);
    }
    let descriptor_size = core::mem::size_of::<ExtentRecord>();
    let descriptor_bytes = (first.extent_count as usize).checked_mul(descriptor_size)
        .ok_or(StoreError::MemoryLimit)?;
    // A single descriptor is fixed read overhead even for a tiny payload.
    // Variable chain storage must independently fit the supplied budget;
    // this is not yet accounting for all simultaneously live scan buffers.
    if descriptor_bytes > maximum.max(descriptor_size) {
        return Err(StoreError::MemoryLimit);
    }
    Ok(())
}

/// Resolve a possibly multi-extent authority payload. Extent 0 is named by
/// the checkpoint; sibling extents are collected from the extent 0 segment
/// scan and, when the chain spans segments, from authenticated scans of
/// every allocated segment. The returned bytes are the concatenated logical
/// authority snapshot payload.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_pointer_authority_payload<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    allocated_segments: impl Iterator<Item = u64>,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, ExtentRecord), StoreError<D::Error>> {
    read_pointer_authority_payload_with_memo(device, store_uuid, admitted_segments,
        next_segment_generation, checkpoint_generation, pointer, allocated_segments,
        maximum_bytes, None).await
}

// Test-only observations of real authority reads, with no allocator hooks or
// production counters: reads with siblings, allocation reused without growth.
#[cfg(test)]
std::thread_local! {
    pub(crate) static AUTHORITY_CHAIN_REUSE: core::cell::Cell<(usize, usize)> = const {
        core::cell::Cell::new((0, 0))
    };
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_pointer_authority_payload_with_memo<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    allocated_segments: impl Iterator<Item = u64>,
    maximum_bytes: usize,
    memo: Option<&VerifiedSegmentScans>,
) -> Result<(Vec<u8>, ExtentRecord), StoreError<D::Error>> {
    read_pointer_authority_payload_with_buffer_limit(device, store_uuid, admitted_segments,
        next_segment_generation, checkpoint_generation, pointer, allocated_segments,
        maximum_bytes, usize::MAX, memo).await.map(|(bytes, record, _)| (bytes, record))
}

// Bounds owned scan/result/chain vectors and payload, returning their peak.
// Fixed page buffers and aggregate caller-owned memo allocations are separate.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn read_pointer_authority_payload_with_buffer_limit<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    allocated_segments: impl Iterator<Item = u64>,
    maximum_bytes: usize,
    payload_chain_limit: usize,
    memo: Option<&VerifiedSegmentScans>,
) -> Result<(Vec<u8>, ExtentRecord, usize), StoreError<D::Error>> {
    let PhysicalPointer::Value(pointer) = pointer else {
        return Err(StoreError::Corrupt);
    };
    if pointer.extent_kind != ExtentKind::Authority
        || pointer.exact_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
    {
        return Err(StoreError::Corrupt);
    }
    let scanned = scan_segment_with_matches(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        &[],
        true,
        None,
        memo,
        false,
        payload_chain_limit,
    )
    .await?;
    let first = scanned.matched.ok_or(StoreError::Corrupt)?;
    validate_authority_payload_bound(&first, maximum_bytes)?;
    let requested_chain_bytes = (first.extent_count as usize)
        .checked_mul(core::mem::size_of::<ExtentRecord>()).ok_or(StoreError::MemoryLimit)?;
    if requested_chain_bytes > payload_chain_limit { return Err(StoreError::MemoryLimit); }
    #[cfg(test)]
    let sibling_allocation = (
        scanned.authority_siblings.as_ptr(), scanned.authority_siblings.capacity(),
        !scanned.authority_siblings.is_empty(),
    );
    let mut descriptor_peak = scanned.descriptor_peak_bytes;
    let (mut records, chain_preparation_peak) = prepare_authority_chain_storage(
        scanned.authority_siblings, &first, payload_chain_limit)?;
    descriptor_peak = descriptor_peak.max(chain_preparation_peak);
    let descriptor_bytes = records.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
        .ok_or(StoreError::MemoryLimit)?;
    if descriptor_bytes > maximum_bytes.max(core::mem::size_of::<ExtentRecord>())
        || descriptor_bytes > payload_chain_limit
    {
        return Err(StoreError::MemoryLimit);
    }
    #[cfg(test)]
    if sibling_allocation.2 {
        let reused = sibling_allocation.1 <= first.extent_count as usize
            && records.as_ptr() == sibling_allocation.0
            && records.capacity() == sibling_allocation.1;
        AUTHORITY_CHAIN_REUSE.with(|stats| {
            let (reads, stable) = stats.get();
            stats.set((reads + 1, stable + usize::from(reused)));
        });
    }
    records.push(first);
    if records.len() as u32 != first.extent_count {
        for segment_no in allocated_segments {
            if segment_no == pointer.segment_no {
                continue;
            }
            let (found, scan_peak) = scan_segment_authority_records(
                device,
                store_uuid,
                admitted_segments,
                next_segment_generation,
                checkpoint_generation,
                segment_no,
                first.extent_count as usize,
                first.binding.target_checkpoint_generation,
                memo,
                payload_chain_limit.checked_sub(descriptor_bytes).ok_or(StoreError::MemoryLimit)?,
            )
            .await?;
            descriptor_peak = descriptor_peak.max(descriptor_bytes.checked_add(scan_peak).ok_or(StoreError::MemoryLimit)?);
            collect_authority_generation(&mut records, found, &first)?;
        }
    }
    records.sort_unstable_by_key(|extent| extent.extent_index);
    validate_authority_extent_chain(&records)?;
    if records.len() as u32 != first.extent_count {
        return Err(StoreError::Corrupt);
    }
    let total = records.iter().try_fold(0usize, |total, extent| {
        usize::try_from(extent.payload_byte_len)
            .map_err(|_| StoreError::Corrupt)
            .and_then(|bytes| total.checked_add(bytes).ok_or(StoreError::Corrupt))
    })?;
    if total as u64 != first.encoded_blob_len {
        return Err(StoreError::Corrupt);
    }
    if total > maximum_bytes {
        return Err(StoreError::MemoryLimit);
    }
    let chain_bytes = records.capacity().checked_mul(core::mem::size_of::<ExtentRecord>())
        .ok_or(StoreError::MemoryLimit)?;
    if total.checked_add(chain_bytes).is_none_or(|bytes| bytes > payload_chain_limit) {
        return Err(StoreError::MemoryLimit);
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| StoreError::MemoryLimit)?;
    if bytes.capacity() > maximum_bytes || bytes.capacity().checked_add(chain_bytes)
        .is_none_or(|bytes| bytes > payload_chain_limit)
    {
        return Err(StoreError::MemoryLimit);
    }
    let mut single_extent_digest = None;
    for extent in &records {
        let exact_len =
            usize::try_from(extent.payload_byte_len).map_err(|_| StoreError::Corrupt)?;
        let base = segment_base_page(extent.binding.segment_no)?;
        if exact_len.div_ceil(PAGE_SIZE) != extent.payload_pages as usize {
            return Err(StoreError::Corrupt);
        }
        let start = bytes.len();
        let end = start.checked_add(exact_len).ok_or(StoreError::Corrupt)?;
        if end > total {
            return Err(StoreError::Corrupt);
        }
        bytes.resize(end, 0);
        let chunk = &mut bytes[start..end];
        read_payload_into(
            device, base + u64::from(extent.payload_first_relative_page), chunk,
        ).await?;
        let observed = payload_sha256(chunk);
        if observed != extent.payload_sha256 {
            return Err(StoreError::Corrupt);
        }
        if first.extent_count == 1 {
            single_extent_digest = Some(observed);
        }
    }
    // The sole extent is the entire logical payload. Compare its observed
    // digest with both commitments without hashing identical bytes twice.
    // Multi-extent reads still hash the complete concatenated payload.
    drop(records);
    let complete_digest = single_extent_digest.unwrap_or_else(|| payload_sha256(&bytes));
    if bytes.len() != total || complete_digest != first.merkle_root {
        return Err(StoreError::Corrupt);
    }
    let source_peak = descriptor_peak.max(bytes.capacity().checked_add(chain_bytes).ok_or(StoreError::MemoryLimit)?);
    if source_peak > payload_chain_limit { return Err(StoreError::MemoryLimit); }
    Ok((bytes, first, source_peak))
}

#[allow(clippy::too_many_arguments)]
async fn read_recovery_authority_payload<D: PageDevice>(
    device: &D,
    store_uuid: StoreUuid,
    admitted_segments: u64,
    next_segment_generation: u64,
    checkpoint_generation: u64,
    pointer: PhysicalPointer,
    allocated_segments: impl Iterator<Item = u64>,
    memory_limit: usize,
    resident_bytes: usize,
    memo: Option<&VerifiedSegmentScans>,
) -> Result<(Vec<u8>, ExtentRecord), StoreError<D::Error>> {
    let remaining = recovery_remaining(memory_limit, resident_bytes)?;
    if let PhysicalPointer::Value(pointer) = pointer {
        if pointer.extent_kind != ExtentKind::Authority
            || pointer.exact_byte_len > MAX_EXTENT_PAYLOAD_PAGES as u64 * PAGE_SIZE as u64
        {
            return Err(StoreError::Corrupt);
        }
        if pointer.exact_byte_len > remaining as u64 {
            return Err(StoreError::MemoryLimit);
        }
    }
    read_pointer_authority_payload_with_memo(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        allocated_segments,
        remaining,
        memo,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn recover_checkpoint_pair<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    left: Option<VerifiedRecord<Checkpoint>>,
    right: Option<VerifiedRecord<Checkpoint>>,
    selected_generation: u64,
    limits: StoreLimits,
    memo: Option<&VerifiedSegmentScans>,
) -> Result<MountedState, StoreError<D::Error>> {
    let state = match (left, right) {
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
                    recover_state_with_memo(device, superblock, older, limits, memo).await?;
                let older_peak = older_state.recovery_peak_bytes;
                let witness = CheckpointTransitionWitness::from_mounted(older_state);
                let witness_bytes = witness.resident_bytes().ok_or(StoreError::MemoryLimit)?;
                let remaining = limits
                    .recovery_memory_bytes
                    .checked_sub(witness_bytes)
                    .ok_or(StoreError::MemoryLimit)?;
                let newer_limits = StoreLimits {
                    recovery_memory_bytes: remaining,
                    ..limits
                };
                let mut newer_state =
                    recover_state_with_memo(device, superblock, newer, newer_limits, memo).await?;
                validate_checkpoint_transition(&witness, &newer_state)?;
                let pair_peak = witness_bytes
                    .checked_add(newer_state.recovery_peak_bytes)
                    .ok_or(StoreError::MemoryLimit)?;
                newer_state.recovery_peak_bytes = older_peak.max(pair_peak);
                if newer_state.recovery_peak_bytes > limits.recovery_memory_bytes {
                    return Err(StoreError::MemoryLimit);
                }
                newer_state
            }
            (Some(candidate), None) | (None, Some(candidate)) => {
                if candidate.value().binding.generation != selected_generation {
                    return Err(StoreError::Corrupt);
                }
                recover_state_with_memo(device, superblock, candidate, limits, memo).await?
            }
            (None, None) => return Err(StoreError::Unformatted),
        };
    Ok(state)
}

/// Scrub must establish fresh media proofs, independently of mount and prior
/// scrub calls. Cache only within this checkpoint reconstruction, then drop it
/// before the caller's separate content/padding/closure verification.
pub(crate) async fn recover_state_for_scrub<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    checkpoint: VerifiedRecord<Checkpoint>,
    limits: StoreLimits,
) -> Result<MountedState, StoreError<D::Error>> {
    const MEMO_BYTES: usize = 64 * 1024;
    if let Some(remaining) = limits.recovery_memory_bytes.checked_sub(MEMO_BYTES) {
        let memo = VerifiedSegmentScans::with_budget(MEMO_BYTES, 32);
        let cached_limits = StoreLimits { recovery_memory_bytes: remaining, ..limits };
        match recover_state_with_memo(device, superblock, checkpoint, cached_limits, Some(&memo)).await {
            Ok(mut state) => {
                debug_assert!(memo.allocated_bytes() <= MEMO_BYTES);
                state.recovery_peak_bytes = state.recovery_peak_bytes
                    .checked_add(MEMO_BYTES).ok_or(StoreError::MemoryLimit)?;
                return Ok(state);
            }
            Err(StoreError::MemoryLimit) => {
                drop(memo);
                let mut state = recover_state(device, superblock, checkpoint, limits).await?;
                state.recovery_peak_bytes = limits.recovery_memory_bytes;
                return Ok(state);
            }
            Err(error) => return Err(error),
        }
    }
    recover_state(device, superblock, checkpoint, limits).await
}

pub(crate) async fn recover_state<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    checkpoint: VerifiedRecord<Checkpoint>,
    limits: StoreLimits,
) -> Result<MountedState, StoreError<D::Error>> {
    recover_state_with_memo(device, superblock, checkpoint, limits, None).await
}

async fn recover_state_with_memo<D: PageDevice>(
    device: &D,
    superblock: Superblock,
    checkpoint: VerifiedRecord<Checkpoint>,
    limits: StoreLimits,
    memo: Option<&VerifiedSegmentScans>,
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
            memo,
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
            memo,
        )
        .await?;
        if snapshot.bytes.starts_with(b"VIBECAS2") {
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
            let snapshot_generation = decoded.checkpoint_generation;
            let CasSnapshot {
                objects: mut objects,
                blobs: mut blobs,
                ..
            } = decoded;
            let snapshot_capacity = snapshot.bytes.capacity();
            // The decoded tables own their data; release the encoded snapshot
            // before reading anything else so the measured recovery peak is
            // also the actual live-memory bound.
            drop(snapshot);
            if checkpoint.replay_count != 0 {
                // Bounded replay: every delta after the snapshot root minted
                // exactly one object (and at most one new Blob). Walk the
                // chain from the checkpoint's tail back to the root, then
                // apply it in commit order under the frozen chain rules.
                let replay_count = checkpoint.replay_count as usize;
                let chain_bytes = replay_count
                    .checked_mul(mem::size_of::<CasDelta>())
                    .ok_or(StoreError::MemoryLimit)?;
                let table_bytes = objects
                    .capacity()
                    .checked_mul(mem::size_of::<ObjectMapping>())
                    .and_then(|bytes| {
                        blobs
                            .capacity()
                            .checked_mul(mem::size_of::<BlobMapping>())
                            .and_then(|more| bytes.checked_add(more))
                    })
                    .ok_or(StoreError::MemoryLimit)?;
                let replay_resident = allocation_bytes
                    .checked_add(table_bytes)
                    .and_then(|bytes| bytes.checked_add(chain_bytes))
                    .ok_or(StoreError::MemoryLimit)?;
                recovery_observe(
                    &mut recovery_peak,
                    limits.recovery_memory_bytes,
                    replay_resident,
                )?;
                let mut chain: Vec<CasDelta> = Vec::new();
                chain
                    .try_reserve_exact(replay_count)
                    .map_err(|_| StoreError::MemoryLimit)?;
                let mut pointer = checkpoint.replay_tail;
                let mut depth = checkpoint.replay_count;
                while depth != 0 {
                    require_allocated_pointer(&allocation, pointer)?;
                    let record = read_recovery_pointer_payload(
                        device,
                        superblock.binding.store_uuid,
                        checkpoint.admitted_segments,
                        checkpoint.next_segment_generation,
                        checkpoint.binding.generation,
                        pointer,
                        ExtentKind::CatalogDelta,
                        limits.recovery_memory_bytes,
                        replay_resident,
                        memo,
                    )
                    .await?;
                    let delta = decode_cas_delta(&record.bytes, context)
                        .map_err(|_| StoreError::Corrupt)?;
                    if delta.chain_count != depth
                        || delta.checkpoint_generation > checkpoint.binding.generation
                        || delta.checkpoint_generation
                            != record.extent.binding.target_checkpoint_generation
                    {
                        return Err(StoreError::Corrupt);
                    }
                    chain.push(delta);
                    pointer = delta.previous_delta;
                    depth -= 1;
                }
                if pointer != PhysicalPointer::Null {
                    return Err(StoreError::Corrupt);
                }
                objects
                    .try_reserve(replay_count)
                    .map_err(|_| StoreError::MemoryLimit)?;
                blobs
                    .try_reserve(replay_count)
                    .map_err(|_| StoreError::MemoryLimit)?;
                let mut previous_generation = snapshot_generation;
                let mut previous_id = objects.last().map_or(0, |object| object.object_id);
                for delta in chain.iter().rev() {
                    // Chain generations never decrease (one checkpoint may
                    // append several deltas), ObjectIds strictly increase, a
                    // reuse resolves an already published Blob and a new
                    // Blob mapping publishes its key exactly once.
                    if delta.checkpoint_generation < previous_generation
                        || delta.object.object_id <= previous_id
                    {
                        return Err(StoreError::Corrupt);
                    }
                    previous_generation = delta.checkpoint_generation;
                    previous_id = delta.object.object_id;
                    let position =
                        blobs.binary_search_by_key(&delta.object.blob_key, |blob| blob.blob_key);
                    match (delta.new_blob, position) {
                        (None, Ok(_)) => {}
                        (Some(blob), Err(insert)) if blob.blob_key == delta.object.blob_key => {
                            blobs.insert(insert, blob);
                        }
                        _ => return Err(StoreError::Corrupt),
                    }
                    objects.push(delta.object);
                }
                if objects.len() > limits.max_catalog_entries as usize
                    || blobs.len() > limits.max_catalog_entries as usize
                {
                    return Err(StoreError::Corrupt);
                }
            }
            let cas_bytes = objects
                .capacity()
                .checked_mul(mem::size_of::<ObjectMapping>())
                .and_then(|bytes| {
                    blobs
                        .capacity()
                        .checked_mul(mem::size_of::<BlobMapping>())
                        .and_then(|more| bytes.checked_add(more))
                })
                .ok_or(StoreError::MemoryLimit)?;
            recovery_observe(
                &mut recovery_peak,
                limits.recovery_memory_bytes,
                allocation_bytes
                    .checked_add(cas_bytes)
                    .and_then(|bytes| bytes.checked_add(snapshot_capacity))
                    .ok_or(StoreError::MemoryLimit)?,
            )?;
            for blob in &blobs {
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
                    memo,
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
                    memo,
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
            cas = Some(CasMountedState { objects, blobs });
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
    #[cfg(feature = "experimental-authority-delta")]
    let mut recovered_authority_depth = None;
    let mut persistent_authority = None;
    if checkpoint.authority_root != PhysicalPointer::Null {
        let resident_before_roots =
            recovery_resident_bytes(&allocation, &catalog, cas.as_ref(), None, None)
                .map_err(|_| StoreError::MemoryLimit)?;
        // Most authority payloads fit in the root segment. Defer enumeration
        // until a cross-segment chain actually needs it, and borrow the bitmap
        // instead of keeping an allocated-segment Vec alongside read buffers.
        let allocated_segments = (0..checkpoint.admitted_segments).filter(|&segment_no| {
            allocation.segment_state(segment_no) == Some(SegmentAllocation::Allocated)
        });
        let (authority_bytes, authority_extent) = read_recovery_authority_payload(
            device,
            superblock.binding.store_uuid,
            checkpoint.admitted_segments,
            checkpoint.next_segment_generation,
            checkpoint.binding.generation,
            checkpoint.authority_root,
            allocated_segments,
            limits.recovery_memory_bytes,
            resident_before_roots,
            memo,
        )
        .await?;
        #[cfg(any(test, feature = "experimental-authority-delta"))]
        let authority_bytes = if authority_bytes.starts_with(b"VIBEAUL1") {
            // Experimental bridge must respect the mount's remaining allowance
            // and expose its transient workspace peak to recovery telemetry.
            let (bytes, delta_peak, _delta_depth) = crate::authority_delta::replay_checkpoint_for_test(
                device, &superblock, &checkpoint, &allocation,
                recovery_remaining(limits.recovery_memory_bytes, resident_before_roots)?,
                authority_bytes, authority_extent.binding.target_checkpoint_generation,
                memo,
            ).await?;
            #[cfg(feature = "experimental-authority-delta")]
            { recovered_authority_depth = Some(_delta_depth); }
            recovery_observe(&mut recovery_peak, limits.recovery_memory_bytes,
                resident_before_roots.checked_add(delta_peak).ok_or(StoreError::MemoryLimit)?)?;
            bytes
        } else { authority_bytes };
        // A freshly formatted V2 store has a null catalog root. Installing an
        // explicit empty authority snapshot is still valid: there are no
        // bindings which would require CAS resolution yet.
        let cas_objects: &[ObjectMapping] =
            cas.as_ref().map_or(&[], |state| state.objects.as_slice());
        let (decoded_roots, decoded_authority) = if authority_bytes.starts_with(b"VIBEAUT2") {
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                resident_before_roots,
                authority_bytes.capacity(),
                persistent_authority_recovery_capacity_upper_bound(&authority_bytes)?,
            )?;
            let decode_resident = resident_before_roots.checked_add(authority_bytes.capacity())
                .ok_or(StoreError::MemoryLimit)?;
            let decode_budget = recovery_remaining(limits.recovery_memory_bytes, decode_resident)?;
            let (decoded, decode_peak) = decode_persistent_authority_snapshot_bounded(
                &authority_bytes, decode_budget,
            ).map_err(|error| match error {
                crate::authority_snapshot::AuthoritySnapshotError::MemoryLimit => StoreError::MemoryLimit,
                _ => StoreError::Corrupt,
            })?;
            recovery_observe(&mut recovery_peak, limits.recovery_memory_bytes,
                decode_resident.checked_add(decode_peak).ok_or(StoreError::MemoryLimit)?)?;
            if decoded.checkpoint_generation()
                != authority_extent.binding.target_checkpoint_generation
            {
                return Err(StoreError::Corrupt);
            }
            let roots = authority_roots_from_snapshot(&decoded)?;
            (roots, Some(decoded))
        } else {
            recovery_preflight_decode(
                limits.recovery_memory_bytes,
                resident_before_roots,
                authority_bytes.capacity(),
                persistent_roots_decode_capacity_upper_bound(&authority_bytes)?,
            )?;
            let decoded =
                decode_persistent_root_set(&authority_bytes).map_err(|_| StoreError::Corrupt)?;
            if decoded.checkpoint_generation > checkpoint.binding.generation
                || decoded.checkpoint_generation
                    != authority_extent.binding.target_checkpoint_generation
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
                .checked_add(authority_bytes.capacity())
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
    // A CAS catalog consumed its replay chain above; only the legacy catalog
    // replays entries here.
    let legacy_replay_count = if cas.is_some() { 0 } else { checkpoint.replay_count };
    let replay_capacity_bytes = usize::try_from(legacy_replay_count)
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
        .try_reserve_exact(legacy_replay_count as usize)
        .map_err(|_| StoreError::MemoryLimit)?;
    recovery_observe(
        &mut recovery_peak,
        limits.recovery_memory_bytes,
        resident_bytes
            .checked_add(reverse_deltas.capacity() * mem::size_of::<CatalogEntry>())
            .ok_or(StoreError::MemoryLimit)?,
    )?;
    let mut pointer = if cas.is_some() {
        PhysicalPointer::Null
    } else {
        checkpoint.replay_tail
    };
    let mut expected_depth = u64::from(legacy_replay_count);
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
            memo,
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
                None,
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
        #[cfg(feature = "experimental-authority-delta")]
        recovered_authority_depth,
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
        durably_cleared_seals: alloc::collections::BTreeSet::new(),
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
    memo: Option<&VerifiedSegmentScans>,
) -> Result<(), StoreError<D::Error>> {
    let scanned = scan_segment(
        device,
        store_uuid,
        admitted_segments,
        next_segment_generation,
        checkpoint_generation,
        pointer,
        memo,
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
    memo: Option<&VerifiedSegmentScans>,
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
            memo,
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

/// Keep the existing 32-page request boundaries while borrowing complete
/// payload pages. Only the last, partial-page batch needs a zero-padded copy.
/// Publication barriers remain the caller's responsibility.
pub(crate) async fn write_payload_pages<D: PageDevice>(
    device: &D,
    first_page: u64,
    payload: &[u8],
) -> Result<(), StoreError<D::Error>> {
    for (index, bytes) in payload.chunks(32 * PAGE_SIZE).enumerate() {
        let (pages, tail) = bytes.as_chunks::<PAGE_SIZE>();
        let first = first_page + (index * 32) as u64;
        if tail.is_empty() {
            device.write_pages(first, pages).await.map_err(StoreError::Mutation)?;
        } else {
            let mut padded = vec![[0; PAGE_SIZE]; pages.len() + 1];
            padded.as_flattened_mut()[..bytes.len()].copy_from_slice(bytes);
            device.write_pages(first, &padded).await.map_err(StoreError::Mutation)?;
        }
    }
    Ok(())
}

async fn write_extent<D: PageDevice>(
    device: &D,
    base: u64,
    extent: &BuiltExtent<'_>,
) -> Result<(), StoreError<D::Error>> {
    let relative = extent.value.binding.self_page - base;
    write_payload_pages(
        device,
        base + u64::from(extent.value.payload_first_relative_page),
        extent.payload,
    ).await?;
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
            None,
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
        None,
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
        None,
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
mod payload_read_tests {
    use super::*;
    use core::cell::{Cell, RefCell};
    use core::future::Future;
    use core::task::{Context, Poll, Waker};

    #[test]
    fn authority_declared_chain_is_bounded_before_descriptor_reservation() {
        let mut first = build_extent(StoreUuid::new([7; 16]).unwrap(), 1, 1, 9, 1, DATA_FIRST_PAGE,
            ExtentKind::Authority, 1, 16, [1; 32], &[1; 16]).unwrap().value;
        first.extent_count = 2;
        first.content_byte_len = 25;
        first.encoded_blob_len = 25;
        let descriptor_budget = 2 * core::mem::size_of::<ExtentRecord>();
        validate_authority_payload_bound::<()>(&first, descriptor_budget).unwrap();
        assert!(matches!(validate_authority_payload_bound::<()>(&first, descriptor_budget - 1), Err(StoreError::MemoryLimit)));
        assert!(matches!(validate_authority_payload_bound::<()>(&first, 24), Err(StoreError::MemoryLimit)));
        for length in [0, 16, 33] {
            let mut bad = first;
            bad.content_byte_len = length;
            bad.encoded_blob_len = length;
            assert!(matches!(validate_authority_payload_bound::<()>(&bad, usize::MAX), Err(StoreError::Corrupt)));
        }
        first.extent_count = u32::MAX;
        assert!(matches!(validate_authority_payload_bound::<()>(&first, usize::MAX), Err(StoreError::Corrupt)));
        first.content_byte_len = u64::from(u32::MAX) * 16;
        first.encoded_blob_len = first.content_byte_len;
        assert!(matches!(validate_authority_payload_bound::<()>(&first, 1024), Err(StoreError::MemoryLimit)));
    }

    #[test]
    fn authority_chain_storage_charges_growth_and_replacement_overlap() {
        let mut first = build_extent(StoreUuid::new([7; 16]).unwrap(), 1, 1, 9, 1, DATA_FIRST_PAGE,
            ExtentKind::Authority, 1, 16, [1; 32], &[1;16]).unwrap().value;
        first.extent_count = 2;
        let mut sibling = first;
        sibling.extent_index = 1;
        let item = core::mem::size_of::<ExtentRecord>();
        let input = |capacity| {
            let mut values = Vec::with_capacity(capacity);
            values.push(sibling);
            values
        };
        // Grow a one-slot sibling list into the two-slot chain, allowing
        // allocator relocation to keep the old allocation alive temporarily.
        assert!(matches!(prepare_authority_chain_storage::<()>(input(1), &first, 3 * item - 1),
            Err(StoreError::MemoryLimit)));
        let (grown, growth_peak) = prepare_authority_chain_storage::<()>(input(1), &first, 3 * item).unwrap();
        assert_eq!(grown.as_slice(), &[sibling]);
        assert_eq!(grown.capacity(), 2);
        assert_eq!(growth_peak, 3 * item);
        // Oversized sibling capacity is retained until its replacement exists.
        assert!(matches!(prepare_authority_chain_storage::<()>(input(4), &first, 6 * item - 1),
            Err(StoreError::MemoryLimit)));
        let (replaced, replacement_peak) = prepare_authority_chain_storage::<()>(input(4), &first, 6 * item).unwrap();
        assert_eq!(replaced.as_slice(), &[sibling]);
        assert_eq!(replaced.capacity(), 2);
        assert_eq!(replacement_peak, 6 * item);
        let ready = input(2);
        let pointer = ready.as_ptr();
        let (reused, reuse_peak) = prepare_authority_chain_storage::<()>(ready, &first, 2 * item).unwrap();
        assert_eq!(reused.as_ptr(), pointer);
        assert_eq!(reused.capacity(), 2);
        assert_eq!(reuse_peak, 2 * item);
    }

    #[test]
    fn authority_collection_bounds_retained_history_and_rejects_extra_siblings() {
        let payload = [1_u8; 16];
        let mut first = build_extent(StoreUuid::new([7; 16]).unwrap(), 1, 1, 9, 1, DATA_FIRST_PAGE,
            ExtentKind::Authority, 1, 16, [1; 32], &payload).unwrap().value;
        first.extent_count = 2;
        let mut sibling = first;
        sibling.extent_index = 1;
        let mut old = first;
        old.binding.target_checkpoint_generation = 8;
        let mut selected = Vec::new();
        for _ in 0..10_000 {
            collect_requested_authority::<()>(&mut selected, old, 9, 2).unwrap();
        }
        assert_eq!(selected.capacity(), 0, "unrelated history must allocate nothing");
        collect_requested_authority::<()>(&mut selected, first, 9, 2).unwrap();
        collect_requested_authority::<()>(&mut selected, sibling, 9, 2).unwrap();
        let retained = selected.capacity();
        assert!(matches!(collect_requested_authority::<()>(&mut selected, sibling, 9, 2), Err(StoreError::Corrupt)));
        assert_eq!(selected.capacity(), retained);
        let mut records = Vec::with_capacity(2);
        records.push(first);
        let capacity = records.capacity();
        collect_authority_generation::<()>(&mut records, core::iter::repeat_n(old, 10_000), &first).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records.capacity(), capacity);
        collect_authority_generation::<()>(&mut records, [old, sibling, old], &first).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].extent_index, 1);
        assert_eq!(records.capacity(), capacity);
        // Continue checking later segments even after the expected count was
        // found, so a duplicate authenticated sibling cannot be hidden.
        assert!(matches!(collect_authority_generation::<()>(&mut records, [old, sibling], &first), Err(StoreError::Corrupt)));
        assert_eq!(records.len(), 2);
        assert_eq!(records.capacity(), capacity);
    }

    #[test]
    fn authority_decode_budget_includes_external_root_table() {
        use vibeos_durable_format::{RecordBody, RecordChain, StoreId};
        let records = RecordChain::new(StoreId::new(7).unwrap())
            .append(None, RecordBody::Format).unwrap().to_vec();
        let plain = PersistentAuthoritySnapshot::new(3, [1;32], records, vec![], vec![]).unwrap();
        let rooted = plain.clone().with_external_roots(vec![
            PersistentRootEntry { object_id: 1, commit_generation: 2, object_kind: 7 },
            PersistentRootEntry { object_id: 2, commit_generation: 3, object_kind: 8 },
        ]).unwrap();
        let before = crate::encode_persistent_authority_snapshot(&plain).unwrap();
        let encoded = crate::encode_persistent_authority_snapshot(&rooted).unwrap();
        let base = persistent_authority_decode_capacity_upper_bound::<()>(&before).unwrap();
        let required = persistent_authority_decode_capacity_upper_bound::<()>(&encoded).unwrap();
        assert_eq!(required - base, 2 * mem::size_of::<PersistentRootEntry>());
        let decoded = crate::authority_snapshot::decode_persistent_authority_snapshot(&encoded).unwrap();
        assert!(required >= decoded.allocated_bytes().unwrap());
        // The old estimate admitted this budget although the root table did
        // not fit. The pre-allocation check must reject it now.
        let budget = encoded.len() + required - 1;
        assert!(recovery_preflight_decode::<()>(budget, 0, encoded.len(), base).is_ok());
        assert!(matches!(recovery_preflight_decode::<()>(budget, 0, encoded.len(), required), Err(StoreError::MemoryLimit)));
        recovery_preflight_decode::<()>(budget+1, 0, encoded.len(), required).unwrap();
    }

    #[test]
    fn authority_roots_are_preallocated_budgeted_and_reject_collisions() {
        use vibeos_durable_format::{RecordBody, RecordChain, StoreId};
        let records = RecordChain::new(StoreId::new(7).unwrap()).append(None, RecordBody::Format).unwrap().to_vec();
        let snapshot = PersistentAuthoritySnapshot::new(3, [1;32], records, vec![
            crate::authority_snapshot::PersistentObjectBinding {
                stable_object_id: 1, v2_object_id: 3, commit_generation: 2, object_kind: 7,
            }
        ], vec![]).unwrap().with_external_roots(vec![
            PersistentRootEntry { object_id: 2, commit_generation: 3, object_kind: 8 },
        ]).unwrap();
        let encoded = crate::encode_persistent_authority_snapshot(&snapshot).unwrap();
        let roots = authority_roots_from_snapshot::<()>(&snapshot).unwrap();
        assert_eq!(roots.entries().iter().map(|entry| entry.object_id).collect::<Vec<_>>(), vec![2,3]);
        assert_eq!(roots.allocated_bytes().unwrap(), 2 * mem::size_of::<PersistentRootEntry>());
        let decoded = persistent_authority_decode_capacity_upper_bound::<()>(&encoded).unwrap();
        let required = persistent_authority_recovery_capacity_upper_bound::<()>(&encoded).unwrap();
        assert_eq!(required, decoded + roots.allocated_bytes().unwrap());
        let short = encoded.len()+required-1;
        assert!(recovery_preflight_decode::<()>(short, 0, encoded.len(), decoded).is_ok());
        assert!(matches!(recovery_preflight_decode::<()>(short, 0, encoded.len(), required), Err(StoreError::MemoryLimit)));
        recovery_preflight_decode::<()>(short+1, 0, encoded.len(), required).unwrap();
        assert!(snapshot.clone().with_external_roots(vec![
            PersistentRootEntry { object_id: 3, commit_generation: 2, object_kind: 7 },
        ]).is_err());
        // Crate-visible bindings can be changed internally; the root builder
        // remains defensive even if supplied a conflicting binding table.
        let mut colliding = snapshot;
        colliding.objects[0].v2_object_id = 2;
        assert!(matches!(authority_roots_from_snapshot::<()>(&colliding), Err(StoreError::Corrupt)));
    }

    struct Device {
        calls: RefCell<Vec<(u64, usize)>>,
        fail_at: Cell<Option<usize>>,
    }

    impl PageDevice for Device {
        type Error = ();
        fn info(&self) -> crate::device::PageDeviceInfo {
            unreachable!()
        }
        async fn write_page(&self, _: u64, _: &Page) -> Result<(), MutationFailure<()>> {
            unreachable!()
        }
        async fn flush(&self) -> Result<(), MutationFailure<()>> {
            unreachable!()
        }
        async fn read_page(&self, first: u64, out: &mut Page) -> Result<(), ()> {
            self.read_pages(first, core::slice::from_mut(out)).await
        }
        async fn read_pages(&self, first: u64, out: &mut [Page]) -> Result<(), ()> {
            let index = self.calls.borrow().len();
            self.calls.borrow_mut().push((first, out.len()));
            // Drivers may modify the DMA buffer before reporting failure.
            for (page_index, page) in out.iter_mut().enumerate() {
                for (byte_index, byte) in page.iter_mut().enumerate() {
                    *byte = (((first as usize + page_index) * PAGE_SIZE + byte_index) % 251) as u8;
                }
                if self.fail_at.get() == Some(index) {
                    return Err(());
                }
            }
            Ok(())
        }
    }

    fn run<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("memory device unexpectedly yielded"),
        }
    }

    #[test]
    fn payload_writes_borrow_full_batches_preserve_padding_and_failures() {
        struct Writer<'a> {
            source: &'a [u8],
            calls: RefCell<Vec<(u64, usize)>>,
            fail_at: Cell<Option<usize>>,
        }
        impl PageDevice for Writer<'_> {
            type Error = ();
            fn info(&self) -> crate::device::PageDeviceInfo { unreachable!() }
            async fn read_page(&self, _: u64, _: &mut Page) -> Result<(), ()> { unreachable!() }
            async fn write_page(&self, _: u64, _: &Page) -> Result<(), MutationFailure<()>> { unreachable!() }
            async fn flush(&self) -> Result<(), MutationFailure<()>> { panic!("helper changed barriers") }
            async fn write_pages(&self, first: u64, pages: &[Page]) -> Result<(), MutationFailure<()>> {
                let index = self.calls.borrow().len();
                self.calls.borrow_mut().push((first, pages.len()));
                let offset = (first - 7) as usize * PAGE_SIZE;
                let len = (self.source.len() - offset).min(32 * PAGE_SIZE);
                let expected = &self.source[offset..offset + len];
                assert_eq!(pages.len(), len.div_ceil(PAGE_SIZE));
                assert_eq!(&pages.as_flattened()[..len], expected);
                assert!(pages.as_flattened()[len..].iter().all(|byte| *byte == 0));
                if len % PAGE_SIZE == 0 {
                    assert_eq!(pages.as_flattened().as_ptr(), expected.as_ptr());
                }
                if self.fail_at.get() == Some(index) {
                    return Err(MutationFailure::ambiguous(()));
                }
                Ok(())
            }
        }
        for len in [0, 1, PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE + 1,
            31 * PAGE_SIZE + 1, 32 * PAGE_SIZE, 32 * PAGE_SIZE + 1,
            33 * PAGE_SIZE, 64 * PAGE_SIZE + 3] {
            // Deliberately offset the input: Page's byte alignment must not
            // impose a stronger alignment requirement on the caller.
            let input: Vec<u8> = (0..len + 1).map(|i| (i % 251) as u8).collect();
            let writer = Writer { source: &input[1..], calls: RefCell::new(Vec::new()), fail_at: Cell::new(None) };
            run(write_payload_pages(&writer, 7, writer.source)).unwrap();
            let expected: Vec<_> = (0..len.div_ceil(32 * PAGE_SIZE))
                .map(|i| (7 + (i * 32) as u64, (len - i * 32 * PAGE_SIZE).div_ceil(PAGE_SIZE).min(32)))
                .collect();
            assert_eq!(*writer.calls.borrow(), expected);
            for failure in 0..expected.len() {
                writer.calls.borrow_mut().clear();
                writer.fail_at.set(Some(failure));
                match run(write_payload_pages(&writer, 7, writer.source)) {
                    Err(StoreError::Mutation(error)) => assert_eq!(error.certainty(), MutationCertainty::Ambiguous),
                    other => panic!("unexpected write result: {other:?}"),
                }
                assert_eq!(*writer.calls.borrow(), expected[..=failure]);
            }
        }
    }

    #[test]
    fn owned_payload_coalescing_respects_budget_and_errors() {
        for len in [0, 1, PAGE_SIZE, PAGE_SIZE + 1, 2 * PAGE_SIZE - 1,
            31 * PAGE_SIZE + 1, 32 * PAGE_SIZE, 32 * PAGE_SIZE + 1] {
            let rounded = len.next_multiple_of(PAGE_SIZE);
            for budget in [0, rounded.saturating_sub(1), rounded] {
                let device = Device { calls: RefCell::new(Vec::new()), fail_at: Cell::new(None) };
                let bytes = run(read_payload_owned(&device, 7, len, budget)).unwrap();
                let expected: Vec<u8> = (0..len).map(|i| ((7 * PAGE_SIZE + i) % 251) as u8).collect();
                assert_eq!(bytes, expected);
                let eligible = len > PAGE_SIZE && len % PAGE_SIZE != 0
                    && rounded <= 32 * PAGE_SIZE && rounded <= budget;
                let calls = device.calls.borrow().clone();
                if eligible {
                    assert_eq!(calls, [(7, len.div_ceil(PAGE_SIZE))]);
                    assert!(bytes.capacity() <= budget);
                } else if len == PAGE_SIZE + 1 {
                    assert_eq!(calls, [(7, 1), (8, 1)]);
                }
                for failed in 0..calls.len() {
                    device.calls.borrow_mut().clear();
                    device.fail_at.set(Some(failed));
                    assert!(matches!(run(read_payload_owned(&device, 7, len, budget)),
                        Err(StoreError::Device(()))));
                    assert_eq!(*device.calls.borrow(), calls[..=failed]);
                }
            }
        }
    }

    #[test]
    fn payload_runs_bound_requests_and_propagate_partial_transfer_errors() {
        for len in [
            0,
            1,
            PAGE_SIZE - 1,
            PAGE_SIZE,
            PAGE_SIZE + 1,
            31 * PAGE_SIZE,
            32 * PAGE_SIZE,
            32 * PAGE_SIZE + 1,
            33 * PAGE_SIZE + 19,
            64 * PAGE_SIZE + 3,
        ] {
            let device = Device {
                calls: RefCell::new(Vec::new()),
                fail_at: Cell::new(None),
            };
            let expected: Vec<u8> = (0..len)
                .map(|i| ((7 * PAGE_SIZE + i) % 251) as u8)
                .collect();
            let mut bytes = vec![0; len];
            run(read_payload_into(&device, 7, &mut bytes)).unwrap();
            assert_eq!(bytes, expected);
            let calls = device.calls.borrow().clone();
            let mut next = 7;
            for &(first, count) in &calls {
                assert_eq!(first, next);
                assert!((1..=32).contains(&count));
                next += count as u64;
            }
            assert_eq!(next - 7, len.div_ceil(PAGE_SIZE) as u64);
            if len == 64 * PAGE_SIZE + 3 {
                assert_eq!(calls, [(7, 32), (39, 32), (71, 1)]);
            }
            for failure in 0..calls.len() {
                device.calls.borrow_mut().clear();
                device.fail_at.set(Some(failure));
                bytes.fill(0);
                assert!(matches!(
                    run(read_payload_into(&device, 7, &mut bytes)),
                    Err(StoreError::Device(()))
                ));
                assert_eq!(device.calls.borrow().len(), failure + 1);
                device.calls.borrow_mut().clear();
                device.fail_at.set(None);
                run(read_payload_into(&device, 7, &mut bytes)).unwrap();
                assert_eq!(bytes, expected);
            }
        }
    }
}

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
