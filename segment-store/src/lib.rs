//! Bounded, append-only Storage V2 segment store.
//!
//! This crate owns store allocation and recovery. Committed objects cross its
//! publication boundary only as opaque [`AuthorizedObject`] values; media
//! identities and physical pointers remain private behind [`ObjectHandle`].

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod allocation_v2;
mod authority;
mod authority_snapshot;
mod cas;
mod cas_codec;
mod codec;
mod compat;
mod device;
mod fs_api;
mod fs_codec;
mod fs_reference;
mod gc;
mod maintenance;
#[cfg(test)]
mod maintenance_growth_tests;
mod mark;
mod migration;
mod persistent_authority;
#[cfg(test)]
mod persistent_authority_tests;
mod pins;
mod quota;
#[cfg(test)]
mod quota_integration_tests;
mod root_codec;
mod scrub;
#[cfg(test)]
mod scrub_tests;
mod store;
mod typed_api;
mod typed_manifest;

pub use allocation_v2::{
    decode_allocation_v2, encode_allocation_v2, AllocationCounts, AllocationTransition,
    AllocationV2, AllocationV2Error, RetiredSegment, SegmentAllocation, ALLOCATION_V2_HEADER_LEN,
    ALLOCATION_V2_VERSION, MAX_ALLOCATION_V2_PAYLOAD_LEN, MAX_ALLOCATION_V2_SEGMENTS,
    RETIRED_SEGMENT_ENTRY_LEN,
};

pub use authority::{
    resolve_authorized, AccessError, AuthorizedObject, AuthorizedObjectSpace,
    AuthorizedPublication, ObjectPublicationPersistence, ObjectPublicationTarget,
    PublicationIntent, PublishError,
};
pub use authority_snapshot::{
    decode_persistent_authority_snapshot, encode_persistent_authority_snapshot,
    root_policy_commitment, AuthoritySnapshotError, PersistentAuthorityImport,
    PersistentAuthoritySnapshot, PersistentPrincipalPolicy, StablePrincipalId,
    LEGACY_SYSTEM_PRINCIPAL, MAX_PERSISTENT_AUTHORITY_PAYLOAD_LEN, MAX_STABLE_PRINCIPALS,
    PERSISTENT_AUTHORITY_HEADER_LEN, PERSISTENT_AUTHORITY_OBJECT_BINDING_LEN,
    PERSISTENT_AUTHORITY_PRINCIPAL_LEN, PERSISTENT_AUTHORITY_SNAPSHOT_VERSION,
};
pub use cas::{
    BlobWriter, CasCommitError, CasObjectHandle, CasStoreError, ForegroundBlobError,
    ReleasedRuntimePins, RuntimeObjectPin, RuntimeObjectPinClass, RuntimePinOwner,
    RuntimePinOwnerError, StoppedRuntimePinOwner, VerifiedCasBlob, VerifiedCasChunk,
};
pub use cas_codec::{
    canonical_blob_encoded_len, decode_blob_key, decode_blob_manifest, decode_cas_delta,
    decode_cas_snapshot, encode_blob_key, encode_blob_manifest, encode_cas_delta,
    encode_cas_snapshot, BlobKey, BlobManifest, BlobMapping, CasCodecContext, CasCodecError,
    CasDelta, CasSnapshot, ManifestExtent, ObjectMapping, BLOB_KEY_LEN, BLOB_MANIFEST_HEADER_LEN,
    BLOB_MAPPING_LEN, CANONICAL_CONTENT_EXTENT_LEN, CAS_CODEC_VERSION, CAS_DELTA_HEADER_LEN,
    CAS_DELTA_NEW_BLOB_LEN, CAS_DELTA_REUSE_LEN, CAS_GC_CODEC_VERSION, CAS_SNAPSHOT_HEADER_LEN,
    MANIFEST_EXTENT_LEN, MAX_BLOB_CONTENT_LEN, MAX_BLOB_EXTENTS, OBJECT_MAPPING_LEN,
    REFERENCE_CODEC_FS_V1, REFERENCE_CODEC_RAW, REFERENCE_CODEC_TYPED_V1,
};
pub use codec::{
    decode_allocation, decode_catalog, encode_allocation, encode_catalog, AllocationState,
    CatalogEntry, CatalogPayload, CatalogPayloadKind, CodecError, ALLOCATION_PAYLOAD_LEN,
    CATALOG_DELTA_HEADER_LEN, CATALOG_DELTA_PAYLOAD_LEN, CATALOG_ENTRY_LEN,
    CATALOG_SNAPSHOT_HEADER_LEN,
};
pub use compat::PutGetAdapter;
pub use device::{BlockPageDevice, BlockPageError, GrowablePageDevice, PageDevice, PageDeviceInfo};
pub use fs_api::{
    FsNodeEntryInput, FsPersistentData, FsPersistentRoot, FsPersistentTreeEntry,
    FsRootPublishError, FsStructuralCommitError,
};
pub use fs_codec::{
    decode_fs_btree_node_v1, decode_fs_root_v1, encode_fs_btree_node_v1, encode_fs_root_v1,
    FsBtreeEntryV1, FsBtreeNodeV1, FsCodecError, FsRootV1, FsTreeKind, FS_BTREE_HEADER_LEN,
    FS_BTREE_MAX_HEIGHT, FS_OBJECT_MAX_LEN, FS_ROOT_V1_LEN,
};
pub use fs_reference::{
    decode_fs_typed_references, fs_typed_reference_kinds, FsReferenceError, FS_BTREE_NODE_V1_KIND,
    FS_DATA_V1_KIND, FS_ROOT_V1_KIND,
};
pub use gc::{GcError, GcStoreError, GcTelemetry, GcTimeSource};
pub use maintenance::{
    GrowError, MaintenanceAuthorityError, MaintenanceOperation, StoreMaintenance,
    StoreMaintenanceProvisioner,
};
pub use migration::{
    decode_migration_control, encode_migration_control, probe_storage_formats,
    select_migration_control, ColdScrubEvidence, FormatProbe, LegacyFormatProbe, MigrationControl,
    MigrationControlError, MigrationController, MigrationError, MigrationState,
    MigrationTransition, MigrationWrite, StorageV2FormatProbe, CONTROL_BODY_MAGIC,
    CONTROL_FORMAT_VERSION, CONTROL_PAGE_COUNT, CONTROL_SEAL_MAGIC, CONTROL_TERMINAL_MARKER,
    M4_FIRST_LOGICAL_BLOCK, M4_LOGICAL_BLOCK_COUNT, MIGRATION_CONTROL_FIRST_LOGICAL_BLOCK,
    MIGRATION_CONTROL_LOGICAL_BLOCK_COUNT, V2_DEFAULT_FIRST_LOGICAL_BLOCK,
    V2_DEFAULT_LOGICAL_BLOCK_COUNT,
};
pub use persistent_authority::{
    PersistentAuthorityAppendResult, PersistentAuthorityError, PersistentAuthorityTransientObjects,
    PersistentAuthorityView, PersistentAuthorityWriter, PersistentObjectHandle,
    PersistentSingletonUpdate,
};
pub use quota::{
    canonical_attributable_physical_bytes, PrincipalQuotaLimits, PrincipalQuotaUsage,
    QuotaDiagnostics, QuotaError, StoragePrincipal, StorageQuotaProvisioner,
    DEFAULT_MAX_STORAGE_PRINCIPALS, QUOTA_DEDUP_UNIQUE_OBJECT_BYTES,
    QUOTA_PHYSICAL_FORMULA_VERSION,
};
pub use root_codec::{
    decode_persistent_root_set, encode_persistent_root_set, PersistentRootEntry, PersistentRootSet,
    RootCodecError, MAX_PERSISTENT_ROOT_ENTRIES, MAX_PERSISTENT_ROOT_SET_PAYLOAD_LEN,
    PERSISTENT_ROOT_ENTRY_LEN, PERSISTENT_ROOT_SET_HEADER_LEN, PERSISTENT_ROOT_SET_VERSION,
};
pub use scrub::{
    ScrubCorruptionDomain, ScrubDeviceHealth, ScrubError, ScrubReport, ScrubStatus,
    SCRUB_REPORT_VERSION,
};
pub use store::{
    CapacityClass, FormatOptions, ObjectHandle, RuntimeContextError, SegmentStore, StoreError,
    StoreInfo, StoreLimits, StoreRuntimeContext, MAX_TYPED_REFERENCE_KINDS,
    ROOT_POLICY_HEADROOM_SEGMENTS,
};
pub use typed_api::TypedCommitError;
pub use typed_manifest::{
    decode_typed_manifest_refs_v1, encode_typed_manifest_refs_v1, ReferenceCodecAdmission,
    ReferenceCodecTag, TypedManifestRefsV1, TypedObjectReference, TypedRefsError,
    MAX_TYPED_REFERENCES, MAX_TYPED_REFS_PAYLOAD_LEN, REFERENCE_CODEC_TAG_LEN,
    REFS_V1_ADMISSION_TAG, TYPED_REFERENCE_ENTRY_LEN, TYPED_REFS_HEADER_LEN, TYPED_REFS_VERSION,
};
