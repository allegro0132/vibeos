//! Bounded, append-only Storage V2 segment store.
//!
//! This crate owns store allocation and recovery. Committed objects cross its
//! publication boundary only as opaque [`AuthorizedObject`] values; media
//! identities and physical pointers remain private behind [`ObjectHandle`].

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

mod authority;
mod cas;
mod cas_codec;
mod codec;
mod compat;
mod device;
mod store;

pub use authority::{
    AccessError, AuthorizedObject, AuthorizedObjectSpace, ObjectPublicationTarget,
    PublicationIntent, PublishError, resolve_authorized,
};
pub use cas::{
    BlobWriter, CasCommitError, CasObjectHandle, CasStoreError, VerifiedCasBlob, VerifiedCasChunk,
};
pub use cas_codec::{
    BLOB_KEY_LEN, BLOB_MANIFEST_HEADER_LEN, BLOB_MAPPING_LEN, BlobKey, BlobManifest, BlobMapping,
    CANONICAL_CONTENT_EXTENT_LEN, CAS_CODEC_VERSION, CAS_DELTA_HEADER_LEN, CAS_DELTA_NEW_BLOB_LEN,
    CAS_DELTA_REUSE_LEN, CAS_SNAPSHOT_HEADER_LEN, CasCodecContext, CasCodecError, CasDelta,
    CasSnapshot, MANIFEST_EXTENT_LEN, MAX_BLOB_CONTENT_LEN, MAX_BLOB_EXTENTS, ManifestExtent,
    OBJECT_MAPPING_LEN, ObjectMapping, canonical_blob_encoded_len, decode_blob_key,
    decode_blob_manifest, decode_cas_delta, decode_cas_snapshot, encode_blob_key,
    encode_blob_manifest, encode_cas_delta, encode_cas_snapshot,
};
pub use codec::{
    ALLOCATION_PAYLOAD_LEN, AllocationState, CATALOG_DELTA_HEADER_LEN, CATALOG_DELTA_PAYLOAD_LEN,
    CATALOG_ENTRY_LEN, CATALOG_SNAPSHOT_HEADER_LEN, CatalogEntry, CatalogPayload,
    CatalogPayloadKind, CodecError, decode_allocation, decode_catalog, encode_allocation,
    encode_catalog,
};
pub use compat::PutGetAdapter;
pub use device::{BlockPageDevice, BlockPageError, PageDevice, PageDeviceInfo};
pub use store::{
    CapacityClass, FormatOptions, ObjectHandle, SegmentStore, StoreError, StoreInfo, StoreLimits,
};
