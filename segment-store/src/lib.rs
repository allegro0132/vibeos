//! Bounded, append-only Storage V2 segment store.
//!
//! This crate owns store allocation and recovery, but it does not grant object
//! authority.  Media identities and physical pointers remain private behind an
//! opaque [`ObjectHandle`].

#![no_std]
#![allow(async_fn_in_trait)]

extern crate alloc;

mod codec;
mod compat;
mod device;
mod store;

pub use codec::{
    decode_allocation, decode_catalog, encode_allocation, encode_catalog, AllocationState,
    CatalogEntry, CatalogPayload, CatalogPayloadKind, CodecError, ALLOCATION_PAYLOAD_LEN,
    CATALOG_DELTA_HEADER_LEN, CATALOG_DELTA_PAYLOAD_LEN, CATALOG_ENTRY_LEN,
    CATALOG_SNAPSHOT_HEADER_LEN,
};
pub use compat::PutGetAdapter;
pub use device::{BlockPageDevice, BlockPageError, PageDevice, PageDeviceInfo};
pub use store::{
    CapacityClass, FormatOptions, ObjectHandle, SegmentStore, StoreError, StoreInfo, StoreLimits,
};
