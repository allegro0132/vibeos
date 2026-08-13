//! Narrow compatibility surface for the pre-streaming object API.

use alloc::vec::Vec;

use vibeos_segment_format::payload_sha256;

use crate::{
    FormatOptions, ObjectHandle, PageDevice, SegmentStore, StoreError, StoreInfo, StoreLimits,
};

/// Transitional `put/get` adapter used while authority publication remains in
/// `object-store`.  It exposes no digest lookup or object enumeration.
pub struct PutGetAdapter<D> {
    store: SegmentStore<D>,
}

impl<D: PageDevice> PutGetAdapter<D> {
    pub fn new(device: D, limits: StoreLimits) -> Self {
        Self {
            store: SegmentStore::new(device, limits),
        }
    }

    pub fn from_store(store: SegmentStore<D>) -> Self {
        Self { store }
    }

    pub fn into_store(self) -> SegmentStore<D> {
        self.store
    }

    pub fn info(&self) -> Result<StoreInfo, StoreError<D::Error>> {
        self.store.info()
    }

    pub async fn format(
        &mut self,
        options: FormatOptions,
    ) -> Result<StoreInfo, StoreError<D::Error>> {
        self.store.format(options).await
    }

    pub async fn mount(&mut self) -> Result<StoreInfo, StoreError<D::Error>> {
        self.store.mount().await
    }

    pub async fn put(
        &mut self,
        object_kind: u32,
        bytes: &[u8],
    ) -> Result<ObjectHandle, StoreError<D::Error>> {
        self.store
            .put(object_kind, payload_sha256(bytes), bytes)
            .await
    }

    pub async fn get(&self, handle: &ObjectHandle) -> Result<Vec<u8>, StoreError<D::Error>> {
        self.store.get(handle).await
    }
}
