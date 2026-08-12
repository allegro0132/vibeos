//! Capability-safe construction of canonical typed-reference manifests.
//!
//! The caller supplies already authorized child witnesses.  Their private
//! catalog tuple is revalidated against the mounted store before it is copied
//! into `refs-v1`; there is no `ObjectId`/digest lookup API.  Ordinary
//! [`SegmentStore::begin_blob`](crate::store::SegmentStore::begin_blob) keeps
//! tagging identical bytes as raw, while this builder alone selects the
//! typed-reference admission codec.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use vibeos_segment_format::PAGE_SIZE;

use crate::authority::AuthorizedObject;
use crate::cas::{CasObjectHandle, CasStoreError, ForegroundBlobError};
use crate::cas_codec::REFERENCE_CODEC_TYPED_V1;
use crate::device::PageDevice;
use crate::gc::{GcStoreError, GcTelemetry, GcTimeSource};
use crate::store::{SegmentStore, StoreError};
use crate::typed_manifest::{
    encode_typed_manifest_refs_v1, TypedManifestRefsV1, TypedObjectReference, TypedRefsError,
    MAX_TYPED_REFERENCES,
};

#[derive(Debug)]
pub enum TypedCommitError<E> {
    Store(CasStoreError<E>),
    Gc(GcStoreError<E>),
    Manifest(TypedRefsError),
    TooManyChildren,
}

impl<E: fmt::Display> fmt::Display for TypedCommitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::Gc(error) => write!(f, "{error}"),
            Self::Manifest(error) => write!(f, "{error}"),
            Self::TooManyChildren => {
                f.write_str("typed manifest exceeds the fixed child-reference bound")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> core::error::Error for TypedCommitError<E> {}

impl<E> From<CasStoreError<E>> for TypedCommitError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<StoreError<E>> for TypedCommitError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value.into())
    }
}

impl<E> From<GcStoreError<E>> for TypedCommitError<E> {
    fn from(value: GcStoreError<E>) -> Self {
        Self::Gc(value)
    }
}

impl<E> From<ForegroundBlobError<E>> for TypedCommitError<E> {
    fn from(value: ForegroundBlobError<E>) -> Self {
        match value {
            ForegroundBlobError::Cas(error) => Self::Store(error),
            ForegroundBlobError::Gc(error) => Self::Gc(error),
        }
    }
}

impl<E> From<TypedRefsError> for TypedCommitError<E> {
    fn from(value: TypedRefsError) -> Self {
        Self::Manifest(value)
    }
}

impl<D: PageDevice> SegmentStore<D> {
    fn typed_manifest_payload(
        &self,
        object_kind: u32,
        children: &[&AuthorizedObject<CasObjectHandle>],
    ) -> Result<Vec<u8>, TypedCommitError<D::Error>> {
        if children.len() > MAX_TYPED_REFERENCES || children.len() > crate::gc::GC_CHILD_BUDGET {
            return Err(TypedCommitError::TooManyChildren);
        }
        if self
            .typed_reference_kinds
            .binary_search(&object_kind)
            .is_err()
        {
            return Err(TypedRefsError::NotAdmitted.into());
        }
        let state = self.require_current_generation()?;
        let checkpoint_generation = state
            .generation
            .checked_add(1)
            .ok_or(StoreError::IdExhausted)?;
        // A freshly formatted store has no CAS snapshot yet; an empty typed
        // manifest is nevertheless a valid first CAS object. Non-empty child
        // input requires the selected catalog below.
        let cas = state.cas.as_ref();
        let store_uuid = state.superblock.binding.store_uuid;

        let mut references = Vec::new();
        references
            .try_reserve_exact(children.len())
            .map_err(|_| TypedCommitError::TooManyChildren)?;
        for child in children {
            let cas = cas.ok_or(StoreError::ObjectUnavailable)?;
            let handle = child.backend_handle();
            if handle.store_uuid() != store_uuid {
                return Err(StoreError::ObjectUnavailable.into());
            }
            let key = handle
                .root_key(&self.pins)
                .map_err(|_| StoreError::ObjectUnavailable)?;
            if key.object_kind() != child.object_kind() {
                return Err(StoreError::ObjectUnavailable.into());
            }
            let mapping = cas
                .objects
                .binary_search_by_key(&key.object_id(), |mapping| mapping.object_id)
                .ok()
                .map(|index| cas.objects[index])
                .filter(|mapping| {
                    mapping.commit_generation == key.commit_generation()
                        && mapping.blob_key.object_kind() == key.object_kind()
                        && mapping.blob_key.exact_len() == child.exact_len()
                })
                .ok_or(StoreError::ObjectUnavailable)?;
            references.push(TypedObjectReference {
                object_id: mapping.object_id,
                commit_generation: mapping.commit_generation,
                object_kind: mapping.blob_key.object_kind(),
            });
        }
        references.sort_unstable_by_key(|reference| reference.object_id);
        references.dedup();
        let manifest = TypedManifestRefsV1::new(object_kind, checkpoint_generation, references)?;
        encode_typed_manifest_refs_v1(&manifest).map_err(Into::into)
    }

    /// Commits a canonical `refs-v1` object whose only GC edges come from live
    /// child capabilities.  Repeated witnesses for the same exact object are
    /// deduplicated; conflicting generations/kinds cannot be manufactured
    /// because every tuple is recovered from the opaque handle and catalog.
    pub async fn commit_typed_manifest(
        &mut self,
        object_kind: u32,
        children: &[&AuthorizedObject<CasObjectHandle>],
    ) -> Result<AuthorizedObject<CasObjectHandle>, TypedCommitError<D::Error>> {
        let payload = self.typed_manifest_payload(object_kind, children)?;
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| TypedCommitError::TooManyChildren)?;
        let mut writer = self.begin_blob_with_reference_codec(
            object_kind,
            payload_len,
            None,
            REFERENCE_CODEC_TYPED_V1,
        )?;
        for chunk in payload.chunks(PAGE_SIZE) {
            writer.write_chunk(chunk).await?;
        }
        writer.commit().await.map_err(Into::into)
    }

    /// Foreground typed admission uses the same bounded cleaner path as raw
    /// streaming Blobs. The manifest is rebuilt after any collection so its
    /// embedded commit generation exactly matches the eventual CAS mapping.
    pub async fn commit_typed_manifest_with_foreground_gc<C: GcTimeSource>(
        &mut self,
        object_kind: u32,
        children: &[&AuthorizedObject<CasObjectHandle>],
        clock: &C,
    ) -> Result<(AuthorizedObject<CasObjectHandle>, Option<GcTelemetry>), TypedCommitError<D::Error>>
    {
        let probe = self.typed_manifest_payload(object_kind, children)?;
        let payload_len =
            u64::try_from(probe.len()).map_err(|_| TypedCommitError::TooManyChildren)?;
        drop(probe);
        let telemetry = self
            .prepare_blob_with_reference_codec_foreground_gc(
                object_kind,
                payload_len,
                None,
                REFERENCE_CODEC_TYPED_V1,
                clock,
            )
            .await?;
        let payload = self.typed_manifest_payload(object_kind, children)?;
        if payload.len() as u64 != payload_len {
            return Err(StoreError::RecoveryRequired.into());
        }
        let mut writer = self.begin_blob_with_reference_codec(
            object_kind,
            payload_len,
            None,
            REFERENCE_CODEC_TYPED_V1,
        )?;
        for chunk in payload.chunks(PAGE_SIZE) {
            writer.write_chunk(chunk).await?;
        }
        let object = writer.commit().await?;
        Ok((object, telemetry))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::rc::Rc;

    use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
    use vibeos_storage_device::MutationFailure;

    use crate::cas_codec::REFERENCE_CODEC_RAW;
    use crate::device::PageDeviceInfo;
    use crate::store::{FormatOptions, StoreLimits, StoreRuntimeContext};
    use crate::typed_manifest::{decode_typed_manifest_refs_v1, REFS_V1_ADMISSION_TAG};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        loop {
            match future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn typed_runtime(object_kind: u32) -> StoreRuntimeContext {
        StoreRuntimeContext::with_typed_reference_kinds(&[object_kind]).unwrap()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestDeviceError {
        OutsideRange,
    }

    impl fmt::Display for TestDeviceError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    #[derive(Clone)]
    struct TestDevice {
        page_count: u64,
        pages: Rc<RefCell<BTreeMap<u64, Page>>>,
    }

    impl TestDevice {
        fn blank(segment_count: u64) -> Self {
            Self {
                page_count: admitted_pages(segment_count).unwrap(),
                pages: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }
    }

    impl PageDevice for TestDevice {
        type Error = TestDeviceError;

        fn info(&self) -> PageDeviceInfo {
            PageDeviceInfo {
                device_id: [0x73; 16],
                range_first_logical_block: 0,
                logical_block_count: self.page_count * 8,
                logical_block_size: 512,
                page_count: self.page_count,
            }
        }

        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            if page >= self.page_count {
                return Err(TestDeviceError::OutsideRange);
            }
            *output = self
                .pages
                .borrow()
                .get(&page)
                .copied()
                .unwrap_or([0; PAGE_SIZE]);
            Ok(())
        }

        async fn write_page(
            &self,
            page: u64,
            input: &Page,
        ) -> Result<(), MutationFailure<Self::Error>> {
            if page >= self.page_count {
                return Err(MutationFailure::not_submitted(
                    TestDeviceError::OutsideRange,
                ));
            }
            self.pages.borrow_mut().insert(page, *input);
            Ok(())
        }

        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            Ok(())
        }
    }

    #[test]
    fn encoded_builder_payload_carries_the_refs_v1_admission_tag() {
        let manifest = TypedManifestRefsV1::new(0x44, 7, Vec::new()).unwrap();
        let payload = encode_typed_manifest_refs_v1(&manifest).unwrap();
        assert_eq!(&payload[0x10..0x20], &REFS_V1_ADMISSION_TAG);
        assert_eq!(decode_typed_manifest_refs_v1(&payload).unwrap(), manifest);
    }

    #[test]
    fn raw_and_typed_tag_values_are_distinct() {
        // The bytes alone do not choose the CAS admission tag: begin_blob()
        // hard-codes RAW, while commit_typed_manifest() passes TYPED_V1.
        assert_ne!(
            crate::cas_codec::REFERENCE_CODEC_RAW,
            REFERENCE_CODEC_TYPED_V1
        );
    }

    struct StepClock(Cell<u64>);

    impl GcTimeSource for StepClock {
        fn monotonic_ns(&self) -> u64 {
            let value = self.0.get();
            self.0.set(value + 100);
            value
        }
    }

    #[test]
    fn typed_foreground_admission_cleans_metadata_and_rebuilds_commit_generation() {
        const RAW_KIND: u32 = 0x5241_5721;
        const MANIFEST_KIND: u32 = 0x5459_5045;
        let limits = StoreLimits {
            max_catalog_entries: 1,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        };
        let mut store = SegmentStore::new_with_runtime_context(
            TestDevice::blank(16),
            limits,
            typed_runtime(MANIFEST_KIND),
        );
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new([0x7a; 16]).unwrap(),
            cleaner_reserve_segments: 5,
            limits,
        }))
        .unwrap();
        let mut garbage_writer = store.begin_blob(RAW_KIND, 1, None).unwrap();
        block_on(garbage_writer.write_chunk(&[0x41])).unwrap();
        let garbage = block_on(garbage_writer.commit()).unwrap();
        drop(garbage);
        block_on(store.synchronize_gc_roots(&[])).unwrap();

        let clock = StepClock(Cell::new(1_000));
        let (typed, telemetry) =
            block_on(store.commit_typed_manifest_with_foreground_gc(MANIFEST_KIND, &[], &clock))
                .unwrap();
        assert!(telemetry.is_some());
        let mapping = store
            .mounted
            .as_ref()
            .unwrap()
            .cas
            .as_ref()
            .unwrap()
            .objects[0];
        assert_eq!(mapping.reference_codec, REFERENCE_CODEC_TYPED_V1);
        let chunk = block_on(store.get_blob_chunk(&typed, 0)).unwrap();
        let decoded = decode_typed_manifest_refs_v1(&chunk.bytes).unwrap();
        assert_eq!(
            decoded.manifest_commit_generation,
            mapping.commit_generation
        );
    }

    #[test]
    fn identical_payload_deduplicates_but_raw_commit_never_inherits_typed_admission() {
        const MANIFEST_KIND: u32 = 0x5459_5045;
        let limits = StoreLimits {
            max_catalog_entries: 16,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        };
        let mut store = SegmentStore::new_with_runtime_context(
            TestDevice::blank(12),
            limits,
            typed_runtime(MANIFEST_KIND),
        );
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new([0x75; 16]).unwrap(),
            cleaner_reserve_segments: 2,
            limits,
        }))
        .unwrap();

        let typed = block_on(store.commit_typed_manifest(MANIFEST_KIND, &[])).unwrap();
        assert_eq!(typed.object_kind(), MANIFEST_KIND);

        // Recreate the exact bytes committed above, then intentionally admit
        // them through the ordinary raw writer. Complete-Blob dedup should
        // reuse bytes, while the second Object mapping must remain RAW.
        let exact_payload = encode_typed_manifest_refs_v1(
            &TypedManifestRefsV1::new(MANIFEST_KIND, 2, Vec::new()).unwrap(),
        )
        .unwrap();
        let mut raw_writer = store
            .begin_blob(MANIFEST_KIND, exact_payload.len() as u64, None)
            .unwrap();
        block_on(raw_writer.write_chunk(&exact_payload)).unwrap();
        let raw = block_on(raw_writer.commit()).unwrap();
        assert_eq!(raw.object_kind(), MANIFEST_KIND);

        let objects = &store
            .mounted
            .as_ref()
            .unwrap()
            .cas
            .as_ref()
            .unwrap()
            .objects;
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].blob_key, objects[1].blob_key);
        assert_eq!(objects[0].reference_codec, REFERENCE_CODEC_TYPED_V1);
        assert_eq!(objects[1].reference_codec, REFERENCE_CODEC_RAW);
    }

    #[test]
    fn authorized_children_are_sorted_deduplicated_and_streamed_canonically() {
        const CHILD_KIND: u32 = 0x4348_494c;
        const MANIFEST_KIND: u32 = 0x5459_5045;
        let limits = StoreLimits {
            max_catalog_entries: 16,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        };
        let mut store = SegmentStore::new_with_runtime_context(
            TestDevice::blank(16),
            limits,
            typed_runtime(MANIFEST_KIND),
        );
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new([0x76; 16]).unwrap(),
            cleaner_reserve_segments: 2,
            limits,
        }))
        .unwrap();

        let mut first_writer = store.begin_blob(CHILD_KIND, 5, None).unwrap();
        block_on(first_writer.write_chunk(b"first")).unwrap();
        let first = block_on(first_writer.commit()).unwrap();
        let mut second_writer = store.begin_blob(CHILD_KIND, 6, None).unwrap();
        block_on(second_writer.write_chunk(b"second")).unwrap();
        let second = block_on(second_writer.commit()).unwrap();

        let typed =
            block_on(store.commit_typed_manifest(MANIFEST_KIND, &[&second, &first, &second]))
                .unwrap();
        let chunk = block_on(store.get_blob_chunk(&typed, 0)).unwrap();
        let decoded = decode_typed_manifest_refs_v1(&chunk.bytes).unwrap();
        assert_eq!(decoded.references().len(), 2);
        assert!(
            decoded.references()[0].object_id < decoded.references()[1].object_id,
            "canonical refs-v1 order is strict ObjectId order"
        );
        assert_eq!(decoded.references()[0].commit_generation, 2);
        assert_eq!(decoded.references()[1].commit_generation, 3);
        assert!(decoded
            .references()
            .iter()
            .all(|reference| reference.object_kind == CHILD_KIND));
    }

    #[test]
    fn typed_commit_requires_a_trusted_runtime_object_kind_policy() {
        const MANIFEST_KIND: u32 = 0x5459_5045;
        let limits = StoreLimits {
            max_catalog_entries: 16,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        };
        let mut store = SegmentStore::new(TestDevice::blank(12), limits);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new([0x77; 16]).unwrap(),
            cleaner_reserve_segments: 2,
            limits,
        }))
        .unwrap();
        assert!(matches!(
            block_on(store.commit_typed_manifest(MANIFEST_KIND, &[])),
            Err(TypedCommitError::Manifest(TypedRefsError::NotAdmitted))
        ));
    }

    #[test]
    fn unregistered_valid_refs_payload_is_opaque_to_production_gc() {
        const CHILD_KIND: u32 = 0x4348_494c;
        const UNREGISTERED_KIND: u32 = 0x4f50_4151;
        let limits = StoreLimits {
            max_catalog_entries: 16,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        };
        let mut store = SegmentStore::new(TestDevice::blank(16), limits);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new([0x78; 16]).unwrap(),
            cleaner_reserve_segments: 4,
            limits,
        }))
        .unwrap();

        let mut child_writer = store.begin_blob(CHILD_KIND, 5, None).unwrap();
        block_on(child_writer.write_chunk(b"child")).unwrap();
        let child = block_on(child_writer.commit()).unwrap();
        let child_mapping = store
            .mounted
            .as_ref()
            .unwrap()
            .cas
            .as_ref()
            .unwrap()
            .objects[0];
        let payload = encode_typed_manifest_refs_v1(
            &TypedManifestRefsV1::new(
                UNREGISTERED_KIND,
                3,
                vec![TypedObjectReference {
                    object_id: child_mapping.object_id,
                    commit_generation: child_mapping.commit_generation,
                    object_kind: CHILD_KIND,
                }],
            )
            .unwrap(),
        )
        .unwrap();
        let mut forged_media_writer = store
            .begin_blob_with_reference_codec(
                UNREGISTERED_KIND,
                payload.len() as u64,
                None,
                REFERENCE_CODEC_TYPED_V1,
            )
            .unwrap();
        block_on(forged_media_writer.write_chunk(&payload)).unwrap();
        let parent = block_on(forged_media_writer.commit()).unwrap();

        block_on(store.synchronize_gc_roots(&[&parent])).unwrap();
        drop(child);
        let telemetry = block_on(store.collect_garbage()).unwrap();
        assert_eq!(telemetry.live_object_count, 1);
        assert_eq!(telemetry.live_blob_count, 1);
        assert_eq!(store.info().unwrap().object_count, 1);
        assert_eq!(
            block_on(store.get_blob_chunk(&parent, 0)).unwrap().bytes,
            payload
        );
    }
}
