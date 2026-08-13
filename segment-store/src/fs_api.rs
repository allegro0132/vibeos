//! Opaque file-tree construction and persistent-root publication.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use vibeos_segment_format::PAGE_SIZE;

use crate::authority::AuthorizedObject;
use crate::cas::{
    recover_persistent_cas_object, recover_promotable_cas_object, CasObjectHandle, CasStoreError,
};
use crate::cas_codec::{ObjectMapping, REFERENCE_CODEC_FS_V1, REFERENCE_CODEC_RAW};
use crate::device::PageDevice;
use crate::gc::GcStoreError;
use crate::{
    decode_fs_btree_node_v1, encode_fs_btree_node_v1, encode_fs_root_v1, FsBtreeEntryV1,
    FsBtreeNodeV1, FsCodecError, FsRootV1, FsTreeKind, SegmentStore, StoreError,
    TypedObjectReference, FS_BTREE_MAX_HEIGHT, FS_BTREE_NODE_V1_KIND, FS_DATA_V1_KIND,
    FS_ROOT_V1_KIND,
};

pub struct FsNodeEntryInput<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
    pub child: Option<&'a AuthorizedObject<CasObjectHandle>>,
}

#[derive(Debug)]
pub enum FsStructuralCommitError<E> {
    Store(CasStoreError<E>),
    Codec(FsCodecError),
    InvalidChild,
}

impl<E> From<CasStoreError<E>> for FsStructuralCommitError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Store(value)
    }
}
impl<E> From<StoreError<E>> for FsStructuralCommitError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value.into())
    }
}
impl<E> From<FsCodecError> for FsStructuralCommitError<E> {
    fn from(value: FsCodecError) -> Self {
        Self::Codec(value)
    }
}

#[derive(Debug)]
pub enum FsRootPublishError<E> {
    Store(CasStoreError<E>),
    Gc(GcStoreError<E>),
    Codec(FsCodecError),
    Conflict,
    InvalidRoot,
    MultipleRoots,
}

impl<E> From<CasStoreError<E>> for FsRootPublishError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Store(value)
    }
}
impl<E> From<StoreError<E>> for FsRootPublishError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value.into())
    }
}
impl<E> From<GcStoreError<E>> for FsRootPublishError<E> {
    fn from(value: GcStoreError<E>) -> Self {
        Self::Gc(value)
    }
}
impl<E> From<FsCodecError> for FsRootPublishError<E> {
    fn from(value: FsCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Cold-recoverable namespace root. Object identity and CAS keys remain
/// private; callers can inspect only file-tree policy fields.
pub struct FsPersistentRoot {
    _object: Arc<AuthorizedObject<CasObjectHandle>>,
    decoded: FsRootV1,
}

#[derive(Clone)]
pub struct FsPersistentData {
    object: Arc<AuthorizedObject<CasObjectHandle>>,
}

impl FsPersistentData {
    pub fn exact_len(&self) -> u64 {
        self.object.exact_len()
    }

    pub fn chunk_count(&self) -> u64 {
        self.object.exact_len().div_ceil(PAGE_SIZE as u64)
    }
}

pub struct FsPersistentTreeEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub content: Option<FsPersistentData>,
}

impl FsPersistentRoot {
    pub const fn namespace_uuid(&self) -> u128 {
        self.decoded.namespace_uuid
    }
    pub const fn generation(&self) -> u64 {
        self.decoded.commit_generation
    }
    pub const fn next_file_id(&self) -> u64 {
        self.decoded.next_file_id
    }
    pub const fn root_file_id(&self) -> u64 {
        self.decoded.root_file_id
    }
}

impl<D: PageDevice> SegmentStore<D> {
    fn recover_fs_reference(
        &self,
        reference: TypedObjectReference,
        expected_kind: u32,
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsRootPublishError<D::Error>> {
        if reference.object_kind != expected_kind {
            return Err(FsRootPublishError::InvalidRoot);
        }
        let mapping = self
            .require_current_generation()?
            .cas
            .as_ref()
            .and_then(|cas| {
                cas.objects
                    .binary_search_by_key(&reference.object_id, |item| item.object_id)
                    .ok()
                    .map(|index| cas.objects[index])
            })
            .filter(|mapping| {
                mapping.commit_generation == reference.commit_generation
                    && mapping.blob_key.object_kind() == expected_kind
                    && match expected_kind {
                        FS_BTREE_NODE_V1_KIND => mapping.reference_codec == REFERENCE_CODEC_FS_V1,
                        FS_DATA_V1_KIND => mapping.reference_codec == REFERENCE_CODEC_RAW,
                        _ => false,
                    }
            })
            .ok_or(FsRootPublishError::InvalidRoot)?;
        Ok(Arc::new(
            recover_promotable_cas_object(
                self.require_current_generation()?
                    .superblock
                    .binding
                    .store_uuid,
                mapping,
                &self.pins,
            )
            .map_err(|_| StoreError::ObjectUnavailable)?,
        ))
    }

    fn fs_reference_for(
        &self,
        child: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<TypedObjectReference, FsStructuralCommitError<D::Error>> {
        let state = self.require_current_generation()?;
        let handle = child.backend_handle();
        if handle.store_uuid() != state.superblock.binding.store_uuid
            || handle.object_kind() != child.object_kind()
            || handle.exact_len() != child.exact_len()
        {
            return Err(FsStructuralCommitError::InvalidChild);
        }
        let key = handle
            .authority_key()
            .map_err(|_| FsStructuralCommitError::InvalidChild)?;
        let mapping = state
            .cas
            .as_ref()
            .and_then(|cas| {
                cas.objects
                    .binary_search_by_key(&key.object_id(), |item| item.object_id)
                    .ok()
                    .map(|index| cas.objects[index])
            })
            .filter(|mapping| {
                mapping.commit_generation == key.commit_generation()
                    && mapping.blob_key.object_kind() == key.object_kind()
                    && mapping.blob_key.exact_len() == child.exact_len()
                    && match mapping.blob_key.object_kind() {
                        FS_ROOT_V1_KIND | FS_BTREE_NODE_V1_KIND => {
                            mapping.reference_codec == REFERENCE_CODEC_FS_V1
                        }
                        crate::FS_DATA_V1_KIND => mapping.reference_codec == REFERENCE_CODEC_RAW,
                        _ => false,
                    }
            })
            .ok_or(FsStructuralCommitError::InvalidChild)?;
        Ok(TypedObjectReference {
            object_id: mapping.object_id,
            commit_generation: mapping.commit_generation,
            object_kind: mapping.blob_key.object_kind(),
        })
    }

    pub async fn commit_fs_btree_node(
        &mut self,
        tree: FsTreeKind,
        level: u8,
        namespace_generation: u64,
        entries: &[FsNodeEntryInput<'_>],
    ) -> Result<AuthorizedObject<CasObjectHandle>, FsStructuralCommitError<D::Error>> {
        let mut canonical = Vec::new();
        canonical
            .try_reserve_exact(entries.len())
            .map_err(|_| FsCodecError::OutOfBounds)?;
        for entry in entries {
            canonical.push(FsBtreeEntryV1 {
                key: entry.key.to_vec(),
                value: entry.value.to_vec(),
                reference: match entry.child {
                    Some(child) => Some(self.fs_reference_for(child)?),
                    None => None,
                },
            });
        }
        let payload = encode_fs_btree_node_v1(&FsBtreeNodeV1 {
            tree,
            level,
            commit_generation: namespace_generation,
            entries: canonical,
        })?;
        let mut writer = self.begin_blob_with_reference_codec(
            FS_BTREE_NODE_V1_KIND,
            payload.len() as u64,
            None,
            REFERENCE_CODEC_FS_V1,
        )?;
        for chunk in payload.chunks(PAGE_SIZE) {
            writer.write_chunk(chunk).await?;
        }
        writer.commit().await.map_err(Into::into)
    }

    pub async fn commit_fs_root(
        &mut self,
        namespace_uuid: u128,
        namespace_generation: u64,
        next_file_id: u64,
        root_file_id: u64,
        inode_tree: &AuthorizedObject<CasObjectHandle>,
        dirent_tree: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<AuthorizedObject<CasObjectHandle>, FsStructuralCommitError<D::Error>> {
        let inode_tree = self.fs_reference_for(inode_tree)?;
        let dirent_tree = self.fs_reference_for(dirent_tree)?;
        let payload = encode_fs_root_v1(&FsRootV1 {
            namespace_uuid,
            commit_generation: namespace_generation,
            next_file_id,
            root_file_id,
            inode_tree,
            dirent_tree,
        })?;
        let mut writer = self.begin_blob_with_reference_codec(
            FS_ROOT_V1_KIND,
            payload.len() as u64,
            None,
            REFERENCE_CODEC_FS_V1,
        )?;
        for chunk in payload.chunks(PAGE_SIZE) {
            writer.write_chunk(chunk).await?;
        }
        writer.commit().await.map_err(Into::into)
    }

    async fn read_fs_object_bytes(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<Vec<u8>, CasStoreError<D::Error>> {
        let verified = self.verify_blob(object).await?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(object.exact_len() as usize)
            .map_err(|_| StoreError::MemoryLimit)?;
        for index in 0..verified.descriptor.leaf_count {
            bytes.extend_from_slice(&self.get_blob_chunk(object, index).await?.bytes);
        }
        Ok(bytes)
    }

    fn current_fs_root_mapping(
        &self,
    ) -> Result<Option<ObjectMapping>, FsRootPublishError<D::Error>> {
        let state = self.require_current_generation()?;
        let Some(roots) = state.persistent_roots.as_ref() else {
            return Ok(None);
        };
        let mut selected = None;
        for root in roots
            .entries()
            .iter()
            .filter(|root| root.object_kind == FS_ROOT_V1_KIND)
        {
            if selected.is_some() {
                return Err(FsRootPublishError::MultipleRoots);
            }
            selected = state
                .cas
                .as_ref()
                .and_then(|cas| {
                    cas.objects
                        .binary_search_by_key(&root.object_id, |item| item.object_id)
                        .ok()
                        .map(|index| cas.objects[index])
                })
                .filter(|mapping| {
                    mapping.commit_generation == root.commit_generation
                        && mapping.blob_key.object_kind() == root.object_kind
                        && mapping.reference_codec == REFERENCE_CODEC_FS_V1
                });
            if selected.is_none() {
                return Err(FsRootPublishError::InvalidRoot);
            }
        }
        Ok(selected)
    }

    /// Atomically replace the unique file-tree persistent root only if the
    /// currently durable namespace generation matches `expected_generation`.
    pub async fn compare_exchange_fs_root(
        &mut self,
        namespace_uuid: u128,
        expected_generation: u64,
        new_root: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<u64, FsRootPublishError<D::Error>> {
        if new_root.object_kind() != FS_ROOT_V1_KIND {
            return Err(FsRootPublishError::InvalidRoot);
        }
        let new_key = new_root
            .backend_handle()
            .authority_key()
            .map_err(|_| FsRootPublishError::InvalidRoot)?;
        self.require_current_generation()?
            .cas
            .as_ref()
            .and_then(|cas| {
                cas.objects
                    .binary_search_by_key(&new_key.object_id(), |item| item.object_id)
                    .ok()
                    .map(|index| cas.objects[index])
            })
            .filter(|mapping| {
                mapping.commit_generation == new_key.commit_generation()
                    && mapping.blob_key.object_kind() == FS_ROOT_V1_KIND
                    && mapping.reference_codec == REFERENCE_CODEC_FS_V1
            })
            .ok_or(FsRootPublishError::InvalidRoot)?;
        let next = crate::decode_fs_root_v1(&self.read_fs_object_bytes(new_root).await?)?;
        if next.namespace_uuid != namespace_uuid
            || next.commit_generation
                != expected_generation
                    .checked_add(1)
                    .ok_or(FsRootPublishError::Conflict)?
        {
            return Err(FsRootPublishError::Conflict);
        }
        match self.current_fs_root_mapping()? {
            None if expected_generation == 0 => {}
            Some(mapping) => {
                let current = recover_persistent_cas_object(
                    self.require_current_generation()?
                        .superblock
                        .binding
                        .store_uuid,
                    mapping,
                );
                let decoded =
                    crate::decode_fs_root_v1(&self.read_fs_object_bytes(&current).await?)?;
                if decoded.namespace_uuid != namespace_uuid
                    || decoded.commit_generation != expected_generation
                {
                    return Err(FsRootPublishError::Conflict);
                }
            }
            None => return Err(FsRootPublishError::Conflict),
        }
        self.synchronize_gc_roots(&[new_root]).await?;
        // Re-read the checkpoint and the selected root before acknowledging.
        let mapping = self
            .current_fs_root_mapping()?
            .ok_or(FsRootPublishError::InvalidRoot)?;
        let persisted = recover_persistent_cas_object(
            self.require_current_generation()?
                .superblock
                .binding
                .store_uuid,
            mapping,
        );
        let observed = crate::decode_fs_root_v1(&self.read_fs_object_bytes(&persisted).await?)?;
        if observed.namespace_uuid != namespace_uuid
            || observed.commit_generation != next.commit_generation
        {
            return Err(FsRootPublishError::InvalidRoot);
        }
        Ok(observed.commit_generation)
    }

    pub async fn recover_fs_root(
        &self,
        namespace_uuid: u128,
    ) -> Result<Option<FsPersistentRoot>, FsRootPublishError<D::Error>> {
        let Some(mapping) = self.current_fs_root_mapping()? else {
            return Ok(None);
        };
        let object = Arc::new(recover_persistent_cas_object(
            self.require_current_generation()?
                .superblock
                .binding
                .store_uuid,
            mapping,
        ));
        let decoded = crate::decode_fs_root_v1(&self.read_fs_object_bytes(&object).await?)?;
        if decoded.namespace_uuid != namespace_uuid {
            return Ok(None);
        }
        Ok(Some(FsPersistentRoot {
            _object: object,
            decoded,
        }))
    }

    /// Traverse only typed children reachable from the supplied opaque root.
    /// The caller chooses a fixed entry budget before any allocation growth.
    pub async fn read_fs_tree(
        &self,
        root: &FsPersistentRoot,
        tree: FsTreeKind,
        max_entries: usize,
    ) -> Result<Vec<FsPersistentTreeEntry>, FsRootPublishError<D::Error>> {
        let reference = match tree {
            FsTreeKind::Inode => root.decoded.inode_tree,
            FsTreeKind::Dirent => root.decoded.dirent_tree,
        };
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(1)
            .map_err(|_| StoreError::MemoryLimit)?;
        pending.push((reference, None::<Vec<u8>>));
        let mut output = Vec::new();
        while let Some((reference, expected_minimum)) = pending.pop() {
            let object = self.recover_fs_reference(reference, FS_BTREE_NODE_V1_KIND)?;
            let node = decode_fs_btree_node_v1(&self.read_fs_object_bytes(&object).await?)?;
            if node.tree != tree
                || node.level > FS_BTREE_MAX_HEIGHT
                || node.commit_generation > root.decoded.commit_generation
                || expected_minimum.as_ref().is_some_and(|minimum| {
                    node.entries.first().map(|entry| &entry.key) != Some(minimum)
                })
            {
                return Err(FsRootPublishError::InvalidRoot);
            }
            if node.level == 0 {
                if output.len().saturating_add(node.entries.len()) > max_entries {
                    return Err(StoreError::MemoryLimit.into());
                }
                output
                    .try_reserve(node.entries.len())
                    .map_err(|_| StoreError::MemoryLimit)?;
                for entry in node.entries {
                    let content = match entry.reference {
                        Some(reference) => Some(FsPersistentData {
                            object: self.recover_fs_reference(reference, FS_DATA_V1_KIND)?,
                        }),
                        None => None,
                    };
                    output.push(FsPersistentTreeEntry {
                        key: entry.key,
                        value: entry.value,
                        content,
                    });
                }
            } else {
                if pending.len().saturating_add(node.entries.len()) > max_entries.max(1) {
                    return Err(StoreError::MemoryLimit.into());
                }
                pending
                    .try_reserve(node.entries.len())
                    .map_err(|_| StoreError::MemoryLimit)?;
                for entry in node.entries.into_iter().rev() {
                    let child = entry.reference.ok_or(FsRootPublishError::InvalidRoot)?;
                    pending.push((child, Some(entry.key)));
                }
            }
        }
        if output.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err(FsRootPublishError::InvalidRoot);
        }
        Ok(output)
    }

    pub async fn read_fs_data_chunk(
        &self,
        data: &FsPersistentData,
        index: u64,
    ) -> Result<Option<Vec<u8>>, FsRootPublishError<D::Error>> {
        if index >= data.chunk_count() {
            return Ok(None);
        }
        let index = u32::try_from(index).map_err(|_| FsRootPublishError::InvalidRoot)?;
        Ok(Some(self.get_blob_chunk(&data.object, index).await?.bytes))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::{Arc as StdArc, Mutex};

    use vibeos_segment_format::{admitted_pages, Page, StoreUuid};
    use vibeos_storage_device::MutationFailure;

    use crate::device::PageDeviceInfo;
    use crate::store::{FormatOptions, StoreLimits, StoreRuntimeContext};

    const NAMESPACE: u128 = 0x5649_4245_4f53_2d46_494c_4554_5245_45;

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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Injected,
        DriverRestarted,
        OutsideRange,
    }

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    #[derive(Clone)]
    struct TestDevice {
        media: StdArc<Mutex<TestMedia>>,
    }

    #[derive(Clone, Copy)]
    enum FaultAction {
        NotSubmitted,
        AmbiguousNone,
        AmbiguousDurable,
    }

    struct TestMedia {
        page_count: u64,
        visible: BTreeMap<u64, Page>,
        durable: BTreeMap<u64, Page>,
        mutation_count: usize,
        fault: Option<(usize, FaultAction)>,
    }

    impl TestDevice {
        fn blank(segment_count: u64) -> Self {
            Self {
                media: StdArc::new(Mutex::new(TestMedia {
                    page_count: admitted_pages(segment_count).unwrap(),
                    visible: BTreeMap::new(),
                    durable: BTreeMap::new(),
                    mutation_count: 0,
                    fault: None,
                })),
            }
        }

        fn reset_mutations(&self) {
            let mut media = self.media.lock().unwrap();
            media.mutation_count = 0;
            media.fault = None;
        }

        fn mutation_count(&self) -> usize {
            self.media.lock().unwrap().mutation_count
        }

        fn arm(&self, boundary: usize, action: FaultAction) {
            let mut media = self.media.lock().unwrap();
            media.mutation_count = 0;
            media.fault = Some((boundary, action));
        }

        fn next_action(&self) -> Option<FaultAction> {
            let mut media = self.media.lock().unwrap();
            let index = media.mutation_count;
            media.mutation_count += 1;
            media
                .fault
                .filter(|(boundary, _)| *boundary == index)
                .map(|(_, action)| action)
        }

        fn power_cycle(&self) {
            let mut media = self.media.lock().unwrap();
            media.visible = media.durable.clone();
            media.mutation_count = 0;
            media.fault = None;
        }
    }

    impl PageDevice for TestDevice {
        type Error = TestError;

        fn info(&self) -> PageDeviceInfo {
            let page_count = self.media.lock().unwrap().page_count;
            PageDeviceInfo {
                device_id: [0x66; 16],
                range_first_logical_block: 0,
                logical_block_count: page_count * 8,
                logical_block_size: 512,
                page_count,
            }
        }

        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            let media = self.media.lock().unwrap();
            if page >= media.page_count {
                return Err(TestError::OutsideRange);
            }
            *output = media.visible.get(&page).copied().unwrap_or([0; PAGE_SIZE]);
            Ok(())
        }

        async fn write_page(
            &self,
            page: u64,
            input: &Page,
        ) -> Result<(), MutationFailure<Self::Error>> {
            if page >= self.media.lock().unwrap().page_count {
                return Err(MutationFailure::not_submitted(TestError::OutsideRange));
            }
            match self.next_action() {
                None => {
                    self.media.lock().unwrap().visible.insert(page, *input);
                    Ok(())
                }
                Some(FaultAction::NotSubmitted) => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                Some(FaultAction::AmbiguousNone) => {
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
                Some(FaultAction::AmbiguousDurable) => {
                    let mut media = self.media.lock().unwrap();
                    media.visible.insert(page, *input);
                    media.durable.insert(page, *input);
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
            }
        }

        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            match self.next_action() {
                None => {
                    let mut media = self.media.lock().unwrap();
                    media.durable = media.visible.clone();
                    Ok(())
                }
                Some(FaultAction::NotSubmitted) => {
                    Err(MutationFailure::not_submitted(TestError::Injected))
                }
                Some(FaultAction::AmbiguousNone) => {
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
                Some(FaultAction::AmbiguousDurable) => {
                    let mut media = self.media.lock().unwrap();
                    media.durable = media.visible.clone();
                    Err(MutationFailure::ambiguous(TestError::DriverRestarted))
                }
            }
        }
    }

    fn limits() -> StoreLimits {
        StoreLimits {
            max_catalog_entries: 64,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        }
    }

    fn runtime() -> StoreRuntimeContext {
        StoreRuntimeContext::with_typed_reference_kinds(&crate::fs_typed_reference_kinds()).unwrap()
    }

    fn format(device: TestDevice) -> SegmentStore<TestDevice> {
        let store_limits = limits();
        let mut store = SegmentStore::new_with_runtime_context(device, store_limits, runtime());
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-ROOT-V1!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: store_limits,
        }))
        .unwrap();
        store
    }

    fn empty_root(
        store: &mut SegmentStore<TestDevice>,
        generation: u64,
        next_file_id: u64,
    ) -> AuthorizedObject<CasObjectHandle> {
        let inode =
            block_on(store.commit_fs_btree_node(FsTreeKind::Inode, 0, generation, &[])).unwrap();
        let dirent =
            block_on(store.commit_fs_btree_node(FsTreeKind::Dirent, 0, generation, &[])).unwrap();
        block_on(store.commit_fs_root(NAMESPACE, generation, next_file_id, 1, &inode, &dirent))
            .unwrap()
    }

    #[test]
    fn persistent_root_compare_exchange_is_opaque_conflict_checked_and_cold_recoverable() {
        let device = TestDevice::blank(48);
        let mut store = format(device.clone());
        let first = empty_root(&mut store, 1, 2);
        assert_eq!(
            block_on(store.compare_exchange_fs_root(NAMESPACE, 0, &first)).unwrap(),
            1
        );

        let stale = empty_root(&mut store, 1, 3);
        assert!(matches!(
            block_on(store.compare_exchange_fs_root(NAMESPACE, 0, &stale)),
            Err(FsRootPublishError::Conflict)
        ));
        assert_eq!(
            block_on(store.recover_fs_root(NAMESPACE))
                .unwrap()
                .unwrap()
                .next_file_id(),
            2
        );

        let second = empty_root(&mut store, 2, 4);
        assert_eq!(
            block_on(store.compare_exchange_fs_root(NAMESPACE, 1, &second)).unwrap(),
            2
        );
        drop(store);

        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(cold.mount()).unwrap();
        let recovered = block_on(cold.recover_fs_root(NAMESPACE)).unwrap().unwrap();
        assert_eq!(recovered.namespace_uuid(), NAMESPACE);
        assert_eq!(recovered.generation(), 2);
        assert_eq!(recovered.next_file_id(), 4);
        assert_eq!(recovered.root_file_id(), 1);
    }

    fn root_switch_fixture() -> (
        TestDevice,
        SegmentStore<TestDevice>,
        AuthorizedObject<CasObjectHandle>,
    ) {
        let device = TestDevice::blank(48);
        let mut store = format(device.clone());
        let first = empty_root(&mut store, 1, 2);
        block_on(store.compare_exchange_fs_root(NAMESPACE, 0, &first)).unwrap();
        let second = empty_root(&mut store, 2, 4);
        (device, store, second)
    }

    #[test]
    fn every_root_switch_mutation_recovers_complete_old_or_new_root() {
        let (probe_device, mut probe, probe_root) = root_switch_fixture();
        probe_device.reset_mutations();
        assert_eq!(
            block_on(probe.compare_exchange_fs_root(NAMESPACE, 1, &probe_root)).unwrap(),
            2
        );
        let mutation_count = probe_device.mutation_count();
        assert!(mutation_count > 0);

        for boundary in 0..mutation_count {
            for action in [
                FaultAction::NotSubmitted,
                FaultAction::AmbiguousNone,
                FaultAction::AmbiguousDurable,
            ] {
                let (device, mut store, next) = root_switch_fixture();
                device.arm(boundary, action);
                assert!(block_on(store.compare_exchange_fs_root(NAMESPACE, 1, &next)).is_err());
                device.power_cycle();

                let mut cold =
                    SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime());
                block_on(cold.mount()).unwrap_or_else(|error| {
                    panic!("boundary {boundary}: cold mount failed: {error:?}")
                });
                let recovered = block_on(cold.recover_fs_root(NAMESPACE)).unwrap().unwrap();
                assert!(
                    matches!(
                        (recovered.generation(), recovered.next_file_id()),
                        (1, 2) | (2, 4)
                    ),
                    "boundary {boundary} recovered a partial root"
                );
            }
        }
    }
}
