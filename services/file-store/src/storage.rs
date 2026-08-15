//! Storage V2 transaction adapter.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vibeos_segment_store::{
    AuthorizedObject, CasObjectHandle, CasStoreError, FsNodeEntryInput, FsPersistentData,
    FsRootPublishError, FsStructuralCommitError, FsTreeKind, PageDevice, SegmentStore,
    StoragePrincipal, StoreError, StoreMaintenance,
};

use crate::{
    decode_dirent_key, decode_dirent_value, decode_inode_key, decode_inode_value,
    encode_dirent_key, encode_dirent_value, encode_inode_key, encode_inode_value, Content,
    FileError, FileId, FileTreeRoot, FileType, FsTransaction, Inode, NamespaceState,
    PersistedInodeV1,
};

#[derive(Debug)]
pub enum PersistentCommitError<E> {
    File(FileError),
    Store(CasStoreError<E>),
    Structure(FsStructuralCommitError<E>),
    Publish(FsRootPublishError<E>),
}

#[derive(Debug)]
pub enum PersistentLoadError<E> {
    File(FileError),
    Publish(FsRootPublishError<E>),
}

impl<E> From<FileError> for PersistentLoadError<E> {
    fn from(value: FileError) -> Self {
        Self::File(value)
    }
}

impl<E> From<FsRootPublishError<E>> for PersistentLoadError<E> {
    fn from(value: FsRootPublishError<E>) -> Self {
        Self::Publish(value)
    }
}

impl<E> From<FileError> for PersistentCommitError<E> {
    fn from(value: FileError) -> Self {
        Self::File(value)
    }
}

impl<E> From<CasStoreError<E>> for PersistentCommitError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<StoreError<E>> for PersistentCommitError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value.into())
    }
}

impl<E> From<FsStructuralCommitError<E>> for PersistentCommitError<E> {
    fn from(value: FsStructuralCommitError<E>) -> Self {
        Self::Structure(value)
    }
}

impl<E> From<FsRootPublishError<E>> for PersistentCommitError<E> {
    fn from(value: FsRootPublishError<E>) -> Self {
        Self::Publish(value)
    }
}

fn inode_size(inode: &Inode) -> u64 {
    match &inode.content {
        Content::None => 0,
        Content::Symlink(target) => target.len() as u64,
        Content::File(chunks) => chunks.iter().map(|chunk| chunk.len() as u64).sum(),
        Content::PersistentFile(data) => data.exact_len(),
    }
}

async fn commit_content<D: PageDevice>(
    store: &mut SegmentStore<D>,
    inode: &Inode,
    principal: Option<&StoragePrincipal>,
    maintenance: Option<&StoreMaintenance>,
) -> Result<Option<FsPersistentData>, PersistentCommitError<D::Error>> {
    let data = match &inode.content {
        Content::None => return Ok(None),
        Content::PersistentFile(data) => return Ok(Some(data.clone())),
        Content::File(chunks) => {
            let mut tail = None;
            if chunks.is_empty() {
                tail = Some(match (principal, maintenance) {
                    (Some(principal), None) => {
                        store
                            .commit_fs_data_chunk_for_principal(principal, None, &[])
                            .await?
                    }
                    (None, Some(maintenance)) => {
                        store
                            .commit_fs_data_chunk_for_maintenance(maintenance, None, &[])
                            .await?
                    }
                    (None, None) => store.commit_fs_data_chunk(None, &[]).await?,
                    (Some(_), Some(_)) => return Err(FileError::InvalidType.into()),
                });
            }
            for chunk in chunks {
                tail = Some(match (principal, maintenance) {
                    (Some(principal), None) => {
                        store
                            .commit_fs_data_chunk_for_principal(principal, tail.as_ref(), chunk)
                            .await?
                    }
                    (None, Some(maintenance)) => {
                        store
                            .commit_fs_data_chunk_for_maintenance(maintenance, tail.as_ref(), chunk)
                            .await?
                    }
                    (None, None) => store.commit_fs_data_chunk(tail.as_ref(), chunk).await?,
                    (Some(_), Some(_)) => return Err(FileError::InvalidType.into()),
                });
            }
            tail.ok_or(FileError::InvalidType)?
        }
        Content::Symlink(target) => match (principal, maintenance) {
            (Some(principal), None) => {
                store
                    .commit_fs_data_chunk_for_principal(principal, None, target.as_bytes())
                    .await?
            }
            (None, Some(maintenance)) => {
                store
                    .commit_fs_data_chunk_for_maintenance(maintenance, None, target.as_bytes())
                    .await?
            }
            (None, None) => store.commit_fs_data_chunk(None, target.as_bytes()).await?,
            (Some(_), Some(_)) => return Err(FileError::InvalidType.into()),
        },
    };
    Ok(Some(data))
}

async fn commit_tree<D: PageDevice>(
    store: &mut SegmentStore<D>,
    previous: Option<&vibeos_segment_store::FsPersistentRoot>,
    tree: FsTreeKind,
    generation: u64,
    entries: &[(Vec<u8>, Vec<u8>)],
    content: Option<&BTreeMap<FileId, FsPersistentData>>,
    principal: Option<&StoragePrincipal>,
    maintenance: Option<&StoreMaintenance>,
) -> Result<alloc::sync::Arc<AuthorizedObject<CasObjectHandle>>, PersistentCommitError<D::Error>> {
    let mut inputs = Vec::new();
    for (key, value) in entries {
        let data = if let Some(content) = content {
            let file_id = crate::decode_inode_key(key).map_err(|_| FileError::InvalidType)?;
            content.get(&file_id)
        } else {
            None
        };
        inputs.push(FsNodeEntryInput {
            key,
            value,
            child: None,
            data,
        });
    }
    match (principal, maintenance) {
        (Some(principal), None) => store
            .commit_fs_cow_tree_for_principal(principal, previous, tree, generation, &inputs)
            .await
            .map_err(Into::into),
        (None, Some(maintenance)) => store
            .commit_fs_cow_tree_for_maintenance(maintenance, previous, tree, generation, &inputs)
            .await
            .map_err(Into::into),
        (None, None) => store
            .commit_fs_cow_tree(previous, tree, generation, &inputs)
            .await
            .map_err(Into::into),
        (Some(_), Some(_)) => Err(FileError::InvalidType.into()),
    }
}

fn encode_namespace(
    state: &NamespaceState,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(Vec<u8>, Vec<u8>)>), FileError> {
    let mut inode_entries = Vec::new();
    for (file_id, inode) in &state.inodes {
        let metadata = PersistedInodeV1 {
            file_id: *file_id,
            file_type: inode.file_type,
            size: inode_size(inode),
            link_count: state.link_count(*file_id, inode.file_type),
            change_generation: if inode.change_generation == 0 {
                state.generation
            } else {
                inode.change_generation
            },
            has_content: inode.file_type != FileType::Directory,
        };
        inode_entries.push((
            encode_inode_key(*file_id)
                .map_err(|_| FileError::InvalidType)?
                .to_vec(),
            encode_inode_value(metadata)
                .map_err(|_| FileError::InvalidType)?
                .to_vec(),
        ));
    }
    let mut dirent_entries = Vec::new();
    for ((parent, name), child) in &state.dirents {
        dirent_entries.push((
            encode_dirent_key(*parent, name).map_err(|_| FileError::InvalidName)?,
            encode_dirent_value(*child)
                .map_err(|_| FileError::InvalidType)?
                .to_vec(),
        ));
    }
    Ok((inode_entries, dirent_entries))
}

impl FsTransaction {
    /// Persist all staged data and structural nodes, atomically switch the
    /// namespace root, then publish the same immutable state to local readers.
    /// Any error or cancellation before the root switch leaves only unreachable
    /// objects for GC and keeps the old namespace visible.
    pub async fn commit_persistent<D: PageDevice>(
        self,
        store: &mut SegmentStore<D>,
    ) -> Result<u64, PersistentCommitError<D::Error>> {
        self.commit_persistent_inner(store, None, None).await
    }

    pub async fn commit_persistent_for_principal<D: PageDevice>(
        self,
        store: &mut SegmentStore<D>,
        principal: &StoragePrincipal,
    ) -> Result<u64, PersistentCommitError<D::Error>> {
        self.commit_persistent_inner(store, Some(principal), None)
            .await
    }

    pub async fn commit_persistent_for_maintenance<D: PageDevice>(
        self,
        store: &mut SegmentStore<D>,
        maintenance: &StoreMaintenance,
    ) -> Result<u64, PersistentCommitError<D::Error>> {
        self.commit_persistent_inner(store, None, Some(maintenance))
            .await
    }

    async fn commit_persistent_inner<D: PageDevice>(
        mut self,
        store: &mut SegmentStore<D>,
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<u64, PersistentCommitError<D::Error>> {
        let generation = self.next_generation()?;
        self.working.generation = generation;
        for inode in self.working.inodes.values_mut() {
            if inode.change_generation == 0 {
                inode.change_generation = generation;
            }
        }
        if self.root.state.lock().generation != self.base_generation {
            return Err(FileError::Conflict.into());
        }

        // Every inode leaf is encoded from the complete namespace model, so
        // every non-directory entry must carry its content edge even when a
        // metadata-only edit (for example hard-link count) left the bytes
        // unchanged. PersistentFile returns the existing opaque handle and
        // therefore preserves COW reuse without reopening object identity.
        let content_inodes: Vec<FileId> = self
            .working
            .inodes
            .iter()
            .filter_map(|(file_id, inode)| {
                (inode.file_type != FileType::Directory).then_some(*file_id)
            })
            .collect();
        let mut content = BTreeMap::new();
        for file_id in content_inodes {
            let inode = self
                .working
                .inodes
                .get(&file_id)
                .ok_or(FileError::NotFound)?;
            if let Some(data) = commit_content(store, inode, principal, maintenance).await? {
                if inode.file_type == FileType::Regular {
                    self.working
                        .inodes
                        .get_mut(&file_id)
                        .ok_or(FileError::NotFound)?
                        .content = Content::PersistentFile(data.clone());
                }
                content.insert(file_id, data);
            }
        }
        let (inode_entries, dirent_entries) = encode_namespace(&self.working)?;
        let inode_root = commit_tree(
            store,
            self.previous_root.as_ref(),
            FsTreeKind::Inode,
            generation,
            &inode_entries,
            Some(&content),
            principal,
            maintenance,
        )
        .await?;
        let dirent_root = commit_tree(
            store,
            self.previous_root.as_ref(),
            FsTreeKind::Dirent,
            generation,
            &dirent_entries,
            None,
            principal,
            maintenance,
        )
        .await?;
        let new_root = match (principal, maintenance) {
            (Some(principal), None) => {
                store
                    .commit_fs_root_for_principal(
                        principal,
                        self.working.namespace,
                        generation,
                        self.working.next_file_id,
                        crate::ROOT_FILE_ID,
                        &inode_root,
                        &dirent_root,
                    )
                    .await?
            }
            (None, Some(maintenance)) => {
                store
                    .commit_fs_root_for_maintenance(
                        maintenance,
                        self.working.namespace,
                        generation,
                        self.working.next_file_id,
                        crate::ROOT_FILE_ID,
                        &inode_root,
                        &dirent_root,
                    )
                    .await?
            }
            (None, None) => {
                store
                    .commit_fs_root(
                        self.working.namespace,
                        generation,
                        self.working.next_file_id,
                        crate::ROOT_FILE_ID,
                        &inode_root,
                        &dirent_root,
                    )
                    .await?
            }
            (Some(_), Some(_)) => return Err(FileError::InvalidType.into()),
        };
        match maintenance {
            Some(maintenance) => {
                store
                    .compare_exchange_fs_root_for_maintenance(
                        maintenance,
                        self.working.namespace,
                        self.base_generation,
                        &new_root,
                    )
                    .await?;
            }
            None => {
                store
                    .compare_exchange_fs_root(
                        self.working.namespace,
                        self.base_generation,
                        &new_root,
                    )
                    .await?;
            }
        }
        let persisted = store
            .recover_fs_root(self.working.namespace)
            .await?
            .ok_or(FileError::InvalidType)?;

        *self.root.state.lock() = alloc::sync::Arc::new(self.working.clone());
        *self.root.persistent_root.lock() = Some(persisted);
        self.committed = true;
        assert!(self.root.release_writer_claim(self.claim));
        Ok(generation)
    }
}

impl FileTreeRoot {
    /// Cold-load one boot-policy-selected namespace by following only typed
    /// edges reachable from its opaque persistent root.
    pub async fn recover_persistent<D: PageDevice>(
        store: &SegmentStore<D>,
        namespace: u128,
        max_entries: usize,
    ) -> Result<Option<Self>, PersistentLoadError<D::Error>> {
        let Some(root) = store.recover_fs_root(namespace).await? else {
            return Ok(None);
        };
        let inode_entries = store
            .read_fs_tree(&root, FsTreeKind::Inode, max_entries)
            .await?;
        let dirent_entries = store
            .read_fs_tree(&root, FsTreeKind::Dirent, max_entries)
            .await?;
        let mut persisted_metadata = BTreeMap::new();
        let mut inodes = BTreeMap::new();
        for entry in inode_entries {
            let file_id = decode_inode_key(&entry.key).map_err(|_| FileError::InvalidType)?;
            let metadata =
                decode_inode_value(file_id, &entry.value).map_err(|_| FileError::InvalidType)?;
            if metadata.change_generation > root.generation()
                || metadata.file_id >= root.next_file_id()
                || metadata.has_content != entry.content.is_some()
            {
                return Err(FileError::InvalidType.into());
            }
            let content = match (metadata.file_type, entry.content) {
                (FileType::Directory, None) => Content::None,
                (FileType::Regular, Some(data)) => {
                    if data.exact_len() != metadata.size {
                        return Err(FileError::InvalidType.into());
                    }
                    Content::PersistentFile(data)
                }
                (FileType::Symlink, Some(data)) => {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(metadata.size as usize)
                        .map_err(|_| FileError::BudgetExceeded)?;
                    for index in 0..data.chunk_count() {
                        bytes.extend_from_slice(
                            &store
                                .read_fs_data_chunk(&data, index)
                                .await?
                                .ok_or(FileError::InvalidType)?,
                        );
                    }
                    if bytes.len() as u64 != metadata.size {
                        return Err(FileError::InvalidType.into());
                    }
                    Content::Symlink(
                        alloc::string::String::from_utf8(bytes)
                            .map_err(|_| FileError::InvalidType)?,
                    )
                }
                _ => return Err(FileError::InvalidType.into()),
            };
            persisted_metadata.insert(file_id, metadata);
            inodes.insert(
                file_id,
                Inode {
                    file_type: metadata.file_type,
                    change_generation: metadata.change_generation,
                    content,
                },
            );
        }
        let mut dirents = BTreeMap::new();
        for entry in dirent_entries {
            if entry.content.is_some() {
                return Err(FileError::InvalidType.into());
            }
            let (parent, name) =
                decode_dirent_key(&entry.key).map_err(|_| FileError::InvalidName)?;
            let child = decode_dirent_value(&entry.value).map_err(|_| FileError::InvalidType)?;
            if inodes.get(&parent).map(|inode| inode.file_type) != Some(FileType::Directory)
                || !inodes.contains_key(&child)
                || dirents.insert((parent, name.into()), child).is_some()
            {
                return Err(FileError::InvalidType.into());
            }
        }
        let state = NamespaceState {
            namespace,
            generation: root.generation(),
            next_file_id: root.next_file_id(),
            inodes,
            dirents,
        };
        if root.root_file_id() != crate::ROOT_FILE_ID
            || state
                .inodes
                .get(&crate::ROOT_FILE_ID)
                .map(|inode| inode.file_type)
                != Some(FileType::Directory)
            || persisted_metadata.iter().any(|(file_id, metadata)| {
                state.link_count(*file_id, metadata.file_type) != metadata.link_count
            })
            || state.inodes.iter().any(|(file_id, inode)| {
                if *file_id == crate::ROOT_FILE_ID {
                    return state.dirents.values().any(|child| child == file_id);
                }
                let incoming = state
                    .dirents
                    .values()
                    .filter(|child| *child == file_id)
                    .count();
                incoming == 0 || (inode.file_type == FileType::Directory && incoming != 1)
            })
        {
            return Err(FileError::InvalidType.into());
        }
        Ok(Some(Self {
            inner: alloc::sync::Arc::new(crate::FileTreeInner {
                state: vibeos_core::sync::SpinLock::new(alloc::sync::Arc::new(state)),
                persistent_root: vibeos_core::sync::SpinLock::new(Some(root)),
                writer_claim: vibeos_core::sync::SpinLock::new(None),
                next_writer_token: core::sync::atomic::AtomicU64::new(1),
                backend: None,
            }),
        }))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use vibeos_segment_format::{admitted_pages, Page, StoreUuid, PAGE_SIZE};
    use vibeos_segment_store::{FormatOptions, PageDeviceInfo, StoreLimits, StoreRuntimeContext};
    use vibeos_storage_device::MutationFailure;

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

    #[derive(Clone, Copy, Debug)]
    enum DeviceError {
        OutsideRange,
    }

    impl fmt::Display for DeviceError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{self:?}")
        }
    }

    #[derive(Clone)]
    struct MemoryDevice {
        page_count: u64,
        pages: Arc<Mutex<BTreeMap<u64, Page>>>,
    }

    impl MemoryDevice {
        fn blank(segments: u64) -> Self {
            Self {
                page_count: admitted_pages(segments).unwrap(),
                pages: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }
    }

    impl PageDevice for MemoryDevice {
        type Error = DeviceError;

        fn info(&self) -> PageDeviceInfo {
            PageDeviceInfo {
                device_id: [0x46; 16],
                range_first_logical_block: 0,
                logical_block_count: self.page_count * 8,
                logical_block_size: 512,
                page_count: self.page_count,
            }
        }

        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            if page >= self.page_count {
                return Err(DeviceError::OutsideRange);
            }
            *output = self
                .pages
                .lock()
                .unwrap()
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
                return Err(MutationFailure::not_submitted(DeviceError::OutsideRange));
            }
            self.pages.lock().unwrap().insert(page, *input);
            Ok(())
        }

        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            Ok(())
        }
    }

    fn limits() -> StoreLimits {
        StoreLimits {
            max_catalog_entries: 128,
            max_replay_records: 4,
            recovery_memory_bytes: 2 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        }
    }

    fn runtime() -> StoreRuntimeContext {
        StoreRuntimeContext::with_typed_reference_kinds(
            &vibeos_segment_store::fs_typed_reference_kinds(),
        )
        .unwrap()
    }

    struct TestBackend {
        store: Mutex<SegmentStore<MemoryDevice>>,
        maximum_staged_chunk: AtomicUsize,
    }

    impl crate::FileTreeBackend for TestBackend {
        fn stage_chunk<'a>(
            &'a self,
            previous: Option<vibeos_segment_store::FsPersistentData>,
            bytes: Vec<u8>,
        ) -> crate::FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
            self.maximum_staged_chunk
                .fetch_max(bytes.len(), Ordering::Relaxed);
            let result = block_on(
                self.store
                    .lock()
                    .unwrap()
                    .commit_fs_data_chunk(previous.as_ref(), &bytes),
            )
            .map_err(|_| crate::FileError::ServiceUnavailable);
            Box::pin(async move { result })
        }

        fn read_chunk<'a>(
            &'a self,
            data: vibeos_segment_store::FsPersistentData,
            index: u64,
        ) -> crate::FileTreeFuture<'a, Option<Vec<u8>>> {
            let result = block_on(self.store.lock().unwrap().read_fs_data_chunk(&data, index))
                .map_err(|_| crate::FileError::ServiceUnavailable);
            Box::pin(async move { result })
        }

        fn commit<'a>(
            &'a self,
            transaction: crate::FsTransaction,
        ) -> crate::FileTreeFuture<'a, u64> {
            let result = block_on(transaction.commit_persistent(&mut self.store.lock().unwrap()))
                .map_err(|error| match error {
                    PersistentCommitError::File(error) => error,
                    _ => crate::FileError::ServiceUnavailable,
                });
            Box::pin(async move { result })
        }
    }

    #[test]
    fn stager_carries_multi_mib_content_in_segment_sized_chunks() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d42_4947_4649_4c45_5f31;
        let device = MemoryDevice::blank(96);
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-BIGFILE!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let backend = Arc::new(TestBackend {
            store: Mutex::new(store),
            maximum_staged_chunk: AtomicUsize::new(0),
        });
        let mut root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        root.attach_backend(backend.clone()).unwrap();
        let path = crate::RelPath::parse("large").unwrap();

        // 20 MiB + a ragged tail: six full 3 MiB chunks plus a partial one.
        let total = 20 * 1024 * 1024 + 12345_usize;
        let mut stager = root.begin_content_stager(&path, false).unwrap();
        let mut written = 0_usize;
        let mut step = 0_u64;
        while written < total {
            let len = (total - written).min(1 << (14 + step % 8));
            let bytes: Vec<u8> = (written..written + len)
                .map(|offset| (offset % 251) as u8)
                .collect();
            block_on(stager.push(&bytes)).unwrap();
            written += len;
            step += 1;
        }
        let staged = block_on(stager.finish()).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction.write_staged(&path, staged).unwrap();
        assert_eq!(block_on(transaction.commit_authoritative()).unwrap(), 1);
        // The stager must have cut at the persistent stride, not at 4 KiB.
        assert_eq!(
            backend.maximum_staged_chunk.load(Ordering::Relaxed),
            crate::PERSISTENT_STAGE_CHUNK_SIZE
        );

        let reader = root.reader(&path).unwrap();
        assert_eq!(
            reader.chunk_count(),
            (total as u64).div_ceil(crate::PERSISTENT_STAGE_CHUNK_SIZE as u64)
        );
        let mut offset = 0_usize;
        for index in 0..reader.chunk_count() {
            let chunk = block_on(reader.read_chunk(index)).unwrap().unwrap();
            assert!(chunk
                .iter()
                .enumerate()
                .all(|(at, byte)| *byte == ((offset + at) % 251) as u8));
            offset += chunk.len();
        }
        assert_eq!(offset, total);
    }

    #[test]
    fn backend_stager_bounds_unknown_input_and_publishes_only_on_commit() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d53_5441_4745_5445_53;
        let device = MemoryDevice::blank(96);
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-STAGING!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let backend = Arc::new(TestBackend {
            store: Mutex::new(store),
            maximum_staged_chunk: AtomicUsize::new(0),
        });
        let mut root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        root.attach_backend(backend.clone()).unwrap();
        let path = crate::RelPath::parse("stream").unwrap();

        let mut abandoned = root.begin_content_stager(&path, false).unwrap();
        block_on(abandoned.push(&alloc::vec![0xaa; 9000])).unwrap();
        drop(abandoned);
        assert_eq!(root.snapshot().generation(), 0);
        assert!(matches!(
            root.snapshot().stat(&path, true),
            Err(crate::FileError::NotFound)
        ));

        let mut expected = Vec::new();
        let mut stager = root.begin_content_stager(&path, false).unwrap();
        for length in [1, 7000, 3, 8193, 4095] {
            let bytes = alloc::vec![(length % 251) as u8; length];
            expected.extend_from_slice(&bytes);
            block_on(stager.push(&bytes)).unwrap();
        }
        let staged = block_on(stager.finish()).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction.write_staged(&path, staged).unwrap();
        assert_eq!(block_on(transaction.commit_authoritative()).unwrap(), 1);
        assert!(
            backend.maximum_staged_chunk.load(Ordering::Relaxed)
                <= crate::PERSISTENT_STAGE_CHUNK_SIZE
        );

        let reader = root.reader(&path).unwrap();
        let mut actual = Vec::new();
        for index in 0..reader.chunk_count() {
            actual.extend(block_on(reader.read_chunk(index)).unwrap().unwrap());
        }
        assert_eq!(actual, expected);

        let mut stager = root.begin_content_stager(&path, true).unwrap();
        block_on(stager.push(b"tail")).unwrap();
        let staged = block_on(stager.finish()).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction.write_staged(&path, staged).unwrap();
        assert_eq!(block_on(transaction.commit_authoritative()).unwrap(), 2);
        let reader = root.reader(&path).unwrap();
        let mut appended = Vec::new();
        for index in 0..reader.chunk_count() {
            appended.extend(block_on(reader.read_chunk(index)).unwrap().unwrap());
        }
        expected.extend_from_slice(b"tail");
        assert_eq!(appended, expected);
    }

    #[test]
    fn governed_store_rejects_a_boot_local_file_tree_principal_from_persistent_policy() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d51_554f_5441_5445_53;
        let device = MemoryDevice::blank(48);
        let (context, quota, _maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let principal = quota
            .admit_principal(vibeos_segment_store::PrincipalQuotaLimits {
                logical_bytes: 8 * 1024 * 1024,
                physical_bytes: 32 * 1024 * 1024,
            })
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device, limits(), context);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-QUOTAS!!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction
            .mkdir(&crate::RelPath::parse("governed").unwrap(), false)
            .unwrap();
        assert!(matches!(
            block_on(transaction.commit_persistent_for_principal(&mut store, &principal)),
            Err(PersistentCommitError::Publish(FsRootPublishError::Gc(_)))
        ));
        assert!(block_on(store.recover_fs_root(NAMESPACE))
            .unwrap()
            .is_none());
    }

    #[test]
    fn governed_authority_and_file_tree_share_one_durable_checkpoint_root() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d41_5554_4846_5352_54;
        const POLICY: &[u8] = b"test authority plus opaque file-tree root v1";
        let device = MemoryDevice::blank(64);
        let (context, _quota, maintenance_provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), context);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-AUTHROOT").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let maintenance = store
            .provision_maintenance_root(&maintenance_provisioner)
            .unwrap();
        let import = vibeos_segment_store::PersistentAuthorityImport::empty(
            vibeos_durable_format::StoreId::new(91).unwrap(),
            POLICY,
            Vec::new(),
        )
        .unwrap();
        block_on(store.import_persistent_authority(&maintenance, import)).unwrap();

        let root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction
            .mkdir(&crate::RelPath::parse("etc").unwrap(), false)
            .unwrap();
        transaction
            .write_chunks(
                &crate::RelPath::parse("etc/config").unwrap(),
                [b"authority-preserved"],
                false,
            )
            .unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent_for_maintenance(&mut store, &maintenance,))
                .unwrap(),
            1
        );
        let authority = block_on(
            store
                .recover_persistent_authority(vibeos_segment_store::root_policy_commitment(POLICY)),
        )
        .unwrap();
        assert!(!authority.record_stream().is_empty());
        drop(authority);
        drop(store);

        let (cold_context, _cold_quota, _cold_maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), cold_context);
        block_on(cold.mount()).unwrap();
        let authority = block_on(
            cold.recover_persistent_authority(vibeos_segment_store::root_policy_commitment(POLICY)),
        )
        .unwrap();
        assert_eq!(authority.principals().len(), 1);
        let recovered = block_on(crate::FileTreeRoot::recover_persistent(
            &cold, NAMESPACE, 128,
        ))
        .unwrap()
        .unwrap();
        let data = recovered
            .snapshot()
            .persistent_data(&crate::RelPath::parse("etc/config").unwrap())
            .unwrap();
        assert_eq!(
            block_on(cold.read_fs_data_chunk(&data, 0))
                .unwrap()
                .unwrap(),
            b"authority-preserved"
        );
    }

    #[test]
    fn persistent_commit_switches_one_root_and_cold_recovers_generation() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d46_494c_4554_5245_45;
        let device = MemoryDevice::blank(48);
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), runtime());
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FILE-STORE!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction
            .mkdir(&crate::RelPath::parse("etc").unwrap(), false)
            .unwrap();
        transaction
            .write_chunks(
                &crate::RelPath::parse("etc/config").unwrap(),
                [b"durable"],
                false,
            )
            .unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent(&mut store)).unwrap(),
            1
        );
        assert_eq!(root.snapshot().generation(), 1);
        let objects_after_first = store.info().unwrap().object_count;
        let transaction = root.begin().unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent(&mut store)).unwrap(),
            2
        );
        assert_eq!(
            store.info().unwrap().object_count,
            objects_after_first + 1,
            "an unchanged transaction reuses both B+tree roots and data"
        );
        let objects_before_overwrite = store.info().unwrap().object_count;
        let mut transaction = root.begin().unwrap();
        transaction
            .write_chunks(
                &crate::RelPath::parse("etc/config").unwrap(),
                [b"updated"],
                false,
            )
            .unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent(&mut store)).unwrap(),
            3
        );
        assert_eq!(
            store.info().unwrap().object_count,
            objects_before_overwrite + 3,
            "overwrite writes data, the affected inode leaf, and the root only"
        );
        let mut transaction = root.begin().unwrap();
        transaction
            .hard_link(
                &crate::RelPath::parse("etc/config").unwrap(),
                &crate::RelPath::parse("etc/hard").unwrap(),
                false,
            )
            .unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent(&mut store)).unwrap(),
            4
        );
        drop(store);

        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(cold.mount()).unwrap();
        let recovered = block_on(cold.recover_fs_root(NAMESPACE)).unwrap().unwrap();
        assert_eq!(recovered.generation(), 4);
        assert_eq!(recovered.next_file_id(), 4);
        let recovered_tree = block_on(crate::FileTreeRoot::recover_persistent(
            &cold, NAMESPACE, 128,
        ))
        .unwrap()
        .unwrap();
        let data = recovered_tree
            .snapshot()
            .persistent_data(&crate::RelPath::parse("etc/config").unwrap())
            .unwrap();
        let mut bytes = Vec::new();
        for index in 0..data.chunk_count() {
            bytes.extend(
                block_on(cold.read_fs_data_chunk(&data, index))
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(bytes, b"updated");
        let snapshot = recovered_tree.snapshot();
        let config = snapshot
            .stat(&crate::RelPath::parse("etc/config").unwrap(), false)
            .unwrap();
        let hard = snapshot
            .stat(&crate::RelPath::parse("etc/hard").unwrap(), false)
            .unwrap();
        assert_eq!(config.file_id, hard.file_id);
        assert_eq!(config.link_count, 2);
    }
}
