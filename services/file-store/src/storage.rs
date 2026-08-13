//! Storage V2 transaction adapter.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vibeos_segment_store::{
    AuthorizedObject, CasObjectHandle, CasStoreError, FsNodeEntryInput, FsRootPublishError,
    FsStructuralCommitError, FsTreeKind, PageDevice, SegmentStore, StoreError, FS_DATA_V1_KIND,
};

use crate::{
    decode_dirent_key, decode_dirent_value, decode_inode_key, decode_inode_value,
    encode_dirent_key, encode_dirent_value, encode_inode_key, encode_inode_value, plan_btree_pages,
    BtreePagePlan, Content, FileError, FileId, FileTreeRoot, FileType, FsTransaction, Inode,
    NamespaceState, PersistedInodeV1,
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

struct BuiltNode {
    minimum_key: Vec<u8>,
    object: AuthorizedObject<CasObjectHandle>,
}

fn inode_size(inode: &Inode) -> u64 {
    match &inode.content {
        Content::None => 0,
        Content::Symlink(target) => target.len() as u64,
        Content::File(chunks) => chunks.iter().map(|chunk| chunk.len() as u64).sum(),
    }
}

async fn commit_content<D: PageDevice>(
    store: &mut SegmentStore<D>,
    inode: &Inode,
) -> Result<Option<AuthorizedObject<CasObjectHandle>>, PersistentCommitError<D::Error>> {
    let exact_len = inode_size(inode);
    let mut writer = match &inode.content {
        Content::None => return Ok(None),
        Content::File(_) | Content::Symlink(_) => {
            store.begin_blob(FS_DATA_V1_KIND, exact_len, None)?
        }
    };
    match &inode.content {
        Content::File(chunks) => {
            for chunk in chunks {
                writer.write_chunk(chunk).await?;
            }
        }
        Content::Symlink(target) => writer.write_chunk(target.as_bytes()).await?,
        Content::None => unreachable!(),
    }
    Ok(Some(writer.commit().await?))
}

async fn commit_tree<D: PageDevice>(
    store: &mut SegmentStore<D>,
    tree: FsTreeKind,
    generation: u64,
    entries: &[(Vec<u8>, Vec<u8>)],
    content: Option<&BTreeMap<FileId, AuthorizedObject<CasObjectHandle>>>,
    plan: &BtreePagePlan,
) -> Result<AuthorizedObject<CasObjectHandle>, PersistentCommitError<D::Error>> {
    let mut nodes = Vec::new();
    for range in &plan.levels[0] {
        let mut inputs = Vec::new();
        for (key, value) in &entries[range.clone()] {
            let child = if let Some(content) = content {
                let file_id = crate::decode_inode_key(key).map_err(|_| FileError::InvalidType)?;
                content.get(&file_id)
            } else {
                None
            };
            inputs.push(FsNodeEntryInput { key, value, child });
        }
        let object = store
            .commit_fs_btree_node(tree, 0, generation, &inputs)
            .await?;
        nodes.push(BuiltNode {
            minimum_key: entries
                .get(range.start)
                .map(|entry| entry.0.clone())
                .unwrap_or_default(),
            object,
        });
    }
    for (level, ranges) in plan.levels.iter().enumerate().skip(1) {
        let mut parents = Vec::new();
        for range in ranges {
            let mut inputs = Vec::new();
            for child in &nodes[range.clone()] {
                inputs.push(FsNodeEntryInput {
                    key: &child.minimum_key,
                    value: &[],
                    child: Some(&child.object),
                });
            }
            let object = store
                .commit_fs_btree_node(tree, level as u8, generation, &inputs)
                .await?;
            parents.push(BuiltNode {
                minimum_key: nodes[range.start].minimum_key.clone(),
                object,
            });
        }
        nodes = parents;
    }
    if nodes.len() != 1 {
        return Err(FileError::InvalidType.into());
    }
    Ok(nodes.pop().unwrap().object)
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

impl FsTransaction<'_> {
    /// Persist all staged data and structural nodes, atomically switch the
    /// namespace root, then publish the same immutable state to local readers.
    /// Any error or cancellation before the root switch leaves only unreachable
    /// objects for GC and keeps the old namespace visible.
    pub async fn commit_persistent<D: PageDevice>(
        mut self,
        store: &mut SegmentStore<D>,
    ) -> Result<u64, PersistentCommitError<D::Error>> {
        let generation = self.next_generation()?;
        self.working.generation = generation;
        if self.root.state.lock().generation != self.base_generation {
            return Err(FileError::Conflict.into());
        }

        let mut content = BTreeMap::new();
        for (file_id, inode) in &self.working.inodes {
            if let Some(object) = commit_content(store, inode).await? {
                content.insert(*file_id, object);
            }
        }
        let (inode_entries, dirent_entries) = encode_namespace(&self.working)?;
        let inode_plan = plan_btree_pages(&inode_entries).map_err(|_| FileError::InvalidType)?;
        let dirent_plan = plan_btree_pages(&dirent_entries).map_err(|_| FileError::InvalidType)?;
        let inode_root = commit_tree(
            store,
            FsTreeKind::Inode,
            generation,
            &inode_entries,
            Some(&content),
            &inode_plan,
        )
        .await?;
        let dirent_root = commit_tree(
            store,
            FsTreeKind::Dirent,
            generation,
            &dirent_entries,
            None,
            &dirent_plan,
        )
        .await?;
        let new_root = store
            .commit_fs_root(
                self.working.namespace,
                generation,
                self.working.next_file_id,
                crate::ROOT_FILE_ID,
                &inode_root,
                &dirent_root,
            )
            .await?;
        store
            .compare_exchange_fs_root(self.working.namespace, self.base_generation, &new_root)
            .await?;

        *self.root.state.lock() = alloc::sync::Arc::new(self.working.clone());
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
                    let mut chunks = Vec::new();
                    for index in 0..data.chunk_count() {
                        let bytes = store
                            .read_fs_data_chunk(&data, index)
                            .await?
                            .ok_or(FileError::InvalidType)?;
                        chunks.push(alloc::sync::Arc::<[u8]>::from(bytes));
                    }
                    if chunks.iter().map(|chunk| chunk.len() as u64).sum::<u64>() != metadata.size {
                        return Err(FileError::InvalidType.into());
                    }
                    Content::File(chunks)
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
        {
            return Err(FileError::InvalidType.into());
        }
        Ok(Some(Self {
            state: vibeos_core::sync::SpinLock::new(alloc::sync::Arc::new(state)),
            writer_claim: vibeos_core::sync::SpinLock::new(None),
            next_writer_token: core::sync::atomic::AtomicU64::new(1),
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
        drop(store);

        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(cold.mount()).unwrap();
        let recovered = block_on(cold.recover_fs_root(NAMESPACE)).unwrap().unwrap();
        assert_eq!(recovered.generation(), 1);
        assert_eq!(recovered.next_file_id(), 4);
        let recovered_tree = block_on(crate::FileTreeRoot::recover_persistent(
            &cold, NAMESPACE, 128,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            recovered_tree
                .snapshot()
                .read_chunks(&crate::RelPath::parse("etc/config").unwrap())
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"durable"
        );
    }
}
