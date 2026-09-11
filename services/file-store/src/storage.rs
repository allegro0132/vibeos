//! Storage V2 transaction adapter.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vibeos_segment_store::{
    AuthorizedObject, CasObjectHandle, CasStoreError, FsNodeEntryInput, FsPendingContent,
    FsPersistentData, FsRootPublishError, FsStructuralCommitError, FsTreeKind, PageDevice, SegmentStore,
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
            pending: None,
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
    inode_entries
        .try_reserve_exact(state.inodes.len())
        .map_err(|_| FileError::BudgetExceeded)?;
    let link_counts = state.link_counts();
    for (file_id, inode) in &state.inodes {
        let metadata = PersistedInodeV1 {
            file_id: *file_id,
            file_type: inode.file_type,
            size: inode_size(inode),
            link_count: link_counts.get(file_id).copied().unwrap_or(0),
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
        self.check_publication()?;
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
        // Under the fused trusted-service path, small in-memory content is
        // not committed ahead of the trees: it is handed to the fused
        // transaction and published under the same checkpoint.
        let fold_content = principal.is_none() && maintenance.is_some();
        let mut pending_files: Vec<(FileId, Vec<u8>)> = Vec::new();
        for file_id in content_inodes {
            let inode = self
                .working
                .inodes
                .get(&file_id)
                .ok_or(FileError::NotFound)?;
            if fold_content {
                if let Content::File(chunks) = &inode.content {
                    let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
                    if total > 0 && total <= crate::FUSED_CONTENT_LIMIT {
                        let mut bytes = Vec::new();
                        bytes
                            .try_reserve_exact(total)
                            .map_err(|_| FileError::BudgetExceeded)?;
                        for chunk in chunks {
                            bytes.extend_from_slice(chunk);
                        }
                        pending_files.push((file_id, bytes));
                        continue;
                    }
                }
            }
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
        if let (None, Some(maintenance)) = (principal, maintenance) {
            // Fused trusted-service path: both trees, the namespace root,
            // and the persistent root switch publish under one staged-batch
            // checkpoint instead of one checkpoint for the batch plus one
            // for the root-policy switch.
            let pending_index: BTreeMap<FileId, usize> = pending_files
                .iter()
                .enumerate()
                .map(|(index, (file_id, _))| (*file_id, index))
                .collect();
            let inode_inputs =
                build_node_inputs(&inode_entries, Some(&content), Some(&pending_index))?;
            let dirent_inputs = build_node_inputs(&dirent_entries, None, None)?;
            let pending: Vec<FsPendingContent<'_>> = pending_files
                .iter()
                .map(|(_, bytes)| FsPendingContent { bytes })
                .collect();
            self.check_publication()?;
            let (_, published_data) = store
                .commit_fs_transaction_with_root_switch_and_content_for_maintenance(
                    maintenance,
                    self.previous_root.as_ref(),
                    self.working.namespace,
                    generation,
                    self.working.next_file_id,
                    crate::ROOT_FILE_ID,
                    &inode_inputs,
                    &dirent_inputs,
                    &pending,
                    self.base_generation,
                )
                .await?;
            if published_data.len() != pending_files.len() {
                return Err(FileError::ServiceUnavailable.into());
            }
            for ((file_id, _), data) in pending_files.iter().zip(published_data) {
                self.working
                    .inodes
                    .get_mut(file_id)
                    .ok_or(FileError::NotFound)?
                    .content = Content::PersistentFile(data);
            }
        } else {
            let new_root = self
                .commit_persistent_trees_and_root(
                    store,
                    generation,
                    &inode_entries,
                    &dirent_entries,
                    &content,
                    principal,
                    maintenance,
                )
                .await?;
            self.check_publication()?;
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
        }
        let persisted = store
            .recover_fs_root(self.working.namespace)
            .await?
            .ok_or(FileError::InvalidType)?;

        // The transaction is consumed: publish its working state by moving it
        // instead of cloning every inode and entry a second time.
        let namespace = self.working.namespace;
        let published = core::mem::replace(
            &mut self.working,
            NamespaceState {
                namespace,
                generation: 0,
                next_file_id: 0,
                inodes: BTreeMap::new(),
                dirents: BTreeMap::new(),
            },
        );
        *self.root.state.lock() = alloc::sync::Arc::new(published);
        *self.root.persistent_root.lock() = Some(persisted);
        self.committed = true;
        assert!(self.root.release_writer_claim(self.claim));
        Ok(generation)
    }

    /// Sequential commit sequence for callers without maintenance authority:
    /// one COW commit per tree followed by the namespace-root commit.
    #[allow(clippy::too_many_arguments)]
    async fn commit_persistent_trees_and_root<D: PageDevice>(
        &self,
        store: &mut SegmentStore<D>,
        generation: u64,
        inode_entries: &[(Vec<u8>, Vec<u8>)],
        dirent_entries: &[(Vec<u8>, Vec<u8>)],
        content: &BTreeMap<FileId, FsPersistentData>,
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<AuthorizedObject<CasObjectHandle>, PersistentCommitError<D::Error>> {
        let inode_root = commit_tree(
            store,
            self.previous_root.as_ref(),
            FsTreeKind::Inode,
            generation,
            inode_entries,
            Some(content),
            principal,
            maintenance,
        )
        .await?;
        let dirent_root = commit_tree(
            store,
            self.previous_root.as_ref(),
            FsTreeKind::Dirent,
            generation,
            dirent_entries,
            None,
            principal,
            maintenance,
        )
        .await?;
        match (principal, maintenance) {
            (Some(principal), None) => store
                .commit_fs_root_for_principal(
                    principal,
                    self.working.namespace,
                    generation,
                    self.working.next_file_id,
                    crate::ROOT_FILE_ID,
                    &inode_root,
                    &dirent_root,
                )
                .await
                .map_err(Into::into),
            (None, Some(maintenance)) => store
                .commit_fs_root_for_maintenance(
                    maintenance,
                    self.working.namespace,
                    generation,
                    self.working.next_file_id,
                    crate::ROOT_FILE_ID,
                    &inode_root,
                    &dirent_root,
                )
                .await
                .map_err(Into::into),
            (None, None) => store
                .commit_fs_root(
                    self.working.namespace,
                    generation,
                    self.working.next_file_id,
                    crate::ROOT_FILE_ID,
                    &inode_root,
                    &dirent_root,
                )
                .await
                .map_err(Into::into),
            (Some(_), Some(_)) => Err(FileError::InvalidType.into()),
        }
    }
}

/// Build the leaf inputs one tree commit consumes from encoded namespace
/// entries, attaching each non-directory inode's content edge.
fn build_node_inputs<'a>(
    entries: &'a [(Vec<u8>, Vec<u8>)],
    content: Option<&'a BTreeMap<FileId, FsPersistentData>>,
    pending: Option<&BTreeMap<FileId, usize>>,
) -> Result<Vec<FsNodeEntryInput<'a>>, FileError> {
    let mut inputs = Vec::new();
    for (key, value) in entries {
        let (data, pending) = if let Some(content) = content {
            let file_id = crate::decode_inode_key(key).map_err(|_| FileError::InvalidType)?;
            (
                content.get(&file_id),
                pending.and_then(|pending| pending.get(&file_id).copied()),
            )
        } else {
            (None, None)
        };
        inputs.push(FsNodeEntryInput {
            key,
            value,
            child: None,
            data,
            pending,
        });
    }
    Ok(inputs)
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
            || {
                let link_counts = state.link_counts();
                persisted_metadata.iter().any(|(file_id, metadata)| {
                    link_counts.get(file_id).copied().unwrap_or(0) != metadata.link_count
                })
            }
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
        reads: Arc<AtomicUsize>,
        panic_at: Arc<AtomicUsize>,
    }

    impl MemoryDevice {
        fn blank(segments: u64) -> Self {
            Self {
                page_count: admitted_pages(segments).unwrap(),
                pages: Arc::new(Mutex::new(BTreeMap::new())),
                reads: Arc::new(AtomicUsize::new(0)),
                panic_at: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
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
            let count = self.reads.fetch_add(1, Ordering::Relaxed) + 1;
            let trigger = self.panic_at.load(Ordering::Relaxed);
            if trigger != 0 && count == trigger {
                panic!("read sample at device read #{count}");
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
            assert!(stager.pending.capacity() <= crate::PERSISTENT_STAGE_CHUNK_SIZE);
            assert!(stager.staged.iter().all(|chunk| {
                chunk.capacity() <= crate::PERSISTENT_STAGE_CHUNK_SIZE
            }));
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
    fn fused_maintenance_commit_batches_trees_and_root_and_cold_recovers() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d46_5553_4544_5458_4e;
        const POLICY: &[u8] = b"fused transaction commit policy v1";
        // Enough segments that the first transaction's forty sequential
        // content commits never force capacity-relief collections into the
        // second transaction's checkpoint budget.
        let device = MemoryDevice::blank(256);
        let (context, _quota, maintenance_provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), context);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-FUSED-TX").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        let maintenance = store
            .provision_maintenance_root(&maintenance_provisioner)
            .unwrap();
        let import = vibeos_segment_store::PersistentAuthorityImport::empty(
            vibeos_durable_format::StoreId::new(92).unwrap(),
            POLICY,
            Vec::new(),
        )
        .unwrap();
        block_on(store.import_persistent_authority(&maintenance, import)).unwrap();

        // Enough files that both trees split into several leaves plus an
        // internal level, so the fused plan stages parents whose children are
        // batch-predicted identities.
        let root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction
            .mkdir(&crate::RelPath::parse("d").unwrap(), false)
            .unwrap();
        for index in 0..40_u32 {
            let path = alloc::format!("d/file-{index:02}");
            transaction
                .write_chunks(
                    &crate::RelPath::parse(&path).unwrap(),
                    [alloc::format!("payload-{index:02}").into_bytes()],
                    false,
                )
                .unwrap();
        }
        assert_eq!(
            block_on(transaction.commit_persistent_for_maintenance(&mut store, &maintenance))
                .unwrap(),
            1
        );

        // A follow-up single-file change reuses unchanged nodes and rides at
        // most three checkpoints: the content batch, the fused tree/root
        // batch, and the persistent root swap.
        let generation_before = store.info().unwrap().generation;
        let mut transaction = root.begin().unwrap();
        transaction
            .write_chunks(
                &crate::RelPath::parse("d/file-00").unwrap(),
                [b"rewritten".to_vec()],
                false,
            )
            .unwrap();
        assert_eq!(
            block_on(transaction.commit_persistent_for_maintenance(&mut store, &maintenance))
                .unwrap(),
            2
        );
        let generation_delta = store.info().unwrap().generation - generation_before;
        assert!(
            generation_delta <= 3,
            "fused transaction must not spend one checkpoint per tree node (delta={generation_delta})"
        );
        drop(store);

        let (cold_context, _cold_quota, _cold_maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), cold_context);
        block_on(cold.mount()).unwrap();
        let recovered = block_on(crate::FileTreeRoot::recover_persistent(
            &cold, NAMESPACE, 256,
        ))
        .unwrap()
        .unwrap();
        let snapshot = recovered.snapshot();
        for index in 0..40_u32 {
            let path = alloc::format!("d/file-{index:02}");
            let data = snapshot
                .persistent_data(&crate::RelPath::parse(&path).unwrap())
                .unwrap();
            let expected = if index == 0 {
                b"rewritten".to_vec()
            } else {
                alloc::format!("payload-{index:02}").into_bytes()
            };
            assert_eq!(
                block_on(cold.read_fs_data_chunk(&data, 0)).unwrap().unwrap(),
                expected
            );
        }
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

    /// Diagnostic benchmark for the sustained-commit cost on a small device
    /// (the Milk-V Duo data slice is sixteen 4 MiB segments). Prints device
    /// reads per fused maintenance commit as the tree grows.
    #[test]
    fn small_device_commit_read_volume_diagnostic() {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d53_4d41_4c4c_4445_5631;
        const POLICY: &[u8] = b"small-device diagnostic policy v1";
        // Mirrors the QEMU file-tree image: 128 MiB, 32 four-MiB segments.
        let device = MemoryDevice::blank(32);
        let (context, _quota, provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut store =
            SegmentStore::new_with_runtime_context(device.clone(), limits(), context);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-SMALLDEV").unwrap(),
            cleaner_reserve_segments: 2,
            limits: limits(),
        }))
        .unwrap();
        store.set_deferred_commit_readback(true);
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let import = vibeos_segment_store::PersistentAuthorityImport::empty(
            vibeos_durable_format::StoreId::new(91).unwrap(),
            POLICY,
            Vec::new(),
        )
        .unwrap();
        block_on(store.import_persistent_authority(&maintenance, import)).unwrap();
        let mut root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        for index in 0..120_u32 {
            let mut transaction = root.begin().unwrap();
            transaction
                .mkdir(
                    &crate::RelPath::parse(&std::format!("d{index}")).unwrap(),
                    false,
                )
                .unwrap();
            transaction
                .write_chunks(
                    &crate::RelPath::parse(&std::format!("d{index}/f.txt")).unwrap(),
                    [std::format!("payload-{index}").as_bytes()],
                    false,
                )
                .unwrap();
            let info = store.info().unwrap();
            std::println!(
                "  pre-op {index}: free={} admitted={} objects={} generation={}",
                info.free_segments, info.admitted_segments, info.object_count, info.generation
            );
            let before = device.reads();
            if index == 20 {
                if let Ok(offset) = std::env::var("READ_SAMPLE_OFFSET") {
                    let offset: usize = offset.parse().unwrap();
                    device.panic_at.store(before + offset, Ordering::Relaxed);
                }
            }
            match block_on(transaction.commit_persistent_for_maintenance(&mut store, &maintenance)) {
                Ok(_) => {}
                Err(error) => {
                    std::println!("COMMIT FAILED at op {index}: {error:?}");
                    return;
                }
            }
            std::println!("mkdir {index}: {} device page reads", device.reads() - before);
        }
    }
}

#[cfg(test)]
mod io_trace {
    //! Diagnostic: itemize device writes and flushes for the benchmark's
    //! create+fsync+unlink sequence. Run with
    //! `cargo test -p vibeos-file-store --lib io_trace -- --ignored --nocapture`.
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::Mutex;

    use vibeos_segment_format::{
        admitted_pages, Page, StoreUuid, ANCHOR_PAGES, PAGE_SIZE, SEGMENT_PAGES,
    };
    use vibeos_segment_store::{
        FormatOptions, PageDeviceInfo, StoreLimits, StoreMaintenance, StoreRuntimeContext,
    };
    use vibeos_storage_device::MutationFailure;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
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
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{self:?}")
        }
    }

    #[derive(Clone, Debug)]
    enum Event {
        Write(u64, u64),
        Read(u64, u64),
        Flush,
        /// Phase probe from instrumented engine code (id, time).
        Probe(u64, std::time::Instant),
    }

    #[derive(Clone)]
    struct TraceDevice {
        page_count: u64,
        pages: Arc<Mutex<BTreeMap<u64, Page>>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl TraceDevice {
        fn blank(segments: u64) -> Self {
            Self {
                page_count: admitted_pages(segments).unwrap(),
                pages: Arc::new(Mutex::new(BTreeMap::new())),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }
        fn take(&self) -> Vec<Event> {
            core::mem::take(&mut *self.events.lock().unwrap())
        }
    }

    fn region(page: u64) -> std::string::String {
        if page < ANCHOR_PAGES {
            return alloc::format!("anchor:{page}");
        }
        let segment = (page - ANCHOR_PAGES) / SEGMENT_PAGES;
        let relative = (page - ANCHOR_PAGES) % SEGMENT_PAGES;
        alloc::format!("seg{segment}+{relative}")
    }

    fn report(label: &str, events: &[Event]) {
        let probes: Vec<(u64, std::time::Instant)> = events
            .iter()
            .filter_map(|event| match event {
                Event::Probe(id, at) => Some((*id, *at)),
                _ => None,
            })
            .collect();
        if probes.len() >= 2 {
            let total = probes[probes.len() - 1].1.duration_since(probes[0].1);
            let mut line = alloc::format!("  {label} phases ({:.2} ms total):", total.as_secs_f64() * 1e3);
            for pair in probes.windows(2) {
                let span = pair[1].1.duration_since(pair[0].1);
                line.push_str(&alloc::format!(" {}->{} {:.2}ms", pair[0].0, pair[1].0, span.as_secs_f64() * 1e3));
            }
            std::println!("{line}");
            let mut current = 0_u64;
            let mut per: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
            for event in events {
                match event {
                    Event::Probe(id, _) => current = *id,
                    Event::Read(_, count) => {
                        let entry = per.entry(current).or_insert((0, 0));
                        entry.0 += 1;
                        entry.1 += count;
                    }
                    _ => {}
                }
            }
            let mut reads = alloc::format!("  {label} reads after probe:");
            for (probe, (requests, pages)) in &per {
                reads.push_str(&alloc::format!(" {probe}:{requests}req/{}KiB", pages * 4));
            }
            std::println!("{reads}");
        }
        let mut writes = 0_u64;
        let mut write_pages = 0_u64;
        let mut reads = 0_u64;
        let mut read_pages = 0_u64;
        let mut flushes = 0_u64;
        let mut read_by_region: BTreeMap<std::string::String, (u64, u64)> = BTreeMap::new();
        let mut lines = std::string::String::new();
        for event in events {
            match event {
                Event::Write(first, count) => {
                    writes += 1;
                    write_pages += count;
                    lines.push_str(&alloc::format!("  W {}..+{}\n", region(*first), count));
                }
                Event::Read(first, count) => {
                    reads += 1;
                    read_pages += count;
                    let key = if *first < ANCHOR_PAGES { "anchor".into() } else { alloc::format!("seg{}", (*first - ANCHOR_PAGES) / SEGMENT_PAGES) };
                    let entry = read_by_region.entry(key).or_insert((0_u64, 0_u64));
                    entry.0 += 1;
                    entry.1 += count;
                }
                Event::Probe(..) => {}
                Event::Flush => {
                    flushes += 1;
                    lines.push_str("  ---- FLUSH\n");
                }
            }
        }
        std::println!(
            "== {label}: writes={writes} ({} KiB) flushes={flushes} reads={reads} ({} KiB)",
            write_pages * 4,
            read_pages * 4
        );
        std::print!("{lines}");
        for (key, (count, pages)) in read_by_region {
            std::println!("  R {key}: {count} requests, {} KiB", pages * 4);
        }
        let mut distinct: BTreeMap<u64, u64> = BTreeMap::new();
        for event in events {
            if let Event::Read(first, count) = event {
                for page in *first..*first + *count {
                    *distinct.entry(page).or_insert(0) += 1;
                }
            }
        }
        let repeated: u64 = distinct.values().map(|n| n - 1).sum();
        let mut classes: BTreeMap<&str, u64> = BTreeMap::new();
        for (page, count) in &distinct {
            if *count < 2 {
                continue;
            }
            let class = if *page < ANCHOR_PAGES {
                "anchor"
            } else {
                match (*page - ANCHOR_PAGES) % SEGMENT_PAGES {
                    0 | 1 => "segment header",
                    1020..=1023 => "summary/seal",
                    _ => "descriptor or payload",
                }
            };
            *classes.entry(class).or_insert(0) += count - 1;
        }
        for (class, count) in classes {
            std::println!("  R repeats in {class}: {count} pages");
        }
        if !distinct.is_empty() {
            std::println!(
                "  R distinct pages={} ({} KiB), repeated page reads={} ({} KiB)",
                distinct.len(),
                distinct.len() * 4,
                repeated,
                repeated * 4
            );
        }
    }

    impl PageDevice for TraceDevice {
        type Error = DeviceError;
        fn info(&self) -> PageDeviceInfo {
            PageDeviceInfo {
                device_id: [0x47; 16],
                range_first_logical_block: 0,
                logical_block_count: self.page_count * 8,
                logical_block_size: 512,
                page_count: self.page_count,
            }
        }
        async fn read_page(&self, page: u64, output: &mut Page) -> Result<(), Self::Error> {
            if page >= self.page_count {
                if page >= u64::MAX - 128 {
                    self.events
                        .lock()
                        .unwrap()
                        .push(Event::Probe(u64::MAX - page, std::time::Instant::now()));
                }
                return Err(DeviceError::OutsideRange);
            }
            self.events.lock().unwrap().push(Event::Read(page, 1));
            *output = self.pages.lock().unwrap().get(&page).copied().unwrap_or([0; PAGE_SIZE]);
            Ok(())
        }
        async fn read_pages(&self, first: u64, output: &mut [Page]) -> Result<(), Self::Error> {
            if first + output.len() as u64 > self.page_count {
                return Err(DeviceError::OutsideRange);
            }
            self.events.lock().unwrap().push(Event::Read(first, output.len() as u64));
            let pages = self.pages.lock().unwrap();
            for (offset, page) in output.iter_mut().enumerate() {
                *page = pages.get(&(first + offset as u64)).copied().unwrap_or([0; PAGE_SIZE]);
            }
            Ok(())
        }
        async fn write_page(&self, page: u64, input: &Page) -> Result<(), MutationFailure<Self::Error>> {
            if page >= self.page_count {
                return Err(MutationFailure::not_submitted(DeviceError::OutsideRange));
            }
            self.events.lock().unwrap().push(Event::Write(page, 1));
            self.pages.lock().unwrap().insert(page, *input);
            Ok(())
        }
        async fn write_pages(&self, first: u64, input: &[Page]) -> Result<(), MutationFailure<Self::Error>> {
            if first + input.len() as u64 > self.page_count {
                return Err(MutationFailure::not_submitted(DeviceError::OutsideRange));
            }
            self.events.lock().unwrap().push(Event::Write(first, input.len() as u64));
            let mut pages = self.pages.lock().unwrap();
            for (offset, page) in input.iter().enumerate() {
                pages.insert(first + offset as u64, *page);
            }
            Ok(())
        }
        async fn flush(&self) -> Result<(), MutationFailure<Self::Error>> {
            self.events.lock().unwrap().push(Event::Flush);
            Ok(())
        }
    }

    fn limits() -> StoreLimits {
        StoreLimits {
            max_catalog_entries: 4096,
            max_replay_records: 32,
            recovery_memory_bytes: 8 * 1024 * 1024,
            max_compat_object_bytes: 64 * 1024,
        }
    }

    struct TraceBackend {
        store: Mutex<SegmentStore<TraceDevice>>,
        maintenance: StoreMaintenance,
    }

    impl crate::FileTreeBackend for TraceBackend {
        fn stage_chunk<'a>(
            &'a self,
            previous: Option<vibeos_segment_store::FsPersistentData>,
            bytes: Vec<u8>,
        ) -> crate::FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
            let result = block_on(self.store.lock().unwrap().commit_fs_data_chunk_for_maintenance(
                &self.maintenance,
                previous.as_ref(),
                &bytes,
            ))
            .map_err(|_| crate::FileError::ServiceUnavailable);
            Box::pin(async move { result })
        }
        fn stage_chunks<'a>(
            &'a self,
            previous: Option<vibeos_segment_store::FsPersistentData>,
            chunks: Vec<Vec<u8>>,
        ) -> crate::FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
            let result = block_on(self.store.lock().unwrap().stage_fs_data_chunks_for_maintenance(
                &self.maintenance,
                previous.as_ref(),
                &chunks,
            ))
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
        fn commit<'a>(&'a self, transaction: crate::FsTransaction) -> crate::FileTreeFuture<'a, u64> {
            let result = block_on(
                transaction.commit_persistent_for_maintenance(
                    &mut self.store.lock().unwrap(),
                    &self.maintenance,
                ),
            )
            .map_err(|error| match error {
                PersistentCommitError::File(error) => error,
                _ => crate::FileError::ServiceUnavailable,
            });
            Box::pin(async move { result })
        }
    }

    struct Fixture {
        device: TraceDevice,
        root: crate::FileTreeRoot,
        backend: Arc<TraceBackend>,
    }

    /// Format a store, import an empty persistent authority, attach the
    /// maintenance backend, and populate `warm` 4 KiB files in commits of 40.
    fn fixture(warm: u32) -> Fixture {
        let segments: u64 = std::env::var("VIBE_IO_TRACE_SEGMENTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(256);
        fixture_with(warm, segments)
    }

    fn fixture_with(warm: u32, segments: u64) -> Fixture {
        const NAMESPACE: u128 = 0x5649_4245_4f53_2d54_5241_4345_5f49_4f31;
        const POLICY: &[u8] = b"io trace policy v1";
        let device = TraceDevice::blank(segments);
        let (context, _quota, provisioner) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut store = SegmentStore::new_with_runtime_context(device.clone(), limits(), context);
        block_on(store.format(FormatOptions {
            store_uuid: StoreUuid::new(*b"VIBE-FS-IOTRACE!").unwrap(),
            cleaner_reserve_segments: 6,
            limits: limits(),
        }))
        .unwrap();
        store.set_deferred_commit_readback(true);
        let maintenance = store.provision_maintenance_root(&provisioner).unwrap();
        let import = vibeos_segment_store::PersistentAuthorityImport::empty(
            vibeos_durable_format::StoreId::new(92).unwrap(),
            POLICY,
            Vec::new(),
        )
        .unwrap();
        block_on(store.import_persistent_authority(&maintenance, import)).unwrap();
        let backend = Arc::new(TraceBackend { store: Mutex::new(store), maintenance });
        let mut root = crate::FileTreeRoot::new_empty(NAMESPACE).unwrap();
        root.attach_backend(backend.clone()).unwrap();
        let mut done = 0_u32;
        while done < warm {
            let mut tx = root.begin().unwrap();
            let batch = (warm - done).min(40);
            for index in done..done + batch {
                let path = alloc::format!("warm-{index:04}");
                tx.write_chunks(&crate::RelPath::parse(&path).unwrap(), [alloc::vec![index as u8; 4096]], false)
                    .unwrap();
            }
            block_on(tx.commit_durable()).unwrap();
            done += batch;
        }
        let warm_events = device.take();
        if std::env::var("VIBE_IO_TRACE_WARM_REPORT").is_ok() {
            let single_page_writes = warm_events
                .iter()
                .filter(|event| matches!(event, Event::Write(_, 1)))
                .count();
            let (mut writes, mut pages, mut flushes) = (0_u64, 0_u64, 0_u64);
            for event in &warm_events {
                match event {
                    Event::Write(_, count) => {
                        writes += 1;
                        pages += count;
                    }
                    Event::Flush => flushes += 1,
                    Event::Read(..) | Event::Probe(..) => {}
                }
            }
            std::println!(
                "== warm phase: writes={writes} ({} KiB, {single_page_writes} single-page) flushes={flushes} edge-cache={:?}",
                pages * 4,
                backend.store.lock().unwrap().typed_edge_cache_stats()
            );
        }
        Fixture { device, root, backend }
    }

    fn payload(seed: u32) -> Vec<u8> {
        (0..4096_u32)
            .map(|i| (i.wrapping_mul(131).wrapping_add(seed.wrapping_mul(17)) % 251) as u8)
            .collect()
    }

    fn flushes(events: &[Event]) -> usize {
        events.iter().filter(|event| matches!(event, Event::Flush)).count()
    }

    fn write_pages(events: &[Event]) -> u64 {
        events
            .iter()
            .map(|event| match event {
                Event::Write(_, count) => *count,
                _ => 0,
            })
            .sum()
    }

    fn generation(backend: &TraceBackend) -> u64 {
        backend.store.lock().unwrap().info().unwrap().generation
    }

    #[test]
    fn populated_tree_recovery_io_is_bounded() {
        let fixture = fixture_with(100, 64);
        let namespace = fixture.root.snapshot().namespace();
        let (context, _quota, _maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut cold =
            SegmentStore::new_with_runtime_context(fixture.device.clone(), limits(), context);
        block_on(cold.mount()).unwrap();
        fixture.device.take();
        let root = block_on(crate::FileTreeRoot::recover_persistent(
            &cold, namespace, 4096,
        ))
        .unwrap()
        .unwrap();
        for index in 0..100 {
            let path = crate::RelPath::parse(&alloc::format!("warm-{index:04}")).unwrap();
            assert_eq!(root.snapshot().stat(&path, false).unwrap().size, 4096);
        }
        let events = fixture.device.take();
        let mut requests = 0;
        let mut pages = 0;
        for event in &events {
            if let Event::Read(_, count) = event {
                requests += 1;
                pages += count;
            }
        }
        std::println!("tree recovery: requests={requests}, pages={pages}");
        assert!(
            requests < 800 && pages < 1200,
            "metadata recovery repeated sealed segment walks: {requests} requests, {pages} pages"
        );
    }

    #[test]
    #[ignore = "qualify the thousand-file single-transaction workload"]
    fn thousand_file_batch_commit_and_cold_recovery() {
        let fixture = fixture_with(0, 256);
        let payload = alloc::vec![0x5au8; 4096];
        let mut staged = Vec::new();
        let mut expected = Vec::new();
        for index in 0..1000 {
            let name = alloc::format!("batch-{index:04}");
            let path = crate::RelPath::parse(&name).unwrap();
            let mut stager = fixture.root.begin_content_stager(&path, false).unwrap();
            block_on(stager.push(&payload)).unwrap();
            staged.push((path, block_on(stager.finish()).unwrap()));
            expected.push((name, payload.clone()));
        }
        let mut tx = fixture.root.begin().unwrap();
        for (path, content) in staged {
            tx.write_staged(&path, content).unwrap();
        }
        block_on(tx.commit_persistent_for_maintenance(
            &mut fixture.backend.store.lock().unwrap(), &fixture.backend.maintenance
        )).unwrap();
        let events = fixture.device.take();
        let written_pages: u64 = events.iter().map(|event| match event {
            Event::Write(_, pages) => *pages,
            _ => 0,
        }).sum();
        assert!(written_pages * (PAGE_SIZE as u64) < 2 * 1024 * 1024,
            "duplicate file content consumed scratch pages: {written_pages}");
        assert!(flushes(&events) <= 4);
        report("thousand-file-commit", &events);
        let expected: Vec<_> = expected.iter().map(|(name, bytes)| (name.as_str(), bytes.clone())).collect();
        cold_mount_and_check(&fixture.device,
            0x5649_4245_4f53_2d54_5241_4345_5f49_4f31, &expected);
    }

    #[test]
    fn large_unique_file_io_attribution() {
        trace_unique_file_io(16 * 1024 * 1024, 64);
    }

    #[test]
    #[ignore = "large-file I/O attribution; allocates a 256 MiB host payload"]
    fn file_256m_io_attribution() {
        trace_unique_file_io(256 * 1024 * 1024, 256);
    }

    fn trace_unique_file_io(size: usize, segments: u64) {
        let fixture = fixture_with(0, segments);
        let path = crate::RelPath::parse("large-unique").unwrap();
        let bytes: Vec<u8> = (0..size)
            .map(|i| ((i as u64).wrapping_mul(131) ^ ((i as u64) >> 13) ^ ((i as u64) >> 21)) as u8)
            .collect();
        let mut stager = fixture.root.begin_content_stager(&path, false).unwrap();
        block_on(stager.push(&bytes)).unwrap();
        let staged = block_on(stager.finish()).unwrap();
        report("unique-stage", &fixture.device.take());
        let mut tx = fixture.root.begin().unwrap();
        tx.write_staged(&path, staged).unwrap();
        block_on(tx.commit_durable()).unwrap();
        report("unique-commit", &fixture.device.take());
        let reader = fixture.root.reader(&path).unwrap();
        let mut at = 0;
        for index in 0..reader.chunk_count() {
            let chunk = block_on(reader.read_chunk(index)).unwrap().unwrap();
            assert_eq!(chunk, bytes[at..at + chunk.len()]);
            at += chunk.len();
        }
        assert_eq!(at, bytes.len());
        let reads = fixture.device.take();
        let read_pages: u64 = reads
            .iter()
            .map(|event| match event {
                Event::Read(_, count) => *count,
                _ => 0,
            })
            .sum();
        assert!(
            read_pages * (PAGE_SIZE as u64) < bytes.len() as u64 * 5 / 4,
            "whole-file read repeated payload verification: {read_pages} pages"
        );
        let read_requests = reads.iter().filter(|event| matches!(event, Event::Read(_, _))).count();
        if size == 16 * 1024 * 1024 {
            assert!(read_requests < 400,
                "whole-file verification fragmented sequential reads: {read_requests} requests");
        }
        if size == 256 * 1024 * 1024 {
            assert!(read_requests < 7000 && read_pages * (PAGE_SIZE as u64) < size as u64 * 11 / 10,
                "large-file read thrashes segment proofs: {read_requests} requests, {read_pages} pages");
        }
        report("unique-read", &reads);
        let mut tx = fixture.root.begin().unwrap();
        tx.remove(&path, false, false).unwrap();
        block_on(tx.commit_durable()).unwrap();
        report("unique-remove", &fixture.device.take());
    }

    /// A small file's content rides the fused tree transaction: the stager
    /// touches no media, the create is exactly one checkpoint whose slot
    /// protocol is the only barrier (three flushes, the scratch seal having
    /// been pre-cleared by the previous publication), and the content cold
    /// recovers through the predicted data edge.
    #[test]
    fn small_create_is_one_checkpoint_with_three_flushes_and_cold_recovers() {
        let fixture = fixture(8);
        let bytes = payload(1);
        let path = crate::RelPath::parse("bench-file-1").unwrap();
        let mut stager = fixture.root.begin_content_stager(&path, false).unwrap();
        block_on(stager.push(&bytes)).unwrap();
        let staged = block_on(stager.finish()).unwrap();
        let staging = fixture.device.take();
        assert!(staging.is_empty(), "stager must not touch media for small content");

        let before = generation(&fixture.backend);
        let mut tx = fixture.root.begin().unwrap();
        tx.write_staged(&path, staged).unwrap();
        block_on(tx.commit_durable()).unwrap();
        let create = fixture.device.take();
        assert_eq!(generation(&fixture.backend) - before, 1, "content and trees share one checkpoint");
        assert_eq!(flushes(&create), 3, "one checkpoint: clear old seal, body, seal");

        let reader = fixture.root.reader(&path).unwrap();
        assert_eq!(block_on(reader.read_chunk(0)).unwrap().unwrap(), bytes);

        let mut tx = fixture.root.begin().unwrap();
        tx.remove(&path, false, false).unwrap();
        block_on(tx.commit_durable()).unwrap();
        assert_eq!(flushes(&fixture.device.take()), 3);

        // Cold recovery of a folded file: reopen from the device image.
        let path2 = crate::RelPath::parse("bench-file-2").unwrap();
        let bytes2 = payload(2);
        let mut stager = fixture.root.begin_content_stager(&path2, false).unwrap();
        block_on(stager.push(&bytes2)).unwrap();
        let staged = block_on(stager.finish()).unwrap();
        let mut tx = fixture.root.begin().unwrap();
        tx.write_staged(&path2, staged).unwrap();
        block_on(tx.commit_durable()).unwrap();
        let namespace = fixture.root.snapshot().namespace();
        drop(fixture.root);
        let (cold_context, _cold_quota, _cold_maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut cold = SegmentStore::new_with_runtime_context(
            fixture.device.clone(),
            limits(),
            cold_context,
        );
        block_on(cold.mount()).unwrap();
        let recovered = block_on(crate::FileTreeRoot::recover_persistent(&cold, namespace, 4096))
            .unwrap()
            .unwrap();
        let snapshot = recovered.snapshot();
        assert!(snapshot.persistent_data(&path).is_err(), "unlinked file stays gone");
        let data = snapshot.persistent_data(&path2).unwrap();
        assert_eq!(block_on(cold.read_fs_data_chunk(&data, 0)).unwrap().unwrap(), bytes2);
        let warm = snapshot
            .persistent_data(&crate::RelPath::parse("warm-0003").unwrap())
            .unwrap();
        assert_eq!(
            block_on(cold.read_fs_data_chunk(&warm, 0)).unwrap().unwrap(),
            alloc::vec![3_u8; 4096]
        );
    }

    /// One create in a populated namespace re-stages only the nodes on the
    /// modified paths: with 600 files the greedy packing re-staged 14 tree
    /// nodes (219 segment pages); boundary-stable partitioning stays within
    /// a handful, so the fused segment is bounded.
    #[test]
    fn single_create_in_populated_namespace_restages_bounded_nodes() {
        let fixture = fixture(600);
        let bytes = payload(3);
        let path = crate::RelPath::parse("bench-file-3").unwrap();
        let mut stager = fixture.root.begin_content_stager(&path, false).unwrap();
        block_on(stager.push(&bytes)).unwrap();
        let staged = block_on(stager.finish()).unwrap();
        let mut tx = fixture.root.begin().unwrap();
        tx.write_staged(&path, staged).unwrap();
        block_on(tx.commit_durable()).unwrap();
        let create = fixture.device.take();
        let pages = write_pages(&create);
        assert!(
            pages <= 150,
            "single create wrote {pages} pages; expected a few nodes plus catalog, not a tree rewrite"
        );
        assert_eq!(flushes(&create), 3);
    }

    fn replay_count(backend: &TraceBackend) -> u32 {
        backend.store.lock().unwrap().info().unwrap().replay_count
    }

    fn cold_mount_and_check(device: &TraceDevice, namespace: u128, expected: &[(&str, Vec<u8>)]) {
        let (cold_context, _cold_quota, _cold_maintenance) =
            StoreRuntimeContext::governed_with_typed_reference_kinds_and_maintenance_provisioner(
                &vibeos_segment_store::fs_typed_reference_kinds(),
            )
            .unwrap();
        let mut cold =
            SegmentStore::new_with_runtime_context(device.clone(), limits(), cold_context);
        block_on(cold.mount()).unwrap();
        let recovered = block_on(crate::FileTreeRoot::recover_persistent(&cold, namespace, 4096))
            .unwrap()
            .unwrap();
        let snapshot = recovered.snapshot();
        for (path, bytes) in expected {
            let data = snapshot
                .persistent_data(&crate::RelPath::parse(path).unwrap())
                .unwrap();
            assert_eq!(
                block_on(cold.read_fs_data_chunk(&data, 0)).unwrap().unwrap(),
                *bytes,
                "{path} content after cold mount"
            );
        }
    }

    /// Against a populated catalog, small transactions publish catalog
    /// deltas instead of rewriting the whole `VIBECAS2` snapshot: the replay
    /// chain grows by one record per minted object, cold mount replays it,
    /// and the chain resets to a snapshot before it exceeds the superblock's
    /// replay budget.
    #[test]
    fn small_transactions_publish_catalog_deltas_that_cold_mount_replays() {
        let fixture = fixture(600);
        let namespace = fixture.root.snapshot().namespace();
        let budget = limits().max_replay_records;
        let mut expected: Vec<(&str, Vec<u8>)> = Vec::new();
        let names = [
            "delta-a", "delta-b", "delta-c", "delta-d", "delta-e", "delta-f", "delta-g",
            "delta-h", "delta-i", "delta-j", "delta-k", "delta-l",
        ];
        let mut saw_chain = false;
        let mut saw_reset = false;
        let mut previous_depth = replay_count(&fixture.backend);
        for (index, name) in names.iter().enumerate() {
            let bytes = payload(100 + index as u32);
            let path = crate::RelPath::parse(name).unwrap();
            let mut stager = fixture.root.begin_content_stager(&path, false).unwrap();
            block_on(stager.push(&bytes)).unwrap();
            let staged = block_on(stager.finish()).unwrap();
            let mut tx = fixture.root.begin().unwrap();
            tx.write_staged(&path, staged).unwrap();
            block_on(tx.commit_durable()).unwrap();
            let events = fixture.device.take();
            assert_eq!(flushes(&events), 3, "a delta commit is still one checkpoint");
            let depth = replay_count(&fixture.backend);
            assert!(depth <= budget, "chain depth {depth} exceeds the replay budget {budget}");
            if depth > previous_depth {
                saw_chain = true;
                // One delta per minted object: content node, touched tree
                // nodes, root — never more than a handful.
                assert!(depth - previous_depth <= 8, "unexpectedly many deltas per commit");
            } else if previous_depth > 0 && depth == 0 {
                saw_reset = true;
            }
            previous_depth = depth;
            expected.push((name, bytes));
            if index == 2 {
                assert!(saw_chain, "Auto policy must choose deltas against a 600-file catalog");
                cold_mount_and_check(&fixture.device, namespace, &expected);
            }
        }
        assert!(saw_chain && saw_reset, "chain={saw_chain} reset={saw_reset}");
        cold_mount_and_check(&fixture.device, namespace, &expected);
        let mut all: Vec<(&str, Vec<u8>)> = expected.clone();
        all.push(("warm-0007", alloc::vec![7_u8; 4096]));
        cold_mount_and_check(&fixture.device, namespace, &all);
        if let Ok(path) = std::env::var("VIBE_IO_TRACE_DUMP") {
            let pages = fixture.device.pages.lock().unwrap();
            let mut image =
                alloc::vec![0_u8; (fixture.device.page_count * PAGE_SIZE as u64) as usize];
            for (page, bytes) in pages.iter() {
                let at = (*page as usize) * PAGE_SIZE;
                image[at..at + PAGE_SIZE].copy_from_slice(bytes);
            }
            std::fs::write(path, image).unwrap();
        }
    }

    /// `Never` keeps the pre-replay behaviour: every commit rewrites the
    /// complete snapshot and the chain stays empty.
    #[test]
    fn never_policy_keeps_compact_snapshots() {
        let fixture = fixture(600);
        fixture
            .backend
            .store
            .lock()
            .unwrap()
            .set_catalog_delta_policy(vibeos_segment_store::CatalogDeltaPolicy::Never);
        for index in 0..3_u32 {
            let path = crate::RelPath::parse(&alloc::format!("compact-{index}")).unwrap();
            let mut tx = fixture.root.begin().unwrap();
            tx.write_chunks(&path, [payload(200 + index)], false).unwrap();
            block_on(tx.commit_durable()).unwrap();
            assert_eq!(replay_count(&fixture.backend), 0);
        }
    }

    /// A collection round that follows an earlier round in the same process
    /// rebuilds reachability from the typed edge memo and reads only objects
    /// committed since, so its device reads drop by more than half.
    #[test]
    fn later_collection_rounds_reuse_authenticated_edges() {
        // 900 files on a 36-segment device: the free-segment floor forces a
        // collection round every third create+unlink pair.
        let fixture = fixture_with(900, 36);
        let device = fixture.device.clone();
        let mut rounds: Vec<(u64, u64, u64)> = Vec::new(); // (read pages, hits, misses)
        for sample in 0..8_u32 {
            let bytes = payload(300 + sample);
            let path = crate::RelPath::parse(&alloc::format!("gc-{sample}")).unwrap();
            let mut tx = fixture.root.begin().unwrap();
            tx.write_chunks(&path, [bytes], false).unwrap();
            block_on(tx.commit_durable()).unwrap();
            device.take();
            let mut tx = fixture.root.begin().unwrap();
            tx.remove(&path, false, false).unwrap();
            block_on(tx.commit_durable()).unwrap();
            let events = device.take();
            if flushes(&events) >= 10 {
                let pages: u64 = events
                    .iter()
                    .map(|event| match event {
                        Event::Read(_, count) => *count,
                        _ => 0,
                    })
                    .sum();
                let (_, hits, misses) = fixture.backend.store.lock().unwrap().typed_edge_cache_stats();
                rounds.push((pages, hits, misses));
            }
        }
        assert!(rounds.len() >= 2, "expected at least two collection rounds, saw {rounds:?}");
        let (first_pages, first_hits, _) = rounds[0];
        let (later_pages, later_hits, _) = rounds[rounds.len() - 1];
        assert_eq!(first_hits, 0, "the first round in a process has nothing to reuse");
        assert!(later_hits > first_hits, "later rounds must hit the edge memo: {rounds:?}");
        assert!(
            later_pages * 2 < first_pages,
            "a warm round should read less than half of a cold one: {rounds:?}"
        );
    }

    #[test]
    #[ignore]
    fn trace_create_fsync_unlink() {
        let fixture = fixture(
            std::env::var("VIBE_IO_TRACE_WARM").ok().and_then(|v| v.parse().ok()).unwrap_or(8),
        );
        let device = fixture.device.clone();
        let root = fixture.root;
        let samples: u32 = std::env::var("VIBE_IO_TRACE_SAMPLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(2);
        for sample in 0..samples {
            let payload = payload(sample);
            let path = crate::RelPath::parse(&alloc::format!("bench-file-{sample}")).unwrap();
            let mut stager = root.begin_content_stager(&path, false).unwrap();
            block_on(stager.push(&payload)).unwrap();
            let staged = block_on(stager.finish()).unwrap();
            report(&alloc::format!("s{sample} stage content"), &device.take());
            let wall = std::time::Instant::now();
            let mut tx = root.begin().unwrap();
            std::println!("  s{sample} begin wall {:.2} ms", wall.elapsed().as_secs_f64() * 1e3);
            tx.write_staged(&path, staged).unwrap();
            block_on(tx.commit_durable()).unwrap();
            std::println!("  s{sample} commit create wall {:.2} ms", wall.elapsed().as_secs_f64() * 1e3);
            report(&alloc::format!("s{sample} commit create"), &device.take());
            let reader = root.reader(&path).unwrap();
            let chunk = block_on(reader.read_chunk(0)).unwrap().unwrap();
            assert_eq!(chunk, payload);
            report(&alloc::format!("s{sample} read back"), &device.take());
            let wall = std::time::Instant::now();
            let mut tx = root.begin().unwrap();
            tx.remove(&path, false, false).unwrap();
            block_on(tx.commit_durable()).unwrap();
            std::println!("  s{sample} commit unlink wall {:.2} ms", wall.elapsed().as_secs_f64() * 1e3);
            report(&alloc::format!("s{sample} commit unlink"), &device.take());
            std::println!(
                "  edge-cache (objects, hits, misses) = {:?}",
                fixture.backend.store.lock().unwrap().typed_edge_cache_stats()
            );
        }
        if let Ok(path) = std::env::var("VIBE_IO_TRACE_DUMP") {
            let pages = device.pages.lock().unwrap();
            let mut image = alloc::vec![0_u8; (device.page_count * PAGE_SIZE as u64) as usize];
            for (page, bytes) in pages.iter() {
                let at = (*page as usize) * PAGE_SIZE;
                image[at..at + PAGE_SIZE].copy_from_slice(bytes);
            }
            std::fs::write(path, image).unwrap();
        }
    }
}
