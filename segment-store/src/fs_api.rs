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
use crate::maintenance::{MaintenanceOperation, StoreMaintenance};
use crate::persistent_authority::PersistentAuthorityError;
use crate::root_codec::PersistentRootEntry;
use crate::fs_codec::{decode_fs_data_node_v1_prefix, FsDataNodeMeta};
use crate::{
    decode_fs_btree_node_v1, encode_fs_btree_node_v1,
    encode_fs_data_node_v1, encode_fs_root_v1, FsBtreeEntryV1, FsBtreeNodeV1, FsCodecError,
    FsDataNodeV1, FsRootV1, FsTreeKind, SegmentStore, StoragePrincipal, StoreError,
    TypedObjectReference, FS_BTREE_ENTRY_HEADER_LEN, FS_BTREE_HEADER_LEN, FS_BTREE_MAX_HEIGHT,
    FS_BTREE_NODE_V1_KIND, FS_DATA_CHUNK_MAX_LEN, FS_DATA_V1_KIND, FS_OBJECT_MAX_LEN,
    FS_ROOT_V1_KIND,
};

pub struct FsNodeEntryInput<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
    pub child: Option<&'a AuthorizedObject<CasObjectHandle>>,
    pub data: Option<&'a FsPersistentData>,
}

#[derive(Debug)]
pub enum FsStructuralCommitError<E> {
    Store(CasStoreError<E>),
    Gc(GcStoreError<E>),
    Codec(FsCodecError),
    InvalidChild,
}

impl<E> From<CasStoreError<E>> for FsStructuralCommitError<E> {
    fn from(value: CasStoreError<E>) -> Self {
        Self::Store(value)
    }
}
impl<E> From<GcStoreError<E>> for FsStructuralCommitError<E> {
    fn from(value: GcStoreError<E>) -> Self {
        Self::Gc(value)
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
    Authority(PersistentAuthorityError<E>),
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
impl<E> From<PersistentAuthorityError<E>> for FsRootPublishError<E> {
    fn from(value: PersistentAuthorityError<E>) -> Self {
        Self::Authority(value)
    }
}

/// Cold-recoverable namespace root. Object identity and CAS keys remain
/// private; callers can inspect only file-tree policy fields.
#[derive(Clone)]
pub struct FsPersistentRoot {
    _object: Arc<AuthorizedObject<CasObjectHandle>>,
    decoded: FsRootV1,
}

#[derive(Clone)]
pub struct FsPersistentData {
    object: Arc<AuthorizedObject<CasObjectHandle>>,
    layout: FsPersistentDataLayout,
}

#[derive(Clone)]
enum FsPersistentDataLayout {
    Raw,
    /// Skip-linked stream node held as structure-only metadata. Content bytes
    /// stay on media and are read (and Merkle-verified) per leaf on demand, so
    /// a resident handle to a multi-MiB chunk costs only its ancestor table.
    Stream(FsDataNodeMeta),
}

impl FsPersistentData {
    pub fn exact_len(&self) -> u64 {
        match &self.layout {
            FsPersistentDataLayout::Raw => self.object.exact_len(),
            FsPersistentDataLayout::Stream(node) => node.total_len,
        }
    }

    pub fn chunk_count(&self) -> u64 {
        match &self.layout {
            FsPersistentDataLayout::Raw => self.object.exact_len().div_ceil(PAGE_SIZE as u64),
            FsPersistentDataLayout::Stream(node) if node.total_len == 0 => 0,
            FsPersistentDataLayout::Stream(node) => node.chunk_index + 1,
        }
    }
}

pub struct FsPersistentTreeEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub content: Option<FsPersistentData>,
}

struct RecoverableFsNode {
    decoded: FsBtreeNodeV1,
    mapping: ObjectMapping,
}

struct CowBuiltNode {
    minimum_key: Vec<u8>,
    object: Arc<AuthorizedObject<CasObjectHandle>>,
}

fn partition_fs_entries(
    entries: &[FsBtreeEntryV1],
) -> Result<Vec<core::ops::Range<usize>>, FsCodecError> {
    let mut pages = Vec::new();
    let mut start = 0usize;
    let mut used = FS_BTREE_HEADER_LEN;
    for (index, entry) in entries.iter().enumerate() {
        let size = FS_BTREE_ENTRY_HEADER_LEN
            .checked_add(entry.key.len())
            .and_then(|size| size.checked_add(entry.value.len()))
            .ok_or(FsCodecError::OutOfBounds)?;
        if FS_BTREE_HEADER_LEN + size > FS_OBJECT_MAX_LEN {
            return Err(FsCodecError::OutOfBounds);
        }
        if index > start && used + size > FS_OBJECT_MAX_LEN {
            pages.push(start..index);
            start = index;
            used = FS_BTREE_HEADER_LEN;
        }
        used += size;
    }
    pages.push(start..entries.len());
    Ok(pages)
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
    async fn commit_fs_payload(
        &mut self,
        object_kind: u32,
        payload: &[u8],
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<AuthorizedObject<CasObjectHandle>, FsStructuralCommitError<D::Error>> {
        if principal.is_some() && maintenance.is_some() {
            return Err(FsStructuralCommitError::InvalidChild);
        }
        if let Some(maintenance) = maintenance {
            let maximum_cycles = self.info()?.admitted_segments;
            let mut cycles = 0_u64;
            loop {
                let lease = self
                    .acquire_maintenance(maintenance, MaintenanceOperation::ExplicitMaintenance)
                    .ok_or(FsStructuralCommitError::InvalidChild)?;
                let admission = self
                    .begin_blob_with_reference_codec_for_maintenance(
                        &lease,
                        object_kind,
                        payload.len() as u64,
                        None,
                        REFERENCE_CODEC_FS_V1,
                    )
                    .map(drop);
                match admission {
                    Ok(()) => {
                        drop(lease);
                        let lease = self
                            .acquire_maintenance(
                                maintenance,
                                MaintenanceOperation::ExplicitMaintenance,
                            )
                            .ok_or(FsStructuralCommitError::InvalidChild)?;
                        let mut writer = self.begin_blob_with_reference_codec_for_maintenance(
                            &lease,
                            object_kind,
                            payload.len() as u64,
                            None,
                            REFERENCE_CODEC_FS_V1,
                        )?;
                        for chunk in payload.chunks(PAGE_SIZE) {
                            writer.write_chunk(chunk).await?;
                        }
                        return writer.commit().await.map_err(Into::into);
                    }
                    Err(
                        error @ CasStoreError::Store(
                            StoreError::GcResumeRequired
                            | StoreError::Capacity(
                                crate::CapacityClass::Metadata
                                | crate::CapacityClass::CleanerReserve,
                            ),
                        ),
                    ) => {
                        drop(lease);
                        if cycles == maximum_cycles {
                            return Err(error.into());
                        }
                        self.collect_garbage().await?;
                        cycles += 1;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let mut writer = match principal {
            Some(principal) => self.begin_blob_with_reference_codec_for_principal(
                principal,
                object_kind,
                payload.len() as u64,
                None,
                REFERENCE_CODEC_FS_V1,
            )?,
            None => self.begin_blob_with_reference_codec(
                object_kind,
                payload.len() as u64,
                None,
                REFERENCE_CODEC_FS_V1,
            )?,
        };
        for chunk in payload.chunks(PAGE_SIZE) {
            writer.write_chunk(chunk).await?;
        }
        writer.commit().await.map_err(Into::into)
    }

    fn fs_mapping_for_reference(
        &self,
        reference: TypedObjectReference,
        expected_kind: u32,
    ) -> Result<ObjectMapping, FsRootPublishError<D::Error>> {
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
                        FS_DATA_V1_KIND => matches!(
                            mapping.reference_codec,
                            REFERENCE_CODEC_RAW | REFERENCE_CODEC_FS_V1
                        ),
                        _ => false,
                    }
            })
            .ok_or(FsRootPublishError::InvalidRoot)?;
        Ok(mapping)
    }

    fn recover_fs_reference(
        &self,
        reference: TypedObjectReference,
        expected_kind: u32,
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsRootPublishError<D::Error>> {
        let mapping = self.fs_mapping_for_reference(reference, expected_kind)?;
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

    async fn recover_fs_data_reference(
        &self,
        reference: TypedObjectReference,
    ) -> Result<FsPersistentData, FsRootPublishError<D::Error>> {
        let mapping = self.fs_mapping_for_reference(reference, FS_DATA_V1_KIND)?;
        let object = self.recover_fs_reference(reference, FS_DATA_V1_KIND)?;
        let layout = if mapping.reference_codec == REFERENCE_CODEC_FS_V1 {
            FsPersistentDataLayout::Stream(self.read_fs_data_node_meta(&object).await?)
        } else {
            FsPersistentDataLayout::Raw
        };
        Ok(FsPersistentData { object, layout })
    }

    /// Read and validate a data node's structural prefix from its first leaf.
    /// The header and full ancestor table always fit one leaf, so a skip-list
    /// hop costs one verified 4 KiB read regardless of the chunk's size.
    async fn read_fs_data_node_meta(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<FsDataNodeMeta, FsRootPublishError<D::Error>> {
        const _: () = assert!(
            crate::fs_codec::FS_DATA_HEADER_LEN
                + crate::fs_codec::FS_DATA_MAX_ANCESTORS * crate::fs_codec::FS_DATA_REFERENCE_LEN
                <= vibeos_blob_format::LEAF_SIZE,
            "a data node's structural prefix must fit the first Merkle leaf",
        );
        let first = self.get_blob_chunk(object, 0).await?;
        let meta = decode_fs_data_node_v1_prefix(&first.bytes)?;
        // Bind the prefix to the whole object: the recorded payload length
        // must name exactly the committed blob's byte length.
        if meta.encoded_len() as u64 != object.exact_len() {
            return Err(FsRootPublishError::InvalidRoot);
        }
        Ok(meta)
    }

    /// Read a data node's content bytes with per-leaf Merkle verification,
    /// without materializing the encoded node twice.
    async fn read_fs_data_node_content(
        &self,
        object: &AuthorizedObject<CasObjectHandle>,
        meta: &FsDataNodeMeta,
    ) -> Result<Vec<u8>, FsRootPublishError<D::Error>> {
        if meta.encoded_len() as u64 != object.exact_len() {
            return Err(FsRootPublishError::InvalidRoot);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(meta.bytes_len)
            .map_err(|_| StoreError::MemoryLimit)?;
        if meta.bytes_len == 0 {
            return Ok(bytes);
        }
        let leaf_size = vibeos_blob_format::LEAF_SIZE;
        let start = meta.bytes_offset();
        let end = meta.encoded_len();
        let first_leaf = start / leaf_size;
        let last_leaf = (end - 1) / leaf_size;
        for leaf in first_leaf..=last_leaf {
            let chunk = self
                .get_blob_chunk(object, u32::try_from(leaf).map_err(|_| StoreError::Corrupt)?)
                .await?;
            let leaf_start = leaf * leaf_size;
            let copy_from = start.saturating_sub(leaf_start);
            let copy_to = (end - leaf_start).min(chunk.bytes.len());
            if copy_from >= copy_to {
                return Err(FsRootPublishError::InvalidRoot);
            }
            bytes.extend_from_slice(&chunk.bytes[copy_from..copy_to]);
        }
        if bytes.len() != meta.bytes_len {
            return Err(FsRootPublishError::InvalidRoot);
        }
        Ok(bytes)
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
                        crate::FS_DATA_V1_KIND => matches!(
                            mapping.reference_codec,
                            REFERENCE_CODEC_RAW | REFERENCE_CODEC_FS_V1
                        ),
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

    /// Append one bounded file-data chunk to an immutable skip-linked stream.
    /// Only the tail handle and at most 64 opaque ancestor references are kept
    /// in memory, so staging memory is independent of the resulting file size.
    pub async fn commit_fs_data_chunk(
        &mut self,
        previous: Option<&FsPersistentData>,
        bytes: &[u8],
    ) -> Result<FsPersistentData, FsStructuralCommitError<D::Error>> {
        self.commit_fs_data_chunk_inner(previous, bytes, None, None)
            .await
    }

    pub async fn commit_fs_data_chunk_for_principal(
        &mut self,
        principal: &StoragePrincipal,
        previous: Option<&FsPersistentData>,
        bytes: &[u8],
    ) -> Result<FsPersistentData, FsStructuralCommitError<D::Error>> {
        self.commit_fs_data_chunk_inner(previous, bytes, Some(principal), None)
            .await
    }

    pub async fn commit_fs_data_chunk_for_maintenance(
        &mut self,
        maintenance: &StoreMaintenance,
        previous: Option<&FsPersistentData>,
        bytes: &[u8],
    ) -> Result<FsPersistentData, FsStructuralCommitError<D::Error>> {
        self.commit_fs_data_chunk_inner(previous, bytes, None, Some(maintenance))
            .await
    }

    async fn commit_fs_data_chunk_inner(
        &mut self,
        previous: Option<&FsPersistentData>,
        bytes: &[u8],
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<FsPersistentData, FsStructuralCommitError<D::Error>> {
        if bytes.len() > FS_DATA_CHUNK_MAX_LEN
            || (bytes.is_empty() && previous.is_some_and(|data| data.exact_len() != 0))
        {
            return Err(FsCodecError::OutOfBounds.into());
        }
        let (chunk_index, total_len, ancestors) = match previous {
            None => (0, bytes.len() as u64, Vec::new()),
            Some(data) if data.exact_len() == 0 => (0, bytes.len() as u64, Vec::new()),
            Some(data) => {
                let FsPersistentDataLayout::Stream(node) = &data.layout else {
                    return Err(FsStructuralCommitError::InvalidChild);
                };
                let chunk_index = node
                    .chunk_index
                    .checked_add(1)
                    .ok_or(FsCodecError::ArithmeticOverflow)?;
                let total_len = node
                    .total_len
                    .checked_add(bytes.len() as u64)
                    .ok_or(FsCodecError::ArithmeticOverflow)?;
                let required = (u64::BITS - chunk_index.leading_zeros()) as usize;
                let mut ancestors = Vec::new();
                ancestors
                    .try_reserve_exact(required)
                    .map_err(|_| FsCodecError::OutOfBounds)?;
                ancestors.push(self.fs_reference_for(&data.object)?);
                for level in 1..required {
                    let halfway = self
                        .recover_fs_data_reference(ancestors[level - 1])
                        .await
                        .map_err(|error| match error {
                            FsRootPublishError::Store(error) => {
                                FsStructuralCommitError::Store(error)
                            }
                            FsRootPublishError::Codec(error) => {
                                FsStructuralCommitError::Codec(error)
                            }
                            _ => FsStructuralCommitError::InvalidChild,
                        })?;
                    let FsPersistentDataLayout::Stream(halfway_node) = &halfway.layout else {
                        return Err(FsStructuralCommitError::InvalidChild);
                    };
                    let reference = halfway_node
                        .ancestors
                        .get(level - 1)
                        .copied()
                        .ok_or(FsStructuralCommitError::InvalidChild)?;
                    ancestors.push(reference);
                }
                (chunk_index, total_len, ancestors)
            }
        };
        let decoded = FsDataNodeV1 {
            chunk_index,
            total_len,
            ancestors,
            bytes: bytes.to_vec(),
        };
        let payload = encode_fs_data_node_v1(&decoded)?;
        let meta = FsDataNodeMeta::from_node(&decoded);
        drop(decoded);
        Ok(FsPersistentData {
            object: Arc::new(
                self.commit_fs_payload(FS_DATA_V1_KIND, &payload, principal, maintenance)
                    .await?,
            ),
            layout: FsPersistentDataLayout::Stream(meta),
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
            if entry.child.is_some() && entry.data.is_some() {
                return Err(FsStructuralCommitError::InvalidChild);
            }
            canonical.push(FsBtreeEntryV1 {
                key: entry.key.to_vec(),
                value: entry.value.to_vec(),
                reference: match (entry.child, entry.data) {
                    (Some(child), None) => Some(self.fs_reference_for(child)?),
                    (None, Some(data)) => Some(self.fs_reference_for(&data.object)?),
                    (None, None) => None,
                    (Some(_), Some(_)) => unreachable!(),
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

    async fn recover_fs_nodes(
        &self,
        root: &FsPersistentRoot,
        tree: FsTreeKind,
    ) -> Result<Vec<RecoverableFsNode>, FsRootPublishError<D::Error>> {
        let first = match tree {
            FsTreeKind::Inode => root.decoded.inode_tree,
            FsTreeKind::Dirent => root.decoded.dirent_tree,
        };
        let mut pending = alloc::vec![first];
        let mut nodes = Vec::new();
        while let Some(reference) = pending.pop() {
            if nodes.len() >= 4096 {
                return Err(StoreError::MemoryLimit.into());
            }
            let object = self.recover_fs_reference(reference, FS_BTREE_NODE_V1_KIND)?;
            let decoded = decode_fs_btree_node_v1(&self.read_fs_object_bytes(&object).await?)?;
            if decoded.tree != tree || decoded.commit_generation > root.decoded.commit_generation {
                return Err(FsRootPublishError::InvalidRoot);
            }
            if decoded.level > 0 {
                for entry in &decoded.entries {
                    pending.push(entry.reference.ok_or(FsRootPublishError::InvalidRoot)?);
                }
            }
            let mapping = self.fs_mapping_for_reference(reference, FS_BTREE_NODE_V1_KIND)?;
            nodes.push(RecoverableFsNode { decoded, mapping });
        }
        Ok(nodes)
    }

    async fn commit_cow_node(
        &mut self,
        node: FsBtreeNodeV1,
        old_nodes: &[RecoverableFsNode],
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsStructuralCommitError<D::Error>> {
        if let Some(reused) = old_nodes
            .iter()
            .find(|old| {
                old.decoded.tree == node.tree
                    && old.decoded.level == node.level
                    && old.decoded.entries == node.entries
            })
            .map(|old| old.mapping)
        {
            return Ok(Arc::new(
                recover_promotable_cas_object(
                    self.require_current_generation()?
                        .superblock
                        .binding
                        .store_uuid,
                    reused,
                    &self.pins,
                )
                .map_err(|_| StoreError::ObjectUnavailable)?,
            ));
        }
        let payload = encode_fs_btree_node_v1(&node)?;
        Ok(Arc::new(
            self.commit_fs_payload(FS_BTREE_NODE_V1_KIND, &payload, principal, maintenance)
                .await?,
        ))
    }

    /// Build a deterministic B+tree while reusing byte-equivalent nodes and
    /// unchanged leaf data edges reachable from the previous opaque root.
    pub async fn commit_fs_cow_tree(
        &mut self,
        previous: Option<&FsPersistentRoot>,
        tree: FsTreeKind,
        namespace_generation: u64,
        entries: &[FsNodeEntryInput<'_>],
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsStructuralCommitError<D::Error>> {
        self.commit_fs_cow_tree_inner(previous, tree, namespace_generation, entries, None, None)
            .await
    }

    pub async fn commit_fs_cow_tree_for_principal(
        &mut self,
        principal: &StoragePrincipal,
        previous: Option<&FsPersistentRoot>,
        tree: FsTreeKind,
        namespace_generation: u64,
        entries: &[FsNodeEntryInput<'_>],
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsStructuralCommitError<D::Error>> {
        self.commit_fs_cow_tree_inner(
            previous,
            tree,
            namespace_generation,
            entries,
            Some(principal),
            None,
        )
        .await
    }

    pub async fn commit_fs_cow_tree_for_maintenance(
        &mut self,
        maintenance: &StoreMaintenance,
        previous: Option<&FsPersistentRoot>,
        tree: FsTreeKind,
        namespace_generation: u64,
        entries: &[FsNodeEntryInput<'_>],
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsStructuralCommitError<D::Error>> {
        self.commit_fs_cow_tree_inner(
            previous,
            tree,
            namespace_generation,
            entries,
            None,
            Some(maintenance),
        )
        .await
    }

    async fn commit_fs_cow_tree_inner(
        &mut self,
        previous: Option<&FsPersistentRoot>,
        tree: FsTreeKind,
        namespace_generation: u64,
        entries: &[FsNodeEntryInput<'_>],
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
    ) -> Result<Arc<AuthorizedObject<CasObjectHandle>>, FsStructuralCommitError<D::Error>> {
        let old_nodes = match previous {
            Some(root) => self
                .recover_fs_nodes(root, tree)
                .await
                .map_err(|error| match error {
                    FsRootPublishError::Store(error) => FsStructuralCommitError::Store(error),
                    FsRootPublishError::Codec(error) => FsStructuralCommitError::Codec(error),
                    _ => FsStructuralCommitError::InvalidChild,
                })?,
            None => Vec::new(),
        };
        let mut leaves = Vec::new();
        leaves
            .try_reserve_exact(entries.len())
            .map_err(|_| FsCodecError::OutOfBounds)?;
        for input in entries {
            if input.child.is_some() && input.data.is_some() {
                return Err(FsStructuralCommitError::InvalidChild);
            }
            let mut reference = match (input.child, input.data) {
                (Some(child), None) => Some(self.fs_reference_for(child)?),
                (None, Some(data)) => Some(self.fs_reference_for(&data.object)?),
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!(),
            };
            if reference.is_none() && tree == FsTreeKind::Inode {
                reference = old_nodes
                    .iter()
                    .filter(|node| node.decoded.level == 0)
                    .flat_map(|node| &node.decoded.entries)
                    .find(|entry| entry.key == input.key && entry.value == input.value)
                    .and_then(|entry| entry.reference);
            }
            leaves.push(FsBtreeEntryV1 {
                key: input.key.to_vec(),
                value: input.value.to_vec(),
                reference,
            });
        }
        let mut built = Vec::new();
        for range in partition_fs_entries(&leaves)? {
            let object = self
                .commit_cow_node(
                    FsBtreeNodeV1 {
                        tree,
                        level: 0,
                        commit_generation: namespace_generation,
                        entries: leaves[range.clone()].to_vec(),
                    },
                    &old_nodes,
                    principal,
                    maintenance,
                )
                .await?;
            built.push(CowBuiltNode {
                minimum_key: leaves
                    .get(range.start)
                    .map(|entry| entry.key.clone())
                    .unwrap_or_default(),
                object,
            });
        }
        let mut level = 1u8;
        while built.len() > 1 {
            if level > FS_BTREE_MAX_HEIGHT {
                return Err(FsCodecError::OutOfBounds.into());
            }
            let mut internal = Vec::new();
            for child in &built {
                internal.push(FsBtreeEntryV1 {
                    key: child.minimum_key.clone(),
                    value: Vec::new(),
                    reference: Some(self.fs_reference_for(&child.object)?),
                });
            }
            let mut parents = Vec::new();
            for range in partition_fs_entries(&internal)? {
                let object = self
                    .commit_cow_node(
                        FsBtreeNodeV1 {
                            tree,
                            level,
                            commit_generation: namespace_generation,
                            entries: internal[range.clone()].to_vec(),
                        },
                        &old_nodes,
                        principal,
                        maintenance,
                    )
                    .await?;
                parents.push(CowBuiltNode {
                    minimum_key: internal[range.start].key.clone(),
                    object,
                });
            }
            built = parents;
            level += 1;
        }
        built
            .pop()
            .map(|node| node.object)
            .ok_or(FsStructuralCommitError::InvalidChild)
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
        self.commit_fs_root_inner(
            namespace_uuid,
            namespace_generation,
            next_file_id,
            root_file_id,
            inode_tree,
            dirent_tree,
            None,
            None,
        )
        .await
    }

    pub async fn commit_fs_root_for_principal(
        &mut self,
        principal: &StoragePrincipal,
        namespace_uuid: u128,
        namespace_generation: u64,
        next_file_id: u64,
        root_file_id: u64,
        inode_tree: &AuthorizedObject<CasObjectHandle>,
        dirent_tree: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<AuthorizedObject<CasObjectHandle>, FsStructuralCommitError<D::Error>> {
        self.commit_fs_root_inner(
            namespace_uuid,
            namespace_generation,
            next_file_id,
            root_file_id,
            inode_tree,
            dirent_tree,
            Some(principal),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit_fs_root_for_maintenance(
        &mut self,
        maintenance: &StoreMaintenance,
        namespace_uuid: u128,
        namespace_generation: u64,
        next_file_id: u64,
        root_file_id: u64,
        inode_tree: &AuthorizedObject<CasObjectHandle>,
        dirent_tree: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<AuthorizedObject<CasObjectHandle>, FsStructuralCommitError<D::Error>> {
        self.commit_fs_root_inner(
            namespace_uuid,
            namespace_generation,
            next_file_id,
            root_file_id,
            inode_tree,
            dirent_tree,
            None,
            Some(maintenance),
        )
        .await
    }

    async fn commit_fs_root_inner(
        &mut self,
        namespace_uuid: u128,
        namespace_generation: u64,
        next_file_id: u64,
        root_file_id: u64,
        inode_tree: &AuthorizedObject<CasObjectHandle>,
        dirent_tree: &AuthorizedObject<CasObjectHandle>,
        principal: Option<&StoragePrincipal>,
        maintenance: Option<&StoreMaintenance>,
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
        self.commit_fs_payload(FS_ROOT_V1_KIND, &payload, principal, maintenance)
            .await
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
        self.compare_exchange_fs_root_inner(namespace_uuid, expected_generation, new_root, None)
            .await
    }

    pub async fn compare_exchange_fs_root_for_maintenance(
        &mut self,
        maintenance: &StoreMaintenance,
        namespace_uuid: u128,
        expected_generation: u64,
        new_root: &AuthorizedObject<CasObjectHandle>,
    ) -> Result<u64, FsRootPublishError<D::Error>> {
        self.compare_exchange_fs_root_inner(
            namespace_uuid,
            expected_generation,
            new_root,
            Some(maintenance),
        )
        .await
    }

    async fn compare_exchange_fs_root_inner(
        &mut self,
        namespace_uuid: u128,
        expected_generation: u64,
        new_root: &AuthorizedObject<CasObjectHandle>,
        maintenance: Option<&StoreMaintenance>,
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
        if let Some(maintenance) = maintenance {
            let mut external_roots = self
                .require_current_generation()?
                .persistent_authority
                .as_ref()
                .ok_or(FsRootPublishError::InvalidRoot)?
                .external_roots()
                .iter()
                .copied()
                .filter(|root| root.object_kind != FS_ROOT_V1_KIND)
                .collect::<Vec<_>>();
            external_roots.push(PersistentRootEntry {
                object_id: new_key.object_id(),
                commit_generation: new_key.commit_generation(),
                object_kind: FS_ROOT_V1_KIND,
            });
            external_roots.sort_unstable_by_key(|root| root.object_id);
            self.replace_persistent_external_roots(maintenance, external_roots)
                .await?;
        } else {
            self.synchronize_gc_roots(&[new_root]).await?;
        }
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
                        Some(reference) => Some(self.recover_fs_data_reference(reference).await?),
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
        match &data.layout {
            FsPersistentDataLayout::Raw => {
                let index = u32::try_from(index).map_err(|_| FsRootPublishError::InvalidRoot)?;
                Ok(Some(self.get_blob_chunk(&data.object, index).await?.bytes))
            }
            FsPersistentDataLayout::Stream(tail) => {
                let mut current = data.clone();
                let mut current_index = tail.chunk_index;
                while current_index > index {
                    let distance = current_index - index;
                    let jump = (u64::BITS - 1 - distance.leading_zeros()) as usize;
                    let FsPersistentDataLayout::Stream(node) = &current.layout else {
                        return Err(FsRootPublishError::InvalidRoot);
                    };
                    let reference = *node
                        .ancestors
                        .get(jump)
                        .ok_or(FsRootPublishError::InvalidRoot)?;
                    let next = self.recover_fs_data_reference(reference).await?;
                    let FsPersistentDataLayout::Stream(next_node) = &next.layout else {
                        return Err(FsRootPublishError::InvalidRoot);
                    };
                    let expected_index = current_index
                        .checked_sub(1u64 << jump)
                        .ok_or(FsRootPublishError::InvalidRoot)?;
                    if next_node.chunk_index != expected_index
                        || next_node.total_len >= node.total_len
                        || next_node.total_len + node.bytes_len as u64 > node.total_len
                    {
                        return Err(FsRootPublishError::InvalidRoot);
                    }
                    current = next;
                    current_index = expected_index;
                }
                let FsPersistentDataLayout::Stream(node) = &current.layout else {
                    return Err(FsRootPublishError::InvalidRoot);
                };
                Ok(Some(
                    self.read_fs_data_node_content(&current.object, node).await?,
                ))
            }
        }
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

    #[test]
    fn file_data_stream_keeps_a_bounded_tail_and_supports_logarithmic_lookup() {
        let device = TestDevice::blank(48);
        let mut store = format(device);
        let empty = block_on(store.commit_fs_data_chunk(None, &[])).unwrap();
        assert_eq!(empty.exact_len(), 0);
        assert_eq!(empty.chunk_count(), 0);
        assert_eq!(block_on(store.read_fs_data_chunk(&empty, 0)).unwrap(), None);

        let mut tail = empty;
        for index in 0u8..16 {
            let bytes = alloc::vec![index; usize::from(index % 5 + 1)];
            tail = block_on(store.commit_fs_data_chunk(Some(&tail), &bytes)).unwrap();
        }
        assert_eq!(tail.chunk_count(), 16);
        assert_eq!(tail.exact_len(), 46);
        for index in [0, 1, 7, 8, 14, 15] {
            assert_eq!(
                block_on(store.read_fs_data_chunk(&tail, index)).unwrap(),
                Some(alloc::vec![index as u8; (index as usize % 5) + 1])
            );
        }
        assert_eq!(
            block_on(store.read_fs_data_chunk(&tail, tail.chunk_count())).unwrap(),
            None
        );
    }

    #[test]
    fn multi_page_data_chunks_commit_and_cold_recover() {
        let device = TestDevice::blank(64);
        let mut store = format(device.clone());
        let pattern = |index: usize, len: usize| -> Vec<u8> {
            (0..len)
                .map(|offset| (index * 31 + offset * 7) as u8)
                .collect()
        };
        // Mixed chunk sizes in one stream: historical 4 KiB nodes, multi-MiB
        // nodes, and a short tail all chain and read back.
        let sizes = [4096_usize, 1024 * 1024, 2 * 1024 * 1024, 4096, 700];
        let mut tail = None;
        for (index, size) in sizes.iter().enumerate() {
            let bytes = pattern(index, *size);
            let next =
                block_on(store.commit_fs_data_chunk(tail.as_ref(), &bytes)).unwrap();
            assert_eq!(next.chunk_count(), index as u64 + 1);
            tail = Some(next);
        }
        let tail = tail.unwrap();
        let total: usize = sizes.iter().sum();
        assert_eq!(tail.exact_len(), total as u64);
        for (index, size) in sizes.iter().enumerate() {
            assert_eq!(
                block_on(store.read_fs_data_chunk(&tail, index as u64)).unwrap(),
                Some(pattern(index, *size)),
                "chunk {index} readback",
            );
        }
        drop(store);

        // Cold mount must recover the same stream through prefix-only metadata
        // reads. Rebuild the tail handle from a freshly recovered store by
        // committing one more chunk against a re-recovered reference chain.
        let mut cold = SegmentStore::new_with_runtime_context(device, limits(), runtime());
        block_on(cold.mount()).unwrap();
        let extended = block_on(cold.commit_fs_data_chunk(Some(&tail), &pattern(9, 4096))).unwrap();
        assert_eq!(extended.chunk_count(), sizes.len() as u64 + 1);
        assert_eq!(
            block_on(cold.read_fs_data_chunk(&extended, 2)).unwrap(),
            Some(pattern(2, 2 * 1024 * 1024))
        );
        assert_eq!(
            block_on(cold.read_fs_data_chunk(&extended, sizes.len() as u64)).unwrap(),
            Some(pattern(9, 4096))
        );
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
