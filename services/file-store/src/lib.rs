//! Capability-rooted file namespace for VibeOS.
//!
//! A [`RelPath`] is only a selector inside a separately held [`FileTreeRoot`]
//! resource. This crate exposes no ambient namespace, current directory,
//! object-ID lookup, or physical-store handle.

#![no_std]

extern crate alloc;

mod path;
mod persistence;
mod storage;

pub use path::*;
pub use persistence::*;
pub use storage::*;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use vibeos_core::cap::Resource;
use vibeos_core::sync::SpinLock;

pub type FileId = u64;
pub const ROOT_FILE_ID: FileId = 1;
pub const MAX_TRANSACTION_EDITS: usize = 4096;
pub const DATA_CHUNK_SIZE: usize = 4096;
/// Chunk stride for content staged straight to the persistent backend. Three
/// 1 MiB content extents plus header and Merkle tree fill one 4 MiB scratch
/// segment, so this is the largest stride that still commits whole segments.
/// In-memory (volatile) files keep the 4 KiB stride.
pub const PERSISTENT_STAGE_CHUNK_SIZE: usize = 3 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileError {
    Busy,
    BudgetExceeded,
    Conflict,
    DirectoryNotEmpty,
    EscapeRoot,
    Exists,
    FileIdExhausted,
    InvalidName,
    InvalidPath,
    InvalidType,
    IsDirectory,
    NotDirectory,
    NotFound,
    PathTooLong,
    RootProtected,
    ServiceUnavailable,
    SymlinkLoop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub file_id: FileId,
    pub file_type: FileType,
    pub size: u64,
    pub link_count: u64,
    pub change_generation: u64,
}

#[derive(Clone)]
enum Content {
    None,
    File(Vec<Arc<[u8]>>),
    PersistentFile(vibeos_segment_store::FsPersistentData),
    Symlink(String),
}

#[derive(Clone)]
struct Inode {
    file_type: FileType,
    change_generation: u64,
    content: Content,
}

#[derive(Clone)]
struct NamespaceState {
    namespace: u128,
    generation: u64,
    next_file_id: FileId,
    inodes: BTreeMap<FileId, Inode>,
    dirents: BTreeMap<(FileId, String), FileId>,
}

impl NamespaceState {
    fn empty(namespace: u128) -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            ROOT_FILE_ID,
            Inode {
                file_type: FileType::Directory,
                change_generation: 0,
                content: Content::None,
            },
        );
        Self {
            namespace,
            generation: 0,
            next_file_id: 2,
            inodes,
            dirents: BTreeMap::new(),
        }
    }

    fn allocate(&mut self, inode: Inode) -> Result<FileId, FileError> {
        let id = self.next_file_id;
        if id == 0 {
            return Err(FileError::FileIdExhausted);
        }
        self.next_file_id = id.checked_add(1).ok_or(FileError::FileIdExhausted)?;
        self.inodes.insert(id, inode);
        Ok(id)
    }

    fn lookup_child(&self, parent: FileId, name: &str) -> Result<FileId, FileError> {
        self.dirents
            .get(&(parent, name.to_string()))
            .copied()
            .ok_or(FileError::NotFound)
    }

    fn resolve_canonical(
        &self,
        path: &RelPath,
        follow_final: bool,
    ) -> Result<(FileId, Vec<String>), FileError> {
        self.resolve_canonical_from(ROOT_FILE_ID, path, follow_final)
    }

    fn resolve_canonical_from(
        &self,
        boundary: FileId,
        path: &RelPath,
        follow_final: bool,
    ) -> Result<(FileId, Vec<String>), FileError> {
        if self.inodes.get(&boundary).ok_or(FileError::NotFound)?.file_type != FileType::Directory {
            return Err(FileError::NotDirectory);
        }
        let mut pending = path.components().to_vec();
        let mut resolved_names: Vec<String> = Vec::new();
        let mut current = boundary;
        let mut followed = 0usize;
        let mut index = 0usize;
        while index < pending.len() {
            let inode = self.inodes.get(&current).ok_or(FileError::NotFound)?;
            if inode.file_type != FileType::Directory {
                return Err(FileError::NotDirectory);
            }
            let child = self.lookup_child(current, &pending[index])?;
            let child_inode = self.inodes.get(&child).ok_or(FileError::NotFound)?;
            let is_final = index + 1 == pending.len();
            if child_inode.file_type == FileType::Symlink && (follow_final || !is_final) {
                followed += 1;
                if followed > MAX_SYMLINKS {
                    return Err(FileError::SymlinkLoop);
                }
                let Content::Symlink(target) = &child_inode.content else {
                    return Err(FileError::InvalidType);
                };
                let target_path = RelPath::joined_from(&resolved_names, target)?;
                let mut replacement = target_path.components().to_vec();
                replacement.extend_from_slice(&pending[index + 1..]);
                pending = RelPath::from_components(replacement)?.components().to_vec();
                resolved_names.clear();
                current = boundary;
                index = 0;
                continue;
            }
            current = child;
            resolved_names.push(pending[index].clone());
            index += 1;
        }
        Ok((current, resolved_names))
    }

    fn resolve(&self, path: &RelPath, follow_final: bool) -> Result<FileId, FileError> {
        self.resolve_canonical(path, follow_final)
            .map(|value| value.0)
    }

    fn admit_file_id(&self, boundary: FileId, id: FileId) -> Result<(), FileError> {
        if !self.inodes.contains_key(&id) { return Err(FileError::NotFound); }
        if boundary == ROOT_FILE_ID || id == boundary { return Ok(()); }
        // Do not follow symlinks. A file identity must have a real directory
        // entry below the boundary; existing hard links retain inode semantics.
        let mut directories = alloc::vec![boundary];
        let mut visited = BTreeSet::new();
        while let Some(directory) = directories.pop() {
            if !visited.insert(directory) { continue; }
            for ((parent, _), child) in &self.dirents {
                if *parent != directory { continue; }
                if *child == id { return Ok(()); }
                if self.inodes.get(child).is_some_and(|inode| inode.file_type == FileType::Directory) {
                    directories.push(*child);
                }
            }
        }
        Err(FileError::EscapeRoot)
    }

    /// Link counts of every inode in one pass over the directory entries:
    /// directories count 2 plus their subdirectories, everything else counts
    /// its incoming entries. Encoding or validating a whole namespace must
    /// use this instead of [`Self::link_count`] per inode, which scans every
    /// entry per inode and made each commit quadratic in the file count.
    fn link_counts(&self) -> BTreeMap<FileId, u64> {
        let mut counts: BTreeMap<FileId, u64> = BTreeMap::new();
        for (id, inode) in &self.inodes {
            counts.insert(*id, if inode.file_type == FileType::Directory { 2 } else { 0 });
        }
        for ((parent, _), child) in &self.dirents {
            let child_is_directory = self
                .inodes
                .get(child)
                .is_some_and(|inode| inode.file_type == FileType::Directory);
            let counted = if child_is_directory { *parent } else { *child };
            if let Some(count) = counts.get_mut(&counted) {
                *count += 1;
            }
        }
        counts
    }

    fn link_count(&self, id: FileId, kind: FileType) -> u64 {
        if kind == FileType::Directory {
            2 + self
                .dirents
                .iter()
                .filter(|((parent, _), child)| {
                    *parent == id
                        && self
                            .inodes
                            .get(child)
                            .is_some_and(|i| i.file_type == FileType::Directory)
                })
                .count() as u64
        } else {
            self.dirents.values().filter(|child| **child == id).count() as u64
        }
    }

    fn metadata(&self, id: FileId) -> Result<Metadata, FileError> {
        let inode = self.inodes.get(&id).ok_or(FileError::NotFound)?;
        let size = match &inode.content {
            Content::None => 0,
            Content::Symlink(target) => target.len() as u64,
            Content::File(chunks) => chunks.iter().map(|c| c.len() as u64).sum(),
            Content::PersistentFile(data) => data.exact_len(),
        };
        Ok(Metadata {
            file_id: id,
            file_type: inode.file_type,
            size,
            link_count: self.link_count(id, inode.file_type),
            change_generation: inode.change_generation,
        })
    }
}

/// A pinned immutable namespace version. Existing snapshots remain readable
/// after later commits because the published state is replaced, never mutated.
#[derive(Clone)]
pub struct FsSnapshotLease {
    state: Arc<NamespaceState>,
    boundary: FileId,
}

impl FsSnapshotLease {
    /// Pin a directory as this snapshot's namespace boundary. Symbolic links
    /// are resolved relative to that boundary, including links encountered in
    /// intermediate components. This is an immutable read view, not new
    /// mutation authority or a live capability: callers must still revalidate
    /// their source capability before admitting a later operation.
    pub fn directory(&self, path: &RelPath) -> Result<Self, FileError> {
        let boundary = self.resolve(path, true)?;
        if self.state.metadata(boundary)?.file_type != FileType::Directory {
            return Err(FileError::NotDirectory);
        }
        Ok(Self { state: self.state.clone(), boundary })
    }
    fn resolve(&self, path: &RelPath, follow_final: bool) -> Result<FileId, FileError> {
        self.state.resolve_canonical_from(self.boundary, path, follow_final).map(|v| v.0)
    }

    pub fn namespace(&self) -> u128 {
        self.state.namespace
    }
    pub fn generation(&self) -> u64 {
        self.state.generation
    }
    pub fn stat(&self, path: &RelPath, follow_final: bool) -> Result<Metadata, FileError> {
        self.state.metadata(self.resolve(path, follow_final)?)
    }
    pub fn readlink(&self, path: &RelPath) -> Result<&str, FileError> {
        let id = self.resolve(path, false)?;
        match &self
            .state
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .content
        {
            Content::Symlink(value) => Ok(value),
            _ => Err(FileError::InvalidType),
        }
    }
    pub fn read_chunks(&self, path: &RelPath) -> Result<impl Iterator<Item = &[u8]>, FileError> {
        let id = self.resolve(path, true)?;
        match &self
            .state
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .content
        {
            Content::File(chunks) => Ok(chunks.iter().map(|chunk| chunk.as_ref())),
            Content::None => Err(FileError::IsDirectory),
            Content::PersistentFile(_) | Content::Symlink(_) => Err(FileError::InvalidType),
        }
    }
    pub fn read_owned_chunks(&self, path: &RelPath) -> Result<Vec<Arc<[u8]>>, FileError> {
        let id = self.resolve(path, true)?;
        match &self
            .state
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .content
        {
            Content::File(chunks) => Ok(chunks.clone()),
            Content::None => Err(FileError::IsDirectory),
            Content::PersistentFile(_) | Content::Symlink(_) => Err(FileError::InvalidType),
        }
    }
    pub fn persistent_data(
        &self,
        path: &RelPath,
    ) -> Result<vibeos_segment_store::FsPersistentData, FileError> {
        let id = self.resolve(path, true)?;
        match &self
            .state
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .content
        {
            Content::PersistentFile(data) => Ok(data.clone()),
            Content::None => Err(FileError::IsDirectory),
            Content::File(_) | Content::Symlink(_) => Err(FileError::InvalidType),
        }
    }
    pub fn canonical_path(&self, path: &RelPath) -> Result<String, FileError> {
        let (_, components) = self.state.resolve_canonical_from(self.boundary, path, true)?;
        Ok(components.join("/"))
    }
    pub fn list(
        &self,
        path: &RelPath,
        follow_final: bool,
    ) -> Result<Vec<(String, Metadata)>, FileError> {
        let id = self.resolve(path, follow_final)?;
        if self
            .state
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .file_type
            != FileType::Directory
        {
            return Err(FileError::NotDirectory);
        }
        let mut out = Vec::new();
        for ((parent, name), child) in &self.state.dirents {
            if *parent == id {
                out.push((name.clone(), self.state.metadata(*child)?));
            }
        }
        Ok(out)
    }
}

pub struct FsFileReader {
    source: FsFileReaderSource,
}

enum FsFileReaderSource {
    Volatile(Vec<Arc<[u8]>>),
    Persistent {
        backend: Arc<dyn FileTreeBackend>,
        data: vibeos_segment_store::FsPersistentData,
    },
}

impl FsFileReader {
    /// Read a bounded prefix at a byte offset. A result may stop at a chunk
    /// boundary; callers needing more bytes continue at the returned offset.
    /// Volatile files skip prefix metadata without copying preceding chunks.
    pub async fn read_at(&self, mut offset: u64, maximum: usize) -> Result<Vec<u8>, FileError> {
        if maximum == 0 { return Ok(Vec::new()); }
        if let FsFileReaderSource::Volatile(chunks) = &self.source {
            for chunk in chunks {
                if offset >= chunk.len() as u64 { offset -= chunk.len() as u64; continue; }
                let start = offset as usize;
                let length = maximum.min(chunk.len() - start);
                return Ok(chunk[start..start + length].to_vec());
            }
            return Ok(Vec::new());
        }
        // Persistent streams may contain differently sized chunks; preserve
        // their backend's verified reads rather than assuming a fixed stride.
        for index in 0..self.chunk_count() {
            let chunk = self.read_chunk(index).await?.ok_or(FileError::ServiceUnavailable)?;
            if offset >= chunk.len() as u64 { offset -= chunk.len() as u64; continue; }
            let start = offset as usize;
            let length = maximum.min(chunk.len() - start);
            return Ok(chunk[start..start + length].to_vec());
        }
        Ok(Vec::new())
    }

    pub fn chunk_count(&self) -> u64 {
        match &self.source {
            FsFileReaderSource::Volatile(chunks) => chunks.len() as u64,
            FsFileReaderSource::Persistent { data, .. } => data.chunk_count(),
        }
    }

    pub async fn read_chunk(&self, index: u64) -> Result<Option<Vec<u8>>, FileError> {
        match &self.source {
            FsFileReaderSource::Volatile(chunks) => Ok(chunks
                .get(usize::try_from(index).map_err(|_| FileError::BudgetExceeded)?)
                .map(|chunk| chunk.to_vec())),
            FsFileReaderSource::Persistent { backend, data } => {
                backend.read_chunk(data.clone(), index).await
            }
        }
    }
}

/// How many full persistent chunks one backend staging call may carry. Four
/// 3 MiB chunks bound the stager's buffered bytes at 12 MiB while letting a
/// batching backend publish them under a single durable transaction.
pub const STAGE_FLUSH_CHUNKS: usize = 4;

pub struct FsContentStager {
    backend: Arc<dyn FileTreeBackend>,
    tail: Option<vibeos_segment_store::FsPersistentData>,
    pending: Vec<u8>,
    staged: Vec<Vec<u8>>,
}

/// Content no larger than this that a stager finishes without having staged
/// anything stays in memory and is published inside the transaction's own
/// fused checkpoint, instead of through a checkpoint of its own first. The
/// bound matches the segment store's small-blob packing, so the content
/// shares the tree nodes' scratch segment.
pub const FUSED_CONTENT_LIMIT: usize = 192 * 1024;

pub struct StagedFileContent {
    source: StagedContentSource,
}

enum StagedContentSource {
    Persistent(vibeos_segment_store::FsPersistentData),
    Inline(Vec<u8>),
}

impl FsContentStager {
    pub async fn push(&mut self, mut bytes: &[u8]) -> Result<(), FileError> {
        while !bytes.is_empty() {
            let take = core::cmp::min(
                PERSISTENT_STAGE_CHUNK_SIZE - self.pending.len(),
                bytes.len(),
            );
            if self.pending.len() + take > self.pending.capacity()
                && self.pending.capacity() > PERSISTENT_STAGE_CHUNK_SIZE / 2
            {
                // Geometric growth would round a 3 MiB chunk up to 4 MiB.
                // Keep small writes incremental, but cap the final growth
                // so a four-chunk batch holds at most 12 MiB of capacity.
                self.pending.reserve_exact(PERSISTENT_STAGE_CHUNK_SIZE - self.pending.len());
            }
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() == PERSISTENT_STAGE_CHUNK_SIZE {
                self.staged.push(core::mem::take(&mut self.pending));
                if self.staged.len() == STAGE_FLUSH_CHUNKS {
                    self.flush().await?;
                }
            }
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), FileError> {
        if self.staged.is_empty() {
            return Ok(());
        }
        let chunks = core::mem::take(&mut self.staged);
        self.tail = Some(self.backend.stage_chunks(self.tail.clone(), chunks).await?);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<StagedFileContent, FileError> {
        if self.tail.is_none()
            && self.staged.is_empty()
            && !self.pending.is_empty()
            && self.pending.len() <= FUSED_CONTENT_LIMIT
        {
            // Nothing reached the backend yet: let the committing transaction
            // publish this content under its own checkpoint.
            return Ok(StagedFileContent {
                source: StagedContentSource::Inline(core::mem::take(&mut self.pending)),
            });
        }
        if !self.pending.is_empty() {
            self.staged.push(core::mem::take(&mut self.pending));
        }
        self.flush().await?;
        if self.tail.is_none() {
            // An empty file still needs its zero-length stream head.
            self.tail = Some(self.backend.stage_chunk(None, Vec::new()).await?);
        }
        Ok(StagedFileContent {
            source: StagedContentSource::Persistent(self.tail.ok_or(FileError::InvalidType)?),
        })
    }
}

/// The capability resource. Holding an authorized capability to this value is
/// the only way a task can obtain a snapshot or start a writer.
pub struct FileTreeRoot {
    inner: Arc<FileTreeInner>,
    boundary: FileId,
}

struct FileTreeInner {
    state: SpinLock<Arc<NamespaceState>>,
    persistent_root: SpinLock<Option<vibeos_segment_store::FsPersistentRoot>>,
    writer_claim: SpinLock<Option<FileWriterClaim>>,
    next_writer_token: AtomicU64,
    backend: Option<Arc<dyn FileTreeBackend>>,
}

pub type FileTreeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FileError>> + Send + 'a>>;

/// Opaque adapter implemented by the boot-policy-selected Storage V2 runtime.
/// It exposes file operations, never the store, object IDs, keys, or physical
/// pointers, and therefore cannot be used for ambient catalog lookup.
pub trait FileTreeBackend: Send + Sync {
    fn stage_chunk<'a>(
        &'a self,
        previous: Option<vibeos_segment_store::FsPersistentData>,
        bytes: Vec<u8>,
    ) -> FileTreeFuture<'a, vibeos_segment_store::FsPersistentData>;

    /// Stage several full chunks at once. Backends that can batch chunks
    /// under one durable transaction override this; the default preserves
    /// per-chunk semantics exactly.
    fn stage_chunks<'a>(
        &'a self,
        previous: Option<vibeos_segment_store::FsPersistentData>,
        chunks: Vec<Vec<u8>>,
    ) -> FileTreeFuture<'a, vibeos_segment_store::FsPersistentData> {
        Box::pin(async move {
            let mut tail = previous;
            for bytes in chunks {
                tail = Some(self.stage_chunk(tail, bytes).await?);
            }
            tail.ok_or(FileError::InvalidType)
        })
    }

    fn read_chunk<'a>(
        &'a self,
        data: vibeos_segment_store::FsPersistentData,
        index: u64,
    ) -> FileTreeFuture<'a, Option<Vec<u8>>>;

    fn commit<'a>(&'a self, transaction: FsTransaction) -> FileTreeFuture<'a, u64>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileWriterClaim {
    pub owner: u64,
    pub token: u64,
    pub base_generation: u64,
}

impl FileTreeRoot {
    pub fn new_empty(namespace: u128) -> Result<Self, FileError> {
        if namespace == 0 {
            return Err(FileError::InvalidPath);
        }
        Ok(Self {
            boundary: ROOT_FILE_ID,
            inner: Arc::new(FileTreeInner {
                state: SpinLock::new(Arc::new(NamespaceState::empty(namespace))),
                persistent_root: SpinLock::new(None),
                writer_claim: SpinLock::new(None),
                next_writer_token: AtomicU64::new(1),
                backend: None,
            }),
        })
    }
    /// Share the live namespace while confining all reads and transactions to
    /// a directory identity. The caller supplies capability authorization;
    /// this view itself neither mints nor extends authority.
    pub fn directory(&self, path: &RelPath) -> Result<Self, FileError> {
        let snapshot = self.snapshot().directory(path)?;
        Ok(Self { inner: self.inner.clone(), boundary: snapshot.boundary })
    }
    fn resolve_in(&self, snapshot: &NamespaceState, path: &RelPath, follow_final: bool) -> Result<FileId, FileError> {
        snapshot.resolve_canonical_from(self.boundary, path, follow_final).map(|v| v.0)
    }
    pub fn attach_backend(&mut self, backend: Arc<dyn FileTreeBackend>) -> Result<(), FileError> {
        let inner = Arc::get_mut(&mut self.inner).ok_or(FileError::Busy)?;
        if inner.backend.is_some() {
            return Err(FileError::Exists);
        }
        inner.backend = Some(backend);
        Ok(())
    }
    pub fn snapshot(&self) -> FsSnapshotLease {
        FsSnapshotLease {
            boundary: self.boundary,
            state: self.inner.state.lock().clone(),
        }
    }
    pub fn is_persistent(&self) -> bool {
        self.inner.backend.is_some()
    }
    /// Pin metadata and content from one namespace generation, rejecting symlinks.
    pub fn regular_reader(&self, path: &RelPath) -> Result<(Metadata, FsFileReader), FileError> {
        let snapshot = self.inner.state.lock().clone();
        let lease = FsSnapshotLease {
            boundary: self.boundary,
            state: snapshot.clone(),
        };
        let metadata = lease.stat(path, false)?;
        if metadata.file_type != FileType::Regular
            || lease.canonical_path(path)? != path.to_selector_string()
        {
            return Err(FileError::InvalidType);
        }
        Ok((metadata, self.reader_in(snapshot, path)?))
    }
    pub fn reader(&self, path: &RelPath) -> Result<FsFileReader, FileError> {
        self.reader_in(self.inner.state.lock().clone(), path)
    }
    /// Follow capability-contained symlinks, pinning metadata and bytes from
    /// the same namespace generation. Unlike regular_reader this admits links.
    pub fn resolved_regular_reader(&self, path: &RelPath) -> Result<(Metadata, FsFileReader), FileError> {
        let snapshot = self.inner.state.lock().clone();
        let metadata = FsSnapshotLease { state: snapshot.clone(), boundary: self.boundary }.stat(path, true)?;
        if metadata.file_type == FileType::Directory { return Err(FileError::IsDirectory); }
        if metadata.file_type != FileType::Regular { return Err(FileError::InvalidType); }
        Ok((metadata, self.reader_in(snapshot, path)?))
    }
    /// Obtain current content for an identity already admitted from this root.
    pub fn regular_reader_by_id(&self, id: FileId) -> Result<(Metadata, FsFileReader), FileError> {
        let snapshot = self.inner.state.lock().clone();
        let metadata = snapshot.metadata(id)?;
        let reader = self.reader_id_in(snapshot, id)?;
        Ok((metadata, reader))
    }

    fn reader_in(
        &self,
        snapshot: Arc<NamespaceState>,
        path: &RelPath,
    ) -> Result<FsFileReader, FileError> {
        let id = self.resolve_in(&snapshot, path, true)?;
        self.reader_id_in(snapshot, id)
    }
    fn reader_id_in(&self, snapshot: Arc<NamespaceState>, id: FileId) -> Result<FsFileReader, FileError> {
        snapshot.admit_file_id(self.boundary, id)?;
        match &snapshot.inodes.get(&id).ok_or(FileError::NotFound)?.content {
            Content::File(chunks) => Ok(FsFileReader {
                source: FsFileReaderSource::Volatile(chunks.clone()),
            }),
            Content::PersistentFile(data) => Ok(FsFileReader {
                source: FsFileReaderSource::Persistent {
                    backend: self
                        .inner
                        .backend
                        .clone()
                        .ok_or(FileError::ServiceUnavailable)?,
                    data: data.clone(),
                },
            }),
            Content::None => Err(FileError::IsDirectory),
            Content::Symlink(_) => Err(FileError::InvalidType),
        }
    }
    pub fn begin_content_stager(
        &self,
        path: &RelPath,
        append: bool,
    ) -> Result<FsContentStager, FileError> {
        let snapshot = self.inner.state.lock().clone();
        self.resolve_in(&snapshot, &RelPath::root(), true)?;
        let backend = self
            .inner
            .backend
            .clone()
            .ok_or(FileError::ServiceUnavailable)?;
        let tail = match self.resolve_in(&snapshot, path, true) {
            Ok(id) => {
                let inode = snapshot.inodes.get(&id).ok_or(FileError::NotFound)?;
                if inode.file_type == FileType::Directory {
                    return Err(FileError::IsDirectory);
                }
                if inode.file_type != FileType::Regular {
                    return Err(FileError::InvalidType);
                }
                if append {
                    match &inode.content {
                        Content::PersistentFile(data) => Some(data.clone()),
                        _ => return Err(FileError::ServiceUnavailable),
                    }
                } else {
                    None
                }
            }
            Err(FileError::NotFound) => {
                if self.resolve_in(&snapshot, path, false).is_ok() {
                    return Err(FileError::NotFound);
                }
                None
            }
            Err(error) => return Err(error),
        };
        Ok(FsContentStager {
            backend,
            tail,
            pending: Vec::new(),
            staged: Vec::new(),
        })
    }
    pub fn begin(&self) -> Result<FsTransaction, FileError> {
        let token = self
            .inner
            .next_writer_token
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| FileError::FileIdExhausted)?;
        self.begin_with_claim(0, token)
    }
    /// Observe an authoritative generation only when no publication is pending.
    /// Completed writes already awaited the selected backend's commit policy.
    /// This adds no persistence guarantee to an intentionally volatile root.
    pub fn completed_generation(&self) -> Result<u64, FileError> {
        // Match commit's state -> writer lock order. Keep the publication
        // snapshot stable while checking its writer claim.
        let state = self.inner.state.lock();
        self.resolve_in(&state, &RelPath::root(), true)?;
        let writer = self.inner.writer_claim.lock();
        if writer.is_some() { return Err(FileError::Busy); }
        Ok(state.generation)
    }
    pub fn begin_with_claim(&self, owner: u64, token: u64) -> Result<FsTransaction, FileError> {
        if token == 0 {
            return Err(FileError::InvalidPath);
        }
        let snapshot = self.inner.state.lock().clone();
        self.resolve_in(&snapshot, &RelPath::root(), true)?;
        let previous_root = self.inner.persistent_root.lock().clone();
        let claim = FileWriterClaim {
            owner,
            token,
            base_generation: snapshot.generation,
        };
        let mut active = self.inner.writer_claim.lock();
        if active.is_some() {
            return Err(FileError::Busy);
        }
        *active = Some(claim);
        drop(active);
        Ok(FsTransaction {
            root: self.inner.clone(),
            claim,
            previous_root,
            base_generation: snapshot.generation,
            working: (*snapshot).clone(),
            boundary: self.boundary,
            edits: 0,
            committed: false,
            cancellation: None,
        })
    }
    pub fn recover_writer_claim(&self, owner: u64, token: u64) -> bool {
        let mut active = self.inner.writer_claim.lock();
        if active.is_some_and(|claim| claim.owner == owner && claim.token == token) {
            *active = None;
            true
        } else {
            false
        }
    }
}

impl FileTreeInner {
    fn release_writer_claim(&self, expected: FileWriterClaim) -> bool {
        let mut active = self.writer_claim.lock();
        if *active == Some(expected) {
            *active = None;
            true
        } else {
            false
        }
    }
}

impl Resource for FileTreeRoot {
    fn kind(&self) -> &'static str {
        "file-tree-root"
    }
    fn describe(&self) -> String {
        let state = self.inner.state.lock();
        alloc::format!("file tree generation {}", state.generation)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct FsTransaction {
    root: Arc<FileTreeInner>,
    claim: FileWriterClaim,
    previous_root: Option<vibeos_segment_store::FsPersistentRoot>,
    base_generation: u64,
    working: NamespaceState,
    boundary: FileId,
    edits: usize,
    committed: bool,
    cancellation: Option<Arc<AtomicBool>>,
}

impl FsTransaction {
    /// Narrow an unmodified transaction to one directory in its pinned working
    /// generation. Publication still commits the shared namespace atomically.
    /// Consuming self prevents accidental reuse of an unrestricted transaction
    /// after failed admission. Previously staged edits cannot be smuggled in.
    pub fn into_directory(mut self, path: &RelPath) -> Result<Self, FileError> {
        if self.edits != 0 { return Err(FileError::Conflict); }
        let boundary = self.resolve(path, true)?;
        if self.working.inodes.get(&boundary).ok_or(FileError::NotFound)?.file_type != FileType::Directory {
            return Err(FileError::NotDirectory);
        }
        self.boundary = boundary;
        Ok(self)
    }
    fn resolve(&self, path: &RelPath, follow_final: bool) -> Result<FileId, FileError> {
        self.working.resolve_canonical_from(self.boundary, path, follow_final).map(|v| v.0)
    }

    /// Recheck cancellation after backend waits, before entering the atomic
    /// root-publication operation. Once publication starts it completes atomically.
    pub fn cancel_on(&mut self, flag: Arc<AtomicBool>) {
        self.cancellation = Some(flag);
    }

    fn check_publication(&self) -> Result<(), FileError> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Err(FileError::Conflict)
        } else {
            Ok(())
        }
    }
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }

    pub async fn commit_authoritative(self) -> Result<u64, FileError> {
        let backend = self.root.backend.clone();
        match backend {
            Some(backend) => backend.commit(self).await,
            None => self.commit(),
        }
    }

    pub async fn commit_durable(self) -> Result<u64, FileError> {
        let backend = self
            .root
            .backend
            .clone()
            .ok_or(FileError::ServiceUnavailable)?;
        backend.commit(self).await
    }
    fn charge(&mut self, count: usize) -> Result<(), FileError> {
        self.edits = self
            .edits
            .checked_add(count)
            .ok_or(FileError::BudgetExceeded)?;
        if self.edits > MAX_TRANSACTION_EDITS {
            Err(FileError::BudgetExceeded)
        } else {
            Ok(())
        }
    }
    fn next_generation(&self) -> Result<u64, FileError> {
        self.base_generation
            .checked_add(1)
            .ok_or(FileError::FileIdExhausted)
    }
    fn parent(&self, path: &RelPath) -> Result<(FileId, String), FileError> {
        let (parent, name) = path.parent_and_name()?;
        let id = self.resolve(&parent, true)?;
        if self
            .working
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .file_type
            != FileType::Directory
        {
            return Err(FileError::NotDirectory);
        }
        Ok((id, name.to_string()))
    }
    pub fn mkdir(&mut self, path: &RelPath, parents: bool) -> Result<(), FileError> {
        if !parents {
            let (parent, name) = self.parent(path)?;
            if self.working.dirents.contains_key(&(parent, name.clone())) {
                return Err(FileError::Exists);
            }
            self.charge(2)?;
            let id = self.working.allocate(Inode {
                file_type: FileType::Directory,
                change_generation: self.next_generation()?,
                content: Content::None,
            })?;
            self.working.dirents.insert((parent, name), id);
            return Ok(());
        }
        let mut current = self.boundary;
        for name in path.components() {
            if let Some(id) = self.working.dirents.get(&(current, name.clone())).copied() {
                if self
                    .working
                    .inodes
                    .get(&id)
                    .ok_or(FileError::NotFound)?
                    .file_type
                    != FileType::Directory
                {
                    return Err(FileError::NotDirectory);
                }
                current = id;
            } else {
                self.charge(2)?;
                let id = self.working.allocate(Inode {
                    file_type: FileType::Directory,
                    change_generation: self.next_generation()?,
                    content: Content::None,
                })?;
                self.working.dirents.insert((current, name.clone()), id);
                current = id;
            }
        }
        Ok(())
    }
    /// Resolve a regular file inside this transaction's unpublished generation.
    pub fn regular_file_id(&self, path: &RelPath) -> Result<FileId, FileError> {
        let id = self.resolve(path, true)?;
        match self.working.metadata(id)?.file_type {
            FileType::Regular => Ok(id),
            FileType::Directory => Err(FileError::IsDirectory),
            FileType::Symlink => Err(FileError::InvalidType),
        }
    }

    /// Update an already-admitted file identity, independent of its current name.
    /// Callers must obtain the ID from this root and enforce their capability.
    /// Publication remains explicit; aborting the transaction discards the edit.
    pub async fn write_file_range(
        &mut self, id: FileId, offset: u64, bytes: &[u8],
    ) -> Result<(), FileError> {
        let offset = usize::try_from(offset).map_err(|_| FileError::BudgetExceeded)?;
        let end = offset.checked_add(bytes.len()).ok_or(FileError::BudgetExceeded)?;
        let mut data = self.file_bytes(id).await?;
        if bytes.is_empty() { return Ok(()); }
        if end > data.len() {
            data.try_reserve(end - data.len()).map_err(|_| FileError::BudgetExceeded)?;
            data.resize(end, 0);
        }
        data[offset..end].copy_from_slice(bytes);
        self.replace_file_bytes(id, &data)
    }

    /// Preserve inode identity and hard links while shrinking or zero-extending.
    pub async fn truncate_file(&mut self, id: FileId, length: u64) -> Result<(), FileError> {
        let length = usize::try_from(length).map_err(|_| FileError::BudgetExceeded)?;
        let mut data = self.file_bytes(id).await?;
        if length > data.len() {
            data.try_reserve(length - data.len()).map_err(|_| FileError::BudgetExceeded)?;
        }
        data.resize(length, 0);
        self.replace_file_bytes(id, &data)
    }

    async fn file_bytes(&self, id: FileId) -> Result<Vec<u8>, FileError> {
        self.working.admit_file_id(self.boundary, id)?;
        let inode = self.working.inodes.get(&id).ok_or(FileError::NotFound)?;
        let source = match &inode.content {
            Content::File(chunks) => FsFileReaderSource::Volatile(chunks.clone()),
            Content::PersistentFile(data) => FsFileReaderSource::Persistent {
                backend: self.root.backend.clone().ok_or(FileError::ServiceUnavailable)?,
                data: data.clone(),
            },
            Content::None => return Err(FileError::IsDirectory),
            Content::Symlink(_) => return Err(FileError::InvalidType),
        };
        let expected = usize::try_from(self.working.metadata(id)?.size)
            .map_err(|_| FileError::BudgetExceeded)?;
        let mut bytes = Vec::new();
        bytes.try_reserve(expected).map_err(|_| FileError::BudgetExceeded)?;
        let reader = FsFileReader { source };
        for index in 0..reader.chunk_count() {
            let chunk = reader.read_chunk(index).await?.ok_or(FileError::ServiceUnavailable)?;
            if chunk.len() > expected - bytes.len() { return Err(FileError::ServiceUnavailable); }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != expected { return Err(FileError::ServiceUnavailable); }
        Ok(bytes)
    }

    fn replace_file_bytes(&mut self, id: FileId, bytes: &[u8]) -> Result<(), FileError> {
        let count = bytes.len().div_ceil(DATA_CHUNK_SIZE);
        let mut chunks = Vec::new();
        chunks.try_reserve(count).map_err(|_| FileError::BudgetExceeded)?;
        for chunk in bytes.chunks(DATA_CHUNK_SIZE) { chunks.push(Arc::<[u8]>::from(chunk)); }
        let generation = self.next_generation()?;
        self.charge(1)?;
        let inode = self.working.inodes.get_mut(&id).ok_or(FileError::NotFound)?;
        inode.content = Content::File(chunks);
        inode.change_generation = generation;
        Ok(())
    }

    pub fn write_chunks<I, B>(
        &mut self,
        path: &RelPath,
        chunks: I,
        append: bool,
    ) -> Result<(), FileError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut data = Vec::new();
        let mut pending = Vec::new();
        for chunk in chunks {
            let mut bytes = chunk.as_ref();
            while !bytes.is_empty() {
                let take = core::cmp::min(DATA_CHUNK_SIZE - pending.len(), bytes.len());
                pending.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if pending.len() == DATA_CHUNK_SIZE {
                    data.push(Arc::<[u8]>::from(core::mem::take(&mut pending)));
                }
            }
        }
        if !pending.is_empty() {
            data.push(Arc::<[u8]>::from(pending));
        }
        let generation = self.next_generation()?;
        match self.resolve(path, true) {
            Ok(id) => {
                self.charge(1)?;
                let inode = self
                    .working
                    .inodes
                    .get_mut(&id)
                    .ok_or(FileError::NotFound)?;
                if inode.file_type == FileType::Directory {
                    return Err(FileError::IsDirectory);
                }
                if inode.file_type != FileType::Regular {
                    return Err(FileError::InvalidType);
                }
                if append {
                    let Content::File(existing) = &mut inode.content else {
                        return Err(FileError::InvalidType);
                    };
                    if let Some(last) = existing
                        .last()
                        .filter(|chunk| chunk.len() < DATA_CHUNK_SIZE)
                    {
                        let mut tail = last.to_vec();
                        let mut merged = Vec::new();
                        for chunk in data {
                            let mut bytes = chunk.as_ref();
                            while !bytes.is_empty() {
                                let take =
                                    core::cmp::min(DATA_CHUNK_SIZE - tail.len(), bytes.len());
                                tail.extend_from_slice(&bytes[..take]);
                                bytes = &bytes[take..];
                                if tail.len() == DATA_CHUNK_SIZE {
                                    merged.push(Arc::<[u8]>::from(core::mem::take(&mut tail)));
                                }
                            }
                        }
                        if !tail.is_empty() {
                            merged.push(Arc::<[u8]>::from(tail));
                        }
                        existing.pop();
                        existing.extend(merged);
                    } else {
                        existing.extend(data);
                    }
                } else {
                    inode.content = Content::File(data);
                }
                inode.change_generation = generation;
            }
            Err(FileError::NotFound) => {
                let (parent, name) = self.parent(path)?;
                if self.working.dirents.contains_key(&(parent, name.clone())) {
                    return Err(FileError::Exists);
                }
                self.charge(2)?;
                let id = self.working.allocate(Inode {
                    file_type: FileType::Regular,
                    change_generation: generation,
                    content: Content::File(data),
                })?;
                self.working.dirents.insert((parent, name), id);
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    pub fn write_staged(
        &mut self,
        path: &RelPath,
        staged: StagedFileContent,
    ) -> Result<(), FileError> {
        let generation = self.next_generation()?;
        let content = match staged.source {
            StagedContentSource::Persistent(data) => Content::PersistentFile(data),
            StagedContentSource::Inline(bytes) => Content::File(
                bytes
                    .chunks(DATA_CHUNK_SIZE)
                    .map(Arc::<[u8]>::from)
                    .collect(),
            ),
        };
        match self.resolve(path, true) {
            Ok(id) => {
                self.charge(1)?;
                let inode = self
                    .working
                    .inodes
                    .get_mut(&id)
                    .ok_or(FileError::NotFound)?;
                if inode.file_type == FileType::Directory {
                    return Err(FileError::IsDirectory);
                }
                if inode.file_type != FileType::Regular {
                    return Err(FileError::InvalidType);
                }
                inode.content = content;
                inode.change_generation = generation;
            }
            Err(FileError::NotFound) => {
                let (parent, name) = self.parent(path)?;
                if self.working.dirents.contains_key(&(parent, name.clone())) {
                    return Err(FileError::Exists);
                }
                self.charge(2)?;
                let id = self.working.allocate(Inode {
                    file_type: FileType::Regular,
                    change_generation: generation,
                    content,
                })?;
                self.working.dirents.insert((parent, name), id);
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    pub fn symlink(&mut self, target: &str, link: &RelPath) -> Result<(), FileError> {
        let (link_parent, _) = link.parent_and_name()?;
        // Validate the stored relative target in the directory where the link
        // will live. It may be dangling, but it may never lexically escape the
        // capability root.
        RelPath::joined_from(link_parent.components(), target)?;
        let (parent, name) = self.parent(link)?;
        if self.working.dirents.contains_key(&(parent, name.clone())) {
            return Err(FileError::Exists);
        }
        self.charge(2)?;
        let id = self.working.allocate(Inode {
            file_type: FileType::Symlink,
            change_generation: self.next_generation()?,
            content: Content::Symlink(target.to_string()),
        })?;
        self.working.dirents.insert((parent, name), id);
        Ok(())
    }
    pub fn hard_link(
        &mut self,
        source: &RelPath,
        destination: &RelPath,
        follow: bool,
    ) -> Result<(), FileError> {
        let source_id = self.resolve(source, follow)?;
        if self
            .working
            .inodes
            .get(&source_id)
            .ok_or(FileError::NotFound)?
            .file_type
            == FileType::Directory
        {
            return Err(FileError::IsDirectory);
        }
        let (parent, name) = self.parent(destination)?;
        if self.working.dirents.contains_key(&(parent, name.clone())) {
            return Err(FileError::Exists);
        }
        self.charge(1)?;
        self.working.dirents.insert((parent, name), source_id);
        Ok(())
    }
    pub fn copy_from(
        &mut self,
        source: &FsSnapshotLease,
        source_path: &RelPath,
        destination: &RelPath,
        recursive: bool,
        follow_source_symlink: bool,
        follow_all_symlinks: bool,
    ) -> Result<(), FileError> {
        let source_id = source.resolve(source_path, follow_source_symlink)?;
        let (parent, name) = self.parent(destination)?;
        let generation = self.next_generation()?;
        let source_inode = source
            .state
            .inodes
            .get(&source_id)
            .ok_or(FileError::NotFound)?
            .clone();
        if source.state.namespace == self.working.namespace
            && source_inode.file_type == FileType::Directory
        {
            let mut cursor = parent;
            loop {
                if cursor == source_id {
                    return Err(FileError::EscapeRoot);
                }
                if cursor == ROOT_FILE_ID {
                    break;
                }
                cursor = self
                    .working
                    .dirents
                    .iter()
                    .find_map(|((candidate, _), child)| (*child == cursor).then_some(*candidate))
                    .ok_or(FileError::NotFound)?;
            }
        }
        if let Some(destination_id) = self.working.dirents.get(&(parent, name.clone())).copied() {
            if source_inode.file_type == FileType::Directory {
                return Err(FileError::Exists);
            }
            self.charge(1)?;
            let destination_inode = self
                .working
                .inodes
                .get_mut(&destination_id)
                .ok_or(FileError::NotFound)?;
            if destination_inode.file_type != FileType::Regular
                || source_inode.file_type != FileType::Regular
            {
                return Err(FileError::InvalidType);
            }
            destination_inode.content = source_inode.content;
            destination_inode.change_generation = generation;
            return Ok(());
        }
        fn clone_inode(
            tx: &mut FsTransaction,
            source: &NamespaceState,
            boundary: FileId,
            source_id: FileId,
            source_path: &RelPath,
            parent: FileId,
            name: String,
            recursive: bool,
            generation: u64,
            follow_all_symlinks: bool,
            active_directories: &mut BTreeSet<FileId>,
        ) -> Result<(), FileError> {
            let inode = source
                .inodes
                .get(&source_id)
                .ok_or(FileError::NotFound)?
                .clone();
            if inode.file_type == FileType::Directory && !recursive {
                return Err(FileError::IsDirectory);
            }
            tx.charge(2)?;
            let kind = inode.file_type;
            let new_id = tx.working.allocate(Inode {
                file_type: kind,
                change_generation: generation,
                content: inode.content,
            })?;
            tx.working.dirents.insert((parent, name), new_id);
            if kind == FileType::Directory {
                if !active_directories.insert(source_id) {
                    return Err(FileError::SymlinkLoop);
                }
                let children: Vec<(String, FileId)> = source
                    .dirents
                    .iter()
                    .filter_map(|((p, n), c)| (*p == source_id).then_some((n.clone(), *c)))
                    .collect();
                for (child_name, child_id) in children {
                    let child_path = source_path.joined_name(&child_name)?;
                    let child_id = if follow_all_symlinks {
                        source.resolve_canonical_from(boundary, &child_path, true)?.0
                    } else {
                        child_id
                    };
                    clone_inode(
                        tx,
                        source,
                        boundary,
                        child_id,
                        &child_path,
                        new_id,
                        child_name,
                        true,
                        generation,
                        follow_all_symlinks,
                        active_directories,
                    )?;
                }
                active_directories.remove(&source_id);
            }
            Ok(())
        }
        clone_inode(
            self,
            &source.state,
            source.boundary,
            source_id,
            source_path,
            parent,
            name,
            recursive,
            generation,
            follow_all_symlinks,
            &mut BTreeSet::new(),
        )
    }
    fn collect_subtree(
        &self,
        id: FileId,
        recursive: bool,
        out: &mut Vec<FileId>,
    ) -> Result<(), FileError> {
        let inode = self.working.inodes.get(&id).ok_or(FileError::NotFound)?;
        if inode.file_type == FileType::Directory {
            let children: Vec<FileId> = self
                .working
                .dirents
                .iter()
                .filter_map(|((p, _), c)| (*p == id).then_some(*c))
                .collect();
            if !children.is_empty() && !recursive {
                return Err(FileError::DirectoryNotEmpty);
            }
            for child in children {
                self.collect_subtree(child, recursive, out)?;
            }
        }
        out.push(id);
        Ok(())
    }
    pub fn remove(
        &mut self,
        path: &RelPath,
        recursive: bool,
        directory: bool,
    ) -> Result<(), FileError> {
        let (parent, name) = self.parent(path)?;
        let id = self.working.lookup_child(parent, &name)?;
        let kind = self
            .working
            .inodes
            .get(&id)
            .ok_or(FileError::NotFound)?
            .file_type;
        if kind == FileType::Directory && !recursive && !directory {
            return Err(FileError::IsDirectory);
        }
        let mut ids = Vec::new();
        self.collect_subtree(id, recursive, &mut ids)?;
        self.charge(ids.len().saturating_mul(2))?;
        let doomed: BTreeSet<FileId> = ids.iter().copied().collect();
        self.working
            .dirents
            .retain(|(p, n), _child| !doomed.contains(p) && !(*p == parent && *n == name));
        for inode_id in ids {
            let inode_type = self
                .working
                .inodes
                .get(&inode_id)
                .map(|inode| inode.file_type)
                .unwrap_or(FileType::Regular);
            if inode_type == FileType::Directory
                || self.working.link_count(inode_id, inode_type) == 0
            {
                self.working.inodes.remove(&inode_id);
            }
        }
        Ok(())
    }
    pub fn rename(
        &mut self,
        source: &RelPath,
        destination: &RelPath,
        no_clobber: bool,
    ) -> Result<(), FileError> {
        let (sp, sn) = self.parent(source)?;
        let source_id = self.working.lookup_child(sp, &sn)?;
        let (dp, dn) = self.parent(destination)?;
        if sp == dp && sn == dn {
            return Ok(());
        }
        if self.working.dirents.contains_key(&(dp, dn.clone())) {
            if no_clobber {
                return Ok(());
            }
            let source_kind = self
                .working
                .inodes
                .get(&source_id)
                .ok_or(FileError::NotFound)?
                .file_type;
            let destination_id = self.working.lookup_child(dp, &dn)?;
            let destination_kind = self
                .working
                .inodes
                .get(&destination_id)
                .ok_or(FileError::NotFound)?
                .file_type;
            if (source_kind == FileType::Directory) != (destination_kind == FileType::Directory) {
                return Err(FileError::InvalidType);
            }
            let destination_path = destination.clone();
            self.remove(&destination_path, false, true)?;
        }
        if self
            .working
            .inodes
            .get(&source_id)
            .is_some_and(|i| i.file_type == FileType::Directory)
        {
            let mut cursor = dp;
            while cursor != self.boundary {
                if cursor == source_id {
                    return Err(FileError::EscapeRoot);
                }
                cursor = self
                    .working
                    .dirents
                    .iter()
                    .find_map(|((p, _), c)| (*c == cursor).then_some(*p))
                    .ok_or(FileError::NotFound)?;
            }
        }
        self.charge(2)?;
        self.working.dirents.remove(&(sp, sn));
        self.working.dirents.insert((dp, dn), source_id);
        Ok(())
    }
    pub fn commit(mut self) -> Result<u64, FileError> {
        self.check_publication()?;
        let generation = self.next_generation()?;
        self.working.generation = generation;
        let mut published = self.root.state.lock();
        if published.generation != self.base_generation {
            return Err(FileError::Conflict);
        }
        *published = Arc::new(self.working.clone());
        *self.root.persistent_root.lock() = None;
        self.committed = true;
        assert!(self.root.release_writer_claim(self.claim));
        Ok(generation)
    }
}

impl Drop for FsTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.root.release_writer_claim(self.claim);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_byte_offsets_preserve_variable_chunk_boundaries() {
        let reader = FsFileReader { source: FsFileReaderSource::Volatile(alloc::vec![
            Arc::from(&b"abc"[..]), Arc::from(&b""[..]), Arc::from(&b"defgh"[..]),
        ]) };
        assert_eq!(ready(reader.read_at(0, 2)).unwrap(), b"ab");
        assert_eq!(ready(reader.read_at(2, 4)).unwrap(), b"c");
        assert_eq!(ready(reader.read_at(3, 99)).unwrap(), b"defgh");
        assert_eq!(ready(reader.read_at(6, 2)).unwrap(), b"gh");
        assert!(ready(reader.read_at(8, 1)).unwrap().is_empty());
        assert!(ready(reader.read_at(u64::MAX, 1)).unwrap().is_empty());
        assert!(ready(reader.read_at(0, 0)).unwrap().is_empty());
    }

    #[test]
    fn completed_generation_rejects_pending_publication() {
        let root = FileTreeRoot::new_empty(901).unwrap();
        let initial = root.completed_generation().unwrap();
        let transaction = root.begin().unwrap();
        assert_eq!(root.completed_generation(), Err(FileError::Busy));
        drop(transaction);
        assert_eq!(root.completed_generation(), Ok(initial));
        let mut transaction = root.begin().unwrap();
        transaction.write_chunks(&RelPath::parse("synced").unwrap(), [b"ok".as_slice()], false).unwrap();
        assert_eq!(root.completed_generation(), Err(FileError::Busy));
        let committed = transaction.commit().unwrap();
        assert!(committed > initial);
        assert_eq!(root.completed_generation(), Ok(committed));
        assert_eq!(root.snapshot().generation(), committed);
    }

    fn path(value: &str) -> RelPath {
        RelPath::parse(value).unwrap()
    }

    fn ready<T>(future: impl core::future::Future<Output = T>) -> T {
        let mut future = core::pin::pin!(future);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        match future.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(value) => value,
            core::task::Poll::Pending => panic!("volatile test unexpectedly suspended"),
        }
    }

    #[test]
    fn live_directory_view_shares_commits_without_exposing_siblings() {
        let root = FileTreeRoot::new_empty(915).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("project"), false).unwrap();
        tx.write_chunks(&path("secret"), [b"outside"], false).unwrap();
        tx.write_chunks(&path("project/value"), [b"initial"], false).unwrap();
        tx.symlink("../secret", &path("project/escape")).unwrap();
        tx.commit().unwrap();
        let outside = root.snapshot().stat(&path("secret"), true).unwrap().file_id;
        let view = root.directory(&path("project")).unwrap();
        assert!(matches!(view.reader(&path("escape")), Err(FileError::EscapeRoot)));
        assert!(matches!(view.regular_reader_by_id(outside), Err(FileError::EscapeRoot)));
        let mut tx = view.begin().unwrap();
        // An independently granted source snapshot may be an ancestor of this
        // view; preserve the copy-into-descendant rejection across boundaries.
        assert_eq!(tx.copy_from(&root.snapshot(), &RelPath::root(), &path("recursive"), true, true, true),
                   Err(FileError::EscapeRoot));
        tx.write_chunks(&path("value"), [b"changed"], false).unwrap();
        tx.mkdir(&path("nested"), false).unwrap();
        assert_eq!(ready(tx.truncate_file(outside, 0)), Err(FileError::EscapeRoot));
        tx.commit().unwrap();
        assert_eq!(root.snapshot().read_chunks(&path("project/value")).unwrap().flatten().copied().collect::<Vec<_>>(), b"changed");
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("project/value"), [b"parent-change"], false).unwrap();
        tx.commit().unwrap();
        assert_eq!(view.resolved_regular_reader(&path("value")).unwrap().0.size, 13);
        let mut tx = root.begin().unwrap();
        tx.remove(&path("project"), true, false).unwrap();
        tx.mkdir(&path("project"), false).unwrap();
        tx.commit().unwrap();
        assert!(matches!(view.begin(), Err(FileError::NotFound)));
        assert!(matches!(view.begin_content_stager(&path("new"), false), Err(FileError::NotFound)));
        assert_eq!(view.snapshot().stat(&RelPath::root(), true), Err(FileError::NotFound));
        assert_eq!(root.snapshot().read_chunks(&path("secret")).unwrap().flatten().copied().collect::<Vec<_>>(), b"outside");
    }

    #[test]
    fn directory_transaction_confines_mutations_and_inode_access() {
        let root = FileTreeRoot::new_empty(913).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("project"), false).unwrap();
        tx.mkdir(&path("outside"), false).unwrap();
        tx.write_chunks(&path("outside/value"), [b"protected"], false).unwrap();
        tx.write_chunks(&path("project/value"), [b"inside"], false).unwrap();
        tx.symlink("../outside", &path("project/escape")).unwrap();
        tx.symlink("value", &path("project/local")).unwrap();
        tx.commit().unwrap();
        let outside = root.snapshot().stat(&path("outside/value"), true).unwrap().file_id;
        let mut tx = root.begin().unwrap().into_directory(&path("project")).unwrap();
        assert_eq!(tx.write_chunks(&path("escape/value"), [b"bad"], false), Err(FileError::EscapeRoot));
        assert_eq!(tx.mkdir(&path("escape/new"), false), Err(FileError::EscapeRoot));
        assert_eq!(tx.rename(&path("value"), &path("escape/moved"), false), Err(FileError::EscapeRoot));
        assert_eq!(tx.hard_link(&path("escape/value"), &path("alias"), true), Err(FileError::EscapeRoot));
        assert_eq!(ready(tx.write_file_range(outside, 0, b"bad")), Err(FileError::EscapeRoot));
        assert_eq!(ready(tx.truncate_file(outside, 0)), Err(FileError::EscapeRoot));
        assert_eq!(tx.remove(&RelPath::root(), true, false), Err(FileError::RootProtected));
        tx.mkdir(&path("sub/deep"), true).unwrap();
        tx.write_chunks(&path("local"), [b"updated"], false).unwrap();
        let inside = tx.regular_file_id(&path("value")).unwrap();
        tx.rename(&path("value"), &path("sub/value"), false).unwrap();
        ready(tx.write_file_range(inside, 0, b"OK")).unwrap();
        ready(tx.truncate_file(inside, 2)).unwrap();
        tx.remove(&path("escape"), false, false).unwrap();
        tx.commit().unwrap();
        let snapshot = root.snapshot();
        assert_eq!(snapshot.read_chunks(&path("outside/value")).unwrap().flatten().copied().collect::<Vec<_>>(), b"protected");
        assert_eq!(snapshot.read_chunks(&path("project/sub/value")).unwrap().flatten().copied().collect::<Vec<_>>(), b"OK");
        assert_eq!(snapshot.stat(&path("sub"), true), Err(FileError::NotFound));
        assert_eq!(snapshot.stat(&path("project/escape"), false), Err(FileError::NotFound));
    }

    #[test]
    fn narrowing_transaction_rejects_prior_edits_and_cannot_widen() {
        let root = FileTreeRoot::new_empty(914).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("project/sub"), true).unwrap();
        tx.write_chunks(&path("project/value"), [b"keep"], false).unwrap();
        tx.commit().unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("outside"), [b"discard"], false).unwrap();
        assert!(matches!(tx.into_directory(&path("project")), Err(FileError::Conflict)));
        assert_eq!(root.snapshot().stat(&path("outside"), true), Err(FileError::NotFound));
        let parent_id = root.snapshot().stat(&path("project/value"), true).unwrap().file_id;
        let mut tx = root.begin().unwrap().into_directory(&path("project")).unwrap()
            .into_directory(&path("sub")).unwrap().into_directory(&RelPath::root()).unwrap();
        assert_eq!(ready(tx.truncate_file(parent_id, 0)), Err(FileError::EscapeRoot));
        tx.write_chunks(&path("new"), [b"nested"], false).unwrap();
        tx.commit().unwrap();
        assert_eq!(root.snapshot().read_chunks(&path("project/sub/new")).unwrap().flatten().copied().collect::<Vec<_>>(), b"nested");
        assert_eq!(root.snapshot().read_chunks(&path("project/value")).unwrap().flatten().copied().collect::<Vec<_>>(), b"keep");
    }

    #[test]
    fn directory_snapshot_confines_links_and_hides_parent_names() {
        let root = FileTreeRoot::new_empty(910).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("project/sub"), true).unwrap();
        tx.write_chunks(&path("secret"), [b"outside"], false).unwrap();
        tx.write_chunks(&path("project/value"), [b"inside"], false).unwrap();
        tx.symlink("../value", &path("project/sub/local")).unwrap();
        tx.symlink("../secret", &path("project/escape")).unwrap();
        assert_eq!(tx.symlink("/secret", &path("project/absolute")), Err(FileError::EscapeRoot));
        tx.symlink("../../secret", &path("project/sub/escape")).unwrap();
        tx.symlink("escape", &path("project/chain")).unwrap();
        tx.commit().unwrap();
        let full = root.snapshot();
        let scoped = full.directory(&path("project")).unwrap();
        assert_eq!(scoped.stat(&RelPath::root(), true).unwrap().file_id,
                   full.stat(&path("project"), true).unwrap().file_id);
        assert_eq!(scoped.canonical_path(&path("sub/local")).unwrap(), "value");
        assert_eq!(scoped.read_chunks(&path("sub/local")).unwrap().flatten().copied().collect::<Vec<_>>(), b"inside");
        assert_eq!(scoped.stat(&path("secret"), true), Err(FileError::NotFound));
        for selector in ["escape", "sub/escape", "chain", "escape/child"] {
            assert_eq!(scoped.stat(&path(selector), true), Err(FileError::EscapeRoot));
            assert_eq!(scoped.canonical_path(&path(selector)), Err(FileError::EscapeRoot));
            assert!(scoped.read_chunks(&path(selector)).is_err());
        }
        assert_eq!(scoped.readlink(&path("escape")).unwrap(), "../secret");
        assert_eq!(scoped.stat(&path("escape"), false).unwrap().file_type, FileType::Symlink);
        assert!(!scoped.list(&RelPath::root(), true).unwrap().iter().any(|(name, _)| name == "secret"));
        let nested = scoped.directory(&path("sub")).unwrap();
        assert_eq!(nested.stat(&path("local"), true), Err(FileError::EscapeRoot));
        assert!(matches!(scoped.directory(&path("value")), Err(FileError::NotDirectory)));
        // Pinning does not accidentally switch to a replacement directory.
        let mut tx = root.begin().unwrap();
        tx.rename(&path("project"), &path("moved"), false).unwrap();
        tx.mkdir(&path("project"), false).unwrap();
        tx.write_chunks(&path("project/value"), [b"replacement"], false).unwrap();
        tx.commit().unwrap();
        assert_eq!(scoped.read_chunks(&path("value")).unwrap().flatten().copied().collect::<Vec<_>>(), b"inside");
    }

    #[test]
    fn recursive_copy_preserves_source_snapshot_boundary() {
        let source = FileTreeRoot::new_empty(911).unwrap();
        let destination = FileTreeRoot::new_empty(912).unwrap();
        let mut tx = source.begin().unwrap();
        tx.mkdir(&path("project/sub"), true).unwrap();
        tx.write_chunks(&path("secret"), [b"outside"], false).unwrap();
        tx.write_chunks(&path("project/value"), [b"inside"], false).unwrap();
        tx.symlink("../value", &path("project/sub/local")).unwrap();
        tx.symlink("../../secret", &path("project/sub/escape")).unwrap();
        tx.commit().unwrap();
        let scoped = source.snapshot().directory(&path("project")).unwrap();
        let mut tx = destination.begin().unwrap();
        assert_eq!(tx.copy_from(&scoped, &path("sub"), &path("copy"), true, true, true),
                   Err(FileError::EscapeRoot));
        drop(tx);
        assert_eq!(destination.snapshot().stat(&path("copy"), true), Err(FileError::NotFound));
        let mut tx = destination.begin().unwrap();
        tx.copy_from(&scoped, &path("sub/local"), &path("safe"), false, true, true).unwrap();
        tx.commit().unwrap();
        assert_eq!(destination.snapshot().read_chunks(&path("safe")).unwrap().flatten().copied().collect::<Vec<_>>(), b"inside");
    }

    #[test]
    fn range_write_preserves_identity_across_rename_and_hardlinks() {
        let root = FileTreeRoot::new_empty(901).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("old"), [b"abcdef"], false).unwrap();
        tx.hard_link(&path("old"), &path("alias"), true).unwrap();
        tx.commit().unwrap();
        let pinned = root.snapshot();
        let id = pinned.stat(&path("old"), true).unwrap().file_id;
        let mut tx = root.begin().unwrap();
        tx.rename(&path("old"), &path("new"), false).unwrap();
        tx.write_chunks(&path("old"), [b"unrelated"], false).unwrap();
        ready(tx.write_file_range(id, 2, b"XY")).unwrap();
        tx.commit().unwrap();
        let snapshot = root.snapshot();
        for name in ["new", "alias"] {
            assert_eq!(snapshot.read_chunks(&path(name)).unwrap().flatten().copied().collect::<Vec<_>>(), b"abXYef");
            assert_eq!(snapshot.stat(&path(name), true).unwrap().file_id, id);
        }
        assert_eq!(snapshot.read_chunks(&path("old")).unwrap().flatten().copied().collect::<Vec<_>>(), b"unrelated");
        assert_eq!(pinned.read_chunks(&path("old")).unwrap().flatten().copied().collect::<Vec<_>>(), b"abcdef");
        let mut tx = root.begin().unwrap();
        ready(tx.truncate_file(id, 1)).unwrap();
        drop(tx);
        assert_eq!(root.snapshot().stat(&path("new"), true).unwrap().size, 6);
    }

    #[test]
    fn range_write_zero_fills_and_truncates_across_chunks() {
        let root = FileTreeRoot::new_empty(902).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("file"), [b"abc"], false).unwrap();
        tx.commit().unwrap();
        let id = root.snapshot().stat(&path("file"), true).unwrap().file_id;
        let mut tx = root.begin().unwrap();
        ready(tx.write_file_range(id, 4095, b"XYZ")).unwrap();
        ready(tx.write_file_range(id, u64::MAX, b"overflow")).unwrap_err();
        tx.commit().unwrap();
        let bytes = root.snapshot().read_chunks(&path("file")).unwrap().flatten().copied().collect::<Vec<_>>();
        assert_eq!(&bytes[..3], b"abc");
        assert!(bytes[3..4095].iter().all(|b| *b == 0));
        assert_eq!(&bytes[4095..], b"XYZ");
        let mut tx = root.begin().unwrap();
        ready(tx.truncate_file(id, 2)).unwrap();
        ready(tx.truncate_file(id, 5)).unwrap();
        ready(tx.write_file_range(id, 100, b"")).unwrap();
        assert_eq!(ready(tx.write_file_range(ROOT_FILE_ID, 0, b"x")), Err(FileError::IsDirectory));
        assert_eq!(ready(tx.truncate_file(u64::MAX, 0)), Err(FileError::NotFound));
        tx.commit().unwrap();
        assert_eq!(root.snapshot().read_chunks(&path("file")).unwrap().flatten().copied().collect::<Vec<_>>(), b"ab\0\0\0");
    }

    #[test]
    fn transaction_is_atomic_and_snapshot_is_pinned() {
        let root = FileTreeRoot::new_empty(7).unwrap();
        let old = root.snapshot();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("etc"), false).unwrap();
        tx.write_chunks(&path("etc/config"), [b"hello"], false)
            .unwrap();
        assert_eq!(old.stat(&path("etc"), true), Err(FileError::NotFound));
        assert_eq!(tx.commit().unwrap(), 1);
        assert_eq!(
            root.snapshot()
                .read_chunks(&path("etc/config"))
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"hello"
        );
        assert_eq!(old.stat(&path("etc"), true), Err(FileError::NotFound));
    }

    #[test]
    fn cancelled_publication_preserves_generation_and_releases_writer() {
        let root = FileTreeRoot::new_empty(321).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&RelPath::parse("cancelled").unwrap(), false)
            .unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        tx.cancel_on(cancel.clone());
        cancel.store(true, Ordering::Release);
        assert_eq!(tx.commit(), Err(FileError::Conflict));
        assert_eq!(root.snapshot().generation(), 0);
        assert!(root.begin().is_ok());
    }

    #[test]
    fn abort_keeps_generation_and_file_ids_unpublished() {
        let root = FileTreeRoot::new_empty(9).unwrap();
        {
            let mut tx = root.begin().unwrap();
            tx.mkdir(&path("discarded"), false).unwrap();
        }
        assert_eq!(root.snapshot().generation(), 0);
        assert_eq!(
            root.snapshot().stat(&path("discarded"), true),
            Err(FileError::NotFound)
        );
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("kept"), false).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            root.snapshot().stat(&path("kept"), true).unwrap().file_id,
            2
        );
    }

    #[test]
    fn hard_link_overwrite_is_inode_wide() {
        let root = FileTreeRoot::new_empty(11).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("a"), [b"old"], false).unwrap();
        tx.hard_link(&path("a"), &path("b"), false).unwrap();
        tx.commit().unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("b"), [b"new"], false).unwrap();
        tx.commit().unwrap();
        let snap = root.snapshot();
        assert_eq!(snap.stat(&path("a"), false).unwrap().link_count, 2);
        assert_eq!(
            snap.read_chunks(&path("a"))
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"new"
        );
    }

    #[test]
    fn symlink_is_relative_and_cannot_escape() {
        let root = FileTreeRoot::new_empty(12).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("d"), false).unwrap();
        tx.write_chunks(&path("target"), [b"ok"], false).unwrap();
        tx.symlink("../target", &path("d/link")).unwrap();
        assert_eq!(
            tx.symlink("../../bad", &path("d/bad")),
            Err(FileError::EscapeRoot)
        );
        tx.commit().unwrap();
        assert_eq!(
            root.snapshot()
                .read_chunks(&path("d/link"))
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"ok"
        );
    }

    #[test]
    fn resolved_reader_pins_metadata_and_bytes_across_replacement() {
        let root = FileTreeRoot::new_empty(42).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("target"), [b"old"], false).unwrap();
        tx.symlink("target", &path("alias")).unwrap();
        tx.symlink("loop", &path("loop")).unwrap();
        tx.commit().unwrap();
        assert!(root.regular_reader(&path("alias")).is_err());
        let (metadata, reader) = root.resolved_regular_reader(&path("alias")).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("target"), [b"longer new value"], false).unwrap();
        tx.commit().unwrap();
        assert_eq!(metadata.size, 3);
        let mut read = core::pin::pin!(reader.read_chunk(0));
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        assert_eq!(read.as_mut().poll(&mut cx), core::task::Poll::Ready(Ok(Some(b"old".to_vec()))));
        assert_eq!(root.resolved_regular_reader(&path("alias")).unwrap().0.size, 16);
        assert!(matches!(root.resolved_regular_reader(&path("loop")), Err(FileError::SymlinkLoop)));
        assert!(matches!(root.resolved_regular_reader(&RelPath::root()), Err(FileError::IsDirectory)));
    }

    #[test]
    fn recursive_remove_never_follows_symlink() {
        let root = FileTreeRoot::new_empty(13).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("tree"), false).unwrap();
        tx.write_chunks(&path("outside"), [b"safe"], false).unwrap();
        tx.symlink("../outside", &path("tree/link")).unwrap();
        tx.remove(&path("tree"), true, false).unwrap();
        tx.commit().unwrap();
        assert!(root.snapshot().stat(&path("outside"), true).is_ok());
        assert_eq!(root.snapshot().state.inodes.len(), 2);
    }

    #[test]
    fn writes_and_appends_keep_canonical_stream_chunks() {
        let root = FileTreeRoot::new_empty(14).unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("stream"), [&[1; 3][..], &[2; 4096][..]], false)
            .unwrap();
        tx.commit().unwrap();
        let mut tx = root.begin().unwrap();
        tx.write_chunks(&path("stream"), [&[3; 4094][..]], true)
            .unwrap();
        tx.commit().unwrap();
        let chunks = root.snapshot().read_owned_chunks(&path("stream")).unwrap();
        assert_eq!(
            chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
            [4096, 4096, 1]
        );
    }

    #[test]
    fn exact_fault_cleanup_cannot_clear_a_different_writer_claim() {
        let root = FileTreeRoot::new_empty(15).unwrap();
        let transaction = root.begin_with_claim(7, 11).unwrap();
        assert!(!root.recover_writer_claim(7, 12));
        assert!(matches!(root.begin_with_claim(8, 13), Err(FileError::Busy)));
        assert!(root.recover_writer_claim(7, 11));
        core::mem::forget(transaction);
        assert!(root.begin_with_claim(8, 13).is_ok());
    }

    #[test]
    fn append_creates_and_rename_rejects_directory_type_mismatch() {
        let root = FileTreeRoot::new_empty(16).unwrap();
        let mut transaction = root.begin().unwrap();
        transaction
            .write_chunks(&path("created"), [b"append"], true)
            .unwrap();
        transaction.mkdir(&path("directory"), false).unwrap();
        assert_eq!(
            transaction.rename(&path("created"), &path("directory"), false),
            Err(FileError::InvalidType)
        );
        transaction.commit().unwrap();
        assert_eq!(
            root.snapshot()
                .read_chunks(&path("created"))
                .unwrap()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
            b"append"
        );
    }
}
