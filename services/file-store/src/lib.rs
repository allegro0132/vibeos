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
use core::sync::atomic::{AtomicU64, Ordering};
use vibeos_core::cap::Resource;
use vibeos_core::sync::SpinLock;

pub type FileId = u64;
pub const ROOT_FILE_ID: FileId = 1;
pub const MAX_TRANSACTION_EDITS: usize = 4096;
pub const DATA_CHUNK_SIZE: usize = 4096;

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
        let mut pending = path.components().to_vec();
        let mut resolved_names: Vec<String> = Vec::new();
        let mut current = ROOT_FILE_ID;
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
                current = ROOT_FILE_ID;
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
}

impl FsSnapshotLease {
    pub fn namespace(&self) -> u128 {
        self.state.namespace
    }
    pub fn generation(&self) -> u64 {
        self.state.generation
    }
    pub fn stat(&self, path: &RelPath, follow_final: bool) -> Result<Metadata, FileError> {
        self.state.metadata(self.state.resolve(path, follow_final)?)
    }
    pub fn readlink(&self, path: &RelPath) -> Result<&str, FileError> {
        let id = self.state.resolve(path, false)?;
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
        let id = self.state.resolve(path, true)?;
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
        let id = self.state.resolve(path, true)?;
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
        let id = self.state.resolve(path, true)?;
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
        let (_, components) = self.state.resolve_canonical(path, true)?;
        Ok(components.join("/"))
    }
    pub fn list(
        &self,
        path: &RelPath,
        follow_final: bool,
    ) -> Result<Vec<(String, Metadata)>, FileError> {
        let id = self.state.resolve(path, follow_final)?;
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

pub struct FsContentStager {
    backend: Arc<dyn FileTreeBackend>,
    tail: Option<vibeos_segment_store::FsPersistentData>,
    pending: Vec<u8>,
}

pub struct StagedFileContent {
    data: vibeos_segment_store::FsPersistentData,
}

impl FsContentStager {
    pub async fn push(&mut self, mut bytes: &[u8]) -> Result<(), FileError> {
        while !bytes.is_empty() {
            let take = core::cmp::min(DATA_CHUNK_SIZE - self.pending.len(), bytes.len());
            self.pending.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.pending.len() == DATA_CHUNK_SIZE {
                let chunk = core::mem::take(&mut self.pending);
                self.tail = Some(self.backend.stage_chunk(self.tail.clone(), chunk).await?);
            }
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<StagedFileContent, FileError> {
        if !self.pending.is_empty() || self.tail.is_none() {
            self.tail = Some(
                self.backend
                    .stage_chunk(self.tail.clone(), core::mem::take(&mut self.pending))
                    .await?,
            );
        }
        Ok(StagedFileContent {
            data: self.tail.ok_or(FileError::InvalidType)?,
        })
    }
}

/// The capability resource. Holding an authorized capability to this value is
/// the only way a task can obtain a snapshot or start a writer.
pub struct FileTreeRoot {
    inner: Arc<FileTreeInner>,
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
            inner: Arc::new(FileTreeInner {
                state: SpinLock::new(Arc::new(NamespaceState::empty(namespace))),
                persistent_root: SpinLock::new(None),
                writer_claim: SpinLock::new(None),
                next_writer_token: AtomicU64::new(1),
                backend: None,
            }),
        })
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
            state: self.inner.state.lock().clone(),
        }
    }
    pub fn is_persistent(&self) -> bool {
        self.inner.backend.is_some()
    }
    pub fn reader(&self, path: &RelPath) -> Result<FsFileReader, FileError> {
        let snapshot = self.inner.state.lock().clone();
        let id = snapshot.resolve(path, true)?;
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
        let backend = self
            .inner
            .backend
            .clone()
            .ok_or(FileError::ServiceUnavailable)?;
        let snapshot = self.inner.state.lock().clone();
        let tail = match snapshot.resolve(path, true) {
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
                if snapshot.resolve(path, false).is_ok() {
                    return Err(FileError::NotFound);
                }
                None
            }
            Err(error) => return Err(error),
        };
        Ok(FsContentStager {
            backend,
            tail,
            pending: Vec::with_capacity(DATA_CHUNK_SIZE),
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
    pub fn begin_with_claim(&self, owner: u64, token: u64) -> Result<FsTransaction, FileError> {
        if token == 0 {
            return Err(FileError::InvalidPath);
        }
        let snapshot = self.inner.state.lock().clone();
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
            edits: 0,
            committed: false,
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
    edits: usize,
    committed: bool,
}

impl FsTransaction {
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
        let id = self.working.resolve(&parent, true)?;
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
        let mut current = ROOT_FILE_ID;
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
        match self.working.resolve(path, true) {
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
        match self.working.resolve(path, true) {
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
                inode.content = Content::PersistentFile(staged.data);
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
                    content: Content::PersistentFile(staged.data),
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
        let source_id = self.working.resolve(source, follow)?;
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
        let source_id = source.state.resolve(source_path, follow_source_symlink)?;
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
                        source.resolve(&child_path, true)?
                    } else {
                        child_id
                    };
                    clone_inode(
                        tx,
                        source,
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
            if self.working.link_count(
                inode_id,
                self.working
                    .inodes
                    .get(&inode_id)
                    .map(|i| i.file_type)
                    .unwrap_or(FileType::Regular),
            ) == 0
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
            while cursor != ROOT_FILE_ID {
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

    fn path(value: &str) -> RelPath {
        RelPath::parse(value).unwrap()
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
    fn recursive_remove_never_follows_symlink() {
        let root = FileTreeRoot::new_empty(13).unwrap();
        let mut tx = root.begin().unwrap();
        tx.mkdir(&path("tree"), false).unwrap();
        tx.write_chunks(&path("outside"), [b"safe"], false).unwrap();
        tx.symlink("../outside", &path("tree/link")).unwrap();
        tx.remove(&path("tree"), true, false).unwrap();
        tx.commit().unwrap();
        assert!(root.snapshot().stat(&path("outside"), true).is_ok());
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
