//! Canonical Merkle-verified immutable blob format.
//!
//! This crate owns only bytes and hashes. It has no block-device, namespace,
//! capability, or publication API, so the durable store can audit those
//! authority boundaries separately.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub type Hash = [u8; HASH_SIZE];

pub const HASH_SIZE: usize = 32;
pub const HEADER_SIZE: usize = 128;
pub const LEAF_SIZE: usize = 4096;
pub const FORMAT_VERSION: u16 = 1;
pub const HASH_ALGORITHM_SHA256: u16 = 1;
pub const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024;
/// Maximum number of content leaves in a canonical blob.
pub const MAX_LEAF_COUNT: usize = MAX_BLOB_SIZE / LEAF_SIZE;
/// Maximum distance from a leaf to the root at the format size limit.
pub const MAX_MERKLE_HEIGHT: usize = 14;
/// Hash slots retained by [`StreamingMerkle`], independent of object length.
pub const STREAMING_FRONTIER_SLOTS: usize = MAX_MERKLE_HEIGHT + 1;
/// Maximum tree-node writes caused by one content or padding leaf.
pub const MAX_STREAMING_EMISSIONS_PER_STEP: usize = MAX_MERKLE_HEIGHT + 1;
/// Exact byte size of the builder's hash frontier (the caller-owned sink is excluded).
pub const STREAMING_FRONTIER_BYTES: usize =
    core::mem::size_of::<[Option<Hash>; STREAMING_FRONTIER_SLOTS]>();

const MAGIC: [u8; 8] = *b"VIBEBLB\0";
const LEAF_LOG2: u8 = 12;
const LEAF_DOMAIN: &[u8] = b"VIBEBLOB-LEAF-v1\0";
const EMPTY_DOMAIN: &[u8] = b"VIBEBLOB-EMPTY-v1\0";
const NODE_DOMAIN: &[u8] = b"VIBEBLOB-NODE-v1\0";
const ROOT_DOMAIN: &[u8] = b"VIBEBLOB-ROOT-v1\0";

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 8;
const HEADER_LEN_OFFSET: usize = 10;
const HASH_ALGORITHM_OFFSET: usize = 12;
const LEAF_LOG2_OFFSET: usize = 14;
const FLAGS_OFFSET: usize = 15;
const OBJECT_KIND_OFFSET: usize = 16;
const RESERVED0_OFFSET: usize = 20;
const BYTE_LEN_OFFSET: usize = 24;
const LEAF_COUNT_OFFSET: usize = 32;
const TREE_NODE_COUNT_OFFSET: usize = 36;
const ROOT_OFFSET: usize = 40;
const DATA_OFFSET_OFFSET: usize = 72;
const TREE_OFFSET_OFFSET: usize = 80;
const ENCODED_LEN_OFFSET: usize = 88;
const RESERVED1_OFFSET: usize = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobError {
    EmptyObjectKind,
    TooLarge,
    LengthOverflow,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnsupportedHash,
    NonCanonical,
    RootMismatch,
    TreeMismatch,
    ChunkOutOfRange,
    WrongChunkLength,
    InvalidProof,
}

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::EmptyObjectKind => "blob object kind must be non-zero",
            Self::TooLarge => "blob exceeds the format size limit",
            Self::LengthOverflow => "blob length arithmetic overflowed",
            Self::Truncated => "blob is truncated",
            Self::BadMagic => "blob magic is invalid",
            Self::UnsupportedVersion => "blob format version is unsupported",
            Self::UnsupportedHash => "blob hash algorithm is unsupported",
            Self::NonCanonical => "blob encoding is not canonical",
            Self::RootMismatch => "blob descriptor root does not match its tree",
            Self::TreeMismatch => "blob data does not match its Merkle tree",
            Self::ChunkOutOfRange => "blob chunk is out of range",
            Self::WrongChunkLength => "blob chunk has the wrong length",
            Self::InvalidProof => "blob Merkle proof is invalid",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobDescriptor {
    pub object_kind: u32,
    pub byte_len: u64,
    pub leaf_count: u32,
    pub tree_node_count: u32,
    pub root: Hash,
}

/// Validated canonical layout geometry for a blob of an exact content length.
///
/// Constructing this value applies the same size and overflow rules as encoding
/// and streaming. Callers can therefore reserve separate header, content, and
/// indexed-tree extents without duplicating format arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobGeometry {
    exact_len: u64,
    geometry: Geometry,
    tree_len: usize,
    tree_offset: usize,
    encoded_len: usize,
}

impl BlobGeometry {
    pub fn for_len(exact_len: u64) -> Result<Self, BlobError> {
        if exact_len > MAX_BLOB_SIZE as u64 {
            return Err(BlobError::TooLarge);
        }
        let byte_len = usize::try_from(exact_len).map_err(|_| BlobError::TooLarge)?;
        let geometry = Geometry::for_len(byte_len)?;
        let tree_len = geometry
            .node_count
            .checked_mul(HASH_SIZE)
            .ok_or(BlobError::LengthOverflow)?;
        let tree_offset = HEADER_SIZE
            .checked_add(byte_len)
            .ok_or(BlobError::LengthOverflow)?;
        let encoded_len = tree_offset
            .checked_add(tree_len)
            .ok_or(BlobError::LengthOverflow)?;
        Ok(Self {
            exact_len,
            geometry,
            tree_len,
            tree_offset,
            encoded_len,
        })
    }

    pub const fn exact_len(self) -> u64 {
        self.exact_len
    }

    pub const fn leaf_count(self) -> u32 {
        self.geometry.leaf_count as u32
    }

    pub const fn padded_leaf_count(self) -> u32 {
        self.geometry.padded_leaves as u32
    }

    pub const fn tree_node_count(self) -> u32 {
        self.geometry.node_count as u32
    }

    pub const fn tree_len(self) -> usize {
        self.tree_len
    }

    pub const fn tree_offset(self) -> usize {
        self.tree_offset
    }

    pub const fn encoded_len(self) -> usize {
        self.encoded_len
    }

    pub const fn height(self) -> u8 {
        self.geometry.height as u8
    }
}

impl BlobDescriptor {
    pub fn from_content(object_kind: u32, bytes: &[u8]) -> Result<Self, BlobError> {
        if object_kind == 0 {
            return Err(BlobError::EmptyObjectKind);
        }
        let layout = BlobGeometry::for_len(bytes.len() as u64)?;
        let geometry = layout.geometry;
        let tree = build_tree(object_kind, bytes, geometry)?;
        let tree_root = *tree.last().ok_or(BlobError::TreeMismatch)?;
        Ok(Self {
            object_kind,
            byte_len: bytes.len() as u64,
            leaf_count: geometry.leaf_count as u32,
            tree_node_count: geometry.node_count as u32,
            root: blob_root(
                object_kind,
                bytes.len() as u64,
                geometry.leaf_count as u32,
                &tree_root,
            ),
        })
    }

    pub fn encode(self) -> Result<[u8; HEADER_SIZE], BlobError> {
        let layout = BlobGeometry::for_len(self.byte_len)?;
        let geometry = layout.geometry;
        if self.object_kind == 0
            || self.leaf_count != geometry.leaf_count as u32
            || self.tree_node_count != geometry.node_count as u32
        {
            return Err(BlobError::NonCanonical);
        }
        let mut header = [0u8; HEADER_SIZE];
        header[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()].copy_from_slice(&MAGIC);
        put_u16(&mut header, VERSION_OFFSET, FORMAT_VERSION);
        put_u16(&mut header, HEADER_LEN_OFFSET, HEADER_SIZE as u16);
        put_u16(&mut header, HASH_ALGORITHM_OFFSET, HASH_ALGORITHM_SHA256);
        header[LEAF_LOG2_OFFSET] = LEAF_LOG2;
        header[FLAGS_OFFSET] = 0;
        put_u32(&mut header, OBJECT_KIND_OFFSET, self.object_kind);
        put_u64(&mut header, BYTE_LEN_OFFSET, self.byte_len);
        put_u32(&mut header, LEAF_COUNT_OFFSET, self.leaf_count);
        put_u32(&mut header, TREE_NODE_COUNT_OFFSET, self.tree_node_count);
        header[ROOT_OFFSET..ROOT_OFFSET + HASH_SIZE].copy_from_slice(&self.root);
        put_u64(&mut header, DATA_OFFSET_OFFSET, HEADER_SIZE as u64);
        put_u64(&mut header, TREE_OFFSET_OFFSET, layout.tree_offset as u64);
        put_u64(&mut header, ENCODED_LEN_OFFSET, layout.encoded_len as u64);
        Ok(header)
    }

    /// Strictly decodes a standalone canonical header.
    ///
    /// This validates every fixed, reserved, geometry, and offset field and
    /// returns the declared root. Binding that root to content and tree bytes is
    /// intentionally left to [`BlobView::decode`].
    pub fn decode_header(header: &[u8; HEADER_SIZE]) -> Result<Self, BlobError> {
        if header[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] != MAGIC {
            return Err(BlobError::BadMagic);
        }
        if get_u16(header, VERSION_OFFSET)? != FORMAT_VERSION
            || get_u16(header, HEADER_LEN_OFFSET)? != HEADER_SIZE as u16
        {
            return Err(BlobError::UnsupportedVersion);
        }
        if get_u16(header, HASH_ALGORITHM_OFFSET)? != HASH_ALGORITHM_SHA256 {
            return Err(BlobError::UnsupportedHash);
        }
        if header[LEAF_LOG2_OFFSET] != LEAF_LOG2
            || header[FLAGS_OFFSET] != 0
            || header[RESERVED0_OFFSET..BYTE_LEN_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            || header[RESERVED1_OFFSET..HEADER_SIZE]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(BlobError::NonCanonical);
        }

        let object_kind = get_u32(header, OBJECT_KIND_OFFSET)?;
        if object_kind == 0 {
            return Err(BlobError::EmptyObjectKind);
        }
        let byte_len = get_u64(header, BYTE_LEN_OFFSET)?;
        let layout = BlobGeometry::for_len(byte_len)?;
        let leaf_count = get_u32(header, LEAF_COUNT_OFFSET)?;
        let tree_node_count = get_u32(header, TREE_NODE_COUNT_OFFSET)?;
        if leaf_count != layout.leaf_count() || tree_node_count != layout.tree_node_count() {
            return Err(BlobError::NonCanonical);
        }
        if get_u64(header, DATA_OFFSET_OFFSET)? != HEADER_SIZE as u64
            || get_u64(header, TREE_OFFSET_OFFSET)? != layout.tree_offset as u64
            || get_u64(header, ENCODED_LEN_OFFSET)? != layout.encoded_len as u64
        {
            return Err(BlobError::NonCanonical);
        }
        let root = header[ROOT_OFFSET..ROOT_OFFSET + HASH_SIZE]
            .try_into()
            .map_err(|_| BlobError::Truncated)?;
        Ok(Self {
            object_kind,
            byte_len,
            leaf_count,
            tree_node_count,
            root,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub siblings: Vec<Hash>,
}

/// Destination for canonical Merkle-tree nodes produced by [`StreamingMerkle`].
///
/// The blob format stores nodes in level order (all leaves, then their parents),
/// but a single-pass builder discovers parents while later leaves are still being
/// read. Consequently a streaming sink must support index-addressed writes. Node
/// `index` is the same index used by the tree suffix emitted by [`encode_blob`];
/// its byte offset within that suffix is `index * HASH_SIZE`.
pub trait MerkleTreeSink {
    type Error;

    fn write_hash(&mut self, index: u32, hash: Hash) -> Result<(), Self::Error>;
}

/// Failure from the incremental canonical Merkle builder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamingError<E> {
    Blob(BlobError),
    Sink(E),
    ChunkTooLarge {
        actual: usize,
    },
    OutOfOrder {
        expected: u32,
        actual: u32,
    },
    UnexpectedChunk {
        index: u32,
    },
    WrongChunkLength {
        index: u32,
        expected: usize,
        actual: usize,
    },
    Incomplete {
        expected: u64,
        received: u64,
    },
    PaddingRemaining {
        remaining: u32,
    },
    PaddingComplete,
    /// A sink failed after it may have accepted a subset of a chunk's nodes.
    /// The builder deliberately refuses to continue after this ambiguous state.
    Poisoned,
}

impl<E> From<BlobError> for StreamingError<E> {
    fn from(error: BlobError) -> Self {
        Self::Blob(error)
    }
}

#[derive(Clone)]
struct StreamingCore {
    object_kind: u32,
    exact_len: usize,
    geometry: Geometry,
    received: usize,
    next_leaf: usize,
    frontier: [Option<Hash>; STREAMING_FRONTIER_SLOTS],
    poisoned: bool,
}

/// Incrementally constructs the exact Merkle tree used by [`encode_blob`].
///
/// Content is never retained. Each call supplies exactly one canonical leaf:
/// 4 KiB except for the final partial leaf. The builder retains at most
/// [`STREAMING_FRONTIER_SLOTS`] hashes (`O(log MAX_LEAF_COUNT)`) and writes every
/// canonical tree node once to the caller-provided indexed sink.
pub struct StreamingMerkle<S> {
    core: StreamingCore,
    sink: S,
}

/// Successful streaming result, including the caller-owned populated tree sink.
pub struct StreamingCommit<S> {
    pub descriptor: BlobDescriptor,
    pub header: [u8; HEADER_SIZE],
    pub sink: S,
}

impl<S: MerkleTreeSink> StreamingMerkle<S> {
    /// Starts a stream whose total content length is fixed before any bytes are read.
    pub fn begin(
        object_kind: u32,
        exact_len: u64,
        sink: S,
    ) -> Result<Self, StreamingError<S::Error>> {
        if object_kind == 0 {
            return Err(StreamingError::Blob(BlobError::EmptyObjectKind));
        }
        let layout = BlobGeometry::for_len(exact_len).map_err(StreamingError::Blob)?;
        let exact_len = layout.exact_len as usize;
        let geometry = layout.geometry;
        debug_assert!(geometry.height <= MAX_MERKLE_HEIGHT);
        Ok(Self {
            core: StreamingCore {
                object_kind,
                exact_len,
                geometry,
                received: 0,
                next_leaf: 0,
                frontier: [None; STREAMING_FRONTIER_SLOTS],
                poisoned: false,
            },
            sink,
        })
    }

    pub const fn exact_len(&self) -> u64 {
        self.core.exact_len as u64
    }

    pub const fn received_len(&self) -> u64 {
        self.core.received as u64
    }

    pub const fn next_chunk_index(&self) -> u32 {
        self.core.next_leaf as u32
    }

    /// Number of hashes currently retained in the logarithmic carry frontier.
    pub fn retained_hashes(&self) -> usize {
        self.core.frontier.iter().flatten().count()
    }

    /// Provides access to the emission sink between builder steps.
    ///
    /// This is intended for a fixed-capacity sink whose at most
    /// [`MAX_STREAMING_EMISSIONS_PER_STEP`] indexed writes are drained to an
    /// asynchronous medium before the next builder call. If that external drain
    /// is ambiguous, the caller must discard the builder rather than resume it.
    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    /// Accepts the next canonical content chunk.
    ///
    /// Supplying the explicit index makes reordering, duplication, and skipped
    /// chunks fail closed before the sink is touched.
    pub fn push_chunk(&mut self, index: u32, chunk: &[u8]) -> Result<(), StreamingError<S::Error>> {
        if self.core.poisoned {
            return Err(StreamingError::Poisoned);
        }
        let expected_index = self.next_chunk_index();
        if index != expected_index {
            return Err(StreamingError::OutOfOrder {
                expected: expected_index,
                actual: index,
            });
        }
        if chunk.len() > LEAF_SIZE {
            return Err(StreamingError::ChunkTooLarge {
                actual: chunk.len(),
            });
        }
        if self.core.exact_len == 0 || self.core.received == self.core.exact_len {
            return Err(StreamingError::UnexpectedChunk { index });
        }
        let expected_len = (self.core.exact_len - self.core.received).min(LEAF_SIZE);
        if chunk.len() != expected_len {
            return Err(StreamingError::WrongChunkLength {
                index,
                expected: expected_len,
                actual: chunk.len(),
            });
        }

        let hash = leaf_hash(self.core.object_kind, index, chunk);
        self.append_leaf_hash(index as usize, hash)?;
        self.core.received += chunk.len();
        self.core.next_leaf += 1;
        Ok(())
    }

    /// Returns how many padding steps remain after all content was accepted.
    ///
    /// Empty content has one remaining step for its canonical zero-length real
    /// leaf. Every non-empty remaining step represents one padding leaf.
    pub fn padding_remaining(&self) -> Result<u32, StreamingError<S::Error>> {
        if self.core.poisoned {
            return Err(StreamingError::Poisoned);
        }
        if self.core.received != self.core.exact_len {
            return Err(StreamingError::Incomplete {
                expected: self.core.exact_len as u64,
                received: self.core.received as u64,
            });
        }
        Ok((self.core.geometry.padded_leaves - self.core.next_leaf) as u32)
    }

    /// Emits one canonical padding step and no more than one leaf plus tree height nodes.
    pub fn pad_next(&mut self) -> Result<(), StreamingError<S::Error>> {
        let remaining = self.padding_remaining()?;
        if remaining == 0 {
            return Err(StreamingError::PaddingComplete);
        }
        let index = self.core.next_leaf;
        // An empty object has one real, zero-length leaf. It is distinct from a
        // padding leaf and requires no content chunk from the caller.
        let hash = if self.core.exact_len == 0 && index == 0 {
            leaf_hash(self.core.object_kind, 0, &[])
        } else {
            empty_hash(self.core.object_kind, index as u32)
        };
        self.append_leaf_hash(index, hash)?;
        self.core.next_leaf += 1;
        Ok(())
    }

    /// Finalizes only after content and every explicit padding step are complete.
    pub fn finalize(self) -> Result<StreamingCommit<S>, StreamingError<S::Error>> {
        let remaining = self.padding_remaining()?;
        if remaining != 0 {
            return Err(StreamingError::PaddingRemaining { remaining });
        }

        let tree_root =
            self.core.frontier[self.core.geometry.height].ok_or(StreamingError::Poisoned)?;
        debug_assert!(
            self.core.frontier[..self.core.geometry.height]
                .iter()
                .all(Option::is_none)
        );
        let descriptor = BlobDescriptor {
            object_kind: self.core.object_kind,
            byte_len: self.core.exact_len as u64,
            leaf_count: self.core.geometry.leaf_count as u32,
            tree_node_count: self.core.geometry.node_count as u32,
            root: blob_root(
                self.core.object_kind,
                self.core.exact_len as u64,
                self.core.geometry.leaf_count as u32,
                &tree_root,
            ),
        };
        let header = descriptor.encode().map_err(StreamingError::Blob)?;
        Ok(StreamingCommit {
            descriptor,
            header,
            sink: self.sink,
        })
    }

    /// Convenience wrapper that emits all padding synchronously and finalizes.
    ///
    /// Asynchronous media should instead call [`Self::pad_next`], drain
    /// [`Self::sink_mut`] between steps, then call [`Self::finalize`].
    pub fn commit(mut self) -> Result<StreamingCommit<S>, StreamingError<S::Error>> {
        while self.padding_remaining()? != 0 {
            self.pad_next()?;
        }
        self.finalize()
    }

    fn append_leaf_hash(
        &mut self,
        leaf_index: usize,
        mut hash: Hash,
    ) -> Result<(), StreamingError<S::Error>> {
        self.core.poisoned = true;
        self.sink
            .write_hash(leaf_index as u32, hash)
            .map_err(StreamingError::Sink)?;

        let mut position = leaf_index;
        let mut level = 0usize;
        loop {
            if position & 1 == 0 {
                self.core.frontier[level] = Some(hash);
                break;
            }
            let left = self.core.frontier[level]
                .take()
                .ok_or(StreamingError::Poisoned)?;
            level += 1;
            position /= 2;
            hash = node_hash(level as u32, &left, &hash);
            let node_index = level_base(self.core.geometry.padded_leaves, level)
                .checked_add(position)
                .ok_or(StreamingError::Blob(BlobError::LengthOverflow))?;
            self.sink
                .write_hash(node_index as u32, hash)
                .map_err(StreamingError::Sink)?;
        }
        self.core.poisoned = false;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct BlobView<'a> {
    descriptor: BlobDescriptor,
    data: &'a [u8],
    tree_bytes: &'a [u8],
    geometry: Geometry,
}

impl<'a> BlobView<'a> {
    pub fn decode(encoded: &'a [u8]) -> Result<Self, BlobError> {
        if encoded.len() < HEADER_SIZE {
            return Err(BlobError::Truncated);
        }
        let header: &[u8; HEADER_SIZE] = encoded[..HEADER_SIZE]
            .try_into()
            .map_err(|_| BlobError::Truncated)?;
        let descriptor = BlobDescriptor::decode_header(header)?;
        let layout = BlobGeometry::for_len(descriptor.byte_len)?;
        let geometry = layout.geometry;
        let tree_offset = layout.tree_offset;
        let encoded_len = layout.encoded_len;
        if encoded.len() != encoded_len {
            return Err(if encoded.len() < encoded_len {
                BlobError::Truncated
            } else {
                BlobError::NonCanonical
            });
        }

        let tree_bytes = &encoded[tree_offset..encoded_len];
        let tree_root = tree_hash(tree_bytes, geometry.node_count - 1)?;
        if blob_root(
            descriptor.object_kind,
            descriptor.byte_len,
            descriptor.leaf_count,
            &tree_root,
        ) != descriptor.root
        {
            return Err(BlobError::RootMismatch);
        }
        Ok(Self {
            descriptor,
            data: &encoded[HEADER_SIZE..tree_offset],
            tree_bytes,
            geometry,
        })
    }

    pub const fn descriptor(&self) -> BlobDescriptor {
        self.descriptor
    }

    pub const fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn chunk(&self, index: u32) -> Result<&'a [u8], BlobError> {
        let index = usize::try_from(index).map_err(|_| BlobError::ChunkOutOfRange)?;
        chunk_at(self.data, self.geometry.leaf_count, index)
    }

    pub fn proof(&self, index: u32) -> Result<MerkleProof, BlobError> {
        let index_usize = usize::try_from(index).map_err(|_| BlobError::ChunkOutOfRange)?;
        if index_usize >= self.geometry.leaf_count {
            return Err(BlobError::ChunkOutOfRange);
        }
        let mut siblings = Vec::with_capacity(self.geometry.height);
        let mut position = index_usize;
        let mut level_width = self.geometry.padded_leaves;
        let mut level_base = 0usize;
        while level_width > 1 {
            siblings.push(tree_hash(self.tree_bytes, level_base + (position ^ 1))?);
            level_base = level_base
                .checked_add(level_width)
                .ok_or(BlobError::LengthOverflow)?;
            position /= 2;
            level_width /= 2;
        }
        Ok(MerkleProof {
            leaf_index: index,
            siblings,
        })
    }

    pub fn verify_chunk(&self, index: u32) -> Result<(), BlobError> {
        let chunk = self.chunk(index)?;
        let proof = self.proof(index)?;
        verify_proof(self.descriptor, chunk, &proof)
    }

    pub fn verify_all(&self) -> Result<(), BlobError> {
        let expected = build_tree(self.descriptor.object_kind, self.data, self.geometry)?;
        for (index, hash) in expected.iter().enumerate() {
            if tree_hash(self.tree_bytes, index)? != *hash {
                return Err(BlobError::TreeMismatch);
            }
        }
        Ok(())
    }
}

pub fn encode_blob(object_kind: u32, bytes: &[u8]) -> Result<Vec<u8>, BlobError> {
    if object_kind == 0 {
        return Err(BlobError::EmptyObjectKind);
    }
    let layout = BlobGeometry::for_len(bytes.len() as u64)?;
    let geometry = layout.geometry;
    let tree = build_tree(object_kind, bytes, geometry)?;
    let tree_root = *tree.last().ok_or(BlobError::TreeMismatch)?;
    let descriptor = BlobDescriptor {
        object_kind,
        byte_len: bytes.len() as u64,
        leaf_count: geometry.leaf_count as u32,
        tree_node_count: geometry.node_count as u32,
        root: blob_root(
            object_kind,
            bytes.len() as u64,
            geometry.leaf_count as u32,
            &tree_root,
        ),
    };
    let header = descriptor.encode()?;
    let capacity = layout.encoded_len;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(bytes);
    for hash in tree {
        encoded.extend_from_slice(&hash);
    }
    debug_assert_eq!(encoded.len(), capacity);
    Ok(encoded)
}

/// Exact encoded size for a canonical blob carrying `byte_len` content bytes.
/// Callers can enforce a backend limit before allocating the encoded object.
pub fn encoded_len(byte_len: usize) -> Result<usize, BlobError> {
    Ok(BlobGeometry::for_len(byte_len as u64)?.encoded_len)
}

pub fn verify_proof(
    descriptor: BlobDescriptor,
    chunk: &[u8],
    proof: &MerkleProof,
) -> Result<(), BlobError> {
    if descriptor.object_kind == 0 {
        return Err(BlobError::EmptyObjectKind);
    }
    let byte_len = usize::try_from(descriptor.byte_len).map_err(|_| BlobError::TooLarge)?;
    let geometry = Geometry::for_len(byte_len)?;
    if descriptor.leaf_count != geometry.leaf_count as u32
        || descriptor.tree_node_count != geometry.node_count as u32
        || proof.siblings.len() != geometry.height
    {
        return Err(BlobError::InvalidProof);
    }
    let index = usize::try_from(proof.leaf_index).map_err(|_| BlobError::ChunkOutOfRange)?;
    if index >= geometry.leaf_count {
        return Err(BlobError::ChunkOutOfRange);
    }
    let expected_len = chunk_len(byte_len, geometry.leaf_count, index)?;
    if chunk.len() != expected_len {
        return Err(BlobError::WrongChunkLength);
    }

    let mut position = index;
    let mut level = 1u32;
    let mut current = leaf_hash(descriptor.object_kind, proof.leaf_index, chunk);
    for sibling in &proof.siblings {
        current = if position & 1 == 0 {
            node_hash(level, &current, sibling)
        } else {
            node_hash(level, sibling, &current)
        };
        position /= 2;
        level = level.checked_add(1).ok_or(BlobError::LengthOverflow)?;
    }
    let root = blob_root(
        descriptor.object_kind,
        descriptor.byte_len,
        descriptor.leaf_count,
        &current,
    );
    if root == descriptor.root {
        Ok(())
    } else {
        Err(BlobError::InvalidProof)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Geometry {
    leaf_count: usize,
    padded_leaves: usize,
    node_count: usize,
    height: usize,
}

impl Geometry {
    fn for_len(byte_len: usize) -> Result<Self, BlobError> {
        if byte_len > MAX_BLOB_SIZE {
            return Err(BlobError::TooLarge);
        }
        let leaf_count = if byte_len == 0 {
            1
        } else {
            byte_len
                .checked_add(LEAF_SIZE - 1)
                .ok_or(BlobError::LengthOverflow)?
                / LEAF_SIZE
        };
        let padded_leaves = leaf_count
            .checked_next_power_of_two()
            .ok_or(BlobError::LengthOverflow)?;
        let node_count = padded_leaves
            .checked_mul(2)
            .and_then(|count| count.checked_sub(1))
            .ok_or(BlobError::LengthOverflow)?;
        Ok(Self {
            leaf_count,
            padded_leaves,
            node_count,
            height: padded_leaves.trailing_zeros() as usize,
        })
    }
}

fn build_tree(object_kind: u32, bytes: &[u8], geometry: Geometry) -> Result<Vec<Hash>, BlobError> {
    let mut tree = Vec::with_capacity(geometry.node_count);
    for index in 0..geometry.padded_leaves {
        if index < geometry.leaf_count {
            let chunk = chunk_at(bytes, geometry.leaf_count, index)?;
            tree.push(leaf_hash(object_kind, index as u32, chunk));
        } else {
            tree.push(empty_hash(object_kind, index as u32));
        }
    }
    let mut level_base = 0usize;
    let mut level_width = geometry.padded_leaves;
    let mut level = 1u32;
    while level_width > 1 {
        for offset in (0..level_width).step_by(2) {
            let left = tree[level_base + offset];
            let right = tree[level_base + offset + 1];
            tree.push(node_hash(level, &left, &right));
        }
        level_base = level_base
            .checked_add(level_width)
            .ok_or(BlobError::LengthOverflow)?;
        level_width /= 2;
        level = level.checked_add(1).ok_or(BlobError::LengthOverflow)?;
    }
    Ok(tree)
}

fn level_base(padded_leaves: usize, level: usize) -> usize {
    let mut base = 0usize;
    let mut width = padded_leaves;
    let mut current = 0usize;
    while current < level {
        base += width;
        width /= 2;
        current += 1;
    }
    base
}

fn chunk_at(bytes: &[u8], leaf_count: usize, index: usize) -> Result<&[u8], BlobError> {
    if index >= leaf_count {
        return Err(BlobError::ChunkOutOfRange);
    }
    let start = index
        .checked_mul(LEAF_SIZE)
        .ok_or(BlobError::LengthOverflow)?;
    let end = start
        .checked_add(LEAF_SIZE)
        .ok_or(BlobError::LengthOverflow)?
        .min(bytes.len());
    bytes.get(start..end).ok_or(BlobError::ChunkOutOfRange)
}

fn chunk_len(byte_len: usize, leaf_count: usize, index: usize) -> Result<usize, BlobError> {
    if index >= leaf_count {
        return Err(BlobError::ChunkOutOfRange);
    }
    if byte_len == 0 {
        return Ok(0);
    }
    let start = index
        .checked_mul(LEAF_SIZE)
        .ok_or(BlobError::LengthOverflow)?;
    Ok(byte_len.saturating_sub(start).min(LEAF_SIZE))
}

fn leaf_hash(object_kind: u32, index: u32, chunk: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(object_kind.to_le_bytes());
    hasher.update(index.to_le_bytes());
    hasher.update((chunk.len() as u32).to_le_bytes());
    hasher.update(chunk);
    hasher.finalize().into()
}

fn empty_hash(object_kind: u32, index: u32) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_DOMAIN);
    hasher.update(object_kind.to_le_bytes());
    hasher.update(index.to_le_bytes());
    hasher.finalize().into()
}

fn node_hash(level: u32, left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(level.to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn blob_root(object_kind: u32, byte_len: u64, leaf_count: u32, tree_root: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(object_kind.to_le_bytes());
    hasher.update(byte_len.to_le_bytes());
    hasher.update((LEAF_SIZE as u32).to_le_bytes());
    hasher.update(leaf_count.to_le_bytes());
    hasher.update(tree_root);
    hasher.finalize().into()
}

fn tree_hash(bytes: &[u8], index: usize) -> Result<Hash, BlobError> {
    let start = index
        .checked_mul(HASH_SIZE)
        .ok_or(BlobError::LengthOverflow)?;
    let end = start
        .checked_add(HASH_SIZE)
        .ok_or(BlobError::LengthOverflow)?;
    bytes
        .get(start..end)
        .ok_or(BlobError::Truncated)?
        .try_into()
        .map_err(|_| BlobError::Truncated)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, BlobError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(BlobError::Truncated)?
            .try_into()
            .map_err(|_| BlobError::Truncated)?,
    ))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, BlobError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(BlobError::Truncated)?
            .try_into()
            .map_err(|_| BlobError::Truncated)?,
    ))
}

fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, BlobError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(BlobError::Truncated)?
            .try_into()
            .map_err(|_| BlobError::Truncated)?,
    ))
}

pub fn sha256(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}
