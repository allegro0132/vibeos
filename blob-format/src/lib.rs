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

impl BlobDescriptor {
    pub fn from_content(object_kind: u32, bytes: &[u8]) -> Result<Self, BlobError> {
        if object_kind == 0 {
            return Err(BlobError::EmptyObjectKind);
        }
        let geometry = Geometry::for_len(bytes.len())?;
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
        let byte_len = usize::try_from(self.byte_len).map_err(|_| BlobError::TooLarge)?;
        let geometry = Geometry::for_len(byte_len)?;
        if self.object_kind == 0
            || self.leaf_count != geometry.leaf_count as u32
            || self.tree_node_count != geometry.node_count as u32
        {
            return Err(BlobError::NonCanonical);
        }
        let tree_offset = HEADER_SIZE
            .checked_add(byte_len)
            .ok_or(BlobError::LengthOverflow)?;
        let encoded_len = tree_offset
            .checked_add(
                geometry
                    .node_count
                    .checked_mul(HASH_SIZE)
                    .ok_or(BlobError::LengthOverflow)?,
            )
            .ok_or(BlobError::LengthOverflow)?;

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
        put_u64(&mut header, TREE_OFFSET_OFFSET, tree_offset as u64);
        put_u64(&mut header, ENCODED_LEN_OFFSET, encoded_len as u64);
        Ok(header)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    pub leaf_index: u32,
    pub siblings: Vec<Hash>,
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
        let header = &encoded[..HEADER_SIZE];
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
        let byte_len_u64 = get_u64(header, BYTE_LEN_OFFSET)?;
        let byte_len = usize::try_from(byte_len_u64).map_err(|_| BlobError::TooLarge)?;
        let geometry = Geometry::for_len(byte_len)?;
        let leaf_count = get_u32(header, LEAF_COUNT_OFFSET)?;
        let tree_node_count = get_u32(header, TREE_NODE_COUNT_OFFSET)?;
        if leaf_count != geometry.leaf_count as u32 || tree_node_count != geometry.node_count as u32
        {
            return Err(BlobError::NonCanonical);
        }

        let tree_offset = HEADER_SIZE
            .checked_add(byte_len)
            .ok_or(BlobError::LengthOverflow)?;
        let tree_len = geometry
            .node_count
            .checked_mul(HASH_SIZE)
            .ok_or(BlobError::LengthOverflow)?;
        let encoded_len = tree_offset
            .checked_add(tree_len)
            .ok_or(BlobError::LengthOverflow)?;
        if get_u64(header, DATA_OFFSET_OFFSET)? != HEADER_SIZE as u64
            || get_u64(header, TREE_OFFSET_OFFSET)? != tree_offset as u64
            || get_u64(header, ENCODED_LEN_OFFSET)? != encoded_len as u64
            || encoded.len() != encoded_len
        {
            return Err(if encoded.len() < encoded_len {
                BlobError::Truncated
            } else {
                BlobError::NonCanonical
            });
        }

        let root: Hash = header[ROOT_OFFSET..ROOT_OFFSET + HASH_SIZE]
            .try_into()
            .map_err(|_| BlobError::Truncated)?;
        let tree_bytes = &encoded[tree_offset..encoded_len];
        let tree_root = tree_hash(tree_bytes, geometry.node_count - 1)?;
        if blob_root(object_kind, byte_len_u64, leaf_count, &tree_root) != root {
            return Err(BlobError::RootMismatch);
        }
        Ok(Self {
            descriptor: BlobDescriptor {
                object_kind,
                byte_len: byte_len_u64,
                leaf_count,
                tree_node_count,
                root,
            },
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
    let geometry = Geometry::for_len(bytes.len())?;
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
    let tree_bytes = geometry
        .node_count
        .checked_mul(HASH_SIZE)
        .ok_or(BlobError::LengthOverflow)?;
    let capacity = HEADER_SIZE
        .checked_add(bytes.len())
        .and_then(|size| size.checked_add(tree_bytes))
        .ok_or(BlobError::LengthOverflow)?;
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
    let geometry = Geometry::for_len(byte_len)?;
    HEADER_SIZE
        .checked_add(byte_len)
        .and_then(|size| {
            geometry
                .node_count
                .checked_mul(HASH_SIZE)
                .and_then(|tree_len| size.checked_add(tree_len))
        })
        .ok_or(BlobError::LengthOverflow)
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

#[derive(Clone, Copy)]
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
    hasher.update(&object_kind.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.update(&(chunk.len() as u32).to_le_bytes());
    hasher.update(chunk);
    hasher.finalize().into()
}

fn empty_hash(object_kind: u32, index: u32) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_DOMAIN);
    hasher.update(&object_kind.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.finalize().into()
}

fn node_hash(level: u32, left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(&level.to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn blob_root(object_kind: u32, byte_len: u64, leaf_count: u32, tree_root: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(&object_kind.to_le_bytes());
    hasher.update(&byte_len.to_le_bytes());
    hasher.update(&(LEAF_SIZE as u32).to_le_bytes());
    hasher.update(&leaf_count.to_le_bytes());
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

/// The implementation replaced by RustCrypto in M7.0. It remains compiled only
/// into this crate's unit tests as a differential compatibility oracle and is
/// removed once the frozen M4 fixtures have passed the compatibility gate.
#[cfg(test)]
struct TestSha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    byte_len: u64,
}

#[cfg(test)]
impl TestSha256 {
    const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            block_len: 0,
            byte_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.byte_len = self
            .byte_len
            .checked_add(input.len() as u64)
            .expect("blob SHA-256 input length is format-bounded");
        if self.block_len != 0 {
            let take = (64 - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
            if self.block_len == 64 {
                compress(&mut self.state, &self.block);
                self.block_len = 0;
            } else {
                return;
            }
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("exact SHA-256 block");
            compress(&mut self.state, block);
            input = &input[64..];
        }
        self.block[..input.len()].copy_from_slice(input);
        self.block_len = input.len();
    }

    fn finish(mut self) -> Hash {
        let bit_len = self
            .byte_len
            .checked_mul(8)
            .expect("format-bounded bit length");
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].fill(0);
            compress(&mut self.state, &self.block);
            self.block = [0; 64];
        } else {
            self.block[self.block_len..56].fill(0);
        }
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);
        let mut digest = [0u8; HASH_SIZE];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

#[cfg(test)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut words = [0u32; 64];
    for (index, word) in words[..16].iter_mut().enumerate() {
        *word = u32::from_be_bytes(
            block[index * 4..index * 4 + 4]
                .try_into()
                .expect("exact SHA-256 word"),
        );
    }
    for index in 16..64 {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choice = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(K[index])
            .wrapping_add(words[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

#[cfg(test)]
mod compatibility_oracle {
    use super::{sha256, Hash, TestSha256};

    fn oracle(input: &[u8]) -> Hash {
        let mut hasher = TestSha256::new();
        hasher.update(input);
        hasher.finish()
    }

    #[test]
    fn rustcrypto_matches_the_previous_implementation_at_block_boundaries() {
        for len in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 4096, 65_537] {
            let input: alloc::vec::Vec<u8> = (0..len)
                .map(|index| ((index * 37 + 11) % 251) as u8)
                .collect();
            assert_eq!(sha256(&input), oracle(&input), "length {len}");
        }
    }
}
