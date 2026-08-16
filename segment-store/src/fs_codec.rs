//! Canonical Storage V2 payloads for capability-rooted file trees.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::{TypedObjectReference, FS_BTREE_NODE_V1_KIND, FS_DATA_V1_KIND};

pub const FS_OBJECT_MAX_LEN: usize = 4096;
pub const FS_BTREE_MAX_HEIGHT: u8 = 8;
pub const FS_ROOT_V1_LEN: usize = 0xb0;
pub const FS_BTREE_HEADER_LEN: usize = 0x40;
pub const FS_BTREE_ENTRY_HEADER_LEN: usize = 0x30;
pub const FS_DATA_HEADER_LEN: usize = 0x40;
pub const FS_DATA_REFERENCE_LEN: usize = 0x28;
pub const FS_DATA_MAX_ANCESTORS: usize = 64;
/// Format envelope for one data node's content bytes. Large sequential file
/// content stages multi-page chunks so one CAS commit carries megabytes, while
/// the historical 4 KiB nodes remain valid: this is a ceiling, not a stride.
pub const FS_DATA_CHUNK_MAX_LEN: usize = 4 * 1024 * 1024;
const FS_ROOT_MAGIC: &[u8; 8] = b"VIBEFSR1";
const FS_NODE_MAGIC: &[u8; 8] = b"VIBEFSN1";
const FS_DATA_MAGIC: &[u8; 8] = b"VIBEFSD1";
const FS_CODEC_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsCodecError {
    ArithmeticOverflow,
    InvalidField,
    InvalidLength,
    InvalidMagic,
    InvalidReference,
    NonZeroReserved,
    OutOfBounds,
    UnsortedOrDuplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsTreeKind {
    Inode = 1,
    Dirent = 2,
}

impl FsTreeKind {
    fn decode(value: u8) -> Result<Self, FsCodecError> {
        match value {
            1 => Ok(Self::Inode),
            2 => Ok(Self::Dirent),
            _ => Err(FsCodecError::InvalidField),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsRootV1 {
    pub namespace_uuid: u128,
    pub commit_generation: u64,
    pub next_file_id: u64,
    pub root_file_id: u64,
    pub inode_tree: TypedObjectReference,
    pub dirent_tree: TypedObjectReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsBtreeEntryV1 {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub reference: Option<TypedObjectReference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsBtreeNodeV1 {
    pub tree: FsTreeKind,
    /// Zero is a leaf. Eight is the highest admitted internal level.
    pub level: u8,
    pub commit_generation: u64,
    pub entries: Vec<FsBtreeEntryV1>,
}

/// One immutable, bounded file-content chunk. `ancestors[k]` names the node
/// exactly `2^k` chunks before this node. The inode points at the final node,
/// permitting append-only staging with a fixed 64-reference frontier while
/// retaining logarithmic lookup of any 4 KiB chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsDataNodeV1 {
    pub chunk_index: u64,
    pub total_len: u64,
    pub ancestors: Vec<TypedObjectReference>,
    pub bytes: Vec<u8>,
}

/// The structural half of one data node: everything except the content bytes.
/// Skip-list walks and stream-tail bookkeeping need only this, so holding or
/// recovering a node's metadata must not require materializing a multi-MiB
/// chunk in memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsDataNodeMeta {
    pub chunk_index: u64,
    pub total_len: u64,
    pub bytes_len: usize,
    pub ancestors: Vec<TypedObjectReference>,
}

impl FsDataNodeMeta {
    pub fn from_node(node: &FsDataNodeV1) -> Self {
        Self {
            chunk_index: node.chunk_index,
            total_len: node.total_len,
            bytes_len: node.bytes.len(),
            ancestors: node.ancestors.clone(),
        }
    }

    /// Encoded offset of the first content byte within the node payload.
    pub fn bytes_offset(&self) -> usize {
        FS_DATA_HEADER_LEN + self.ancestors.len() * FS_DATA_REFERENCE_LEN
    }

    /// Total encoded payload length of the node this metadata describes.
    pub fn encoded_len(&self) -> usize {
        self.bytes_offset() + self.bytes_len
    }
}

fn validate_data_node_shape(
    chunk_index: u64,
    total_len: u64,
    bytes_len: usize,
    ancestors: &[TypedObjectReference],
) -> Result<(), FsCodecError> {
    let expected_ancestors = fs_data_ancestor_count(chunk_index);
    if ancestors.len() != expected_ancestors
        || ancestors.len() > FS_DATA_MAX_ANCESTORS
        || bytes_len > FS_DATA_CHUNK_MAX_LEN
        || (total_len == 0 && (chunk_index != 0 || !ancestors.is_empty() || bytes_len != 0))
        || (total_len != 0 && bytes_len == 0)
        || total_len < bytes_len as u64
        || (chunk_index == 0 && total_len != bytes_len as u64)
        || (chunk_index != 0 && total_len <= bytes_len as u64)
    {
        return Err(FsCodecError::InvalidField);
    }
    for reference in ancestors {
        validate_reference(*reference, Some(FS_DATA_V1_KIND))?;
    }
    Ok(())
}

/// Decode a data node's header and ancestor table from an encoded prefix.
/// `input` must cover at least the header and ancestor references; any content
/// bytes present past that prefix are ignored. Every header field is validated
/// with exactly the canonical-encoding rules, so a prefix accepted here names
/// the same structure a full [`decode_fs_data_node_v1`] would produce.
pub fn decode_fs_data_node_v1_prefix(input: &[u8]) -> Result<FsDataNodeMeta, FsCodecError> {
    if input.len() < FS_DATA_HEADER_LEN {
        return Err(FsCodecError::InvalidLength);
    }
    if &input[..8] != FS_DATA_MAGIC {
        return Err(FsCodecError::InvalidMagic);
    }
    if get_u16(input, 0x08) != FS_CODEC_VERSION
        || get_u16(input, 0x0a) as usize != FS_DATA_HEADER_LEN
        || !zero(&input[0x26..FS_DATA_HEADER_LEN])
    {
        return Err(FsCodecError::InvalidField);
    }
    let chunk_index = get_u64(input, 0x10);
    let total_len = get_u64(input, 0x18);
    let bytes_len = get_u32(input, 0x20) as usize;
    let ancestor_count = get_u16(input, 0x24) as usize;
    let references_len = ancestor_count
        .checked_mul(FS_DATA_REFERENCE_LEN)
        .ok_or(FsCodecError::ArithmeticOverflow)?;
    let bytes_offset = FS_DATA_HEADER_LEN
        .checked_add(references_len)
        .ok_or(FsCodecError::ArithmeticOverflow)?;
    if get_u32(input, 0x0c) as usize != bytes_offset.checked_add(bytes_len).ok_or(FsCodecError::ArithmeticOverflow)? {
        return Err(FsCodecError::InvalidLength);
    }
    if input.len() < bytes_offset {
        return Err(FsCodecError::InvalidLength);
    }
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(ancestor_count)
        .map_err(|_| FsCodecError::OutOfBounds)?;
    for index in 0..ancestor_count {
        ancestors.push(decode_reference(
            input,
            FS_DATA_HEADER_LEN + index * FS_DATA_REFERENCE_LEN,
        )?);
    }
    validate_data_node_shape(chunk_index, total_len, bytes_len, &ancestors)?;
    Ok(FsDataNodeMeta {
        chunk_index,
        total_len,
        bytes_len,
        ancestors,
    })
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn put_u128(out: &mut [u8], offset: usize, value: u128) {
    out[offset..offset + 16].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(input[offset..offset + 2].try_into().expect("fixed field"))
}
fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().expect("fixed field"))
}
fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().expect("fixed field"))
}
fn get_u128(input: &[u8], offset: usize) -> u128 {
    u128::from_le_bytes(input[offset..offset + 16].try_into().expect("fixed field"))
}
fn zero(input: &[u8]) -> bool {
    input.iter().all(|byte| *byte == 0)
}

fn validate_reference(
    reference: TypedObjectReference,
    expected_kind: Option<u32>,
) -> Result<(), FsCodecError> {
    if reference.object_id == 0 || reference.commit_generation == 0 || reference.object_kind == 0 {
        return Err(FsCodecError::InvalidReference);
    }
    if expected_kind.is_some_and(|kind| reference.object_kind != kind) {
        return Err(FsCodecError::InvalidReference);
    }
    Ok(())
}

fn encode_reference(out: &mut [u8], offset: usize, reference: TypedObjectReference) {
    put_u128(out, offset, reference.object_id);
    put_u64(out, offset + 0x10, reference.commit_generation);
    put_u32(out, offset + 0x18, reference.object_kind);
}

fn decode_reference(input: &[u8], offset: usize) -> Result<TypedObjectReference, FsCodecError> {
    if !zero(&input[offset + 0x1c..offset + 0x28]) {
        return Err(FsCodecError::NonZeroReserved);
    }
    let reference = TypedObjectReference {
        object_id: get_u128(input, offset),
        commit_generation: get_u64(input, offset + 0x10),
        object_kind: get_u32(input, offset + 0x18),
    };
    validate_reference(reference, None)?;
    Ok(reference)
}

pub fn encode_fs_root_v1(root: &FsRootV1) -> Result<Vec<u8>, FsCodecError> {
    if root.namespace_uuid == 0
        || root.commit_generation == 0
        || root.next_file_id < 2
        || root.root_file_id == 0
        || root.root_file_id >= root.next_file_id
    {
        return Err(FsCodecError::InvalidField);
    }
    validate_reference(root.inode_tree, Some(FS_BTREE_NODE_V1_KIND))?;
    validate_reference(root.dirent_tree, Some(FS_BTREE_NODE_V1_KIND))?;
    let mut out = vec![0; FS_ROOT_V1_LEN];
    out[..8].copy_from_slice(FS_ROOT_MAGIC);
    put_u16(&mut out, 0x08, FS_CODEC_VERSION);
    put_u16(&mut out, 0x0a, 0x60);
    put_u32(&mut out, 0x0c, FS_ROOT_V1_LEN as u32);
    put_u128(&mut out, 0x10, root.namespace_uuid);
    put_u64(&mut out, 0x20, root.commit_generation);
    put_u64(&mut out, 0x28, root.next_file_id);
    put_u64(&mut out, 0x30, root.root_file_id);
    put_u16(&mut out, 0x38, 2);
    encode_reference(&mut out, 0x60, root.inode_tree);
    encode_reference(&mut out, 0x88, root.dirent_tree);
    Ok(out)
}

pub fn decode_fs_root_v1(input: &[u8]) -> Result<FsRootV1, FsCodecError> {
    if input.len() != FS_ROOT_V1_LEN {
        return Err(FsCodecError::InvalidLength);
    }
    if &input[..8] != FS_ROOT_MAGIC {
        return Err(FsCodecError::InvalidMagic);
    }
    if get_u16(input, 0x08) != FS_CODEC_VERSION
        || get_u16(input, 0x0a) != 0x60
        || get_u32(input, 0x0c) as usize != FS_ROOT_V1_LEN
        || get_u16(input, 0x38) != 2
    {
        return Err(FsCodecError::InvalidField);
    }
    if !zero(&input[0x3a..0x60]) {
        return Err(FsCodecError::NonZeroReserved);
    }
    let root = FsRootV1 {
        namespace_uuid: get_u128(input, 0x10),
        commit_generation: get_u64(input, 0x20),
        next_file_id: get_u64(input, 0x28),
        root_file_id: get_u64(input, 0x30),
        inode_tree: decode_reference(input, 0x60)?,
        dirent_tree: decode_reference(input, 0x88)?,
    };
    // Reuse the encoder's semantic validation without accepting alternate bytes.
    if encode_fs_root_v1(&root)? != input {
        return Err(FsCodecError::InvalidField);
    }
    Ok(root)
}

fn fs_data_ancestor_count(chunk_index: u64) -> usize {
    if chunk_index == 0 {
        0
    } else {
        (u64::BITS - chunk_index.leading_zeros()) as usize
    }
}

pub fn encode_fs_data_node_v1(node: &FsDataNodeV1) -> Result<Vec<u8>, FsCodecError> {
    validate_data_node_shape(
        node.chunk_index,
        node.total_len,
        node.bytes.len(),
        &node.ancestors,
    )?;
    let length = FS_DATA_HEADER_LEN
        .checked_add(
            node.ancestors
                .len()
                .checked_mul(FS_DATA_REFERENCE_LEN)
                .ok_or(FsCodecError::ArithmeticOverflow)?,
        )
        .and_then(|length| length.checked_add(node.bytes.len()))
        .ok_or(FsCodecError::ArithmeticOverflow)?;
    let mut out = vec![0; length];
    out[..8].copy_from_slice(FS_DATA_MAGIC);
    put_u16(&mut out, 0x08, FS_CODEC_VERSION);
    put_u16(&mut out, 0x0a, FS_DATA_HEADER_LEN as u16);
    put_u32(
        &mut out,
        0x0c,
        u32::try_from(length).map_err(|_| FsCodecError::OutOfBounds)?,
    );
    put_u64(&mut out, 0x10, node.chunk_index);
    put_u64(&mut out, 0x18, node.total_len);
    put_u32(&mut out, 0x20, node.bytes.len() as u32);
    put_u16(&mut out, 0x24, node.ancestors.len() as u16);
    let mut offset = FS_DATA_HEADER_LEN;
    for reference in &node.ancestors {
        encode_reference(&mut out, offset, *reference);
        offset += FS_DATA_REFERENCE_LEN;
    }
    out[offset..].copy_from_slice(&node.bytes);
    Ok(out)
}

pub fn decode_fs_data_node_v1(input: &[u8]) -> Result<FsDataNodeV1, FsCodecError> {
    if input.len() < FS_DATA_HEADER_LEN || &input[..8] != FS_DATA_MAGIC {
        return Err(if input.len() < FS_DATA_HEADER_LEN {
            FsCodecError::InvalidLength
        } else {
            FsCodecError::InvalidMagic
        });
    }
    if get_u16(input, 0x08) != FS_CODEC_VERSION
        || get_u16(input, 0x0a) as usize != FS_DATA_HEADER_LEN
        || get_u32(input, 0x0c) as usize != input.len()
        || !zero(&input[0x26..FS_DATA_HEADER_LEN])
    {
        return Err(FsCodecError::InvalidField);
    }
    let chunk_index = get_u64(input, 0x10);
    let total_len = get_u64(input, 0x18);
    let bytes_len = get_u32(input, 0x20) as usize;
    let ancestor_count = get_u16(input, 0x24) as usize;
    let references_len = ancestor_count
        .checked_mul(FS_DATA_REFERENCE_LEN)
        .ok_or(FsCodecError::ArithmeticOverflow)?;
    let bytes_offset = FS_DATA_HEADER_LEN
        .checked_add(references_len)
        .ok_or(FsCodecError::ArithmeticOverflow)?;
    if bytes_offset.checked_add(bytes_len) != Some(input.len()) {
        return Err(FsCodecError::InvalidLength);
    }
    let mut ancestors = Vec::new();
    ancestors
        .try_reserve_exact(ancestor_count)
        .map_err(|_| FsCodecError::OutOfBounds)?;
    for index in 0..ancestor_count {
        ancestors.push(decode_reference(
            input,
            FS_DATA_HEADER_LEN + index * FS_DATA_REFERENCE_LEN,
        )?);
    }
    let node = FsDataNodeV1 {
        chunk_index,
        total_len,
        ancestors,
        bytes: input[bytes_offset..].to_vec(),
    };
    if encode_fs_data_node_v1(&node)? != input {
        return Err(FsCodecError::InvalidField);
    }
    Ok(node)
}

fn validate_node(node: &FsBtreeNodeV1) -> Result<usize, FsCodecError> {
    if node.level > FS_BTREE_MAX_HEIGHT
        || node.commit_generation == 0
        || (node.level > 0 && node.entries.is_empty())
    {
        return Err(FsCodecError::InvalidField);
    }
    let mut length = FS_BTREE_HEADER_LEN;
    let mut previous: Option<&[u8]> = None;
    for entry in &node.entries {
        if entry.key.is_empty()
            || entry.key.len() > u16::MAX as usize
            || entry.value.len() > u16::MAX as usize
        {
            return Err(FsCodecError::InvalidField);
        }
        if previous.is_some_and(|key| key >= entry.key.as_slice()) {
            return Err(FsCodecError::UnsortedOrDuplicate);
        }
        previous = Some(&entry.key);
        if node.level > 0 {
            if !entry.value.is_empty() {
                return Err(FsCodecError::InvalidField);
            }
            validate_reference(
                entry.reference.ok_or(FsCodecError::InvalidReference)?,
                Some(FS_BTREE_NODE_V1_KIND),
            )?;
        } else if let Some(reference) = entry.reference {
            validate_reference(reference, Some(FS_DATA_V1_KIND))?;
            if node.tree == FsTreeKind::Dirent {
                return Err(FsCodecError::InvalidReference);
            }
        }
        length = length
            .checked_add(FS_BTREE_ENTRY_HEADER_LEN)
            .and_then(|value| value.checked_add(entry.key.len()))
            .and_then(|value| value.checked_add(entry.value.len()))
            .ok_or(FsCodecError::ArithmeticOverflow)?;
    }
    if length > FS_OBJECT_MAX_LEN {
        return Err(FsCodecError::OutOfBounds);
    }
    Ok(length)
}

pub fn encode_fs_btree_node_v1(node: &FsBtreeNodeV1) -> Result<Vec<u8>, FsCodecError> {
    let length = validate_node(node)?;
    let count = u16::try_from(node.entries.len()).map_err(|_| FsCodecError::OutOfBounds)?;
    let mut out = vec![0; length];
    out[..8].copy_from_slice(FS_NODE_MAGIC);
    put_u16(&mut out, 0x08, FS_CODEC_VERSION);
    put_u16(&mut out, 0x0a, FS_BTREE_HEADER_LEN as u16);
    put_u32(&mut out, 0x0c, length as u32);
    out[0x10] = node.tree as u8;
    out[0x11] = node.level;
    put_u16(&mut out, 0x12, count);
    put_u64(&mut out, 0x18, node.commit_generation);
    let mut offset = FS_BTREE_HEADER_LEN;
    for entry in &node.entries {
        put_u16(&mut out, offset, entry.key.len() as u16);
        put_u16(&mut out, offset + 2, entry.value.len() as u16);
        if let Some(reference) = entry.reference {
            encode_reference(&mut out, offset + 8, reference);
        }
        offset += FS_BTREE_ENTRY_HEADER_LEN;
        out[offset..offset + entry.key.len()].copy_from_slice(&entry.key);
        offset += entry.key.len();
        out[offset..offset + entry.value.len()].copy_from_slice(&entry.value);
        offset += entry.value.len();
    }
    Ok(out)
}

pub fn decode_fs_btree_node_v1(input: &[u8]) -> Result<FsBtreeNodeV1, FsCodecError> {
    if input.len() < FS_BTREE_HEADER_LEN || input.len() > FS_OBJECT_MAX_LEN {
        return Err(FsCodecError::InvalidLength);
    }
    if &input[..8] != FS_NODE_MAGIC {
        return Err(FsCodecError::InvalidMagic);
    }
    if get_u16(input, 0x08) != FS_CODEC_VERSION
        || get_u16(input, 0x0a) as usize != FS_BTREE_HEADER_LEN
        || get_u32(input, 0x0c) as usize != input.len()
        || !zero(&input[0x14..0x18])
        || !zero(&input[0x20..FS_BTREE_HEADER_LEN])
    {
        return Err(FsCodecError::NonZeroReserved);
    }
    let tree = FsTreeKind::decode(input[0x10])?;
    let level = input[0x11];
    let count = get_u16(input, 0x12) as usize;
    let commit_generation = get_u64(input, 0x18);
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| FsCodecError::OutOfBounds)?;
    let mut offset = FS_BTREE_HEADER_LEN;
    for _ in 0..count {
        let header_end = offset
            .checked_add(FS_BTREE_ENTRY_HEADER_LEN)
            .ok_or(FsCodecError::ArithmeticOverflow)?;
        if header_end > input.len() {
            return Err(FsCodecError::InvalidLength);
        }
        let key_len = get_u16(input, offset) as usize;
        let value_len = get_u16(input, offset + 2) as usize;
        if !zero(&input[offset + 4..offset + 8]) {
            return Err(FsCodecError::NonZeroReserved);
        }
        let reference = if zero(&input[offset + 8..offset + FS_BTREE_ENTRY_HEADER_LEN]) {
            None
        } else {
            Some(decode_reference(input, offset + 8)?)
        };
        offset = header_end;
        let key_end = offset
            .checked_add(key_len)
            .ok_or(FsCodecError::ArithmeticOverflow)?;
        let value_end = key_end
            .checked_add(value_len)
            .ok_or(FsCodecError::ArithmeticOverflow)?;
        if value_end > input.len() {
            return Err(FsCodecError::InvalidLength);
        }
        entries.push(FsBtreeEntryV1 {
            key: input[offset..key_end].to_vec(),
            value: input[key_end..value_end].to_vec(),
            reference,
        });
        offset = value_end;
    }
    if offset != input.len() {
        return Err(FsCodecError::InvalidLength);
    }
    let node = FsBtreeNodeV1 {
        tree,
        level,
        commit_generation,
        entries,
    };
    if encode_fs_btree_node_v1(&node)? != input {
        return Err(FsCodecError::InvalidField);
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(id: u128, kind: u32) -> TypedObjectReference {
        TypedObjectReference {
            object_id: id,
            commit_generation: 7,
            object_kind: kind,
        }
    }

    #[test]
    fn root_and_nodes_are_canonical_and_bounded() {
        let root = FsRootV1 {
            namespace_uuid: 9,
            commit_generation: 8,
            next_file_id: 3,
            root_file_id: 1,
            inode_tree: reference(1, FS_BTREE_NODE_V1_KIND),
            dirent_tree: reference(2, FS_BTREE_NODE_V1_KIND),
        };
        let bytes = encode_fs_root_v1(&root).unwrap();
        assert_eq!(bytes.len(), FS_ROOT_V1_LEN);
        assert_eq!(decode_fs_root_v1(&bytes).unwrap(), root);

        let leaf = FsBtreeNodeV1 {
            tree: FsTreeKind::Inode,
            level: 0,
            commit_generation: 8,
            entries: vec![FsBtreeEntryV1 {
                key: 1_u64.to_be_bytes().to_vec(),
                value: vec![1, 2],
                reference: Some(reference(3, FS_DATA_V1_KIND)),
            }],
        };
        let bytes = encode_fs_btree_node_v1(&leaf).unwrap();
        assert!(bytes.len() <= FS_OBJECT_MAX_LEN);
        assert_eq!(decode_fs_btree_node_v1(&bytes).unwrap(), leaf);
    }

    #[test]
    fn malformed_tree_shape_fails_closed() {
        let entry = FsBtreeEntryV1 {
            key: vec![1],
            value: Vec::new(),
            reference: None,
        };
        let unsorted = FsBtreeNodeV1 {
            tree: FsTreeKind::Dirent,
            level: 0,
            commit_generation: 1,
            entries: vec![entry.clone(), entry],
        };
        assert_eq!(
            encode_fs_btree_node_v1(&unsorted),
            Err(FsCodecError::UnsortedOrDuplicate)
        );
        let too_high = FsBtreeNodeV1 {
            tree: FsTreeKind::Dirent,
            level: 9,
            commit_generation: 1,
            entries: vec![FsBtreeEntryV1 {
                key: vec![1],
                value: vec![2],
                reference: None,
            }],
        };
        assert_eq!(
            encode_fs_btree_node_v1(&too_high),
            Err(FsCodecError::InvalidField)
        );
    }

    #[test]
    fn data_nodes_are_canonical_bounded_and_cannot_forge_child_kinds() {
        let first = FsDataNodeV1 {
            chunk_index: 0,
            total_len: 3,
            ancestors: Vec::new(),
            bytes: vec![1, 2, 3],
        };
        let encoded = encode_fs_data_node_v1(&first).unwrap();
        assert_eq!(decode_fs_data_node_v1(&encoded).unwrap(), first);

        let fourth = FsDataNodeV1 {
            chunk_index: 3,
            total_len: 16,
            ancestors: vec![
                reference(10, FS_DATA_V1_KIND),
                reference(8, FS_DATA_V1_KIND),
            ],
            bytes: vec![9; 4],
        };
        let encoded = encode_fs_data_node_v1(&fourth).unwrap();
        assert_eq!(decode_fs_data_node_v1(&encoded).unwrap(), fourth);

        let mut wrong_kind = fourth.clone();
        wrong_kind.ancestors[0] = reference(10, FS_BTREE_NODE_V1_KIND);
        assert_eq!(
            encode_fs_data_node_v1(&wrong_kind),
            Err(FsCodecError::InvalidReference)
        );
        let mut corrupt = encoded;
        corrupt[0x26] = 1;
        assert!(decode_fs_data_node_v1(&corrupt).is_err());
    }

    #[test]
    fn data_node_prefix_decode_matches_full_decode() {
        let node = FsDataNodeV1 {
            chunk_index: 5,
            total_len: 40,
            ancestors: vec![
                reference(20, FS_DATA_V1_KIND),
                reference(18, FS_DATA_V1_KIND),
                reference(14, FS_DATA_V1_KIND),
            ],
            bytes: vec![7; 8],
        };
        let encoded = encode_fs_data_node_v1(&node).unwrap();
        let expected = FsDataNodeMeta::from_node(&node);
        // Full payload, exact prefix, and prefix-plus-partial-data all agree.
        assert_eq!(decode_fs_data_node_v1_prefix(&encoded).unwrap(), expected);
        let prefix_len = expected.bytes_offset();
        assert_eq!(
            decode_fs_data_node_v1_prefix(&encoded[..prefix_len]).unwrap(),
            expected
        );
        assert_eq!(
            decode_fs_data_node_v1_prefix(&encoded[..prefix_len + 3]).unwrap(),
            expected
        );
        assert_eq!(expected.encoded_len(), encoded.len());

        // A prefix short of the ancestor table fails closed.
        assert!(decode_fs_data_node_v1_prefix(&encoded[..prefix_len - 1]).is_err());
        // A tampered length field fails closed.
        let mut bad_len = encoded.clone();
        bad_len[0x0c] ^= 1;
        assert!(decode_fs_data_node_v1_prefix(&bad_len).is_err());
        // A tampered ancestor count fails closed.
        let mut bad_count = encoded.clone();
        bad_count[0x24] = 2;
        assert!(decode_fs_data_node_v1_prefix(&bad_count).is_err());
        // A wrong-kind ancestor reference fails closed.
        let mut bad_kind = encoded;
        put_u32(&mut bad_kind, FS_DATA_HEADER_LEN + 0x18, FS_BTREE_NODE_V1_KIND);
        assert!(decode_fs_data_node_v1_prefix(&bad_kind).is_err());
    }

    #[test]
    fn data_node_format_admits_multi_page_chunks() {
        let node = FsDataNodeV1 {
            chunk_index: 0,
            total_len: (2 * 1024 * 1024) as u64,
            ancestors: Vec::new(),
            bytes: vec![0xa5; 2 * 1024 * 1024],
        };
        let encoded = encode_fs_data_node_v1(&node).unwrap();
        assert_eq!(decode_fs_data_node_v1(&encoded).unwrap(), node);
        assert_eq!(
            decode_fs_data_node_v1_prefix(&encoded[..FS_DATA_HEADER_LEN]).unwrap(),
            FsDataNodeMeta::from_node(&node)
        );
        let oversize = FsDataNodeV1 {
            chunk_index: 0,
            total_len: (FS_DATA_CHUNK_MAX_LEN + 1) as u64,
            ancestors: Vec::new(),
            bytes: vec![0; FS_DATA_CHUNK_MAX_LEN + 1],
        };
        assert_eq!(
            encode_fs_data_node_v1(&oversize),
            Err(FsCodecError::InvalidField)
        );
    }
}
