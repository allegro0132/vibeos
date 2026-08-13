//! Canonical Storage V2 payloads for capability-rooted file trees.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::{TypedObjectReference, FS_BTREE_NODE_V1_KIND, FS_DATA_V1_KIND};

pub const FS_OBJECT_MAX_LEN: usize = 4096;
pub const FS_BTREE_MAX_HEIGHT: u8 = 8;
pub const FS_ROOT_V1_LEN: usize = 0xb0;
pub const FS_BTREE_HEADER_LEN: usize = 0x40;
const FS_BTREE_ENTRY_HEADER_LEN: usize = 0x30;
const FS_ROOT_MAGIC: &[u8; 8] = b"VIBEFSR1";
const FS_NODE_MAGIC: &[u8; 8] = b"VIBEFSN1";
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

fn validate_node(node: &FsBtreeNodeV1) -> Result<usize, FsCodecError> {
    if node.level > FS_BTREE_MAX_HEIGHT || node.commit_generation == 0 || node.entries.is_empty() {
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
}
