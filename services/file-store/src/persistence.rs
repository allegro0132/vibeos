//! Canonical namespace records and bounded B+tree page planning.
//!
//! Object references are intentionally absent from these values. Storage V2
//! carries content and child references in its trusted typed-reference field,
//! so arbitrary file bytes can never manufacture graph edges.

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Range;

use crate::{validate_name, FileError, FileId, FileType, ROOT_FILE_ID};

pub const INODE_VALUE_V1_LEN: usize = 32;
pub const DIRENT_VALUE_V1_LEN: usize = 8;
pub const BTREE_OBJECT_MAX_LEN: usize = 4096;
pub const BTREE_HEADER_LEN: usize = 0x40;
pub const BTREE_ENTRY_HEADER_LEN: usize = 0x30;
pub const BTREE_MAX_HEIGHT: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceCodecError {
    EmptyKey,
    InvalidField,
    InvalidLength,
    InvalidName,
    NonZeroReserved,
    OutOfBounds,
    TreeTooHigh,
    UnsortedOrDuplicate,
}

impl From<FileError> for PersistenceCodecError {
    fn from(_: FileError) -> Self {
        Self::InvalidName
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedInodeV1 {
    pub file_id: FileId,
    pub file_type: FileType,
    pub size: u64,
    pub link_count: u64,
    pub change_generation: u64,
    pub has_content: bool,
}

pub fn encode_inode_key(file_id: FileId) -> Result<[u8; 8], PersistenceCodecError> {
    if file_id == 0 {
        return Err(PersistenceCodecError::InvalidField);
    }
    Ok(file_id.to_be_bytes())
}

pub fn decode_inode_key(bytes: &[u8]) -> Result<FileId, PersistenceCodecError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| PersistenceCodecError::InvalidLength)?;
    let file_id = u64::from_be_bytes(bytes);
    if file_id == 0 {
        return Err(PersistenceCodecError::InvalidField);
    }
    Ok(file_id)
}

pub fn encode_inode_value(inode: PersistedInodeV1) -> Result<[u8; 32], PersistenceCodecError> {
    if inode.file_id == 0
        || inode.link_count == 0
        || inode.change_generation == 0
        || (inode.file_type == FileType::Directory && (inode.size != 0 || inode.has_content))
        || (inode.file_type != FileType::Directory && !inode.has_content)
    {
        return Err(PersistenceCodecError::InvalidField);
    }
    let mut out = [0; INODE_VALUE_V1_LEN];
    out[0] = match inode.file_type {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::Symlink => 3,
    };
    out[1] = u8::from(inode.has_content);
    out[8..16].copy_from_slice(&inode.size.to_le_bytes());
    out[16..24].copy_from_slice(&inode.link_count.to_le_bytes());
    out[24..32].copy_from_slice(&inode.change_generation.to_le_bytes());
    Ok(out)
}

pub fn decode_inode_value(
    file_id: FileId,
    bytes: &[u8],
) -> Result<PersistedInodeV1, PersistenceCodecError> {
    if bytes.len() != INODE_VALUE_V1_LEN {
        return Err(PersistenceCodecError::InvalidLength);
    }
    if bytes[2..8].iter().any(|byte| *byte != 0) || bytes[1] > 1 {
        return Err(PersistenceCodecError::NonZeroReserved);
    }
    let file_type = match bytes[0] {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::Symlink,
        _ => return Err(PersistenceCodecError::InvalidField),
    };
    let inode = PersistedInodeV1 {
        file_id,
        file_type,
        size: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        link_count: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        change_generation: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        has_content: bytes[1] != 0,
    };
    if encode_inode_value(inode)? != bytes {
        return Err(PersistenceCodecError::InvalidField);
    }
    Ok(inode)
}

pub fn encode_dirent_key(parent: FileId, name: &str) -> Result<Vec<u8>, PersistenceCodecError> {
    if parent == 0 {
        return Err(PersistenceCodecError::InvalidField);
    }
    validate_name(name)?;
    let mut key = Vec::new();
    key.try_reserve_exact(8 + name.len())
        .map_err(|_| PersistenceCodecError::OutOfBounds)?;
    key.extend_from_slice(&parent.to_be_bytes());
    key.extend_from_slice(name.as_bytes());
    Ok(key)
}

pub fn decode_dirent_key(bytes: &[u8]) -> Result<(FileId, &str), PersistenceCodecError> {
    if bytes.len() <= 8 {
        return Err(PersistenceCodecError::InvalidLength);
    }
    let parent = decode_inode_key(&bytes[..8])?;
    let name = core::str::from_utf8(&bytes[8..]).map_err(|_| PersistenceCodecError::InvalidName)?;
    validate_name(name)?;
    Ok((parent, name))
}

pub fn encode_dirent_value(child: FileId) -> Result<[u8; 8], PersistenceCodecError> {
    encode_inode_key(child)
}

pub fn decode_dirent_value(bytes: &[u8]) -> Result<FileId, PersistenceCodecError> {
    decode_inode_key(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtreePagePlan {
    /// Level zero contains leaf pages. The last level has exactly one root.
    pub levels: Vec<Vec<Range<usize>>>,
}

impl BtreePagePlan {
    pub fn height(&self) -> u8 {
        self.levels.len().saturating_sub(1) as u8
    }
}

fn entry_size(key_len: usize, value_len: usize) -> Result<usize, PersistenceCodecError> {
    if key_len == 0 || key_len > u16::MAX as usize || value_len > u16::MAX as usize {
        return Err(PersistenceCodecError::OutOfBounds);
    }
    BTREE_ENTRY_HEADER_LEN
        .checked_add(key_len)
        .and_then(|size| size.checked_add(value_len))
        .ok_or(PersistenceCodecError::OutOfBounds)
}

fn partition_sizes<I>(sizes: I) -> Result<Vec<Range<usize>>, PersistenceCodecError>
where
    I: IntoIterator<Item = Result<usize, PersistenceCodecError>>,
{
    let mut pages = Vec::new();
    let mut start = 0usize;
    let mut count = 0usize;
    let mut used = BTREE_HEADER_LEN;
    for size in sizes {
        let size = size?;
        if BTREE_HEADER_LEN + size > BTREE_OBJECT_MAX_LEN {
            return Err(PersistenceCodecError::OutOfBounds);
        }
        if count > start && used + size > BTREE_OBJECT_MAX_LEN {
            pages.push(start..count);
            start = count;
            used = BTREE_HEADER_LEN;
        }
        used += size;
        count += 1;
    }
    pages.push(start..count);
    Ok(pages)
}

/// Plan deterministic 4 KiB B+tree pages from strictly ordered leaf keys.
/// Internal separator keys are the minimum key of each child page.
pub fn plan_btree_pages(
    entries: &[(Vec<u8>, Vec<u8>)],
) -> Result<BtreePagePlan, PersistenceCodecError> {
    for pair in entries.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(PersistenceCodecError::UnsortedOrDuplicate);
        }
    }
    if entries.iter().any(|(key, _)| key.is_empty()) {
        return Err(PersistenceCodecError::EmptyKey);
    }
    let mut levels = Vec::new();
    let mut key_lengths: Vec<usize> = entries.iter().map(|(key, _)| key.len()).collect();
    let mut pages = partition_sizes(
        entries
            .iter()
            .map(|(key, value)| entry_size(key.len(), value.len())),
    )?;
    levels.push(pages.clone());
    while pages.len() > 1 {
        if levels.len() > BTREE_MAX_HEIGHT as usize {
            return Err(PersistenceCodecError::TreeTooHigh);
        }
        let separator_lengths: Vec<usize> = pages
            .iter()
            .map(|page| {
                key_lengths
                    .get(page.start)
                    .copied()
                    .ok_or(PersistenceCodecError::InvalidField)
            })
            .collect::<Result<_, _>>()?;
        pages = partition_sizes(
            separator_lengths
                .iter()
                .map(|key_len| entry_size(*key_len, 0)),
        )?;
        key_lengths = separator_lengths;
        levels.push(pages.clone());
    }
    Ok(BtreePagePlan { levels })
}

pub fn validate_namespace_records(
    inodes: &[PersistedInodeV1],
    dirents: &[(FileId, &str, FileId)],
    next_file_id: FileId,
) -> Result<(), PersistenceCodecError> {
    if next_file_id <= ROOT_FILE_ID
        || inodes.first().map(|inode| inode.file_id) != Some(ROOT_FILE_ID)
        || inodes
            .windows(2)
            .any(|pair| pair[0].file_id >= pair[1].file_id)
        || inodes.iter().any(|inode| inode.file_id >= next_file_id)
    {
        return Err(PersistenceCodecError::InvalidField);
    }
    let root = inodes.first().ok_or(PersistenceCodecError::InvalidField)?;
    if root.file_type != FileType::Directory {
        return Err(PersistenceCodecError::InvalidField);
    }
    for (parent, name, child) in dirents {
        encode_dirent_key(*parent, name)?;
        encode_dirent_value(*child)?;
        if inodes
            .binary_search_by_key(parent, |inode| inode.file_id)
            .is_err()
            || inodes
                .binary_search_by_key(child, |inode| inode.file_id)
                .is_err()
        {
            return Err(PersistenceCodecError::InvalidField);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn inode(file_id: u64, file_type: FileType, links: u64) -> PersistedInodeV1 {
        PersistedInodeV1 {
            file_id,
            file_type,
            size: if file_type == FileType::Directory {
                0
            } else {
                7
            },
            link_count: links,
            change_generation: 9,
            has_content: file_type != FileType::Directory,
        }
    }

    #[test]
    fn inode_and_dirent_records_are_canonical() {
        for expected in [
            inode(1, FileType::Directory, 2),
            inode(2, FileType::Regular, 1),
        ] {
            let key = encode_inode_key(expected.file_id).unwrap();
            let value = encode_inode_value(expected).unwrap();
            assert_eq!(decode_inode_key(&key).unwrap(), expected.file_id);
            assert_eq!(
                decode_inode_value(expected.file_id, &value).unwrap(),
                expected
            );
        }
        let key = encode_dirent_key(1, "文件 name").unwrap();
        assert_eq!(decode_dirent_key(&key).unwrap(), (1, "文件 name"));
        assert_eq!(
            decode_dirent_value(&encode_dirent_value(2).unwrap()).unwrap(),
            2
        );
    }

    #[test]
    fn page_plan_splits_deterministically_and_stays_bounded() {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (1_u64..=4096)
            .map(|id| (id.to_be_bytes().to_vec(), vec![0x55; INODE_VALUE_V1_LEN]))
            .collect();
        let plan = plan_btree_pages(&entries).unwrap();
        assert!(plan.levels[0].len() > 1);
        assert!(plan.height() <= BTREE_MAX_HEIGHT);
        assert_eq!(
            plan.levels.last().unwrap(),
            &[0..plan.levels[plan.levels.len() - 2].len()]
        );
        for level in &plan.levels {
            assert!(!level.is_empty());
            assert_eq!(level.first().unwrap().start, 0);
            for adjacent in level.windows(2) {
                assert_eq!(adjacent[0].end, adjacent[1].start);
            }
        }
    }

    #[test]
    fn malformed_records_and_order_fail_closed() {
        assert_eq!(
            encode_inode_key(0),
            Err(PersistenceCodecError::InvalidField)
        );
        assert_eq!(
            encode_dirent_key(1, "bad/name"),
            Err(PersistenceCodecError::InvalidName)
        );
        assert_eq!(
            plan_btree_pages(&[(vec![2], vec![]), (vec![1], vec![])]),
            Err(PersistenceCodecError::UnsortedOrDuplicate)
        );
        assert!(validate_namespace_records(
            &[
                inode(1, FileType::Directory, 2),
                inode(2, FileType::Regular, 1)
            ],
            &[(1, "a", 2)],
            3,
        )
        .is_ok());
    }
}
