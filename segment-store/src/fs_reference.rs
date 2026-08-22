//! Storage-policy admission for the file tree's typed object graph.
//!
//! A media ObjectKind does not select its own parser. Boot policy must admit
//! these exact non-zero kinds; this wrapper then validates both canonical
//! `refs-v1` encoding and the narrower FS parent/child relation.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    decode_fs_btree_node_v1, decode_fs_data_node_v1, decode_fs_root_v1, FsCodecError,
    TypedManifestRefsV1, TypedObjectReference, TypedRefsError,
};

pub const FS_ROOT_V1_KIND: u32 = 0x4653_0101;
pub const FS_BTREE_NODE_V1_KIND: u32 = 0x4653_0102;
pub const FS_DATA_V1_KIND: u32 = 0x4653_0103;

pub const fn fs_typed_reference_kinds() -> [u32; 3] {
    [FS_ROOT_V1_KIND, FS_BTREE_NODE_V1_KIND, FS_DATA_V1_KIND]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsReferenceError {
    Codec(TypedRefsError),
    FsCodec(FsCodecError),
    InvalidParentKind,
    InvalidChildKind,
    RootShape,
}

impl From<TypedRefsError> for FsReferenceError {
    fn from(value: TypedRefsError) -> Self {
        Self::Codec(value)
    }
}

impl From<FsCodecError> for FsReferenceError {
    fn from(value: FsCodecError) -> Self {
        Self::FsCodec(value)
    }
}

/// Decode references only after policy selected the exact FS codec for this
/// object. Raw file bytes retain the raw codec and therefore cannot manufacture
/// graph edges even if they happen to contain a byte-perfect data-node payload.
pub fn decode_fs_typed_references(
    parent_kind: u32,
    bytes: &[u8],
    storage_commit_generation: u64,
) -> Result<TypedManifestRefsV1, FsReferenceError> {
    if parent_kind != FS_ROOT_V1_KIND
        && parent_kind != FS_BTREE_NODE_V1_KIND
        && parent_kind != FS_DATA_V1_KIND
    {
        return Err(FsReferenceError::InvalidParentKind);
    }
    let mut references: Vec<TypedObjectReference> = if parent_kind == FS_ROOT_V1_KIND {
        let root = decode_fs_root_v1(bytes)?;
        alloc::vec![root.inode_tree, root.dirent_tree]
    } else if parent_kind == FS_BTREE_NODE_V1_KIND {
        let node = decode_fs_btree_node_v1(bytes)?;
        node.entries
            .into_iter()
            .filter_map(|entry| entry.reference)
            .collect()
    } else {
        decode_fs_data_node_v1(bytes)?.ancestors
    };
    references.sort_unstable_by_key(|reference| reference.object_id);
    references.dedup();
    TypedManifestRefsV1::new(parent_kind, storage_commit_generation, references).map_err(Into::into)
}

/// Decode a data node's references from an authenticated encoded prefix
/// covering at least the header and ancestor table. `exact_len` must be the
/// node's full encoded payload length from its authenticated Blob identity;
/// the header's own length field must agree, so a truncated or padded prefix
/// cannot impersonate a different node.
pub fn decode_fs_data_typed_references_from_prefix(
    prefix: &[u8],
    exact_len: u64,
    storage_commit_generation: u64,
) -> Result<TypedManifestRefsV1, FsReferenceError> {
    let meta = crate::fs_codec::decode_fs_data_node_v1_prefix(prefix)?;
    if meta.encoded_len() as u64 != exact_len {
        return Err(FsReferenceError::FsCodec(FsCodecError::InvalidLength));
    }
    let mut references = meta.ancestors;
    references.sort_unstable_by_key(|reference| reference.object_id);
    references.dedup();
    TypedManifestRefsV1::new(FS_DATA_V1_KIND, storage_commit_generation, references)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encode_fs_btree_node_v1, encode_fs_root_v1, FsBtreeEntryV1, FsBtreeNodeV1, FsRootV1,
        FsTreeKind,
    };
    use alloc::vec;

    #[test]
    fn fs_parent_child_kinds_are_fail_closed() {
        let node = TypedObjectReference {
            object_id: 1,
            commit_generation: 7,
            object_kind: FS_BTREE_NODE_V1_KIND,
        };
        let other_node = TypedObjectReference {
            object_id: 2,
            ..node
        };
        let root = FsRootV1 {
            namespace_uuid: 1,
            commit_generation: 9,
            next_file_id: 2,
            root_file_id: 1,
            inode_tree: node,
            dirent_tree: other_node,
        };
        assert_eq!(
            decode_fs_typed_references(FS_ROOT_V1_KIND, &encode_fs_root_v1(&root).unwrap(), 10)
                .unwrap()
                .references(),
            &[node, other_node]
        );
        let data = TypedObjectReference {
            object_id: 3,
            commit_generation: 7,
            object_kind: FS_DATA_V1_KIND,
        };
        let leaf = FsBtreeNodeV1 {
            tree: FsTreeKind::Inode,
            level: 0,
            commit_generation: 9,
            entries: vec![FsBtreeEntryV1 {
                key: vec![1],
                value: vec![2],
                reference: Some(data),
            }],
        };
        assert_eq!(
            decode_fs_typed_references(
                FS_BTREE_NODE_V1_KIND,
                &encode_fs_btree_node_v1(&leaf).unwrap(),
                10,
            )
            .unwrap()
            .references(),
            &[data]
        );
        let data_node = crate::FsDataNodeV1 {
            chunk_index: 1,
            total_len: 2,
            ancestors: vec![data],
            bytes: vec![2],
        };
        assert_eq!(
            decode_fs_typed_references(
                FS_DATA_V1_KIND,
                &crate::encode_fs_data_node_v1(&data_node).unwrap(),
                10,
            )
            .unwrap()
            .references(),
            &[data]
        );
    }

    #[test]
    fn data_node_prefix_names_the_same_references_as_the_full_decode() {
        let ancestor = TypedObjectReference {
            object_id: 3,
            commit_generation: 7,
            object_kind: FS_DATA_V1_KIND,
        };
        let node = crate::FsDataNodeV1 {
            chunk_index: 1,
            total_len: 5000,
            ancestors: vec![ancestor],
            bytes: vec![0xa5; 4996],
        };
        let encoded = crate::encode_fs_data_node_v1(&node).unwrap();
        let exact_len = encoded.len() as u64;
        // The first content leaf is all a prefix reader ever sees.
        let prefix = &encoded[..encoded.len().min(4096)];
        let full = decode_fs_typed_references(FS_DATA_V1_KIND, &encoded, 10).unwrap();
        let from_prefix =
            decode_fs_data_typed_references_from_prefix(prefix, exact_len, 10).unwrap();
        assert_eq!(from_prefix.references(), full.references());
        // A prefix that does not match the authenticated whole-node length
        // fails closed, so a truncated or padded impostor cannot slip through.
        assert!(decode_fs_data_typed_references_from_prefix(prefix, exact_len - 1, 10).is_err());
        assert!(decode_fs_data_typed_references_from_prefix(prefix, exact_len + 1, 10).is_err());
        assert!(decode_fs_data_typed_references_from_prefix(
            &prefix[..crate::fs_codec::FS_DATA_HEADER_LEN - 1],
            exact_len,
            10
        )
        .is_err());
    }
}
