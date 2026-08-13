//! Storage-policy admission for the file tree's typed object graph.
//!
//! A media ObjectKind does not select its own parser. Boot policy must admit
//! these exact non-zero kinds; this wrapper then validates both canonical
//! `refs-v1` encoding and the narrower FS parent/child relation.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    decode_fs_btree_node_v1, decode_fs_root_v1, FsCodecError, TypedManifestRefsV1,
    TypedObjectReference, TypedRefsError,
};

pub const FS_ROOT_V1_KIND: u32 = 0x4653_0101;
pub const FS_BTREE_NODE_V1_KIND: u32 = 0x4653_0102;
pub const FS_DATA_V1_KIND: u32 = 0x4653_0103;

pub const fn fs_typed_reference_kinds() -> [u32; 2] {
    [FS_ROOT_V1_KIND, FS_BTREE_NODE_V1_KIND]
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

/// Decode references only after policy has selected an FS structural kind.
/// Data objects are deliberately excluded: arbitrary file bytes can never
/// manufacture GC edges even when they contain a byte-perfect refs payload.
pub fn decode_fs_typed_references(
    parent_kind: u32,
    bytes: &[u8],
    storage_commit_generation: u64,
) -> Result<TypedManifestRefsV1, FsReferenceError> {
    if parent_kind != FS_ROOT_V1_KIND && parent_kind != FS_BTREE_NODE_V1_KIND {
        return Err(FsReferenceError::InvalidParentKind);
    }
    let mut references: Vec<TypedObjectReference> = if parent_kind == FS_ROOT_V1_KIND {
        let root = decode_fs_root_v1(bytes)?;
        alloc::vec![root.inode_tree, root.dirent_tree]
    } else {
        let node = decode_fs_btree_node_v1(bytes)?;
        node.entries
            .into_iter()
            .filter_map(|entry| entry.reference)
            .collect()
    };
    references.sort_unstable_by_key(|reference| reference.object_id);
    references.dedup();
    TypedManifestRefsV1::new(parent_kind, storage_commit_generation, references).map_err(Into::into)
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
        assert_eq!(
            decode_fs_typed_references(FS_DATA_V1_KIND, &[], 10),
            Err(FsReferenceError::InvalidParentKind)
        );
    }
}
