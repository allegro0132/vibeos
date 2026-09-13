#![cfg(feature = "experimental-root-bundle")]
mod production_common;
use vibeos_segment_format::*;
use vibeos_segment_format::experimental_root_checkpoint::{self as experimental, BundleCheckpoint};

fn bundled() -> BundleCheckpoint {
    let mut base = production_common::checkpoint(2);
    base.authority_root = base.catalog_root;
    base.allocation_root = base.catalog_root;
    BundleCheckpoint { base, root_bundle_mask: 7 }
}

fn super_pair(copy: u8, tagged: bool) -> (Page, Page) {
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let value = production_common::superblock(copy);
    let digest = if tagged { experimental::encode_superblock(&value, &mut body).unwrap() }
        else { encode_superblock_body(&value, &mut body).unwrap() };
    encode_record_seal(digest, &mut seal).unwrap();
    (body, seal)
}

fn checkpoint_pair(generation: u64) -> (Page, Page) {
    let mut value = bundled();
    value.base = production_common::checkpoint(generation);
    value.base.authority_root = value.base.catalog_root;
    value.base.allocation_root = value.base.catalog_root;
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = experimental::encode_body(value, &mut body).unwrap();
    encode_record_seal(digest, &mut seal).unwrap();
    (body, seal)
}

#[test]
fn admission_requires_tagged_superblocks_and_rejects_mixed_or_corrupt_copies() {
    let left = super_pair(0, true);
    let right = super_pair(1, true);
    let empty = [0; PAGE_SIZE];
    assert!(experimental::admit((&empty, &empty), (&empty, &empty)).unwrap().is_none());
    assert!(experimental::admit((&left.0, &left.1), (&right.0, &right.1)).unwrap().is_some());
    assert!(experimental::admit((&left.0, &left.1), (&empty, &empty)).unwrap().is_some());
    assert!(experimental::admit((&empty, &empty), (&right.0, &right.1)).unwrap().is_some());
    assert_eq!(decode_superblock(&left.0, &left.1), Err(FormatError::NonZeroReserved));
    let old_left = super_pair(0, false);
    let old_right = super_pair(1, false);
    assert!(experimental::admit((&old_left.0, &old_left.1), (&right.0, &right.1)).is_err());
    assert!(experimental::admit((&left.0, &left.1), (&old_right.0, &old_right.1)).is_err());
    let mut corrupt = right.0;
    corrupt[0xf4] ^= 1;
    assert!(experimental::admit((&left.0, &left.1), (&corrupt, &right.1)).is_err());
    assert!(experimental::admit((&right.0, &right.1), (&left.0, &left.1)).is_err());
}

#[test]
fn admitted_selection_checks_both_slots_before_choosing_newest() {
    let left = super_pair(0, true);
    let right = super_pair(1, true);
    let admitted = experimental::admit((&left.0, &left.1), (&right.0, &right.1)).unwrap().unwrap();
    let old = checkpoint_pair(3);
    let new = checkpoint_pair(4);
    let empty = [0; PAGE_SIZE];
    let maximum = admitted_pages(4).unwrap();
    let selected = admitted.select_checkpoints((&old.0, &old.1), (&new.0, &new.1), maximum)
        .unwrap().unwrap();
    assert_eq!(selected.value().base.binding.generation, 4);
    assert!(admitted.select_checkpoints((&new.0, &new.1), (&old.0, &old.1), maximum).is_err());
    assert!(admitted.select_checkpoints((&old.0, &old.1), (&new.0, &new.1), maximum - 1).is_err());
    let gap = checkpoint_pair(6);
    assert!(admitted.select_checkpoints((&old.0, &old.1), (&gap.0, &gap.1), maximum).is_err());
    for prefix in [0, 1, 16, 512, 2048, 4080, 4095] {
        let mut partial = empty;
        partial[..prefix].copy_from_slice(&new.1[..prefix]);
        let selected = admitted.select_checkpoints((&old.0, &old.1), (&new.0, &partial), maximum)
            .unwrap().unwrap();
        assert_eq!(selected.value().base.binding.generation, 3);
    }
    let mut corrupt = new.0;
    corrupt[0xc0] ^= 1;
    assert!(admitted.select_checkpoints((&old.0, &old.1), (&corrupt, &new.1), maximum).is_err());
    let mut legacy_body = empty;
    let mut legacy_seal = empty;
    let digest = encode_checkpoint_body(&production_common::checkpoint(4), &mut legacy_body).unwrap();
    encode_record_seal(digest, &mut legacy_seal).unwrap();
    assert!(admitted.select_checkpoints((&old.0, &old.1), (&legacy_body, &legacy_seal), maximum).is_err());
}

#[test]
fn sealed_bundle_and_fallback_checkpoints_are_explicit_and_roundtrip() {
    let full = bundled();
    let mut mixed = full;
    mixed.base.authority_root = production_common::checkpoint(2).authority_root;
    mixed.root_bundle_mask = 5;
    let fallback = BundleCheckpoint { base: production_common::checkpoint(2), root_bundle_mask: 0 };
    for checkpoint in [full, mixed, fallback] {
        let mut body = [0; PAGE_SIZE];
        let mut seal = [0; PAGE_SIZE];
        let digest = experimental::encode_body(checkpoint, &mut body).unwrap();
        encode_record_seal(digest, &mut seal).unwrap();
        let DecodeStatus::Sealed(decoded) = experimental::decode_verified(&body, &seal).unwrap() else {
            panic!("missing sealed checkpoint");
        };
        assert_eq!(decoded.value(), &checkpoint);
        assert_eq!(decode_checkpoint(&body, &seal), Err(FormatError::NonZeroReserved));
        for offset in [0xb4, 0xb8, 0xc0, 0x120, 0x180] {
            let mut changed = body;
            changed[offset] ^= 1;
            assert!(!matches!(experimental::decode_verified(&changed, &seal), Ok(DecodeStatus::Sealed(_))));
        }
    }
    let mut body = [0; PAGE_SIZE];
    let mut seal = [0; PAGE_SIZE];
    let digest = encode_checkpoint_body(&production_common::checkpoint(2), &mut body).unwrap();
    encode_record_seal(digest, &mut seal).unwrap();
    assert!(experimental::decode_verified(&body, &seal).is_err(), "no implicit legacy fallback");
}

#[test]
fn bundled_checkpoint_rejects_implicit_aliases_and_invalid_metadata() {
    for mask in [0, 1, 2, 3, 4, 5, 6, 8, u32::MAX] {
        assert!(BundleCheckpoint { root_bundle_mask: mask, ..bundled() }.validate().is_err());
    }
    let mut value = bundled();
    value.base.replay_tail = value.base.catalog_root;
    assert!(value.validate().is_err());
    let mut value = bundled();
    value.base.previous_generation = 0;
    assert!(value.validate().is_err());
    let mut value = bundled();
    value.base.slot = 0;
    assert!(value.validate().is_err());
    let mut value = bundled();
    value.base.authority_root = PhysicalPointer::Null;
    assert!(value.validate().is_err());
}
