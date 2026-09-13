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
