#![cfg(feature = "c812-r2-reference-validation")]

//! C8.12-R2 acceptance-only Component containment and mutation checks.

use std::panic::{catch_unwind, AssertUnwindSafe};

use vibeos_component_format::{
    current_validation_engine_identity, ProfileIdentity, PROFILE_2_SYNC_FLOAT_PROFILE_CODE,
    PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE,
};
use vibeos_component_runtime::decode::{
    inspect_component_for_profile, inspect_component_for_profile_6_candidate, DecodeError,
};

fn component_fixture() -> Vec<u8> {
    wat::parse_str(
        r#"(component
            (core module
              (table 2 funcref)
              (func $f)
              (elem (i32.const 0) $f)
              (func (export "run") (result i32)
                ref.null func ref.is_null
                ref.func $f ref.is_null i32.add
                i32.const 0 table.get ref.is_null i32.add)))"#,
    )
    .unwrap()
}

#[test]
fn funcref_is_contained_inside_core_and_code9_stays_non_current() {
    let bytes = component_fixture();
    let plan = inspect_component_for_profile_6_candidate(&bytes).unwrap();
    assert_eq!(plan.summary().embedded_modules, 1);
    assert!(matches!(
        inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION
        ),
        Err(DecodeError::Unsupported)
    ));
    assert!(current_validation_engine_identity(
        ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION
    )
    .is_none());
    assert_eq!(PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE, 9);
    assert_eq!(PROFILE_2_SYNC_FLOAT_PROFILE_CODE, 5);
    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(matches!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_1_SYNC),
        Err(DecodeError::InvalidEmbeddedCore | DecodeError::Unsupported)
    ));
}

#[test]
fn externref_and_reference_component_boundaries_fail_closed() {
    let external = wat::parse_str(
        r#"(component
            (core module
              (func (param externref) local.get 0 drop)))"#,
    )
    .unwrap();
    assert!(matches!(
        inspect_component_for_profile_6_candidate(&external),
        Err(DecodeError::InvalidEmbeddedCore)
    ));

    // The Component Model text grammar has no Core `funcref` value type.
    assert!(wat::parse_str(r#"(component (type (func (param "forbidden" funcref))))"#).is_err());
}

#[test]
fn fixed_mutation_corpus_never_panics_or_widens_authority() {
    let original = component_fixture();
    let mut rejected = 0usize;
    for index in 0..256usize {
        let mut changed = original.clone();
        let offset = 8 + (index * 131 % (changed.len() - 8));
        changed[offset] ^= 1 << (index % 8);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            inspect_component_for_profile_6_candidate(&changed)
        }));
        let result = outcome.expect("mutation panicked");
        if result.is_err() {
            rejected += 1;
        } else {
            assert!(current_validation_engine_identity(
                ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION
            )
            .is_none());
        }
    }
    assert_eq!(rejected, 208, "mutation corpus outcome drifted");
}
