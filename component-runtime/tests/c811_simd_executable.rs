#![cfg(feature = "c811-simd-executable")]

use vibeos_component_format::{current_validation_engine_identity, ProfileIdentity};
use vibeos_component_runtime::decode::{inspect_component_for_profile, DecodeError};

fn component_fixture() -> Vec<u8> {
    wat::parse_str(
        r#"(component
            (core module
              (func (export "run") (param v128 v128) (result v128)
                local.get 0 local.get 1 i32x4.add)))"#,
    )
    .unwrap()
}

#[test]
fn code8_is_current_without_promoting_code7_or_code5() {
    let bytes = component_fixture();
    let plan =
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE)
            .unwrap();
    assert!(plan.runtime_ready());
    assert_eq!(plan.summary().embedded_modules, 1);
    assert!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE)
            .is_some()
    );
    assert!(
        current_validation_engine_identity(ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION)
            .is_none()
    );
    assert!(current_validation_engine_identity(ProfileIdentity::PROFILE_2_SYNC_FLOAT).is_none());
    assert!(matches!(
        inspect_component_for_profile(&bytes, ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION),
        Err(DecodeError::Unsupported)
    ));
}

#[test]
fn relaxed_simd_and_component_v128_boundary_fail_closed() {
    let relaxed = wat::parse_str(
        r#"(component
            (core module
              (func (param v128 v128 v128) (result v128)
                local.get 0 local.get 1 local.get 2 f32x4.relaxed_madd)))"#,
    )
    .unwrap();
    assert!(matches!(
        inspect_component_for_profile(&relaxed, ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE,),
        Err(DecodeError::InvalidEmbeddedCore)
    ));
    assert!(wat::parse_str(r#"(component (type (func (param "forbidden" v128))))"#).is_err());
}
