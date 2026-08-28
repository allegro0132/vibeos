use vibeos_component_format::{
    current_validation_engine_identity, profile_2_sync_float_validation_contract, LimitKind,
    ProfileIdentity, TrapCode, PROFILE_1_LIMITS,
};
use vibeos_wasm_runtime::{
    current_core_validation_engine, inspect_core, inspect_core_for_profile_2_candidate,
    inspect_core_with_current_engine, inspect_profile_2_candidate_compile_reservation,
    profile_2_candidate_required_compile_bytes, AdmissionDetail, AdmissionError,
    OwnerAllocationReservation,
};

fn unsupported(error: AdmissionError) {
    assert_eq!(
        error,
        AdmissionError {
            trap: TrapCode::UnsupportedFeature,
            detail: AdmissionDetail::UnsupportedFeature,
        }
    );
}

#[test]
fn profile_1_paths_remain_integer_only() {
    let current = current_core_validation_engine(ProfileIdentity::PROFILE_1_SYNC).unwrap();
    let cases = [
        "(module (func (result f32) f32.const 0))",
        "(module (global f64 (f64.const 0)))",
    ];

    for source in cases {
        let bytes = wat::parse_str(source).unwrap();
        unsupported(inspect_core(&bytes).unwrap_err());
        unsupported(inspect_core_with_current_engine(&bytes, &current).unwrap_err());
    }
}

#[test]
fn sealed_profile_2_candidate_accepts_scalar_float_structure() {
    let bytes = wat::parse_str(
        r#"
        (module
          (global f32 (f32.const 1.25))
          (global f64 (f64.const -2.5))
          (func (export "mix") (param f32 f64) (result f64)
            (local f32)
            local.get 0
            f32.const 1.5
            f32.add
            local.set 2
            local.get 2
            f64.promote_f32
            local.get 1
            f64.add))
        "#,
    )
    .unwrap();

    let summary = inspect_core_for_profile_2_candidate(&bytes).unwrap();
    assert_eq!(summary.types, 1);
    assert_eq!(summary.functions, 1);
    assert_eq!(summary.globals, 2);
    assert_eq!(summary.locals, 1);
    assert_eq!(summary.max_params, 2);
    assert_eq!(summary.max_results, 1);
}

#[test]
fn candidate_compile_reservation_reuses_the_profile_1_policy_charge() {
    let bytes = wat::parse_str(
        "(module (func (export \"sqrt\") (param f64) (result f64) local.get 0 f64.sqrt))",
    )
    .unwrap();
    let required = profile_2_candidate_required_compile_bytes(&bytes).unwrap();
    let (summary, charged) = inspect_profile_2_candidate_compile_reservation(
        &bytes,
        OwnerAllocationReservation::new(required),
    )
    .unwrap();
    assert_eq!(charged, required);
    assert_eq!(summary.functions, 1);
    assert_eq!(summary.max_params, 1);

    assert_eq!(
        inspect_profile_2_candidate_compile_reservation(
            &bytes,
            OwnerAllocationReservation::new(required - 1),
        )
        .unwrap_err(),
        AdmissionError {
            trap: TrapCode::LimitExceeded,
            detail: AdmissionDetail::AllocationReservation,
        }
    );
}

#[test]
fn candidate_keeps_profile_limits_and_non_float_features_closed() {
    let too_many_params = format!(
        "(module (func {}))",
        "(param f32)".repeat(PROFILE_1_LIMITS.max_params_per_function as usize + 1)
    );
    let too_many_params = wat::parse_str(too_many_params).unwrap();
    assert_eq!(
        inspect_core_for_profile_2_candidate(&too_many_params)
            .unwrap_err()
            .detail,
        AdmissionDetail::Limit(LimitKind::Parameters)
    );

    let oversized = vec![0; PROFILE_1_LIMITS.max_core_module_bytes + 1];
    assert_eq!(
        inspect_core_for_profile_2_candidate(&oversized)
            .unwrap_err()
            .detail,
        AdmissionDetail::Limit(LimitKind::CoreModuleBytes)
    );

    let disabled = [
        "(module (global (mut f32) (f32.const 0)))",
        "(module (func (param i32) (result i32) local.get 0 i32.extend8_s))",
        "(module (func (param f32) (result i32) local.get 0 i32.trunc_sat_f32_s))",
        "(module (func (param v128) (result v128) local.get 0))",
        "(module (func (result i32 f32) i32.const 1 f32.const 2))",
        "(module (memory 1 1) (func i32.const 0 i32.const 0 i32.const 0 memory.copy))",
        "(module (func $start) (start $start))",
    ];
    for source in disabled {
        let bytes = wat::parse_str(source).unwrap();
        unsupported(inspect_core_for_profile_2_candidate(&bytes).unwrap_err());
    }
}

#[test]
fn candidate_inspection_does_not_activate_profile_code_5() {
    let profile = ProfileIdentity::PROFILE_2_SYNC_FLOAT;
    let contract = profile_2_sync_float_validation_contract();
    assert_eq!(contract.profile(), profile);
    assert!(!contract.runtime_ready());
    assert!(current_validation_engine_identity(profile).is_none());
    assert!(current_core_validation_engine(profile).is_none());

    let bytes = wat::parse_str("(module (func (result f32) f32.const 0))").unwrap();
    inspect_core_for_profile_2_candidate(&bytes).unwrap();

    assert!(current_validation_engine_identity(profile).is_none());
    assert!(current_core_validation_engine(profile).is_none());
}
