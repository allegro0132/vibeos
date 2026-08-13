use vibeos_component_format::{
    CoreFeature, LimitKind, TrapCode, ValidationAccount, ARTIFACT_ABI_VERSION, ARTIFACT_MAGIC,
    CANONICAL_ABI_REVISION, COMPONENT_MODEL_REVISION, COMPONENT_PROFILE_VERSION,
    CORE_PROFILE_VERSION, PROFILE_1_LIMITS, RUNTIME_ABI_VERSION, WIT_PACKAGES,
};

#[test]
fn profile_identity_and_packages_are_exact() {
    assert_eq!(ARTIFACT_MAGIC, *b"VIBECMP\0");
    assert_eq!(ARTIFACT_ABI_VERSION, 1);
    assert_eq!(COMPONENT_PROFILE_VERSION, 1);
    assert_eq!(CORE_PROFILE_VERSION, 1);
    assert_eq!(RUNTIME_ABI_VERSION, 1);
    assert_eq!(
        COMPONENT_MODEL_REVISION,
        "wasmparser-component-model-0.255.0"
    );
    assert_eq!(CANONICAL_ABI_REVISION, "component-model-0.255.0-sync");
    assert_eq!(WIT_PACKAGES.len(), 5);
    assert_eq!(WIT_PACKAGES[0].name, "vibe:stream");
    assert_eq!(WIT_PACKAGES[4].version, "1.0.0");
}

#[test]
fn profile_starts_integer_only_and_proposal_closed() {
    for feature in [
        CoreFeature::IntegerArithmetic,
        CoreFeature::StructuredControl,
        CoreFeature::Functions,
        CoreFeature::Locals,
        CoreFeature::Globals,
        CoreFeature::LinearMemory,
        CoreFeature::Tables,
        CoreFeature::ImportsExports,
        CoreFeature::Start,
        CoreFeature::DataElements,
    ] {
        assert!(feature.enabled(), "{feature:?}");
    }
    for feature in [
        CoreFeature::Float,
        CoreFeature::Simd,
        CoreFeature::RelaxedSimd,
        CoreFeature::ReferenceTypes,
        CoreFeature::FunctionReferences,
        CoreFeature::BulkMemory,
        CoreFeature::MultiValue,
        CoreFeature::TailCall,
        CoreFeature::Threads,
        CoreFeature::MultiMemory,
        CoreFeature::Memory64,
        CoreFeature::ExtendedConst,
        CoreFeature::Exceptions,
        CoreFeature::StackSwitching,
        CoreFeature::GarbageCollection,
        CoreFeature::CustomPageSizes,
        CoreFeature::WideArithmetic,
    ] {
        assert!(!feature.enabled(), "{feature:?}");
    }
}

#[test]
fn malformed_lengths_fail_at_the_exact_boundary_without_mutation() {
    let mut account = ValidationAccount::default();
    account
        .charge_artifact_bytes(PROFILE_1_LIMITS.max_artifact_bytes)
        .unwrap();
    let before = account;
    let error = account.charge_artifact_bytes(1).unwrap_err();
    assert_eq!(error.kind, LimitKind::ArtifactBytes);
    assert_eq!(account, before);

    let mut account = ValidationAccount::default();
    let before = account;
    let error = account
        .charge_embedded_module_bytes(PROFILE_1_LIMITS.max_core_module_bytes + 1)
        .unwrap_err();
    assert_eq!(error.kind, LimitKind::CoreModuleBytes);
    assert_eq!(account, before);
}

#[test]
fn every_counter_accepts_exact_limit_and_rejects_one_more_atomically() {
    let cases: &[(fn(&mut ValidationAccount, u32) -> _, u32, LimitKind)] = &[
        (
            ValidationAccount::charge_types,
            PROFILE_1_LIMITS.max_types,
            LimitKind::Types,
        ),
        (
            ValidationAccount::charge_functions,
            PROFILE_1_LIMITS.max_functions,
            LimitKind::Functions,
        ),
        (
            ValidationAccount::charge_imports,
            PROFILE_1_LIMITS.max_imports,
            LimitKind::Imports,
        ),
        (
            ValidationAccount::charge_exports,
            PROFILE_1_LIMITS.max_exports,
            LimitKind::Exports,
        ),
        (
            ValidationAccount::charge_resources,
            PROFILE_1_LIMITS.max_resources,
            LimitKind::Resources,
        ),
    ];
    for (charge, maximum, kind) in cases {
        let mut account = ValidationAccount::default();
        charge(&mut account, *maximum).unwrap();
        let before = account;
        assert_eq!(charge(&mut account, 1).unwrap_err().kind, *kind);
        assert_eq!(account, before);
    }
}

#[test]
fn stable_trap_codes_do_not_alias() {
    let traps = [
        TrapCode::Validation,
        TrapCode::UnsupportedFeature,
        TrapCode::LimitExceeded,
        TrapCode::Unreachable,
        TrapCode::IntegerDivisionByZero,
        TrapCode::IntegerOverflow,
        TrapCode::MemoryOutOfBounds,
        TrapCode::TableOutOfBounds,
        TrapCode::IndirectCallTypeMismatch,
        TrapCode::CallDepthExceeded,
        TrapCode::FuelExhausted,
        TrapCode::Cancelled,
        TrapCode::CanonicalAbi,
        TrapCode::ResourceMisuse,
    ];
    for (index, trap) in traps.iter().enumerate() {
        assert!(!trap.name().is_empty());
        assert!(traps[index + 1..]
            .iter()
            .all(|other| *trap as u16 != *other as u16));
    }
}
