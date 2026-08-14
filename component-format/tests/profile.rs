use vibeos_component_format::{
    CanonicalAbiFeature, CoreFeature, LimitError, LimitKind, ProfileIdentity, ProfileStage,
    TrapCode, ValidationAccount, ARTIFACT_ABI_VERSION, ARTIFACT_MAGIC, ASYNC_ARTIFACT_ABI_VERSION,
    ASYNC_CANONICAL_ABI_REVISION, ASYNC_COMPONENT_MODEL_REVISION, ASYNC_RUNTIME_ABI_VERSION,
    ASYNC_WASM_TOOLS_REVISION, CANONICAL_ABI_REVISION, COMPONENT_MODEL_REVISION,
    COMPONENT_PROFILE_VERSION, CORE_PROFILE_VERSION, PROFILE_1_LIMITS, RUNTIME_ABI_VERSION,
    SYNC_WASM_TOOLS_REVISION, WASI_API_REVISION, WASMPARSER_0_255_0_CHECKSUM,
    WASM_ENCODER_0_255_0_CHECKSUM, WIT_PACKAGES, WIT_PARSER_0_255_0_CHECKSUM,
};

type ChargeCounter = fn(&mut ValidationAccount, u32) -> Result<(), LimitError>;

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
fn c51_validation_identity_and_feature_vector_are_exact() {
    let identity = ProfileIdentity::PROFILE_1_ASYNC;
    assert_eq!(ASYNC_ARTIFACT_ABI_VERSION, 2);
    assert_eq!(ASYNC_RUNTIME_ABI_VERSION, 2);
    assert_ne!(identity, ProfileIdentity::PROFILE_1_SYNC);
    assert_eq!(identity.artifact_abi, ASYNC_ARTIFACT_ABI_VERSION);
    assert_eq!(identity.runtime_abi, ASYNC_RUNTIME_ABI_VERSION);
    assert_eq!(identity.component_revision, ASYNC_COMPONENT_MODEL_REVISION);
    assert_eq!(
        identity.canonical_abi_revision,
        ASYNC_CANONICAL_ABI_REVISION
    );
    assert_eq!(identity.wasm_tools_revision, ASYNC_WASM_TOOLS_REVISION);
    assert_eq!(
        ProfileIdentity::PROFILE_1_SYNC.wasm_tools_revision,
        SYNC_WASM_TOOLS_REVISION
    );
    assert_eq!(identity.wasi_revision, WASI_API_REVISION);
    assert_eq!(identity.stage, ProfileStage::ValidationOnly);
    assert!(!identity.execution_enabled());
    assert!(ProfileIdentity::PROFILE_1.execution_enabled());
    assert_eq!(
        ASYNC_COMPONENT_MODEL_REVISION,
        "component-model-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc"
    );
    assert_eq!(
        ASYNC_WASM_TOOLS_REVISION,
        "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380"
    );
    assert_eq!(
        WASI_API_REVISION,
        "wasi-v0.3.0-3ee2a590c766594ae44a54730fc74fc27da5c609"
    );
    for checksum in [
        WASMPARSER_0_255_0_CHECKSUM,
        WASM_ENCODER_0_255_0_CHECKSUM,
        WIT_PARSER_0_255_0_CHECKSUM,
    ] {
        assert_eq!(checksum.len(), 64);
        assert!(checksum.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    for feature in [
        CanonicalAbiFeature::Utf8,
        CanonicalAbiFeature::SyncLiftLower,
        CanonicalAbiFeature::Resources,
        CanonicalAbiFeature::AsyncFunctions,
        CanonicalAbiFeature::CallbackLift,
        CanonicalAbiFeature::AsyncLower,
        CanonicalAbiFeature::Futures,
        CanonicalAbiFeature::Streams,
        CanonicalAbiFeature::TaskBuiltins,
        CanonicalAbiFeature::ContextI32,
        CanonicalAbiFeature::Subtasks,
        CanonicalAbiFeature::CooperativeYield,
        CanonicalAbiFeature::WaitableSets,
        CanonicalAbiFeature::Backpressure,
    ] {
        assert!(feature.enabled_in_async_profile(), "{feature:?}");
    }
    for feature in [
        CanonicalAbiFeature::StackfulAsync,
        CanonicalAbiFeature::MoreAsyncBuiltins,
        CanonicalAbiFeature::Threading,
        CanonicalAbiFeature::ErrorContext,
        CanonicalAbiFeature::Gc,
        CanonicalAbiFeature::Component64,
        CanonicalAbiFeature::Utf16,
    ] {
        assert!(!feature.enabled_in_async_profile(), "{feature:?}");
    }
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
        CoreFeature::Start,
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
    let cases: &[(ChargeCounter, u32, LimitKind)] = &[
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
        (
            ValidationAccount::charge_canonical_options,
            PROFILE_1_LIMITS.max_canonical_options,
            LimitKind::CanonicalOptions,
        ),
        (
            ValidationAccount::charge_async_functions,
            PROFILE_1_LIMITS.max_async_functions,
            LimitKind::AsyncFunctions,
        ),
        (
            ValidationAccount::charge_future_types,
            PROFILE_1_LIMITS.max_future_types,
            LimitKind::FutureTypes,
        ),
        (
            ValidationAccount::charge_stream_types,
            PROFILE_1_LIMITS.max_stream_types,
            LimitKind::StreamTypes,
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
