use vibeos_component_format::{
    CanonicalAbiFeature, CoreFeature, LimitError, LimitKind, ProfileIdentity, ProfileStage,
    SelectedWasiCapability, SelectedWasiInterfaceDirection, SelectedWasiMappingCategory, TrapCode,
    ValidationAccount, ARTIFACT_ABI_VERSION, ARTIFACT_MAGIC, ASYNC_ARTIFACT_ABI_VERSION,
    ASYNC_CANONICAL_ABI_REVISION, ASYNC_COMPONENT_MODEL_REVISION, ASYNC_RUNTIME_ABI_VERSION,
    ASYNC_WASM_TOOLS_REVISION, CANONICAL_ABI_REVISION, COMPONENT_MODEL_REVISION,
    COMPONENT_PROFILE_VERSION, CORE_PROFILE_VERSION,
    NATIVE_ASYNC_RESOURCE_FREE_ARTIFACT_ABI_VERSION,
    NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_ABI_REVISION,
    NATIVE_ASYNC_RESOURCE_FREE_RUNTIME_ABI_VERSION, NATIVE_ASYNC_RESOURCE_FREE_WASI_REVISION,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN, PREVIEW1_WRAPPED_ADAPTER_ASSET_NAME,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_PROVENANCE, PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256,
    PREVIEW1_WRAPPED_ADAPTER_COMMIT, PREVIEW1_WRAPPED_ADAPTER_RELEASE,
    PREVIEW1_WRAPPED_ADAPTER_REVISION, PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION,
    PREVIEW1_WRAPPED_CANONICAL_FEATURES, PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION,
    PREVIEW1_WRAPPED_WASI_REVISION, PREVIEW1_WRAPPED_WASM_TOOLS_REVISION, PROFILE_1_LIMITS,
    RUNTIME_ABI_VERSION, SELECTED_WASI_CLI_TYPES_INTERFACE, SELECTED_WASI_CLOCK_TYPES_INTERFACE,
    SELECTED_WASI_COMMAND_STDIN_INTERFACE, SELECTED_WASI_COMMAND_STDOUT_INTERFACE,
    SELECTED_WASI_COMMAND_WIT, SELECTED_WASI_COMMAND_WORLD, SELECTED_WASI_INTERFACE_MAPPINGS,
    SELECTED_WASI_INVOCATION_LIFECYCLE_INTERFACE, SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
    SELECTED_WASI_PACKAGES, SELECTED_WASI_SECURE_RANDOM_INTERFACE, SYNC_WASM_TOOLS_REVISION,
    WASI_API_REVISION, WASMPARSER_0_255_0_CHECKSUM, WASM_ENCODER_0_255_0_CHECKSUM, WIT_PACKAGES,
    WIT_PARSER_0_255_0_CHECKSUM,
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
    assert_eq!(
        WIT_PACKAGES.map(|package| (package.name, package.version)),
        [
            ("vibe:stream", "1.0.0"),
            ("vibe:clock", "1.0.0"),
            ("vibe:random", "1.0.0"),
            ("vibe:blob", "1.0.0"),
            ("vibe:log", "1.0.0"),
        ]
    );
}

#[test]
fn c56_selected_wasi_command_contract_and_mapping_are_exact() {
    assert_eq!(
        SELECTED_WASI_COMMAND_WORLD,
        "vibe:wasi-selected/command@1.0.0"
    );
    assert_eq!(
        SELECTED_WASI_PACKAGES.map(|package| (package.name, package.version)),
        [
            ("wasi:clocks", "0.3.0"),
            ("wasi:random", "0.3.0"),
            ("wasi:cli", "0.3.0"),
        ]
    );

    assert_eq!(
        SELECTED_WASI_CLOCK_TYPES_INTERFACE,
        "wasi:clocks/types@0.3.0"
    );
    assert_eq!(SELECTED_WASI_CLI_TYPES_INTERFACE, "wasi:cli/types@0.3.0");

    let expected = [
        (
            SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
            SelectedWasiInterfaceDirection::Import,
            SelectedWasiMappingCategory::Capability(SelectedWasiCapability::MonotonicClock),
            Some(SelectedWasiCapability::MonotonicClock),
        ),
        (
            SELECTED_WASI_SECURE_RANDOM_INTERFACE,
            SelectedWasiInterfaceDirection::Import,
            SelectedWasiMappingCategory::Capability(SelectedWasiCapability::SecureRandom),
            Some(SelectedWasiCapability::SecureRandom),
        ),
        (
            SELECTED_WASI_COMMAND_STDIN_INTERFACE,
            SelectedWasiInterfaceDirection::Import,
            SelectedWasiMappingCategory::CommandStdin,
            None,
        ),
        (
            SELECTED_WASI_COMMAND_STDOUT_INTERFACE,
            SelectedWasiInterfaceDirection::Import,
            SelectedWasiMappingCategory::CommandStdout,
            None,
        ),
        (
            SELECTED_WASI_INVOCATION_LIFECYCLE_INTERFACE,
            SelectedWasiInterfaceDirection::Export,
            SelectedWasiMappingCategory::InvocationLifecycle,
            None,
        ),
    ];
    assert_eq!(SELECTED_WASI_INTERFACE_MAPPINGS.len(), expected.len());
    for (mapping, (interface, direction, category, capability)) in
        SELECTED_WASI_INTERFACE_MAPPINGS.iter().zip(expected)
    {
        assert_eq!(mapping.interface(), interface);
        assert_eq!(mapping.direction(), direction);
        assert_eq!(mapping.category(), category);
        assert_eq!(mapping.capability(), capability);
        assert_ne!(mapping.interface(), SELECTED_WASI_CLOCK_TYPES_INTERFACE);
        assert_ne!(mapping.interface(), SELECTED_WASI_CLI_TYPES_INTERFACE);
    }
    for (index, mapping) in SELECTED_WASI_INTERFACE_MAPPINGS.iter().enumerate() {
        assert!(SELECTED_WASI_INTERFACE_MAPPINGS[..index]
            .iter()
            .all(|earlier| earlier.interface() != mapping.interface()));
    }

    for marker in [
        "package vibe:wasi-selected@1.0.0;",
        "package wasi:clocks@0.3.0 {",
        "package wasi:random@0.3.0 {",
        "package wasi:cli@0.3.0 {",
        "world command {",
        "type duration = u64;",
        "wait-until: async func(when: mark);",
        "wait-for: async func(how-long: duration);",
        "get-random-bytes: func(max-len: u64) -> list<u8>;",
        "read-via-stream: func() -> tuple<stream<u8>, future<result<_, error-code>>>;",
        "write-via-stream: func(data: stream<u8>) -> future<result<_, error-code>>;",
        "run: async func() -> result;",
        "import wasi:clocks/monotonic-clock@0.3.0;",
        "import wasi:random/random@0.3.0;",
        "import wasi:cli/stdin@0.3.0;",
        "import wasi:cli/stdout@0.3.0;",
        "export wasi:cli/run@0.3.0;",
    ] {
        assert!(SELECTED_WASI_COMMAND_WIT.contains(marker), "{marker}");
    }
    // The nested operational interfaces refer to these type interfaces. The
    // resolver expands their exact identities; the world must not duplicate
    // them as explicit imports.
    for type_only in [
        SELECTED_WASI_CLOCK_TYPES_INTERFACE,
        SELECTED_WASI_CLI_TYPES_INTERFACE,
    ] {
        assert!(
            !SELECTED_WASI_COMMAND_WIT.contains(type_only),
            "{type_only}"
        );
    }
    for ambient in [
        "system-clock",
        "timezone",
        "insecure-seed",
        "interface insecure",
        "interface environment",
        "interface exit",
        "interface stderr",
        "terminal-",
        "wasi:filesystem",
        "wasi:sockets",
    ] {
        assert!(!SELECTED_WASI_COMMAND_WIT.contains(ambient), "{ambient}");
    }

    assert_eq!(
        ProfileIdentity::PROFILE_1_ASYNC.wasi_revision,
        WASI_API_REVISION
    );
    assert_eq!(
        ProfileIdentity::PROFILE_1_ASYNC.stage,
        ProfileStage::ValidationOnly
    );
    assert!(!ProfileIdentity::PROFILE_1_ASYNC.execution_enabled());
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
fn c53_native_async_resource_free_identity_and_feature_vector_are_exact() {
    let identity = ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE;

    assert_eq!(NATIVE_ASYNC_RESOURCE_FREE_ARTIFACT_ABI_VERSION, 3);
    assert_eq!(NATIVE_ASYNC_RESOURCE_FREE_RUNTIME_ABI_VERSION, 3);
    assert_ne!(identity, ProfileIdentity::PROFILE_1_SYNC);
    assert_ne!(identity, ProfileIdentity::PROFILE_1_ASYNC);
    assert_eq!(
        identity.artifact_abi,
        NATIVE_ASYNC_RESOURCE_FREE_ARTIFACT_ABI_VERSION
    );
    assert_eq!(identity.component_profile, COMPONENT_PROFILE_VERSION);
    assert_eq!(identity.core_profile, CORE_PROFILE_VERSION);
    assert_eq!(
        identity.runtime_abi,
        NATIVE_ASYNC_RESOURCE_FREE_RUNTIME_ABI_VERSION
    );
    assert_eq!(identity.core_revision, "webassembly-core-2.0-integer-v1");
    assert_eq!(identity.component_revision, ASYNC_COMPONENT_MODEL_REVISION);
    assert_eq!(
        identity.canonical_abi_revision,
        NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_ABI_REVISION
    );
    assert_eq!(
        NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_ABI_REVISION,
        "canonical-abi-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc-vibe-async-callback-1-resource-free-exec-1"
    );
    assert_eq!(identity.wasm_tools_revision, ASYNC_WASM_TOOLS_REVISION);
    assert_eq!(
        identity.wasi_revision,
        NATIVE_ASYNC_RESOURCE_FREE_WASI_REVISION
    );
    assert_eq!(
        NATIVE_ASYNC_RESOURCE_FREE_WASI_REVISION,
        "wasi-not-selected-native-async-resource-free"
    );
    assert_eq!(identity.stage, ProfileStage::ValidationOnly);
    assert!(!identity.execution_enabled());
    assert_eq!(identity.canonical_features.count_ones(), 7);

    for feature in [
        CanonicalAbiFeature::Utf8,
        CanonicalAbiFeature::AsyncFunctions,
        CanonicalAbiFeature::CallbackLift,
        CanonicalAbiFeature::Futures,
        CanonicalAbiFeature::Streams,
        CanonicalAbiFeature::TaskBuiltins,
        CanonicalAbiFeature::WaitableSets,
    ] {
        assert!(
            feature.enabled_in_native_async_resource_free_profile(),
            "{feature:?}"
        );
    }

    for feature in [
        CanonicalAbiFeature::SyncLiftLower,
        CanonicalAbiFeature::Resources,
        CanonicalAbiFeature::AsyncLower,
        CanonicalAbiFeature::ContextI32,
        CanonicalAbiFeature::Subtasks,
        CanonicalAbiFeature::CooperativeYield,
        CanonicalAbiFeature::Backpressure,
        CanonicalAbiFeature::StackfulAsync,
        CanonicalAbiFeature::MoreAsyncBuiltins,
        CanonicalAbiFeature::Threading,
        CanonicalAbiFeature::ErrorContext,
        CanonicalAbiFeature::Gc,
        CanonicalAbiFeature::Component64,
        CanonicalAbiFeature::Utf16,
    ] {
        assert!(
            !feature.enabled_in_native_async_resource_free_profile(),
            "{feature:?}"
        );
    }

    assert_eq!(ProfileIdentity::PROFILE_1, ProfileIdentity::PROFILE_1_SYNC);
    assert_eq!(ProfileIdentity::PROFILE_1_ASYNC.artifact_abi, 2);
    assert_eq!(ProfileIdentity::PROFILE_1_ASYNC.runtime_abi, 2);
    assert_eq!(
        ProfileIdentity::PROFILE_1_ASYNC.stage,
        ProfileStage::ValidationOnly
    );
}

#[test]
fn c81_preview1_wrapped_identity_adapter_and_feature_vector_are_exact() {
    let identity = ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED;

    assert_eq!(PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION, 4);
    assert_eq!(PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION, 4);
    assert_ne!(identity, ProfileIdentity::PROFILE_1_SYNC);
    assert_ne!(identity, ProfileIdentity::PROFILE_1_ASYNC);
    assert_ne!(
        identity,
        ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
    );
    assert_eq!(identity.artifact_abi, PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION);
    assert_eq!(identity.component_profile, COMPONENT_PROFILE_VERSION);
    assert_eq!(identity.core_profile, CORE_PROFILE_VERSION);
    assert_eq!(identity.runtime_abi, PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION);
    assert_eq!(identity.core_revision, "webassembly-core-2.0-integer-v1");
    assert_eq!(identity.component_revision, COMPONENT_MODEL_REVISION);
    assert_eq!(identity.canonical_abi_revision, CANONICAL_ABI_REVISION);
    assert_eq!(
        identity.wasm_tools_revision,
        PREVIEW1_WRAPPED_WASM_TOOLS_REVISION
    );
    assert_eq!(
        PREVIEW1_WRAPPED_WASM_TOOLS_REVISION,
        "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380"
    );
    assert_eq!(identity.wasi_revision, PREVIEW1_WRAPPED_WASI_REVISION);
    assert_eq!(PREVIEW1_WRAPPED_WASI_REVISION, "wasi-v0.2.12");
    assert_eq!(identity.stage, ProfileStage::ValidationOnly);
    assert!(!identity.execution_enabled());
    assert_eq!(
        identity.canonical_features,
        PREVIEW1_WRAPPED_CANONICAL_FEATURES
    );
    assert_eq!(
        identity.canonical_features,
        ProfileIdentity::PROFILE_1_SYNC.canonical_features
    );
    assert_eq!(identity.canonical_features.count_ones(), 3);

    for feature in [
        CanonicalAbiFeature::Utf8,
        CanonicalAbiFeature::SyncLiftLower,
        CanonicalAbiFeature::Resources,
    ] {
        assert!(feature.enabled_in_preview1_wrapped_profile(), "{feature:?}");
    }
    for feature in [
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
        CanonicalAbiFeature::StackfulAsync,
        CanonicalAbiFeature::MoreAsyncBuiltins,
        CanonicalAbiFeature::Threading,
        CanonicalAbiFeature::ErrorContext,
        CanonicalAbiFeature::Gc,
        CanonicalAbiFeature::Component64,
        CanonicalAbiFeature::Utf16,
    ] {
        assert!(
            !feature.enabled_in_preview1_wrapped_profile(),
            "{feature:?}"
        );
    }

    assert_eq!(PREVIEW1_WRAPPED_ADAPTER_RELEASE, "wasmtime-v48.0.0");
    assert_eq!(
        PREVIEW1_WRAPPED_ADAPTER_COMMIT,
        "f1412a598f96f3c261a19118d94caffcb0c36235"
    );
    assert_eq!(
        PREVIEW1_WRAPPED_ADAPTER_ASSET_NAME,
        "wasi_snapshot_preview1.command.wasm"
    );
    assert_eq!(
        PREVIEW1_WRAPPED_ADAPTER_REVISION,
        "wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm"
    );
    assert_eq!(PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN, 51_828);
    assert_eq!(
        PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256,
        [
            0x31, 0x6d, 0xfb, 0xf1, 0x71, 0x59, 0x1d, 0x69, 0xae, 0x41, 0x4e, 0xfd, 0x13, 0xb8,
            0x59, 0x33, 0xca, 0x13, 0x52, 0x6a, 0xf8, 0xd9, 0xe0, 0xa7, 0x35, 0xab, 0x88, 0xae,
            0x08, 0xfd, 0x85, 0xf0,
        ]
    );
    assert_eq!(
        PREVIEW1_WRAPPED_ADAPTER_ASSET_PROVENANCE,
        "https://github.com/bytecodealliance/wasmtime/releases/download/v48.0.0/wasi_snapshot_preview1.command.wasm"
    );
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
