//! Versioned, inert contracts for Vibe Component profiles.
//!
//! This crate deliberately contains no engine, host service, capability, or
//! filesystem integration.  It is usable by admission tooling and the kernel's
//! `no_std + alloc` build without making component bytes executable.

#![no_std]

extern crate alloc;

mod artifact;
mod authentication;
mod engine;
mod graph_authentication;
mod graph_version;

pub use artifact::*;
pub use authentication::*;
pub use engine::*;
pub use graph_authentication::*;
pub use graph_version::*;

/// Canonical eight-byte prefix for a durable component artifact envelope.
pub const ARTIFACT_MAGIC: [u8; 8] = *b"VIBECMP\0";
pub const ARTIFACT_ABI_VERSION: u16 = 1;
pub const COMPONENT_PROFILE_VERSION: u16 = 1;
pub const CORE_PROFILE_VERSION: u16 = 1;
pub const RUNTIME_ABI_VERSION: u16 = 1;

/// Exact tooling/specification identities admitted by Profile 1.
///
/// These values are part of artifact identity.  Changing one requires a new
/// profile or ABI version; a semver-compatible dependency update is not an
/// implicit compatibility promise.
pub const CORE_SPEC_REVISION: &str = "webassembly-core-2.0-integer-v1";
pub const COMPONENT_MODEL_REVISION: &str = "wasmparser-component-model-0.255.0";
pub const CANONICAL_ABI_REVISION: &str = "component-model-0.255.0-sync";

/// Selected C5.1 validation/planning identity. It remains separate from the
/// active synchronous execution identity until C5.2 supplies continuations.
pub const ASYNC_ARTIFACT_ABI_VERSION: u16 = 2;
pub const ASYNC_RUNTIME_ABI_VERSION: u16 = 2;
/// Project-selected pre-standard Component Model draft. Upstream does not
/// publish a machine-readable mapping from wasm-tools releases to spec commits;
/// the checked-in strict-validation and mutation corpus is therefore part of
/// this project-selected pin.
pub const ASYNC_COMPONENT_MODEL_REVISION: &str =
    "component-model-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc";
pub const ASYNC_CANONICAL_ABI_REVISION: &str =
    "canonical-abi-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc-vibe-async-callback-1";

/// Resource-free native async execution contract selected by C5.3. This is a
/// distinct artifact/runtime ABI even though it consumes the same pinned
/// upstream Component Model and wasm-tools revisions as the C5.1 validator.
pub const NATIVE_ASYNC_RESOURCE_FREE_ARTIFACT_ABI_VERSION: u16 = 3;
pub const NATIVE_ASYNC_RESOURCE_FREE_RUNTIME_ABI_VERSION: u16 = 3;
pub const NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_ABI_REVISION: &str = "canonical-abi-73b7ad51d3b5d6f1ef53c923d8c585e28b242bcc-vibe-async-callback-1-resource-free-exec-1";
pub const NATIVE_ASYNC_RESOURCE_FREE_WASI_REVISION: &str =
    "wasi-not-selected-native-async-resource-free";

/// C8.1's host-wrapped WASIp1 validation contract. The adapter is selected and
/// applied off-device; this profile records the resulting Component as inert
/// data and deliberately has no current validation/runtime engine binding.
pub const PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION: u16 = 4;
pub const PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION: u16 = 4;
pub const PREVIEW1_WRAPPED_WASM_TOOLS_REVISION: &str =
    "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380";
pub const PREVIEW1_WRAPPED_WASI_REVISION: &str = "wasi-v0.2.12";

/// C8.8-F1's validation-only synchronous scalar-float contract. Code 5 is
/// deliberately disjoint from every Profile 1 artifact/runtime ABI, while the
/// Component and Core profile numbers advance together to 2.
pub const PROFILE_2_SYNC_FLOAT_PROFILE_CODE: u16 = 5;
pub const PROFILE_2_SYNC_FLOAT_ARTIFACT_ABI_VERSION: u16 = 5;
pub const PROFILE_2_SYNC_FLOAT_COMPONENT_PROFILE_VERSION: u16 = 2;
pub const PROFILE_2_SYNC_FLOAT_CORE_PROFILE_VERSION: u16 = 2;
pub const PROFILE_2_SYNC_FLOAT_RUNTIME_ABI_VERSION: u16 = 5;
pub const PROFILE_2_SYNC_FLOAT_CORE_SPEC_REVISION: &str =
    "webassembly-core-2.0-scalar-f32-f64-deterministic-software-float-v1";
pub const PROFILE_2_SYNC_FLOAT_CANONICAL_ABI_REVISION: &str =
    "component-model-0.255.0-sync-float-values-deterministic-software-float-v1";
pub const PROFILE_2_SYNC_FLOAT_WASI_REVISION: &str = "wasi-not-selected-sync-float";

/// C8.9's independently numbered executable successor. Code 5 is never
/// reinterpreted: every durable and runtime ABI coordinate advances to 6 and
/// both Component and Core profile coordinates advance to 3.
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE: u16 = 6;
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_ARTIFACT_ABI_VERSION: u16 = 6;
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_COMPONENT_PROFILE_VERSION: u16 = 3;
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_CORE_PROFILE_VERSION: u16 = 3;
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_RUNTIME_ABI_VERSION: u16 = 6;
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_CORE_SPEC_REVISION: &str =
    "webassembly-core-2.0-scalar-f32-f64-deterministic-software-float-v1-c89-exec-v1";
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_COMPONENT_MODEL_REVISION: &str =
    "wasmparser-component-model-0.255.0-c89-sync-float-exec-v1";
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_CANONICAL_ABI_REVISION: &str =
    "component-model-0.255.0-sync-float-values-deterministic-software-float-v1-c89-exec-v1";
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_WASI_REVISION: &str = "wasi-not-selected-c89-sync-float";
pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_WORLD: &str = "vibe:float/runtime@1.0.0";

/// C8.10's independently versioned fixed-width SIMD validation identity.
/// Code 7 is candidate metadata only: `v128` remains Core-internal and this
/// identity has no current engine, admission, or execution authority.
pub const PROFILE_4_SYNC_SIMD_VALIDATION_PROFILE_CODE: u16 = 7;
pub const PROFILE_4_SYNC_SIMD_VALIDATION_ARTIFACT_ABI_VERSION: u16 = 7;
pub const PROFILE_4_SYNC_SIMD_VALIDATION_COMPONENT_PROFILE_VERSION: u16 = 4;
pub const PROFILE_4_SYNC_SIMD_VALIDATION_CORE_PROFILE_VERSION: u16 = 4;
pub const PROFILE_4_SYNC_SIMD_VALIDATION_RUNTIME_ABI_VERSION: u16 = 7;
pub const PROFILE_4_SYNC_SIMD_VALIDATION_CORE_SPEC_REVISION: &str =
    "webassembly-core-2.0-fixed-width-simd-1.0-deterministic-software-float-c810-v1";
pub const PROFILE_4_SYNC_SIMD_VALIDATION_COMPONENT_MODEL_REVISION: &str =
    "wasmparser-component-model-0.255.0-c810-simd-validation-v1";
pub const PROFILE_4_SYNC_SIMD_VALIDATION_CANONICAL_ABI_REVISION: &str =
    "component-model-0.255.0-sync-float-values-no-v128-boundary-c810-simd-validation-v1";
pub const PROFILE_4_SYNC_SIMD_VALIDATION_WASI_REVISION: &str = "wasi-not-selected-c810-simd";
pub const PROFILE_4_SYNC_SIMD_VALIDATION_WORLD: &str = "vibe:simd/validation@1.0.0";

/// C8.11's independently numbered executable fixed-width SIMD successor.
/// Code 7 remains validation-only and is never reinterpreted as this identity.
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_PROFILE_CODE: u16 = 8;
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_ARTIFACT_ABI_VERSION: u16 = 8;
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_COMPONENT_PROFILE_VERSION: u16 = 5;
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_CORE_PROFILE_VERSION: u16 = 5;
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_RUNTIME_ABI_VERSION: u16 = 8;
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_CORE_SPEC_REVISION: &str =
    "webassembly-core-2.0-fixed-width-simd-1.0-deterministic-software-float-c811-exec-v1";
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_COMPONENT_MODEL_REVISION: &str =
    "wasmparser-component-model-0.255.0-c811-simd-exec-v1";
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_CANONICAL_ABI_REVISION: &str =
    "component-model-0.255.0-sync-float-values-no-v128-boundary-c811-simd-exec-v1";
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_WASI_REVISION: &str = "wasi-not-selected-c811-sync-simd";
pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_WORLD: &str = "vibe:simd/runtime@1.0.0";

/// C8.12's independently numbered Reference Types validation identity. Code 9
/// is candidate metadata only and cannot become executable under this identity.
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE: u16 = 9;
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_ARTIFACT_ABI_VERSION: u16 = 9;
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_COMPONENT_PROFILE_VERSION: u16 = 6;
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CORE_PROFILE_VERSION: u16 = 6;
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_RUNTIME_ABI_VERSION: u16 = 9;
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CORE_SPEC_REVISION: &str =
    "webassembly-core-2.0-reference-types-1.0-nullable-funcref-c812-validation-v1";
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_COMPONENT_MODEL_REVISION: &str =
    "wasmparser-component-model-0.255.0-c812-ref-validation-v1";
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CANONICAL_ABI_REVISION: &str =
    "component-model-0.255.0-sync-no-core-reference-boundary-c812-ref-validation-v1";
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_WASI_REVISION: &str =
    "wasi-not-selected-c812-reference-types";
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_WORLD: &str =
    "vibe:references/validation@1.0.0";

/// Exact Wasmtime release asset admitted as the C8.1 command adapter. These
/// values describe provenance only; the asset bytes are never bundled or
/// selected by this `no_std` format crate.
pub const PREVIEW1_WRAPPED_ADAPTER_RELEASE: &str = "wasmtime-v48.0.0";
pub const PREVIEW1_WRAPPED_ADAPTER_COMMIT: &str = "f1412a598f96f3c261a19118d94caffcb0c36235";
pub const PREVIEW1_WRAPPED_ADAPTER_ASSET_NAME: &str = "wasi_snapshot_preview1.command.wasm";
/// Canonical manifest token binding the release, source commit, and asset name.
pub const PREVIEW1_WRAPPED_ADAPTER_REVISION: &str =
    "wasmtime-v48.0.0-f1412a598f96f3c261a19118d94caffcb0c36235/wasi_snapshot_preview1.command.wasm";
pub const PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN: usize = 51_828;
pub const PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256: [u8; 32] = [
    0x31, 0x6d, 0xfb, 0xf1, 0x71, 0x59, 0x1d, 0x69, 0xae, 0x41, 0x4e, 0xfd, 0x13, 0xb8, 0x59, 0x33,
    0xca, 0x13, 0x52, 0x6a, 0xf8, 0xd9, 0xe0, 0xa7, 0x35, 0xab, 0x88, 0xae, 0x08, 0xfd, 0x85, 0xf0,
];
pub const PREVIEW1_WRAPPED_ADAPTER_ASSET_PROVENANCE: &str = "https://github.com/bytecodealliance/wasmtime/releases/download/v48.0.0/wasi_snapshot_preview1.command.wasm";

pub const SYNC_WASM_TOOLS_REVISION: &str =
    "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380";
pub const ASYNC_WASM_TOOLS_REVISION: &str =
    "wasm-tools-v1.255.0-76e20611d1920a7a39ca08983c6c77c3060de380";
pub const WASI_API_REVISION: &str = "wasi-v0.3.0-3ee2a590c766594ae44a54730fc74fc27da5c609";

/// Exact, inert WIT source for the selected WASI command validation contract.
///
/// The nested packages are retained locally so parsing requires neither a
/// filesystem package search nor a network lookup. This constant is format
/// metadata only: it supplies no host implementation or execution authority.
pub const SELECTED_WASI_COMMAND_WIT: &str = include_str!("../wit/selected-wasi-command.wit");
pub const SELECTED_WASI_COMMAND_WORLD: &str = "vibe:wasi-selected/command@1.0.0";

/// Crates.io payload identities for the exact frontend crates used by C5.1.
pub const WASMPARSER_0_255_0_CHECKSUM: &str =
    "e8e329ef4b5d46e73b91d3ac6924417cad55a8cbbf869c199283383427c3320b";
pub const WASM_ENCODER_0_255_0_CHECKSUM: &str =
    "9b524283fb5df62eec102ed0574838961bdd7ba5ac9c50d38e2756c51c971a42";
pub const WIT_PARSER_0_255_0_CHECKSUM: &str =
    "ab5f6371fc71f15730b756c1dea3562a67adab1a7e519c4ca010173d883695bb";

/// Independently selected Canonical ABI language features. The upstream
/// `CM_ASYNC` validator feature contains several proposals; this finer-grained
/// bitmap is the durable Vibe contract enforced by predecode and inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CanonicalAbiFeature {
    Utf8 = 0,
    SyncLiftLower = 1,
    Resources = 2,
    AsyncFunctions = 3,
    CallbackLift = 4,
    AsyncLower = 5,
    Futures = 6,
    Streams = 7,
    TaskBuiltins = 8,
    ContextI32 = 9,
    Subtasks = 10,
    CooperativeYield = 11,
    WaitableSets = 12,
    Backpressure = 13,
    StackfulAsync = 14,
    MoreAsyncBuiltins = 15,
    Threading = 16,
    ErrorContext = 17,
    Gc = 18,
    Component64 = 19,
    Utf16 = 20,
    FloatValues = 21,
}

impl CanonicalAbiFeature {
    pub const fn bit(self) -> u64 {
        1_u64 << self as u8
    }

    pub const fn enabled_in_async_profile(self) -> bool {
        ASYNC_CANONICAL_FEATURES & self.bit() != 0
    }

    pub const fn enabled_in_native_async_resource_free_profile(self) -> bool {
        NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_FEATURES & self.bit() != 0
    }

    pub const fn enabled_in_preview1_wrapped_profile(self) -> bool {
        PREVIEW1_WRAPPED_CANONICAL_FEATURES & self.bit() != 0
    }

    pub const fn enabled_in_profile_2_sync_float(self) -> bool {
        PROFILE_2_SYNC_FLOAT_CANONICAL_FEATURES & self.bit() != 0
    }
}

/// Exact synchronous Canonical ABI baseline shared by identities which do not
/// select async or any adjacent Component proposal.
pub const SYNC_CANONICAL_FEATURES: u64 = CanonicalAbiFeature::Utf8.bit()
    | CanonicalAbiFeature::SyncLiftLower.bit()
    | CanonicalAbiFeature::Resources.bit();

/// C8.1 uses the synchronous Canonical ABI plus nominal resources. Wrapping a
/// WASIp1 module does not implicitly enable any async or adjacent proposal.
pub const PREVIEW1_WRAPPED_CANONICAL_FEATURES: u64 = SYNC_CANONICAL_FEATURES;

/// Profile 2 adds only scalar float values to the unchanged synchronous
/// Canonical ABI surface. Async and all adjacent Component proposals remain
/// disabled.
pub const PROFILE_2_SYNC_FLOAT_CANONICAL_FEATURES: u64 = CanonicalAbiFeature::Utf8.bit()
    | CanonicalAbiFeature::SyncLiftLower.bit()
    | CanonicalAbiFeature::Resources.bit()
    | CanonicalAbiFeature::FloatValues.bit();

pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE_CANONICAL_FEATURES: u64 =
    PROFILE_2_SYNC_FLOAT_CANONICAL_FEATURES;

/// SIMD is deliberately not a Canonical ABI feature. Code 7 uses the scalar
/// Float Component boundary and confines `v128` to embedded Core modules.
pub const PROFILE_4_SYNC_SIMD_VALIDATION_CANONICAL_FEATURES: u64 =
    PROFILE_2_SYNC_FLOAT_CANONICAL_FEATURES;

pub const PROFILE_5_SYNC_SIMD_EXECUTABLE_CANONICAL_FEATURES: u64 =
    PROFILE_4_SYNC_SIMD_VALIDATION_CANONICAL_FEATURES;

/// Core references never cross the Component boundary, so code 9 retains the
/// integer-only synchronous Canonical ABI surface.
pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CANONICAL_FEATURES: u64 =
    SYNC_CANONICAL_FEATURES;

pub const ASYNC_CANONICAL_FEATURES: u64 = CanonicalAbiFeature::Utf8.bit()
    | CanonicalAbiFeature::SyncLiftLower.bit()
    | CanonicalAbiFeature::Resources.bit()
    | CanonicalAbiFeature::AsyncFunctions.bit()
    | CanonicalAbiFeature::CallbackLift.bit()
    | CanonicalAbiFeature::AsyncLower.bit()
    | CanonicalAbiFeature::Futures.bit()
    | CanonicalAbiFeature::Streams.bit()
    | CanonicalAbiFeature::TaskBuiltins.bit()
    | CanonicalAbiFeature::ContextI32.bit()
    | CanonicalAbiFeature::Subtasks.bit()
    | CanonicalAbiFeature::CooperativeYield.bit()
    | CanonicalAbiFeature::WaitableSets.bit()
    | CanonicalAbiFeature::Backpressure.bit();

/// Closed feature set for C5.3's resource-free native async executor. In
/// particular, this excludes synchronous lifting/lowering, resources, async
/// lowering, context, subtasks, cooperative yield, and backpressure.
pub const NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_FEATURES: u64 = CanonicalAbiFeature::Utf8.bit()
    | CanonicalAbiFeature::AsyncFunctions.bit()
    | CanonicalAbiFeature::CallbackLift.bit()
    | CanonicalAbiFeature::Futures.bit()
    | CanonicalAbiFeature::Streams.bit()
    | CanonicalAbiFeature::TaskBuiltins.bit()
    | CanonicalAbiFeature::WaitableSets.bit();

/// Exact format, frontend and runtime contract carried by trusted artifact and
/// image-policy metadata. Raw Component bytes do not encode these revisions;
/// callers must never synthesize this identity from a custom section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProfileStage {
    Executable = 1,
    ValidationOnly = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProfileIdentity {
    pub artifact_abi: u16,
    pub component_profile: u16,
    pub core_profile: u16,
    pub runtime_abi: u16,
    pub core_revision: &'static str,
    pub component_revision: &'static str,
    pub canonical_abi_revision: &'static str,
    pub wasm_tools_revision: &'static str,
    pub wasi_revision: &'static str,
    pub canonical_features: u64,
    pub stage: ProfileStage,
}

impl ProfileIdentity {
    /// Active C0-C4 synchronous execution identity. C5.1 deliberately leaves
    /// this alias unchanged; the async identity below is validation-only.
    pub const PROFILE_1_SYNC: Self = Self {
        artifact_abi: ARTIFACT_ABI_VERSION,
        component_profile: COMPONENT_PROFILE_VERSION,
        core_profile: CORE_PROFILE_VERSION,
        runtime_abi: RUNTIME_ABI_VERSION,
        core_revision: CORE_SPEC_REVISION,
        component_revision: COMPONENT_MODEL_REVISION,
        canonical_abi_revision: CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: "wasi-not-selected-sync",
        canonical_features: CanonicalAbiFeature::Utf8.bit()
            | CanonicalAbiFeature::SyncLiftLower.bit()
            | CanonicalAbiFeature::Resources.bit(),
        stage: ProfileStage::Executable,
    };

    /// Fully pinned C5.1 validator/planner identity. Async execution remains a
    /// separate C5.2 capability and this identity can never become runnable.
    pub const PROFILE_1_ASYNC: Self = Self {
        artifact_abi: ASYNC_ARTIFACT_ABI_VERSION,
        component_profile: COMPONENT_PROFILE_VERSION,
        core_profile: CORE_PROFILE_VERSION,
        runtime_abi: ASYNC_RUNTIME_ABI_VERSION,
        core_revision: CORE_SPEC_REVISION,
        component_revision: ASYNC_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: ASYNC_CANONICAL_ABI_REVISION,
        wasm_tools_revision: ASYNC_WASM_TOOLS_REVISION,
        wasi_revision: WASI_API_REVISION,
        canonical_features: ASYNC_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    /// Pinned C5.3 resource-free native async identity. It remains
    /// validation-only until the matching executor and admission path are
    /// sealed; the older validation identity and active sync alias remain
    /// unchanged.
    pub const PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE: Self = Self {
        artifact_abi: NATIVE_ASYNC_RESOURCE_FREE_ARTIFACT_ABI_VERSION,
        component_profile: COMPONENT_PROFILE_VERSION,
        core_profile: CORE_PROFILE_VERSION,
        runtime_abi: NATIVE_ASYNC_RESOURCE_FREE_RUNTIME_ABI_VERSION,
        core_revision: CORE_SPEC_REVISION,
        component_revision: ASYNC_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_ABI_REVISION,
        wasm_tools_revision: ASYNC_WASM_TOOLS_REVISION,
        wasi_revision: NATIVE_ASYNC_RESOURCE_FREE_WASI_REVISION,
        canonical_features: NATIVE_ASYNC_RESOURCE_FREE_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    /// Pinned C8.1 validation identity for a Core WASIp1 command wrapped
    /// off-device with the exact Preview1 adapter above. It deliberately shares
    /// the synchronous Component/Canonical ABI base while remaining permanently
    /// non-executable under this identity.
    pub const PROFILE_1_PREVIEW1_WRAPPED: Self = Self {
        artifact_abi: PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION,
        component_profile: COMPONENT_PROFILE_VERSION,
        core_profile: CORE_PROFILE_VERSION,
        runtime_abi: PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION,
        core_revision: CORE_SPEC_REVISION,
        component_revision: COMPONENT_MODEL_REVISION,
        canonical_abi_revision: CANONICAL_ABI_REVISION,
        wasm_tools_revision: PREVIEW1_WRAPPED_WASM_TOOLS_REVISION,
        wasi_revision: PREVIEW1_WRAPPED_WASI_REVISION,
        canonical_features: PREVIEW1_WRAPPED_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    /// C8.8-F1's independently versioned synchronous scalar-float identity.
    /// Code 5 is permanently validation-only: it freezes format and future
    /// validator metadata, but can never gain execution authority in place.
    /// Any executable successor must allocate a new profile code and ABIs so a
    /// historical code-5 artifact cannot become runnable after an upgrade.
    pub const PROFILE_2_SYNC_FLOAT: Self = Self {
        artifact_abi: PROFILE_2_SYNC_FLOAT_ARTIFACT_ABI_VERSION,
        component_profile: PROFILE_2_SYNC_FLOAT_COMPONENT_PROFILE_VERSION,
        core_profile: PROFILE_2_SYNC_FLOAT_CORE_PROFILE_VERSION,
        runtime_abi: PROFILE_2_SYNC_FLOAT_RUNTIME_ABI_VERSION,
        core_revision: PROFILE_2_SYNC_FLOAT_CORE_SPEC_REVISION,
        component_revision: COMPONENT_MODEL_REVISION,
        canonical_abi_revision: PROFILE_2_SYNC_FLOAT_CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: PROFILE_2_SYNC_FLOAT_WASI_REVISION,
        canonical_features: PROFILE_2_SYNC_FLOAT_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    /// C8.9's executable scalar-float identity. This is intentionally not an
    /// alias of code 5 even though the closed numeric semantics are reused.
    pub const PROFILE_3_SYNC_FLOAT_EXECUTABLE: Self = Self {
        artifact_abi: PROFILE_3_SYNC_FLOAT_EXECUTABLE_ARTIFACT_ABI_VERSION,
        component_profile: PROFILE_3_SYNC_FLOAT_EXECUTABLE_COMPONENT_PROFILE_VERSION,
        core_profile: PROFILE_3_SYNC_FLOAT_EXECUTABLE_CORE_PROFILE_VERSION,
        runtime_abi: PROFILE_3_SYNC_FLOAT_EXECUTABLE_RUNTIME_ABI_VERSION,
        core_revision: PROFILE_3_SYNC_FLOAT_EXECUTABLE_CORE_SPEC_REVISION,
        component_revision: PROFILE_3_SYNC_FLOAT_EXECUTABLE_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: PROFILE_3_SYNC_FLOAT_EXECUTABLE_CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: PROFILE_3_SYNC_FLOAT_EXECUTABLE_WASI_REVISION,
        canonical_features: PROFILE_3_SYNC_FLOAT_EXECUTABLE_CANONICAL_FEATURES,
        stage: ProfileStage::Executable,
    };

    /// C8.10's fixed-width SIMD candidate identity. It is never an alias of
    /// code 6 and remains validation-only throughout C8.10.
    pub const PROFILE_4_SYNC_SIMD_VALIDATION: Self = Self {
        artifact_abi: PROFILE_4_SYNC_SIMD_VALIDATION_ARTIFACT_ABI_VERSION,
        component_profile: PROFILE_4_SYNC_SIMD_VALIDATION_COMPONENT_PROFILE_VERSION,
        core_profile: PROFILE_4_SYNC_SIMD_VALIDATION_CORE_PROFILE_VERSION,
        runtime_abi: PROFILE_4_SYNC_SIMD_VALIDATION_RUNTIME_ABI_VERSION,
        core_revision: PROFILE_4_SYNC_SIMD_VALIDATION_CORE_SPEC_REVISION,
        component_revision: PROFILE_4_SYNC_SIMD_VALIDATION_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: PROFILE_4_SYNC_SIMD_VALIDATION_CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: PROFILE_4_SYNC_SIMD_VALIDATION_WASI_REVISION,
        canonical_features: PROFILE_4_SYNC_SIMD_VALIDATION_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    /// C8.11's executable SIMD successor. Its fresh code and ABI coordinates
    /// ensure that code 7 remains validation-only under every upgrade.
    pub const PROFILE_5_SYNC_SIMD_EXECUTABLE: Self = Self {
        artifact_abi: PROFILE_5_SYNC_SIMD_EXECUTABLE_ARTIFACT_ABI_VERSION,
        component_profile: PROFILE_5_SYNC_SIMD_EXECUTABLE_COMPONENT_PROFILE_VERSION,
        core_profile: PROFILE_5_SYNC_SIMD_EXECUTABLE_CORE_PROFILE_VERSION,
        runtime_abi: PROFILE_5_SYNC_SIMD_EXECUTABLE_RUNTIME_ABI_VERSION,
        core_revision: PROFILE_5_SYNC_SIMD_EXECUTABLE_CORE_SPEC_REVISION,
        component_revision: PROFILE_5_SYNC_SIMD_EXECUTABLE_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: PROFILE_5_SYNC_SIMD_EXECUTABLE_CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: PROFILE_5_SYNC_SIMD_EXECUTABLE_WASI_REVISION,
        canonical_features: PROFILE_5_SYNC_SIMD_EXECUTABLE_CANONICAL_FEATURES,
        stage: ProfileStage::Executable,
    };

    /// C8.12's bounded Reference Types validator identity. A separately
    /// numbered successor is required for any future execution authority.
    pub const PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION: Self = Self {
        artifact_abi: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_ARTIFACT_ABI_VERSION,
        component_profile: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_COMPONENT_PROFILE_VERSION,
        core_profile: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CORE_PROFILE_VERSION,
        runtime_abi: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_RUNTIME_ABI_VERSION,
        core_revision: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CORE_SPEC_REVISION,
        component_revision: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_COMPONENT_MODEL_REVISION,
        canonical_abi_revision: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CANONICAL_ABI_REVISION,
        wasm_tools_revision: SYNC_WASM_TOOLS_REVISION,
        wasi_revision: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_WASI_REVISION,
        canonical_features: PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_CANONICAL_FEATURES,
        stage: ProfileStage::ValidationOnly,
    };

    pub const PROFILE_1: Self = Self::PROFILE_1_SYNC;

    pub const fn execution_enabled(self) -> bool {
        matches!(self.stage, ProfileStage::Executable)
    }
}

const _: () = assert!(matches!(
    ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED.stage,
    ProfileStage::ValidationOnly
));
const _: () = assert!(!ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED.artifact_abi
        == PREVIEW1_WRAPPED_ARTIFACT_ABI_VERSION
);
const _: () = assert!(
    ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED.runtime_abi == PREVIEW1_WRAPPED_RUNTIME_ABI_VERSION
);
const _: () = assert!(SYNC_CANONICAL_FEATURES & CanonicalAbiFeature::FloatValues.bit() == 0);
const _: () = assert!(PREVIEW1_WRAPPED_CANONICAL_FEATURES == SYNC_CANONICAL_FEATURES);
const _: () = assert!(matches!(
    ProfileIdentity::PROFILE_2_SYNC_FLOAT.stage,
    ProfileStage::ValidationOnly
));
const _: () = assert!(!ProfileIdentity::PROFILE_2_SYNC_FLOAT.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_2_SYNC_FLOAT.artifact_abi == PROFILE_2_SYNC_FLOAT_PROFILE_CODE
);
const _: () =
    assert!(ProfileIdentity::PROFILE_2_SYNC_FLOAT.runtime_abi == PROFILE_2_SYNC_FLOAT_PROFILE_CODE);
const _: () = assert!(ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE.artifact_abi
        == PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE
);
const _: () = assert!(
    ProfileIdentity::PROFILE_3_SYNC_FLOAT_EXECUTABLE.runtime_abi
        == PROFILE_3_SYNC_FLOAT_EXECUTABLE_PROFILE_CODE
);
const _: () = assert!(matches!(
    ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION.stage,
    ProfileStage::ValidationOnly
));
const _: () = assert!(!ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION.artifact_abi
        == PROFILE_4_SYNC_SIMD_VALIDATION_PROFILE_CODE
);
const _: () = assert!(
    ProfileIdentity::PROFILE_4_SYNC_SIMD_VALIDATION.runtime_abi
        == PROFILE_4_SYNC_SIMD_VALIDATION_PROFILE_CODE
);
const _: () = assert!(ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE.artifact_abi
        == PROFILE_5_SYNC_SIMD_EXECUTABLE_PROFILE_CODE
);
const _: () = assert!(
    ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE.runtime_abi
        == PROFILE_5_SYNC_SIMD_EXECUTABLE_PROFILE_CODE
);
const _: () = assert!(matches!(
    ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION.stage,
    ProfileStage::ValidationOnly
));
const _: () =
    assert!(!ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION.execution_enabled());
const _: () = assert!(
    ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION.artifact_abi
        == PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE
);
const _: () = assert!(
    ProfileIdentity::PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION.runtime_abi
        == PROFILE_6_SYNC_REFERENCE_TYPES_VALIDATION_PROFILE_CODE
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitPackage {
    pub name: &'static str,
    pub version: &'static str,
}

pub const WIT_PACKAGES: [WitPackage; 5] = [
    WitPackage {
        name: "vibe:stream",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:clock",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:random",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:blob",
        version: "1.0.0",
    },
    WitPackage {
        name: "vibe:log",
        version: "1.0.0",
    },
];

/// Exact standard packages nested in [`SELECTED_WASI_COMMAND_WIT`]. The Vibe
/// root package is named separately by [`SELECTED_WASI_COMMAND_WORLD`] and is
/// deliberately not added to the unchanged Profile 1 [`WIT_PACKAGES`] list.
pub const SELECTED_WASI_PACKAGES: [WitPackage; 3] = [
    WitPackage {
        name: "wasi:clocks",
        version: "0.3.0",
    },
    WitPackage {
        name: "wasi:random",
        version: "0.3.0",
    },
    WitPackage {
        name: "wasi:cli",
        version: "0.3.0",
    },
];

/// Exact identities of the five operational interfaces selected by the
/// validation-only command world.
pub const SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE: &str = "wasi:clocks/monotonic-clock@0.3.0";
pub const SELECTED_WASI_SECURE_RANDOM_INTERFACE: &str = "wasi:random/random@0.3.0";
pub const SELECTED_WASI_COMMAND_STDIN_INTERFACE: &str = "wasi:cli/stdin@0.3.0";
pub const SELECTED_WASI_COMMAND_STDOUT_INTERFACE: &str = "wasi:cli/stdout@0.3.0";
pub const SELECTED_WASI_INVOCATION_LIFECYCLE_INTERFACE: &str = "wasi:cli/run@0.3.0";

/// Exact identities of the two imported interfaces that contribute types but
/// no callable host operation and therefore never receive an authority mapping.
pub const SELECTED_WASI_CLOCK_TYPES_INTERFACE: &str = "wasi:clocks/types@0.3.0";
pub const SELECTED_WASI_CLI_TYPES_INTERFACE: &str = "wasi:cli/types@0.3.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SelectedWasiInterfaceDirection {
    Import,
    Export,
}

/// Semantic capability classes selected by the inert standard-interface map.
/// Concrete capabilities and CSpace identities remain outside this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SelectedWasiCapability {
    MonotonicClock,
    SecureRandom,
}

/// Closed disposition for one operational interface in the selected world.
///
/// There is intentionally no ambient or catch-all variant. An interface absent
/// from [`SELECTED_WASI_INTERFACE_MAPPINGS`] is not selected and must be rejected
/// by admission rather than projected through this vocabulary.
///
/// ```compile_fail
/// use vibeos_component_format::SelectedWasiMappingCategory;
///
/// let _ = SelectedWasiMappingCategory::Ambient;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SelectedWasiMappingCategory {
    Capability(SelectedWasiCapability),
    CommandStdin,
    CommandStdout,
    InvocationLifecycle,
}

/// One fixed operational-interface mapping. Private fields prevent downstream
/// callers from manufacturing an adjacent spelling or reclassifying a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SelectedWasiInterfaceMapping {
    interface: &'static str,
    direction: SelectedWasiInterfaceDirection,
    category: SelectedWasiMappingCategory,
}

impl SelectedWasiInterfaceMapping {
    pub const fn interface(&self) -> &'static str {
        self.interface
    }

    pub const fn direction(&self) -> SelectedWasiInterfaceDirection {
        self.direction
    }

    pub const fn category(&self) -> SelectedWasiMappingCategory {
        self.category
    }

    pub const fn capability(&self) -> Option<SelectedWasiCapability> {
        match self.category {
            SelectedWasiMappingCategory::Capability(capability) => Some(capability),
            SelectedWasiMappingCategory::CommandStdin
            | SelectedWasiMappingCategory::CommandStdout
            | SelectedWasiMappingCategory::InvocationLifecycle => None,
        }
    }
}

/// Complete operational surface of the selected command world. The two
/// type-only interfaces are intentionally excluded from this fixed table.
pub const SELECTED_WASI_INTERFACE_MAPPINGS: [SelectedWasiInterfaceMapping; 5] = [
    SelectedWasiInterfaceMapping {
        interface: SELECTED_WASI_MONOTONIC_CLOCK_INTERFACE,
        direction: SelectedWasiInterfaceDirection::Import,
        category: SelectedWasiMappingCategory::Capability(SelectedWasiCapability::MonotonicClock),
    },
    SelectedWasiInterfaceMapping {
        interface: SELECTED_WASI_SECURE_RANDOM_INTERFACE,
        direction: SelectedWasiInterfaceDirection::Import,
        category: SelectedWasiMappingCategory::Capability(SelectedWasiCapability::SecureRandom),
    },
    SelectedWasiInterfaceMapping {
        interface: SELECTED_WASI_COMMAND_STDIN_INTERFACE,
        direction: SelectedWasiInterfaceDirection::Import,
        category: SelectedWasiMappingCategory::CommandStdin,
    },
    SelectedWasiInterfaceMapping {
        interface: SELECTED_WASI_COMMAND_STDOUT_INTERFACE,
        direction: SelectedWasiInterfaceDirection::Import,
        category: SelectedWasiMappingCategory::CommandStdout,
    },
    SelectedWasiInterfaceMapping {
        interface: SELECTED_WASI_INVOCATION_LIFECYCLE_INTERFACE,
        direction: SelectedWasiInterfaceDirection::Export,
        category: SelectedWasiMappingCategory::InvocationLifecycle,
    },
];

/// Scalar float value types selected by Profile 2's validation-only contract.
/// SIMD lanes and every adjacent numeric proposal remain outside this list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScalarFloatType {
    F32 = 1,
    F64 = 2,
}

pub const PROFILE_2_SYNC_FLOAT_SCALAR_TYPES: [ScalarFloatType; 2] =
    [ScalarFloatType::F32, ScalarFloatType::F64];

/// Closed instruction-path classes for deterministic scalar NaN handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FloatNaNOperationClass {
    /// Scalar arithmetic that creates or propagates a NaN.
    Arithmetic = 1,
    MinimumMaximum = 2,
    SquareRoot = 3,
    /// `ceil`, `floor`, `trunc`, and `nearest`.
    Rounding = 4,
    PromoteDemote = 5,
    /// Constant folding of an operation in one of the canonicalizing classes
    /// above. Folding value transport or sign-only operations remains in their
    /// respective classes.
    ConstantFold = 6,
    /// Bit-preserving Core value transport: constants, loads, stores,
    /// reinterpret, locals, globals, `select`, and Core calls/returns.
    ValueTransport = 7,
    /// `abs`, `neg`, and `copysign`.
    AbsoluteNegateCopySign = 8,
    /// Crossing the Component/Canonical ABI boundary, including scalar or
    /// nested values and Component calls/returns. Component-level floats have
    /// one abstract NaN, so lift collapses every Core NaN and lower emits the
    /// fixed canonical bits.
    CanonicalAbiBoundary = 9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FloatNaNDisposition {
    /// Produce the fixed positive canonical quiet NaN for the result width.
    FixedPositiveCanonicalQuiet = 1,
    /// Preserve every input bit, including sign and NaN payload.
    PreserveAllBits = 2,
    /// Preserve the payload and modify only the sign bit required by the op.
    PreservePayloadAndApplyOnlySpecifiedSign = 3,
}

/// Profile 2's strict deterministic software-float NaN contract. F1 freezes
/// this policy as validation metadata; a later node must implement and prove
/// every path before the profile may become runtime-ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FloatNaNPolicy {
    DeterministicCanonicalV1 = 1,
}

pub const PROFILE_2_SYNC_FLOAT_NAN_POLICY: FloatNaNPolicy =
    FloatNaNPolicy::DeterministicCanonicalV1;
pub const PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS: u32 = 0x7fc0_0000;
pub const PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS: u64 = 0x7ff8_0000_0000_0000;

impl FloatNaNPolicy {
    pub const fn disposition(self, class: FloatNaNOperationClass) -> FloatNaNDisposition {
        match self {
            Self::DeterministicCanonicalV1 => match class {
                FloatNaNOperationClass::Arithmetic
                | FloatNaNOperationClass::MinimumMaximum
                | FloatNaNOperationClass::SquareRoot
                | FloatNaNOperationClass::Rounding
                | FloatNaNOperationClass::PromoteDemote
                | FloatNaNOperationClass::ConstantFold
                | FloatNaNOperationClass::CanonicalAbiBoundary => {
                    FloatNaNDisposition::FixedPositiveCanonicalQuiet
                }
                FloatNaNOperationClass::ValueTransport => FloatNaNDisposition::PreserveAllBits,
                FloatNaNOperationClass::AbsoluteNegateCopySign => {
                    FloatNaNDisposition::PreservePayloadAndApplyOnlySpecifiedSign
                }
            },
        }
    }

    pub const fn canonical_f32_bits(self) -> u32 {
        match self {
            Self::DeterministicCanonicalV1 => PROFILE_2_SYNC_FLOAT_F32_CANONICAL_NAN_BITS,
        }
    }

    pub const fn canonical_f64_bits(self) -> u64 {
        match self {
            Self::DeterministicCanonicalV1 => PROFILE_2_SYNC_FLOAT_F64_CANONICAL_NAN_BITS,
        }
    }

    pub const fn software_float_required(self) -> bool {
        matches!(self, Self::DeterministicCanonicalV1)
    }

    pub const fn cross_target_bit_determinism_required(self) -> bool {
        matches!(self, Self::DeterministicCanonicalV1)
    }
}

/// Proposals and baseline value classes reviewed for the private Core profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreFeature {
    IntegerArithmetic,
    StructuredControl,
    Functions,
    Locals,
    Globals,
    LinearMemory,
    Tables,
    ImportsExports,
    Start,
    DataElements,
    Float,
    Simd,
    RelaxedSimd,
    ReferenceTypes,
    FunctionReferences,
    BulkMemory,
    MultiValue,
    TailCall,
    Threads,
    MultiMemory,
    Memory64,
    ExtendedConst,
    Exceptions,
    StackSwitching,
    GarbageCollection,
    CustomPageSizes,
    WideArithmetic,
}

impl CoreFeature {
    /// Permanently frozen Profile 1 feature decision. This method remains an
    /// alias for Profile 1 so adding later profiles cannot silently widen it.
    pub const fn enabled(self) -> bool {
        self.enabled_in_profile_1()
    }

    pub const fn enabled_in_profile_1(self) -> bool {
        matches!(
            self,
            Self::IntegerArithmetic
                | Self::StructuredControl
                | Self::Functions
                | Self::Locals
                | Self::Globals
                | Self::LinearMemory
                | Self::Tables
                | Self::ImportsExports
                | Self::DataElements
        )
    }

    pub const fn enabled_in_profile_2_sync_float(self) -> bool {
        self.enabled_in_profile_1() || matches!(self, Self::Float)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileLimits {
    /// Maximum raw code-artifact input admitted by Profile 1. This predates
    /// the C7 durable envelope and does not include its bounded metadata.
    pub max_artifact_bytes: usize,
    /// Maximum exact raw Component payload within either volatile admission or
    /// a canonical durable [`ComponentArtifactV1`] envelope.
    pub max_component_bytes: usize,
    pub max_core_module_bytes: usize,
    pub max_component_nesting: u32,
    pub max_core_nesting: u32,
    pub max_types: u32,
    pub max_functions: u32,
    pub max_params_per_function: u32,
    pub max_results_per_function: u32,
    pub max_imports: u32,
    pub max_exports: u32,
    pub max_globals: u32,
    pub max_locals_per_function: u32,
    pub max_memories: u32,
    pub max_initial_memory_pages: u32,
    pub max_memory_pages: u32,
    pub max_tables: u32,
    pub max_table_elements: u32,
    pub max_data_segments: u32,
    pub max_element_segments: u32,
    pub max_custom_sections: u32,
    /// Aggregate encoded custom-section payload bytes, including each name's
    /// length prefix, name, and data.
    pub max_custom_section_bytes: usize,
    pub max_embedded_modules: u32,
    pub max_component_instances: u32,
    pub max_component_definitions: u32,
    pub max_aliases: u32,
    pub max_canonical_functions: u32,
    pub max_canonical_options: u32,
    pub max_canonical_options_per_function: u32,
    pub max_async_functions: u32,
    pub max_future_types: u32,
    pub max_stream_types: u32,
    pub max_adapters: u32,
    pub max_resources: u32,
    pub max_call_depth: u32,
    pub max_canonical_value_bytes: usize,
    pub max_canonical_nesting: u32,
    pub max_canonical_values: u32,
    pub max_abi_allocations: u32,
    pub max_cleanup_actions: u32,
    pub max_string_bytes: usize,
    pub max_list_elements: u32,
    pub total_fuel: u64,
    pub poll_quantum: u64,
}

pub const PROFILE_1_LIMITS: ProfileLimits = ProfileLimits {
    max_artifact_bytes: 1024 * 1024,
    max_component_bytes: 1024 * 1024,
    max_core_module_bytes: 512 * 1024,
    max_component_nesting: 16,
    max_core_nesting: 128,
    max_types: 1024,
    max_functions: 1024,
    max_params_per_function: 32,
    max_results_per_function: 32,
    max_imports: 256,
    max_exports: 256,
    max_globals: 256,
    max_locals_per_function: 4096,
    max_memories: 1,
    max_initial_memory_pages: 16,
    max_memory_pages: 256,
    max_tables: 1,
    max_table_elements: 4096,
    max_data_segments: 256,
    max_element_segments: 256,
    max_custom_sections: 256,
    max_custom_section_bytes: 64 * 1024,
    max_embedded_modules: 8,
    max_component_instances: 16,
    max_component_definitions: 256,
    max_aliases: 256,
    max_canonical_functions: 256,
    max_canonical_options: 1024,
    max_canonical_options_per_function: 8,
    max_async_functions: 128,
    max_future_types: 128,
    max_stream_types: 128,
    max_adapters: 16,
    max_resources: 256,
    max_call_depth: 128,
    max_canonical_value_bytes: 64 * 1024,
    max_canonical_nesting: 32,
    max_canonical_values: 4096,
    max_abi_allocations: 256,
    max_cleanup_actions: 256,
    max_string_bytes: 64 * 1024,
    max_list_elements: 4096,
    total_fuel: 10_000_000,
    poll_quantum: 10_000,
};

/// Absolute aggregate ceilings for one inert C6 component-composition plan.
///
/// These are deliberately separate from [`PROFILE_1_LIMITS`]: those limits
/// describe one Component binary or instance, while these limits bound the
/// complete multi-principal graph before any graph-plan storage is allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphLimits {
    pub max_nodes: u64,
    pub max_edges: u64,
    pub max_nesting: u64,
    pub max_external_imports: u64,
    pub max_published_exports: u64,
    pub max_component_bytes: u64,
    pub max_core_instances: u64,
    pub max_adapters: u64,
    pub max_resource_types: u64,
    pub max_resource_slots: u64,
    pub max_memory_bytes: u64,
    pub max_total_fuel: u64,
    pub max_poll_quantum: u64,
}

pub const PROFILE_1_COMPONENT_GRAPH_LIMITS: ComponentGraphLimits = ComponentGraphLimits {
    max_nodes: 16,
    max_edges: 256,
    // Kept below the node ceiling so the containment-depth gate has an
    // independently testable failure boundary.
    max_nesting: 8,
    max_external_imports: PROFILE_1_LIMITS.max_imports as u64,
    max_published_exports: PROFILE_1_LIMITS.max_exports as u64,
    max_component_bytes: PROFILE_1_LIMITS.max_component_bytes as u64,
    max_core_instances: PROFILE_1_LIMITS.max_component_instances as u64,
    max_adapters: PROFILE_1_LIMITS.max_adapters as u64,
    max_resource_types: PROFILE_1_LIMITS.max_resources as u64,
    max_resource_slots: PROFILE_1_LIMITS.max_resources as u64,
    max_memory_bytes: PROFILE_1_LIMITS.max_memory_pages as u64 * 65_536,
    max_total_fuel: PROFILE_1_LIMITS.total_fuel,
    max_poll_quantum: PROFILE_1_LIMITS.poll_quantum,
};

/// Policy-selected volatile capacity for one graph node. These values carry no
/// admission authority; C6.2 must intersect them with the exact admitted node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComponentGraphInstanceBudget {
    pub resource_slots: u64,
    pub memory_bytes: u64,
    pub total_fuel: u64,
    pub poll_quantum: u64,
}

/// Complete charge for one node after runtime-owned component facts have been
/// combined with its requested instance budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComponentGraphNodeBudget {
    pub component_bytes: u64,
    pub core_instances: u64,
    pub adapters: u64,
    pub resource_types: u64,
    pub resource_slots: u64,
    pub memory_bytes: u64,
    pub total_fuel: u64,
    pub poll_quantum: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum TrapCode {
    Validation = 0x0100,
    UnsupportedFeature = 0x0101,
    LimitExceeded = 0x0102,
    Unreachable = 0x0200,
    IntegerDivisionByZero = 0x0201,
    IntegerOverflow = 0x0202,
    MemoryOutOfBounds = 0x0203,
    TableOutOfBounds = 0x0204,
    IndirectCallTypeMismatch = 0x0205,
    CallDepthExceeded = 0x0206,
    InvalidConversionToInteger = 0x0207,
    FuelExhausted = 0x0300,
    Cancelled = 0x0301,
    CanonicalAbi = 0x0400,
    ResourceMisuse = 0x0401,
}

impl TrapCode {
    /// Returns the stable 16-bit diagnostic projection for Component ABI and
    /// supervisor boundaries.
    pub const fn code(self) -> u16 {
        self as u16
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::UnsupportedFeature => "unsupported-feature",
            Self::LimitExceeded => "limit-exceeded",
            Self::Unreachable => "unreachable",
            Self::IntegerDivisionByZero => "integer-division-by-zero",
            Self::IntegerOverflow => "integer-overflow",
            Self::MemoryOutOfBounds => "memory-out-of-bounds",
            Self::TableOutOfBounds => "table-out-of-bounds",
            Self::IndirectCallTypeMismatch => "indirect-call-type-mismatch",
            Self::CallDepthExceeded => "call-depth-exceeded",
            Self::InvalidConversionToInteger => "invalid-conversion-to-integer",
            Self::FuelExhausted => "fuel-exhausted",
            Self::Cancelled => "cancelled",
            Self::CanonicalAbi => "canonical-abi",
            Self::ResourceMisuse => "resource-misuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    ArtifactBytes,
    ComponentBytes,
    CoreModuleBytes,
    Types,
    Functions,
    Parameters,
    Results,
    Imports,
    Exports,
    Globals,
    Locals,
    Memories,
    InitialMemoryPages,
    MemoryPages,
    Tables,
    TableElements,
    DataSegments,
    ElementSegments,
    CustomSections,
    CustomSectionBytes,
    EmbeddedModules,
    ComponentInstances,
    ComponentDefinitions,
    Aliases,
    CanonicalFunctions,
    CanonicalOptions,
    AsyncFunctions,
    FutureTypes,
    StreamTypes,
    Adapters,
    Resources,
    CanonicalValueBytes,
    CanonicalNesting,
    CanonicalValues,
    AbiAllocations,
    CleanupActions,
    StringBytes,
    ListElements,
    CoreNesting,
    EngineAllocationBytes,
    GraphNodes,
    GraphEdges,
    GraphNesting,
    GraphExternalImports,
    GraphPublishedExports,
    GraphComponentBytes,
    GraphCoreInstances,
    GraphAdapters,
    GraphResourceTypes,
    GraphResourceSlots,
    GraphMemoryBytes,
    GraphTotalFuel,
    GraphPollQuantum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitError {
    pub kind: LimitKind,
    pub attempted: u64,
    pub maximum: u64,
}

/// Allocation-independent aggregate accounting for one component graph.
///
/// Every mutating operation is transactional: a failed multi-field node charge
/// leaves the complete account unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComponentGraphAccount {
    pub nodes: u64,
    pub edges: u64,
    pub maximum_nesting: u64,
    pub external_imports: u64,
    pub published_exports: u64,
    pub component_bytes: u64,
    pub core_instances: u64,
    pub adapters: u64,
    pub resource_types: u64,
    pub resource_slots: u64,
    pub memory_bytes: u64,
    pub total_fuel: u64,
    pub maximum_poll_quantum: u64,
}

impl ComponentGraphAccount {
    fn added(current: u64, amount: u64, maximum: u64, kind: LimitKind) -> Result<u64, LimitError> {
        let attempted = current.checked_add(amount).ok_or(LimitError {
            kind,
            attempted: u64::MAX,
            maximum,
        })?;
        if attempted > maximum {
            return Err(LimitError {
                kind,
                attempted,
                maximum,
            });
        }
        Ok(attempted)
    }

    fn observed(
        current: u64,
        value: u64,
        maximum: u64,
        kind: LimitKind,
    ) -> Result<u64, LimitError> {
        if value > maximum {
            return Err(LimitError {
                kind,
                attempted: value,
                maximum,
            });
        }
        Ok(if value > current { value } else { current })
    }

    pub fn charge_node(&mut self, budget: ComponentGraphNodeBudget) -> Result<(), LimitError> {
        let limits = PROFILE_1_COMPONENT_GRAPH_LIMITS;
        let mut next = *self;
        next.nodes = Self::added(next.nodes, 1, limits.max_nodes, LimitKind::GraphNodes)?;
        next.component_bytes = Self::added(
            next.component_bytes,
            budget.component_bytes,
            limits.max_component_bytes,
            LimitKind::GraphComponentBytes,
        )?;
        next.core_instances = Self::added(
            next.core_instances,
            budget.core_instances,
            limits.max_core_instances,
            LimitKind::GraphCoreInstances,
        )?;
        next.adapters = Self::added(
            next.adapters,
            budget.adapters,
            limits.max_adapters,
            LimitKind::GraphAdapters,
        )?;
        next.resource_types = Self::added(
            next.resource_types,
            budget.resource_types,
            limits.max_resource_types,
            LimitKind::GraphResourceTypes,
        )?;
        next.resource_slots = Self::added(
            next.resource_slots,
            budget.resource_slots,
            limits.max_resource_slots,
            LimitKind::GraphResourceSlots,
        )?;
        next.memory_bytes = Self::added(
            next.memory_bytes,
            budget.memory_bytes,
            limits.max_memory_bytes,
            LimitKind::GraphMemoryBytes,
        )?;
        next.total_fuel = Self::added(
            next.total_fuel,
            budget.total_fuel,
            limits.max_total_fuel,
            LimitKind::GraphTotalFuel,
        )?;
        next.maximum_poll_quantum = Self::observed(
            next.maximum_poll_quantum,
            budget.poll_quantum,
            limits.max_poll_quantum,
            LimitKind::GraphPollQuantum,
        )?;
        *self = next;
        Ok(())
    }

    pub fn observe_nesting(&mut self, depth: u64) -> Result<(), LimitError> {
        self.maximum_nesting = Self::observed(
            self.maximum_nesting,
            depth,
            PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting,
            LimitKind::GraphNesting,
        )?;
        Ok(())
    }

    pub fn charge_edges(&mut self, amount: u64) -> Result<(), LimitError> {
        self.edges = Self::added(
            self.edges,
            amount,
            PROFILE_1_COMPONENT_GRAPH_LIMITS.max_edges,
            LimitKind::GraphEdges,
        )?;
        Ok(())
    }

    pub fn charge_external_imports(&mut self, amount: u64) -> Result<(), LimitError> {
        self.external_imports = Self::added(
            self.external_imports,
            amount,
            PROFILE_1_COMPONENT_GRAPH_LIMITS.max_external_imports,
            LimitKind::GraphExternalImports,
        )?;
        Ok(())
    }

    pub fn charge_published_exports(&mut self, amount: u64) -> Result<(), LimitError> {
        self.published_exports = Self::added(
            self.published_exports,
            amount,
            PROFILE_1_COMPONENT_GRAPH_LIMITS.max_published_exports,
            LimitKind::GraphPublishedExports,
        )?;
        Ok(())
    }
}

/// Allocation-independent counters used while streaming an untrusted binary.
///
/// Callers charge a declared length or count before reserving storage for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValidationAccount {
    pub artifact_bytes: u64,
    pub component_bytes: u64,
    pub embedded_module_bytes: u64,
    pub types: u64,
    pub functions: u64,
    pub imports: u64,
    pub exports: u64,
    pub resources: u64,
    pub canonical_options: u64,
    pub async_functions: u64,
    pub future_types: u64,
    pub stream_types: u64,
}

impl ValidationAccount {
    fn charge(
        value: &mut u64,
        amount: u64,
        maximum: u64,
        kind: LimitKind,
    ) -> Result<(), LimitError> {
        let attempted = value.checked_add(amount).ok_or(LimitError {
            kind,
            attempted: u64::MAX,
            maximum,
        })?;
        if attempted > maximum {
            return Err(LimitError {
                kind,
                attempted,
                maximum,
            });
        }
        *value = attempted;
        Ok(())
    }

    pub fn charge_artifact_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        Self::charge(
            &mut self.artifact_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_artifact_bytes as u64,
            LimitKind::ArtifactBytes,
        )
    }

    pub fn charge_component_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        Self::charge(
            &mut self.component_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_component_bytes as u64,
            LimitKind::ComponentBytes,
        )
    }

    pub fn charge_embedded_module_bytes(&mut self, amount: usize) -> Result<(), LimitError> {
        if amount > PROFILE_1_LIMITS.max_core_module_bytes {
            return Err(LimitError {
                kind: LimitKind::CoreModuleBytes,
                attempted: amount as u64,
                maximum: PROFILE_1_LIMITS.max_core_module_bytes as u64,
            });
        }
        Self::charge(
            &mut self.embedded_module_bytes,
            amount as u64,
            PROFILE_1_LIMITS.max_component_bytes as u64,
            LimitKind::CoreModuleBytes,
        )
    }

    pub fn charge_types(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.types,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_types),
            LimitKind::Types,
        )
    }

    pub fn charge_functions(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.functions,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_functions),
            LimitKind::Functions,
        )
    }

    pub fn charge_imports(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.imports,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_imports),
            LimitKind::Imports,
        )
    }

    pub fn charge_exports(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.exports,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_exports),
            LimitKind::Exports,
        )
    }

    pub fn charge_resources(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.resources,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_resources),
            LimitKind::Resources,
        )
    }

    pub fn charge_canonical_options(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.canonical_options,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_canonical_options),
            LimitKind::CanonicalOptions,
        )
    }

    pub fn charge_async_functions(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.async_functions,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_async_functions),
            LimitKind::AsyncFunctions,
        )
    }

    pub fn charge_future_types(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.future_types,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_future_types),
            LimitKind::FutureTypes,
        )
    }

    pub fn charge_stream_types(&mut self, amount: u32) -> Result<(), LimitError> {
        Self::charge(
            &mut self.stream_types,
            u64::from(amount),
            u64::from(PROFILE_1_LIMITS.max_stream_types),
            LimitKind::StreamTypes,
        )
    }
}

const _: () = assert!(PROFILE_1_LIMITS.poll_quantum > 0);
const _: () = assert!(PROFILE_1_LIMITS.poll_quantum < PROFILE_1_LIMITS.total_fuel);
const _: () = assert!(PROFILE_1_LIMITS.max_memories == 1);
const _: () =
    assert!(PROFILE_1_LIMITS.max_initial_memory_pages <= PROFILE_1_LIMITS.max_memory_pages);
const _: () = assert!(PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes <= u16::MAX as u64);
const _: () = assert!(PROFILE_1_LIMITS.max_imports <= u16::MAX as u32 + 1);
const _: () = assert!(PROFILE_1_LIMITS.max_exports <= u16::MAX as u32 + 1);
const _: () = assert!(PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting > 0);
const _: () = assert!(
    PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nesting < PROFILE_1_COMPONENT_GRAPH_LIMITS.max_nodes
);
const _: () = assert!(
    PROFILE_1_COMPONENT_GRAPH_LIMITS.max_poll_quantum
        <= PROFILE_1_COMPONENT_GRAPH_LIMITS.max_total_fuel
);
