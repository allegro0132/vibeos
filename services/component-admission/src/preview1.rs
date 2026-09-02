//! Closed, validation-only admission for an off-device Preview1 wrapper.
//!
//! This module is intentionally independent of ordinary, authenticated,
//! selected-WASI, and loader admission. It consumes one already canonical
//! artifact envelope, revalidates the live Component and every embedded Core
//! module with the pinned wasmparser frontend, and retains no executable plan.

use alloc::{string::String, vec::Vec};
use core::{fmt, ops::Range};

use sha2::{Digest, Sha256};
use vibeos_component_format::{
    ComponentArtifactCoreModuleV1, ComponentArtifactSignerPolicyKind, ComponentArtifactV1,
    ProfileIdentity, PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256, PREVIEW1_WRAPPED_ADAPTER_REVISION, PROFILE_1_LIMITS,
};
use wasmparser::{
    CanonicalFunction, ComponentExternalKind, Encoding, Parser, Payload, TypeRef, ValType,
    Validator, WasmFeatures,
};

use crate::{private, AdmissionError};
use vibeos_wasm_runtime::inspect_core;

const PREVIEW1_MODULE: &str = "wasi_snapshot_preview1";
const PREVIEW1_FD_WRITE: &str = "fd_write";
const PREVIEW1_START: &str = "_start";
const PREVIEW1_WRAPPED_GUEST_MODULE_ORDINAL: u32 = 0;
const PREVIEW1_WRAPPED_PRUNED_ADAPTER_MODULE_ORDINAL: u32 = 1;
const PREVIEW1_WRAPPED_IMPORTS: [&str; 8] = [
    "wasi:io/error@0.2.12",
    "wasi:io/streams@0.2.12",
    "wasi:cli/stdin@0.2.12",
    "wasi:cli/stdout@0.2.12",
    "wasi:cli/stderr@0.2.12",
    "wasi:clocks/wall-clock@0.2.12",
    "wasi:filesystem/types@0.2.12",
    "wasi:filesystem/preopens@0.2.12",
];
const PREVIEW1_WRAPPED_EXPORT: &str = "wasi:cli/run@0.2.12";
const LOWERING_FINGERPRINT_DOMAIN: &[u8] = b"vibeos.preview1-wrapped.canonical-lowerings.v1\0";

/// The deliberately tiny Core value vocabulary admitted for the C8.1 guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview1CoreValueType {
    I32,
}

/// Exact raw module pin in Component traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview1WrappedCoreModulePin {
    pub byte_len: u32,
    pub sha256: [u8; 32],
}

/// Exact guest function import and Core signature selected by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview1GuestFunctionImportPin<'a> {
    pub module: &'a str,
    pub name: &'a str,
    pub params: &'a [Preview1CoreValueType],
    pub results: &'a [Preview1CoreValueType],
}

/// Direction of one top-level Component entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Preview1WrappedEntityDirection {
    Import,
    Export,
}

/// Live wasmparser kind of one top-level Component entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Preview1WrappedEntityKind {
    Module,
    Function,
    Value,
    Type,
    Component,
    Instance,
}

/// Exact top-level name/direction plus SHA-256 of its raw canonical entry.
///
/// The fingerprint is computed over the entry bytes returned by wasmparser,
/// excluding only the enclosing section count. The whole-artifact commitment
/// additionally pins every referenced type definition and nominal identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview1WrappedTopLevelEntityPin<'a> {
    pub direction: Preview1WrappedEntityDirection,
    pub kind: Preview1WrappedEntityKind,
    pub name: &'a str,
    pub raw_entry_sha256: [u8; 32],
}

/// Explicit host policy for exactly one immutable Preview1-wrapped artifact.
///
/// No field is inferred from descriptor text. In particular, manifest adapter
/// bytes and interface diagnostic shapes are never semantic authority: fresh
/// parser evidence must independently match all pins below.
pub struct Preview1WrappedAdmissionPolicy<'a> {
    pub artifact_commitment: [u8; 32],
    pub external_policy_digest: [u8; 32],
    pub adapter_revision: &'a str,
    /// Ordinal of the pruned adapter-derived Core module in the wrapped
    /// Component topology. It is intentionally distinct from the release
    /// asset bytes below.
    pub adapter_embedded_module_ordinal: u32,
    pub adapter_asset_byte_len: u32,
    pub adapter_asset_sha256: [u8; 32],
    pub guest_module_ordinal: u32,
    pub guest_module_byte_len: u32,
    pub guest_module_sha256: [u8; 32],
    pub embedded_modules: &'a [Preview1WrappedCoreModulePin],
    pub guest_function_imports: &'a [Preview1GuestFunctionImportPin<'a>],
    pub top_level_entities: &'a [Preview1WrappedTopLevelEntityPin<'a>],
    /// SHA-256 over `LOWERING_FINGERPRINT_DOMAIN`, followed in top-level
    /// traversal order by each lowering entry's little-endian u64 length and
    /// exact raw bytes.
    pub canonical_lowering_sha256: [u8; 32],
    pub canonical_lowering_count: u32,
    pub nested_component_count: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Preview1GuestFunctionImportDiagnostic {
    module: String,
    name: String,
    params: Vec<Preview1CoreValueType>,
    results: Vec<Preview1CoreValueType>,
}

impl Preview1GuestFunctionImportDiagnostic {
    pub fn module(&self) -> &str {
        &self.module
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn params(&self) -> &[Preview1CoreValueType] {
        &self.params
    }

    pub fn results(&self) -> &[Preview1CoreValueType] {
        &self.results
    }
}

#[derive(PartialEq, Eq)]
pub struct Preview1WrappedTopLevelEntityDiagnostic {
    direction: Preview1WrappedEntityDirection,
    kind: Preview1WrappedEntityKind,
    name: String,
    raw_entry_sha256: [u8; 32],
}

impl Preview1WrappedTopLevelEntityDiagnostic {
    pub const fn direction(&self) -> Preview1WrappedEntityDirection {
        self.direction
    }

    pub const fn kind(&self) -> Preview1WrappedEntityKind {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Read-only evidence retained by a validation-only candidate.
#[derive(PartialEq, Eq)]
pub struct Preview1WrappedAdmissionDiagnostics {
    artifact_commitment: [u8; 32],
    external_policy_digest: [u8; 32],
    adapter_revision: String,
    adapter_embedded_module_ordinal: u32,
    adapter_asset_byte_len: u32,
    adapter_asset_sha256: [u8; 32],
    guest_module_ordinal: u32,
    guest_module_byte_len: u32,
    guest_module_sha256: [u8; 32],
    embedded_modules: Vec<Preview1WrappedCoreModulePin>,
    guest_function_imports: Vec<Preview1GuestFunctionImportDiagnostic>,
    top_level_entities: Vec<Preview1WrappedTopLevelEntityDiagnostic>,
    canonical_lowering_sha256: [u8; 32],
    canonical_lowering_count: u32,
    nested_component_count: u32,
}

impl Preview1WrappedAdmissionDiagnostics {
    pub fn adapter_revision(&self) -> &str {
        &self.adapter_revision
    }

    pub const fn adapter_embedded_module_ordinal(&self) -> u32 {
        self.adapter_embedded_module_ordinal
    }

    pub const fn adapter_asset_byte_len(&self) -> u32 {
        self.adapter_asset_byte_len
    }

    pub const fn guest_module_ordinal(&self) -> u32 {
        self.guest_module_ordinal
    }

    pub const fn guest_module_byte_len(&self) -> u32 {
        self.guest_module_byte_len
    }

    pub fn embedded_module_count(&self) -> usize {
        self.embedded_modules.len()
    }

    pub fn embedded_module_byte_len(&self, ordinal: usize) -> Option<u32> {
        self.embedded_modules
            .get(ordinal)
            .map(|module| module.byte_len)
    }

    pub fn guest_function_imports(&self) -> &[Preview1GuestFunctionImportDiagnostic] {
        &self.guest_function_imports
    }

    pub fn top_level_entities(&self) -> &[Preview1WrappedTopLevelEntityDiagnostic] {
        &self.top_level_entities
    }

    pub const fn canonical_lowering_count(&self) -> u32 {
        self.canonical_lowering_count
    }

    pub const fn nested_component_count(&self) -> u32 {
        self.nested_component_count
    }
}

impl fmt::Debug for Preview1WrappedTopLevelEntityDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preview1WrappedTopLevelEntityDiagnostic")
            .field("direction", &self.direction)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("raw_entry_sha256", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for Preview1WrappedAdmissionDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preview1WrappedAdmissionDiagnostics")
            .field("artifact_commitment", &"<redacted>")
            .field("external_policy_digest", &"<redacted>")
            .field("adapter_revision", &self.adapter_revision)
            .field(
                "adapter_embedded_module_ordinal",
                &self.adapter_embedded_module_ordinal,
            )
            .field("adapter_asset_byte_len", &self.adapter_asset_byte_len)
            .field("adapter_asset_sha256", &"<redacted>")
            .field("guest_module_ordinal", &self.guest_module_ordinal)
            .field("guest_module_byte_len", &self.guest_module_byte_len)
            .field("guest_module_sha256", &"<redacted>")
            .field("embedded_module_count", &self.embedded_modules.len())
            .field("guest_function_imports", &self.guest_function_imports)
            .field("top_level_entities", &self.top_level_entities)
            .field("canonical_lowering_sha256", &"<redacted>")
            .field("canonical_lowering_count", &self.canonical_lowering_count)
            .field("nested_component_count", &self.nested_component_count)
            .finish()
    }
}

/// Sealed, move-only, permanently inert C8.1 admission result.
///
/// It exposes diagnostics and fresh revalidation only. There is no artifact
/// byte accessor, executable plan, command manifest, grant table, runner,
/// resource handle, activation conversion, or cloning surface.
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn duplicate(candidate: AdmittedPreview1WrappedCandidate) {
///     let _ = candidate.clone();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn raw_bytes(candidate: &AdmittedPreview1WrappedCandidate) {
///     let _ = candidate.bytes();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn executable(candidate: &AdmittedPreview1WrappedCandidate) {
///     let _ = candidate.validated_plan();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn authority(candidate: &AdmittedPreview1WrappedCandidate) {
///     let _ = candidate.grants();
///     let _ = candidate.command_manifest();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn durable_ids(candidate: &AdmittedPreview1WrappedCandidate) {
///     let diagnostics = candidate.diagnostics();
///     let _ = diagnostics.artifact_commitment();
///     let _ = diagnostics.external_policy_digest();
///     let _ = diagnostics.adapter_asset_sha256();
///     let _ = diagnostics.guest_module_sha256();
///     let _ = diagnostics.canonical_lowering_sha256();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn raw_entity_fingerprint(candidate: &AdmittedPreview1WrappedCandidate) {
///     let entity = &candidate.diagnostics().top_level_entities()[0];
///     let _ = entity.raw_entry_sha256();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::{
///     AdmittedComponent, AdmittedPreview1WrappedCandidate,
/// };
/// fn activate(candidate: AdmittedPreview1WrappedCandidate) -> AdmittedComponent {
///     candidate.into()
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1WrappedCandidate;
/// fn forge() -> AdmittedPreview1WrappedCandidate {
///     AdmittedPreview1WrappedCandidate {
///         artifact: panic!(),
///         policy: panic!(),
///         diagnostics: panic!(),
///         _sealed: panic!(),
///     }
/// }
/// ```
pub struct AdmittedPreview1WrappedCandidate {
    artifact: ComponentArtifactV1,
    policy: Preview1WrappedPolicySnapshot,
    diagnostics: Preview1WrappedAdmissionDiagnostics,
    _sealed: private::Seal,
}

impl AdmittedPreview1WrappedCandidate {
    pub const fn profile(&self) -> ProfileIdentity {
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
    }

    pub fn diagnostics(&self) -> &Preview1WrappedAdmissionDiagnostics {
        &self.diagnostics
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// Admission and revalidation never invoke guest code.
    pub const fn guest_calls(&self) -> u64 {
        0
    }

    pub fn revalidate(&self) -> Result<(), AdmissionError> {
        let observed = validate_artifact(
            &self.artifact,
            &self.policy,
            AdmissionError::RevalidationMismatch,
        )?;
        if observed != self.diagnostics {
            return Err(AdmissionError::RevalidationMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for AdmittedPreview1WrappedCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedPreview1WrappedCandidate")
            .field("profile", &ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED)
            .field("diagnostics", &self.diagnostics)
            .field("runtime_ready", &false)
            .field("guest_calls", &0_u64)
            .finish()
    }
}

/// Freshly validate and seal one exact host-produced Preview1 wrapper.
pub fn admit_preview1_wrapped_candidate(
    artifact: ComponentArtifactV1,
    policy: &Preview1WrappedAdmissionPolicy<'_>,
) -> Result<AdmittedPreview1WrappedCandidate, AdmissionError> {
    let policy = Preview1WrappedPolicySnapshot::new(policy)?;
    let diagnostics = validate_artifact(&artifact, &policy, AdmissionError::InvalidPolicy)?;
    let candidate = AdmittedPreview1WrappedCandidate {
        artifact,
        policy,
        diagnostics,
        _sealed: private::Seal,
    };
    candidate.revalidate()?;
    Ok(candidate)
}

#[derive(PartialEq, Eq)]
struct Preview1WrappedPolicySnapshot {
    artifact_commitment: [u8; 32],
    external_policy_digest: [u8; 32],
    adapter_revision: String,
    adapter_embedded_module_ordinal: u32,
    adapter_asset_byte_len: u32,
    adapter_asset_sha256: [u8; 32],
    guest_module_ordinal: u32,
    guest_module_byte_len: u32,
    guest_module_sha256: [u8; 32],
    embedded_modules: Vec<Preview1WrappedCoreModulePin>,
    guest_function_imports: Vec<OwnedGuestFunctionImportPin>,
    top_level_entities: Vec<OwnedTopLevelEntityPin>,
    canonical_lowering_sha256: [u8; 32],
    canonical_lowering_count: u32,
    nested_component_count: u32,
}

#[derive(PartialEq, Eq)]
struct OwnedGuestFunctionImportPin {
    module: String,
    name: String,
    params: Vec<Preview1CoreValueType>,
    results: Vec<Preview1CoreValueType>,
}

#[derive(PartialEq, Eq)]
struct OwnedTopLevelEntityPin {
    direction: Preview1WrappedEntityDirection,
    kind: Preview1WrappedEntityKind,
    name: String,
    raw_entry_sha256: [u8; 32],
}

impl Preview1WrappedPolicySnapshot {
    fn new(policy: &Preview1WrappedAdmissionPolicy<'_>) -> Result<Self, AdmissionError> {
        if zero_hash(&policy.artifact_commitment)
            || zero_hash(&policy.external_policy_digest)
            || zero_hash(&policy.adapter_asset_sha256)
            || zero_hash(&policy.guest_module_sha256)
            || zero_hash(&policy.canonical_lowering_sha256)
            || policy.adapter_asset_byte_len == 0
            || policy.guest_module_byte_len == 0
            || policy.adapter_embedded_module_ordinal == policy.guest_module_ordinal
            || policy.adapter_embedded_module_ordinal
                != PREVIEW1_WRAPPED_PRUNED_ADAPTER_MODULE_ORDINAL
            || policy.guest_module_ordinal != PREVIEW1_WRAPPED_GUEST_MODULE_ORDINAL
            || policy.canonical_lowering_count == 0
            || policy.canonical_lowering_count > PROFILE_1_LIMITS.max_canonical_functions
            || policy.nested_component_count > PROFILE_1_LIMITS.max_component_nesting
            || !valid_token(policy.adapter_revision, 512)
            || policy.adapter_revision != PREVIEW1_WRAPPED_ADAPTER_REVISION
            || policy.adapter_asset_byte_len as usize != PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN
            || policy.adapter_asset_sha256 != PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256
            || policy.embedded_modules.len() != 4
            || policy.top_level_entities.len()
                > (PROFILE_1_LIMITS.max_imports as usize + PROFILE_1_LIMITS.max_exports as usize)
        {
            return Err(AdmissionError::InvalidPolicy);
        }

        let adapter_index = usize::try_from(policy.adapter_embedded_module_ordinal)
            .map_err(|_| AdmissionError::InvalidPolicy)?;
        let guest_index = usize::try_from(policy.guest_module_ordinal)
            .map_err(|_| AdmissionError::InvalidPolicy)?;
        if policy.embedded_modules.get(adapter_index).is_none() {
            return Err(AdmissionError::InvalidPolicy);
        }
        let Some(guest_pin) = policy.embedded_modules.get(guest_index) else {
            return Err(AdmissionError::InvalidPolicy);
        };
        if guest_pin.byte_len != policy.guest_module_byte_len
            || guest_pin.sha256 != policy.guest_module_sha256
            || policy
                .embedded_modules
                .iter()
                .any(|pin| pin.byte_len == 0 || zero_hash(&pin.sha256))
        {
            return Err(AdmissionError::InvalidPolicy);
        }

        if policy.guest_function_imports.len() != 1 {
            return Err(AdmissionError::InvalidPolicy);
        }
        let guest_import = policy.guest_function_imports[0];
        if guest_import.module != PREVIEW1_MODULE
            || guest_import.name != PREVIEW1_FD_WRITE
            || guest_import.params != [Preview1CoreValueType::I32; 4]
            || guest_import.results != [Preview1CoreValueType::I32]
        {
            return Err(AdmissionError::InvalidPolicy);
        }

        if !exact_top_level_surface(policy.top_level_entities) {
            return Err(AdmissionError::InvalidPolicy);
        }
        for (index, pin) in policy.top_level_entities.iter().enumerate() {
            if !valid_token(pin.name, 512)
                || zero_hash(&pin.raw_entry_sha256)
                || policy.top_level_entities[..index]
                    .iter()
                    .any(|prior| prior.direction == pin.direction && prior.name == pin.name)
            {
                return Err(AdmissionError::InvalidPolicy);
            }
        }

        let mut embedded_modules = Vec::new();
        embedded_modules
            .try_reserve_exact(policy.embedded_modules.len())
            .map_err(|_| AdmissionError::Allocation)?;
        embedded_modules.extend_from_slice(policy.embedded_modules);

        let mut guest_function_imports = Vec::new();
        guest_function_imports
            .try_reserve_exact(1)
            .map_err(|_| AdmissionError::Allocation)?;
        guest_function_imports.push(OwnedGuestFunctionImportPin {
            module: copied(guest_import.module)?,
            name: copied(guest_import.name)?,
            params: copied_values(guest_import.params)?,
            results: copied_values(guest_import.results)?,
        });

        let mut top_level_entities = Vec::new();
        top_level_entities
            .try_reserve_exact(policy.top_level_entities.len())
            .map_err(|_| AdmissionError::Allocation)?;
        for pin in policy.top_level_entities {
            top_level_entities.push(OwnedTopLevelEntityPin {
                direction: pin.direction,
                kind: pin.kind,
                name: copied(pin.name)?,
                raw_entry_sha256: pin.raw_entry_sha256,
            });
        }
        top_level_entities.sort_unstable_by(|left, right| {
            left.direction
                .cmp(&right.direction)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.kind.cmp(&right.kind))
        });

        Ok(Self {
            artifact_commitment: policy.artifact_commitment,
            external_policy_digest: policy.external_policy_digest,
            adapter_revision: copied(policy.adapter_revision)?,
            adapter_embedded_module_ordinal: policy.adapter_embedded_module_ordinal,
            adapter_asset_byte_len: policy.adapter_asset_byte_len,
            adapter_asset_sha256: policy.adapter_asset_sha256,
            guest_module_ordinal: policy.guest_module_ordinal,
            guest_module_byte_len: policy.guest_module_byte_len,
            guest_module_sha256: policy.guest_module_sha256,
            embedded_modules,
            guest_function_imports,
            top_level_entities,
            canonical_lowering_sha256: policy.canonical_lowering_sha256,
            canonical_lowering_count: policy.canonical_lowering_count,
            nested_component_count: policy.nested_component_count,
        })
    }
}

fn exact_top_level_surface(pins: &[Preview1WrappedTopLevelEntityPin<'_>]) -> bool {
    if pins.len() != PREVIEW1_WRAPPED_IMPORTS.len() + 1 {
        return false;
    }
    for expected in PREVIEW1_WRAPPED_IMPORTS {
        if pins
            .iter()
            .filter(|pin| {
                pin.direction == Preview1WrappedEntityDirection::Import
                    && pin.kind == Preview1WrappedEntityKind::Instance
                    && pin.name == expected
            })
            .count()
            != 1
        {
            return false;
        }
    }
    pins.iter()
        .filter(|pin| {
            pin.direction == Preview1WrappedEntityDirection::Export
                && pin.kind == Preview1WrappedEntityKind::Instance
                && pin.name == PREVIEW1_WRAPPED_EXPORT
        })
        .count()
        == 1
}

fn validate_artifact(
    artifact: &ComponentArtifactV1,
    policy: &Preview1WrappedPolicySnapshot,
    mismatch: AdmissionError,
) -> Result<Preview1WrappedAdmissionDiagnostics, AdmissionError> {
    let profile = artifact.profile();
    if profile != ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
        || profile.execution_enabled()
        || artifact.runtime_ready()
        || artifact.signer_policy().kind() != ComponentArtifactSignerPolicyKind::DevelopmentImagePin
    {
        return Err(mismatch);
    }
    let commitment = artifact.artifact_commitment().map_err(|_| mismatch)?;
    if commitment.as_bytes() != &policy.artifact_commitment
        || artifact.signer_policy().policy_digest().as_bytes() != &policy.external_policy_digest
    {
        return Err(mismatch);
    }

    let bytes = artifact.component_bytes();
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map_err(|_| mismatch)?;
    let observed = inspect_component(bytes, mismatch)?;
    if observed.embedded_modules != policy.embedded_modules
        || observed.top_level_entities != policy.top_level_entities
        || observed.canonical_lowering_sha256 != policy.canonical_lowering_sha256
        || observed.canonical_lowering_count != policy.canonical_lowering_count
        || observed.nested_component_count != policy.nested_component_count
    {
        return Err(mismatch);
    }

    let guest_index = usize::try_from(policy.guest_module_ordinal).map_err(|_| mismatch)?;
    let guest_bytes = observed.module_bytes.get(guest_index).ok_or(mismatch)?;
    if usize_u32(guest_bytes.len())? != policy.guest_module_byte_len
        || raw_sha256(guest_bytes) != policy.guest_module_sha256
    {
        return Err(mismatch);
    }

    let manifest = artifact.manifest();
    if manifest.core_modules().len() != observed.module_bytes.len()
        || manifest.adapters().len() != 1
    {
        return Err(mismatch);
    }
    for (raw, descriptor) in observed.module_bytes.iter().zip(manifest.core_modules()) {
        let fresh = ComponentArtifactCoreModuleV1::from_bytes(raw).map_err(|_| mismatch)?;
        if &fresh != descriptor {
            return Err(mismatch);
        }
    }
    let adapter = &manifest.adapters()[0];
    if adapter.ordinal() != 0
        || adapter.revision() != policy.adapter_revision
        || usize_u32(adapter.bytes().len())? != policy.adapter_asset_byte_len
        || raw_sha256(adapter.bytes()) != policy.adapter_asset_sha256
    {
        return Err(mismatch);
    }

    let guest_function_imports = validate_guest_module(guest_bytes, policy, mismatch)?;

    let mut guest_diagnostics = Vec::new();
    guest_diagnostics
        .try_reserve_exact(guest_function_imports.len())
        .map_err(|_| AdmissionError::Allocation)?;
    for import in guest_function_imports {
        guest_diagnostics.push(Preview1GuestFunctionImportDiagnostic::from(import));
    }
    let mut entity_diagnostics = Vec::new();
    entity_diagnostics
        .try_reserve_exact(observed.top_level_entities.len())
        .map_err(|_| AdmissionError::Allocation)?;
    for entity in observed.top_level_entities {
        entity_diagnostics.push(Preview1WrappedTopLevelEntityDiagnostic::from(entity));
    }

    Ok(Preview1WrappedAdmissionDiagnostics {
        artifact_commitment: policy.artifact_commitment,
        external_policy_digest: policy.external_policy_digest,
        adapter_revision: copied(&policy.adapter_revision)?,
        adapter_embedded_module_ordinal: policy.adapter_embedded_module_ordinal,
        adapter_asset_byte_len: policy.adapter_asset_byte_len,
        adapter_asset_sha256: policy.adapter_asset_sha256,
        guest_module_ordinal: policy.guest_module_ordinal,
        guest_module_byte_len: policy.guest_module_byte_len,
        guest_module_sha256: policy.guest_module_sha256,
        embedded_modules: observed.embedded_modules,
        guest_function_imports: guest_diagnostics,
        top_level_entities: entity_diagnostics,
        canonical_lowering_sha256: observed.canonical_lowering_sha256,
        canonical_lowering_count: observed.canonical_lowering_count,
        nested_component_count: observed.nested_component_count,
    })
}

struct ObservedComponent<'a> {
    module_bytes: Vec<&'a [u8]>,
    embedded_modules: Vec<Preview1WrappedCoreModulePin>,
    top_level_entities: Vec<OwnedTopLevelEntityPin>,
    canonical_lowering_sha256: [u8; 32],
    canonical_lowering_count: u32,
    nested_component_count: u32,
}

fn inspect_component(
    bytes: &[u8],
    mismatch: AdmissionError,
) -> Result<ObservedComponent<'_>, AdmissionError> {
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::all());
    let mut encodings = Vec::new();
    let mut module_bytes = Vec::new();
    let mut embedded_modules = Vec::new();
    let mut top_level_entities = Vec::new();
    let mut lowering_hasher = Sha256::new();
    lowering_hasher.update(LOWERING_FINGERPRINT_DOMAIN);
    let mut lowering_count = 0_u32;
    let mut nested_component_count = 0_u32;
    let mut saw_top = false;

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|_| mismatch)?;
        match payload {
            Payload::Version { encoding, .. } => {
                if !saw_top {
                    if encoding != Encoding::Component {
                        return Err(mismatch);
                    }
                    saw_top = true;
                }
                encodings
                    .try_reserve(1)
                    .map_err(|_| AdmissionError::Allocation)?;
                encodings.push(encoding);
            }
            Payload::End(_) => {
                if encodings.pop().is_none() {
                    return Err(mismatch);
                }
            }
            Payload::ModuleSection {
                unchecked_range, ..
            } => {
                let raw = checked_range(bytes, unchecked_range, mismatch)?;
                Validator::new_with_features(WasmFeatures::all())
                    .validate_all(raw)
                    .map_err(|_| mismatch)?;
                module_bytes
                    .try_reserve(1)
                    .map_err(|_| AdmissionError::Allocation)?;
                embedded_modules
                    .try_reserve(1)
                    .map_err(|_| AdmissionError::Allocation)?;
                module_bytes.push(raw);
                embedded_modules.push(Preview1WrappedCoreModulePin {
                    byte_len: usize_u32(raw.len())?,
                    sha256: raw_sha256(raw),
                });
            }
            Payload::ComponentSection { .. } => {
                nested_component_count = nested_component_count.checked_add(1).ok_or(mismatch)?;
            }
            Payload::ComponentImportSection(reader) if encodings.len() == 1 => {
                collect_top_level_imports(bytes, reader, &mut top_level_entities, mismatch)?;
            }
            Payload::ComponentExportSection(reader) if encodings.len() == 1 => {
                collect_top_level_exports(bytes, reader, &mut top_level_entities, mismatch)?;
            }
            Payload::ComponentCanonicalSection(reader) if encodings.len() == 1 => {
                collect_lowerings(
                    bytes,
                    reader,
                    &mut lowering_hasher,
                    &mut lowering_count,
                    mismatch,
                )?
            }
            Payload::UnknownSection { .. } => return Err(mismatch),
            _ => {}
        }
    }
    if !saw_top || !encodings.is_empty() {
        return Err(mismatch);
    }
    top_level_entities.sort_unstable_by(|left, right| {
        left.direction
            .cmp(&right.direction)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    for pair in top_level_entities.windows(2) {
        if pair[0].direction == pair[1].direction && pair[0].name == pair[1].name {
            return Err(mismatch);
        }
    }

    Ok(ObservedComponent {
        module_bytes,
        embedded_modules,
        top_level_entities,
        canonical_lowering_sha256: lowering_hasher.finalize().into(),
        canonical_lowering_count: lowering_count,
        nested_component_count,
    })
}

fn collect_top_level_imports(
    bytes: &[u8],
    reader: wasmparser::ComponentImportSectionReader<'_>,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let section_end = reader.range().end;
    let mut previous = None;
    for item in reader.into_iter_with_offsets() {
        let (offset, import) = item.map_err(|_| mismatch)?;
        if let Some((start, prior)) = previous.take() {
            push_import(bytes, start..offset, prior, out, mismatch)?;
        }
        previous = Some((offset, import));
    }
    if let Some((start, import)) = previous {
        push_import(bytes, start..section_end, import, out, mismatch)?;
    }
    Ok(())
}

fn push_import(
    bytes: &[u8],
    range: Range<usize>,
    import: wasmparser::ComponentImport<'_>,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let raw = checked_range(bytes, range, mismatch)?;
    out.try_reserve(1).map_err(|_| AdmissionError::Allocation)?;
    out.push(OwnedTopLevelEntityPin {
        direction: Preview1WrappedEntityDirection::Import,
        kind: entity_kind(import.ty.kind()),
        name: copied(import.name.name)?,
        raw_entry_sha256: raw_sha256(raw),
    });
    Ok(())
}

fn collect_top_level_exports(
    bytes: &[u8],
    reader: wasmparser::ComponentExportSectionReader<'_>,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let section_end = reader.range().end;
    let mut previous = None;
    for item in reader.into_iter_with_offsets() {
        let (offset, export) = item.map_err(|_| mismatch)?;
        if let Some((start, prior)) = previous.take() {
            push_export(bytes, start..offset, prior, out, mismatch)?;
        }
        previous = Some((offset, export));
    }
    if let Some((start, export)) = previous {
        push_export(bytes, start..section_end, export, out, mismatch)?;
    }
    Ok(())
}

fn push_export(
    bytes: &[u8],
    range: Range<usize>,
    export: wasmparser::ComponentExport<'_>,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let raw = checked_range(bytes, range, mismatch)?;
    out.try_reserve(1).map_err(|_| AdmissionError::Allocation)?;
    out.push(OwnedTopLevelEntityPin {
        direction: Preview1WrappedEntityDirection::Export,
        kind: entity_kind(export.kind),
        name: copied(export.name.name)?,
        raw_entry_sha256: raw_sha256(raw),
    });
    Ok(())
}

fn collect_lowerings(
    bytes: &[u8],
    reader: wasmparser::ComponentCanonicalSectionReader<'_>,
    hasher: &mut Sha256,
    count: &mut u32,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let section_end = reader.range().end;
    let mut previous = None;
    for item in reader.into_iter_with_offsets() {
        let (offset, function) = item.map_err(|_| mismatch)?;
        if let Some((start, prior)) = previous.take() {
            record_lowering(bytes, start..offset, prior, hasher, count, mismatch)?;
        }
        previous = Some((offset, function));
    }
    if let Some((start, function)) = previous {
        record_lowering(bytes, start..section_end, function, hasher, count, mismatch)?;
    }
    Ok(())
}

fn record_lowering(
    bytes: &[u8],
    range: Range<usize>,
    function: CanonicalFunction,
    hasher: &mut Sha256,
    count: &mut u32,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    if matches!(function, CanonicalFunction::Lower { .. }) {
        let raw = checked_range(bytes, range, mismatch)?;
        hasher.update((raw.len() as u64).to_le_bytes());
        hasher.update(raw);
        *count = count.checked_add(1).ok_or(mismatch)?;
    }
    Ok(())
}

fn validate_guest_module(
    bytes: &[u8],
    policy: &Preview1WrappedPolicySnapshot,
    mismatch: AdmissionError,
) -> Result<Vec<OwnedGuestFunctionImportPin>, AdmissionError> {
    inspect_core(bytes).map_err(|_| mismatch)?;
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::empty());
    let mut function_types: Vec<(Vec<Preview1CoreValueType>, Vec<Preview1CoreValueType>)> =
        Vec::new();
    let mut function_type_indices = Vec::new();
    let mut imports = Vec::new();
    let mut start_exports = 0_u32;
    let mut memory_exports = 0_u32;
    let mut defined_functions = 0_u32;
    let mut memories = 0_u32;
    let mut code_bodies = 0_u32;
    let mut name_sections = 0_u32;
    let mut saw_module = false;

    for payload in parser.parse_all(bytes) {
        match payload.map_err(|_| mismatch)? {
            Payload::Version { encoding, .. } => {
                if saw_module || encoding != Encoding::Module {
                    return Err(mismatch);
                }
                saw_module = true;
            }
            Payload::TypeSection(reader) => {
                function_types
                    .try_reserve_exact(reader.count() as usize)
                    .map_err(|_| AdmissionError::Allocation)?;
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| mismatch)?;
                    function_types.push((
                        core_values(ty.params(), mismatch)?,
                        core_values(ty.results(), mismatch)?,
                    ));
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(|_| mismatch)?;
                    let TypeRef::Func(type_index) = import.ty else {
                        return Err(mismatch);
                    };
                    let signature = function_types.get(type_index as usize).ok_or(mismatch)?;
                    function_type_indices
                        .try_reserve(1)
                        .map_err(|_| AdmissionError::Allocation)?;
                    imports
                        .try_reserve(1)
                        .map_err(|_| AdmissionError::Allocation)?;
                    function_type_indices.push(type_index);
                    imports.push(OwnedGuestFunctionImportPin {
                        module: copied(import.module)?,
                        name: copied(import.name)?,
                        params: copied_values(&signature.0)?,
                        results: copied_values(&signature.1)?,
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                defined_functions = reader.count();
                function_type_indices
                    .try_reserve_exact(reader.count() as usize)
                    .map_err(|_| AdmissionError::Allocation)?;
                for type_index in reader {
                    function_type_indices.push(type_index.map_err(|_| mismatch)?);
                }
            }
            Payload::MemorySection(reader) => {
                memories = reader.count();
                if memories != 1 {
                    return Err(mismatch);
                }
                for memory in reader {
                    let memory = memory.map_err(|_| mismatch)?;
                    let Some(maximum) = memory.maximum else {
                        return Err(mismatch);
                    };
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.initial > u64::from(PROFILE_1_LIMITS.max_initial_memory_pages)
                        || maximum > u64::from(PROFILE_1_LIMITS.max_memory_pages)
                        || maximum < memory.initial
                    {
                        return Err(mismatch);
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|_| mismatch)?;
                    match export.kind {
                        wasmparser::ExternalKind::Func => {
                            if export.name != PREVIEW1_START {
                                return Err(mismatch);
                            }
                            let type_index = *function_type_indices
                                .get(export.index as usize)
                                .ok_or(mismatch)?;
                            let signature =
                                function_types.get(type_index as usize).ok_or(mismatch)?;
                            if !signature.0.is_empty() || !signature.1.is_empty() {
                                return Err(mismatch);
                            }
                            start_exports = start_exports.checked_add(1).ok_or(mismatch)?;
                        }
                        wasmparser::ExternalKind::Memory => {
                            if export.name != "memory" || export.index != 0 {
                                return Err(mismatch);
                            }
                            memory_exports = memory_exports.checked_add(1).ok_or(mismatch)?;
                        }
                        wasmparser::ExternalKind::Table
                        | wasmparser::ExternalKind::Global
                        | wasmparser::ExternalKind::Tag
                        | wasmparser::ExternalKind::FuncExact => return Err(mismatch),
                    }
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count != 1 {
                    return Err(mismatch);
                }
            }
            Payload::CodeSectionEntry(_) => {
                code_bodies = code_bodies.checked_add(1).ok_or(mismatch)?;
            }
            Payload::CustomSection(section) => {
                if section.name() != "name"
                    || section.range().len() > PROFILE_1_LIMITS.max_custom_section_bytes
                {
                    return Err(mismatch);
                }
                name_sections = name_sections.checked_add(1).ok_or(mismatch)?;
                if name_sections > 1 {
                    return Err(mismatch);
                }
            }
            Payload::End(_) => {}
            Payload::TableSection(_)
            | Payload::GlobalSection(_)
            | Payload::TagSection(_)
            | Payload::ElementSection(_)
            | Payload::DataCountSection { .. }
            | Payload::DataSection(_)
            | Payload::StartSection { .. }
            | Payload::UnknownSection { .. } => return Err(mismatch),
            _ => return Err(mismatch),
        }
    }
    if !saw_module
        || defined_functions != 1
        || memories != 1
        || code_bodies != 1
        || name_sections != 1
        || start_exports != 1
        || memory_exports != 1
        || imports != policy.guest_function_imports
    {
        return Err(mismatch);
    }
    Ok(imports)
}

fn core_values(
    values: &[ValType],
    mismatch: AdmissionError,
) -> Result<Vec<Preview1CoreValueType>, AdmissionError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| AdmissionError::Allocation)?;
    for value in values {
        match value {
            ValType::I32 => result.push(Preview1CoreValueType::I32),
            _ => return Err(mismatch),
        }
    }
    Ok(result)
}

impl From<OwnedGuestFunctionImportPin> for Preview1GuestFunctionImportDiagnostic {
    fn from(value: OwnedGuestFunctionImportPin) -> Self {
        Self {
            module: value.module,
            name: value.name,
            params: value.params,
            results: value.results,
        }
    }
}

impl From<OwnedTopLevelEntityPin> for Preview1WrappedTopLevelEntityDiagnostic {
    fn from(value: OwnedTopLevelEntityPin) -> Self {
        Self {
            direction: value.direction,
            kind: value.kind,
            name: value.name,
            raw_entry_sha256: value.raw_entry_sha256,
        }
    }
}

fn entity_kind(kind: ComponentExternalKind) -> Preview1WrappedEntityKind {
    match kind {
        ComponentExternalKind::Module => Preview1WrappedEntityKind::Module,
        ComponentExternalKind::Func => Preview1WrappedEntityKind::Function,
        ComponentExternalKind::Value => Preview1WrappedEntityKind::Value,
        ComponentExternalKind::Type => Preview1WrappedEntityKind::Type,
        ComponentExternalKind::Component => Preview1WrappedEntityKind::Component,
        ComponentExternalKind::Instance => Preview1WrappedEntityKind::Instance,
    }
}

fn checked_range(
    bytes: &[u8],
    range: Range<usize>,
    mismatch: AdmissionError,
) -> Result<&[u8], AdmissionError> {
    if range.start > range.end || range.end > bytes.len() {
        return Err(mismatch);
    }
    Ok(&bytes[range])
}

fn raw_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn zero_hash(hash: &[u8; 32]) -> bool {
    hash.iter().all(|byte| *byte == 0)
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn copied(value: &str) -> Result<String, AdmissionError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| AdmissionError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn copied_values(
    values: &[Preview1CoreValueType],
) -> Result<Vec<Preview1CoreValueType>, AdmissionError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| AdmissionError::Allocation)?;
    result.extend_from_slice(values);
    Ok(result)
}

fn usize_u32(value: usize) -> Result<u32, AdmissionError> {
    u32::try_from(value).map_err(|_| AdmissionError::InvalidPolicy)
}
