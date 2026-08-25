//! Default-off C8.2 admission and execution for a closed Preview1 corpus.
//!
//! The public input is always a complete [`ComponentArtifactV1`]. Admission
//! validates the whole wrapper, manifest, adapter, topology, and every embedded
//! module before retaining a move-only candidate. The acceptance constructor
//! then repeats that validation and privately projects guest Core ordinal zero;
//! raw guest bytes and executable plans never cross the public API.

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt, ops::Range};

use sha2::{Digest, Sha256};
use vibeos_component_format::{
    ComponentArtifactCoreModuleV1, ComponentArtifactSignerPolicyKind, ComponentArtifactV1,
    ProfileIdentity, TrapCode, PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN,
    PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256, PREVIEW1_WRAPPED_ADAPTER_REVISION, PROFILE_1_LIMITS,
};
use vibeos_component_host::{
    ByteStreamReader, ByteStreamWriter, StreamCloseReason, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, MAX_STREAM_CHUNK_BYTES,
};
use vibeos_component_runtime::host::HostOperationToken;
use vibeos_wasm_runtime::{
    CallMetrics, CoreHostCall, CoreHostImport, CoreInstance, CoreValue, CoreValueType,
    OwnerAllocationReservation, PollResult, ValidatedCore,
};
use wasmparser::{
    CanonicalFunction, ComponentExternalKind, Encoding, Parser, Payload, TypeRef, ValType,
    Validator, WasmFeatures,
};

use crate::{
    AdmissionError, Preview1WrappedCoreModulePin, Preview1WrappedEntityDirection,
    Preview1WrappedEntityKind, Preview1WrappedTopLevelEntityPin,
};

const PREVIEW1_MODULE: &str = "wasi_snapshot_preview1";
const PREVIEW1_START: &str = "_start";
const MEMORY_EXPORT: &str = "memory";
const LOWERING_FINGERPRINT_DOMAIN: &[u8] = b"vibeos.preview1-wrapped.canonical-lowerings.v1\0";
const EXPECTED_EMBEDDED_MODULES: usize = 4;
const EXPECTED_CANONICAL_LOWERINGS: u32 = 18;
const EXPECTED_NESTED_COMPONENTS: u32 = 1;
const EXPECTED_COMPONENT_IMPORTS: [&str; 10] = [
    "wasi:cli/environment@0.2.12",
    "wasi:cli/exit@0.2.12",
    "wasi:cli/stderr@0.2.12",
    "wasi:cli/stdin@0.2.12",
    "wasi:cli/stdout@0.2.12",
    "wasi:clocks/wall-clock@0.2.12",
    "wasi:filesystem/preopens@0.2.12",
    "wasi:filesystem/types@0.2.12",
    "wasi:io/error@0.2.12",
    "wasi:io/streams@0.2.12",
];
const EXPECTED_COMPONENT_EXPORT: &str = "wasi:cli/run@0.2.12";
const EXPECTED_TOP_LEVEL_ENTITIES: usize = EXPECTED_COMPONENT_IMPORTS.len() + 1;

const HOST_FD_READ: u32 = 1;
const HOST_FD_WRITE: u32 = 2;
const HOST_ARGS_SIZES_GET: u32 = 3;
const HOST_ARGS_GET: u32 = 4;
const HOST_PROC_EXIT: u32 = 5;

const ERRNO_SUCCESS: i32 = 0;
const ERRNO_BADF: i32 = 8;
const ERRNO_FAULT: i32 = 21;
const ERRNO_INVAL: i32 = 28;
const ERRNO_IO: i32 = 29;
const ERRNO_PIPE: i32 = 64;

/// Versioned C8.2 host-work schedule. One returning Preview1 import always
/// leaves a single Core fuel unit for its suspended continuation. I/O handlers
/// conservatively pre-charge their admitted maximum before any guest-memory or
/// stream effect; a retry of a blocked stream operation pays one more unit.
const HOST_DISPATCH_BASE_WORK: u64 = 1;
const HOST_RETURN_FUEL_RESERVE: u64 = 1;
const HOST_STREAM_RETRY_WORK: u64 = 1;
const HOST_ARGS_SIZES_MEMORY_WORK: u64 = 8;
const HOST_IOVEC_FIXED_WORK: u64 = 4;
const HOST_IOVEC_SLOT_WORK: u64 = 12;
const HOST_IO_BYTE_WORK: u64 = 3;

const I32_X1: [CoreValueType; 1] = [CoreValueType::I32];
const I32_X2: [CoreValueType; 2] = [CoreValueType::I32; 2];
const I32_X4: [CoreValueType; 4] = [CoreValueType::I32; 4];

const HOST_IMPORTS: [CoreHostImport<'static>; 5] = [
    CoreHostImport {
        id: HOST_FD_READ,
        module: PREVIEW1_MODULE,
        name: "fd_read",
        params: &I32_X4,
        results: &I32_X1,
    },
    CoreHostImport {
        id: HOST_FD_WRITE,
        module: PREVIEW1_MODULE,
        name: "fd_write",
        params: &I32_X4,
        results: &I32_X1,
    },
    CoreHostImport {
        id: HOST_ARGS_SIZES_GET,
        module: PREVIEW1_MODULE,
        name: "args_sizes_get",
        params: &I32_X2,
        results: &I32_X1,
    },
    CoreHostImport {
        id: HOST_ARGS_GET,
        module: PREVIEW1_MODULE,
        name: "args_get",
        params: &I32_X2,
        results: &I32_X1,
    },
    CoreHostImport {
        id: HOST_PROC_EXIT,
        module: PREVIEW1_MODULE,
        name: "proc_exit",
        params: &I32_X1,
        results: &[],
    },
];

/// Hard ceilings compiled into the C8.2 acceptance façade.
pub const PREVIEW1_CORPUS_MAX_ARGUMENTS: usize = 128;
pub const PREVIEW1_CORPUS_MAX_ARGUMENT_BYTES: usize = 16 * 1024;
pub const PREVIEW1_CORPUS_MAX_IOVECS: usize = 64;
pub const PREVIEW1_CORPUS_MAX_STREAM_BYTES: usize = 64 * 1024;
pub const PREVIEW1_CORPUS_MAX_HOST_CALLS: u32 = 4_096;

/// Exact external policy for one immutable C8.2 corpus artifact.
///
/// The five guest imports are not caller-selectable. They are compiled into
/// this façade; these fields pin the independently reviewed wrapper and bound
/// every invocation value or host effect.
pub struct Preview1CorpusAdmissionPolicy<'a> {
    pub artifact_commitment: [u8; 32],
    pub external_policy_digest: [u8; 32],
    pub command_name: &'a str,
    pub adapter_revision: &'a str,
    pub adapter_embedded_module_ordinal: u32,
    pub adapter_asset_byte_len: u32,
    pub adapter_asset_sha256: [u8; 32],
    pub guest_module_ordinal: u32,
    pub guest_module_byte_len: u32,
    pub guest_module_sha256: [u8; 32],
    pub embedded_modules: &'a [Preview1WrappedCoreModulePin],
    pub top_level_entities: &'a [Preview1WrappedTopLevelEntityPin<'a>],
    pub canonical_lowering_sha256: [u8; 32],
    pub canonical_lowering_count: u32,
    pub nested_component_count: u32,
    /// Includes the immutable command name installed as `argv[0]`.
    pub max_arguments: u16,
    /// Includes every terminating NUL byte.
    pub max_argument_bytes: u32,
    pub max_iovecs: u16,
    pub max_io_bytes_per_call: u32,
    pub max_stdin_bytes: u32,
    pub max_stdout_bytes: u32,
    pub max_host_calls: u32,
}

#[derive(PartialEq, Eq)]
struct PolicySnapshot {
    artifact_commitment: [u8; 32],
    external_policy_digest: [u8; 32],
    command_name: String,
    adapter_revision: String,
    adapter_embedded_module_ordinal: u32,
    adapter_asset_byte_len: u32,
    adapter_asset_sha256: [u8; 32],
    guest_module_ordinal: u32,
    guest_module_byte_len: u32,
    guest_module_sha256: [u8; 32],
    embedded_modules: Vec<Preview1WrappedCoreModulePin>,
    top_level_entities: Vec<OwnedTopLevelEntityPin>,
    canonical_lowering_sha256: [u8; 32],
    canonical_lowering_count: u32,
    nested_component_count: u32,
    limits: CorpusLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CorpusLimits {
    max_arguments: usize,
    max_argument_bytes: usize,
    max_iovecs: usize,
    max_io_bytes_per_call: usize,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_host_calls: u32,
}

#[derive(PartialEq, Eq)]
struct OwnedTopLevelEntityPin {
    direction: Preview1WrappedEntityDirection,
    kind: Preview1WrappedEntityKind,
    name: String,
    raw_entry_sha256: [u8; 32],
}

impl PolicySnapshot {
    fn new(policy: &Preview1CorpusAdmissionPolicy<'_>) -> Result<Self, AdmissionError> {
        let limits = CorpusLimits {
            max_arguments: usize::from(policy.max_arguments),
            max_argument_bytes: usize::try_from(policy.max_argument_bytes)
                .map_err(|_| AdmissionError::InvalidPolicy)?,
            max_iovecs: usize::from(policy.max_iovecs),
            max_io_bytes_per_call: usize::try_from(policy.max_io_bytes_per_call)
                .map_err(|_| AdmissionError::InvalidPolicy)?,
            max_stdin_bytes: usize::try_from(policy.max_stdin_bytes)
                .map_err(|_| AdmissionError::InvalidPolicy)?,
            max_stdout_bytes: usize::try_from(policy.max_stdout_bytes)
                .map_err(|_| AdmissionError::InvalidPolicy)?,
            max_host_calls: policy.max_host_calls,
        };
        if zero_hash(&policy.artifact_commitment)
            || zero_hash(&policy.external_policy_digest)
            || zero_hash(&policy.adapter_asset_sha256)
            || zero_hash(&policy.guest_module_sha256)
            || zero_hash(&policy.canonical_lowering_sha256)
            || policy.adapter_revision != PREVIEW1_WRAPPED_ADAPTER_REVISION
            || policy.adapter_asset_byte_len as usize != PREVIEW1_WRAPPED_ADAPTER_ASSET_BYTE_LEN
            || policy.adapter_asset_sha256 != PREVIEW1_WRAPPED_ADAPTER_ASSET_SHA256
            || policy.guest_module_ordinal != 0
            || policy.adapter_embedded_module_ordinal != 1
            || policy.guest_module_byte_len == 0
            || policy.embedded_modules.len() != EXPECTED_EMBEDDED_MODULES
            || policy.top_level_entities.len() != EXPECTED_TOP_LEVEL_ENTITIES
            || policy.canonical_lowering_count != EXPECTED_CANONICAL_LOWERINGS
            || policy.nested_component_count != EXPECTED_NESTED_COMPONENTS
            || !valid_token(policy.command_name, 128)
            || !valid_limits(limits, policy.command_name.len())
        {
            return Err(AdmissionError::InvalidPolicy);
        }
        let guest = policy
            .embedded_modules
            .get(policy.guest_module_ordinal as usize)
            .ok_or(AdmissionError::InvalidPolicy)?;
        if guest.byte_len != policy.guest_module_byte_len
            || guest.sha256 != policy.guest_module_sha256
            || policy
                .embedded_modules
                .iter()
                .any(|pin| pin.byte_len == 0 || zero_hash(&pin.sha256))
        {
            return Err(AdmissionError::InvalidPolicy);
        }

        let mut embedded_modules = Vec::new();
        embedded_modules
            .try_reserve_exact(policy.embedded_modules.len())
            .map_err(|_| AdmissionError::Allocation)?;
        embedded_modules.extend_from_slice(policy.embedded_modules);

        let mut top_level_entities = Vec::new();
        top_level_entities
            .try_reserve_exact(policy.top_level_entities.len())
            .map_err(|_| AdmissionError::Allocation)?;
        for pin in policy.top_level_entities {
            if !valid_token(pin.name, 512) || zero_hash(&pin.raw_entry_sha256) {
                return Err(AdmissionError::InvalidPolicy);
            }
            top_level_entities.push(OwnedTopLevelEntityPin {
                direction: pin.direction,
                kind: pin.kind,
                name: copied(pin.name)?,
                raw_entry_sha256: pin.raw_entry_sha256,
            });
        }
        top_level_entities.sort_unstable_by(compare_entities);
        if top_level_entities
            .windows(2)
            .any(|pair| pair[0].direction == pair[1].direction && pair[0].name == pair[1].name)
            || !exact_top_level_surface(&top_level_entities)
        {
            return Err(AdmissionError::InvalidPolicy);
        }

        Ok(Self {
            artifact_commitment: policy.artifact_commitment,
            external_policy_digest: policy.external_policy_digest,
            command_name: copied(policy.command_name)?,
            adapter_revision: copied(policy.adapter_revision)?,
            adapter_embedded_module_ordinal: policy.adapter_embedded_module_ordinal,
            adapter_asset_byte_len: policy.adapter_asset_byte_len,
            adapter_asset_sha256: policy.adapter_asset_sha256,
            guest_module_ordinal: policy.guest_module_ordinal,
            guest_module_byte_len: policy.guest_module_byte_len,
            guest_module_sha256: policy.guest_module_sha256,
            embedded_modules,
            top_level_entities,
            canonical_lowering_sha256: policy.canonical_lowering_sha256,
            canonical_lowering_count: policy.canonical_lowering_count,
            nested_component_count: policy.nested_component_count,
            limits,
        })
    }
}

fn exact_top_level_surface(entities: &[OwnedTopLevelEntityPin]) -> bool {
    entities.len() == EXPECTED_TOP_LEVEL_ENTITIES
        && EXPECTED_COMPONENT_IMPORTS.iter().all(|expected| {
            entities.iter().any(|entity| {
                entity.direction == Preview1WrappedEntityDirection::Import
                    && entity.kind == Preview1WrappedEntityKind::Instance
                    && entity.name == *expected
            })
        })
        && entities.iter().any(|entity| {
            entity.direction == Preview1WrappedEntityDirection::Export
                && entity.kind == Preview1WrappedEntityKind::Instance
                && entity.name == EXPECTED_COMPONENT_EXPORT
        })
}

fn valid_limits(limits: CorpusLimits, command_name_bytes: usize) -> bool {
    limits.max_arguments > 0
        && limits.max_arguments <= PREVIEW1_CORPUS_MAX_ARGUMENTS
        && limits.max_argument_bytes >= command_name_bytes.saturating_add(1)
        && limits.max_argument_bytes <= PREVIEW1_CORPUS_MAX_ARGUMENT_BYTES
        && limits.max_iovecs > 0
        && limits.max_iovecs <= PREVIEW1_CORPUS_MAX_IOVECS
        && limits.max_io_bytes_per_call > 0
        && limits.max_io_bytes_per_call <= PREVIEW1_CORPUS_MAX_STREAM_BYTES
        && limits.max_stdin_bytes > 0
        && limits.max_stdin_bytes <= PREVIEW1_CORPUS_MAX_STREAM_BYTES
        && limits.max_stdout_bytes > 0
        && limits.max_stdout_bytes <= PREVIEW1_CORPUS_MAX_STREAM_BYTES
        && limits.max_io_bytes_per_call <= limits.max_stdin_bytes
        && limits.max_io_bytes_per_call <= limits.max_stdout_bytes
        && limits.max_host_calls > 0
        && limits.max_host_calls <= PREVIEW1_CORPUS_MAX_HOST_CALLS
}

/// Redacted, read-only evidence retained by the C8.2 candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preview1CorpusAdmissionDiagnostics {
    embedded_modules: u32,
    top_level_entities: u32,
    canonical_lowerings: u32,
    nested_components: u32,
    guest_imports: u32,
}

impl Preview1CorpusAdmissionDiagnostics {
    pub const fn embedded_module_count(self) -> u32 {
        self.embedded_modules
    }

    pub const fn top_level_entity_count(self) -> u32 {
        self.top_level_entities
    }

    pub const fn canonical_lowering_count(self) -> u32 {
        self.canonical_lowerings
    }

    pub const fn nested_component_count(self) -> u32 {
        self.nested_components
    }

    pub const fn guest_import_count(self) -> u32 {
        self.guest_imports
    }
}

/// Move-only C8.2 candidate. Its profile remains permanently validation-only.
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1CorpusCandidate;
/// fn duplicate(candidate: AdmittedPreview1CorpusCandidate) {
///     let _ = candidate.clone();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1CorpusCandidate;
/// fn raw(candidate: &AdmittedPreview1CorpusCandidate) {
///     let _ = candidate.bytes();
///     let _ = candidate.guest_core();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::AdmittedPreview1CorpusCandidate;
/// fn authority(candidate: &AdmittedPreview1CorpusCandidate) {
///     let _ = candidate.validated_plan();
///     let _ = candidate.grants();
///     let _ = candidate.command_manifest();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_admission::{AdmittedComponent, AdmittedPreview1CorpusCandidate};
/// fn ordinary(candidate: AdmittedPreview1CorpusCandidate) -> AdmittedComponent {
///     candidate.into()
/// }
/// ```
pub struct AdmittedPreview1CorpusCandidate {
    artifact: ComponentArtifactV1,
    policy: PolicySnapshot,
    diagnostics: Preview1CorpusAdmissionDiagnostics,
}

impl AdmittedPreview1CorpusCandidate {
    pub const fn profile(&self) -> ProfileIdentity {
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    pub const fn guest_calls(&self) -> u64 {
        0
    }

    pub const fn diagnostics(&self) -> Preview1CorpusAdmissionDiagnostics {
        self.diagnostics
    }

    /// Revalidate the complete immutable artifact without exposing guest bytes.
    pub fn revalidate(&self) -> Result<(), AdmissionError> {
        let observed = validate_artifact(
            &self.artifact,
            &self.policy,
            AdmissionError::RevalidationMismatch,
        )?;
        if observed.diagnostics != self.diagnostics {
            return Err(AdmissionError::RevalidationMismatch);
        }
        Ok(())
    }

    /// Consume the sealed candidate and privately instantiate guest ordinal 0.
    ///
    /// Enabling this explicitly named façade does not change the profile or any
    /// `runtime_ready` bit. The returned invocation exposes only polling,
    /// terminal status, metrics, and cancellation—not Core bytes or memory.
    pub fn into_acceptance_invocation(
        self,
        input: Preview1CorpusInvocationInput,
    ) -> Result<Preview1CorpusInvocation, Preview1CorpusBuildError> {
        let observed = validate_artifact(
            &self.artifact,
            &self.policy,
            AdmissionError::RevalidationMismatch,
        )
        .map_err(Preview1CorpusBuildError::Admission)?;
        if observed.diagnostics != self.diagnostics {
            return Err(Preview1CorpusBuildError::Admission(
                AdmissionError::RevalidationMismatch,
            ));
        }
        if input.stdin.same_stream_as(&input.stdout) {
            return Err(Preview1CorpusBuildError::InvalidStreams);
        }

        let arguments = encode_arguments(
            &self.policy.command_name,
            input.arguments,
            self.policy.limits,
        )?;
        let validated = ValidatedCore::new(
            observed.guest_bytes,
            OwnerAllocationReservation::profile_default(),
        )
        .map_err(|error| Preview1CorpusBuildError::Core(error.trap))?;
        let mut instance = validated
            .instantiate_with_imports(&HOST_IMPORTS)
            .map_err(|error| Preview1CorpusBuildError::Core(error.trap))?;
        let artifact_limits = self.artifact.instance_limits();
        instance
            .start_call(
                PREVIEW1_START,
                &[],
                artifact_limits.total_fuel(),
                artifact_limits.poll_quantum(),
            )
            .map_err(Preview1CorpusBuildError::Core)?;

        Ok(Preview1CorpusInvocation {
            instance,
            stdin: input.stdin,
            stdout: input.stdout,
            arguments,
            limits: self.policy.limits,
            state: BrokerState::Core,
            host_calls: 0,
            stdin_bytes: 0,
            stdout_bytes: 0,
        })
    }
}

impl fmt::Debug for AdmittedPreview1CorpusCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedPreview1CorpusCandidate")
            .field("profile", &ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED)
            .field("diagnostics", &self.diagnostics)
            .field("runtime_ready", &false)
            .field("guest_calls", &0_u64)
            .finish()
    }
}

/// Freshly admit one exact C8.2 corpus artifact without executing guest code.
pub fn admit_preview1_corpus_candidate(
    artifact: ComponentArtifactV1,
    policy: &Preview1CorpusAdmissionPolicy<'_>,
) -> Result<AdmittedPreview1CorpusCandidate, AdmissionError> {
    let policy = PolicySnapshot::new(policy)?;
    let diagnostics =
        validate_artifact(&artifact, &policy, AdmissionError::InvalidPolicy)?.diagnostics;
    let candidate = AdmittedPreview1CorpusCandidate {
        artifact,
        policy,
        diagnostics,
    };
    candidate.revalidate()?;
    Ok(candidate)
}

struct ValidatedArtifact<'a> {
    guest_bytes: &'a [u8],
    diagnostics: Preview1CorpusAdmissionDiagnostics,
}

fn validate_artifact<'a>(
    artifact: &'a ComponentArtifactV1,
    policy: &PolicySnapshot,
    mismatch: AdmissionError,
) -> Result<ValidatedArtifact<'a>, AdmissionError> {
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

    let guest_bytes = *observed
        .module_bytes
        .get(policy.guest_module_ordinal as usize)
        .ok_or(mismatch)?;
    if usize_u32(guest_bytes.len())? != policy.guest_module_byte_len
        || raw_sha256(guest_bytes) != policy.guest_module_sha256
    {
        return Err(mismatch);
    }
    let adapter_module_ordinal = policy.adapter_embedded_module_ordinal as usize;
    let adapter_module_bytes = *observed
        .module_bytes
        .get(adapter_module_ordinal)
        .ok_or(mismatch)?;
    let adapter_module_pin = policy
        .embedded_modules
        .get(adapter_module_ordinal)
        .ok_or(mismatch)?;
    if adapter_module_ordinal == policy.guest_module_ordinal as usize
        || usize_u32(adapter_module_bytes.len())? != adapter_module_pin.byte_len
        || raw_sha256(adapter_module_bytes) != adapter_module_pin.sha256
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

    validate_guest_module(
        guest_bytes,
        artifact.instance_limits().memory_bytes(),
        mismatch,
    )?;
    Ok(ValidatedArtifact {
        guest_bytes,
        diagnostics: Preview1CorpusAdmissionDiagnostics {
            embedded_modules: usize_u32(observed.embedded_modules.len())?,
            top_level_entities: usize_u32(observed.top_level_entities.len())?,
            canonical_lowerings: observed.canonical_lowering_count,
            nested_components: observed.nested_component_count,
            guest_imports: HOST_IMPORTS.len() as u32,
        },
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
        match payload.map_err(|_| mismatch)? {
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
                )?;
            }
            Payload::UnknownSection { .. } => return Err(mismatch),
            _ => {}
        }
    }
    if !saw_top || !encodings.is_empty() {
        return Err(mismatch);
    }
    top_level_entities.sort_unstable_by(compare_entities);
    if top_level_entities
        .windows(2)
        .any(|pair| pair[0].direction == pair[1].direction && pair[0].name == pair[1].name)
    {
        return Err(mismatch);
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
    let mut previous: Option<(usize, wasmparser::ComponentImport<'_>)> = None;
    for item in reader.into_iter_with_offsets() {
        let (offset, import) = item.map_err(|_| mismatch)?;
        if let Some((start, prior)) = previous.take() {
            push_entity(
                bytes,
                start..offset,
                Preview1WrappedEntityDirection::Import,
                entity_kind(prior.ty.kind()),
                prior.name.name,
                out,
                mismatch,
            )?;
        }
        previous = Some((offset, import));
    }
    if let Some((start, import)) = previous {
        push_entity(
            bytes,
            start..section_end,
            Preview1WrappedEntityDirection::Import,
            entity_kind(import.ty.kind()),
            import.name.name,
            out,
            mismatch,
        )?;
    }
    Ok(())
}

fn collect_top_level_exports(
    bytes: &[u8],
    reader: wasmparser::ComponentExportSectionReader<'_>,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let section_end = reader.range().end;
    let mut previous: Option<(usize, wasmparser::ComponentExport<'_>)> = None;
    for item in reader.into_iter_with_offsets() {
        let (offset, export) = item.map_err(|_| mismatch)?;
        if let Some((start, prior)) = previous.take() {
            push_entity(
                bytes,
                start..offset,
                Preview1WrappedEntityDirection::Export,
                entity_kind(prior.kind),
                prior.name.name,
                out,
                mismatch,
            )?;
        }
        previous = Some((offset, export));
    }
    if let Some((start, export)) = previous {
        push_entity(
            bytes,
            start..section_end,
            Preview1WrappedEntityDirection::Export,
            entity_kind(export.kind),
            export.name.name,
            out,
            mismatch,
        )?;
    }
    Ok(())
}

fn push_entity(
    bytes: &[u8],
    range: Range<usize>,
    direction: Preview1WrappedEntityDirection,
    kind: Preview1WrappedEntityKind,
    name: &str,
    out: &mut Vec<OwnedTopLevelEntityPin>,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    let raw = checked_range(bytes, range, mismatch)?;
    out.try_reserve(1).map_err(|_| AdmissionError::Allocation)?;
    out.push(OwnedTopLevelEntityPin {
        direction,
        kind,
        name: copied(name)?,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigType {
    I32,
    I64,
}

#[derive(PartialEq, Eq)]
struct GuestImport {
    module: String,
    name: String,
    params: Vec<SigType>,
    results: Vec<SigType>,
}

fn validate_guest_module(
    bytes: &[u8],
    artifact_memory_bytes: u64,
    mismatch: AdmissionError,
) -> Result<(), AdmissionError> {
    vibeos_wasm_runtime::inspect_core(bytes).map_err(|_| mismatch)?;
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::empty());
    let mut function_types: Vec<(Vec<SigType>, Vec<SigType>)> = Vec::new();
    let mut function_type_indices = Vec::new();
    let mut imports = Vec::new();
    let mut defined_functions = 0_u32;
    let mut code_bodies = 0_u32;
    let mut memories = 0_u32;
    let mut start_exports = 0_u32;
    let mut memory_exports = 0_u32;
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
                for ty in reader.into_iter_err_on_gc_types() {
                    let ty = ty.map_err(|_| mismatch)?;
                    function_types.push((
                        signature_types(ty.params(), mismatch)?,
                        signature_types(ty.results(), mismatch)?,
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
                    function_type_indices.push(type_index);
                    imports.push(GuestImport {
                        module: copied(import.module)?,
                        name: copied(import.name)?,
                        params: copied_signature(&signature.0)?,
                        results: copied_signature(&signature.1)?,
                    });
                }
            }
            Payload::FunctionSection(reader) => {
                defined_functions = reader.count();
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
                    let maximum_bytes = maximum.checked_mul(65_536).ok_or(mismatch)?;
                    if memory.memory64
                        || memory.shared
                        || memory.page_size_log2.is_some()
                        || memory.initial > u64::from(PROFILE_1_LIMITS.max_initial_memory_pages)
                        || maximum > u64::from(PROFILE_1_LIMITS.max_memory_pages)
                        || maximum < memory.initial
                        || maximum_bytes > artifact_memory_bytes
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
                            if export.name != MEMORY_EXPORT || export.index != 0 {
                                return Err(mismatch);
                            }
                            memory_exports = memory_exports.checked_add(1).ok_or(mismatch)?;
                        }
                        _ => return Err(mismatch),
                    }
                }
            }
            Payload::CodeSectionStart { count, .. } => {
                if count != defined_functions {
                    return Err(mismatch);
                }
            }
            Payload::CodeSectionEntry(_) => {
                code_bodies = code_bodies.checked_add(1).ok_or(mismatch)?;
            }
            Payload::DataCountSection { .. }
            | Payload::DataSection(_)
            | Payload::CustomSection(_)
            | Payload::End(_) => {}
            Payload::TableSection(_)
            | Payload::GlobalSection(_)
            | Payload::TagSection(_)
            | Payload::ElementSection(_)
            | Payload::StartSection { .. }
            | Payload::UnknownSection { .. } => return Err(mismatch),
            _ => return Err(mismatch),
        }
    }
    if !saw_module
        || defined_functions == 0
        || code_bodies != defined_functions
        || memories != 1
        || start_exports != 1
        || memory_exports != 1
        || !exact_guest_imports(&imports)
    {
        return Err(mismatch);
    }
    Ok(())
}

fn exact_guest_imports(imports: &[GuestImport]) -> bool {
    if imports.len() != HOST_IMPORTS.len() {
        return false;
    }
    HOST_IMPORTS.iter().all(|expected| {
        imports.iter().any(|actual| {
            actual.module == expected.module
                && actual.name == expected.name
                && signature_matches(&actual.params, expected.params)
                && signature_matches(&actual.results, expected.results)
        })
    })
}

fn signature_matches(actual: &[SigType], expected: &[CoreValueType]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            matches!(
                (actual, expected),
                (SigType::I32, CoreValueType::I32) | (SigType::I64, CoreValueType::I64)
            )
        })
}

fn signature_types(
    values: &[ValType],
    mismatch: AdmissionError,
) -> Result<Vec<SigType>, AdmissionError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| AdmissionError::Allocation)?;
    for value in values {
        result.push(match value {
            ValType::I32 => SigType::I32,
            ValType::I64 => SigType::I64,
            _ => return Err(mismatch),
        });
    }
    Ok(result)
}

fn copied_signature(values: &[SigType]) -> Result<Vec<SigType>, AdmissionError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| AdmissionError::Allocation)?;
    result.extend_from_slice(values);
    Ok(result)
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

fn compare_entities(
    left: &OwnedTopLevelEntityPin,
    right: &OwnedTopLevelEntityPin,
) -> core::cmp::Ordering {
    left.direction
        .cmp(&right.direction)
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.kind.cmp(&right.kind))
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

fn usize_u32(value: usize) -> Result<u32, AdmissionError> {
    u32::try_from(value).map_err(|_| AdmissionError::ArtifactLimit)
}

/// Invocation-scoped values for the closed Preview1 broker.
///
/// Only the two selected byte-stream endpoints and bounded argument strings
/// can enter the broker. There is deliberately no environment, path, process,
/// thread, socket, clock, random, descriptor table, or ambient resolver.
pub struct Preview1CorpusInvocationInput {
    stdin: Arc<ByteStreamReader>,
    stdout: Arc<ByteStreamWriter>,
    arguments: Vec<String>,
}

impl Preview1CorpusInvocationInput {
    pub fn new(
        stdin: Arc<ByteStreamReader>,
        stdout: Arc<ByteStreamWriter>,
        arguments: Vec<String>,
    ) -> Self {
        Self {
            stdin,
            stdout,
            arguments,
        }
    }
}

impl fmt::Debug for Preview1CorpusInvocationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preview1CorpusInvocationInput")
            .field("argument_count", &self.arguments.len())
            .field("streams", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview1CorpusBuildError {
    Admission(AdmissionError),
    Core(TrapCode),
    InvalidArguments,
    InvalidStreams,
    Allocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview1CorpusPending {
    Fuel,
    HostWork,
    Stdin,
    Stdout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview1CorpusTerminal {
    Exited(u32),
    Trapped(TrapCode),
    LimitExceeded,
    Denied,
    StreamFault,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preview1CorpusPoll {
    Pending {
        reason: Preview1CorpusPending,
        metrics: CallMetrics,
    },
    Ready(Preview1CorpusTerminal),
}

struct EncodedArguments {
    values: Vec<Vec<u8>>,
    encoded_bytes: usize,
}

fn encode_arguments(
    command_name: &str,
    supplied: Vec<String>,
    limits: CorpusLimits,
) -> Result<EncodedArguments, Preview1CorpusBuildError> {
    let count = supplied
        .len()
        .checked_add(1)
        .ok_or(Preview1CorpusBuildError::InvalidArguments)?;
    if count > limits.max_arguments {
        return Err(Preview1CorpusBuildError::InvalidArguments);
    }

    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| Preview1CorpusBuildError::Allocation)?;
    let mut encoded_bytes = 0_usize;
    for argument in core::iter::once(command_name).chain(supplied.iter().map(String::as_str)) {
        if argument.as_bytes().contains(&0) {
            return Err(Preview1CorpusBuildError::InvalidArguments);
        }
        encoded_bytes = encoded_bytes
            .checked_add(argument.len())
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or(Preview1CorpusBuildError::InvalidArguments)?;
        if encoded_bytes > limits.max_argument_bytes {
            return Err(Preview1CorpusBuildError::InvalidArguments);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(argument.len())
            .map_err(|_| Preview1CorpusBuildError::Allocation)?;
        bytes.extend_from_slice(argument.as_bytes());
        values.push(bytes);
    }
    Ok(EncodedArguments {
        values,
        encoded_bytes,
    })
}

#[derive(Clone, Copy)]
struct GuestIovec {
    start: usize,
    length: usize,
}

struct ReadState {
    host_call: u32,
    result_pointer: usize,
    iovecs: Vec<GuestIovec>,
    capacity: usize,
    operation: Option<HostOperationToken>,
}

struct WriteState {
    host_call: u32,
    result_pointer: usize,
    bytes: Vec<u8>,
    offset: usize,
    operation: Option<HostOperationToken>,
}

enum BrokerState {
    Core,
    Reading(ReadState),
    Writing(WriteState),
    Terminal(Preview1CorpusTerminal),
    Poisoned,
}

#[derive(Clone, Copy)]
enum IoIssue {
    Fault,
    Invalid,
    Limit,
}

#[derive(Clone, Copy)]
enum Preview1IoDirection {
    Read,
    Write,
}

/// Move-only invocation of the closed C8.2 Preview1 broker.
///
/// The broker exports no Core instance, memory, bytes, linker, descriptor
/// table, or host-operation token. Every poll performs at most one guest fuel
/// quantum or one bounded stream operation.
///
/// ```compile_fail
/// use vibeos_component_admission::Preview1CorpusInvocation;
/// fn raw(invocation: &Preview1CorpusInvocation) {
///     let _ = invocation.instance();
///     let _ = invocation.memory();
///     let _ = invocation.bytes();
///     let _ = invocation.operation_token();
/// }
/// ```
pub struct Preview1CorpusInvocation {
    instance: CoreInstance,
    stdin: Arc<ByteStreamReader>,
    stdout: Arc<ByteStreamWriter>,
    arguments: EncodedArguments,
    limits: CorpusLimits,
    state: BrokerState,
    host_calls: u32,
    stdin_bytes: usize,
    stdout_bytes: usize,
}

impl fmt::Debug for Preview1CorpusInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preview1CorpusInvocation")
            .field("host_calls", &self.host_calls)
            .field("stdin_bytes", &self.stdin_bytes)
            .field("stdout_bytes", &self.stdout_bytes)
            .field("state", &self.state_name())
            .finish()
    }
}

impl Preview1CorpusInvocation {
    pub const fn profile(&self) -> ProfileIdentity {
        ProfileIdentity::PROFILE_1_PREVIEW1_WRAPPED
    }

    pub const fn runtime_ready(&self) -> bool {
        false
    }

    pub const fn host_calls(&self) -> u32 {
        self.host_calls
    }

    pub const fn stdin_bytes(&self) -> usize {
        self.stdin_bytes
    }

    pub const fn stdout_bytes(&self) -> usize {
        self.stdout_bytes
    }

    /// Fuel evidence for the active or most recently terminated guest call.
    pub fn metrics(&self) -> Option<CallMetrics> {
        self.instance.call_metrics()
    }

    pub fn poll(&mut self) -> Preview1CorpusPoll {
        let state = core::mem::replace(&mut self.state, BrokerState::Poisoned);
        match state {
            BrokerState::Core => self.poll_core(),
            BrokerState::Reading(read) => self.poll_read(read),
            BrokerState::Writing(write) => self.poll_write(write),
            BrokerState::Terminal(terminal) => {
                self.state = BrokerState::Terminal(terminal);
                Preview1CorpusPoll::Ready(terminal)
            }
            BrokerState::Poisoned => self.finish_terminal(Preview1CorpusTerminal::Denied),
        }
    }

    /// Invocation-scoped cancellation. Pending stream work is revoked by its
    /// exact opaque token, and no further guest instruction is executed.
    pub fn cancel(&mut self) -> Preview1CorpusPoll {
        let state = core::mem::replace(&mut self.state, BrokerState::Poisoned);
        if let BrokerState::Terminal(terminal) = state {
            self.state = BrokerState::Terminal(terminal);
            return Preview1CorpusPoll::Ready(terminal);
        }
        self.cancel_stream_operation(&state);
        self.finish_terminal(Preview1CorpusTerminal::Cancelled)
    }

    fn poll_core(&mut self) -> Preview1CorpusPoll {
        match self.instance.poll_call() {
            PollResult::Pending {
                consumed_fuel,
                remaining_fuel,
            } => {
                self.state = BrokerState::Core;
                Preview1CorpusPoll::Pending {
                    reason: Preview1CorpusPending::Fuel,
                    metrics: CallMetrics {
                        consumed_fuel,
                        remaining_fuel,
                    },
                }
            }
            PollResult::Ready(values) => {
                if values.is_empty() {
                    self.finish_terminal(Preview1CorpusTerminal::Exited(0))
                } else {
                    self.finish_terminal(Preview1CorpusTerminal::Denied)
                }
            }
            PollResult::Trapped(TrapCode::FuelExhausted | TrapCode::LimitExceeded) => {
                self.finish_terminal(Preview1CorpusTerminal::LimitExceeded)
            }
            PollResult::Trapped(TrapCode::Cancelled) => {
                self.finish_terminal(Preview1CorpusTerminal::Cancelled)
            }
            PollResult::Trapped(trap) => {
                self.finish_terminal(Preview1CorpusTerminal::Trapped(trap))
            }
            PollResult::HostCall(call) => self.dispatch_host_call(call),
        }
    }

    fn dispatch_host_call(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        if call.origin_instance != 0 {
            return self.finish_terminal(Preview1CorpusTerminal::Denied);
        }
        let next_host_calls = match self.host_calls.checked_add(1) {
            Some(count) if count <= self.limits.max_host_calls => count,
            _ => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        let dispatch_work = match u64::try_from(call.arguments.len())
            .ok()
            .and_then(|arguments| HOST_DISPATCH_BASE_WORK.checked_add(arguments))
        {
            Some(work) => work,
            None => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        let continuation_reserve = if call.id == HOST_PROC_EXIT {
            0
        } else {
            HOST_RETURN_FUEL_RESERVE
        };
        if let Err(trap) = self.charge_host_work(dispatch_work, continuation_reserve) {
            return self.finish_host_work_error(trap);
        }
        self.host_calls = next_host_calls;

        match call.id {
            HOST_ARGS_SIZES_GET => self.args_sizes_get(call),
            HOST_ARGS_GET => self.args_get(call),
            HOST_FD_READ => self.fd_read(call),
            HOST_FD_WRITE => self.fd_write(call),
            HOST_PROC_EXIT => self.proc_exit(call),
            _ => self.finish_terminal(Preview1CorpusTerminal::Denied),
        }
    }

    fn args_sizes_get(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        let [argc_pointer, bytes_pointer] = match i32_arguments::<2>(&call) {
            Some(arguments) => arguments,
            None => return self.finish_terminal(Preview1CorpusTerminal::Denied),
        };
        let memory_size = match self.instance.memory_size(MEMORY_EXPORT) {
            Ok(size) => size,
            Err(trap) => return self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        };
        let argc_pointer = match checked_guest_range(memory_size, argc_pointer, 4) {
            Ok(pointer) => pointer,
            Err(_) => return self.resume_errno(call.id, ERRNO_FAULT),
        };
        let bytes_pointer = match checked_guest_range(memory_size, bytes_pointer, 4) {
            Ok(pointer) => pointer,
            Err(_) => return self.resume_errno(call.id, ERRNO_FAULT),
        };
        if ranges_overlap(
            argc_pointer..argc_pointer + 4,
            bytes_pointer..bytes_pointer + 4,
        ) {
            return self.resume_errno(call.id, ERRNO_INVAL);
        }
        let Ok(argc) = u32::try_from(self.arguments.values.len()) else {
            return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
        };
        let Ok(argument_bytes) = u32::try_from(self.arguments.encoded_bytes) else {
            return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
        };
        if let Err(trap) =
            self.charge_host_work(HOST_ARGS_SIZES_MEMORY_WORK, HOST_RETURN_FUEL_RESERVE)
        {
            return self.finish_host_work_error(trap);
        }
        if self.write_u32(argc_pointer, argc).is_err()
            || self.write_u32(bytes_pointer, argument_bytes).is_err()
        {
            return self
                .finish_terminal(Preview1CorpusTerminal::Trapped(TrapCode::MemoryOutOfBounds));
        }
        self.resume_errno(call.id, ERRNO_SUCCESS)
    }

    fn args_get(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        let [argv_pointer, buffer_pointer] = match i32_arguments::<2>(&call) {
            Some(arguments) => arguments,
            None => return self.finish_terminal(Preview1CorpusTerminal::Denied),
        };
        let memory_size = match self.instance.memory_size(MEMORY_EXPORT) {
            Ok(size) => size,
            Err(trap) => return self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        };
        let table_bytes = match self.arguments.values.len().checked_mul(4) {
            Some(bytes) => bytes,
            None => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        let argv_pointer = match checked_guest_range(memory_size, argv_pointer, table_bytes) {
            Ok(pointer) => pointer,
            Err(_) => return self.resume_errno(call.id, ERRNO_FAULT),
        };
        let buffer_pointer =
            match checked_guest_range(memory_size, buffer_pointer, self.arguments.encoded_bytes) {
                Ok(pointer) => pointer,
                Err(_) => return self.resume_errno(call.id, ERRNO_FAULT),
            };
        if ranges_overlap(
            argv_pointer..argv_pointer + table_bytes,
            buffer_pointer..buffer_pointer + self.arguments.encoded_bytes,
        ) {
            return self.resume_errno(call.id, ERRNO_INVAL);
        }
        let argument_work = match u64::try_from(table_bytes).ok().and_then(|table| {
            u64::try_from(self.arguments.encoded_bytes)
                .ok()
                .and_then(|encoded| table.checked_add(encoded))
        }) {
            Some(work) => work,
            None => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        if let Err(trap) = self.charge_host_work(argument_work, HOST_RETURN_FUEL_RESERVE) {
            return self.finish_host_work_error(trap);
        }

        let mut cursor = buffer_pointer;
        for index in 0..self.arguments.values.len() {
            let Ok(pointer) = u32::try_from(cursor) else {
                return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
            };
            if self.write_u32(argv_pointer + index * 4, pointer).is_err() {
                return self
                    .finish_terminal(Preview1CorpusTerminal::Trapped(TrapCode::MemoryOutOfBounds));
            }
            let argument = &self.arguments.values[index];
            if self
                .instance
                .write_memory(MEMORY_EXPORT, cursor, argument)
                .is_err()
                || self
                    .instance
                    .write_memory(MEMORY_EXPORT, cursor + argument.len(), &[0])
                    .is_err()
            {
                return self
                    .finish_terminal(Preview1CorpusTerminal::Trapped(TrapCode::MemoryOutOfBounds));
            }
            cursor += argument.len() + 1;
        }
        self.resume_errno(call.id, ERRNO_SUCCESS)
    }

    fn fd_read(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        let [fd, table_pointer, count, result_pointer] = match i32_arguments::<4>(&call) {
            Some(arguments) => arguments,
            None => return self.finish_terminal(Preview1CorpusTerminal::Denied),
        };
        if fd != 0 {
            return self.resume_errno(call.id, ERRNO_BADF);
        }
        let read_work = match preview1_io_work(self.limits, Preview1IoDirection::Read) {
            Some(work) => work,
            None => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        if let Err(trap) = self.charge_host_work(read_work, HOST_RETURN_FUEL_RESERVE) {
            return self.finish_host_work_error(trap);
        }
        let (iovecs, result_pointer, guest_capacity) =
            match self.parse_iovecs(table_pointer, count, result_pointer) {
                Ok(parsed) => parsed,
                Err(IoIssue::Fault) => return self.resume_errno(call.id, ERRNO_FAULT),
                Err(IoIssue::Invalid) => return self.resume_errno(call.id, ERRNO_INVAL),
                Err(IoIssue::Limit) => {
                    return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
                }
            };
        // Preview1 permits a guest iovec to describe its entire remaining
        // buffer. The policy bounds the bytes transferred by this host call,
        // so return a short read instead of rejecting that larger capacity.
        let capacity = core::cmp::min(guest_capacity, self.limits.max_io_bytes_per_call);
        let read = ReadState {
            host_call: call.id,
            result_pointer,
            iovecs,
            capacity,
            operation: None,
        };
        if capacity == 0 {
            return self.finish_read(read, &[], ERRNO_SUCCESS);
        }
        self.poll_read(read)
    }

    fn fd_write(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        let [fd, table_pointer, count, result_pointer] = match i32_arguments::<4>(&call) {
            Some(arguments) => arguments,
            None => return self.finish_terminal(Preview1CorpusTerminal::Denied),
        };
        if fd != 1 {
            return self.resume_errno(call.id, ERRNO_BADF);
        }
        let write_work = match preview1_io_work(self.limits, Preview1IoDirection::Write) {
            Some(work) => work,
            None => return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded),
        };
        if let Err(trap) = self.charge_host_work(write_work, HOST_RETURN_FUEL_RESERVE) {
            return self.finish_host_work_error(trap);
        }
        let (iovecs, result_pointer, guest_total) =
            match self.parse_iovecs(table_pointer, count, result_pointer) {
                Ok(parsed) => parsed,
                Err(IoIssue::Fault) => return self.resume_errno(call.id, ERRNO_FAULT),
                Err(IoIssue::Invalid) => return self.resume_errno(call.id, ERRNO_INVAL),
                Err(IoIssue::Limit) => {
                    return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
                }
            };
        // As with reads, a short write is the bounded Preview1 result. The
        // corpus guest is responsible for advancing and retrying its iovec.
        let total = core::cmp::min(guest_total, self.limits.max_io_bytes_per_call);
        if self
            .stdout_bytes
            .checked_add(total)
            .is_none_or(|bytes| bytes > self.limits.max_stdout_bytes)
        {
            return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(total).is_err() {
            return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
        }
        for iovec in iovecs {
            let remaining = total - bytes.len();
            if remaining == 0 {
                break;
            }
            let length = core::cmp::min(iovec.length, remaining);
            let offset = bytes.len();
            bytes.resize(offset + length, 0);
            if self
                .instance
                .read_memory(
                    MEMORY_EXPORT,
                    iovec.start,
                    &mut bytes[offset..offset + length],
                )
                .is_err()
            {
                return self.resume_errno(call.id, ERRNO_FAULT);
            }
        }
        let write = WriteState {
            host_call: call.id,
            result_pointer,
            bytes,
            offset: 0,
            operation: None,
        };
        if total == 0 {
            return self.finish_write(write, ERRNO_SUCCESS);
        }
        self.poll_write(write)
    }

    fn proc_exit(&mut self, call: CoreHostCall) -> Preview1CorpusPoll {
        let [status] = match i32_arguments::<1>(&call) {
            Some(arguments) => arguments,
            None => return self.finish_terminal(Preview1CorpusTerminal::Denied),
        };
        let termination = match self.instance.host_termination_token(call) {
            Ok(termination) => termination,
            Err(trap) => return self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        };
        match self.instance.terminate_suspended_host_call(termination) {
            Ok(()) => self.finish_terminal(Preview1CorpusTerminal::Exited(status)),
            Err(trap) => self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        }
    }

    fn poll_read(&mut self, mut read: ReadState) -> Preview1CorpusPoll {
        let prior_operation = read.operation.take();
        if prior_operation.is_some() {
            if let Err(trap) =
                self.charge_host_work(HOST_STREAM_RETRY_WORK, HOST_RETURN_FUEL_RESERVE)
            {
                if let Some(operation) = prior_operation {
                    let _ = self.stdin.cancel(operation);
                }
                return self.finish_host_work_error(trap);
            }
        }
        let dispatch = match prior_operation {
            Some(operation) => self.stdin.resume(operation),
            None => self.stdin.start(),
        };
        match dispatch {
            Ok(StreamReceiveDispatch::Waiting(operation)) => {
                read.operation = Some(operation);
                self.state = BrokerState::Reading(read);
                self.pending(Preview1CorpusPending::Stdin)
            }
            Ok(StreamReceiveDispatch::Prepared(prepared)) => {
                let length = prepared.length();
                if length == 0 || length > MAX_STREAM_CHUNK_BYTES {
                    let _ = self.stdin.cancel(prepared.operation());
                    return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
                }
                let Some(remaining_budget) =
                    self.limits.max_stdin_bytes.checked_sub(self.stdin_bytes)
                else {
                    let _ = self.stdin.cancel(prepared.operation());
                    return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
                };
                let delivered = read.capacity.min(length).min(remaining_budget);
                if delivered == 0 {
                    let _ = self.stdin.cancel(prepared.operation());
                    return self.finish_terminal(Preview1CorpusTerminal::LimitExceeded);
                }
                let mut bytes = [0_u8; MAX_STREAM_CHUNK_BYTES];
                let commit = self
                    .stdin
                    .commit_prefix(prepared.operation(), &mut bytes[..delivered]);
                match commit {
                    Ok(StreamReceiveCommit::Received(received)) if received == delivered => {
                        self.stdin_bytes += received;
                        self.finish_read(read, &bytes[..delivered], ERRNO_SUCCESS)
                    }
                    Ok(StreamReceiveCommit::Received(_)) => {
                        self.finish_terminal(Preview1CorpusTerminal::StreamFault)
                    }
                    Ok(StreamReceiveCommit::Closed(reason)) => {
                        let _ = self.stdin.cancel(prepared.operation());
                        self.finish_read(read, &[], errno_for_read_close(reason))
                    }
                    Err(_) => {
                        let _ = self.stdin.cancel(prepared.operation());
                        self.finish_terminal(Preview1CorpusTerminal::StreamFault)
                    }
                }
            }
            Ok(StreamReceiveDispatch::Closed(reason)) => {
                self.finish_read(read, &[], errno_for_read_close(reason))
            }
            Err(_) => {
                if let Some(operation) = prior_operation {
                    let _ = self.stdin.cancel(operation);
                }
                self.finish_terminal(Preview1CorpusTerminal::StreamFault)
            }
        }
    }

    fn finish_read(&mut self, read: ReadState, bytes: &[u8], errno: i32) -> Preview1CorpusPoll {
        let mut cursor = 0_usize;
        for iovec in &read.iovecs {
            let count = core::cmp::min(iovec.length, bytes.len() - cursor);
            if count == 0 {
                continue;
            }
            if self
                .instance
                .write_memory(MEMORY_EXPORT, iovec.start, &bytes[cursor..cursor + count])
                .is_err()
            {
                return self.resume_errno(read.host_call, ERRNO_FAULT);
            }
            cursor += count;
            if cursor == bytes.len() {
                break;
            }
        }
        if self.write_u32(read.result_pointer, cursor as u32).is_err() {
            return self.resume_errno(read.host_call, ERRNO_FAULT);
        }
        self.resume_errno(read.host_call, errno)
    }

    fn poll_write(&mut self, mut write: WriteState) -> Preview1CorpusPoll {
        let end = core::cmp::min(write.offset + MAX_STREAM_CHUNK_BYTES, write.bytes.len());
        let chunk = &write.bytes[write.offset..end];
        let prior_operation = write.operation.take();
        if prior_operation.is_some() {
            if let Err(trap) =
                self.charge_host_work(HOST_STREAM_RETRY_WORK, HOST_RETURN_FUEL_RESERVE)
            {
                if let Some(operation) = prior_operation {
                    let _ = self.stdout.cancel(operation);
                }
                return self.finish_host_work_error(trap);
            }
        }
        let dispatch = match prior_operation {
            Some(operation) => self.stdout.resume(operation, chunk),
            None => self.stdout.start(chunk),
        };
        match dispatch {
            Ok(StreamSendDispatch::Sent) => {
                self.stdout_bytes += chunk.len();
                write.offset = end;
                if write.offset == write.bytes.len() {
                    self.finish_write(write, ERRNO_SUCCESS)
                } else {
                    self.state = BrokerState::Writing(write);
                    self.pending(Preview1CorpusPending::HostWork)
                }
            }
            Ok(StreamSendDispatch::Waiting(operation)) => {
                write.operation = Some(operation);
                self.state = BrokerState::Writing(write);
                self.pending(Preview1CorpusPending::Stdout)
            }
            Ok(StreamSendDispatch::Closed(_)) => self.finish_write(write, ERRNO_PIPE),
            Err(_) => {
                if let Some(operation) = prior_operation {
                    let _ = self.stdout.cancel(operation);
                }
                self.finish_terminal(Preview1CorpusTerminal::StreamFault)
            }
        }
    }

    fn finish_write(&mut self, write: WriteState, errno: i32) -> Preview1CorpusPoll {
        if self
            .write_u32(write.result_pointer, write.offset as u32)
            .is_err()
        {
            return self.resume_errno(write.host_call, ERRNO_FAULT);
        }
        self.resume_errno(write.host_call, errno)
    }

    fn parse_iovecs(
        &self,
        table_pointer: u32,
        count: u32,
        result_pointer: u32,
    ) -> Result<(Vec<GuestIovec>, usize, usize), IoIssue> {
        let count = usize::try_from(count).map_err(|_| IoIssue::Limit)?;
        if count > self.limits.max_iovecs {
            return Err(IoIssue::Limit);
        }
        let memory_size = self
            .instance
            .memory_size(MEMORY_EXPORT)
            .map_err(|_| IoIssue::Fault)?;
        let table_bytes = count.checked_mul(8).ok_or(IoIssue::Limit)?;
        let table_pointer = checked_guest_range(memory_size, table_pointer, table_bytes)?;
        let result_pointer = checked_guest_range(memory_size, result_pointer, 4)?;
        let table_range = table_pointer..table_pointer + table_bytes;
        let result_range = result_pointer..result_pointer + 4;
        if ranges_overlap(table_range.clone(), result_range.clone()) {
            return Err(IoIssue::Invalid);
        }

        let mut iovecs: Vec<GuestIovec> = Vec::new();
        iovecs
            .try_reserve_exact(count)
            .map_err(|_| IoIssue::Limit)?;
        let mut total = 0_usize;
        for index in 0..count {
            let entry = table_pointer + index * 8;
            let mut raw = [0_u8; 8];
            self.instance
                .read_memory(MEMORY_EXPORT, entry, &mut raw)
                .map_err(|_| IoIssue::Fault)?;
            let pointer = u32::from_le_bytes(raw[..4].try_into().expect("four bytes"));
            let length = u32::from_le_bytes(raw[4..].try_into().expect("four bytes"));
            let length = usize::try_from(length).map_err(|_| IoIssue::Limit)?;
            let start = checked_guest_range(memory_size, pointer, length)?;
            let range = start..start + length;
            if ranges_overlap(range.clone(), table_range.clone())
                || ranges_overlap(range.clone(), result_range.clone())
                || iovecs.iter().any(|prior| {
                    ranges_overlap(
                        range.clone(),
                        prior.start..prior.start.saturating_add(prior.length),
                    )
                })
            {
                return Err(IoIssue::Invalid);
            }
            total = total.checked_add(length).ok_or(IoIssue::Limit)?;
            iovecs.push(GuestIovec { start, length });
        }
        Ok((iovecs, result_pointer, total))
    }

    fn resume_errno(&mut self, host_call: u32, errno: i32) -> Preview1CorpusPoll {
        match self
            .instance
            .resume_host_call(host_call, &[CoreValue::I32(errno)])
        {
            Ok(()) => {
                self.state = BrokerState::Core;
                self.pending(Preview1CorpusPending::HostWork)
            }
            Err(trap) => self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        }
    }

    /// Charges host/ABI work to the active Core ledger while retaining the
    /// requested continuation reserve. The `&mut self` check and debit are
    /// serialized, and the runtime debit itself is failure-atomic.
    fn charge_host_work(&mut self, amount: u64, reserve: u64) -> Result<(), TrapCode> {
        if !self.instance.has_active_call() {
            return Err(TrapCode::Validation);
        }
        let required = amount.checked_add(reserve).ok_or(TrapCode::FuelExhausted)?;
        let remaining = self
            .instance
            .call_metrics()
            .ok_or(TrapCode::Validation)?
            .remaining_fuel;
        if remaining < required {
            return Err(TrapCode::FuelExhausted);
        }
        self.instance.debit_call_fuel(amount)
    }

    fn finish_host_work_error(&mut self, trap: TrapCode) -> Preview1CorpusPoll {
        match trap {
            TrapCode::FuelExhausted | TrapCode::LimitExceeded => {
                self.finish_terminal(Preview1CorpusTerminal::LimitExceeded)
            }
            trap => self.finish_terminal(Preview1CorpusTerminal::Trapped(trap)),
        }
    }

    fn write_u32(&mut self, pointer: usize, value: u32) -> Result<(), TrapCode> {
        self.instance
            .write_memory(MEMORY_EXPORT, pointer, &value.to_le_bytes())
    }

    fn pending(&self, reason: Preview1CorpusPending) -> Preview1CorpusPoll {
        let metrics = self.instance.call_metrics().unwrap_or(CallMetrics {
            consumed_fuel: 0,
            remaining_fuel: 0,
        });
        Preview1CorpusPoll::Pending { reason, metrics }
    }

    fn finish_terminal(&mut self, terminal: Preview1CorpusTerminal) -> Preview1CorpusPoll {
        if self.instance.has_active_call() {
            let _ = self.instance.discard_call();
        }
        self.close_stream_endpoints(terminal);
        self.state = BrokerState::Terminal(terminal);
        Preview1CorpusPoll::Ready(terminal)
    }

    fn close_stream_endpoints(&self, terminal: Preview1CorpusTerminal) {
        // Stdin closure means only that this invocation is done consuming.
        // Publishing Normal is safe even when the producer or supervisor
        // already published another immutable reason, and it atomically
        // discards buffered input so a backpressured producer is released.
        let _ = self.stdin.close(StreamCloseReason::Normal);

        // An explicit process status is invocation metadata, not an output
        // transport failure. Keep every Exited status on the normal producer
        // close path so already-buffered stdout remains drainable before the
        // supervisor promotes the provisional close to final EOF.
        let _ = self.stdout.close(stdout_terminal_close_reason(terminal));
    }

    fn cancel_stream_operation(&self, state: &BrokerState) {
        match state {
            BrokerState::Reading(ReadState {
                operation: Some(operation),
                ..
            }) => {
                let _ = self.stdin.cancel(*operation);
            }
            BrokerState::Writing(WriteState {
                operation: Some(operation),
                ..
            }) => {
                let _ = self.stdout.cancel(*operation);
            }
            _ => {}
        }
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            BrokerState::Core => "core",
            BrokerState::Reading(_) => "stdin",
            BrokerState::Writing(_) => "stdout",
            BrokerState::Terminal(_) => "terminal",
            BrokerState::Poisoned => "poisoned",
        }
    }
}

impl Drop for Preview1CorpusInvocation {
    fn drop(&mut self) {
        let state = core::mem::replace(&mut self.state, BrokerState::Poisoned);
        self.cancel_stream_operation(&state);
        if self.instance.has_active_call() {
            let _ = self.instance.discard_call();
        }
        let terminal = match state {
            BrokerState::Terminal(terminal) => terminal,
            _ => Preview1CorpusTerminal::Cancelled,
        };
        // Repeat endpoint closure even for an already-terminal invocation.
        // Close is monotonic/idempotent for the same reason, so Drop remains
        // a final safety net without changing a terminal stream outcome.
        self.close_stream_endpoints(terminal);
    }
}

fn i32_arguments<const N: usize>(call: &CoreHostCall) -> Option<[u32; N]> {
    if call.arguments.len() != N {
        return None;
    }
    let mut values = [0_u32; N];
    for (output, input) in values.iter_mut().zip(&call.arguments) {
        let CoreValue::I32(value) = input else {
            return None;
        };
        *output = *value as u32;
    }
    Some(values)
}

/// Conservative versioned cost for one complete Preview1 fd operation.
///
/// The iovec term charges the result word, eight table bytes plus four units
/// of decode/range/allocation work per admitted slot, and every pairwise
/// overlap comparison. Three units per possible byte cover allocation or
/// scratch initialization, the guest-memory copy, and the stream copy. Fresh
/// stream attempts are prepaid here; only blocked retries pay separately.
fn preview1_io_work(limits: CorpusLimits, direction: Preview1IoDirection) -> Option<u64> {
    let iovecs = u64::try_from(limits.max_iovecs).ok()?;
    let overlap_pairs = iovecs.checked_mul(iovecs.checked_sub(1)?)? / 2;
    let iovec_work = HOST_IOVEC_FIXED_WORK
        .checked_add(HOST_IOVEC_SLOT_WORK.checked_mul(iovecs)?)?
        .checked_add(overlap_pairs)?;
    let maximum_bytes = match direction {
        Preview1IoDirection::Read => limits.max_io_bytes_per_call.min(MAX_STREAM_CHUNK_BYTES),
        Preview1IoDirection::Write => limits.max_io_bytes_per_call,
    };
    let maximum_bytes = u64::try_from(maximum_bytes).ok()?;
    let chunk_bytes = u64::try_from(MAX_STREAM_CHUNK_BYTES).ok()?;
    let stream_attempts = maximum_bytes
        .checked_add(chunk_bytes.checked_sub(1)?)?
        .checked_div(chunk_bytes)?;
    iovec_work
        .checked_add(HOST_IO_BYTE_WORK.checked_mul(maximum_bytes)?)?
        .checked_add(stream_attempts)
}

fn checked_guest_range(memory_size: usize, pointer: u32, length: usize) -> Result<usize, IoIssue> {
    let pointer = usize::try_from(pointer).map_err(|_| IoIssue::Fault)?;
    let end = pointer.checked_add(length).ok_or(IoIssue::Fault)?;
    if end > memory_size {
        return Err(IoIssue::Fault);
    }
    Ok(pointer)
}

fn ranges_overlap(left: Range<usize>, right: Range<usize>) -> bool {
    !left.is_empty() && !right.is_empty() && left.start < right.end && right.start < left.end
}

fn errno_for_read_close(reason: StreamCloseReason) -> i32 {
    if reason == StreamCloseReason::Normal {
        ERRNO_SUCCESS
    } else {
        ERRNO_IO
    }
}

fn terminal_close_reason(terminal: Preview1CorpusTerminal) -> StreamCloseReason {
    match terminal {
        Preview1CorpusTerminal::Exited(0) => StreamCloseReason::Normal,
        Preview1CorpusTerminal::Exited(_) => StreamCloseReason::Failure,
        Preview1CorpusTerminal::LimitExceeded => StreamCloseReason::Exhausted,
        Preview1CorpusTerminal::Denied => StreamCloseReason::Denied,
        Preview1CorpusTerminal::Cancelled => StreamCloseReason::Cancelled,
        Preview1CorpusTerminal::StreamFault | Preview1CorpusTerminal::Trapped(_) => {
            StreamCloseReason::BackendFault
        }
    }
}

fn stdout_terminal_close_reason(terminal: Preview1CorpusTerminal) -> StreamCloseReason {
    match terminal {
        Preview1CorpusTerminal::Exited(_) => StreamCloseReason::Normal,
        _ => terminal_close_reason(terminal),
    }
}
