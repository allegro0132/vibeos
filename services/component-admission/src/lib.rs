//! Pure inspection and policy admission for immutable Component artifacts.
//!
//! Component bytes remain data until [`admit`] returns a sealed, volatile
//! [`AdmittedComponent`]. Inspection never instantiates Core modules or runs
//! guest start code. The admitted template owns bytes and inert policy results,
//! but never stores a self-referential [`ComponentPlan`], a live capability, a
//! CSpace identity, or a guest resource token.

#![cfg_attr(
    not(feature = "native-async-acceptance"),
    doc = r#"
The validation-only native async admission surface is structurally absent by
default:

```compile_fail
use vibeos_component_admission::{
    admit_native_async_acceptance_candidate,
    AdmittedNativeAsyncAcceptanceCandidate,
};
```
"#
)]
#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};
pub use vibeos_component_format::ProfileIdentity;
#[cfg(feature = "native-async-acceptance")]
use vibeos_component_format::ProfileStage;
use vibeos_component_format::{ProfileLimits, PROFILE_1_LIMITS};
use vibeos_component_host::{
    HostManifestError, HostResourceKind, VibeHostManifest, VibeHostRequirement,
};
use vibeos_component_runtime::{
    decode::{inspect_component_for_profile, ComponentPlan, ComponentSummary, DecodeError},
    world::{NamedEntityShape, WorldContract, WorldError},
};
use vibeos_core::cap::Rights;
use vibeos_wasm_runtime::{inspect_core, AdmissionError as CoreAdmissionError, CoreSummary};

/// Exact Profile-1 command world that binds shell byte streams to the nominal
/// `reader` and `writer` resources in `vibe:stream/streams@1.0.0`.
pub const STREAM_FILTER_WORLD: &str = "vibe:stream/filter@1.0.0";

/// Exact validation-only native async stream world used by the isolated C5.3
/// acceptance candidate. This does not replace [`STREAM_FILTER_WORLD`] and is
/// never accepted by the synchronous command path.
#[cfg(feature = "native-async-acceptance")]
pub const NATIVE_STREAM_FILTER_WORLD: &str = "vibe:stream/native-filter@1.0.0";

/// Stable SHA-256 identity of the exact immutable Component bytes.
///
/// Formatting is deliberately redacted so diagnostics cannot accidentally
/// turn artifact identity into an ambient lookup or authority channel.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentIdentity([u8; 32]);

impl ComponentIdentity {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ComponentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ComponentIdentity(<redacted>)")
    }
}

/// Owned immutable bytes. Construction charges the public artifact bound before
/// performing a fallible copy.
pub struct ComponentArtifact {
    bytes: Vec<u8>,
    identity: ComponentIdentity,
    profile: ProfileIdentity,
}

impl ComponentArtifact {
    /// Copy immutable payload bytes while binding the trusted descriptor that
    /// supplied their revision identity. The descriptor is not parsed from a
    /// component-controlled custom section.
    pub fn copy_from(bytes: &[u8], profile: ProfileIdentity) -> Result<Self, AdmissionError> {
        if bytes.len() > PROFILE_1_LIMITS.max_artifact_bytes {
            return Err(AdmissionError::ArtifactLimit);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| AdmissionError::Allocation)?;
        owned.extend_from_slice(bytes);
        Ok(Self {
            identity: ComponentIdentity(Sha256::digest(bytes).into()),
            bytes: owned,
            profile,
        })
    }

    pub const fn identity(&self) -> ComponentIdentity {
        self.identity
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn inspect(&self) -> Result<InspectedComponent<'_>, AdmissionError> {
        if self.profile != ProfileIdentity::PROFILE_1
            && self.profile != ProfileIdentity::PROFILE_1_ASYNC
        {
            return Err(AdmissionError::BadProfile);
        }
        let plan = inspect_component_for_profile(&self.bytes, self.profile)
            .map_err(AdmissionError::Decode)?;
        let mut modules = Vec::new();
        modules
            .try_reserve_exact(plan.embedded_modules().len())
            .map_err(|_| AdmissionError::Allocation)?;
        for bytes in plan.embedded_modules() {
            modules.push(inspect_core(bytes).map_err(AdmissionError::Core)?);
        }
        Ok(InspectedComponent {
            artifact: self,
            plan,
            modules,
        })
    }
}

/// Borrowed pure inspection. The plan borrows the separately owned artifact,
/// so this type is not self-referential.
pub struct InspectedComponent<'a> {
    artifact: &'a ComponentArtifact,
    plan: ComponentPlan<'a>,
    modules: Vec<CoreSummary>,
}

impl InspectedComponent<'_> {
    pub const fn identity(&self) -> ComponentIdentity {
        self.artifact.identity
    }

    pub const fn summary(&self) -> ComponentSummary {
        self.plan.summary()
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.artifact.profile
    }

    pub const fn limits(&self) -> ProfileLimits {
        PROFILE_1_LIMITS
    }

    pub fn imports(&self) -> &[NamedEntityShape] {
        self.plan.imports()
    }

    pub fn exports(&self) -> &[NamedEntityShape] {
        self.plan.exports()
    }

    pub fn embedded_modules(&self) -> &[CoreSummary] {
        &self.modules
    }

    pub fn plan(&self) -> &ComponentPlan<'_> {
        &self.plan
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactTrust {
    /// Development/boot admission: the image pins the exact SHA-256 identity.
    /// Authenticated signer/operator policy is intentionally deferred to C7.
    ImagePinned(ComponentIdentity),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStreamMode {
    Required,
    Optional,
    Closed,
}

/// Exact instance ceilings selected by image policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstanceLimits {
    pub memory_bytes: usize,
    pub total_fuel: u64,
    pub poll_quantum: u64,
    pub resources: u16,
}

impl InstanceLimits {
    pub const fn profile_default(memory_bytes: usize) -> Self {
        Self {
            memory_bytes,
            total_fuel: PROFILE_1_LIMITS.total_fuel,
            poll_quantum: PROFILE_1_LIMITS.poll_quantum,
            resources: PROFILE_1_LIMITS.max_resources as u16,
        }
    }

    fn validate(self) -> Result<(), AdmissionError> {
        let maximum_memory = (PROFILE_1_LIMITS.max_memory_pages as usize)
            .checked_mul(65_536)
            .ok_or(AdmissionError::InvalidLimits)?;
        if self.memory_bytes == 0
            || self.memory_bytes > maximum_memory
            || self.total_fuel == 0
            || self.total_fuel > PROFILE_1_LIMITS.total_fuel
            || self.poll_quantum == 0
            || self.poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || self.poll_quantum > self.total_fuel
            || self.resources == 0
            || usize::from(self.resources) > PROFILE_1_LIMITS.max_resources as usize
        {
            return Err(AdmissionError::InvalidLimits);
        }
        Ok(())
    }
}

/// Image ceiling for one exact versioned host interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceCeiling<'a> {
    pub label: &'a str,
    pub interface: &'a str,
    pub kind: HostResourceKind,
    pub rights: Rights,
}

/// Caller-owned grantable authority offered to this admission operation.
/// This is metadata only: live Caps remain exclusively in the caller CSpace.
/// `grantable` is the already-attenuated operation-rights ceiling; the kernel
/// adapter may construct an offer only after verifying live `GRANT` authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityOffer<'a> {
    pub label: &'a str,
    pub kind: HostResourceKind,
    pub grantable: Rights,
}

pub struct AdmissionPolicy<'a> {
    pub command_name: &'a str,
    /// Exact public executable export selected by trusted image policy.
    pub entrypoint: &'a str,
    /// Shell-visible value arguments are policy, not inferred from the WIT
    /// function signature. The synchronous stream-filter runner introduced in
    /// C4 admits only `0..=0`; retaining these exact bounds in the sealed
    /// manifest prevents an integration adapter from inventing defaults.
    pub min_args: usize,
    pub max_args: usize,
    /// Semantic contract supplied by trusted policy code. Admission checks it
    /// exactly against the decoded artifact, but Rust values do not encode
    /// provenance: a policy adapter must derive this contract independently
    /// (normally by parsing image-pinned WIT), never by copying the artifact's
    /// own decoded imports/exports. The image/SSH integration gate exercises
    /// that independent-WIT path.
    pub exact_world: &'a WorldContract,
    pub profile: ProfileIdentity,
    pub trust: ArtifactTrust,
    pub limits: InstanceLimits,
    pub stdin: CommandStreamMode,
    pub stdout: CommandStreamMode,
    pub stderr: CommandStreamMode,
    pub interfaces: &'a [InterfaceCeiling<'a>],
}

pub struct CallerAuthority<'a> {
    pub offers: &'a [AuthorityOffer<'a>],
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthorityRequirement {
    label: String,
    interface: &'static str,
    resource: &'static str,
    kind: HostResourceKind,
    rights: Rights,
}

impl AuthorityRequirement {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn interface(&self) -> &'static str {
        self.interface
    }

    pub const fn resource(&self) -> &'static str {
        self.resource
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

/// Capability-free grant plan. Indices refer to immutable requirement/offer
/// arrays; no capability representation enters this crate.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorityGrant {
    requirement: u16,
    offer: u16,
    source_label: String,
    kind: HostResourceKind,
    rights: Rights,
}

impl AuthorityGrant {
    pub const fn requirement_index(&self) -> u16 {
        self.requirement
    }

    /// Ordinal in the caller offer table used during this admission. Kernel
    /// code may use this only while consuming that exact table transaction.
    pub const fn offer_index(&self) -> u16 {
        self.offer
    }

    /// Owned semantic route retained after the transient offer table is gone.
    /// A later instance must resolve this label again and revalidate live
    /// delegation authority; the label is never a capability representation.
    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    pub const fn kind(&self) -> HostResourceKind {
        self.kind
    }

    pub const fn rights(&self) -> Rights {
        self.rights
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ComponentCommandManifest {
    name: String,
    profile: ProfileIdentity,
    artifact: ComponentIdentity,
    world: String,
    entrypoint: String,
    min_args: usize,
    max_args: usize,
    stdin: CommandStreamMode,
    stdout: CommandStreamMode,
    stderr: CommandStreamMode,
    stream_transport: bool,
    limits: InstanceLimits,
    requirements: Vec<AuthorityRequirement>,
}

impl ComponentCommandManifest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn abi(&self) -> u16 {
        self.profile.runtime_abi
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub const fn artifact(&self) -> ComponentIdentity {
        self.artifact
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub const fn min_args(&self) -> usize {
        self.min_args
    }

    pub const fn max_args(&self) -> usize {
        self.max_args
    }

    pub const fn stdin(&self) -> CommandStreamMode {
        self.stdin
    }

    pub const fn stdout(&self) -> CommandStreamMode {
        self.stdout
    }

    pub const fn stderr(&self) -> CommandStreamMode {
        self.stderr
    }

    /// Whether stdin/stdout use the exact `vibe:stream/streams@1.0.0`
    /// transport. Transport resources are installed atomically by the trusted
    /// lifecycle and never appear in ambient requirements or grants.
    pub const fn uses_stream_transport(&self) -> bool {
        self.stream_transport
    }

    pub const fn limits(&self) -> InstanceLimits {
        self.limits
    }

    pub fn requirements(&self) -> &[AuthorityRequirement] {
        &self.requirements
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InspectionSummary {
    profile: ProfileIdentity,
    world: String,
    component: ComponentSummary,
    modules: Vec<CoreSummary>,
    imports: Vec<NamedEntityShape>,
    exports: Vec<NamedEntityShape>,
}

impl InspectionSummary {
    pub const fn profile(&self) -> ProfileIdentity {
        self.profile
    }

    pub fn world(&self) -> &str {
        &self.world
    }

    pub const fn component(&self) -> ComponentSummary {
        self.component
    }

    pub fn embedded_modules(&self) -> &[CoreSummary] {
        &self.modules
    }

    pub fn imports(&self) -> &[NamedEntityShape] {
        &self.imports
    }

    pub fn exports(&self) -> &[NamedEntityShape] {
        &self.exports
    }
}

mod private {
    pub struct Seal;
}

/// Sealed, authority-free C5.3 validation candidate.
///
/// This type is deliberately distinct from [`AdmittedComponent`]: it has no
/// ordinary command manifest, no grants, and no conversion into the
/// synchronous runner. The native identity remains `ValidationOnly`; a later
/// kernel acceptance driver may borrow a freshly revalidated plan only through
/// [`Self::validated_plan`].
#[cfg(feature = "native-async-acceptance")]
pub struct AdmittedNativeAsyncAcceptanceCandidate {
    artifact: ComponentArtifact,
    inspection: InspectionSummary,
    command_name: String,
    entrypoint: String,
    min_args: usize,
    max_args: usize,
    limits: InstanceLimits,
    stdin: CommandStreamMode,
    stdout: CommandStreamMode,
    stderr: CommandStreamMode,
    _sealed: private::Seal,
}

#[cfg(feature = "native-async-acceptance")]
impl AdmittedNativeAsyncAcceptanceCandidate {
    pub const fn identity(&self) -> ComponentIdentity {
        self.artifact.identity
    }

    pub fn inspection(&self) -> &InspectionSummary {
        &self.inspection
    }

    pub fn command_name(&self) -> &str {
        &self.command_name
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.inspection.profile
    }

    pub const fn abi(&self) -> u16 {
        self.inspection.profile.runtime_abi
    }

    pub fn world(&self) -> &str {
        &self.inspection.world
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub const fn min_args(&self) -> usize {
        self.min_args
    }

    pub const fn max_args(&self) -> usize {
        self.max_args
    }

    pub const fn limits(&self) -> InstanceLimits {
        self.limits
    }

    pub const fn stdin(&self) -> CommandStreamMode {
        self.stdin
    }

    pub const fn stdout(&self) -> CommandStreamMode {
        self.stdout
    }

    pub const fn stderr(&self) -> CommandStreamMode {
        self.stderr
    }

    /// Revalidate the exact immutable bytes and the closed native executor
    /// topology without changing either runtime-readiness bit.
    pub fn validated_plan(&self) -> Result<ComponentPlan<'_>, AdmissionError> {
        let identity = ComponentIdentity(Sha256::digest(&self.artifact.bytes).into());
        if identity != self.artifact.identity
            || self.artifact.profile != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
            || self.inspection.profile != self.artifact.profile
            || self.inspection.world != NATIVE_STREAM_FILTER_WORLD
            || !valid_name(&self.command_name)
            || !valid_entrypoint(&self.entrypoint)
            || self.entrypoint != "run"
            || self.min_args != 0
            || self.max_args != 0
            || self.limits.validate().is_err()
            || usize::from(self.limits.resources) != PROFILE_1_LIMITS.max_resources as usize
            || self.stdin != CommandStreamMode::Required
            || self.stdout != CommandStreamMode::Required
            || self.stderr == CommandStreamMode::Required
        {
            return Err(AdmissionError::RevalidationMismatch);
        }

        let plan = inspect_component_for_profile(&self.artifact.bytes, self.artifact.profile)
            .map_err(AdmissionError::Decode)?;
        if plan.summary() != self.inspection.component
            || plan.profile() != self.inspection.profile
            || plan.imports() != self.inspection.imports
            || plan.exports() != self.inspection.exports
            || plan.embedded_modules().len() != self.inspection.modules.len()
            || !native_async_acceptance_plan_matches(&plan, &self.entrypoint)
        {
            return Err(AdmissionError::RevalidationMismatch);
        }
        for (bytes, expected) in plan.embedded_modules().iter().zip(&self.inspection.modules) {
            if inspect_core(bytes).map_err(AdmissionError::Core)? != *expected {
                return Err(AdmissionError::RevalidationMismatch);
            }
        }
        Ok(plan)
    }
}

/// Volatile, sealed result of complete inspection and policy intersection.
pub struct AdmittedComponent {
    artifact: ComponentArtifact,
    inspection: InspectionSummary,
    command: ComponentCommandManifest,
    grants: Vec<AuthorityGrant>,
    _sealed: private::Seal,
}

impl AdmittedComponent {
    pub const fn identity(&self) -> ComponentIdentity {
        self.artifact.identity
    }

    pub fn inspection(&self) -> &InspectionSummary {
        &self.inspection
    }

    pub fn command_manifest(&self) -> &ComponentCommandManifest {
        &self.command
    }

    pub fn grants(&self) -> &[AuthorityGrant] {
        &self.grants
    }

    pub fn validated_plan(&self) -> Result<ComponentPlan<'_>, AdmissionError> {
        let identity = ComponentIdentity(Sha256::digest(&self.artifact.bytes).into());
        if identity != self.artifact.identity
            || identity != self.command.artifact
            || self.artifact.profile != ProfileIdentity::PROFILE_1
            || self.artifact.profile != self.command.profile
            || self.artifact.profile != self.inspection.profile
            || self.inspection.profile != ProfileIdentity::PROFILE_1
            || self.command.world != self.inspection.world
            || !valid_manifest_text(&self.inspection.world, 256)
            || !valid_name(&self.command.name)
            || !valid_entrypoint(&self.command.entrypoint)
            || !valid_argument_limits(self.command.min_args, self.command.max_args)
            || self.command.limits.validate().is_err()
            || (self.command.stream_transport
                && (self.command.world != STREAM_FILTER_WORLD
                    || self.command.min_args != 0
                    || self.command.max_args != 0
                    || self.command.stdin != CommandStreamMode::Required
                    || self.command.stdout != CommandStreamMode::Required
                    || self.command.stderr == CommandStreamMode::Required
                    || !self.command.requirements.is_empty()
                    || !self.grants.is_empty()))
            || self.grants.len() != self.command.requirements.len()
        {
            return Err(AdmissionError::RevalidationMismatch);
        }

        for (index, (grant, requirement)) in self
            .grants
            .iter()
            .zip(&self.command.requirements)
            .enumerate()
        {
            if usize::from(grant.requirement) != index
                || grant.kind != requirement.kind
                || grant.rights != requirement.rights
                || !valid_label(&grant.source_label)
                || !valid_label(&requirement.label)
                || !operation_rights(requirement.kind).contains(requirement.rights)
            {
                return Err(AdmissionError::RevalidationMismatch);
            }
        }

        let plan = inspect_component_for_profile(&self.artifact.bytes, self.artifact.profile)
            .map_err(AdmissionError::Decode)?;
        if plan.summary() != self.inspection.component
            || plan.profile() != self.artifact.profile
            || !plan.runtime_ready()
            || plan.imports() != self.inspection.imports
            || plan.exports() != self.inspection.exports
            || plan.embedded_modules().len() != self.inspection.modules.len()
        {
            return Err(AdmissionError::RevalidationMismatch);
        }
        for (bytes, expected) in plan.embedded_modules().iter().zip(&self.inspection.modules) {
            if inspect_core(bytes).map_err(AdmissionError::Core)? != *expected {
                return Err(AdmissionError::RevalidationMismatch);
            }
        }

        let entrypoints = plan
            .executable_exports()
            .filter(|export| export.name == self.command.entrypoint)
            .count();
        if entrypoints != 1 {
            return Err(AdmissionError::RevalidationMismatch);
        }

        if !host_manifest_matches(
            &plan,
            &self.command.requirements,
            self.command.stream_transport,
        )? {
            return Err(AdmissionError::RevalidationMismatch);
        }
        Ok(plan)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum AdmissionError {
    ArtifactLimit = 1,
    Allocation = 2,
    Decode(DecodeError) = 3,
    Core(CoreAdmissionError) = 4,
    BadProfile = 5,
    UntrustedArtifact = 6,
    InvalidLimits = 7,
    InvalidCommandName = 8,
    World(WorldError) = 9,
    HostManifest(HostManifestError) = 10,
    InvalidPolicy = 11,
    MissingImageCeiling = 12,
    MissingCallerAuthority = 13,
    RightsAmplification = 14,
    RevalidationMismatch = 15,
    InvalidEntrypoint = 16,
    InvalidArgumentLimits = 17,
    RuntimeUnavailable = 18,
}

impl AdmissionError {
    pub const fn code(self) -> u16 {
        match self {
            Self::ArtifactLimit => 1,
            Self::Allocation => 2,
            Self::Decode(_) => 3,
            Self::Core(_) => 4,
            Self::BadProfile => 5,
            Self::UntrustedArtifact => 6,
            Self::InvalidLimits => 7,
            Self::InvalidCommandName => 8,
            Self::World(_) => 9,
            Self::HostManifest(_) => 10,
            Self::InvalidPolicy => 11,
            Self::MissingImageCeiling => 12,
            Self::MissingCallerAuthority => 13,
            Self::RightsAmplification => 14,
            Self::RevalidationMismatch => 15,
            Self::InvalidEntrypoint => 16,
            Self::InvalidArgumentLimits => 17,
            Self::RuntimeUnavailable => 18,
        }
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ArtifactLimit => "component artifact exceeds the profile bound",
            Self::Allocation => "component admission allocation failed",
            Self::Decode(_) => "component validation failed",
            Self::Core(_) => "embedded Core validation failed",
            Self::BadProfile => "component profile identity does not match image policy",
            Self::UntrustedArtifact => "component artifact is not pinned by image policy",
            Self::InvalidLimits => "component instance limits are invalid",
            Self::InvalidCommandName => "component command name is invalid",
            Self::World(_) => "component WIT world does not match image policy",
            Self::HostManifest(_) => "component host import manifest is invalid",
            Self::InvalidPolicy => "component admission policy is ambiguous or invalid",
            Self::MissingImageCeiling => "component requirement has no image-policy ceiling",
            Self::MissingCallerAuthority => {
                "component requirement has no matching caller authority"
            }
            Self::RightsAmplification => "component admission would amplify authority",
            Self::RevalidationMismatch => "component revalidation differs from admitted manifest",
            Self::InvalidEntrypoint => "component entrypoint is not an executable export",
            Self::InvalidArgumentLimits => "component command argument limits are invalid",
            Self::RuntimeUnavailable => {
                "component requires async execution that is unavailable before C5.2"
            }
        })
    }
}

/// Apply exact profile, world, host-interface, image, and caller policy without
/// instantiating or executing the component.
pub fn admit(
    artifact: ComponentArtifact,
    policy: &AdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedComponent, AdmissionError> {
    if policy.profile != ProfileIdentity::PROFILE_1
        && policy.profile != ProfileIdentity::PROFILE_1_ASYNC
    {
        return Err(AdmissionError::BadProfile);
    }
    if artifact.profile != policy.profile {
        return Err(AdmissionError::BadProfile);
    }
    if policy.trust != ArtifactTrust::ImagePinned(artifact.identity) {
        return Err(AdmissionError::UntrustedArtifact);
    }
    policy.limits.validate()?;
    if !valid_name(policy.command_name) {
        return Err(AdmissionError::InvalidCommandName);
    }
    if !valid_entrypoint(policy.entrypoint) {
        return Err(AdmissionError::InvalidEntrypoint);
    }
    if !valid_argument_limits(policy.min_args, policy.max_args) {
        return Err(AdmissionError::InvalidArgumentLimits);
    }
    if !valid_manifest_text(&policy.exact_world.identity, 256) {
        return Err(AdmissionError::InvalidPolicy);
    }
    if policy.interfaces.len() > PROFILE_1_LIMITS.max_imports as usize
        || caller.offers.len() > PROFILE_1_LIMITS.max_imports as usize
    {
        return Err(AdmissionError::InvalidPolicy);
    }
    validate_policy_tables(policy.interfaces, caller.offers)?;

    let (component, modules, imports, exports, host_requirements, stream_transport) = {
        let InspectedComponent { plan, modules, .. } = artifact.inspect()?;
        plan.check_world(policy.exact_world)
            .map_err(AdmissionError::World)?;
        if !policy.profile.execution_enabled() || !plan.runtime_ready() {
            return Err(AdmissionError::RuntimeUnavailable);
        }
        let entrypoints = plan
            .executable_exports()
            .filter(|export| export.name == policy.entrypoint)
            .count();
        if entrypoints != 1 {
            return Err(AdmissionError::InvalidEntrypoint);
        }
        let mut requirements = Vec::new();
        let mut stream_reader = false;
        let mut stream_writer = false;
        if !plan.imports().is_empty() || plan.host_imports().next().is_some() {
            let host = VibeHostManifest::from_plan(&plan).map_err(AdmissionError::HostManifest)?;
            requirements
                .try_reserve_exact(host.requirements().count())
                .map_err(|_| AdmissionError::Allocation)?;
            for requirement in host.requirements() {
                match requirement.kind() {
                    HostResourceKind::ByteStreamReader => stream_reader = true,
                    HostResourceKind::ByteStreamWriter => stream_writer = true,
                    _ => requirements.push(requirement),
                }
            }
        }
        if stream_reader != stream_writer {
            return Err(AdmissionError::InvalidPolicy);
        }
        let stream_transport = stream_reader && stream_writer;
        if stream_transport
            && (policy.exact_world.identity != STREAM_FILTER_WORLD
                || policy.min_args != 0
                || policy.max_args != 0
                || policy.stdin != CommandStreamMode::Required
                || policy.stdout != CommandStreamMode::Required
                || policy.stderr == CommandStreamMode::Required
                || !requirements.is_empty())
        {
            return Err(AdmissionError::InvalidPolicy);
        }
        let component = plan.summary();
        (
            component,
            modules,
            plan.imports,
            plan.exports,
            requirements,
            stream_transport,
        )
    };

    let mut requirements = Vec::new();
    let mut grants = Vec::new();
    requirements
        .try_reserve_exact(host_requirements.len())
        .map_err(|_| AdmissionError::Allocation)?;
    grants
        .try_reserve_exact(host_requirements.len())
        .map_err(|_| AdmissionError::Allocation)?;

    for host in host_requirements {
        let (ceiling_index, ceiling) = unique_ceiling(policy.interfaces, host)?;
        let (offer_index, offer) = unique_offer(caller.offers, ceiling, host)?;
        let rights = host.rights();
        if !ceiling.rights.contains(rights) || !offer.grantable.contains(rights) {
            return Err(AdmissionError::RightsAmplification);
        }
        let requirement =
            u16::try_from(requirements.len()).map_err(|_| AdmissionError::InvalidPolicy)?;
        let offer_ordinal =
            u16::try_from(offer_index).map_err(|_| AdmissionError::InvalidPolicy)?;
        let label = copied(ceiling.label)?;
        let source_label = copied(offer.label)?;
        requirements.push(AuthorityRequirement {
            label,
            interface: host.interface(),
            resource: host.resource(),
            kind: host.kind(),
            rights,
        });
        grants.push(AuthorityGrant {
            requirement,
            offer: offer_ordinal,
            source_label,
            kind: host.kind(),
            rights,
        });
        let _ = ceiling_index;
    }

    let name = copied(policy.command_name)?;
    let world = copied(&policy.exact_world.identity)?;
    let inspection_world = copied(&policy.exact_world.identity)?;
    let entrypoint = copied(policy.entrypoint)?;
    let command = ComponentCommandManifest {
        name,
        profile: policy.profile,
        artifact: artifact.identity,
        world,
        entrypoint,
        min_args: policy.min_args,
        max_args: policy.max_args,
        stdin: policy.stdin,
        stdout: policy.stdout,
        stderr: policy.stderr,
        stream_transport,
        limits: policy.limits,
        requirements,
    };
    Ok(AdmittedComponent {
        artifact,
        inspection: InspectionSummary {
            profile: policy.profile,
            world: inspection_world,
            component,
            modules,
            imports,
            exports,
        },
        command,
        grants,
        _sealed: private::Seal,
    })
}

/// Admit the one isolated, validation-only native async acceptance shape.
///
/// The caller and image-policy authority tables must both be empty. Native
/// stream endpoints are lifecycle-owned transport in the later kernel driver;
/// WIT types and immutable bytes cannot mint ambient authority here.
#[cfg(feature = "native-async-acceptance")]
pub fn admit_native_async_acceptance_candidate(
    artifact: ComponentArtifact,
    policy: &AdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedNativeAsyncAcceptanceCandidate, AdmissionError> {
    let profile = ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE;
    if policy.profile != profile || artifact.profile != profile {
        return Err(AdmissionError::BadProfile);
    }
    if profile.stage != ProfileStage::ValidationOnly || profile.execution_enabled() {
        return Err(AdmissionError::BadProfile);
    }
    if policy.trust != ArtifactTrust::ImagePinned(artifact.identity) {
        return Err(AdmissionError::UntrustedArtifact);
    }
    policy.limits.validate()?;
    if usize::from(policy.limits.resources) != PROFILE_1_LIMITS.max_resources as usize {
        return Err(AdmissionError::InvalidLimits);
    }
    if !valid_name(policy.command_name) {
        return Err(AdmissionError::InvalidCommandName);
    }
    if policy.entrypoint != "run" || !valid_entrypoint(policy.entrypoint) {
        return Err(AdmissionError::InvalidEntrypoint);
    }
    if policy.min_args != 0 || policy.max_args != 0 {
        return Err(AdmissionError::InvalidArgumentLimits);
    }
    if policy.exact_world.identity != NATIVE_STREAM_FILTER_WORLD
        || !valid_manifest_text(&policy.exact_world.identity, 256)
        || policy.stdin != CommandStreamMode::Required
        || policy.stdout != CommandStreamMode::Required
        || policy.stderr == CommandStreamMode::Required
        || !policy.interfaces.is_empty()
        || !caller.offers.is_empty()
    {
        return Err(AdmissionError::InvalidPolicy);
    }

    let (component, modules, imports, exports) = {
        let plan = inspect_component_for_profile(&artifact.bytes, profile)
            .map_err(AdmissionError::Decode)?;
        plan.check_world(policy.exact_world)
            .map_err(AdmissionError::World)?;
        if !native_async_acceptance_plan_matches(&plan, policy.entrypoint) {
            return Err(AdmissionError::InvalidPolicy);
        }

        let mut modules = Vec::new();
        modules
            .try_reserve_exact(plan.embedded_modules().len())
            .map_err(|_| AdmissionError::Allocation)?;
        for bytes in plan.embedded_modules() {
            modules.push(inspect_core(bytes).map_err(AdmissionError::Core)?);
        }
        (plan.summary(), modules, plan.imports, plan.exports)
    };

    Ok(AdmittedNativeAsyncAcceptanceCandidate {
        artifact,
        inspection: InspectionSummary {
            profile,
            world: copied(&policy.exact_world.identity)?,
            component,
            modules,
            imports,
            exports,
        },
        command_name: copied(policy.command_name)?,
        entrypoint: copied(policy.entrypoint)?,
        min_args: policy.min_args,
        max_args: policy.max_args,
        limits: policy.limits,
        stdin: policy.stdin,
        stdout: policy.stdout,
        stderr: policy.stderr,
        _sealed: private::Seal,
    })
}

#[cfg(feature = "native-async-acceptance")]
fn native_async_acceptance_plan_matches(plan: &ComponentPlan<'_>, entrypoint: &str) -> bool {
    if plan.profile() != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
        || plan.profile().stage != ProfileStage::ValidationOnly
        || plan.runtime_ready()
        || plan.native_async_runtime_ready()
        || plan.summary().resources != 0
        || plan.embedded_modules().len() != 2
        || plan.runtime_instance_count() != 2
        || !native_async_memory_provider_matches(plan.embedded_modules()[0])
        || plan.exports().len() != 1
        || plan.executable_exports().next().is_some()
        || plan.host_imports().next().is_some()
    {
        return false;
    }
    let Some(native) = plan.native_async_execution_plan() else {
        return false;
    };
    if !native_async_instances_match(native)
        || !native_async_canonical_plans_match(native)
        || !native_async_import_bridges_match(native)
        || native.exports().len() != 1
        || native.exports()[0].name != entrypoint
        || native.exports()[0].canonical != 14
    {
        return false;
    }
    true
}

#[cfg(feature = "native-async-acceptance")]
fn native_async_memory_provider_matches(bytes: &[u8]) -> bool {
    let Ok(summary) = inspect_core(bytes) else {
        return false;
    };
    summary.types == 0
        && summary.functions == 0
        && summary.max_params == 0
        && summary.max_results == 0
        && summary.imports == 0
        && summary.exports == 1
        && summary.globals == 0
        && summary.locals == 0
        && summary.memories == 1
        && summary.tables == 0
        && summary.data_segments == 0
        && summary.element_segments == 0
        // The version-pinned WAT encoder emits one name section for the
        // provider's symbolic module/memory labels. No other custom payload
        // is admitted by this exact artifact topology.
        && summary.custom_sections == 1
        && summary.custom_section_bytes == 18
        && summary.max_control_depth == 0
}

#[cfg(feature = "native-async-acceptance")]
fn native_async_instances_match(
    native: &vibeos_component_runtime::decode::NativeAsyncExecutionPlan,
) -> bool {
    use vibeos_component_runtime::decode::NativeAsyncCoreImportPlan;

    let [memory, guest] = native.instances() else {
        return false;
    };
    if memory.module != 0 || !memory.imports.is_empty() || guest.module != 1 {
        return false;
    }
    let Some((first, canonical)) = guest.imports.split_first() else {
        return false;
    };
    if !matches!(
        first,
        NativeAsyncCoreImportPlan::InstanceExport {
            module,
            field,
            core_instance: 0,
            export,
        } if module == "env" && field == "memory" && export == "memory"
    ) || canonical.len() != 14
    {
        return false;
    }
    canonical.iter().enumerate().all(|(index, import)| {
        matches!(
            import,
            NativeAsyncCoreImportPlan::Canonical { bridge }
                if usize::try_from(*bridge).ok() == Some(index)
        )
    })
}

#[cfg(feature = "native-async-acceptance")]
fn native_async_canonical_plans_match(
    native: &vibeos_component_runtime::decode::NativeAsyncExecutionPlan,
) -> bool {
    use vibeos_component_runtime::decode::{
        NativeAsyncCanonicalFunctionPlan as Function, NativeAsyncFuturePlan as Future,
        NativeAsyncStreamPlan as Stream, NativeAsyncWaitablePlan as Waitable,
    };
    use vibeos_component_runtime::world::FunctionEffect;

    let plans = native.canonical_plans();
    if plans.len() != 15
        || !plans
            .iter()
            .enumerate()
            .all(|(index, plan)| usize::try_from(plan.canonical_index).ok() == Some(index))
    {
        return false;
    }
    for (index, plan) in plans.iter().enumerate() {
        let matches = match (index, &plan.function) {
            (0, Function::TaskReturn { result, options }) => {
                result.as_ref().is_some_and(native_byte_stream_type)
                    && native_options_match(options, false, false)
            }
            (
                1,
                Function::Stream(Stream::New {
                    type_index,
                    value_type,
                }),
            ) => *type_index == 3 && native_bytes_type(value_type),
            (
                2,
                Function::Stream(Stream::Read {
                    type_index,
                    value_type,
                    options,
                }),
            )
            | (
                3,
                Function::Stream(Stream::Write {
                    type_index,
                    value_type,
                    options,
                }),
            ) => {
                *type_index == 3
                    && native_bytes_type(value_type)
                    && native_options_match(options, true, true)
            }
            (
                4,
                Function::Stream(Stream::DropReadable {
                    type_index,
                    value_type,
                }),
            )
            | (
                5,
                Function::Stream(Stream::DropWritable {
                    type_index,
                    value_type,
                }),
            ) => *type_index == 3 && native_bytes_type(value_type),
            (
                6,
                Function::Future(Future::New {
                    type_index,
                    value_type,
                }),
            ) => *type_index == 5 && native_closed_type(value_type),
            (
                7,
                Function::Future(Future::Read {
                    type_index,
                    value_type,
                    options,
                }),
            )
            | (
                8,
                Function::Future(Future::Write {
                    type_index,
                    value_type,
                    options,
                }),
            ) => {
                *type_index == 5
                    && native_closed_type(value_type)
                    && native_options_match(options, true, true)
            }
            (
                9,
                Function::Future(Future::DropReadable {
                    type_index,
                    value_type,
                }),
            )
            | (
                10,
                Function::Future(Future::DropWritable {
                    type_index,
                    value_type,
                }),
            ) => *type_index == 5 && native_closed_type(value_type),
            (11, Function::Waitable(Waitable::SetNew))
            | (12, Function::Waitable(Waitable::SetDrop))
            | (13, Function::Waitable(Waitable::Join)) => true,
            (
                14,
                Function::Lift {
                    core_function,
                    function_type,
                    callback,
                    options,
                },
            ) => {
                core_function.core_instance == 1
                    && core_function.export == "run"
                    && callback.core_instance == 1
                    && callback.export == "callback"
                    && native_options_match(options, true, false)
                    && function_type.effect == FunctionEffect::Async
                    && function_type.parameters.len() == 1
                    && function_type.parameters[0].name == "input"
                    && native_byte_stream_type(&function_type.parameters[0].value)
                    && function_type
                        .result
                        .as_ref()
                        .is_some_and(native_byte_stream_type)
            }
            _ => false,
        };
        if !matches {
            return false;
        }
    }
    true
}

#[cfg(feature = "native-async-acceptance")]
fn native_async_import_bridges_match(
    native: &vibeos_component_runtime::decode::NativeAsyncExecutionPlan,
) -> bool {
    use vibeos_component_runtime::decode::AsyncCoreValueType::{I32, I64};

    const FIELDS: [&str; 14] = [
        "task-return",
        "stream-new",
        "stream-read",
        "stream-write",
        "stream-drop-readable",
        "stream-drop-writable",
        "future-new",
        "future-read",
        "future-write",
        "future-drop-readable",
        "future-drop-writable",
        "waitable-set-new",
        "waitable-set-drop",
        "waitable-join",
    ];
    let bridges = native.canonical_import_bridges();
    if bridges.len() != FIELDS.len() {
        return false;
    }
    bridges.iter().enumerate().all(|(index, bridge)| {
        bridge.core_instance == 1
            && bridge.core_module == "vibe:async"
            && bridge.core_field == FIELDS[index]
            && usize::try_from(bridge.canonical).ok() == Some(index)
            && match index {
                0 => {
                    bridge.signature.parameters == [I32, I32] && bridge.signature.results.is_empty()
                }
                1 | 6 => {
                    bridge.signature.parameters.is_empty() && bridge.signature.results == [I64]
                }
                2 | 3 => {
                    bridge.signature.parameters == [I32, I32, I32]
                        && bridge.signature.results == [I32]
                }
                4 | 5 | 9 | 10 | 12 => {
                    bridge.signature.parameters == [I32] && bridge.signature.results.is_empty()
                }
                7 | 8 => {
                    bridge.signature.parameters == [I32, I32] && bridge.signature.results == [I32]
                }
                11 => bridge.signature.parameters.is_empty() && bridge.signature.results == [I32],
                13 => {
                    bridge.signature.parameters == [I32, I32] && bridge.signature.results.is_empty()
                }
                _ => false,
            }
    })
}

#[cfg(feature = "native-async-acceptance")]
fn native_options_match(
    options: &vibeos_component_runtime::decode::NativeAsyncCanonicalOptionsPlan,
    async_: bool,
    memory: bool,
) -> bool {
    options.string_encoding.is_none()
        && options.async_ == async_
        && options.realloc.is_none()
        && match (&options.memory, memory) {
            (None, false) => true,
            (Some(memory), true) => memory.core_instance == 0 && memory.export == "memory",
            _ => false,
        }
}

#[cfg(feature = "native-async-acceptance")]
fn native_bytes_type(value: &vibeos_component_runtime::value::ValueType) -> bool {
    use vibeos_component_runtime::value::ValueType;

    matches!(
        value,
        ValueType::Stream {
            type_id,
            element: Some(element),
        } if type_id.get() == 1 && **element == ValueType::U8
    )
}

#[cfg(feature = "native-async-acceptance")]
fn native_closed_type(value: &vibeos_component_runtime::value::ValueType) -> bool {
    use vibeos_component_runtime::value::ValueType;

    matches!(
        value,
        ValueType::Future {
            type_id,
            payload: Some(payload),
        } if type_id.get() == 2 && **payload == ValueType::Enum(8)
    )
}

#[cfg(feature = "native-async-acceptance")]
fn native_byte_stream_type(value: &vibeos_component_runtime::value::ValueType) -> bool {
    use vibeos_component_runtime::value::ValueType;

    matches!(
        value,
        ValueType::Record(fields)
            if fields.len() == 2
                && native_bytes_type(&fields[0])
                && native_closed_type(&fields[1])
    )
}

fn host_manifest_matches(
    plan: &ComponentPlan<'_>,
    expected: &[AuthorityRequirement],
    expected_stream_transport: bool,
) -> Result<bool, AdmissionError> {
    if plan.imports().is_empty() && plan.host_imports().next().is_none() {
        return Ok(expected.is_empty() && !expected_stream_transport);
    }
    let manifest = VibeHostManifest::from_plan(plan).map_err(AdmissionError::HostManifest)?;
    let mut stream_reader = false;
    let mut stream_writer = false;
    let mut ambient_index = 0_usize;
    for observed in manifest.requirements() {
        match observed.kind() {
            HostResourceKind::ByteStreamReader => stream_reader = true,
            HostResourceKind::ByteStreamWriter => stream_writer = true,
            _ => {
                let Some(expected) = expected.get(ambient_index) else {
                    return Ok(false);
                };
                if observed.interface() != expected.interface
                    || observed.resource() != expected.resource
                    || observed.kind() != expected.kind
                    || observed.rights() != expected.rights
                {
                    return Ok(false);
                }
                ambient_index += 1;
            }
        }
    }
    if stream_reader != stream_writer
        || (stream_reader && stream_writer) != expected_stream_transport
    {
        return Ok(false);
    }
    Ok(ambient_index == expected.len())
}

fn unique_ceiling<'a>(
    ceilings: &'a [InterfaceCeiling<'a>],
    host: VibeHostRequirement,
) -> Result<(usize, &'a InterfaceCeiling<'a>), AdmissionError> {
    let mut found = None;
    for (index, ceiling) in ceilings.iter().enumerate() {
        if ceiling.interface == host.interface() && ceiling.kind == host.kind() {
            if found.is_some() {
                return Err(AdmissionError::InvalidPolicy);
            }
            found = Some((index, ceiling));
        }
    }
    found.ok_or(AdmissionError::MissingImageCeiling)
}

fn unique_offer<'a>(
    offers: &'a [AuthorityOffer<'a>],
    ceiling: &InterfaceCeiling<'_>,
    host: VibeHostRequirement,
) -> Result<(usize, &'a AuthorityOffer<'a>), AdmissionError> {
    let mut found = None;
    for (index, offer) in offers.iter().enumerate() {
        if offer.label == ceiling.label && offer.kind == host.kind() {
            if found.is_some() {
                return Err(AdmissionError::InvalidPolicy);
            }
            found = Some((index, offer));
        }
    }
    found.ok_or(AdmissionError::MissingCallerAuthority)
}

fn validate_policy_tables(
    ceilings: &[InterfaceCeiling<'_>],
    offers: &[AuthorityOffer<'_>],
) -> Result<(), AdmissionError> {
    for (index, ceiling) in ceilings.iter().enumerate() {
        if stream_transport_kind(ceiling.kind)
            || !valid_label(ceiling.label)
            || ceiling.interface.is_empty()
            || ceiling.interface.len() > 256
            || !operation_rights(ceiling.kind).contains(ceiling.rights)
            || ceilings[..index].iter().any(|earlier| {
                earlier.interface == ceiling.interface && earlier.kind == ceiling.kind
            })
        {
            return Err(AdmissionError::InvalidPolicy);
        }
    }
    for (index, offer) in offers.iter().enumerate() {
        if stream_transport_kind(offer.kind)
            || !valid_label(offer.label)
            || !operation_rights(offer.kind).contains(offer.grantable)
            || offers[..index]
                .iter()
                .any(|earlier| earlier.label == offer.label && earlier.kind == offer.kind)
        {
            return Err(AdmissionError::InvalidPolicy);
        }
    }
    Ok(())
}

const fn operation_rights(kind: HostResourceKind) -> Rights {
    match kind {
        HostResourceKind::Clock | HostResourceKind::Random | HostResourceKind::Blob => Rights::READ,
        HostResourceKind::StructuredLog => Rights::WRITE,
        HostResourceKind::ByteStreamReader => Rights::RECV,
        HostResourceKind::ByteStreamWriter => Rights::SEND,
    }
}

const fn stream_transport_kind(kind: HostResourceKind) -> bool {
    matches!(
        kind,
        HostResourceKind::ByteStreamReader | HostResourceKind::ByteStreamWriter
    )
}

fn copied(value: &str) -> Result<String, AdmissionError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| AdmissionError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes.first().copied().is_some_and(name_start)
        && bytes[1..].iter().copied().all(name_continue)
}

fn valid_label(label: &str) -> bool {
    valid_manifest_text(label, 128)
}

fn valid_entrypoint(entrypoint: &str) -> bool {
    valid_manifest_text(entrypoint, 256)
}

fn valid_argument_limits(minimum: usize, maximum: usize) -> bool {
    minimum <= maximum && maximum <= 128
}

fn valid_manifest_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

const fn name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn name_continue(byte: u8) -> bool {
    name_start(byte) || byte.is_ascii_digit() || byte == b'-'
}
