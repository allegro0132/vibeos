//! Capability-bound loading of canonical durable Component artifacts.
//!
//! C7.2 deliberately keeps two authorities separate. Durable media may retain
//! one exact `READ` root to immutable [`vibeos_object_store::StoredObject`]
//! bytes. Only after those bytes match an independent image pin and pass fresh
//! Component, Core, WIT, manifest, limit, and ordinary policy admission does
//! this crate construct a boot-local command runner. The runner remains
//! unavailable in C7.2: it can be installed as a volatile VSH `Command`, but
//! it cannot execute guest code and never acquires durable `INVOKE` authority.

#![no_std]

extern crate alloc;

mod root;

pub use root::*;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use vibeos_component_admission::{
    admit, canonical_entity_shape_text_v1, AdmissionError, AdmissionPolicy, AdmittedComponent,
    ArtifactTrust, CallerAuthority, ComponentArtifact, InstanceLimits,
};
use vibeos_component_command::{
    try_manifest_from_admitted, validate_admitted_filter, RunnerBuildError,
};
use vibeos_component_format::{
    ComponentArtifactCoreModuleV1, ComponentArtifactEntityKind, ComponentArtifactError,
    ComponentArtifactInterfaceDirection, ComponentArtifactManifestV1,
    ComponentArtifactSignerPolicyKind, ComponentArtifactV1, ProfileIdentity, PROFILE_1_LIMITS,
};
use vibeos_component_runtime::world::{
    EntityShape, NamedEntityShape, TypeShape, ValueShape, WorldContract, WorldError,
};
use vibeos_core::cap::{InvocationLease, Resource, Rights};
use vibeos_object_store::{get_with, StoreError, StoreService, StoredObject};
use vibeos_vsh::{
    ComponentCommandFuture, ComponentCommandManifest, ComponentCommandResult,
    ComponentCommandRunner, ComponentTerminal, PreparedComponentStage,
};

/// Independent development policy for one exact durable artifact.
///
/// `exact_artifact_bytes` and `exact_wit_source` must come from trusted image
/// configuration, never from the object which is being loaded. The whole-byte
/// pin is intentionally stronger than a self-declared content hash. C7.3 will
/// add an authenticated operator-policy alternative.
pub struct DevelopmentComponentLoadPolicy<'a> {
    exact_artifact_bytes: &'a [u8],
    exact_wit_source: &'a str,
    signer_policy_digest: [u8; 32],
    admission: &'a AdmissionPolicy<'a>,
}

impl<'a> DevelopmentComponentLoadPolicy<'a> {
    /// Bind the loader to independent, immutable image policy.
    ///
    /// The caller must source these values from trusted boot configuration;
    /// reflecting them from the recovered object would defeat the trust
    /// boundary and is intentionally not offered by any recovery API here.
    pub const fn new(
        exact_artifact_bytes: &'a [u8],
        exact_wit_source: &'a str,
        signer_policy_digest: [u8; 32],
        admission: &'a AdmissionPolicy<'a>,
    ) -> Self {
        Self {
            exact_artifact_bytes,
            exact_wit_source,
            signer_policy_digest,
            admission,
        }
    }
}

/// Stable, redacted C7.2 load failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentLoadError {
    Root(ComponentRootError),
    StoreAuthority,
    RootRevoked,
    Store(StoreError),
    ReadLength,
    Artifact(ComponentArtifactError),
    ImagePinMismatch,
    SignerPolicy,
    Profile,
    Limits,
    UnsupportedWitPackageSet,
    Wit(WorldError),
    WitPolicyMismatch,
    InterfaceManifest,
    CoreManifest,
    UnsupportedAdapterEvidence,
    UnsupportedResourceShape,
    UnsupportedImports,
    Admission(AdmissionError),
    Command(RunnerBuildError),
    RevalidationMismatch,
}

impl fmt::Display for ComponentLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Root(_) => "component durable root failed exact validation",
            Self::StoreAuthority => "component loader requires exact READ store authority",
            Self::RootRevoked => "component artifact READ root is no longer live",
            Self::Store(_) => "component artifact capability read failed",
            Self::ReadLength => "component artifact read length differs from the rooted object",
            Self::Artifact(_) => "component artifact canonical decoding failed",
            Self::ImagePinMismatch => "component artifact differs from independent image policy",
            Self::SignerPolicy => "component signer-policy descriptor differs from image policy",
            Self::Profile => "component artifact profile is outside the C7.2 loading profile",
            Self::Limits => "component artifact instance limits differ from image policy",
            Self::UnsupportedWitPackageSet => "C7.2 requires one independently pinned WIT source",
            Self::Wit(_) => "component artifact WIT source failed fresh parsing",
            Self::WitPolicyMismatch => "component WIT world differs from independent image policy",
            Self::InterfaceManifest => {
                "component interface manifest differs from fresh validator evidence"
            }
            Self::CoreManifest => {
                "component Core-module manifest differs from fresh traversal evidence"
            }
            Self::UnsupportedAdapterEvidence => {
                "C7.2 rejects adapters until exact validator evidence is available"
            }
            Self::UnsupportedResourceShape => {
                "C7.2 rejects nominal resources until scoped identity evidence is available"
            }
            Self::UnsupportedImports => {
                "C7.2 durable command loading admits no external component authority"
            }
            Self::Admission(_) => "component failed ordinary policy admission",
            Self::Command(_) => "component failed volatile command projection",
            Self::RevalidationMismatch => "volatile component command revalidation changed",
        })
    }
}

impl From<ComponentRootError> for ComponentLoadError {
    fn from(error: ComponentRootError) -> Self {
        Self::Root(error)
    }
}

impl From<StoreError> for ComponentLoadError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// A boot-local command created only by the complete C7.2 loader gate.
///
/// The admitted Component is private and cannot be converted into the
/// synchronous guest runner. The only public runner implementation returns
/// `Unavailable`, keeping C7.2's activation bit false while still allowing the
/// ordinary VSH session to construct a real volatile `Command` capability.
///
/// ```compile_fail
/// use vibeos_component_loader::VolatileComponentCommand;
///
/// fn raw_bytes(command: &VolatileComponentCommand) {
///     let _ = command.artifact_bytes();
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_command::SynchronousCommandRunner;
/// use vibeos_component_loader::VolatileComponentCommand;
///
/// fn activate(command: VolatileComponentCommand) -> SynchronousCommandRunner {
///     command.into()
/// }
/// ```
///
/// ```compile_fail
/// use vibeos_component_loader::VolatileComponentCommand;
///
/// fn durable_identity(command: &VolatileComponentCommand) {
///     let _ = command.object_id();
/// }
/// ```
pub struct VolatileComponentCommand {
    admitted: AdmittedComponent,
    manifest: ComponentCommandManifest,
}

impl VolatileComponentCommand {
    pub fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    /// C7.2 constructs command authority but does not activate guest runtime.
    pub const fn runtime_ready(&self) -> bool {
        false
    }

    /// No path in this type enters a Component engine.
    pub const fn guest_calls(&self) -> u64 {
        0
    }

    fn revalidate(&self) -> Result<(), ComponentLoadError> {
        let observed =
            try_manifest_from_admitted(&self.admitted).map_err(ComponentLoadError::Command)?;
        if observed != self.manifest {
            return Err(ComponentLoadError::RevalidationMismatch);
        }
        validate_admitted_filter(&self.admitted, &self.manifest)
            .map_err(ComponentLoadError::Command)
    }
}

impl fmt::Debug for VolatileComponentCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolatileComponentCommand")
            .field("name", &self.manifest.name())
            .field("world", &self.manifest.world())
            .field("runtime_ready", &false)
            .field("guest_calls", &0_u64)
            .finish()
    }
}

impl ComponentCommandRunner for VolatileComponentCommand {
    fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    fn preflight(&self, observed: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
        if observed != &self.manifest || self.revalidate().is_err() {
            return Err(ComponentTerminal::Denied);
        }
        Err(ComponentTerminal::Unavailable)
    }

    fn run<'a>(&'a self, _stage: PreparedComponentStage) -> ComponentCommandFuture<'a> {
        Box::pin(async {
            ComponentCommandResult::try_new(ComponentTerminal::Unavailable, Vec::new())
                .expect("an empty unavailable result is always canonical")
        })
    }
}

/// Load one root-bound object through two exact READ capabilities.
///
/// Neither a raw object ID nor an object kind/name/hash lookup is accepted by
/// this API. `artifact_read` can only be produced by exact root recovery and
/// installation. The store lease supplies only the capability-bound read
/// operation; this crate never receives the broader journal append façade.
pub async fn load_component_command(
    store_read: InvocationLease<StoreService>,
    artifact_read: ComponentArtifactPersistentRead,
    policy: &DevelopmentComponentLoadPolicy<'_>,
) -> Result<VolatileComponentCommand, ComponentLoadError> {
    load_component_command_with(store_read, artifact_read, policy, |store, object| {
        get_with(store, object)
    })
    .await
}

async fn load_component_command_with<Read, ReadFuture>(
    store_read: InvocationLease<StoreService>,
    artifact_read: ComponentArtifactPersistentRead,
    policy: &DevelopmentComponentLoadPolicy<'_>,
    read: Read,
) -> Result<VolatileComponentCommand, ComponentLoadError>
where
    Read: FnOnce(InvocationLease<StoreService>, InvocationLease<StoredObject>) -> ReadFuture,
    ReadFuture: Future<Output = Result<Vec<u8>, StoreError>>,
{
    if !lease_has_exact_read(&store_read) {
        return Err(ComponentLoadError::StoreAuthority);
    }
    let (artifact, expected_len) = artifact_read.into_parts();
    let object_read = artifact
        .try_into_invocation_lease(Rights::READ)
        .map_err(|_| ComponentLoadError::RootRevoked)?;
    let bytes = read(store_read, object_read).await?;
    if bytes.len() != expected_len {
        return Err(ComponentLoadError::ReadLength);
    }
    revalidate_and_project(&bytes, policy)
}

fn lease_has_exact_read<T: Resource>(lease: &InvocationLease<T>) -> bool {
    lease.authorizes(Rights::READ)
        && !lease.authorizes(Rights::WRITE)
        && !lease.authorizes(Rights::SEND)
        && !lease.authorizes(Rights::RECV)
        && !lease.authorizes(Rights::GRANT)
        && !lease.authorizes(Rights::REVOKE)
        && !lease.authorizes(Rights::INVOKE)
}

fn revalidate_and_project(
    bytes: &[u8],
    policy: &DevelopmentComponentLoadPolicy<'_>,
) -> Result<VolatileComponentCommand, ComponentLoadError> {
    // Parse the trusted image copy independently. The trust identity below is
    // derived from this copy, never from the durable bytes under review.
    let expected = ComponentArtifactV1::decode(policy.exact_artifact_bytes)
        .map_err(ComponentLoadError::Artifact)?;
    validate_external_policy(&expected, policy)?;
    if bytes != policy.exact_artifact_bytes {
        return Err(ComponentLoadError::ImagePinMismatch);
    }
    let durable = ComponentArtifactV1::decode(bytes).map_err(ComponentLoadError::Artifact)?;
    validate_external_policy(&durable, policy)?;

    let expected_component =
        ComponentArtifact::copy_from(expected.component_bytes(), expected.profile())
            .map_err(ComponentLoadError::Admission)?;
    let expected_identity = expected_component.identity();
    if policy.admission.trust != ArtifactTrust::ImagePinned(expected_identity) {
        return Err(ComponentLoadError::ImagePinMismatch);
    }

    let component = ComponentArtifact::copy_from(durable.component_bytes(), durable.profile())
        .map_err(ComponentLoadError::Admission)?;
    if component.identity() != expected_identity {
        return Err(ComponentLoadError::ImagePinMismatch);
    }
    validate_fresh_evidence(&durable, &component, policy)?;

    let admitted = admit(
        component,
        policy.admission,
        &CallerAuthority { offers: &[] },
    )
    .map_err(ComponentLoadError::Admission)?;
    if !admitted.grants().is_empty() || !admitted.command_manifest().requirements().is_empty() {
        return Err(ComponentLoadError::UnsupportedImports);
    }
    let manifest = try_manifest_from_admitted(&admitted).map_err(ComponentLoadError::Command)?;
    validate_admitted_filter(&admitted, &manifest).map_err(ComponentLoadError::Command)?;
    let command = VolatileComponentCommand { admitted, manifest };
    command.revalidate()?;
    Ok(command)
}

fn validate_external_policy(
    artifact: &ComponentArtifactV1,
    policy: &DevelopmentComponentLoadPolicy<'_>,
) -> Result<(), ComponentLoadError> {
    if artifact.profile() != ProfileIdentity::PROFILE_1_SYNC
        || policy.admission.profile != ProfileIdentity::PROFILE_1_SYNC
        || artifact.profile() != policy.admission.profile
        || artifact.profile_limits() != PROFILE_1_LIMITS
        || artifact.runtime_ready()
    {
        return Err(ComponentLoadError::Profile);
    }
    if artifact.signer_policy().kind() != ComponentArtifactSignerPolicyKind::DevelopmentImagePin
        || artifact.signer_policy().policy_digest().as_bytes() != &policy.signer_policy_digest
    {
        return Err(ComponentLoadError::SignerPolicy);
    }
    if !instance_limits_match(artifact, policy.admission.limits) {
        return Err(ComponentLoadError::Limits);
    }
    if !policy.admission.interfaces.is_empty() {
        return Err(ComponentLoadError::UnsupportedImports);
    }
    let [package] = artifact.manifest().wit_packages() else {
        return Err(ComponentLoadError::UnsupportedWitPackageSet);
    };
    if package.source() != policy.exact_wit_source {
        return Err(ComponentLoadError::WitPolicyMismatch);
    }
    let (package_name, package_version) =
        world_package(artifact.manifest().world()).ok_or(ComponentLoadError::WitPolicyMismatch)?;
    if package.name() != package_name || package.version() != package_version {
        return Err(ComponentLoadError::WitPolicyMismatch);
    }
    let parsed = WorldContract::parse(package.source(), artifact.manifest().world())
        .map_err(ComponentLoadError::Wit)?;
    if &parsed != policy.admission.exact_world
        || artifact.manifest().world() != policy.admission.exact_world.identity
    {
        return Err(ComponentLoadError::WitPolicyMismatch);
    }
    if !entities_are_resource_free(&parsed.imports) || !entities_are_resource_free(&parsed.exports)
    {
        return Err(ComponentLoadError::UnsupportedResourceShape);
    }
    Ok(())
}

fn validate_fresh_evidence(
    artifact: &ComponentArtifactV1,
    component: &ComponentArtifact,
    policy: &DevelopmentComponentLoadPolicy<'_>,
) -> Result<(), ComponentLoadError> {
    let inspection = component.inspect().map_err(ComponentLoadError::Admission)?;
    let plan = inspection.plan();
    if plan.profile() != artifact.profile()
        || !plan.runtime_ready()
        || plan.summary().resources != 0
        || !plan.imports().is_empty()
        || plan.host_imports().next().is_some()
    {
        return Err(ComponentLoadError::UnsupportedImports);
    }
    if !entities_are_resource_free(plan.imports()) || !entities_are_resource_free(plan.exports()) {
        return Err(ComponentLoadError::UnsupportedResourceShape);
    }
    let [package] = artifact.manifest().wit_packages() else {
        return Err(ComponentLoadError::UnsupportedWitPackageSet);
    };
    let parsed = WorldContract::parse(package.source(), artifact.manifest().world())
        .map_err(ComponentLoadError::Wit)?;
    if parsed != *policy.admission.exact_world || plan.check_world(&parsed).is_err() {
        return Err(ComponentLoadError::WitPolicyMismatch);
    }
    if !interface_manifest_matches(artifact.manifest(), plan.imports(), plan.exports()) {
        return Err(ComponentLoadError::InterfaceManifest);
    }
    if !artifact.manifest().adapters().is_empty() || plan.summary().adapters != 0 {
        return Err(ComponentLoadError::UnsupportedAdapterEvidence);
    }
    let modules = plan.embedded_modules();
    if modules.len() != artifact.manifest().core_modules().len() {
        return Err(ComponentLoadError::CoreManifest);
    }
    for (bytes, expected) in modules.iter().zip(artifact.manifest().core_modules()) {
        let observed = ComponentArtifactCoreModuleV1::from_bytes(bytes)
            .map_err(ComponentLoadError::Artifact)?;
        if observed.byte_len() != expected.byte_len()
            || observed.commitment() != expected.commitment()
        {
            return Err(ComponentLoadError::CoreManifest);
        }
    }
    Ok(())
}

fn instance_limits_match(artifact: &ComponentArtifactV1, expected: InstanceLimits) -> bool {
    let observed = artifact.instance_limits();
    u64::try_from(expected.memory_bytes).ok() == Some(observed.memory_bytes())
        && expected.total_fuel == observed.total_fuel()
        && expected.poll_quantum == observed.poll_quantum()
        && u64::from(expected.resources) == observed.resources()
}

fn world_package(world: &str) -> Option<(&str, &str)> {
    let (package, selected) = world.rsplit_once('/')?;
    let (_, version) = selected.rsplit_once('@')?;
    (!package.is_empty() && !version.is_empty()).then_some((package, version))
}

fn interface_manifest_matches(
    manifest: &ComponentArtifactManifestV1,
    imports: &[NamedEntityShape],
    exports: &[NamedEntityShape],
) -> bool {
    let Some(total) = imports.len().checked_add(exports.len()) else {
        return false;
    };
    if manifest.interfaces().len() != total {
        return false;
    }
    manifest.interfaces().iter().all(|claimed| {
        let entities = match claimed.direction() {
            ComponentArtifactInterfaceDirection::Import => imports,
            ComponentArtifactInterfaceDirection::Export => exports,
        };
        entities.iter().any(|fresh| {
            fresh.name == claimed.name()
                && entity_kind(&fresh.entity) == claimed.kind()
                && canonical_entity_shape_text_v1(&fresh.entity)
                    .is_ok_and(|shape| shape == claimed.diagnostic_shape())
        })
    })
}

const fn entity_kind(entity: &EntityShape) -> ComponentArtifactEntityKind {
    match entity {
        EntityShape::Function(_) => ComponentArtifactEntityKind::Function,
        EntityShape::Interface(_) => ComponentArtifactEntityKind::Interface,
        EntityShape::Type(_) => ComponentArtifactEntityKind::Type,
    }
}

fn entities_are_resource_free(entities: &[NamedEntityShape]) -> bool {
    entities
        .iter()
        .all(|entity| entity_is_resource_free(&entity.entity))
}

fn entity_is_resource_free(entity: &EntityShape) -> bool {
    match entity {
        EntityShape::Function(function) => {
            function
                .parameters
                .iter()
                .all(|parameter| value_is_resource_free(&parameter.value))
                && function.result.as_ref().is_none_or(value_is_resource_free)
        }
        EntityShape::Interface(entities) => entities_are_resource_free(entities),
        EntityShape::Type(TypeShape::Resource) => false,
        EntityShape::Type(TypeShape::Value(value)) => value_is_resource_free(value),
    }
}

fn value_is_resource_free(value: &ValueShape) -> bool {
    match value {
        ValueShape::List(value) | ValueShape::Option(value) => value_is_resource_free(value),
        ValueShape::Tuple(values) => values.iter().all(value_is_resource_free),
        ValueShape::Record(fields) => fields
            .iter()
            .all(|field| value_is_resource_free(&field.value)),
        ValueShape::Result { ok, error } => {
            ok.as_deref().is_none_or(value_is_resource_free)
                && error.as_deref().is_none_or(value_is_resource_free)
        }
        ValueShape::Variant(cases) => cases
            .iter()
            .all(|case| case.value.as_ref().is_none_or(value_is_resource_free)),
        ValueShape::Future(value) | ValueShape::Stream(value) => {
            value.as_deref().is_none_or(value_is_resource_free)
        }
        ValueShape::Own(_) | ValueShape::Borrow(_) => false,
        ValueShape::Bool
        | ValueShape::U8
        | ValueShape::U16
        | ValueShape::U32
        | ValueShape::U64
        | ValueShape::S8
        | ValueShape::S16
        | ValueShape::S32
        | ValueShape::S64
        | ValueShape::Char
        | ValueShape::String
        | ValueShape::Flags(_)
        | ValueShape::Enum(_) => true,
    }
}

#[cfg(test)]
mod tests;
