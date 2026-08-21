#![cfg_attr(
    not(feature = "native-async-command-projection"),
    doc = r#"
The native async command projection is structurally absent by default:

```compile_fail
use vibeos_component_image_adapter::{
    project_native_async_command,
    NativeAsyncCommandProjection,
};
```
"#
)]
#![no_std]

#[cfg(feature = "native-async-command-projection")]
extern crate alloc;

#[cfg(feature = "native-async-command-projection")]
use alloc::vec::Vec;
#[cfg(feature = "native-async-command-projection")]
use vibeos_component_admission::{
    admit_native_async_acceptance_candidate, AdmissionError, AdmissionPolicy, ArtifactTrust,
    CallerAuthority, CommandStreamMode, ComponentArtifact, InstanceLimits,
};
#[cfg(feature = "native-async-command-projection")]
use vibeos_component_format::{ProfileIdentity, ProfileStage};
#[cfg(feature = "native-async-command-projection")]
use vibeos_component_runtime::{
    decode::ComponentPlan,
    world::{WorldContract, WorldError},
};
#[cfg(feature = "native-async-command-projection")]
use vibeos_image_policy::{ComponentInstanceLimits, ComponentStreamMode, NativeAsyncCommandPin};
#[cfg(feature = "native-async-command-projection")]
use vibeos_vsh::{ComponentArtifactIdentity, ComponentCommandManifest, StreamMode};

#[cfg(feature = "native-async-command-projection")]
mod private {
    pub struct Seal;
}

/// Stable construction and revalidation failures for the sealed projection.
#[cfg(feature = "native-async-command-projection")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    Artifact(AdmissionError),
    DigestMismatch,
    Wit(WorldError),
    Admission(AdmissionError),
    ManifestRejected,
    RevalidationMismatch,
}

/// Inert native async command metadata derived from one explicit image pin.
///
/// Fields are private, the value is not `Clone`, and it exposes neither raw
/// bytes nor the underlying admission candidate. The ordinary synchronous
/// runner accepts only `AdmittedComponent`, and there is deliberately no
/// conversion from this projection to that type.
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_native_async_command;
/// # use vibeos_image_policy::C53_NATIVE_ASYNC_COMMAND;
/// let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
/// let _: vibeos_component_admission::AdmittedComponent = projection.into();
/// ```
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_native_async_command;
/// # use vibeos_image_policy::C53_NATIVE_ASYNC_COMMAND;
/// let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
/// let _ = projection.artifact_bytes();
/// ```
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_native_async_command;
/// # use vibeos_image_policy::C53_NATIVE_ASYNC_COMMAND;
/// let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
/// let _ = projection.clone();
/// ```
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use vibeos_component_image_adapter::project_native_async_command;
/// # use vibeos_image_policy::C53_NATIVE_ASYNC_COMMAND;
/// # use vibeos_vsh::ComponentCommandRunner;
/// let projection = project_native_async_command(C53_NATIVE_ASYNC_COMMAND).unwrap();
/// let _: Arc<dyn ComponentCommandRunner> = Arc::new(projection);
/// ```
#[cfg(feature = "native-async-command-projection")]
pub struct NativeAsyncCommandProjection {
    pin: NativeAsyncCommandPin,
    candidate: vibeos_component_admission::AdmittedNativeAsyncAcceptanceCandidate,
    world: WorldContract,
    manifest: ComponentCommandManifest,
    _sealed: private::Seal,
}

#[cfg(feature = "native-async-command-projection")]
impl NativeAsyncCommandProjection {
    /// Borrow the exact VSH manifest. This is metadata, not invocation
    /// authority and not a command runner.
    pub fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    /// Revalidate the owned bytes, independent WIT contract, admission result,
    /// and exact VSH projection without activating either runtime-ready bit.
    pub fn validated_plan(&self) -> Result<ComponentPlan<'_>, ProjectionError> {
        let reparsed_world = WorldContract::parse(self.pin.wit_source(), self.pin.world())
            .map_err(ProjectionError::Wit)?;
        let plan = self
            .candidate
            .validated_plan()
            .map_err(ProjectionError::Admission)?;
        let profile = self.candidate.profile();
        let limits = self.candidate.limits();
        let pin_limits = admission_limits(self.pin.limits());
        if self.pin.profile() != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE
            || self.pin.profile().stage != ProfileStage::ValidationOnly
            || self.pin.profile().execution_enabled()
            || profile != self.pin.profile()
            || profile.stage != ProfileStage::ValidationOnly
            || profile.execution_enabled()
            || plan.profile() != profile
            || plan.runtime_ready()
            || plan.native_async_runtime_ready()
            || self.candidate.identity().as_bytes() != &self.pin.expected_sha256()
            || self.candidate.command_name() != self.pin.command_name()
            || self.candidate.abi() != self.pin.abi()
            || self.candidate.world() != self.pin.world()
            || self.candidate.entrypoint() != self.pin.entrypoint()
            || self.candidate.min_args() != self.pin.min_args()
            || self.candidate.max_args() != self.pin.max_args()
            || limits != pin_limits
            || self.candidate.stdin() != admission_stream_mode(self.pin.stdin())
            || self.candidate.stdout() != admission_stream_mode(self.pin.stdout())
            || self.candidate.stderr() != admission_stream_mode(self.pin.stderr())
            || reparsed_world != self.world
            || self.world.identity != self.candidate.world()
            || reparsed_world
                .check_component(plan.imports(), plan.exports())
                .is_err()
            || self.manifest.name() != self.pin.command_name()
            || self.manifest.abi() != self.pin.abi()
            || self.manifest.artifact().as_bytes() != &self.pin.expected_sha256()
            || self.manifest.world() != self.pin.world()
            || self.manifest.entrypoint() != self.pin.entrypoint()
            || self.manifest.min_args() != self.pin.min_args()
            || self.manifest.max_args() != self.pin.max_args()
            || self.manifest.stdin() != vsh_stream_mode(admission_stream_mode(self.pin.stdin()))
            || self.manifest.stdout() != vsh_stream_mode(admission_stream_mode(self.pin.stdout()))
            || self.manifest.stderr() != vsh_stream_mode(admission_stream_mode(self.pin.stderr()))
            || self.manifest.memory_bytes() != pin_limits.memory_bytes
            || self.manifest.total_fuel() != pin_limits.total_fuel
            || self.manifest.poll_quantum() != pin_limits.poll_quantum
            || self.manifest.resource_limit() != pin_limits.resources
            || !self.manifest.requirements().is_empty()
        {
            return Err(ProjectionError::RevalidationMismatch);
        }
        Ok(plan)
    }
}

/// The sole construction path for a native async command projection.
///
/// The input type is the explicit command-projection image root, not the
/// acceptance fixture pin, raw bytes, or an admission candidate.
#[cfg(feature = "native-async-command-projection")]
pub fn project_native_async_command(
    pin: NativeAsyncCommandPin,
) -> Result<NativeAsyncCommandProjection, ProjectionError> {
    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile())
        .map_err(ProjectionError::Artifact)?;
    if artifact.identity().as_bytes() != &pin.expected_sha256() {
        return Err(ProjectionError::DigestMismatch);
    }

    let world =
        WorldContract::parse(pin.wit_source(), pin.world()).map_err(ProjectionError::Wit)?;
    let identity = artifact.identity();
    let policy = AdmissionPolicy {
        command_name: pin.command_name(),
        entrypoint: pin.entrypoint(),
        min_args: pin.min_args(),
        max_args: pin.max_args(),
        exact_world: &world,
        profile: pin.profile(),
        trust: ArtifactTrust::ImagePinned(identity),
        limits: admission_limits(pin.limits()),
        stdin: admission_stream_mode(pin.stdin()),
        stdout: admission_stream_mode(pin.stdout()),
        stderr: admission_stream_mode(pin.stderr()),
        interfaces: &[],
    };
    let candidate = admit_native_async_acceptance_candidate(
        artifact,
        &policy,
        &CallerAuthority { offers: &[] },
    )
    .map_err(ProjectionError::Admission)?;
    if candidate.identity().as_bytes() != &pin.expected_sha256()
        || candidate.command_name() != pin.command_name()
        || candidate.profile() != pin.profile()
        || candidate.world() != pin.world()
        || candidate.entrypoint() != pin.entrypoint()
        || candidate.min_args() != pin.min_args()
        || candidate.max_args() != pin.max_args()
        || candidate.limits() != admission_limits(pin.limits())
        || candidate.stdin() != admission_stream_mode(pin.stdin())
        || candidate.stdout() != admission_stream_mode(pin.stdout())
        || candidate.stderr() != admission_stream_mode(pin.stderr())
    {
        return Err(ProjectionError::RevalidationMismatch);
    }

    let limits = pin.limits();
    let manifest = ComponentCommandManifest::try_from_borrowed(
        pin.command_name(),
        pin.abi(),
        ComponentArtifactIdentity::new(pin.expected_sha256()),
        pin.world(),
        pin.entrypoint(),
        pin.min_args(),
        pin.max_args(),
        vsh_stream_mode(admission_stream_mode(pin.stdin())),
        vsh_stream_mode(admission_stream_mode(pin.stdout())),
        vsh_stream_mode(admission_stream_mode(pin.stderr())),
        limits.memory_bytes,
        limits.total_fuel,
        limits.poll_quantum,
        limits.resources,
        Vec::new(),
    )
    .map_err(|_| ProjectionError::ManifestRejected)?;

    let projection = NativeAsyncCommandProjection {
        pin,
        candidate,
        world,
        manifest,
        _sealed: private::Seal,
    };
    projection.validated_plan()?;
    Ok(projection)
}

#[cfg(feature = "native-async-command-projection")]
const fn admission_limits(limits: ComponentInstanceLimits) -> InstanceLimits {
    InstanceLimits {
        memory_bytes: limits.memory_bytes,
        total_fuel: limits.total_fuel,
        poll_quantum: limits.poll_quantum,
        resources: limits.resources,
    }
}

#[cfg(feature = "native-async-command-projection")]
const fn admission_stream_mode(mode: ComponentStreamMode) -> CommandStreamMode {
    match mode {
        ComponentStreamMode::Required => CommandStreamMode::Required,
        ComponentStreamMode::Optional => CommandStreamMode::Optional,
        ComponentStreamMode::Closed => CommandStreamMode::Closed,
    }
}

#[cfg(feature = "native-async-command-projection")]
const fn vsh_stream_mode(mode: CommandStreamMode) -> StreamMode {
    match mode {
        CommandStreamMode::Required => StreamMode::Required,
        CommandStreamMode::Optional => StreamMode::Optional,
        CommandStreamMode::Closed => StreamMode::Closed,
    }
}
