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
#![cfg_attr(
    not(feature = "c88-f4-float-candidate-core"),
    doc = r#"
The C8.8-F4 image-pinned scalar-float candidate is structurally absent by
default:

```compile_fail
use vibeos_component_image_adapter::{
    project_float_candidate,
    FloatCandidateProjection,
};
```
"#
)]
#![no_std]

#[cfg(all(
    feature = "c88-f4-float-candidate",
    feature = "c88-f4-float-candidate-duo"
))]
compile_error!(
    "features `c88-f4-float-candidate` and `c88-f4-float-candidate-duo` are mutually exclusive image-policy selections"
);

#[cfg(all(
    feature = "c88-f4-float-candidate-core",
    not(any(
        feature = "c88-f4-float-candidate",
        feature = "c88-f4-float-candidate-duo"
    ))
))]
compile_error!(
    "internal feature `c88-f4-float-candidate-core` requires one explicit platform selector"
);

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

#[cfg(feature = "c88-f4-float-candidate-core")]
use vibeos_component_admission::{
    admit_float_acceptance_candidate, AdmissionError as FloatAdmissionError,
    ArtifactTrust as FloatArtifactTrust, CallerAuthority as FloatCallerAuthority,
    ComponentArtifact as FloatArtifact, FloatAcceptanceAdmissionPolicy,
    InstanceLimits as FloatAdmissionLimits, FLOAT_ACCEPTANCE_ACTIVATION_LABEL,
};
#[cfg(feature = "c88-f4-float-candidate-core")]
use vibeos_component_format::{
    ProfileIdentity as FloatProfileIdentity, ProfileStage as FloatStage,
};
#[cfg(feature = "c88-f4-float-candidate-core")]
use vibeos_component_runtime::{
    decode::{current_component_validation_engine, ComponentPlan as FloatComponentPlan},
    float_candidate::{
        FloatCandidateComponent, FloatCandidateError as FloatRuntimeError, FloatCandidateLifecycle,
        FloatCandidateLimits,
    },
    world::{WorldContract as FloatWorldContract, WorldError as FloatWorldError},
};
#[cfg(feature = "c88-f4-float-candidate-core")]
use vibeos_image_policy::{ComponentInstanceLimits as FloatImageLimits, FloatCandidatePin};

#[cfg(any(
    feature = "native-async-command-projection",
    feature = "c88-f4-float-candidate-core"
))]
mod private {
    pub struct Seal;
}

/// Stable failures from the image-pinned F4 candidate projection.
#[cfg(feature = "c88-f4-float-candidate-core")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatCandidateProjectionError {
    Artifact(FloatAdmissionError),
    DigestMismatch,
    Wit(FloatWorldError),
    Admission(FloatAdmissionError),
    Runtime(FloatRuntimeError),
    RevalidationMismatch,
}

/// Move-only join of the exact image pin and sealed float admission receipt.
///
/// This value is neither a command projection nor durable publication input.
/// It has no manifest, artifact-byte getter, command name, or conversion to
/// ordinary admission:
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_float_candidate;
/// # use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;
/// let projection = project_float_candidate(C88_F4_FLOAT_CANDIDATE).unwrap();
/// let _: vibeos_component_admission::AdmittedComponent = projection.into();
/// ```
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_float_candidate;
/// # use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;
/// let projection = project_float_candidate(C88_F4_FLOAT_CANDIDATE).unwrap();
/// let _ = projection.manifest();
/// ```
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_float_candidate;
/// # use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;
/// let projection = project_float_candidate(C88_F4_FLOAT_CANDIDATE).unwrap();
/// let _ = projection.artifact_bytes();
/// ```
///
/// ```compile_fail
/// # use vibeos_component_image_adapter::project_float_candidate;
/// # use vibeos_image_policy::C88_F4_FLOAT_CANDIDATE;
/// let projection = project_float_candidate(C88_F4_FLOAT_CANDIDATE).unwrap();
/// let _ = projection.clone();
/// ```
#[cfg(feature = "c88-f4-float-candidate-core")]
pub struct FloatCandidateProjection {
    pin: FloatCandidatePin,
    candidate: vibeos_component_admission::AdmittedFloatAcceptanceCandidate,
    world: FloatWorldContract,
    _sealed: private::Seal,
}

#[cfg(feature = "c88-f4-float-candidate-core")]
impl FloatCandidateProjection {
    pub fn activation_label(&self) -> &str {
        self.candidate.activation_label()
    }

    pub const fn profile(&self) -> FloatProfileIdentity {
        self.candidate.profile()
    }

    pub const fn limits(&self) -> FloatAdmissionLimits {
        self.candidate.limits()
    }

    /// Freshly revalidates the immutable bytes and independent WIT policy.
    /// The resulting plan is still validation-only and has no executable
    /// exports in the ordinary runtime.
    pub fn validated_plan(&self) -> Result<FloatComponentPlan<'_>, FloatCandidateProjectionError> {
        let reparsed_world = FloatWorldContract::parse_profile_2_sync_float_candidate(
            self.pin.wit_source(),
            self.pin.world(),
        )
        .map_err(FloatCandidateProjectionError::Wit)?;
        let plan = self
            .candidate
            .validated_plan()
            .map_err(FloatCandidateProjectionError::Admission)?;
        let pin_limits = float_admission_limits(self.pin.limits());
        let profile = self.candidate.profile();
        if self.pin.profile() != FloatProfileIdentity::PROFILE_2_SYNC_FLOAT
            || self.pin.profile().stage != FloatStage::ValidationOnly
            || self.pin.profile().execution_enabled()
            || profile != self.pin.profile()
            || profile.stage != FloatStage::ValidationOnly
            || profile.execution_enabled()
            || current_component_validation_engine(profile).is_some()
            || plan.profile() != profile
            || plan.runtime_ready()
            || plan.native_async_runtime_ready()
            || plan.executable_exports().next().is_some()
            || plan.host_imports().next().is_some()
            || self.candidate.identity().as_bytes() != &self.pin.expected_sha256()
            || self.candidate.activation_label() != self.pin.activation_label()
            || self.candidate.activation_label() != FLOAT_ACCEPTANCE_ACTIVATION_LABEL
            || self.candidate.world() != self.pin.world()
            || self.candidate.entrypoint() != self.pin.export_name()
            || self.candidate.limits() != pin_limits
            || pin_limits.resources != 0
            || reparsed_world != self.world
            || reparsed_world
                .check_component(plan.imports(), plan.exports())
                .is_err()
        {
            return Err(FloatCandidateProjectionError::RevalidationMismatch);
        }
        Ok(plan)
    }

    /// Consumes the sole projection and explicitly activates the default-off
    /// candidate lifecycle. No ordinary engine resolver or command registry is
    /// consulted. Compilation receives the exact deterministic charge derived
    /// from the freshly revalidated pinned Core bytes.
    pub fn activate_candidate(
        self,
    ) -> Result<FloatCandidateLifecycle, FloatCandidateProjectionError> {
        let component = {
            let plan = self.validated_plan()?;
            let compile_reservation = FloatCandidateComponent::required_compile_reservation(&plan)
                .map_err(FloatCandidateProjectionError::Runtime)?;
            let policy = self.pin.limits();
            FloatCandidateComponent::compile(
                &plan,
                FloatCandidateLimits {
                    compile_reservation_bytes: compile_reservation,
                    memory_bytes: policy.memory_bytes,
                    total_fuel: policy.total_fuel,
                    poll_quantum: policy.poll_quantum,
                },
            )
            .map_err(FloatCandidateProjectionError::Runtime)?
        };
        component
            .activate()
            .map_err(FloatCandidateProjectionError::Runtime)
    }
}

/// The sole image-to-admission construction path for the F4 candidate.
#[cfg(feature = "c88-f4-float-candidate-core")]
pub fn project_float_candidate(
    pin: FloatCandidatePin,
) -> Result<FloatCandidateProjection, FloatCandidateProjectionError> {
    let artifact = FloatArtifact::copy_from(pin.artifact_bytes(), pin.profile())
        .map_err(FloatCandidateProjectionError::Artifact)?;
    if artifact.identity().as_bytes() != &pin.expected_sha256() {
        return Err(FloatCandidateProjectionError::DigestMismatch);
    }
    let world =
        FloatWorldContract::parse_profile_2_sync_float_candidate(pin.wit_source(), pin.world())
            .map_err(FloatCandidateProjectionError::Wit)?;
    let identity = artifact.identity();
    let policy = FloatAcceptanceAdmissionPolicy {
        activation_label: pin.activation_label(),
        exact_world: &world,
        trust: FloatArtifactTrust::ImagePinned(identity),
        limits: float_admission_limits(pin.limits()),
    };
    let candidate =
        admit_float_acceptance_candidate(artifact, &policy, &FloatCallerAuthority { offers: &[] })
            .map_err(FloatCandidateProjectionError::Admission)?;
    if candidate.identity().as_bytes() != &pin.expected_sha256()
        || candidate.activation_label() != pin.activation_label()
        || candidate.profile() != pin.profile()
        || candidate.world() != pin.world()
        || candidate.entrypoint() != pin.export_name()
        || candidate.limits() != float_admission_limits(pin.limits())
    {
        return Err(FloatCandidateProjectionError::RevalidationMismatch);
    }
    let projection = FloatCandidateProjection {
        pin,
        candidate,
        world,
        _sealed: private::Seal,
    };
    projection.validated_plan()?;
    Ok(projection)
}

#[cfg(feature = "c88-f4-float-candidate-core")]
const fn float_admission_limits(limits: FloatImageLimits) -> FloatAdmissionLimits {
    FloatAdmissionLimits {
        memory_bytes: limits.memory_bytes,
        total_fuel: limits.total_fuel,
        poll_quantum: limits.poll_quantum,
        resources: limits.resources,
    }
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
