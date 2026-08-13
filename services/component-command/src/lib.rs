//! Sealed integration from pure Component admission to a first-class VSH
//! synchronous byte-stream command.
//!
//! The runner owns one immutable admitted artifact. Every preflight and run
//! revalidates the exact bytes, world, entrypoint, limits, requirements, and
//! VSH manifest before creating a fresh runtime instance and resource-table
//! incarnation. Profile 1 deliberately admits only an import-free
//! `run(input: list<u8>) -> list<u8>`-shaped filter at this boundary.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vibeos_component_admission::{
    AdmissionError, AdmittedComponent, CommandStreamMode,
    ComponentCommandManifest as AdmissionManifest,
};
use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_component_host::HostResourceKind;
use vibeos_component_runtime::decode::ComponentPlan;
use vibeos_component_runtime::host::HostError;
use vibeos_component_runtime::resource::ResourceTable;
use vibeos_component_runtime::sync::{SyncError, SynchronousComponent, TypedPoll};
use vibeos_component_runtime::value::{CanonicalValue, ValueType};
use vibeos_vsh::{
    ComponentArtifactIdentity, ComponentAuthorityRequirement, ComponentCommandFuture,
    ComponentCommandManifest, ComponentCommandResult, ComponentCommandRunner, ComponentTerminal,
    ComponentTrapCode, PreparedComponentStage, StreamMode,
};
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

/// Exact parameter name in the reviewed Profile-1 VSH byte-filter ABI.
pub const BYTE_FILTER_PARAMETER: &str = "input";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerBuildError {
    Admission(AdmissionError),
    Allocation,
    ManifestRejected,
    ManifestMismatch,
    UnsupportedImports,
    UnsupportedArguments,
    UnsupportedStreams,
    UnsupportedSignature,
    UnsupportedRuntimeInstances,
}

/// Derive the VSH manifest without dropping any admitted field. In particular,
/// parameter bounds, the resource-table ceiling, and each requirement's exact
/// interface/resource pair remain policy-owned data rather than adapter
/// defaults.
pub fn try_manifest_from_admitted(
    admitted: &AdmittedComponent,
) -> Result<ComponentCommandManifest, RunnerBuildError> {
    admitted
        .validated_plan()
        .map_err(RunnerBuildError::Admission)?;
    let source = admitted.command_manifest();
    let mut requirements = Vec::new();
    requirements
        .try_reserve_exact(source.requirements().len())
        .map_err(|_| RunnerBuildError::Allocation)?;
    for requirement in source.requirements() {
        requirements.push(
            ComponentAuthorityRequirement::try_from_borrowed(
                requirement.label(),
                requirement.interface(),
                requirement.resource(),
                vsh_resource_kind(requirement.kind()),
                requirement.rights(),
            )
            .map_err(|_| RunnerBuildError::ManifestRejected)?,
        );
    }
    ComponentCommandManifest::try_from_borrowed(
        source.name(),
        source.abi(),
        ComponentArtifactIdentity::new(*source.artifact().as_bytes()),
        source.world(),
        source.entrypoint(),
        source.min_args(),
        source.max_args(),
        stream_mode(source.stdin()),
        stream_mode(source.stdout()),
        stream_mode(source.stderr()),
        source.limits().memory_bytes,
        source.limits().total_fuel,
        source.limits().poll_quantum,
        source.limits().resources,
        requirements,
    )
    .map_err(|_| RunnerBuildError::ManifestRejected)
}

/// Immutable, capability-free executable template around one admitted
/// Component artifact. Runtime state is always invocation-local.
pub struct SynchronousCommandRunner {
    admitted: Arc<AdmittedComponent>,
    manifest: ComponentCommandManifest,
    engine: ProfileEngine,
    next_resource_generation: AtomicU64,
    started_invocations: AtomicU64,
}

impl SynchronousCommandRunner {
    pub fn new(admitted: Arc<AdmittedComponent>) -> Result<Self, RunnerBuildError> {
        let manifest = try_manifest_from_admitted(&admitted)?;
        validate_admitted_filter(&admitted, &manifest)?;
        Ok(Self {
            admitted,
            manifest,
            engine: ProfileEngine::new(),
            next_resource_generation: AtomicU64::new(1),
            started_invocations: AtomicU64::new(0),
        })
    }

    /// A redacted monotonic count, useful to prove that failed whole-pipeline
    /// admission did not start this artifact.
    pub fn started_invocations(&self) -> u64 {
        self.started_invocations.load(Ordering::Acquire)
    }

    fn validate_exact(&self, observed: &ComponentCommandManifest) -> Result<(), RunnerBuildError> {
        let regenerated = try_manifest_from_admitted(&self.admitted)?;
        if regenerated != self.manifest || observed != &self.manifest {
            return Err(RunnerBuildError::ManifestMismatch);
        }
        validate_admitted_filter(&self.admitted, &self.manifest)
    }

    fn take_resource_generation(&self) -> Result<u64, RunnerBuildError> {
        self.next_resource_generation
            .try_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .map_err(|_| RunnerBuildError::Allocation)
    }

    async fn run_stage(&self, stage: PreparedComponentStage) -> ComponentCommandResult {
        if let Err(error) = self.validate_exact(stage.manifest()) {
            return terminal_result(build_error_terminal(error));
        }
        if !stage.arguments().is_empty() || !stage.authorities().is_empty() {
            return terminal_result(ComponentTerminal::Denied);
        }
        if stage.cancellation().is_cancelled() {
            return terminal_result(ComponentTerminal::Cancelled);
        }
        if stage.input().len() > byte_value_limit() {
            return terminal_result(ComponentTerminal::BudgetExceeded);
        }

        let generation = match self.take_resource_generation() {
            Ok(generation) => generation,
            Err(error) => return terminal_result(build_error_terminal(error)),
        };
        let plan = match self.admitted.validated_plan() {
            Ok(plan) => plan,
            Err(error) => {
                return terminal_result(build_error_terminal(RunnerBuildError::Admission(error)));
            }
        };
        let mut component = match SynchronousComponent::instantiate_with_memory_limit(
            &plan,
            &self.engine,
            OwnerAllocationReservation::new(self.manifest.memory_bytes()),
            self.manifest.memory_bytes(),
        ) {
            Ok(component) => component,
            Err(error) => return terminal_result(sync_error_terminal(error)),
        };
        if !runtime_signature_matches(&component, self.manifest.entrypoint()) {
            return terminal_result(ComponentTerminal::BackendFault);
        }
        let mut resources =
            match ResourceTable::<()>::new(generation, self.manifest.resource_limit()) {
                Ok(resources) => resources,
                Err(_) => return terminal_result(ComponentTerminal::BudgetExceeded),
            };
        let arguments = match byte_arguments(stage.input()) {
            Ok(arguments) => arguments,
            Err(terminal) => return terminal_result(terminal),
        };
        let mut call = match component.start_typed_call(
            &mut resources,
            self.manifest.entrypoint(),
            arguments,
            self.manifest.total_fuel(),
            self.manifest.poll_quantum(),
        ) {
            Ok(call) => call,
            Err(error) => return terminal_result(sync_error_terminal(error)),
        };
        let _ =
            self.started_invocations
                .try_update(Ordering::AcqRel, Ordering::Acquire, |started| {
                    started.checked_add(1)
                });

        let value = loop {
            if stage.cancellation().is_cancelled() {
                call.cancel();
            }
            match call.poll() {
                TypedPoll::Pending(_) => vibeos_core::exec::yield_now().await,
                TypedPoll::Ready(value) => break value,
                TypedPoll::HostFailed(error) => {
                    return terminal_result(host_error_terminal(error));
                }
                TypedPoll::Trapped(trap) => return terminal_result(trap_terminal(trap)),
            }
        };
        drop(call);
        match byte_output(value) {
            Ok(output) => ComponentCommandResult::try_new(ComponentTerminal::Success, output)
                .unwrap_or_else(|_| ComponentCommandResult::budget_exceeded()),
            Err(terminal) => terminal_result(terminal),
        }
    }
}

impl ComponentCommandRunner for SynchronousCommandRunner {
    fn manifest(&self) -> &ComponentCommandManifest {
        &self.manifest
    }

    fn preflight(&self, manifest: &ComponentCommandManifest) -> Result<(), ComponentTerminal> {
        self.validate_exact(manifest).map_err(build_error_terminal)
    }

    fn run<'a>(&'a self, stage: PreparedComponentStage) -> ComponentCommandFuture<'a> {
        Box::pin(self.run_stage(stage))
    }
}

/// Revalidate the immutable admission record and the exact VSH manifest
/// without constructing any runtime state. Kernel lifecycle adapters use this
/// before reserving an owner, arena, CSpace, or executor identity.
pub fn validate_admitted_filter(
    admitted: &AdmittedComponent,
    manifest: &ComponentCommandManifest,
) -> Result<(), RunnerBuildError> {
    let source = admitted.command_manifest();
    let plan = admitted
        .validated_plan()
        .map_err(RunnerBuildError::Admission)?;
    if !plan.imports().is_empty()
        || plan.host_imports().next().is_some()
        || !source.requirements().is_empty()
        || !admitted.grants().is_empty()
    {
        return Err(RunnerBuildError::UnsupportedImports);
    }
    if plan.runtime_instance_count() != 1 {
        return Err(RunnerBuildError::UnsupportedRuntimeInstances);
    }
    if source.min_args() != 0 || source.max_args() != 0 {
        return Err(RunnerBuildError::UnsupportedArguments);
    }
    if !matches!(
        source.stdin(),
        CommandStreamMode::Required | CommandStreamMode::Closed
    ) || source.stdout() != CommandStreamMode::Required
        || source.stderr() == CommandStreamMode::Required
    {
        return Err(RunnerBuildError::UnsupportedStreams);
    }
    if !plan_signature_matches(&plan, source) {
        return Err(RunnerBuildError::UnsupportedSignature);
    }
    let regenerated = try_manifest_from_admitted(admitted)?;
    if &regenerated != manifest {
        return Err(RunnerBuildError::ManifestMismatch);
    }
    Ok(())
}

fn plan_signature_matches(plan: &ComponentPlan<'_>, manifest: &AdmissionManifest) -> bool {
    let mut exports = plan
        .executable_exports()
        .filter(|export| export.name == manifest.entrypoint());
    let Some(export) = exports.next() else {
        return false;
    };
    exports.next().is_none() && function_is_byte_filter(&export.function)
}

fn runtime_signature_matches(component: &SynchronousComponent, entrypoint: &str) -> bool {
    component
        .function_type(entrypoint)
        .is_some_and(function_is_byte_filter)
}

fn function_is_byte_filter(function: &vibeos_component_runtime::types::FunctionType) -> bool {
    let [parameter] = function.parameters.as_slice() else {
        return false;
    };
    parameter.name == BYTE_FILTER_PARAMETER
        && byte_list(&parameter.value)
        && function.result.as_ref().is_some_and(byte_list)
}

fn byte_list(value: &ValueType) -> bool {
    matches!(value, ValueType::List(item) if matches!(item.as_ref(), ValueType::U8))
}

fn byte_arguments(input: &[u8]) -> Result<Vec<CanonicalValue>, ComponentTerminal> {
    if input.len() > byte_value_limit() {
        return Err(ComponentTerminal::BudgetExceeded);
    }
    let mut items = Vec::new();
    items
        .try_reserve_exact(input.len())
        .map_err(|_| ComponentTerminal::BudgetExceeded)?;
    items.extend(input.iter().copied().map(CanonicalValue::U8));
    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(1)
        .map_err(|_| ComponentTerminal::BudgetExceeded)?;
    arguments.push(CanonicalValue::List(items));
    Ok(arguments)
}

fn byte_output(value: CanonicalValue) -> Result<Vec<u8>, ComponentTerminal> {
    let CanonicalValue::List(values) = value else {
        return Err(ComponentTerminal::BackendFault);
    };
    if values.len() > byte_value_limit() {
        return Err(ComponentTerminal::BudgetExceeded);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(values.len())
        .map_err(|_| ComponentTerminal::BudgetExceeded)?;
    for value in values {
        let CanonicalValue::U8(byte) = value else {
            return Err(ComponentTerminal::BackendFault);
        };
        output.push(byte);
    }
    Ok(output)
}

const fn byte_value_limit() -> usize {
    let elements = PROFILE_1_LIMITS.max_list_elements as usize;
    if elements < PROFILE_1_LIMITS.max_canonical_value_bytes {
        elements
    } else {
        PROFILE_1_LIMITS.max_canonical_value_bytes
    }
}

fn stream_mode(mode: CommandStreamMode) -> StreamMode {
    match mode {
        CommandStreamMode::Required => StreamMode::Required,
        CommandStreamMode::Optional => StreamMode::Optional,
        CommandStreamMode::Closed => StreamMode::Closed,
    }
}

const fn vsh_resource_kind(kind: HostResourceKind) -> &'static str {
    match kind {
        HostResourceKind::Clock => "component-clock",
        HostResourceKind::Random => "component-random",
        HostResourceKind::Blob => "component-blob",
        HostResourceKind::StructuredLog => "component-structured-log",
    }
}

const fn build_error_terminal(error: RunnerBuildError) -> ComponentTerminal {
    match error {
        RunnerBuildError::UnsupportedImports | RunnerBuildError::UnsupportedArguments => {
            ComponentTerminal::Denied
        }
        RunnerBuildError::Allocation => ComponentTerminal::BudgetExceeded,
        RunnerBuildError::Admission(_)
        | RunnerBuildError::ManifestRejected
        | RunnerBuildError::ManifestMismatch
        | RunnerBuildError::UnsupportedStreams
        | RunnerBuildError::UnsupportedSignature
        | RunnerBuildError::UnsupportedRuntimeInstances => ComponentTerminal::BackendFault,
    }
}

const fn sync_error_terminal(error: SyncError) -> ComponentTerminal {
    match error {
        SyncError::Allocation | SyncError::CoreAdmission | SyncError::InvalidBudget => {
            ComponentTerminal::BudgetExceeded
        }
        SyncError::CoreInstantiation
        | SyncError::MissingModule
        | SyncError::MissingExport
        | SyncError::InvalidWiring
        | SyncError::Memory
        | SyncError::Codec
        | SyncError::Busy
        | SyncError::Trapped
        | SyncError::Value
        | SyncError::Resource
        | SyncError::Poisoned => ComponentTerminal::BackendFault,
    }
}

const fn host_error_terminal(error: HostError) -> ComponentTerminal {
    match error {
        HostError::Denied => ComponentTerminal::Denied,
        HostError::Unavailable => ComponentTerminal::Unavailable,
        HostError::Exhausted | HostError::BudgetExceeded => ComponentTerminal::BudgetExceeded,
        HostError::InvalidArgument | HostError::BackendFault => ComponentTerminal::BackendFault,
    }
}

const fn trap_terminal(trap: TrapCode) -> ComponentTerminal {
    match trap {
        TrapCode::Cancelled => ComponentTerminal::Cancelled,
        TrapCode::FuelExhausted | TrapCode::LimitExceeded => ComponentTerminal::BudgetExceeded,
        _ => ComponentTerminal::Trapped(ComponentTrapCode::new(trap as u16)),
    }
}

fn terminal_result(terminal: ComponentTerminal) -> ComponentCommandResult {
    ComponentCommandResult::try_new(terminal, Vec::new())
        .unwrap_or_else(|_| ComponentCommandResult::budget_exceeded())
}
