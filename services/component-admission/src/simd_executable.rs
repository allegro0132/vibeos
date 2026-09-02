//! Authority-free volatile admission and lifecycle for the independent code-8
//! executable SIMD successor.

use super::*;
use vibeos_component_format::{ProfileStage, TrapCode, PROFILE_5_SYNC_SIMD_EXECUTABLE_WORLD};
use vibeos_wasm_runtime::current_profile_required_compile_bytes;
use vibeos_wasm_simd_executable::{execute, ExecutableValue};

pub const SIMD_EXECUTABLE_ACTIVATION_LABEL: &str = "c811-s2-simd-runtime";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimdExecutableAdmissionPolicy<'a> {
    pub activation_label: &'a str,
    pub exact_world: &'a WorldContract,
    pub trust: ArtifactTrust,
    pub limits: InstanceLimits,
    pub compile_reservation_bytes: usize,
}

/// Move-only, authority-free code-8 admission result. It exposes no raw bytes,
/// command conversion, durable conversion, or capability table.
pub struct AdmittedSimdExecutable {
    artifact: ComponentArtifact,
    inspection: InspectionSummary,
    activation_label: String,
    limits: InstanceLimits,
    compile_reservation_bytes: usize,
    _sealed: private::Seal,
}

impl AdmittedSimdExecutable {
    pub const fn identity(&self) -> ComponentIdentity {
        self.artifact.identity
    }

    pub const fn profile(&self) -> ProfileIdentity {
        self.inspection.profile
    }

    pub fn activation_label(&self) -> &str {
        &self.activation_label
    }

    pub fn world(&self) -> &str {
        &self.inspection.world
    }

    pub const fn limits(&self) -> InstanceLimits {
        self.limits
    }

    pub const fn compile_reservation_bytes(&self) -> usize {
        self.compile_reservation_bytes
    }

    pub fn validated_plan(&self) -> Result<ComponentPlan<'_>, AdmissionError> {
        revalidate(self)
    }

    pub fn activate(self) -> Result<SimdExecutableLifecycle, SimdExecutableError> {
        let plan = self
            .validated_plan()
            .map_err(SimdExecutableError::Admission)?;
        let core = plan
            .embedded_modules()
            .first()
            .ok_or(SimdExecutableError::InvalidPlan)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(core.len())
            .map_err(|_| SimdExecutableError::Allocation)?;
        owned.extend_from_slice(core);
        Ok(SimdExecutableLifecycle {
            core: owned,
            limits: self.limits,
            state: SimdExecutableState::Idle,
            pending: None,
            metrics: SimdExecutableMetrics {
                activations: 1,
                peak_live_instances: 1,
                ..SimdExecutableMetrics::default()
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdExecutableError {
    Admission(AdmissionError),
    InvalidPlan,
    InvalidLimits,
    Allocation,
    Busy,
    NotRunning,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdExecutableState {
    Idle,
    Running,
    Cancelled,
    Faulted(TrapCode),
    Revoked,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SimdExecutableMetrics {
    pub activations: u64,
    pub calls_started: u64,
    pub calls_completed: u64,
    pub cancellations: u64,
    pub faults: u64,
    pub revocations: u64,
    pub recoveries: u64,
    pub reclaimed_instances: u64,
    pub peak_live_instances: u8,
    pub last_consumed_fuel: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SimdExecutablePoll {
    Ready(Vec<u8>),
    Faulted(TrapCode),
}

/// Single-instance volatile lifecycle. Calls are bounded by the exact total
/// fuel ceiling; cancel, fault, and revoke reclaim the live instance.
pub struct SimdExecutableLifecycle {
    core: Vec<u8>,
    limits: InstanceLimits,
    state: SimdExecutableState,
    pending: Option<(u32, u32)>,
    metrics: SimdExecutableMetrics,
}

impl SimdExecutableLifecycle {
    pub const fn state(&self) -> SimdExecutableState {
        self.state
    }

    pub const fn metrics(&self) -> SimdExecutableMetrics {
        self.metrics
    }

    pub const fn live_instances(&self) -> u8 {
        if matches!(
            self.state,
            SimdExecutableState::Idle | SimdExecutableState::Running
        ) {
            1
        } else {
            0
        }
    }

    pub fn start_call(&mut self, mode: u32, input: &[u8]) -> Result<(), SimdExecutableError> {
        match self.state {
            SimdExecutableState::Revoked => return Err(SimdExecutableError::Revoked),
            SimdExecutableState::Idle => {}
            _ => return Err(SimdExecutableError::Busy),
        }
        let length = u32::try_from(input.len()).map_err(|_| SimdExecutableError::InvalidLimits)?;
        if input.len() > self.limits.memory_bytes {
            return Err(SimdExecutableError::InvalidLimits);
        }
        self.pending = Some((mode, length));
        self.state = SimdExecutableState::Running;
        self.metrics.calls_started = self.metrics.calls_started.saturating_add(1);
        Ok(())
    }

    pub fn poll_call(&mut self) -> Result<SimdExecutablePoll, SimdExecutableError> {
        if self.state == SimdExecutableState::Revoked {
            return Err(SimdExecutableError::Revoked);
        }
        let (mode, length) = self.pending.take().ok_or(SimdExecutableError::NotRunning)?;
        let result = execute(
            &self.core,
            "run",
            &[
                ExecutableValue::I32(mode as i32),
                ExecutableValue::I32(0),
                ExecutableValue::I32(length as i32),
            ],
            self.limits.total_fuel,
        );
        match result {
            Ok((values, consumed))
                if consumed <= self.limits.total_fuel
                    && values.as_slice() == [ExecutableValue::I32(512)] =>
            {
                self.state = SimdExecutableState::Idle;
                self.metrics.calls_completed = self.metrics.calls_completed.saturating_add(1);
                self.metrics.last_consumed_fuel = consumed;
                Ok(SimdExecutablePoll::Ready(Vec::new()))
            }
            Ok(_) => self.fault(TrapCode::Validation),
            Err(trap) => self.fault(trap),
        }
    }

    fn fault(&mut self, trap: TrapCode) -> Result<SimdExecutablePoll, SimdExecutableError> {
        self.state = SimdExecutableState::Faulted(trap);
        self.metrics.faults = self.metrics.faults.saturating_add(1);
        self.metrics.reclaimed_instances = self.metrics.reclaimed_instances.saturating_add(1);
        Ok(SimdExecutablePoll::Faulted(trap))
    }

    pub fn cancel(&mut self) -> Result<(), SimdExecutableError> {
        if self.state != SimdExecutableState::Running {
            return Err(SimdExecutableError::NotRunning);
        }
        self.pending = None;
        self.state = SimdExecutableState::Cancelled;
        self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
        self.metrics.reclaimed_instances = self.metrics.reclaimed_instances.saturating_add(1);
        Ok(())
    }

    pub fn recover(&mut self) -> Result<(), SimdExecutableError> {
        match self.state {
            SimdExecutableState::Cancelled | SimdExecutableState::Faulted(_) => {
                self.pending = None;
                self.state = SimdExecutableState::Idle;
                self.metrics.activations = self.metrics.activations.saturating_add(1);
                self.metrics.recoveries = self.metrics.recoveries.saturating_add(1);
                Ok(())
            }
            SimdExecutableState::Revoked => Err(SimdExecutableError::Revoked),
            _ => Err(SimdExecutableError::Busy),
        }
    }

    pub fn revoke(&mut self) {
        if self.state == SimdExecutableState::Revoked {
            return;
        }
        if self.live_instances() == 1 {
            self.metrics.reclaimed_instances = self.metrics.reclaimed_instances.saturating_add(1);
        }
        self.pending = None;
        self.state = SimdExecutableState::Revoked;
        self.metrics.revocations = self.metrics.revocations.saturating_add(1);
    }
}

pub fn admit_simd_executable(
    artifact: ComponentArtifact,
    policy: &SimdExecutableAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedSimdExecutable, AdmissionError> {
    let profile = ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE;
    if artifact.profile != profile
        || profile.stage != ProfileStage::Executable
        || !profile.execution_enabled()
    {
        return Err(AdmissionError::BadProfile);
    }
    if policy.trust != ArtifactTrust::ImagePinned(artifact.identity) {
        return Err(AdmissionError::UntrustedArtifact);
    }
    policy.limits.validate_float_acceptance()?;
    if policy.limits.memory_bytes != 65_536
        || policy.limits.poll_quantum != policy.limits.total_fuel
    {
        return Err(AdmissionError::InvalidLimits);
    }
    if policy.activation_label != SIMD_EXECUTABLE_ACTIVATION_LABEL
        || policy.exact_world.identity != PROFILE_5_SYNC_SIMD_EXECUTABLE_WORLD
        || !valid_manifest_text(&policy.exact_world.identity, 256)
        || !caller.offers.is_empty()
    {
        return Err(AdmissionError::InvalidPolicy);
    }

    let engine = current_component_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    let core_engine = current_core_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    if engine.identity() != core_engine.identity() {
        return Err(AdmissionError::BadProfile);
    }
    let (component, modules, imports, exports, required) = {
        let plan = inspect_component_with_current_engine(&artifact.bytes, &engine)
            .map_err(AdmissionError::Decode)?;
        plan.check_world(policy.exact_world)
            .map_err(AdmissionError::World)?;
        if !plan_matches(&plan) {
            return Err(AdmissionError::InvalidPolicy);
        }
        let core = plan.embedded_modules()[0];
        let required = current_profile_required_compile_bytes(core, &core_engine)
            .map_err(AdmissionError::Core)?;
        if policy.compile_reservation_bytes != required {
            return Err(AdmissionError::InvalidLimits);
        }
        let summary =
            inspect_core_with_current_engine(core, &core_engine).map_err(AdmissionError::Core)?;
        if summary.imports != 0 {
            return Err(AdmissionError::InvalidPolicy);
        }
        let mut modules = Vec::new();
        modules
            .try_reserve_exact(1)
            .map_err(|_| AdmissionError::Allocation)?;
        modules.push(summary);
        let component = plan.summary();
        let (imports, exports) = plan.into_world_shapes();
        (component, modules, imports, exports, required)
    };

    Ok(AdmittedSimdExecutable {
        artifact,
        inspection: InspectionSummary {
            profile,
            world: copied(&policy.exact_world.identity)?,
            component,
            modules,
            imports,
            exports,
        },
        activation_label: copied(policy.activation_label)?,
        limits: policy.limits,
        compile_reservation_bytes: required,
        _sealed: private::Seal,
    })
}

fn revalidate(candidate: &AdmittedSimdExecutable) -> Result<ComponentPlan<'_>, AdmissionError> {
    let identity = ComponentIdentity(Sha256::digest(&candidate.artifact.bytes).into());
    let profile = ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE;
    if identity != candidate.artifact.identity
        || candidate.artifact.profile != profile
        || candidate.inspection.profile != profile
        || candidate.inspection.profile.stage != ProfileStage::Executable
        || !candidate.inspection.profile.execution_enabled()
        || candidate.activation_label != SIMD_EXECUTABLE_ACTIVATION_LABEL
        || candidate.limits.validate_float_acceptance().is_err()
    {
        return Err(AdmissionError::RevalidationMismatch);
    }
    let engine = current_component_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    let core_engine = current_core_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    let plan = inspect_component_with_current_engine(&candidate.artifact.bytes, &engine)
        .map_err(AdmissionError::Decode)?;
    if plan.summary() != candidate.inspection.component
        || plan.profile() != candidate.inspection.profile
        || plan.imports() != candidate.inspection.imports
        || plan.exports() != candidate.inspection.exports
        || plan.embedded_modules().len() != 1
        || !plan_matches(&plan)
    {
        return Err(AdmissionError::RevalidationMismatch);
    }
    let core = plan.embedded_modules()[0];
    if inspect_core_with_current_engine(core, &core_engine).map_err(AdmissionError::Core)?
        != candidate.inspection.modules[0]
        || current_profile_required_compile_bytes(core, &core_engine)
            .map_err(AdmissionError::Core)?
            != candidate.compile_reservation_bytes
    {
        return Err(AdmissionError::RevalidationMismatch);
    }
    Ok(plan)
}

fn plan_matches(plan: &ComponentPlan<'_>) -> bool {
    let summary = plan.summary();
    if plan.profile() != ProfileIdentity::PROFILE_5_SYNC_SIMD_EXECUTABLE
        || plan.profile().stage != ProfileStage::Executable
        || !plan.profile().execution_enabled()
        || !plan.runtime_ready()
        || !summary.async_abi.is_empty()
        || summary.embedded_modules != 1
        || summary.core_instances != 1
        || summary.component_instances != 0
        || summary.canonical_functions != 1
        || summary.resources != 0
        || summary.imports != 0
        || summary.exports != 1
        || !plan.imports().is_empty()
        || plan.host_imports().next().is_some()
        || plan.executable_exports().next().is_some()
        || !plan.has_exact_simd_candidate_execution_binding()
        || plan.exports().len() != 1
    {
        return false;
    }
    let export = &plan.exports()[0];
    let EntityShape::Function(function) = &export.entity else {
        return false;
    };
    export.name == "run"
        && function.effect == FunctionEffect::Sync
        && function.parameters.len() == 2
        && function.parameters[0].name == "mode"
        && function.parameters[0].value == ValueShape::U32
        && function.parameters[1].name == "input"
        && matches!(&function.parameters[1].value, ValueShape::List(item) if **item == ValueShape::U8)
        && matches!(&function.result, Some(ValueShape::List(item)) if **item == ValueShape::U8)
}
