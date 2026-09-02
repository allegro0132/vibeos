//! Authority-free volatile admission for independently numbered code 10.

use super::*;
use vibeos_component_format::{
    ProfileStage, TrapCode, PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE_WORLD,
};
use vibeos_wasm_reference_executable::{execute, ExecutableValue};
use vibeos_wasm_runtime::current_profile_required_compile_bytes;

pub const REFERENCE_EXECUTABLE_ACTIVATION_LABEL: &str = "c813-e2-reference-runtime";

pub struct ReferenceExecutableAdmissionPolicy<'a> {
    pub activation_label: &'a str,
    pub exact_world: &'a WorldContract,
    pub trust: ArtifactTrust,
    pub limits: InstanceLimits,
    pub compile_reservation_bytes: usize,
}

pub struct AdmittedReferenceExecutable {
    artifact: ComponentArtifact,
    inspection: InspectionSummary,
    limits: InstanceLimits,
    compile_reservation_bytes: usize,
    _sealed: private::Seal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceExecutableError {
    Admission(AdmissionError),
    InvalidPlan,
    Allocation,
    Busy,
    NotRunning,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReferenceExecutableState {
    Idle,
    Running,
    Cancelled,
    Faulted(TrapCode),
    Revoked,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceExecutableMetrics {
    pub activations: u64,
    pub calls_started: u64,
    pub calls_completed: u64,
    pub cancellations: u64,
    pub faults: u64,
    pub revocations: u64,
    pub recoveries: u64,
    pub reclaimed_instances: u64,
    pub last_consumed_fuel: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReferenceExecutablePoll {
    Ready(Vec<u8>),
    Faulted(TrapCode),
}

pub struct ReferenceExecutableLifecycle {
    core: Vec<u8>,
    limits: InstanceLimits,
    state: ReferenceExecutableState,
    pending: Option<(u32, u32)>,
    metrics: ReferenceExecutableMetrics,
}

impl AdmittedReferenceExecutable {
    pub const fn profile(&self) -> ProfileIdentity {
        self.inspection.profile
    }
    pub const fn compile_reservation_bytes(&self) -> usize {
        self.compile_reservation_bytes
    }
    pub fn activate(self) -> Result<ReferenceExecutableLifecycle, ReferenceExecutableError> {
        let engine = current_component_validation_engine(self.inspection.profile)
            .ok_or(ReferenceExecutableError::InvalidPlan)?;
        let plan = inspect_component_with_current_engine(&self.artifact.bytes, &engine)
            .map_err(|_| ReferenceExecutableError::InvalidPlan)?;
        let core = plan
            .embedded_modules()
            .first()
            .ok_or(ReferenceExecutableError::InvalidPlan)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(core.len())
            .map_err(|_| ReferenceExecutableError::Allocation)?;
        owned.extend_from_slice(core);
        Ok(ReferenceExecutableLifecycle {
            core: owned,
            limits: self.limits,
            state: ReferenceExecutableState::Idle,
            pending: None,
            metrics: ReferenceExecutableMetrics {
                activations: 1,
                ..Default::default()
            },
        })
    }
}

impl ReferenceExecutableLifecycle {
    pub const fn state(&self) -> ReferenceExecutableState {
        self.state
    }
    pub const fn metrics(&self) -> ReferenceExecutableMetrics {
        self.metrics
    }
    pub fn start_call(&mut self, mode: u32, input: &[u8]) -> Result<(), ReferenceExecutableError> {
        match self.state {
            ReferenceExecutableState::Revoked => return Err(ReferenceExecutableError::Revoked),
            ReferenceExecutableState::Idle => {}
            _ => return Err(ReferenceExecutableError::Busy),
        }
        if input.len() > self.limits.memory_bytes {
            return Err(ReferenceExecutableError::InvalidPlan);
        }
        self.pending = Some((mode, input.len() as u32));
        self.state = ReferenceExecutableState::Running;
        self.metrics.calls_started = self.metrics.calls_started.saturating_add(1);
        Ok(())
    }
    pub fn poll_call(&mut self) -> Result<ReferenceExecutablePoll, ReferenceExecutableError> {
        if self.state == ReferenceExecutableState::Revoked {
            return Err(ReferenceExecutableError::Revoked);
        }
        let (mode, length) = self
            .pending
            .take()
            .ok_or(ReferenceExecutableError::NotRunning)?;
        match execute(
            &self.core,
            "run",
            &[
                ExecutableValue::I32(mode as i32),
                ExecutableValue::I32(0),
                ExecutableValue::I32(length as i32),
            ],
            self.limits.total_fuel,
        ) {
            Ok((values, consumed))
                if values.as_slice() == [ExecutableValue::I32(512)]
                    && consumed <= self.limits.total_fuel =>
            {
                self.state = ReferenceExecutableState::Idle;
                self.metrics.calls_completed += 1;
                self.metrics.last_consumed_fuel = consumed;
                Ok(ReferenceExecutablePoll::Ready(Vec::new()))
            }
            Ok(_) => self.fault(TrapCode::Validation),
            Err(trap) => self.fault(trap),
        }
    }
    fn fault(
        &mut self,
        trap: TrapCode,
    ) -> Result<ReferenceExecutablePoll, ReferenceExecutableError> {
        self.state = ReferenceExecutableState::Faulted(trap);
        self.metrics.faults += 1;
        self.metrics.reclaimed_instances += 1;
        Ok(ReferenceExecutablePoll::Faulted(trap))
    }
    pub fn cancel(&mut self) -> Result<(), ReferenceExecutableError> {
        if self.state != ReferenceExecutableState::Running {
            return Err(ReferenceExecutableError::NotRunning);
        }
        self.pending = None;
        self.state = ReferenceExecutableState::Cancelled;
        self.metrics.cancellations += 1;
        self.metrics.reclaimed_instances += 1;
        Ok(())
    }
    pub fn recover(&mut self) -> Result<(), ReferenceExecutableError> {
        match self.state {
            ReferenceExecutableState::Cancelled | ReferenceExecutableState::Faulted(_) => {
                self.state = ReferenceExecutableState::Idle;
                self.metrics.activations += 1;
                self.metrics.recoveries += 1;
                Ok(())
            }
            ReferenceExecutableState::Revoked => Err(ReferenceExecutableError::Revoked),
            _ => Err(ReferenceExecutableError::Busy),
        }
    }
    pub fn revoke(&mut self) {
        if self.state != ReferenceExecutableState::Revoked {
            self.pending = None;
            self.state = ReferenceExecutableState::Revoked;
            self.metrics.revocations += 1;
            self.metrics.reclaimed_instances += 1;
        }
    }
}

pub fn admit_reference_executable(
    artifact: ComponentArtifact,
    policy: &ReferenceExecutableAdmissionPolicy<'_>,
    caller: &CallerAuthority<'_>,
) -> Result<AdmittedReferenceExecutable, AdmissionError> {
    let profile = ProfileIdentity::PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE;
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
    if policy.activation_label != REFERENCE_EXECUTABLE_ACTIVATION_LABEL
        || policy.exact_world.identity != PROFILE_7_SYNC_REFERENCE_TYPES_EXECUTABLE_WORLD
        || !caller.offers.is_empty()
    {
        return Err(AdmissionError::InvalidPolicy);
    }
    let component_engine =
        current_component_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    let core_engine = current_core_validation_engine(profile).ok_or(AdmissionError::BadProfile)?;
    if component_engine.identity() != core_engine.identity() {
        return Err(AdmissionError::BadProfile);
    }
    let plan = inspect_component_with_current_engine(&artifact.bytes, &component_engine)
        .map_err(AdmissionError::Decode)?;
    plan.check_world(policy.exact_world)
        .map_err(AdmissionError::World)?;
    if !plan.runtime_ready()
        || plan.embedded_modules().len() != 1
        || plan.summary().resources != 0
        || plan.summary().imports != 0
        || plan.summary().exports != 1
    {
        return Err(AdmissionError::InvalidPolicy);
    }
    let core = plan.embedded_modules()[0];
    let required =
        current_profile_required_compile_bytes(core, &core_engine).map_err(AdmissionError::Core)?;
    if required != policy.compile_reservation_bytes
        || inspect_core_with_current_engine(core, &core_engine)
            .map_err(AdmissionError::Core)?
            .imports
            != 0
    {
        return Err(AdmissionError::InvalidLimits);
    }
    let summary = plan.summary();
    let (imports, exports) = plan.into_world_shapes();
    Ok(AdmittedReferenceExecutable {
        artifact,
        inspection: InspectionSummary {
            profile,
            world: copied(&policy.exact_world.identity)?,
            component: summary,
            modules: Vec::new(),
            imports,
            exports,
        },
        limits: policy.limits,
        compile_reservation_bytes: required,
        _sealed: private::Seal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle() -> ReferenceExecutableLifecycle {
        let core = wat::parse_str("(module (type (func (param i32) (result i32))) (func $id (type 0) local.get 0) (table 1 funcref) (elem (i32.const 0) $id) (func (export \"run\") (param i32 i32 i32) (result i32) i32.const 512 i32.const 0 call_indirect (type 0)))").unwrap();
        ReferenceExecutableLifecycle {
            core,
            limits: InstanceLimits {
                memory_bytes: 65_536,
                total_fuel: 10_000,
                poll_quantum: 10_000,
                resources: 1,
            },
            state: ReferenceExecutableState::Idle,
            pending: None,
            metrics: ReferenceExecutableMetrics::default(),
        }
    }

    #[test]
    fn volatile_lifecycle_completes_cancels_recovers_and_revokes() {
        let mut runtime = lifecycle();
        runtime.start_call(0, b"").unwrap();
        assert_eq!(
            runtime.poll_call().unwrap(),
            ReferenceExecutablePoll::Ready(Vec::new())
        );
        runtime.start_call(0, b"").unwrap();
        runtime.cancel().unwrap();
        runtime.recover().unwrap();
        runtime.revoke();
        assert_eq!(runtime.state(), ReferenceExecutableState::Revoked);
        assert_eq!(
            runtime.start_call(0, b""),
            Err(ReferenceExecutableError::Revoked)
        );
    }
}
