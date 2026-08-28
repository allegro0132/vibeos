//! Default-off lifecycle wiring for the C8.8 scalar-float candidate.
//!
//! This module joins the independently identified F2 Core engine to the F3
//! bit-only Canonical ABI codec. It accepts only one closed, import-free
//! validation-candidate shape. The ordinary Component execution plan remains
//! empty, artifact profile code 5 remains `ValidationOnly`, and no value here
//! implements a production command, loader, or current-engine interface.

use crate::{
    abi_value::float_candidate::{
        lift_flat_values, lower_flat_values, CandidateFlatValue, CodecError, PayloadAllocator,
        RejectResources,
    },
    decode::ComponentPlan,
    memory::VecMemory,
    value::{CanonicalValue, ValuePosition, ValueType},
    world::{EntityShape, FunctionEffect, ValueShape},
};
use alloc::vec::Vec;
use vibeos_component_format::{ProfileIdentity, ProfileStage, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_float_candidate::{
    CandidateCallMetrics, CandidateInstance, CandidateModule, CandidatePoll, CandidateValue,
    CANDIDATE_IDENTITY,
};
use vibeos_wasm_runtime::{
    profile_2_candidate_required_compile_bytes, AdmissionError as CoreAdmissionError,
    OwnerAllocationReservation,
};

/// The sole Core export wired by the F4 lifecycle candidate.
pub const FLOAT_CANDIDATE_CORE_EXPORT: &str = "run";

/// Exact lifecycle ceilings supplied by trusted candidate policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FloatCandidateLimits {
    pub compile_reservation_bytes: usize,
    pub memory_bytes: usize,
    pub total_fuel: u64,
    pub poll_quantum: u64,
}

impl FloatCandidateLimits {
    fn validate(self) -> Result<(), FloatCandidateError> {
        let maximum_memory = (PROFILE_1_LIMITS.max_memory_pages as usize)
            .checked_mul(65_536)
            .ok_or(FloatCandidateError::InvalidLimits)?;
        if self.compile_reservation_bytes == 0
            || self.memory_bytes == 0
            || self.memory_bytes > maximum_memory
            || self.total_fuel == 0
            || self.total_fuel > PROFILE_1_LIMITS.total_fuel
            || self.poll_quantum == 0
            || self.poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || self.poll_quantum > self.total_fuel
        {
            return Err(FloatCandidateError::InvalidLimits);
        }
        Ok(())
    }
}

/// Stable failures from the candidate-only activation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatCandidateError {
    InvalidPlan,
    InvalidLimits,
    CoreAdmission(CoreAdmissionError),
    Instantiation(TrapCode),
    Codec(CodecError),
    Busy,
    NotRunning,
    RecoveryUnavailable,
    Revoked,
}

/// Observable lifecycle state. `Cancelled` and `Faulted` contain no live
/// engine instance; recovery always creates a cold replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatCandidateState {
    Idle,
    Running,
    Cancelled,
    Faulted(TrapCode),
    Poisoned,
    Revoked,
}

/// Bounded lifecycle accounting. At most one instance can be live because the
/// module and lifecycle types are move-only and expose no duplicate method.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FloatCandidateLifecycleMetrics {
    pub activations: u64,
    pub calls_started: u64,
    pub calls_completed: u64,
    pub cancellations: u64,
    pub revocations: u64,
    pub faults: u64,
    pub reclaimed_instances: u64,
    pub peak_live_instances: u8,
}

/// Candidate scheduler result after one exact F2 poll quantum.
#[derive(Debug, PartialEq, Eq)]
pub enum FloatCandidateLifecyclePoll {
    Pending(CandidateCallMetrics),
    Ready(CanonicalValue),
    Faulted(TrapCode),
}

/// Compiled but not yet activated candidate.
///
/// ```compile_fail
/// use vibeos_component_runtime::float_candidate::FloatCandidateComponent;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<FloatCandidateComponent>();
/// ```
pub struct FloatCandidateComponent {
    module: CandidateModule,
    binding: crate::decode::FloatCandidateExecutionBinding,
    limits: FloatCandidateLimits,
}

impl FloatCandidateComponent {
    /// Returns the deterministic owner charge for the sole embedded Core
    /// module after rechecking the complete candidate plan shape.
    pub fn required_compile_reservation(
        plan: &ComponentPlan<'_>,
    ) -> Result<usize, FloatCandidateError> {
        if !float_candidate_plan_matches(plan) {
            return Err(FloatCandidateError::InvalidPlan);
        }
        let binding = plan
            .float_candidate_execution_binding()
            .ok_or(FloatCandidateError::InvalidPlan)?;
        profile_2_candidate_required_compile_bytes(plan.embedded_modules()[binding.module()])
            .map_err(FloatCandidateError::CoreAdmission)
    }

    /// Compiles the only accepted F4 Component shape under an exact owner
    /// reservation. `plan` remains permanently inert; only its sole embedded
    /// Core module is passed to the separately identified candidate engine.
    pub fn compile(
        plan: &ComponentPlan<'_>,
        limits: FloatCandidateLimits,
    ) -> Result<Self, FloatCandidateError> {
        limits.validate()?;
        if !float_candidate_plan_matches(plan)
            || CANDIDATE_IDENTITY.production_ready
            || CANDIDATE_IDENTITY.acceptance_feature != "c88-f2-acceptance"
        {
            return Err(FloatCandidateError::InvalidPlan);
        }
        let required_compile_reservation = Self::required_compile_reservation(plan)?;
        if limits.compile_reservation_bytes > required_compile_reservation {
            return Err(FloatCandidateError::InvalidLimits);
        }
        let binding = plan
            .float_candidate_execution_binding()
            .ok_or(FloatCandidateError::InvalidPlan)?;
        let module = CandidateModule::compile(
            plan.embedded_modules()[binding.module()],
            OwnerAllocationReservation::new(limits.compile_reservation_bytes),
        )
        .map_err(FloatCandidateError::CoreAdmission)?;
        Ok(Self {
            module,
            binding,
            limits,
        })
    }

    pub const fn limits(&self) -> FloatCandidateLimits {
        self.limits
    }

    /// Explicitly activates this default-off candidate. The move consumes the
    /// compiled value, preventing a single policy decision from minting two
    /// live instances.
    pub fn activate(self) -> Result<FloatCandidateLifecycle, FloatCandidateError> {
        let instance = self
            .module
            .instantiate_with_memory_limit(self.limits.memory_bytes)
            .map_err(FloatCandidateError::Instantiation)?;
        let codec_memory = VecMemory::new(0, 8).map_err(|_| FloatCandidateError::InvalidLimits)?;
        Ok(FloatCandidateLifecycle {
            module: self.module,
            binding: self.binding,
            instance: Some(instance),
            codec_memory,
            limits: self.limits,
            state: FloatCandidateState::Idle,
            metrics: FloatCandidateLifecycleMetrics {
                activations: 1,
                peak_live_instances: 1,
                ..FloatCandidateLifecycleMetrics::default()
            },
            last_call_metrics: None,
        })
    }
}

/// Move-only cold-recoverable acceptance lifecycle.
///
/// It deliberately exposes neither the underlying instance nor artifact/Core
/// bytes, so it cannot be adapted into the ordinary runtime or durable loader.
pub struct FloatCandidateLifecycle {
    module: CandidateModule,
    binding: crate::decode::FloatCandidateExecutionBinding,
    instance: Option<CandidateInstance>,
    codec_memory: VecMemory,
    limits: FloatCandidateLimits,
    state: FloatCandidateState,
    metrics: FloatCandidateLifecycleMetrics,
    last_call_metrics: Option<CandidateCallMetrics>,
}

impl FloatCandidateLifecycle {
    pub const fn state(&self) -> FloatCandidateState {
        self.state
    }

    pub const fn metrics(&self) -> FloatCandidateLifecycleMetrics {
        self.metrics
    }

    pub const fn limits(&self) -> FloatCandidateLimits {
        self.limits
    }

    pub fn live_instances(&self) -> u8 {
        u8::from(self.instance.is_some())
    }

    /// Most recent candidate-engine fuel observation for this lifecycle.
    ///
    /// The value is reset before each call and retained across terminal
    /// reclamation so target qualification can prove the exact final fuel
    /// state without exposing the underlying engine instance. This remains an
    /// acceptance-only observation surface behind `c88-f4-acceptance`.
    pub const fn last_call_metrics(&self) -> Option<CandidateCallMetrics> {
        self.last_call_metrics
    }

    /// Canonically lowers one exact `(u32, f32, f64) -> f64` call and starts
    /// it in the F2 engine using only the policy-selected fuel and quantum.
    pub fn start_call(
        &mut self,
        mode: u32,
        left: crate::value::CanonicalF32,
        right: crate::value::CanonicalF64,
    ) -> Result<(), FloatCandidateError> {
        match self.state {
            FloatCandidateState::Idle => {}
            FloatCandidateState::Running => return Err(FloatCandidateError::Busy),
            FloatCandidateState::Revoked => return Err(FloatCandidateError::Revoked),
            FloatCandidateState::Cancelled
            | FloatCandidateState::Faulted(_)
            | FloatCandidateState::Poisoned => {
                return Err(FloatCandidateError::RecoveryUnavailable)
            }
        }
        let values = [
            CanonicalValue::U32(mode),
            CanonicalValue::F32(left),
            CanonicalValue::F64(right),
        ];
        let mut allocator = NoPayloadAllocation;
        let (flat, _) = lower_flat_values(
            &mut self.codec_memory,
            &mut allocator,
            &parameter_types(),
            &values,
        )
        .map_err(FloatCandidateError::Codec)?;
        let inputs = core_inputs(flat)?;
        let instance = self
            .instance
            .as_mut()
            .ok_or(FloatCandidateError::RecoveryUnavailable)?;
        instance
            .start_call(
                self.binding.core_export(),
                &inputs,
                self.limits.total_fuel,
                self.limits.poll_quantum,
            )
            .map_err(FloatCandidateError::Instantiation)?;
        self.last_call_metrics = None;
        self.metrics.calls_started = self.metrics.calls_started.saturating_add(1);
        self.state = FloatCandidateState::Running;
        Ok(())
    }

    pub fn poll_call(&mut self) -> Result<FloatCandidateLifecyclePoll, FloatCandidateError> {
        if self.state == FloatCandidateState::Revoked {
            return Err(FloatCandidateError::Revoked);
        }
        if self.state != FloatCandidateState::Running {
            return Err(FloatCandidateError::NotRunning);
        }
        let poll = self
            .instance
            .as_mut()
            .ok_or(FloatCandidateError::RecoveryUnavailable)?
            .poll_call();
        self.last_call_metrics = self
            .instance
            .as_ref()
            .and_then(CandidateInstance::call_metrics);
        match poll {
            CandidatePoll::Pending(metrics) => Ok(FloatCandidateLifecyclePoll::Pending(metrics)),
            CandidatePoll::Ready(values) => match self.lift_result(values) {
                Ok(value) => {
                    self.metrics.calls_completed = self.metrics.calls_completed.saturating_add(1);
                    self.state = FloatCandidateState::Idle;
                    Ok(FloatCandidateLifecyclePoll::Ready(value))
                }
                Err(error) => {
                    self.poison_and_reclaim();
                    Err(error)
                }
            },
            CandidatePoll::Trapped(trap) => {
                self.metrics.faults = self.metrics.faults.saturating_add(1);
                self.reclaim_instance();
                self.state = FloatCandidateState::Faulted(trap);
                Ok(FloatCandidateLifecyclePoll::Faulted(trap))
            }
        }
    }

    /// Cancels only a pending call. The whole engine instance and continuation
    /// are dropped; reuse requires [`Self::recover`] to cold-instantiate.
    pub fn cancel(&mut self) -> Result<(), FloatCandidateError> {
        if self.state == FloatCandidateState::Revoked {
            return Err(FloatCandidateError::Revoked);
        }
        if self.state != FloatCandidateState::Running {
            return Err(FloatCandidateError::NotRunning);
        }
        self.metrics.cancellations = self.metrics.cancellations.saturating_add(1);
        self.reclaim_instance();
        self.state = FloatCandidateState::Cancelled;
        Ok(())
    }

    /// Revocation is absorbing and synchronously drops any live instance or
    /// continuation. No recovery method accepts the `Revoked` state.
    pub fn revoke(&mut self) {
        if self.state != FloatCandidateState::Revoked {
            self.metrics.revocations = self.metrics.revocations.saturating_add(1);
            self.reclaim_instance();
            self.state = FloatCandidateState::Revoked;
        }
    }

    /// Cold-instantiates after cancellation or a fault. A poisoned codec path
    /// is intentionally non-recoverable because it may indicate a wiring bug.
    pub fn recover(&mut self) -> Result<(), FloatCandidateError> {
        match self.state {
            FloatCandidateState::Cancelled | FloatCandidateState::Faulted(_) => {}
            FloatCandidateState::Revoked => return Err(FloatCandidateError::Revoked),
            FloatCandidateState::Poisoned
            | FloatCandidateState::Idle
            | FloatCandidateState::Running => return Err(FloatCandidateError::RecoveryUnavailable),
        }
        debug_assert!(self.instance.is_none());
        let instance = self
            .module
            .instantiate_with_memory_limit(self.limits.memory_bytes)
            .map_err(FloatCandidateError::Instantiation)?;
        self.instance = Some(instance);
        self.metrics.activations = self.metrics.activations.saturating_add(1);
        self.metrics.peak_live_instances = self.metrics.peak_live_instances.max(1);
        self.state = FloatCandidateState::Idle;
        Ok(())
    }

    fn lift_result(
        &mut self,
        values: Vec<CandidateValue>,
    ) -> Result<CanonicalValue, FloatCandidateError> {
        let flat = candidate_outputs(values)?;
        let (mut values, _) = lift_flat_values(
            &self.codec_memory,
            &RejectResources,
            &result_types(),
            &flat,
            ValuePosition::Result,
        )
        .map_err(FloatCandidateError::Codec)?;
        if values.len() != 1 {
            return Err(FloatCandidateError::Codec(CodecError::TypeMismatch));
        }
        Ok(values.remove(0))
    }

    fn reclaim_instance(&mut self) {
        if let Some(instance) = self.instance.take() {
            self.last_call_metrics = instance.call_metrics().or(self.last_call_metrics);
            self.metrics.reclaimed_instances = self.metrics.reclaimed_instances.saturating_add(1);
        }
    }

    fn poison_and_reclaim(&mut self) {
        self.metrics.faults = self.metrics.faults.saturating_add(1);
        self.reclaim_instance();
        self.state = FloatCandidateState::Poisoned;
    }
}

#[derive(Default)]
struct NoPayloadAllocation;

impl PayloadAllocator<VecMemory> for NoPayloadAllocation {
    fn allocate(
        &mut self,
        _memory: &mut VecMemory,
        _size: u32,
        _alignment: u32,
    ) -> Result<u32, CodecError> {
        Err(CodecError::Allocation)
    }
}

fn parameter_types() -> [ValueType; 3] {
    [ValueType::U32, ValueType::F32, ValueType::F64]
}

fn result_types() -> [ValueType; 1] {
    [ValueType::F64]
}

fn core_inputs(flat: Vec<CandidateFlatValue>) -> Result<Vec<CandidateValue>, FloatCandidateError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(flat.len())
        .map_err(|_| FloatCandidateError::Codec(CodecError::Allocation))?;
    for value in flat {
        values.push(match value {
            CandidateFlatValue::I32(value) => CandidateValue::I32(value),
            CandidateFlatValue::I64(value) => CandidateValue::I64(value),
            CandidateFlatValue::F32Bits(bits) => CandidateValue::F32Bits(bits),
            CandidateFlatValue::F64Bits(bits) => CandidateValue::F64Bits(bits),
        });
    }
    Ok(values)
}

fn candidate_outputs(
    values: Vec<CandidateValue>,
) -> Result<Vec<CandidateFlatValue>, FloatCandidateError> {
    let mut flat = Vec::new();
    flat.try_reserve_exact(values.len())
        .map_err(|_| FloatCandidateError::Codec(CodecError::Allocation))?;
    for value in values {
        flat.push(match value {
            CandidateValue::I32(value) => CandidateFlatValue::I32(value),
            CandidateValue::I64(value) => CandidateFlatValue::I64(value),
            CandidateValue::F32Bits(bits) => CandidateFlatValue::F32Bits(bits),
            CandidateValue::F64Bits(bits) => CandidateFlatValue::F64Bits(bits),
        });
    }
    Ok(flat)
}

fn float_candidate_plan_matches(plan: &ComponentPlan<'_>) -> bool {
    let summary = plan.summary();
    if plan.profile() != ProfileIdentity::PROFILE_2_SYNC_FLOAT
        || plan.profile().stage != ProfileStage::ValidationOnly
        || plan.profile().execution_enabled()
        || plan.runtime_ready()
        || plan.native_async_runtime_ready()
        || !summary.async_abi.is_empty()
        || summary.embedded_modules != 1
        || summary.core_instances != 1
        || summary.component_instances != 0
        || summary.definitions != 1
        || summary.aliases != 1
        || summary.canonical_functions != 1
        || summary.adapters != 0
        || summary.resources != 0
        || summary.imports != 0
        || summary.exports != 1
        || plan.embedded_modules().len() != 1
        || !plan.imports().is_empty()
        || plan.exports().len() != 1
        || plan.host_imports().next().is_some()
        || plan.executable_exports().next().is_some()
        || !plan.has_exact_float_candidate_execution_binding()
    {
        return false;
    }
    let export = &plan.exports()[0];
    if export.name != FLOAT_CANDIDATE_CORE_EXPORT {
        return false;
    }
    let EntityShape::Function(function) = &export.entity else {
        return false;
    };
    function.effect == FunctionEffect::Sync
        && function.parameters.len() == 3
        && function.parameters[0].name == "mode"
        && function.parameters[0].value == ValueShape::U32
        && function.parameters[1].name == "left"
        && function.parameters[1].value == ValueShape::F32
        && function.parameters[2].name == "right"
        && function.parameters[2].value == ValueShape::F64
        && function.result == Some(ValueShape::F64)
}
