//! Pre-activation executor for the resource-free native async profile.
//!
//! The public profile remains validation-only.  This module is private and
//! its ordinary constructor independently requires the sealed runtime-ready
//! bit, which is deliberately false until the remaining canonical builtins
//! and admission boundary are complete.

#![allow(dead_code)]

use crate::{
    async_abi::{unpack_callback_result, CallbackCode, EventCode},
    async_state::{AsyncState, AsyncStateError, AsyncStateLimits, TaskHandle},
    decode::ComponentPlan,
    execution::{
        AsyncCoreValueType, NativeAsyncCanonicalFunctionPlan, NativeAsyncCoreImportPlan,
        NativeAsyncExecutionPlan,
    },
    world::FunctionEffect,
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{ProfileIdentity, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreCallReservation, CoreComponentGroup, CoreHostImport, CoreInstanceExportImport,
    CoreModuleImport, CoreValue, CoreValueType, OwnerAllocationReservation, PollResult,
    ProfileEngine, ValidatedCore,
};

/// Versioned Vibe fuel charged for resolving one empty native async result.
const TASK_RETURN_WORK: u64 = 1;
/// Versioned Vibe fuel charged for decoding and committing one callback code.
const CALLBACK_RESULT_WORK: u64 = 1;

#[cfg(test)]
use crate::async_state::TaskInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum NativeAsyncError {
    Allocation = 1,
    CoreAdmission = 2,
    CoreInstantiation = 3,
    MissingModule = 4,
    InvalidBudget = 5,
    MissingExport = 6,
    InvalidWiring = 7,
    Busy = 8,
    Poisoned = 9,
    AsyncUnavailable = 10,
    UnsupportedFeature = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeAsyncMetrics {
    pub consumed_work: u64,
    pub remaining_work: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAsyncPoll {
    Pending(NativeAsyncMetrics),
    Resolved(NativeAsyncMetrics),
    Yielded(NativeAsyncMetrics),
    Complete(NativeAsyncMetrics),
    Trapped(TrapCode),
}

pub(crate) struct NativeAsyncComponent {
    modules: CoreComponentGroup,
    exports: Vec<RuntimeExport>,
    bridges: Vec<RuntimeBridge>,
    poisoned: bool,
}

struct RuntimeExport {
    name: String,
    core_instance: usize,
    core_function: String,
    callback_instance: usize,
    callback: String,
}

#[derive(Clone, Copy)]
enum BridgeAction {
    TaskReturn,
    Unsupported,
}

struct RuntimeBridge {
    origin_instance: usize,
    action: BridgeAction,
}

enum OwnedCoreImport {
    Host {
        id: u32,
        module: String,
        name: String,
        parameters: Vec<CoreValueType>,
        results: Vec<CoreValueType>,
    },
    InstanceExport {
        module: String,
        name: String,
        instance: usize,
        export: String,
    },
}

impl OwnedCoreImport {
    fn descriptor(&self) -> CoreModuleImport<'_> {
        match self {
            Self::Host {
                id,
                module,
                name,
                parameters,
                results,
            } => CoreModuleImport::Host(CoreHostImport {
                id: *id,
                module,
                name,
                params: parameters,
                results,
            }),
            Self::InstanceExport {
                module,
                name,
                instance,
                export,
            } => CoreModuleImport::InstanceExport(CoreInstanceExportImport {
                module,
                name,
                instance: *instance,
                export,
            }),
        }
    }
}

impl NativeAsyncComponent {
    pub(crate) fn instantiate(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
    ) -> Result<Self, NativeAsyncError> {
        if !plan.native_async_runtime_ready() {
            return Err(NativeAsyncError::AsyncUnavailable);
        }
        Self::instantiate_sealed(
            plan,
            engine,
            reservation_per_module,
            PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
        )
    }

    #[cfg(test)]
    fn instantiate_validation_plan(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
    ) -> Result<Self, NativeAsyncError> {
        Self::instantiate_sealed(
            plan,
            engine,
            reservation_per_module,
            PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
        )
    }

    fn instantiate_sealed(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
        memory_bytes: usize,
    ) -> Result<Self, NativeAsyncError> {
        if plan.profile() != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE {
            return Err(NativeAsyncError::AsyncUnavailable);
        }
        let execution = plan
            .native_async_execution_plan()
            .ok_or(NativeAsyncError::InvalidWiring)?;
        // Classify every canonical bridge and reject unsupported exported
        // lifts before a Core module is instantiated. Core start functions
        // are guest execution; linked-but-disabled builtins remain fail-closed.
        let bridges = runtime_bridges(execution)?;
        let exports = runtime_exports(execution)?;
        let mut modules = CoreComponentGroup::new_with_memory_limit(
            engine,
            execution.instances().len(),
            memory_bytes,
        )
        .map_err(|_| NativeAsyncError::CoreInstantiation)?;
        for (runtime_instance, instance) in execution.instances().iter().enumerate() {
            let bytes = plan
                .embedded_modules()
                .get(instance.module)
                .ok_or(NativeAsyncError::MissingModule)?;
            let validated = ValidatedCore::new_in(engine, bytes, reservation_per_module)
                .map_err(|_| NativeAsyncError::CoreAdmission)?;
            let owned = owned_imports(runtime_instance, instance.imports.as_slice(), execution)?;
            let mut descriptors = Vec::new();
            descriptors
                .try_reserve_exact(owned.len())
                .map_err(|_| NativeAsyncError::Allocation)?;
            for import in &owned {
                descriptors.push(import.descriptor());
            }
            if modules
                .add_instance(&validated, &descriptors)
                .map_err(|_| NativeAsyncError::CoreInstantiation)?
                != runtime_instance
            {
                return Err(NativeAsyncError::InvalidWiring);
            }
        }
        modules
            .seal()
            .map_err(|_| NativeAsyncError::CoreInstantiation)?;
        Ok(Self {
            modules,
            exports,
            bridges,
            poisoned: false,
        })
    }

    fn start<'a>(
        &'a mut self,
        export: &str,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<NativeAsyncInvocation<'a>, NativeAsyncError> {
        // `poll_quantum` is the maximum Core-engine grant per public poll.
        // A surfaced canonical transition can additionally spend its small,
        // versioned work constant from the same total invocation ledger.
        if self.poisoned {
            return Err(NativeAsyncError::Poisoned);
        }
        if self.modules.any_active_call() {
            return Err(NativeAsyncError::Busy);
        }
        if total_work == 0
            || total_work > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_work
        {
            return Err(NativeAsyncError::InvalidBudget);
        }
        let export_index = self
            .exports
            .iter()
            .position(|candidate| candidate.name == export)
            .ok_or(NativeAsyncError::MissingExport)?;
        let binding = self
            .exports
            .get(export_index)
            .ok_or(NativeAsyncError::InvalidWiring)?;
        let mut state = AsyncState::new(AsyncStateLimits {
            handles: 1,
            pairs: 1,
            tasks: 1,
            waitables_per_set: 1,
        })
        .map_err(map_state_error)?;
        let task = state.create_task().map_err(map_state_error)?;
        let callback_reservation = self
            .modules
            .reserve_call(binding.callback_instance, &binding.callback)
            .map_err(|_| NativeAsyncError::InvalidWiring)?;
        self.modules
            .start_call(
                binding.core_instance,
                &binding.core_function,
                &[],
                total_work,
                poll_quantum,
            )
            .map_err(|_| NativeAsyncError::InvalidWiring)?;
        Ok(NativeAsyncInvocation {
            component: self,
            export: export_index,
            state,
            task,
            stage: InvocationStage::Run,
            total_work,
            remaining_work: total_work,
            active_call_budget: total_work,
            poll_quantum,
            callback_reservation: Some(callback_reservation),
            terminal: false,
        })
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

fn owned_imports(
    runtime_instance: usize,
    imports: &[NativeAsyncCoreImportPlan],
    execution: &NativeAsyncExecutionPlan,
) -> Result<Vec<OwnedCoreImport>, NativeAsyncError> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(imports.len())
        .map_err(|_| NativeAsyncError::Allocation)?;
    for import in imports {
        match import {
            NativeAsyncCoreImportPlan::InstanceExport {
                module,
                field,
                core_instance,
                export,
            } => {
                if *core_instance >= runtime_instance {
                    return Err(NativeAsyncError::InvalidWiring);
                }
                owned.push(OwnedCoreImport::InstanceExport {
                    module: copied(module)?,
                    name: copied(field)?,
                    instance: *core_instance,
                    export: copied(export)?,
                });
            }
            NativeAsyncCoreImportPlan::Canonical { bridge } => {
                let bridge_index =
                    usize::try_from(*bridge).map_err(|_| NativeAsyncError::InvalidWiring)?;
                let binding = execution
                    .canonical_import_bridges()
                    .get(bridge_index)
                    .ok_or(NativeAsyncError::InvalidWiring)?;
                if binding.core_instance != runtime_instance {
                    return Err(NativeAsyncError::InvalidWiring);
                }
                let mut parameters = Vec::new();
                parameters
                    .try_reserve_exact(binding.signature.parameters.len())
                    .map_err(|_| NativeAsyncError::Allocation)?;
                parameters.extend(
                    binding
                        .signature
                        .parameters
                        .iter()
                        .copied()
                        .map(runtime_core_type),
                );
                let mut results = Vec::new();
                results
                    .try_reserve_exact(binding.signature.results.len())
                    .map_err(|_| NativeAsyncError::Allocation)?;
                results.extend(
                    binding
                        .signature
                        .results
                        .iter()
                        .copied()
                        .map(runtime_core_type),
                );
                owned.push(OwnedCoreImport::Host {
                    id: *bridge,
                    module: copied(&binding.core_module)?,
                    name: copied(&binding.core_field)?,
                    parameters,
                    results,
                });
            }
        }
    }
    Ok(owned)
}

fn runtime_bridges(
    execution: &NativeAsyncExecutionPlan,
) -> Result<Vec<RuntimeBridge>, NativeAsyncError> {
    let mut bridges = Vec::new();
    bridges
        .try_reserve_exact(execution.canonical_import_bridges().len())
        .map_err(|_| NativeAsyncError::Allocation)?;
    for bridge in execution.canonical_import_bridges() {
        let canonical = execution
            .canonical_plans()
            .get(bridge.canonical as usize)
            .ok_or(NativeAsyncError::InvalidWiring)?;
        let action = match &canonical.function {
            NativeAsyncCanonicalFunctionPlan::TaskReturn { result, options }
                if result.is_none()
                    && !options.async_
                    && options.memory.is_none()
                    && options.realloc.is_none() =>
            {
                BridgeAction::TaskReturn
            }
            _ => BridgeAction::Unsupported,
        };
        bridges.push(RuntimeBridge {
            origin_instance: bridge.core_instance,
            action,
        });
    }
    Ok(bridges)
}

fn runtime_exports(
    execution: &NativeAsyncExecutionPlan,
) -> Result<Vec<RuntimeExport>, NativeAsyncError> {
    let mut exports = Vec::new();
    exports
        .try_reserve_exact(execution.exports().len())
        .map_err(|_| NativeAsyncError::Allocation)?;
    for export in execution.exports() {
        let canonical = execution
            .canonical_plans()
            .get(export.canonical as usize)
            .ok_or(NativeAsyncError::InvalidWiring)?;
        let NativeAsyncCanonicalFunctionPlan::Lift {
            core_function,
            function_type,
            callback,
            options,
        } = &canonical.function
        else {
            return Err(NativeAsyncError::InvalidWiring);
        };
        if function_type.effect != FunctionEffect::Async
            || !function_type.parameters.is_empty()
            || function_type.result.is_some()
            || !options.async_
            || options.memory.is_some()
            || options.realloc.is_some()
        {
            return Err(NativeAsyncError::UnsupportedFeature);
        }
        exports.push(RuntimeExport {
            name: copied(&export.name)?,
            core_instance: core_function.core_instance,
            core_function: copied(&core_function.export)?,
            callback_instance: callback.core_instance,
            callback: copied(&callback.export)?,
        });
    }
    Ok(exports)
}

const fn runtime_core_type(value: AsyncCoreValueType) -> CoreValueType {
    match value {
        AsyncCoreValueType::I32 => CoreValueType::I32,
        AsyncCoreValueType::I64 => CoreValueType::I64,
    }
}

fn copied(value: &str) -> Result<String, NativeAsyncError> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| NativeAsyncError::Allocation)?;
    copy.push_str(value);
    Ok(copy)
}

const fn map_state_error(error: AsyncStateError) -> NativeAsyncError {
    match error {
        AsyncStateError::AllocationFailed => NativeAsyncError::Allocation,
        AsyncStateError::InvalidLimits
        | AsyncStateError::HandleTableFull
        | AsyncStateError::PairTableFull
        | AsyncStateError::TaskTableFull => NativeAsyncError::InvalidWiring,
        _ => NativeAsyncError::InvalidWiring,
    }
}

#[derive(Clone, Copy)]
enum InvocationStage {
    Run,
    StartCallback,
    Callback,
    Terminal,
}

pub(crate) struct NativeAsyncInvocation<'a> {
    component: &'a mut NativeAsyncComponent,
    export: usize,
    state: AsyncState,
    task: TaskHandle,
    stage: InvocationStage,
    total_work: u64,
    remaining_work: u64,
    active_call_budget: u64,
    poll_quantum: u64,
    callback_reservation: Option<CoreCallReservation>,
    terminal: bool,
}

impl NativeAsyncInvocation<'_> {
    pub(crate) fn poll(&mut self) -> NativeAsyncPoll {
        if self.terminal {
            return NativeAsyncPoll::Trapped(TrapCode::Cancelled);
        }
        match self.stage {
            InvocationStage::Run => {
                let active = self.binding().core_instance;
                self.poll_core(active)
            }
            InvocationStage::StartCallback => self.start_callback(),
            InvocationStage::Callback => {
                let active = self.binding().callback_instance;
                self.poll_core(active)
            }
            InvocationStage::Terminal => NativeAsyncPoll::Trapped(TrapCode::Cancelled),
        }
    }

    pub(crate) const fn metrics(&self) -> NativeAsyncMetrics {
        NativeAsyncMetrics {
            consumed_work: self.total_work - self.remaining_work,
            remaining_work: self.remaining_work,
        }
    }

    fn binding(&self) -> &RuntimeExport {
        &self.component.exports[self.export]
    }

    fn poll_core(&mut self, active_instance: usize) -> NativeAsyncPoll {
        let result = self.component.modules.poll_call(active_instance);
        if !self.settle_metrics(active_instance) {
            return self.finish_trap(TrapCode::Validation);
        }
        match result {
            PollResult::Pending { .. } => NativeAsyncPoll::Pending(self.metrics()),
            PollResult::HostCall(call) => self.handle_host_call(active_instance, call),
            PollResult::Ready(values) => self.handle_callback_result(values),
            PollResult::Trapped(trap) => self.finish_trap(trap),
        }
    }

    fn settle_metrics(&mut self, active_instance: usize) -> bool {
        let Some(metrics) = self.component.modules.call_metrics(active_instance) else {
            return false;
        };
        metrics.remaining_fuel <= self.remaining_work
            && metrics.remaining_fuel.checked_add(metrics.consumed_fuel)
                == Some(self.active_call_budget)
            && {
                self.remaining_work = metrics.remaining_fuel;
                true
            }
    }

    fn handle_host_call(
        &mut self,
        active_instance: usize,
        call: vibeos_wasm_runtime::CoreHostCall,
    ) -> NativeAsyncPoll {
        let Ok(bridge_index) = usize::try_from(call.id) else {
            return self.finish_trap(TrapCode::Validation);
        };
        let Some(bridge) = self.component.bridges.get(bridge_index) else {
            return self.finish_trap(TrapCode::Validation);
        };
        if call.origin_instance != bridge.origin_instance {
            return self.finish_trap(TrapCode::Validation);
        }
        match bridge.action {
            BridgeAction::TaskReturn if call.arguments.is_empty() => {
                if self
                    .component
                    .modules
                    .debit_call_fuel(active_instance, TASK_RETURN_WORK)
                    .is_err()
                {
                    return self.finish_trap(TrapCode::FuelExhausted);
                }
                if !self.settle_metrics(active_instance) {
                    return self.finish_trap(TrapCode::Validation);
                }
                if self.state.resolve_task_result(self.task).is_err()
                    || self
                        .component
                        .modules
                        .resume_host_call(active_instance, call.id, &[])
                        .is_err()
                {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                NativeAsyncPoll::Resolved(self.metrics())
            }
            BridgeAction::TaskReturn | BridgeAction::Unsupported => {
                self.finish_trap(TrapCode::CanonicalAbi)
            }
        }
    }

    fn handle_callback_result(&mut self, values: Vec<CoreValue>) -> NativeAsyncPoll {
        let [CoreValue::I32(raw)] = values.as_slice() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let Ok(result) = unpack_callback_result(*raw as u32) else {
            return self.finish_trap(TrapCode::CanonicalAbi);
        };
        if !self.charge_inactive_work(CALLBACK_RESULT_WORK) {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        match result.code {
            CallbackCode::Exit => {
                if self.state.callback_exit(self.task).is_err()
                    || self.state.drop_task(self.task).is_err()
                {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                self.stage = InvocationStage::Terminal;
                self.terminal = true;
                NativeAsyncPoll::Complete(self.metrics())
            }
            CallbackCode::Yield => {
                if matches!(self.stage, InvocationStage::Callback) {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                self.stage = InvocationStage::StartCallback;
                NativeAsyncPoll::Yielded(self.metrics())
            }
            CallbackCode::Wait => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn start_callback(&mut self) -> NativeAsyncPoll {
        if self.remaining_work == 0 {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        let inputs = [
            CoreValue::I32(EventCode::None as i32),
            CoreValue::I32(0),
            CoreValue::I32(0),
        ];
        let quantum = self.poll_quantum.min(self.remaining_work);
        let (modules, exports) = (&mut self.component.modules, &self.component.exports);
        let binding = &exports[self.export];
        let Some(reservation) = self.callback_reservation.take() else {
            return self.finish_trap(TrapCode::Validation);
        };
        if modules
            .start_call_reserved(
                reservation,
                binding.callback_instance,
                &binding.callback,
                &inputs,
                self.remaining_work,
                quantum,
            )
            .is_err()
        {
            return self.finish_trap(TrapCode::Validation);
        }
        self.active_call_budget = self.remaining_work;
        self.stage = InvocationStage::Callback;
        NativeAsyncPoll::Pending(self.metrics())
    }

    fn charge_inactive_work(&mut self, amount: u64) -> bool {
        let Some(remaining) = self.remaining_work.checked_sub(amount) else {
            return false;
        };
        self.remaining_work = remaining;
        true
    }

    fn finish_trap(&mut self, trap: TrapCode) -> NativeAsyncPoll {
        self.component.modules.discard_all_calls();
        self.component.poisoned = true;
        self.stage = InvocationStage::Terminal;
        self.terminal = true;
        NativeAsyncPoll::Trapped(trap)
    }

    #[cfg(test)]
    fn task_info(&self) -> TaskInfo {
        self.state.task_info(self.task).unwrap()
    }
}

impl Drop for NativeAsyncInvocation<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.component.modules.discard_all_calls();
            self.component.poisoned = true;
            self.stage = InvocationStage::Terminal;
            self.terminal = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        async_state::{TaskCallbackState, TaskResultState},
        decode::inspect_component_for_profile,
    };
    use vibeos_wasm_runtime::CoreHostCall;

    const SMOKE: &str = include_str!(
        "../../component-format/tests/corpus/component/native-async-smoke-0.255.0.component.wat"
    );
    const WORK: u64 = 100_000;
    const QUANTUM: u64 = 10_000;

    fn instantiate(source: &str) -> NativeAsyncComponent {
        let bytes = wat::parse_str(source).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        NativeAsyncComponent::instantiate_validation_plan(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap()
    }

    fn replace_once(source: &str, from: &str, to: &str) -> String {
        assert_eq!(source.matches(from).count(), 1);
        source.replacen(from, to, 1)
    }

    fn assert_smoke_sequence(component: &mut NativeAsyncComponent) -> NativeAsyncMetrics {
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
        let task = call.task_info();
        assert_eq!(task.result, TaskResultState::Resolved);
        assert_eq!(task.callback, TaskCallbackState::Running);
        assert!(!task.waiting);
        let run_instance = call.binding().core_instance;
        let run = call.component.modules.poll_call(run_instance);
        assert!(call.settle_metrics(run_instance));
        let before_yield = call.metrics();
        let PollResult::Ready(values) = run else {
            panic!("the resumed smoke run must return YIELD")
        };
        assert!(matches!(
            call.handle_callback_result(values),
            NativeAsyncPoll::Yielded(_)
        ));
        let after_yield = call.metrics();
        assert_eq!(
            before_yield.remaining_work - after_yield.remaining_work,
            CALLBACK_RESULT_WORK
        );
        assert_eq!(
            after_yield.consumed_work - before_yield.consumed_work,
            CALLBACK_RESULT_WORK
        );
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
        let NativeAsyncPoll::Complete(metrics) = call.poll() else {
            panic!("the exact callback must exit after task resolution")
        };
        metrics
    }

    #[test]
    fn production_constructor_cannot_execute_the_validation_only_identity() {
        let bytes = wat::parse_str(SMOKE).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        assert_eq!(
            NativeAsyncComponent::instantiate(
                &plan,
                &ProfileEngine::new(),
                OwnerAllocationReservation::new(0),
            )
            .err(),
            Some(NativeAsyncError::AsyncUnavailable)
        );
    }

    #[test]
    fn result_or_memory_bearing_task_return_is_rejected_before_guest_entry() {
        let result_only = r#"(component
          (type $run-type (func async (result u32)))
          (core func $task-return (canon task.return (result u32)))
          (core instance $builtins
            (export "task-return" (func $task-return)))
          (core module $guest
            (import "vibe:async" "task-return"
              (func $task-return (param i32)))
            (func (export "run") (result i32)
              i32.const 7
              call $task-return
              i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32)
              i32.const 0))
          (core instance $guest-instance
            (instantiate $guest
              (with "vibe:async" (instance $builtins))))
          (alias core export $guest-instance "run" (core func $run))
          (alias core export $guest-instance "callback" (core func $callback))
          (func $lifted (type $run-type)
            (canon lift (core func $run)
              async
              (callback (core func $callback))))
          (export "run" (func $lifted)))"#;
        let memory_only = r#"(component
          (core module $memory-provider
            (memory (export "memory") 1 1))
          (core instance $memory-instance (instantiate $memory-provider))
          (alias core export $memory-instance "memory" (core memory $memory))
          (type $run-type (func async))
          (core func $task-return (canon task.return (memory $memory)))
          (core instance $builtins
            (export "task-return" (func $task-return)))
          (core module $guest
            (import "env" "memory" (memory 1 1))
            (import "vibe:async" "task-return" (func $task-return))
            (func (export "run") (result i32)
              call $task-return
              i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32)
              i32.const 0))
          (core instance $guest-instance
            (instantiate $guest
              (with "env" (instance $memory-instance))
              (with "vibe:async" (instance $builtins))))
          (alias core export $guest-instance "run" (core func $run))
          (alias core export $guest-instance "callback" (core func $callback))
          (func $lifted (type $run-type)
            (canon lift (core func $run)
              async
              (callback (core func $callback))
              (memory $memory)))
          (export "run" (func $lifted)))"#;
        for source in [result_only, memory_only] {
            let bytes = wat::parse_str(source).unwrap();
            let plan = inspect_component_for_profile(
                &bytes,
                ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
            )
            .unwrap();
            assert_eq!(
                NativeAsyncComponent::instantiate_validation_plan(
                    &plan,
                    &ProfileEngine::new(),
                    OwnerAllocationReservation::profile_default(),
                )
                .err(),
                Some(NativeAsyncError::UnsupportedFeature)
            );
        }
    }

    #[test]
    fn smoke_resolves_before_callback_exit_and_clean_exit_is_reusable() {
        let mut component = instantiate(SMOKE);
        let first = assert_smoke_sequence(&mut component);
        assert!(first.consumed_work > 0);
        assert!(!component.is_poisoned());
        let second = assert_smoke_sequence(&mut component);
        assert_eq!(first.consumed_work, second.consumed_work);
        assert!(!component.is_poisoned());
    }

    #[test]
    fn canonical_transitions_debit_the_shared_ledger_exactly_once() {
        let mut component = instantiate(SMOKE);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let run_instance = call.binding().core_instance;
        let host = call.component.modules.poll_call(run_instance);
        assert!(call.settle_metrics(run_instance));
        let before_return = call.metrics();
        let PollResult::HostCall(host) = host else {
            panic!("the smoke run must stop at task.return")
        };
        assert!(matches!(
            call.handle_host_call(run_instance, host),
            NativeAsyncPoll::Resolved(_)
        ));
        let after_return = call.metrics();
        assert_eq!(
            before_return.remaining_work - after_return.remaining_work,
            TASK_RETURN_WORK
        );
        assert_eq!(
            after_return.consumed_work - before_return.consumed_work,
            TASK_RETURN_WORK
        );

        assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
        let callback_instance = call.binding().callback_instance;
        let callback = call.component.modules.poll_call(callback_instance);
        assert!(call.settle_metrics(callback_instance));
        let before_callback_result = call.metrics();
        let PollResult::Ready(values) = callback else {
            panic!("the smoke callback must finish with EXIT")
        };
        assert!(matches!(
            call.handle_callback_result(values),
            NativeAsyncPoll::Complete(_)
        ));
        let after_callback_result = call.metrics();
        assert_eq!(
            before_callback_result.remaining_work - after_callback_result.remaining_work,
            CALLBACK_RESULT_WORK
        );
        assert_eq!(
            after_callback_result.consumed_work - before_callback_result.consumed_work,
            CALLBACK_RESULT_WORK
        );
    }

    #[test]
    fn exit_before_task_return_and_duplicate_task_return_fail_stop() {
        let early = replace_once(
            SMOKE,
            "      call $task-return\n      i32.const 1",
            "      i32.const 0",
        );
        let mut component = instantiate(&early);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());
        assert_eq!(
            component.start("run", WORK, QUANTUM).err(),
            Some(NativeAsyncError::Poisoned)
        );

        let yielded_unresolved = replace_once(
            SMOKE,
            "      call $task-return\n      i32.const 1",
            "      i32.const 1",
        );
        let mut component = instantiate(&yielded_unresolved);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());

        let duplicate = replace_once(
            SMOKE,
            "      call $task-return\n      i32.const 1",
            "      call $task-return\n      call $task-return\n      i32.const 1",
        );
        let mut component = instantiate(&duplicate);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());
    }

    #[test]
    fn callback_may_resolve_an_unresolved_yielded_task_before_exit() {
        let source = replace_once(
            &replace_once(
                SMOKE,
                "      call $task-return\n      i32.const 1",
                "      i32.const 1",
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      call $task-return\n      i32.const 0)",
        );
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
        assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
        assert_eq!(call.task_info().result, TaskResultState::Resolved);
        assert!(matches!(call.poll(), NativeAsyncPoll::Complete(_)));
    }

    #[test]
    fn first_callback_receives_the_exact_none_zero_zero_event() {
        let source = replace_once(
            SMOKE,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      local.get 0\n      i32.eqz\n      local.get 1\n      i32.eqz\n      i32.and\n      local.get 2\n      i32.eqz\n      i32.and\n      if (result i32)\n        i32.const 0\n      else\n        i32.const 3\n      end)",
        );
        let mut component = instantiate(&source);
        assert_smoke_sequence(&mut component);
    }

    #[test]
    fn dynamically_mismatched_task_return_type_traps_fail_closed() {
        let source = r#"(component
          (type $run-type (func async))
          (core func $wrong-return (canon task.return (result u32)))
          (core instance $builtins
            (export "wrong-return" (func $wrong-return)))
          (core module $guest
            (import "vibe:async" "wrong-return"
              (func $wrong-return (param i32)))
            (func (export "run") (result i32)
              i32.const 7
              call $wrong-return
              i32.const 1)
            (func (export "callback") (param i32 i32 i32) (result i32)
              i32.const 0))
          (core instance $guest-instance
            (instantiate $guest
              (with "vibe:async" (instance $builtins))))
          (alias core export $guest-instance "run" (core func $run))
          (alias core export $guest-instance "callback" (core func $callback))
          (func $lifted (type $run-type)
            (canon lift (core func $run)
              async
              (callback (core func $callback))))
          (export "run" (func $lifted)))"#;
        let mut component = instantiate(source);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());
    }

    #[test]
    fn invalid_callback_and_unsupported_builtin_poison_the_component() {
        let invalid = replace_once(
            SMOKE,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 3)",
        );
        let mut component = instantiate(&invalid);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());

        let unsupported = replace_once(
            SMOKE,
            "      call $task-return\n      i32.const 1",
            "      call $stream-new\n      drop\n      call $task-return\n      i32.const 1",
        );
        let mut component = instantiate(&unsupported);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
        }
        assert!(component.is_poisoned());
    }

    #[test]
    fn host_id_uses_bridge_then_canonical_not_an_identity_mapping() {
        let source = replace_once(
            SMOKE,
            "  (core func $task-return (canon task.return))",
            "  (core func $unbridged (canon waitable-set.new))\n  (core func $task-return (canon task.return))",
        );
        let bytes = wat::parse_str(&source).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        let execution = plan.native_async_execution_plan().unwrap();
        assert_eq!(execution.canonical_import_bridges()[0].canonical, 1);
        let mut component = NativeAsyncComponent::instantiate_validation_plan(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap();
        assert_smoke_sequence(&mut component);
    }

    #[test]
    fn transitive_host_origin_is_not_the_active_continuation_instance() {
        let source = r#"(component
          (type $run-type (func async))
          (core func $task-return (canon task.return))
          (core instance $builtins
            (export "task-return" (func $task-return)))
          (core module $provider
            (import "vibe:async" "task-return" (func $task-return))
            (func (export "resolve") call $task-return))
          (core instance $provider-instance
            (instantiate $provider
              (with "vibe:async" (instance $builtins))))
          (core module $guest
            (import "provider" "resolve" (func $resolve))
            (func (export "run") (result i32)
              call $resolve
              i32.const 1)
            (func (export "callback") (param i32 i32 i32) (result i32)
              i32.const 0))
          (core instance $guest-instance
            (instantiate $guest
              (with "provider" (instance $provider-instance))))
          (alias core export $guest-instance "run" (core func $run))
          (alias core export $guest-instance "callback" (core func $callback))
          (func $lifted (type $run-type)
            (canon lift (core func $run) async
              (callback (core func $callback))))
          (export "run" (func $lifted)))"#;
        let bytes = wat::parse_str(source).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        let execution = plan.native_async_execution_plan().unwrap();
        assert_eq!(execution.canonical_import_bridges()[0].core_instance, 0);
        let NativeAsyncCanonicalFunctionPlan::Lift { core_function, .. } =
            &execution.canonical_plans()[1].function
        else {
            panic!("the second canonical must be the lift")
        };
        assert_eq!(core_function.core_instance, 1);
        let mut component = NativeAsyncComponent::instantiate_validation_plan(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
        )
        .unwrap();
        assert_smoke_sequence(&mut component);
    }

    #[test]
    fn fabricated_and_late_host_calls_clear_the_active_continuation() {
        for after_resolution in [false, true] {
            let mut component = instantiate(SMOKE);
            {
                let mut call = component.start("run", WORK, QUANTUM).unwrap();
                if after_resolution {
                    assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
                }
                let active = call.binding().core_instance;
                let (origin_instance, id) = if after_resolution {
                    (usize::MAX, 0)
                } else {
                    (0, u32::MAX)
                };
                assert_eq!(
                    call.handle_host_call(
                        active,
                        CoreHostCall {
                            origin_instance,
                            id,
                            arguments: Vec::new(),
                        },
                    ),
                    NativeAsyncPoll::Trapped(TrapCode::Validation)
                );
                assert!(!call.component.modules.any_active_call());
            }
            assert!(component.is_poisoned());
        }
    }

    #[test]
    fn dropping_a_started_or_resolved_call_discards_and_poisons() {
        for resolve_first in [false, true] {
            let mut component = instantiate(SMOKE);
            {
                let mut call = component.start("run", WORK, QUANTUM).unwrap();
                if resolve_first {
                    assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
                }
            }
            assert!(component.is_poisoned());
            assert!(!component.modules.any_active_call());
            assert_eq!(
                component.start("run", WORK, QUANTUM).err(),
                Some(NativeAsyncError::Poisoned)
            );
        }
    }

    #[test]
    fn run_and_callback_spend_one_shared_fuel_ledger() {
        let run_body = "      (local $n i32)\n      i32.const 80\n      local.set $n\n      block $done\n        loop $loop\n          local.get $n\n          i32.eqz\n          br_if $done\n          local.get $n\n          i32.const 1\n          i32.sub\n          local.set $n\n          br $loop\n        end\n      end\n      call $task-return\n      i32.const 1";
        let callback_body = "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      (local $n i32)\n      i32.const 80\n      local.set $n\n      block $done\n        loop $loop\n          local.get $n\n          i32.eqz\n          br_if $done\n          local.get $n\n          i32.const 1\n          i32.sub\n          local.set $n\n          br $loop\n        end\n      end\n      i32.const 0)";
        let source = replace_once(
            &replace_once(
                SMOKE,
                "      call $task-return\n      i32.const 1",
                run_body,
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            callback_body,
        );

        let mut component = instantiate(&source);
        let (run_consumed, total_consumed) = {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let mut run_consumed = None;
            let total_consumed = loop {
                match call.poll() {
                    NativeAsyncPoll::Yielded(metrics) => run_consumed = Some(metrics.consumed_work),
                    NativeAsyncPoll::Complete(metrics) => break metrics.consumed_work,
                    NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Resolved(_) => {}
                    NativeAsyncPoll::Trapped(trap) => panic!("high-budget call trapped: {trap:?}"),
                }
            };
            (run_consumed.unwrap(), total_consumed)
        };
        let callback_consumed = total_consumed.checked_sub(run_consumed).unwrap();
        assert!(run_consumed > 0);
        assert!(callback_consumed > 0);

        let tight = run_consumed.max(callback_consumed);
        assert!(tight < total_consumed);
        let mut component = instantiate(&source);
        let mut call = component.start("run", tight, tight.min(QUANTUM)).unwrap();
        let trap = loop {
            match call.poll() {
                NativeAsyncPoll::Trapped(trap) => break trap,
                NativeAsyncPoll::Complete(_) => {
                    panic!("separate per-Core fuel ledgers would incorrectly complete")
                }
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
            }
        };
        assert_eq!(trap, TrapCode::FuelExhausted);
        assert!(call.metrics().consumed_work <= tight);
    }
}
