//! Atomic construction and bounded synchronous execution of one validated
//! Component Model principal.

use crate::{
    abi_value::{
        lift_results, lower_parameters, CodecError, CodecUsage, LoweredParameters,
        PayloadAllocator, ResourceBinder,
    },
    decode::ComponentPlan,
    execution::ExecutableExportPlan,
    memory::{AbiError, GuestMemory},
    resource::{GuestCallResources, ResourceTable, ResourceToken, ResourceTypeId},
    types::FunctionType,
    value::{
        validate_value_with_resources, CanonicalValue, ResourceOwnership, ValuePosition, ValueType,
    },
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreInstance, CoreValue, OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SyncError {
    Allocation = 1,
    CoreAdmission = 2,
    CoreInstantiation = 3,
    MissingModule = 4,
    InvalidBudget = 5,
    MissingExport = 6,
    InvalidWiring = 7,
    Memory = 8,
    Codec = 9,
    Busy = 10,
    Trapped = 11,
    Value = 12,
    Resource = 13,
    Poisoned = 14,
}

impl SyncError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// One principal's validated Core instances and immutable Component wiring.
pub struct SynchronousComponent {
    modules: Vec<CoreInstance>,
    exports: Vec<RuntimeExport>,
    poisoned: bool,
}

struct RuntimeExport {
    name: String,
    function_type: FunctionType,
    core_instance: usize,
    function: String,
    memory: Option<String>,
    realloc: Option<String>,
    post_return: Option<String>,
}

impl SynchronousComponent {
    pub fn instantiate(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
    ) -> Result<Self, SyncError> {
        let execution = &plan.execution;
        let mut modules = Vec::new();
        modules
            .try_reserve_exact(execution.instances().len())
            .map_err(|_| SyncError::Allocation)?;
        for instance in execution.instances() {
            let bytes = plan
                .embedded_modules()
                .get(instance.module())
                .ok_or(SyncError::MissingModule)?;
            let validated = ValidatedCore::new_in(engine, bytes, reservation_per_module)
                .map_err(|_| SyncError::CoreAdmission)?;
            modules.push(
                validated
                    .instantiate()
                    .map_err(|_| SyncError::CoreInstantiation)?,
            );
        }
        let mut exports = Vec::new();
        exports
            .try_reserve_exact(execution.exports().len())
            .map_err(|_| SyncError::Allocation)?;
        for export in execution.exports() {
            exports.push(runtime_export(export)?);
        }
        Ok(Self {
            modules,
            exports,
            poisoned: false,
        })
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Whether execution crossed into guest state and then failed before full
    /// canonical cleanup. A poisoned instance is diagnostic-only and must be
    /// cold-instantiated before it can execute again.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn function_type(&self, name: &str) -> Option<&FunctionType> {
        self.exports
            .iter()
            .find(|export| export.name == name)
            .map(|export| &export.function_type)
    }

    /// Starts a validator-wired, typed Component export call.
    ///
    /// The returned call exclusively borrows both the component and its exact
    /// resource table until it reaches post-return or is dropped. That is the
    /// synchronous borrow scope: resource handles cannot be removed while the
    /// guest continuation is pending.
    pub fn start_typed_call<'a, A>(
        &'a mut self,
        resources: &'a mut ResourceTable<A>,
        export: &str,
        mut arguments: Vec<CanonicalValue>,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<TypedCall<'a, A>, SyncError> {
        if self.poisoned {
            return Err(SyncError::Poisoned);
        }
        if self.modules.iter().any(CoreInstance::has_active_call) {
            return Err(SyncError::Busy);
        }
        if total_work == 0
            || total_work > PROFILE_1_LIMITS.total_fuel
            || poll_quantum == 0
            || poll_quantum > PROFILE_1_LIMITS.poll_quantum
            || poll_quantum > total_work
        {
            return Err(SyncError::InvalidBudget);
        }
        let export = self
            .exports
            .iter()
            .position(|binding| binding.name == export)
            .ok_or(SyncError::MissingExport)?;
        let binding = &self.exports[export];
        if binding.memory.is_none() || binding.realloc.is_none() {
            return Err(SyncError::InvalidWiring);
        }
        if binding.function_type.parameters.len() != arguments.len() {
            return Err(SyncError::Value);
        }
        for (parameter, argument) in binding.function_type.parameters.iter().zip(&arguments) {
            validate_value_with_resources(
                &parameter.value,
                argument,
                resources,
                ValuePosition::Parameter,
            )
            .map_err(|_| SyncError::Resource)?;
        }

        let parameter_types = clone_parameter_types(&binding.function_type)?;
        let mut guest_resources = resources
            .begin_guest_call()
            .map_err(|_| SyncError::Resource)?;
        if lower_argument_resources(
            &parameter_types,
            &mut arguments,
            resources,
            &mut guest_resources,
        )
        .is_err()
        {
            let _ = resources.close_guest_call(guest_resources);
            return Err(SyncError::Resource);
        }
        let mut planning_memory = PlanningMemory;
        let mut planner = AllocationPlanner::default();
        let planned = match lower_parameters(
            &mut planning_memory,
            &mut planner,
            &parameter_types,
            &arguments,
        ) {
            Ok(planned) => planned,
            Err(_) => {
                let _ = resources.close_guest_call(guest_resources);
                return Err(SyncError::Codec);
            }
        };
        let (planned_arguments, usage) = match lowered_parts(planned) {
            Ok(parts) => parts,
            Err(error) => {
                let _ = resources.close_guest_call(guest_resources);
                return Err(error);
            }
        };
        if usage.work > total_work {
            let _ = resources.close_guest_call(guest_resources);
            return Ok(TypedCall::terminal(
                self,
                resources,
                export,
                total_work,
                poll_quantum,
                TrapCode::FuelExhausted,
            ));
        }
        let remaining_work = total_work - usage.work;
        if remaining_work == 0 && (!planner.requests.is_empty() || !planned_arguments.is_empty()) {
            let _ = resources.close_guest_call(guest_resources);
            return Ok(TypedCall::terminal(
                self,
                resources,
                export,
                total_work,
                poll_quantum,
                TrapCode::FuelExhausted,
            ));
        }
        Ok(TypedCall {
            component: self,
            resources,
            export,
            arguments,
            allocations: planner.requests,
            allocation_index: 0,
            pointers: Vec::new(),
            replay_arguments: None,
            core_results: None,
            result: None,
            stage: TypedStage::Allocate,
            total_work,
            remaining_work,
            poll_quantum,
            active_baseline: 0,
            cancelled: false,
            guest_started: false,
            guest_resources: Some(guest_resources),
        })
    }

    /// Copy-only access to the exact Core memory named by an export's
    /// canonical options. Primarily useful for diagnostics and tests.
    pub fn read_export_memory(
        &self,
        export: &str,
        offset: u32,
        destination: &mut [u8],
    ) -> Result<(), SyncError> {
        let binding = self
            .exports
            .iter()
            .find(|binding| binding.name == export)
            .ok_or(SyncError::MissingExport)?;
        let memory = binding.memory.as_deref().ok_or(SyncError::InvalidWiring)?;
        self.modules
            .get(binding.core_instance)
            .ok_or(SyncError::InvalidWiring)?
            .read_memory(memory, offset as usize, destination)
            .map_err(|_| SyncError::Memory)
    }
}

fn runtime_export(export: &ExecutableExportPlan) -> Result<RuntimeExport, SyncError> {
    Ok(RuntimeExport {
        name: copied(&export.info.name)?,
        function_type: crate::types::try_clone_function_type(&export.info.function)
            .map_err(|_| SyncError::Allocation)?,
        core_instance: export.core_instance,
        function: copied(&export.function)?,
        memory: export.memory.as_deref().map(copied).transpose()?,
        realloc: export.realloc.as_deref().map(copied).transpose()?,
        post_return: export.post_return.as_deref().map(copied).transpose()?,
    })
}

fn copied(value: &str) -> Result<String, SyncError> {
    let mut result = String::new();
    result
        .try_reserve_exact(value.len())
        .map_err(|_| SyncError::Allocation)?;
    result.push_str(value);
    Ok(result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedCallMetrics {
    pub consumed_work: u64,
    pub remaining_work: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TypedPoll {
    Pending(TypedCallMetrics),
    Ready(CanonicalValue),
    Trapped(TrapCode),
}

enum TypedStage {
    Allocate,
    Replay,
    Transform,
    Lift,
    PostReturn,
    Cleanup,
    Terminal(TrapCode),
    Complete,
}

/// One non-async Component call. Every `poll` drives at most one Core call
/// poll, so a Core `Pending` is never hidden behind an internal loop.
pub struct TypedCall<'a, A> {
    component: &'a mut SynchronousComponent,
    resources: &'a mut ResourceTable<A>,
    export: usize,
    arguments: Vec<CanonicalValue>,
    allocations: Vec<AllocationRequest>,
    allocation_index: usize,
    pointers: Vec<u32>,
    replay_arguments: Option<Vec<CoreValue>>,
    core_results: Option<Vec<CoreValue>>,
    result: Option<CanonicalValue>,
    stage: TypedStage,
    total_work: u64,
    remaining_work: u64,
    poll_quantum: u64,
    active_baseline: u64,
    cancelled: bool,
    guest_started: bool,
    guest_resources: Option<GuestCallResources>,
}

impl<'a, A> TypedCall<'a, A> {
    fn terminal(
        component: &'a mut SynchronousComponent,
        resources: &'a mut ResourceTable<A>,
        export: usize,
        total_work: u64,
        poll_quantum: u64,
        trap: TrapCode,
    ) -> Self {
        Self {
            component,
            resources,
            export,
            arguments: Vec::new(),
            allocations: Vec::new(),
            allocation_index: 0,
            pointers: Vec::new(),
            replay_arguments: None,
            core_results: None,
            result: None,
            stage: TypedStage::Terminal(trap),
            total_work,
            remaining_work: 0,
            poll_quantum,
            active_baseline: 0,
            cancelled: false,
            guest_started: false,
            guest_resources: None,
        }
    }

    pub const fn metrics(&self) -> TypedCallMetrics {
        TypedCallMetrics {
            consumed_work: self.total_work - self.remaining_work,
            remaining_work: self.remaining_work,
        }
    }

    pub fn cancel(&mut self) {
        if matches!(self.stage, TypedStage::Terminal(_) | TypedStage::Complete) {
            return;
        }
        self.cancelled = true;
        self.component.poisoned = true;
        if let Some(instance) = self.active_instance_mut() {
            let _ = instance.cancel_call();
        }
    }

    pub fn poll(&mut self) -> TypedPoll {
        if self.cancelled && self.active_instance_mut().is_none() {
            self.stage = TypedStage::Terminal(TrapCode::Cancelled);
        }
        match self.stage {
            TypedStage::Terminal(trap) => {
                if self.close_resources(false).is_err() {
                    self.component.poisoned = true;
                }
                self.stage = TypedStage::Complete;
                TypedPoll::Trapped(trap)
            }
            TypedStage::Complete => TypedPoll::Trapped(TrapCode::Cancelled),
            TypedStage::Allocate => self.poll_allocate(),
            TypedStage::Replay => self.replay(),
            TypedStage::Transform => self.poll_transform(),
            TypedStage::Lift => self.lift(),
            TypedStage::PostReturn => self.poll_post_return(),
            TypedStage::Cleanup => self.poll_cleanup(),
        }
    }

    fn poll_allocate(&mut self) -> TypedPoll {
        if self.active_instance_mut().is_none() {
            if self.allocation_index >= self.allocations.len() {
                self.stage = TypedStage::Replay;
                return TypedPoll::Pending(self.metrics());
            }
            let request = self.allocations[self.allocation_index];
            let inputs = [
                CoreValue::I32(0),
                CoreValue::I32(0),
                CoreValue::I32(request.alignment as i32),
                CoreValue::I32(request.size as i32),
            ];
            if let Err(trap) = self.start_subcall(Subcall::Realloc, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall() {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) => match values.as_slice() {
                [CoreValue::I32(pointer)] if *pointer != 0 => {
                    let request = self.allocations[self.allocation_index];
                    let pointer = *pointer as u32;
                    if pointer & (request.alignment - 1) != 0
                        || !self.valid_allocation(pointer, request.size)
                    {
                        return self.finish_trap(TrapCode::CanonicalAbi);
                    }
                    if self.pointers.try_reserve(1).is_err() {
                        return self.finish_trap(TrapCode::LimitExceeded);
                    }
                    self.pointers.push(pointer);
                    self.allocation_index += 1;
                    TypedPoll::Pending(self.metrics())
                }
                _ => self.finish_trap(TrapCode::CanonicalAbi),
            },
        }
    }

    fn replay(&mut self) -> TypedPoll {
        let binding = &self.component.exports[self.export];
        let instance_index = binding.core_instance;
        let Some(memory_name) = binding.memory.as_deref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let parameter_types =
            match clone_parameter_types(&self.component.exports[self.export].function_type) {
                Ok(types) => types,
                Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
            };
        let Some(instance) = self.component.modules.get_mut(instance_index) else {
            return self.finish_trap(TrapCode::Validation);
        };
        let mut memory = match CoreGuestMemory::new(instance, memory_name) {
            Ok(memory) => memory,
            Err(_) => return self.finish_trap(TrapCode::MemoryOutOfBounds),
        };
        let mut replay = ReplayAllocator {
            pointers: &self.pointers,
            requests: &self.allocations,
            cursor: 0,
        };
        let lowered =
            match lower_parameters(&mut memory, &mut replay, &parameter_types, &self.arguments) {
                Ok(lowered) if replay.cursor == replay.requests.len() => lowered,
                _ => return self.finish_trap(TrapCode::CanonicalAbi),
            };
        self.replay_arguments = match lowered_parts(lowered) {
            Ok((arguments, _)) => Some(arguments),
            Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
        };
        self.stage = TypedStage::Transform;
        TypedPoll::Pending(self.metrics())
    }

    fn poll_transform(&mut self) -> TypedPoll {
        if self.active_instance_mut().is_none() {
            let Some(arguments) = self.replay_arguments.take() else {
                return self.finish_trap(TrapCode::Validation);
            };
            if let Err(trap) = self.start_subcall(Subcall::Transform, &arguments) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall() {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(results) => {
                self.core_results = Some(results);
                self.stage = TypedStage::Lift;
                TypedPoll::Pending(self.metrics())
            }
        }
    }

    fn lift(&mut self) -> TypedPoll {
        let function_type = match crate::types::try_clone_function_type(
            &self.component.exports[self.export].function_type,
        ) {
            Ok(function) => function,
            Err(_) => return self.finish_trap(TrapCode::LimitExceeded),
        };
        let Some(result_type) = function_type.result.as_ref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let results = match self.core_results.as_deref() {
            Some(results) => results,
            None => return self.finish_trap(TrapCode::Validation),
        };
        let binding = &self.component.exports[self.export];
        let instance_index = binding.core_instance;
        let Some(memory_name) = binding.memory.as_deref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let Some(instance) = self.component.modules.get_mut(instance_index) else {
            return self.finish_trap(TrapCode::Validation);
        };
        let memory = match CoreGuestMemory::new(instance, memory_name) {
            Ok(memory) => memory,
            Err(_) => return self.finish_trap(TrapCode::MemoryOutOfBounds),
        };
        let binder = TableBinder {
            table: &*self.resources,
        };
        let (mut values, usage) = match lift_results(
            &memory,
            &binder,
            core::slice::from_ref(result_type),
            results,
        ) {
            Ok(value) => value,
            Err(_) => return self.finish_trap(TrapCode::CanonicalAbi),
        };
        if self.charge(usage.work).is_err() {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        let Some(result) = values.pop() else {
            return self.finish_trap(TrapCode::CanonicalAbi);
        };
        let result = match lift_result_resources(
            result_type,
            result,
            self.resources,
            self.guest_resources
                .as_mut()
                .expect("a running typed call owns one resource scope"),
        ) {
            Ok(result) => result,
            Err(_) => return self.finish_trap(TrapCode::CanonicalAbi),
        };
        self.result = Some(result);
        if self.component.exports[self.export].post_return.is_some() {
            self.stage = TypedStage::PostReturn;
        } else {
            self.stage = TypedStage::Cleanup;
        }
        TypedPoll::Pending(self.metrics())
    }

    fn poll_post_return(&mut self) -> TypedPoll {
        if self.active_instance_mut().is_none() {
            let Some(results) = self.core_results.as_ref() else {
                return self.finish_trap(TrapCode::Validation);
            };
            let mut inputs = Vec::new();
            if inputs.try_reserve_exact(results.len()).is_err() {
                return self.finish_trap(TrapCode::LimitExceeded);
            }
            inputs.extend_from_slice(results);
            if let Err(trap) = self.start_subcall(Subcall::PostReturn, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall() {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) if values.is_empty() => {
                self.stage = TypedStage::Cleanup;
                TypedPoll::Pending(self.metrics())
            }
            PollResult::Ready(_) => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn poll_cleanup(&mut self) -> TypedPoll {
        if self.active_instance_mut().is_none() {
            if self.allocation_index == 0 {
                if self.close_resources(true).is_err() {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                self.stage = TypedStage::Complete;
                return TypedPoll::Ready(self.result.take().expect("lift produced one result"));
            }
            let request = self.allocations[self.allocation_index - 1];
            let pointer = self.pointers[self.allocation_index - 1];
            let inputs = [
                CoreValue::I32(pointer as i32),
                CoreValue::I32(request.size as i32),
                CoreValue::I32(request.alignment as i32),
                CoreValue::I32(0),
            ];
            if let Err(trap) = self.start_subcall(Subcall::Free, &inputs) {
                return self.finish_trap(trap);
            }
        }
        match self.poll_subcall() {
            PollResult::Pending { .. } => TypedPoll::Pending(self.metrics()),
            PollResult::Trapped(trap) => self.finish_trap(trap),
            PollResult::Ready(values) if values == [CoreValue::I32(0)] => {
                self.allocation_index -= 1;
                TypedPoll::Pending(self.metrics())
            }
            PollResult::Ready(_) => self.finish_trap(TrapCode::CanonicalAbi),
        }
    }

    fn start_subcall(&mut self, kind: Subcall, inputs: &[CoreValue]) -> Result<(), TrapCode> {
        if self.remaining_work == 0 {
            return Err(TrapCode::FuelExhausted);
        }
        let binding = &self.component.exports[self.export];
        let name = match kind {
            Subcall::Realloc => binding.realloc.as_deref(),
            Subcall::Transform => Some(binding.function.as_str()),
            Subcall::PostReturn => binding.post_return.as_deref(),
            Subcall::Free => binding.realloc.as_deref(),
        }
        .ok_or(TrapCode::Validation)?;
        let instance = self
            .component
            .modules
            .get_mut(binding.core_instance)
            .ok_or(TrapCode::Validation)?;
        instance.start_call(
            name,
            inputs,
            self.remaining_work,
            self.poll_quantum.min(self.remaining_work),
        )?;
        // Each Core call starts a fresh continuation whose consumed-fuel
        // counter begins at zero. Metrics retained from an earlier completed
        // call must not become the baseline for this one.
        self.active_baseline = 0;
        self.guest_started = true;
        Ok(())
    }

    fn poll_subcall(&mut self) -> PollResult {
        let Some(instance) = self.active_instance_mut() else {
            return PollResult::Trapped(TrapCode::Validation);
        };
        let result = instance.poll_call();
        let consumed = instance
            .call_metrics()
            .map_or(0, |metrics| metrics.consumed_fuel)
            .saturating_sub(self.active_baseline);
        self.active_baseline = self.active_baseline.saturating_add(consumed);
        self.remaining_work = self.remaining_work.saturating_sub(consumed);
        result
    }

    fn active_instance_mut(&mut self) -> Option<&mut CoreInstance> {
        let index = self.component.exports.get(self.export)?.core_instance;
        let instance = self.component.modules.get_mut(index)?;
        instance.has_active_call().then_some(instance)
    }

    fn memory_binding(&self) -> Result<(usize, &str), TrapCode> {
        let binding = self
            .component
            .exports
            .get(self.export)
            .ok_or(TrapCode::Validation)?;
        Ok((
            binding.core_instance,
            binding.memory.as_deref().ok_or(TrapCode::Validation)?,
        ))
    }

    fn valid_span(&self, pointer: u32, size: u32) -> bool {
        let Ok((instance, memory)) = self.memory_binding() else {
            return false;
        };
        let Some(instance) = self.component.modules.get(instance) else {
            return false;
        };
        let Ok(length) = instance.memory_size(memory) else {
            return false;
        };
        u64::from(pointer)
            .checked_add(u64::from(size))
            .is_some_and(|end| end <= length as u64)
    }

    fn valid_allocation(&self, pointer: u32, size: u32) -> bool {
        if !self.valid_span(pointer, size) {
            return false;
        }
        let start = u64::from(pointer);
        let end = start + u64::from(size);
        for (index, previous) in self.pointers.iter().copied().enumerate() {
            let Some(request) = self.allocations.get(index) else {
                return false;
            };
            let previous_start = u64::from(previous);
            let previous_end = previous_start + u64::from(request.size);
            if start < previous_end && previous_start < end {
                return false;
            }
        }
        true
    }

    fn charge(&mut self, work: u64) -> Result<(), ()> {
        self.remaining_work = self.remaining_work.checked_sub(work).ok_or(())?;
        Ok(())
    }

    fn finish_trap(&mut self, trap: TrapCode) -> TypedPoll {
        self.component.poisoned = true;
        if let Some(instance) = self.active_instance_mut() {
            let _ = instance.discard_call();
        }
        let _ = self.close_resources(false);
        self.stage = TypedStage::Complete;
        TypedPoll::Trapped(trap)
    }

    fn close_resources(&mut self, commit: bool) -> Result<(), ()> {
        let Some(mut scope) = self.guest_resources.take() else {
            return Ok(());
        };
        if commit && self.resources.commit_guest_call(&mut scope).is_err() {
            let _ = self.resources.close_guest_call(scope);
            return Err(());
        }
        self.resources.close_guest_call(scope).map_err(|_| ())
    }
}

impl<A> Drop for TypedCall<'_, A> {
    fn drop(&mut self) {
        if self.guest_started && !matches!(self.stage, TypedStage::Complete) {
            self.component.poisoned = true;
        }
        if let Some(instance) = self.active_instance_mut() {
            let _ = instance.discard_call();
        }
        let _ = self.close_resources(false);
    }
}

#[derive(Clone, Copy)]
enum Subcall {
    Realloc,
    Transform,
    PostReturn,
    Free,
}

#[derive(Clone, Copy)]
struct AllocationRequest {
    size: u32,
    alignment: u32,
}

#[derive(Default)]
struct AllocationPlanner {
    requests: Vec<AllocationRequest>,
    next: u32,
}

impl PayloadAllocator<PlanningMemory> for AllocationPlanner {
    fn allocate(
        &mut self,
        _memory: &mut PlanningMemory,
        size: u32,
        alignment: u32,
    ) -> Result<u32, CodecError> {
        if alignment == 0 || !alignment.is_power_of_two() {
            return Err(CodecError::Misaligned);
        }
        if self.requests.len() >= PROFILE_1_LIMITS.max_abi_allocations as usize {
            return Err(CodecError::AllocationLimit);
        }
        let mask = alignment - 1;
        let pointer = self
            .next
            .max(1)
            .checked_add(mask)
            .ok_or(CodecError::Overflow)?
            & !mask;
        self.next = pointer.checked_add(size).ok_or(CodecError::Overflow)?;
        self.requests
            .try_reserve(1)
            .map_err(|_| CodecError::Allocation)?;
        self.requests.push(AllocationRequest { size, alignment });
        Ok(pointer)
    }
}

struct PlanningMemory;

impl GuestMemory for PlanningMemory {
    fn len(&self) -> u64 {
        u64::from(u32::MAX) + 1
    }

    fn read_exact(&self, _pointer: u32, destination: &mut [u8]) -> Result<(), AbiError> {
        destination.fill(0);
        Ok(())
    }

    fn write_exact(&mut self, _pointer: u32, _source: &[u8]) -> Result<(), AbiError> {
        Ok(())
    }
}

struct ReplayAllocator<'a> {
    pointers: &'a [u32],
    requests: &'a [AllocationRequest],
    cursor: usize,
}

impl<M: GuestMemory> PayloadAllocator<M> for ReplayAllocator<'_> {
    fn allocate(&mut self, _memory: &mut M, size: u32, alignment: u32) -> Result<u32, CodecError> {
        let request = self
            .requests
            .get(self.cursor)
            .ok_or(CodecError::AllocationLimit)?;
        if request.size != size || request.alignment != alignment {
            return Err(CodecError::TypeMismatch);
        }
        let pointer = *self
            .pointers
            .get(self.cursor)
            .ok_or(CodecError::AllocationLimit)?;
        self.cursor += 1;
        Ok(pointer)
    }
}

/// Copy-only view of one exact Core memory named by canonical options.
struct CoreGuestMemory<'a> {
    instance: &'a mut CoreInstance,
    export: &'a str,
    length: usize,
}

impl<'a> CoreGuestMemory<'a> {
    fn new(instance: &'a mut CoreInstance, export: &'a str) -> Result<Self, SyncError> {
        let length = instance
            .memory_size(export)
            .map_err(|_| SyncError::Memory)?;
        Ok(Self {
            instance,
            export,
            length,
        })
    }
}

impl GuestMemory for CoreGuestMemory<'_> {
    fn len(&self) -> u64 {
        self.length as u64
    }

    fn read_exact(&self, pointer: u32, destination: &mut [u8]) -> Result<(), AbiError> {
        self.instance
            .read_memory(self.export, pointer as usize, destination)
            .map_err(|_| AbiError::OutOfBounds)
    }

    fn write_exact(&mut self, pointer: u32, source: &[u8]) -> Result<(), AbiError> {
        self.instance
            .write_memory(self.export, pointer as usize, source)
            .map_err(|_| AbiError::OutOfBounds)
    }
}

struct TableBinder<'a, A> {
    table: &'a ResourceTable<A>,
}

impl<A> ResourceBinder for TableBinder<'_, A> {
    fn bind(
        &self,
        guest_index: u32,
        expected: ResourceTypeId,
        ownership: ResourceOwnership,
        position: ValuePosition,
    ) -> Result<ResourceToken, CodecError> {
        if ownership == ResourceOwnership::Borrow && position == ValuePosition::Result {
            return Err(CodecError::BorrowEscape);
        }
        let token = self.table.token_from_guest_index(guest_index);
        match (ownership, position) {
            (ResourceOwnership::Own, ValuePosition::Result) => self
                .table
                .contains_guest_owned_index(guest_index, expected)
                .map_err(|_| CodecError::ResourceBinding)?,
            _ => self
                .table
                .contains(token, expected)
                .map_err(|_| CodecError::ResourceBinding)?,
        };
        Ok(token)
    }
}

fn clone_parameter_types(function: &FunctionType) -> Result<Vec<ValueType>, SyncError> {
    let cloned =
        crate::types::try_clone_function_type(function).map_err(|_| SyncError::Allocation)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(cloned.parameters.len())
        .map_err(|_| SyncError::Allocation)?;
    for parameter in cloned.parameters {
        result.push(parameter.value);
    }
    Ok(result)
}

fn lowered_parts(lowered: LoweredParameters) -> Result<(Vec<CoreValue>, CodecUsage), SyncError> {
    match lowered {
        LoweredParameters::Flat { values, usage } => Ok((values, usage)),
        LoweredParameters::Indirect {
            arguments, usage, ..
        } => {
            let mut values = Vec::new();
            values
                .try_reserve_exact(arguments.len())
                .map_err(|_| SyncError::Allocation)?;
            values.extend_from_slice(&arguments);
            Ok((values, usage))
        }
    }
}

fn lower_argument_resources<A>(
    types: &[ValueType],
    values: &mut [CanonicalValue],
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    if types.len() != values.len() {
        return Err(());
    }
    for (ty, value) in types.iter().zip(values) {
        rewrite_lowered_resources(ty, value, table, scope)?;
    }
    Ok(())
}

fn rewrite_lowered_resources<A>(
    ty: &ValueType,
    value: &mut CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership,
            },
            CanonicalValue::Resource(token),
        ) => {
            *token = match ownership {
                ResourceOwnership::Borrow => {
                    table.lower_borrow_for_guest(scope, *token, *resource_type)
                }
                ResourceOwnership::Own => {
                    table.lower_owned_for_guest(scope, *token, *resource_type)
                }
            }
            .map_err(|_| ())?;
            Ok(())
        }
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                rewrite_lowered_resources(item, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            lower_argument_resources(types, values, table, scope)
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            rewrite_lowered_resources(inner, value, table, scope)
        }
        (ValueType::Option(_), CanonicalValue::Option(None)) => Ok(()),
        (ValueType::Result { ok, .. }, CanonicalValue::Result(Ok(value))) => {
            rewrite_optional_lowered(ok.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Result { error, .. }, CanonicalValue::Result(Err(value))) => {
            rewrite_optional_lowered(error.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let ty = cases.get(*case as usize).ok_or(())?.as_ref();
            rewrite_optional_lowered(ty, payload.as_deref_mut(), table, scope)
        }
        _ => Ok(()),
    }
}

fn rewrite_optional_lowered<A>(
    ty: Option<&ValueType>,
    value: Option<&mut CanonicalValue>,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => rewrite_lowered_resources(ty, value, table, scope),
        _ => Err(()),
    }
}

fn lift_result_resources<A>(
    ty: &ValueType,
    mut value: CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<CanonicalValue, ()> {
    rewrite_lifted_resources(ty, &mut value, table, scope)?;
    Ok(value)
}

fn rewrite_lifted_resources<A>(
    ty: &ValueType,
    value: &mut CanonicalValue,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (
            ValueType::Resource {
                resource_type,
                ownership: ResourceOwnership::Own,
            },
            CanonicalValue::Resource(token),
        ) => {
            *token = table
                .lift_owned_from_guest(scope, token.guest_index(), *resource_type)
                .map_err(|_| ())?;
            Ok(())
        }
        (
            ValueType::Resource {
                ownership: ResourceOwnership::Borrow,
                ..
            },
            CanonicalValue::Resource(_),
        ) => Err(()),
        (ValueType::List(item), CanonicalValue::List(values)) => {
            for value in values {
                rewrite_lifted_resources(item, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Tuple(types), CanonicalValue::Tuple(values))
        | (ValueType::Record(types), CanonicalValue::Record(values)) => {
            if types.len() != values.len() {
                return Err(());
            }
            for (ty, value) in types.iter().zip(values) {
                rewrite_lifted_resources(ty, value, table, scope)?;
            }
            Ok(())
        }
        (ValueType::Option(inner), CanonicalValue::Option(Some(value))) => {
            rewrite_lifted_resources(inner, value, table, scope)
        }
        (ValueType::Option(_), CanonicalValue::Option(None)) => Ok(()),
        (ValueType::Result { ok, .. }, CanonicalValue::Result(Ok(value))) => {
            rewrite_optional_lifted(ok.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Result { error, .. }, CanonicalValue::Result(Err(value))) => {
            rewrite_optional_lifted(error.as_deref(), value.as_deref_mut(), table, scope)
        }
        (ValueType::Variant(cases), CanonicalValue::Variant { case, payload }) => {
            let ty = cases.get(*case as usize).ok_or(())?.as_ref();
            rewrite_optional_lifted(ty, payload.as_deref_mut(), table, scope)
        }
        _ => Ok(()),
    }
}

fn rewrite_optional_lifted<A>(
    ty: Option<&ValueType>,
    value: Option<&mut CanonicalValue>,
    table: &mut ResourceTable<A>,
    scope: &mut GuestCallResources,
) -> Result<(), ()> {
    match (ty, value) {
        (None, None) => Ok(()),
        (Some(ty), Some(value)) => rewrite_lifted_resources(ty, value, table, scope),
        _ => Err(()),
    }
}
