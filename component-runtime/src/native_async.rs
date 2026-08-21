//! Pre-activation executor for the resource-free native async profile.
//!
//! The public profile remains validation-only.  This module is private and
//! its ordinary constructor independently requires the sealed runtime-ready
//! bit, which is deliberately false until the remaining canonical builtins
//! and admission boundary are complete.

#![allow(dead_code)]

use crate::{
    async_abi::{
        pack_endpoint_pair, unpack_callback_result, CallbackCode, EndpointPair as AbiEndpointPair,
        EventCode,
    },
    async_state::{
        AsyncState, AsyncStateError, AsyncStateLimits, CommitError, CopyBegin, EndpointKind, Event,
        EventLease, EventLeaseState, EventToken, HostReadableBindingsPair, ReadableTransferRequest,
        ReclaimError, TaskCancelState, TaskHandle, TaskResultState, TransferredReadableEndpoint,
        WaitBegin, WaitResume, WaitTicket,
    },
    buffer_registry::{BufferPlanId, BufferRegistry, BufferRole},
    decode::ComponentPlan,
    execution::{
        AsyncCoreValueType, NativeAsyncCanonicalFunctionPlan, NativeAsyncCoreImportPlan,
        NativeAsyncExecutionPlan, NativeAsyncFuturePlan, NativeAsyncStreamPlan,
        NativeAsyncWaitablePlan,
    },
    value::{
        AsyncValueTypeId, EndpointDirection, ReadableFutureEndpointToken,
        ReadableStreamEndpointToken, ValueType,
    },
    world::FunctionEffect,
};
use alloc::{string::String, vec::Vec};
use vibeos_component_format::{ProfileIdentity, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreCallSlot, CoreCallSlotState, CoreComponentGroup, CoreHostImport, CoreInstanceExportImport,
    CoreMemoryAuthority, CoreModuleImport, CoreSlotPollResult, CoreValue, CoreValueType,
    OwnerAllocationReservation, PollResult, ProfileEngine, ValidatedCore,
};

/// Versioned Vibe fuel charged for resolving one empty native async result.
const TASK_RETURN_WORK: u64 = 1;
/// Versioned Vibe fuel charged for one handle-arena transition.
///
/// Pair creation can scan each bounded pair/handle table while preparing and
/// inserting, and a reserve can move their existing entries (at most seven
/// `max_resources`-sized passes in total). Join and joined-endpoint drop scan
/// and move at most four such member ranges. Eight full passes plus one fixed
/// dispatch/commit unit is therefore a conservative upper bound for every
/// handle action enabled by this executor slice.
const HANDLE_STATE_SCAN_FACTOR: u64 = 8;
const HANDLE_STATE_WORK: u64 = 1 + HANDLE_STATE_SCAN_FACTOR * PROFILE_1_LIMITS.max_resources as u64;
/// Versioned work for finding and sealing one component-owned buffer slot.
const BUFFER_STATE_WORK: u64 = 1 + PROFILE_1_LIMITS.max_resources as u64;
/// A stream begin/cancel validates both the canonical handle and buffer arena.
const BUFFER_BRIDGE_WORK: u64 = HANDLE_STATE_WORK + BUFFER_STATE_WORK;
/// Fixed work for committing one local byte-stream transfer.
const BUFFER_COPY_BASE_WORK: u64 = 1;
/// Versioned Vibe fuel charged for one actual callback wait selection.
///
/// Beginning or explicitly resuming a wait may scan the same bounded handle
/// arena as another handle transition. Merely observing an already-blocked
/// invocation does no state work and therefore spends no fuel.
const WAIT_STATE_WORK: u64 = HANDLE_STATE_WORK;
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
    WaitPending {
        token: NativeAsyncWaitToken,
        metrics: NativeAsyncMetrics,
    },
    Complete(NativeAsyncMetrics),
    Trapped(TrapCode),
}

/// Exact owner authority for one blocked callback wait.
///
/// The task seal binds the token to one Component instance and invocation;
/// the monotonically increasing generation prevents reuse across successive
/// waits by the same task. Fields remain private so callers cannot forge it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeAsyncWaitToken {
    task: TaskHandle,
    generation: u64,
}

impl core::fmt::Debug for NativeAsyncWaitToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeAsyncWaitToken(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAsyncCancelOutcome {
    Requested,
    TooLate,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAsyncControlError {
    Invariant,
    InvalidWaitToken,
    NotWaiting,
}

pub(crate) struct NativeAsyncComponent {
    modules: CoreComponentGroup,
    exports: Vec<RuntimeExport>,
    /// One allocation-backed callback call shell per exact runtime export.
    ///
    /// These are reserved during Component instantiation and retain their
    /// generations for the full Component lifetime. An invocation only moves
    /// the matching slot between Idle and Active.
    callback_slots: Vec<CoreCallSlot>,
    bridges: Vec<RuntimeBridge>,
    /// Component-lifetime authorities for every live guest copy buffer.
    buffers: BufferRegistry,
    /// Canonical handles belong to the Component instance, not one invocation.
    state: AsyncState,
    poisoned: bool,
}

struct RuntimeExport {
    name: String,
    core_instance: usize,
    core_function: String,
    callback_instance: usize,
    callback: String,
    contract: RuntimeExportContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteStreamContract {
    stream: AsyncValueTypeId,
    closed: AsyncValueTypeId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeExportContract {
    Unit,
    ByteStream(ByteStreamContract),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeAction {
    TaskReturn(RuntimeExportContract),
    StreamNew(AsyncValueTypeId),
    FutureNew(AsyncValueTypeId),
    DropEndpoint {
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    },
    WaitableSetNew,
    WaitableSetDrop,
    WaitableJoin,
    StreamCopy {
        plan: BufferPlanId,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    },
    StreamCancel {
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    },
    FutureCopy {
        plan: BufferPlanId,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    },
    FutureCancel {
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
    },
    Unsupported,
}

struct RuntimeBridge {
    origin_instance: usize,
    action: BridgeAction,
    memory_binding: Option<RuntimeMemoryBinding>,
    memory: Option<CoreMemoryAuthority>,
}

struct RuntimeMemoryBinding {
    core_instance: usize,
    export: String,
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
        let mut bridges = runtime_bridges(execution)?;
        let exports = runtime_exports(execution)?;
        // Reserve all registry slots and the fixed byte-stream copy scratch
        // before any Core start function can execute during instantiation.
        let buffers = BufferRegistry::new(PROFILE_1_LIMITS.max_resources, memory_bytes)
            .map_err(|_| NativeAsyncError::Allocation)?;
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
        // Resolve validator-derived memory bindings once into opaque
        // underlying-memory authorities. Re-export aliases consequently share
        // the same capability and remain valid across memory.grow.
        for bridge in &mut bridges {
            bridge.memory = match &bridge.memory_binding {
                Some(binding) => Some(
                    modules
                        .memory_authority(binding.core_instance, &binding.export)
                        .map_err(|_| NativeAsyncError::InvalidWiring)?,
                ),
                None => None,
            };
        }
        let mut callback_slots = Vec::new();
        callback_slots
            .try_reserve_exact(exports.len())
            .map_err(|_| NativeAsyncError::Allocation)?;
        for binding in &exports {
            let slot = modules
                .reserve_call_slot(binding.callback_instance, &binding.callback)
                .map_err(|trap| match trap {
                    TrapCode::LimitExceeded => NativeAsyncError::Allocation,
                    _ => NativeAsyncError::InvalidWiring,
                })?;
            callback_slots.push(slot);
        }
        let state = AsyncState::new(AsyncStateLimits {
            handles: PROFILE_1_LIMITS.max_resources,
            pairs: PROFILE_1_LIMITS.max_resources,
            tasks: 1,
            waitables_per_set: PROFILE_1_LIMITS.max_resources,
        })
        .map_err(map_state_error)?;
        Ok(Self {
            modules,
            exports,
            callback_slots,
            bridges,
            buffers,
            state,
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
        if binding.contract != RuntimeExportContract::Unit {
            return Err(NativeAsyncError::UnsupportedFeature);
        }
        let callback_slot = self
            .callback_slots
            .get(export_index)
            .ok_or(NativeAsyncError::InvalidWiring)?;
        if callback_slot.state() != CoreCallSlotState::Idle {
            self.poisoned = true;
            return Err(NativeAsyncError::Poisoned);
        }
        self.modules
            .start_call(
                binding.core_instance,
                &binding.core_function,
                &[],
                total_work,
                poll_quantum,
            )
            .map_err(|_| NativeAsyncError::InvalidWiring)?;
        let task = match self.state.create_task() {
            Ok(task) => task,
            Err(error) => {
                self.modules.discard_all_calls();
                self.poisoned = true;
                return Err(map_state_error(error));
            }
        };
        Ok(NativeAsyncInvocation {
            component: self,
            export: export_index,
            task,
            stage: InvocationStage::Run,
            total_work,
            remaining_work: total_work,
            active_call_budget: total_work,
            poll_quantum,
            callback_pending: false,
            wait_ticket: None,
            wait_token: None,
            next_wait_generation: 1,
            input: None,
            output_stream: None,
            output_closed: None,
            terminal: false,
        })
    }

    /// Starts the exact resource-free C5.3 byte-stream filter contract.
    ///
    /// This entry point remains crate-private while the profile identity is
    /// validation-only. Both input endpoints are installed atomically before
    /// Core entry, and no raw handle or host endpoint authority crosses this
    /// executor boundary.
    pub(crate) fn start_filter<'a>(
        &'a mut self,
        export: &str,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<NativeAsyncInvocation<'a>, NativeAsyncError> {
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
        let RuntimeExportContract::ByteStream(contract) = binding.contract else {
            return Err(NativeAsyncError::UnsupportedFeature);
        };
        let callback_slot = self
            .callback_slots
            .get(export_index)
            .ok_or(NativeAsyncError::InvalidWiring)?;
        if callback_slot.state() != CoreCallSlotState::Idle {
            self.poisoned = true;
            return Err(NativeAsyncError::Poisoned);
        }

        // A filter start is transactional across the task arena, both input
        // endpoint pairs, and Core continuation state. Expected bounded-state
        // failures roll back without poisoning; only loss of a sealed cleanup
        // authority or validated Core wiring latches fail-stop.
        let task = match self.state.create_task() {
            Ok(task) => task,
            Err(error) => {
                if start_state_failure_is_invariant(error) {
                    self.poisoned = true;
                }
                return Err(map_state_error(error));
            }
        };
        let mut input = match self.state.insert_host_readables_pair(
            (EndpointKind::Stream, contract.stream),
            (EndpointKind::Future, contract.closed),
        ) {
            Ok(input) => input,
            Err(error) => {
                if self.state.abort_task(task).is_err() {
                    self.poisoned = true;
                    return Err(NativeAsyncError::Poisoned);
                }
                if start_state_failure_is_invariant(error) {
                    self.poisoned = true;
                }
                return Err(map_state_error(error));
            }
        };
        let inputs = [
            CoreValue::I32(input.first.guest.raw() as i32),
            CoreValue::I32(input.second.guest.raw() as i32),
        ];
        if self
            .modules
            .start_call(
                binding.core_instance,
                &binding.core_function,
                &inputs,
                total_work,
                poll_quantum,
            )
            .is_err()
        {
            self.modules.discard_all_calls();
            let endpoints_clean = self.state.discard_host_readables_pair(&mut input).is_ok();
            let task_clean = self.state.abort_task(task).is_ok();
            if endpoints_clean && task_clean {
                return Err(NativeAsyncError::InvalidWiring);
            }
            self.poisoned = true;
            return Err(NativeAsyncError::Poisoned);
        }
        Ok(NativeAsyncInvocation {
            component: self,
            export: export_index,
            task,
            stage: InvocationStage::Run,
            total_work,
            remaining_work: total_work,
            active_call_budget: total_work,
            poll_quantum,
            callback_pending: false,
            wait_ticket: None,
            wait_token: None,
            next_wait_generation: 1,
            input: Some(input),
            output_stream: None,
            output_closed: None,
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
        let (action, memory_binding) = match &canonical.function {
            NativeAsyncCanonicalFunctionPlan::TaskReturn { result, options } => {
                if options.async_ || options.memory.is_some() || options.realloc.is_some() {
                    return Err(NativeAsyncError::UnsupportedFeature);
                }
                let contract = match result {
                    None => RuntimeExportContract::Unit,
                    Some(result) => RuntimeExportContract::ByteStream(
                        byte_stream_contract(result).ok_or(NativeAsyncError::UnsupportedFeature)?,
                    ),
                };
                (BridgeAction::TaskReturn(contract), None)
            }
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::New {
                value_type,
                ..
            }) => (
                BridgeAction::StreamNew(stream_value_type_id(value_type)?),
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::Read {
                value_type,
                options,
                ..
            }) if stream_u8_value_type_id(value_type).is_some()
                && options.async_
                && options.realloc.is_none() =>
            {
                let value_type =
                    stream_u8_value_type_id(value_type).ok_or(NativeAsyncError::InvalidWiring)?;
                (
                    BridgeAction::StreamCopy {
                        plan: BufferPlanId::new(value_type.get())
                            .ok_or(NativeAsyncError::InvalidWiring)?,
                        direction: EndpointDirection::Read,
                        value_type,
                    },
                    Some(runtime_memory_binding(options)?),
                )
            }
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::Write {
                value_type,
                options,
                ..
            }) if stream_u8_value_type_id(value_type).is_some()
                && options.async_
                && options.realloc.is_none() =>
            {
                let value_type =
                    stream_u8_value_type_id(value_type).ok_or(NativeAsyncError::InvalidWiring)?;
                (
                    BridgeAction::StreamCopy {
                        plan: BufferPlanId::new(value_type.get())
                            .ok_or(NativeAsyncError::InvalidWiring)?,
                        direction: EndpointDirection::Write,
                        value_type,
                    },
                    Some(runtime_memory_binding(options)?),
                )
            }
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::CancelRead {
                value_type,
                ..
            }) if stream_u8_value_type_id(value_type).is_some() => (
                BridgeAction::StreamCancel {
                    direction: EndpointDirection::Read,
                    value_type: stream_u8_value_type_id(value_type)
                        .ok_or(NativeAsyncError::InvalidWiring)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::CancelWrite {
                value_type,
                ..
            }) if stream_u8_value_type_id(value_type).is_some() => (
                BridgeAction::StreamCancel {
                    direction: EndpointDirection::Write,
                    value_type: stream_u8_value_type_id(value_type)
                        .ok_or(NativeAsyncError::InvalidWiring)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::DropReadable {
                value_type,
                ..
            }) => (
                BridgeAction::DropEndpoint {
                    kind: EndpointKind::Stream,
                    direction: EndpointDirection::Read,
                    value_type: stream_value_type_id(value_type)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Stream(NativeAsyncStreamPlan::DropWritable {
                value_type,
                ..
            }) => (
                BridgeAction::DropEndpoint {
                    kind: EndpointKind::Stream,
                    direction: EndpointDirection::Write,
                    value_type: stream_value_type_id(value_type)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::New {
                value_type,
                ..
            }) => (
                BridgeAction::FutureNew(future_value_type_id(value_type)?),
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::Read {
                value_type,
                options,
                ..
            }) if future_enum8_value_type_id(value_type).is_some()
                && options.async_
                && options.realloc.is_none() =>
            {
                let value_type = future_enum8_value_type_id(value_type)
                    .ok_or(NativeAsyncError::InvalidWiring)?;
                (
                    BridgeAction::FutureCopy {
                        plan: BufferPlanId::new(value_type.get())
                            .ok_or(NativeAsyncError::InvalidWiring)?,
                        direction: EndpointDirection::Read,
                        value_type,
                    },
                    Some(runtime_memory_binding(options)?),
                )
            }
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::Write {
                value_type,
                options,
                ..
            }) if future_enum8_value_type_id(value_type).is_some()
                && options.async_
                && options.realloc.is_none() =>
            {
                let value_type = future_enum8_value_type_id(value_type)
                    .ok_or(NativeAsyncError::InvalidWiring)?;
                (
                    BridgeAction::FutureCopy {
                        plan: BufferPlanId::new(value_type.get())
                            .ok_or(NativeAsyncError::InvalidWiring)?,
                        direction: EndpointDirection::Write,
                        value_type,
                    },
                    Some(runtime_memory_binding(options)?),
                )
            }
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::CancelRead {
                value_type,
                ..
            }) if future_enum8_value_type_id(value_type).is_some() => (
                BridgeAction::FutureCancel {
                    direction: EndpointDirection::Read,
                    value_type: future_enum8_value_type_id(value_type)
                        .ok_or(NativeAsyncError::InvalidWiring)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::CancelWrite {
                value_type,
                ..
            }) if future_enum8_value_type_id(value_type).is_some() => (
                BridgeAction::FutureCancel {
                    direction: EndpointDirection::Write,
                    value_type: future_enum8_value_type_id(value_type)
                        .ok_or(NativeAsyncError::InvalidWiring)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::DropReadable {
                value_type,
                ..
            }) => (
                BridgeAction::DropEndpoint {
                    kind: EndpointKind::Future,
                    direction: EndpointDirection::Read,
                    value_type: future_value_type_id(value_type)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Future(NativeAsyncFuturePlan::DropWritable {
                value_type,
                ..
            }) => (
                BridgeAction::DropEndpoint {
                    kind: EndpointKind::Future,
                    direction: EndpointDirection::Write,
                    value_type: future_value_type_id(value_type)?,
                },
                None,
            ),
            NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetNew) => {
                (BridgeAction::WaitableSetNew, None)
            }
            NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::SetDrop) => {
                (BridgeAction::WaitableSetDrop, None)
            }
            NativeAsyncCanonicalFunctionPlan::Waitable(NativeAsyncWaitablePlan::Join) => {
                (BridgeAction::WaitableJoin, None)
            }
            _ => (BridgeAction::Unsupported, None),
        };
        bridges.push(RuntimeBridge {
            origin_instance: bridge.core_instance,
            action,
            memory_binding,
            memory: None,
        });
    }
    Ok(bridges)
}

fn runtime_memory_binding(
    options: &crate::execution::NativeAsyncCanonicalOptionsPlan,
) -> Result<RuntimeMemoryBinding, NativeAsyncError> {
    let memory = options
        .memory
        .as_ref()
        .ok_or(NativeAsyncError::InvalidWiring)?;
    Ok(RuntimeMemoryBinding {
        core_instance: memory.core_instance,
        export: copied(&memory.export)?,
    })
}

fn stream_u8_value_type_id(value: &ValueType) -> Option<AsyncValueTypeId> {
    match value {
        ValueType::Stream {
            type_id,
            element: Some(element),
        } if matches!(element.as_ref(), ValueType::U8) => Some(*type_id),
        _ => None,
    }
}

fn stream_value_type_id(value: &ValueType) -> Result<AsyncValueTypeId, NativeAsyncError> {
    match value {
        ValueType::Stream { type_id, .. } => Ok(*type_id),
        _ => Err(NativeAsyncError::InvalidWiring),
    }
}

fn future_value_type_id(value: &ValueType) -> Result<AsyncValueTypeId, NativeAsyncError> {
    match value {
        ValueType::Future { type_id, .. } => Ok(*type_id),
        _ => Err(NativeAsyncError::InvalidWiring),
    }
}

/// Selects the one-byte enum shape supported by this executor slice. Canonical
/// execution depends only on shape; admission separately binds the exact C5.3
/// close-reason case names before any host transport is installed.
fn future_enum8_value_type_id(value: &ValueType) -> Option<AsyncValueTypeId> {
    match value {
        ValueType::Future {
            type_id,
            payload: Some(payload),
        } if matches!(payload.as_ref(), ValueType::Enum(8)) => Some(*type_id),
        _ => None,
    }
}

/// Recognizes only the scalar-flattened C5.3 transport aggregate, including
/// its field order. Record field names are intentionally not represented in
/// [`ValueType`]; admission binds those names through the exact WIT world.
fn byte_stream_contract(value: &ValueType) -> Option<ByteStreamContract> {
    let ValueType::Record(fields) = value else {
        return None;
    };
    let [stream, closed] = fields.as_slice() else {
        return None;
    };
    Some(ByteStreamContract {
        stream: stream_u8_value_type_id(stream)?,
        closed: future_enum8_value_type_id(closed)?,
    })
}

fn export_contract(
    function_type: &crate::types::FunctionType,
) -> Result<RuntimeExportContract, NativeAsyncError> {
    if function_type.effect != FunctionEffect::Async {
        return Err(NativeAsyncError::UnsupportedFeature);
    }
    match (
        function_type.parameters.as_slice(),
        function_type.result.as_ref(),
    ) {
        ([], None) => Ok(RuntimeExportContract::Unit),
        ([input], Some(result)) => {
            let input =
                byte_stream_contract(&input.value).ok_or(NativeAsyncError::UnsupportedFeature)?;
            let result =
                byte_stream_contract(result).ok_or(NativeAsyncError::UnsupportedFeature)?;
            if input != result {
                return Err(NativeAsyncError::UnsupportedFeature);
            }
            Ok(RuntimeExportContract::ByteStream(input))
        }
        _ => Err(NativeAsyncError::UnsupportedFeature),
    }
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
        if !options.async_ || options.memory.is_some() || options.realloc.is_some() {
            return Err(NativeAsyncError::UnsupportedFeature);
        }
        let contract = export_contract(function_type)?;
        exports.push(RuntimeExport {
            name: copied(&export.name)?,
            core_instance: core_function.core_instance,
            core_function: copied(&core_function.export)?,
            callback_instance: callback.core_instance,
            callback: copied(&callback.export)?,
            contract,
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

const fn buffer_role(direction: EndpointDirection) -> BufferRole {
    match direction {
        EndpointDirection::Read => BufferRole::TargetRead,
        EndpointDirection::Write => BufferRole::SourceWrite,
    }
}

const fn copy_event_code(kind: EndpointKind, direction: EndpointDirection) -> EventCode {
    match (kind, direction) {
        (EndpointKind::Stream, EndpointDirection::Read) => EventCode::StreamRead,
        (EndpointKind::Stream, EndpointDirection::Write) => EventCode::StreamWrite,
        (EndpointKind::Future, EndpointDirection::Read) => EventCode::FutureRead,
        (EndpointKind::Future, EndpointDirection::Write) => EventCode::FutureWrite,
    }
}

fn buffer_copy_work(progress: u32, scratch_bytes: usize) -> Option<u64> {
    let bytes = u64::from(progress);
    let scratch = u64::try_from(scratch_bytes)
        .ok()
        .filter(|scratch| *scratch != 0)?;
    let chunks = bytes
        .checked_add(scratch.checked_sub(1)?)?
        .checked_div(scratch)?;
    BUFFER_COPY_BASE_WORK
        .checked_add(u64::from(progress))?
        .checked_add(bytes.checked_mul(2)?)?
        .checked_add(chunks)
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

/// Classifies native-filter setup failures before any guest-observable Core
/// entry. Exhausted bounded endpoint capacity is recoverable; every other
/// state rejection means an executor-owned precondition or rollback seal was
/// lost and therefore latches the Component fail-stop bit.
const fn start_state_failure_is_invariant(error: AsyncStateError) -> bool {
    !matches!(
        error,
        AsyncStateError::AllocationFailed
            | AsyncStateError::HandleTableFull
            | AsyncStateError::PairTableFull
            | AsyncStateError::GenerationExhausted
    )
}

/// Maps an async-state failure surfaced at a guest canonical boundary.
///
/// Guest-controlled raw handles and legal-but-invalid state transitions are
/// Canonical ABI misuse. Bounded arena/allocation exhaustion is a profile
/// limit. Sealed-ticket and executor invariants are validation failures.
const fn map_runtime_state_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::AllocationFailed
        | AsyncStateError::HandleTableFull
        | AsyncStateError::PairTableFull
        | AsyncStateError::ProgressLimit
        | AsyncStateError::GenerationExhausted
        | AsyncStateError::WaitableSetFull
        | AsyncStateError::TaskTableFull => TrapCode::LimitExceeded,
        AsyncStateError::InvalidLimits
        | AsyncStateError::WrongState
        | AsyncStateError::StaleOperation
        | AsyncStateError::PairInvariant
        | AsyncStateError::InvalidCopyResult
        | AsyncStateError::NoPendingEvent
        | AsyncStateError::EventAlreadyDelivered
        | AsyncStateError::StaleEvent
        | AsyncStateError::AuthorityConsumed
        | AsyncStateError::WaitableNotJoined
        | AsyncStateError::WaitableSetNotWaiting
        | AsyncStateError::StaleWait
        | AsyncStateError::TaskIncomplete => TrapCode::Validation,
        AsyncStateError::InvalidHandle
        | AsyncStateError::StaleHandle
        | AsyncStateError::WrongHandleKind
        | AsyncStateError::WrongEndpointKind
        | AsyncStateError::WrongDirection
        | AsyncStateError::WrongType
        | AsyncStateError::EndpointBusy
        | AsyncStateError::EndpointDone
        | AsyncStateError::OperationNotCopying
        | AsyncStateError::PairBusy
        | AsyncStateError::DropWhileCopying
        | AsyncStateError::FutureWritableNotDone
        | AsyncStateError::DuplicateHandle
        | AsyncStateError::WaitableSetNotEmpty
        | AsyncStateError::WaitableSetWaiting
        | AsyncStateError::AlreadyWaiting
        | AsyncStateError::TaskAlreadyResolved
        | AsyncStateError::TaskNotResolved
        | AsyncStateError::TaskAlreadyExited
        | AsyncStateError::TaskCancelState
        | AsyncStateError::TransferWhileJoined
        | AsyncStateError::CancelWhileJoined => TrapCode::CanonicalAbi,
    }
}

/// Once a guest raw handle has been resolved, loss of that exact sealed slot
/// is an executor invariant failure rather than a second guest-handle error.
const fn map_sealed_state_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::InvalidHandle | AsyncStateError::StaleHandle => TrapCode::Validation,
        _ => map_runtime_state_error(error),
    }
}

/// Maps a failure after an endpoint's raw handle, kind, direction, and value
/// type were all sealed by one read-only preflight. Losing any of that exact
/// identity is an executor invariant; legal state misuse remains Canonical ABI.
const fn map_exact_endpoint_state_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::InvalidHandle
        | AsyncStateError::StaleHandle
        | AsyncStateError::WrongState
        | AsyncStateError::WrongHandleKind
        | AsyncStateError::WrongEndpointKind
        | AsyncStateError::WrongDirection
        | AsyncStateError::WrongType => TrapCode::Validation,
        _ => map_runtime_state_error(error),
    }
}

/// A yielded callback owns one exact running task and cannot already be
/// exited or waiting. Failure of that executor-controlled precondition is an
/// invariant violation, not a guest canonical-ABI error.
const fn map_callback_yield_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::InvalidHandle
        | AsyncStateError::StaleHandle
        | AsyncStateError::TaskAlreadyExited
        | AsyncStateError::AlreadyWaiting => TrapCode::Validation,
        _ => map_runtime_state_error(error),
    }
}

/// Maps failures after the guest's raw waitable-set handle has been sealed.
///
/// The raw set's seal and kind were already checked, so task/set authority loss
/// and duplicate wait registrations are executor invariants. Bounded
/// exhaustion retains its limit class.
const fn map_callback_wait_begin_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::AllocationFailed
        | AsyncStateError::HandleTableFull
        | AsyncStateError::PairTableFull
        | AsyncStateError::ProgressLimit
        | AsyncStateError::GenerationExhausted
        | AsyncStateError::WaitableSetFull
        | AsyncStateError::TaskTableFull => TrapCode::LimitExceeded,
        _ => TrapCode::Validation,
    }
}

/// An explicit resume carries an exact unforgeable wait ticket. Any rejected
/// state authority is therefore an executor invariant, except genuine bounded
/// exhaustion which keeps the profile's limit trap.
const fn map_callback_wait_resume_error(error: AsyncStateError) -> TrapCode {
    match error {
        AsyncStateError::AllocationFailed
        | AsyncStateError::HandleTableFull
        | AsyncStateError::PairTableFull
        | AsyncStateError::ProgressLimit
        | AsyncStateError::GenerationExhausted
        | AsyncStateError::WaitableSetFull
        | AsyncStateError::TaskTableFull => TrapCode::LimitExceeded,
        _ => TrapCode::Validation,
    }
}

#[derive(Clone, Copy)]
enum InvocationStage {
    Run,
    StartCallback,
    Callback,
    WaitBlocked,
    Terminal,
}

#[derive(Clone, Copy)]
enum CallAuthority {
    Run(usize),
    Callback,
}

pub(crate) struct NativeAsyncInvocation<'a> {
    component: &'a mut NativeAsyncComponent,
    export: usize,
    task: TaskHandle,
    stage: InvocationStage,
    total_work: u64,
    remaining_work: u64,
    active_call_budget: u64,
    poll_quantum: u64,
    callback_pending: bool,
    wait_ticket: Option<WaitTicket>,
    wait_token: Option<NativeAsyncWaitToken>,
    next_wait_generation: u64,
    /// Exact input-side host authorities and the guest handles passed to Core.
    /// This aggregate is deliberately private and non-cloneable.
    input: Option<HostReadableBindingsPair>,
    /// Exact output-side tokens lifted atomically by `task.return`.
    output_stream: Option<ReadableStreamEndpointToken>,
    output_closed: Option<ReadableFutureEndpointToken>,
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
                self.poll_run(active)
            }
            InvocationStage::StartCallback => self.start_callback(),
            InvocationStage::Callback => self.poll_callback(),
            InvocationStage::WaitBlocked => self.poll_wait_blocked(),
            InvocationStage::Terminal => NativeAsyncPoll::Trapped(TrapCode::Cancelled),
        }
    }

    pub(crate) const fn metrics(&self) -> NativeAsyncMetrics {
        NativeAsyncMetrics {
            consumed_work: self.total_work - self.remaining_work,
            remaining_work: self.remaining_work,
        }
    }

    /// Requests owner-side task cancellation without cancelling or otherwise
    /// disturbing the currently active Core continuation.
    pub(crate) fn request_cancel(
        &mut self,
    ) -> Result<NativeAsyncCancelOutcome, NativeAsyncControlError> {
        if self.terminal || self.component.poisoned {
            return Ok(NativeAsyncCancelOutcome::AlreadyTerminal);
        }
        let info = self
            .component
            .state
            .task_info(self.task)
            .map_err(|_| NativeAsyncControlError::Invariant)?;
        if info.result == TaskResultState::Resolved {
            return Ok(NativeAsyncCancelOutcome::TooLate);
        }
        match info.cancel {
            TaskCancelState::None => {
                self.component
                    .state
                    .request_task_cancel(self.task)
                    .map_err(|_| NativeAsyncControlError::Invariant)?;
                Ok(NativeAsyncCancelOutcome::Requested)
            }
            TaskCancelState::Requested => Ok(NativeAsyncCancelOutcome::Requested),
            TaskCancelState::Delivered | TaskCancelState::Acknowledged => {
                Ok(NativeAsyncCancelOutcome::TooLate)
            }
        }
    }

    /// Uses one exact owner token to perform one real blocked-wait scan.
    ///
    /// Ordinary [`Self::poll`] calls never scan a blocked wait. A pending
    /// explicit resume spends one bounded state-transition charge and rotates
    /// the token, making retries and spurious wakes observable and linear.
    pub(crate) fn resume_wait(
        &mut self,
        token: NativeAsyncWaitToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncControlError> {
        if !matches!(self.stage, InvocationStage::WaitBlocked) {
            return Err(NativeAsyncControlError::NotWaiting);
        }
        let Some(expected) = self.wait_token else {
            return Ok(self.finish_trap(TrapCode::Validation));
        };
        if token != expected {
            return Err(NativeAsyncControlError::InvalidWaitToken);
        }
        if self.wait_ticket.is_none() {
            return Ok(self.finish_trap(TrapCode::Validation));
        }
        if self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
            || self.callback_pending
        {
            return Ok(self.finish_trap(TrapCode::Validation));
        }

        // Consume the exact wake authority before doing state work. If the
        // selector remains pending, `park_wait` mints a fresh authority.
        self.wait_token = None;
        if !self.charge_wait_state_work() {
            return Ok(self.finish_trap(TrapCode::FuelExhausted));
        }
        let resumed = {
            let Some(ticket) = self.wait_ticket.as_mut() else {
                return Ok(self.finish_trap(TrapCode::Validation));
            };
            self.component.state.resume_callback_wait(ticket)
        };
        match resumed {
            Ok(WaitResume::Pending) => {
                let token = match self.mint_wait_token() {
                    Ok(token) => token,
                    Err(trap) => return Ok(self.finish_trap(trap)),
                };
                self.wait_token = Some(token);
                Ok(NativeAsyncPoll::WaitPending {
                    token,
                    metrics: self.metrics(),
                })
            }
            Ok(WaitResume::Ready(lease)) => {
                self.wait_ticket = None;
                Ok(self.handle_wait_event(lease))
            }
            Err(error) => Ok(self.finish_trap(map_callback_wait_resume_error(error))),
        }
    }

    fn binding(&self) -> &RuntimeExport {
        &self.component.exports[self.export]
    }

    fn poll_wait_blocked(&mut self) -> NativeAsyncPoll {
        let Some(token) = self.wait_token else {
            return self.finish_trap(TrapCode::Validation);
        };
        if self.wait_ticket.is_none()
            || self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
            || self.callback_pending
        {
            return self.finish_trap(TrapCode::Validation);
        }
        NativeAsyncPoll::WaitPending {
            token,
            metrics: self.metrics(),
        }
    }

    fn poll_run(&mut self, active_instance: usize) -> NativeAsyncPoll {
        let result = self.component.modules.poll_call(active_instance);
        let authority = CallAuthority::Run(active_instance);
        if !self.settle_metrics(authority) {
            return self.finish_trap(TrapCode::Validation);
        }
        match result {
            PollResult::Pending { .. } => NativeAsyncPoll::Pending(self.metrics()),
            PollResult::HostCall(call) => self.handle_host_call(authority, call),
            PollResult::Ready(values) => self.handle_callback_result(values.as_slice()),
            PollResult::Trapped(trap) => self.finish_trap(trap),
        }
    }

    fn poll_callback(&mut self) -> NativeAsyncPoll {
        let result = self
            .component
            .modules
            .poll_call_slot(&mut self.component.callback_slots[self.export]);
        if !self.settle_metrics(CallAuthority::Callback) {
            return self.finish_trap(TrapCode::Validation);
        }
        match result {
            CoreSlotPollResult::Pending { .. } => NativeAsyncPoll::Pending(self.metrics()),
            CoreSlotPollResult::HostCall(call) => {
                self.handle_host_call(CallAuthority::Callback, call)
            }
            CoreSlotPollResult::Ready(values) => self.handle_callback_result(values.as_slice()),
            CoreSlotPollResult::Trapped(trap) => self.finish_trap(trap),
        }
    }

    fn settle_metrics(&mut self, authority: CallAuthority) -> bool {
        let metrics = match authority {
            CallAuthority::Run(active_instance) => {
                self.component.modules.call_metrics(active_instance)
            }
            CallAuthority::Callback => self
                .component
                .modules
                .call_metrics_slot(&self.component.callback_slots[self.export]),
        };
        let Some(metrics) = metrics else {
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
        authority: CallAuthority,
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
        let action = bridge.action;
        let memory = bridge.memory;
        match (action, call.arguments.as_slice()) {
            (BridgeAction::TaskReturn(RuntimeExportContract::Unit), []) => {
                if self.binding().contract != RuntimeExportContract::Unit {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                if let Err(trap) = self.debit_active_work(authority, TASK_RETURN_WORK) {
                    return self.finish_trap(trap);
                }
                if let Err(error) = self.component.state.resolve_task_result(self.task) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Resolved(self.metrics())
            }
            (
                BridgeAction::TaskReturn(RuntimeExportContract::ByteStream(contract)),
                [CoreValue::I32(stream_raw), CoreValue::I32(closed_raw)],
            ) => {
                if self.binding().contract != RuntimeExportContract::ByteStream(contract) {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                match (self.output_stream.is_some(), self.output_closed.is_some()) {
                    (false, false) => {}
                    (true, true) => return self.finish_trap(TrapCode::CanonicalAbi),
                    (true, false) | (false, true) => {
                        return self.finish_trap(TrapCode::Validation);
                    }
                }
                // Seal both guest handles before charging fuel. The fixed-pair
                // transfer then performs all remaining busy/join/type checks
                // before either endpoint is detached.
                let stream = match self.component.state.resolve_guest_endpoint(
                    *stream_raw as u32,
                    EndpointKind::Stream,
                    EndpointDirection::Read,
                    contract.stream,
                ) {
                    Ok(stream) => stream,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                let closed = match self.component.state.resolve_guest_endpoint(
                    *closed_raw as u32,
                    EndpointKind::Future,
                    EndpointDirection::Read,
                    contract.closed,
                ) {
                    Ok(closed) => closed,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                if let Err(trap) = self.debit_active_work(authority, TASK_RETURN_WORK) {
                    return self.finish_trap(trap);
                }
                let detached = self.component.state.detach_readables_pair(
                    ReadableTransferRequest {
                        handle: stream,
                        kind: EndpointKind::Stream,
                        value_type: contract.stream,
                    },
                    ReadableTransferRequest {
                        handle: closed,
                        kind: EndpointKind::Future,
                        value_type: contract.closed,
                    },
                );
                let (stream, closed) = match detached {
                    Ok((
                        TransferredReadableEndpoint::Stream(stream),
                        TransferredReadableEndpoint::Future(closed),
                    )) if stream.value_type() == contract.stream
                        && closed.value_type() == contract.closed =>
                    {
                        (stream, closed)
                    }
                    Ok(_) => return self.finish_trap(TrapCode::Validation),
                    Err(error) => return self.finish_trap(map_exact_endpoint_state_error(error)),
                };
                // Store both linear output authorities before the next
                // fallible operation. Fail-stop cleanup can consequently
                // reclaim them even if task resolution or Core resume detects
                // an executor invariant.
                self.output_stream = Some(stream);
                self.output_closed = Some(closed);
                if let Err(error) = self.component.state.resolve_task_result(self.task) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Resolved(self.metrics())
            }
            (BridgeAction::StreamNew(value_type), []) => {
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                let pair = match self.component.state.create_stream_pair(value_type) {
                    Ok(pair) => pair,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                let Ok(packed) = pack_endpoint_pair(AbiEndpointPair {
                    readable: pair.readable.raw(),
                    writable: pair.writable.raw(),
                }) else {
                    return self.finish_trap(TrapCode::Validation);
                };
                let results = [CoreValue::I64(packed as i64)];
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &results) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (BridgeAction::FutureNew(value_type), []) => {
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                let pair = match self.component.state.create_future_pair(value_type) {
                    Ok(pair) => pair,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                let Ok(packed) = pack_endpoint_pair(AbiEndpointPair {
                    readable: pair.readable.raw(),
                    writable: pair.writable.raw(),
                }) else {
                    return self.finish_trap(TrapCode::Validation);
                };
                let results = [CoreValue::I64(packed as i64)];
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &results) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (
                BridgeAction::StreamCopy {
                    plan,
                    direction,
                    value_type,
                },
                [CoreValue::I32(raw), CoreValue::I32(pointer), CoreValue::I32(elements)],
            ) => {
                let Some(memory) = memory else {
                    return self.finish_trap(TrapCode::Validation);
                };
                self.handle_copy(
                    authority,
                    call.id,
                    plan,
                    memory,
                    EndpointKind::Stream,
                    direction,
                    value_type,
                    *raw as u32,
                    *pointer as u32,
                    *elements as u32,
                )
            }
            (
                BridgeAction::FutureCopy {
                    plan,
                    direction,
                    value_type,
                },
                [CoreValue::I32(raw), CoreValue::I32(pointer)],
            ) => {
                let Some(memory) = memory else {
                    return self.finish_trap(TrapCode::Validation);
                };
                self.handle_copy(
                    authority,
                    call.id,
                    plan,
                    memory,
                    EndpointKind::Future,
                    direction,
                    value_type,
                    *raw as u32,
                    *pointer as u32,
                    1,
                )
            }
            (
                BridgeAction::StreamCancel {
                    direction,
                    value_type,
                },
                [CoreValue::I32(raw)],
            ) => self.handle_copy_cancel(
                authority,
                call.id,
                EndpointKind::Stream,
                direction,
                value_type,
                *raw as u32,
            ),
            (
                BridgeAction::FutureCancel {
                    direction,
                    value_type,
                },
                [CoreValue::I32(raw)],
            ) => self.handle_copy_cancel(
                authority,
                call.id,
                EndpointKind::Future,
                direction,
                value_type,
                *raw as u32,
            ),
            (
                BridgeAction::DropEndpoint {
                    kind,
                    direction,
                    value_type,
                },
                [CoreValue::I32(raw)],
            ) => {
                let handle = match self.component.state.resolve_guest_handle(*raw as u32) {
                    Ok(handle) => handle,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                if let Err(error) = self
                    .component
                    .state
                    .drop_endpoint(handle, kind, direction, value_type)
                {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (BridgeAction::WaitableSetNew, []) => {
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                let set = match self.component.state.create_waitable_set() {
                    Ok(set) => set,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                let results = [CoreValue::I32(set.raw() as i32)];
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &results) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (BridgeAction::WaitableSetDrop, [CoreValue::I32(raw)]) => {
                let set = match self.component.state.resolve_guest_handle(*raw as u32) {
                    Ok(set) => set,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                if let Err(error) = self.component.state.drop_waitable_set(set) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (
                BridgeAction::WaitableJoin,
                [CoreValue::I32(waitable_raw), CoreValue::I32(set_raw)],
            ) => {
                let waitable = match self
                    .component
                    .state
                    .resolve_guest_handle(*waitable_raw as u32)
                {
                    Ok(waitable) => waitable,
                    Err(error) => return self.finish_trap(map_runtime_state_error(error)),
                };
                if let Err(trap) = self.debit_active_work(authority, HANDLE_STATE_WORK) {
                    return self.finish_trap(trap);
                }
                if let Err(error) = self
                    .component
                    .state
                    .join_waitable(waitable, *set_raw as u32)
                {
                    return self.finish_trap(map_runtime_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                NativeAsyncPoll::Pending(self.metrics())
            }
            (BridgeAction::Unsupported, _) => self.finish_trap(TrapCode::CanonicalAbi),
            _ => self.finish_trap(TrapCode::Validation),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_copy(
        &mut self,
        authority: CallAuthority,
        host_id: u32,
        plan: BufferPlanId,
        memory: CoreMemoryAuthority,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        raw: u32,
        pointer: u32,
        elements: u32,
    ) -> NativeAsyncPoll {
        // Guest-controlled handles, ranges, and arena availability are all
        // checked before either fuel or state changes.
        let handle = match self
            .component
            .state
            .resolve_guest_endpoint(raw, kind, direction, value_type)
        {
            Ok(handle) => handle,
            Err(error) => return self.finish_trap(map_runtime_state_error(error)),
        };
        if let Err(error) = self
            .component
            .state
            .preflight_begin_copy(handle, kind, direction, value_type, elements)
        {
            return self.finish_trap(map_exact_endpoint_state_error(error));
        }
        let role = buffer_role(direction);
        let prepared = match self.component.buffers.preflight(
            &self.component.modules,
            plan,
            memory,
            role,
            pointer,
            elements,
            value_type,
        ) {
            Ok(prepared) => prepared,
            Err(trap) => return self.finish_trap(trap),
        };
        if let Err(trap) = self.debit_active_work_with_reserve(authority, BUFFER_BRIDGE_WORK) {
            return self.finish_trap(trap);
        }
        let lease = match self.component.buffers.issue(prepared) {
            Ok(lease) => lease,
            Err(_) => return self.finish_trap(TrapCode::Validation),
        };
        let begun = match self
            .component
            .state
            .begin_copy(handle, kind, direction, value_type, lease)
        {
            Ok(begun) => begun,
            Err(failure) => {
                let (error, lease) = failure.into_parts();
                if self.component.buffers.discard_owned(lease).is_err() {
                    return self.finish_trap(TrapCode::Validation);
                }
                return self.finish_trap(map_exact_endpoint_state_error(error));
            }
        };

        let event = match begun {
            CopyBegin::Blocked { abi, .. } => {
                let results = [CoreValue::I32(abi as i32)];
                if let Err(trap) = self.resume_active_host_call(authority, host_id, &results) {
                    return self.finish_trap(trap);
                }
                return NativeAsyncPoll::Pending(self.metrics());
            }
            CopyBegin::Ready(event) => event,
            CopyBegin::Local(mut ticket) => {
                let progress = match self.component.state.local_copy_progress(&ticket) {
                    Ok(progress) => progress,
                    Err(_) => return self.finish_trap(TrapCode::Validation),
                };
                let Some(work) = buffer_copy_work(progress, self.component.buffers.scratch_bytes())
                else {
                    return self.finish_trap(TrapCode::FuelExhausted);
                };
                if let Err(trap) = self.debit_active_work_with_reserve(authority, work) {
                    return self.finish_trap(trap);
                }
                let copied = {
                    let (state, buffers, modules) = (
                        &mut self.component.state,
                        &mut self.component.buffers,
                        &mut self.component.modules,
                    );
                    state.commit_local_copy(&mut ticket, progress, |source, target, progress| {
                        // The supported future has a one-byte enum layout, but a
                        // guest write buffer is still untrusted Core memory.
                        // Validate its discriminant immediately before the
                        // target publication; the source may have changed
                        // after an earlier BLOCKED return.
                        if kind == EndpointKind::Future {
                            let _ = buffers.lift_enum8(modules, source)?;
                        }
                        buffers.copy_local(modules, source, target, progress)
                    })
                };
                match copied {
                    Ok(event) => event,
                    Err(CommitError::State(_)) => {
                        return self.finish_trap(TrapCode::Validation);
                    }
                    Err(CommitError::Operation(TrapCode::CanonicalAbi)) => {
                        return self.finish_trap(TrapCode::CanonicalAbi);
                    }
                    Err(CommitError::Operation(_)) => {
                        return self.finish_trap(TrapCode::Validation);
                    }
                }
            }
        };
        self.finish_copy_event(authority, host_id, event, kind, direction, raw)
    }

    fn handle_copy_cancel(
        &mut self,
        authority: CallAuthority,
        host_id: u32,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        raw: u32,
    ) -> NativeAsyncPoll {
        let handle = match self
            .component
            .state
            .resolve_guest_endpoint(raw, kind, direction, value_type)
        {
            Ok(handle) => handle,
            Err(error) => return self.finish_trap(map_runtime_state_error(error)),
        };
        if let Err(error) = self
            .component
            .state
            .preflight_cancel_copy(handle, kind, direction, value_type)
        {
            return self.finish_trap(map_exact_endpoint_state_error(error));
        }
        if let Err(trap) = self.debit_active_work_with_reserve(authority, BUFFER_BRIDGE_WORK) {
            return self.finish_trap(trap);
        }
        let event = match self
            .component
            .state
            .cancel_copy(handle, kind, direction, value_type)
        {
            Ok(event) => event,
            Err(error) => return self.finish_trap(map_exact_endpoint_state_error(error)),
        };
        self.finish_copy_event(authority, host_id, event, kind, direction, raw)
    }

    fn finish_copy_event(
        &mut self,
        authority: CallAuthority,
        host_id: u32,
        event: EventToken,
        kind: EndpointKind,
        direction: EndpointDirection,
        raw: u32,
    ) -> NativeAsyncPoll {
        let (event, mut reclaim) = match self.component.state.deliver_event(&event) {
            Ok(delivered) => delivered,
            Err(_) => return self.finish_trap(TrapCode::Validation),
        };
        if event.code != copy_event_code(kind, direction) || event.p1 != raw {
            return self.finish_trap(TrapCode::Validation);
        }
        let reclaimed = {
            let (state, buffers) = (&mut self.component.state, &mut self.component.buffers);
            state.reclaim_event(&mut reclaim, |lease| {
                buffers.release(lease, buffer_role(direction))
            })
        };
        match reclaimed {
            Ok(()) => {}
            Err(ReclaimError::State(_)) | Err(ReclaimError::Operation(_)) => {
                return self.finish_trap(TrapCode::Validation);
            }
        }
        let results = [CoreValue::I32(event.p2 as i32)];
        if let Err(trap) = self.resume_active_host_call(authority, host_id, &results) {
            return self.finish_trap(trap);
        }
        NativeAsyncPoll::Pending(self.metrics())
    }

    fn debit_active_work_with_reserve(
        &mut self,
        authority: CallAuthority,
        amount: u64,
    ) -> Result<(), TrapCode> {
        if self.remaining_work <= amount {
            return Err(TrapCode::FuelExhausted);
        }
        self.debit_active_work(authority, amount)
    }

    fn debit_active_work(&mut self, authority: CallAuthority, amount: u64) -> Result<(), TrapCode> {
        debug_assert!(amount > 0);
        match authority {
            CallAuthority::Run(active_instance) => self
                .component
                .modules
                .debit_call_fuel(active_instance, amount)?,
            CallAuthority::Callback => self
                .component
                .modules
                .debit_call_fuel_slot(&self.component.callback_slots[self.export], amount)?,
        }
        if self.settle_metrics(authority) {
            Ok(())
        } else {
            Err(TrapCode::Validation)
        }
    }

    fn resume_active_host_call(
        &mut self,
        authority: CallAuthority,
        id: u32,
        results: &[CoreValue],
    ) -> Result<(), TrapCode> {
        match authority {
            CallAuthority::Run(active_instance) => {
                self.component
                    .modules
                    .resume_host_call(active_instance, id, results)
            }
            CallAuthority::Callback => self.component.modules.resume_host_call_slot(
                &self.component.callback_slots[self.export],
                id,
                results,
            ),
        }
    }

    fn handle_callback_result(&mut self, values: &[CoreValue]) -> NativeAsyncPoll {
        let [CoreValue::I32(raw)] = values else {
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
                if self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
                    || self.callback_pending
                    || self.wait_ticket.is_some()
                    || self.wait_token.is_some()
                {
                    return self.finish_trap(TrapCode::Validation);
                }
                if let Err(error) = self.component.state.callback_exit(self.task) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(error) = self.component.state.drop_task(self.task) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                self.stage = InvocationStage::Terminal;
                self.terminal = true;
                NativeAsyncPoll::Complete(self.metrics())
            }
            CallbackCode::Yield => {
                if self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
                    || self.callback_pending
                    || self.wait_ticket.is_some()
                    || self.wait_token.is_some()
                {
                    return self.finish_trap(TrapCode::Validation);
                }
                self.callback_pending = true;
                self.stage = InvocationStage::StartCallback;
                NativeAsyncPoll::Yielded(self.metrics())
            }
            CallbackCode::Wait => {
                let Some(raw_set) = result.waitable_set else {
                    return self.finish_trap(TrapCode::Validation);
                };
                self.begin_callback_wait(raw_set)
            }
        }
    }

    fn begin_callback_wait(&mut self, raw_set: u32) -> NativeAsyncPoll {
        if self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
            || self.callback_pending
            || self.wait_ticket.is_some()
            || self.wait_token.is_some()
        {
            return self.finish_trap(TrapCode::Validation);
        }
        // Resolve the guest's raw set before charging or mutating the wait
        // selector. A malformed or wrong-kind handle is guest ABI misuse.
        let set = match self.component.state.resolve_guest_waitable_set(raw_set) {
            Ok(set) => set,
            Err(error) => return self.finish_trap(map_runtime_state_error(error)),
        };
        // A selected cancellation/event must be able to start its callback in
        // this same transition, so retain at least one unit of Core fuel.
        if !self.charge_wait_state_work() {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        match self.component.state.begin_callback_wait(self.task, set) {
            Ok(WaitBegin::Ready(lease)) => self.handle_wait_event(lease),
            Ok(WaitBegin::Blocked { ticket }) => self.park_wait(ticket),
            Err(error) => self.finish_trap(map_callback_wait_begin_error(error)),
        }
    }

    fn park_wait(&mut self, ticket: WaitTicket) -> NativeAsyncPoll {
        if self.wait_ticket.is_some() || self.wait_token.is_some() {
            return self.finish_trap(TrapCode::Validation);
        }
        self.wait_ticket = Some(ticket);
        let token = match self.mint_wait_token() {
            Ok(token) => token,
            Err(trap) => return self.finish_trap(trap),
        };
        self.wait_token = Some(token);
        self.stage = InvocationStage::WaitBlocked;
        NativeAsyncPoll::WaitPending {
            token,
            metrics: self.metrics(),
        }
    }

    fn mint_wait_token(&mut self) -> Result<NativeAsyncWaitToken, TrapCode> {
        let generation = self.next_wait_generation;
        let next = generation.checked_add(1).ok_or(TrapCode::LimitExceeded)?;
        if generation == 0 {
            return Err(TrapCode::Validation);
        }
        self.next_wait_generation = next;
        Ok(NativeAsyncWaitToken {
            task: self.task,
            generation,
        })
    }

    fn handle_wait_event(&mut self, mut lease: EventLease) -> NativeAsyncPoll {
        self.wait_token = None;
        match lease.state() {
            EventLeaseState::TaskCancelled => {
                let Some(event) = lease.take_task_cancelled() else {
                    return self.finish_trap(TrapCode::Validation);
                };
                self.start_callback_event(event)
            }
            EventLeaseState::EndpointPending => {
                if lease.prepare_endpoint(&mut self.component.state).is_err() {
                    return self.finish_trap(TrapCode::Validation);
                }
                let finished = {
                    let (state, buffers) = (&mut self.component.state, &mut self.component.buffers);
                    lease.finish_endpoint(state, |buffer| buffers.release_owned(buffer))
                };
                match finished {
                    Ok(event) => self.start_callback_event(event),
                    Err(_) => self.finish_trap(TrapCode::Validation),
                }
            }
            EventLeaseState::EndpointDelivered | EventLeaseState::Consumed => {
                self.finish_trap(TrapCode::Validation)
            }
        }
    }

    fn start_callback(&mut self) -> NativeAsyncPoll {
        if self.remaining_work == 0 {
            return self.finish_trap(TrapCode::FuelExhausted);
        }
        if !self.callback_pending {
            return self.finish_trap(TrapCode::Validation);
        }
        if self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle {
            return self.finish_trap(TrapCode::Validation);
        }
        // Select at the owner-visible Yielded -> poll boundary, then start the
        // exact callback immediately. This makes cancellation requested while
        // yielded visible to the next callback without caching a replayable
        // event across another executor boundary.
        let event = match self.component.state.callback_yield(self.task) {
            Ok(event) => event,
            Err(error) => return self.finish_trap(map_callback_yield_error(error)),
        };
        self.start_callback_event(event)
    }

    fn start_callback_event(&mut self, event: Event) -> NativeAsyncPoll {
        if self.remaining_work == 0
            || self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
        {
            return self.finish_trap(if self.remaining_work == 0 {
                TrapCode::FuelExhausted
            } else {
                TrapCode::Validation
            });
        }
        let inputs = [
            CoreValue::I32(event.code as i32),
            CoreValue::I32(event.p1 as i32),
            CoreValue::I32(event.p2 as i32),
        ];
        let quantum = self.poll_quantum.min(self.remaining_work);
        let (modules, exports, callback_slots) = (
            &mut self.component.modules,
            &self.component.exports,
            &mut self.component.callback_slots,
        );
        let binding = &exports[self.export];
        let slot = &mut callback_slots[self.export];
        if modules
            .start_call_slot(
                slot,
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
        self.callback_pending = false;
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

    fn charge_wait_state_work(&mut self) -> bool {
        let Some(remaining) = self.remaining_work.checked_sub(WAIT_STATE_WORK) else {
            return false;
        };
        if remaining == 0 {
            return false;
        }
        self.remaining_work = remaining;
        true
    }

    fn finish_trap(&mut self, trap: TrapCode) -> NativeAsyncPoll {
        self.stage = InvocationStage::Terminal;
        self.terminal = true;
        self.poison_and_discard();
        NativeAsyncPoll::Trapped(trap)
    }

    fn poison_and_discard(&mut self) {
        // Latch fail-stop before touching any independently fallible cleanup
        // authority. No cleanup error may make this Component reusable.
        self.component.poisoned = true;
        // A reusable call's storage can only be recovered with its exact slot
        // authority. Recover every active slot before the principal-wide
        // fallback so no slot can be left looking reusable after its storage
        // was destroyed.
        let (modules, callback_slots) = (
            &mut self.component.modules,
            &mut self.component.callback_slots,
        );
        for slot in callback_slots {
            if slot.state() == CoreCallSlotState::Active {
                let _ = modules.discard_call_slot(slot);
            }
        }
        modules.discard_all_calls();

        let wait_cancelled = match self.wait_ticket.as_mut() {
            Some(ticket) => self.component.state.cancel_callback_wait(ticket).is_ok(),
            None => true,
        };
        if wait_cancelled {
            self.wait_ticket = None;
        }
        // Move every linear lease out of AsyncState before invalidating the
        // registry. Exact discard failures are already fail-stop; `poison`
        // then rotates every slot as the bounded invariant-recovery fallback.
        {
            let (state, buffers) = (&mut self.component.state, &mut self.component.buffers);
            state.abort_all_copies(|lease| {
                let _ = buffers.discard_owned(lease);
            });
            buffers.poison();
        }
        // Result endpoints have already crossed the guest-to-host ownership
        // boundary, so retain and use their exact tokens for best-effort
        // fail-stop reclamation. Clear an authority only after the state
        // accepted that exact token.
        if self.output_stream.as_ref().is_some_and(|stream| {
            self.component
                .state
                .drop_stream_host_readable(stream)
                .is_ok()
        }) {
            self.output_stream = None;
        }
        if self.output_closed.as_ref().is_some_and(|closed| {
            self.component
                .state
                .drop_future_host_readable(closed)
                .is_ok()
        }) {
            self.output_closed = None;
        }
        // Before task.return, an untouched input aggregate can be rolled back
        // exactly. Once guest code has dropped, copied, joined, or transferred
        // either readable end, the narrow startup rollback authority correctly
        // rejects it. Its host-writer authority then remains confined to this
        // unusable poisoned Component and is reclaimed only when the whole
        // Component is dropped; it is never exposed or reused.
        if self.input.as_mut().is_some_and(|input| {
            self.component
                .state
                .discard_host_readables_pair(input)
                .is_ok()
        }) {
            self.input = None;
        }
        self.wait_token = None;
        self.callback_pending = false;
        let _ = self.component.state.abort_task(self.task);
    }

    #[cfg(test)]
    fn task_info(&self) -> TaskInfo {
        self.component.state.task_info(self.task).unwrap()
    }
}

impl Drop for NativeAsyncInvocation<'_> {
    fn drop(&mut self) {
        // A unit invocation owns no transport authority after a clean exit and
        // can leave its Component reusable. The filter transport is not yet
        // externally drivable while this profile remains validation-only, so
        // silently dropping any retained input or result authority would lose
        // its exact Host holder while leaving the pair arena live. Fail-stop
        // until the host-pending slice has explicitly consumed every one of
        // those authorities; a partially wired caller must never turn a clean
        // callback exit into bounded per-invocation leakage.
        let retained_transport =
            self.input.is_some() || self.output_stream.is_some() || self.output_closed.is_some();
        if !self.terminal || (!self.component.poisoned && retained_transport) {
            self.stage = InvocationStage::Terminal;
            self.terminal = true;
            self.poison_and_discard();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        async_state::{BufferLease, CopyBegin, TaskCallbackState},
        decode::inspect_component_for_profile,
    };
    use alloc::format;
    use vibeos_wasm_runtime::CoreHostCall;

    const SMOKE: &str = include_str!(
        "../../component-format/tests/corpus/component/native-async-smoke-0.255.0.component.wat"
    );
    const FILTER: &str = r#"(component
      (type $close-reason-private
        (enum "normal" "failure" "cancelled" "denied" "unavailable"
          "exhausted" "invalid" "backend-fault"))
      (import "close-reason"
        (type $close-reason (eq $close-reason-private)))
      (type $bytes-private (stream u8))
      (import "bytes" (type $bytes (eq $bytes-private)))
      (type $closed-private (future $close-reason))
      (import "closed" (type $closed (eq $closed-private)))
      (type $byte-stream-private
        (record (field "bytes" $bytes) (field "closed" $closed)))
      (import "byte-stream"
        (type $byte-stream (eq $byte-stream-private)))
      (type $run-type
        (func async (param "input" $byte-stream) (result $byte-stream)))

      (core func $task-return
        (canon task.return (result $byte-stream)))
      (core instance $builtins
        (export "task-return" (func $task-return)))
      (core module $guest
        (import "vibe:async" "task-return"
          (func $task-return (param i32 i32)))
        (func (export "run")
          (param $input-bytes i32) (param $input-closed i32) (result i32)
          local.get $input-bytes
          i32.eqz
          if unreachable end
          local.get $input-closed
          i32.eqz
          if unreachable end
          local.get $input-bytes
          local.get $input-closed
          i32.eq
          if unreachable end
          local.get $input-bytes
          local.get $input-closed
          call $task-return
          i32.const 1)
        (func (export "callback") (param i32 i32 i32) (result i32)
          i32.const 0))
      (core instance $guest-instance
        (instantiate $guest (with "vibe:async" (instance $builtins))))
      (alias core export $guest-instance "run" (core func $run))
      (alias core export $guest-instance "callback" (core func $callback))
      (func $lifted (type $run-type)
        (canon lift (core func $run) async
          (callback (core func $callback))))
      (export "run" (func $lifted)))"#;
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

    fn filter_core_without_inputs(function_type: &str) -> String {
        replace_once(
            &replace_once(
                FILTER,
                "(func async (param \"input\" $byte-stream) (result $byte-stream))",
                function_type,
            ),
            r#"(func (export "run")
          (param $input-bytes i32) (param $input-closed i32) (result i32)
          local.get $input-bytes
          i32.eqz
          if unreachable end
          local.get $input-closed
          i32.eqz
          if unreachable end
          local.get $input-bytes
          local.get $input-closed
          i32.eq
          if unreachable end
          local.get $input-bytes
          local.get $input-closed
          call $task-return
          i32.const 1)"#,
            r#"(func (export "run") (result i32)
          i32.const 1
          i32.const 2
          call $task-return
          i32.const 1)"#,
        )
    }

    fn wait_component(resolve_before_wait: bool, callback: &str) -> String {
        let task_return = if resolve_before_wait {
            "      call $task-return\n"
        } else {
            ""
        };
        let run = format!(
            r#"    (func (export "run") (result i32)
      (local $set i32)
      call $waitable-set-new
      local.set $set
      i32.const 0
      local.get $set
      i32.store
{task_return}      local.get $set
      i32.const 4
      i32.shl
      i32.const 2
      i32.or)"#
        );
        replace_once(
            &replace_once(
                SMOKE,
                "    (func (export \"run\") (result i32)\n      call $task-return\n      i32.const 1)",
                &run,
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            callback,
        )
    }

    fn cancellation_exit_callback() -> &'static str {
        r#"    (func (export "callback") (param $event i32) (param $p1 i32) (param $p2 i32) (result i32)
      local.get $event
      i32.const 6
      i32.ne
      if
        unreachable
      end
      local.get $p1
      local.get $p2
      i32.or
      if
        unreachable
      end
      i32.const 0
      i32.load
      call $waitable-set-drop
      call $task-return
      i32.const 0)"#
    }

    fn poll_to_wait(
        call: &mut NativeAsyncInvocation<'_>,
    ) -> (NativeAsyncWaitToken, NativeAsyncMetrics) {
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::WaitPending { token, metrics } => return (token, metrics),
                NativeAsyncPoll::Complete(_) => panic!("wait fixture completed before WAIT"),
                NativeAsyncPoll::Trapped(trap) => panic!("wait fixture trapped: {trap:?}"),
            }
        }
    }

    fn finish_cancelled_wait_callback(call: &mut NativeAsyncInvocation<'_>) {
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Complete(_) => return,
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("cancel callback unexpectedly waited")
                }
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("cancel callback trapped: {trap:?}")
                }
            }
        }
    }

    fn handle_component(run_body: &str) -> String {
        format!(
            r#"(component
              (type $bytes (stream u8))
              (type $words (stream u16))
              (type $future (future u8))
              (type $run-type (func async))

              (core func $task-return (canon task.return))
              (core func $task-cancel (canon task.cancel))
              (core func $stream-new (canon stream.new $bytes))
              (core func $stream-drop-readable
                (canon stream.drop-readable $bytes))
              (core func $stream-drop-readable-words
                (canon stream.drop-readable $words))
              (core func $stream-drop-writable
                (canon stream.drop-writable $bytes))
              (core func $future-new (canon future.new $future))
              (core func $future-drop-readable
                (canon future.drop-readable $future))
              (core func $future-drop-writable
                (canon future.drop-writable $future))
              (core func $waitable-set-new (canon waitable-set.new))
              (core func $waitable-set-drop (canon waitable-set.drop))
              (core func $waitable-join (canon waitable.join))

              (core instance $builtins
                (export "task-return" (func $task-return))
                (export "task-cancel" (func $task-cancel))
                (export "stream-new" (func $stream-new))
                (export "stream-drop-readable" (func $stream-drop-readable))
                (export "stream-drop-readable-words"
                  (func $stream-drop-readable-words))
                (export "stream-drop-writable" (func $stream-drop-writable))
                (export "future-new" (func $future-new))
                (export "future-drop-readable" (func $future-drop-readable))
                (export "future-drop-writable" (func $future-drop-writable))
                (export "waitable-set-new" (func $waitable-set-new))
                (export "waitable-set-drop" (func $waitable-set-drop))
                (export "waitable-join" (func $waitable-join)))

              (core module $guest
                (import "vibe:async" "task-return" (func $task-return))
                (import "vibe:async" "task-cancel" (func $task-cancel))
                (import "vibe:async" "stream-new"
                  (func $stream-new (result i64)))
                (import "vibe:async" "stream-drop-readable"
                  (func $stream-drop-readable (param i32)))
                (import "vibe:async" "stream-drop-readable-words"
                  (func $stream-drop-readable-words (param i32)))
                (import "vibe:async" "stream-drop-writable"
                  (func $stream-drop-writable (param i32)))
                (import "vibe:async" "future-new"
                  (func $future-new (result i64)))
                (import "vibe:async" "future-drop-readable"
                  (func $future-drop-readable (param i32)))
                (import "vibe:async" "future-drop-writable"
                  (func $future-drop-writable (param i32)))
                (import "vibe:async" "waitable-set-new"
                  (func $waitable-set-new (result i32)))
                (import "vibe:async" "waitable-set-drop"
                  (func $waitable-set-drop (param i32)))
                (import "vibe:async" "waitable-join"
                  (func $waitable-join (param i32 i32)))
                (memory $state 1 1)
                (func (export "run") (result i32)
                  (local $pair i64)
                  (local $set i32)
                  {run_body}
                  call $task-return
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
              (export "run" (func $lifted)))"#
        )
    }

    fn byte_stream_component(run: &str, callback: &str) -> String {
        replace_once(
            &replace_once(
                SMOKE,
                "    (func (export \"run\") (result i32)\n      call $task-return\n      i32.const 1)",
                run,
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            callback,
        )
    }

    fn close_future_component(run: &str, callback: &str) -> String {
        replace_once(
            &byte_stream_component(run, callback),
            "  (type $closed (future u32))",
            r#"  (type $close-reason
    (enum "normal" "failure" "cancelled" "denied" "unavailable"
      "exhausted" "invalid" "backend-fault"))
  (type $closed (future $close-reason))"#,
        )
    }

    fn trap_call(component: &mut NativeAsyncComponent) -> TrapCode {
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Trapped(trap) => return trap,
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("invalid handle fixture unexpectedly waited")
                }
                NativeAsyncPoll::Complete(_) => panic!("invalid handle fixture completed"),
            }
        }
    }

    fn assert_exact_run_bridge_debits(call: &mut NativeAsyncInvocation<'_>) -> usize {
        let active = call.binding().core_instance;
        let mut handle_transitions = 0;
        loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => {
                    let action = call.component.bridges[host.id as usize].action;
                    let expected = match action {
                        BridgeAction::TaskReturn(_) => TASK_RETURN_WORK,
                        BridgeAction::StreamNew(_)
                        | BridgeAction::FutureNew(_)
                        | BridgeAction::DropEndpoint { .. }
                        | BridgeAction::WaitableSetNew
                        | BridgeAction::WaitableSetDrop
                        | BridgeAction::WaitableJoin => {
                            handle_transitions += 1;
                            HANDLE_STATE_WORK
                        }
                        BridgeAction::StreamCopy { .. }
                        | BridgeAction::StreamCancel { .. }
                        | BridgeAction::FutureCopy { .. }
                        | BridgeAction::FutureCancel { .. } => {
                            handle_transitions += 1;
                            BUFFER_BRIDGE_WORK
                        }
                        BridgeAction::Unsupported => {
                            panic!("fixture reached an unsupported bridge")
                        }
                    };
                    let before = call.metrics();
                    let progress = call.handle_host_call(CallAuthority::Run(active), host);
                    if matches!(action, BridgeAction::TaskReturn(_)) {
                        assert!(matches!(progress, NativeAsyncPoll::Resolved(_)));
                    } else {
                        assert!(matches!(progress, NativeAsyncPoll::Pending(_)));
                    }
                    let after = call.metrics();
                    assert_eq!(before.remaining_work - after.remaining_work, expected);
                    assert_eq!(after.consumed_work - before.consumed_work, expected);
                }
                PollResult::Ready(values) => {
                    let before = call.metrics();
                    assert!(matches!(
                        call.handle_callback_result(values.as_slice()),
                        NativeAsyncPoll::Yielded(_)
                    ));
                    let after = call.metrics();
                    assert_eq!(
                        before.remaining_work - after.remaining_work,
                        CALLBACK_RESULT_WORK
                    );
                    assert_eq!(
                        after.consumed_work - before.consumed_work,
                        CALLBACK_RESULT_WORK
                    );
                    return handle_transitions;
                }
                PollResult::Trapped(trap) => panic!("run trapped before callback: {trap:?}"),
            }
        }
    }

    fn finish_yielded_call(call: &mut NativeAsyncInvocation<'_>) {
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
        loop {
            match call.poll() {
                NativeAsyncPoll::Complete(_) => return,
                NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Resolved(_) => {}
                NativeAsyncPoll::Yielded(_) => panic!("callback unexpectedly yielded"),
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("callback unexpectedly waited")
                }
                NativeAsyncPoll::Trapped(trap) => panic!("callback trapped: {trap:?}"),
            }
        }
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
        assert!(call.settle_metrics(CallAuthority::Run(run_instance)));
        let before_yield = call.metrics();
        let PollResult::Ready(values) = run else {
            panic!("the resumed smoke run must return YIELD")
        };
        assert!(matches!(
            call.handle_callback_result(values.as_slice()),
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
    fn native_filter_receives_nonzero_inputs_and_atomically_returns_the_exact_pair() {
        let mut component = instantiate(FILTER);
        assert_eq!(
            component.start("run", WORK, QUANTUM).err(),
            Some(NativeAsyncError::UnsupportedFeature)
        );
        assert!(!component.is_poisoned());

        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let input = call.input.as_ref().expect("filter input authorities");
        let stream_raw = input.first.guest.raw();
        let closed_raw = input.second.guest.raw();
        assert_ne!(stream_raw, 0);
        assert_ne!(closed_raw, 0);
        assert_ne!(stream_raw, closed_raw);

        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Resolved(_) => break,
                other => panic!("filter must resolve its exact output pair: {other:?}"),
            }
        }
        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("filter binding lost its exact contract")
        };
        assert_eq!(
            call.output_stream.as_ref().unwrap().value_type(),
            contract.stream
        );
        assert_eq!(
            call.output_closed.as_ref().unwrap().value_type(),
            contract.closed
        );
        assert_eq!(call.task_info().result, TaskResultState::Resolved);

        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Complete(_) => break,
                other => panic!("filter callback must exit cleanly: {other:?}"),
            }
        }
        assert!(call.output_stream.is_some());
        assert!(call.output_closed.is_some());
        assert!(!call.component.is_poisoned());
        drop(call);

        // Until the host-pending transport consumes the retained linear
        // authorities, a completed validation-only filter is deliberately
        // one-shot rather than silently leaking arena capacity across reuse.
        assert!(component.is_poisoned());
        assert_eq!(
            component.start_filter("run", WORK, QUANTUM).err(),
            Some(NativeAsyncError::Poisoned)
        );
    }

    #[test]
    fn repeated_filter_task_return_is_canonical_abi_misuse_without_a_second_transfer() {
        let source = replace_once(
            FILTER,
            "          local.get $input-bytes\n          local.get $input-closed\n          call $task-return\n          i32.const 1",
            "          local.get $input-bytes\n          local.get $input-closed\n          call $task-return\n          local.get $input-bytes\n          local.get $input-closed\n          call $task-return\n          i32.const 1",
        );
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::Resolved(_) => break,
                other => panic!("first filter result must resolve: {other:?}"),
            }
        }
        assert!(call.output_stream.is_some());
        assert!(call.output_closed.is_some());
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi) => break,
                other => panic!("duplicate filter result must fail closed: {other:?}"),
            }
        }
        // Fail-stop consumed the exact first result tokens. The duplicate was
        // classified before any second handle resolution or transfer.
        assert!(call.output_stream.is_none());
        assert!(call.output_closed.is_none());
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn malformed_filter_task_return_does_not_partially_detach_the_stream() {
        let source = replace_once(
            FILTER,
            "          local.get $input-bytes\n          local.get $input-closed\n          call $task-return",
            "          local.get $input-bytes\n          i32.const 0\n          call $task-return",
        );
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi) => break,
                other => panic!("bad result handle must trap: {other:?}"),
            }
        }
        assert!(call.output_stream.is_none());
        assert!(call.output_closed.is_none());
        // Fail-stop can discard the exact untouched input aggregate only if
        // the failed fixed-pair detach left *both* guest handles in place.
        // This observes atomicity without moving either host authority out of
        // its invocation owner.
        assert!(call.input.is_none());
    }

    fn assert_filter_contract_rejected_before_core_entry(source: &str) {
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

    #[test]
    fn adjacent_native_filter_shapes_are_rejected_before_core_entry() {
        let extra_parameter = replace_once(
            &replace_once(
                FILTER,
                "(func async (param \"input\" $byte-stream) (result $byte-stream))",
                "(func async (param \"input\" $byte-stream) (param \"extra\" u32) (result $byte-stream))",
            ),
            "(param $input-bytes i32) (param $input-closed i32) (result i32)",
            "(param $input-bytes i32) (param $input-closed i32) (param i32) (result i32)",
        );
        let missing_parameter = filter_core_without_inputs("(func async (result $byte-stream))");
        let reversed_record = replace_once(
            FILTER,
            "(record (field \"bytes\" $bytes) (field \"closed\" $closed))",
            "(record (field \"closed\" $closed) (field \"bytes\" $bytes))",
        );
        let u16_stream = replace_once(
            FILTER,
            "(type $bytes-private (stream u8))",
            "(type $bytes-private (stream u16))",
        );
        let enum7 = replace_once(
            FILTER,
            "\"exhausted\" \"invalid\" \"backend-fault\"))",
            "\"exhausted\" \"invalid\"))",
        );
        let enum9 = replace_once(
            FILTER,
            "\"exhausted\" \"invalid\" \"backend-fault\"))",
            "\"exhausted\" \"invalid\" \"backend-fault\" \"other\"))",
        );

        let different_result_ids = replace_once(
            &FILTER.replace("(result $byte-stream)", "(result $byte-stream-output)"),
            "      (type $run-type",
            r#"      (type $close-reason-output-private
        (enum "other-normal" "failure" "cancelled" "denied" "unavailable"
          "exhausted" "invalid" "backend-fault"))
      (import "close-reason-output"
        (type $close-reason-output (eq $close-reason-output-private)))
      (type $closed-output-private (future $close-reason-output))
      (import "closed-output"
        (type $closed-output (eq $closed-output-private)))
      (type $byte-stream-output-private
        (record (field "bytes" $bytes) (field "closed" $closed-output)))
      (import "byte-stream-output"
        (type $byte-stream-output (eq $byte-stream-output-private)))
      (type $run-type"#,
        );

        for source in [
            extra_parameter,
            missing_parameter,
            reversed_record,
            u16_stream,
            enum7,
            enum9,
            different_result_ids,
        ] {
            assert_filter_contract_rejected_before_core_entry(&source);
        }
    }

    #[test]
    fn task_return_record_names_are_admission_metadata_not_runtime_authority() {
        let source = replace_once(
            FILTER,
            "      (core func $task-return\n        (canon task.return (result $byte-stream)))",
            r#"      (type $canonical-result
        (record (field "foo" $bytes) (field "bar" $closed)))
      (core func $task-return
        (canon task.return (result $canonical-result)))"#,
        );
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Resolved(_) => break,
                other => {
                    panic!("canonical name-only alias must retain endpoint identity: {other:?}")
                }
            }
        }
        assert!(call.output_stream.is_some());
        assert!(call.output_closed.is_some());
        // Field names are checked on the exported WIT world by admission.
        // This executor boundary deliberately compares only fixed order and
        // the exact stream/future identities that carry linear authority.
        drop(call);
        assert!(component.is_poisoned());
    }

    #[test]
    fn filter_core_start_failure_rolls_back_task_and_both_input_pairs() {
        let mut component = instantiate(FILTER);
        let RuntimeExportContract::ByteStream(contract) = component.exports[0].contract else {
            panic!("filter fixture must have the exact contract")
        };
        component.exports[0].core_function = String::from("missing");
        assert_eq!(
            component.start_filter("run", WORK, QUANTUM).err(),
            Some(NativeAsyncError::InvalidWiring)
        );
        assert!(!component.is_poisoned());
        assert!(!component.modules.any_active_call());
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);

        // Task capacity is one, so this succeeds only if the failed start
        // removed its exact task seal.
        let task = component.state.create_task().unwrap();
        component.state.abort_task(task).unwrap();

        // Each aggregate consumes two handle and two pair slots. Filling the
        // complete advertised capacity proves neither failed input survived.
        let mut retained = Vec::new();
        for _ in 0..PROFILE_1_LIMITS.max_resources / 2 {
            retained.push(
                component
                    .state
                    .insert_host_readables_pair(
                        (EndpointKind::Stream, contract.stream),
                        (EndpointKind::Future, contract.closed),
                    )
                    .unwrap(),
            );
        }
        assert!(matches!(
            component.state.insert_host_readables_pair(
                (EndpointKind::Stream, contract.stream),
                (EndpointKind::Future, contract.closed),
            ),
            Err(AsyncStateError::HandleTableFull | AsyncStateError::PairTableFull)
        ));
        drop(retained);
    }

    #[test]
    fn filter_input_capacity_failure_removes_the_task_without_poisoning() {
        let mut component = instantiate(FILTER);
        let RuntimeExportContract::ByteStream(contract) = component.exports[0].contract else {
            panic!("filter fixture must have the exact contract")
        };
        let mut retained = Vec::new();
        for _ in 0..PROFILE_1_LIMITS.max_resources / 2 {
            retained.push(
                component
                    .state
                    .insert_host_readables_pair(
                        (EndpointKind::Stream, contract.stream),
                        (EndpointKind::Future, contract.closed),
                    )
                    .unwrap(),
            );
        }
        assert_eq!(
            component.start_filter("run", WORK, QUANTUM).err(),
            Some(NativeAsyncError::InvalidWiring)
        );
        assert!(!component.is_poisoned());
        assert!(!component.modules.any_active_call());
        let task = component.state.create_task().unwrap();
        component.state.abort_task(task).unwrap();
        drop(retained);
    }

    #[test]
    fn non_filter_result_or_memory_bearing_task_return_is_rejected_before_guest_entry() {
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
        assert_eq!(component.callback_slots.len(), component.exports.len());
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);
        let first = assert_smoke_sequence(&mut component);
        assert!(first.consumed_work > 0);
        assert!(!component.is_poisoned());
        let second = assert_smoke_sequence(&mut component);
        assert_eq!(first.consumed_work, second.consumed_work);
        assert!(!component.is_poisoned());
    }

    #[test]
    fn callback_slot_generation_survives_invocations_and_three_yield_rounds() {
        let source = replace_once(
            &replace_once(
                SMOKE,
                "      call $task-return\n      i32.const 1",
                "      i32.const 0\n      i32.const 0\n      i32.store\n      call $task-return\n      i32.const 1",
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0
      i32.const 0
      i32.load
      i32.const 1
      i32.add
      i32.store
      i32.const 0
      i32.load
      i32.const 4
      i32.lt_u)"#,
        );
        let mut component = instantiate(&source);
        let generation = component.callback_slots[0].generation();

        for _ in 0..2 {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            let run_instance = call.binding().core_instance;
            let run_values = loop {
                let result = call.component.modules.poll_call(run_instance);
                assert!(call.settle_metrics(CallAuthority::Run(run_instance)));
                match result {
                    PollResult::Pending { .. } => {}
                    PollResult::Ready(values) => break values,
                    other => panic!("expected repeated fixture run result, got {other:?}"),
                }
            };
            let before = call.metrics();
            assert!(matches!(
                call.handle_callback_result(run_values.as_slice()),
                NativeAsyncPoll::Yielded(_)
            ));
            let after = call.metrics();
            assert_eq!(
                before.remaining_work - after.remaining_work,
                CALLBACK_RESULT_WORK
            );
            assert_eq!(
                after.consumed_work - before.consumed_work,
                CALLBACK_RESULT_WORK
            );
            let mut callback_results = 0;
            let mut callback_yields = 0;
            loop {
                assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
                assert_eq!(
                    call.component.callback_slots[call.export].state(),
                    CoreCallSlotState::Active
                );
                let values = loop {
                    let result = call
                        .component
                        .modules
                        .poll_call_slot(&mut call.component.callback_slots[call.export]);
                    assert!(call.settle_metrics(CallAuthority::Callback));
                    match result {
                        CoreSlotPollResult::Pending { .. } => {}
                        CoreSlotPollResult::Ready(values) => break values,
                        other => {
                            panic!("expected repeated fixture callback result, got {other:?}")
                        }
                    }
                };
                let before = call.metrics();
                let progress = call.handle_callback_result(values.as_slice());
                let after = call.metrics();
                assert_eq!(
                    before.remaining_work - after.remaining_work,
                    CALLBACK_RESULT_WORK
                );
                assert_eq!(
                    after.consumed_work - before.consumed_work,
                    CALLBACK_RESULT_WORK
                );
                callback_results += 1;
                assert_eq!(
                    call.component.callback_slots[call.export].state(),
                    CoreCallSlotState::Idle
                );
                assert_eq!(
                    call.component.callback_slots[call.export].generation(),
                    generation
                );
                match progress {
                    NativeAsyncPoll::Yielded(_) => callback_yields += 1,
                    NativeAsyncPoll::Complete(_) => break,
                    other => {
                        panic!("unexpected repeated callback progress: {other:?}")
                    }
                }
            }
            assert_eq!(callback_yields, 3);
            assert_eq!(callback_results, 4, "three YIELDs plus one EXIT");
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Idle
            );
        }

        assert_eq!(component.callback_slots[0].generation(), generation);
        assert!(!component.is_poisoned());
    }

    #[test]
    fn yielded_owner_cancel_is_delivered_once_and_late_requests_are_stable() {
        let source = replace_once(
            &replace_once(
                SMOKE,
                "      call $task-return\n      i32.const 1",
                "      i32.const 4\n      i32.const 0\n      i32.store\n      i32.const 1",
            ),
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            r#"    (func (export "callback") (param $event i32) (param $p1 i32) (param $p2 i32) (result i32)
      i32.const 4
      i32.load
      if (result i32)
        local.get $event
        i32.eqz
        local.get $p1
        i32.eqz
        i32.and
        local.get $p2
        i32.eqz
        i32.and
        if (result i32)
          i32.const 0
        else
          i32.const 3
        end
      else
        local.get $event
        i32.const 6
        i32.eq
        local.get $p1
        i32.eqz
        i32.and
        local.get $p2
        i32.eqz
        i32.and
        if (result i32)
          call $task-return
          i32.const 4
          i32.const 1
          i32.store
          i32.const 1
        else
          i32.const 3
        end
      end)"#,
        );
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();

        assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
        assert_eq!(call.task_info().cancel, TaskCancelState::None);
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        assert_eq!(call.task_info().cancel, TaskCancelState::Requested);
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        assert!(!call.component.is_poisoned());

        // The selector runs on this exact Yielded -> poll boundary and the
        // selected event is passed immediately to the reusable callback.
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
        assert_eq!(call.task_info().cancel, TaskCancelState::Delivered);
        assert_eq!(call.request_cancel(), Ok(NativeAsyncCancelOutcome::TooLate));
        assert_eq!(call.task_info().cancel, TaskCancelState::Delivered);
        assert!(!call.component.is_poisoned());

        let mut saw_resolved = false;
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("cancel delivery fixture unexpectedly waited")
                }
                NativeAsyncPoll::Resolved(_) => {
                    saw_resolved = true;
                    assert_eq!(call.task_info().result, TaskResultState::Resolved);
                    assert_eq!(call.task_info().cancel, TaskCancelState::None);
                    assert_eq!(call.request_cancel(), Ok(NativeAsyncCancelOutcome::TooLate));
                    assert_eq!(call.request_cancel(), Ok(NativeAsyncCancelOutcome::TooLate));
                    assert!(!call.component.is_poisoned());
                }
                NativeAsyncPoll::Complete(_) => break,
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("cancel delivery callback trapped: {trap:?}")
                }
            }
        }
        assert!(saw_resolved);
        assert!(!call.component.is_poisoned());
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::AlreadyTerminal)
        );
    }

    #[test]
    fn exhausted_yield_does_not_run_or_mutate_the_callback_selector() {
        let source = replace_once(
            SMOKE,
            "      call $task-return\n      i32.const 1",
            "      i32.const 1",
        );
        let exact_yield_work = {
            let mut component = instantiate(&source);
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let NativeAsyncPoll::Yielded(metrics) = call.poll() else {
                panic!("unresolved run must yield")
            };
            metrics.consumed_work
        };
        assert!(exact_yield_work > CALLBACK_RESULT_WORK);

        let mut component = instantiate(&source);
        let mut call = component
            .start("run", exact_yield_work, exact_yield_work)
            .unwrap();
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::Yielded(NativeAsyncMetrics {
                consumed_work: exact_yield_work,
                remaining_work: 0,
            })
        );
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        assert_eq!(call.task_info().cancel, TaskCancelState::Requested);
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
        assert_eq!(
            call.component.state.task_info(call.task).err(),
            Some(AsyncStateError::StaleHandle)
        );
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        assert!(!call.component.modules.any_active_call());
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::AlreadyTerminal)
        );
    }

    #[test]
    fn canonical_transitions_debit_the_shared_ledger_exactly_once() {
        let mut component = instantiate(SMOKE);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let run_instance = call.binding().core_instance;
        let host = call.component.modules.poll_call(run_instance);
        assert!(call.settle_metrics(CallAuthority::Run(run_instance)));
        let before_return = call.metrics();
        let PollResult::HostCall(host) = host else {
            panic!("the smoke run must stop at task.return")
        };
        assert!(matches!(
            call.handle_host_call(CallAuthority::Run(run_instance), host),
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
        let callback = call
            .component
            .modules
            .poll_call_slot(&mut call.component.callback_slots[call.export]);
        assert!(call.settle_metrics(CallAuthority::Callback));
        let before_callback_result = call.metrics();
        let CoreSlotPollResult::Ready(values) = callback else {
            panic!("the smoke callback must finish with EXIT")
        };
        assert!(matches!(
            call.handle_callback_result(values.as_slice()),
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
    fn callback_host_calls_use_only_exact_slot_authority_and_shared_fuel() {
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
              i32.const 1)
            (func (export "callback") (param i32 i32 i32) (result i32)
              call $resolve
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
        let mut component = instantiate(source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
        assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));

        let callback_instance = call.binding().callback_instance;
        let host = loop {
            let result = call
                .component
                .modules
                .poll_call_slot(&mut call.component.callback_slots[call.export]);
            assert!(call.settle_metrics(CallAuthority::Callback));
            match result {
                CoreSlotPollResult::Pending { .. } => {}
                CoreSlotPollResult::HostCall(host) => break host,
                other => panic!("expected transitive callback task.return, got {other:?}"),
            }
        };
        assert!(matches!(
            call.component.bridges[host.id as usize].action,
            BridgeAction::TaskReturn(RuntimeExportContract::Unit)
        ));
        assert_ne!(host.origin_instance, callback_instance);
        let exact_before = call
            .component
            .modules
            .call_metrics_slot(&call.component.callback_slots[call.export])
            .unwrap();

        // Every ordinary authority rejects the slot-owned continuation and
        // leaves the exact slot metrics and pending host call untouched.
        assert_eq!(call.component.modules.call_metrics(callback_instance), None);
        assert_eq!(
            call.component.modules.debit_call_fuel(callback_instance, 1),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            call.component
                .modules
                .credit_call_fuel(callback_instance, 1),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            call.component
                .modules
                .resume_host_call(callback_instance, host.id, &[]),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            call.component.modules.cancel_call(callback_instance),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            call.component.modules.discard_call(callback_instance),
            Err(TrapCode::Validation)
        );
        assert_eq!(
            call.component
                .modules
                .call_metrics_slot(&call.component.callback_slots[call.export]),
            Some(exact_before)
        );

        let before = call.metrics();
        assert!(matches!(
            call.handle_host_call(CallAuthority::Callback, host),
            NativeAsyncPoll::Resolved(_)
        ));
        let after = call.metrics();
        assert_eq!(
            before.remaining_work - after.remaining_work,
            TASK_RETURN_WORK
        );
        assert_eq!(after.consumed_work - before.consumed_work, TASK_RETURN_WORK);

        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::Complete(_) => break,
                NativeAsyncPoll::Resolved(_) | NativeAsyncPoll::Yielded(_) => {
                    panic!("callback host-call fixture surfaced unexpected progress")
                }
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("callback host-call fixture unexpectedly waited")
                }
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("callback host-call fixture trapped: {trap:?}")
                }
            }
        }
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
    }

    #[test]
    fn component_handle_state_persists_across_invocations_with_exact_fuel() {
        let source = handle_component(
            r#"i32.const 8
                  i32.load
                  if
                    call $waitable-set-new
                    local.set $set
                    i32.const 0
                    i64.load
                    i32.wrap_i64
                    local.get $set
                    call $waitable-join
                    i32.const 0
                    i64.load
                    i32.wrap_i64
                    i32.const 0
                    call $waitable-join
                    local.get $set
                    call $waitable-set-drop
                    i32.const 0
                    i64.load
                    i32.wrap_i64
                    call $stream-drop-readable
                    i32.const 0
                    i64.load
                    i64.const 32
                    i64.shr_u
                    i32.wrap_i64
                    call $stream-drop-writable
                  else
                    i32.const 0
                    call $stream-new
                    i64.store
                    i32.const 8
                    i32.const 1
                    i32.store
                  end"#,
        );
        let mut component = instantiate(&source);

        {
            let mut first = component.start("run", WORK, QUANTUM).unwrap();
            assert_eq!(assert_exact_run_bridge_debits(&mut first), 1);
            finish_yielded_call(&mut first);
        }
        assert!(!component.is_poisoned());

        {
            let mut second = component.start("run", WORK, QUANTUM).unwrap();
            assert_eq!(assert_exact_run_bridge_debits(&mut second), 6);
            finish_yielded_call(&mut second);
        }
        assert!(!component.is_poisoned());
    }

    #[test]
    fn future_handle_actions_are_classified_and_readable_drop_executes() {
        let source = handle_component(
            r#"call $future-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $future-drop-readable"#,
        );
        let mut component = instantiate(&source);
        assert!(component.bridges.iter().any(|bridge| matches!(
            bridge.action,
            BridgeAction::DropEndpoint {
                kind: EndpointKind::Future,
                direction: EndpointDirection::Write,
                ..
            }
        )));
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert_eq!(assert_exact_run_bridge_debits(&mut call), 2);
        finish_yielded_call(&mut call);
    }

    #[test]
    fn future_writer_drop_requires_a_write_terminal_even_after_reader_drop() {
        let source = handle_component(
            r#"call $future-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $future-drop-readable
                  local.get $pair
                  i64.const 32
                  i64.shr_u
                  i32.wrap_i64
                  call $future-drop-writable"#,
        );
        let mut component = instantiate(&source);
        assert_eq!(trap_call(&mut component), TrapCode::CanonicalAbi);
        assert!(component.is_poisoned());
    }

    #[test]
    fn byte_stream_bridges_activate_while_future_copy_and_task_cancel_stay_sealed() {
        let smoke = instantiate(SMOKE);
        assert_eq!(
            smoke
                .bridges
                .iter()
                .filter(|bridge| bridge.action == BridgeAction::Unsupported)
                .count(),
            4
        );
        assert_eq!(
            smoke
                .bridges
                .iter()
                .filter(|bridge| matches!(bridge.action, BridgeAction::StreamCopy { .. }))
                .count(),
            2
        );
        assert_eq!(
            smoke
                .bridges
                .iter()
                .filter(|bridge| matches!(bridge.action, BridgeAction::StreamCancel { .. }))
                .count(),
            2
        );
        assert!(smoke
            .bridges
            .iter()
            .filter(|bridge| matches!(bridge.action, BridgeAction::StreamCopy { .. }))
            .all(|bridge| bridge.memory.is_some()));

        let mut task_cancel = instantiate(&handle_component("call $task-cancel"));
        assert_eq!(trap_call(&mut task_cancel), TrapCode::CanonicalAbi);
        assert!(task_cancel.is_poisoned());
    }

    #[test]
    fn future_copy_classification_is_exactly_the_generic_enum8_abi_shape() {
        let base = close_future_component(
            r#"    (func (export "run") (result i32)
      call $task-return
      i32.const 1)"#,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let pinned = r#"(enum "normal" "failure" "cancelled" "denied" "unavailable"
      "exhausted" "invalid" "backend-fault")"#;
        let adjacent = replace_once(&base, pinned, r#"(enum "a" "b" "c" "d" "e" "f" "g" "h")"#);
        for source in [&base, &adjacent] {
            let component = instantiate(source);
            assert_eq!(
                component
                    .bridges
                    .iter()
                    .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCopy { .. }))
                    .count(),
                2
            );
            assert_eq!(
                component
                    .bridges
                    .iter()
                    .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCancel { .. }))
                    .count(),
                2
            );
        }

        for rejected in [
            r#"(enum "a" "b" "c" "d" "e" "f" "g")"#,
            r#"(enum "a" "b" "c" "d" "e" "f" "g" "h" "i")"#,
        ] {
            let component = instantiate(&replace_once(&base, pinned, rejected));
            assert_eq!(
                component
                    .bridges
                    .iter()
                    .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCopy { .. }))
                    .count(),
                0
            );
            assert_eq!(
                component
                    .bridges
                    .iter()
                    .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCancel { .. }))
                    .count(),
                0
            );
            assert_eq!(
                component
                    .bridges
                    .iter()
                    .filter(|bridge| bridge.action == BridgeAction::Unsupported)
                    .count(),
                4
            );
        }
    }

    #[test]
    fn close_reason_future_copies_one_byte_and_reclaims_both_sides() {
        let run = r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $future-new
      local.set $pair
      i32.const 16
      i32.const 6
      i32.store8
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      call $future-write
      i32.const -1
      i32.ne
      if unreachable end
      local.get $pair
      i32.wrap_i64
      i32.const 24
      call $future-read
      if unreachable end
      i32.const 24
      i32.load8_u
      i32.const 6
      i32.ne
      if unreachable end
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $future-cancel-write
      if unreachable end
      local.get $pair
      i32.wrap_i64
      call $future-drop-readable
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $future-drop-writable
      call $task-return
      i32.const 1)"#;
        let source = close_future_component(
            run,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate(&source);
        assert_eq!(
            component
                .bridges
                .iter()
                .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCopy { .. }))
                .count(),
            2
        );
        assert_eq!(
            component
                .bridges
                .iter()
                .filter(|bridge| matches!(bridge.action, BridgeAction::FutureCancel { .. }))
                .count(),
            2
        );
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            loop {
                match call.poll() {
                    NativeAsyncPoll::Pending(_)
                    | NativeAsyncPoll::Resolved(_)
                    | NativeAsyncPoll::Yielded(_) => {}
                    NativeAsyncPoll::Complete(_) => break,
                    NativeAsyncPoll::WaitPending { .. } => {
                        panic!("local close future unexpectedly waited")
                    }
                    NativeAsyncPoll::Trapped(trap) => {
                        panic!("local close future trapped: {trap:?}")
                    }
                }
            }
        }
        assert_eq!(component.buffers.live(), 0);
        let mut close_reason = [0xff];
        component
            .modules
            .read_memory(0, "memory", 24, &mut close_reason)
            .unwrap();
        assert_eq!(close_reason, [6]);
    }

    #[test]
    fn close_reason_future_rejects_a_discriminant_changed_after_blocking() {
        let run = r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $future-new
      local.set $pair
      i32.const 24
      i32.const 170
      i32.store8
      i32.const 16
      i32.const 6
      i32.store8
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      call $future-write
      i32.const -1
      i32.ne
      if unreachable end
      i32.const 16
      i32.const 255
      i32.store8
      local.get $pair
      i32.wrap_i64
      i32.const 24
      call $future-read
      drop
      unreachable)"#;
        let source = close_future_component(
            run,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      unreachable)"#,
        );
        let mut component = instantiate(&source);
        assert_eq!(trap_call(&mut component), TrapCode::CanonicalAbi);
        assert!(component.is_poisoned());
        assert_eq!(component.buffers.live(), 0);
        let mut target = [0_u8];
        component
            .modules
            .read_memory(0, "memory", 24, &mut target)
            .unwrap();
        assert_eq!(target, [0xaa]);
    }

    #[test]
    fn byte_stream_local_copy_uses_min_progress_and_reclaims_both_sides() {
        let run = r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      i32.const 16
      i32.const 67305985
      i32.store
      i32.const 24
      i32.const -1431655766
      i32.store
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      i32.const 4
      call $stream-write
      i32.const -1
      i32.ne
      if unreachable end
      local.get $pair
      i32.wrap_i64
      i32.const 24
      i32.const 2
      call $stream-read
      i32.const 32
      i32.ne
      if unreachable end
      i32.const 24
      i32.load16_u
      i32.const 513
      i32.ne
      if unreachable end
      i32.const 26
      i32.load16_u
      i32.const 43690
      i32.ne
      if unreachable end
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $stream-cancel-write
      i32.const 32
      i32.ne
      if unreachable end
      call $task-return
      i32.const 1)"#;
        let source = byte_stream_component(
            run,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate(&source);
        let metrics = {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            loop {
                match call.poll() {
                    NativeAsyncPoll::Complete(metrics) => break metrics,
                    NativeAsyncPoll::Pending(_)
                    | NativeAsyncPoll::Resolved(_)
                    | NativeAsyncPoll::Yielded(_) => {}
                    NativeAsyncPoll::WaitPending { .. } => {
                        panic!("local byte-stream fixture unexpectedly waited")
                    }
                    NativeAsyncPoll::Trapped(trap) => {
                        panic!("local byte-stream fixture trapped: {trap:?}")
                    }
                }
            }
        };
        assert!(metrics.consumed_work >= 3 * BUFFER_BRIDGE_WORK);
        assert_eq!(component.buffers.live(), 0);
        assert!(!component.buffers.is_poisoned());
        let mut copied = [0_u8; 4];
        component
            .modules
            .read_memory(0, "memory", 24, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 0xaa, 0xaa]);
    }

    #[test]
    fn endpoint_wait_reclaims_before_callback_can_reuse_the_same_stream_end() {
        let run = r#"    (func (export "run") (result i32)
      (local $pair i64)
      (local $set i32)
      call $stream-new
      local.set $pair
      i32.const 8
      local.get $pair
      i32.wrap_i64
      i32.store
      i32.const 4
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.store
      call $waitable-set-new
      local.set $set
      i32.const 0
      local.get $set
      i32.store
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      local.get $set
      call $waitable-join
      i32.const 16
      i32.const 67305985
      i32.store
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      i32.const 4
      call $stream-write
      i32.const -1
      i32.ne
      if unreachable end
      local.get $pair
      i32.wrap_i64
      i32.const 24
      i32.const 4
      call $stream-read
      i32.const 64
      i32.ne
      if unreachable end
      i32.const 1)"#;
        let callback = r#"    (func (export "callback")
      (param $event i32) (param $p1 i32) (param $p2 i32) (result i32)
      local.get $event
      i32.eqz
      if (result i32)
        i32.const 0
        i32.load
        i32.const 4
        i32.shl
        i32.const 2
        i32.or
      else
        i32.const 12
        i32.const 1
        i32.store
        local.get $event
        i32.const 3
        i32.ne
        if unreachable end
        local.get $p1
        i32.const 4
        i32.load
        i32.ne
        if unreachable end
        local.get $p2
        i32.const 64
        i32.ne
        if unreachable end
        i32.const 4
        i32.load
        i32.const 0
        call $waitable-join
        i32.const 4
        i32.load
        i32.const -1
        i32.const 0
        call $stream-write
        i32.const -1
        i32.ne
        if unreachable end
        i32.const 4
        i32.load
        call $stream-cancel-write
        i32.const 2
        i32.ne
        if unreachable end
        i32.const 8
        i32.load
        call $stream-drop-readable
        i32.const 4
        i32.load
        call $stream-drop-writable
        i32.const 0
        i32.load
        call $waitable-set-drop
        call $task-return
        i32.const 0
      end)"#;
        let source = byte_stream_component(run, callback);
        let mut component = instantiate(&source);
        let mut observed_reclaim_boundary = false;
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            loop {
                let before_live = call.component.buffers.live();
                let progress = call.poll();
                let after_live = call.component.buffers.live();
                if !observed_reclaim_boundary && before_live == 1 && after_live == 0 {
                    assert!(matches!(progress, NativeAsyncPoll::Pending(_)));
                    assert!(matches!(call.stage, InvocationStage::Callback));
                    assert_eq!(
                        call.component.callback_slots[call.export].state(),
                        CoreCallSlotState::Active
                    );
                    let mut marker = [0_u8; 4];
                    call.component
                        .modules
                        .read_memory(0, "memory", 12, &mut marker)
                        .unwrap();
                    assert_eq!(marker, [0; 4]);
                    observed_reclaim_boundary = true;
                }
                match progress {
                    NativeAsyncPoll::Complete(_) => break,
                    NativeAsyncPoll::Pending(_)
                    | NativeAsyncPoll::Resolved(_)
                    | NativeAsyncPoll::Yielded(_) => {}
                    NativeAsyncPoll::WaitPending { .. } => {
                        panic!("ready endpoint wait must start its callback immediately")
                    }
                    NativeAsyncPoll::Trapped(trap) => {
                        panic!("endpoint wait fixture trapped: {trap:?}")
                    }
                }
            }
        }
        assert!(observed_reclaim_boundary);
        assert_eq!(component.buffers.live(), 0);
        assert!(!component.buffers.is_poisoned());
        let mut copied = [0_u8; 4];
        component
            .modules
            .read_memory(0, "memory", 24, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4]);
        let mut marker = [0_u8; 4];
        component
            .modules
            .read_memory(0, "memory", 12, &mut marker)
            .unwrap();
        assert_eq!(marker, 1_u32.to_le_bytes());
    }

    #[test]
    fn byte_stream_zero_count_and_hostile_ranges_have_pinned_traps() {
        let zero = byte_stream_component(
            r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const -1
      i32.const 0
      call $stream-write
      i32.const -1
      i32.ne
      if unreachable end
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $stream-cancel-write
      i32.const 2
      i32.ne
      if unreachable end
      call $task-return
      i32.const 1)"#,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate(&zero);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            loop {
                match call.poll() {
                    NativeAsyncPoll::Complete(_) => break,
                    NativeAsyncPoll::Pending(_)
                    | NativeAsyncPoll::Resolved(_)
                    | NativeAsyncPoll::Yielded(_) => {}
                    NativeAsyncPoll::WaitPending { .. } => panic!("zero copy unexpectedly waited"),
                    NativeAsyncPoll::Trapped(trap) => panic!("zero copy trapped: {trap:?}"),
                }
            }
        }
        assert_eq!(component.buffers.live(), 0);

        for (pointer, elements, expected) in [
            (65_536, 1, TrapCode::MemoryOutOfBounds),
            (0, 1_u32 << 28, TrapCode::LimitExceeded),
        ] {
            let run = format!(
                r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const {pointer}
      i32.const {elements}
      call $stream-write
      drop
      i32.const 1)"#
            );
            let source = byte_stream_component(
                &run,
                r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
            );
            let mut component = instantiate(&source);
            assert_eq!(trap_call(&mut component), expected);
            assert_eq!(component.buffers.live(), 0);
            assert!(component.buffers.is_poisoned());
        }
    }

    #[test]
    fn busy_stream_copy_state_precedes_hostile_range_and_bridge_fuel() {
        for (pointer, elements) in [(65_536, 1), (0, 1_u32 << 28)] {
            let run = format!(
                r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      i32.const 1
      call $stream-write
      drop
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const {pointer}
      i32.const {elements}
      call $stream-write
      drop
      i32.const 1)"#
            );
            let source = byte_stream_component(
                &run,
                r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
            );
            let mut component = instantiate(&source);
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let active = call.binding().core_instance;
            let authority = CallAuthority::Run(active);
            let mut writes = 0;

            loop {
                let result = call.component.modules.poll_call(active);
                assert!(call.settle_metrics(authority));
                match result {
                    PollResult::Pending { .. } => {}
                    PollResult::HostCall(host) => {
                        let action = call.component.bridges[host.id as usize].action;
                        if matches!(
                            action,
                            BridgeAction::StreamCopy {
                                direction: EndpointDirection::Write,
                                ..
                            }
                        ) {
                            writes += 1;
                            if writes == 2 {
                                assert_eq!(call.component.buffers.live(), 1);
                                let before = call.metrics();
                                assert_eq!(
                                    call.handle_host_call(authority, host),
                                    NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                                );
                                assert_eq!(call.metrics(), before);
                                break;
                            }
                        }
                        assert!(matches!(
                            call.handle_host_call(authority, host),
                            NativeAsyncPoll::Pending(_)
                        ));
                    }
                    PollResult::Ready(_) => panic!("busy copy fixture unexpectedly returned"),
                    PollResult::Trapped(trap) => {
                        panic!("busy copy fixture trapped before the second write: {trap:?}")
                    }
                }
            }

            assert_eq!(writes, 2);
            assert!(call.component.is_poisoned());
            assert!(call.component.buffers.is_poisoned());
            assert_eq!(call.component.buffers.live(), 0);
        }
    }

    #[test]
    fn invalid_stream_cancel_state_precedes_bridge_fuel() {
        let fixtures = [
            (
                r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $stream-cancel-write
      drop
      i32.const 1)"#,
                0,
            ),
            (
                r#"    (func (export "run") (result i32)
      (local $pair i64)
      (local $set i32)
      call $stream-new
      local.set $pair
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const -1
      i32.const 0
      call $stream-write
      drop
      call $waitable-set-new
      local.set $set
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      local.get $set
      call $waitable-join
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $stream-cancel-write
      drop
      i32.const 1)"#,
                1,
            ),
        ];

        for (run, live_before_cancel) in fixtures {
            let source = byte_stream_component(
                run,
                r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
            );
            let mut component = instantiate(&source);
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let active = call.binding().core_instance;
            let authority = CallAuthority::Run(active);

            loop {
                let result = call.component.modules.poll_call(active);
                assert!(call.settle_metrics(authority));
                match result {
                    PollResult::Pending { .. } => {}
                    PollResult::HostCall(host) => {
                        let action = call.component.bridges[host.id as usize].action;
                        if matches!(action, BridgeAction::StreamCancel { .. }) {
                            assert_eq!(call.component.buffers.live(), live_before_cancel);
                            let excess = call
                                .metrics()
                                .remaining_work
                                .checked_sub(BUFFER_BRIDGE_WORK)
                                .unwrap();
                            call.debit_active_work(authority, excess).unwrap();
                            let before = call.metrics();
                            assert_eq!(before.remaining_work, BUFFER_BRIDGE_WORK);
                            assert_eq!(
                                call.handle_host_call(authority, host),
                                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                            );
                            assert_eq!(call.metrics(), before);
                            break;
                        }
                        assert!(matches!(
                            call.handle_host_call(authority, host),
                            NativeAsyncPoll::Pending(_)
                                | NativeAsyncPoll::Resolved(_)
                                | NativeAsyncPoll::Yielded(_)
                        ));
                    }
                    PollResult::Ready(_) => panic!("invalid cancel fixture unexpectedly returned"),
                    PollResult::Trapped(trap) => {
                        panic!("invalid cancel fixture trapped before cancel: {trap:?}")
                    }
                }
            }

            assert!(call.component.is_poisoned());
            assert!(call.component.buffers.is_poisoned());
            assert_eq!(call.component.buffers.live(), 0);
        }
    }

    #[test]
    fn byte_stream_transfer_fuel_is_reserved_before_the_first_memory_write() {
        let source = byte_stream_component(
            r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      i32.const 16
      i32.const 67305985
      i32.store
      i32.const 24
      i32.const -1431655766
      i32.store
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      i32.const 4
      call $stream-write
      drop
      local.get $pair
      i32.wrap_i64
      i32.const 24
      i32.const 4
      call $stream-read
      drop
      i32.const 1)"#,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let authority = CallAuthority::Run(active);
        loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(authority));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => {
                    let action = call.component.bridges[host.id as usize].action;
                    if matches!(
                        action,
                        BridgeAction::StreamCopy {
                            direction: EndpointDirection::Read,
                            ..
                        }
                    ) {
                        assert_eq!(call.component.buffers.live(), 1);
                        let transfer =
                            buffer_copy_work(4, call.component.buffers.scratch_bytes()).unwrap();
                        let tight = BUFFER_BRIDGE_WORK + transfer;
                        let excess = call.metrics().remaining_work.checked_sub(tight).unwrap();
                        call.debit_active_work(authority, excess).unwrap();
                        let before = call.metrics();
                        assert_eq!(
                            call.handle_host_call(authority, host),
                            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
                        );
                        let after = call.metrics();
                        assert_eq!(
                            before.remaining_work - after.remaining_work,
                            BUFFER_BRIDGE_WORK
                        );
                        break;
                    }
                    assert!(matches!(
                        call.handle_host_call(authority, host),
                        NativeAsyncPoll::Pending(_)
                    ));
                }
                PollResult::Ready(_) => panic!("copy fuel fixture unexpectedly returned"),
                PollResult::Trapped(trap) => panic!("copy fuel fixture trapped early: {trap:?}"),
            }
        }
        assert!(call.component.is_poisoned());
        assert!(call.component.buffers.is_poisoned());
        assert_eq!(call.component.buffers.live(), 0);
        assert!(!call.component.modules.any_active_call());
        let mut target = [0_u8; 4];
        call.component
            .modules
            .read_memory(0, "memory", 24, &mut target)
            .unwrap();
        assert_eq!(target, [0xaa; 4]);
    }

    #[test]
    fn runtime_state_errors_preserve_guest_limit_and_invariant_classes() {
        for error in [
            AsyncStateError::AllocationFailed,
            AsyncStateError::HandleTableFull,
            AsyncStateError::PairTableFull,
            AsyncStateError::WaitableSetFull,
            AsyncStateError::TaskTableFull,
        ] {
            assert_eq!(map_runtime_state_error(error), TrapCode::LimitExceeded);
        }
        for error in [
            AsyncStateError::PairInvariant,
            AsyncStateError::WrongState,
            AsyncStateError::StaleOperation,
            AsyncStateError::StaleEvent,
            AsyncStateError::StaleWait,
        ] {
            assert_eq!(map_runtime_state_error(error), TrapCode::Validation);
        }
        for error in [
            AsyncStateError::InvalidHandle,
            AsyncStateError::StaleHandle,
            AsyncStateError::WrongHandleKind,
            AsyncStateError::WrongEndpointKind,
            AsyncStateError::WrongDirection,
            AsyncStateError::WrongType,
            AsyncStateError::DropWhileCopying,
        ] {
            assert_eq!(map_runtime_state_error(error), TrapCode::CanonicalAbi);
        }
        assert_eq!(
            map_sealed_state_error(AsyncStateError::StaleHandle),
            TrapCode::Validation
        );
        for error in [
            AsyncStateError::InvalidHandle,
            AsyncStateError::StaleHandle,
            AsyncStateError::WrongState,
            AsyncStateError::WrongHandleKind,
            AsyncStateError::WrongEndpointKind,
            AsyncStateError::WrongDirection,
            AsyncStateError::WrongType,
        ] {
            assert_eq!(map_exact_endpoint_state_error(error), TrapCode::Validation);
        }
        for error in [
            AsyncStateError::EndpointBusy,
            AsyncStateError::EndpointDone,
            AsyncStateError::OperationNotCopying,
            AsyncStateError::CancelWhileJoined,
        ] {
            assert_eq!(
                map_exact_endpoint_state_error(error),
                TrapCode::CanonicalAbi
            );
        }
        assert_eq!(
            map_callback_yield_error(AsyncStateError::TaskAlreadyExited),
            TrapCode::Validation
        );
        assert_eq!(
            map_callback_yield_error(AsyncStateError::AlreadyWaiting),
            TrapCode::Validation
        );
        for error in [
            AsyncStateError::InvalidHandle,
            AsyncStateError::StaleHandle,
            AsyncStateError::WrongHandleKind,
            AsyncStateError::WrongState,
            AsyncStateError::WaitableSetWaiting,
            AsyncStateError::AlreadyWaiting,
        ] {
            assert_eq!(map_callback_wait_begin_error(error), TrapCode::Validation);
            assert_eq!(map_callback_wait_resume_error(error), TrapCode::Validation);
        }
        assert_eq!(
            map_callback_wait_begin_error(AsyncStateError::GenerationExhausted),
            TrapCode::LimitExceeded
        );
        assert_eq!(
            map_callback_wait_resume_error(AsyncStateError::WaitableSetFull),
            TrapCode::LimitExceeded
        );
    }

    #[test]
    fn full_handle_arena_traps_as_limit_after_exact_transition_debit() {
        let source = handle_component("call $stream-new\n                  drop");
        let mut component = instantiate(&source);
        let value_type = component
            .bridges
            .iter()
            .find_map(|bridge| match bridge.action {
                BridgeAction::StreamNew(value_type) => Some(value_type),
                _ => None,
            })
            .unwrap();
        assert_eq!(PROFILE_1_LIMITS.max_resources % 2, 0);
        for _ in 0..PROFILE_1_LIMITS.max_resources / 2 {
            component.state.create_stream_pair(value_type).unwrap();
        }

        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let active = call.binding().core_instance;
            let host = loop {
                let result = call.component.modules.poll_call(active);
                assert!(call.settle_metrics(CallAuthority::Run(active)));
                match result {
                    PollResult::Pending { .. } => {}
                    PollResult::HostCall(host) => break host,
                    other => panic!("expected stream.new host call, got {other:?}"),
                }
            };
            let before = call.metrics();
            assert_eq!(
                call.handle_host_call(CallAuthority::Run(active), host),
                NativeAsyncPoll::Trapped(TrapCode::LimitExceeded)
            );
            let after = call.metrics();
            assert_eq!(
                before.remaining_work - after.remaining_work,
                HANDLE_STATE_WORK
            );
            assert_eq!(
                after.consumed_work - before.consumed_work,
                HANDLE_STATE_WORK
            );
        }
        assert!(component.is_poisoned());
    }

    #[test]
    fn wrong_handle_kind_endpoint_kind_direction_type_stale_and_raw_handles_fail_stop() {
        let invalid_bodies = [
            r#"call $waitable-set-new
                  call $stream-drop-readable"#,
            r#"call $stream-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $future-drop-readable"#,
            r#"call $stream-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $stream-drop-writable"#,
            r#"call $stream-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $stream-drop-readable-words"#,
            r#"call $stream-new
                  local.set $pair
                  local.get $pair
                  i32.wrap_i64
                  call $stream-drop-readable
                  local.get $pair
                  i32.wrap_i64
                  call $stream-drop-readable"#,
            r#"i32.const -1
                  call $stream-drop-readable"#,
        ];
        for body in invalid_bodies {
            let mut component = instantiate(&handle_component(body));
            assert_eq!(trap_call(&mut component), TrapCode::CanonicalAbi);
            assert!(component.is_poisoned());
        }
    }

    #[test]
    fn dropping_a_nonempty_waitable_set_fails_stop() {
        let source = handle_component(
            r#"call $stream-new
                  local.set $pair
                  call $waitable-set-new
                  local.set $set
                  local.get $pair
                  i32.wrap_i64
                  local.get $set
                  call $waitable-join
                  local.get $set
                  call $waitable-set-drop"#,
        );
        let mut component = instantiate(&source);
        assert_eq!(trap_call(&mut component), TrapCode::CanonicalAbi);
        assert!(component.is_poisoned());
    }

    #[test]
    fn fabricated_bridge_value_shape_is_an_executor_validation_failure() {
        let source = handle_component("call $stream-new\n                  drop");
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let mut host = loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => break host,
                other => panic!("expected stream.new host call, got {other:?}"),
            }
        };
        host.arguments.push(CoreValue::I32(0));
        let before = call.metrics();
        assert_eq!(
            call.handle_host_call(CallAuthority::Run(active), host),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        assert_eq!(call.metrics(), before);
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn post_commit_resume_failure_preserves_the_runtime_trap_class() {
        let source = handle_component("call $waitable-set-new\n                  drop");
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let host = loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => break host,
                other => panic!("expected waitable-set.new host call, got {other:?}"),
            }
        };

        // Seal a correctly typed response first so the dispatcher reaches a
        // post-state-commit duplicate-resume invariant instead of a guest ABI
        // error. The runtime's Validation class must survive fail-stop.
        call.component
            .modules
            .resume_host_call(active, host.id, &[CoreValue::I32(1)])
            .unwrap();
        let before = call.metrics();
        assert_eq!(
            call.handle_host_call(CallAuthority::Run(active), host),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        let after = call.metrics();
        assert_eq!(
            before.remaining_work - after.remaining_work,
            HANDLE_STATE_WORK
        );
        assert_eq!(
            after.consumed_work - before.consumed_work,
            HANDLE_STATE_WORK
        );
        assert!(call.component.is_poisoned());
        assert!(!call.component.modules.any_active_call());
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
    fn dynamically_mismatched_supported_task_return_contract_traps_canonical_abi() {
        let source = filter_core_without_inputs("(func async)");
        let mut component = instantiate(&source);
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
            "      i32.const 1\n      call $stream-cancel-read\n      drop\n      call $task-return\n      i32.const 1",
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
    fn invalid_zero_wait_handle_restores_slot_before_poison() {
        let source = replace_once(
            SMOKE,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 2)",
        );
        let mut component = instantiate(&source);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
            );
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Idle
            );
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());
    }

    #[test]
    fn empty_callback_wait_has_a_stable_zero_cost_poll_token() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, blocked_metrics) = poll_to_wait(&mut call);
        assert!(call.task_info().waiting);
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        assert!(!call.component.modules.any_active_call());

        for _ in 0..3 {
            assert_eq!(
                call.poll(),
                NativeAsyncPoll::WaitPending {
                    token,
                    metrics: blocked_metrics,
                }
            );
            assert_eq!(call.metrics(), blocked_metrics);
            assert!(call.task_info().waiting);
        }
    }

    #[test]
    fn exact_wait_resume_charges_once_rotates_and_rejects_stale_or_foreign_tokens() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut foreign_component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let mut foreign_call = foreign_component.start("run", WORK, QUANTUM).unwrap();
        let (token, blocked_metrics) = poll_to_wait(&mut call);
        let (foreign, _) = poll_to_wait(&mut foreign_call);
        assert_ne!(token, foreign);

        assert_eq!(
            call.resume_wait(foreign),
            Err(NativeAsyncControlError::InvalidWaitToken)
        );
        assert_eq!(call.metrics(), blocked_metrics);
        let NativeAsyncPoll::WaitPending {
            token: rotated,
            metrics: resumed_metrics,
        } = call.resume_wait(token).unwrap()
        else {
            panic!("empty wait must remain blocked")
        };
        assert_ne!(rotated, token);
        assert_eq!(
            blocked_metrics.remaining_work - resumed_metrics.remaining_work,
            WAIT_STATE_WORK
        );
        assert_eq!(
            resumed_metrics.consumed_work - blocked_metrics.consumed_work,
            WAIT_STATE_WORK
        );

        assert_eq!(
            call.resume_wait(token),
            Err(NativeAsyncControlError::InvalidWaitToken)
        );
        assert_eq!(call.metrics(), resumed_metrics);
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::WaitPending {
                token: rotated,
                metrics: resumed_metrics,
            }
        );

        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::WaitPending {
                token: rotated,
                metrics: resumed_metrics,
            }
        );
        assert_eq!(call.task_info().cancel, TaskCancelState::Requested);
        let before_cancel_resume = call.metrics();
        assert!(matches!(
            call.resume_wait(rotated),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        assert_eq!(
            before_cancel_resume.remaining_work - call.metrics().remaining_work,
            WAIT_STATE_WORK
        );
        assert_eq!(call.task_info().cancel, TaskCancelState::Delivered);
        assert_eq!(
            call.resume_wait(rotated),
            Err(NativeAsyncControlError::NotWaiting)
        );
        finish_cancelled_wait_callback(&mut call);
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        assert!(call.wait_ticket.is_none());
        assert!(call.wait_token.is_none());
        assert!(!call.component.is_poisoned());
        let old_invocation_token = rotated;
        drop(call);

        let mut next_call = component.start("run", WORK, QUANTUM).unwrap();
        let (next_token, next_metrics) = poll_to_wait(&mut next_call);
        assert_ne!(next_token, old_invocation_token);
        assert_eq!(
            next_call.resume_wait(old_invocation_token),
            Err(NativeAsyncControlError::InvalidWaitToken)
        );
        assert_eq!(next_call.metrics(), next_metrics);
    }

    #[test]
    fn cancellation_before_wait_is_selected_and_started_immediately() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        let mut saw_delivered = false;
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) | NativeAsyncPoll::Resolved(_) => {
                    if let Ok(info) = call.component.state.task_info(call.task) {
                        saw_delivered |= info.cancel == TaskCancelState::Delivered;
                    }
                }
                NativeAsyncPoll::Complete(_) => break,
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("pre-WAIT cancellation must not park")
                }
                NativeAsyncPoll::Yielded(_) => panic!("WAIT fixture unexpectedly yielded"),
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("pre-WAIT cancellation callback trapped: {trap:?}")
                }
            }
        }
        assert!(saw_delivered);
        drop(call);
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);
        assert!(!component.is_poisoned());
    }

    #[test]
    fn resolved_tasks_can_wait_but_owner_cancellation_is_too_late() {
        let source = wait_component(
            true,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
        );
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, metrics) = poll_to_wait(&mut call);
        assert_eq!(call.task_info().result, TaskResultState::Resolved);
        assert_eq!(call.request_cancel(), Ok(NativeAsyncCancelOutcome::TooLate));
        let NativeAsyncPoll::WaitPending {
            token: rotated,
            metrics: resumed,
        } = call.resume_wait(token).unwrap()
        else {
            panic!("resolved empty wait must remain pending")
        };
        assert_ne!(rotated, token);
        assert_eq!(
            metrics.remaining_work - resumed.remaining_work,
            WAIT_STATE_WORK
        );
        assert_eq!(call.request_cancel(), Ok(NativeAsyncCancelOutcome::TooLate));
        assert!(call.task_info().waiting);
    }

    #[test]
    fn invalid_and_wrong_kind_wait_sets_trap_before_selector_fuel() {
        let invalid = replace_once(
            SMOKE,
            "    (func (export \"run\") (result i32)\n      call $task-return\n      i32.const 1)",
            "    (func (export \"run\") (result i32)\n      i32.const 2)",
        );
        let wrong_kind = replace_once(
            SMOKE,
            "    (func (export \"run\") (result i32)\n      call $task-return\n      i32.const 1)",
            r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      local.get $pair
      i32.wrap_i64
      i32.const 4
      i32.shl
      i32.const 2
      i32.or)"#,
        );

        for source in [invalid, wrong_kind] {
            let mut component = instantiate(&source);
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let active = call.binding().core_instance;
            loop {
                let result = call.component.modules.poll_call(active);
                assert!(call.settle_metrics(CallAuthority::Run(active)));
                match result {
                    PollResult::Pending { .. } => {}
                    PollResult::HostCall(host) => assert!(matches!(
                        call.handle_host_call(CallAuthority::Run(active), host),
                        NativeAsyncPoll::Pending(_)
                    )),
                    PollResult::Ready(values) => {
                        let before = call.metrics();
                        assert_eq!(
                            call.handle_callback_result(values.as_slice()),
                            NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                        );
                        let after = call.metrics();
                        assert_eq!(
                            before.remaining_work - after.remaining_work,
                            CALLBACK_RESULT_WORK
                        );
                        assert_eq!(
                            after.consumed_work - before.consumed_work,
                            CALLBACK_RESULT_WORK
                        );
                        break;
                    }
                    PollResult::Trapped(trap) => panic!("wait handle fixture trapped: {trap:?}"),
                }
            }
        }
    }

    #[test]
    fn blocked_wait_drop_and_trap_cancel_ticket_abort_task_and_poison() {
        for trap in [false, true] {
            let source = wait_component(false, cancellation_exit_callback());
            let mut component = instantiate(&source);
            let (task, set) = {
                let mut call = component.start("run", WORK, QUANTUM).unwrap();
                let _ = poll_to_wait(&mut call);
                let set = call.component.state.resolve_guest_waitable_set(1).unwrap();
                let task = call.task;
                if trap {
                    assert_eq!(
                        call.finish_trap(TrapCode::Validation),
                        NativeAsyncPoll::Trapped(TrapCode::Validation)
                    );
                }
                (task, set)
            };
            assert!(component.is_poisoned());
            assert!(!component.modules.any_active_call());
            assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);
            assert_eq!(
                component.state.task_info(task).err(),
                Some(AsyncStateError::StaleHandle)
            );
            component.state.drop_waitable_set(set).unwrap();
        }
    }

    #[test]
    fn endpoint_wait_reclaim_failure_drains_copy_state_before_poison() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, blocked) = poll_to_wait(&mut call);
        let set = call.component.state.resolve_guest_waitable_set(1).unwrap();
        let value_type = AsyncValueTypeId::new(99).unwrap();
        let pair = call.component.state.create_stream_pair(value_type).unwrap();
        call.component
            .state
            .join_waitable(pair.readable, set.raw())
            .unwrap();
        call.component
            .state
            .drop_endpoint(
                pair.writable,
                EndpointKind::Stream,
                EndpointDirection::Write,
                value_type,
            )
            .unwrap();
        assert!(matches!(
            call.component.state.begin_copy(
                pair.readable,
                EndpointKind::Stream,
                EndpointDirection::Read,
                value_type,
                BufferLease::issue(1, 1, 1, 4).unwrap(),
            ),
            Ok(CopyBegin::Ready(_))
        ));

        assert_eq!(
            call.resume_wait(token),
            Ok(NativeAsyncPoll::Trapped(TrapCode::Validation))
        );
        assert_eq!(
            blocked.remaining_work - call.metrics().remaining_work,
            WAIT_STATE_WORK
        );
        let endpoint = call.component.state.endpoint_info(pair.readable).unwrap();
        assert!(!endpoint.has_pending_event);
        assert!(!endpoint.event_delivered);
        assert_eq!(endpoint.copy_state, crate::async_state::CopyState::Done);
        assert_eq!(call.component.buffers.live(), 0);
        assert!(call.component.buffers.is_poisoned());
        assert_eq!(
            call.component.state.task_info(call.task).err(),
            Some(AsyncStateError::StaleHandle)
        );
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn wait_selector_fuel_is_precharged_without_consuming_begin_or_resume_state() {
        let source = wait_component(false, cancellation_exit_callback());

        // Begin: stop with the decoded Core result in hand, then leave exactly
        // the selector charge after CALLBACK_RESULT_WORK. The required one
        // unit callback reserve makes selection fail before registration or
        // cancellation delivery.
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let values = loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => assert!(matches!(
                    call.handle_host_call(CallAuthority::Run(active), host),
                    NativeAsyncPoll::Pending(_)
                )),
                PollResult::Ready(values) => break values,
                PollResult::Trapped(trap) => panic!("WAIT begin fixture trapped: {trap:?}"),
            }
        };
        let set = call.component.state.resolve_guest_waitable_set(1).unwrap();
        let task = call.task;
        call.remaining_work = CALLBACK_RESULT_WORK + WAIT_STATE_WORK;
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        let before = call.metrics();
        assert_eq!(
            call.handle_callback_result(values.as_slice()),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
        let after = call.metrics();
        assert_eq!(
            before.remaining_work - after.remaining_work,
            CALLBACK_RESULT_WORK
        );
        assert_eq!(after.remaining_work, WAIT_STATE_WORK);
        assert_eq!(
            call.component.state.task_info(task).err(),
            Some(AsyncStateError::StaleHandle)
        );
        call.component.state.drop_waitable_set(set).unwrap();
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        drop(call);

        // Resume: an exact token with no spare callback unit spends nothing
        // and teardown cancels the still-live registration before aborting the
        // task, so the set can be dropped cleanly.
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, _) = poll_to_wait(&mut call);
        let set = call.component.state.resolve_guest_waitable_set(1).unwrap();
        let task = call.task;
        call.remaining_work = WAIT_STATE_WORK;
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        let before = call.metrics();
        assert_eq!(
            call.resume_wait(token),
            Ok(NativeAsyncPoll::Trapped(TrapCode::FuelExhausted))
        );
        assert_eq!(call.metrics(), before);
        assert_eq!(
            call.component.state.task_info(task).err(),
            Some(AsyncStateError::StaleHandle)
        );
        call.component.state.drop_waitable_set(set).unwrap();
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
    }

    #[test]
    fn blocked_wait_rejects_corrupt_callback_slot_before_fuel_or_selector_work() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, _) = poll_to_wait(&mut call);
        let inputs = [CoreValue::I32(0), CoreValue::I32(0), CoreValue::I32(0)];
        let (modules, exports, slots) = (
            &mut call.component.modules,
            &call.component.exports,
            &mut call.component.callback_slots,
        );
        let binding = &exports[call.export];
        modules
            .start_call_slot(
                &mut slots[call.export],
                binding.callback_instance,
                &binding.callback,
                &inputs,
                call.remaining_work,
                call.poll_quantum.min(call.remaining_work),
            )
            .unwrap();
        assert_eq!(slots[call.export].state(), CoreCallSlotState::Active);
        let before = call.metrics();
        assert_eq!(
            call.resume_wait(token),
            Ok(NativeAsyncPoll::Trapped(TrapCode::Validation))
        );
        assert_eq!(call.metrics(), before);
        assert_eq!(
            call.component.callback_slots[call.export].state(),
            CoreCallSlotState::Idle
        );
        assert!(!call.component.modules.any_active_call());
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn blocked_wait_missing_internal_authority_is_fail_stop_not_a_control_error() {
        let source = wait_component(false, cancellation_exit_callback());
        let mut component = instantiate(&source);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let (token, _) = poll_to_wait(&mut call);
        call.wait_token = None;
        let before = call.metrics();
        assert_eq!(
            call.resume_wait(token),
            Ok(NativeAsyncPoll::Trapped(TrapCode::Validation))
        );
        assert_eq!(call.metrics(), before);
        assert!(call.component.is_poisoned());
        assert_eq!(
            call.component.state.task_info(call.task).err(),
            Some(AsyncStateError::StaleHandle)
        );
    }

    #[test]
    fn callback_trap_and_drop_clean_up_the_exact_active_slot() {
        let trapping = replace_once(
            SMOKE,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      unreachable)",
        );
        let mut component = instantiate(&trapping);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Trapped(_)));
            assert_eq!(
                call.request_cancel(),
                Ok(NativeAsyncCancelOutcome::AlreadyTerminal)
            );
            assert_eq!(
                call.component.state.task_info(call.task).err(),
                Some(AsyncStateError::StaleHandle)
            );
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Idle
            );
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());

        let mut component = instantiate(SMOKE);
        let generation = component.callback_slots[0].generation();
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Active
            );
            // Drop invokes exact discard_call_slot before the principal-wide
            // fallback; no slot-owned active call is orphaned.
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);
        assert_eq!(component.callback_slots[0].generation(), generation);

        let host_calling = replace_once(
            SMOKE,
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      i32.const 0)",
            "    (func (export \"callback\") (param i32 i32 i32) (result i32)\n      call $waitable-set-new\n      drop\n      i32.const 0)",
        );
        let mut component = instantiate(&host_calling);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            loop {
                let result = call
                    .component
                    .modules
                    .poll_call_slot(&mut call.component.callback_slots[call.export]);
                assert!(call.settle_metrics(CallAuthority::Callback));
                match result {
                    CoreSlotPollResult::Pending { .. } => {}
                    CoreSlotPollResult::HostCall(_) => break,
                    other => panic!("expected suspended callback host call, got {other:?}"),
                }
            }
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Active
            );
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);

        let mut component = instantiate(SMOKE);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Idle
            );
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());
        assert_eq!(component.callback_slots[0].state(), CoreCallSlotState::Idle);
    }

    #[test]
    fn generic_poll_of_callback_slot_fails_closed_without_reusable_storage() {
        let mut component = instantiate(SMOKE);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            assert!(matches!(call.poll(), NativeAsyncPoll::Resolved(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Yielded(_)));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            let callback_instance = call.binding().callback_instance;
            assert_eq!(
                call.component.modules.poll_call(callback_instance),
                PollResult::Trapped(TrapCode::Validation)
            );
            assert_eq!(
                call.finish_trap(TrapCode::Validation),
                NativeAsyncPoll::Trapped(TrapCode::Validation)
            );
            assert_eq!(
                call.component.callback_slots[call.export].state(),
                CoreCallSlotState::Poisoned
            );
        }
        assert!(component.is_poisoned());
        assert!(!component.modules.any_active_call());
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
                        CallAuthority::Run(active),
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
                    NativeAsyncPoll::WaitPending { .. } => {
                        panic!("shared-fuel fixture unexpectedly waited")
                    }
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
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("shared-fuel fixture unexpectedly waited")
                }
            }
        };
        assert_eq!(trap, TrapCode::FuelExhausted);
        assert!(call.metrics().consumed_work <= tight);
    }
}
