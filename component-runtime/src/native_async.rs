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
        AsyncArenaUsage, AsyncState, AsyncStateError, AsyncStateLimits, AsyncStateMetrics,
        CommitError, CopyBegin, EndpointKind, Event, EventLease, EventLeaseState, EventToken,
        HostCopyTicket, HostPeerDropReceipt, HostReadableBindingsPair, NativeFilterFinalizeError,
        ReadableTransferRequest, ReclaimError, TaskCancelState, TaskHandle, TaskResultState,
        TransferredReadableEndpoint, WaitBegin, WaitResume, WaitTicket,
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
use core::num::NonZeroU64;
use vibeos_component_format::{ProfileIdentity, TrapCode, PROFILE_1_LIMITS};
use vibeos_wasm_runtime::{
    CoreCallSlot, CoreCallSlotState, CoreComponentGroup, CoreHostCall, CoreHostImport,
    CoreInstanceExportImport, CoreMemoryAuthority, CoreModuleImport, CoreResults,
    CoreSlotPollResult, CoreValue, CoreValueType, OwnerAllocationReservation, PollResult,
    ProfileEngine, ValidatedCore,
};

/// Versioned Vibe fuel charged for resolving one empty native async result.
const TASK_RETURN_WORK: u64 = 1;
const HANDLE_STATE_SCAN_FACTOR: u64 = 8;
/// Versioned conservative passes used by fail-stop reclamation.
///
/// The handle-derived term covers the pair, handle, buffer, transferred-token,
/// wait, and task walks. Callback slots and Core instances are then charged
/// separately from the exact instantiated graph shape.
const FAIL_STOP_CORE_INSTANCE_FACTOR: u64 = 2;
/// Fixed work for committing one local byte-stream transfer.
const BUFFER_COPY_BASE_WORK: u64 = 1;
/// Versioned Vibe fuel charged for decoding and committing one callback code.
const CALLBACK_RESULT_WORK: u64 = 1;

/// Versioned work schedule derived from one Component's admitted async arena.
///
/// Pair creation can scan each bounded pair/handle table while preparing and
/// inserting, and a reserve can move their existing entries (at most seven
/// `resource_limit`-sized passes in total). Join, joined-endpoint drop, and
/// wait selection scan the same fixed arena. The fixed dispatch/commit unit is
/// included in every public cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAsyncWorkCosts {
    pub handle_state: u64,
    pub buffer_state: u64,
    pub buffer_bridge: u64,
    pub wait_state: u64,
}

impl NativeAsyncWorkCosts {
    const fn from_resource_limit(resource_limit: u32) -> Self {
        let handle_state = 1 + HANDLE_STATE_SCAN_FACTOR * resource_limit as u64;
        let buffer_state = 1 + resource_limit as u64;
        Self {
            handle_state,
            buffer_state,
            buffer_bridge: handle_state + buffer_state,
            wait_state: handle_state,
        }
    }
}

fn fail_stop_cleanup_work(
    work_costs: NativeAsyncWorkCosts,
    core_instances: usize,
    callback_slots: usize,
) -> Option<u64> {
    let core_instances = u64::try_from(core_instances).ok()?;
    let callback_slots = u64::try_from(callback_slots).ok()?;
    work_costs
        .handle_state
        .checked_add(callback_slots)?
        .checked_add(core_instances.checked_mul(FAIL_STOP_CORE_INSTANCE_FACTOR)?)
}

/// Identity-free current, peak, and configured native async storage counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAsyncStorageMetrics {
    pub async_state: AsyncStateMetrics,
    pub buffers: AsyncArenaUsage,
}

#[cfg(test)]
const PROFILE_WORK_COSTS: NativeAsyncWorkCosts =
    NativeAsyncWorkCosts::from_resource_limit(PROFILE_1_LIMITS.max_resources);
#[cfg(test)]
const HANDLE_STATE_WORK: u64 = PROFILE_WORK_COSTS.handle_state;
#[cfg(test)]
const BUFFER_BRIDGE_WORK: u64 = PROFILE_WORK_COSTS.buffer_bridge;
#[cfg(test)]
const WAIT_STATE_WORK: u64 = PROFILE_WORK_COSTS.wait_state;

#[cfg(test)]
use crate::async_state::TaskInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NativeAsyncError {
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
    NotValidationCandidate = 12,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeAsyncMetrics {
    pub consumed_work: u64,
    pub remaining_work: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncPoll {
    Pending(NativeAsyncMetrics),
    Resolved(NativeAsyncMetrics),
    Yielded(NativeAsyncMetrics),
    WaitPending {
        token: NativeAsyncWaitToken,
        metrics: NativeAsyncMetrics,
    },
    HostPending {
        token: NativeAsyncHostToken,
        request: NativeAsyncHostRequest,
        metrics: NativeAsyncMetrics,
    },
    Complete(NativeAsyncMetrics),
    /// Fail-stop authority is already fenced, but bounded reclamation must run
    /// after one owner-visible quantum boundary.
    CleanupPending {
        trap: TrapCode,
        metrics: NativeAsyncMetrics,
    },
    Trapped(TrapCode),
}

/// Exact owner authority for one native guest/host copy transition.
///
/// The task seal prevents cross-invocation reuse and the non-zero generation
/// rotates at every two-phase driver transition. Private fields make tokens
/// unforgeable outside this executor module.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NativeAsyncHostToken {
    task: TaskHandle,
    generation: NonZeroU64,
}

impl core::fmt::Debug for NativeAsyncHostToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeAsyncHostToken(<opaque>)")
    }
}

impl NativeAsyncHostToken {
    /// Prove strict rotation within one opaque native task seal without
    /// exposing either identity or numeric generation to the kernel adapter.
    pub fn strictly_after(self, previous: Self) -> bool {
        self.task == previous.task && self.generation > previous.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncHostRequest {
    InputStream { maximum: u32 },
    InputClosed,
    OutputStream { maximum: u32 },
    OutputClosed { value: Option<u8> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncHostError {
    InvalidToken,
    NotPending,
    WrongRequest,
    WrongPhase,
    InvalidProgress,
}

/// Exact owner authority for one blocked callback wait.
///
/// The task seal binds the token to one Component instance and invocation;
/// the monotonically increasing generation prevents reuse across successive
/// waits by the same task. Fields remain private so callers cannot forge it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NativeAsyncWaitToken {
    task: TaskHandle,
    generation: u64,
}

impl core::fmt::Debug for NativeAsyncWaitToken {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("NativeAsyncWaitToken(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncCancelOutcome {
    Requested,
    TooLate,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncControlError {
    Invariant,
    InvalidWaitToken,
    NotWaiting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAsyncFinalizeError {
    NotReady,
    AlreadyFinalized,
    WrongContract,
    Poisoned,
    /// Terminal finalization detected an executor invariant after paying its
    /// own bounded turn. Authority is fenced; one later poll must pay the
    /// separately reserved cleanup charge and return the matching trap.
    CleanupPending {
        trap: TrapCode,
        metrics: NativeAsyncMetrics,
    },
}

pub struct NativeAsyncComponent {
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
    work_costs: NativeAsyncWorkCosts,
    fail_stop_cleanup_work: u64,
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
        manifest_memory_bytes: usize,
        manifest_resource_limit: u32,
    ) -> Result<Self, NativeAsyncError> {
        if !plan.native_async_runtime_ready() {
            return Err(NativeAsyncError::AsyncUnavailable);
        }
        Self::instantiate_sealed(
            plan,
            engine,
            reservation_per_module,
            manifest_memory_bytes,
            manifest_resource_limit,
        )
    }

    /// Instantiates only the still-inert native async validation candidate.
    ///
    /// This constructor is deliberately available only to the acceptance
    /// façade. It neither consults nor changes a production activation bit;
    /// instead it rejects a plan that claims to be runtime-ready and applies
    /// the manifest-selected memory and async-arena ceilings directly to the
    /// Core stores and every canonical state registry.
    #[cfg(feature = "native-async-acceptance")]
    pub fn instantiate_validation_candidate_with_memory_limit(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
        manifest_memory_bytes: usize,
        manifest_resource_limit: u32,
    ) -> Result<Self, NativeAsyncError> {
        if plan.native_async_runtime_ready() {
            return Err(NativeAsyncError::NotValidationCandidate);
        }
        Self::instantiate_sealed(
            plan,
            engine,
            reservation_per_module,
            manifest_memory_bytes,
            manifest_resource_limit,
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
            PROFILE_1_LIMITS.max_resources,
        )
    }

    fn instantiate_sealed(
        plan: &ComponentPlan<'_>,
        engine: &ProfileEngine,
        reservation_per_module: OwnerAllocationReservation,
        memory_bytes: usize,
        resource_limit: u32,
    ) -> Result<Self, NativeAsyncError> {
        if plan.profile() != ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE {
            return Err(NativeAsyncError::AsyncUnavailable);
        }
        if resource_limit == 0 || resource_limit > PROFILE_1_LIMITS.max_resources {
            return Err(NativeAsyncError::InvalidBudget);
        }
        let execution = plan
            .native_async_execution_plan()
            .ok_or(NativeAsyncError::InvalidWiring)?;
        let work_costs = NativeAsyncWorkCosts::from_resource_limit(resource_limit);
        let fail_stop_cleanup_work = fail_stop_cleanup_work(
            work_costs,
            execution.instances().len(),
            execution.exports().len(),
        )
        .ok_or(NativeAsyncError::InvalidBudget)?;
        // Classify every canonical bridge and reject unsupported exported
        // lifts before a Core module is instantiated. Core start functions
        // are guest execution; linked-but-disabled builtins remain fail-closed.
        let mut bridges = runtime_bridges(execution)?;
        let exports = runtime_exports(execution)?;
        // Reserve all registry slots and the fixed byte-stream copy scratch
        // before any Core start function can execute during instantiation.
        let buffers = BufferRegistry::new(resource_limit, memory_bytes)
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
            handles: resource_limit,
            pairs: resource_limit,
            tasks: 1,
            waitables_per_set: resource_limit,
        })
        .map_err(map_state_error)?;
        Ok(Self {
            modules,
            exports,
            callback_slots,
            bridges,
            buffers,
            state,
            work_costs,
            fail_stop_cleanup_work,
            poisoned: false,
        })
    }

    /// Return the exact work schedule derived from this Component's ceiling.
    pub const fn work_costs(&self) -> NativeAsyncWorkCosts {
        self.work_costs
    }

    /// Return aggregate storage accounting without exposing runtime identity.
    pub const fn storage_metrics(&self) -> NativeAsyncStorageMetrics {
        NativeAsyncStorageMetrics {
            async_state: self.state.metrics(),
            buffers: self.buffers.usage(),
        }
    }

    /// Minimum public quantum which can make progress through every admitted
    /// native bridge in this Component, including bridges reached through a
    /// transitive Core-instance export. Core execution itself may consume the
    /// complete configured quantum because its outcome is deferred to the next
    /// public turn.
    fn minimum_poll_quantum(&self, _binding: &RuntimeExport) -> Option<u64> {
        let mut required = CALLBACK_RESULT_WORK.max(self.fail_stop_cleanup_work);
        let mut has_waitable_bridge = false;
        for bridge in &self.bridges {
            let work = match bridge.action {
                BridgeAction::TaskReturn(RuntimeExportContract::Unit) => TASK_RETURN_WORK,
                BridgeAction::TaskReturn(RuntimeExportContract::ByteStream(_))
                | BridgeAction::StreamNew(_)
                | BridgeAction::FutureNew(_)
                | BridgeAction::DropEndpoint { .. }
                | BridgeAction::WaitableSetNew
                | BridgeAction::WaitableSetDrop
                | BridgeAction::WaitableJoin => self.work_costs.handle_state,
                BridgeAction::StreamCopy { .. } | BridgeAction::FutureCopy { .. } => self
                    .work_costs
                    .buffer_bridge
                    .checked_add(buffer_copy_work(1, self.buffers.scratch_bytes())?)?,
                BridgeAction::StreamCancel { .. } | BridgeAction::FutureCancel { .. } => {
                    self.work_costs.buffer_bridge
                }
                BridgeAction::Unsupported => 0,
            };
            has_waitable_bridge |= matches!(
                bridge.action,
                BridgeAction::WaitableSetNew
                    | BridgeAction::WaitableSetDrop
                    | BridgeAction::WaitableJoin
            );
            required = required.max(work);
        }
        if has_waitable_bridge {
            required = required.max(CALLBACK_RESULT_WORK.checked_add(self.work_costs.wait_state)?);
        }
        Some(required)
    }

    fn start<'a>(
        &'a mut self,
        export: &str,
        total_work: u64,
        poll_quantum: u64,
    ) -> Result<NativeAsyncInvocation<'a>, NativeAsyncError> {
        // `poll_quantum` bounds both kinds of owner-visible turn. Core gets at
        // most one complete grant, then its outcome is retained; the following
        // poll spends only the corresponding versioned canonical work.
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
        if self
            .minimum_poll_quantum(binding)
            .is_none_or(|minimum| poll_quantum < minimum)
        {
            return Err(NativeAsyncError::InvalidBudget);
        }
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
        let cleanup_reserve = self.fail_stop_cleanup_work;
        let finalize_reserve = 0;
        let execution_work = total_work
            .checked_sub(cleanup_reserve)
            .and_then(|work| work.checked_sub(finalize_reserve))
            .filter(|work| *work != 0)
            .ok_or(NativeAsyncError::InvalidBudget)?;
        self.modules
            .start_call(
                binding.core_instance,
                &binding.core_function,
                &[],
                execution_work,
                poll_quantum.min(execution_work),
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
            active_call_budget: execution_work,
            poll_quantum,
            cleanup_reserve,
            finalize_reserve,
            pending_trap: None,
            deferred_core: None,
            callback_pending: false,
            wait_ticket: None,
            wait_token: None,
            next_wait_generation: 1,
            input: None,
            output_stream: None,
            output_closed: None,
            host_current: None,
            host_next: None,
            host_token: None,
            next_host_generation: 1,
            terminal_drops: NativeFilterTerminalDropLedger::default(),
            transport_finalized: false,
            terminal: false,
        })
    }

    /// Starts the exact resource-free C5.3 byte-stream filter contract.
    ///
    /// This entry point is reachable publicly only through the feature-gated
    /// acceptance façade; the executor module remains private and the profile
    /// identity remains validation-only. Both input endpoints are installed
    /// atomically before Core entry, and no raw handle or host endpoint
    /// authority crosses this executor boundary.
    pub fn start_filter<'a>(
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
        if self
            .minimum_poll_quantum(binding)
            .is_none_or(|minimum| poll_quantum < minimum)
        {
            return Err(NativeAsyncError::InvalidBudget);
        }
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
        let cleanup_reserve = self.fail_stop_cleanup_work;
        // A successful filter has one final owner-visible transport commit;
        // an invariant in that commit then needs a distinct later fail-stop
        // cleanup turn. Keep both worst-case charges out of Core/canonical
        // fuel so neither turn can consume the other's authority.
        let finalize_reserve = self.fail_stop_cleanup_work;
        let execution_work = total_work
            .checked_sub(cleanup_reserve)
            .and_then(|work| work.checked_sub(finalize_reserve))
            .filter(|work| *work != 0)
            .ok_or(NativeAsyncError::InvalidBudget)?;

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
                execution_work,
                poll_quantum.min(execution_work),
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
            active_call_budget: execution_work,
            poll_quantum,
            cleanup_reserve,
            finalize_reserve,
            pending_trap: None,
            deferred_core: None,
            callback_pending: false,
            wait_ticket: None,
            wait_token: None,
            next_wait_generation: 1,
            input: Some(input),
            output_stream: None,
            output_closed: None,
            host_current: None,
            host_next: None,
            host_token: None,
            next_host_generation: 1,
            terminal_drops: NativeFilterTerminalDropLedger::default(),
            transport_finalized: false,
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

/// Selects the largest non-empty stream prefix whose complete local bridge
/// work fits in `available_work`. The schedule is monotonic in `progress`, so
/// this search is bounded by the width of `u32`, not by guest input size.
fn maximum_local_copy_progress(
    limit: u32,
    scratch_bytes: usize,
    available_work: u64,
) -> Option<u32> {
    if limit == 0 || buffer_copy_work(1, scratch_bytes)? > available_work {
        return None;
    }
    let mut low = 1_u32;
    let mut high = limit;
    while low < high {
        let midpoint = low + (high - low) / 2 + 1;
        match buffer_copy_work(midpoint, scratch_bytes) {
            Some(work) if work <= available_work => low = midpoint,
            _ => high = midpoint - 1,
        }
    }
    Some(low)
}

/// Host transport freezes one guest buffer and moves each selected byte once.
/// The Canonical ABI bridge transition was already charged separately.
const fn host_copy_work(progress: u32) -> Option<u64> {
    BUFFER_COPY_BASE_WORK.checked_add(progress as u64)
}

const fn map_host_commit_error(error: CommitError<TrapCode>) -> TrapCode {
    match error {
        CommitError::State(_) => TrapCode::Validation,
        CommitError::Operation(trap) => trap,
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvocationStage {
    Run,
    StartCallback,
    Callback,
    WaitBlocked,
    HostBlocked,
    Cleanup,
    Terminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallAuthority {
    Run(usize),
    Callback,
}

/// One Core outcome retained across the mandatory Core/native turn boundary.
///
/// Core may consume the entire public poll quantum before producing any of
/// these outcomes. Keeping exactly one bounded result here ensures that host
/// bridge work, callback decoding, and fail-stop cleanup begin only on the
/// next owner-visible poll.
enum DeferredCoreTurn {
    Host {
        authority: CallAuthority,
        call: CoreHostCall,
    },
    RunReady(Vec<CoreValue>),
    CallbackReady(CoreResults),
    Trapped(TrapCode),
}

const fn call_stage(authority: CallAuthority) -> InvocationStage {
    match authority {
        CallAuthority::Run(_) => InvocationStage::Run,
        CallAuthority::Callback => InvocationStage::Callback,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostCopyPhase {
    Offered,
    Prepared,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostRequestKind {
    InputStream,
    InputClosed,
    OutputStream,
    OutputClosed,
}

const fn host_request_kind(request: NativeAsyncHostRequest) -> HostRequestKind {
    match request {
        NativeAsyncHostRequest::InputStream { .. } => HostRequestKind::InputStream,
        NativeAsyncHostRequest::InputClosed => HostRequestKind::InputClosed,
        NativeAsyncHostRequest::OutputStream { .. } => HostRequestKind::OutputStream,
        NativeAsyncHostRequest::OutputClosed { .. } => HostRequestKind::OutputClosed,
    }
}

struct PendingHostCopy {
    ticket: HostCopyTicket,
    authority: CallAuthority,
    request: NativeAsyncHostRequest,
    kind: EndpointKind,
    direction: EndpointDirection,
    value_type: AsyncValueTypeId,
    resume_stage: InvocationStage,
    phase: HostCopyPhase,
    limit: u32,
    progress: u32,
    charged: bool,
}

#[derive(Default)]
struct NativeFilterTerminalDropLedger {
    input_stream: Option<HostPeerDropReceipt>,
    output_stream: Option<HostPeerDropReceipt>,
    output_closed: Option<HostPeerDropReceipt>,
}

pub struct NativeAsyncInvocation<'a> {
    component: &'a mut NativeAsyncComponent,
    export: usize,
    task: TaskHandle,
    stage: InvocationStage,
    total_work: u64,
    remaining_work: u64,
    active_call_budget: u64,
    poll_quantum: u64,
    cleanup_reserve: u64,
    finalize_reserve: u64,
    pending_trap: Option<TrapCode>,
    deferred_core: Option<DeferredCoreTurn>,
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
    /// At most two native host copies can exist: byte stream before close.
    host_current: Option<PendingHostCopy>,
    host_next: Option<PendingHostCopy>,
    host_token: Option<NativeAsyncHostToken>,
    next_host_generation: u64,
    terminal_drops: NativeFilterTerminalDropLedger,
    transport_finalized: bool,
    terminal: bool,
}

impl NativeAsyncInvocation<'_> {
    pub fn poll(&mut self) -> NativeAsyncPoll {
        if self.terminal {
            return NativeAsyncPoll::Trapped(TrapCode::Cancelled);
        }
        if let Some(deferred) = self.deferred_core.take() {
            return self.finish_deferred_core_turn(deferred);
        }
        match self.stage {
            InvocationStage::Run => {
                let active = self.binding().core_instance;
                self.poll_run(active)
            }
            InvocationStage::StartCallback => self.start_callback(),
            InvocationStage::Callback => self.poll_callback(),
            InvocationStage::WaitBlocked => self.poll_wait_blocked(),
            InvocationStage::HostBlocked => self.poll_host_blocked(),
            InvocationStage::Cleanup => self.finish_fail_stop_cleanup(),
            InvocationStage::Terminal => NativeAsyncPoll::Trapped(TrapCode::Cancelled),
        }
    }

    pub const fn metrics(&self) -> NativeAsyncMetrics {
        NativeAsyncMetrics {
            consumed_work: self.total_work - self.remaining_work,
            remaining_work: self.remaining_work,
        }
    }

    fn reserved_work(&self) -> Option<u64> {
        self.cleanup_reserve.checked_add(self.finalize_reserve)
    }

    fn spendable_work(&self) -> Option<u64> {
        self.remaining_work.checked_sub(self.reserved_work()?)
    }

    fn spendable_work_with_continuation_reserve(&self) -> Option<u64> {
        self.spendable_work()?.checked_sub(1)
    }

    /// Requests owner-side task cancellation without cancelling or otherwise
    /// disturbing the currently active Core continuation.
    pub fn request_cancel(&mut self) -> Result<NativeAsyncCancelOutcome, NativeAsyncControlError> {
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

    /// Reserves byte work and validates the exact guest input target before a
    /// backend is allowed to linearize an input receive.
    pub fn prepare_host_input_stream(
        &mut self,
        token: NativeAsyncHostToken,
        progress: u32,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::InputStream, HostCopyPhase::Offered)?;
        let limit = self.host_current.as_ref().unwrap().limit;
        if progress > limit {
            return Err(NativeAsyncHostError::InvalidProgress);
        }
        let preflight = {
            let host = self.host_current.as_ref().unwrap();
            let (state, buffers, modules) = (
                &self.component.state,
                &self.component.buffers,
                &self.component.modules,
            );
            state.with_host_input_buffer(&host.ticket, progress, |lease| {
                buffers.preflight_copy_from_host(modules, lease, progress as usize)
            })
        };
        if let Err(error) = preflight {
            let trap = map_host_commit_error(error);
            return Ok(self.finish_trap(trap));
        }
        Ok(self.finish_host_prepare(progress, None))
    }

    pub fn prepare_host_input_closed(
        &mut self,
        token: NativeAsyncHostToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::InputClosed, HostCopyPhase::Offered)?;
        let preflight = {
            let host = self.host_current.as_ref().unwrap();
            let (state, buffers, modules) = (
                &self.component.state,
                &self.component.buffers,
                &self.component.modules,
            );
            state.with_host_input_buffer(&host.ticket, 1, |lease| {
                buffers.preflight_copy_from_host(modules, lease, 1)
            })
        };
        if let Err(error) = preflight {
            let trap = map_host_commit_error(error);
            return Ok(self.finish_trap(trap));
        }
        Ok(self.finish_host_prepare(1, None))
    }

    /// Copies the exact frozen guest source once into caller-owned fixed
    /// storage. The caller may linearize its backend send before committing.
    pub fn prepare_host_output_stream(
        &mut self,
        token: NativeAsyncHostToken,
        output: &mut [u8],
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::OutputStream, HostCopyPhase::Offered)?;
        let Ok(progress) = u32::try_from(output.len()) else {
            return Err(NativeAsyncHostError::InvalidProgress);
        };
        if progress > self.host_current.as_ref().unwrap().limit {
            return Err(NativeAsyncHostError::InvalidProgress);
        }
        let ticket_preflight = {
            let host = self.host_current.as_ref().unwrap();
            self.component
                .state
                .with_host_copy_buffer(&host.ticket, progress, |_| Ok::<(), TrapCode>(()))
        };
        if let Err(error) = ticket_preflight {
            return Ok(self.finish_trap(map_host_commit_error(error)));
        }
        let prepared_token = match self.charge_host_prepare(progress) {
            Ok(token) => token,
            Err(trap) => return Ok(self.finish_trap(trap)),
        };
        let copied = {
            let host = self.host_current.as_ref().unwrap();
            let (state, buffers, modules) = (
                &self.component.state,
                &self.component.buffers,
                &self.component.modules,
            );
            state.with_host_copy_buffer(&host.ticket, progress, |lease| {
                buffers.copy_to_host(modules, lease, output)
            })
        };
        if let Err(error) = copied {
            return Ok(self.finish_trap(map_host_commit_error(error)));
        }
        Ok(self.mark_host_prepared(progress, None, prepared_token))
    }

    /// Lifts the exact frozen close discriminant once. The value is retained
    /// in the stable HostPending request until backend linearization commits.
    pub fn prepare_host_output_closed(
        &mut self,
        token: NativeAsyncHostToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::OutputClosed, HostCopyPhase::Offered)?;
        let ticket_preflight = {
            let host = self.host_current.as_ref().unwrap();
            self.component
                .state
                .with_host_copy_buffer(&host.ticket, 1, |_| Ok::<(), TrapCode>(()))
        };
        if let Err(error) = ticket_preflight {
            return Ok(self.finish_trap(map_host_commit_error(error)));
        }
        let prepared_token = match self.charge_host_prepare(1) {
            Ok(token) => token,
            Err(trap) => return Ok(self.finish_trap(trap)),
        };
        let lifted = {
            let host = self.host_current.as_ref().unwrap();
            let (state, buffers, modules) = (
                &self.component.state,
                &self.component.buffers,
                &self.component.modules,
            );
            state.with_host_copy_buffer(&host.ticket, 1, |lease| buffers.lift_enum8(modules, lease))
        };
        match lifted {
            Ok(value) => Ok(self.mark_host_prepared(1, Some(value), prepared_token)),
            Err(error) => Ok(self.finish_trap(map_host_commit_error(error))),
        }
    }

    pub fn commit_host_input_stream(
        &mut self,
        token: NativeAsyncHostToken,
        input: &[u8],
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::InputStream, HostCopyPhase::Prepared)?;
        if usize::try_from(self.host_current.as_ref().unwrap().progress).ok() != Some(input.len()) {
            return Err(NativeAsyncHostError::InvalidProgress);
        }
        self.host_token = None;
        let committed = {
            let host = self.host_current.as_mut().unwrap();
            let (state, buffers, modules) = (
                &mut self.component.state,
                &self.component.buffers,
                &mut self.component.modules,
            );
            state.commit_host_copy(
                &mut host.ticket,
                crate::async_abi::CopyResult::Completed,
                host.progress,
                |lease, _| buffers.copy_from_host(modules, lease, input),
            )
        };
        match committed {
            Ok(_event) => Ok(self.finish_host_commit()),
            Err(error) => Ok(self.finish_trap(map_host_commit_error(error))),
        }
    }

    pub fn commit_host_input_closed(
        &mut self,
        token: NativeAsyncHostToken,
        value: u8,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_host_driver(token, HostRequestKind::InputClosed, HostCopyPhase::Prepared)?;
        if value >= 8 {
            self.host_token = None;
            return Ok(self.finish_trap(TrapCode::CanonicalAbi));
        }
        self.host_token = None;
        let committed = {
            let host = self.host_current.as_mut().unwrap();
            let (state, buffers, modules) = (
                &mut self.component.state,
                &self.component.buffers,
                &mut self.component.modules,
            );
            state.commit_host_copy(
                &mut host.ticket,
                crate::async_abi::CopyResult::Completed,
                1,
                |lease, _| buffers.lower_enum8(modules, lease, value),
            )
        };
        match committed {
            Ok(_event) => Ok(self.finish_host_commit()),
            Err(error) => Ok(self.finish_trap(map_host_commit_error(error))),
        }
    }

    pub fn commit_host_output(
        &mut self,
        token: NativeAsyncHostToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_any_output_host_driver(token, HostCopyPhase::Prepared)?;
        self.host_token = None;
        let committed = {
            let host = self.host_current.as_mut().unwrap();
            self.component
                .state
                .commit_prepared_host_copy(&mut host.ticket, host.progress)
        };
        match committed {
            Ok(_event) => Ok(self.finish_host_commit()),
            Err(_) => Ok(self.finish_trap(TrapCode::Validation)),
        }
    }

    pub fn cancel_host_copy(
        &mut self,
        token: NativeAsyncHostToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_any_host_driver(token)?;
        if let Err(trap) = self.begin_host_control() {
            return Ok(self.finish_trap(trap));
        }
        let cancelled = {
            let host = self.host_current.as_mut().unwrap();
            self.component.state.cancel_host_copy(&mut host.ticket)
        };
        match cancelled {
            Ok(_event) => Ok(self.finish_host_commit()),
            Err(_) => Ok(self.finish_trap(TrapCode::Validation)),
        }
    }

    pub fn drop_host_copy_peer(
        &mut self,
        token: NativeAsyncHostToken,
    ) -> Result<NativeAsyncPoll, NativeAsyncHostError> {
        self.validate_any_host_driver(token)?;
        if matches!(
            self.host_current.as_ref().map(|host| host.request),
            Some(NativeAsyncHostRequest::InputClosed)
        ) {
            return Err(NativeAsyncHostError::WrongRequest);
        }
        let request = self.host_current.as_ref().unwrap().request;
        if let Err(trap) = self.begin_host_control() {
            return Ok(self.finish_trap(trap));
        }
        let dropped = {
            let host = self.host_current.as_mut().unwrap();
            self.component
                .state
                .drop_host_copy_peer_with_receipt(&mut host.ticket)
        };
        match dropped {
            Ok((_event, receipt)) => {
                let slot = match request {
                    NativeAsyncHostRequest::InputStream { .. } => {
                        &mut self.terminal_drops.input_stream
                    }
                    NativeAsyncHostRequest::OutputStream { .. } => {
                        &mut self.terminal_drops.output_stream
                    }
                    NativeAsyncHostRequest::OutputClosed { .. } => {
                        &mut self.terminal_drops.output_closed
                    }
                    NativeAsyncHostRequest::InputClosed => {
                        return Ok(self.finish_trap(TrapCode::Validation))
                    }
                };
                if slot.is_some() {
                    return Ok(self.finish_trap(TrapCode::Validation));
                }
                *slot = Some(receipt);
                Ok(self.finish_host_commit())
            }
            Err(error) => Ok(self.finish_trap(map_runtime_state_error(error))),
        }
    }

    /// Consumes the retained filter transport after clean guest termination.
    ///
    /// Caller-visible early attempts are read-only. The guest must first
    /// reclaim every copy event, drop all four peer endpoints, exit its
    /// callback, and leave no Core, wait, host-copy, or buffer continuation.
    /// A rejection of an opaque seal at that exact boundary is an executor
    /// invariant and therefore poisons the Component fail-stop.
    pub fn finalize_transport(&mut self) -> Result<(), NativeAsyncFinalizeError> {
        if self.component.poisoned {
            return Err(NativeAsyncFinalizeError::Poisoned);
        }
        if self.transport_finalized {
            return Err(NativeAsyncFinalizeError::AlreadyFinalized);
        }
        let RuntimeExportContract::ByteStream(contract) = self.binding().contract else {
            return Err(NativeAsyncFinalizeError::WrongContract);
        };
        if !self.terminal || self.stage != InvocationStage::Terminal {
            return Err(NativeAsyncFinalizeError::NotReady);
        }
        // Finalization is a real owner-visible state transition, not part of
        // the `Complete` turn which made it eligible. Pay its exact reserved
        // worst-case charge before the first graph or arena scan. The cleanup
        // reserve remains intact in case any sealed invariant rejects below.
        if !self.charge_finalize_work() {
            return Err(self.poison_finalize_invariant());
        }
        if self.component.modules.any_active_call()
            || self
                .component
                .callback_slots
                .iter()
                .any(|slot| slot.state() != CoreCallSlotState::Idle)
            || self.callback_pending
            || self.wait_ticket.is_some()
            || self.wait_token.is_some()
            || self.deferred_core.is_some()
            || self.host_current.is_some()
            || self.host_next.is_some()
            || self.host_token.is_some()
        {
            return Err(self.poison_finalize_invariant());
        }
        if !matches!(
            self.component.state.task_info(self.task),
            Err(AsyncStateError::StaleHandle)
        ) {
            return Err(self.poison_finalize_invariant());
        }
        if self.component.buffers.live() != 0 {
            return Err(self.poison_finalize_invariant());
        }

        let finalized = match (
            self.input.as_mut(),
            self.output_stream.as_ref(),
            self.output_closed.as_ref(),
        ) {
            (Some(input), Some(output_stream), Some(output_closed)) => {
                if input.first.host.kind() != EndpointKind::Stream
                    || input.first.host.direction() != EndpointDirection::Write
                    || input.first.host.value_type() != contract.stream
                    || input.second.host.kind() != EndpointKind::Future
                    || input.second.host.direction() != EndpointDirection::Write
                    || input.second.host.value_type() != contract.closed
                    || output_stream.value_type() != contract.stream
                    || output_closed.value_type() != contract.closed
                {
                    return Err(self.poison_finalize_invariant());
                }
                self.component.state.finalize_native_filter_transport(
                    input,
                    output_stream,
                    output_closed,
                    self.terminal_drops.input_stream.as_ref(),
                    self.terminal_drops.output_stream.as_ref(),
                    self.terminal_drops.output_closed.as_ref(),
                )
            }
            _ => {
                return Err(self.poison_finalize_invariant());
            }
        };
        match finalized {
            Ok(()) => {
                self.input = None;
                self.output_stream = None;
                self.output_closed = None;
                self.terminal_drops = NativeFilterTerminalDropLedger::default();
                self.transport_finalized = true;
                // No fail-stop work remains after the atomic terminal commit.
                // Its reserve was never consumed, so make it ordinary unused
                // invocation fuel without moving the public metrics ledger.
                self.cleanup_reserve = 0;
                Ok(())
            }
            Err(NativeFilterFinalizeError::Invariant(_)) => Err(self.poison_finalize_invariant()),
        }
    }

    fn charge_finalize_work(&mut self) -> bool {
        let exact = self.component.fail_stop_cleanup_work;
        let Some(required_reserve) = exact.checked_add(self.cleanup_reserve) else {
            return false;
        };
        if self.finalize_reserve != exact
            || self.cleanup_reserve != exact
            || self.remaining_work < required_reserve
        {
            return false;
        }
        self.remaining_work -= exact;
        self.finalize_reserve = 0;
        true
    }

    fn poison_finalize_invariant(&mut self) -> NativeAsyncFinalizeError {
        match self.finish_trap(TrapCode::Validation) {
            NativeAsyncPoll::CleanupPending { trap, metrics } => {
                NativeAsyncFinalizeError::CleanupPending { trap, metrics }
            }
            _ => unreachable!("finish_trap always enters or retains cleanup"),
        }
    }

    /// Uses one exact owner token to perform one real blocked-wait scan.
    ///
    /// Ordinary [`Self::poll`] calls never scan a blocked wait. A pending
    /// explicit resume spends one bounded state-transition charge and rotates
    /// the token, making retries and spurious wakes observable and linear.
    pub fn resume_wait(
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

    fn poll_host_blocked(&mut self) -> NativeAsyncPoll {
        let Some(token) = self.host_token else {
            return self.finish_trap(TrapCode::Validation);
        };
        let Some(host) = self.host_current.as_ref() else {
            return self.finish_trap(TrapCode::Validation);
        };
        let next_is_exact = match self.host_next.as_ref() {
            Some(next) => {
                matches!(host.request, NativeAsyncHostRequest::OutputStream { .. })
                    && next.authority == host.authority
                    && next.resume_stage == host.resume_stage
                    && self.host_copy_invariant(next, true)
            }
            None => true,
        };
        if token.task != self.task
            || token != self.host_token.unwrap()
            || !self.host_copy_invariant(host, false)
            || !next_is_exact
        {
            return self.finish_trap(TrapCode::Validation);
        }
        NativeAsyncPoll::HostPending {
            token,
            request: host.request,
            metrics: self.metrics(),
        }
    }

    fn host_copy_invariant(&self, host: &PendingHostCopy, queued: bool) -> bool {
        let RuntimeExportContract::ByteStream(contract) = self.binding().contract else {
            return false;
        };
        if host.resume_stage != call_stage(host.authority)
            || matches!(host.authority, CallAuthority::Run(active) if active != self.binding().core_instance)
            || host.charged != (host.phase == HostCopyPhase::Prepared)
            || host.progress > host.limit
            || (host.phase == HostCopyPhase::Offered && host.progress != 0)
            || (host.kind == EndpointKind::Future
                && (host.limit != 1
                    || host.progress
                        != if host.phase == HostCopyPhase::Prepared {
                            1
                        } else {
                            0
                        }))
        {
            return false;
        }
        match host.request {
            NativeAsyncHostRequest::InputStream { maximum } => {
                !queued
                    && maximum == host.limit
                    && host.kind == EndpointKind::Stream
                    && host.direction == EndpointDirection::Read
                    && host.value_type == contract.stream
                    && self.input.as_ref().is_some_and(|input| {
                        input.first.host.kind() == EndpointKind::Stream
                            && input.first.host.direction() == EndpointDirection::Write
                            && input.first.host.value_type() == contract.stream
                    })
            }
            NativeAsyncHostRequest::InputClosed => {
                !queued
                    && host.limit == 1
                    && host.progress <= 1
                    && host.kind == EndpointKind::Future
                    && host.direction == EndpointDirection::Read
                    && host.value_type == contract.closed
                    && self.input.as_ref().is_some_and(|input| {
                        input.second.host.kind() == EndpointKind::Future
                            && input.second.host.direction() == EndpointDirection::Write
                            && input.second.host.value_type() == contract.closed
                    })
            }
            NativeAsyncHostRequest::OutputStream { maximum } => {
                !queued
                    && maximum == host.limit
                    && host.kind == EndpointKind::Stream
                    && host.direction == EndpointDirection::Write
                    && host.value_type == contract.stream
                    && self
                        .output_stream
                        .as_ref()
                        .is_some_and(|stream| stream.value_type() == contract.stream)
            }
            NativeAsyncHostRequest::OutputClosed { value } => {
                host.limit == 1
                    && host.progress <= 1
                    && value.is_some() == (host.phase == HostCopyPhase::Prepared)
                    && (!queued || host.phase == HostCopyPhase::Offered)
                    && host.kind == EndpointKind::Future
                    && host.direction == EndpointDirection::Write
                    && host.value_type == contract.closed
                    && self
                        .output_closed
                        .as_ref()
                        .is_some_and(|closed| closed.value_type() == contract.closed)
            }
        }
    }

    fn validate_host_driver(
        &self,
        token: NativeAsyncHostToken,
        request: HostRequestKind,
        phase: HostCopyPhase,
    ) -> Result<(), NativeAsyncHostError> {
        self.validate_any_host_driver(token)?;
        let host = self
            .host_current
            .as_ref()
            .ok_or(NativeAsyncHostError::NotPending)?;
        if host_request_kind(host.request) != request {
            return Err(NativeAsyncHostError::WrongRequest);
        }
        if host.phase != phase {
            return Err(NativeAsyncHostError::WrongPhase);
        }
        Ok(())
    }

    fn validate_any_output_host_driver(
        &self,
        token: NativeAsyncHostToken,
        phase: HostCopyPhase,
    ) -> Result<(), NativeAsyncHostError> {
        self.validate_any_host_driver(token)?;
        let host = self
            .host_current
            .as_ref()
            .ok_or(NativeAsyncHostError::NotPending)?;
        if !matches!(
            host.request,
            NativeAsyncHostRequest::OutputStream { .. }
                | NativeAsyncHostRequest::OutputClosed { .. }
        ) {
            return Err(NativeAsyncHostError::WrongRequest);
        }
        if host.phase != phase {
            return Err(NativeAsyncHostError::WrongPhase);
        }
        Ok(())
    }

    fn validate_any_host_driver(
        &self,
        token: NativeAsyncHostToken,
    ) -> Result<(), NativeAsyncHostError> {
        if !matches!(self.stage, InvocationStage::HostBlocked)
            || self.host_current.is_none()
            || self.host_token.is_none()
        {
            return Err(NativeAsyncHostError::NotPending);
        }
        if token.task != self.task || self.host_token != Some(token) {
            return Err(NativeAsyncHostError::InvalidToken);
        }
        Ok(())
    }

    fn finish_host_prepare(&mut self, progress: u32, value: Option<u8>) -> NativeAsyncPoll {
        let token = match self.charge_host_prepare(progress) {
            Ok(token) => token,
            Err(trap) => return self.finish_trap(trap),
        };
        self.mark_host_prepared(progress, value, token)
    }

    /// Revokes the current driver generation and charges an offered copy's
    /// state-only terminal transition. A prepared copy already prepaid its
    /// fixed transition unit together with the selected byte prefix.
    fn begin_host_control(&mut self) -> Result<(), TrapCode> {
        let host = self.host_current.as_ref().ok_or(TrapCode::Validation)?;
        let authority = host.authority;
        let charged = host.charged;
        self.host_token = None;
        if charged {
            Ok(())
        } else {
            self.debit_active_work_with_reserve(authority, BUFFER_COPY_BASE_WORK)
        }
    }

    fn charge_host_prepare(&mut self, progress: u32) -> Result<NativeAsyncHostToken, TrapCode> {
        let host = self.host_current.as_ref().ok_or(TrapCode::Validation)?;
        if host.phase != HostCopyPhase::Offered
            || host.charged
            || host.progress != 0
            || progress > host.limit
        {
            return Err(TrapCode::Validation);
        }
        let authority = host.authority;
        let work = host_copy_work(progress).ok_or(TrapCode::FuelExhausted)?;
        // Revoke the offered token before the first fuel mutation. A failed
        // prepare can never be retried through the old generation.
        self.host_token = None;
        let token = self.mint_host_token()?;
        self.debit_active_work_with_reserve(authority, work)?;
        let host = self.host_current.as_mut().ok_or(TrapCode::Validation)?;
        host.progress = progress;
        host.charged = true;
        Ok(token)
    }

    fn mark_host_prepared(
        &mut self,
        progress: u32,
        value: Option<u8>,
        token: NativeAsyncHostToken,
    ) -> NativeAsyncPoll {
        let Some(host) = self.host_current.as_mut() else {
            return self.finish_trap(TrapCode::Validation);
        };
        if host.phase != HostCopyPhase::Offered
            || !host.charged
            || host.progress != progress
            || self.host_token.is_some()
        {
            return self.finish_trap(TrapCode::Validation);
        }
        match (&mut host.request, value) {
            (NativeAsyncHostRequest::OutputClosed { value: slot }, Some(value)) => {
                *slot = Some(value);
            }
            (NativeAsyncHostRequest::InputStream { .. }, None)
            | (NativeAsyncHostRequest::InputClosed, None)
            | (NativeAsyncHostRequest::OutputStream { .. }, None) => {}
            _ => return self.finish_trap(TrapCode::Validation),
        }
        host.phase = HostCopyPhase::Prepared;
        self.host_token = Some(token);
        self.poll_host_blocked()
    }

    fn finish_host_commit(&mut self) -> NativeAsyncPoll {
        self.host_token = None;
        let Some(completed) = self.host_current.take() else {
            return self.finish_trap(TrapCode::Validation);
        };
        if let Some(next) = self.host_next.take() {
            if !matches!(
                (completed.request, next.request),
                (
                    NativeAsyncHostRequest::OutputStream { .. },
                    NativeAsyncHostRequest::OutputClosed { value: None }
                )
            ) {
                return self.finish_trap(TrapCode::Validation);
            }
            self.host_current = Some(next);
            return self.activate_queued_host_copy();
        }
        self.stage = completed.resume_stage;
        NativeAsyncPoll::Pending(self.metrics())
    }

    fn poll_run(&mut self, active_instance: usize) -> NativeAsyncPoll {
        let result = self.component.modules.poll_call(active_instance);
        let authority = CallAuthority::Run(active_instance);
        if !self.settle_metrics(authority) {
            return self.finish_trap(TrapCode::Validation);
        }
        match result {
            PollResult::Pending { .. } => NativeAsyncPoll::Pending(self.metrics()),
            PollResult::HostCall(call) => {
                self.defer_core_turn(DeferredCoreTurn::Host { authority, call })
            }
            PollResult::Ready(values) => self.defer_core_turn(DeferredCoreTurn::RunReady(values)),
            PollResult::Trapped(trap) => self.defer_core_turn(DeferredCoreTurn::Trapped(trap)),
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
            CoreSlotPollResult::HostCall(call) => self.defer_core_turn(DeferredCoreTurn::Host {
                authority: CallAuthority::Callback,
                call,
            }),
            CoreSlotPollResult::Ready(values) => {
                self.defer_core_turn(DeferredCoreTurn::CallbackReady(values))
            }
            CoreSlotPollResult::Trapped(trap) => {
                self.defer_core_turn(DeferredCoreTurn::Trapped(trap))
            }
        }
    }

    fn defer_core_turn(&mut self, deferred: DeferredCoreTurn) -> NativeAsyncPoll {
        if self.deferred_core.replace(deferred).is_some() {
            return self.finish_trap(TrapCode::Validation);
        }
        NativeAsyncPoll::Pending(self.metrics())
    }

    fn finish_deferred_core_turn(&mut self, deferred: DeferredCoreTurn) -> NativeAsyncPoll {
        match deferred {
            DeferredCoreTurn::Host { authority, call } => {
                if self.stage != call_stage(authority) {
                    return self.finish_trap(TrapCode::Validation);
                }
                self.handle_host_call(authority, call)
            }
            DeferredCoreTurn::RunReady(values) => {
                if self.stage != InvocationStage::Run {
                    return self.finish_trap(TrapCode::Validation);
                }
                self.handle_callback_result(values.as_slice())
            }
            DeferredCoreTurn::CallbackReady(values) => {
                if self.stage != InvocationStage::Callback {
                    return self.finish_trap(TrapCode::Validation);
                }
                self.handle_callback_result(values.as_slice())
            }
            DeferredCoreTurn::Trapped(trap) => self.finish_trap(trap),
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
        metrics.remaining_fuel <= self.spendable_work().unwrap_or(0)
            && metrics.remaining_fuel.checked_add(metrics.consumed_fuel)
                == Some(self.active_call_budget)
            && {
                let Some(remaining_work) = self
                    .reserved_work()
                    .and_then(|reserve| metrics.remaining_fuel.checked_add(reserve))
                else {
                    return false;
                };
                self.remaining_work = remaining_work;
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
                // A component input's peer is already owned by the host. It
                // cannot be turned into a drivable output by echoing the
                // guest-readable handle: there is no guest write operation or
                // frozen guest source for the HostPending protocol to settle.
                // Compare sealed handles, not raw integers, so reuse cannot
                // turn this topology check into an ABA alias.
                if self.input.as_ref().is_some_and(|input| {
                    input.first.guest == stream || input.second.guest == closed
                }) {
                    return self.finish_trap(TrapCode::CanonicalAbi);
                }
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
                    return self.finish_trap(trap);
                }
                let detached = self.component.state.detach_readables_pair_with_pending(
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
                let (stream, closed, stream_pending, closed_pending) = match detached {
                    Ok(detached) => match (detached.first.endpoint, detached.second.endpoint) {
                        (
                            TransferredReadableEndpoint::Stream(stream),
                            TransferredReadableEndpoint::Future(closed),
                        ) if stream.value_type() == contract.stream
                            && closed.value_type() == contract.closed =>
                        {
                            (
                                stream,
                                closed,
                                detached.first.pending,
                                detached.second.pending,
                            )
                        }
                        _ => return self.finish_trap(TrapCode::Validation),
                    },
                    Err(error) => return self.finish_trap(map_exact_endpoint_state_error(error)),
                };
                // Store both linear output authorities before the next
                // fallible operation. Fail-stop cleanup can consequently
                // reclaim them even if task resolution or Core resume detects
                // an executor invariant.
                self.output_stream = Some(stream);
                self.output_closed = Some(closed);
                self.host_current = stream_pending.map(|ticket| PendingHostCopy {
                    ticket,
                    authority,
                    request: NativeAsyncHostRequest::OutputStream { maximum: 0 },
                    kind: EndpointKind::Stream,
                    direction: EndpointDirection::Write,
                    value_type: contract.stream,
                    resume_stage: call_stage(authority),
                    phase: HostCopyPhase::Offered,
                    limit: 0,
                    progress: 0,
                    charged: false,
                });
                let closed_host = closed_pending.map(|ticket| PendingHostCopy {
                    ticket,
                    authority,
                    request: NativeAsyncHostRequest::OutputClosed { value: None },
                    kind: EndpointKind::Future,
                    direction: EndpointDirection::Write,
                    value_type: contract.closed,
                    resume_stage: call_stage(authority),
                    phase: HostCopyPhase::Offered,
                    limit: 0,
                    progress: 0,
                    charged: false,
                });
                if self.host_current.is_some() {
                    self.host_next = closed_host;
                } else {
                    self.host_current = closed_host;
                }
                if let Err(trap) = self.initialize_output_host_copies() {
                    return self.finish_trap(trap);
                }
                if let Err(error) = self.component.state.resolve_task_result(self.task) {
                    return self.finish_trap(map_sealed_state_error(error));
                }
                if let Err(trap) = self.resume_active_host_call(authority, call.id, &[]) {
                    return self.finish_trap(trap);
                }
                if self.host_current.is_some() {
                    self.activate_queued_host_copy()
                } else {
                    NativeAsyncPoll::Resolved(self.metrics())
                }
            }
            (BridgeAction::StreamNew(value_type), []) => {
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
                let work = self.component.work_costs.handle_state;
                if let Err(trap) = self.debit_active_work(authority, work) {
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
        let work = self.component.work_costs.buffer_bridge;
        if let Err(trap) = self.debit_active_work_with_reserve(authority, work) {
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
            CopyBegin::Blocked { abi, operation } => {
                let results = [CoreValue::I32(abi as i32)];
                if let Err(trap) = self.resume_active_host_call(authority, host_id, &results) {
                    return self.finish_trap(trap);
                }
                match self
                    .capture_host_copy(authority, kind, direction, value_type, handle, operation)
                {
                    Ok(Some(host)) => return self.activate_host_copy(host),
                    Ok(None) => return NativeAsyncPoll::Pending(self.metrics()),
                    Err(trap) => return self.finish_trap(trap),
                }
            }
            CopyBegin::Ready(event) => event,
            CopyBegin::Local(mut ticket) => {
                let limit = match self.component.state.local_copy_progress(&ticket) {
                    Ok(limit) => limit,
                    Err(_) => return self.finish_trap(TrapCode::Validation),
                };
                let turn_available = match self
                    .poll_quantum
                    .checked_sub(self.component.work_costs.buffer_bridge)
                {
                    Some(available) => available,
                    None => return self.finish_trap(TrapCode::LimitExceeded),
                };
                let Some(fuel_available) = self.spendable_work_with_continuation_reserve() else {
                    return self.finish_trap(TrapCode::FuelExhausted);
                };
                let available = turn_available.min(fuel_available);
                let progress = match maximum_local_copy_progress(
                    limit,
                    self.component.buffers.scratch_bytes(),
                    available,
                ) {
                    Some(progress) => progress,
                    None => return self.finish_trap(TrapCode::FuelExhausted),
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

    fn capture_host_copy(
        &mut self,
        authority: CallAuthority,
        kind: EndpointKind,
        direction: EndpointDirection,
        value_type: AsyncValueTypeId,
        handle: crate::async_state::AsyncHandle,
        operation: crate::async_state::CopyOpToken,
    ) -> Result<Option<PendingHostCopy>, TrapCode> {
        if direction == EndpointDirection::Write {
            let prepared = match kind {
                EndpointKind::Stream => {
                    let Some(stream) = self
                        .output_stream
                        .as_ref()
                        .filter(|stream| stream.value_type() == value_type)
                    else {
                        return Ok(None);
                    };
                    self.component
                        .state
                        .prepare_stream_host_copy(stream, &operation)
                }
                EndpointKind::Future => {
                    let Some(closed) = self
                        .output_closed
                        .as_ref()
                        .filter(|closed| closed.value_type() == value_type)
                    else {
                        return Ok(None);
                    };
                    self.component
                        .state
                        .prepare_future_host_copy(closed, &operation)
                }
            };
            let ticket = match prepared {
                Ok(ticket) => ticket,
                Err(AsyncStateError::StaleOperation) => return Ok(None),
                Err(_) => return Err(TrapCode::Validation),
            };
            let limit = self
                .component
                .state
                .host_copy_progress_limit(&ticket)
                .map_err(|_| TrapCode::Validation)?;
            let limit = self.host_progress_limit(kind, limit)?;
            let request = match kind {
                EndpointKind::Stream => NativeAsyncHostRequest::OutputStream { maximum: limit },
                EndpointKind::Future if limit == 1 => {
                    NativeAsyncHostRequest::OutputClosed { value: None }
                }
                EndpointKind::Future => return Err(TrapCode::Validation),
            };
            return Ok(Some(PendingHostCopy {
                ticket,
                authority,
                request,
                kind,
                direction,
                value_type,
                resume_stage: call_stage(authority),
                phase: HostCopyPhase::Offered,
                limit,
                progress: 0,
                charged: false,
            }));
        }
        if direction != EndpointDirection::Read {
            return Ok(None);
        }
        let Some(input) = self.input.as_ref() else {
            return Ok(None);
        };
        let binding = match kind {
            EndpointKind::Stream
                if input.first.guest == handle
                    && input.first.host.kind() == EndpointKind::Stream
                    && input.first.host.direction() == EndpointDirection::Write
                    && input.first.host.value_type() == value_type =>
            {
                &input.first.host
            }
            EndpointKind::Future
                if input.second.guest == handle
                    && input.second.host.kind() == EndpointKind::Future
                    && input.second.host.direction() == EndpointDirection::Write
                    && input.second.host.value_type() == value_type =>
            {
                &input.second.host
            }
            _ => return Ok(None),
        };
        let ticket = self
            .component
            .state
            .prepare_host_copy(binding, &operation)
            .map_err(|_| TrapCode::Validation)?;
        let limit = self
            .component
            .state
            .host_copy_progress_limit(&ticket)
            .map_err(|_| TrapCode::Validation)?;
        let limit = self.host_progress_limit(kind, limit)?;
        let request = match kind {
            EndpointKind::Stream => NativeAsyncHostRequest::InputStream { maximum: limit },
            EndpointKind::Future if limit == 1 => NativeAsyncHostRequest::InputClosed,
            EndpointKind::Future => return Err(TrapCode::Validation),
        };
        Ok(Some(PendingHostCopy {
            ticket,
            authority,
            request,
            kind,
            direction,
            value_type,
            resume_stage: call_stage(authority),
            phase: HostCopyPhase::Offered,
            limit,
            progress: 0,
            charged: false,
        }))
    }

    fn activate_host_copy(&mut self, host: PendingHostCopy) -> NativeAsyncPoll {
        if self.host_current.is_some() || self.host_token.is_some() {
            return self.finish_trap(TrapCode::Validation);
        }
        self.host_current = Some(host);
        self.activate_queued_host_copy()
    }

    fn activate_queued_host_copy(&mut self) -> NativeAsyncPoll {
        if self.host_current.is_none() || self.host_token.is_some() {
            return self.finish_trap(TrapCode::Validation);
        }
        if let Err(trap) = self.refresh_current_host_copy_limit() {
            return self.finish_trap(trap);
        }
        let token = match self.mint_host_token() {
            Ok(token) => token,
            Err(trap) => return self.finish_trap(trap),
        };
        let Some(request) = self.host_current.as_ref().map(|host| host.request) else {
            return self.finish_trap(TrapCode::Validation);
        };
        self.host_token = Some(token);
        self.stage = InvocationStage::HostBlocked;
        NativeAsyncPoll::HostPending {
            token,
            request,
            metrics: self.metrics(),
        }
    }

    fn initialize_output_host_copies(&mut self) -> Result<(), TrapCode> {
        let host_progress_limit = self.host_progress_budget()?;
        for host in [&mut self.host_current, &mut self.host_next]
            .into_iter()
            .flatten()
        {
            let exact = self
                .component
                .state
                .host_copy_progress_limit(&host.ticket)
                .map_err(|_| TrapCode::Validation)?;
            let limit = exact.min(host_progress_limit);
            if limit == 0 && host.kind == EndpointKind::Stream {
                if exact != 0 {
                    return Err(TrapCode::FuelExhausted);
                }
            } else if limit == 0 {
                return Err(TrapCode::FuelExhausted);
            }
            if host.kind == EndpointKind::Future && limit != 1 {
                return Err(TrapCode::FuelExhausted);
            }
            host.limit = limit;
            host.request = match host.kind {
                EndpointKind::Stream => NativeAsyncHostRequest::OutputStream { maximum: limit },
                EndpointKind::Future if limit == 1 => {
                    NativeAsyncHostRequest::OutputClosed { value: None }
                }
                EndpointKind::Future => return Err(TrapCode::Validation),
            };
        }
        Ok(())
    }

    fn host_progress_budget(&self) -> Result<u32, TrapCode> {
        let turn = self
            .poll_quantum
            .checked_sub(BUFFER_COPY_BASE_WORK)
            .ok_or(TrapCode::LimitExceeded)?;
        let fuel = self
            .spendable_work_with_continuation_reserve()
            .and_then(|work| work.checked_sub(BUFFER_COPY_BASE_WORK))
            .ok_or(TrapCode::FuelExhausted)?;
        Ok(u32::try_from(turn.min(fuel)).unwrap_or(u32::MAX))
    }

    fn host_progress_limit(&self, kind: EndpointKind, exact: u32) -> Result<u32, TrapCode> {
        let budget = self.host_progress_budget()?;
        if exact == 0 && kind == EndpointKind::Stream {
            return Ok(0);
        }
        let limit = exact.min(budget);
        if limit == 0 {
            return Err(TrapCode::FuelExhausted);
        }
        if kind == EndpointKind::Future && limit != 1 {
            return Err(TrapCode::FuelExhausted);
        }
        Ok(limit)
    }

    fn refresh_current_host_copy_limit(&mut self) -> Result<(), TrapCode> {
        let host = self.host_current.as_ref().ok_or(TrapCode::Validation)?;
        if host.phase != HostCopyPhase::Offered || host.charged || host.progress != 0 {
            return Err(TrapCode::Validation);
        }
        let exact = self
            .component
            .state
            .host_copy_progress_limit(&host.ticket)
            .map_err(|_| TrapCode::Validation)?;
        let kind = host.kind;
        let limit = self.host_progress_limit(kind, exact)?;
        let host = self.host_current.as_mut().ok_or(TrapCode::Validation)?;
        host.limit = limit;
        host.request = match kind {
            EndpointKind::Stream => match host.request {
                NativeAsyncHostRequest::InputStream { .. } => {
                    NativeAsyncHostRequest::InputStream { maximum: limit }
                }
                NativeAsyncHostRequest::OutputStream { .. } => {
                    NativeAsyncHostRequest::OutputStream { maximum: limit }
                }
                NativeAsyncHostRequest::InputClosed
                | NativeAsyncHostRequest::OutputClosed { .. } => return Err(TrapCode::Validation),
            },
            EndpointKind::Future => match host.request {
                NativeAsyncHostRequest::InputClosed => NativeAsyncHostRequest::InputClosed,
                NativeAsyncHostRequest::OutputClosed { value: None } => {
                    NativeAsyncHostRequest::OutputClosed { value: None }
                }
                NativeAsyncHostRequest::InputStream { .. }
                | NativeAsyncHostRequest::OutputStream { .. }
                | NativeAsyncHostRequest::OutputClosed { value: Some(_) } => {
                    return Err(TrapCode::Validation)
                }
            },
        };
        Ok(())
    }

    fn mint_host_token(&mut self) -> Result<NativeAsyncHostToken, TrapCode> {
        let generation = NonZeroU64::new(self.next_host_generation).ok_or(TrapCode::Validation)?;
        self.next_host_generation = self
            .next_host_generation
            .checked_add(1)
            .ok_or(TrapCode::LimitExceeded)?;
        Ok(NativeAsyncHostToken {
            task: self.task,
            generation,
        })
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
        let work = self.component.work_costs.buffer_bridge;
        if let Err(trap) = self.debit_active_work_with_reserve(authority, work) {
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
        if self
            .spendable_work()
            .is_none_or(|spendable| spendable <= amount)
        {
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
        if self.spendable_work() == Some(0) {
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
        let Some(spendable_work) = self.spendable_work() else {
            return self.finish_trap(TrapCode::Validation);
        };
        if spendable_work == 0
            || self.component.callback_slots[self.export].state() != CoreCallSlotState::Idle
        {
            return self.finish_trap(if spendable_work == 0 {
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
        let quantum = self.poll_quantum.min(spendable_work);
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
                spendable_work,
                quantum,
            )
            .is_err()
        {
            return self.finish_trap(TrapCode::Validation);
        }
        self.callback_pending = false;
        self.active_call_budget = spendable_work;
        self.stage = InvocationStage::Callback;
        NativeAsyncPoll::Pending(self.metrics())
    }

    fn charge_inactive_work(&mut self, amount: u64) -> bool {
        let Some(spendable) = self.spendable_work() else {
            return false;
        };
        let Some(spendable) = spendable.checked_sub(amount) else {
            return false;
        };
        let Some(remaining) = self
            .reserved_work()
            .and_then(|reserve| spendable.checked_add(reserve))
        else {
            return false;
        };
        self.remaining_work = remaining;
        true
    }

    fn charge_wait_state_work(&mut self) -> bool {
        let Some(spendable) = self.spendable_work() else {
            return false;
        };
        let Some(spendable) = spendable.checked_sub(self.component.work_costs.wait_state) else {
            return false;
        };
        if spendable == 0 {
            return false;
        }
        let Some(remaining) = self
            .reserved_work()
            .and_then(|reserve| spendable.checked_add(reserve))
        else {
            return false;
        };
        self.remaining_work = remaining;
        true
    }

    fn finish_trap(&mut self, trap: TrapCode) -> NativeAsyncPoll {
        if self.stage == InvocationStage::Cleanup {
            let trap = self.pending_trap.unwrap_or(trap);
            return NativeAsyncPoll::CleanupPending {
                trap,
                metrics: self.metrics(),
            };
        }
        // Latch fail-stop and revoke every owner-visible continuation before
        // yielding. The exact bounded reclamation charge is reserved from the
        // invocation ledger and paid only by the following public poll.
        self.component.poisoned = true;
        self.host_token = None;
        self.wait_token = None;
        self.deferred_core = None;
        self.pending_trap = Some(trap);
        self.stage = InvocationStage::Cleanup;
        self.terminal = false;
        NativeAsyncPoll::CleanupPending {
            trap,
            metrics: self.metrics(),
        }
    }

    fn finish_fail_stop_cleanup(&mut self) -> NativeAsyncPoll {
        let trap = self.pending_trap.take().unwrap_or(TrapCode::Validation);
        let exact = self.component.fail_stop_cleanup_work;
        let charged = self.cleanup_reserve == exact && self.remaining_work >= exact;
        if charged {
            self.remaining_work -= exact;
            self.cleanup_reserve = 0;
            // A trapped invocation never reaches the successful transport
            // finalizer, so its independent terminal reserve remains unused.
            self.finalize_reserve = 0;
        }
        self.poison_and_discard();
        self.stage = InvocationStage::Terminal;
        self.terminal = true;
        NativeAsyncPoll::Trapped(if charged { trap } else { TrapCode::Validation })
    }

    fn poison_and_discard(&mut self) {
        // Latch fail-stop before touching any independently fallible cleanup
        // authority. No cleanup error may make this Component reusable.
        self.component.poisoned = true;
        self.host_token = None;
        self.deferred_core = None;
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
        // `abort_all_copies` invalidated both tickets before they are dropped.
        self.host_current = None;
        self.host_next = None;
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
        // can leave its Component reusable. A filter invocation must also pass
        // the exact terminal finalizer, which atomically consumes all retained
        // Host holders and clears these fields. Silently dropping any
        // remaining input or result authority would lose its exact holder
        // while leaving the pair arena live, so incomplete acceptance drivers
        // remain fail-stop.
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
        instantiate_with_resource_limit(source, PROFILE_1_LIMITS.max_resources).unwrap()
    }

    fn instantiate_with_resource_limit(
        source: &str,
        resource_limit: u32,
    ) -> Result<NativeAsyncComponent, NativeAsyncError> {
        let bytes = wat::parse_str(source).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        NativeAsyncComponent::instantiate_sealed(
            &plan,
            &ProfileEngine::new(),
            OwnerAllocationReservation::profile_default(),
            PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
            resource_limit,
        )
    }

    fn replace_once(source: &str, from: &str, to: &str) -> String {
        assert_eq!(source.matches(from).count(), 1);
        source.replacen(from, to, 1)
    }

    fn filter_transport_component(run: &str, callback: &str) -> String {
        format!(
            r#"(component
              (core module $memory-provider
                (memory (export "memory") 1 1))
              (core instance $memory-instance (instantiate $memory-provider))
              (alias core export $memory-instance "memory" (core memory $memory))

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
              (core func $stream-new (canon stream.new $bytes))
              (core func $stream-read
                (canon stream.read $bytes async (memory $memory)))
              (core func $stream-write
                (canon stream.write $bytes async (memory $memory)))
              (core func $stream-drop-readable
                (canon stream.drop-readable $bytes))
              (core func $stream-drop-writable
                (canon stream.drop-writable $bytes))
              (core func $future-new (canon future.new $closed))
              (core func $future-read
                (canon future.read $closed async (memory $memory)))
              (core func $future-write
                (canon future.write $closed async (memory $memory)))
              (core func $future-drop-readable
                (canon future.drop-readable $closed))
              (core func $future-drop-writable
                (canon future.drop-writable $closed))
              (core func $waitable-set-new (canon waitable-set.new))
              (core func $waitable-set-drop (canon waitable-set.drop))
              (core func $waitable-join (canon waitable.join))
              (core instance $builtins
                (export "task-return" (func $task-return))
                (export "stream-new" (func $stream-new))
                (export "stream-read" (func $stream-read))
                (export "stream-write" (func $stream-write))
                (export "stream-drop-readable" (func $stream-drop-readable))
                (export "stream-drop-writable" (func $stream-drop-writable))
                (export "future-new" (func $future-new))
                (export "future-read" (func $future-read))
                (export "future-write" (func $future-write))
                (export "future-drop-readable" (func $future-drop-readable))
                (export "future-drop-writable" (func $future-drop-writable))
                (export "waitable-set-new" (func $waitable-set-new))
                (export "waitable-set-drop" (func $waitable-set-drop))
                (export "waitable-join" (func $waitable-join)))

              (core module $guest
                (import "env" "memory" (memory 1 1))
                (import "vibe:async" "task-return"
                  (func $task-return (param i32 i32)))
                (import "vibe:async" "stream-new"
                  (func $stream-new (result i64)))
                (import "vibe:async" "stream-read"
                  (func $stream-read (param i32 i32 i32) (result i32)))
                (import "vibe:async" "stream-write"
                  (func $stream-write (param i32 i32 i32) (result i32)))
                (import "vibe:async" "stream-drop-readable"
                  (func $stream-drop-readable (param i32)))
                (import "vibe:async" "stream-drop-writable"
                  (func $stream-drop-writable (param i32)))
                (import "vibe:async" "future-new"
                  (func $future-new (result i64)))
                (import "vibe:async" "future-read"
                  (func $future-read (param i32 i32) (result i32)))
                (import "vibe:async" "future-write"
                  (func $future-write (param i32 i32) (result i32)))
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
                (func (export "run")
                  (param $input-bytes i32) (param $input-closed i32) (result i32)
                  (local $stream-pair i64)
                  (local $closed-pair i64)
                  (local $set i32)
                  {run})
                (func (export "callback")
                  (param $event i32) (param $p1 i32) (param $p2 i32) (result i32)
                  {callback}))
              (core instance $guest-instance
                (instantiate $guest
                  (with "env" (instance $memory-instance))
                  (with "vibe:async" (instance $builtins))))
              (alias core export $guest-instance "run" (core func $run))
              (alias core export $guest-instance "callback" (core func $callback))
              (func $lifted (type $run-type)
                (canon lift (core func $run) async
                  (callback (core func $callback))))
              (export "run" (func $lifted)))"#
        )
    }

    fn poll_to_host(
        call: &mut NativeAsyncInvocation<'_>,
    ) -> (
        NativeAsyncHostToken,
        NativeAsyncHostRequest,
        NativeAsyncMetrics,
    ) {
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::HostPending {
                    token,
                    request,
                    metrics,
                } => return (token, request, metrics),
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("host transport fixture unexpectedly waited")
                }
                NativeAsyncPoll::Complete(_) => {
                    panic!("host transport fixture completed before HostPending")
                }
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("host transport fixture entered cleanup: {trap:?}")
                }
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("host transport fixture trapped: {trap:?}")
                }
            }
        }
    }

    fn input_transport_component() -> String {
        filter_transport_component(
            r#"local.get $input-bytes
              i32.const 16
              i32.const 4
              call $stream-read
              i32.const -1
              i32.ne
              if unreachable end
              local.get $input-closed
              i32.const 32
              call $future-read
              i32.const -1
              i32.ne
              if unreachable end
              unreachable"#,
            "i32.const 0",
        )
    }

    fn output_transport_component(
        stream_before_return: bool,
        closed_before_return: bool,
        stream_after_return: bool,
    ) -> String {
        let stream_before = if stream_before_return {
            r#"local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.const 64
              i32.const 4
              call $stream-write
              i32.const -1
              i32.ne
              if unreachable end"#
        } else {
            ""
        };
        let closed_before = if closed_before_return {
            r#"local.get $closed-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.const 72
              call $future-write
              i32.const -1
              i32.ne
              if unreachable end"#
        } else {
            ""
        };
        let stream_after = if stream_after_return {
            r#"local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.const 64
              i32.const 4
              call $stream-write
              i32.const -1
              i32.ne
              if unreachable end"#
        } else {
            ""
        };
        let run = format!(
            r#"call $stream-new
              local.set $stream-pair
              call $future-new
              local.set $closed-pair
              i32.const 0
              local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.store
              i32.const 4
              local.get $closed-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.store
              i32.const 64
              i32.const 67305985
              i32.store
              i32.const 72
              i32.const 6
              i32.store8
              {stream_before}
              {closed_before}
              local.get $stream-pair
              i32.wrap_i64
              local.get $closed-pair
              i32.wrap_i64
              call $task-return
              {stream_after}
              i32.const 64
              i32.const 151587081
              i32.store
              i32.const 72
              i32.const 7
              i32.store8
              i32.const 1"#
        );
        filter_transport_component(&run, "i32.const 0")
    }

    fn clean_finalize_component(leak_local_pair: bool) -> String {
        clean_finalize_component_with_peer_drops(false, false, false, leak_local_pair)
    }

    fn clean_finalize_component_with_peer_drops(
        drop_input_stream: bool,
        drop_output_stream: bool,
        drop_output_closed: bool,
        leak_local_pair: bool,
    ) -> String {
        let leak = if leak_local_pair {
            // This pair is deliberately unrelated to the four retained
            // filter pairs. A callback Exit with it still live is a sealed
            // terminal-state invariant, never work for finalization to guess.
            "call $stream-new\n              drop"
        } else {
            ""
        };
        let input_stream = if drop_input_stream {
            r#"local.get $input-bytes
              local.get $set
              call $waitable-join
              local.get $input-bytes
              i32.const 16
              i32.const 4
              call $stream-read
              i32.const -1
              i32.ne
              if unreachable end"#
        } else {
            r#"local.get $input-bytes
              call $stream-drop-readable"#
        };
        let output_stream = if drop_output_stream {
            r#"i32.const 64
              i32.const 67305985
              i32.store
              local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              local.get $set
              call $waitable-join
              local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.const 64
              i32.const 4
              call $stream-write
              i32.const -1
              i32.ne
              if unreachable end"#
        } else {
            r#"local.get $stream-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              call $stream-drop-writable"#
        };
        let output_closed_result = u32::from(drop_output_closed);
        let run = format!(
            r#"i32.const 80
              i32.const 0
              i32.store
              call $waitable-set-new
              local.set $set
              i32.const 84
              local.get $set
              i32.store
              {input_stream}
              local.get $input-closed
              local.get $set
              call $waitable-join
              local.get $input-closed
              i32.const 32
              call $future-read
              i32.const -1
              i32.ne
              if unreachable end
              call $stream-new
              local.set $stream-pair
              {output_stream}
              call $future-new
              local.set $closed-pair
              local.get $closed-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              local.get $set
              call $waitable-join
              i32.const 72
              i32.const 6
              i32.store8
              local.get $closed-pair
              i64.const 32
              i64.shr_u
              i32.wrap_i64
              i32.const 72
              call $future-write
              i32.const -1
              i32.ne
              if unreachable end
              {leak}
              local.get $stream-pair
              i32.wrap_i64
              local.get $closed-pair
              i32.wrap_i64
              call $task-return
              local.get $set
              i32.const 4
              i32.shl
              i32.const 2
              i32.or"#
        );
        let expected_events = 2 + u32::from(drop_input_stream) + u32::from(drop_output_stream);
        let callback = format!(
            r#"local.get $event
                  i32.const 2
                  i32.eq
                  if
                    local.get $p2
                    i32.const 1
                    i32.ne
                    if unreachable end
                    local.get $p1
                    call $stream-drop-readable
                  else
                    local.get $event
                    i32.const 3
                    i32.eq
                    if
                      local.get $p2
                      i32.const 1
                      i32.ne
                      if unreachable end
                      local.get $p1
                      call $stream-drop-writable
                    else
                      local.get $event
                      i32.const 4
                      i32.eq
                      if
                        local.get $p2
                        if unreachable end
                        local.get $p1
                        call $future-drop-readable
                      else
                        local.get $event
                        i32.const 5
                        i32.ne
                        if unreachable end
                        local.get $p2
                        i32.const {output_closed_result}
                        i32.ne
                        if unreachable end
                        local.get $p1
                        call $future-drop-writable
                      end
                    end
                  end
                  i32.const 80
                  i32.const 80
                  i32.load
                  i32.const 1
                  i32.add
                  i32.store
                  i32.const 80
                  i32.load
                  i32.const {expected_events}
                  i32.eq
                  if (result i32)
                    i32.const 84
                    i32.load
                    call $waitable-set-drop
                    i32.const 0
                  else
                    i32.const 84
                    i32.load
                    i32.const 4
                    i32.shl
                    i32.const 2
                    i32.or
                  end"#
        );
        filter_transport_component(&run, &callback)
    }

    fn drive_clean_filter_to_complete(
        call: &mut NativeAsyncInvocation<'_>,
        drop_input_stream: bool,
        drop_output_stream: bool,
        drop_output_closed: bool,
    ) {
        let mut saw_input_stream = false;
        let mut saw_input_closed = false;
        let mut saw_output_stream = false;
        let mut saw_output_closed = false;
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::HostPending {
                    token,
                    request: NativeAsyncHostRequest::InputStream { maximum: 4 },
                    ..
                } => {
                    assert!(drop_input_stream);
                    assert!(!saw_input_stream);
                    saw_input_stream = true;
                    assert!(matches!(
                        call.drop_host_copy_peer(token),
                        Ok(NativeAsyncPoll::Pending(_))
                    ));
                }
                NativeAsyncPoll::HostPending {
                    token,
                    request: NativeAsyncHostRequest::InputClosed,
                    ..
                } => {
                    assert!(!saw_input_closed);
                    saw_input_closed = true;
                    let token = match call.prepare_host_input_closed(token).unwrap() {
                        NativeAsyncPoll::HostPending {
                            token,
                            request: NativeAsyncHostRequest::InputClosed,
                            ..
                        } => token,
                        other => panic!("input future prepare failed: {other:?}"),
                    };
                    assert!(matches!(
                        call.commit_host_input_closed(token, 0),
                        Ok(NativeAsyncPoll::Pending(_))
                    ));
                }
                NativeAsyncPoll::HostPending {
                    token,
                    request: NativeAsyncHostRequest::OutputStream { maximum: 4 },
                    ..
                } => {
                    assert!(drop_output_stream);
                    assert!(!saw_output_stream);
                    saw_output_stream = true;
                    assert!(matches!(
                        call.drop_host_copy_peer(token),
                        Ok(NativeAsyncPoll::HostPending { .. } | NativeAsyncPoll::Pending(_))
                    ));
                }
                NativeAsyncPoll::HostPending {
                    token,
                    request: NativeAsyncHostRequest::OutputClosed { value: None },
                    ..
                } => {
                    assert!(!saw_output_closed);
                    saw_output_closed = true;
                    if drop_output_stream {
                        assert!(call.terminal_drops.output_stream.is_some());
                    }
                    if drop_output_closed {
                        assert!(matches!(
                            call.drop_host_copy_peer(token),
                            Ok(NativeAsyncPoll::Pending(_))
                        ));
                    } else {
                        let token = match call.prepare_host_output_closed(token).unwrap() {
                            NativeAsyncPoll::HostPending {
                                token,
                                request: NativeAsyncHostRequest::OutputClosed { value: Some(6) },
                                ..
                            } => token,
                            other => panic!("output future prepare failed: {other:?}"),
                        };
                        assert!(matches!(
                            call.commit_host_output(token),
                            Ok(NativeAsyncPoll::Pending(_))
                        ));
                    }
                }
                NativeAsyncPoll::HostPending { request, .. } => {
                    panic!("clean zero-byte filter requested {request:?}")
                }
                NativeAsyncPoll::WaitPending { .. } => {
                    let mut count = [0_u8; 4];
                    call.component
                        .modules
                        .read_memory(0, "memory", 80, &mut count)
                        .unwrap();
                    panic!(
                        "clean-filter completion event is not ready after callback count {}",
                        u32::from_le_bytes(count)
                    )
                }
                NativeAsyncPoll::Complete(_) => break,
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("clean filter entered cleanup before finalization: {trap:?}")
                }
                NativeAsyncPoll::Trapped(trap) => {
                    panic!("clean filter trapped before finalization: {trap:?}")
                }
            }
        }
        assert_eq!(saw_input_stream, drop_input_stream);
        assert!(saw_input_closed);
        assert_eq!(saw_output_stream, drop_output_stream);
        assert!(saw_output_closed);
        assert_eq!(
            call.terminal_drops.input_stream.is_some(),
            drop_input_stream
        );
        assert_eq!(
            call.terminal_drops.output_stream.is_some(),
            drop_output_stream
        );
        assert_eq!(
            call.terminal_drops.output_closed.is_some(),
            drop_output_closed
        );
        assert_eq!(call.component.buffers.live(), 0);
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("wait fixture unexpectedly requested host transport")
                }
                NativeAsyncPoll::Complete(_) => panic!("wait fixture completed before WAIT"),
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("wait fixture entered cleanup: {trap:?}")
                }
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("cancel callback unexpectedly requested host transport")
                }
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("cancel callback entered cleanup: {trap:?}")
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
                pending @ NativeAsyncPoll::CleanupPending { .. } => {
                    let NativeAsyncPoll::Trapped(trap) = finish_cleanup_turn(&mut call, pending)
                    else {
                        unreachable!("cleanup helper pins its terminal result")
                    };
                    return trap;
                }
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("invalid handle fixture unexpectedly waited")
                }
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("invalid handle fixture unexpectedly requested host transport")
                }
                NativeAsyncPoll::Complete(_) => panic!("invalid handle fixture completed"),
            }
        }
    }

    /// Executes exactly one owner-visible poll and pins its aggregate work.
    fn poll_within_quantum(call: &mut NativeAsyncInvocation<'_>) -> NativeAsyncPoll {
        let before = call.metrics().consumed_work;
        let progress = call.poll();
        let delta = call.metrics().consumed_work - before;
        assert!(
            delta <= call.poll_quantum,
            "one public poll spent {delta} work with quantum {}",
            call.poll_quantum
        );
        progress
    }

    fn finish_cleanup_turn(
        call: &mut NativeAsyncInvocation<'_>,
        pending: NativeAsyncPoll,
    ) -> NativeAsyncPoll {
        let NativeAsyncPoll::CleanupPending { trap, metrics } = pending else {
            return pending;
        };
        assert_eq!(metrics, call.metrics());
        assert!(call.component.is_poisoned());
        assert_eq!(call.stage, InvocationStage::Cleanup);
        let exact = call.component.fail_stop_cleanup_work;
        let before = call.metrics();
        let terminal = poll_within_quantum(call);
        let after = call.metrics();
        assert_eq!(before.remaining_work - after.remaining_work, exact);
        assert_eq!(after.consumed_work - before.consumed_work, exact);
        assert_eq!(terminal, NativeAsyncPoll::Trapped(trap));
        terminal
    }

    fn finish_finalize_cleanup_turn(
        call: &mut NativeAsyncInvocation<'_>,
        pending: NativeAsyncFinalizeError,
    ) -> NativeAsyncPoll {
        let NativeAsyncFinalizeError::CleanupPending { trap, metrics } = pending else {
            panic!("finalize invariant did not retain fail-stop cleanup: {pending:?}")
        };
        finish_cleanup_turn(call, NativeAsyncPoll::CleanupPending { trap, metrics })
    }

    /// Drives at most one deferred Core outcome and, for legacy fixture
    /// callers, a separately measured cleanup turn.
    fn poll_after_core_turn(call: &mut NativeAsyncInvocation<'_>) -> NativeAsyncPoll {
        let first = poll_within_quantum(call);
        let progress = if call.deferred_core.is_none() {
            first
        } else {
            assert!(matches!(first, NativeAsyncPoll::Pending(_)));
            poll_within_quantum(call)
        };
        finish_cleanup_turn(call, progress)
    }

    fn assert_exact_run_bridge_debits(call: &mut NativeAsyncInvocation<'_>) -> usize {
        let active = call.binding().core_instance;
        let work_costs = call.component.work_costs();
        let mut handle_transitions = 0;
        loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => {
                    let action = call.component.bridges[host.id as usize].action;
                    let expected = match action {
                        BridgeAction::TaskReturn(RuntimeExportContract::Unit) => TASK_RETURN_WORK,
                        BridgeAction::TaskReturn(RuntimeExportContract::ByteStream(_))
                        | BridgeAction::StreamNew(_)
                        | BridgeAction::FutureNew(_)
                        | BridgeAction::DropEndpoint { .. }
                        | BridgeAction::WaitableSetNew
                        | BridgeAction::WaitableSetDrop
                        | BridgeAction::WaitableJoin => {
                            handle_transitions += 1;
                            work_costs.handle_state
                        }
                        BridgeAction::StreamCopy { .. }
                        | BridgeAction::StreamCancel { .. }
                        | BridgeAction::FutureCopy { .. }
                        | BridgeAction::FutureCancel { .. } => {
                            handle_transitions += 1;
                            work_costs.buffer_bridge
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("callback unexpectedly requested host transport")
                }
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("callback entered cleanup: {trap:?}")
                }
                NativeAsyncPoll::Trapped(trap) => panic!("callback trapped: {trap:?}"),
            }
        }
    }

    fn assert_smoke_sequence(component: &mut NativeAsyncComponent) -> NativeAsyncMetrics {
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Resolved(_)
        ));
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
        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        let NativeAsyncPoll::Complete(metrics) = poll_after_core_turn(&mut call) else {
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
                PROFILE_1_LIMITS.max_memory_pages as usize * 65_536,
                PROFILE_1_LIMITS.max_resources,
            )
            .err(),
            Some(NativeAsyncError::AsyncUnavailable)
        );
    }

    #[test]
    fn manifest_resource_ceiling_binds_arenas_metrics_and_state_work() {
        assert_eq!(
            instantiate_with_resource_limit(SMOKE, 0).err(),
            Some(NativeAsyncError::InvalidBudget)
        );
        assert_eq!(
            instantiate_with_resource_limit(SMOKE, PROFILE_1_LIMITS.max_resources + 1).err(),
            Some(NativeAsyncError::InvalidBudget)
        );

        let mut component = instantiate_with_resource_limit(SMOKE, 8).unwrap();
        assert_eq!(
            component.work_costs(),
            NativeAsyncWorkCosts {
                handle_state: 65,
                buffer_state: 9,
                buffer_bridge: 74,
                wait_state: 65,
            }
        );
        let storage = component.storage_metrics();
        assert_eq!(
            storage.async_state.handles,
            AsyncArenaUsage {
                current: 0,
                peak: 0,
                limit: 8,
            }
        );
        assert_eq!(storage.async_state.pairs.limit, 8);
        assert_eq!(storage.async_state.tasks.limit, 1);
        assert_eq!(storage.async_state.joined_waitables.limit, 8);
        assert_eq!(storage.async_state.wait_registrations.limit, 1);
        assert_eq!(
            storage.buffers,
            AsyncArenaUsage {
                current: 0,
                peak: 0,
                limit: 8,
            }
        );

        let value_type = AsyncValueTypeId::new(1).unwrap();
        for _ in 0..4 {
            component.state.create_stream_pair(value_type).unwrap();
        }
        let full = component.storage_metrics();
        assert_eq!(
            (
                full.async_state.handles.current,
                full.async_state.handles.peak
            ),
            (8, 8)
        );
        assert_eq!(
            (full.async_state.pairs.current, full.async_state.pairs.peak),
            (4, 4)
        );
        assert!(matches!(
            component.state.create_stream_pair(value_type),
            Err(AsyncStateError::HandleTableFull)
        ));
        assert_eq!(component.storage_metrics(), full);
    }

    #[test]
    fn core_host_and_ready_outcomes_are_deferred_with_one_quantum_per_public_poll() {
        const PIN_QUANTUM: u64 = 100;
        let mut component = instantiate_with_resource_limit(SMOKE, 8).unwrap();
        let mut call = component.start("run", WORK, PIN_QUANTUM).unwrap();

        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        assert!(matches!(
            call.deferred_core.as_ref(),
            Some(DeferredCoreTurn::Host {
                authority: CallAuthority::Run(_),
                ..
            })
        ));
        assert_eq!(call.task_info().result, TaskResultState::Pending);

        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Resolved(_)
        ));
        assert!(call.deferred_core.is_none());
        assert_eq!(call.task_info().result, TaskResultState::Resolved);

        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        assert!(matches!(
            call.deferred_core.as_ref(),
            Some(DeferredCoreTurn::RunReady(_))
        ));
        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
        assert!(call.deferred_core.is_none());

        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Complete(_)
        ));
    }

    #[test]
    fn fail_stop_cleanup_is_a_separate_exact_reserved_quantum() {
        const PIN_QUANTUM: u64 = 100;
        let source = replace_once(
            SMOKE,
            "    (func (export \"run\") (result i32)\n      call $task-return\n      i32.const 1)",
            "    (func (export \"run\") (result i32)\n      unreachable)",
        );
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        assert_eq!(component.fail_stop_cleanup_work, 70);
        assert!(component.fail_stop_cleanup_work <= PIN_QUANTUM);
        let mut call = component.start("run", WORK, PIN_QUANTUM).unwrap();

        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        assert!(matches!(
            call.deferred_core,
            Some(DeferredCoreTurn::Trapped(TrapCode::Unreachable))
        ));
        let before_failure = call.metrics();
        let NativeAsyncPoll::CleanupPending { trap, metrics } = poll_within_quantum(&mut call)
        else {
            panic!("deferred Core trap did not enter fail-stop cleanup")
        };
        assert_eq!(trap, TrapCode::Unreachable);
        assert_eq!(metrics, before_failure);
        assert_eq!(call.metrics(), before_failure);
        assert_eq!(call.stage, InvocationStage::Cleanup);
        assert!(!call.terminal);
        assert!(call.component.is_poisoned());
        assert!(call.host_token.is_none());
        assert!(call.wait_token.is_none());
        assert!(call.deferred_core.is_none());

        let terminal = poll_within_quantum(&mut call);
        assert_eq!(terminal, NativeAsyncPoll::Trapped(TrapCode::Unreachable));
        assert_eq!(call.stage, InvocationStage::Terminal);
        assert!(call.terminal);
        assert_eq!(call.cleanup_reserve, 0);
        assert_eq!(
            call.metrics().consumed_work - before_failure.consumed_work,
            70
        );
        assert_eq!(
            before_failure.remaining_work - call.metrics().remaining_work,
            70
        );
    }

    #[test]
    fn minimum_quantum_rejection_precedes_unit_and_filter_state_mutation() {
        let mut unit = instantiate_with_resource_limit(SMOKE, 8).unwrap();
        let unit_minimum = unit.minimum_poll_quantum(&unit.exports[0]).unwrap();
        assert_eq!(unit_minimum, 79);
        let unit_storage = unit.storage_metrics();
        let unit_generation = unit.callback_slots[0].generation();
        assert_eq!(
            unit.start("run", WORK, unit_minimum - 1).err(),
            Some(NativeAsyncError::InvalidBudget)
        );
        assert_eq!(unit.storage_metrics(), unit_storage);
        assert_eq!(unit.callback_slots[0].state(), CoreCallSlotState::Idle);
        assert_eq!(unit.callback_slots[0].generation(), unit_generation);
        assert!(!unit.modules.any_active_call());
        assert!(!unit.is_poisoned());

        let source = input_transport_component();
        let mut filter = instantiate_with_resource_limit(&source, 8).unwrap();
        let filter_minimum = filter.minimum_poll_quantum(&filter.exports[0]).unwrap();
        assert_eq!(filter_minimum, 79);
        let filter_storage = filter.storage_metrics();
        let filter_generation = filter.callback_slots[0].generation();
        assert_eq!(
            filter.start_filter("run", WORK, filter_minimum - 1).err(),
            Some(NativeAsyncError::InvalidBudget)
        );
        assert_eq!(filter.storage_metrics(), filter_storage);
        assert_eq!(filter.callback_slots[0].state(), CoreCallSlotState::Idle);
        assert_eq!(filter.callback_slots[0].generation(), filter_generation);
        assert!(!filter.modules.any_active_call());
        assert!(!filter.is_poisoned());
    }

    #[test]
    fn resource_eight_quantum_100_pins_host_99_and_local_prefix_eight() {
        const PIN_QUANTUM: u64 = 100;
        let source = filter_transport_component(
            r#"local.get $input-bytes
              i32.const 16
              i32.const 1024
              call $stream-read
              i32.const -1
              i32.ne
              if unreachable end
              unreachable"#,
            "i32.const 0",
        );
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let costs = component.work_costs();
        assert_eq!(costs.buffer_bridge, 74);
        let scratch_bytes = component.buffers.scratch_bytes();
        assert!(scratch_bytes >= 1024);
        let available_copy_work = PIN_QUANTUM - costs.buffer_bridge;
        assert_eq!(available_copy_work, 26);
        assert_eq!(
            maximum_local_copy_progress(1024, scratch_bytes, available_copy_work),
            Some(8)
        );
        assert_eq!(buffer_copy_work(8, scratch_bytes), Some(26));
        assert_eq!(
            costs.buffer_bridge + buffer_copy_work(8, scratch_bytes).unwrap(),
            PIN_QUANTUM
        );
        assert!(costs.buffer_bridge + buffer_copy_work(9, scratch_bytes).unwrap() > PIN_QUANTUM);

        let mut call = component.start_filter("run", WORK, PIN_QUANTUM).unwrap();
        let (offered, maximum) = loop {
            match poll_within_quantum(&mut call) {
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::HostPending {
                    token,
                    request: NativeAsyncHostRequest::InputStream { maximum },
                    ..
                } => break (token, maximum),
                other => panic!("large input did not reach HostPending: {other:?}"),
            }
        };
        assert_eq!(maximum, 99);

        let before_prepare = call.metrics();
        let prepared = match call.prepare_host_input_stream(offered, maximum).unwrap() {
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::InputStream { maximum: 99 },
                ..
            } => token,
            other => panic!("99-byte host prepare failed: {other:?}"),
        };
        assert_eq!(
            call.metrics().consumed_work - before_prepare.consumed_work,
            PIN_QUANTUM
        );
        let before_commit = call.metrics();
        assert!(matches!(
            call.commit_host_input_stream(prepared, &[0x5a; 99]),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        assert!(call.metrics().consumed_work - before_commit.consumed_work <= PIN_QUANTUM);

        let run = r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      i32.const 16
      i64.const 0x0807060504030201
      i64.store
      i32.const 32
      i64.const 0xaaaaaaaaaaaaaaaa
      i64.store
      i32.const 40
      i32.const 170
      i32.store8
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 16
      i32.const 1024
      call $stream-write
      i32.const -1
      i32.ne
      if unreachable end
      local.get $pair
      i32.wrap_i64
      i32.const 32
      i32.const 1024
      call $stream-read
      i32.const 128
      i32.ne
      if unreachable end
      i32.const 48
      i32.const 1
      i32.store
      i32.const 32
      i64.load
      i64.const 0x0807060504030201
      i64.ne
      if unreachable end
      i32.const 40
      i32.load8_u
      i32.const 170
      i32.ne
      if unreachable end
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      call $stream-cancel-write
      i32.const 128
      i32.ne
      if unreachable end
      i32.const 48
      i32.const 48
      i32.load
      i32.const 1
      i32.add
      i32.store
      call $task-return
      i32.const 1)"#;
        let source = byte_stream_component(
            run,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut call = component.start("run", WORK, PIN_QUANTUM).unwrap();
        let mut saw_exact_local_turn = false;
        loop {
            let before = call.metrics();
            let live_before = call.component.buffers.live();
            let progress = poll_within_quantum(&mut call);
            let delta = call.metrics().consumed_work - before.consumed_work;
            if live_before == 1 && call.component.buffers.live() == 1 && delta == PIN_QUANTUM {
                assert!(!saw_exact_local_turn);
                saw_exact_local_turn = true;
            }
            match progress {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Complete(_) => break,
                other => panic!("local eight-byte rendezvous failed: {other:?}"),
            }
        }
        assert!(saw_exact_local_turn);
        let mut copied = [0_u8; 9];
        call.component
            .modules
            .read_memory(0, "memory", 32, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 3, 4, 5, 6, 7, 8, 0xaa]);
        let mut events = [0_u8; 4];
        call.component
            .modules
            .read_memory(0, "memory", 48, &mut events)
            .unwrap();
        assert_eq!(u32::from_le_bytes(events), 2);
    }

    #[test]
    fn remaining_fuel_clamps_host_and_local_stream_prefixes() {
        const PIN_QUANTUM: u64 = 100;
        let source = input_transport_component();
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut call = component.start_filter("run", WORK, PIN_QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let authority = CallAuthority::Run(active);
        let host = loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(authority));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => break host,
                other => panic!("input clamp fixture did not reach stream.read: {other:?}"),
            }
        };
        assert!(matches!(
            call.component.bridges[host.id as usize].action,
            BridgeAction::StreamCopy {
                direction: EndpointDirection::Read,
                ..
            }
        ));
        let desired_spendable = call
            .component
            .work_costs
            .buffer_bridge
            .checked_add(host_copy_work(2).unwrap())
            .and_then(|work| work.checked_add(1))
            .unwrap();
        let desired_remaining = call
            .reserved_work()
            .and_then(|reserve| reserve.checked_add(desired_spendable))
            .unwrap();
        let excess = call.remaining_work.checked_sub(desired_remaining).unwrap();
        call.debit_active_work(authority, excess).unwrap();
        let before = call.metrics();
        let NativeAsyncPoll::HostPending {
            token,
            request: NativeAsyncHostRequest::InputStream { maximum },
            metrics,
        } = call.handle_host_call(authority, host)
        else {
            panic!("low remaining fuel did not offer a host prefix")
        };
        assert_eq!(maximum, 2);
        assert_eq!(
            metrics.consumed_work - before.consumed_work,
            call.component.work_costs.buffer_bridge
        );
        let prepared = match call.prepare_host_input_stream(token, maximum).unwrap() {
            NativeAsyncPoll::HostPending { token, .. } => token,
            other => panic!("clamped host prefix did not prepare: {other:?}"),
        };
        assert!(matches!(
            call.commit_host_input_stream(prepared, &[1, 2]),
            Ok(NativeAsyncPoll::Pending(_))
        ));

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
      drop
      local.get $pair
      i32.wrap_i64
      i32.const 24
      i32.const 4
      call $stream-read
      drop
      unreachable)"#;
        let source = byte_stream_component(
            run,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      unreachable)"#,
        );
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut call = component.start("run", WORK, PIN_QUANTUM).unwrap();
        let active = call.binding().core_instance;
        let authority = CallAuthority::Run(active);
        let mut stream_copies = 0;
        loop {
            let result = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(authority));
            match result {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => {
                    if matches!(
                        call.component.bridges[host.id as usize].action,
                        BridgeAction::StreamCopy { .. }
                    ) {
                        stream_copies += 1;
                    }
                    if stream_copies == 2 {
                        let local_work =
                            buffer_copy_work(2, call.component.buffers.scratch_bytes()).unwrap();
                        let desired_spendable = call
                            .component
                            .work_costs
                            .buffer_bridge
                            .checked_add(local_work)
                            .and_then(|work| work.checked_add(1))
                            .unwrap();
                        let desired_remaining = call
                            .reserved_work()
                            .and_then(|reserve| reserve.checked_add(desired_spendable))
                            .unwrap();
                        let excess = call.remaining_work.checked_sub(desired_remaining).unwrap();
                        call.debit_active_work(authority, excess).unwrap();
                        let before = call.metrics();
                        assert!(matches!(
                            call.handle_host_call(authority, host),
                            NativeAsyncPoll::Pending(_)
                        ));
                        let after = call.metrics();
                        assert_eq!(
                            after.consumed_work - before.consumed_work,
                            call.component.work_costs.buffer_bridge + local_work
                        );
                        break;
                    }
                    assert!(matches!(
                        call.handle_host_call(authority, host),
                        NativeAsyncPoll::Pending(_)
                    ));
                }
                other => panic!("local clamp fixture failed before rendezvous: {other:?}"),
            }
        }
        assert_eq!(stream_copies, 2);
        let mut copied = [0_u8; 4];
        call.component
            .modules
            .read_memory(0, "memory", 24, &mut copied)
            .unwrap();
        assert_eq!(copied, [1, 2, 0xaa, 0xaa]);
    }

    #[cfg(feature = "native-async-acceptance")]
    #[test]
    fn acceptance_facade_requires_an_explicit_candidate_and_manifest_limits() {
        let source = clean_finalize_component(false);
        let bytes = wat::parse_str(&source).unwrap();
        let plan = inspect_component_for_profile(
            &bytes,
            ProfileIdentity::PROFILE_1_NATIVE_ASYNC_RESOURCE_FREE,
        )
        .unwrap();
        assert!(!plan.native_async_runtime_ready());
        assert_eq!(
            NativeAsyncComponent::instantiate(
                &plan,
                &ProfileEngine::new(),
                OwnerAllocationReservation::profile_default(),
                65_536,
                PROFILE_1_LIMITS.max_resources,
            )
            .err(),
            Some(NativeAsyncError::AsyncUnavailable)
        );
        assert_eq!(
            NativeAsyncComponent::instantiate_validation_candidate_with_memory_limit(
                &plan,
                &ProfileEngine::new(),
                OwnerAllocationReservation::profile_default(),
                65_535,
                PROFILE_1_LIMITS.max_resources,
            )
            .err(),
            Some(NativeAsyncError::CoreInstantiation)
        );
        let component: crate::native_async_acceptance::Component =
            NativeAsyncComponent::instantiate_validation_candidate_with_memory_limit(
                &plan,
                &ProfileEngine::new(),
                OwnerAllocationReservation::profile_default(),
                65_536,
                PROFILE_1_LIMITS.max_resources,
            )
            .unwrap();
        assert!(!component.is_poisoned());
    }

    #[test]
    fn finalize_success_debits_exact_reserved_turn_and_clean_completion_is_reusable() {
        let source = clean_finalize_component(false);
        let mut component = instantiate(&source);
        for invocation in 0..2 {
            {
                let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
                let before_metrics = call.metrics();
                let before_stream = call.input.as_ref().unwrap().first.guest;
                let before_closed = call.input.as_ref().unwrap().second.guest;
                assert_eq!(
                    call.finalize_transport(),
                    Err(NativeAsyncFinalizeError::NotReady)
                );
                assert_eq!(call.metrics(), before_metrics);
                assert_eq!(call.input.as_ref().unwrap().first.guest, before_stream);
                assert_eq!(call.input.as_ref().unwrap().second.guest, before_closed);
                assert!(!call.component.is_poisoned());

                drive_clean_filter_to_complete(&mut call, false, false, false);
                let before_finalize = call.metrics();
                let exact_finalize = call.component.fail_stop_cleanup_work;
                assert_eq!(call.finalize_reserve, exact_finalize);
                assert_eq!(call.cleanup_reserve, exact_finalize);
                assert_eq!(call.finalize_transport(), Ok(()));
                let after_finalize = call.metrics();
                assert_eq!(
                    after_finalize.consumed_work - before_finalize.consumed_work,
                    exact_finalize
                );
                assert_eq!(
                    before_finalize.remaining_work - after_finalize.remaining_work,
                    exact_finalize
                );
                assert_eq!(call.finalize_reserve, 0);
                assert_eq!(call.cleanup_reserve, 0);
                assert!(call.input.is_none());
                assert!(call.output_stream.is_none());
                assert!(call.output_closed.is_none());
                assert_eq!(
                    call.finalize_transport(),
                    Err(NativeAsyncFinalizeError::AlreadyFinalized)
                );
            }
            assert!(
                !component.is_poisoned(),
                "clean finalized invocation {invocation} poisoned its component"
            );
        }
    }

    #[test]
    fn consumed_host_peers_finalize_exactly_and_input_eof_is_reusable() {
        // Real input EOF consumes the input stream's Host writer. Its receipt
        // remains bound to the old pair generation until the guest reclaims
        // the Dropped event and drops its readable endpoint.
        let source = clean_finalize_component_with_peer_drops(true, false, false, false);
        let mut component = instantiate(&source);
        for invocation in 0..2 {
            {
                let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
                drive_clean_filter_to_complete(&mut call, true, false, false);
                assert!(call.terminal_drops.input_stream.is_some());
                assert_eq!(call.finalize_transport(), Ok(()));
                assert!(call.terminal_drops.input_stream.is_none());
            }
            assert!(
                !component.is_poisoned(),
                "input EOF invocation {invocation} did not remain reusable"
            );
        }

        // The first queued output copy is dropped before the close future is
        // activated. This proves the stream receipt is archived before the
        // fixed second request advances; dropping that future archives the
        // third and final legal receipt slot as well.
        let source = clean_finalize_component_with_peer_drops(false, true, true, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        drive_clean_filter_to_complete(&mut call, false, true, true);
        assert!(call.terminal_drops.input_stream.is_none());
        assert!(call.terminal_drops.output_stream.is_some());
        assert!(call.terminal_drops.output_closed.is_some());
        assert_eq!(call.finalize_transport(), Ok(()));
        drop(call);
        assert!(!component.is_poisoned());

        // Mixed retained/consumed state exercises an allocation-free commit
        // of only the two pairs whose Host holders remain live.
        let source = clean_finalize_component_with_peer_drops(true, true, false, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        drive_clean_filter_to_complete(&mut call, true, true, false);
        assert_eq!(call.finalize_transport(), Ok(()));
        drop(call);
        assert!(!component.is_poisoned());

        // All three droppable peers consumed leaves only InputClosed retained,
        // exercising the one-pair terminal commit.
        let source = clean_finalize_component_with_peer_drops(true, true, true, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        drive_clean_filter_to_complete(&mut call, true, true, true);
        assert_eq!(call.finalize_transport(), Ok(()));
        drop(call);
        assert!(!component.is_poisoned());
    }

    #[test]
    fn finalize_wrong_contract_is_read_only() {
        let mut component = instantiate(SMOKE);
        {
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let before_metrics = call.metrics();
            let before_task = call.task_info();
            assert_eq!(
                call.finalize_transport(),
                Err(NativeAsyncFinalizeError::WrongContract)
            );
            assert_eq!(call.metrics(), before_metrics);
            assert_eq!(call.task_info(), before_task);
            assert!(!call.component.is_poisoned());
            loop {
                match call.poll() {
                    NativeAsyncPoll::Pending(_)
                    | NativeAsyncPoll::Resolved(_)
                    | NativeAsyncPoll::Yielded(_) => {}
                    NativeAsyncPoll::Complete(_) => break,
                    other => panic!("unit call changed by wrong finalize: {other:?}"),
                }
            }
        }
        assert!(!component.is_poisoned());
    }

    #[test]
    fn terminal_transport_invariant_debits_finalize_then_cleanup_in_distinct_turns() {
        // A guest callback which exits without dropping every retained peer
        // has no remaining execution path that could make progress. This is
        // terminal malformed cleanup, not a retryable early finalize.
        let source = output_transport_component(false, false, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::Complete(_) => break,
                other => panic!("unclean terminal fixture failed early: {other:?}"),
            }
        }
        assert_eq!(call.component.buffers.live(), 0);
        let exact = call.component.fail_stop_cleanup_work;
        let before_finalize = call.metrics();
        let finalize_pending = call.finalize_transport().unwrap_err();
        let NativeAsyncFinalizeError::CleanupPending { trap, metrics } = finalize_pending else {
            panic!("terminal invariant did not enter finalize cleanup")
        };
        assert_eq!(trap, TrapCode::Validation);
        assert_eq!(metrics, call.metrics());
        assert_eq!(metrics.consumed_work - before_finalize.consumed_work, exact);
        assert_eq!(
            before_finalize.remaining_work - metrics.remaining_work,
            exact
        );
        assert_eq!(call.finalize_reserve, 0);
        assert_eq!(call.cleanup_reserve, exact);
        assert_eq!(call.stage, InvocationStage::Cleanup);
        assert!(!call.terminal);
        assert!(!call.transport_finalized);
        assert!(call.component.is_poisoned());
        let before_cleanup = call.metrics();
        assert_eq!(
            finish_finalize_cleanup_turn(&mut call, finalize_pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        let after_cleanup = call.metrics();
        assert_eq!(
            after_cleanup.consumed_work - before_cleanup.consumed_work,
            exact
        );
        assert_eq!(
            before_cleanup.remaining_work - after_cleanup.remaining_work,
            exact
        );
        assert_eq!(call.cleanup_reserve, 0);

        // Even with the expected four pairs otherwise clean, an unrelated
        // live guest pair at callback Exit violates the exact global baseline.
        let source = clean_finalize_component(true);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        drive_clean_filter_to_complete(&mut call, false, false, false);
        let finalize_pending = call.finalize_transport().unwrap_err();
        assert_eq!(
            finish_finalize_cleanup_turn(&mut call, finalize_pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        assert!(!call.transport_finalized);
        assert!(call.component.is_poisoned());

        // A consumed input stream receipt remains bound to its old generation.
        // Reusing the raw handle/pair slots with a new live aggregate must not
        // let the stale receipt substitute for that replacement.
        let source = clean_finalize_component_with_peer_drops(true, false, false, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let old_input = call.input.as_ref().unwrap().first.guest;
        drive_clean_filter_to_complete(&mut call, true, false, false);
        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("replacement fixture lost its filter contract")
        };
        let replacement = call
            .component
            .state
            .insert_host_readables_pair(
                (EndpointKind::Stream, contract.stream),
                (EndpointKind::Future, contract.closed),
            )
            .unwrap();
        assert_eq!(replacement.first.guest.raw(), old_input.raw());
        assert_ne!(replacement.first.guest, old_input);
        let finalize_pending = call.finalize_transport().unwrap_err();
        assert_eq!(
            finish_finalize_cleanup_turn(&mut call, finalize_pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        assert!(!call.transport_finalized);
        assert!(call.component.is_poisoned());
        drop(replacement);
    }

    #[test]
    fn live_buffer_at_terminal_finalize_is_a_fail_stop_invariant() {
        let source = clean_finalize_component(false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        drive_clean_filter_to_complete(&mut call, false, false, false);
        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("clean filter lost its byte-stream contract")
        };
        let prepared = call
            .component
            .buffers
            .preflight(
                &call.component.modules,
                BufferPlanId::new(contract.stream.get()).unwrap(),
                call.component
                    .modules
                    .memory_authority(0, "memory")
                    .unwrap(),
                BufferRole::TargetRead,
                0,
                0,
                contract.stream,
            )
            .unwrap();
        let _orphaned_for_invariant_test = call.component.buffers.issue(prepared).unwrap();
        assert_eq!(call.component.buffers.live(), 1);
        let finalize_pending = call.finalize_transport().unwrap_err();
        assert!(!call.transport_finalized);
        assert!(call.component.is_poisoned());
        assert_eq!(call.component.buffers.live(), 1);
        assert_eq!(
            finish_finalize_cleanup_turn(&mut call, finalize_pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
        assert_eq!(call.component.buffers.live(), 0);
    }

    #[test]
    fn native_filter_rejects_an_undrivable_host_backed_input_echo_atomically() {
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
                NativeAsyncPoll::Pending(_) => {}
                pending @ NativeAsyncPoll::CleanupPending {
                    trap: TrapCode::CanonicalAbi,
                    ..
                } => {
                    assert_eq!(
                        finish_cleanup_turn(&mut call, pending),
                        NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                    );
                    break;
                }
                other => panic!("host-backed input echo must fail closed: {other:?}"),
            }
        }
        assert!(call.output_stream.is_none());
        assert!(call.output_closed.is_none());
        assert!(call.input.is_none());
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn native_filter_rejects_a_mixed_host_backed_result_before_partial_transfer() {
        let source = filter_transport_component(
            r#"call $stream-new
              local.set $stream-pair
              local.get $stream-pair
              i32.wrap_i64
              local.get $input-closed
              call $task-return
              unreachable"#,
            "i32.const 0",
        );
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        loop {
            match call.poll() {
                NativeAsyncPoll::Pending(_) => {}
                pending @ NativeAsyncPoll::CleanupPending {
                    trap: TrapCode::CanonicalAbi,
                    ..
                } => {
                    assert_eq!(
                        finish_cleanup_turn(&mut call, pending),
                        NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                    );
                    break;
                }
                other => panic!("mixed host-backed result must fail closed: {other:?}"),
            }
        }
        assert!(call.output_stream.is_none());
        assert!(call.output_closed.is_none());
        assert!(call.component.is_poisoned());
    }

    #[test]
    fn input_host_transport_is_stable_two_phase_and_token_exact_in_both_directions() {
        let source = input_transport_component();
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let input_stream = call.input.as_ref().unwrap().first.guest;
        let input_closed = call.input.as_ref().unwrap().second.guest;
        let (offered, request, metrics) = poll_to_host(&mut call);
        assert_eq!(request, NativeAsyncHostRequest::InputStream { maximum: 4 });
        assert_eq!(format!("{offered:?}"), "NativeAsyncHostToken(<opaque>)");

        let active = call.binding().core_instance;
        let core_metrics = call.component.modules.call_metrics(active).unwrap();
        let mut target = [0xff; 4];
        call.component
            .modules
            .read_memory(0, "memory", 16, &mut target)
            .unwrap();
        assert_eq!(target, [0; 4]);
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::HostPending {
                token: offered,
                request,
                metrics,
            }
        );
        assert_eq!(call.metrics(), metrics);
        assert_eq!(
            call.component.modules.call_metrics(active),
            Some(core_metrics)
        );

        let wrong_generation = NativeAsyncHostToken {
            task: offered.task,
            generation: NonZeroU64::new(offered.generation.get() + 37).unwrap(),
        };
        assert_eq!(
            call.prepare_host_input_stream(wrong_generation, 4),
            Err(NativeAsyncHostError::InvalidToken)
        );
        assert_eq!(
            call.prepare_host_input_closed(offered),
            Err(NativeAsyncHostError::WrongRequest)
        );
        assert_eq!(call.metrics(), metrics);

        let mut other_component = instantiate(&source);
        let mut other_call = other_component.start_filter("run", WORK, QUANTUM).unwrap();
        let (cross_component, _, _) = poll_to_host(&mut other_call);
        assert_eq!(
            call.prepare_host_input_stream(cross_component, 4),
            Err(NativeAsyncHostError::InvalidToken)
        );
        assert_eq!(call.metrics(), metrics);

        let prepared = call.prepare_host_input_stream(offered, 4).unwrap();
        let (prepared, prepared_request, prepared_metrics) = match prepared {
            NativeAsyncPoll::HostPending {
                token,
                request,
                metrics,
            } => (token, request, metrics),
            other => panic!("input stream prepare must stay host-blocked: {other:?}"),
        };
        assert_ne!(prepared, offered);
        assert!(prepared.strictly_after(offered));
        assert!(!offered.strictly_after(prepared));
        assert!(!cross_component.strictly_after(offered));
        assert_eq!(prepared_request, request);
        assert_eq!(
            prepared_metrics.consumed_work - metrics.consumed_work,
            host_copy_work(4).unwrap()
        );
        assert_eq!(
            call.commit_host_input_stream(offered, &[1, 2, 3, 4]),
            Err(NativeAsyncHostError::InvalidToken)
        );
        assert_eq!(
            call.commit_host_input_stream(prepared, &[1, 2, 3]),
            Err(NativeAsyncHostError::InvalidProgress)
        );
        assert_eq!(call.metrics(), prepared_metrics);
        assert!(matches!(
            call.commit_host_input_stream(prepared, &[1, 2, 3, 4]),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        call.component
            .modules
            .read_memory(0, "memory", 16, &mut target)
            .unwrap();
        assert_eq!(target, [1, 2, 3, 4]);
        assert!(
            call.component
                .state
                .endpoint_info(input_stream)
                .unwrap()
                .has_pending_event
        );

        let (closed_offered, closed_request, closed_metrics) = poll_to_host(&mut call);
        assert_eq!(closed_request, NativeAsyncHostRequest::InputClosed);
        assert_ne!(closed_offered, offered);
        assert_ne!(closed_offered, prepared);
        assert!(closed_offered.strictly_after(prepared));
        assert_eq!(
            call.prepare_host_input_stream(prepared, 1),
            Err(NativeAsyncHostError::InvalidToken)
        );
        assert_eq!(
            call.drop_host_copy_peer(closed_offered),
            Err(NativeAsyncHostError::WrongRequest)
        );
        assert_eq!(call.metrics(), closed_metrics);
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::HostPending {
                token: closed_offered,
                request: closed_request,
                metrics: closed_metrics,
            }
        );
        let closed_prepared = match call.prepare_host_input_closed(closed_offered).unwrap() {
            NativeAsyncPoll::HostPending { token, metrics, .. } => {
                assert_eq!(
                    metrics.consumed_work - closed_metrics.consumed_work,
                    host_copy_work(1).unwrap()
                );
                token
            }
            other => panic!("input close prepare must stay host-blocked: {other:?}"),
        };
        assert!(matches!(
            call.commit_host_input_closed(closed_prepared, 6),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        let mut closed = [0xff];
        call.component
            .modules
            .read_memory(0, "memory", 32, &mut closed)
            .unwrap();
        assert_eq!(closed, [6]);
        assert!(
            call.component
                .state
                .endpoint_info(input_closed)
                .unwrap()
                .has_pending_event
        );
    }

    #[test]
    fn two_pending_outputs_are_ordered_frozen_and_read_once_before_commit() {
        let source = output_transport_component(true, true, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let (stream_offered, stream_request, stream_metrics) = poll_to_host(&mut call);
        assert_eq!(
            stream_request,
            NativeAsyncHostRequest::OutputStream { maximum: 4 }
        );
        assert!(call.host_next.is_some());
        assert_eq!(call.task_info().result, TaskResultState::Resolved);
        assert!(call.output_stream.is_some());
        assert!(call.output_closed.is_some());

        let active = call.binding().core_instance;
        let core_metrics = call.component.modules.call_metrics(active).unwrap();
        let mut source_bytes = [0; 4];
        call.component
            .modules
            .read_memory(0, "memory", 64, &mut source_bytes)
            .unwrap();
        assert_eq!(source_bytes, [1, 2, 3, 4]);
        assert_eq!(
            call.poll(),
            NativeAsyncPoll::HostPending {
                token: stream_offered,
                request: stream_request,
                metrics: stream_metrics,
            }
        );
        assert_eq!(
            call.component.modules.call_metrics(active),
            Some(core_metrics)
        );

        let mut oversized = [0xaa; 5];
        assert_eq!(
            call.prepare_host_output_stream(stream_offered, &mut oversized),
            Err(NativeAsyncHostError::InvalidProgress)
        );
        assert_eq!(oversized, [0xaa; 5]);
        assert_eq!(call.metrics(), stream_metrics);

        let mut output = [0; 4];
        let stream_prepared = match call
            .prepare_host_output_stream(stream_offered, &mut output)
            .unwrap()
        {
            NativeAsyncPoll::HostPending { token, metrics, .. } => {
                assert_eq!(
                    metrics.consumed_work - stream_metrics.consumed_work,
                    host_copy_work(4).unwrap()
                );
                token
            }
            other => panic!("output stream prepare must stay host-blocked: {other:?}"),
        };
        assert_eq!(output, [1, 2, 3, 4]);
        let prepared_metrics = call.metrics();
        let prepared_core_metrics = call.component.modules.call_metrics(active).unwrap();
        assert!(matches!(
            call.poll(),
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputStream { maximum: 4 },
                metrics,
            } if token == stream_prepared && metrics == prepared_metrics
        ));
        assert_eq!(
            call.component.modules.call_metrics(active),
            Some(prepared_core_metrics)
        );

        // Deliberately perturb Core memory after the one permitted lift. A
        // correct commit settles only the prepared ticket and never rereads.
        call.component
            .modules
            .write_memory(0, "memory", 64, &[8, 8, 8, 8])
            .unwrap();
        let closed_offered = match call.commit_host_output(stream_prepared).unwrap() {
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputClosed { value: None },
                metrics,
            } => {
                assert_eq!(metrics, prepared_metrics);
                token
            }
            other => panic!("second pending output must be close: {other:?}"),
        };
        assert_eq!(output, [1, 2, 3, 4]);

        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("transport fixture lost its filter contract")
        };
        let mut raw = [0; 8];
        call.component
            .modules
            .read_memory(0, "memory", 0, &mut raw)
            .unwrap();
        let stream_writer_raw = u32::from_le_bytes(raw[..4].try_into().unwrap());
        let closed_writer_raw = u32::from_le_bytes(raw[4..].try_into().unwrap());
        let stream_writer = call
            .component
            .state
            .resolve_guest_endpoint(
                stream_writer_raw,
                EndpointKind::Stream,
                EndpointDirection::Write,
                contract.stream,
            )
            .unwrap();
        assert!(
            call.component
                .state
                .endpoint_info(stream_writer)
                .unwrap()
                .has_pending_event
        );

        let closed_metrics = call.metrics();
        let closed_prepared = match call.prepare_host_output_closed(closed_offered).unwrap() {
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputClosed { value: Some(6) },
                metrics,
            } => {
                assert_eq!(
                    metrics.consumed_work - closed_metrics.consumed_work,
                    host_copy_work(1).unwrap()
                );
                token
            }
            other => panic!("output close prepare must lift enum8 once: {other:?}"),
        };
        let close_prepared_metrics = call.metrics();
        assert!(matches!(
            call.poll(),
            NativeAsyncPoll::HostPending {
                token,
                request: NativeAsyncHostRequest::OutputClosed { value: Some(6) },
                metrics,
            } if token == closed_prepared && metrics == close_prepared_metrics
        ));
        call.component
            .modules
            .write_memory(0, "memory", 72, &[0xff])
            .unwrap();
        assert!(matches!(
            call.commit_host_output(closed_prepared),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        let closed_writer = call
            .component
            .state
            .resolve_guest_endpoint(
                closed_writer_raw,
                EndpointKind::Future,
                EndpointDirection::Write,
                contract.closed,
            )
            .unwrap();
        assert!(
            call.component
                .state
                .endpoint_info(closed_writer)
                .unwrap()
                .has_pending_event
        );

        // No Core instruction ran during either HostPending phase. Only the
        // explicit test perturbations above changed memory; the guest's post-
        // return stores execute after both commits release the continuation.
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
        call.component
            .modules
            .read_memory(0, "memory", 64, &mut source_bytes)
            .unwrap();
        assert_eq!(source_bytes, [9, 9, 9, 9]);
        let mut closed_source = [0];
        call.component
            .modules
            .read_memory(0, "memory", 72, &mut closed_source)
            .unwrap();
        assert_eq!(closed_source, [7]);
    }

    #[test]
    fn queued_host_limit_is_refreshed_from_remaining_fuel_on_activation() {
        const PIN_QUANTUM: u64 = 100;
        let source = output_transport_component(true, true, false);
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut call = component.start_filter("run", WORK, PIN_QUANTUM).unwrap();
        let (offered, request, _) = poll_to_host(&mut call);
        assert_eq!(request, NativeAsyncHostRequest::OutputStream { maximum: 4 });
        assert!(matches!(
            call.host_next.as_ref().map(|host| host.request),
            Some(NativeAsyncHostRequest::OutputClosed { value: None })
        ));
        let mut output = [0_u8; 4];
        let prepared = match call
            .prepare_host_output_stream(offered, &mut output)
            .unwrap()
        {
            NativeAsyncPoll::HostPending { token, .. } => token,
            other => panic!("queued-limit fixture did not prepare its stream: {other:?}"),
        };
        assert_eq!(output, [1, 2, 3, 4]);
        let authority = call.host_current.as_ref().unwrap().authority;
        let desired_remaining = call
            .reserved_work()
            .and_then(|reserve| reserve.checked_add(2))
            .unwrap();
        let excess = call.remaining_work.checked_sub(desired_remaining).unwrap();
        call.debit_active_work(authority, excess).unwrap();
        let before = call.metrics();
        let pending = call.commit_host_output(prepared).unwrap();
        assert_eq!(call.metrics(), before);
        assert!(matches!(
            pending,
            NativeAsyncPoll::CleanupPending {
                trap: TrapCode::FuelExhausted,
                metrics,
            } if metrics == before
        ));
        assert!(call.host_token.is_none());
        assert!(call.host_next.is_none());
        assert!(matches!(
            call.host_current.as_ref().map(|host| host.kind),
            Some(EndpointKind::Future)
        ));
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
    }

    #[test]
    fn zero_one_and_post_return_pending_outputs_preserve_cancel_and_drop_events() {
        // Zero pending copies at task.return: the guest write begins only
        // after the exact result pair has transferred to the host.
        let source = output_transport_component(false, false, true);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let mut saw_zero_pending_detach = false;
        let (token, request, metrics) = loop {
            match call.poll() {
                NativeAsyncPoll::Resolved(_) => {
                    saw_zero_pending_detach = true;
                    assert!(call.host_current.is_none());
                    assert!(call.host_next.is_none());
                }
                NativeAsyncPoll::Pending(_) => {}
                NativeAsyncPoll::HostPending {
                    token,
                    request,
                    metrics,
                } => break (token, request, metrics),
                other => panic!("post-return output write failed: {other:?}"),
            }
        };
        assert!(saw_zero_pending_detach);
        assert_eq!(request, NativeAsyncHostRequest::OutputStream { maximum: 4 });
        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("transport fixture lost its filter contract")
        };
        let mut raw = [0; 4];
        call.component
            .modules
            .read_memory(0, "memory", 0, &mut raw)
            .unwrap();
        let writer = call
            .component
            .state
            .resolve_guest_endpoint(
                u32::from_le_bytes(raw),
                EndpointKind::Stream,
                EndpointDirection::Write,
                contract.stream,
            )
            .unwrap();
        assert!(matches!(
            call.cancel_host_copy(token),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        assert_eq!(
            call.metrics().consumed_work - metrics.consumed_work,
            BUFFER_COPY_BASE_WORK
        );
        assert!(
            call.component
                .state
                .endpoint_info(writer)
                .unwrap()
                .has_pending_event
        );

        // Exactly one pending copy at task.return, in the future position.
        let source = output_transport_component(false, true, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let (token, request, metrics) = poll_to_host(&mut call);
        assert_eq!(
            request,
            NativeAsyncHostRequest::OutputClosed { value: None }
        );
        assert!(call.host_next.is_none());
        let RuntimeExportContract::ByteStream(contract) = call.binding().contract else {
            panic!("transport fixture lost its filter contract")
        };
        let mut raw = [0; 4];
        call.component
            .modules
            .read_memory(0, "memory", 4, &mut raw)
            .unwrap();
        let writer = call
            .component
            .state
            .resolve_guest_endpoint(
                u32::from_le_bytes(raw),
                EndpointKind::Future,
                EndpointDirection::Write,
                contract.closed,
            )
            .unwrap();
        assert!(matches!(
            call.drop_host_copy_peer(token),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        assert_eq!(
            call.metrics().consumed_work - metrics.consumed_work,
            BUFFER_COPY_BASE_WORK
        );
        assert!(
            call.component
                .state
                .endpoint_info(writer)
                .unwrap()
                .has_pending_event
        );
    }

    #[test]
    fn host_input_zero_length_invalid_enum_and_low_fuel_fail_at_exact_boundaries() {
        let source = input_transport_component();

        // A zero-byte stream transfer is a real completed event and charges
        // only the fixed host-copy unit.
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let input_stream = call.input.as_ref().unwrap().first.guest;
        let (offered, _, before) = poll_to_host(&mut call);
        let prepared = match call.prepare_host_input_stream(offered, 0).unwrap() {
            NativeAsyncPoll::HostPending { token, metrics, .. } => {
                assert_eq!(
                    metrics.consumed_work - before.consumed_work,
                    host_copy_work(0).unwrap()
                );
                token
            }
            other => panic!("zero input prepare failed: {other:?}"),
        };
        assert!(matches!(
            call.commit_host_input_stream(prepared, &[]),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        assert!(
            call.component
                .state
                .endpoint_info(input_stream)
                .unwrap()
                .has_pending_event
        );
        let mut target = [0xff; 4];
        call.component
            .modules
            .read_memory(0, "memory", 16, &mut target)
            .unwrap();
        assert_eq!(target, [0; 4]);

        // Future input lowering validates enum8 before publication and
        // revokes the prepared owner token before trapping.
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let (stream, _, _) = poll_to_host(&mut call);
        assert!(matches!(
            call.cancel_host_copy(stream),
            Ok(NativeAsyncPoll::Pending(_))
        ));
        let (closed, NativeAsyncHostRequest::InputClosed, _) = poll_to_host(&mut call) else {
            panic!("cancelled stream must advance to input close")
        };
        call.component
            .modules
            .write_memory(0, "memory", 32, &[0xaa])
            .unwrap();
        let prepared = match call.prepare_host_input_closed(closed).unwrap() {
            NativeAsyncPoll::HostPending { token, .. } => token,
            other => panic!("input close prepare failed: {other:?}"),
        };
        let pending = call.commit_host_input_closed(prepared, 8).unwrap();
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
        );
        let mut target = [0];
        call.component
            .modules
            .read_memory(0, "memory", 32, &mut target)
            .unwrap();
        assert_eq!(target, [0xaa]);
        assert!(call.host_token.is_none());

        // Leaving exactly the requested host-copy work is insufficient: one
        // Core fuel unit is reserved for the eventual continuation.
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let (offered, _, _) = poll_to_host(&mut call);
        let work = host_copy_work(4).unwrap();
        let authority = call.host_current.as_ref().unwrap().authority;
        let remaining = call
            .reserved_work()
            .and_then(|reserve| reserve.checked_add(work))
            .unwrap();
        let debit = call.remaining_work.checked_sub(remaining).unwrap();
        call.debit_active_work(authority, debit).unwrap();
        assert_eq!(call.remaining_work, remaining);
        let before = call.metrics();
        let pending = call.prepare_host_input_stream(offered, 4).unwrap();
        let NativeAsyncPoll::CleanupPending { metrics, .. } = pending else {
            panic!("low-fuel host prepare did not enter cleanup")
        };
        assert_eq!(metrics, before);
        assert_eq!(
            finish_cleanup_turn(
                &mut call,
                NativeAsyncPoll::CleanupPending {
                    trap: TrapCode::FuelExhausted,
                    metrics,
                },
            ),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
        assert!(call.host_token.is_none());
        let mut target = [0xff; 4];
        call.component
            .modules
            .read_memory(0, "memory", 16, &mut target)
            .unwrap();
        assert_eq!(target, [0; 4]);
    }

    #[test]
    fn host_blocked_corruption_of_limit_type_or_value_phase_is_fail_stop() {
        let source = input_transport_component();
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let _ = poll_to_host(&mut call);
        let NativeAsyncHostRequest::InputStream { maximum } =
            &mut call.host_current.as_mut().unwrap().request
        else {
            panic!("input fixture did not block on its stream")
        };
        *maximum += 1;
        let pending = call.poll();
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );

        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let _ = poll_to_host(&mut call);
        let host = call.host_current.as_mut().unwrap();
        host.value_type = AsyncValueTypeId::new(host.value_type.get() + 1).unwrap();
        let pending = call.poll();
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );

        let source = output_transport_component(false, true, false);
        let mut component = instantiate(&source);
        let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
        let _ = poll_to_host(&mut call);
        call.host_current.as_mut().unwrap().request =
            NativeAsyncHostRequest::OutputClosed { value: Some(6) };
        let pending = call.poll();
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
    }

    #[test]
    fn reused_raw_input_slots_do_not_rebind_stale_host_authority() {
        for (run, label) in [
            (
                r#"local.get $input-bytes
                  call $stream-drop-readable
                  call $stream-new
                  local.set $stream-pair
                  i32.const 96
                  local.get $stream-pair
                  i32.wrap_i64
                  i32.store
                  local.get $stream-pair
                  i32.wrap_i64
                  local.get $input-bytes
                  i32.ne
                  if unreachable end
                  local.get $stream-pair
                  i32.wrap_i64
                  i32.const 16
                  i32.const 4
                  call $stream-read
                  i32.const -1
                  i32.ne
                  if unreachable end
                  i32.const 100
                  i32.const 1
                  i32.store
                  unreachable"#,
                "stream",
            ),
            (
                r#"local.get $input-closed
                  call $future-drop-readable
                  call $future-new
                  local.set $closed-pair
                  i32.const 96
                  local.get $closed-pair
                  i32.wrap_i64
                  i32.store
                  local.get $closed-pair
                  i32.wrap_i64
                  local.get $input-closed
                  i32.ne
                  if unreachable end
                  local.get $closed-pair
                  i32.wrap_i64
                  i32.const 32
                  call $future-read
                  i32.const -1
                  i32.ne
                  if unreachable end
                  i32.const 100
                  i32.const 1
                  i32.store
                  unreachable"#,
                "future",
            ),
        ] {
            let source = filter_transport_component(run, "i32.const 0");
            let mut component = instantiate(&source);
            let mut call = component.start_filter("run", WORK, QUANTUM).unwrap();
            let input_raw = match label {
                "stream" => call.input.as_ref().unwrap().first.guest.raw(),
                "future" => call.input.as_ref().unwrap().second.guest.raw(),
                _ => unreachable!(),
            };
            let mut pending = 0;
            loop {
                match call.poll() {
                    NativeAsyncPoll::Pending(_) => pending += 1,
                    cleanup @ NativeAsyncPoll::CleanupPending {
                        trap: TrapCode::Unreachable,
                        ..
                    } => {
                        assert_eq!(
                            finish_cleanup_turn(&mut call, cleanup),
                            NativeAsyncPoll::Trapped(TrapCode::Unreachable)
                        );
                        break;
                    }
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("{label} raw ABA rebound the stale input authority")
                    }
                    NativeAsyncPoll::Trapped(trap) => {
                        panic!("{label} raw ABA trapped as {trap:?}")
                    }
                    other => panic!("{label} raw ABA produced unexpected progress: {other:?}"),
                }
            }
            assert!(pending >= 3);
            let mut proof = [0_u8; 8];
            call.component
                .modules
                .read_memory(0, "memory", 96, &mut proof)
                .unwrap();
            assert_eq!(
                u32::from_le_bytes(proof[..4].try_into().unwrap()),
                input_raw
            );
            assert_eq!(u32::from_le_bytes(proof[4..].try_into().unwrap()), 1);
        }
    }

    #[test]
    fn repeated_filter_task_return_is_canonical_abi_misuse_without_a_second_transfer() {
        let source = filter_transport_component(
            r#"call $stream-new
              local.set $stream-pair
              call $future-new
              local.set $closed-pair
              local.get $stream-pair
              i32.wrap_i64
              local.get $closed-pair
              i32.wrap_i64
              call $task-return
              local.get $stream-pair
              i32.wrap_i64
              local.get $closed-pair
              i32.wrap_i64
              call $task-return
              i32.const 1"#,
            "i32.const 0",
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
                pending @ NativeAsyncPoll::CleanupPending {
                    trap: TrapCode::CanonicalAbi,
                    ..
                } => {
                    assert_eq!(
                        finish_cleanup_turn(&mut call, pending),
                        NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                    );
                    break;
                }
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
                pending @ NativeAsyncPoll::CleanupPending {
                    trap: TrapCode::CanonicalAbi,
                    ..
                } => {
                    assert_eq!(
                        finish_cleanup_turn(&mut call, pending),
                        NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                    );
                    break;
                }
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
        let fixture = filter_transport_component(
            r#"call $stream-new
              local.set $stream-pair
              call $future-new
              local.set $closed-pair
              local.get $stream-pair
              i32.wrap_i64
              local.get $closed-pair
              i32.wrap_i64
              call $task-return
              i32.const 1"#,
            "i32.const 0",
        );
        let source = replace_once(
            &fixture,
            "              (core func $task-return\n                (canon task.return (result $byte-stream)))",
            r#"              (type $canonical-result
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
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

        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("cancel delivery fixture unexpectedly requested host transport")
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
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("cancel delivery callback entered cleanup: {trap:?}")
                }
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
            r#"      (local $n i32)
      i32.const 80
      local.set $n
      block $done
        loop $loop
          local.get $n
          i32.eqz
          br_if $done
          local.get $n
          i32.const 1
          i32.sub
          local.set $n
          br $loop
        end
      end
      i32.const 1"#,
        );
        let exact_yield_work = {
            let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
            let mut call = component.start("run", WORK, QUANTUM).unwrap();
            let NativeAsyncPoll::Yielded(metrics) = poll_after_core_turn(&mut call) else {
                panic!("unresolved run must yield")
            };
            metrics.consumed_work
        };
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let minimum = component
            .minimum_poll_quantum(&component.exports[0])
            .unwrap();
        assert!(exact_yield_work >= minimum);
        let cleanup = component.fail_stop_cleanup_work;
        let total = exact_yield_work.checked_add(cleanup).unwrap();

        let mut call = component.start("run", total, exact_yield_work).unwrap();
        assert_eq!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(NativeAsyncMetrics {
                consumed_work: exact_yield_work,
                remaining_work: cleanup,
            })
        );
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        assert_eq!(call.task_info().cancel, TaskCancelState::Requested);
        let pending = call.poll();
        assert!(matches!(pending, NativeAsyncPoll::CleanupPending { .. }));
        assert_eq!(call.metrics().remaining_work, cleanup);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
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

        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
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
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("callback host-call fixture unexpectedly requested host transport")
                }
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("callback host-call fixture entered cleanup: {trap:?}")
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
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("local close future unexpectedly requested host transport")
                    }
                    NativeAsyncPoll::CleanupPending { trap, .. } => {
                        panic!("local close future entered cleanup: {trap:?}")
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
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("local byte-stream fixture unexpectedly requested host transport")
                    }
                    NativeAsyncPoll::CleanupPending { trap, .. } => {
                        panic!("local byte-stream fixture entered cleanup: {trap:?}")
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
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("ready endpoint wait unexpectedly requested host transport")
                    }
                    NativeAsyncPoll::CleanupPending { trap, .. } => {
                        panic!("endpoint wait fixture entered cleanup: {trap:?}")
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
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("zero copy unexpectedly requested host transport")
                    }
                    NativeAsyncPoll::CleanupPending { trap, .. } => {
                        panic!("zero copy entered cleanup: {trap:?}")
                    }
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
                                let pending = call.handle_host_call(authority, host);
                                assert_eq!(call.metrics(), before);
                                assert_eq!(
                                    finish_cleanup_turn(&mut call, pending),
                                    NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                                );
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
                            let desired = call
                                .cleanup_reserve
                                .checked_add(BUFFER_BRIDGE_WORK)
                                .unwrap();
                            let excess =
                                call.metrics().remaining_work.checked_sub(desired).unwrap();
                            call.debit_active_work(authority, excess).unwrap();
                            let before = call.metrics();
                            assert_eq!(before.remaining_work, desired);
                            let pending = call.handle_host_call(authority, host);
                            assert_eq!(call.metrics(), before);
                            assert_eq!(
                                finish_cleanup_turn(&mut call, pending),
                                NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
                            );
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
                        let minimum_transfer =
                            buffer_copy_work(1, call.component.buffers.scratch_bytes()).unwrap();
                        let tight = call
                            .cleanup_reserve
                            .checked_add(BUFFER_BRIDGE_WORK)
                            .and_then(|work| work.checked_add(minimum_transfer))
                            .unwrap();
                        let excess = call.metrics().remaining_work.checked_sub(tight).unwrap();
                        call.debit_active_work(authority, excess).unwrap();
                        let before = call.metrics();
                        let pending = call.handle_host_call(authority, host);
                        let after = call.metrics();
                        assert_eq!(
                            before.remaining_work - after.remaining_work,
                            BUFFER_BRIDGE_WORK
                        );
                        assert_eq!(
                            finish_cleanup_turn(&mut call, pending),
                            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
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
    fn selected_handle_arena_traps_as_limit_after_its_exact_transition_debit() {
        let source = handle_component("call $stream-new\n                  drop");
        for resource_limit in [8, PROFILE_1_LIMITS.max_resources] {
            let mut component = instantiate_with_resource_limit(&source, resource_limit).unwrap();
            let value_type = component
                .bridges
                .iter()
                .find_map(|bridge| match bridge.action {
                    BridgeAction::StreamNew(value_type) => Some(value_type),
                    _ => None,
                })
                .unwrap();
            assert_eq!(resource_limit % 2, 0);
            for _ in 0..resource_limit / 2 {
                component.state.create_stream_pair(value_type).unwrap();
            }
            let expected_work = component.work_costs().handle_state;
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
            let pending = call.handle_host_call(CallAuthority::Run(active), host);
            let after = call.metrics();
            assert_eq!(before.remaining_work - after.remaining_work, expected_work);
            assert_eq!(after.consumed_work - before.consumed_work, expected_work);
            assert_eq!(
                finish_cleanup_turn(&mut call, pending),
                NativeAsyncPoll::Trapped(TrapCode::LimitExceeded)
            );
            drop(call);
            assert!(component.is_poisoned());
        }
    }

    #[test]
    fn selected_buffer_arena_charges_its_exact_bridge_work() {
        let source = byte_stream_component(
            r#"    (func (export "run") (result i32)
      (local $pair i64)
      call $stream-new
      local.set $pair
      i32.const 0
      i32.const 42
      i32.store8
      local.get $pair
      i64.const 32
      i64.shr_u
      i32.wrap_i64
      i32.const 0
      i32.const 1
      call $stream-write
      drop
      i32.const 1)"#,
            r#"    (func (export "callback") (param i32 i32 i32) (result i32)
      i32.const 0)"#,
        );
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        assert_eq!(component.work_costs().buffer_bridge, 74);
        let mut call = component.start("run", WORK, QUANTUM).unwrap();
        let active = call.binding().core_instance;
        loop {
            let progress = call.component.modules.poll_call(active);
            assert!(call.settle_metrics(CallAuthority::Run(active)));
            match progress {
                PollResult::Pending { .. } => {}
                PollResult::HostCall(host) => {
                    let action = call.component.bridges[host.id as usize].action;
                    let before = call.metrics();
                    let progress = call.handle_host_call(CallAuthority::Run(active), host);
                    let after = call.metrics();
                    if matches!(action, BridgeAction::StreamCopy { .. }) {
                        assert!(matches!(progress, NativeAsyncPoll::Pending(_)));
                        assert_eq!(before.remaining_work - after.remaining_work, 74);
                        assert_eq!(after.consumed_work - before.consumed_work, 74);
                        assert_eq!(call.component.buffers.usage().peak, 1);
                        break;
                    }
                    assert!(matches!(progress, NativeAsyncPoll::Pending(_)));
                }
                PollResult::Ready(_) => panic!("copy fixture returned before stream.write"),
                PollResult::Trapped(trap) => panic!("copy fixture trapped early: {trap:?}"),
            }
        }
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
        let pending = call.handle_host_call(CallAuthority::Run(active), host);
        assert_eq!(call.metrics(), before);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
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
        let pending = call.handle_host_call(CallAuthority::Run(active), host);
        let after = call.metrics();
        assert_eq!(
            before.remaining_work - after.remaining_work,
            HANDLE_STATE_WORK
        );
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
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
                poll_after_core_turn(&mut call),
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
            assert!(matches!(
                poll_within_quantum(&mut call),
                NativeAsyncPoll::Pending(_)
            ));
            assert_eq!(
                poll_after_core_turn(&mut call),
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert_eq!(
                poll_after_core_turn(&mut call),
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
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Yielded(_)
        ));
        assert!(matches!(
            poll_within_quantum(&mut call),
            NativeAsyncPoll::Pending(_)
        ));
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Resolved(_)
        ));
        assert_eq!(call.task_info().result, TaskResultState::Resolved);
        assert!(matches!(
            poll_after_core_turn(&mut call),
            NativeAsyncPoll::Complete(_)
        ));
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
                poll_after_core_turn(&mut call),
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
            assert!(matches!(
                poll_within_quantum(&mut call),
                NativeAsyncPoll::Pending(_)
            ));
            assert_eq!(
                poll_after_core_turn(&mut call),
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
                poll_after_core_turn(&mut call),
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
            assert!(matches!(
                poll_within_quantum(&mut call),
                NativeAsyncPoll::Pending(_)
            ));
            assert_eq!(
                poll_after_core_turn(&mut call),
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
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut foreign_component = instantiate_with_resource_limit(&source, 8).unwrap();
        let wait_work = component.work_costs().wait_state;
        assert_eq!(wait_work, 65);
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
            wait_work
        );
        assert_eq!(
            resumed_metrics.consumed_work - blocked_metrics.consumed_work,
            wait_work
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
            wait_work
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
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("pre-WAIT cancellation unexpectedly requested host transport")
                }
                NativeAsyncPoll::Yielded(_) => panic!("WAIT fixture unexpectedly yielded"),
                NativeAsyncPoll::CleanupPending { trap, .. } => {
                    panic!("pre-WAIT cancellation entered cleanup: {trap:?}")
                }
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
                        let pending = call.handle_callback_result(values.as_slice());
                        let after = call.metrics();
                        assert_eq!(
                            before.remaining_work - after.remaining_work,
                            CALLBACK_RESULT_WORK
                        );
                        assert_eq!(
                            after.consumed_work - before.consumed_work,
                            CALLBACK_RESULT_WORK
                        );
                        assert_eq!(
                            finish_cleanup_turn(&mut call, pending),
                            NativeAsyncPoll::Trapped(TrapCode::CanonicalAbi)
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
                    assert!(matches!(
                        call.finish_trap(TrapCode::Validation),
                        NativeAsyncPoll::CleanupPending {
                            trap: TrapCode::Validation,
                            ..
                        }
                    ));
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

        let pending = call.resume_wait(token).unwrap();
        let after_failure = call.metrics();
        assert_eq!(
            blocked.remaining_work - after_failure.remaining_work,
            WAIT_STATE_WORK
        );
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
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
        call.remaining_work = call
            .cleanup_reserve
            .checked_add(CALLBACK_RESULT_WORK)
            .and_then(|work| work.checked_add(WAIT_STATE_WORK))
            .unwrap();
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        let before = call.metrics();
        let pending = call.handle_callback_result(values.as_slice());
        let after = call.metrics();
        assert_eq!(
            before.remaining_work - after.remaining_work,
            CALLBACK_RESULT_WORK
        );
        assert_eq!(after.remaining_work, call.cleanup_reserve + WAIT_STATE_WORK);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
        assert_eq!(call.metrics().remaining_work, WAIT_STATE_WORK);
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
        call.remaining_work = call.cleanup_reserve + WAIT_STATE_WORK;
        assert_eq!(
            call.request_cancel(),
            Ok(NativeAsyncCancelOutcome::Requested)
        );
        let before = call.metrics();
        let pending = call.resume_wait(token).unwrap();
        assert_eq!(call.metrics(), before);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::FuelExhausted)
        );
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
        let pending = call.resume_wait(token).unwrap();
        assert_eq!(call.metrics(), before);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
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
        let pending = call.resume_wait(token).unwrap();
        assert_eq!(call.metrics(), before);
        assert_eq!(
            finish_cleanup_turn(&mut call, pending),
            NativeAsyncPoll::Trapped(TrapCode::Validation)
        );
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Trapped(_)
            ));
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
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
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Resolved(_)
            ));
            assert!(matches!(
                poll_after_core_turn(&mut call),
                NativeAsyncPoll::Yielded(_)
            ));
            assert!(matches!(call.poll(), NativeAsyncPoll::Pending(_)));
            let callback_instance = call.binding().callback_instance;
            assert_eq!(
                call.component.modules.poll_call(callback_instance),
                PollResult::Trapped(TrapCode::Validation)
            );
            let pending = call.finish_trap(TrapCode::Validation);
            assert_eq!(
                finish_cleanup_turn(&mut call, pending),
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
                    assert!(matches!(
                        poll_after_core_turn(&mut call),
                        NativeAsyncPoll::Resolved(_)
                    ));
                }
                let active = call.binding().core_instance;
                let (origin_instance, id) = if after_resolution {
                    (usize::MAX, 0)
                } else {
                    (0, u32::MAX)
                };
                let pending = call.handle_host_call(
                    CallAuthority::Run(active),
                    CoreHostCall {
                        origin_instance,
                        id,
                        arguments: Vec::new(),
                    },
                );
                assert_eq!(
                    finish_cleanup_turn(&mut call, pending),
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
                    assert!(matches!(
                        poll_after_core_turn(&mut call),
                        NativeAsyncPoll::Resolved(_)
                    ));
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

        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
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
                    NativeAsyncPoll::HostPending { .. } => {
                        panic!("shared-fuel fixture unexpectedly requested host transport")
                    }
                    NativeAsyncPoll::CleanupPending { trap, .. } => {
                        panic!("high-budget call entered cleanup: {trap:?}")
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
        let mut component = instantiate_with_resource_limit(&source, 8).unwrap();
        let mut call = component.start("run", tight, tight.min(QUANTUM)).unwrap();
        let trap = loop {
            match call.poll() {
                NativeAsyncPoll::Trapped(trap) => break trap,
                pending @ NativeAsyncPoll::CleanupPending { .. } => {
                    let NativeAsyncPoll::Trapped(trap) = finish_cleanup_turn(&mut call, pending)
                    else {
                        unreachable!("cleanup helper pins its terminal result")
                    };
                    break trap;
                }
                NativeAsyncPoll::Complete(_) => {
                    panic!("separate per-Core fuel ledgers would incorrectly complete")
                }
                NativeAsyncPoll::Pending(_)
                | NativeAsyncPoll::Resolved(_)
                | NativeAsyncPoll::Yielded(_) => {}
                NativeAsyncPoll::WaitPending { .. } => {
                    panic!("shared-fuel fixture unexpectedly waited")
                }
                NativeAsyncPoll::HostPending { .. } => {
                    panic!("shared-fuel fixture unexpectedly requested host transport")
                }
            }
        };
        assert_eq!(trap, TrapCode::FuelExhausted);
        assert!(call.metrics().consumed_work <= tight);
    }
}
