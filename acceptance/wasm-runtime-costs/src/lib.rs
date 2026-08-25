//! Target-owned C8.3 WebAssembly runtime-cost samples.
//!
//! The guest emits raw integer `rdtime` observations.  Host tooling owns the
//! closed schema, independently recomputes summaries, and binds the transcript
//! to a clean source commit and a fresh capture challenge.  This crate contains
//! no regression budgets: C8.3 publishes observations; product budgets remain
//! a separate C8.4 decision.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Arguments;

use vibeos_component_format::{ComponentGraphInstanceBudget, ProfileIdentity, PROFILE_1_LIMITS};
use vibeos_component_runtime::async_abi::EventCode;
use vibeos_component_runtime::async_state::{AsyncState, AsyncStateLimits, WaitBegin, WaitResume};
use vibeos_component_runtime::canonical::{
    AbiBudget, CallGate, CanonicalMachine, ReallocRequest, Reallocator,
};
use vibeos_component_runtime::decode::{
    inspect_component, inspect_component_for_profile, ComponentPlan,
};
use vibeos_component_runtime::graph::{
    plan_component_graph, ComponentGraphEdgeSpec, ComponentGraphEntityIndex,
    ComponentGraphExportEndpoint, ComponentGraphExternalImportSpec, ComponentGraphImportEndpoint,
    ComponentGraphNesting, ComponentGraphNodeId, ComponentGraphNodeSpec,
    ComponentGraphPublishedExportSpec,
};
use vibeos_component_runtime::memory::{AbiError, Allocation, GuestMemory, VecMemory};
use vibeos_component_runtime::sync::SynchronousComponent;
use vibeos_core::cap::{CSpace, Resource, Revocable, Rights};
use vibeos_wasm_runtime::{
    CoreHostImport, CoreValue, CoreValueType, OwnerAllocationReservation, PollResult,
    ProfileEngine, ValidatedCore,
};

include!(concat!(env!("OUT_DIR"), "/identity.rs"));

const SYNC_COMPONENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sync.component.wasm"));
const ROUTE_COMPONENT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/async-route.component.wasm"));
const CORE_MODULE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/core-host-fuel.wasm"));

pub const SCHEMA_VERSION: u32 = 1;
pub const WORKLOAD_REVISION: u32 = 1;
pub const WORKLOAD_COUNT: u32 = 10;
pub const RAW_RECORD_COUNT: u32 = 3 * (HEAVY_WARMUP + HEAVY_SAMPLES)
    + 6 * (HOT_WARMUP + HOT_SAMPLES)
    + FUEL_WARMUP
    + FUEL_SAMPLES;

const HEAVY_WARMUP: u32 = 3;
const HEAVY_SAMPLES: u32 = 21;
const HOT_WARMUP: u32 = 5;
const HOT_SAMPLES: u32 = 41;
const FUEL_WARMUP: u32 = 3;
const FUEL_SAMPLES: u32 = 21;

const VALIDATION_BATCH: u64 = 4;
const STARTUP_BATCH: u64 = 4;
const CANONICAL_BATCH: u64 = 256;
const ASYNC_BATCH: u64 = 1_024;
const COMPOSITION_BATCH: u64 = 256;
const HOST_CALL_BATCH: u64 = 256;
const MEMORY_BATCH: u64 = 16;
const CANCELLATION_BATCH: u64 = 2_048;
const REVOCATION_BATCH: u64 = 512;
const FUEL_ITERATIONS: u64 = 32_768;

const CANONICAL_TEXT: &str = concat!(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_",
);
const CANONICAL_LIST: [u32; 64] = [0x0102_0304; 64];

/// One exact, resettable live-byte observation owned by a workload sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeapWindowObservation {
    pub live_before: usize,
    pub peak_live_bytes: usize,
    pub live_after: usize,
}

/// Platform-owned guard for one exclusive allocator observation window.
pub trait HeapWindow {
    fn finish(self) -> HeapWindowObservation;
}

/// Target services deliberately kept smaller than the runtime under test.
pub trait Platform {
    type HeapWindow<'a>: HeapWindow
    where
        Self: 'a;

    fn platform_id(&self) -> &'static str;
    fn time(&self) -> u64;
    fn timebase_hz(&self) -> u64;
    fn begin_heap_window(&self) -> Option<Self::HeapWindow<'_>>;
    fn log(&self, arguments: Arguments<'_>);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RuntimeCostError {
    SourceCommitUnbound = 1,
    ChallengeUnbound = 2,
    PlatformContract = 3,
    ComponentValidation = 4,
    ComponentStartup = 5,
    CanonicalAbi = 6,
    AsyncState = 7,
    Composition = 8,
    CoreValidation = 9,
    CoreInstantiation = 10,
    CoreCall = 11,
    Memory = 12,
    Cancellation = 13,
    Revocation = 14,
    HeapDidNotReturn = 15,
    Arithmetic = 16,
}

impl RuntimeCostError {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy)]
struct Sample<'a> {
    workload: &'a str,
    category: &'a str,
    sample_index: u32,
    warmup: bool,
    ticks: u64,
    operations: u64,
    bytes: u64,
    fuel_consumed: u64,
    poll_quanta: u64,
    heap_before: usize,
    heap_peak: usize,
    heap_after: usize,
    logical_live_after: u32,
    result: u64,
}

struct Emitter<'a, P> {
    platform: &'a P,
    sequence: u64,
    accumulator: u64,
}

impl<P: Platform> Emitter<'_, P> {
    fn emit(&mut self, sample: Sample<'_>) {
        let warmup = if sample.warmup { "true" } else { "false" };
        self.platform.log(format_args!(
            "VIBE_WASM_COST_SAMPLE {{\"schema\":\"vibeos.wasm-runtime-cost.sample\",\"version\":{},\"run_id\":\"{}\",\"challenge\":\"{}\",\"sequence\":{},\"workload_id\":\"{}\",\"category\":\"{}\",\"sample_index\":{},\"warmup\":{},\"ticks\":{},\"operations\":{},\"bytes\":{},\"fuel_consumed\":{},\"poll_quanta\":{},\"heap_before\":{},\"heap_peak\":{},\"heap_after\":{},\"logical_live_after\":{},\"result\":{}}}",
            SCHEMA_VERSION,
            RUN_ID,
            CHALLENGE,
            self.sequence,
            sample.workload,
            sample.category,
            sample.sample_index,
            warmup,
            sample.ticks,
            sample.operations,
            sample.bytes,
            sample.fuel_consumed,
            sample.poll_quanta,
            sample.heap_before,
            sample.heap_peak,
            sample.heap_after,
            sample.logical_live_after,
            sample.result,
        ));
        self.accumulator = self
            .accumulator
            .rotate_left(7)
            .wrapping_add(self.sequence)
            .wrapping_add(sample.ticks.rotate_left(11))
            .wrapping_add(sample.operations.rotate_left(19))
            .wrapping_add(sample.fuel_consumed.rotate_left(29))
            .wrapping_add(sample.result.rotate_left(37));
        self.sequence += 1;
    }
}

fn is_nonzero_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn checked_elapsed<P: Platform>(platform: &P, started: u64) -> u64 {
    platform.time().saturating_sub(started).max(1)
}

fn begin_heap_window<P: Platform>(platform: &P) -> Result<P::HeapWindow<'_>, RuntimeCostError> {
    platform
        .begin_heap_window()
        .ok_or(RuntimeCostError::PlatformContract)
}

fn finish_heap_window<W: HeapWindow>(window: W) -> Result<HeapWindowObservation, RuntimeCostError> {
    let observation = window.finish();
    if observation.live_before != observation.live_after
        || observation.peak_live_bytes < observation.live_before
        || observation.peak_live_bytes < observation.live_after
    {
        Err(RuntimeCostError::HeapDidNotReturn)
    } else {
        Ok(observation)
    }
}

fn sample_range(warmup: u32, samples: u32) -> core::ops::Range<u32> {
    0..warmup + samples
}

/// Emit one complete raw-sample suite.
///
/// A missing end record is a failed run. Callers should print the returned
/// stable error code and must not synthesize an end record after failure.
pub fn run<P: Platform>(platform: &P) -> Result<(), RuntimeCostError> {
    if !is_nonzero_hex(SOURCE_COMMIT, 40) {
        return Err(RuntimeCostError::SourceCommitUnbound);
    }
    if !is_nonzero_hex(CHALLENGE, 64) {
        return Err(RuntimeCostError::ChallengeUnbound);
    }
    let expected_timebase = match platform.platform_id() {
        "qemu-virt" => 10_000_000,
        "milkv-duo-cv1800b" => 25_000_000,
        _ => return Err(RuntimeCostError::PlatformContract),
    };
    if platform.timebase_hz() != expected_timebase {
        return Err(RuntimeCostError::PlatformContract);
    }

    platform.log(format_args!(
        "VIBE_WASM_COST_META {{\"schema\":\"vibeos.wasm-runtime-cost.meta\",\"version\":{},\"suite_id\":\"vibeos.c83.runtime-costs\",\"workload_revision\":{},\"source_commit\":\"{}\",\"challenge\":\"{}\",\"run_id\":\"{}\",\"manifest_sha256\":\"{}\",\"transcript_schema_sha256\":\"{}\",\"platform\":\"{}\",\"target\":\"riscv64imac-unknown-none-elf\",\"clock\":\"riscv.rdtime\",\"timebase_hz\":{},\"sync_profile_stage\":\"executable\",\"async_scope\":\"validation-candidate-primitives\",\"composition_scope\":\"validation-only-plan\",\"sync_component_sha256\":\"{}\",\"sync_component_bytes\":{},\"route_component_sha256\":\"{}\",\"route_component_bytes\":{},\"core_module_sha256\":\"{}\",\"core_module_bytes\":{},\"workloads\":{}}}",
        SCHEMA_VERSION,
        WORKLOAD_REVISION,
        SOURCE_COMMIT,
        CHALLENGE,
        RUN_ID,
        MANIFEST_SHA256,
        TRANSCRIPT_SCHEMA_SHA256,
        platform.platform_id(),
        platform.timebase_hz(),
        SYNC_COMPONENT_SHA256,
        SYNC_COMPONENT_BYTES,
        ROUTE_COMPONENT_SHA256,
        ROUTE_COMPONENT_BYTES,
        CORE_MODULE_SHA256,
        CORE_MODULE_BYTES,
        WORKLOAD_COUNT,
    ));

    let mut emitter = Emitter {
        platform,
        sequence: 0,
        accumulator: 0,
    };
    validation_samples(&mut emitter)?;

    let sync_plan =
        inspect_component(SYNC_COMPONENT).map_err(|_| RuntimeCostError::ComponentValidation)?;
    if !sync_plan.runtime_ready() {
        return Err(RuntimeCostError::ComponentValidation);
    }
    startup_samples(&mut emitter, &sync_plan)?;
    canonical_samples(&mut emitter)?;
    async_samples(&mut emitter)?;

    let route_plan =
        inspect_component_for_profile(ROUTE_COMPONENT, ProfileIdentity::PROFILE_1_ASYNC)
            .map_err(|_| RuntimeCostError::ComponentValidation)?;
    if route_plan.runtime_ready() {
        return Err(RuntimeCostError::ComponentValidation);
    }
    composition_samples(&mut emitter, &route_plan)?;

    let engine = ProfileEngine::new();
    let core = ValidatedCore::new_in(
        &engine,
        CORE_MODULE,
        OwnerAllocationReservation::profile_default(),
    )
    .map_err(|_| RuntimeCostError::CoreValidation)?;
    host_call_samples(&mut emitter, &core)?;
    memory_samples(&mut emitter)?;
    fuel_samples(&mut emitter, &core)?;
    cancellation_samples(&mut emitter)?;
    revocation_samples(&mut emitter)?;

    if emitter.sequence != u64::from(RAW_RECORD_COUNT) {
        return Err(RuntimeCostError::Arithmetic);
    }

    platform.log(format_args!(
        "VIBE_WASM_COST_END {{\"schema\":\"vibeos.wasm-runtime-cost\",\"version\":{},\"run_id\":\"{}\",\"challenge\":\"{}\",\"records\":{},\"workloads\":{},\"accumulator\":{}}}",
        SCHEMA_VERSION,
        RUN_ID,
        CHALLENGE,
        emitter.sequence,
        WORKLOAD_COUNT,
        emitter.accumulator,
    ));
    Ok(())
}

fn validation_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HEAVY_WARMUP, HEAVY_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 1..VALIDATION_BATCH {
            let plan = inspect_component(SYNC_COMPONENT)
                .map_err(|_| RuntimeCostError::ComponentValidation)?;
            result = result
                .checked_add(validation_result(&plan)?)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let held_plan =
            inspect_component(SYNC_COMPONENT).map_err(|_| RuntimeCostError::ComponentValidation)?;
        result = result
            .checked_add(validation_result(&held_plan)?)
            .ok_or(RuntimeCostError::Arithmetic)?;
        let ticks = checked_elapsed(emitter.platform, started);
        drop(held_plan);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "component-validation",
            category: "validation",
            sample_index,
            warmup: sample_index < HEAVY_WARMUP,
            ticks,
            operations: VALIDATION_BATCH,
            bytes: VALIDATION_BATCH * SYNC_COMPONENT.len() as u64,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

fn validation_result(plan: &ComponentPlan<'_>) -> Result<u64, RuntimeCostError> {
    if !plan.runtime_ready() || plan.embedded_modules().len() != 1 {
        return Err(RuntimeCostError::ComponentValidation);
    }
    let summary = plan.summary();
    u64::from(summary.bytes)
        .checked_add(u64::from(summary.embedded_modules) << 32)
        .ok_or(RuntimeCostError::Arithmetic)
}

fn startup_samples<P: Platform>(
    emitter: &mut Emitter<'_, P>,
    plan: &ComponentPlan<'_>,
) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HEAVY_WARMUP, HEAVY_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 1..STARTUP_BATCH {
            let component = instantiate_component(plan)?;
            result = result
                .checked_add(component.module_count() as u64)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let component = instantiate_component(plan)?;
        result = result
            .checked_add(component.module_count() as u64)
            .ok_or(RuntimeCostError::Arithmetic)?;
        let ticks = checked_elapsed(emitter.platform, started);
        drop(component);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "cold-component-startup",
            category: "startup",
            sample_index,
            warmup: sample_index < HEAVY_WARMUP,
            ticks,
            operations: STARTUP_BATCH,
            bytes: STARTUP_BATCH * SYNC_COMPONENT.len() as u64,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

fn instantiate_component(
    plan: &ComponentPlan<'_>,
) -> Result<SynchronousComponent, RuntimeCostError> {
    let engine = ProfileEngine::new();
    let component = SynchronousComponent::instantiate(
        plan,
        &engine,
        OwnerAllocationReservation::profile_default(),
    )
    .map_err(|_| RuntimeCostError::ComponentStartup)?;
    if component.module_count() != 1 || component.is_poisoned() {
        return Err(RuntimeCostError::ComponentStartup);
    }
    Ok(component)
}

#[derive(Debug)]
struct ResettingBump {
    next: u32,
    live: u32,
}

impl ResettingBump {
    const fn new() -> Self {
        Self { next: 64, live: 0 }
    }
}

impl Reallocator<VecMemory> for ResettingBump {
    fn realloc(
        &mut self,
        memory: &mut VecMemory,
        _gate: &CallGate,
        request: ReallocRequest,
        _budget: &mut AbiBudget,
    ) -> Result<u32, AbiError> {
        if request.old_pointer != 0 || request.old_size != 0 || request.new_size == 0 {
            return Err(AbiError::BadRealloc);
        }
        let aligned = self
            .next
            .checked_add(request.alignment - 1)
            .map(|value| value & !(request.alignment - 1))
            .ok_or(AbiError::Overflow)?;
        let end = aligned
            .checked_add(request.new_size)
            .ok_or(AbiError::Overflow)?;
        if memory.len() < u64::from(end) {
            memory.grow_to(end as usize)?;
        }
        self.next = end;
        self.live = self.live.checked_add(1).ok_or(AbiError::AllocationLimit)?;
        Ok(aligned)
    }

    fn free(
        &mut self,
        _memory: &mut VecMemory,
        _gate: &CallGate,
        _allocation: Allocation,
        _budget: &mut AbiBudget,
    ) -> Result<(), AbiError> {
        self.live = self.live.checked_sub(1).ok_or(AbiError::CleanupFailed)?;
        if self.live == 0 {
            self.next = 64;
        }
        Ok(())
    }

    fn discard_arena(&mut self, _memory: &mut VecMemory, _gate: &CallGate) {
        self.next = 64;
        self.live = 0;
    }
}

fn canonical_operation(
    machine: &mut CanonicalMachine<VecMemory, ResettingBump>,
) -> Result<u64, RuntimeCostError> {
    machine
        .begin_call()
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    let (text_pointer, text_length) = machine
        .lower_utf8(CANONICAL_TEXT)
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    let lifted_text = machine
        .lift_utf8(text_pointer, text_length)
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    let (list_pointer, list_length) = machine
        .lower_u32_list(&CANONICAL_LIST)
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    let lifted_list = machine
        .lift_u32_list(list_pointer, list_length)
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    if lifted_text != CANONICAL_TEXT || lifted_list.as_slice() != CANONICAL_LIST {
        return Err(RuntimeCostError::CanonicalAbi);
    }
    let result = lifted_text.len() as u64 + lifted_list.len() as u64;
    machine
        .finish_success(|_, _, _| Ok(()))
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    Ok(result)
}

fn canonical_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    let memory = VecMemory::new(65_536, 65_536).map_err(|_| RuntimeCostError::CanonicalAbi)?;
    let mut machine = CanonicalMachine::new(memory, ResettingBump::new(), 100_000)
        .map_err(|_| RuntimeCostError::CanonicalAbi)?;
    canonical_operation(&mut machine)?;
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 0..CANONICAL_BATCH {
            result = result
                .checked_add(canonical_operation(&mut machine)?)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "canonical-string-list-roundtrip",
            category: "lift-lower",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: CANONICAL_BATCH,
            bytes: CANONICAL_BATCH * (CANONICAL_TEXT.len() + CANONICAL_LIST.len() * 4) as u64,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

fn async_operation() -> Result<u64, RuntimeCostError> {
    let mut state = AsyncState::new(AsyncStateLimits {
        handles: 8,
        pairs: 4,
        tasks: 4,
        waitables_per_set: 4,
    })
    .map_err(|_| RuntimeCostError::AsyncState)?;
    let set = state
        .create_waitable_set()
        .map_err(|_| RuntimeCostError::AsyncState)?;
    let task = state
        .create_task()
        .map_err(|_| RuntimeCostError::AsyncState)?;
    let mut ticket = match state
        .begin_callback_wait(task, set)
        .map_err(|_| RuntimeCostError::AsyncState)?
    {
        WaitBegin::Blocked { ticket } => ticket,
        WaitBegin::Ready(_) => return Err(RuntimeCostError::AsyncState),
    };
    if !matches!(
        state
            .resume_callback_wait(&mut ticket)
            .map_err(|_| RuntimeCostError::AsyncState)?,
        WaitResume::Pending
    ) {
        return Err(RuntimeCostError::AsyncState);
    }
    state
        .cancel_callback_wait(&mut ticket)
        .map_err(|_| RuntimeCostError::AsyncState)?;
    state
        .resolve_task_result(task)
        .map_err(|_| RuntimeCostError::AsyncState)?;
    state
        .callback_exit(task)
        .map_err(|_| RuntimeCostError::AsyncState)?;
    state
        .drop_task(task)
        .map_err(|_| RuntimeCostError::AsyncState)?;
    state
        .drop_waitable_set(set)
        .map_err(|_| RuntimeCostError::AsyncState)?;
    let metrics = state.metrics();
    if metrics.handles.current != 0
        || metrics.pairs.current != 0
        || metrics.tasks.current != 0
        || metrics.wait_registrations.current != 0
    {
        return Err(RuntimeCostError::AsyncState);
    }
    Ok(u64::from(metrics.wait_registrations.peak))
}

fn async_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 0..ASYNC_BATCH {
            result = result
                .checked_add(async_operation()?)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "async-wait-suspend-resume",
            category: "async",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: ASYNC_BATCH,
            bytes: 0,
            fuel_consumed: 0,
            poll_quanta: ASYNC_BATCH * 2,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

fn graph_node<'a>(plan: &'a ComponentPlan<'_>) -> ComponentGraphNodeSpec<'a> {
    ComponentGraphNodeSpec::from_plan(
        "c83-node",
        "vibe:c83/async-route@1.0.0",
        ComponentGraphNesting::Root,
        plan,
        ComponentGraphInstanceBudget {
            resource_slots: 1,
            memory_bytes: 65_536,
            total_fuel: 100_000,
            poll_quantum: 1_000,
        },
    )
}

fn graph_export(node: u16) -> ComponentGraphExportEndpoint {
    ComponentGraphExportEndpoint::new(
        ComponentGraphNodeId::new(node),
        ComponentGraphEntityIndex::new(0),
    )
}

fn graph_import(node: u16) -> ComponentGraphImportEndpoint {
    ComponentGraphImportEndpoint::new(
        ComponentGraphNodeId::new(node),
        ComponentGraphEntityIndex::new(0),
    )
}

fn composition_operation(plan: &ComponentPlan<'_>) -> Result<u64, RuntimeCostError> {
    let nodes = [graph_node(plan); 8];
    let edges = [
        ComponentGraphEdgeSpec::new(graph_export(0), graph_import(1)),
        ComponentGraphEdgeSpec::new(graph_export(1), graph_import(2)),
        ComponentGraphEdgeSpec::new(graph_export(2), graph_import(3)),
        ComponentGraphEdgeSpec::new(graph_export(3), graph_import(4)),
        ComponentGraphEdgeSpec::new(graph_export(4), graph_import(5)),
        ComponentGraphEdgeSpec::new(graph_export(5), graph_import(6)),
        ComponentGraphEdgeSpec::new(graph_export(6), graph_import(7)),
    ];
    let external = [ComponentGraphExternalImportSpec::new(graph_import(0))];
    let published = [ComponentGraphPublishedExportSpec::new(graph_export(7))];
    let graph = plan_component_graph(&nodes, &edges, &external, &published)
        .map_err(|_| RuntimeCostError::Composition)?;
    if graph.runtime_ready()
        || graph.account().nodes != 8
        || graph.account().edges != 7
        || graph.account().external_imports != 1
        || graph.account().published_exports != 1
    {
        return Err(RuntimeCostError::Composition);
    }
    Ok((graph.account().nodes << 32) | graph.account().edges)
}

fn composition_samples<P: Platform>(
    emitter: &mut Emitter<'_, P>,
    plan: &ComponentPlan<'_>,
) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HEAVY_WARMUP, HEAVY_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 0..COMPOSITION_BATCH {
            result = result
                .checked_add(composition_operation(plan)?)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "composition-plan-8-nodes-7-edges",
            category: "composition",
            sample_index,
            warmup: sample_index < HEAVY_WARMUP,
            ticks,
            operations: COMPOSITION_BATCH,
            bytes: 0,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

const HOST_PARAMS: [CoreValueType; 1] = [CoreValueType::I64];
const HOST_RESULTS: [CoreValueType; 1] = [CoreValueType::I64];

fn host_import() -> CoreHostImport<'static> {
    CoreHostImport {
        id: 83,
        module: "vibe:bench/host@1.0.0",
        name: "echo",
        params: &HOST_PARAMS,
        results: &HOST_RESULTS,
    }
}

fn host_call_operation(
    instance: &mut vibeos_wasm_runtime::CoreInstance,
) -> Result<(u64, u64), RuntimeCostError> {
    instance
        .start_call(
            "host-roundtrip",
            &[CoreValue::I64(40)],
            100_000,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .map_err(|_| RuntimeCostError::CoreCall)?;
    let mut polls = 0_u64;
    let request = loop {
        polls += 1;
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::HostCall(call) => break call,
            _ => return Err(RuntimeCostError::CoreCall),
        }
        if polls > 1_000 {
            return Err(RuntimeCostError::CoreCall);
        }
    };
    if request.id != 83 || request.arguments != [CoreValue::I64(40)] {
        return Err(RuntimeCostError::CoreCall);
    }
    instance
        .resume_host_call(83, &[CoreValue::I64(41)])
        .map_err(|_| RuntimeCostError::CoreCall)?;
    let result = loop {
        polls += 1;
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::Ready(values) => break values,
            _ => return Err(RuntimeCostError::CoreCall),
        }
        if polls > 1_000 {
            return Err(RuntimeCostError::CoreCall);
        }
    };
    if result.as_slice() != [CoreValue::I64(42)] {
        return Err(RuntimeCostError::CoreCall);
    }
    let fuel = instance
        .call_metrics()
        .ok_or(RuntimeCostError::CoreCall)?
        .consumed_fuel;
    Ok((fuel, polls))
}

fn host_call_samples<P: Platform>(
    emitter: &mut Emitter<'_, P>,
    core: &ValidatedCore,
) -> Result<(), RuntimeCostError> {
    let mut instance = core
        .instantiate_with_imports(&[host_import()])
        .map_err(|_| RuntimeCostError::CoreInstantiation)?;
    host_call_operation(&mut instance)?;
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut fuel = 0_u64;
        let mut polls = 0_u64;
        for _ in 0..HOST_CALL_BATCH {
            let (operation_fuel, operation_polls) = host_call_operation(&mut instance)?;
            fuel = fuel
                .checked_add(operation_fuel)
                .ok_or(RuntimeCostError::Arithmetic)?;
            polls = polls
                .checked_add(operation_polls)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "core-host-call-roundtrip",
            category: "host-call",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: HOST_CALL_BATCH,
            bytes: HOST_CALL_BATCH * 16,
            fuel_consumed: fuel,
            poll_quanta: polls,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result: HOST_CALL_BATCH * 42,
        });
    }
    Ok(())
}

fn memory_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut memories = Vec::new();
        memories
            .try_reserve_exact(MEMORY_BATCH as usize)
            .map_err(|_| RuntimeCostError::Memory)?;
        let mut result = 0_u64;
        for _ in 0..MEMORY_BATCH {
            let mut memory = VecMemory::new(0, 65_536).map_err(|_| RuntimeCostError::Memory)?;
            memory
                .grow_to(65_536)
                .map_err(|_| RuntimeCostError::Memory)?;
            result = result
                .checked_add(65_536)
                .ok_or(RuntimeCostError::Arithmetic)?;
            memories.push(memory);
        }
        let ticks = checked_elapsed(emitter.platform, started);
        core::hint::black_box(&memories);
        drop(memories);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "linear-memory-grow-64k",
            category: "memory",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: MEMORY_BATCH,
            bytes: MEMORY_BATCH * 65_536,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

fn fuel_operation(
    instance: &mut vibeos_wasm_runtime::CoreInstance,
) -> Result<(u64, u64), RuntimeCostError> {
    instance
        .start_call(
            "burn",
            &[CoreValue::I32(FUEL_ITERATIONS as i32)],
            1_000_000,
            PROFILE_1_LIMITS.poll_quantum,
        )
        .map_err(|_| RuntimeCostError::CoreCall)?;
    let mut polls = 0_u64;
    loop {
        polls += 1;
        match instance.poll_call() {
            PollResult::Pending { .. } => {}
            PollResult::Ready(values) if values.as_slice() == [CoreValue::I32(0)] => break,
            _ => return Err(RuntimeCostError::CoreCall),
        }
        if polls > 1_000 {
            return Err(RuntimeCostError::CoreCall);
        }
    }
    let fuel = instance
        .call_metrics()
        .ok_or(RuntimeCostError::CoreCall)?
        .consumed_fuel;
    if fuel == 0 || fuel >= 1_000_000 {
        return Err(RuntimeCostError::CoreCall);
    }
    Ok((fuel, polls))
}

fn fuel_samples<P: Platform>(
    emitter: &mut Emitter<'_, P>,
    core: &ValidatedCore,
) -> Result<(), RuntimeCostError> {
    let mut instance = core
        .instantiate_with_imports(&[host_import()])
        .map_err(|_| RuntimeCostError::CoreInstantiation)?;
    fuel_operation(&mut instance)?;
    for sample_index in sample_range(FUEL_WARMUP, FUEL_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let (fuel, polls) = fuel_operation(&mut instance)?;
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "core-integer-fuel-throughput",
            category: "fuel",
            sample_index,
            warmup: sample_index < FUEL_WARMUP,
            ticks,
            operations: FUEL_ITERATIONS,
            bytes: 0,
            fuel_consumed: fuel,
            poll_quanta: polls,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result: 0,
        });
    }
    Ok(())
}

fn cancellation_operation() -> Result<u64, RuntimeCostError> {
    let mut state = AsyncState::new(AsyncStateLimits {
        handles: 2,
        pairs: 1,
        tasks: 2,
        waitables_per_set: 1,
    })
    .map_err(|_| RuntimeCostError::Cancellation)?;
    let task = state
        .create_task()
        .map_err(|_| RuntimeCostError::Cancellation)?;
    state
        .request_task_cancel(task)
        .map_err(|_| RuntimeCostError::Cancellation)?;
    let event = state
        .callback_yield(task)
        .map_err(|_| RuntimeCostError::Cancellation)?;
    if event.code != EventCode::TaskCancelled || event.p1 != 0 || event.p2 != 0 {
        return Err(RuntimeCostError::Cancellation);
    }
    state
        .acknowledge_task_cancel(task)
        .map_err(|_| RuntimeCostError::Cancellation)?;
    state
        .callback_exit(task)
        .map_err(|_| RuntimeCostError::Cancellation)?;
    state
        .drop_task(task)
        .map_err(|_| RuntimeCostError::Cancellation)?;
    if state.metrics().tasks.current != 0 {
        return Err(RuntimeCostError::Cancellation);
    }
    Ok(1)
}

fn cancellation_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for _ in 0..CANCELLATION_BATCH {
            result = result
                .checked_add(cancellation_operation()?)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "task-cancel-to-terminal",
            category: "cancellation",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: CANCELLATION_BATCH,
            bytes: 0,
            fuel_consumed: 0,
            poll_quanta: CANCELLATION_BATCH,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

struct BenchResource;

impl Resource for BenchResource {
    fn kind(&self) -> &'static str {
        "c83-bench-resource"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct PreparedRevocation {
    space: CSpace,
    root: vibeos_core::cap::Cap,
    leaf: Revocable<BenchResource>,
}

fn prepare_revocation() -> Result<PreparedRevocation, RuntimeCostError> {
    let mut space = CSpace::new("c83-revocation");
    let rights = Rights::READ.union(Rights::GRANT).union(Rights::REVOKE);
    let root = space.mint(Arc::new(BenchResource), rights);
    let mut cap = root;
    for _ in 0..8 {
        cap = space
            .derive(cap, rights)
            .map_err(|_| RuntimeCostError::Revocation)?;
    }
    let leaf = space
        .lookup_revocable::<BenchResource>(cap, Rights::READ)
        .map_err(|_| RuntimeCostError::Revocation)?;
    Ok(PreparedRevocation { space, root, leaf })
}

fn revocation_samples<P: Platform>(emitter: &mut Emitter<'_, P>) -> Result<(), RuntimeCostError> {
    for sample_index in sample_range(HOT_WARMUP, HOT_SAMPLES) {
        let heap_window = begin_heap_window(emitter.platform)?;
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(REVOCATION_BATCH as usize)
            .map_err(|_| RuntimeCostError::Revocation)?;
        for _ in 0..REVOCATION_BATCH {
            prepared.push(prepare_revocation()?);
        }
        let started = emitter.platform.time();
        let mut result = 0_u64;
        for item in &mut prepared {
            let revoked = item
                .space
                .revoke(item.root)
                .map_err(|_| RuntimeCostError::Revocation)?;
            if revoked != 9 || item.leaf.try_with(|_| 1_u8).is_ok() {
                return Err(RuntimeCostError::Revocation);
            }
            result = result
                .checked_add(revoked as u64)
                .ok_or(RuntimeCostError::Arithmetic)?;
        }
        let ticks = checked_elapsed(emitter.platform, started);
        drop(prepared);
        let heap = finish_heap_window(heap_window)?;
        emitter.emit(Sample {
            workload: "cap-revoke-to-denial",
            category: "revocation",
            sample_index,
            warmup: sample_index < HOT_WARMUP,
            ticks,
            operations: REVOCATION_BATCH,
            bytes: 0,
            fuel_consumed: 0,
            poll_quanta: 0,
            heap_before: heap.live_before,
            heap_peak: heap.peak_live_bytes,
            heap_after: heap.live_after,
            logical_live_after: 0,
            result,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    struct HostPlatform {
        ticks: AtomicU64,
        output: Arc<Mutex<Vec<String>>>,
    }

    struct HostHeapWindow;

    impl HeapWindow for HostHeapWindow {
        fn finish(self) -> HeapWindowObservation {
            HeapWindowObservation {
                live_before: 0,
                peak_live_bytes: 0,
                live_after: 0,
            }
        }
    }

    impl Platform for HostPlatform {
        type HeapWindow<'a> = HostHeapWindow;

        fn platform_id(&self) -> &'static str {
            "qemu-virt"
        }

        fn time(&self) -> u64 {
            self.ticks.fetch_add(10_000, Ordering::Relaxed)
        }

        fn timebase_hz(&self) -> u64 {
            10_000_000
        }

        fn begin_heap_window(&self) -> Option<Self::HeapWindow<'_>> {
            Some(HostHeapWindow)
        }

        fn log(&self, arguments: Arguments<'_>) {
            self.output.lock().unwrap().push(format!("{arguments}"));
        }
    }

    #[test]
    fn build_binds_exact_fixture_identity() {
        assert_eq!(SYNC_COMPONENT.len(), SYNC_COMPONENT_BYTES);
        assert_eq!(ROUTE_COMPONENT.len(), ROUTE_COMPONENT_BYTES);
        assert_eq!(CORE_MODULE.len(), CORE_MODULE_BYTES);
        assert_eq!(SYNC_COMPONENT_SHA256.len(), 64);
        assert_eq!(ROUTE_COMPONENT_SHA256.len(), 64);
        assert_eq!(CORE_MODULE_SHA256.len(), 64);
    }

    #[test]
    fn unbound_normal_build_cannot_publish_evidence() {
        if SOURCE_COMMIT.bytes().all(|byte| byte == b'0') {
            let platform = HostPlatform {
                ticks: AtomicU64::new(1),
                output: Arc::new(Mutex::new(Vec::new())),
            };
            assert_eq!(run(&platform), Err(RuntimeCostError::SourceCommitUnbound));
            assert!(platform.output.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn bound_build_runs_every_workload_and_closes_once() {
        if !is_nonzero_hex(SOURCE_COMMIT, 40) || !is_nonzero_hex(CHALLENGE, 64) {
            return;
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let platform = HostPlatform {
            ticks: AtomicU64::new(1),
            output: output.clone(),
        };
        run(&platform).expect("bound C8.3 host model must complete");
        let output = output.lock().unwrap();
        assert_eq!(
            output
                .iter()
                .filter(|line| line.starts_with("VIBE_WASM_COST_META "))
                .count(),
            1
        );
        assert_eq!(
            output
                .iter()
                .filter(|line| line.starts_with("VIBE_WASM_COST_SAMPLE "))
                .count(),
            RAW_RECORD_COUNT as usize
        );
        assert_eq!(
            output
                .iter()
                .filter(|line| line.starts_with("VIBE_WASM_COST_END "))
                .count(),
            1
        );
    }
}
