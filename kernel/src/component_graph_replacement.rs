//! Boot-local C6.6/C7.6 single-node replacement for one exact admitted graph.
//!
//! The acceptance path is deliberately validation-only. Stage A publishes
//! only the current three-node graph and its two routes.
//! Stage B is unreachable without the loader's move-only post-readback proof;
//! only then may it stage a fresh middle principal, retire both incident
//! routes and the old middle principal, rotate only the siblings'
//! incident endpoints from their own current tasks, then atomically publishes
//! the complete fresh route bundle and the replacement task. No guest bytes
//! are instantiated or invoked.

use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
use core::alloc::Layout;
use core::cell::UnsafeCell;
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
use core::fmt;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll};

#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use vibeos_component_admission::{
    admit_component_graph, admit_component_graph_replacement, ArtifactTrust, CallerAuthority,
    ComponentArtifact, ComponentGraphAdmissionPolicy, ComponentGraphNodeAdmissionPolicy,
    ComponentGraphNodeReplacementPolicy,
};
use vibeos_component_admission::{
    ComponentGraphCyclePolicy, ComponentGraphReplacementEdgeAction,
    ComponentGraphReplacementEdgePolicy, ComponentGraphReplacementNodeAction, InstanceLimits,
    ProfileIdentity,
};
#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use vibeos_component_command::ComponentGraphNodeReplacementTemplate;
use vibeos_component_command::{
    ComponentGraphNodeTerminal, ComponentGraphNodeTerminalReport, ComponentGraphPrincipalTemplate,
};
use vibeos_component_host::{
    revoke_owned_supervised, ByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter,
    ComponentAuthority, StreamCloseOutcome, StreamCloseReason, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSealedWakeToken, StreamSendDispatch, StreamWakeRegistration,
    StreamWakeSignal,
};
#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
use vibeos_component_loader::{
    C76PolicyCancelPermit, C76SupervisorCurrentGraph, C76SupervisorGraphReplacement,
};
use vibeos_component_runtime::graph::{
    ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
    ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
    ComponentGraphPublishedExportSpec,
};
use vibeos_component_runtime::host::{AtomicHostOperationSlot, HostOperationToken};
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
use vibeos_component_runtime::memory::{GuestMemory, VecMemory};
use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use vibeos_component_runtime::world::WorldContract;
use vibeos_core::cap::Rights;
#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use vibeos_image_policy::ComponentGraphReplacementPinAction;
#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use vibeos_image_policy::C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
use vibeos_image_policy::C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;

use crate::exec::{OneShotWaitQueue, PreparedTaskBatch, TaskHandle, TaskState};
use crate::heap::{AllocationDomain, OwnerId};
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
use crate::instance::InstancePhase;
use crate::instance::{
    AcceptanceInstanceProbe, InstanceContinuation, InstanceContinuationKind,
    InstanceContinuationSignal, InstanceContinuationToken, InstancePayload, InstanceSpace,
    InstanceToken,
};
use crate::sync::SpinLock;

#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
use super::release_empty_domain;
use super::{
    abort_pristine_registry_batch, checked_plan, completion_guest_calls, create_domains,
    lifecycle_invariant_failed, publication_pairs, reserve_registry_batch,
    reserve_resource_generations, retire_domain, ComponentGraphPrincipalLifecycleError,
    PRINCIPAL_TASK_NAME, RUNTIME_UNAVAILABLE_COMPLETION,
};
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
use super::{PrincipalFuelEnvelope, COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES};

const C66_NODE_COUNT: usize = 3;
const C66_INCARNATION_COUNT: usize = 4;
const C66_TARGET_INDEX: usize = 1;
const C66_SOURCE_BIT: u8 = 1 << 0;
const C66_TARGET_BIT: u8 = 1 << 1;
const C66_SINK_BIT: u8 = 1 << 2;
const C66_ALL_NODE_BITS: u8 = C66_SOURCE_BIT | C66_TARGET_BIT | C66_SINK_BIT;
const C66_SIBLING_BITS: u8 = C66_SOURCE_BIT | C66_SINK_BIT;
const C66_VALUE: u8 = 0x66;
#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
const C77_MEMORY_BYTES_PER_NODE: usize = 64 * 1024;
const C66_WIT_SHA256: [u8; 32] = [
    0x05, 0x3e, 0x44, 0x72, 0x9a, 0x38, 0x75, 0x45, 0xf5, 0xdc, 0x73, 0xba, 0xc2, 0x11, 0xd3, 0x07,
    0xde, 0x74, 0x6a, 0x4c, 0xf7, 0x58, 0xd1, 0x79, 0xc0, 0xfa, 0x3c, 0xf2, 0xb9, 0xe8, 0xc5, 0xbf,
];

const C66_SOURCE_WRITER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_06_0001);
const C66_RELAY_READER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_06_0002);
const C66_RELAY_WRITER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_06_0003);
const C66_SINK_READER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_06_0004);

const C66_PHASE_BITS: u32 = 8;
const C66_PHASE_OLD: u8 = 1;
const C66_PHASE_DISCONNECTED: u8 = 2;
const C66_PHASE_ROTATE: u8 = 3;
const C66_PHASE_COMMITTED: u8 = 4;
const C66_PHASE_SEND: u8 = 5;
const C66_PHASE_RECEIVE: u8 = 6;
const C66_PHASE_DONE: u8 = 7;

static NEXT_C66_GENERATION: AtomicU64 = AtomicU64::new(1);
static C66_GRAPH_CONTROL: AtomicU64 = AtomicU64::new(0);
static C66_OLD_READY: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_SIBLINGS_ROTATED: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_CANDIDATE_WAITING: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_CANDIDATE_DONE: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_FRESH_DONE: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_FAILURE: OneShotWaitQueue = OneShotWaitQueue::new();
static C66_OLD_OPERATION: AtomicHostOperationSlot = AtomicHostOperationSlot::new();
static C66_CANDIDATE_OPERATION: AtomicHostOperationSlot = AtomicHostOperationSlot::new();
static C66_OLD_WAKE_SIGNAL: C66WakeSignalSlot = C66WakeSignalSlot::new();
static C66_CANDIDATE_WAKE_SIGNAL: C66WakeSignalSlot = C66WakeSignalSlot::new();
static C66_OLD_WAKE_WORDS: SpinLock<Option<[usize; 4]>> = SpinLock::new(None);
static C66_CANDIDATE_WAKE_WORDS: SpinLock<Option<[usize; 4]>> = SpinLock::new(None);
static C66_OLD_OPERATION_REPLAY: SpinLock<Option<HostOperationToken>> = SpinLock::new(None);

/// One fixed supervisor cell for a callback-issued, move-only stream signal.
/// The paired atomic operation remains the route identity; publication
/// rechecks it under this lock so a late callback cannot populate a replacement
/// generation after teardown cleared the operation ledger.
struct C66WakeSignalSlot {
    signal: SpinLock<Option<StreamWakeSignal>>,
}

impl C66WakeSignalSlot {
    const fn new() -> Self {
        Self {
            signal: SpinLock::new(None),
        }
    }

    fn publish_exact(
        &self,
        operation_slot: &AtomicHostOperationSlot,
        signal: StreamWakeSignal,
    ) -> bool {
        let operation = signal.operation();
        let mut stored = self.signal.lock();
        if stored.is_some() || !operation_slot.contains(operation) {
            return false;
        }
        *stored = Some(signal);
        true
    }

    fn take_exact(&self, operation: HostOperationToken) -> Option<StreamWakeSignal> {
        let mut stored = self.signal.lock();
        if stored
            .as_ref()
            .is_some_and(|signal| signal.operation() == operation)
        {
            stored.take()
        } else {
            None
        }
    }

    fn clear_exact(&self, operation: HostOperationToken) -> bool {
        let mut stored = self.signal.lock();
        match stored.as_ref() {
            Some(signal) if signal.operation() == operation => {
                drop(stored.take());
                true
            }
            None => true,
            Some(_) => false,
        }
    }

    fn clear(&self) {
        drop(self.signal.lock().take());
    }

    fn is_empty(&self) -> bool {
        self.signal.lock().is_none()
    }
}

const fn c66_phase_word(generation: u64, phase: u8) -> Option<u64> {
    if generation == 0 || generation > (u64::MAX >> C66_PHASE_BITS) {
        None
    } else {
        Some((generation << C66_PHASE_BITS) | phase as u64)
    }
}

fn c66_phase(generation: u64) -> Option<u8> {
    let word = C66_GRAPH_CONTROL.load(Ordering::Acquire);
    ((word >> C66_PHASE_BITS) == generation).then_some(word as u8)
}

fn c66_transition(generation: u64, from: u8, to: u8) -> bool {
    let (Some(from), Some(to)) = (
        c66_phase_word(generation, from),
        c66_phase_word(generation, to),
    ) else {
        return false;
    };
    C66_GRAPH_CONTROL
        .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

struct C66Audit {
    generation: AtomicU64,
    failed: AtomicBool,
    old_ready_mask: AtomicU8,
    rotated_mask: AtomicU8,
    fresh_completed_mask: AtomicU8,
    wake_registrations: AtomicU64,
    wake_callbacks: AtomicU64,
    continuation_resumes: AtomicU64,
    sealed_resumes: AtomicU64,
    old_routes_retired: AtomicU64,
    fresh_routes: AtomicU64,
    stale_sibling_routes: AtomicU64,
    stable_sibling_resource_tables: AtomicU64,
    stale_replacement_tokens: AtomicU64,
    late_wake_stale: AtomicU64,
    fresh_edge_deliveries: AtomicU64,
    sink_deliveries: AtomicU64,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    c77_runtime_mask: AtomicU8,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    c77_pending_ledger_mask: AtomicU8,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    c77_active_pending_mask: AtomicU8,
}

impl C66Audit {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            failed: AtomicBool::new(false),
            old_ready_mask: AtomicU8::new(0),
            rotated_mask: AtomicU8::new(0),
            fresh_completed_mask: AtomicU8::new(0),
            wake_registrations: AtomicU64::new(0),
            wake_callbacks: AtomicU64::new(0),
            continuation_resumes: AtomicU64::new(0),
            sealed_resumes: AtomicU64::new(0),
            old_routes_retired: AtomicU64::new(0),
            fresh_routes: AtomicU64::new(0),
            stale_sibling_routes: AtomicU64::new(0),
            stable_sibling_resource_tables: AtomicU64::new(0),
            stale_replacement_tokens: AtomicU64::new(0),
            late_wake_stale: AtomicU64::new(0),
            fresh_edge_deliveries: AtomicU64::new(0),
            sink_deliveries: AtomicU64::new(0),
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            c77_runtime_mask: AtomicU8::new(0),
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            c77_pending_ledger_mask: AtomicU8::new(0),
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            c77_active_pending_mask: AtomicU8::new(0),
        }
    }

    fn reset(&self, generation: u64) -> bool {
        let Some(old_phase) = c66_phase_word(generation, C66_PHASE_OLD) else {
            return false;
        };
        if C66_OLD_OPERATION.load().is_some() || C66_CANDIDATE_OPERATION.load().is_some() {
            return false;
        }
        C66_OLD_WAKE_SIGNAL.clear();
        C66_CANDIDATE_WAKE_SIGNAL.clear();
        if !C66_OLD_WAKE_SIGNAL.is_empty()
            || !C66_CANDIDATE_WAKE_SIGNAL.is_empty()
            || C66_OLD_WAKE_WORDS.lock().is_some()
            || C66_CANDIDATE_WAKE_WORDS.lock().is_some()
            || C66_OLD_OPERATION_REPLAY.lock().is_some()
            || self
                .generation
                .compare_exchange(0, generation, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        if C66_GRAPH_CONTROL
            .compare_exchange(0, old_phase, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            let _ = self.generation.compare_exchange(
                generation,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return false;
        }
        self.failed.store(false, Ordering::Release);
        self.old_ready_mask.store(0, Ordering::Release);
        self.rotated_mask.store(0, Ordering::Release);
        self.fresh_completed_mask.store(0, Ordering::Release);
        self.wake_registrations.store(0, Ordering::Release);
        self.wake_callbacks.store(0, Ordering::Release);
        self.continuation_resumes.store(0, Ordering::Release);
        self.sealed_resumes.store(0, Ordering::Release);
        self.old_routes_retired.store(0, Ordering::Release);
        self.fresh_routes.store(0, Ordering::Release);
        self.stale_sibling_routes.store(0, Ordering::Release);
        self.stable_sibling_resource_tables
            .store(0, Ordering::Release);
        self.stale_replacement_tokens.store(0, Ordering::Release);
        self.late_wake_stale.store(0, Ordering::Release);
        self.fresh_edge_deliveries.store(0, Ordering::Release);
        self.sink_deliveries.store(0, Ordering::Release);
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        {
            self.c77_runtime_mask.store(0, Ordering::Release);
            self.c77_pending_ledger_mask.store(0, Ordering::Release);
            self.c77_active_pending_mask.store(0, Ordering::Release);
        }
        true
    }

    fn matches(&self, generation: u64) -> bool {
        generation != 0 && self.generation.load(Ordering::Acquire) == generation
    }
}

static C66_AUDIT: C66Audit = C66Audit::new();

fn c66_increment(counter: &AtomicU64, generation: u64) -> bool {
    C66_AUDIT.matches(generation)
        && counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .is_ok()
}

fn c66_publish_failure(generation: u64) {
    if !C66_AUDIT.matches(generation) {
        return;
    }
    C66_AUDIT.failed.store(true, Ordering::Release);
    if let Ok(wake) = C66_FAILURE.publish(generation) {
        let _ = wake.dispatch();
    }
}

fn c66_mark_mask(
    generation: u64,
    mask: &AtomicU8,
    bit: u8,
    expected: u8,
    queue: &'static OneShotWaitQueue,
) -> bool {
    if !C66_AUDIT.matches(generation)
        || mask
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current & bit == 0).then_some(current | bit)
            })
            .is_err()
    {
        c66_publish_failure(generation);
        return false;
    }
    if mask.load(Ordering::Acquire) == expected {
        match queue.publish(generation) {
            Ok(wake) => {
                let _ = wake.dispatch();
            }
            Err(_) => {
                c66_publish_failure(generation);
                return false;
            }
        }
    }
    true
}

fn c66_stream_wake(words: [usize; 4], wake_signal: StreamWakeSignal) {
    let generation = C66_AUDIT.generation.load(Ordering::Acquire);
    if !C66_AUDIT.matches(generation) || C66_AUDIT.failed.load(Ordering::Acquire) {
        return;
    }
    let operation = wake_signal.operation();
    let old = C66_OLD_OPERATION.contains(operation);
    let candidate = C66_CANDIDATE_OPERATION.contains(operation);
    let (operation_slot, signal_slot) = match (old, candidate) {
        (true, false) => (&C66_OLD_OPERATION, &C66_OLD_WAKE_SIGNAL),
        (false, true) => (&C66_CANDIDATE_OPERATION, &C66_CANDIDATE_WAKE_SIGNAL),
        // No match is an inert callback which lost a cancellation/replacement
        // race. Two matches violate globally unique operation routing.
        (false, false) => return,
        (true, true) => {
            c66_publish_failure(generation);
            return;
        }
    };
    if !signal_slot.publish_exact(operation_slot, wake_signal) {
        c66_publish_failure(generation);
        return;
    }
    if !c66_increment(&C66_AUDIT.wake_callbacks, generation)
        || super::super::component_instances::registry().signal_continuation_words(words)
            != InstanceContinuationSignal::Signalled
    {
        let _ = signal_slot.clear_exact(operation);
        c66_publish_failure(generation);
    }
}

const C66_HANDOFF_EMPTY: u8 = 0;
const C66_HANDOFF_WRITING: u8 = 1;
const C66_HANDOFF_READY: u8 = 2;
const C66_HANDOFF_TAKEN: u8 = 3;

/// One allocation-only Stage-A latch. It carries no candidate identity,
/// resource, route, CSpace, arena, or task. Stage B may fill it exactly once
/// with the already-complete hidden candidate transaction, then wake the
/// exact SYSTEM supervisor published alongside the current graph.
struct C66SupervisorActivationCell {
    generation: u64,
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<C66Supervisor>>,
}

unsafe impl Send for C66SupervisorActivationCell {}
unsafe impl Sync for C66SupervisorActivationCell {}

impl Drop for C66SupervisorActivationCell {
    fn drop(&mut self) {
        if *self.state.get_mut() == C66_HANDOFF_READY {
            // SAFETY: READY is published only after the sole writer fully
            // initialized `value`, and TAKEN is published by the sole reader.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

struct C66SupervisorActivationPublisher {
    cell: Arc<C66SupervisorActivationCell>,
}

struct C66SupervisorActivationReceiver {
    cell: Arc<C66SupervisorActivationCell>,
}

fn c66_supervisor_activation(
    generation: u64,
) -> (
    C66SupervisorActivationPublisher,
    C66SupervisorActivationReceiver,
) {
    let cell = Arc::new(C66SupervisorActivationCell {
        generation,
        state: AtomicU8::new(C66_HANDOFF_EMPTY),
        value: UnsafeCell::new(MaybeUninit::uninit()),
    });
    (
        C66SupervisorActivationPublisher {
            cell: Arc::clone(&cell),
        },
        C66SupervisorActivationReceiver { cell },
    )
}

impl C66SupervisorActivationPublisher {
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn is_unpublished_exact(&self, generation: u64) -> bool {
        self.cell.generation == generation
            && self.cell.state.load(Ordering::Acquire) == C66_HANDOFF_EMPTY
    }

    fn publish(self, generation: u64, supervisor: C66Supervisor) -> Result<(), C66Supervisor> {
        if self.cell.generation != generation
            || self
                .cell
                .state
                .compare_exchange(
                    C66_HANDOFF_EMPTY,
                    C66_HANDOFF_WRITING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return Err(supervisor);
        }
        // SAFETY: the successful EMPTY -> WRITING transition gives this
        // consumed publisher unique initialization access.
        unsafe { (*self.cell.value.get()).write(supervisor) };
        self.cell.state.store(C66_HANDOFF_READY, Ordering::Release);
        Ok(())
    }
}

impl C66SupervisorActivationReceiver {
    fn try_take(&mut self, generation: u64) -> Option<C66Supervisor> {
        if self.cell.generation != generation
            || self
                .cell
                .state
                .compare_exchange(
                    C66_HANDOFF_READY,
                    C66_HANDOFF_TAKEN,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            return None;
        }
        // SAFETY: READY proves initialization and the successful transition
        // gives this sole receiver unique ownership of the value.
        Some(unsafe { (*self.cell.value.get()).assume_init_read() })
    }
}

struct C66FreshEndpointCell<T> {
    generation: u64,
    instance: InstanceToken,
    task: TaskHandle,
    state: AtomicU8,
    endpoint: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the endpoint is written exactly once by the unique publisher after
// EMPTY -> WRITING, published by a Release store to READY, and moved exactly
// once by the unique receiver after READY -> TAKEN. A fault in WRITING or
// TAKEN conservatively leaks the value; it can never expose or drop it twice.
unsafe impl<T: Send> Send for C66FreshEndpointCell<T> {}
// SAFETY: all cross-task access to the UnsafeCell is serialized by the atomic
// one-way state machine described above. No shared reference to `T` escapes.
unsafe impl<T: Send> Sync for C66FreshEndpointCell<T> {}

impl<T> Drop for C66FreshEndpointCell<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == C66_HANDOFF_READY {
            // SAFETY: READY is published only after the unique publisher
            // initialized the slot, and TAKEN is stored before the unique
            // receiver moves it out.
            unsafe { self.endpoint.get_mut().assume_init_drop() };
        }
    }
}

struct C66FreshEndpointPublisher<T> {
    cell: Arc<C66FreshEndpointCell<T>>,
}

struct C66FreshEndpointReceiver<T> {
    cell: Arc<C66FreshEndpointCell<T>>,
}

struct C66FreshEndpointAudit<T> {
    cell: Arc<C66FreshEndpointCell<T>>,
}

fn c66_fresh_endpoint_handoff<T>(
    generation: u64,
    instance: InstanceToken,
    task: &TaskHandle,
) -> (
    C66FreshEndpointPublisher<T>,
    C66FreshEndpointReceiver<T>,
    C66FreshEndpointAudit<T>,
) {
    let cell = Arc::new(C66FreshEndpointCell {
        generation,
        instance,
        task: task.clone(),
        state: AtomicU8::new(C66_HANDOFF_EMPTY),
        endpoint: UnsafeCell::new(MaybeUninit::uninit()),
    });
    (
        C66FreshEndpointPublisher { cell: cell.clone() },
        C66FreshEndpointReceiver { cell: cell.clone() },
        C66FreshEndpointAudit { cell },
    )
}

fn c66_task_handle_matches(left: &TaskHandle, right: &TaskHandle) -> bool {
    left.id() == right.id()
        && left.allocation_domain() == right.allocation_domain()
        && left.shares_status_with(right)
}

impl<T> C66FreshEndpointPublisher<T> {
    fn publish(
        self,
        generation: u64,
        instance: InstanceToken,
        task: &TaskHandle,
        endpoint: T,
    ) -> Result<(), T> {
        if !C66_AUDIT.matches(generation)
            || self.cell.generation != generation
            || self.cell.instance != instance
            || !c66_task_handle_matches(&self.cell.task, task)
            || !task.acceptance_is_parked_exact()
            || c66_phase(generation) != Some(C66_PHASE_DISCONNECTED)
        {
            return Err(endpoint);
        }
        if self
            .cell
            .state
            .compare_exchange(
                C66_HANDOFF_EMPTY,
                C66_HANDOFF_WRITING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(endpoint);
        }
        // SAFETY: this unique publisher owns the WRITING transition and no
        // receiver may read the slot until the following Release store.
        unsafe { (*self.cell.endpoint.get()).write(endpoint) };
        self.cell.state.store(C66_HANDOFF_READY, Ordering::Release);
        Ok(())
    }
}

impl<T> C66FreshEndpointReceiver<T> {
    fn take(self, generation: u64, instance: InstanceToken) -> Option<T> {
        if !C66_AUDIT.matches(generation)
            || self.cell.generation != generation
            || self.cell.instance != instance
            || c66_phase(generation) != Some(C66_PHASE_ROTATE)
            || !self.cell.task.acceptance_is_current_exact()
        {
            return None;
        }
        if self
            .cell
            .state
            .compare_exchange(
                C66_HANDOFF_READY,
                C66_HANDOFF_TAKEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        // SAFETY: the Acquire side of READY -> TAKEN observes the publisher's
        // initialized slot, and this unique receiver is the only reader.
        Some(unsafe { (*self.cell.endpoint.get()).assume_init_read() })
    }
}

impl<T> C66FreshEndpointAudit<T> {
    fn is_consumed_exact(
        &self,
        generation: u64,
        instance: InstanceToken,
        task: &TaskHandle,
    ) -> bool {
        Arc::strong_count(&self.cell) == 1
            && self.cell.generation == generation
            && self.cell.instance == instance
            && c66_task_handle_matches(&self.cell.task, task)
            && self.cell.state.load(Ordering::Acquire) == C66_HANDOFF_TAKEN
    }
}

#[derive(Clone, Copy)]
struct C66Drain {
    token: ResourceToken,
    resource_type: ResourceTypeId,
}

struct C66PendingReceive {
    token: InstanceContinuationToken,
    continuation: InstanceContinuation<'static>,
    registration: StreamWakeRegistration,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
struct C77PendingLedger {
    active_calls: u8,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
struct C77EphemeralRuntimeState {
    memory: VecMemory,
    fuel: PrincipalFuelEnvelope,
    pending: C77PendingLedger,
    node_bit: u8,
    resource_generation: u64,
    expected_live_resources: usize,
    guest_calls: u64,
    observed: bool,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
impl C77EphemeralRuntimeState {
    fn new(
        memory: VecMemory,
        fuel_limit: u64,
        poll_quantum: u64,
        node_bit: u8,
        resource_generation: u64,
        expected_live_resources: usize,
    ) -> Self {
        Self {
            memory,
            fuel: PrincipalFuelEnvelope {
                limit: fuel_limit,
                poll_quantum,
                consumed: 0,
            },
            pending: C77PendingLedger { active_calls: 0 },
            node_bit,
            resource_generation,
            expected_live_resources,
            guest_calls: 0,
            observed: false,
        }
    }

    fn memory_is_zeroed(&self) -> bool {
        let Ok(length) = usize::try_from(self.memory.len()) else {
            return false;
        };
        if length != C77_MEMORY_BYTES_PER_NODE {
            return false;
        }
        let mut offset = 0usize;
        let mut bytes = [0_u8; 256];
        while offset < length {
            let count = (length - offset).min(bytes.len());
            let Ok(pointer) = u32::try_from(offset) else {
                return false;
            };
            if self
                .memory
                .read_exact(pointer, &mut bytes[..count])
                .is_err()
                || bytes[..count].iter().any(|byte| *byte != 0)
            {
                return false;
            }
            offset += count;
        }
        true
    }

    fn shape_is_valid(&self, resources: &ResourceTable<ComponentAuthority>) -> bool {
        self.node_bit != 0
            && self.node_bit & !C66_ALL_NODE_BITS == 0
            && self.memory_is_zeroed()
            && self.fuel.limit != 0
            && self.fuel.poll_quantum != 0
            && self.fuel.poll_quantum <= self.fuel.limit
            && self.fuel.consumed == 0
            && self.pending.active_calls <= 1
            && self.resource_generation != 0
            && resources.instance_generation() == self.resource_generation
            && resources.len() == self.expected_live_resources
            && self.guest_calls == 0
    }

    fn observe_once(&mut self, generation: u64) -> bool {
        if self.observed {
            return C66_AUDIT.c77_runtime_mask.load(Ordering::Acquire) & self.node_bit != 0
                && C66_AUDIT.c77_pending_ledger_mask.load(Ordering::Acquire) & self.node_bit != 0;
        }
        if !C66_AUDIT.matches(generation) {
            return false;
        }
        let runtime_before = C66_AUDIT
            .c77_runtime_mask
            .fetch_or(self.node_bit, Ordering::AcqRel);
        let pending_before = C66_AUDIT
            .c77_pending_ledger_mask
            .fetch_or(self.node_bit, Ordering::AcqRel);
        if runtime_before & self.node_bit != 0 || pending_before & self.node_bit != 0 {
            return false;
        }
        self.observed = true;
        true
    }

    fn arm_pending(&mut self, generation: u64) -> bool {
        if self.pending.active_calls != 0 || !C66_AUDIT.matches(generation) {
            return false;
        }
        let before = C66_AUDIT
            .c77_active_pending_mask
            .fetch_or(self.node_bit, Ordering::AcqRel);
        if before & self.node_bit != 0 {
            return false;
        }
        self.pending.active_calls = 1;
        true
    }

    fn clear_pending(&mut self, generation: u64) -> bool {
        if self.pending.active_calls != 1 || !C66_AUDIT.matches(generation) {
            return false;
        }
        let before = C66_AUDIT
            .c77_active_pending_mask
            .fetch_and(!self.node_bit, Ordering::AcqRel);
        if before & self.node_bit == 0 {
            return false;
        }
        self.pending.active_calls = 0;
        true
    }
}

enum C66CandidateStage {
    Receive,
    Write(u8),
}

enum C66Role {
    Source {
        announced: bool,
        rotated: bool,
        handoff: Option<C66FreshEndpointReceiver<Arc<ByteStreamWriter>>>,
    },
    OldTarget {
        waiting: Option<C66PendingReceive>,
        announced: bool,
    },
    Sink {
        announced: bool,
        rotated: bool,
        handoff: Option<C66FreshEndpointReceiver<Arc<ByteStreamReader>>>,
    },
    Candidate {
        waiting: Option<C66PendingReceive>,
        stage: C66CandidateStage,
    },
    Transitioning,
    Completed,
}

struct C66Payload {
    generation: u64,
    instance: InstanceToken,
    resources: ResourceTable<ComponentAuthority>,
    drains: [Option<C66Drain>; 2],
    role: C66Role,
    completed: bool,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    c77_runtime: Option<C77EphemeralRuntimeState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C66PayloadOutcome {
    Pending,
    Complete,
    InvariantFailure,
}

fn c66_with_reader<R>(
    resources: &mut ResourceTable<ComponentAuthority>,
    endpoint: C66Drain,
    space: &InstanceSpace,
    operation: impl for<'a> FnOnce(&'a ByteStreamReader) -> R,
) -> Result<R, ()> {
    resources
        .with_borrow(endpoint.token, endpoint.resource_type, |borrowed| {
            borrowed.with(|authority| {
                authority.with_resource::<ByteStreamReader, _, _>(
                    space.cspace(),
                    Rights::RECV,
                    operation,
                )
            })
        })
        .map_err(|_| ())?
        .map_err(|_| ())
}

fn c66_with_writer<R>(
    resources: &mut ResourceTable<ComponentAuthority>,
    endpoint: C66Drain,
    space: &InstanceSpace,
    operation: impl for<'a> FnOnce(&'a ByteStreamWriter) -> R,
) -> Result<R, ()> {
    resources
        .with_borrow(endpoint.token, endpoint.resource_type, |borrowed| {
            borrowed.with(|authority| {
                authority.with_resource::<ByteStreamWriter, _, _>(
                    space.cspace(),
                    Rights::SEND,
                    operation,
                )
            })
        })
        .map_err(|_| ())?
        .map_err(|_| ())
}

fn c66_wake_signal_slot(
    operation_slot: &'static AtomicHostOperationSlot,
) -> Option<&'static C66WakeSignalSlot> {
    if core::ptr::eq(operation_slot, &C66_OLD_OPERATION) {
        Some(&C66_OLD_WAKE_SIGNAL)
    } else if core::ptr::eq(operation_slot, &C66_CANDIDATE_OPERATION) {
        Some(&C66_CANDIDATE_WAKE_SIGNAL)
    } else {
        None
    }
}

impl C66Payload {
    fn new(
        generation: u64,
        instance: InstanceToken,
        resources: ResourceTable<ComponentAuthority>,
        drains: [Option<C66Drain>; 2],
        role: C66Role,
    ) -> Self {
        Self {
            generation,
            instance,
            resources,
            drains,
            role,
            completed: false,
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            c77_runtime: None,
        }
    }

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn with_c77_runtime(mut self, runtime: Option<C77EphemeralRuntimeState>) -> Self {
        self.c77_runtime = runtime;
        self
    }

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn c77_arm_pending(&mut self) -> bool {
        self.c77_runtime
            .as_mut()
            .is_none_or(|runtime| runtime.arm_pending(self.generation))
    }

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn c77_clear_pending(&mut self) -> bool {
        self.c77_runtime
            .as_mut()
            .is_none_or(|runtime| runtime.clear_pending(self.generation))
    }

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn c77_runtime_shape_is_valid(&self) -> bool {
        self.c77_runtime
            .as_ref()
            .is_none_or(|runtime| runtime.shape_is_valid(&self.resources))
    }

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    fn c77_pending_role_matches(&self) -> bool {
        let Some(runtime) = self.c77_runtime.as_ref() else {
            return true;
        };
        let role_has_pending = matches!(
            self.role,
            C66Role::OldTarget {
                waiting: Some(_),
                ..
            } | C66Role::Candidate {
                waiting: Some(_),
                ..
            }
        );
        role_has_pending == (runtime.pending.active_calls == 1)
    }

    fn drain(&self, index: usize) -> Result<C66Drain, ()> {
        self.drains.get(index).copied().flatten().ok_or(())
    }

    fn finish(&mut self) -> C66PayloadOutcome {
        if self.completed {
            return C66PayloadOutcome::InvariantFailure;
        }
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        if !self.c77_runtime_shape_is_valid()
            || self
                .c77_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.pending.active_calls != 0)
        {
            return C66PayloadOutcome::InvariantFailure;
        }
        for drain in &mut self.drains {
            if let Some(exact) = drain.take() {
                if self
                    .resources
                    .drop_owned(exact.token, exact.resource_type)
                    .is_err()
                {
                    return C66PayloadOutcome::InvariantFailure;
                }
            }
        }
        if !self.resources.is_empty() {
            return C66PayloadOutcome::InvariantFailure;
        }
        self.completed = true;
        self.role = C66Role::Completed;
        C66PayloadOutcome::Complete
    }

    fn rotate_writer(&mut self, space: &InstanceSpace, fresh: Arc<ByteStreamWriter>) -> bool {
        let table_generation = self.resources.instance_generation();
        let Ok(old) = self.drain(0) else {
            return false;
        };
        let prepared = {
            let mut cspace = space.cspace().lock();
            if revoke_owned_supervised::<ByteStreamWriter>(
                &mut self.resources,
                old.token,
                old.resource_type,
                &mut cspace,
            ) != Ok(1)
            {
                return false;
            }
            let cap = cspace.mint(fresh, Rights::SEND);
            match ComponentAuthority::prepare_ephemeral_in::<ByteStreamWriter>(
                &cspace,
                cap,
                Rights::SEND,
            ) {
                Ok(authority) => authority,
                Err(_) => return false,
            }
        };
        let Ok(token) = self
            .resources
            .insert_owned(old.resource_type, prepared.into_authority())
        else {
            return false;
        };
        if self.resources.instance_generation() != table_generation
            || self.resources.len() != 1
            || self.resources.contains(old.token, old.resource_type) != Err(ResourceError::Stale)
            || !c66_increment(&C66_AUDIT.stale_sibling_routes, self.generation)
            || !c66_increment(&C66_AUDIT.stable_sibling_resource_tables, self.generation)
            || !c66_increment(&C66_AUDIT.fresh_routes, self.generation)
        {
            return false;
        }
        self.drains[0] = Some(C66Drain {
            token,
            resource_type: old.resource_type,
        });
        true
    }

    fn rotate_reader(&mut self, space: &InstanceSpace, fresh: Arc<ByteStreamReader>) -> bool {
        let table_generation = self.resources.instance_generation();
        let Ok(old) = self.drain(0) else {
            return false;
        };
        let prepared = {
            let mut cspace = space.cspace().lock();
            if revoke_owned_supervised::<ByteStreamReader>(
                &mut self.resources,
                old.token,
                old.resource_type,
                &mut cspace,
            ) != Ok(1)
            {
                return false;
            }
            let cap = cspace.mint(fresh, Rights::RECV);
            match ComponentAuthority::prepare_ephemeral_in::<ByteStreamReader>(
                &cspace,
                cap,
                Rights::RECV,
            ) {
                Ok(authority) => authority,
                Err(_) => return false,
            }
        };
        let Ok(token) = self
            .resources
            .insert_owned(old.resource_type, prepared.into_authority())
        else {
            return false;
        };
        if self.resources.instance_generation() != table_generation
            || self.resources.len() != 1
            || self.resources.contains(old.token, old.resource_type) != Err(ResourceError::Stale)
            || !c66_increment(&C66_AUDIT.stale_sibling_routes, self.generation)
            || !c66_increment(&C66_AUDIT.stable_sibling_resource_tables, self.generation)
            || !c66_increment(&C66_AUDIT.fresh_routes, self.generation)
        {
            return false;
        }
        self.drains[0] = Some(C66Drain {
            token,
            resource_type: old.resource_type,
        });
        true
    }

    fn cancel_receive(
        &mut self,
        space: &InstanceSpace,
        endpoint: C66Drain,
        pending: C66PendingReceive,
        slot: &'static AtomicHostOperationSlot,
    ) -> bool {
        let Some(signal_slot) = c66_wake_signal_slot(slot) else {
            return false;
        };
        let operation = pending.registration.operation();
        let cancelled = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.cancel(operation)
        }) == Ok(Ok(()));
        let backend_revoked = cancelled || !slot.contains(operation);
        // Even an impossible backend cancellation failure must not leave a
        // stable route through which its eventual callback could populate a
        // replacement signal cell. The false return still forces fail-stop.
        let _ = slot.clear_exact(operation);
        let signal_cleared = signal_slot.clear_exact(operation);
        if core::ptr::eq(slot, &C66_OLD_OPERATION) {
            let _ = C66_OLD_WAKE_WORDS.lock().take();
            let mut replay = C66_OLD_OPERATION_REPLAY.lock();
            if replay.as_ref() == Some(&operation) {
                let _ = replay.take();
            }
        } else {
            let _ = C66_CANDIDATE_WAKE_WORDS.lock().take();
        }
        // The registration is retained through exact cancellation and is
        // dropped only after the backend revoke attempt has completed.
        drop(pending);
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        let pending_cleared = self.c77_clear_pending();
        #[cfg(not(feature = "wasm-c77-ephemeral-runtime-acceptance"))]
        let pending_cleared = true;
        backend_revoked && signal_cleared && !slot.contains(operation) && pending_cleared
    }

    fn abandon_receive_arm(
        &mut self,
        space: &InstanceSpace,
        endpoint: C66Drain,
        operation: HostOperationToken,
        slot: &'static AtomicHostOperationSlot,
        words: &'static SpinLock<Option<[usize; 4]>>,
    ) {
        let _ = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.cancel(operation)
        });
        let _ = slot.clear_exact(operation);
        if let Some(signal_slot) = c66_wake_signal_slot(slot) {
            let _ = signal_slot.clear_exact(operation);
        }
        let _ = words.lock().take();
        if core::ptr::eq(slot, &C66_OLD_OPERATION) {
            let mut replay = C66_OLD_OPERATION_REPLAY.lock();
            if replay.as_ref() == Some(&operation) {
                let _ = replay.take();
            }
        }
    }

    fn arm_receive(
        &mut self,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        endpoint: C66Drain,
        operation: HostOperationToken,
        slot: &'static AtomicHostOperationSlot,
        words: &'static SpinLock<Option<[usize; 4]>>,
    ) -> Result<C66PendingReceive, ()> {
        let signal_slot = c66_wake_signal_slot(slot).ok_or(())?;
        if !signal_slot.is_empty() || !slot.publish(operation) {
            let _ = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
                reader.cancel(operation)
            });
            return Err(());
        }
        if core::ptr::eq(slot, &C66_OLD_OPERATION) {
            let mut replay = C66_OLD_OPERATION_REPLAY.lock();
            if replay.is_some() {
                drop(replay);
                self.abandon_receive_arm(space, endpoint, operation, slot, words);
                return Err(());
            }
            *replay = Some(operation);
        }
        let token = match super::super::component_instances::registry()
            .arm_continuation_current(self.instance, InstanceContinuationKind::External)
        {
            Ok(token) => token,
            Err(_) => {
                self.abandon_receive_arm(space, endpoint, operation, slot, words);
                return Err(());
            }
        };
        let mut continuation: InstanceContinuation<'static> =
            match super::super::component_instances::registry().wait_continuation(token) {
                Ok(continuation) => continuation,
                Err(_) => {
                    self.abandon_receive_arm(space, endpoint, operation, slot, words);
                    return Err(());
                }
            };
        if Pin::new(&mut continuation).poll(context) != Poll::Pending {
            self.abandon_receive_arm(space, endpoint, operation, slot, words);
            return Err(());
        }
        let signal_words = token.signal_words();
        {
            let mut stored = words.lock();
            if stored.is_some() {
                drop(stored);
                self.abandon_receive_arm(space, endpoint, operation, slot, words);
                return Err(());
            }
            *stored = Some(signal_words);
        }
        let registration = match c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.register_wake_sealed(
                operation,
                StreamSealedWakeToken::new(signal_words, c66_stream_wake),
            )
        }) {
            Ok(Ok(registration)) => registration,
            _ => {
                self.abandon_receive_arm(space, endpoint, operation, slot, words);
                return Err(());
            }
        };
        if !slot.contains(operation)
            || !c66_increment(&C66_AUDIT.wake_registrations, self.generation)
        {
            self.abandon_receive_arm(space, endpoint, operation, slot, words);
            drop(registration);
            return Err(());
        }
        let pending = C66PendingReceive {
            token,
            continuation,
            registration,
        };
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        if !self.c77_arm_pending() {
            let _ = self.cancel_receive(space, endpoint, pending, slot);
            return Err(());
        }
        Ok(pending)
    }

    fn resume_receive(
        &mut self,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        endpoint: C66Drain,
        mut pending: C66PendingReceive,
        slot: &'static AtomicHostOperationSlot,
    ) -> Result<(StreamReceiveDispatch, Option<C66PendingReceive>), ()> {
        match Pin::new(&mut pending.continuation).poll(context) {
            Poll::Pending => {
                return Ok((
                    StreamReceiveDispatch::Waiting(pending.registration.operation()),
                    Some(pending),
                ))
            }
            Poll::Ready(Ok(consumed)) if consumed.matches_token(pending.token) => {}
            _ => {
                let _ = self.cancel_receive(space, endpoint, pending, slot);
                return Err(());
            }
        }
        let operation = pending.registration.operation();
        let Some(signal_slot) = c66_wake_signal_slot(slot) else {
            let _ = self.cancel_receive(space, endpoint, pending, slot);
            return Err(());
        };
        if !slot.contains(operation) {
            let _ = self.cancel_receive(space, endpoint, pending, slot);
            return Err(());
        }
        let Some(wake_signal) = signal_slot.take_exact(operation) else {
            let _ = self.cancel_receive(space, endpoint, pending, slot);
            return Err(());
        };
        if !c66_increment(&C66_AUDIT.continuation_resumes, self.generation) {
            self.abandon_receive_arm(
                space,
                endpoint,
                operation,
                slot,
                if core::ptr::eq(slot, &C66_OLD_OPERATION) {
                    &C66_OLD_WAKE_WORDS
                } else {
                    &C66_CANDIDATE_WAKE_WORDS
                },
            );
            drop(wake_signal);
            drop(pending);
            return Err(());
        }
        let resumed = c66_with_reader(&mut self.resources, endpoint, space, move |reader| {
            reader.resume_after_wake(wake_signal)
        });
        let dispatch = match resumed {
            Ok(Ok(dispatch)) => {
                // Successful signal consumption retires the cancellation-only
                // registration. It is never used as resume authority.
                drop(pending);
                dispatch
            }
            Ok(Err(failure)) => {
                drop(failure.into_signal());
                let _ = self.cancel_receive(space, endpoint, pending, slot);
                return Err(());
            }
            Err(()) => {
                let _ = self.cancel_receive(space, endpoint, pending, slot);
                return Err(());
            }
        };
        if !slot.clear_exact(operation)
            || !signal_slot.is_empty()
            || !c66_increment(&C66_AUDIT.sealed_resumes, self.generation)
        {
            return Err(());
        }
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        if !self.c77_clear_pending() {
            return Err(());
        }
        if core::ptr::eq(slot, &C66_CANDIDATE_OPERATION) {
            let _ = C66_CANDIDATE_WAKE_WORDS.lock().take();
        }
        Ok((dispatch, None))
    }

    fn commit_byte(
        &mut self,
        space: &InstanceSpace,
        endpoint: C66Drain,
        dispatch: StreamReceiveDispatch,
    ) -> Result<u8, ()> {
        let StreamReceiveDispatch::Prepared(prepared) = dispatch else {
            return Err(());
        };
        if prepared.length() != 1 {
            return Err(());
        }
        let mut byte = [0_u8];
        let commit = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.commit(prepared.operation(), &mut byte)
        })?;
        (commit == Ok(StreamReceiveCommit::Received(1)))
            .then_some(byte[0])
            .ok_or(())
    }

    fn poll_source(
        &mut self,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        mut announced: bool,
        mut rotated: bool,
        mut handoff: Option<C66FreshEndpointReceiver<Arc<ByteStreamWriter>>>,
    ) -> C66PayloadOutcome {
        match c66_phase(self.generation) {
            Some(C66_PHASE_OLD) if !announced => {
                announced = c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.old_ready_mask,
                    C66_SOURCE_BIT,
                    C66_ALL_NODE_BITS,
                    &C66_OLD_READY,
                );
            }
            Some(C66_PHASE_ROTATE) if announced && !rotated => {
                let Some(receiver) = handoff.take() else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                let Some(endpoint) = receiver.take(self.generation, self.instance) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if !self.rotate_writer(space, endpoint) {
                    return C66PayloadOutcome::InvariantFailure;
                }
                rotated = true;
                if !c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.rotated_mask,
                    C66_SOURCE_BIT,
                    C66_SIBLING_BITS,
                    &C66_SIBLINGS_ROTATED,
                ) {
                    return C66PayloadOutcome::InvariantFailure;
                }
            }
            Some(C66_PHASE_SEND) if rotated => {
                let Ok(output) = self.drain(0) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if c66_with_writer(&mut self.resources, output, space, |writer| {
                    writer.start(&[C66_VALUE])
                }) != Ok(Ok(StreamSendDispatch::Sent))
                {
                    return C66PayloadOutcome::InvariantFailure;
                }
                if !c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.fresh_completed_mask,
                    C66_SOURCE_BIT,
                    C66_ALL_NODE_BITS,
                    &C66_FRESH_DONE,
                ) {
                    return C66PayloadOutcome::InvariantFailure;
                }
                return self.finish();
            }
            _ => {}
        }
        self.role = C66Role::Source {
            announced,
            rotated,
            handoff,
        };
        let _ = context;
        C66PayloadOutcome::Pending
    }

    fn poll_old_target(
        &mut self,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        mut waiting: Option<C66PendingReceive>,
        mut announced: bool,
    ) -> C66PayloadOutcome {
        let Ok(input) = self.drain(0) else {
            return C66PayloadOutcome::InvariantFailure;
        };
        if let Some(pending) = waiting.take() {
            let Ok((dispatch, still_waiting)) =
                self.resume_receive(space, context, input, pending, &C66_OLD_OPERATION)
            else {
                return C66PayloadOutcome::InvariantFailure;
            };
            if let Some(pending) = still_waiting {
                self.role = C66Role::OldTarget {
                    waiting: Some(pending),
                    announced,
                };
                return C66PayloadOutcome::Pending;
            }
            if dispatch != StreamReceiveDispatch::Closed(StreamCloseReason::Cancelled) {
                return C66PayloadOutcome::InvariantFailure;
            }
            return self.finish();
        }
        if !announced && c66_phase(self.generation) == Some(C66_PHASE_OLD) {
            let Ok(dispatch) =
                c66_with_reader(&mut self.resources, input, space, ByteStreamReader::start)
            else {
                return C66PayloadOutcome::InvariantFailure;
            };
            let Ok(StreamReceiveDispatch::Waiting(operation)) = dispatch else {
                return C66PayloadOutcome::InvariantFailure;
            };
            let Ok(pending) = self.arm_receive(
                space,
                context,
                input,
                operation,
                &C66_OLD_OPERATION,
                &C66_OLD_WAKE_WORDS,
            ) else {
                return C66PayloadOutcome::InvariantFailure;
            };
            announced = c66_mark_mask(
                self.generation,
                &C66_AUDIT.old_ready_mask,
                C66_TARGET_BIT,
                C66_ALL_NODE_BITS,
                &C66_OLD_READY,
            );
            waiting = Some(pending);
        }
        self.role = C66Role::OldTarget { waiting, announced };
        C66PayloadOutcome::Pending
    }

    fn poll_sink(
        &mut self,
        space: &InstanceSpace,
        mut announced: bool,
        mut rotated: bool,
        mut handoff: Option<C66FreshEndpointReceiver<Arc<ByteStreamReader>>>,
    ) -> C66PayloadOutcome {
        match c66_phase(self.generation) {
            Some(C66_PHASE_OLD) if !announced => {
                announced = c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.old_ready_mask,
                    C66_SINK_BIT,
                    C66_ALL_NODE_BITS,
                    &C66_OLD_READY,
                );
            }
            Some(C66_PHASE_ROTATE) if announced && !rotated => {
                let Some(receiver) = handoff.take() else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                let Some(endpoint) = receiver.take(self.generation, self.instance) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if !self.rotate_reader(space, endpoint) {
                    return C66PayloadOutcome::InvariantFailure;
                }
                rotated = true;
                if !c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.rotated_mask,
                    C66_SINK_BIT,
                    C66_SIBLING_BITS,
                    &C66_SIBLINGS_ROTATED,
                ) {
                    return C66PayloadOutcome::InvariantFailure;
                }
            }
            Some(C66_PHASE_RECEIVE) if rotated => {
                let Ok(input) = self.drain(0) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                let Ok(Ok(dispatch)) =
                    c66_with_reader(&mut self.resources, input, space, ByteStreamReader::start)
                else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                let Ok(byte) = self.commit_byte(space, input, dispatch) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if byte != C66_VALUE
                    || !c66_increment(&C66_AUDIT.fresh_edge_deliveries, self.generation)
                    || !c66_increment(&C66_AUDIT.sink_deliveries, self.generation)
                {
                    return C66PayloadOutcome::InvariantFailure;
                }
                if !c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.fresh_completed_mask,
                    C66_SINK_BIT,
                    C66_ALL_NODE_BITS,
                    &C66_FRESH_DONE,
                ) {
                    return C66PayloadOutcome::InvariantFailure;
                }
                return self.finish();
            }
            _ => {}
        }
        self.role = C66Role::Sink {
            announced,
            rotated,
            handoff,
        };
        C66PayloadOutcome::Pending
    }

    fn poll_candidate(
        &mut self,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        mut waiting: Option<C66PendingReceive>,
        mut stage: C66CandidateStage,
    ) -> C66PayloadOutcome {
        match stage {
            C66CandidateStage::Receive => {
                let Ok(input) = self.drain(0) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                let dispatch = if let Some(pending) = waiting.take() {
                    let Ok((dispatch, still_waiting)) = self.resume_receive(
                        space,
                        context,
                        input,
                        pending,
                        &C66_CANDIDATE_OPERATION,
                    ) else {
                        return C66PayloadOutcome::InvariantFailure;
                    };
                    if let Some(pending) = still_waiting {
                        self.role = C66Role::Candidate {
                            waiting: Some(pending),
                            stage,
                        };
                        return C66PayloadOutcome::Pending;
                    }
                    dispatch
                } else {
                    let Ok(Ok(dispatch)) =
                        c66_with_reader(&mut self.resources, input, space, ByteStreamReader::start)
                    else {
                        return C66PayloadOutcome::InvariantFailure;
                    };
                    match dispatch {
                        StreamReceiveDispatch::Waiting(operation) => {
                            let Ok(pending) = self.arm_receive(
                                space,
                                context,
                                input,
                                operation,
                                &C66_CANDIDATE_OPERATION,
                                &C66_CANDIDATE_WAKE_WORDS,
                            ) else {
                                return C66PayloadOutcome::InvariantFailure;
                            };
                            match C66_CANDIDATE_WAITING.publish(self.generation) {
                                Ok(wake) => {
                                    let _ = wake.dispatch();
                                }
                                Err(_) => return C66PayloadOutcome::InvariantFailure,
                            }
                            self.role = C66Role::Candidate {
                                waiting: Some(pending),
                                stage,
                            };
                            return C66PayloadOutcome::Pending;
                        }
                        prepared @ StreamReceiveDispatch::Prepared(_) => prepared,
                        _ => return C66PayloadOutcome::InvariantFailure,
                    }
                };
                let Ok(byte) = self.commit_byte(space, input, dispatch) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if byte != C66_VALUE
                    || !c66_increment(&C66_AUDIT.fresh_edge_deliveries, self.generation)
                {
                    return C66PayloadOutcome::InvariantFailure;
                }
                stage = C66CandidateStage::Write(byte);
                context.waker().wake_by_ref();
                self.role = C66Role::Candidate { waiting, stage };
                C66PayloadOutcome::Pending
            }
            C66CandidateStage::Write(byte) => {
                let Ok(output) = self.drain(1) else {
                    return C66PayloadOutcome::InvariantFailure;
                };
                if byte != C66_VALUE
                    || c66_with_writer(&mut self.resources, output, space, |writer| {
                        writer.start(&[byte])
                    }) != Ok(Ok(StreamSendDispatch::Sent))
                {
                    return C66PayloadOutcome::InvariantFailure;
                }
                if !c66_mark_mask(
                    self.generation,
                    &C66_AUDIT.fresh_completed_mask,
                    C66_TARGET_BIT,
                    C66_ALL_NODE_BITS,
                    &C66_FRESH_DONE,
                ) {
                    return C66PayloadOutcome::InvariantFailure;
                }
                match C66_CANDIDATE_DONE.publish(self.generation) {
                    Ok(wake) => {
                        let _ = wake.dispatch();
                    }
                    Err(_) => return C66PayloadOutcome::InvariantFailure,
                }
                self.finish()
            }
        }
    }
}

impl Drop for C66Payload {
    fn drop(&mut self) {
        debug_assert!(self.resources.is_empty());
        debug_assert!(self.drains.iter().all(Option::is_none));
        debug_assert!(self.completed);
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        if let Some(runtime) = self.c77_runtime.as_ref() {
            debug_assert!(runtime.memory_is_zeroed());
            debug_assert_ne!(runtime.fuel.limit, 0);
            debug_assert_ne!(runtime.fuel.poll_quantum, 0);
            debug_assert_eq!(runtime.fuel.consumed, 0);
            debug_assert_eq!(runtime.guest_calls, 0);
            debug_assert_eq!(runtime.pending.active_calls, 0);
        }
    }
}

// SAFETY: all retained endpoint Arcs are SYSTEM-owned. The payload never lets
// an arena pointer, CSpace guard, resolved capability, or resource borrow
// escape a quantum. Pending receive state contains only exact opaque backend
// and TaskStatus-owned continuation receipts. A sealed callback deposits its
// move-only readiness proof in one exact, boot-stable operation slot before it
// signals that continuation. Normal completion consumes every signal and
// registration plus every table entry before the exact registry finalizer
// resets the CSpace and retires the arena.
unsafe impl InstancePayload for C66Payload {
    fn poll_quantum(&mut self, space: &InstanceSpace, context: &mut Context<'_>) -> Poll<u64> {
        if self.completed {
            c66_publish_failure(self.generation);
            return Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION);
        }
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        {
            if !self.c77_runtime_shape_is_valid()
                || self
                    .c77_runtime
                    .as_mut()
                    .is_some_and(|runtime| !runtime.observe_once(self.generation))
            {
                c66_publish_failure(self.generation);
                return Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION);
            }
        }
        let role = core::mem::replace(&mut self.role, C66Role::Transitioning);
        let outcome = match role {
            C66Role::Source {
                announced,
                rotated,
                handoff,
            } => self.poll_source(space, context, announced, rotated, handoff),
            C66Role::OldTarget { waiting, announced } => {
                self.poll_old_target(space, context, waiting, announced)
            }
            C66Role::Sink {
                announced,
                rotated,
                handoff,
            } => self.poll_sink(space, announced, rotated, handoff),
            C66Role::Candidate { waiting, stage } => {
                self.poll_candidate(space, context, waiting, stage)
            }
            C66Role::Transitioning | C66Role::Completed => C66PayloadOutcome::InvariantFailure,
        };
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        if !self.c77_runtime_shape_is_valid() || !self.c77_pending_role_matches() {
            c66_publish_failure(self.generation);
            return Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION);
        }
        match outcome {
            C66PayloadOutcome::Pending => Poll::Pending,
            C66PayloadOutcome::Complete => Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION),
            C66PayloadOutcome::InvariantFailure => {
                c66_publish_failure(self.generation);
                Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION)
            }
        }
    }
}

struct C66Task {
    token: InstanceToken,
    generation: u64,
}

impl Future for C66Task {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            c66_publish_failure(self.generation);
            let _ = super::super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        };
        if witness.instance_token() != Some(self.token) {
            c66_publish_failure(self.generation);
            let _ = super::super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        }
        match unsafe {
            super::super::component_instances::registry().poll_payload(witness, context)
        } {
            Ok(Poll::Ready(_)) => Poll::Ready(()),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                c66_publish_failure(self.generation);
                let _ = super::super::component_instances::registry().quarantine(self.token);
                Poll::Ready(())
            }
        }
    }
}

const _: () = assert!(core::mem::size_of::<C66Task>() <= 32);

#[derive(Clone, Copy)]
struct C66TerminalReceipt {
    revoked_capabilities: usize,
    guest_calls: u64,
}

struct C66ReplacementReceipt {
    reports: Vec<ComponentGraphNodeTerminalReport>,
    terminal: [C66TerminalReceipt; C66_INCARNATION_COUNT],
    candidate_staged: bool,
    candidate_hidden_before_policy_cancel: bool,
    old_terminal_before_new_ready: bool,
    fresh_generation: bool,
    fresh_cspace: bool,
    fresh_task: bool,
    fresh_arena: bool,
    fresh_resources: bool,
    siblings_stable: usize,
    no_active_poll: bool,
    policy_cancelled: bool,
    old_routes_retired: u64,
    fresh_routes: u64,
    stale_replacement_tokens: u64,
    late_wake_stale: u64,
    graph_version_published: bool,
}

struct C66Completion {
    result: SpinLock<Option<Result<C66ReplacementReceipt, ComponentGraphPrincipalLifecycleError>>>,
}

impl C66Completion {
    const fn new() -> Self {
        Self {
            result: SpinLock::new(None),
        }
    }

    fn publish(
        &self,
        result: Result<C66ReplacementReceipt, ComponentGraphPrincipalLifecycleError>,
    ) {
        let mut slot = self.result.lock();
        assert!(slot.is_none(), "C6.6 replacement result published twice");
        *slot = Some(result);
    }

    fn take(&self) -> Option<Result<C66ReplacementReceipt, ComponentGraphPrincipalLifecycleError>> {
        self.result.lock().take()
    }
}

struct C66Run {
    supervisor: TaskHandle,
    completion: Arc<C66Completion>,
}

/// Held across the exact old-target cancellation sequence and consumed only
/// after terminal finalization. Construction is private to an exact validated
/// replacement relation; this is neither a Task cancellation token nor a
/// graph/runtime identifier.
enum C66PolicyCancelPermit {
    #[cfg(feature = "wasm-c66-node-replacement-acceptance")]
    C66 {
        generation: u64,
        target: ComponentGraphNodeId,
    },
    #[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
    C76(C76PolicyCancelPermit),
}

/// Move-only proof that the loader permit was consumed after the exact old
/// target reached terminal state. Candidate visibility consumes this marker.
struct C66ConsumedPolicyCancel;

impl C66PolicyCancelPermit {
    fn consume_after_terminal(
        self,
        generation: u64,
        target: ComponentGraphNodeId,
    ) -> Result<C66ConsumedPolicyCancel, ComponentGraphPrincipalLifecycleError> {
        #[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
        let _ = (generation, target);
        match self {
            #[cfg(feature = "wasm-c66-node-replacement-acceptance")]
            Self::C66 {
                generation: authorized_generation,
                target: authorized_target,
            } if authorized_generation == generation && authorized_target == target => {
                Ok(C66ConsumedPolicyCancel)
            }
            #[cfg(feature = "wasm-c66-node-replacement-acceptance")]
            Self::C66 { .. } => Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy),
            #[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
            Self::C76(permit) => {
                permit.consume();
                Ok(C66ConsumedPolicyCancel)
            }
        }
    }
}

#[derive(Clone, Copy)]
struct C66CurrentSeal {
    artifacts: [[u8; 32]; C66_NODE_COUNT],
    worlds: [[u8; 32]; C66_NODE_COUNT],
    account: [u64; 13],
}

/// Move-only result of Stage A. At this boundary the current graph and its
/// dormant SYSTEM supervisor are published, while no candidate domain,
/// registry slot, task, resource table, or fresh route has been allocated.
#[must_use = "hold the current graph lifetime or consume it through an exact replacement gate"]
struct C66StagedCurrent {
    current: C66CurrentSeal,
    generation: u64,
    supervisor: TaskHandle,
    completion: Arc<C66Completion>,
    activation: C66SupervisorActivationPublisher,
    old_tokens: [InstanceToken; C66_NODE_COUNT],
    old_handles: [TaskHandle; C66_NODE_COUNT],
    sibling_domains: [AllocationDomain; 2],
    source_probe: AcceptanceInstanceProbe,
    old_target_probe: AcceptanceInstanceProbe,
    sink_probe: AcceptanceInstanceProbe,
    old_streams: [Arc<ByteStream>; 2],
    old_supervisors: [Arc<ByteStreamSupervisor>; 2],
    old_target_reader_token: ResourceToken,
    old_target_writer_token: ResourceToken,
    old_target_resource_generation: u64,
    fresh_source_publisher: C66FreshEndpointPublisher<Arc<ByteStreamWriter>>,
    fresh_sink_publisher: C66FreshEndpointPublisher<Arc<ByteStreamReader>>,
    fresh_source_handoff_audit: C66FreshEndpointAudit<Arc<ByteStreamWriter>>,
    fresh_sink_handoff_audit: C66FreshEndpointAudit<Arc<ByteStreamReader>>,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    c77_resource_generations_distinct: bool,
}

impl C66Run {
    async fn wait(self) -> Result<C66ReplacementReceipt, ComponentGraphPrincipalLifecycleError> {
        if !crate::exec::try_reserve_current_task_registrations(1) {
            return Err(ComponentGraphPrincipalLifecycleError::SupervisorUnavailable);
        }
        let exit = self.supervisor.join().await;
        if exit.state() != TaskState::Exited {
            return Err(ComponentGraphPrincipalLifecycleError::SupervisorUnavailable);
        }
        self.completion.take().unwrap_or(Err(
            ComponentGraphPrincipalLifecycleError::SupervisorUnavailable,
        ))
    }
}

struct C66Supervisor {
    generation: u64,
    candidate_batch: PreparedTaskBatch,
    candidate_token: InstanceToken,
    candidate_handle: TaskHandle,
    old_tokens: [InstanceToken; C66_NODE_COUNT],
    old_handles: [TaskHandle; C66_NODE_COUNT],
    sibling_domains: [AllocationDomain; 2],
    source_probe: AcceptanceInstanceProbe,
    old_target_probe: AcceptanceInstanceProbe,
    sink_probe: AcceptanceInstanceProbe,
    candidate_probe: AcceptanceInstanceProbe,
    streams: [Arc<ByteStream>; 4],
    supervisors: [Arc<ByteStreamSupervisor>; 4],
    fresh_source_writer: Arc<ByteStreamWriter>,
    fresh_sink_reader: Arc<ByteStreamReader>,
    fresh_source_publisher: C66FreshEndpointPublisher<Arc<ByteStreamWriter>>,
    fresh_sink_publisher: C66FreshEndpointPublisher<Arc<ByteStreamReader>>,
    fresh_source_handoff_audit: C66FreshEndpointAudit<Arc<ByteStreamWriter>>,
    fresh_sink_handoff_audit: C66FreshEndpointAudit<Arc<ByteStreamReader>>,
    reports: Vec<ComponentGraphNodeTerminalReport>,
    completion: Arc<C66Completion>,
    policy_cancel: C66PolicyCancelPermit,
    fresh_generation: bool,
    fresh_cspace: bool,
    fresh_task: bool,
    fresh_arena: bool,
    fresh_resources: bool,
}

async fn c66_wait_stage<const N: usize>(
    queue: &'static OneShotWaitQueue,
    generation: u64,
    handles: [&TaskHandle; N],
) -> bool {
    let mut expected = queue.wait(generation);
    let mut failure = C66_FAILURE.wait(generation);
    let mut joins: [_; N] = core::array::from_fn(|index| handles[index].join());
    core::future::poll_fn(|context| {
        if C66_AUDIT.failed.load(Ordering::Acquire) {
            return Poll::Ready(false);
        }
        if Pin::new(&mut failure).poll(context).is_ready() {
            return Poll::Ready(false);
        }
        for join in &mut joins {
            if Pin::new(join).poll(context).is_ready() {
                return Poll::Ready(false);
            }
        }
        match Pin::new(&mut expected).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(true),
            Poll::Ready(Err(_)) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn c66_join_or_failure(handle: &TaskHandle, generation: u64) -> Option<TaskState> {
    let mut join = handle.join();
    let mut failure = C66_FAILURE.wait(generation);
    core::future::poll_fn(|context| {
        if C66_AUDIT.failed.load(Ordering::Acquire)
            || Pin::new(&mut failure).poll(context).is_ready()
        {
            return Poll::Ready(None);
        }
        match Pin::new(&mut join).poll(context) {
            Poll::Ready(exit) => Poll::Ready(Some(exit.state())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

fn c66_finalize(
    token: InstanceToken,
    handle: &TaskHandle,
    expected_revoked_capabilities: usize,
) -> Result<C66TerminalReceipt, ComponentGraphPrincipalLifecycleError> {
    if handle.state() != TaskState::Exited {
        return Err(ComponentGraphPrincipalLifecycleError::TaskTerminal {
            node: ComponentGraphNodeId::new(C66_TARGET_INDEX as u16),
        });
    }
    let outcome = unsafe {
        super::super::component_instances::registry().finalize_with_space_expect_completion(
            token,
            handle,
            Some(RUNTIME_UNAVAILABLE_COMPLETION),
            |_space, _kind| true,
            retire_domain,
        )
    }
    .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant)?;
    let guest_calls = outcome
        .detached_completion
        .and_then(completion_guest_calls)
        .ok_or(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant)?;
    if outcome.revoked_capabilities != expected_revoked_capabilities || guest_calls != 0 {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
    }
    Ok(C66TerminalReceipt {
        revoked_capabilities: outcome.revoked_capabilities,
        guest_calls,
    })
}

fn c66_probe_sibling_stable(
    before: AcceptanceInstanceProbe,
    after: AcceptanceInstanceProbe,
) -> bool {
    before.is_exact()
        && after.is_exact()
        && before.same_space_object(after)
        && before.same_cspace_lock(after)
        && before.same_cspace_identity(after)
        && before.same_cspace_incarnation(after)
        && before.capability_table_len() == after.capability_table_len()
        && before.seal_matches_space()
        && after.seal_matches_space()
        && before.seal_matches_cspace()
        && after.seal_matches_cspace()
        && before.installed_capability_count() == 1
        && after.installed_capability_count() == 1
}

impl C66Supervisor {
    async fn run(self) {
        let C66Supervisor {
            generation,
            mut candidate_batch,
            candidate_token,
            candidate_handle,
            old_tokens,
            old_handles,
            sibling_domains,
            source_probe,
            old_target_probe: _,
            sink_probe,
            candidate_probe: _,
            streams,
            supervisors,
            fresh_source_writer,
            fresh_sink_reader,
            fresh_source_publisher,
            fresh_sink_publisher,
            fresh_source_handoff_audit,
            fresh_sink_handoff_audit,
            reports,
            completion,
            policy_cancel,
            fresh_generation,
            fresh_cspace,
            fresh_task,
            fresh_arena,
            fresh_resources,
        } = self;

        let all_tokens = [old_tokens[0], old_tokens[1], old_tokens[2], candidate_token];
        // Candidate activation is a one-way scheduler/registry boundary. Any
        // mismatch after this point is a kernel invariant failure, never a
        // recoverable component error: returning would drop a staged batch and
        // deliberately retain hidden lifecycle state. Quarantine the exact
        // four incarnations and fail-stop the machine instead.
        let fail = |_error| -> ! {
            c66_publish_failure(generation);
            lifecycle_invariant_failed(&all_tokens, "C6.6 replacement transaction failed")
        };

        let stage = match unsafe {
            candidate_batch.stage_exclusive_reclaimable_with(|bindings| {
                super::super::component_instances::registry().activate_batch(bindings)
            })
        } {
            Ok(stage) => stage,
            Err(_) => {
                fail(ComponentGraphPrincipalLifecycleError::AtomicPublication);
            }
        };
        if candidate_handle.is_published() || !C66_AUDIT.matches(generation) {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let candidate_hidden_before_policy_cancel = !candidate_handle.is_published();

        if !c66_wait_stage(
            &C66_OLD_READY,
            generation,
            [&old_handles[0], &old_handles[1], &old_handles[2]],
        )
        .await
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let mut no_active_poll = false;
        for _ in 0..64 {
            if old_handles
                .iter()
                .all(TaskHandle::acceptance_is_parked_exact)
            {
                no_active_poll = true;
                break;
            }
            crate::exec::yield_now().await;
        }
        if !no_active_poll
            || candidate_handle.is_published()
            || !c66_transition(generation, C66_PHASE_OLD, C66_PHASE_DISCONNECTED)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }

        // Possession of the deferred loader permit authorizes this exact
        // PolicyCancel sequence. It is deliberately not consumed until the
        // old target has reached and finalized its terminal state.
        for supervisor in &supervisors[..2] {
            if supervisor.finalize(StreamCloseReason::Cancelled) != StreamCloseOutcome::Published
                || !c66_increment(&C66_AUDIT.old_routes_retired, generation)
            {
                fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
            }
        }
        let old_target_exit = old_handles[C66_TARGET_INDEX].join().await;
        if old_target_exit.state() != TaskState::Exited
            || C66_OLD_OPERATION.load().is_some()
            || !C66_OLD_WAKE_SIGNAL.is_empty()
            || supervisors[..2].iter().any(|supervisor| {
                supervisor.revoke_pending_after_final().map(|r| r.total()) != Ok(0)
            })
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let old_target_terminal = match c66_finalize(
            old_tokens[C66_TARGET_INDEX],
            &old_handles[C66_TARGET_INDEX],
            2,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                fail(error);
            }
        };
        let policy_cancelled = match policy_cancel.consume_after_terminal(
            generation,
            ComponentGraphNodeId::new(C66_TARGET_INDEX as u16),
        ) {
            Ok(consumed) => consumed,
            Err(error) => {
                fail(error);
            }
        };
        let old_terminal_before_new_ready = !candidate_handle.is_published();

        if !old_terminal_before_new_ready
            || fresh_source_publisher
                .publish(
                    generation,
                    old_tokens[0],
                    &old_handles[0],
                    fresh_source_writer,
                )
                .is_err()
            || fresh_sink_publisher
                .publish(
                    generation,
                    old_tokens[2],
                    &old_handles[2],
                    fresh_sink_reader,
                )
                .is_err()
            || !c66_transition(generation, C66_PHASE_DISCONNECTED, C66_PHASE_ROTATE)
            || !old_handles[0].exact_wake().wake_if_exact()
            || !old_handles[2].exact_wake().wake_if_exact()
            || !c66_wait_stage(
                &C66_SIBLINGS_ROTATED,
                generation,
                [&old_handles[0], &old_handles[2]],
            )
            .await
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let Some(source_after) =
            super::super::component_instances::registry().acceptance_probe(old_tokens[0])
        else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let Some(sink_after) =
            super::super::component_instances::registry().acceptance_probe(old_tokens[2])
        else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let sibling_tasks_and_arenas_stable = old_handles[0].is_published()
            && old_handles[2].is_published()
            && old_handles[0].state() == TaskState::Running
            && old_handles[2].state() == TaskState::Running
            && old_handles[0].allocation_domain() == sibling_domains[0]
            && old_handles[2].allocation_domain() == sibling_domains[1];
        let siblings_stable = if sibling_tasks_and_arenas_stable {
            c66_probe_sibling_stable(source_probe, source_after) as usize
                + c66_probe_sibling_stable(sink_probe, sink_after) as usize
        } else {
            0
        };
        if siblings_stable != 2
            || C66_AUDIT.fresh_routes.load(Ordering::Acquire) != 2
            || C66_AUDIT.stale_sibling_routes.load(Ordering::Acquire) != 2
            || C66_AUDIT
                .stable_sibling_resource_tables
                .load(Ordering::Acquire)
                != 2
            || !fresh_source_handoff_audit.is_consumed_exact(
                generation,
                old_tokens[0],
                &old_handles[0],
            )
            || !fresh_sink_handoff_audit.is_consumed_exact(
                generation,
                old_tokens[2],
                &old_handles[2],
            )
            || !c66_transition(generation, C66_PHASE_ROTATE, C66_PHASE_COMMITTED)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }

        let committed = c66_phase_word(generation, C66_PHASE_COMMITTED)
            .expect("validated C6.6 generation has a committed word");
        // Type-level order: the only marker able to cross this visibility
        // boundary is minted by post-terminal permit consumption above.
        let C66ConsumedPolicyCancel = policy_cancelled;
        let mut candidate_handles =
            match unsafe { stage.publish_ready_if(&C66_GRAPH_CONTROL, committed) } {
                Ok(handles) => handles,
                Err(_) => {
                    fail(ComponentGraphPrincipalLifecycleError::AtomicPublication);
                }
            };
        if candidate_handles.len() != 1
            || !candidate_handles[0].is_published()
            || candidate_handles[0].id() != candidate_handle.id()
            || candidate_handles[0].allocation_domain() != candidate_handle.allocation_domain()
            || !candidate_handles[0].shares_status_with(&candidate_handle)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let published_candidate = candidate_handles
            .pop()
            .expect("validated replacement publication has one candidate");
        if !c66_wait_stage(&C66_CANDIDATE_WAITING, generation, [&published_candidate]).await {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }

        let candidate_polls = published_candidate.polls();
        let Some(old_words) = C66_OLD_WAKE_WORDS.lock().take() else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let Some(old_operation) = C66_OLD_OPERATION_REPLAY.lock().take() else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        if super::super::component_instances::registry().signal_continuation_words(old_words)
            != InstanceContinuationSignal::Stale
            || supervisors[2]
                .cancel_reader_operation_exact(old_operation)
                .is_ok()
            || !c66_increment(&C66_AUDIT.late_wake_stale, generation)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        for _ in 0..4 {
            crate::exec::yield_now().await;
        }
        if published_candidate.polls() != candidate_polls
            || !c66_transition(generation, C66_PHASE_COMMITTED, C66_PHASE_SEND)
            || !old_handles[0].exact_wake().wake_if_exact()
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let source_state = c66_join_or_failure(&old_handles[0], generation).await;
        let candidate_state = c66_join_or_failure(&published_candidate, generation).await;
        if source_state != Some(TaskState::Exited)
            || candidate_state != Some(TaskState::Exited)
            || C66_CANDIDATE_OPERATION.load().is_some()
            || !C66_CANDIDATE_WAKE_SIGNAL.is_empty()
            || !c66_transition(generation, C66_PHASE_SEND, C66_PHASE_RECEIVE)
            || !old_handles[2].exact_wake().wake_if_exact()
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let sink_state = c66_join_or_failure(&old_handles[2], generation).await;
        if sink_state != Some(TaskState::Exited)
            || C66_AUDIT.fresh_completed_mask.load(Ordering::Acquire) != C66_ALL_NODE_BITS
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let Some(source_terminal_probe) =
            super::super::component_instances::registry().acceptance_probe(old_tokens[0])
        else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let Some(sink_terminal_probe) =
            super::super::component_instances::registry().acceptance_probe(old_tokens[2])
        else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        if !c66_probe_sibling_stable(source_probe, source_terminal_probe)
            || !c66_probe_sibling_stable(sink_probe, sink_terminal_probe)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let registrations_empty = [
            &old_handles[0],
            &old_handles[1],
            &old_handles[2],
            &published_candidate,
        ]
        .iter()
        .all(|handle| {
            handle.acceptance_registration_stats().total == 0 && handle.joiner_count() == 0
        });
        let waiters_empty = [
            &C66_OLD_READY,
            &C66_SIBLINGS_ROTATED,
            &C66_CANDIDATE_WAITING,
            &C66_CANDIDATE_DONE,
            &C66_FRESH_DONE,
            &C66_FAILURE,
        ]
        .iter()
        .all(|queue| queue.waiter_count() == 0);
        if !registrations_empty
            || !waiters_empty
            || !fresh_source_handoff_audit.is_consumed_exact(
                generation,
                old_tokens[0],
                &old_handles[0],
            )
            || !fresh_sink_handoff_audit.is_consumed_exact(
                generation,
                old_tokens[2],
                &old_handles[2],
            )
            || C66_OLD_OPERATION.load().is_some()
            || C66_CANDIDATE_OPERATION.load().is_some()
            || !C66_OLD_WAKE_SIGNAL.is_empty()
            || !C66_CANDIDATE_WAKE_SIGNAL.is_empty()
            || C66_OLD_WAKE_WORDS.lock().is_some()
            || C66_CANDIDATE_WAKE_WORDS.lock().is_some()
            || C66_OLD_OPERATION_REPLAY.lock().is_some()
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }

        let sink_terminal = match c66_finalize(old_tokens[2], &old_handles[2], 1) {
            Ok(receipt) => receipt,
            Err(error) => {
                fail(error);
            }
        };
        let candidate_terminal = match c66_finalize(candidate_token, &published_candidate, 2) {
            Ok(receipt) => receipt,
            Err(error) => {
                fail(error);
            }
        };
        let source_terminal = match c66_finalize(old_tokens[0], &old_handles[0], 1) {
            Ok(receipt) => receipt,
            Err(error) => {
                fail(error);
            }
        };
        for supervisor in &supervisors[2..] {
            if supervisor.finalize(StreamCloseReason::Normal) != StreamCloseOutcome::Published
                || supervisor.revoke_pending_after_final().map(|r| r.total()) != Ok(0)
                || supervisor.depth() != 0
            {
                fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
            }
        }
        if streams.iter().any(|stream| stream.depth() != 0)
            || !c66_transition(generation, C66_PHASE_RECEIVE, C66_PHASE_DONE)
        {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }

        let terminal = [
            source_terminal,
            old_target_terminal,
            candidate_terminal,
            sink_terminal,
        ];
        let audit_ok = C66_AUDIT.old_routes_retired.load(Ordering::Acquire) == 2
            && C66_AUDIT.fresh_routes.load(Ordering::Acquire) == 2
            && C66_AUDIT.stale_sibling_routes.load(Ordering::Acquire) == 2
            && C66_AUDIT
                .stable_sibling_resource_tables
                .load(Ordering::Acquire)
                == 2
            && C66_AUDIT.stale_replacement_tokens.load(Ordering::Acquire) == 2
            && C66_AUDIT.late_wake_stale.load(Ordering::Acquire) == 1
            && C66_AUDIT.fresh_edge_deliveries.load(Ordering::Acquire) == 2
            && C66_AUDIT.sink_deliveries.load(Ordering::Acquire) == 1
            && C66_AUDIT.wake_registrations.load(Ordering::Acquire) == 2
            && C66_AUDIT.wake_callbacks.load(Ordering::Acquire) == 2
            && C66_AUDIT.continuation_resumes.load(Ordering::Acquire) == 2
            && C66_AUDIT.sealed_resumes.load(Ordering::Acquire) == 2
            && C66_AUDIT.fresh_completed_mask.load(Ordering::Acquire) == C66_ALL_NODE_BITS
            && !C66_AUDIT.failed.load(Ordering::Acquire)
            && terminal.iter().all(|receipt| {
                receipt.guest_calls == 0 && matches!(receipt.revoked_capabilities, 1 | 2)
            })
            && reports.len() == C66_INCARNATION_COUNT
            && reports.iter().all(|report| {
                report.terminal() == ComponentGraphNodeTerminal::RuntimeUnavailable
                    && report.fuel().consumed() == 0
                    && report.resources().live_slots() == 0
            });
        if !audit_ok {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        completion.publish(Ok(C66ReplacementReceipt {
            reports,
            terminal,
            candidate_staged: true,
            candidate_hidden_before_policy_cancel,
            old_terminal_before_new_ready,
            fresh_generation,
            fresh_cspace,
            fresh_task,
            fresh_arena,
            fresh_resources,
            siblings_stable,
            no_active_poll,
            policy_cancelled: true,
            old_routes_retired: C66_AUDIT.old_routes_retired.load(Ordering::Acquire),
            fresh_routes: C66_AUDIT.fresh_routes.load(Ordering::Acquire),
            stale_replacement_tokens: C66_AUDIT.stale_replacement_tokens.load(Ordering::Acquire),
            late_wake_stale: C66_AUDIT.late_wake_stale.load(Ordering::Acquire),
            // The lifecycle publishes only its boot-local candidate task.
            // Durable G1 graph-version visibility belongs to the boot
            // orchestrator after this receipt is consumed.
            graph_version_published: false,
        }));
    }
}

fn c66_edge(source: u16, target: u16) -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(source),
            ComponentGraphEntityIndex::new(0),
        ),
        ComponentGraphImportEndpoint::new(
            ComponentGraphNodeId::new(target),
            ComponentGraphEntityIndex::new(0),
        ),
    )
}

#[cfg(all(
    feature = "wasm-c66-node-replacement-acceptance",
    not(feature = "wasm-c76-graph-version-replacement-acceptance")
))]
fn c66_expected_worlds_and_limits() -> ([&'static str; C66_NODE_COUNT], InstanceLimits) {
    let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
    let limits = pin.limits();
    (
        [pin.source_world(), pin.relay_world(), pin.sink_world()],
        InstanceLimits {
            memory_bytes: limits.memory_bytes,
            total_fuel: limits.total_fuel,
            poll_quantum: limits.poll_quantum,
            resources: limits.resources,
        },
    )
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
fn c66_expected_worlds_and_limits() -> ([&'static str; C66_NODE_COUNT], InstanceLimits) {
    let pin = C76_GRAPH_OPERATOR_POLICY_QEMU_ACCEPTANCE;
    (pin.node_worlds(), pin.node_limits())
}

#[cfg(all(
    feature = "wasm-c66-node-replacement-acceptance",
    not(feature = "wasm-c76-graph-version-replacement-acceptance")
))]
fn c66_current_artifacts_are_known(artifacts: [[u8; 32]; C66_NODE_COUNT]) -> bool {
    let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
    artifacts
        == [
            pin.source_sha256(),
            pin.old_relay_sha256(),
            pin.sink_sha256(),
        ]
        || artifacts
            == [
                pin.source_sha256(),
                pin.new_relay_sha256(),
                pin.sink_sha256(),
            ]
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
fn c66_current_artifacts_are_known(_artifacts: [[u8; 32]; C66_NODE_COUNT]) -> bool {
    // The only C7.6 caller holds the loader's move-only proof minted by full
    // physical readback plus current signer/policy/engine graph admission.
    true
}

#[cfg(all(
    feature = "wasm-c66-node-replacement-acceptance",
    not(feature = "wasm-c76-graph-version-replacement-acceptance")
))]
fn c66_candidate_artifacts(
    _candidate: &ComponentGraphPrincipalTemplate,
) -> Result<[[u8; 32]; C66_NODE_COUNT], ComponentGraphPrincipalLifecycleError> {
    let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
    Ok([
        pin.source_sha256(),
        pin.new_relay_sha256(),
        pin.sink_sha256(),
    ])
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
fn c66_candidate_artifacts(
    candidate: &ComponentGraphPrincipalTemplate,
) -> Result<[[u8; 32]; C66_NODE_COUNT], ComponentGraphPrincipalLifecycleError> {
    if candidate.principals().len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    Ok(core::array::from_fn(|index| {
        *candidate.principals()[index].artifact().as_bytes()
    }))
}

#[cfg(all(
    feature = "wasm-c66-node-replacement-acceptance",
    not(feature = "wasm-c76-graph-version-replacement-acceptance")
))]
fn c66_current_is_replaceable(current: [[u8; 32]; C66_NODE_COUNT]) -> bool {
    let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
    current
        == [
            pin.source_sha256(),
            pin.old_relay_sha256(),
            pin.sink_sha256(),
        ]
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
fn c66_current_is_replaceable(_current: [[u8; 32]; C66_NODE_COUNT]) -> bool {
    // G0 -> G1 linkage is already sealed into C76SupervisorGraphReplacement.
    true
}

fn exact_c66_graph(
    graph: &ComponentGraphPrincipalTemplate,
    artifacts: [[u8; 32]; C66_NODE_COUNT],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let edges = [c66_edge(0, 1), c66_edge(1, 2)];
    let published = [ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(2),
            ComponentGraphEntityIndex::new(0),
        ),
    )];
    let (worlds, expected_limits) = c66_expected_worlds_and_limits();
    if graph.revalidate().is_err()
        || graph.runtime_ready()
        || graph.profile() != ProfileIdentity::PROFILE_1_ASYNC
        || graph.profile().execution_enabled()
        || graph.principals().len() != C66_NODE_COUNT
        || graph.manifest().cycle_policy() != ComponentGraphCyclePolicy::AcyclicOnly
        || graph.manifest().edges() != edges
        || graph.manifest().external_imports().len() != 0
        || graph.manifest().published_exports() != published
        || !graph.resource_edges().is_empty()
        || !graph.grants().is_empty()
        || graph.async_edges().len() != 2
        || graph
            .async_edges()
            .iter()
            .zip(edges)
            .any(|(edge, expected)| {
                edge.edge() != expected
                    || edge.async_functions() != 1
                    || edge.streams() != 4
                    || edge.futures() != 4
            })
        || graph
            .principals()
            .iter()
            .zip(artifacts.into_iter().zip(worlds))
            .enumerate()
            .any(|(index, (principal, (artifact, world)))| {
                principal.id() != ComponentGraphNodeId::new(index as u16)
                    || principal.artifact().as_bytes() != &artifact
                    || principal.profile() != ProfileIdentity::PROFILE_1_ASYNC
                    || principal.world() != world
                    || principal.nesting() != ComponentGraphNesting::Root
                    || principal.limits() != expected_limits
            })
    {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    Ok(())
}

fn exact_c66_stage_graph(
    current: &ComponentGraphPrincipalTemplate,
) -> Result<C66CurrentSeal, ComponentGraphPrincipalLifecycleError> {
    if current.principals().len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    let artifacts =
        core::array::from_fn(|index| *current.principals()[index].artifact().as_bytes());
    if !c66_current_artifacts_are_known(artifacts) {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    exact_c66_graph(current, artifacts)?;
    let nodes = current.manifest().nodes();
    let account = current.account();
    Ok(C66CurrentSeal {
        artifacts,
        worlds: core::array::from_fn(|index| nodes[index].world_contract_commitment()),
        account: [
            account.nodes,
            account.edges,
            account.maximum_nesting,
            account.external_imports,
            account.published_exports,
            account.component_bytes,
            account.core_instances,
            account.adapters,
            account.resource_types,
            account.resource_slots,
            account.memory_bytes,
            account.total_fuel,
            account.maximum_poll_quantum,
        ],
    })
}

fn exact_c66_replacement(
    current: &ComponentGraphPrincipalTemplate,
    candidate: &ComponentGraphPrincipalTemplate,
    node_action: ComponentGraphReplacementNodeAction,
    max_replacements: u16,
    incident_edges: &[ComponentGraphReplacementEdgePolicy],
    staged: C66CurrentSeal,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let current_seal = exact_c66_stage_graph(current)?;
    let candidate_artifacts = c66_candidate_artifacts(candidate)?;
    exact_c66_graph(candidate, candidate_artifacts)?;
    let expected_edges = [c66_edge(0, 1), c66_edge(1, 2)];
    if !c66_current_is_replaceable(current_seal.artifacts)
        || current_seal.artifacts != staged.artifacts
        || current_seal.worlds != staged.worlds
        || current_seal.account != staged.account
        || node_action != ComponentGraphReplacementNodeAction::PolicyCancel
        || max_replacements != 1
        || incident_edges.len() != 2
        || incident_edges
            .iter()
            .zip(expected_edges)
            .any(|(policy, edge)| {
                policy.edge != edge
                    || policy.action != ComponentGraphReplacementEdgeAction::RecreateFresh
            })
        || current.principals()[0].artifact() != candidate.principals()[0].artifact()
        || current.principals()[2].artifact() != candidate.principals()[2].artifact()
        || current.principals()[C66_TARGET_INDEX].artifact()
            == candidate.principals()[C66_TARGET_INDEX].artifact()
    {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    Ok(())
}

#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
fn exact_c66_template(
    template: &ComponentGraphNodeReplacementTemplate,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
    let current = template.current_graph();
    let candidate = template.candidate_graph();
    let expected_edges = [c66_edge(0, 1), c66_edge(1, 2)];
    if template.revalidate().is_err()
        || template.runtime_ready()
        || template.target() != ComponentGraphNodeId::new(C66_TARGET_INDEX as u16)
        || template.max_replacements() != 1
        || template.node_action() != ComponentGraphReplacementNodeAction::PolicyCancel
        || template.incident_edges().len() != 2
        || template
            .incident_edges()
            .iter()
            .zip(expected_edges)
            .any(|(policy, edge)| {
                policy.edge != edge
                    || policy.action != ComponentGraphReplacementEdgeAction::RecreateFresh
            })
        || current.runtime_ready()
        || candidate.runtime_ready()
        || current.profile() != ProfileIdentity::PROFILE_1_ASYNC
        || candidate.profile() != ProfileIdentity::PROFILE_1_ASYNC
        || current.profile().execution_enabled()
        || candidate.profile().execution_enabled()
        || current.principals().len() != C66_NODE_COUNT
        || candidate.principals().len() != C66_NODE_COUNT
        || current.manifest().edges() != expected_edges
        || candidate.manifest().edges() != expected_edges
        || !current.resource_edges().is_empty()
        || !candidate.resource_edges().is_empty()
        || !current.grants().is_empty()
        || !candidate.grants().is_empty()
        || current.async_edges().len() != 2
        || candidate.async_edges().len() != 2
        || current
            .async_edges()
            .iter()
            .zip(expected_edges)
            .any(|(edge, expected)| {
                edge.edge() != expected
                    || edge.async_functions() != 1
                    || edge.streams() != 4
                    || edge.futures() != 4
            })
        || candidate
            .async_edges()
            .iter()
            .zip(expected_edges)
            .any(|(edge, expected)| {
                edge.edge() != expected
                    || edge.async_functions() != 1
                    || edge.streams() != 4
                    || edge.futures() != 4
            })
        || current.principals()[C66_TARGET_INDEX].artifact()
            == candidate.principals()[C66_TARGET_INDEX].artifact()
        || current.principals()[0].artifact() != candidate.principals()[0].artifact()
        || current.principals()[2].artifact() != candidate.principals()[2].artifact()
        || pin.node_count() != C66_NODE_COUNT as u16
        || pin.replacement_node() != C66_TARGET_INDEX as u16
        || pin.max_replacements() != 1
        || pin
            .incident_edges()
            .iter()
            .zip(expected_edges)
            .any(|(policy, edge)| {
                policy.source_node() != edge.source().node().index()
                    || policy.source_export() != edge.source().export().index()
                    || policy.target_node() != edge.target().node().index()
                    || policy.target_import() != edge.target().import().index()
                    || policy.action() != ComponentGraphReplacementPinAction::RecreateFresh
            })
    {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    Ok(())
}

fn c66_semantic_reports_for(
    current: &ComponentGraphPrincipalTemplate,
    candidate: &ComponentGraphPrincipalTemplate,
) -> Result<Vec<ComponentGraphNodeTerminalReport>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let result = (|| {
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(C66_INCARNATION_COUNT)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::Allocation)?;
        reports.push(
            current
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(0), 1)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            current
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(1), 2)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            candidate
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(1), 2)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            current
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(2), 1)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        Ok(reports)
    })();
    system.restore();
    result
}

fn c66_preflight_reusable_slot<A>(table: &mut ResourceTable<A>) -> bool {
    match table.reserve() {
        Ok(reservation) => {
            drop(reservation);
            true
        }
        Err(_) => false,
    }
}

fn c66_prepare_writer(
    instance: InstanceToken,
    endpoint: Arc<ByteStreamWriter>,
) -> Result<ComponentAuthority, ComponentGraphPrincipalLifecycleError> {
    unsafe {
        super::super::component_instances::registry().configure_reserved_space(instance, |space| {
            let cap = space.mint(endpoint, Rights::SEND);
            ComponentAuthority::prepare_ephemeral_in::<ByteStreamWriter>(space, cap, Rights::SEND)
                .ok()
        })
    }
    .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?
    .map(|prepared| prepared.into_authority())
    .ok_or(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)
}

fn c66_prepare_reader(
    instance: InstanceToken,
    endpoint: Arc<ByteStreamReader>,
) -> Result<ComponentAuthority, ComponentGraphPrincipalLifecycleError> {
    unsafe {
        super::super::component_instances::registry().configure_reserved_space(instance, |space| {
            let cap = space.mint(endpoint, Rights::RECV);
            ComponentAuthority::prepare_ephemeral_in::<ByteStreamReader>(space, cap, Rights::RECV)
                .ok()
        })
    }
    .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?
    .map(|prepared| prepared.into_authority())
    .ok_or(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)
}

fn c66_prepare_relay(
    instance: InstanceToken,
    reader: Arc<ByteStreamReader>,
    writer: Arc<ByteStreamWriter>,
) -> Result<(ComponentAuthority, ComponentAuthority), ComponentGraphPrincipalLifecycleError> {
    unsafe {
        super::super::component_instances::registry().configure_reserved_space(instance, |space| {
            let reader_cap = space.mint(reader, Rights::RECV);
            let writer_cap = space.mint(writer, Rights::SEND);
            Some((
                ComponentAuthority::prepare_ephemeral_in::<ByteStreamReader>(
                    space,
                    reader_cap,
                    Rights::RECV,
                )
                .ok()?,
                ComponentAuthority::prepare_ephemeral_in::<ByteStreamWriter>(
                    space,
                    writer_cap,
                    Rights::SEND,
                )
                .ok()?,
            ))
        })
    }
    .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?
    .map(|(reader, writer)| (reader.into_authority(), writer.into_authority()))
    .ok_or(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)
}

#[derive(Clone, Copy)]
enum C66StageMode {
    Legacy,
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    C77Ephemeral,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_memory_allocation_charge() -> Option<usize> {
    let layout = Layout::array::<u8>(C77_MEMORY_BYTES_PER_NODE).ok()?;
    crate::heap::Heap::allocation_charge(layout)
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_adjust_owner_quotas(
    plans: &mut [super::PrincipalPlan],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let Some(memory_charge) = c77_memory_allocation_charge() else {
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    };
    for plan in plans {
        if plan.guest_memory_limit != C77_MEMORY_BYTES_PER_NODE {
            return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow { node: plan.node });
        }
        plan.owner_quota = memory_charge
            .checked_add(COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES)
            .ok_or(ComponentGraphPrincipalLifecycleError::BudgetOverflow { node: plan.node })?;
    }
    Ok(())
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_allocate_runtime_state(
    plan: super::PrincipalPlan,
    domain: AllocationDomain,
    node_bit: u8,
    expected_live_resources: usize,
) -> Result<C77EphemeralRuntimeState, ComponentGraphPrincipalLifecycleError> {
    let mut allocation = unsafe { crate::heap::enter_domain(domain) };
    let memory = VecMemory::new(plan.guest_memory_limit, plan.guest_memory_limit);
    allocation.restore();
    let memory = memory.map_err(|_| ComponentGraphPrincipalLifecycleError::Allocation)?;
    Ok(C77EphemeralRuntimeState::new(
        memory,
        plan.fuel_limit,
        plan.poll_quantum,
        node_bit,
        plan.resource_generation,
        expected_live_resources,
    ))
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_prepare_runtime_states(
    plans: &[super::PrincipalPlan],
    domains: &[AllocationDomain],
) -> Result<[Option<C77EphemeralRuntimeState>; C66_NODE_COUNT], ComponentGraphPrincipalLifecycleError>
{
    if plans.len() != C66_NODE_COUNT || domains.len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }
    let source = c77_allocate_runtime_state(plans[0], domains[0], C66_SOURCE_BIT, 1)?;
    let target = c77_allocate_runtime_state(plans[1], domains[1], C66_TARGET_BIT, 2)?;
    let sink = c77_allocate_runtime_state(plans[2], domains[2], C66_SINK_BIT, 1)?;
    let memory_charge =
        c77_memory_allocation_charge().ok_or(ComponentGraphPrincipalLifecycleError::Allocation)?;
    for domain in domains {
        let Some(arena) = crate::HEAP.arena_stats(domain.arena) else {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        };
        let Some(owner) = crate::HEAP.account_stats(domain.owner) else {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        };
        if arena.owner != domain.owner
            || arena.live_bytes != memory_charge
            || arena.live_allocations != 1
            || owner.quota_bytes
                != memory_charge + COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES
            || owner.live_bytes != memory_charge
            || owner.live_allocations != 1
        {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        }
    }
    Ok([Some(source), Some(target), Some(sink)])
}

fn stage_c66_current_graph(
    current: &ComponentGraphPrincipalTemplate,
) -> Result<C66StagedCurrent, ComponentGraphPrincipalLifecycleError> {
    stage_c66_current_graph_with_mode(current, C66StageMode::Legacy)
}

fn stage_c66_current_graph_with_mode(
    current: &ComponentGraphPrincipalTemplate,
    mode: C66StageMode,
) -> Result<C66StagedCurrent, ComponentGraphPrincipalLifecycleError> {
    let current_seal = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let seal = exact_c66_stage_graph(current);
        system.restore();
        seal?
    };
    let mut current_plans = checked_plan(current)?;
    if current_plans.len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    if matches!(mode, C66StageMode::C77Ephemeral) {
        c77_adjust_owner_quotas(&mut current_plans)?;
    }
    #[cfg(not(feature = "wasm-c77-ephemeral-runtime-acceptance"))]
    let _ = mode;
    let resource_generation = reserve_resource_generations(C66_NODE_COUNT)?;
    for (index, plan) in current_plans.iter_mut().enumerate() {
        plan.resource_generation = resource_generation
            .checked_add(index as u64)
            .ok_or(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    }
    let domains = create_domains(&current_plans)?;
    if domains.len() != C66_NODE_COUNT {
        let _ = super::release_empty_domains(&domains);
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
    }
    let tokens = match reserve_registry_batch(&domains) {
        Ok(tokens) if tokens.len() == C66_NODE_COUNT => tokens,
        Ok(tokens) => {
            let _ = abort_pristine_registry_batch(&tokens, &domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
        Err(_) => {
            let _ = super::release_empty_domains(&domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
    };
    let old_pairs = match publication_pairs(&tokens, &domains) {
        Ok(pairs) => pairs,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let mut old_batch = PreparedTaskBatch::new();
    if old_batch
        .reserve_managed_publication(&old_pairs, 1)
        .and_then(|_| old_batch.reserve_managed_task_ledgers(1, 5, 1))
        .is_err()
    {
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::SchedulerReservation);
    }

    // Stage A allocates exactly the two current incident routes.
    let streams = [ByteStream::new(), ByteStream::new()];
    let supervisors = [streams[0].supervisor(), streams[1].supervisor()];
    let old_source_writer = streams[0].writer();
    let old_target_reader = streams[0].reader();
    let old_target_writer = streams[1].writer();
    let old_sink_reader = streams[1].reader();

    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let tables = (|| {
        let mut source = ResourceTable::new(
            current_plans[0].resource_generation,
            current_plans[0].resource_slots,
        )
        .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let old_target = ResourceTable::new(
            current_plans[1].resource_generation,
            current_plans[1].resource_slots,
        )
        .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let mut sink = ResourceTable::new(
            current_plans[2].resource_generation,
            current_plans[2].resource_slots,
        )
        .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        if !c66_preflight_reusable_slot(&mut source) || !c66_preflight_reusable_slot(&mut sink) {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        }
        Ok((source, old_target, sink))
    })();
    system.restore();
    let (mut source_table, mut old_target_table, mut sink_table) = match tables {
        Ok(tables) => tables,
        Err(error) => {
            drop(old_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let authorities = (|| {
        let source = c66_prepare_writer(tokens[0], old_source_writer)?;
        let old_target = c66_prepare_relay(tokens[1], old_target_reader, old_target_writer)?;
        let sink = c66_prepare_reader(tokens[2], old_sink_reader)?;
        Ok((source, old_target, sink))
    })();
    let (source_authority, old_target_authorities, sink_authority) = match authorities {
        Ok(authorities) => authorities,
        Err(error) => {
            drop(old_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let inserted = (|| {
        let source = source_table
            .insert_owned(C66_SOURCE_WRITER_TYPE, source_authority)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let old_target_reader = old_target_table
            .insert_owned(C66_RELAY_READER_TYPE, old_target_authorities.0)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let old_target_writer = old_target_table
            .insert_owned(C66_RELAY_WRITER_TYPE, old_target_authorities.1)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let sink = sink_table
            .insert_owned(C66_SINK_READER_TYPE, sink_authority)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        Ok((source, old_target_reader, old_target_writer, sink))
    })();
    system.restore();
    let (source_token, old_target_reader_token, old_target_writer_token, sink_token) =
        match inserted {
            Ok(tokens) => tokens,
            Err(error) => {
                drop(old_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(error);
            }
        };
    if source_table.len() != 1 || old_target_table.len() != 2 || sink_table.len() != 1 {
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }
    let probes = (
        super::super::component_instances::registry().acceptance_probe(tokens[0]),
        super::super::component_instances::registry().acceptance_probe(tokens[1]),
        super::super::component_instances::registry().acceptance_probe(tokens[2]),
    );
    let (Some(source_probe), Some(old_target_probe), Some(sink_probe)) = probes else {
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    };

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let mut c77_runtimes = if matches!(mode, C66StageMode::C77Ephemeral) {
        if ![source_probe, old_target_probe, sink_probe]
            .iter()
            .all(|probe| probe.continuation_is_idle() && probe.continuation_waiters() == 0)
        {
            drop(old_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        }
        match c77_prepare_runtime_states(&current_plans, &domains) {
            Ok(states) => states,
            Err(error) => {
                drop(old_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(error);
            }
        }
    } else {
        [const { None }; C66_NODE_COUNT]
    };

    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let c77_resource_generations_distinct = matches!(mode, C66StageMode::C77Ephemeral)
        && current_plans
            .iter()
            .all(|plan| plan.resource_generation != 0)
        && current_plans[0].resource_generation != current_plans[1].resource_generation
        && current_plans[0].resource_generation != current_plans[2].resource_generation
        && current_plans[1].resource_generation != current_plans[2].resource_generation;
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    if matches!(mode, C66StageMode::C77Ephemeral) && !c77_resource_generations_distinct {
        drop(c77_runtimes);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }

    let generation =
        match NEXT_C66_GENERATION.try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            c66_phase_word(next, C66_PHASE_OLD)?;
            next.checked_add(1)
        }) {
            Ok(generation) => generation,
            Err(_) => {
                #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
                drop(c77_runtimes);
                drop(old_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted);
            }
        };
    if !C66_AUDIT.reset(generation) {
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        drop(c77_runtimes);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }

    let registry = super::super::component_instances::registry();
    for index in 0..C66_NODE_COUNT {
        unsafe {
            old_batch.prepare_managed_instance_owned(
                tokens[index],
                domains[index],
                PRINCIPAL_TASK_NAME,
                C66Task {
                    token: tokens[index],
                    generation,
                },
            );
        }
    }
    let old_handles: [TaskHandle; C66_NODE_COUNT] = [
        old_batch.prepared_handles()[0].clone(),
        old_batch.prepared_handles()[1].clone(),
        old_batch.prepared_handles()[2].clone(),
    ];
    // These empty one-shot cells carry no endpoint. Only Stage B can create
    // and publish a fresh route into them.
    let (
        fresh_source_publisher,
        fresh_source_receiver,
        fresh_source_handoff_audit,
        fresh_sink_publisher,
        fresh_sink_receiver,
        fresh_sink_handoff_audit,
    ) = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let (source_publisher, source_receiver, source_audit) =
            c66_fresh_endpoint_handoff::<Arc<ByteStreamWriter>>(
                generation,
                tokens[0],
                &old_handles[0],
            );
        let (sink_publisher, sink_receiver, sink_audit) = c66_fresh_endpoint_handoff::<
            Arc<ByteStreamReader>,
        >(
            generation, tokens[2], &old_handles[2]
        );
        system.restore();
        (
            source_publisher,
            source_receiver,
            source_audit,
            sink_publisher,
            sink_receiver,
            sink_audit,
        )
    };
    let (activation, mut activation_receiver) = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let activation = c66_supervisor_activation(generation);
        system.restore();
        activation
    };
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let source_runtime = c77_runtimes[0].take();
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let target_runtime = c77_runtimes[1].take();
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let sink_runtime = c77_runtimes[2].take();
    if unsafe {
        registry.install_payload(tokens[0], || {
            let payload = C66Payload::new(
                generation,
                tokens[0],
                source_table,
                [
                    Some(C66Drain {
                        token: source_token,
                        resource_type: C66_SOURCE_WRITER_TYPE,
                    }),
                    None,
                ],
                C66Role::Source {
                    announced: false,
                    rotated: false,
                    handoff: Some(fresh_source_receiver),
                },
            );
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            let payload = payload.with_c77_runtime(source_runtime);
            payload
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 source payload installation failed");
    }
    if unsafe {
        registry.install_payload(tokens[1], || {
            let payload = C66Payload::new(
                generation,
                tokens[1],
                old_target_table,
                [
                    Some(C66Drain {
                        token: old_target_reader_token,
                        resource_type: C66_RELAY_READER_TYPE,
                    }),
                    Some(C66Drain {
                        token: old_target_writer_token,
                        resource_type: C66_RELAY_WRITER_TYPE,
                    }),
                ],
                C66Role::OldTarget {
                    waiting: None,
                    announced: false,
                },
            );
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            let payload = payload.with_c77_runtime(target_runtime);
            payload
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 old target payload installation failed");
    }
    if unsafe {
        registry.install_payload(tokens[2], || {
            let payload = C66Payload::new(
                generation,
                tokens[2],
                sink_table,
                [
                    Some(C66Drain {
                        token: sink_token,
                        resource_type: C66_SINK_READER_TYPE,
                    }),
                    None,
                ],
                C66Role::Sink {
                    announced: false,
                    rotated: false,
                    handoff: Some(fresh_sink_receiver),
                },
            );
            #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            let payload = payload.with_c77_runtime(sink_runtime);
            payload
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 sink payload installation failed");
    }
    if registry
        .bind_batch(
            &tokens,
            old_batch.prepared_reclaimable_bindings(),
            &old_batch.prepared_handles()[..C66_NODE_COUNT],
        )
        .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 old graph binding failed");
    }

    let completion = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let completion = Arc::new(C66Completion::new());
        system.restore();
        completion
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    old_batch.prepare("wasm-c66-node-replacement-supervisor", async move {
        let supervisor = core::future::poll_fn(move |_context| {
            activation_receiver
                .try_take(generation)
                .map_or(Poll::Pending, Poll::Ready)
        })
        .await;
        supervisor.run().await;
    });
    system.restore();
    let prepared_supervisor = old_batch.prepared_handles()[C66_NODE_COUNT].clone();
    let mut published = match unsafe {
        old_batch.publish_exclusive_reclaimable_with(|bindings| registry.activate_batch(bindings))
    } {
        Ok(handles) => handles,
        Err(_) => lifecycle_invariant_failed(&tokens, "C6.6 old graph publication failed"),
    };
    #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
    let c77_task_identity_changed = matches!(mode, C66StageMode::C77Ephemeral)
        && !c77_pairwise_task_identity_is_fresh(&old_handles);
    #[cfg(not(feature = "wasm-c77-ephemeral-runtime-acceptance"))]
    let c77_task_identity_changed = false;
    if published.len() != C66_NODE_COUNT + 1
        || published[..C66_NODE_COUNT]
            .iter()
            .zip(&old_handles)
            .any(|(published, prepared)| {
                published.id() != prepared.id()
                    || published.allocation_domain() != prepared.allocation_domain()
                    || !published.shares_status_with(prepared)
            })
        || published[C66_NODE_COUNT].id() != prepared_supervisor.id()
        || !published[C66_NODE_COUNT].shares_status_with(&prepared_supervisor)
        || c77_task_identity_changed
    {
        lifecycle_invariant_failed(&tokens, "C6.6 old publication identities changed");
    }
    let supervisor = published
        .pop()
        .expect("validated C6.6 publication contains its supervisor");
    drop(published);
    Ok(C66StagedCurrent {
        current: current_seal,
        generation,
        supervisor,
        completion,
        activation,
        old_tokens: [tokens[0], tokens[1], tokens[2]],
        old_handles,
        sibling_domains: [domains[0], domains[2]],
        source_probe,
        old_target_probe,
        sink_probe,
        old_streams: streams,
        old_supervisors: supervisors,
        old_target_reader_token,
        old_target_writer_token,
        old_target_resource_generation: current_plans[C66_TARGET_INDEX].resource_generation,
        fresh_source_publisher,
        fresh_sink_publisher,
        fresh_source_handoff_audit,
        fresh_sink_handoff_audit,
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
        c77_resource_generations_distinct,
    })
}

fn start_c66_authorized_replacement(
    staged: C66StagedCurrent,
    current: &ComponentGraphPrincipalTemplate,
    candidate: &ComponentGraphPrincipalTemplate,
    node_action: ComponentGraphReplacementNodeAction,
    max_replacements: u16,
    incident_edges: &[ComponentGraphReplacementEdgePolicy],
    policy_cancel: C66PolicyCancelPermit,
) -> Result<C66Run, ComponentGraphPrincipalLifecycleError> {
    {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let validation = exact_c66_replacement(
            current,
            candidate,
            node_action,
            max_replacements,
            incident_edges,
            staged.current,
        );
        system.restore();
        validation?;
    }
    let reports = c66_semantic_reports_for(current, candidate)?;
    let candidate_plans = checked_plan(candidate)?;
    if candidate_plans.len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    let mut candidate_plan = candidate_plans[C66_TARGET_INDEX];
    candidate_plan.resource_generation = reserve_resource_generations(1)?;

    // Stage B begins here: only the move-only durable replacement proof can
    // reach the first candidate domain/registry allocation.
    let domains = create_domains(core::slice::from_ref(&candidate_plan))?;
    if domains.len() != 1 {
        let _ = super::release_empty_domains(&domains);
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
    }
    let tokens = match reserve_registry_batch(&domains) {
        Ok(tokens) if tokens.len() == 1 => tokens,
        Ok(tokens) => {
            let _ = abort_pristine_registry_batch(&tokens, &domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
        Err(_) => {
            let _ = super::release_empty_domains(&domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
    };
    let candidate_pairs = match publication_pairs(&tokens, &domains) {
        Ok(pairs) => pairs,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let mut candidate_batch = PreparedTaskBatch::new();
    if candidate_batch
        .reserve_managed_publication(&candidate_pairs, 0)
        .and_then(|_| candidate_batch.reserve_managed_task_ledgers(1, 0, 0))
        .is_err()
    {
        drop(candidate_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::SchedulerReservation);
    }

    let fresh_streams = [ByteStream::new(), ByteStream::new()];
    let fresh_supervisors = [fresh_streams[0].supervisor(), fresh_streams[1].supervisor()];
    let fresh_source_writer = fresh_streams[0].writer();
    let candidate_reader = fresh_streams[0].reader();
    let candidate_writer = fresh_streams[1].writer();
    let fresh_sink_reader = fresh_streams[1].reader();
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let candidate_table = ResourceTable::new(
        candidate_plan.resource_generation,
        candidate_plan.resource_slots,
    )
    .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    system.restore();
    let mut candidate_table = match candidate_table {
        Ok(table) => table,
        Err(error) => {
            drop(candidate_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let candidate_authorities =
        match c66_prepare_relay(tokens[0], candidate_reader, candidate_writer) {
            Ok(authorities) => authorities,
            Err(error) => {
                drop(candidate_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(error);
            }
        };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let inserted = (|| {
        let reader = candidate_table
            .insert_owned(C66_RELAY_READER_TYPE, candidate_authorities.0)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let writer = candidate_table
            .insert_owned(C66_RELAY_WRITER_TYPE, candidate_authorities.1)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        Ok((reader, writer))
    })();
    system.restore();
    let (candidate_reader_token, candidate_writer_token) = match inserted {
        Ok(tokens) => tokens,
        Err(error) => {
            drop(candidate_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let stale_replacement_tokens = candidate_table
        .contains(staged.old_target_reader_token, C66_RELAY_READER_TYPE)
        == Err(ResourceError::WrongInstance)
        && candidate_table.contains(staged.old_target_writer_token, C66_RELAY_WRITER_TYPE)
            == Err(ResourceError::WrongInstance);
    let fresh_resources = stale_replacement_tokens
        && candidate_table.len() == 2
        && candidate_table.instance_generation() != staged.old_target_resource_generation
        && !Arc::ptr_eq(&staged.old_streams[0], &fresh_streams[0])
        && !Arc::ptr_eq(&staged.old_streams[1], &fresh_streams[1]);
    if !fresh_resources {
        drop(candidate_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }
    let Some(candidate_probe) =
        super::super::component_instances::registry().acceptance_probe(tokens[0])
    else {
        drop(candidate_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    };
    let fresh_generation = !staged.old_tokens[C66_TARGET_INDEX].shares_stable_slot(tokens[0]);
    let fresh_cspace = !staged.old_target_probe.same_space_object(candidate_probe)
        && !staged.old_target_probe.same_cspace_lock(candidate_probe)
        && !staged
            .old_target_probe
            .same_cspace_identity(candidate_probe);
    let fresh_arena = staged.old_handles[C66_TARGET_INDEX]
        .allocation_domain()
        .arena
        != domains[0].arena;
    if !C66_AUDIT.matches(staged.generation)
        || !c66_increment(&C66_AUDIT.stale_replacement_tokens, staged.generation)
        || !c66_increment(&C66_AUDIT.stale_replacement_tokens, staged.generation)
    {
        drop(candidate_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }

    let registry = super::super::component_instances::registry();
    unsafe {
        candidate_batch.prepare_managed_instance_owned(
            tokens[0],
            domains[0],
            PRINCIPAL_TASK_NAME,
            C66Task {
                token: tokens[0],
                generation: staged.generation,
            },
        );
    }
    let candidate_handle = candidate_batch.prepared_handles()[0].clone();
    let fresh_task = staged.old_handles[C66_TARGET_INDEX].id() != candidate_handle.id()
        && !staged.old_handles[C66_TARGET_INDEX].shares_status_with(&candidate_handle);
    let lifecycle_tokens = [
        staged.old_tokens[0],
        staged.old_tokens[1],
        staged.old_tokens[2],
        tokens[0],
    ];
    if !fresh_generation || !fresh_cspace || !fresh_task || !fresh_arena {
        lifecycle_invariant_failed(&lifecycle_tokens, "C6.6 candidate identity was not fresh");
    }
    if unsafe {
        registry.install_payload(tokens[0], || {
            C66Payload::new(
                staged.generation,
                tokens[0],
                candidate_table,
                [
                    Some(C66Drain {
                        token: candidate_reader_token,
                        resource_type: C66_RELAY_READER_TYPE,
                    }),
                    Some(C66Drain {
                        token: candidate_writer_token,
                        resource_type: C66_RELAY_WRITER_TYPE,
                    }),
                ],
                C66Role::Candidate {
                    waiting: None,
                    stage: C66CandidateStage::Receive,
                },
            )
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(
            &lifecycle_tokens,
            "C6.6 candidate payload installation failed",
        );
    }
    if registry
        .bind_batch(
            &tokens,
            candidate_batch.prepared_reclaimable_bindings(),
            candidate_batch.prepared_handles(),
        )
        .is_err()
    {
        lifecycle_invariant_failed(&lifecycle_tokens, "C6.6 candidate binding failed");
    }

    let C66StagedCurrent {
        current: _,
        generation,
        supervisor,
        completion,
        activation,
        old_tokens,
        old_handles,
        sibling_domains,
        source_probe,
        old_target_probe,
        sink_probe,
        old_streams,
        old_supervisors,
        old_target_reader_token: _,
        old_target_writer_token: _,
        old_target_resource_generation: _,
        fresh_source_publisher,
        fresh_sink_publisher,
        fresh_source_handoff_audit,
        fresh_sink_handoff_audit,
        #[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
            c77_resource_generations_distinct: _,
    } = staged;
    let [old_stream_0, old_stream_1] = old_streams;
    let [fresh_stream_0, fresh_stream_1] = fresh_streams;
    let [old_supervisor_0, old_supervisor_1] = old_supervisors;
    let [fresh_supervisor_0, fresh_supervisor_1] = fresh_supervisors;
    let replacement = C66Supervisor {
        generation,
        candidate_batch,
        candidate_token: tokens[0],
        candidate_handle,
        old_tokens,
        old_handles,
        sibling_domains,
        source_probe,
        old_target_probe,
        sink_probe,
        candidate_probe,
        streams: [old_stream_0, old_stream_1, fresh_stream_0, fresh_stream_1],
        supervisors: [
            old_supervisor_0,
            old_supervisor_1,
            fresh_supervisor_0,
            fresh_supervisor_1,
        ],
        fresh_source_writer,
        fresh_sink_reader,
        fresh_source_publisher,
        fresh_sink_publisher,
        fresh_source_handoff_audit,
        fresh_sink_handoff_audit,
        reports,
        completion: Arc::clone(&completion),
        policy_cancel,
        fresh_generation,
        fresh_cspace,
        fresh_task,
        fresh_arena,
        fresh_resources,
    };
    if activation.publish(generation, replacement).is_err() {
        lifecycle_invariant_failed(
            &lifecycle_tokens,
            "C6.6 replacement activation published twice",
        );
    }
    if !supervisor.exact_wake().wake_if_exact() {
        lifecycle_invariant_failed(&lifecycle_tokens, "C6.6 dormant supervisor was not live");
    }
    Ok(C66Run {
        supervisor,
        completion,
    })
}

#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
fn start_c66_node_replacement(
    template: Arc<ComponentGraphNodeReplacementTemplate>,
) -> Result<C66Run, ComponentGraphPrincipalLifecycleError> {
    exact_c66_template(&template)?;
    let staged = stage_c66_current_graph(template.current_graph())?;
    let permit = C66PolicyCancelPermit::C66 {
        generation: staged.generation,
        target: template.target(),
    };
    start_c66_authorized_replacement(
        staged,
        template.current_graph(),
        template.candidate_graph(),
        template.node_action(),
        template.max_replacements(),
        template.incident_edges(),
        permit,
    )
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
#[must_use = "hold the current graph lifetime or consume one durable replacement proof"]
pub(crate) struct C76StagedCurrent(C66StagedCurrent);

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
impl C76StagedCurrent {
    pub(crate) const fn current_nodes(&self) -> usize {
        C66_NODE_COUNT
    }

    pub(crate) const fn current_routes(&self) -> usize {
        2
    }

    pub(crate) const fn candidate_lifecycle_objects(&self) -> usize {
        0
    }

    pub(crate) const fn runtime_ready(&self) -> bool {
        false
    }
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
pub(crate) fn stage_c76_current_graph(
    proof: C76SupervisorCurrentGraph,
) -> Result<C76StagedCurrent, ComponentGraphPrincipalLifecycleError> {
    proof
        .consume(|view| stage_c66_current_graph(view.current_graph()))
        .map(C76StagedCurrent)
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
#[must_use = "hold the observed C7.7 boot-local graph until cold reset"]
pub(crate) struct C77StagedEphemeralGraph {
    staged: C66StagedCurrent,
    observed: AtomicBool,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
#[must_use = "inspect every redacted C7.7 boot-local lifecycle count"]
pub(crate) struct C77EphemeralBootReceipt {
    fresh_tasks: usize,
    fresh_arenas: usize,
    fresh_cspaces: usize,
    fresh_memories: usize,
    fresh_resource_tables: usize,
    fresh_fuel_accounts: usize,
    fresh_pending_ledgers: usize,
    active_pending_calls: usize,
    memory_bytes: u64,
    live_resources: usize,
    fuel_consumed: u64,
    runtime_ready: bool,
    guest_calls: u64,
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
impl fmt::Debug for C77EphemeralBootReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("C77EphemeralBootReceipt")
            .field("fresh_tasks", &self.fresh_tasks)
            .field("fresh_arenas", &self.fresh_arenas)
            .field("fresh_cspaces", &self.fresh_cspaces)
            .field("fresh_memories", &self.fresh_memories)
            .field("fresh_resource_tables", &self.fresh_resource_tables)
            .field("fresh_fuel_accounts", &self.fresh_fuel_accounts)
            .field("fresh_pending_ledgers", &self.fresh_pending_ledgers)
            .field("active_pending_calls", &self.active_pending_calls)
            .field("memory_bytes", &self.memory_bytes)
            .field("live_resources", &self.live_resources)
            .field("fuel_consumed", &self.fuel_consumed)
            .field("runtime_ready", &self.runtime_ready)
            .field("guest_calls", &self.guest_calls)
            .finish()
    }
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
impl C77EphemeralBootReceipt {
    pub(crate) const fn fresh_tasks(&self) -> usize {
        self.fresh_tasks
    }

    pub(crate) const fn fresh_arenas(&self) -> usize {
        self.fresh_arenas
    }

    pub(crate) const fn fresh_cspaces(&self) -> usize {
        self.fresh_cspaces
    }

    pub(crate) const fn fresh_memories(&self) -> usize {
        self.fresh_memories
    }

    pub(crate) const fn fresh_resource_tables(&self) -> usize {
        self.fresh_resource_tables
    }

    pub(crate) const fn fresh_fuel_accounts(&self) -> usize {
        self.fresh_fuel_accounts
    }

    pub(crate) const fn fresh_pending_ledgers(&self) -> usize {
        self.fresh_pending_ledgers
    }

    pub(crate) const fn active_pending_calls(&self) -> usize {
        self.active_pending_calls
    }

    pub(crate) const fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    pub(crate) const fn live_resources(&self) -> usize {
        self.live_resources
    }

    pub(crate) const fn fuel_consumed(&self) -> u64 {
        self.fuel_consumed
    }

    pub(crate) const fn runtime_ready(&self) -> bool {
        self.runtime_ready
    }

    pub(crate) const fn guest_calls(&self) -> u64 {
        self.guest_calls
    }
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_pairwise_task_identity_is_fresh(handles: &[TaskHandle; C66_NODE_COUNT]) -> bool {
    handles.iter().enumerate().all(|(index, left)| {
        handles.iter().skip(index + 1).all(|right| {
            let left_domain = left.allocation_domain();
            let right_domain = right.allocation_domain();
            left.id() != right.id()
                && !left.shares_status_with(right)
                && left_domain.owner != right_domain.owner
                && left_domain.arena != right_domain.arena
        })
    })
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_arenas_are_live_and_fresh(handles: &[TaskHandle; C66_NODE_COUNT]) -> bool {
    let Some(memory_charge) = c77_memory_allocation_charge() else {
        return false;
    };
    handles.iter().all(|handle| {
        let domain = handle.allocation_domain();
        let Some(arena) = crate::HEAP.arena_stats(domain.arena) else {
            return false;
        };
        let Some(owner) = crate::HEAP.account_stats(domain.owner) else {
            return false;
        };
        domain.owner != OwnerId::SYSTEM
            && domain.arena.is_tracked()
            && arena.owner == domain.owner
            && arena.live_bytes >= memory_charge
            && arena.live_allocations >= 2
            && owner.owner == domain.owner
            && owner.live_bytes == arena.live_bytes
            && owner.live_allocations == arena.live_allocations
            && owner.denials == 0
    })
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
fn c77_cspace_probe_is_stable(
    before: AcceptanceInstanceProbe,
    after: AcceptanceInstanceProbe,
    installed_capabilities: usize,
) -> bool {
    before.is_exact()
        && before.exact_phase() == Some(InstancePhase::Reserved)
        && after.is_exact()
        && after.exact_phase() == Some(InstancePhase::Active)
        && before.same_space_object(after)
        && before.same_cspace_lock(after)
        && before.same_cspace_identity(after)
        && before.same_cspace_incarnation(after)
        && before.same_capability_table(after)
        && before.seal_matches_space()
        && after.seal_matches_space()
        && before.seal_matches_cspace()
        && after.seal_matches_cspace()
        && before.installed_capability_count() == installed_capabilities
        && after.installed_capability_count() == installed_capabilities
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
pub(crate) fn stage_c77_ephemeral_graph(
    proof: C76SupervisorCurrentGraph,
) -> Result<C77StagedEphemeralGraph, ComponentGraphPrincipalLifecycleError> {
    let baseline = super::super::component_instances::registry().occupancy_stats();
    if baseline.occupied != 0 || baseline.header_mismatches != 0 {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }
    proof
        .consume(|view| {
            stage_c66_current_graph_with_mode(view.current_graph(), C66StageMode::C77Ephemeral)
        })
        .map(|staged| C77StagedEphemeralGraph {
            staged,
            observed: AtomicBool::new(false),
        })
}

#[cfg(feature = "wasm-c77-ephemeral-runtime-acceptance")]
impl C77StagedEphemeralGraph {
    pub(crate) async fn observe(
        &self,
    ) -> Result<C77EphemeralBootReceipt, ComponentGraphPrincipalLifecycleError> {
        if self
            .observed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let staged = &self.staged;
        if !c66_wait_stage(
            &C66_OLD_READY,
            staged.generation,
            [
                &staged.old_handles[0],
                &staged.old_handles[1],
                &staged.old_handles[2],
            ],
        )
        .await
        {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        let mut all_parked = false;
        for _ in 0..64 {
            if staged
                .old_handles
                .iter()
                .all(TaskHandle::acceptance_is_parked_exact)
            {
                all_parked = true;
                break;
            }
            crate::exec::yield_now().await;
        }
        let registry = super::super::component_instances::registry();
        let probes = [
            registry.acceptance_probe(staged.old_tokens[0]),
            registry.acceptance_probe(staged.old_tokens[1]),
            registry.acceptance_probe(staged.old_tokens[2]),
        ];
        let [Some(source_after), Some(target_after), Some(sink_after)] = probes else {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let cspaces_fresh = c77_cspace_probe_is_stable(staged.source_probe, source_after, 1)
            && c77_cspace_probe_is_stable(staged.old_target_probe, target_after, 2)
            && c77_cspace_probe_is_stable(staged.sink_probe, sink_after, 1)
            && !source_after.same_space_object(target_after)
            && !source_after.same_space_object(sink_after)
            && !target_after.same_space_object(sink_after)
            && !source_after.same_cspace_lock(target_after)
            && !source_after.same_cspace_lock(sink_after)
            && !target_after.same_cspace_lock(sink_after)
            && !source_after.same_cspace_identity(target_after)
            && !source_after.same_cspace_identity(sink_after)
            && !target_after.same_cspace_identity(sink_after)
            && !source_after.same_capability_table(target_after)
            && !source_after.same_capability_table(sink_after)
            && !target_after.same_capability_table(sink_after);
        let continuation_cut = source_after.continuation_is_idle()
            && source_after.continuation_waiters() == 0
            && target_after.external_continuation_is_armed()
            && target_after.continuation_waiters() == 1
            && sink_after.continuation_is_idle()
            && sink_after.continuation_waiters() == 0;
        let old_operation = C66_OLD_OPERATION.load();
        let pending_backend_exact = old_operation.is_some()
            && C66_OLD_OPERATION_REPLAY.lock().as_ref() == old_operation.as_ref()
            && C66_OLD_WAKE_WORDS.lock().is_some()
            && C66_OLD_WAKE_SIGNAL.is_empty()
            && C66_CANDIDATE_OPERATION.load().is_none()
            && C66_CANDIDATE_WAKE_WORDS.lock().is_none()
            && C66_CANDIDATE_WAKE_SIGNAL.is_empty();
        let audit_exact = C66_AUDIT.matches(staged.generation)
            && !C66_AUDIT.failed.load(Ordering::Acquire)
            && C66_AUDIT.old_ready_mask.load(Ordering::Acquire) == C66_ALL_NODE_BITS
            && C66_AUDIT.c77_runtime_mask.load(Ordering::Acquire) == C66_ALL_NODE_BITS
            && C66_AUDIT.c77_pending_ledger_mask.load(Ordering::Acquire) == C66_ALL_NODE_BITS
            && C66_AUDIT.c77_active_pending_mask.load(Ordering::Acquire) == C66_TARGET_BIT
            && C66_AUDIT.wake_registrations.load(Ordering::Acquire) == 1
            && C66_AUDIT.wake_callbacks.load(Ordering::Acquire) == 0
            && C66_AUDIT.continuation_resumes.load(Ordering::Acquire) == 0
            && C66_AUDIT.sealed_resumes.load(Ordering::Acquire) == 0
            && C66_AUDIT.old_routes_retired.load(Ordering::Acquire) == 0
            && C66_AUDIT.fresh_routes.load(Ordering::Acquire) == 0
            && C66_AUDIT.fresh_completed_mask.load(Ordering::Acquire) == 0;
        if !all_parked
            || !c77_pairwise_task_identity_is_fresh(&staged.old_handles)
            || !c77_arenas_are_live_and_fresh(&staged.old_handles)
            || !cspaces_fresh
            || !staged.c77_resource_generations_distinct
            || !continuation_cut
            || !pending_backend_exact
            || !audit_exact
            || c66_phase(staged.generation) != Some(C66_PHASE_OLD)
            || !staged.activation.is_unpublished_exact(staged.generation)
        {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        }
        Ok(C77EphemeralBootReceipt {
            fresh_tasks: C66_NODE_COUNT,
            fresh_arenas: C66_NODE_COUNT,
            fresh_cspaces: C66_NODE_COUNT,
            fresh_memories: C66_NODE_COUNT,
            fresh_resource_tables: C66_NODE_COUNT,
            fresh_fuel_accounts: C66_NODE_COUNT,
            fresh_pending_ledgers: C66_NODE_COUNT,
            active_pending_calls: 1,
            memory_bytes: (C77_MEMORY_BYTES_PER_NODE as u64) * (C66_NODE_COUNT as u64),
            live_resources: 4,
            fuel_consumed: 0,
            runtime_ready: false,
            guest_calls: 0,
        })
    }
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
#[must_use = "the C7.6 replacement run must reach its terminal receipt"]
pub(crate) struct C76ReplacementRun(C66Run);

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
pub(crate) struct C76ReplacementReceipt(C66ReplacementReceipt);

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
impl C76ReplacementReceipt {
    pub(crate) const fn candidate_hidden_before_policy_cancel(&self) -> bool {
        self.0.candidate_hidden_before_policy_cancel
    }

    pub(crate) const fn old_terminal_before_new_visible(&self) -> bool {
        self.0.old_terminal_before_new_ready
    }

    pub(crate) const fn siblings_stable(&self) -> usize {
        self.0.siblings_stable
    }

    pub(crate) const fn candidate_identity_is_fresh(&self) -> bool {
        self.0.fresh_generation && self.0.fresh_cspace && self.0.fresh_task && self.0.fresh_arena
    }

    pub(crate) const fn fresh_resources_are_distinct(&self) -> bool {
        self.0.fresh_resources
    }

    pub(crate) const fn old_routes_retired(&self) -> u64 {
        self.0.old_routes_retired
    }

    pub(crate) const fn fresh_routes(&self) -> u64 {
        self.0.fresh_routes
    }

    pub(crate) const fn stale_replacement_tokens(&self) -> u64 {
        self.0.stale_replacement_tokens
    }

    pub(crate) const fn late_wake_stale(&self) -> u64 {
        self.0.late_wake_stale
    }

    pub(crate) const fn policy_cancelled_after_old_terminal(&self) -> bool {
        self.0.policy_cancelled
    }

    pub(crate) const fn no_active_poll_at_cutover(&self) -> bool {
        self.0.no_active_poll
    }

    pub(crate) const fn graph_version_published(&self) -> bool {
        self.0.graph_version_published
    }

    pub(crate) const fn runtime_ready(&self) -> bool {
        false
    }

    pub(crate) fn guest_calls(&self) -> u64 {
        self.0
            .terminal
            .iter()
            .map(|terminal| terminal.guest_calls)
            .sum()
    }

    pub(crate) const fn terminal_receipts(&self) -> usize {
        self.0.terminal.len()
    }

    pub(crate) fn reports_are_runtime_unavailable(&self) -> bool {
        self.0.reports.len() == C66_INCARNATION_COUNT
            && self.0.reports.iter().all(|report| {
                report.terminal() == ComponentGraphNodeTerminal::RuntimeUnavailable
                    && report.fuel().consumed() == 0
                    && report.resources().live_slots() == 0
            })
    }
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
impl C76ReplacementRun {
    pub(crate) async fn wait(
        self,
    ) -> Result<C76ReplacementReceipt, ComponentGraphPrincipalLifecycleError> {
        self.0.wait().await.map(C76ReplacementReceipt)
    }
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
pub(crate) fn start_c76_durable_replacement(
    staged: C76StagedCurrent,
    proof: C76SupervisorGraphReplacement,
) -> Result<C76ReplacementRun, ComponentGraphPrincipalLifecycleError> {
    proof
        .consume(|view, permit| {
            start_c66_authorized_replacement(
                staged.0,
                view.current_graph(),
                view.successor_graph(),
                view.node_action(),
                view.max_replacements(),
                view.incident_edges(),
                C66PolicyCancelPermit::C76(permit),
            )
        })
        .map(C76ReplacementRun)
}

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
const _: fn(
    C76SupervisorCurrentGraph,
) -> Result<C76StagedCurrent, ComponentGraphPrincipalLifecycleError> = stage_c76_current_graph;

#[cfg(feature = "wasm-c76-graph-version-replacement-acceptance")]
const _: fn(
    C76StagedCurrent,
    C76SupervisorGraphReplacement,
) -> Result<C76ReplacementRun, ComponentGraphPrincipalLifecycleError> =
    start_c76_durable_replacement;

#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
fn c66_qemu_acceptance_template(
) -> Option<(Arc<ComponentGraphNodeReplacementTemplate>, AllocationDomain)> {
    let caller_quota = 12usize.checked_mul(1024)?.checked_mul(1024)?;
    let caller_domains = crate::HEAP
        .create_fresh_domains_batch(&[caller_quota])
        .ok()?;
    let [caller_domain] = caller_domains.as_slice() else {
        let _ = super::release_empty_domains(&caller_domains);
        return None;
    };
    let caller_domain = *caller_domain;
    drop(caller_domains);

    // SAFETY: this unpublished fresh domain is owned exclusively by the
    // acceptance task. Both validation-only graphs and their replacement
    // command are synchronously consumed by the sealed start gate before the
    // first await; no caller allocation enters a node or SYSTEM stream.
    let mut caller = unsafe { crate::heap::enter_domain(caller_domain) };
    let template = (|| {
        let pin = C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE;
        if pin.profile() != ProfileIdentity::PROFILE_1_ASYNC
            || pin.profile().execution_enabled()
            || pin.wit_sha256() != C66_WIT_SHA256
            || pin.interface() != "test:c65-chain/pipe@1.0.0"
            || pin.node_count() != C66_NODE_COUNT as u16
            || pin.replacement_node() != C66_TARGET_INDEX as u16
            || pin.max_replacements() != 1
        {
            return None;
        }

        let current_source =
            ComponentArtifact::copy_from(pin.source_bytes(), pin.profile()).ok()?;
        let current_relay =
            ComponentArtifact::copy_from(pin.old_relay_bytes(), pin.profile()).ok()?;
        let current_sink = ComponentArtifact::copy_from(pin.sink_bytes(), pin.profile()).ok()?;
        let candidate_source =
            ComponentArtifact::copy_from(pin.source_bytes(), pin.profile()).ok()?;
        let candidate_relay =
            ComponentArtifact::copy_from(pin.new_relay_bytes(), pin.profile()).ok()?;
        let candidate_sink = ComponentArtifact::copy_from(pin.sink_bytes(), pin.profile()).ok()?;
        if current_source.identity().as_bytes() != &pin.source_sha256()
            || current_relay.identity().as_bytes() != &pin.old_relay_sha256()
            || current_sink.identity().as_bytes() != &pin.sink_sha256()
            || candidate_source.identity().as_bytes() != &pin.source_sha256()
            || candidate_relay.identity().as_bytes() != &pin.new_relay_sha256()
            || candidate_sink.identity().as_bytes() != &pin.sink_sha256()
            || current_source.identity() != candidate_source.identity()
            || current_sink.identity() != candidate_sink.identity()
            || current_relay.identity() == candidate_relay.identity()
        {
            return None;
        }

        let source_world = WorldContract::parse(pin.wit_source(), pin.source_world()).ok()?;
        let relay_world = WorldContract::parse(pin.wit_source(), pin.relay_world()).ok()?;
        let sink_world = WorldContract::parse(pin.wit_source(), pin.sink_world()).ok()?;
        let limits = pin.limits();
        let current_nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-source",
                nesting: ComponentGraphNesting::Root,
                exact_world: &source_world,
                trust: ArtifactTrust::ImagePinned(current_source.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-relay",
                nesting: ComponentGraphNesting::Root,
                exact_world: &relay_world,
                trust: ArtifactTrust::ImagePinned(current_relay.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-sink",
                nesting: ComponentGraphNesting::Root,
                exact_world: &sink_world,
                trust: ArtifactTrust::ImagePinned(current_sink.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
        ];
        let candidate_nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-source",
                nesting: ComponentGraphNesting::Root,
                exact_world: &source_world,
                trust: ArtifactTrust::ImagePinned(candidate_source.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-relay",
                nesting: ComponentGraphNesting::Root,
                exact_world: &relay_world,
                trust: ArtifactTrust::ImagePinned(candidate_relay.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c66-sink",
                nesting: ComponentGraphNesting::Root,
                exact_world: &sink_world,
                trust: ArtifactTrust::ImagePinned(candidate_sink.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
        ];
        let edges = [c66_edge(0, 1), c66_edge(1, 2)];
        let published = [ComponentGraphPublishedExportSpec::new(
            ComponentGraphExportEndpoint::new(
                ComponentGraphNodeId::new(2),
                ComponentGraphEntityIndex::new(0),
            ),
        )];
        let current_policy = ComponentGraphAdmissionPolicy {
            name: "c66-qemu-node-replacement",
            profile: pin.profile(),
            nodes: &current_nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let candidate_policy = ComponentGraphAdmissionPolicy {
            name: "c66-qemu-node-replacement",
            profile: pin.profile(),
            nodes: &candidate_nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let current = admit_component_graph(
            Vec::from([current_source, current_relay, current_sink]),
            &current_policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        let candidate = admit_component_graph(
            Vec::from([candidate_source, candidate_relay, candidate_sink]),
            &candidate_policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        let incident_edges = [
            ComponentGraphReplacementEdgePolicy {
                edge: edges[0],
                action: ComponentGraphReplacementEdgeAction::RecreateFresh,
            },
            ComponentGraphReplacementEdgePolicy {
                edge: edges[1],
                action: ComponentGraphReplacementEdgeAction::RecreateFresh,
            },
        ];
        let replacement_policy = ComponentGraphNodeReplacementPolicy {
            target: ComponentGraphNodeId::new(C66_TARGET_INDEX as u16),
            max_replacements: 1,
            node_action: ComponentGraphReplacementNodeAction::PolicyCancel,
            incident_edges: &incident_edges,
        };
        let replacement = admit_component_graph_replacement(
            Arc::new(current),
            Arc::new(candidate),
            &replacement_policy,
        )
        .ok()?;
        let template = ComponentGraphNodeReplacementTemplate::new(Arc::new(replacement)).ok()?;
        exact_c66_template(&template).ok()?;
        Some(Arc::new(template))
    })();
    caller.restore();
    match template {
        Some(template) => Some((template, caller_domain)),
        None => {
            let _ = release_empty_domain(caller_domain);
            None
        }
    }
}

/// Exercise one exact update of the middle node in a three-node graph. The
/// image remains validation-only: all transport work is performed by bounded
/// host streams under exact per-incarnation CSpaces, and no guest entry point
/// is reachable.
#[cfg(feature = "wasm-c66-node-replacement-acceptance")]
pub(crate) async fn run_qemu_acceptance() -> bool {
    if crate::online_hart_count() != 4 || crate::online_hart_mask() & 0x0f != 0x0f {
        return false;
    }
    let before = super::super::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return false;
    }
    let Some((template, caller_domain)) = c66_qemu_acceptance_template() else {
        return false;
    };
    let run = match start_c66_node_replacement(template) {
        Ok(run) => run,
        Err(_) => {
            let _ = release_empty_domain(caller_domain);
            return false;
        }
    };
    if !release_empty_domain(caller_domain) {
        return false;
    }
    let Ok(receipt) = run.wait().await else {
        return false;
    };
    if !receipt.candidate_staged
        || !receipt.old_terminal_before_new_ready
        || !receipt.fresh_generation
        || !receipt.fresh_cspace
        || !receipt.fresh_task
        || !receipt.fresh_arena
        || !receipt.fresh_resources
        || receipt.siblings_stable != 2
        || !receipt.no_active_poll
        || !receipt.policy_cancelled
        || receipt.old_routes_retired != 2
        || receipt.fresh_routes != 2
        || receipt.stale_replacement_tokens != 2
        || receipt.late_wake_stale != 1
        || receipt.graph_version_published
        || receipt.reports.len() != C66_INCARNATION_COUNT
        || receipt.terminal.len() != C66_INCARNATION_COUNT
        || receipt
            .terminal
            .iter()
            .zip([1_usize, 2, 2, 1])
            .any(|(terminal, revoked)| {
                terminal.revoked_capabilities != revoked || terminal.guest_calls != 0
            })
    {
        return false;
    }
    for (report, (node, peak)) in
        receipt
            .reports
            .iter()
            .zip([(0_u16, 1_u64), (1, 2), (1, 2), (2, 1)])
    {
        if report.node() != ComponentGraphNodeId::new(node)
            || report.terminal() != ComponentGraphNodeTerminal::RuntimeUnavailable
            || report.fuel().limit() != 1_000
            || report.fuel().consumed() != 0
            || report.resources().declared_types() != 0
            || report.resources().slot_limit() != 8
            || report.resources().peak_slots() != peak
            || report.resources().live_slots() != 0
        {
            return false;
        }
    }
    let after = super::super::component_instances::registry().occupancy_stats();
    after.occupied == 0 && after.header_mismatches == 0
}
