//! Boot-local C6.6 single-node replacement for one exact admitted graph.
//!
//! The acceptance path is deliberately validation-only. It stages a fresh
//! middle principal while the old three-node graph remains live, retires both
//! incident routes and the old middle principal, rotates only the siblings'
//! incident endpoints from their own current tasks, then atomically publishes
//! the complete fresh route bundle and the replacement task. No guest bytes
//! are instantiated or invoked.

use alloc::{sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use core::task::{Context, Poll};

use vibeos_component_admission::{
    admit_component_graph, admit_component_graph_replacement, ArtifactTrust, CallerAuthority,
    ComponentArtifact, ComponentGraphAdmissionPolicy, ComponentGraphCyclePolicy,
    ComponentGraphNodeAdmissionPolicy, ComponentGraphNodeReplacementPolicy,
    ComponentGraphReplacementEdgeAction, ComponentGraphReplacementEdgePolicy, InstanceLimits,
    ProfileIdentity,
};
use vibeos_component_command::{
    ComponentGraphNodeReplacementTemplate, ComponentGraphNodeTerminal,
    ComponentGraphNodeTerminalReport,
};
use vibeos_component_host::{
    revoke_owned_supervised, ByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter,
    ComponentAuthority, StreamCloseOutcome, StreamCloseReason, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, StreamWakeRegistration,
};
use vibeos_component_runtime::graph::{
    ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
    ComponentGraphImportEndpoint, ComponentGraphNesting, ComponentGraphNodeId,
    ComponentGraphPublishedExportSpec,
};
use vibeos_component_runtime::host::{AtomicHostOperationSlot, HostOperationToken, HostWakeToken};
use vibeos_component_runtime::resource::{
    ResourceError, ResourceTable, ResourceToken, ResourceTypeId,
};
use vibeos_component_runtime::world::WorldContract;
use vibeos_core::cap::Rights;
use vibeos_image_policy::{
    ComponentGraphReplacementPinAction, C66_NODE_REPLACEMENT_QEMU_ACCEPTANCE,
};

use crate::exec::{OneShotWaitQueue, PreparedTaskBatch, TaskHandle, TaskState};
use crate::heap::{AllocationDomain, OwnerId};
use crate::instance::{
    AcceptanceInstanceProbe, InstanceContinuation, InstanceContinuationKind,
    InstanceContinuationSignal, InstanceContinuationToken, InstancePayload, InstanceSpace,
    InstanceToken,
};
use crate::sync::SpinLock;

use super::{
    abort_pristine_registry_batch, checked_plan, completion_guest_calls, create_domains,
    lifecycle_invariant_failed, publication_pairs, release_empty_domain, reserve_registry_batch,
    reserve_resource_generations, retire_domain, ComponentGraphPrincipalLifecycleError,
    PRINCIPAL_TASK_NAME, RUNTIME_UNAVAILABLE_COMPLETION,
};

const C66_NODE_COUNT: usize = 3;
const C66_INCARNATION_COUNT: usize = 4;
const C66_TARGET_INDEX: usize = 1;
const C66_SOURCE_BIT: u8 = 1 << 0;
const C66_TARGET_BIT: u8 = 1 << 1;
const C66_SINK_BIT: u8 = 1 << 2;
const C66_ALL_NODE_BITS: u8 = C66_SOURCE_BIT | C66_TARGET_BIT | C66_SINK_BIT;
const C66_SIBLING_BITS: u8 = C66_SOURCE_BIT | C66_SINK_BIT;
const C66_VALUE: u8 = 0x66;
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
static C66_OLD_WAKE_WORDS: SpinLock<Option<[usize; 4]>> = SpinLock::new(None);
static C66_CANDIDATE_WAKE_WORDS: SpinLock<Option<[usize; 4]>> = SpinLock::new(None);
static C66_OLD_OPERATION_REPLAY: SpinLock<Option<HostOperationToken>> = SpinLock::new(None);

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
        }
    }

    fn reset(&self, generation: u64) -> bool {
        let Some(old_phase) = c66_phase_word(generation, C66_PHASE_OLD) else {
            return false;
        };
        if C66_OLD_OPERATION.load().is_some()
            || C66_CANDIDATE_OPERATION.load().is_some()
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

fn c66_stream_wake(words: [usize; 4]) {
    let generation = C66_AUDIT.generation.load(Ordering::Acquire);
    if !c66_increment(&C66_AUDIT.wake_callbacks, generation)
        || super::super::component_instances::registry().signal_continuation_words(words)
            != InstanceContinuationSignal::Signalled
    {
        c66_publish_failure(generation);
    }
}

const C66_HANDOFF_EMPTY: u8 = 0;
const C66_HANDOFF_WRITING: u8 = 1;
const C66_HANDOFF_READY: u8 = 2;
const C66_HANDOFF_TAKEN: u8 = 3;

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
        }
    }

    fn drain(&self, index: usize) -> Result<C66Drain, ()> {
        self.drains.get(index).copied().flatten().ok_or(())
    }

    fn finish(&mut self) -> C66PayloadOutcome {
        if self.completed {
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
        let operation = pending.registration.operation();
        let cancelled = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.cancel(operation)
        }) == Ok(Ok(()));
        drop(pending);
        if cancelled {
            let _ = slot.clear_exact(operation);
        }
        cancelled || !slot.contains(operation)
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
        if !slot.publish(operation) {
            let _ = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
                reader.cancel(operation)
            });
            return Err(());
        }
        if core::ptr::eq(slot, &C66_OLD_OPERATION) {
            let mut replay = C66_OLD_OPERATION_REPLAY.lock();
            if replay.is_some() {
                return Err(());
            }
            *replay = Some(operation);
        }
        let token = super::super::component_instances::registry()
            .arm_continuation_current(self.instance, InstanceContinuationKind::External)
            .map_err(|_| ())?;
        let mut continuation: InstanceContinuation<'static> =
            super::super::component_instances::registry()
                .wait_continuation(token)
                .map_err(|_| ())?;
        if Pin::new(&mut continuation).poll(context) != Poll::Pending {
            return Err(());
        }
        let signal_words = token.signal_words();
        {
            let mut stored = words.lock();
            if stored.is_some() {
                return Err(());
            }
            *stored = Some(signal_words);
        }
        let registration = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader
                .register_wake_sealed(operation, HostWakeToken::new(signal_words, c66_stream_wake))
        })
        .map_err(|_| ())?
        .map_err(|_| ())?;
        if !slot.contains(operation)
            || !c66_increment(&C66_AUDIT.wake_registrations, self.generation)
        {
            return Err(());
        }
        Ok(C66PendingReceive {
            token,
            continuation,
            registration,
        })
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
        if !c66_increment(&C66_AUDIT.continuation_resumes, self.generation) {
            let _ = self.cancel_receive(space, endpoint, pending, slot);
            return Err(());
        }
        let operation = pending.registration.operation();
        if !slot.contains(operation) {
            return Err(());
        }
        let resumed = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
            reader.resume_after_wake(pending.registration)
        })
        .map_err(|_| ())?;
        let dispatch = match resumed {
            Ok(dispatch) => dispatch,
            Err(failure) => {
                let registration = failure.into_registration();
                let operation = registration.operation();
                let _ = c66_with_reader(&mut self.resources, endpoint, space, |reader| {
                    reader.cancel(operation)
                });
                drop(registration);
                return Err(());
            }
        };
        let _ = slot.clear_exact(operation);
        if slot.contains(operation) || !c66_increment(&C66_AUDIT.sealed_resumes, self.generation) {
            return Err(());
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
    }
}

// SAFETY: all retained endpoint Arcs are SYSTEM-owned. The payload never lets
// an arena pointer, CSpace guard, resolved capability, or resource borrow
// escape a quantum. Pending receive state contains only exact opaque backend
// and TaskStatus-owned continuation receipts, whose callback carries copy-only
// signal words. Normal completion consumes every registration and table entry
// before the exact registry finalizer resets the CSpace and retires the arena.
unsafe impl InstancePayload for C66Payload {
    fn poll_quantum(&mut self, space: &InstanceSpace, context: &mut Context<'_>) -> Poll<u64> {
        if self.completed {
            c66_publish_failure(self.generation);
            return Poll::Ready(RUNTIME_UNAVAILABLE_COMPLETION);
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
    old_terminal_before_new_ready: bool,
    fresh_generation: bool,
    fresh_cspace: bool,
    fresh_task: bool,
    fresh_arena: bool,
    fresh_resources: bool,
    siblings_stable: usize,
    no_active_poll: bool,
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
        let Some(old_words) = *C66_OLD_WAKE_WORDS.lock() else {
            fail(ComponentGraphPrincipalLifecycleError::NodeReplacementInvariant);
        };
        let Some(old_operation) = *C66_OLD_OPERATION_REPLAY.lock() else {
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
            old_terminal_before_new_ready,
            fresh_generation,
            fresh_cspace,
            fresh_task,
            fresh_arena,
            fresh_resources,
            siblings_stable,
            no_active_poll,
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

fn c66_semantic_reports(
    template: &ComponentGraphNodeReplacementTemplate,
) -> Result<Vec<ComponentGraphNodeTerminalReport>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let result = (|| {
        let mut reports = Vec::new();
        reports
            .try_reserve_exact(C66_INCARNATION_COUNT)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::Allocation)?;
        reports.push(
            template
                .current_graph()
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(0), 1)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            template
                .current_graph()
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(1), 2)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            template
                .candidate_graph()
                .supervisor_prepared_async_unavailable_report(ComponentGraphNodeId::new(1), 2)
                .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy)?,
        );
        reports.push(
            template
                .current_graph()
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

fn start_c66_node_replacement(
    template: Arc<ComponentGraphNodeReplacementTemplate>,
) -> Result<C66Run, ComponentGraphPrincipalLifecycleError> {
    {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let validation = exact_c66_template(&template);
        system.restore();
        validation?;
    }
    let reports = c66_semantic_reports(&template)?;
    let mut current_plans = checked_plan(template.current_graph())?;
    let candidate_plans = checked_plan(template.candidate_graph())?;
    if current_plans.len() != C66_NODE_COUNT || candidate_plans.len() != C66_NODE_COUNT {
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementPolicy);
    }
    let mut candidate_plan = candidate_plans[C66_TARGET_INDEX];
    let resource_generation = reserve_resource_generations(C66_INCARNATION_COUNT)?;
    for (index, plan) in current_plans.iter_mut().enumerate() {
        plan.resource_generation = resource_generation
            .checked_add(index as u64)
            .ok_or(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    }
    candidate_plan.resource_generation = resource_generation
        .checked_add(C66_NODE_COUNT as u64)
        .ok_or(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;

    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut all_plans = Vec::new();
    if all_plans.try_reserve_exact(C66_INCARNATION_COUNT).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    all_plans.extend_from_slice(&current_plans);
    all_plans.push(candidate_plan);
    system.restore();
    let domains = create_domains(&all_plans)?;
    if domains.len() != C66_INCARNATION_COUNT {
        let _ = super::release_empty_domains(&domains);
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
    }
    let tokens = match reserve_registry_batch(&domains) {
        Ok(tokens) if tokens.len() == C66_INCARNATION_COUNT => tokens,
        Ok(tokens) => {
            let _ = abort_pristine_registry_batch(&tokens, &domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
        Err(_) => {
            let _ = super::release_empty_domains(&domains);
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementCapacity);
        }
    };
    let pairs = (|| {
        let old = publication_pairs(&tokens[..C66_NODE_COUNT], &domains[..C66_NODE_COUNT])?;
        let candidate = publication_pairs(
            core::slice::from_ref(&tokens[C66_NODE_COUNT]),
            core::slice::from_ref(&domains[C66_NODE_COUNT]),
        )?;
        Ok((old, candidate))
    })();
    let (old_pairs, candidate_pairs) = match pairs {
        Ok(pairs) => pairs,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let mut candidate_batch = PreparedTaskBatch::new();
    let mut old_batch = PreparedTaskBatch::new();
    let scheduler_reserved = candidate_batch
        .reserve_managed_publication(&candidate_pairs, 0)
        .and_then(|_| candidate_batch.reserve_managed_task_ledgers(1, 0, 0))
        .is_ok()
        && old_batch
            .reserve_managed_publication(&old_pairs, 1)
            .and_then(|_| old_batch.reserve_managed_task_ledgers(1, 5, 1))
            .is_ok();
    if !scheduler_reserved {
        drop(candidate_batch);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::SchedulerReservation);
    }

    let streams = [
        ByteStream::new(),
        ByteStream::new(),
        ByteStream::new(),
        ByteStream::new(),
    ];
    let supervisors = [
        streams[0].supervisor(),
        streams[1].supervisor(),
        streams[2].supervisor(),
        streams[3].supervisor(),
    ];
    let old_source_writer = streams[0].writer();
    let old_target_reader = streams[0].reader();
    let old_target_writer = streams[1].writer();
    let old_sink_reader = streams[1].reader();
    let fresh_source_writer = streams[2].writer();
    let candidate_reader = streams[2].reader();
    let candidate_writer = streams[3].writer();
    let fresh_sink_reader = streams[3].reader();

    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let table_result = (|| {
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
        let candidate = ResourceTable::new(
            candidate_plan.resource_generation,
            candidate_plan.resource_slots,
        )
        .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        if !c66_preflight_reusable_slot(&mut source) || !c66_preflight_reusable_slot(&mut sink) {
            return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
        }
        Ok((source, old_target, sink, candidate))
    })();
    system.restore();
    let (mut source_table, mut old_target_table, mut sink_table, mut candidate_table) =
        match table_result {
            Ok(tables) => tables,
            Err(error) => {
                drop(candidate_batch);
                drop(old_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(error);
            }
        };

    let authorities = (|| {
        let source = c66_prepare_writer(tokens[0], old_source_writer)?;
        let old_target = c66_prepare_relay(tokens[1], old_target_reader, old_target_writer)?;
        let sink = c66_prepare_reader(tokens[2], old_sink_reader)?;
        let candidate = c66_prepare_relay(tokens[3], candidate_reader, candidate_writer)?;
        Ok((source, old_target, sink, candidate))
    })();
    let (source_authority, old_target_authorities, sink_authority, candidate_authorities) =
        match authorities {
            Ok(authorities) => authorities,
            Err(error) => {
                drop(candidate_batch);
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
        let candidate_reader = candidate_table
            .insert_owned(C66_RELAY_READER_TYPE, candidate_authorities.0)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        let candidate_writer = candidate_table
            .insert_owned(C66_RELAY_WRITER_TYPE, candidate_authorities.1)
            .map_err(|_| ComponentGraphPrincipalLifecycleError::NodeReplacementSetup)?;
        Ok((
            source,
            old_target_reader,
            old_target_writer,
            sink,
            candidate_reader,
            candidate_writer,
        ))
    })();
    system.restore();
    let (
        source_token,
        old_target_reader_token,
        old_target_writer_token,
        sink_token,
        candidate_reader_token,
        candidate_writer_token,
    ) = match inserted {
        Ok(tokens) => tokens,
        Err(error) => {
            drop(candidate_batch);
            drop(old_batch);
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let stale_replacement_tokens = candidate_table
        .contains(old_target_reader_token, C66_RELAY_READER_TYPE)
        == Err(ResourceError::WrongInstance)
        && candidate_table.contains(old_target_writer_token, C66_RELAY_WRITER_TYPE)
            == Err(ResourceError::WrongInstance);
    let fresh_resources = stale_replacement_tokens
        && source_table.len() == 1
        && old_target_table.len() == 2
        && sink_table.len() == 1
        && candidate_table.len() == 2
        && candidate_table.instance_generation() != old_target_table.instance_generation()
        && !Arc::ptr_eq(&streams[0], &streams[2])
        && !Arc::ptr_eq(&streams[1], &streams[3]);
    if !fresh_resources {
        drop(candidate_batch);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }

    let probes = (
        super::super::component_instances::registry().acceptance_probe(tokens[0]),
        super::super::component_instances::registry().acceptance_probe(tokens[1]),
        super::super::component_instances::registry().acceptance_probe(tokens[2]),
        super::super::component_instances::registry().acceptance_probe(tokens[3]),
    );
    let (Some(source_probe), Some(old_target_probe), Some(sink_probe), Some(candidate_probe)) =
        probes
    else {
        drop(candidate_batch);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    };
    let fresh_generation = !tokens[1].shares_stable_slot(tokens[3]);
    let fresh_cspace = !old_target_probe.same_space_object(candidate_probe)
        && !old_target_probe.same_cspace_lock(candidate_probe)
        && !old_target_probe.same_cspace_identity(candidate_probe);
    let fresh_arena = domains[1].arena != domains[3].arena;

    let generation =
        match NEXT_C66_GENERATION.try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            c66_phase_word(next, C66_PHASE_OLD)?;
            next.checked_add(1)
        }) {
            Ok(generation) => generation,
            Err(_) => {
                drop(candidate_batch);
                drop(old_batch);
                abort_pristine_registry_batch(&tokens, &domains)?;
                return Err(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted);
            }
        };
    if !C66_AUDIT.reset(generation)
        || !c66_increment(&C66_AUDIT.stale_replacement_tokens, generation)
        || !c66_increment(&C66_AUDIT.stale_replacement_tokens, generation)
    {
        drop(candidate_batch);
        drop(old_batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::NodeReplacementSetup);
    }

    drop(template);
    let registry = super::super::component_instances::registry();
    unsafe {
        candidate_batch.prepare_managed_instance_owned(
            tokens[3],
            domains[3],
            PRINCIPAL_TASK_NAME,
            C66Task {
                token: tokens[3],
                generation,
            },
        );
    }
    let candidate_handle = candidate_batch.prepared_handles()[0].clone();
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
    let fresh_task = old_handles[1].id() != candidate_handle.id()
        && !old_handles[1].shares_status_with(&candidate_handle);
    if !fresh_generation || !fresh_cspace || !fresh_task || !fresh_arena {
        lifecycle_invariant_failed(&tokens, "C6.6 candidate identity was not fresh");
    }
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
    if unsafe {
        registry.install_payload(tokens[0], || {
            C66Payload::new(
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
            )
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 source payload installation failed");
    }
    if unsafe {
        registry.install_payload(tokens[1], || {
            C66Payload::new(
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
            )
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 old target payload installation failed");
    }
    if unsafe {
        registry.install_payload(tokens[2], || {
            C66Payload::new(
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
            )
        })
    }
    .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 sink payload installation failed");
    }
    if unsafe {
        registry.install_payload(tokens[3], || {
            C66Payload::new(
                generation,
                tokens[3],
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
        lifecycle_invariant_failed(&tokens, "C6.6 candidate payload installation failed");
    }

    if registry
        .bind_batch(
            core::slice::from_ref(&tokens[3]),
            candidate_batch.prepared_reclaimable_bindings(),
            candidate_batch.prepared_handles(),
        )
        .is_err()
    {
        lifecycle_invariant_failed(&tokens, "C6.6 candidate binding failed");
    }
    if registry
        .bind_batch(
            &tokens[..C66_NODE_COUNT],
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
    let supervisor = C66Supervisor {
        generation,
        candidate_batch,
        candidate_token: tokens[3],
        candidate_handle,
        old_tokens: [tokens[0], tokens[1], tokens[2]],
        old_handles: old_handles.clone(),
        sibling_domains: [domains[0], domains[2]],
        source_probe,
        old_target_probe,
        sink_probe,
        candidate_probe,
        streams,
        supervisors,
        fresh_source_writer,
        fresh_sink_reader,
        fresh_source_publisher,
        fresh_sink_publisher,
        fresh_source_handoff_audit,
        fresh_sink_handoff_audit,
        reports,
        completion: completion.clone(),
        fresh_generation,
        fresh_cspace,
        fresh_task,
        fresh_arena,
        fresh_resources,
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    old_batch.prepare("wasm-c66-node-replacement-supervisor", async move {
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
    {
        lifecycle_invariant_failed(&tokens, "C6.6 old publication identities changed");
    }
    let supervisor = published
        .pop()
        .expect("validated C6.6 publication contains its supervisor");
    drop(published);
    Ok(C66Run {
        supervisor,
        completion,
    })
}

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
