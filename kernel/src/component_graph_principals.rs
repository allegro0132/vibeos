//! Fresh, separately supervised kernel principals for one admitted Component graph.
//!
//! Every node receives a distinct owner, tracked arena, registry generation,
//! CSpace, task, resource table, and fuel envelope, but its payload never
//! decodes, instantiates, or calls guest code. C6.4 may additionally prepare an
//! exact admitted resource edge while both node reservations are unpublished:
//! the supervisor proves one invocation-scoped borrow and one attenuated owned
//! transfer before either payload becomes runnable, then proves target-first
//! exact revocation before publishing reports. The only successful terminal
//! remains the semantic `RuntimeUnavailable` report supplied by the sealed
//! command template.

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::fmt;
use core::future::Future;
use core::pin::Pin;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use core::sync::atomic::{AtomicBool, AtomicU8};
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use vibeos_component_command::{
    ComponentGraphNodeTerminal, ComponentGraphNodeTerminalReport, ComponentGraphPrincipalIsolation,
    ComponentGraphPrincipalTemplate,
};
use vibeos_component_runtime::graph::ComponentGraphNodeId;
use vibeos_component_runtime::resource::{ResourceTable, ResourceToken, ResourceTypeId};
#[cfg(any(
    feature = "wasm-c63-graph-principal-acceptance",
    feature = "wasm-c64-resource-route-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
use vibeos_component_runtime::{graph::ComponentGraphNesting, world::WorldContract};

#[cfg(any(
    feature = "wasm-c63-graph-principal-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
use vibeos_component_admission::admit_component_graph;
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
use vibeos_component_admission::{
    admit_component_graph_with_resource_policy, ComponentGraphResourceEdgePolicy,
    ComponentGraphResourceMode,
};
#[cfg(any(
    feature = "wasm-c63-graph-principal-acceptance",
    feature = "wasm-c64-resource-route-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
use vibeos_component_admission::{
    ArtifactTrust, CallerAuthority, ComponentArtifact, ComponentGraphAdmissionPolicy,
    ComponentGraphCyclePolicy, ComponentGraphNodeAdmissionPolicy, InstanceLimits, ProfileIdentity,
};
use vibeos_component_host::ComponentAuthority;
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
use vibeos_component_host::{prepare_owned_supervised, with_supervised_borrow};
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
use vibeos_component_host::{ComponentHostResource, HostResourceKind};
#[cfg(any(
    feature = "wasm-c64-resource-route-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
use vibeos_component_runtime::graph::{
    ComponentGraphEdgeSpec, ComponentGraphEntityIndex, ComponentGraphExportEndpoint,
    ComponentGraphImportEndpoint,
};
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
use vibeos_core::cap::Resource;
#[cfg(any(
    feature = "wasm-c64-resource-route-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
use vibeos_core::cap::Rights;
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
use vibeos_image_policy::C64_RESOURCE_ROUTE_QEMU_ACCEPTANCE;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use vibeos_image_policy::C65_ASYNC_CHAIN_QEMU_ACCEPTANCE;

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use vibeos_component_host::{
    ByteStream, ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter, StreamCloseOutcome,
    StreamCloseReason, StreamReceiveCommit, StreamReceiveDispatch, StreamSendDispatch,
    StreamWakeRegistration,
};
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use vibeos_component_runtime::host::{AtomicHostOperationSlot, HostOperationToken, HostWakeToken};

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use crate::exec::OneShotWaitQueue;
use crate::exec::{PreparedTaskBatch, TaskHandle, TaskState};
use crate::heap::{AllocationDomain, FreshDomainBatchError, OwnerId};
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
use crate::instance::{
    InstanceContinuation, InstanceContinuationKind, InstanceContinuationSignal,
    InstanceContinuationToken,
};
use crate::instance::{
    InstancePayload, InstanceSpace, InstanceToken, TerminalRetireKind, MAX_COMPONENT_INSTANCES,
};
use crate::sync::SpinLock;
use crate::HEAP;

/// Audited non-guest storage allowance for one graph-node lifecycle.
///
/// This frozen 64-KiB charge covers the managed task future, registry payload,
/// bounded resource table, and lifecycle bookkeeping allocated in the
/// node's tracked arena. It is added with `checked_add` to the owner quota. The
/// admitted guest-memory ceiling remains a separate field in the payload and
/// is never enlarged by this allowance.
pub const COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES: usize = 64 * 1024;

const PRINCIPAL_CSPACE_NAME: &str = "wasm-graph-principal";
const PRINCIPAL_TASK_NAME: &str = "wasm-graph-principal";
const RUNTIME_UNAVAILABLE_COMPLETION: u64 = 0x5649_4245_4336_0300;
const INVALID_ENVELOPE_COMPLETION: u64 = 0x5649_4245_4336_FFFF;
const RUNTIME_UNAVAILABLE_GUEST_CALL_MASK: u64 = 0xFF;

const fn encode_runtime_unavailable_completion(guest_calls: u64) -> u64 {
    if guest_calls > RUNTIME_UNAVAILABLE_GUEST_CALL_MASK {
        INVALID_ENVELOPE_COMPLETION
    } else {
        RUNTIME_UNAVAILABLE_COMPLETION | guest_calls
    }
}

const fn completion_guest_calls(completion: u64) -> Option<u64> {
    if completion & !RUNTIME_UNAVAILABLE_GUEST_CALL_MASK == RUNTIME_UNAVAILABLE_COMPLETION {
        Some(completion & RUNTIME_UNAVAILABLE_GUEST_CALL_MASK)
    } else {
        None
    }
}

static NEXT_RESOURCE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
const C64_SOURCE_RESOURCE_TYPE: ResourceTypeId = ResourceTypeId(0xC6_04_0001);
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
const C64_TARGET_RESOURCE_TYPE: ResourceTypeId = ResourceTypeId(0xC6_04_0002);
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
const C64_ROUTE_PROBE_VALUE: u32 = 0xC604_0001;
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
const C64_RESOURCE_ROUTE_WIT_SHA256: [u8; 32] = [
    0x07, 0x16, 0xe0, 0x79, 0x84, 0x89, 0x6d, 0xf8, 0x3b, 0xc2, 0x6a, 0x82, 0x82, 0x23, 0x6e, 0x6d,
    0xfa, 0x70, 0x8b, 0xf6, 0x71, 0x92, 0x85, 0x3b, 0xd8, 0xcd, 0x84, 0x79, 0xcc, 0xec, 0x13, 0x41,
];

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_ASYNC_CHAIN_WIT_SHA256: [u8; 32] = [
    0x05, 0x3e, 0x44, 0x72, 0x9a, 0x38, 0x75, 0x45, 0xf5, 0xdc, 0x73, 0xba, 0xc2, 0x11, 0xd3, 0x07,
    0xde, 0x74, 0x6a, 0x4c, 0xf7, 0x58, 0xd1, 0x79, 0xc0, 0xfa, 0x3c, 0xf2, 0xb9, 0xe8, 0xc5, 0xbf,
];
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_SOURCE_WRITER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_05_0001);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_RELAY_READER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_05_0002);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_RELAY_WRITER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_05_0003);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_SINK_READER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_05_0004);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_SINK_WRITER_TYPE: ResourceTypeId = ResourceTypeId(0xC6_05_0005);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_NODE_COUNT: usize = 3;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_ALL_NODES_MASK: u8 = (1 << C65_NODE_COUNT) - 1;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_HOST_WAKE_TAG: usize = 0x4336_3548_4f53_5457;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_SOURCE_FIRST_BYTE: u8 = 0x10;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_RELAY_XOR: u8 = 0x5a;
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
const C65_EXPECTED_HOST_FIRST_BYTE: u8 = (C65_SOURCE_FIRST_BYTE ^ C65_RELAY_XOR).wrapping_add(1);

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static NEXT_C65_SCENARIO_GENERATION: AtomicU64 = AtomicU64::new(1);
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static C65_HOST_READY: OneShotWaitQueue = OneShotWaitQueue::new();
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static C65_ALL_PARKED: OneShotWaitQueue = OneShotWaitQueue::new();
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static C65_FAILURE: OneShotWaitQueue = OneShotWaitQueue::new();
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static C65_WAIT_SLOTS: [[AtomicHostOperationSlot; 2]; C65_NODE_COUNT] = [
    [
        AtomicHostOperationSlot::new(),
        AtomicHostOperationSlot::new(),
    ],
    [
        AtomicHostOperationSlot::new(),
        AtomicHostOperationSlot::new(),
    ],
    [
        AtomicHostOperationSlot::new(),
        AtomicHostOperationSlot::new(),
    ],
];

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
struct C64RouteProbe(u32);

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
impl Resource for C64RouteProbe {
    fn kind(&self) -> &'static str {
        "c64-supervised-route-probe"
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
impl ComponentHostResource for C64RouteProbe {
    const HOST_KIND: HostResourceKind = HostResourceKind::Blob;
    const OPERATION_RIGHTS: Rights = Rights::READ;
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
struct C65AuditState {
    generation: AtomicU64,
    parked_mask: AtomicU8,
    completed_mask: AtomicU8,
    propagation: [AtomicU8; C65_NODE_COUNT],
    propagation_len: AtomicU8,
    wake_registrations: AtomicU64,
    wake_callbacks: AtomicU64,
    continuation_resumes: AtomicU64,
    sealed_resumes: AtomicU64,
    host_wakes: AtomicU64,
    productive_self_wakes: AtomicU64,
    source_chunks: AtomicU64,
    relay_chunks: AtomicU64,
    sink_chunks: AtomicU64,
    completion_reasons: [AtomicU8; C65_NODE_COUNT],
    no_active_repoll: AtomicBool,
    failed: AtomicBool,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy)]
struct C65AuditSnapshot {
    generation: u64,
    parked_mask: u8,
    completed_mask: u8,
    propagation: [u8; C65_NODE_COUNT],
    propagation_len: u8,
    wake_registrations: u64,
    wake_callbacks: u64,
    continuation_resumes: u64,
    sealed_resumes: u64,
    host_wakes: u64,
    productive_self_wakes: u64,
    source_chunks: u64,
    relay_chunks: u64,
    sink_chunks: u64,
    completion_reasons: [u8; C65_NODE_COUNT],
    no_active_repoll: bool,
    failed: bool,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
impl C65AuditState {
    const fn empty() -> Self {
        Self {
            generation: AtomicU64::new(0),
            parked_mask: AtomicU8::new(0),
            completed_mask: AtomicU8::new(0),
            propagation: [const { AtomicU8::new(0) }; C65_NODE_COUNT],
            propagation_len: AtomicU8::new(0),
            wake_registrations: AtomicU64::new(0),
            wake_callbacks: AtomicU64::new(0),
            continuation_resumes: AtomicU64::new(0),
            sealed_resumes: AtomicU64::new(0),
            host_wakes: AtomicU64::new(0),
            productive_self_wakes: AtomicU64::new(0),
            source_chunks: AtomicU64::new(0),
            relay_chunks: AtomicU64::new(0),
            sink_chunks: AtomicU64::new(0),
            completion_reasons: [const { AtomicU8::new(0) }; C65_NODE_COUNT],
            no_active_repoll: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    fn reset(&self, generation: u64) -> bool {
        let previous = self.generation.load(Ordering::Acquire);
        if generation == 0 || (previous != 0 && previous >= generation) {
            return false;
        }
        self.failed.store(true, Ordering::Release);
        self.parked_mask.store(0, Ordering::Release);
        self.completed_mask.store(0, Ordering::Release);
        for entry in &self.propagation {
            entry.store(0, Ordering::Release);
        }
        self.propagation_len.store(0, Ordering::Release);
        self.wake_registrations.store(0, Ordering::Release);
        self.wake_callbacks.store(0, Ordering::Release);
        self.continuation_resumes.store(0, Ordering::Release);
        self.sealed_resumes.store(0, Ordering::Release);
        self.host_wakes.store(0, Ordering::Release);
        self.productive_self_wakes.store(0, Ordering::Release);
        self.source_chunks.store(0, Ordering::Release);
        self.relay_chunks.store(0, Ordering::Release);
        self.sink_chunks.store(0, Ordering::Release);
        for entry in &self.completion_reasons {
            entry.store(0, Ordering::Release);
        }
        self.no_active_repoll.store(false, Ordering::Release);
        self.generation.store(generation, Ordering::Release);
        self.failed.store(false, Ordering::Release);
        true
    }

    fn snapshot(&self) -> C65AuditSnapshot {
        C65AuditSnapshot {
            generation: self.generation.load(Ordering::Acquire),
            parked_mask: self.parked_mask.load(Ordering::Acquire),
            completed_mask: self.completed_mask.load(Ordering::Acquire),
            propagation: core::array::from_fn(|index| {
                self.propagation[index].load(Ordering::Acquire)
            }),
            propagation_len: self.propagation_len.load(Ordering::Acquire),
            wake_registrations: self.wake_registrations.load(Ordering::Acquire),
            wake_callbacks: self.wake_callbacks.load(Ordering::Acquire),
            continuation_resumes: self.continuation_resumes.load(Ordering::Acquire),
            sealed_resumes: self.sealed_resumes.load(Ordering::Acquire),
            host_wakes: self.host_wakes.load(Ordering::Acquire),
            productive_self_wakes: self.productive_self_wakes.load(Ordering::Acquire),
            source_chunks: self.source_chunks.load(Ordering::Acquire),
            relay_chunks: self.relay_chunks.load(Ordering::Acquire),
            sink_chunks: self.sink_chunks.load(Ordering::Acquire),
            completion_reasons: core::array::from_fn(|index| {
                self.completion_reasons[index].load(Ordering::Acquire)
            }),
            no_active_repoll: self.no_active_repoll.load(Ordering::Acquire),
            failed: self.failed.load(Ordering::Acquire),
        }
    }

    fn mark_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn matches_live_generation(&self, generation: u64) -> bool {
        generation != 0
            && self.generation.load(Ordering::Acquire) == generation
            && !self.failed.load(Ordering::Acquire)
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
static C65_AUDIT: C65AuditState = C65AuditState::empty();

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C65NodeKind {
    Source,
    Relay,
    Sink,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy)]
struct C65PrincipalRoute {
    generation: u64,
    instance: InstanceToken,
    kind: C65NodeKind,
    input: Option<PrincipalResourceDrain>,
    output: PrincipalResourceDrain,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C65TransferPhase {
    Transfer,
    Write(u8),
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C65WaitKind {
    Receive,
    Send(u8),
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
impl C65WaitKind {
    const fn slot_index(self) -> usize {
        match self {
            Self::Receive => 0,
            Self::Send(_) => 1,
        }
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
struct C65PendingWait {
    token: InstanceContinuationToken,
    continuation: InstanceContinuation<'static>,
    registration: StreamWakeRegistration,
    kind: C65WaitKind,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
struct C65AsyncPayload {
    route: C65PrincipalRoute,
    phase: C65TransferPhase,
    next_source_byte: u8,
    waiting: Option<C65PendingWait>,
    completed: bool,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
struct C65SupervisorControl {
    generation: u64,
    cause: StreamCloseReason,
    host_reader: Arc<ByteStreamReader>,
    host_registration: Option<StreamWakeRegistration>,
    streams: [Arc<ByteStream>; C65_NODE_COUNT],
    supervisors: [Arc<ByteStreamSupervisor>; C65_NODE_COUNT],
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C65AsyncChainReceipt {
    cause: StreamCloseReason,
    wake_registrations: u64,
    wake_callbacks: u64,
    continuation_resumes: u64,
    sealed_resumes: u64,
    productive_self_wakes: u64,
    source_chunks: u64,
    relay_chunks: u64,
    sink_chunks: u64,
    peak_depths: [usize; C65_NODE_COUNT],
    no_active_repoll: bool,
}

/// A public lifecycle failure contains only a semantic graph-local node and a
/// bounded classification. It never formats a TaskId, owner, arena, registry
/// token, CSpace identity/incarnation, resource handle/generation, or Cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComponentGraphPrincipalLifecycleError {
    Revalidation,
    AuthorityBearingGraph,
    ResourceRouteRequired,
    ResourceRoutePolicy,
    ResourceRouteSetup,
    AsyncRouteRequired,
    AsyncRoutePolicy,
    AsyncRouteSetup,
    AsyncChainInvariant,
    ExecutableTemplate,
    InvalidPrincipalSet,
    BudgetOverflow { node: ComponentGraphNodeId },
    ResourceGenerationExhausted,
    ResourceTableUnavailable { node: ComponentGraphNodeId },
    Allocation,
    DomainBatchUnavailable,
    RegistryReservation,
    SchedulerReservation,
    PayloadInstall { node: ComponentGraphNodeId },
    RegistryBinding,
    AtomicPublication,
    SupervisorUnavailable,
    TaskTerminal { node: ComponentGraphNodeId },
    TerminalTeardown { node: ComponentGraphNodeId },
    SemanticReport { node: ComponentGraphNodeId },
    UnpublishedCleanup,
}

impl fmt::Display for ComponentGraphPrincipalLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Revalidation => "component graph principal revalidation failed",
            Self::AuthorityBearingGraph => {
                "component graph cannot materialize unresolved live authority grants"
            }
            Self::ResourceRouteRequired => {
                "resource-bearing graph requires an explicit supervisor route"
            }
            Self::ResourceRoutePolicy => "component graph resource route is not exact",
            Self::ResourceRouteSetup => "component graph resource route setup failed",
            Self::AsyncRouteRequired => "async-bearing graph requires an explicit supervisor route",
            Self::AsyncRoutePolicy => "component graph async route is not exact",
            Self::AsyncRouteSetup => "component graph async route setup failed",
            Self::AsyncChainInvariant => "component graph async chain invariant failed",
            Self::ExecutableTemplate => {
                "component graph lifecycle accepts only a validation-only template"
            }
            Self::InvalidPrincipalSet => "component graph principal set is invalid",
            Self::BudgetOverflow { .. } => "component graph principal budget overflowed",
            Self::ResourceGenerationExhausted => {
                "component graph resource generation space is exhausted"
            }
            Self::ResourceTableUnavailable { .. } => {
                "component graph resource table could not be created"
            }
            Self::Allocation => "component graph lifecycle metadata allocation failed",
            Self::DomainBatchUnavailable => {
                "component graph allocation domains could not be created atomically"
            }
            Self::RegistryReservation => {
                "component graph registry slots could not be reserved atomically"
            }
            Self::SchedulerReservation => {
                "component graph scheduler publication could not be reserved atomically"
            }
            Self::PayloadInstall { .. } => "component graph payload installation failed",
            Self::RegistryBinding => "component graph task binding failed",
            Self::AtomicPublication => "component graph task publication failed",
            Self::SupervisorUnavailable => "component graph supervisor did not terminate exactly",
            Self::TaskTerminal { .. } => "component graph node did not terminate exactly",
            Self::TerminalTeardown { .. } => "component graph node teardown failed",
            Self::SemanticReport { .. } => "component graph semantic report is invalid",
            Self::UnpublishedCleanup => "component graph unpublished cleanup failed",
        })
    }
}

/// Immutable semantic results published only after every node has completed
/// exact registry finalization and allocator retirement.
pub struct ComponentGraphPrincipalReports {
    reports: Vec<ComponentGraphNodeTerminalReport>,
    teardown: Vec<PrincipalTeardownReceipt>,
    guest_calls: u64,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    async_chain: Option<C65AsyncChainReceipt>,
}

struct PrincipalCompletion {
    result: SpinLock<
        Option<Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>>,
    >,
}

impl PrincipalCompletion {
    const fn new() -> Self {
        Self {
            result: SpinLock::new(None),
        }
    }

    fn publish(
        &self,
        result: Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>,
    ) {
        let mut slot = self.result.lock();
        assert!(slot.is_none(), "graph principal result published twice");
        *slot = Some(result);
    }

    fn take(
        &self,
    ) -> Option<Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError>> {
        self.result.lock().take()
    }
}

/// Non-authoritative observation handle for one atomically published graph.
///
/// Dropping this handle never cancels a node or its SYSTEM supervisor. The
/// scheduler-owned supervisor retains the only node TaskHandles and completes
/// exact teardown even when the caller loses interest in the result.
pub struct ComponentGraphPrincipalRun {
    supervisor: TaskHandle,
    completion: Arc<PrincipalCompletion>,
}

impl ComponentGraphPrincipalRun {
    pub async fn wait(
        self,
    ) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
        let exit = self.supervisor.join().await;
        if exit.state() != TaskState::Exited {
            return Err(ComponentGraphPrincipalLifecycleError::SupervisorUnavailable);
        }
        self.completion.take().unwrap_or(Err(
            ComponentGraphPrincipalLifecycleError::SupervisorUnavailable,
        ))
    }
}

impl fmt::Debug for ComponentGraphPrincipalRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentGraphPrincipalRun")
            .field("supervisor_state", &self.supervisor.state())
            .finish_non_exhaustive()
    }
}

impl ComponentGraphPrincipalReports {
    pub fn nodes(&self) -> &[ComponentGraphNodeTerminalReport] {
        &self.reports
    }

    pub fn node(&self, node: ComponentGraphNodeId) -> Option<&ComponentGraphNodeTerminalReport> {
        self.reports.iter().find(|report| report.node() == node)
    }

    /// Exact guest-call attempts encoded by the terminal payload receipts.
    pub const fn guest_calls(&self) -> u64 {
        self.guest_calls
    }
}

impl fmt::Debug for ComponentGraphPrincipalReports {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ComponentGraphPrincipalReports");
        debug
            .field("nodes", &self.reports)
            .field("guest_calls", &self.guest_calls);
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        debug.field("async_chain", &self.async_chain);
        debug.finish()
    }
}

#[derive(Clone, Copy)]
struct PrincipalPlan {
    node: ComponentGraphNodeId,
    owner_quota: usize,
    guest_memory_limit: usize,
    fuel_limit: u64,
    poll_quantum: u64,
    resource_types: u64,
    resource_slots: u16,
    resource_generation: u64,
    expected_resource_peak: u64,
    expected_revoked_capabilities: usize,
    drains: [Option<PrincipalResourceDrain>; 2],
    report_kind: PrincipalReportKind,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    async_route: Option<C65PrincipalRoute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrincipalReportKind {
    Ordinary,
    ResourceRoute,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    AsyncChain,
}

#[derive(Clone, Copy)]
struct PrincipalResourceDrain {
    token: ResourceToken,
    resource_type: ResourceTypeId,
}

#[derive(Clone, Copy)]
struct ResourceRoutePlan {
    source_index: usize,
    target_index: usize,
}

#[derive(Clone, Copy)]
enum ResourceRouteRequest {
    None,
    #[cfg(feature = "wasm-c64-resource-route-acceptance")]
    C64Exact,
}

#[derive(Clone, Copy)]
enum AsyncRouteRequest {
    None,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    C65Exact {
        cause: StreamCloseReason,
    },
}

#[derive(Clone, Copy)]
enum AsyncRoutePlan {
    None,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    C65Exact {
        cause: StreamCloseReason,
    },
}

#[derive(Clone, Copy)]
struct ResourceRouteReceipt {
    borrow_invocations: u64,
    owned_transfers: u64,
    attenuated_grants: u64,
    source_peak_slots: u64,
    target_peak_slots: u64,
    borrow_source_caps_before: u64,
    borrow_source_caps_after: u64,
    borrow_target_caps_before: u64,
    borrow_target_caps_after: u64,
    source_caps_after_transfer: u64,
    target_caps_after_transfer: u64,
    source_live_after_transfer: u64,
    target_live_after_transfer: u64,
    target_grant_absent: bool,
}

struct PrincipalSupervisor {
    plans: Vec<PrincipalPlan>,
    tokens: Vec<InstanceToken>,
    handles: Vec<TaskHandle>,
    teardown_order: Vec<usize>,
    states: Vec<TaskState>,
    teardown: Vec<PrincipalTeardownReceipt>,
    reports: Vec<ComponentGraphNodeTerminalReport>,
    completion: Arc<PrincipalCompletion>,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    async_control: Option<C65SupervisorControl>,
}

#[derive(Clone, Copy)]
struct PrincipalTeardownReceipt {
    node: ComponentGraphNodeId,
    revoked_capabilities: usize,
    guest_calls: u64,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
async fn c65_wait_for_stage(
    expected: &'static OneShotWaitQueue,
    unexpected: Option<&'static OneShotWaitQueue>,
    generation: u64,
    handles: &[TaskHandle],
) -> bool {
    if handles.len() != C65_NODE_COUNT {
        return false;
    }
    let mut expected = expected.wait(generation);
    let mut unexpected = unexpected.map(|queue| queue.wait(generation));
    let mut failure = C65_FAILURE.wait(generation);
    let mut joins: [_; C65_NODE_COUNT] = core::array::from_fn(|index| handles[index].join());
    core::future::poll_fn(|context| {
        if C65_AUDIT.failed.load(Ordering::Acquire) {
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
            Poll::Ready(Ok(())) => return Poll::Ready(true),
            Poll::Ready(Err(_)) => return Poll::Ready(false),
            Poll::Pending => {}
        }
        if let Some(unexpected) = unexpected.as_mut() {
            if Pin::new(unexpected).poll(context).is_ready() {
                return Poll::Ready(false);
            }
        }
        Poll::Pending
    })
    .await
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
async fn c65_join_or_failure(handle: &TaskHandle, generation: u64) -> Result<TaskState, ()> {
    let mut join = handle.join();
    let mut failure = C65_FAILURE.wait(generation);
    core::future::poll_fn(|context| {
        if C65_AUDIT.failed.load(Ordering::Acquire)
            || Pin::new(&mut failure).poll(context).is_ready()
        {
            return Poll::Ready(Err(()));
        }
        match Pin::new(&mut join).poll(context) {
            Poll::Ready(exit) => Poll::Ready(Ok(exit.state())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_wait_slots_empty() -> bool {
    C65_WAIT_SLOTS
        .iter()
        .flatten()
        .all(AtomicHostOperationSlot::is_empty)
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
impl C65SupervisorControl {
    fn fail_open_streams(&self) {
        for supervisor in self.supervisors.iter().rev() {
            let _ = supervisor.finalize_preserving_first_observed(StreamCloseReason::BackendFault);
        }
    }

    fn cancel_mirrored_waits(&self) {
        for node in (0..C65_NODE_COUNT).rev() {
            if let Some(operation) = C65_WAIT_SLOTS[node][0].load() {
                if node != 0 {
                    let _ = self.supervisors[node - 1].cancel_reader_operation_exact(operation);
                }
                let _ = C65_WAIT_SLOTS[node][0].clear_exact(operation);
            }
            if let Some(operation) = C65_WAIT_SLOTS[node][1].load() {
                let _ = self.supervisors[node].cancel_writer_operation_exact(operation);
                let _ = C65_WAIT_SLOTS[node][1].clear_exact(operation);
            }
        }
    }

    fn revoke_terminal_backend_slots(&self) {
        for supervisor in self.supervisors.iter().rev() {
            let _ = supervisor.revoke_pending_after_final();
        }
    }

    fn cleanup_host_wait(&mut self) {
        if let Some(registration) = self.host_registration.take() {
            let _ = self.host_reader.cancel(registration.operation());
            drop(registration);
        }
    }

    fn cleanup_after_failure(&mut self) {
        C65_AUDIT.mark_failed();
        self.fail_open_streams();
        self.cleanup_host_wait();
        self.cancel_mirrored_waits();
        self.revoke_terminal_backend_slots();
    }

    fn fail(&mut self) -> bool {
        self.cleanup_after_failure();
        false
    }

    async fn drive(&mut self, handles: &[TaskHandle]) -> bool {
        if handles.len() != C65_NODE_COUNT || self.host_registration.is_none() {
            return self.fail();
        }
        // An all-parked publication before the first host delivery is also a
        // terminal failure signal: it prevents a lost callback from leaving
        // the supervisor indefinitely parked on HOST_READY.
        if !c65_wait_for_stage(
            &C65_HOST_READY,
            Some(&C65_ALL_PARKED),
            self.generation,
            handles,
        )
        .await
        {
            return self.fail();
        }
        let Some(registration) = self.host_registration.take() else {
            return self.fail();
        };
        let prepared = match self.host_reader.resume_after_wake(registration) {
            Ok(StreamReceiveDispatch::Prepared(prepared)) if prepared.length() == 1 => prepared,
            Ok(_) => return self.fail(),
            Err(failure) => {
                let registration = failure.into_registration();
                let _ = self.host_reader.cancel(registration.operation());
                drop(registration);
                return self.fail();
            }
        };
        let mut first = [0_u8];
        if self.host_reader.commit(prepared.operation(), &mut first)
            != Ok(StreamReceiveCommit::Received(1))
            || first[0] != C65_EXPECTED_HOST_FIRST_BYTE
        {
            return self.fail();
        }

        if !c65_wait_for_stage(&C65_ALL_PARKED, None, self.generation, handles).await {
            return self.fail();
        }
        for _ in 0..8 {
            crate::exec::yield_now().await;
        }
        let parked = C65_AUDIT.snapshot();
        let depths = [
            self.streams[0].depth(),
            self.streams[1].depth(),
            self.streams[2].depth(),
        ];
        if parked.failed
            || parked.parked_mask != C65_ALL_NODES_MASK
            || parked.completed_mask != 0
            || parked.source_chunks != 27
            || parked.relay_chunks != 18
            || parked.sink_chunks != 9
            || depths != [8, 8, 8]
            || parked.wake_registrations.checked_sub(parked.wake_callbacks)
                != Some(C65_NODE_COUNT as u64)
        {
            return self.fail();
        }
        let parked_polls = [handles[0].polls(), handles[1].polls(), handles[2].polls()];
        for _ in 0..16 {
            crate::exec::yield_now().await;
        }
        let stable_audit = C65_AUDIT.snapshot();
        let stable = handles
            .iter()
            .zip(parked_polls)
            .all(|(handle, polls)| handle.polls() == polls)
            && !stable_audit.failed
            && stable_audit.parked_mask == C65_ALL_NODES_MASK
            && stable_audit.completed_mask == 0
            && stable_audit.source_chunks == 27
            && stable_audit.relay_chunks == 18
            && stable_audit.sink_chunks == 9
            && stable_audit.wake_registrations == parked.wake_registrations
            && stable_audit.wake_callbacks == parked.wake_callbacks
            && stable_audit
                .wake_registrations
                .checked_sub(stable_audit.wake_callbacks)
                == Some(C65_NODE_COUNT as u64)
            && [
                self.streams[0].depth(),
                self.streams[1].depth(),
                self.streams[2].depth(),
            ] == [8, 8, 8];
        if !stable {
            return self.fail();
        }
        C65_AUDIT.no_active_repoll.store(true, Ordering::Release);
        if self.supervisors[2].finalize(self.cause) != StreamCloseOutcome::Published
            || C65_AUDIT.failed.load(Ordering::Acquire)
        {
            return self.fail();
        }
        true
    }

    fn finish(
        &self,
        states: &[TaskState],
    ) -> Result<C65AsyncChainReceipt, ComponentGraphPrincipalLifecycleError> {
        let audit = C65_AUDIT.snapshot();
        let peak_depths = [
            self.streams[0].peak_depth(),
            self.streams[1].peak_depth(),
            self.streams[2].peak_depth(),
        ];
        let expected_propagation = [3, 2, 1];
        let exact = audit.generation == self.generation
            && !audit.failed
            && audit.parked_mask == 0
            && audit.completed_mask == C65_ALL_NODES_MASK
            && audit.propagation_len == C65_NODE_COUNT as u8
            && audit.propagation == expected_propagation
            && audit
                .completion_reasons
                .iter()
                .all(|reason| *reason == self.cause as u8 + 1)
            && audit.wake_registrations != 0
            && audit.wake_registrations == audit.wake_callbacks
            && audit.wake_callbacks == audit.continuation_resumes
            && audit.continuation_resumes == audit.sealed_resumes
            && audit.host_wakes == 1
            && audit.productive_self_wakes != 0
            && audit.source_chunks == 27
            && audit.relay_chunks == 18
            && audit.sink_chunks == 9
            && peak_depths == [8, 8, 8]
            && audit.no_active_repoll
            && self
                .supervisors
                .iter()
                .all(|supervisor| supervisor.final_reason() == Some(self.cause))
            && states.len() == C65_NODE_COUNT
            && states.iter().all(|state| *state == TaskState::Exited)
            && c65_wait_slots_empty();
        if !exact {
            return Err(ComponentGraphPrincipalLifecycleError::AsyncChainInvariant);
        }
        Ok(C65AsyncChainReceipt {
            cause: self.cause,
            wake_registrations: audit.wake_registrations,
            wake_callbacks: audit.wake_callbacks,
            continuation_resumes: audit.continuation_resumes,
            sealed_resumes: audit.sealed_resumes,
            productive_self_wakes: audit.productive_self_wakes,
            source_chunks: audit.source_chunks,
            relay_chunks: audit.relay_chunks,
            sink_chunks: audit.sink_chunks,
            peak_depths,
            no_active_repoll: audit.no_active_repoll,
        })
    }
}

impl PrincipalSupervisor {
    async fn run(mut self) {
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        let mut async_drive_ok = match self.async_control.as_mut() {
            Some(control) => control.drive(&self.handles).await,
            None => true,
        };
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        if self.async_control.is_some() && !async_drive_ok {
            for handle in &self.handles {
                if handle.try_exit().is_none() {
                    let _ = handle.exact_wake().wake_if_exact();
                }
            }
        }
        self.states.resize(self.handles.len(), TaskState::Running);
        // Join in the same consumer-first order used by registry finalization.
        // On a C6.5 fault, the first observed non-success immediately opens
        // every stream and exactly wakes remaining payloads so each one can
        // cancel its continuation and perform normal resource Drop. Executor
        // cancellation would detach a live managed payload and force its
        // registry generation into quarantine instead of completing teardown.
        for &index in &self.teardown_order {
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            let state = if let Some(generation) = self
                .async_control
                .as_ref()
                .filter(|_| async_drive_ok)
                .map(|control| control.generation)
            {
                match c65_join_or_failure(&self.handles[index], generation).await {
                    Ok(state) => state,
                    Err(()) => {
                        async_drive_ok = false;
                        if let Some(control) = self.async_control.as_mut() {
                            control.cleanup_after_failure();
                        }
                        for handle in &self.handles {
                            if handle.try_exit().is_none() {
                                let _ = handle.exact_wake().wake_if_exact();
                            }
                        }
                        self.handles[index].join().await.state()
                    }
                }
            } else {
                self.handles[index].join().await.state()
            };
            #[cfg(not(feature = "wasm-c65-async-chain-acceptance"))]
            let state = self.handles[index].join().await.state();
            self.states[index] = state;
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            if self.async_control.is_some()
                && async_drive_ok
                && (state != TaskState::Exited || C65_AUDIT.failed.load(Ordering::Acquire))
            {
                async_drive_ok = false;
                if let Some(control) = self.async_control.as_mut() {
                    control.cleanup_after_failure();
                }
                for handle in &self.handles {
                    if handle.try_exit().is_none() {
                        let _ = handle.exact_wake().wake_if_exact();
                    }
                }
            }
        }
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        let async_receipt = match self.async_control.as_ref() {
            Some(control) if async_drive_ok => control.finish(&self.states).map(Some),
            Some(_) => Err(ComponentGraphPrincipalLifecycleError::AsyncChainInvariant),
            None => Ok(None),
        };
        let result = finalize_all(
            &self.plans,
            &self.tokens,
            &self.handles,
            &self.states,
            &self.teardown_order,
            &mut self.teardown,
        )
        .and_then(|()| {
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            let async_receipt = async_receipt?;
            publish_semantic_reports(
                &self.plans,
                core::mem::take(&mut self.teardown),
                core::mem::take(&mut self.reports),
                #[cfg(feature = "wasm-c65-async-chain-acceptance")]
                async_receipt,
            )
        });
        self.completion.publish(result);
    }
}

struct PrincipalPayload {
    resources: ResourceTable<ComponentAuthority>,
    fuel: PrincipalFuelEnvelope,
    guest_memory_limit: usize,
    expected_resource_peak: u64,
    resource_slot_limit: u16,
    drains: [Option<PrincipalResourceDrain>; 2],
    guest_calls: u64,
    completed: bool,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    async_chain: Option<C65AsyncPayload>,
}

#[derive(Clone, Copy)]
struct PrincipalFuelEnvelope {
    limit: u64,
    poll_quantum: u64,
    consumed: u64,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C65PayloadOutcome {
    Pending,
    Complete,
    InvariantFailure,
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
impl C65NodeKind {
    const fn node(self) -> ComponentGraphNodeId {
        ComponentGraphNodeId::new(match self {
            Self::Source => 0,
            Self::Relay => 1,
            Self::Sink => 2,
        })
    }

    const fn index(self) -> usize {
        self.node().index() as usize
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_with_reader<R>(
    resources: &mut ResourceTable<ComponentAuthority>,
    endpoint: PrincipalResourceDrain,
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

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_with_writer<R>(
    resources: &mut ResourceTable<ComponentAuthority>,
    endpoint: PrincipalResourceDrain,
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

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_stream_wake(words: [usize; 4]) {
    let signal = super::component_instances::registry().signal_continuation_words(words);
    let generation = C65_AUDIT.generation.load(Ordering::Acquire);
    if !c65_increment(&C65_AUDIT.wake_callbacks, generation)
        || signal != InstanceContinuationSignal::Signalled
    {
        c65_publish_failure(generation);
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_publish_failure(generation: u64) {
    if generation == 0 || C65_AUDIT.generation.load(Ordering::Acquire) != generation {
        return;
    }
    C65_AUDIT.mark_failed();
    if let Ok(wake) = C65_FAILURE.publish(generation) {
        let _ = wake.dispatch();
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_increment(counter: &AtomicU64, generation: u64) -> bool {
    if !C65_AUDIT.matches_live_generation(generation) {
        return false;
    }
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .is_ok()
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_mark_parked(route: C65PrincipalRoute) -> bool {
    let bit = 1_u8 << route.kind.index();
    if !C65_AUDIT.matches_live_generation(route.generation)
        || C65_AUDIT.completed_mask.load(Ordering::Acquire) & bit != 0
    {
        c65_publish_failure(route.generation);
        return false;
    }
    if C65_AUDIT
        .parked_mask
        .try_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
            (mask & bit == 0).then_some(mask | bit)
        })
        .is_err()
    {
        c65_publish_failure(route.generation);
        return false;
    }
    if !c65_increment(&C65_AUDIT.wake_registrations, route.generation) {
        c65_publish_failure(route.generation);
        return false;
    }
    let settled = C65_AUDIT.snapshot();
    let publish = settled.parked_mask == C65_ALL_NODES_MASK
        && settled.source_chunks == 27
        && settled.relay_chunks == 18
        && settled.sink_chunks == 9
        && settled
            .wake_registrations
            .checked_sub(settled.wake_callbacks)
            == Some(C65_NODE_COUNT as u64);
    if publish {
        match C65_ALL_PARKED.publish(route.generation) {
            Ok(wake) => {
                let _ = wake.dispatch();
            }
            Err(_) => {
                c65_publish_failure(route.generation);
                return false;
            }
        }
    }
    true
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_mark_resumed(route: C65PrincipalRoute) -> bool {
    let bit = 1_u8 << route.kind.index();
    if !C65_AUDIT.matches_live_generation(route.generation)
        || C65_AUDIT.completed_mask.load(Ordering::Acquire) & bit != 0
    {
        c65_publish_failure(route.generation);
        return false;
    }
    let cleared = C65_AUDIT
        .parked_mask
        .try_update(Ordering::AcqRel, Ordering::Acquire, |mask| {
            (mask & bit != 0).then_some(mask & !bit)
        })
        .is_ok();
    if !cleared || !c65_increment(&C65_AUDIT.continuation_resumes, route.generation) {
        c65_publish_failure(route.generation);
        return false;
    }
    true
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_productive_wake(route: C65PrincipalRoute, context: &Context<'_>) -> bool {
    if !c65_increment(&C65_AUDIT.productive_self_wakes, route.generation) {
        c65_publish_failure(route.generation);
        return false;
    }
    context.waker().wake_by_ref();
    true
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_record_chunk(route: C65PrincipalRoute) -> bool {
    let counter = match route.kind {
        C65NodeKind::Source => &C65_AUDIT.source_chunks,
        C65NodeKind::Relay => &C65_AUDIT.relay_chunks,
        C65NodeKind::Sink => &C65_AUDIT.sink_chunks,
    };
    let recorded = c65_increment(counter, route.generation);
    if !recorded {
        c65_publish_failure(route.generation);
    }
    recorded
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_record_completion(route: C65PrincipalRoute, reason: StreamCloseReason) -> bool {
    let index = route.kind.index();
    let bit = 1_u8 << index;
    let propagation_index = C65_NODE_COUNT - 1 - index;
    if !C65_AUDIT.matches_live_generation(route.generation)
        || C65_AUDIT.parked_mask.load(Ordering::Acquire) & bit != 0
        || C65_AUDIT
            .propagation_len
            .compare_exchange(
                propagation_index as u8,
                propagation_index as u8 + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        || C65_AUDIT.completed_mask.fetch_or(bit, Ordering::AcqRel) & bit != 0
    {
        c65_publish_failure(route.generation);
        return false;
    }
    C65_AUDIT.propagation[propagation_index].store(index as u8 + 1, Ordering::Release);
    C65_AUDIT.completion_reasons[index].store(reason as u8 + 1, Ordering::Release);
    true
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
impl C65AsyncPayload {
    fn new(route: C65PrincipalRoute) -> Self {
        Self {
            route,
            phase: C65TransferPhase::Transfer,
            next_source_byte: C65_SOURCE_FIRST_BYTE,
            waiting: None,
            completed: false,
        }
    }

    fn input(&self) -> Result<PrincipalResourceDrain, ()> {
        self.route.input.ok_or(())
    }

    fn wait_slot(&self, kind: C65WaitKind) -> &'static AtomicHostOperationSlot {
        &C65_WAIT_SLOTS[self.route.kind.index()][kind.slot_index()]
    }

    fn cancel_wait_operation(
        &self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        kind: C65WaitKind,
        operation: HostOperationToken,
    ) -> bool {
        let cancelled = match kind {
            C65WaitKind::Receive => self.input().ok().is_some_and(|input| {
                c65_with_reader(resources, input, space, |reader| reader.cancel(operation))
                    == Ok(Ok(()))
            }),
            C65WaitKind::Send(_) => {
                c65_with_writer(resources, self.route.output, space, |writer| {
                    writer.cancel(operation)
                }) == Ok(Ok(()))
            }
        };
        let slot = self.wait_slot(kind);
        if cancelled {
            let _ = slot.clear_exact(operation);
        }
        cancelled || !slot.contains(operation)
    }

    fn cancel_pending_wait(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
    ) -> bool {
        let Some(waiting) = self.waiting.take() else {
            return true;
        };
        let operation = waiting.registration.operation();
        let cancelled = self.cancel_wait_operation(resources, space, waiting.kind, operation);
        // Backend wake authority is revoked before the TaskStatus-owned
        // continuation listener is dropped.
        drop(waiting);
        cancelled
    }

    fn arm_wait(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        operation: HostOperationToken,
        kind: C65WaitKind,
    ) -> bool {
        let slot = self.wait_slot(kind);
        if !slot.publish(operation) {
            let _ = self.cancel_wait_operation(resources, space, kind, operation);
            return false;
        }
        let token = match super::component_instances::registry()
            .arm_continuation_current(self.route.instance, InstanceContinuationKind::External)
        {
            Ok(token) => token,
            Err(_) => {
                let _ = self.cancel_wait_operation(resources, space, kind, operation);
                return false;
            }
        };
        let mut continuation: InstanceContinuation<'static> =
            match super::component_instances::registry().wait_continuation(token) {
                Ok(continuation) => continuation,
                Err(_) => {
                    let _ = self.cancel_wait_operation(resources, space, kind, operation);
                    return false;
                }
            };
        if Pin::new(&mut continuation).poll(context) != Poll::Pending {
            let _ = self.cancel_wait_operation(resources, space, kind, operation);
            return false;
        }
        let wake = HostWakeToken::new(token.signal_words(), c65_stream_wake);
        let registration = match kind {
            C65WaitKind::Receive => {
                let Ok(input) = self.input() else {
                    let _ = self.cancel_wait_operation(resources, space, kind, operation);
                    return false;
                };
                let Ok(result) = c65_with_reader(resources, input, space, |reader| {
                    reader.register_wake_sealed(operation, wake)
                }) else {
                    let _ = self.cancel_wait_operation(resources, space, kind, operation);
                    return false;
                };
                match result {
                    Ok(registration) => registration,
                    Err(_) => {
                        let _ = self.cancel_wait_operation(resources, space, kind, operation);
                        return false;
                    }
                }
            }
            C65WaitKind::Send(_) => {
                let Ok(result) = c65_with_writer(resources, self.route.output, space, |writer| {
                    writer.register_wake_sealed(operation, wake)
                }) else {
                    let _ = self.cancel_wait_operation(resources, space, kind, operation);
                    return false;
                };
                match result {
                    Ok(registration) => registration,
                    Err(_) => {
                        let _ = self.cancel_wait_operation(resources, space, kind, operation);
                        return false;
                    }
                }
            }
        };
        if !slot.contains(operation) {
            drop(registration);
            drop(continuation);
            return false;
        }
        self.waiting = Some(C65PendingWait {
            token,
            continuation,
            registration,
            kind,
        });
        if c65_mark_parked(self.route) {
            true
        } else {
            let _ = self.cancel_pending_wait(resources, space);
            false
        }
    }

    fn propagate_and_complete(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        reason: StreamCloseReason,
        from_output: bool,
    ) -> C65PayloadOutcome {
        // Linearize the consumer's typed completion before closing the
        // upstream endpoint. ByteStream close may synchronously schedule the
        // provider on another hart, so recording afterwards would make the
        // asserted consumer-first order racy.
        if !c65_record_completion(self.route, reason) {
            return C65PayloadOutcome::InvariantFailure;
        }
        let propagation = if from_output {
            match self.route.input {
                Some(input) => {
                    c65_with_reader(resources, input, space, |reader| reader.close(reason))
                }
                None => Ok(StreamCloseOutcome::AlreadyPublished),
            }
        } else {
            c65_with_writer(resources, self.route.output, space, |writer| {
                writer.close(reason)
            })
        };
        if !propagation.is_ok_and(|outcome| {
            matches!(
                outcome,
                StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
            )
        }) {
            c65_publish_failure(self.route.generation);
            return C65PayloadOutcome::InvariantFailure;
        }
        self.completed = true;
        C65PayloadOutcome::Complete
    }

    fn read_start(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        context: &mut Context<'_>,
    ) -> C65PayloadOutcome {
        let Ok(input) = self.input() else {
            return C65PayloadOutcome::InvariantFailure;
        };
        let Ok(dispatch) = c65_with_reader(resources, input, space, ByteStreamReader::start) else {
            return C65PayloadOutcome::InvariantFailure;
        };
        match dispatch {
            Ok(StreamReceiveDispatch::Prepared(prepared)) if prepared.length() == 1 => {
                let mut byte = [0_u8];
                let Ok(commit) = c65_with_reader(resources, input, space, |reader| {
                    reader.commit(prepared.operation(), &mut byte)
                }) else {
                    return C65PayloadOutcome::InvariantFailure;
                };
                if commit != Ok(StreamReceiveCommit::Received(1)) {
                    return C65PayloadOutcome::InvariantFailure;
                }
                self.phase = C65TransferPhase::Write(match self.route.kind {
                    C65NodeKind::Relay => byte[0] ^ C65_RELAY_XOR,
                    C65NodeKind::Sink => byte[0].wrapping_add(1),
                    C65NodeKind::Source => return C65PayloadOutcome::InvariantFailure,
                });
                if c65_productive_wake(self.route, context) {
                    C65PayloadOutcome::Pending
                } else {
                    C65PayloadOutcome::InvariantFailure
                }
            }
            Ok(StreamReceiveDispatch::Waiting(operation)) => {
                if self.arm_wait(resources, space, context, operation, C65WaitKind::Receive) {
                    C65PayloadOutcome::Pending
                } else {
                    C65PayloadOutcome::InvariantFailure
                }
            }
            Ok(StreamReceiveDispatch::Closed(reason)) => {
                self.propagate_and_complete(resources, space, reason, false)
            }
            _ => C65PayloadOutcome::InvariantFailure,
        }
    }

    fn write_start(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        context: &mut Context<'_>,
        byte: u8,
    ) -> C65PayloadOutcome {
        let Ok(dispatch) = c65_with_writer(resources, self.route.output, space, |writer| {
            writer.start(core::slice::from_ref(&byte))
        }) else {
            return C65PayloadOutcome::InvariantFailure;
        };
        match dispatch {
            Ok(StreamSendDispatch::Sent) => {
                if !c65_record_chunk(self.route) {
                    return C65PayloadOutcome::InvariantFailure;
                }
                if self.route.kind == C65NodeKind::Source {
                    self.next_source_byte = self.next_source_byte.wrapping_add(1);
                } else {
                    self.phase = C65TransferPhase::Transfer;
                }
                if c65_productive_wake(self.route, context) {
                    C65PayloadOutcome::Pending
                } else {
                    C65PayloadOutcome::InvariantFailure
                }
            }
            Ok(StreamSendDispatch::Waiting(operation)) => {
                if self.arm_wait(
                    resources,
                    space,
                    context,
                    operation,
                    C65WaitKind::Send(byte),
                ) {
                    C65PayloadOutcome::Pending
                } else {
                    C65PayloadOutcome::InvariantFailure
                }
            }
            Ok(StreamSendDispatch::Closed(reason)) => {
                self.propagate_and_complete(resources, space, reason, true)
            }
            _ => C65PayloadOutcome::InvariantFailure,
        }
    }

    fn resume_wait(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        context: &mut Context<'_>,
    ) -> C65PayloadOutcome {
        let Some(mut waiting) = self.waiting.take() else {
            return C65PayloadOutcome::InvariantFailure;
        };
        let kind = waiting.kind;
        let operation = waiting.registration.operation();
        let slot = self.wait_slot(kind);
        let consumed = match Pin::new(&mut waiting.continuation).poll(context) {
            Poll::Ready(Ok(consumed)) if consumed.matches_token(waiting.token) => consumed,
            Poll::Pending => {
                self.waiting = Some(waiting);
                let _ = self.cancel_pending_wait(resources, space);
                c65_publish_failure(self.route.generation);
                return C65PayloadOutcome::InvariantFailure;
            }
            _ => {
                let _ = self.cancel_wait_operation(resources, space, kind, operation);
                drop(waiting);
                c65_publish_failure(self.route.generation);
                return C65PayloadOutcome::InvariantFailure;
            }
        };
        let _ = consumed;
        if !c65_mark_resumed(self.route) {
            let _ = self.cancel_wait_operation(resources, space, kind, operation);
            drop(waiting);
            return C65PayloadOutcome::InvariantFailure;
        }
        if !slot.contains(operation) {
            drop(waiting);
            c65_publish_failure(self.route.generation);
            return C65PayloadOutcome::InvariantFailure;
        }
        match kind {
            C65WaitKind::Receive => {
                let Ok(input) = self.input() else {
                    let _ = self.cancel_wait_operation(resources, space, kind, operation);
                    drop(waiting);
                    return C65PayloadOutcome::InvariantFailure;
                };
                let dispatch = c65_with_reader(resources, input, space, |reader| {
                    reader.resume_after_wake(waiting.registration)
                });
                let dispatch = match dispatch {
                    Ok(Ok(dispatch)) => dispatch,
                    Ok(Err(failure)) => {
                        let registration = failure.into_registration();
                        let _ = self.cancel_wait_operation(
                            resources,
                            space,
                            kind,
                            registration.operation(),
                        );
                        drop(registration);
                        c65_publish_failure(self.route.generation);
                        return C65PayloadOutcome::InvariantFailure;
                    }
                    Err(()) => {
                        let _ = self.cancel_wait_operation(resources, space, kind, operation);
                        c65_publish_failure(self.route.generation);
                        return C65PayloadOutcome::InvariantFailure;
                    }
                };
                let _ = slot.clear_exact(operation);
                if slot.contains(operation)
                    || !c65_increment(&C65_AUDIT.sealed_resumes, self.route.generation)
                {
                    c65_publish_failure(self.route.generation);
                    return C65PayloadOutcome::InvariantFailure;
                }
                match dispatch {
                    StreamReceiveDispatch::Prepared(prepared) if prepared.length() == 1 => {
                        let mut byte = [0_u8];
                        let Ok(commit) = c65_with_reader(resources, input, space, |reader| {
                            reader.commit(prepared.operation(), &mut byte)
                        }) else {
                            return C65PayloadOutcome::InvariantFailure;
                        };
                        if commit != Ok(StreamReceiveCommit::Received(1)) {
                            return C65PayloadOutcome::InvariantFailure;
                        }
                        self.phase = C65TransferPhase::Write(match self.route.kind {
                            C65NodeKind::Relay => byte[0] ^ C65_RELAY_XOR,
                            C65NodeKind::Sink => byte[0].wrapping_add(1),
                            C65NodeKind::Source => return C65PayloadOutcome::InvariantFailure,
                        });
                        if c65_productive_wake(self.route, context) {
                            C65PayloadOutcome::Pending
                        } else {
                            C65PayloadOutcome::InvariantFailure
                        }
                    }
                    StreamReceiveDispatch::Closed(reason) => {
                        self.propagate_and_complete(resources, space, reason, false)
                    }
                    _ => C65PayloadOutcome::InvariantFailure,
                }
            }
            C65WaitKind::Send(byte) => {
                let dispatch = c65_with_writer(resources, self.route.output, space, |writer| {
                    writer.resume_after_wake(waiting.registration, &[byte])
                });
                let dispatch = match dispatch {
                    Ok(Ok(dispatch)) => dispatch,
                    Ok(Err(failure)) => {
                        let registration = failure.into_registration();
                        let _ = self.cancel_wait_operation(
                            resources,
                            space,
                            kind,
                            registration.operation(),
                        );
                        drop(registration);
                        c65_publish_failure(self.route.generation);
                        return C65PayloadOutcome::InvariantFailure;
                    }
                    Err(()) => {
                        let _ = self.cancel_wait_operation(resources, space, kind, operation);
                        c65_publish_failure(self.route.generation);
                        return C65PayloadOutcome::InvariantFailure;
                    }
                };
                let _ = slot.clear_exact(operation);
                if slot.contains(operation)
                    || !c65_increment(&C65_AUDIT.sealed_resumes, self.route.generation)
                {
                    c65_publish_failure(self.route.generation);
                    return C65PayloadOutcome::InvariantFailure;
                }
                match dispatch {
                    StreamSendDispatch::Sent => {
                        if !c65_record_chunk(self.route) {
                            return C65PayloadOutcome::InvariantFailure;
                        }
                        if self.route.kind == C65NodeKind::Source {
                            self.next_source_byte = self.next_source_byte.wrapping_add(1);
                        } else {
                            self.phase = C65TransferPhase::Transfer;
                        }
                        if c65_productive_wake(self.route, context) {
                            C65PayloadOutcome::Pending
                        } else {
                            C65PayloadOutcome::InvariantFailure
                        }
                    }
                    StreamSendDispatch::Closed(reason) => {
                        self.propagate_and_complete(resources, space, reason, true)
                    }
                    _ => C65PayloadOutcome::InvariantFailure,
                }
            }
        }
    }

    fn poll(
        &mut self,
        resources: &mut ResourceTable<ComponentAuthority>,
        space: &InstanceSpace,
        context: &mut Context<'_>,
    ) -> C65PayloadOutcome {
        if self.completed {
            return C65PayloadOutcome::InvariantFailure;
        }
        if self.waiting.is_some() {
            return self.resume_wait(resources, space, context);
        }
        match (self.route.kind, self.phase) {
            (C65NodeKind::Source, C65TransferPhase::Transfer) => {
                self.write_start(resources, space, context, self.next_source_byte)
            }
            (C65NodeKind::Relay | C65NodeKind::Sink, C65TransferPhase::Transfer) => {
                self.read_start(resources, space, context)
            }
            (C65NodeKind::Relay | C65NodeKind::Sink, C65TransferPhase::Write(byte)) => {
                self.write_start(resources, space, context, byte)
            }
            (C65NodeKind::Source, C65TransferPhase::Write(_)) => {
                C65PayloadOutcome::InvariantFailure
            }
        }
    }
}

impl PrincipalPayload {
    fn new(plan: PrincipalPlan, resources: ResourceTable<ComponentAuthority>) -> Self {
        Self {
            resources,
            fuel: PrincipalFuelEnvelope {
                limit: plan.fuel_limit,
                poll_quantum: plan.poll_quantum,
                consumed: 0,
            },
            guest_memory_limit: plan.guest_memory_limit,
            expected_resource_peak: plan.expected_resource_peak,
            resource_slot_limit: plan.resource_slots,
            drains: plan.drains,
            guest_calls: 0,
            completed: false,
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            async_chain: plan.async_route.map(C65AsyncPayload::new),
        }
    }

    fn runtime_unavailable_completion(&mut self) -> u64 {
        let envelope_valid = !self.completed
            && self.fuel.consumed == 0
            && self.fuel.limit != 0
            && self.fuel.poll_quantum != 0
            && self.fuel.poll_quantum <= self.fuel.limit
            && self.guest_memory_limit != 0
            && self.expected_resource_peak <= u64::from(self.resource_slot_limit);
        if !envelope_valid {
            return INVALID_ENVELOPE_COMPLETION;
        }
        for drain in &mut self.drains {
            if let Some(exact) = drain.take() {
                if self
                    .resources
                    .drop_owned(exact.token, exact.resource_type)
                    .is_err()
                {
                    return INVALID_ENVELOPE_COMPLETION;
                }
            }
        }
        if !self.resources.is_empty() {
            return INVALID_ENVELOPE_COMPLETION;
        }
        self.completed = true;
        encode_runtime_unavailable_completion(self.guest_calls)
    }
}

impl Drop for PrincipalPayload {
    fn drop(&mut self) {
        debug_assert!(self.resources.is_empty());
        debug_assert!(self.drains.iter().all(Option::is_none));
        debug_assert_eq!(self.fuel.consumed, 0);
        debug_assert_eq!(self.guest_calls, 0);
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        debug_assert!(self.async_chain.is_none());
    }
}

// SAFETY: the payload owns all arena-local state and never retains a Space,
// CSpace guard, resolved capability, resource pointer, or host lock across a
// quantum. The C6.5-only blocked state retains only opaque operation receipts
// plus `InstanceContinuation`, whose listener is registered against the stable
// SYSTEM instance slot and executor TaskStatus ledger. Before callback
// registration, the backend operation is mirrored into a boot-stable atomic
// slot; the SYSTEM stream supervisor can exact-cancel that mirror and has a
// terminal-only backstop for the bounded start-before-mirror fault window. It
// is consumed before normal payload completion; productive transitions are
// bounded to one chunk, while an external wait returns Pending without
// self-waking. Drop remains bounded and non-reentrant.
unsafe impl InstancePayload for PrincipalPayload {
    fn poll_quantum(&mut self, space: &InstanceSpace, context: &mut Context<'_>) -> Poll<u64> {
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        if let Some(mut async_chain) = self.async_chain.take() {
            let generation = async_chain.route.generation;
            if C65_AUDIT.generation.load(Ordering::Acquire) == generation
                && C65_AUDIT.failed.load(Ordering::Acquire)
            {
                if !async_chain.cancel_pending_wait(&mut self.resources, space) {
                    c65_publish_failure(generation);
                }
                return Poll::Ready(self.runtime_unavailable_completion());
            }
            match async_chain.poll(&mut self.resources, space, context) {
                C65PayloadOutcome::Pending => {
                    self.async_chain = Some(async_chain);
                    return Poll::Pending;
                }
                C65PayloadOutcome::Complete => {}
                C65PayloadOutcome::InvariantFailure => {
                    let _ = async_chain.cancel_pending_wait(&mut self.resources, space);
                    c65_publish_failure(generation);
                    return Poll::Ready(self.runtime_unavailable_completion());
                }
            }
        }
        #[cfg(not(feature = "wasm-c65-async-chain-acceptance"))]
        let _ = (space, context);
        Poll::Ready(self.runtime_unavailable_completion())
    }
}

struct PrincipalTask {
    token: InstanceToken,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    c65_generation: Option<u64>,
}

impl Future for PrincipalTask {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            if let Some(generation) = self.c65_generation {
                c65_publish_failure(generation);
            }
            let _ = super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        };
        if witness.instance_token() != Some(self.token) {
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            if let Some(generation) = self.c65_generation {
                c65_publish_failure(generation);
            }
            let _ = super::component_instances::registry().quarantine(self.token);
            return Poll::Ready(());
        }
        match unsafe { super::component_instances::registry().poll_payload(witness, context) } {
            Ok(Poll::Ready(_)) => Poll::Ready(()),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => {
                #[cfg(feature = "wasm-c65-async-chain-acceptance")]
                if let Some(generation) = self.c65_generation {
                    c65_publish_failure(generation);
                }
                let _ = super::component_instances::registry().quarantine(self.token);
                Poll::Ready(())
            }
        }
    }
}

const _: () = assert!(core::mem::size_of::<PrincipalTask>() <= 32);

fn revalidate_template(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let result = template
        .revalidate()
        .map_err(|_| ComponentGraphPrincipalLifecycleError::Revalidation);
    system.restore();
    result?;
    if !template.grants().is_empty() {
        return Err(ComponentGraphPrincipalLifecycleError::AuthorityBearingGraph);
    }
    if template.runtime_ready() {
        return Err(ComponentGraphPrincipalLifecycleError::ExecutableTemplate);
    }
    Ok(())
}

fn checked_owner_quota(guest_memory_limit: usize) -> Option<usize> {
    guest_memory_limit.checked_add(COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES)
}

fn reserve_resource_generations(
    count: usize,
) -> Result<u64, ComponentGraphPrincipalLifecycleError> {
    let count = u64::try_from(count)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    NEXT_RESOURCE_GENERATION
        .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            next.checked_add(count)
        })
        .map_err(|_| ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)
}

fn checked_plan(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<Vec<PrincipalPlan>, ComponentGraphPrincipalLifecycleError> {
    let principals = template.principals();
    if principals.is_empty() || principals.len() > MAX_COMPONENT_INSTANCES {
        return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut plans = Vec::new();
    if plans.try_reserve_exact(principals.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for (index, principal) in principals.iter().enumerate() {
        let expected = u16::try_from(index).ok().map(ComponentGraphNodeId::new);
        if expected != Some(principal.id())
            || principal.isolation() != ComponentGraphPrincipalIsolation::FreshPerNode
        {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
        }
        let guest_memory_limit = match usize::try_from(principal.memory_bytes()) {
            Ok(limit) if limit != 0 => limit,
            _ => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                    node: principal.id(),
                });
            }
        };
        let Some(owner_quota) = checked_owner_quota(guest_memory_limit) else {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                node: principal.id(),
            });
        };
        let resource_slots = match u16::try_from(principal.resource_slot_limit()) {
            Ok(slots) if slots != 0 => slots,
            _ => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                    node: principal.id(),
                });
            }
        };
        if principal.fuel_limit() == 0
            || principal.poll_quantum() == 0
            || principal.poll_quantum() > principal.fuel_limit()
        {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::BudgetOverflow {
                node: principal.id(),
            });
        }
        plans.push(PrincipalPlan {
            node: principal.id(),
            owner_quota,
            guest_memory_limit,
            fuel_limit: principal.fuel_limit(),
            poll_quantum: principal.poll_quantum(),
            resource_types: principal.budget().resource_types,
            resource_slots,
            resource_generation: 0,
            expected_resource_peak: 0,
            expected_revoked_capabilities: 0,
            drains: [None; 2],
            report_kind: PrincipalReportKind::Ordinary,
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            async_route: None,
        });
    }
    system.restore();
    Ok(plans)
}

fn bind_expected_resource_peaks(
    plans: &mut [PrincipalPlan],
    route: Option<ResourceRoutePlan>,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let Some(route) = route else {
        return Ok(());
    };
    if route.source_index == route.target_index
        || route.source_index >= plans.len()
        || route.target_index >= plans.len()
        || plans[route.source_index].resource_slots == 0
        || plans[route.target_index].resource_slots == 0
        || plans[route.source_index].expected_resource_peak != 0
        || plans[route.target_index].expected_resource_peak != 0
    {
        return Err(ComponentGraphPrincipalLifecycleError::ResourceRoutePolicy);
    }
    plans[route.source_index].expected_resource_peak = 1;
    plans[route.target_index].expected_resource_peak = 1;
    plans[route.source_index].report_kind = PrincipalReportKind::ResourceRoute;
    plans[route.target_index].report_kind = PrincipalReportKind::ResourceRoute;
    Ok(())
}

fn select_resource_route(
    template: &ComponentGraphPrincipalTemplate,
    request: ResourceRouteRequest,
) -> Result<Option<ResourceRoutePlan>, ComponentGraphPrincipalLifecycleError> {
    match request {
        ResourceRouteRequest::None => {
            if template.resource_edges().is_empty() {
                Ok(None)
            } else {
                Err(ComponentGraphPrincipalLifecycleError::ResourceRouteRequired)
            }
        }
        #[cfg(feature = "wasm-c64-resource-route-acceptance")]
        ResourceRouteRequest::C64Exact => exact_c64_resource_route_plan(template).map(Some),
    }
}

fn select_async_route(
    template: &ComponentGraphPrincipalTemplate,
    request: AsyncRouteRequest,
) -> Result<AsyncRoutePlan, ComponentGraphPrincipalLifecycleError> {
    match request {
        AsyncRouteRequest::None => {
            if template.async_edges().is_empty() {
                Ok(AsyncRoutePlan::None)
            } else {
                Err(ComponentGraphPrincipalLifecycleError::AsyncRouteRequired)
            }
        }
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        AsyncRouteRequest::C65Exact { cause } => {
            exact_c65_async_route(template)?;
            if !matches!(
                cause,
                StreamCloseReason::BackendFault | StreamCloseReason::Cancelled
            ) {
                return Err(ComponentGraphPrincipalLifecycleError::AsyncRoutePolicy);
            }
            Ok(AsyncRoutePlan::C65Exact { cause })
        }
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_async_edge(source: u16, target: u16) -> ComponentGraphEdgeSpec {
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

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn exact_c65_async_route(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let expected_edges = [c65_async_edge(0, 1), c65_async_edge(1, 2)];
    let expected_export = vibeos_component_runtime::graph::ComponentGraphPublishedExportSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(2),
            ComponentGraphEntityIndex::new(0),
        ),
    );
    if template.profile() != ProfileIdentity::PROFILE_1_ASYNC
        || template.profile().execution_enabled()
        || template.runtime_ready()
        || template.principals().len() != C65_NODE_COUNT
        || template.manifest().edges() != expected_edges
        || !template.resource_edges().is_empty()
        || !template.manifest().external_imports().is_empty()
        || template.manifest().published_exports() != core::slice::from_ref(&expected_export)
        || !template.grants().is_empty()
        || template.async_edges().len() != expected_edges.len()
        || template
            .async_edges()
            .iter()
            .zip(expected_edges)
            .any(|(route, edge)| {
                route.edge() != edge
                    || route.async_functions() != 1
                    || route.streams() != 4
                    || route.futures() != 4
            })
    {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRoutePolicy);
    }
    Ok(())
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn bind_c65_expected_resources(
    plans: &mut [PrincipalPlan],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    if plans.len() != C65_NODE_COUNT
        || plans.iter().any(|plan| {
            plan.expected_resource_peak != 0
                || plan.expected_revoked_capabilities != 0
                || plan.drains.iter().any(Option::is_some)
                || plan.async_route.is_some()
                || plan.resource_slots < 2
        })
    {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRoutePolicy);
    }
    for (index, peak) in [1_u64, 2, 2].into_iter().enumerate() {
        plans[index].expected_resource_peak = peak;
        plans[index].expected_revoked_capabilities = peak as usize;
        plans[index].report_kind = PrincipalReportKind::AsyncChain;
    }
    Ok(())
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn exact_c64_resource_route_plan(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<ResourceRoutePlan, ComponentGraphPrincipalLifecycleError> {
    let [route] = template.resource_edges() else {
        return Err(ComponentGraphPrincipalLifecycleError::ResourceRoutePolicy);
    };
    if template.principals().len() != 2
        || template.manifest().edges() != core::slice::from_ref(&c64_resource_edge())
        || route.edge() != c64_resource_edge()
        || route.mode() != ComponentGraphResourceMode::OwnAndBorrow
        || route.resources().len() != 1
        || route.resources()[0].as_str() != "handle"
    {
        return Err(ComponentGraphPrincipalLifecycleError::ResourceRoutePolicy);
    }
    Ok(ResourceRoutePlan {
        source_index: usize::from(route.edge().source().node().index()),
        target_index: usize::from(route.edge().target().node().index()),
    })
}

fn assign_resource_generations(
    plans: &mut [PrincipalPlan],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let generation = reserve_resource_generations(plans.len())?;
    for (index, plan) in plans.iter_mut().enumerate() {
        plan.resource_generation = generation
            .checked_add(index as u64)
            .ok_or(ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)?;
    }
    Ok(())
}

fn prepare_resource_tables(
    plans: &[PrincipalPlan],
) -> Result<Vec<Option<ResourceTable<ComponentAuthority>>>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut tables = Vec::new();
    if tables.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        let table = match ResourceTable::new(plan.resource_generation, plan.resource_slots) {
            Ok(table) => table,
            Err(_) => {
                system.restore();
                return Err(
                    ComponentGraphPrincipalLifecycleError::ResourceTableUnavailable {
                        node: plan.node,
                    },
                );
            }
        };
        tables.push(Some(table));
    }
    system.restore();
    Ok(tables)
}

fn prepare_resource_route(
    route: Option<ResourceRoutePlan>,
    plans: &mut [PrincipalPlan],
    tokens: &[InstanceToken],
    tables: &mut [Option<ResourceTable<ComponentAuthority>>],
) -> Result<Option<ResourceRouteReceipt>, ComponentGraphPrincipalLifecycleError> {
    let Some(route) = route else {
        return Ok(None);
    };
    #[cfg(feature = "wasm-c64-resource-route-acceptance")]
    {
        return prepare_c64_resource_route(route, plans, tokens, tables).map(Some);
    }
    #[cfg(not(feature = "wasm-c64-resource-route-acceptance"))]
    {
        let _ = (route, plans, tokens, tables);
        Err(ComponentGraphPrincipalLifecycleError::ResourceRoutePolicy)
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn next_c65_scenario_generation() -> Result<u64, ComponentGraphPrincipalLifecycleError> {
    NEXT_C65_SCENARIO_GENERATION
        .try_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            next.checked_add(1)
        })
        .map_err(|_| ComponentGraphPrincipalLifecycleError::ResourceGenerationExhausted)
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_host_wake_words(generation: u64) -> Option<[usize; 4]> {
    let generation = usize::try_from(generation).ok()?;
    Some([
        generation,
        C65_HOST_WAKE_TAG ^ generation.rotate_left(17),
        C65_HOST_WAKE_TAG.rotate_left(29),
        C65_HOST_WAKE_TAG,
    ])
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_host_wake(words: [usize; 4]) {
    let generation = words[0] as u64;
    let exact = c65_host_wake_words(generation).is_some_and(|expected| expected == words);
    let accepted = exact
        && C65_AUDIT.matches_live_generation(generation)
        && C65_AUDIT
            .host_wakes
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
    if !accepted {
        c65_publish_failure(generation);
        return;
    }
    match C65_HOST_READY.publish(generation) {
        Ok(wake) => {
            let _ = wake.dispatch();
        }
        Err(_) => c65_publish_failure(generation),
    }
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn insert_c65_authority(
    table: &mut ResourceTable<ComponentAuthority>,
    resource_type: ResourceTypeId,
    authority: ComponentAuthority,
) -> Result<ResourceToken, ComponentGraphPrincipalLifecycleError> {
    table
        .insert_owned(resource_type, authority)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn prepare_c65_async_route(
    cause: StreamCloseReason,
    plans: &mut [PrincipalPlan],
    tokens: &[InstanceToken],
    tables: &mut [Option<ResourceTable<ComponentAuthority>>],
) -> Result<C65SupervisorControl, ComponentGraphPrincipalLifecycleError> {
    if plans.len() != C65_NODE_COUNT
        || tokens.len() != C65_NODE_COUNT
        || tables.len() != C65_NODE_COUNT
        || !matches!(
            cause,
            StreamCloseReason::BackendFault | StreamCloseReason::Cancelled
        )
        || plans.iter().zip([1_u64, 2, 2]).any(|(plan, peak)| {
            plan.expected_resource_peak != peak
                || plan.expected_revoked_capabilities != peak as usize
                || plan.report_kind != PrincipalReportKind::AsyncChain
                || plan.async_route.is_some()
                || plan.drains.iter().any(Option::is_some)
        })
    {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRoutePolicy);
    }
    let generation = next_c65_scenario_generation()?;
    if !c65_wait_slots_empty() || !C65_AUDIT.reset(generation) {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup);
    }

    let streams = [ByteStream::new(), ByteStream::new(), ByteStream::new()];
    let supervisors = [
        streams[0].supervisor(),
        streams[1].supervisor(),
        streams[2].supervisor(),
    ];
    let host_reader = streams[2].reader();
    let StreamReceiveDispatch::Waiting(host_operation) = host_reader
        .start()
        .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?
    else {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup);
    };
    let host_words = c65_host_wake_words(generation)
        .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
    let host_registration = host_reader
        .register_wake_sealed(
            host_operation,
            HostWakeToken::new(host_words, c65_host_wake),
        )
        .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;

    let source_writer = streams[0].writer();
    let relay_reader = streams[0].reader();
    let relay_writer = streams[1].writer();
    let sink_reader = streams[1].reader();
    let sink_writer = streams[2].writer();

    let source = unsafe {
        super::component_instances::registry().configure_reserved_space(tokens[0], |space| {
            if space.live_count() != 0 {
                return None;
            }
            let cap = space.mint(source_writer, Rights::SEND);
            ComponentAuthority::prepare_ephemeral_in::<ByteStreamWriter>(space, cap, Rights::SEND)
                .ok()
        })
    }
    .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?
    .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
    let relay = unsafe {
        super::component_instances::registry().configure_reserved_space(tokens[1], |space| {
            if space.live_count() != 0 {
                return None;
            }
            let reader_cap = space.mint(relay_reader, Rights::RECV);
            let writer_cap = space.mint(relay_writer, Rights::SEND);
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
    .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?
    .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
    let sink = unsafe {
        super::component_instances::registry().configure_reserved_space(tokens[2], |space| {
            if space.live_count() != 0 {
                return None;
            }
            let reader_cap = space.mint(sink_reader, Rights::RECV);
            let writer_cap = space.mint(sink_writer, Rights::SEND);
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
    .map_err(|_| ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?
    .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;

    let source_token = {
        let table = tables[0]
            .as_mut()
            .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
        insert_c65_authority(table, C65_SOURCE_WRITER_TYPE, source.into_authority())?
    };
    let (relay_reader_token, relay_writer_token) = {
        let table = tables[1]
            .as_mut()
            .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
        let reader = insert_c65_authority(table, C65_RELAY_READER_TYPE, relay.0.into_authority())?;
        let writer = insert_c65_authority(table, C65_RELAY_WRITER_TYPE, relay.1.into_authority())?;
        (reader, writer)
    };
    let (sink_reader_token, sink_writer_token) = {
        let table = tables[2]
            .as_mut()
            .ok_or(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup)?;
        let reader = insert_c65_authority(table, C65_SINK_READER_TYPE, sink.0.into_authority())?;
        let writer = insert_c65_authority(table, C65_SINK_WRITER_TYPE, sink.1.into_authority())?;
        (reader, writer)
    };

    let source_output = PrincipalResourceDrain {
        token: source_token,
        resource_type: C65_SOURCE_WRITER_TYPE,
    };
    let relay_input = PrincipalResourceDrain {
        token: relay_reader_token,
        resource_type: C65_RELAY_READER_TYPE,
    };
    let relay_output = PrincipalResourceDrain {
        token: relay_writer_token,
        resource_type: C65_RELAY_WRITER_TYPE,
    };
    let sink_input = PrincipalResourceDrain {
        token: sink_reader_token,
        resource_type: C65_SINK_READER_TYPE,
    };
    let sink_output = PrincipalResourceDrain {
        token: sink_writer_token,
        resource_type: C65_SINK_WRITER_TYPE,
    };
    plans[0].drains = [Some(source_output), None];
    plans[0].async_route = Some(C65PrincipalRoute {
        generation,
        instance: tokens[0],
        kind: C65NodeKind::Source,
        input: None,
        output: source_output,
    });
    plans[1].drains = [Some(relay_input), Some(relay_output)];
    plans[1].async_route = Some(C65PrincipalRoute {
        generation,
        instance: tokens[1],
        kind: C65NodeKind::Relay,
        input: Some(relay_input),
        output: relay_output,
    });
    plans[2].drains = [Some(sink_input), Some(sink_output)];
    plans[2].async_route = Some(C65PrincipalRoute {
        generation,
        instance: tokens[2],
        kind: C65NodeKind::Sink,
        input: Some(sink_input),
        output: sink_output,
    });

    if tables[0].as_ref().map(ResourceTable::len) != Some(1)
        || tables[1].as_ref().map(ResourceTable::len) != Some(2)
        || tables[2].as_ref().map(ResourceTable::len) != Some(2)
    {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup);
    }
    Ok(C65SupervisorControl {
        generation,
        cause,
        host_reader,
        host_registration: Some(host_registration),
        streams,
        supervisors,
    })
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn c64_route_tables_mut(
    tables: &mut [Option<ResourceTable<ComponentAuthority>>],
    route: ResourceRoutePlan,
) -> Option<(
    &mut ResourceTable<ComponentAuthority>,
    &mut ResourceTable<ComponentAuthority>,
)> {
    if route.source_index == route.target_index
        || route.source_index >= tables.len()
        || route.target_index >= tables.len()
    {
        return None;
    }
    if route.source_index < route.target_index {
        let (before_target, from_target) = tables.split_at_mut(route.target_index);
        Some((
            before_target[route.source_index].as_mut()?,
            from_target[0].as_mut()?,
        ))
    } else {
        let (before_source, from_source) = tables.split_at_mut(route.source_index);
        Some((
            from_source[0].as_mut()?,
            before_source[route.target_index].as_mut()?,
        ))
    }
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn prepare_c64_resource_route(
    route: ResourceRoutePlan,
    plans: &mut [PrincipalPlan],
    tokens: &[InstanceToken],
    tables: &mut [Option<ResourceTable<ComponentAuthority>>],
) -> Result<ResourceRouteReceipt, ComponentGraphPrincipalLifecycleError> {
    let setup_error = || ComponentGraphPrincipalLifecycleError::ResourceRouteSetup;
    if route.source_index != 0
        || route.target_index != 1
        || plans.len() != 2
        || tokens.len() != 2
        || tables.len() != 2
        || C64_SOURCE_RESOURCE_TYPE == C64_TARGET_RESOURCE_TYPE
        || plans.iter().any(|plan| {
            plan.resource_slots != 2
                || plan.expected_resource_peak != 1
                || plan.expected_revoked_capabilities != 0
                || plan.drains.iter().any(Option::is_some)
        })
        || plans[route.source_index].resource_types != 1
        || plans[route.target_index].resource_types != 0
    {
        return Err(ComponentGraphPrincipalLifecycleError::ResourceRoutePolicy);
    }
    let (source_table, target_table) =
        c64_route_tables_mut(tables, route).ok_or_else(setup_error)?;
    if !source_table.is_empty() || !target_table.is_empty() {
        return Err(setup_error());
    }

    // Prove the exact pair pristine before creating the source root. The root
    // itself is minted through the existing single-reservation setup gate; no
    // cross-space derivation exists until the fused pair transfer below.
    let pair_pristine = unsafe {
        super::component_instances::registry().with_reserved_space_pair(
            tokens[route.source_index],
            tokens[route.target_index],
            |source_space, target_space| {
                source_space.live_count() == 0 && target_space.live_count() == 0
            },
        )
    }
    .map_err(|_| setup_error())?;
    if !pair_pristine {
        return Err(setup_error());
    }

    // Reserve the table entry before minting. The single-space callback
    // returns only a detached copy receipt; table ownership is committed only
    // after that exact reservation's postflight succeeds.
    let source_reservation = source_table.reserve().map_err(|_| setup_error())?;
    let source_receipt = unsafe {
        super::component_instances::registry().configure_reserved_space(
            tokens[route.source_index],
            |source_space| {
                if source_space.live_count() != 0 {
                    return None;
                }
                let source_cap = source_space.mint(
                    Arc::new(C64RouteProbe(C64_ROUTE_PROBE_VALUE)),
                    Rights::READ.union(Rights::GRANT),
                );
                ComponentAuthority::prepare_supervised_ephemeral_source_in::<C64RouteProbe>(
                    source_space,
                    source_cap,
                    Rights::READ,
                )
                .ok()
            },
        )
    }
    .map_err(|_| setup_error())?
    .ok_or_else(setup_error)?;
    let source_token =
        source_reservation.commit(C64_SOURCE_RESOURCE_TYPE, source_receipt.into_authority());
    if source_table.len() != 1
        || source_table.contains(source_token, C64_SOURCE_RESOURCE_TYPE) != Ok(true)
        || !target_table.is_empty()
    {
        return Err(setup_error());
    }

    // One invocation-scoped alias proves the admitted borrow mode. The target
    // receives neither a ResourceTable entry nor a capability, and the source
    // remains byte-for-byte live for the subsequent owned transfer.
    let (
        borrow_source_caps_before,
        borrow_source_caps_after,
        borrow_target_caps_before,
        borrow_target_caps_after,
        borrowed_value,
    ) = unsafe {
        super::component_instances::registry().with_reserved_space_pair(
            tokens[route.source_index],
            tokens[route.target_index],
            |source_space, target_space| {
                let source_before = source_space.live_count();
                let target_before = target_space.live_count();
                if source_before != 1
                    || source_space.singleton_live_shape()
                        != Some((
                            "c64-supervised-route-probe",
                            Rights::READ.union(Rights::GRANT),
                        ))
                    || target_before != 0
                    || source_table.len() != 1
                    || !target_table.is_empty()
                {
                    return None;
                }
                let value = with_supervised_borrow::<C64RouteProbe, _>(
                    source_table,
                    source_token,
                    C64_SOURCE_RESOURCE_TYPE,
                    source_space,
                    target_table,
                    C64_TARGET_RESOURCE_TYPE,
                    target_space,
                    Rights::READ,
                    |scope| {
                        let alias = scope.alias();
                        scope.with_alias(&alias, |resource| resource.0)
                    },
                )
                .ok()?
                .ok()?;
                let source_after = source_space.live_count();
                let target_after = target_space.live_count();
                if source_after != 1
                    || source_space.singleton_live_shape()
                        != Some((
                            "c64-supervised-route-probe",
                            Rights::READ.union(Rights::GRANT),
                        ))
                    || target_after != 0
                    || source_table.len() != 1
                    || !target_table.is_empty()
                {
                    return None;
                }
                Some((
                    u64::try_from(source_before).ok()?,
                    u64::try_from(source_after).ok()?,
                    u64::try_from(target_before).ok()?,
                    u64::try_from(target_after).ok()?,
                    value,
                ))
            },
        )
    }
    .map_err(|_| setup_error())?
    .ok_or_else(setup_error)?;
    if borrowed_value != C64_ROUTE_PROBE_VALUE {
        return Err(setup_error());
    }

    // All ResourceTable fallibility is prepared before the pair transaction.
    // The fused registry gate performs a read-only host preflight, completes
    // the exact two-node postflight, commits the strict grant derivation, drops
    // both CSpace locks, and only then infallibly publishes the table move.
    let transfer = prepare_owned_supervised(
        source_table,
        source_token,
        C64_SOURCE_RESOURCE_TYPE,
        target_table,
        C64_TARGET_RESOURCE_TYPE,
    )
    .map_err(|_| setup_error())?;
    let target_token = unsafe {
        super::component_instances::registry().transfer_reserved_space_pair(
            tokens[route.source_index],
            tokens[route.target_index],
            |source_space, target_space| {
                transfer.prepare_in::<C64RouteProbe>(source_space, target_space, Rights::READ)
            },
            |prepared, receipt| prepared.commit(receipt),
        )
    }
    .map_err(|_| setup_error())?
    .map_err(|_| setup_error())?;

    if !source_table.is_empty()
        || target_table.len() != 1
        || target_table.contains(target_token, C64_TARGET_RESOURCE_TYPE) != Ok(true)
    {
        return Err(setup_error());
    }
    let (source_caps_after_transfer, target_caps_after_transfer, target_grant_absent) = unsafe {
        super::component_instances::registry().with_reserved_space_pair(
            tokens[route.source_index],
            tokens[route.target_index],
            |source_space, target_space| {
                let source = source_space.live_count();
                let target = target_space.live_count();
                let target_shape = target_space.singleton_live_shape();
                (
                    u64::try_from(source).ok(),
                    u64::try_from(target).ok(),
                    target == 1
                        && target_shape.is_some_and(|(kind, rights)| {
                            kind == "c64-supervised-route-probe"
                                && rights == Rights::READ
                                && !rights.contains(Rights::GRANT)
                        }),
                )
            },
        )
    }
    .map_err(|_| setup_error())?;
    let source_caps_after_transfer = source_caps_after_transfer.ok_or_else(setup_error)?;
    let target_caps_after_transfer = target_caps_after_transfer.ok_or_else(setup_error)?;
    if source_caps_after_transfer != 0 || target_caps_after_transfer != 1 || !target_grant_absent {
        return Err(setup_error());
    }

    plans[route.source_index].expected_revoked_capabilities = 0;
    plans[route.source_index].drains = [None; 2];
    plans[route.target_index].expected_revoked_capabilities = 1;
    plans[route.target_index].drains[0] = Some(PrincipalResourceDrain {
        token: target_token,
        resource_type: C64_TARGET_RESOURCE_TYPE,
    });

    Ok(ResourceRouteReceipt {
        borrow_invocations: 1,
        owned_transfers: 1,
        attenuated_grants: 1,
        source_peak_slots: 1,
        target_peak_slots: 1,
        borrow_source_caps_before,
        borrow_source_caps_after,
        borrow_target_caps_before,
        borrow_target_caps_after,
        source_caps_after_transfer,
        target_caps_after_transfer,
        source_live_after_transfer: u64::try_from(source_table.len()).map_err(|_| setup_error())?,
        target_live_after_transfer: u64::try_from(target_table.len()).map_err(|_| setup_error())?,
        target_grant_absent,
    })
}

fn release_empty_domain(domain: AllocationDomain) -> bool {
    HEAP.retire_empty_domains_batch(core::slice::from_ref(&domain))
        .is_ok_and(|outcome| outcome.retired_count() == 1)
}

fn release_empty_domains(domains: &[AllocationDomain]) -> bool {
    HEAP.retire_empty_domains_batch(domains)
        .is_ok_and(|outcome| outcome.retired_count() == domains.len())
}

fn create_domains(
    plans: &[PrincipalPlan],
) -> Result<Vec<AllocationDomain>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut quotas = Vec::new();
    if quotas.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        quotas.push(plan.owner_quota);
    }
    let domains = HEAP
        .create_fresh_domains_batch(&quotas)
        .map_err(|error| match error {
            FreshDomainBatchError::Allocation => ComponentGraphPrincipalLifecycleError::Allocation,
            _ => ComponentGraphPrincipalLifecycleError::DomainBatchUnavailable,
        });
    system.restore();
    domains
}

fn retire_domain(domain: AllocationDomain, kind: TerminalRetireKind) -> bool {
    match kind {
        TerminalRetireKind::Normal => release_empty_domain(domain),
        TerminalRetireKind::FaultReclaimed => HEAP.unregister_owner(domain.owner).is_ok(),
    }
}

fn abort_pristine_registry_batch(
    tokens: &[InstanceToken],
    domains: &[AllocationDomain],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    // Preserve the still-Reserved registry identities if the allocator cannot
    // prove that the whole fresh domain batch is exactly empty. The exclusive
    // fresh-domain contract keeps that proof stable across the registry's
    // allocation-free abort and the all-or-none retirement commit below.
    HEAP.preflight_retire_empty_domains_batch(domains)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::UnpublishedCleanup)?;
    let aborted = super::component_instances::registry()
        .abort_reserved_batch(tokens)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::UnpublishedCleanup)?;
    if aborted.aborted_instances() != tokens.len() || !release_empty_domains(domains) {
        return Err(ComponentGraphPrincipalLifecycleError::UnpublishedCleanup);
    }
    Ok(())
}

fn reserve_registry_batch(
    domains: &[AllocationDomain],
) -> Result<Vec<InstanceToken>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut inputs = Vec::new();
    if inputs.try_reserve_exact(domains.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for domain in domains {
        inputs.push((*domain, PRINCIPAL_CSPACE_NAME));
    }
    let result = super::component_instances::registry()
        .reserve_named_batch(&inputs)
        .map_err(|_| ComponentGraphPrincipalLifecycleError::RegistryReservation);
    system.restore();
    result
}

fn prepare_supervisor(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    teardown_order: Vec<usize>,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")] async_control: Option<C65SupervisorControl>,
    reports: Vec<ComponentGraphNodeTerminalReport>,
) -> Result<
    (
        PrincipalSupervisor,
        Vec<TaskHandle>,
        Arc<PrincipalCompletion>,
    ),
    ComponentGraphPrincipalLifecycleError,
> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let completion = Arc::new(PrincipalCompletion::new());
    let mut supervisor_plans = Vec::new();
    let mut supervisor_tokens = Vec::new();
    let mut handles = Vec::new();
    let mut verification_handles = Vec::new();
    let mut states = Vec::new();
    let mut teardown = Vec::new();
    let reserved = supervisor_plans.try_reserve_exact(plans.len()).is_ok()
        && supervisor_tokens.try_reserve_exact(tokens.len()).is_ok()
        && handles.try_reserve_exact(plans.len()).is_ok()
        && verification_handles.try_reserve_exact(plans.len()).is_ok()
        && states.try_reserve_exact(plans.len()).is_ok()
        && teardown.try_reserve_exact(plans.len()).is_ok();
    if !reserved {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    supervisor_plans.extend_from_slice(plans);
    supervisor_tokens.extend_from_slice(tokens);
    let supervisor = PrincipalSupervisor {
        plans: supervisor_plans,
        tokens: supervisor_tokens,
        handles,
        teardown_order,
        states,
        teardown,
        reports,
        completion: completion.clone(),
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        async_control,
    };
    system.restore();
    Ok((supervisor, verification_handles, completion))
}

fn publication_pairs(
    tokens: &[InstanceToken],
    domains: &[AllocationDomain],
) -> Result<Vec<(InstanceToken, AllocationDomain)>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut pairs = Vec::new();
    if pairs.try_reserve_exact(tokens.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    pairs.extend(tokens.iter().copied().zip(domains.iter().copied()));
    system.restore();
    Ok(pairs)
}

fn quarantine_all(tokens: &[InstanceToken]) {
    for token in tokens {
        let _ = super::component_instances::registry().quarantine(*token);
    }
}

fn lifecycle_invariant_failed(tokens: &[InstanceToken], message: &'static str) -> ! {
    quarantine_all(tokens);
    panic!("{message}")
}

fn install_payloads(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    tables: &mut [Option<ResourceTable<ComponentAuthority>>],
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    for ((plan, token), table) in plans.iter().zip(tokens).zip(tables) {
        let Some(resources) = table.take() else {
            let _ = super::component_instances::registry().quarantine(*token);
            return Err(ComponentGraphPrincipalLifecycleError::PayloadInstall { node: plan.node });
        };
        if unsafe {
            super::component_instances::registry()
                .install_payload(*token, || PrincipalPayload::new(*plan, resources))
        }
        .is_err()
        {
            return Err(ComponentGraphPrincipalLifecycleError::PayloadInstall { node: plan.node });
        }
    }
    Ok(())
}

fn bind_prepared_tasks(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    batch: &PreparedTaskBatch,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    let handles = batch.prepared_handles();
    let bindings = batch.prepared_reclaimable_bindings();
    if handles.len() != plans.len() + 1 || bindings.len() != plans.len() {
        return Err(ComponentGraphPrincipalLifecycleError::AtomicPublication);
    }
    super::component_instances::registry()
        .bind_batch(tokens, bindings, &handles[..plans.len()])
        .map_err(|_| ComponentGraphPrincipalLifecycleError::RegistryBinding)
}

fn finalize_all(
    plans: &[PrincipalPlan],
    tokens: &[InstanceToken],
    handles: &[TaskHandle],
    states: &[TaskState],
    teardown_order: &[usize],
    teardown: &mut Vec<PrincipalTeardownReceipt>,
) -> Result<(), ComponentGraphPrincipalLifecycleError> {
    if teardown_order.len() != plans.len()
        || teardown_order.iter().any(|index| *index >= plans.len())
        || (0..plans.len()).any(|index| {
            teardown_order
                .iter()
                .filter(|candidate| **candidate == index)
                .count()
                != 1
        })
    {
        return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
    }
    let mut first_error = None;
    // The order is derived from admitted edges before the caller-owned graph
    // is dropped. Every consumer is finalized before each provider; reverse
    // node numbering is used only as the deterministic tie-break for
    // disconnected nodes.
    for &index in teardown_order {
        let expected =
            (states[index] == TaskState::Exited).then_some(RUNTIME_UNAVAILABLE_COMPLETION);
        let finalized = unsafe {
            super::component_instances::registry().finalize_with_space_expect_completion(
                tokens[index],
                &handles[index],
                expected,
                |_space, _kind| true,
                retire_domain,
            )
        };
        let teardown_exact = finalized.as_ref().is_ok_and(|outcome| {
            outcome.revoked_capabilities == plans[index].expected_revoked_capabilities
                && outcome.detached_completion == expected
        });
        if states[index] != TaskState::Exited || !teardown_exact {
            first_error.get_or_insert(if !teardown_exact {
                ComponentGraphPrincipalLifecycleError::TerminalTeardown {
                    node: plans[index].node,
                }
            } else {
                ComponentGraphPrincipalLifecycleError::TaskTerminal {
                    node: plans[index].node,
                }
            });
        } else {
            let outcome = finalized
                .as_ref()
                .expect("validated terminal teardown has an outcome");
            let revoked_capabilities = outcome.revoked_capabilities;
            let guest_calls = outcome
                .detached_completion
                .and_then(completion_guest_calls)
                .expect("validated RuntimeUnavailable completion encodes guest calls");
            teardown.push(PrincipalTeardownReceipt {
                node: plans[index].node,
                revoked_capabilities,
                guest_calls,
            });
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn consumer_first_teardown_order(
    template: &ComponentGraphPrincipalTemplate,
) -> Result<Vec<usize>, ComponentGraphPrincipalLifecycleError> {
    let node_count = template.principals().len();
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut outgoing = Vec::new();
    let mut emitted = Vec::new();
    let mut order = Vec::new();
    let reserved = outgoing.try_reserve_exact(node_count).is_ok()
        && emitted.try_reserve_exact(node_count).is_ok()
        && order.try_reserve_exact(node_count).is_ok();
    if !reserved {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    outgoing.resize(node_count, 0_usize);
    emitted.resize(node_count, false);
    for edge in template.manifest().edges() {
        let source = usize::from(edge.source().node().index());
        let target = usize::from(edge.target().node().index());
        if source >= node_count || target >= node_count || source == target {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
        }
        outgoing[source] = match outgoing[source].checked_add(1) {
            Some(count) => count,
            None => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
            }
        };
    }
    while order.len() != node_count {
        let Some(next) = (0..node_count)
            .rev()
            .find(|index| !emitted[*index] && outgoing[*index] == 0)
        else {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
        };
        emitted[next] = true;
        order.push(next);
        for edge in template.manifest().edges() {
            let source = usize::from(edge.source().node().index());
            let target = usize::from(edge.target().node().index());
            if target == next && !emitted[source] {
                let Some(count) = outgoing[source].checked_sub(1) else {
                    system.restore();
                    return Err(ComponentGraphPrincipalLifecycleError::InvalidPrincipalSet);
                };
                outgoing[source] = count;
            }
        }
    }
    system.restore();
    Ok(order)
}

fn semantic_report_matches_plan(
    report: &ComponentGraphNodeTerminalReport,
    plan: &PrincipalPlan,
) -> bool {
    report.node() == plan.node
        && report.terminal() == ComponentGraphNodeTerminal::RuntimeUnavailable
        && report.fuel().limit() == plan.fuel_limit
        && report.fuel().consumed() == 0
        && report.resources().declared_types() == plan.resource_types
        && report.resources().slot_limit() == u64::from(plan.resource_slots)
        && report.resources().peak_slots() == plan.expected_resource_peak
        && report.resources().live_slots() == 0
}

fn precompute_semantic_reports(
    template: &ComponentGraphPrincipalTemplate,
    plans: &[PrincipalPlan],
) -> Result<Vec<ComponentGraphNodeTerminalReport>, ComponentGraphPrincipalLifecycleError> {
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let mut reports = Vec::new();
    if reports.try_reserve_exact(plans.len()).is_err() {
        system.restore();
        return Err(ComponentGraphPrincipalLifecycleError::Allocation);
    }
    for plan in plans {
        let report_result = match plan.report_kind {
            PrincipalReportKind::Ordinary => template.runtime_unavailable_report(plan.node),
            PrincipalReportKind::ResourceRoute => template
                .supervisor_prepared_resource_unavailable_report(
                    plan.node,
                    plan.expected_resource_peak,
                ),
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            PrincipalReportKind::AsyncChain => template
                .supervisor_prepared_async_unavailable_report(
                    plan.node,
                    plan.expected_resource_peak,
                ),
        };
        let report = match report_result {
            Ok(report) => report,
            Err(_) => {
                system.restore();
                return Err(ComponentGraphPrincipalLifecycleError::SemanticReport {
                    node: plan.node,
                });
            }
        };
        if !semantic_report_matches_plan(&report, plan) {
            system.restore();
            return Err(ComponentGraphPrincipalLifecycleError::SemanticReport { node: plan.node });
        }
        reports.push(report);
    }
    system.restore();
    Ok(reports)
}

fn publish_semantic_reports(
    plans: &[PrincipalPlan],
    teardown: Vec<PrincipalTeardownReceipt>,
    reports: Vec<ComponentGraphNodeTerminalReport>,
    #[cfg(feature = "wasm-c65-async-chain-acceptance")] async_chain: Option<C65AsyncChainReceipt>,
) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
    if teardown.len() != plans.len()
        || reports.len() != plans.len()
        || reports
            .iter()
            .zip(plans)
            .any(|(report, plan)| !semantic_report_matches_plan(report, plan))
        || plans.iter().any(|plan| {
            teardown
                .iter()
                .filter(|receipt| receipt.node == plan.node)
                .count()
                != 1
        })
    {
        return Err(ComponentGraphPrincipalLifecycleError::SemanticReport {
            node: plans[0].node,
        });
    }
    let Some(guest_calls) = teardown.iter().try_fold(0_u64, |total, receipt| {
        total.checked_add(receipt.guest_calls)
    }) else {
        return Err(ComponentGraphPrincipalLifecycleError::SemanticReport {
            node: plans[0].node,
        });
    };
    Ok(ComponentGraphPrincipalReports {
        reports,
        teardown,
        guest_calls,
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        async_chain,
    })
}

fn start_component_graph_principals_inner(
    template: Arc<ComponentGraphPrincipalTemplate>,
    route_request: ResourceRouteRequest,
    async_request: AsyncRouteRequest,
) -> Result<
    (ComponentGraphPrincipalRun, Option<ResourceRouteReceipt>),
    ComponentGraphPrincipalLifecycleError,
> {
    revalidate_template(&template)?;
    let route = select_resource_route(&template, route_request)?;
    let async_route = select_async_route(&template, async_request)?;
    let mut plans = checked_plan(&template)?;
    bind_expected_resource_peaks(&mut plans, route)?;
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    if matches!(async_route, AsyncRoutePlan::C65Exact { .. }) {
        bind_c65_expected_resources(&mut plans)?;
    }

    // The batch remains empty and ordinarily droppable through all
    // registry/scheduler reservation failures below. Its reservation method
    // preallocates every task/handle/binding vector before publishing hidden
    // scheduler credits.
    let mut batch = PreparedTaskBatch::new();
    assign_resource_generations(&mut plans)?;
    let mut tables = prepare_resource_tables(&plans)?;
    let domains = create_domains(&plans)?;
    let tokens = match reserve_registry_batch(&domains) {
        Ok(tokens) => tokens,
        Err(error) => {
            return Err(if release_empty_domains(&domains) {
                error
            } else {
                ComponentGraphPrincipalLifecycleError::UnpublishedCleanup
            });
        }
    };
    let route_receipt = match prepare_resource_route(route, &mut plans, &tokens, &mut tables) {
        Ok(receipt) => receipt,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
    let async_control = match async_route {
        AsyncRoutePlan::None => None,
        AsyncRoutePlan::C65Exact { cause } => {
            match prepare_c65_async_route(cause, &mut plans, &tokens, &mut tables) {
                Ok(control) => Some(control),
                Err(error) => {
                    abort_pristine_registry_batch(&tokens, &domains)?;
                    return Err(error);
                }
            }
        }
    };
    #[cfg(not(feature = "wasm-c65-async-chain-acceptance"))]
    let _ = async_route;
    // Freeze reports only after any explicit supervisor route produced its
    // measured receipt. The report buffer is SYSTEM-owned and every element is
    // copy-only semantic data. Dropping the caller Arc here ensures no admitted
    // graph, String, Vec, or other caller-arena allocation can escape into the
    // independently supervised tasks below.
    let reports = match precompute_semantic_reports(&template, &plans) {
        Ok(reports) => reports,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let teardown_order = match consumer_first_teardown_order(&template) {
        Ok(order) => order,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    drop(template);
    let (mut supervisor, mut verification_handles, completion) = match prepare_supervisor(
        &plans,
        &tokens,
        teardown_order,
        #[cfg(feature = "wasm-c65-async-chain-acceptance")]
        async_control,
        reports,
    ) {
        Ok(supervisor) => supervisor,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    let pairs = match publication_pairs(&tokens, &domains) {
        Ok(pairs) => pairs,
        Err(error) => {
            abort_pristine_registry_batch(&tokens, &domains)?;
            return Err(error);
        }
    };
    if batch.reserve_managed_publication(&pairs, 1).is_err() {
        drop(batch);
        abort_pristine_registry_batch(&tokens, &domains)?;
        return Err(ComponentGraphPrincipalLifecycleError::SchedulerReservation);
    }

    for index in 0..plans.len() {
        unsafe {
            batch.prepare_managed_instance_owned(
                tokens[index],
                domains[index],
                PRINCIPAL_TASK_NAME,
                PrincipalTask {
                    token: tokens[index],
                    #[cfg(feature = "wasm-c65-async-chain-acceptance")]
                    c65_generation: plans[index].async_route.map(|route| route.generation),
                },
            );
        }
    }
    let prepared_managed = &batch.prepared_handles()[..plans.len()];
    supervisor.handles.extend(prepared_managed.iter().cloned());
    verification_handles.extend(prepared_managed.iter().cloned());
    let completion_for_run = completion.clone();
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    batch.prepare("wasm-graph-supervisor", async move {
        supervisor.run().await;
    });
    system.restore();

    let supervisor_index = plans.len();
    if !batch.try_reserve_prepared_task_registrations(supervisor_index, 1) {
        lifecycle_invariant_failed(
            &tokens,
            "graph principal supervisor registration reservation failed",
        );
    }
    if install_payloads(&plans, &tokens, &mut tables).is_err() {
        lifecycle_invariant_failed(&tokens, "graph principal payload installation failed");
    }
    if bind_prepared_tasks(&plans, &tokens, &batch).is_err() {
        lifecycle_invariant_failed(&tokens, "graph principal atomic binding failed");
    }

    let prepared_supervisor = batch.prepared_handles()[supervisor_index].clone();
    let mut published = match unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| {
            super::component_instances::registry().activate_batch(bindings)
        })
    } {
        Ok(handles) => handles,
        Err(_) => lifecycle_invariant_failed(
            &tokens,
            "reserved graph principal publication failed after atomic binding",
        ),
    };
    let exact = published.len() == plans.len() + 1
        && published.iter().all(TaskHandle::is_published)
        && published[..plans.len()]
            .iter()
            .zip(&verification_handles)
            .all(|(published, prepared)| {
                published.id() == prepared.id()
                    && published.allocation_domain() == prepared.allocation_domain()
                    && published.shares_status_with(prepared)
            })
        && published[supervisor_index].id() == prepared_supervisor.id()
        && published[supervisor_index].shares_status_with(&prepared_supervisor);
    if !exact {
        lifecycle_invariant_failed(&tokens, "published graph principal identities changed");
    }
    let supervisor = published
        .pop()
        .expect("validated graph publication contains its SYSTEM supervisor");
    drop(published);
    Ok((
        ComponentGraphPrincipalRun {
            supervisor,
            completion: completion_for_run,
        },
        route_receipt,
    ))
}

/// Allocate and publish one fresh kernel principal per admitted graph node.
///
/// This public C6.3-compatible path remains resource-free and rejects every
/// manifest containing a resource edge. Revalidation and the zero-grant gate
/// run before any owner, arena, registry slot, task, or CSpace is created. The
/// executor reservation is established while the registry batch is still
/// pristine and abortable. After the first tracked future is prepared, every
/// remaining fallible identity operation is an internal invariant gate and
/// fail-stops rather than pretending the arena can be rolled back safely.
pub fn start_component_graph_principals(
    template: Arc<ComponentGraphPrincipalTemplate>,
) -> Result<ComponentGraphPrincipalRun, ComponentGraphPrincipalLifecycleError> {
    start_component_graph_principals_inner(
        template,
        ResourceRouteRequest::None,
        AsyncRouteRequest::None,
    )
    .map(|(run, receipt)| {
        debug_assert!(receipt.is_none());
        run
    })
}

/// Convenience wrapper which observes a graph run to completion. Dropping the
/// returned future after publication drops only the observation handle; the
/// scheduler-owned SYSTEM supervisor still tears every node down.
pub async fn supervise_component_graph_principals(
    template: Arc<ComponentGraphPrincipalTemplate>,
) -> Result<ComponentGraphPrincipalReports, ComponentGraphPrincipalLifecycleError> {
    start_component_graph_principals(template)?.wait().await
}

/// Allocation-free checks for the feature-gated architecture-neutral model.
/// The real registry/scheduler path is exercised by
/// the feature-specific QEMU acceptance; this early sanity helper remains directly callable
/// despite the kernel archive's `test = false` setting.
#[cfg(any(
    feature = "wasm-c63-graph-principal-acceptance",
    feature = "wasm-c64-resource-route-acceptance",
    feature = "wasm-c65-async-chain-acceptance"
))]
pub(crate) fn run_host_model_selftest() -> bool {
    if checked_owner_quota(1) != Some(1 + COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES)
        || checked_owner_quota(usize::MAX).is_some()
        || encode_runtime_unavailable_completion(0) != RUNTIME_UNAVAILABLE_COMPLETION
        || completion_guest_calls(RUNTIME_UNAVAILABLE_COMPLETION) != Some(0)
        || completion_guest_calls(encode_runtime_unavailable_completion(1)) != Some(1)
        || encode_runtime_unavailable_completion(RUNTIME_UNAVAILABLE_GUEST_CALL_MASK + 1)
            != INVALID_ENVELOPE_COMPLETION
    {
        return false;
    }
    let Ok(resources) = ResourceTable::new(1, 1) else {
        return false;
    };
    let mut payload = PrincipalPayload::new(
        PrincipalPlan {
            node: ComponentGraphNodeId::new(0),
            owner_quota: 1 + COMPONENT_GRAPH_PRINCIPAL_LIFECYCLE_OVERHEAD_BYTES,
            guest_memory_limit: 1,
            fuel_limit: 1,
            poll_quantum: 1,
            resource_types: 0,
            resource_slots: 1,
            resource_generation: 1,
            expected_resource_peak: 0,
            expected_revoked_capabilities: 0,
            drains: [None; 2],
            report_kind: PrincipalReportKind::Ordinary,
            #[cfg(feature = "wasm-c65-async-chain-acceptance")]
            async_route: None,
        },
        resources,
    );
    payload.runtime_unavailable_completion() == RUNTIME_UNAVAILABLE_COMPLETION
        && payload.resources.is_empty()
        && payload.fuel.consumed == 0
        && payload.runtime_unavailable_completion() == INVALID_ENVELOPE_COMPLETION
}

#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
fn qemu_acceptance_template() -> Option<(Arc<ComponentGraphPrincipalTemplate>, AllocationDomain)> {
    const EMPTY_COMPONENT: &[u8] = b"\0asm\r\0\x01\0";
    const EMPTY_WORLD_WIT: &str = r#"
        package test:c63@1.0.0;

        world empty {}
    "#;
    const EMPTY_WORLD: &str = "test:c63/empty@1.0.0";

    let caller_quota = 2usize.checked_mul(1024)?.checked_mul(1024)?;
    let caller_domains = HEAP.create_fresh_domains_batch(&[caller_quota]).ok()?;
    let [caller_domain] = caller_domains.as_slice() else {
        let _ = release_empty_domains(&caller_domains);
        return None;
    };
    let caller_domain = *caller_domain;
    drop(caller_domains);

    // SAFETY: this acceptance task exclusively owns the unpublished fresh
    // domain. Construction and every failure-path destructor run synchronously
    // in this scope. The sole successful escape is the template under test; the
    // same non-yielding SYSTEM task immediately consumes it through `start` and
    // proves the domain empty before its first await, so no raw reclaimer can
    // race this temporary ownership proof.
    let mut caller = unsafe { crate::heap::enter_domain(caller_domain) };
    let template = (|| {
        let profile = ProfileIdentity::PROFILE_1_ASYNC;
        let root = ComponentArtifact::copy_from(EMPTY_COMPONENT, profile).ok()?;
        let child = ComponentArtifact::copy_from(EMPTY_COMPONENT, profile).ok()?;
        let exact_world = WorldContract::parse(EMPTY_WORLD_WIT, EMPTY_WORLD).ok()?;
        let nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "root-principal",
                nesting: ComponentGraphNesting::Root,
                exact_world: &exact_world,
                trust: ArtifactTrust::ImagePinned(root.identity()),
                limits: InstanceLimits {
                    memory_bytes: 64 * 1024,
                    total_fuel: 1_000,
                    poll_quantum: 100,
                    resources: 3,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "child-principal",
                nesting: ComponentGraphNesting::Nested {
                    parent: ComponentGraphNodeId::new(0),
                },
                exact_world: &exact_world,
                trust: ArtifactTrust::ImagePinned(child.identity()),
                limits: InstanceLimits {
                    memory_bytes: 128 * 1024,
                    total_fuel: 2_000,
                    poll_quantum: 200,
                    resources: 5,
                },
                interfaces: &[],
            },
        ];
        let policy = ComponentGraphAdmissionPolicy {
            name: "c63-qemu-principals",
            profile,
            nodes: &nodes,
            edges: &[],
            external_imports: &[],
            published_exports: &[],
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let admitted = admit_component_graph(
            Vec::from([root, child]),
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        ComponentGraphPrincipalTemplate::new(Arc::new(admitted))
            .ok()
            .map(Arc::new)
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

/// Exercise the real registry, scheduler, payload, supervisor, and teardown
/// path with a two-node, zero-edge, zero-grant admitted graph.
#[cfg(feature = "wasm-c63-graph-principal-acceptance")]
pub(crate) async fn run_qemu_acceptance() -> bool {
    let before = super::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return false;
    }
    let Some((template, caller_domain)) = qemu_acceptance_template() else {
        return false;
    };
    if !template.grants().is_empty() {
        drop(template);
        let _ = release_empty_domain(caller_domain);
        return false;
    }
    let run = match start_component_graph_principals(template) {
        Ok(run) => run,
        Err(_) => {
            let _ = release_empty_domain(caller_domain);
            return false;
        }
    };
    // This retirement precedes the first await. It proves the published SYSTEM
    // supervisor retained no Arc or transitive projection allocation from the
    // tracked caller template.
    if !release_empty_domain(caller_domain) {
        return false;
    }
    let Ok(reports) = run.wait().await else {
        return false;
    };
    if reports.nodes().len() != 2 {
        return false;
    }
    for (index, (fuel_limit, resource_slots)) in [(1_000, 3), (2_000, 5)].iter().enumerate() {
        let Some(report) = reports.node(ComponentGraphNodeId::new(index as u16)) else {
            return false;
        };
        if report.terminal() != ComponentGraphNodeTerminal::RuntimeUnavailable
            || report.fuel().limit() != *fuel_limit
            || report.fuel().consumed() != 0
            || report.resources().declared_types() != 0
            || report.resources().slot_limit() != *resource_slots
            || report.resources().peak_slots() != 0
            || report.resources().live_slots() != 0
        {
            return false;
        }
    }
    let after = super::component_instances::registry().occupancy_stats();
    after.occupied == 0 && after.header_mismatches == 0
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn c64_resource_edge() -> ComponentGraphEdgeSpec {
    ComponentGraphEdgeSpec::new(
        ComponentGraphExportEndpoint::new(
            ComponentGraphNodeId::new(0),
            ComponentGraphEntityIndex::new(0),
        ),
        ComponentGraphImportEndpoint::new(
            ComponentGraphNodeId::new(1),
            ComponentGraphEntityIndex::new(0),
        ),
    )
}

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn c64_qemu_acceptance_template() -> Option<(Arc<ComponentGraphPrincipalTemplate>, AllocationDomain)>
{
    let caller_quota = 4usize.checked_mul(1024)?.checked_mul(1024)?;
    let caller_domains = HEAP.create_fresh_domains_batch(&[caller_quota]).ok()?;
    let [caller_domain] = caller_domains.as_slice() else {
        let _ = release_empty_domains(&caller_domains);
        return None;
    };
    let caller_domain = *caller_domain;
    drop(caller_domains);

    // SAFETY: the acceptance task exclusively owns this unpublished domain.
    // It synchronously consumes the sole successful template escape through
    // the C6.4 start gate and proves the arena empty before its first await.
    let mut caller = unsafe { crate::heap::enter_domain(caller_domain) };
    let template = (|| {
        let pin = C64_RESOURCE_ROUTE_QEMU_ACCEPTANCE;
        if pin.profile() != ProfileIdentity::PROFILE_1_ASYNC
            || pin.profile().execution_enabled()
            || pin.interface() != "test:c64-resource/route@1.0.0"
            || pin.wit_sha256() != C64_RESOURCE_ROUTE_WIT_SHA256
        {
            return None;
        }
        let provider = ComponentArtifact::copy_from(pin.provider_bytes(), pin.profile()).ok()?;
        let consumer = ComponentArtifact::copy_from(pin.consumer_bytes(), pin.profile()).ok()?;
        if provider.identity().as_bytes() != &pin.provider_sha256()
            || consumer.identity().as_bytes() != &pin.consumer_sha256()
        {
            return None;
        }
        let provider_world = WorldContract::parse(pin.wit_source(), pin.provider_world()).ok()?;
        let consumer_world = WorldContract::parse(pin.wit_source(), pin.consumer_world()).ok()?;
        let limits = pin.limits();
        let nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "c64-resource-provider",
                nesting: ComponentGraphNesting::Root,
                exact_world: &provider_world,
                trust: ArtifactTrust::ImagePinned(provider.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c64-resource-consumer",
                nesting: ComponentGraphNesting::Root,
                exact_world: &consumer_world,
                trust: ArtifactTrust::ImagePinned(consumer.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
        ];
        let edges = [c64_resource_edge()];
        let policy = ComponentGraphAdmissionPolicy {
            name: "c64-qemu-resource-route",
            profile: pin.profile(),
            nodes: &nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &[],
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let resource_policy = [ComponentGraphResourceEdgePolicy {
            edge: c64_resource_edge(),
            mode: ComponentGraphResourceMode::OwnAndBorrow,
        }];
        let admitted = admit_component_graph_with_resource_policy(
            Vec::from([provider, consumer]),
            &policy,
            &resource_policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted)).ok()?;
        if template.runtime_ready()
            || !template.grants().is_empty()
            || exact_c64_resource_route_plan(&template).is_err()
        {
            return None;
        }
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

#[cfg(feature = "wasm-c64-resource-route-acceptance")]
fn start_c64_resource_route(
    template: Arc<ComponentGraphPrincipalTemplate>,
) -> Result<(ComponentGraphPrincipalRun, ResourceRouteReceipt), ComponentGraphPrincipalLifecycleError>
{
    let (run, receipt) = start_component_graph_principals_inner(
        template,
        ResourceRouteRequest::C64Exact,
        AsyncRouteRequest::None,
    )?;
    receipt
        .map(|receipt| (run, receipt))
        .ok_or(ComponentGraphPrincipalLifecycleError::ResourceRouteSetup)
}

/// Exercise exact admission, prepublication borrow/own setup, target-first
/// teardown, semantic reports, and arena/registry retirement without ever
/// decoding, instantiating, or calling either pinned guest Component.
#[cfg(feature = "wasm-c64-resource-route-acceptance")]
pub(crate) async fn run_c64_qemu_acceptance() -> Option<u64> {
    let before = super::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return None;
    }
    let Some((template, caller_domain)) = c64_qemu_acceptance_template() else {
        return None;
    };
    if !matches!(
        start_component_graph_principals(template.clone()),
        Err(ComponentGraphPrincipalLifecycleError::ResourceRouteRequired)
    ) {
        drop(template);
        let _ = release_empty_domain(caller_domain);
        return None;
    }
    let (run, route) = match start_c64_resource_route(template) {
        Ok(started) => started,
        Err(_) => {
            let _ = release_empty_domain(caller_domain);
            return None;
        }
    };
    if !release_empty_domain(caller_domain) {
        return None;
    }
    if route.borrow_invocations != 1
        || route.owned_transfers != 1
        || route.attenuated_grants != 1
        || route.source_peak_slots != 1
        || route.target_peak_slots != 1
        || route.borrow_source_caps_before != 1
        || route.borrow_source_caps_after != 1
        || route.borrow_target_caps_before != 0
        || route.borrow_target_caps_after != 0
        || route.source_caps_after_transfer != 0
        || route.target_caps_after_transfer != 1
        || route.source_live_after_transfer != 0
        || route.target_live_after_transfer != 1
        || !route.target_grant_absent
    {
        return None;
    }
    let Ok(reports) = run.wait().await else {
        return None;
    };
    let guest_calls = reports.guest_calls();
    if reports.nodes().len() != 2
        || reports.teardown.len() != 2
        || reports.teardown[0].node != ComponentGraphNodeId::new(1)
        || reports.teardown[0].revoked_capabilities != 1
        || reports.teardown[0].guest_calls != 0
        || reports.teardown[1].node != ComponentGraphNodeId::new(0)
        || reports.teardown[1].revoked_capabilities != 0
        || reports.teardown[1].guest_calls != 0
        || guest_calls != 0
    {
        return None;
    }
    for (index, declared_types) in [1, 0].into_iter().enumerate() {
        let Some(report) = reports.node(ComponentGraphNodeId::new(index as u16)) else {
            return None;
        };
        if report.terminal() != ComponentGraphNodeTerminal::RuntimeUnavailable
            || report.fuel().limit() != 1_000
            || report.fuel().consumed() != 0
            || report.resources().declared_types() != declared_types
            || report.resources().slot_limit() != 2
            || report.resources().peak_slots() != 1
            || report.resources().live_slots() != 0
        {
            return None;
        }
    }
    let after = super::component_instances::registry().occupancy_stats();
    (after.occupied == 0 && after.header_mismatches == 0).then_some(guest_calls)
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn c65_qemu_acceptance_template() -> Option<(Arc<ComponentGraphPrincipalTemplate>, AllocationDomain)>
{
    let caller_quota = 6usize.checked_mul(1024)?.checked_mul(1024)?;
    let caller_domains = HEAP.create_fresh_domains_batch(&[caller_quota]).ok()?;
    let [caller_domain] = caller_domains.as_slice() else {
        let _ = release_empty_domains(&caller_domains);
        return None;
    };
    let caller_domain = *caller_domain;
    drop(caller_domains);

    // SAFETY: this unpublished fresh domain is owned exclusively by the
    // acceptance task. The admitted template is synchronously consumed by the
    // sealed C6.5 start gate before the first await, then this caller domain is
    // proven empty. No artifact allocation enters a node or SYSTEM stream.
    let mut caller = unsafe { crate::heap::enter_domain(caller_domain) };
    let template = (|| {
        let pin = C65_ASYNC_CHAIN_QEMU_ACCEPTANCE;
        if pin.profile() != ProfileIdentity::PROFILE_1_ASYNC
            || pin.profile().execution_enabled()
            || pin.wit_sha256() != C65_ASYNC_CHAIN_WIT_SHA256
            || pin.interface() != "test:c65-chain/pipe@1.0.0"
        {
            return None;
        }
        let source = ComponentArtifact::copy_from(pin.source_bytes(), pin.profile()).ok()?;
        let relay = ComponentArtifact::copy_from(pin.relay_bytes(), pin.profile()).ok()?;
        let sink = ComponentArtifact::copy_from(pin.sink_bytes(), pin.profile()).ok()?;
        if source.identity().as_bytes() != &pin.source_sha256()
            || relay.identity().as_bytes() != &pin.relay_sha256()
            || sink.identity().as_bytes() != &pin.sink_sha256()
            || source.identity() == relay.identity()
            || source.identity() == sink.identity()
            || relay.identity() == sink.identity()
        {
            return None;
        }
        let source_world = WorldContract::parse(pin.wit_source(), pin.source_world()).ok()?;
        let relay_world = WorldContract::parse(pin.wit_source(), pin.relay_world()).ok()?;
        let sink_world = WorldContract::parse(pin.wit_source(), pin.sink_world()).ok()?;
        let limits = pin.limits();
        let nodes = [
            ComponentGraphNodeAdmissionPolicy {
                label: "c65-source",
                nesting: ComponentGraphNesting::Root,
                exact_world: &source_world,
                trust: ArtifactTrust::ImagePinned(source.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c65-relay",
                nesting: ComponentGraphNesting::Root,
                exact_world: &relay_world,
                trust: ArtifactTrust::ImagePinned(relay.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
            ComponentGraphNodeAdmissionPolicy {
                label: "c65-sink",
                nesting: ComponentGraphNesting::Root,
                exact_world: &sink_world,
                trust: ArtifactTrust::ImagePinned(sink.identity()),
                limits: InstanceLimits {
                    memory_bytes: limits.memory_bytes,
                    total_fuel: limits.total_fuel,
                    poll_quantum: limits.poll_quantum,
                    resources: limits.resources,
                },
                interfaces: &[],
            },
        ];
        let edges = [c65_async_edge(0, 1), c65_async_edge(1, 2)];
        let published = [
            vibeos_component_runtime::graph::ComponentGraphPublishedExportSpec::new(
                ComponentGraphExportEndpoint::new(
                    ComponentGraphNodeId::new(2),
                    ComponentGraphEntityIndex::new(0),
                ),
            ),
        ];
        let policy = ComponentGraphAdmissionPolicy {
            name: "c65-qemu-async-chain",
            profile: pin.profile(),
            nodes: &nodes,
            edges: &edges,
            external_imports: &[],
            published_exports: &published,
            cycle_policy: ComponentGraphCyclePolicy::AcyclicOnly,
        };
        let admitted = admit_component_graph(
            Vec::from([source, relay, sink]),
            &policy,
            &CallerAuthority { offers: &[] },
        )
        .ok()?;
        let template = ComponentGraphPrincipalTemplate::new(Arc::new(admitted)).ok()?;
        exact_c65_async_route(&template).ok()?;
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

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
fn start_c65_async_chain(
    template: Arc<ComponentGraphPrincipalTemplate>,
    cause: StreamCloseReason,
) -> Result<ComponentGraphPrincipalRun, ComponentGraphPrincipalLifecycleError> {
    let (run, resource_receipt) = start_component_graph_principals_inner(
        template,
        ResourceRouteRequest::None,
        AsyncRouteRequest::C65Exact { cause },
    )?;
    if resource_receipt.is_some() {
        return Err(ComponentGraphPrincipalLifecycleError::AsyncRouteSetup);
    }
    Ok(run)
}

#[cfg(feature = "wasm-c65-async-chain-acceptance")]
async fn run_c65_qemu_scenario(cause: StreamCloseReason) -> Option<C65AsyncChainReceipt> {
    let before = super::component_instances::registry().occupancy_stats();
    if before.occupied != 0 || before.header_mismatches != 0 {
        return None;
    }
    let (template, caller_domain) = c65_qemu_acceptance_template()?;
    if !matches!(
        start_component_graph_principals(template.clone()),
        Err(ComponentGraphPrincipalLifecycleError::AsyncRouteRequired)
    ) {
        drop(template);
        let _ = release_empty_domain(caller_domain);
        return None;
    }
    let run = match start_c65_async_chain(template, cause) {
        Ok(run) => run,
        Err(_) => {
            let _ = release_empty_domain(caller_domain);
            return None;
        }
    };
    if !release_empty_domain(caller_domain) {
        return None;
    }
    let reports = run.wait().await.ok()?;
    if reports.nodes().len() != C65_NODE_COUNT
        || reports.teardown.len() != C65_NODE_COUNT
        || reports.guest_calls() != 0
        || reports
            .teardown
            .iter()
            .zip([(2_u16, 2_usize), (1, 2), (0, 1)])
            .any(|(receipt, (node, revoked))| {
                receipt.node != ComponentGraphNodeId::new(node)
                    || receipt.revoked_capabilities != revoked
                    || receipt.guest_calls != 0
            })
    {
        return None;
    }
    for (index, peak) in [1_u64, 2, 2].into_iter().enumerate() {
        let report = reports.node(ComponentGraphNodeId::new(index as u16))?;
        if report.terminal() != ComponentGraphNodeTerminal::RuntimeUnavailable
            || report.fuel().limit() != 1_000
            || report.fuel().consumed() != 0
            || report.resources().declared_types() != 0
            || report.resources().slot_limit() != 8
            || report.resources().peak_slots() != peak
            || report.resources().live_slots() != 0
        {
            return None;
        }
    }
    let receipt = reports.async_chain?;
    if receipt.cause != cause
        || receipt.wake_registrations == 0
        || receipt.wake_registrations != receipt.wake_callbacks
        || receipt.wake_callbacks != receipt.continuation_resumes
        || receipt.continuation_resumes != receipt.sealed_resumes
        || receipt.productive_self_wakes == 0
        || receipt.source_chunks <= receipt.relay_chunks
        || receipt.relay_chunks <= receipt.sink_chunks
        || receipt.sink_chunks < 9
        || receipt.peak_depths != [8, 8, 8]
        || !receipt.no_active_repoll
    {
        return None;
    }
    let after = super::component_instances::registry().occupancy_stats();
    (after.occupied == 0 && after.header_mismatches == 0).then_some(receipt)
}

/// Exercise two fresh validation-only graphs. Each uses real SYSTEM streams,
/// exact node CSpaces, external continuations, bounded backpressure, and
/// consumer-first typed propagation. Admission validates the pinned artifacts,
/// but the transport payload never instantiates or calls guest code.
#[cfg(feature = "wasm-c65-async-chain-acceptance")]
pub(crate) async fn run_c65_qemu_acceptance() -> bool {
    let Some(fault) = run_c65_qemu_scenario(StreamCloseReason::BackendFault).await else {
        return false;
    };
    let Some(cancelled) = run_c65_qemu_scenario(StreamCloseReason::Cancelled).await else {
        return false;
    };
    fault.cause == StreamCloseReason::BackendFault
        && cancelled.cause == StreamCloseReason::Cancelled
        && fault.peak_depths == [8, 8, 8]
        && cancelled.peak_depths == [8, 8, 8]
        && fault.no_active_repoll
        && cancelled.no_active_repoll
}
