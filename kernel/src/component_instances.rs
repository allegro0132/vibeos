//! SYSTEM-owned lifecycle registry for managed WASM component invocations.
//!
//! The core registry owns each stable instance Space/CSpace and the arena-local
//! payload.  The executor future contains only its opaque core token, while a
//! separate fixed control table retains the exact TaskHandle and publishes a
//! scalar terminal result to VSH.  The SSH command remains fail-closed until a
//! target acceptance gate explicitly opens the image/session policy.

#[cfg(feature = "wasm-c48-qemu-acceptance")]
#[path = "component_instances_acceptance.rs"]
mod acceptance;

#[cfg(any(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
#[path = "component_instances_native_async.rs"]
mod native_async_acceptance;
#[cfg(any(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
#[path = "native_pending_shadow_model.rs"]
mod native_pending_shadow_model;

#[cfg(feature = "ssh-component-command")]
extern crate alloc;

#[cfg(feature = "ssh-component-command")]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "ssh-component-command")]
use core::cell::UnsafeCell;
#[cfg(feature = "ssh-component-command")]
use core::future::Future;
#[cfg(feature = "ssh-component-command")]
use core::marker::PhantomData;
#[cfg(feature = "ssh-component-command")]
use core::num::NonZeroU64;
#[cfg(feature = "ssh-component-command")]
use core::ops::{Deref, DerefMut};
#[cfg(feature = "ssh-component-command")]
use core::pin::Pin;
#[cfg(feature = "ssh-component-command")]
use core::ptr;
#[cfg(feature = "ssh-component-command")]
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicU8, Ordering};
#[cfg(feature = "ssh-component-command")]
use core::task::{Context, Poll};

use crate::exec::ReclaimableFaultWitness;
#[cfg(feature = "ssh-component-command")]
use crate::exec::{
    ExactTaskWake, OneShotWaitQueue, OneShotWake, PreparedTaskBatch, ReclaimableTaskWitness,
    TaskDetachReason, TaskDetachTarget, TaskHandle, TaskId, TaskState,
};
#[cfg(feature = "ssh-component-command")]
use crate::heap::{AllocationDomain, OwnerId};
#[cfg(feature = "wasm-c48-qemu-acceptance")]
use crate::instance::InstanceContinuation;
#[cfg(feature = "ssh-component-command")]
use crate::instance::{
    CooperativeCancelOutcome, FinalizeOutcome, InstanceContinuationKind, InstancePayload,
    InstancePhase, InstanceSpace, InstanceToken, RegistryError, ReserveError, TerminalRetireKind,
};
use crate::instance::{FaultGateOutcome, InstanceRegistry};
#[cfg(feature = "ssh-component-command")]
use crate::sync::SpinLock;
use crate::HEAP;

#[cfg(feature = "ssh-component-command")]
use crate::cap::{CSpace, CSpaceIdentity, Cap, CapError, InvocationLease, Resource, Rights};

#[cfg(feature = "ssh-component-command")]
use vibeos_component_admission::{
    admit, AdmissionPolicy, AdmittedComponent, ArtifactTrust, CallerAuthority, CommandStreamMode,
    ComponentArtifact, InstanceLimits,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_command::{
    try_manifest_from_admitted, validate_admitted_stream_filter, RunnerBuildError,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_format::TrapCode;
#[cfg(any(
    feature = "wasm-c48-qemu-acceptance",
    feature = "wasm-c53-native-async-qemu-acceptance"
))]
use vibeos_component_host::ByteStream;
#[cfg(feature = "ssh-component-command")]
use vibeos_component_host::{
    ByteStreamReader, ByteStreamSupervisor, ByteStreamWriter, StreamCloseOutcome,
    StreamCloseReason, StreamError, StreamPreparedReceive, StreamReceiveCommit,
    StreamReceiveDispatch, StreamSendDispatch, VibeHostManifest, MAX_STREAM_CHUNK_BYTES,
    STREAM_CLOSE_READER_FUNCTION, STREAM_CLOSE_WRITER_FUNCTION, STREAM_INTERFACE,
    STREAM_READ_FUNCTION, STREAM_WRITE_FUNCTION,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::host::{
    HostDispatch, HostDispatcher, HostError, HostOperationToken, HostPayloadAllocation,
    HostPrepared, HostRequest, HostResponse, HostWakeToken,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::resource::{ResourceTable, ResourceTypeId};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::sync::{SyncError, SynchronousComponent, TypedPoll};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::value::{CanonicalValue, ResourceOwnership, ValueType};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::world::WorldContract;
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::HostImportInfo;
#[cfg(feature = "ssh-component-command")]
use vibeos_image_policy::{ComponentCommandPin, ComponentStreamMode, SSH_EXEC_COMPONENT};
#[cfg(feature = "ssh-component-command")]
use vibeos_sshd::{AuthorizedProfile, SshExecComponentSessionPolicy};
#[cfg(feature = "ssh-component-command")]
use vibeos_vsh::{
    ComponentArtifactIdentity, ComponentCommandManifest, ComponentTerminal, ComponentTrapCode,
    ManagedComponentAcknowledge, ManagedComponentCancel, ManagedComponentIo,
    ManagedComponentLifecycle, ManagedComponentStartAbort, ManagedComponentStartLease,
    ManagedComponentState, ManagedComponentStateFuture, ManagedComponentToken, Session,
    SshExecComponentIoInstall, SshExecComponentPolicy, StreamMode, VIBE_STREAM_FILTER_WORLD,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

static INSTANCES: InstanceRegistry = InstanceRegistry::new();

pub(crate) fn registry() -> &'static InstanceRegistry {
    &INSTANCES
}

#[cfg(feature = "ssh-component-command")]
const CONTROL_SLOTS: usize = crate::instance::MAX_INSTANCE_SLOTS;
#[cfg(feature = "ssh-component-command")]
const CONTROL_SLOT_BITS: u32 = 8;
#[cfg(feature = "ssh-component-command")]
const MAX_CONTROL_GENERATION: u64 = u64::MAX >> CONTROL_SLOT_BITS;
#[cfg(feature = "ssh-component-command")]
const INSTANCE_HEAP_QUOTA: usize = 4 * 1024 * 1024;
#[cfg(feature = "ssh-component-command")]
const CONTROL_ACQUIRE_SPINS: usize = 512;
#[cfg(feature = "ssh-component-command")]
const CONTROL_FAULT_ACQUIRE_SPINS: usize = 1 << 20;

#[cfg(feature = "ssh-component-command")]
const CONTROL_FREE: u64 = 0;
#[cfg(feature = "ssh-component-command")]
const CONTROL_POISONED: u64 = 1;
#[cfg(feature = "ssh-component-command")]
const CONTROL_ACQUIRING: u64 = 2;
#[cfg(feature = "ssh-component-command")]
const CONTROL_HELD: u64 = 3;
#[cfg(feature = "ssh-component-command")]
const POLICY_CLOSED: u8 = 0;
#[cfg(feature = "ssh-component-command")]
const POLICY_PASSED: u8 = 1;
#[cfg(feature = "ssh-component-command")]
const POLICY_FAILED: u8 = 2;

#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
const LIFECYCLE_HEALTHY: u8 = 0;
#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
const LIFECYCLE_FAILED: u8 = 1;

#[cfg(feature = "ssh-component-command")]
const TASK_SHADOW_VACANT: u8 = 0;
#[cfg(feature = "ssh-component-command")]
const TASK_SHADOW_PREPARED: u8 = 1;
#[cfg(feature = "ssh-component-command")]
const TASK_SHADOW_RUNNING: u8 = 2;
#[cfg(feature = "ssh-component-command")]
const TASK_SHADOW_COMPLETE: u8 = 3;
#[cfg(feature = "ssh-component-command")]
const TASK_SHADOW_QUARANTINED: u8 = 4;
#[cfg(feature = "ssh-component-command")]
const PUBLICATION_STATE_BITS: u32 = 2;
#[cfg(feature = "ssh-component-command")]
const PUBLICATION_PREPARED: u64 = 1;
#[cfg(feature = "ssh-component-command")]
const PUBLICATION_COMMITTED: u64 = 2;
#[cfg(feature = "ssh-component-command")]
const PUBLICATION_REJECTED: u64 = 3;

#[cfg(feature = "ssh-component-command")]
const fn publication_state(generation: u64, state: u64) -> u64 {
    (generation << PUBLICATION_STATE_BITS) | state
}

#[cfg(feature = "ssh-component-command")]
const STREAM_READ_WORK: u64 = MAX_STREAM_CHUNK_BYTES as u64 + 4;
#[cfg(feature = "ssh-component-command")]
const STREAM_WRITE_BASE_WORK: u64 = 4;
#[cfg(feature = "ssh-component-command")]
const STREAM_CLOSE_WORK: u64 = 1;

#[cfg(feature = "ssh-component-command")]
static IMAGE_ROOT: AtomicPtr<ImageRoot> = AtomicPtr::new(ptr::null_mut());
#[cfg(feature = "ssh-component-command")]
static SSH_POLICY_GATE: AtomicU8 = AtomicU8::new(POLICY_CLOSED);
#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
static LIFECYCLE_HEALTH: AtomicU8 = AtomicU8::new(LIFECYCLE_HEALTHY);
#[cfg(feature = "ssh-component-command")]
static CONTROL: ControlGate = ControlGate::new();
#[cfg(feature = "ssh-component-command")]
static LIFECYCLE: ImageComponentLifecycle = ImageComponentLifecycle;

#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
fn lifecycle_is_healthy() -> bool {
    LIFECYCLE_HEALTH.load(Ordering::Acquire) == LIFECYCLE_HEALTHY
}

#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
fn lifecycle_fail_stop() {
    CONTROL.reject_prepared_publications();
    LIFECYCLE_HEALTH.store(LIFECYCLE_FAILED, Ordering::Release);
    SSH_POLICY_GATE.store(POLICY_FAILED, Ordering::Release);
    CONTROL.request_fail_stop_wake();
}

#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
fn lifecycle_poll_permit() -> (&'static AtomicU8, u8) {
    (&LIFECYCLE_HEALTH, LIFECYCLE_HEALTHY)
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn lifecycle_is_healthy() -> bool {
    native_async_acceptance::lifecycle_is_healthy()
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn lifecycle_fail_stop() {
    native_async_acceptance::lifecycle_fail_stop();
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
fn lifecycle_poll_permit() -> (&'static AtomicU8, u8) {
    native_async_acceptance::lifecycle_poll_permit()
}

#[cfg(feature = "ssh-component-command")]
struct ImageRoot {
    admitted: AdmittedComponent,
    manifest: ComponentCommandManifest,
    ssh_policy: SshExecComponentPolicy,
    policy_incarnation: NonZeroU64,
}

/// Copy-only projection of the exact capabilities installed in one stable
/// registry-owned CSpace.  It is lookup metadata, never ownership: all four
/// backing Arcs remain owned solely by the CSpace until the registry performs
/// its terminal exact reset.
#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistryStreamBindings {
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
    stdin: Cap,
    stdout: Cap,
    stdin_supervisor: Cap,
    stdout_supervisor: Cap,
}

/// One transient start envelope. It is consumed while the core slot is still
/// Reserved and never enters the arena payload or a published child future.
#[cfg(feature = "ssh-component-command")]
struct InstalledComponentIo {
    stdin: Arc<ByteStreamReader>,
    stdout: Arc<ByteStreamWriter>,
    stdin_supervisor: Arc<ByteStreamSupervisor>,
    stdout_supervisor: Arc<ByteStreamSupervisor>,
}

#[cfg(feature = "ssh-component-command")]
enum ComponentStartInput {
    ManagedSync(ManagedComponentStartLease),
    #[cfg(feature = "ssh-native-async-command")]
    ManagedNativeAsync(ManagedComponentStartLease),
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    Acceptance(Option<InstalledComponentIo>),
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    NativeAsyncAcceptance(Option<InstalledComponentIo>),
}

#[cfg(feature = "ssh-component-command")]
impl ComponentStartInput {
    fn kind(&self) -> ControlStartKind {
        match self {
            Self::ManagedSync(_) => ControlStartKind::ManagedSync,
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(_) => ControlStartKind::ManagedNativeAsync,
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(_) => ControlStartKind::Acceptance,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(_) => ControlStartKind::NativeAsyncAcceptance,
        }
    }

    fn cleanup(&self) -> Option<ManagedComponentStartLease> {
        match self {
            Self::ManagedSync(cleanup) => Some(*cleanup),
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(cleanup) => Some(*cleanup),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(_) => None,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(_) => None,
        }
    }

    fn abort_unpublished(&self, terminal: ComponentTerminal) -> ComponentTerminal {
        match self {
            Self::ManagedSync(cleanup) => match cleanup.abort_before_child_publication(terminal) {
                ManagedComponentStartAbort::CleanAborted => terminal,
                ManagedComponentStartAbort::Quarantined => ComponentTerminal::RunnerFault,
            },
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(cleanup) => {
                match cleanup.abort_before_child_publication(terminal) {
                    ManagedComponentStartAbort::CleanAborted => terminal,
                    ManagedComponentStartAbort::Quarantined => ComponentTerminal::RunnerFault,
                }
            }
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(Some(io)) => finalize_unpublished_start_error(io, terminal),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(None) => ComponentTerminal::RunnerFault,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(Some(io)) => finalize_unpublished_start_error(io, terminal),
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(None) => ComponentTerminal::RunnerFault,
        }
    }

    fn bind(&self, token: ManagedComponentToken) -> bool {
        match self {
            Self::ManagedSync(cleanup) => cleanup.bind_before_child_publication(token),
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(cleanup) => cleanup.bind_before_child_publication(token),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(_) => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(_) => true,
        }
    }

    fn take_bound_io(&mut self, token: ManagedComponentToken) -> Option<InstalledComponentIo> {
        match self {
            Self::ManagedSync(cleanup) => cleanup
                .claim_bound_io(token)
                .map(InstalledComponentIo::from),
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(cleanup) => cleanup
                .claim_bound_io(token)
                .map(InstalledComponentIo::from),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(io) => io.take(),
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(io) => io.take(),
        }
    }

    fn quarantine_partial(&self) {
        match self {
            Self::ManagedSync(cleanup) => cleanup.quarantine_partial_start(),
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync(cleanup) => cleanup.quarantine_partial_start(),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            Self::Acceptance(_) => {}
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance(_) => {}
        }
    }
}

#[cfg(feature = "ssh-component-command")]
impl From<ManagedComponentIo> for InstalledComponentIo {
    fn from(io: ManagedComponentIo) -> Self {
        let (stdin, stdout, stdin_supervisor, stdout_supervisor) = io.into_parts();
        Self {
            stdin,
            stdout,
            stdin_supervisor,
            stdout_supervisor,
        }
    }
}

/// Close both still-unpublished transport streams with the exact start error.
///
/// This is valid only before either endpoint or supervisor has moved into the
/// registry CSpace. At that point there is no child and therefore no later
/// lifecycle finalizer. A conflicting pre-existing reason is an installer
/// invariant failure: fail-stop and report RunnerFault rather than guessing
/// which terminal owns either stream.
#[cfg(feature = "ssh-component-command")]
fn finalize_unpublished_start_error(
    io: &InstalledComponentIo,
    terminal: ComponentTerminal,
) -> ComponentTerminal {
    let reason = terminal.stream_close_reason();
    let stdin = io.stdin_supervisor.finalize(reason);
    let stdout = io.stdout_supervisor.finalize(reason);
    if matches!(
        stdin,
        StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
    ) && matches!(
        stdout,
        StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
    ) {
        terminal
    } else {
        lifecycle_fail_stop();
        ComponentTerminal::RunnerFault
    }
}

#[cfg(feature = "ssh-component-command")]
fn quarantine_committed_start(
    input: &ComponentStartInput,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
) {
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let _ = (task, domain, streams);
    #[cfg(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    ))]
    if input.kind().is_native_async() {
        native_async_acceptance::quarantine_fault_shadow(key, token, task, domain, streams);
    }
    CONTROL.child_shadow[key.slot as usize].quarantine(key);
    CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
    // Quarantine is sticky and never takes/drops the arena-owned payload or
    // resets its Space/CSpace. It only prevents any later finalizer from
    // treating this activated-but-unrunnable record as terminal authority.
    let _ = registry().quarantine(token);
    lifecycle_fail_stop();
    input.quarantine_partial();
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlPhase {
    Vacant,
    Starting,
    Running,
    Complete {
        terminal: ComponentTerminal,
        acknowledged: bool,
    },
    Quarantined,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalCandidateSource {
    Payload,
    Cooperative,
    TaskState,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlStartKind {
    ManagedSync,
    #[cfg(feature = "ssh-native-async-command")]
    ManagedNativeAsync,
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    Acceptance,
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    NativeAsyncAcceptance,
}

#[cfg(feature = "ssh-component-command")]
impl ControlStartKind {
    const fn is_native_async(self) -> bool {
        match self {
            #[cfg(feature = "ssh-native-async-command")]
            Self::ManagedNativeAsync => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance => true,
            _ => false,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
struct ControlRecord {
    generation: u64,
    phase: ControlPhase,
    core_token: Option<InstanceToken>,
    handle: Option<TaskHandle>,
    supervisor: Option<TaskHandle>,
    domain: Option<AllocationDomain>,
    streams: Option<RegistryStreamBindings>,
    cleanup: Option<ManagedComponentStartLease>,
    start_kind: Option<ControlStartKind>,
    terminal_candidate: Option<ComponentTerminal>,
    candidate_source: Option<TerminalCandidateSource>,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone)]
struct ControlTuple {
    core_token: InstanceToken,
    handle: TaskHandle,
    supervisor: TaskHandle,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    cleanup: Option<ManagedComponentStartLease>,
    start_kind: ControlStartKind,
    terminal_candidate: Option<ComponentTerminal>,
    candidate_source: Option<TerminalCandidateSource>,
}

#[cfg(feature = "ssh-component-command")]
fn control_record_matches_tuple(record: &ControlRecord, tuple: &ControlTuple) -> bool {
    record.phase == ControlPhase::Running
        && record.core_token == Some(tuple.core_token)
        && record.domain == Some(tuple.domain)
        && record.streams == Some(tuple.streams)
        && record.terminal_candidate == tuple.terminal_candidate
        && record.candidate_source == tuple.candidate_source
        && record.start_kind == Some(tuple.start_kind)
        && record.handle.as_ref().is_some_and(|handle| {
            handle.id() == tuple.handle.id()
                && handle.allocation_domain() == tuple.domain
                && handle.shares_status_with(&tuple.handle)
        })
        && record.supervisor.as_ref().is_some_and(|supervisor| {
            supervisor.id() == tuple.supervisor.id()
                && supervisor.allocation_domain() == tuple.supervisor.allocation_domain()
                && supervisor.shares_status_with(&tuple.supervisor)
        })
        && match (record.cleanup, tuple.cleanup) {
            (None, None) => true,
            (Some(record_cleanup), Some(tuple_cleanup)) => {
                record_cleanup.matches_exact(tuple_cleanup)
            }
            _ => false,
        }
}

#[cfg(feature = "ssh-component-command")]
fn control_start_projection_exact(
    record: &ControlRecord,
    core_token: InstanceToken,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    child: &TaskHandle,
    supervisor: &TaskHandle,
    cleanup: Option<ManagedComponentStartLease>,
    start_kind: ControlStartKind,
) -> bool {
    record.phase == ControlPhase::Starting
        && record.core_token == Some(core_token)
        && record.domain == Some(domain)
        && record.streams == Some(streams)
        && record.start_kind == Some(start_kind)
        && record.terminal_candidate.is_none()
        && record.candidate_source.is_none()
        && record.handle.as_ref().is_some_and(|stored| {
            stored.id() == child.id()
                && stored.allocation_domain() == domain
                && stored.shares_status_with(child)
        })
        && record.supervisor.as_ref().is_some_and(|stored| {
            stored.id() == supervisor.id()
                && stored.allocation_domain() == supervisor.allocation_domain()
                && stored.shares_status_with(supervisor)
        })
        && match (record.cleanup, cleanup) {
            (Some(stored), Some(expected)) => stored.matches_exact(expected),
            (None, None) => true,
            _ => false,
        }
}

#[cfg(feature = "ssh-component-command")]
enum ChildDetachFold {
    Clear,
    FaultInFlight,
}

#[cfg(feature = "ssh-component-command")]
fn fold_child_detach_reason_locked(
    record: &ControlRecord,
    key: ControlKey,
) -> Result<ChildDetachFold, ()> {
    let handle = record.handle.as_ref().ok_or(())?;
    let domain = record.domain.ok_or(())?;
    let shadow = CONTROL.child_shadow.get(key.slot as usize).ok_or(())?;
    if !shadow.exact(key, handle.id(), domain) {
        return Err(());
    }
    match shadow.phase(key) {
        Some(TASK_SHADOW_RUNNING | TASK_SHADOW_COMPLETE) => {}
        _ => return Err(()),
    }
    match shadow.terminal_reason(key) {
        None => Ok(ChildDetachFold::Clear),
        Some(TaskDetachReason::Exited) if record.terminal_candidate.is_some() => {
            Ok(ChildDetachFold::Clear)
        }
        // A detached fault/cancellation is not by itself payload-terminal
        // authority. CONTROL may preserve an already published first winner,
        // while Faulted-without-candidate remains an in-flight state until the
        // immutable FaultReclaimed + completion(None) proof is visible.
        Some(TaskDetachReason::Faulted) if record.terminal_candidate.is_some() => {
            Ok(ChildDetachFold::Clear)
        }
        Some(TaskDetachReason::Faulted) => Ok(ChildDetachFold::FaultInFlight),
        Some(TaskDetachReason::Cancelled) if record.terminal_candidate.is_some() => {
            Ok(ChildDetachFold::Clear)
        }
        Some(_) => Err(()),
    }
}

#[cfg(feature = "ssh-component-command")]
impl ControlRecord {
    const fn new() -> Self {
        Self {
            generation: 0,
            phase: ControlPhase::Vacant,
            core_token: None,
            handle: None,
            supervisor: None,
            domain: None,
            streams: None,
            cleanup: None,
            start_kind: None,
            terminal_candidate: None,
            candidate_source: None,
        }
    }

    fn quarantine(&mut self) {
        self.phase = ControlPhase::Quarantined;
    }
}

#[cfg(feature = "ssh-component-command")]
struct ControlTable {
    slots: [ControlRecord; CONTROL_SLOTS],
}

#[cfg(feature = "ssh-component-command")]
impl ControlTable {
    const fn new() -> Self {
        Self {
            slots: [const { ControlRecord::new() }; CONTROL_SLOTS],
        }
    }

    fn reserve(&mut self, gate: &ControlGate) -> Option<ControlKey> {
        for reuse_completed in [false, true] {
            for (index, record) in self.slots.iter_mut().enumerate() {
                let reusable = if reuse_completed {
                    matches!(
                        record.phase,
                        ControlPhase::Complete {
                            acknowledged: true,
                            ..
                        }
                    )
                } else {
                    record.phase == ControlPhase::Vacant
                };
                if !reusable {
                    continue;
                }
                if gate.completion[index].waiter_count() != 0
                    || gate.child_exit[index].waiter_count() != 0
                {
                    // A stale task still owns the prior generation's wake
                    // edge. Never advance the slot generation underneath it.
                    record.quarantine();
                    lifecycle_fail_stop();
                    continue;
                }
                let generation = if record.generation == 0 {
                    Some(1)
                } else {
                    record.generation.checked_add(1)
                };
                let Some(generation) = generation.filter(|value| *value <= MAX_CONTROL_GENERATION)
                else {
                    record.quarantine();
                    continue;
                };
                record.generation = generation;
                record.phase = ControlPhase::Starting;
                record.core_token = None;
                record.handle = None;
                record.supervisor = None;
                record.domain = None;
                record.streams = None;
                record.cleanup = None;
                record.start_kind = None;
                record.terminal_candidate = None;
                record.candidate_source = None;
                let key = ControlKey {
                    slot: index as u8,
                    generation,
                };
                if !gate.install_completion_generation(key) {
                    record.quarantine();
                    lifecycle_fail_stop();
                    continue;
                }
                return Some(key);
            }
        }
        None
    }

    fn exact_mut(&mut self, key: ControlKey) -> Option<&mut ControlRecord> {
        self.slots
            .get_mut(key.slot as usize)
            .filter(|record| record.generation == key.generation)
    }

    fn exact(&self, key: ControlKey) -> Option<&ControlRecord> {
        self.slots
            .get(key.slot as usize)
            .filter(|record| record.generation == key.generation)
    }

    fn records_alias(
        record: &ControlRecord,
        core_token: InstanceToken,
        handle: &TaskHandle,
        domain: AllocationDomain,
    ) -> bool {
        record
            .core_token
            .is_some_and(|other| other.shares_stable_slot(core_token))
            || record.handle.as_ref().is_some_and(|other| {
                other.id() == handle.id()
                    || other.shares_status_with(handle)
                    || other.owner() == domain.owner
                    || other.arena() == domain.arena
            })
            || record
                .domain
                .is_some_and(|other| other.owner == domain.owner || other.arena == domain.arena)
    }

    /// Validate one complete running control projection and sticky-quarantine
    /// every other slot that aliases any part of it. A stale VSH generation is
    /// reported separately by returning `None` before touching another slot.
    fn running_tuple_inner(
        &mut self,
        key: ControlKey,
        require_cleanup_active: bool,
    ) -> Result<Option<ControlTuple>, ()> {
        let Some(record) = self.exact(key) else {
            return Ok(None);
        };
        if record.phase != ControlPhase::Running {
            return Ok(None);
        }
        let Some(core_token) = record.core_token else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let Some(handle) = record.handle.clone() else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let Some(supervisor) = record.supervisor.clone() else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let Some(domain) = record.domain else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let Some(streams) = record.streams else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let terminal_candidate = record.terminal_candidate;
        let candidate_source = record.candidate_source;
        let cleanup = record.cleanup;
        let Some(start_kind) = record.start_kind else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        let candidate_exact = terminal_candidate.is_some() == candidate_source.is_some();
        let cleanup_exact = match (start_kind, cleanup) {
            (ControlStartKind::ManagedSync, Some(cleanup)) => key
                .managed_token()
                .is_some_and(|token| !require_cleanup_active || cleanup.is_active_for(token)),
            #[cfg(feature = "ssh-native-async-command")]
            (ControlStartKind::ManagedNativeAsync, Some(cleanup)) => key
                .managed_token()
                .is_some_and(|token| !require_cleanup_active || cleanup.is_active_for(token)),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            (ControlStartKind::Acceptance, None) => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            (ControlStartKind::NativeAsyncAcceptance, None) => true,
            _ => false,
        };
        if handle.allocation_domain() != domain
            || supervisor.owner() != OwnerId::SYSTEM
            || supervisor.arena().is_tracked()
            || !candidate_exact
            || !cleanup_exact
        {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        }

        let mut alias = false;
        for (index, other) in self.slots.iter_mut().enumerate() {
            if index == key.slot as usize {
                continue;
            }
            if Self::records_alias(other, core_token, &handle, domain) {
                other.quarantine();
                alias = true;
            }
        }
        if alias {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        }
        Ok(Some(ControlTuple {
            core_token,
            handle,
            supervisor,
            domain,
            streams,
            cleanup,
            start_kind,
            terminal_candidate,
            candidate_source,
        }))
    }

    fn running_tuple(&mut self, key: ControlKey) -> Result<Option<ControlTuple>, ()> {
        self.running_tuple_inner(key, true)
    }

    /// Copy the complete CONTROL-owned tuple without acquiring VSH. Terminal
    /// publishers seal CONTROL and then revalidate the live VSH reaper before
    /// use. Detached-fault reclaimers instead prove the exact fixed cleanup
    /// shadow is still Active while retaining this same CONTROL guard; parent
    /// liveness is not raw child-arena authority after publication.
    fn running_tuple_structural(&mut self, key: ControlKey) -> Result<Option<ControlTuple>, ()> {
        self.running_tuple_inner(key, false)
    }

    fn starting_tuple_is_unique(
        &mut self,
        key: ControlKey,
        core_token: InstanceToken,
        handle: &TaskHandle,
        domain: AllocationDomain,
    ) -> bool {
        let current_matches = self.exact(key).is_some_and(|record| {
            record.phase == ControlPhase::Starting
                && record.core_token == Some(core_token)
                && record.handle.is_none()
                && record.domain == Some(domain)
                && record.streams.is_some()
                && record.terminal_candidate.is_none()
                && handle.allocation_domain() == domain
        });
        let mut alias = false;
        for (index, other) in self.slots.iter_mut().enumerate() {
            if index == key.slot as usize {
                continue;
            }
            if Self::records_alias(other, core_token, handle, domain) {
                other.quarantine();
                alias = true;
            }
        }
        if !current_matches || alias {
            if let Some(record) = self.exact_mut(key) {
                record.quarantine();
            }
            return false;
        }
        true
    }

    fn fault_tuple(&mut self, witness: ReclaimableFaultWitness) -> Result<ControlKey, ()> {
        let Some(core_token) = witness.instance_token() else {
            return Err(());
        };
        let mut exact = None;
        let mut conflict = false;
        for (index, record) in self.slots.iter_mut().enumerate() {
            let aliases = record
                .core_token
                .is_some_and(|other| other.shares_stable_slot(core_token))
                || record
                    .handle
                    .as_ref()
                    .is_some_and(|handle| handle.id() == witness.task_id())
                || record.domain.is_some_and(|domain| {
                    domain.owner == witness.allocation_domain().owner
                        || domain.arena == witness.allocation_domain().arena
                });
            if !aliases {
                continue;
            }
            let matches = record.phase == ControlPhase::Running
                && record.core_token == Some(core_token)
                && record.domain == Some(witness.allocation_domain())
                && record.handle.as_ref().is_some_and(|handle| {
                    handle.allocation_domain() == witness.allocation_domain()
                        && witness.matches_handle(handle)
                });
            if matches && exact.is_none() {
                exact = Some(ControlKey {
                    slot: index as u8,
                    generation: record.generation,
                });
            } else {
                record.quarantine();
                conflict = true;
            }
        }
        if conflict || exact.is_none() {
            if let Some(key) = exact {
                self.exact_mut(key)
                    .expect("fault control record vanished")
                    .quarantine();
            }
            return Err(());
        }
        let key = exact.expect("checked exact fault control tuple");
        let record = self
            .exact(key)
            .expect("exact fault control record vanished");
        // Keep this first-stage detached-fault lookup usable by the isolated
        // acceptance registry, whose control records deliberately contain
        // only the child identity projection. Production callers validate the
        // complete supervisor/stream/cleanup tuple immediately after this
        // exact key is established and before authorizing raw reclamation.
        let exact_core_token = record
            .core_token
            .expect("exact fault control record has a core token");
        let exact_handle = record
            .handle
            .as_ref()
            .expect("exact fault control record has a handle")
            .clone();
        let exact_domain = record
            .domain
            .expect("exact fault control record has a domain");
        for (index, other) in self.slots.iter_mut().enumerate() {
            if index != key.slot as usize
                && Self::records_alias(other, exact_core_token, &exact_handle, exact_domain)
            {
                other.quarantine();
                conflict = true;
            }
        }
        if conflict {
            self.exact_mut(key)
                .expect("fault control record vanished")
                .quarantine();
            return Err(());
        }
        Ok(key)
    }
}

#[cfg(feature = "ssh-component-command")]
struct TaskDetachShadow {
    generation: AtomicU64,
    task: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    phase: AtomicU8,
    reason: AtomicU8,
    wake: SpinLock<Option<ExactTaskWake>>,
}

#[cfg(feature = "ssh-component-command")]
impl TaskDetachShadow {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            task: AtomicU64::new(0),
            owner: AtomicU64::new(OwnerId::SYSTEM.get()),
            arena: AtomicU64::new(0),
            phase: AtomicU8::new(TASK_SHADOW_VACANT),
            reason: AtomicU8::new(0),
            wake: SpinLock::new(None),
        }
    }

    fn install(&self, key: ControlKey, handle: &TaskHandle) -> bool {
        if key.generation == 0
            || handle.id().0 == 0
            || key.generation <= self.generation.load(Ordering::Acquire)
        {
            return false;
        }
        self.phase.store(TASK_SHADOW_VACANT, Ordering::Release);
        self.task.store(handle.id().0, Ordering::Relaxed);
        self.owner.store(handle.owner().get(), Ordering::Relaxed);
        self.arena.store(handle.arena().get(), Ordering::Relaxed);
        self.reason.store(0, Ordering::Relaxed);
        *self.wake.lock() = Some(handle.exact_wake());
        self.generation.store(key.generation, Ordering::Release);
        self.phase.store(TASK_SHADOW_PREPARED, Ordering::Release);
        true
    }

    fn exact_wake(&self, key: ControlKey) -> Option<ExactTaskWake> {
        if self.generation.load(Ordering::Acquire) != key.generation {
            return None;
        }
        let wake = *self.wake.lock();
        (self.generation.load(Ordering::Acquire) == key.generation)
            .then_some(wake)
            .flatten()
    }

    fn exact(&self, key: ControlKey, task: TaskId, domain: AllocationDomain) -> bool {
        self.generation.load(Ordering::Acquire) == key.generation
            && self.task.load(Ordering::Acquire) == task.0
            && self.owner.load(Ordering::Acquire) == domain.owner.get()
            && self.arena.load(Ordering::Acquire) == domain.arena.get()
    }

    fn exact_handle(&self, key: ControlKey, handle: &TaskHandle) -> bool {
        self.exact(key, handle.id(), handle.allocation_domain())
    }

    fn transition(&self, key: ControlKey, from: u8, to: u8) -> bool {
        self.generation.load(Ordering::Acquire) == key.generation
            && self
                .phase
                .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    fn phase(&self, key: ControlKey) -> Option<u8> {
        (self.generation.load(Ordering::Acquire) == key.generation)
            .then(|| self.phase.load(Ordering::Acquire))
    }

    fn publish_reason(
        &self,
        key: ControlKey,
        task: TaskId,
        domain: AllocationDomain,
        reason: TaskDetachReason,
    ) -> Result<bool, ()> {
        if !self.exact(key, task, domain) {
            return Err(());
        }
        if self.phase.load(Ordering::Acquire) != TASK_SHADOW_RUNNING {
            return Ok(false);
        }
        let encoded = match reason {
            TaskDetachReason::Exited => 1,
            TaskDetachReason::Cancelled => 2,
            TaskDetachReason::Faulted => 3,
        };
        match self
            .reason
            .compare_exchange(0, encoded, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(true),
            Err(existing) if existing == encoded => Ok(false),
            Err(_) => Err(()),
        }
    }

    fn terminal_reason(&self, key: ControlKey) -> Option<TaskDetachReason> {
        if self.generation.load(Ordering::Acquire) != key.generation {
            return None;
        }
        match self.reason.load(Ordering::Acquire) {
            1 => Some(TaskDetachReason::Exited),
            2 => Some(TaskDetachReason::Cancelled),
            3 => Some(TaskDetachReason::Faulted),
            _ => None,
        }
    }

    fn quarantine(&self, key: ControlKey) {
        if self.generation.load(Ordering::Acquire) == key.generation {
            self.phase.store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy)]
enum ManagedCleanupShadowState {
    Bound,
    Active,
    Completing {
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    },
    Complete {
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    },
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy)]
struct ManagedCleanupShadow {
    generation: u64,
    cleanup: Option<ManagedComponentStartLease>,
    state: Option<ManagedCleanupShadowState>,
}

#[cfg(feature = "ssh-component-command")]
impl ManagedCleanupShadow {
    const fn empty() -> Self {
        Self {
            generation: 0,
            cleanup: None,
            state: None,
        }
    }
}

/// The control table uses an exact-task recoverable gate rather than a normal
/// mutex. If trusted lifecycle code faults while mutating the table, the fault
/// cleanup hook atomically changes the exact HELD generation to POISONED. No
/// later task can enter the partially changed table, while an unrelated guest
/// fault observes FREE and leaves the lifecycle untouched.
#[cfg(feature = "ssh-component-command")]
struct ControlGate {
    state: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    publishing_key: AtomicU64,
    publication: [AtomicU64; CONTROL_SLOTS],
    table: UnsafeCell<ControlTable>,
    completion: [OneShotWaitQueue; CONTROL_SLOTS],
    completion_generation: [AtomicU64; CONTROL_SLOTS],
    child_exit: [OneShotWaitQueue; CONTROL_SLOTS],
    child_exit_generation: [AtomicU64; CONTROL_SLOTS],
    child_shadow: [TaskDetachShadow; CONTROL_SLOTS],
    supervisor_shadow: [TaskDetachShadow; CONTROL_SLOTS],
    cleanup_shadow: [SpinLock<ManagedCleanupShadow>; CONTROL_SLOTS],
    fail_wake_pending: AtomicBool,
}

#[cfg(feature = "ssh-component-command")]
unsafe impl Sync for ControlGate {}

#[cfg(feature = "ssh-component-command")]
impl ControlGate {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(CONTROL_FREE),
            owner: AtomicU64::new(OwnerId::SYSTEM.get()),
            arena: AtomicU64::new(0),
            publishing_key: AtomicU64::new(0),
            publication: [const { AtomicU64::new(0) }; CONTROL_SLOTS],
            table: UnsafeCell::new(ControlTable::new()),
            completion: [const { OneShotWaitQueue::new() }; CONTROL_SLOTS],
            completion_generation: [const { AtomicU64::new(0) }; CONTROL_SLOTS],
            child_exit: [const { OneShotWaitQueue::new() }; CONTROL_SLOTS],
            child_exit_generation: [const { AtomicU64::new(0) }; CONTROL_SLOTS],
            child_shadow: [const { TaskDetachShadow::new() }; CONTROL_SLOTS],
            supervisor_shadow: [const { TaskDetachShadow::new() }; CONTROL_SLOTS],
            cleanup_shadow: [const { SpinLock::new(ManagedCleanupShadow::empty()) }; CONTROL_SLOTS],
            fail_wake_pending: AtomicBool::new(false),
        }
    }

    fn completion(&self, key: ControlKey) -> Option<&OneShotWaitQueue> {
        let index = key.slot as usize;
        self.completion_generation
            .get(index)
            .is_some_and(|generation| generation.load(Ordering::Acquire) == key.generation)
            .then(|| &self.completion[index])
    }

    fn child_exit(&self, key: ControlKey) -> Option<&OneShotWaitQueue> {
        let index = key.slot as usize;
        self.child_exit_generation
            .get(index)
            .is_some_and(|generation| generation.load(Ordering::Acquire) == key.generation)
            .then(|| &self.child_exit[index])
    }

    /// Install the queue key while CONTROL serializes the matching record
    /// generation. The monotonically increasing mirror lets a poisoned global
    /// fail-stop wake current listeners without reading a possibly partial
    /// table or guessing at a replacement generation.
    fn install_completion_generation(&self, key: ControlKey) -> bool {
        let Some(current) = self.completion_generation.get(key.slot as usize) else {
            return false;
        };
        let Some(child) = self.child_exit_generation.get(key.slot as usize) else {
            return false;
        };
        let Some(publication) = self.publication.get(key.slot as usize) else {
            return false;
        };
        let previous = current.load(Ordering::Acquire);
        let previous_child = child.load(Ordering::Acquire);
        let previous_publication = publication.load(Ordering::Acquire) >> PUBLICATION_STATE_BITS;
        if key.generation <= previous
            || key.generation <= previous_child
            || key.generation <= previous_publication
        {
            return false;
        }
        current.store(key.generation, Ordering::Release);
        child.store(key.generation, Ordering::Release);
        publication.store(
            publication_state(key.generation, PUBLICATION_PREPARED),
            Ordering::Release,
        );
        true
    }

    fn commit_publication(&self, key: ControlKey) -> bool {
        self.publication
            .get(key.slot as usize)
            .is_some_and(|state| {
                state
                    .compare_exchange(
                        publication_state(key.generation, PUBLICATION_PREPARED),
                        publication_state(key.generation, PUBLICATION_COMMITTED),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            })
    }

    fn publication_permit(&'static self, key: ControlKey) -> Option<(&'static AtomicU64, u64)> {
        self.publication.get(key.slot as usize).map(|state| {
            (
                state,
                publication_state(key.generation, PUBLICATION_COMMITTED),
            )
        })
    }

    fn reject_prepared_publications(&self) {
        for publication in &self.publication {
            let observed = publication.load(Ordering::Acquire);
            if observed & ((1 << PUBLICATION_STATE_BITS) - 1) == PUBLICATION_PREPARED {
                let _ = publication.compare_exchange(
                    observed,
                    (observed & !((1 << PUBLICATION_STATE_BITS) - 1)) | PUBLICATION_REJECTED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
            }
        }
    }

    fn install_cleanup_shadow(&self, key: ControlKey, cleanup: ManagedComponentStartLease) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let mut shadow = shadow.lock();
        if key.generation <= shadow.generation {
            return false;
        }
        *shadow = ManagedCleanupShadow {
            generation: key.generation,
            cleanup: Some(cleanup),
            state: Some(ManagedCleanupShadowState::Bound),
        };
        true
    }

    fn mark_cleanup_active(&self, key: ControlKey, cleanup: ManagedComponentStartLease) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let mut shadow = shadow.lock();
        if shadow.generation != key.generation
            || shadow
                .cleanup
                .is_none_or(|stored| !stored.matches_exact(cleanup))
            || !matches!(shadow.state, Some(ManagedCleanupShadowState::Bound))
        {
            return false;
        }
        shadow.state = Some(ManagedCleanupShadowState::Active);
        true
    }

    fn cleanup_shadow_is_active(
        &self,
        key: ControlKey,
        cleanup: ManagedComponentStartLease,
    ) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let shadow = shadow.lock();
        shadow.generation == key.generation
            && shadow
                .cleanup
                .is_some_and(|stored| stored.matches_exact(cleanup))
            && matches!(shadow.state, Some(ManagedCleanupShadowState::Active))
    }

    fn mark_cleanup_complete(
        &self,
        key: ControlKey,
        cleanup: ManagedComponentStartLease,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let mut shadow = shadow.lock();
        if shadow.generation != key.generation
            || shadow
                .cleanup
                .is_none_or(|stored| !stored.matches_exact(cleanup))
            || !matches!(
                shadow.state,
                Some(ManagedCleanupShadowState::Completing {
                    token: stored_token,
                    terminal: stored_terminal,
                }) if stored_token == token && stored_terminal == terminal
            )
        {
            return false;
        }
        shadow.state = Some(ManagedCleanupShadowState::Complete { token, terminal });
        true
    }

    fn mark_cleanup_completing(
        &self,
        key: ControlKey,
        cleanup: ManagedComponentStartLease,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let mut shadow = shadow.lock();
        if shadow.generation != key.generation
            || shadow
                .cleanup
                .is_none_or(|stored| !stored.matches_exact(cleanup))
            || !matches!(shadow.state, Some(ManagedCleanupShadowState::Active))
        {
            return false;
        }
        shadow.state = Some(ManagedCleanupShadowState::Completing { token, terminal });
        true
    }

    fn clear_cleanup_shadow(&self, key: ControlKey, cleanup: ManagedComponentStartLease) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let mut shadow = shadow.lock();
        if shadow.generation != key.generation
            || shadow
                .cleanup
                .is_none_or(|stored| !stored.matches_exact(cleanup))
        {
            return false;
        }
        shadow.cleanup = None;
        shadow.state = None;
        true
    }

    #[cfg(feature = "ssh-native-async-qemu-acceptance")]
    fn target_cleanup_shadow_residue(&self) -> usize {
        self.cleanup_shadow
            .iter()
            .filter(|shadow| {
                let shadow = shadow.lock();
                shadow.cleanup.is_some() || shadow.state.is_some()
            })
            .count()
    }

    fn cleanup_shadow_is_complete(
        &self,
        key: ControlKey,
        cleanup: ManagedComponentStartLease,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> bool {
        let Some(shadow) = self.cleanup_shadow.get(key.slot as usize) else {
            return false;
        };
        let shadow = shadow.lock();
        shadow.generation == key.generation
            && shadow
                .cleanup
                .is_some_and(|stored| stored.matches_exact(cleanup))
            && matches!(
                shadow.state,
                Some(ManagedCleanupShadowState::Complete {
                    token: stored_token,
                    terminal: stored_terminal,
                }) if stored_token == token && stored_terminal == terminal
            )
    }

    fn fail_stop_cleanups(
        &self,
    ) -> [Option<(ManagedComponentStartLease, ManagedCleanupShadowState)>; CONTROL_SLOTS] {
        let mut cleanups = [const { None }; CONTROL_SLOTS];
        for (index, shadow) in self.cleanup_shadow.iter().enumerate() {
            let shadow = shadow.lock();
            cleanups[index] = shadow.cleanup.zip(shadow.state);
        }
        cleanups
    }

    fn quarantine_cleanups(
        cleanups: [Option<(ManagedComponentStartLease, ManagedCleanupShadowState)>; CONTROL_SLOTS],
    ) {
        for (cleanup, state) in cleanups.into_iter().flatten() {
            match state {
                ManagedCleanupShadowState::Bound | ManagedCleanupShadowState::Active => {
                    cleanup.quarantine_partial_start();
                }
                ManagedCleanupShadowState::Completing { token, terminal }
                | ManagedCleanupShadowState::Complete { token, terminal } => {
                    let _ = cleanup.quarantine_staged_complete(token, terminal);
                }
            }
        }
    }

    fn detach_fail_stop_wakes(
        &self,
    ) -> (
        [Option<OneShotWake>; CONTROL_SLOTS],
        [Option<OneShotWake>; CONTROL_SLOTS],
        [Option<ExactTaskWake>; CONTROL_SLOTS],
    ) {
        let mut completion_wakes = [const { None }; CONTROL_SLOTS];
        let mut child_wakes = [const { None }; CONTROL_SLOTS];
        let mut exact_supervisor_wakes = [const { None }; CONTROL_SLOTS];
        for (index, generation) in self.completion_generation.iter().enumerate() {
            let generation = generation.load(Ordering::Acquire);
            if generation != 0 {
                completion_wakes[index] = self.completion[index].publish(generation).ok();
            }
            let child_generation = self.child_exit_generation[index].load(Ordering::Acquire);
            if child_generation != 0 {
                child_wakes[index] = self.child_exit[index].publish(child_generation).ok();
                exact_supervisor_wakes[index] =
                    self.supervisor_shadow[index].exact_wake(ControlKey {
                        slot: index as u8,
                        generation: child_generation,
                    });
            }
        }
        (completion_wakes, child_wakes, exact_supervisor_wakes)
    }

    fn dispatch_wakes(wakes: [Option<OneShotWake>; CONTROL_SLOTS]) {
        for wake in wakes.into_iter().flatten() {
            wake.dispatch();
        }
    }

    fn dispatch_exact_wakes(wakes: [Option<ExactTaskWake>; CONTROL_SLOTS]) {
        for wake in wakes.into_iter().flatten() {
            let _ = wake.wake_if_exact();
        }
    }

    fn request_fail_stop_wake(&self) {
        self.fail_wake_pending.store(true, Ordering::Release);
        let state = self.state.load(Ordering::Acquire);
        if matches!(state & 0b11, CONTROL_ACQUIRING | CONTROL_HELD) {
            // Never take SCHED while CONTROL is acquiring or held. The
            // eventual ControlGuard::drop detaches under the exact control
            // generation and dispatches after release; an acquiring-task
            // fault first poisons the gate and invokes this path again.
            return;
        }
        // A poisoned gate cannot safely expose its table. The generation
        // mirrors were installed only while CONTROL was exact and are never
        // decremented, so this global fail-stop path cannot target a stale or
        // future replacement generation.
        let wakes = self.detach_fail_stop_wakes();
        let cleanups = self.fail_stop_cleanups();
        Self::dispatch_wakes(wakes.0);
        Self::dispatch_wakes(wakes.1);
        Self::dispatch_exact_wakes(wakes.2);
        Self::quarantine_cleanups(cleanups);
    }

    fn try_lock(&self) -> Result<ControlGuard<'_>, ControlGateError> {
        let task = crate::exec::current_task_id().ok_or(ControlGateError::Unattributed)?;
        self.try_lock_attributed(task, crate::heap::current_domain(), CONTROL_ACQUIRE_SPINS)
    }

    /// Completion acknowledgement is a one-shot lifecycle message from VSH.
    /// Give it the same bounded serialization budget as a detached fault: the
    /// caller cannot retry through the trait after consuming the terminal
    /// scalar, so exhaustion must fail-stop instead of silently pinning a
    /// reusable control slot forever.
    fn try_lock_completion_ack(&self) -> Result<ControlGuard<'_>, ControlGateError> {
        let task = crate::exec::current_task_id().ok_or(ControlGateError::Unattributed)?;
        self.try_lock_attributed(
            task,
            crate::heap::current_domain(),
            CONTROL_FAULT_ACQUIRE_SPINS,
        )
    }

    /// Acquire the stable control table for an already detached exact fault.
    ///
    /// # Safety
    ///
    /// The tuple must come from the executor-forged fault witness after
    /// permanent detach. The guard may only validate/reclaim that same tuple
    /// and must not be held across any scheduling or asynchronous operation.
    unsafe fn try_lock_detached(
        &self,
        task: TaskId,
        domain: AllocationDomain,
    ) -> Result<ControlGuard<'_>, ControlGateError> {
        self.try_lock_attributed(task, domain, CONTROL_FAULT_ACQUIRE_SPINS)
    }

    fn try_lock_attributed(
        &self,
        task: TaskId,
        domain: AllocationDomain,
        acquire_spins: usize,
    ) -> Result<ControlGuard<'_>, ControlGateError> {
        if task.0 > (u64::MAX >> 2) {
            return Err(ControlGateError::Poisoned);
        }
        let acquiring = (task.0 << 2) | CONTROL_ACQUIRING;
        let held = (task.0 << 2) | CONTROL_HELD;
        for _ in 0..acquire_spins {
            let observed = self.state.load(Ordering::Acquire);
            if observed == CONTROL_POISONED {
                return Err(ControlGateError::Poisoned);
            }
            if observed == CONTROL_FREE
                && self
                    .state
                    .compare_exchange(
                        CONTROL_FREE,
                        acquiring,
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                self.owner.store(domain.owner.get(), Ordering::Relaxed);
                self.arena.store(domain.arena.get(), Ordering::Relaxed);
                self.state.store(held, Ordering::Release);
                return Ok(ControlGuard {
                    gate: self,
                    held,
                    not_send: PhantomData,
                });
            }
            core::hint::spin_loop();
        }
        Err(ControlGateError::Busy)
    }

    unsafe fn recover_faulted_task(&self, task: TaskId, domain: AllocationDomain) -> bool {
        if task.0 > (u64::MAX >> 2) {
            return false;
        }
        let acquiring = (task.0 << 2) | CONTROL_ACQUIRING;
        let held = (task.0 << 2) | CONTROL_HELD;
        let observed = self.state.load(Ordering::Acquire);
        if observed == acquiring {
            return self
                .state
                .compare_exchange(
                    acquiring,
                    CONTROL_POISONED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
        }
        if observed != held {
            return false;
        }
        let domain_matches = self.owner.load(Ordering::Relaxed) == domain.owner.get()
            && self.arena.load(Ordering::Relaxed) == domain.arena.get();
        if !domain_matches {
            return self
                .state
                .compare_exchange(held, CONTROL_POISONED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
        }
        self.state
            .compare_exchange(held, CONTROL_POISONED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlGateError {
    Busy,
    Poisoned,
    Unattributed,
}

#[cfg(feature = "ssh-component-command")]
struct ControlGuard<'a> {
    gate: &'a ControlGate,
    held: u64,
    not_send: PhantomData<*mut ()>,
}

#[cfg(feature = "ssh-component-command")]
struct ControlPublicationLease<'a> {
    gate: &'a ControlGate,
    acquiring: u64,
    held: u64,
    task: TaskId,
    domain: AllocationDomain,
    key: ControlKey,
    cleanup: Option<ManagedComponentStartLease>,
    not_send: PhantomData<*mut ()>,
}

#[cfg(feature = "ssh-component-command")]
impl<'a> ControlGuard<'a> {
    /// Suspend table access while preserving exact parent fault attribution.
    /// The ACQUIRING word excludes every ordinary observer but is already
    /// recognized by the raw-fault recovery hook, which poisons it if this
    /// stack is abandoned across the scheduler transaction.
    fn suspend_for_scheduler(
        self,
        key: ControlKey,
        cleanup: Option<ManagedComponentStartLease>,
    ) -> Result<ControlPublicationLease<'a>, ControlGateError> {
        let this = core::mem::ManuallyDrop::new(self);
        let task = TaskId(this.held >> 2);
        let domain = AllocationDomain::new(
            OwnerId::new(this.gate.owner.load(Ordering::Acquire)),
            crate::heap::ArenaId::new(this.gate.arena.load(Ordering::Acquire)),
        );
        let record_exact = this.gate.publishing_key.load(Ordering::Acquire) == 0
            && unsafe { &*this.gate.table.get() }
                .exact(key)
                .is_some_and(|record| match (record.cleanup, cleanup) {
                    (Some(stored), Some(expected)) => stored.matches_exact(expected),
                    (None, None) => true,
                    _ => false,
                });
        let Some(raw_key) = key.encode().map(NonZeroU64::get) else {
            this.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return Err(ControlGateError::Poisoned);
        };
        if crate::exec::current_task_id() != Some(task)
            || crate::heap::current_domain() != domain
            || !record_exact
            || this
                .gate
                .publishing_key
                .compare_exchange(0, raw_key, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            this.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return Err(ControlGateError::Poisoned);
        }
        let acquiring = (task.0 << 2) | CONTROL_ACQUIRING;
        if this
            .gate
            .state
            .compare_exchange(this.held, acquiring, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            this.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return Err(ControlGateError::Poisoned);
        }
        Ok(ControlPublicationLease {
            gate: this.gate,
            acquiring,
            held: this.held,
            task,
            domain,
            key,
            cleanup,
            not_send: PhantomData,
        })
    }
}

#[cfg(feature = "ssh-component-command")]
impl<'a> ControlPublicationLease<'a> {
    fn resume(self) -> Result<ControlGuard<'a>, ControlGateError> {
        let this = core::mem::ManuallyDrop::new(self);
        if crate::exec::current_task_id() != Some(this.task)
            || crate::heap::current_domain() != this.domain
            || this.gate.owner.load(Ordering::Acquire) != this.domain.owner.get()
            || this.gate.arena.load(Ordering::Acquire) != this.domain.arena.get()
            || this.gate.publishing_key.load(Ordering::Acquire)
                != this.key.encode().map(NonZeroU64::get).unwrap_or(0)
            || this
                .gate
                .state
                .compare_exchange(
                    this.acquiring,
                    this.held,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            this.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return Err(ControlGateError::Poisoned);
        }
        let record_exact = unsafe { &*this.gate.table.get() }
            .exact(this.key)
            .is_some_and(|record| match (record.cleanup, this.cleanup) {
                (Some(stored), Some(expected)) => stored.matches_exact(expected),
                (None, None) => true,
                _ => false,
            });
        if !record_exact
            || this
                .gate
                .publishing_key
                .compare_exchange(
                    this.key.encode().map(NonZeroU64::get).unwrap_or(0),
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            this.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return Err(ControlGateError::Poisoned);
        }
        Ok(ControlGuard {
            gate: this.gate,
            held: this.held,
            not_send: PhantomData,
        })
    }
}

#[cfg(feature = "ssh-component-command")]
impl Drop for ControlPublicationLease<'_> {
    fn drop(&mut self) {
        let _ = self.gate.state.compare_exchange(
            self.acquiring,
            CONTROL_POISONED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        // Preserve the nonzero generational seal as fail-stop evidence. It is
        // never reused or cleared after an abandoned publication transaction.
        lifecycle_fail_stop();
    }
}

#[cfg(feature = "ssh-component-command")]
impl Deref for ControlGuard<'_> {
    type Target = ControlTable;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.gate.table.get() }
    }
}

#[cfg(feature = "ssh-component-command")]
impl DerefMut for ControlGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.gate.table.get() }
    }
}

#[cfg(feature = "ssh-component-command")]
impl Drop for ControlGuard<'_> {
    fn drop(&mut self) {
        if self.gate.publishing_key.load(Ordering::Acquire) != 0 {
            self.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
            return;
        }
        let failed = self.gate.fail_wake_pending.swap(false, Ordering::AcqRel);
        let wakes = if failed {
            self.gate.detach_fail_stop_wakes()
        } else {
            (
                [const { None }; CONTROL_SLOTS],
                [const { None }; CONTROL_SLOTS],
                [const { None }; CONTROL_SLOTS],
            )
        };
        let cleanups = if failed {
            self.gate.fail_stop_cleanups()
        } else {
            [const { None }; CONTROL_SLOTS]
        };
        let released = self
            .gate
            .state
            .compare_exchange(
                self.held,
                CONTROL_FREE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .is_ok();
        if !released {
            self.gate.state.store(CONTROL_POISONED, Ordering::Release);
            lifecycle_fail_stop();
        }
        ControlGate::dispatch_wakes(wakes.0);
        ControlGate::dispatch_wakes(wakes.1);
        ControlGate::dispatch_exact_wakes(wakes.2);
        ControlGate::quarantine_cleanups(cleanups);
        // Close the race where another task stores fail_wake_pending after
        // the locked drain above but still observes this guard's HELD word.
        // CONTROL is now FREE or POISONED, so the generation mirror is the
        // conservative lock-independent source of truth.
        if self.gate.fail_wake_pending.swap(false, Ordering::AcqRel) {
            let wakes = self.gate.detach_fail_stop_wakes();
            let cleanups = self.gate.fail_stop_cleanups();
            ControlGate::dispatch_wakes(wakes.0);
            ControlGate::dispatch_wakes(wakes.1);
            ControlGate::dispatch_exact_wakes(wakes.2);
            ControlGate::quarantine_cleanups(cleanups);
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlKey {
    slot: u8,
    generation: u64,
}

#[cfg(feature = "ssh-component-command")]
impl ControlKey {
    fn encode(self) -> Option<NonZeroU64> {
        let slot = u64::from(self.slot).checked_add(1)?;
        NonZeroU64::new((self.generation << CONTROL_SLOT_BITS) | slot)
    }

    fn decode(raw: NonZeroU64) -> Option<Self> {
        let value = raw.get();
        let slot = (value & ((1 << CONTROL_SLOT_BITS) - 1)) as usize;
        let generation = value >> CONTROL_SLOT_BITS;
        if slot == 0 || slot > CONTROL_SLOTS || generation == 0 {
            return None;
        }
        Some(Self {
            slot: (slot - 1) as u8,
            generation,
        })
    }

    fn managed_token(self) -> Option<ManagedComponentToken> {
        self.encode()
            .map(|raw| unsafe { ManagedComponentToken::from_trusted_raw(raw) })
    }
}

#[cfg(feature = "ssh-component-command")]
fn child_detach_target(key: ControlKey) -> Option<TaskDetachTarget> {
    let context = key.encode()?.get();
    Some(unsafe { TaskDetachTarget::new(context, managed_child_detached) })
}

#[cfg(feature = "ssh-component-command")]
fn supervisor_detach_target(key: ControlKey) -> Option<TaskDetachTarget> {
    let context = key.encode()?.get();
    Some(unsafe { TaskDetachTarget::new(context, managed_supervisor_detached) })
}

#[cfg(feature = "ssh-component-command")]
fn detach_key(context: u64) -> Option<ControlKey> {
    ControlKey::decode(NonZeroU64::new(context)?)
}

#[cfg(feature = "ssh-component-command")]
unsafe fn managed_child_detached(
    context: u64,
    task: TaskId,
    domain: AllocationDomain,
    reason: TaskDetachReason,
) {
    let Some(key) = detach_key(context) else {
        lifecycle_fail_stop();
        return;
    };
    let Some(shadow) = CONTROL.child_shadow.get(key.slot as usize) else {
        lifecycle_fail_stop();
        return;
    };
    let Some(phase) = shadow.phase(key) else {
        // A callback from an older generation is permanently inert.
        return;
    };
    if !shadow.exact(key, task, domain) {
        shadow
            .phase
            .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        lifecycle_fail_stop();
        return;
    }
    if phase == TASK_SHADOW_COMPLETE && reason == TaskDetachReason::Exited {
        return;
    }
    if phase == TASK_SHADOW_QUARANTINED {
        return;
    }
    if phase != TASK_SHADOW_RUNNING {
        shadow
            .phase
            .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        lifecycle_fail_stop();
        return;
    }
    let publish = match shadow.publish_reason(key, task, domain, reason) {
        Ok(publish) => publish,
        Err(()) => {
            shadow
                .phase
                .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
            lifecycle_fail_stop();
            return;
        }
    };
    if !publish {
        return;
    }
    let wake = CONTROL
        .child_exit(key)
        .and_then(|queue| queue.publish(key.generation).ok());
    let Some(wake) = wake else {
        shadow
            .phase
            .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        lifecycle_fail_stop();
        return;
    };
    wake.dispatch();
}

#[cfg(feature = "ssh-component-command")]
unsafe fn managed_supervisor_detached(
    context: u64,
    task: TaskId,
    domain: AllocationDomain,
    reason: TaskDetachReason,
) {
    let Some(key) = detach_key(context) else {
        lifecycle_fail_stop();
        return;
    };
    let Some(shadow) = CONTROL.supervisor_shadow.get(key.slot as usize) else {
        lifecycle_fail_stop();
        return;
    };
    let Some(phase) = shadow.phase(key) else {
        return;
    };
    if !shadow.exact(key, task, domain) {
        shadow
            .phase
            .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        lifecycle_fail_stop();
        return;
    }
    if phase == TASK_SHADOW_COMPLETE && reason == TaskDetachReason::Exited {
        return;
    }
    if phase == TASK_SHADOW_QUARANTINED {
        return;
    }
    if phase != TASK_SHADOW_RUNNING || shadow.publish_reason(key, task, domain, reason).is_err() {
        shadow
            .phase
            .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
        lifecycle_fail_stop();
        return;
    }
    shadow
        .phase
        .store(TASK_SHADOW_QUARANTINED, Ordering::Release);
    lifecycle_fail_stop();
}

#[cfg(feature = "ssh-component-command")]
struct ImageComponentLifecycle;

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadMode {
    CommandSync,
    #[cfg(feature = "ssh-native-async-command")]
    NativeAsyncCommand,
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    AcceptanceFault {
        round: u8,
        hart: u8,
    },
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    AcceptanceStream {
        round: u8,
        hart: u8,
    },
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    AcceptanceTerminalRace {
        case: u8,
        terminal: ComponentTerminal,
    },
    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
    NativeAsyncAcceptance,
}

#[cfg(feature = "ssh-component-command")]
impl PayloadMode {
    const fn is_native_async(self) -> bool {
        match self {
            #[cfg(feature = "ssh-native-async-command")]
            Self::NativeAsyncCommand => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            Self::NativeAsyncAcceptance => true,
            _ => false,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StartPolicyGate {
    Sync,
    #[cfg(feature = "ssh-native-async-command")]
    NativeAsync,
    #[cfg(any(
        feature = "wasm-c48-qemu-acceptance",
        feature = "wasm-c53-native-async-qemu-acceptance"
    ))]
    None,
}

#[cfg(feature = "ssh-component-command")]
impl StartPolicyGate {
    fn permits(self) -> bool {
        match self {
            Self::Sync => SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_PASSED,
            #[cfg(feature = "ssh-native-async-command")]
            Self::NativeAsync => native_async_acceptance::policy_gate_passed(),
            #[cfg(any(
                feature = "wasm-c48-qemu-acceptance",
                feature = "wasm-c53-native-async-qemu-acceptance"
            ))]
            Self::None => true,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn start_route_exact(
    gate: StartPolicyGate,
    mode: PayloadMode,
    input: &ComponentStartInput,
) -> bool {
    // In the sync-only feature matrix each input enum has only its sync variant, so the
    // fail-closed wildcard is statically unreachable. Other supported matrices need it.
    #[allow(unreachable_patterns)]
    match (gate, mode, input.kind()) {
        (StartPolicyGate::Sync, PayloadMode::CommandSync, ControlStartKind::ManagedSync) => true,
        #[cfg(feature = "ssh-native-async-command")]
        (
            StartPolicyGate::NativeAsync,
            PayloadMode::NativeAsyncCommand,
            ControlStartKind::ManagedNativeAsync,
        ) => true,
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        (StartPolicyGate::None, PayloadMode::CommandSync, ControlStartKind::Acceptance)
        | (
            StartPolicyGate::None,
            PayloadMode::AcceptanceFault { .. },
            ControlStartKind::Acceptance,
        )
        | (
            StartPolicyGate::None,
            PayloadMode::AcceptanceStream { .. },
            ControlStartKind::Acceptance,
        )
        | (
            StartPolicyGate::None,
            PayloadMode::AcceptanceTerminalRace { .. },
            ControlStartKind::Acceptance,
        ) => true,
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        (
            StartPolicyGate::None,
            PayloadMode::NativeAsyncAcceptance,
            ControlStartKind::NativeAsyncAcceptance,
        ) => true,
        _ => false,
    }
}

#[cfg(feature = "ssh-component-command")]
struct LazyComponentPayload {
    root: Option<&'static ImageRoot>,
    control: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    resource_generation: u64,
    streams: RegistryStreamBindings,
    mode: PayloadMode,
    driver: Option<Pin<Box<dyn Future<Output = u64> + Send>>>,
    ready: Option<u64>,
}

#[cfg(feature = "ssh-component-command")]
struct ManagedChildFuture {
    token: InstanceToken,
    control: ControlKey,
}

#[cfg(feature = "ssh-component-command")]
const _: () = assert!(core::mem::size_of::<ManagedChildFuture>() <= 32);

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChildStartGate {
    Active,
    AwaitStart,
    RetryBusy,
    Isolated,
}

#[cfg(feature = "ssh-component-command")]
fn child_start_gate(
    key: ControlKey,
    token: InstanceToken,
    witness: ReclaimableTaskWitness,
) -> ChildStartGate {
    if !lifecycle_is_healthy() {
        return ChildStartGate::Isolated;
    }
    let shadow = &CONTROL.child_shadow[key.slot as usize];
    match shadow.phase(key) {
        Some(TASK_SHADOW_PREPARED) => return ChildStartGate::AwaitStart,
        Some(TASK_SHADOW_RUNNING) => {}
        _ => return ChildStartGate::Isolated,
    }
    let projection = {
        let mut control = match CONTROL.try_lock() {
            Ok(control) => control,
            Err(ControlGateError::Busy) => return ChildStartGate::RetryBusy,
            Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
                return ChildStartGate::Isolated;
            }
        };
        let exact = control.exact(key).is_some_and(|record| {
            record.phase == ControlPhase::Running
                && record.core_token == Some(token)
                && record.domain == Some(witness.allocation_domain())
                && record.handle.as_ref().is_some_and(|handle| {
                    handle.id() == witness.task_id()
                        && handle.allocation_domain() == witness.allocation_domain()
                        && witness.matches_handle(handle)
                })
                && shadow.exact(key, witness.task_id(), witness.allocation_domain())
                && shadow.phase(key) == Some(TASK_SHADOW_RUNNING)
        });
        if !exact {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            return ChildStartGate::Isolated;
        }
        let record = control
            .exact(key)
            .expect("validated child control record remains exact");
        (record.start_kind, record.cleanup)
    };
    // Never acquire the VSH reaper registry below CONTROL. The second CONTROL
    // projection check closes the check/use window around this copy-only
    // lifecycle query.
    let active = match projection {
        (Some(ControlStartKind::ManagedSync), Some(cleanup)) => key
            .managed_token()
            .is_some_and(|managed| cleanup.is_active_for(managed)),
        #[cfg(feature = "ssh-native-async-command")]
        (Some(ControlStartKind::ManagedNativeAsync), Some(cleanup)) => key
            .managed_token()
            .is_some_and(|managed| cleanup.is_active_for(managed)),
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        (Some(ControlStartKind::Acceptance), None) => true,
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        (Some(ControlStartKind::NativeAsyncAcceptance), None) => true,
        _ => false,
    };
    if !active {
        CONTROL.child_shadow[key.slot as usize].quarantine(key);
        CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
        let _ = registry().quarantine(token);
        lifecycle_fail_stop();
        return ChildStartGate::Isolated;
    }
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return ChildStartGate::RetryBusy,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            return ChildStartGate::Isolated;
        }
    };
    let exact = control.exact(key).is_some_and(|record| {
        record.phase == ControlPhase::Running
            && record.core_token == Some(token)
            && record.start_kind == projection.0
            && match (record.cleanup, projection.1) {
                (Some(current), Some(previous)) => current.matches_exact(previous),
                (None, None) => true,
                _ => false,
            }
            && record
                .handle
                .as_ref()
                .is_some_and(|handle| witness.matches_handle(handle))
    });
    if exact && lifecycle_is_healthy() {
        return ChildStartGate::Active;
    }
    if let Some(record) = control.exact_mut(key) {
        record.quarantine();
    }
    drop(control);
    CONTROL.child_shadow[key.slot as usize].quarantine(key);
    CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
    let _ = registry().quarantine(token);
    lifecycle_fail_stop();
    ChildStartGate::Isolated
}

#[cfg(feature = "ssh-component-command")]
impl Future for ManagedChildFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Poll::Ready(());
        };
        if witness.instance_token() != Some(self.token) {
            lifecycle_fail_stop();
            return Poll::Ready(());
        }
        match child_start_gate(self.control, self.token, witness) {
            ChildStartGate::Active => {}
            ChildStartGate::AwaitStart => return Poll::Pending,
            ChildStartGate::RetryBusy => {
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            ChildStartGate::Isolated => {
                // Only the copy-token executor envelope terminates. The
                // registry payload, arena, Space, and CSpace remain untouched
                // and permanently quarantined by the stable SYSTEM records.
                let _ = registry().quarantine(self.token);
                lifecycle_fail_stop();
                return Poll::Ready(());
            }
        }
        let (permit, expected) = lifecycle_poll_permit();
        match unsafe { registry().poll_payload_if(witness, context, permit, expected) } {
            Ok(Poll::Ready(_)) => Poll::Ready(()),
            Ok(Poll::Pending) => match child_start_gate(self.control, self.token, witness) {
                ChildStartGate::Active | ChildStartGate::AwaitStart => Poll::Pending,
                // The inner payload has already returned Pending and therefore
                // owns the exact wake which makes its next poll useful. A
                // CONTROL collision here is only a failed post-poll proof; a
                // synthetic self-wake would poll an External continuation
                // before its signal. Cancellation and fail-stop separately
                // publish the exact child wake, so preserving Pending cannot
                // strand this generation.
                ChildStartGate::RetryBusy => Poll::Pending,
                ChildStartGate::Isolated => {
                    let _ = registry().quarantine(self.token);
                    lifecycle_fail_stop();
                    Poll::Ready(())
                }
            },
            Err(_) => {
                CONTROL.child_shadow[self.control.slot as usize].quarantine(self.control);
                CONTROL.supervisor_shadow[self.control.slot as usize].quarantine(self.control);
                let _ = registry().quarantine(self.token);
                lifecycle_fail_stop();
                Poll::Ready(())
            }
        }
    }
}

#[cfg(feature = "ssh-component-command")]
impl LazyComponentPayload {
    const fn new(
        root: Option<&'static ImageRoot>,
        control: ControlKey,
        token: InstanceToken,
        task: TaskId,
        domain: AllocationDomain,
        resource_generation: u64,
        streams: RegistryStreamBindings,
        mode: PayloadMode,
    ) -> Self {
        Self {
            root,
            control,
            token,
            task,
            domain,
            resource_generation,
            streams,
            mode,
            driver: None,
            ready: None,
        }
    }
}

#[cfg(any(
    feature = "wasm-c48-qemu-acceptance",
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
impl Drop for LazyComponentPayload {
    fn drop(&mut self) {
        #[cfg(any(
            feature = "wasm-c53-native-async-qemu-acceptance",
            feature = "ssh-native-async-command"
        ))]
        if self.mode.is_native_async() {
            // The runtime future may own the exact InstanceContinuation and
            // backend-local state. Drop it first so the continuation's
            // cancellation state is visible before the stable pending ledger
            // acknowledges the runtime owner and decides whether cleanup is
            // reclaim-safe.
            drop(self.driver.take());
            native_async_acceptance::payload_drop(
                self.control,
                self.token,
                self.task,
                self.domain,
                self.streams,
            );
        }
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        if matches!(self.mode, PayloadMode::AcceptanceFault { .. }) {
            acceptance::record_fault_payload_drop();
        }
    }
}

// SAFETY: every owned field is allocated in the exact instance arena. The
// only external reference is the immutable boot-static image root; neither a
// CSpace nor any arena-backed ownership can escape through it. The inner
// engine/future is created lazily inside the child poll, so all engine Arc
// control blocks and clones are arena-local and may be raw-reclaimed together.
#[cfg(feature = "ssh-component-command")]
unsafe impl InstancePayload for LazyComponentPayload {
    fn poll_quantum(
        &mut self,
        _space: &crate::instance::InstanceSpace,
        context: &mut Context<'_>,
    ) -> Poll<u64> {
        if !lifecycle_is_healthy() {
            // Isolation won before a payload terminal. Keep the arena-owned
            // payload installed; returning Ready would authorize registry
            // take/drop and eventually a CSpace reset without an exact proof.
            return Poll::Pending;
        }
        if self.driver.is_none() {
            self.driver = Some(Box::pin(run_image_component(
                self.root,
                self.control,
                self.token,
                self.task,
                self.domain,
                self.resource_generation,
                self.streams,
                self.mode,
            )));
        }
        if self.ready.is_none() {
            match self
                .driver
                .as_mut()
                .expect("lazy component driver was just installed")
                .as_mut()
                .poll(context)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(word) => self.ready = Some(word),
            }
        }
        let word = self.ready.expect("completed driver retained its word");
        let terminal = terminal_from_word(word);
        if word != terminal_word(terminal) {
            lifecycle_fail_stop();
            return Poll::Ready(terminal_word(ComponentTerminal::RunnerFault));
        }
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        if let PayloadMode::AcceptanceTerminalRace { case, .. } = self.mode {
            acceptance::terminal_race_before_publish(case, terminal);
        }
        match publish_payload_terminal(self.control, self.token, self.streams, terminal) {
            PayloadTerminalPublish::Published(effective) => {
                #[cfg(feature = "wasm-c48-qemu-acceptance")]
                if let PayloadMode::AcceptanceTerminalRace { case, .. } = self.mode {
                    acceptance::terminal_race_after_publish(case, terminal, effective);
                }
                Poll::Ready(terminal_word(effective))
            }
            PayloadTerminalPublish::Busy => {
                context.waker().wake_by_ref();
                Poll::Pending
            }
            PayloadTerminalPublish::Failed => {
                lifecycle_fail_stop();
                Poll::Pending
            }
        }
    }
}

#[cfg(all(
    feature = "ssh-component-command",
    feature = "wasm-c53-native-async-qemu-acceptance"
))]
pub(crate) fn init() {
    // This feature is a sealed validation-candidate image, not an SSH command
    // image. Do not even construct/publish the synchronous SSH_EXEC_COMPONENT
    // root, and prove that its production/session gate remains untouched.
    if !IMAGE_ROOT.load(Ordering::Acquire).is_null()
        || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_CLOSED
    {
        lifecycle_fail_stop();
        panic!("native async acceptance started with a published synchronous root or gate");
    }
    native_async_acceptance::init();
    if !IMAGE_ROOT.load(Ordering::Acquire).is_null()
        || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_CLOSED
    {
        lifecycle_fail_stop();
        panic!("native async acceptance modified the synchronous SSH image path");
    }
}

#[cfg(all(
    feature = "ssh-component-command",
    not(feature = "wasm-c53-native-async-qemu-acceptance")
))]
pub(crate) fn init() {
    if !IMAGE_ROOT.load(Ordering::Acquire).is_null() {
        lifecycle_fail_stop();
        panic!("managed component image root initialized twice");
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let root = match build_image_root() {
        Ok(root) => Box::new(root),
        Err(_) => {
            lifecycle_fail_stop();
            system.restore();
            panic!("image-pinned WASM component admission failed");
        }
    };
    let pointer = Box::into_raw(root);
    if IMAGE_ROOT
        .compare_exchange(
            ptr::null_mut(),
            pointer,
            Ordering::Release,
            Ordering::Acquire,
        )
        .is_err()
    {
        unsafe { drop(Box::from_raw(pointer)) };
        lifecycle_fail_stop();
        system.restore();
        panic!("managed component image root publication raced");
    }
    // The reusable production image publishes only its boot-level image pin
    // here. This does not install an SSH command: every session must still
    // present and immediately revalidate its exact AuthorizedProfile
    // generation, policy incarnation, command name, and artifact digest.
    // The QEMU acceptance image deliberately keeps this gate closed until all
    // mismatch/ABA/multi-hart/repeated-fault and stream lifecycle gates pass.
    #[cfg(not(feature = "wasm-c48-qemu-acceptance"))]
    {
        let root = unsafe { &*pointer };
        if !lifecycle_is_healthy()
            || !revalidate_image_root(root)
            || SSH_POLICY_GATE
                .compare_exchange(
                    POLICY_CLOSED,
                    POLICY_PASSED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            lifecycle_fail_stop();
            system.restore();
            panic!("managed component production image policy publication failed");
        }
    }
    system.restore();
    #[cfg(feature = "ssh-native-async-command")]
    {
        let sync_gate = SSH_POLICY_GATE.load(Ordering::Acquire);
        native_async_acceptance::init();
        if SSH_POLICY_GATE.load(Ordering::Acquire) != sync_gate {
            lifecycle_fail_stop();
            panic!("native async command projection modified the synchronous policy gate");
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn image_root() -> Option<&'static ImageRoot> {
    unsafe { IMAGE_ROOT.load(Ordering::Acquire).as_ref() }
}

#[cfg(feature = "ssh-component-command")]
fn build_image_root() -> Result<ImageRoot, ComponentTerminal> {
    let pin = SSH_EXEC_COMPONENT;
    let world = WorldContract::parse(pin.wit_source(), pin.world())
        .map_err(|_| ComponentTerminal::BackendFault)?;
    let artifact = ComponentArtifact::copy_from(pin.artifact_bytes(), pin.profile())
        .map_err(|_| ComponentTerminal::BackendFault)?;
    let identity = artifact.identity();
    if identity.as_bytes() != &pin.expected_sha256() {
        return Err(ComponentTerminal::BackendFault);
    }
    let limits = pin.limits();
    let admitted = admit(
        artifact,
        &AdmissionPolicy {
            command_name: pin.command_name(),
            entrypoint: pin.entrypoint(),
            min_args: pin.min_args(),
            max_args: pin.max_args(),
            exact_world: &world,
            profile: pin.profile(),
            trust: ArtifactTrust::ImagePinned(identity),
            limits: InstanceLimits {
                memory_bytes: limits.memory_bytes,
                total_fuel: limits.total_fuel,
                poll_quantum: limits.poll_quantum,
                resources: limits.resources,
            },
            stdin: admission_stream(pin.stdin()),
            stdout: admission_stream(pin.stdout()),
            stderr: admission_stream(pin.stderr()),
            interfaces: &[],
        },
        &CallerAuthority { offers: &[] },
    )
    .map_err(|_| ComponentTerminal::BackendFault)?;
    let manifest = try_manifest_from_admitted(&admitted).map_err(build_error_terminal)?;
    validate_admitted_stream_filter(&admitted, &manifest).map_err(build_error_terminal)?;
    let ssh_policy = image_vsh_policy(pin).map_err(|_| ComponentTerminal::BackendFault)?;
    if !ssh_policy.admits_manifest(&manifest)
        || manifest.min_args() != 0
        || manifest.max_args() != 0
        || manifest.world() != VIBE_STREAM_FILTER_WORLD
        || manifest.stdin() != StreamMode::Required
        || manifest.stdout() != StreamMode::Required
        || manifest.stderr() == StreamMode::Required
        || !manifest.requirements().is_empty()
    {
        return Err(ComponentTerminal::BackendFault);
    }
    Ok(ImageRoot {
        admitted,
        manifest,
        ssh_policy,
        policy_incarnation: NonZeroU64::new(1).expect("one is nonzero"),
    })
}

#[cfg(feature = "ssh-component-command")]
fn revalidate_image_root(root: &ImageRoot) -> bool {
    root.policy_incarnation.get() == 1
        && root.admitted.identity().as_bytes() == &SSH_EXEC_COMPONENT.expected_sha256()
        && try_manifest_from_admitted(&root.admitted).is_ok_and(|manifest| {
            manifest == root.manifest
                && root.ssh_policy.admits_manifest(&manifest)
                && validate_admitted_stream_filter(&root.admitted, &manifest).is_ok()
        })
}

#[cfg(feature = "ssh-component-command")]
fn image_vsh_policy(
    pin: ComponentCommandPin,
) -> Result<SshExecComponentPolicy, vibeos_vsh::Diagnostic> {
    let limits = pin.limits();
    SshExecComponentPolicy::from_image_pin(
        pin.command_name(),
        pin.abi(),
        ComponentArtifactIdentity::new(pin.expected_sha256()),
        pin.world(),
        pin.entrypoint(),
        pin.min_args(),
        pin.max_args(),
        vsh_stream(pin.stdin()),
        vsh_stream(pin.stdout()),
        vsh_stream(pin.stderr()),
        limits.memory_bytes,
        limits.total_fuel,
        limits.poll_quantum,
        limits.resources,
        Vec::new(),
    )
}

#[cfg(feature = "ssh-component-command")]
const fn admission_stream(mode: ComponentStreamMode) -> CommandStreamMode {
    match mode {
        ComponentStreamMode::Required => CommandStreamMode::Required,
        ComponentStreamMode::Optional => CommandStreamMode::Optional,
        ComponentStreamMode::Closed => CommandStreamMode::Closed,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn vsh_stream(mode: ComponentStreamMode) -> StreamMode {
    match mode {
        ComponentStreamMode::Required => StreamMode::Required,
        ComponentStreamMode::Optional => StreamMode::Optional,
        ComponentStreamMode::Closed => StreamMode::Closed,
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamEndpoint {
    Reader,
    Writer,
}

/// Arena-local, copy-only authority stored in the Canonical ABI resource
/// table. It cannot keep the stable CSpace or any stream object alive.
#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComponentAuthority {
    instance: InstanceToken,
    cspace_identity: CSpaceIdentity,
    cspace_incarnation: u64,
    cap: Cap,
    endpoint: StreamEndpoint,
}

#[cfg(feature = "ssh-component-command")]
impl ComponentAuthority {
    const fn reader(instance: InstanceToken, streams: RegistryStreamBindings) -> Self {
        Self {
            instance,
            cspace_identity: streams.cspace_identity,
            cspace_incarnation: streams.cspace_incarnation,
            cap: streams.stdin,
            endpoint: StreamEndpoint::Reader,
        }
    }

    const fn writer(instance: InstanceToken, streams: RegistryStreamBindings) -> Self {
        Self {
            instance,
            cspace_identity: streams.cspace_identity,
            cspace_incarnation: streams.cspace_incarnation,
            cap: streams.stdout,
            endpoint: StreamEndpoint::Writer,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingStreamKind {
    ReadWaiting,
    ReadPrepared { length: u16 },
    WriteWaiting,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStreamOperation {
    token: HostOperationToken,
    kind: PendingStreamKind,
}

/// The call-scoped dispatcher is arena-local. Every field is copy-only; live
/// authority is reacquired from the registry-owned CSpace for every method.
#[cfg(feature = "ssh-component-command")]
struct RegistryStreamDispatcher {
    instance: InstanceToken,
    streams: RegistryStreamBindings,
    reader_type: ResourceTypeId,
    writer_type: ResourceTypeId,
    pending: Option<PendingStreamOperation>,
}

#[cfg(feature = "ssh-component-command")]
impl RegistryStreamDispatcher {
    const fn new(
        instance: InstanceToken,
        streams: RegistryStreamBindings,
        reader_type: ResourceTypeId,
        writer_type: ResourceTypeId,
    ) -> Self {
        Self {
            instance,
            streams,
            reader_type,
            writer_type,
            pending: None,
        }
    }

    fn exact_authority(&self, authority: ComponentAuthority, endpoint: StreamEndpoint) -> bool {
        let expected_cap = match endpoint {
            StreamEndpoint::Reader => self.streams.stdin,
            StreamEndpoint::Writer => self.streams.stdout,
        };
        authority.instance == self.instance
            && authority.cspace_identity == self.streams.cspace_identity
            && authority.cspace_incarnation == self.streams.cspace_incarnation
            && authority.cap == expected_cap
            && authority.endpoint == endpoint
    }

    fn borrow_authority(
        &self,
        request: &HostRequest<'_, ComponentAuthority>,
        endpoint: StreamEndpoint,
    ) -> Result<ComponentAuthority, HostError> {
        let authority = request
            .with_borrow_argument(0, |authority| *authority)
            .map_err(|_| HostError::Denied)?;
        if !self.exact_authority(authority, endpoint) {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        Ok(authority)
    }

    fn install_pending(
        &mut self,
        token: HostOperationToken,
        kind: PendingStreamKind,
    ) -> Result<(), HostError> {
        if self.pending.is_some() {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        self.pending = Some(PendingStreamOperation { token, kind });
        Ok(())
    }

    fn replace_pending(
        &mut self,
        previous: PendingStreamOperation,
        token: HostOperationToken,
        kind: PendingStreamKind,
    ) -> Result<(), HostError> {
        if self.pending != Some(previous) || token == previous.token {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        self.pending = Some(PendingStreamOperation { token, kind });
        Ok(())
    }
}

#[cfg(feature = "ssh-component-command")]
impl HostDispatcher<ComponentAuthority> for RegistryStreamDispatcher {
    fn required_work(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<u64, HostError> {
        if stream_read_shape(import, self.reader_type)
            && matches!(arguments, [CanonicalValue::Resource(_)])
        {
            return Ok(STREAM_READ_WORK);
        }
        if stream_write_shape(import, self.writer_type) {
            let [CanonicalValue::Resource(_), CanonicalValue::List(values)] = arguments else {
                return Err(HostError::Denied);
            };
            if values.is_empty()
                || values.len() > MAX_STREAM_CHUNK_BYTES
                || values
                    .iter()
                    .any(|value| !matches!(value, CanonicalValue::U8(_)))
            {
                return Err(HostError::InvalidArgument);
            }
            return STREAM_WRITE_BASE_WORK
                .checked_add(u64::try_from(values.len()).map_err(|_| HostError::Exhausted)?)
                .ok_or(HostError::Exhausted);
        }
        for (endpoint, resource_type) in [
            (StreamEndpoint::Reader, self.reader_type),
            (StreamEndpoint::Writer, self.writer_type),
        ] {
            if stream_close_shape(import, resource_type, endpoint) {
                let [CanonicalValue::Resource(_), reason] = arguments else {
                    return Err(HostError::Denied);
                };
                canonical_close_reason(reason)?;
                return Ok(STREAM_CLOSE_WORK);
            }
        }
        Err(HostError::Denied)
    }

    fn result_allocations(
        &self,
        import: &HostImportInfo,
        arguments: &[CanonicalValue],
    ) -> Result<Vec<HostPayloadAllocation>, HostError> {
        if stream_read_shape(import, self.reader_type)
            && matches!(arguments, [CanonicalValue::Resource(_)])
        {
            Self::read_allocation()
        } else {
            Ok(Vec::new())
        }
    }

    fn start(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        match (
            request.import().interface.as_str(),
            request.import().function.as_str(),
        ) {
            (STREAM_INTERFACE, STREAM_READ_FUNCTION) => self.start_read(request),
            (STREAM_INTERFACE, STREAM_WRITE_FUNCTION) => self.start_write(request),
            (STREAM_INTERFACE, STREAM_CLOSE_READER_FUNCTION) => self.close_reader(request),
            (STREAM_INTERFACE, STREAM_CLOSE_WRITER_FUNCTION) => self.close_writer(request),
            _ => Err(HostError::Denied),
        }
    }

    fn register_wake(
        &mut self,
        operation: HostOperationToken,
        wake: HostWakeToken,
    ) -> Result<(), HostError> {
        let Some(pending) = self.pending else {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        };
        if pending.token != operation {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        match pending.kind {
            PendingStreamKind::ReadWaiting => {
                with_active_reader(self.instance, self.streams, |reader, supervisor| {
                    promote_provisional_eof(supervisor)?;
                    reader
                        .register_wake(operation, wake)
                        .map_err(map_stream_error)
                })??
            }
            PendingStreamKind::WriteWaiting => {
                with_active_writer(self.instance, self.streams, |writer| {
                    writer
                        .register_wake(operation, wake)
                        .map_err(map_stream_error)
                })??;
                #[cfg(feature = "wasm-c48-qemu-acceptance")]
                acceptance::record_stream_host_pending(self.instance, operation);
            }
            PendingStreamKind::ReadPrepared { .. } => {
                lifecycle_fail_stop();
                return Err(HostError::BackendFault);
            }
        }
        Ok(())
    }

    fn resume(
        &mut self,
        operation: HostOperationToken,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        let Some(pending) = self.pending else {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        };
        if pending.token != operation {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        let result = match pending.kind {
            PendingStreamKind::ReadWaiting => self.resume_read(pending, request),
            PendingStreamKind::WriteWaiting => self.resume_write(pending, request),
            PendingStreamKind::ReadPrepared { .. } => {
                lifecycle_fail_stop();
                Err(HostError::BackendFault)
            }
        };
        if result.is_err() {
            // `HostDispatcher::resume` consumes its supplied operation on
            // every return. Preparation/authority/allocation failures may
            // occur before the backend retry, while a post-retry failure may
            // leave a fresh Waiting/Prepared token which was never exposed to
            // the runtime. Detach whichever exact operation remains so Drop
            // cannot issue a delayed duplicate cancellation or retain a stale
            // wake edge.
            if let Some(unexposed) = self.pending {
                if self.cancel(unexposed.token).is_err() {
                    lifecycle_fail_stop();
                    return Err(HostError::BackendFault);
                }
            }
        }
        result
    }

    fn commit_prepared(
        &mut self,
        operation: HostOperationToken,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostResponse, HostError> {
        let Some(pending) = self.pending else {
            return Err(HostError::BackendFault);
        };
        let PendingStreamKind::ReadPrepared { length } = pending.kind else {
            return Err(HostError::BackendFault);
        };
        // Operation tokens are opaque, non-owning generations. A stale,
        // duplicate, or cross-stream value fails closed without mutating the
        // exact live reservation or poisoning unrelated managed instances.
        if pending.token != operation {
            return Err(HostError::BackendFault);
        }
        if !stream_read_shape(request.import(), self.reader_type)
            || !matches!(request.arguments(), [CanonicalValue::Resource(_)])
        {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        let authority = self.borrow_authority(&request, StreamEndpoint::Reader)?;
        let length = usize::from(length);

        // All arena allocations precede the backend pop. After `commit`
        // succeeds, filling both vectors and committing the response cannot
        // allocate or fail.
        let response = HostResponse::reserve_one(STREAM_READ_WORK)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| HostError::Exhausted)?;
        bytes.resize(length, 0);
        let mut values = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| HostError::Exhausted)?;

        let committed = with_active_reader(self.instance, self.streams, |reader, _| {
            reader
                .commit(operation, &mut bytes)
                .map_err(map_stream_error)
        })??;
        match committed {
            StreamReceiveCommit::Received(received) => {
                // The backend pop consumed the reservation even if the
                // returned length violates our sealed prepared shape. Never
                // offer an already-published operation to exact cleanup.
                self.pending = None;
                if received != length {
                    lifecycle_fail_stop();
                    return Err(HostError::BackendFault);
                }
                for byte in bytes {
                    values.push(CanonicalValue::U8(byte));
                }
                if !self.exact_authority(authority, StreamEndpoint::Reader) {
                    lifecycle_fail_stop();
                    return Err(HostError::BackendFault);
                }
                response.commit(CanonicalValue::List(values))
            }
            // A terminal publisher won before the backend pop. Preserve the
            // exact prepared token so the runtime's error path can cancel it
            // once before reclaiming its known guest allocations.
            StreamReceiveCommit::Closed(reason) => Err(closed_stream_error(reason)),
        }
    }

    fn cancel(&mut self, operation: HostOperationToken) -> Result<(), HostError> {
        let Some(pending) = self.pending else {
            return Err(HostError::BackendFault);
        };
        if pending.token != operation {
            return Err(HostError::BackendFault);
        }
        // Consume locally before touching the stable resource. Even an error
        // cannot cause dispatcher Drop to issue a duplicate cancellation.
        self.pending = None;
        match pending.kind {
            PendingStreamKind::ReadWaiting | PendingStreamKind::ReadPrepared { .. } => {
                with_cleanup_reader(self.instance, self.streams, |reader| {
                    reader.cancel(operation).map_err(map_stream_error)
                })??
            }
            PendingStreamKind::WriteWaiting => {
                with_cleanup_writer(self.instance, self.streams, |writer| {
                    writer.cancel(operation).map_err(map_stream_error)
                })??
            }
        }
        Ok(())
    }
}

#[cfg(feature = "ssh-component-command")]
impl Drop for RegistryStreamDispatcher {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let cancelled = match pending.kind {
            PendingStreamKind::ReadWaiting | PendingStreamKind::ReadPrepared { .. } => {
                with_cleanup_reader(self.instance, self.streams, |reader| {
                    reader.cancel(pending.token).map_err(map_stream_error)
                })
            }
            PendingStreamKind::WriteWaiting => {
                with_cleanup_writer(self.instance, self.streams, |writer| {
                    writer.cancel(pending.token).map_err(map_stream_error)
                })
            }
        };
        match cancelled {
            Ok(Ok(())) | Err(HostError::Denied) => {}
            Ok(Err(_))
            | Err(
                HostError::Unavailable
                | HostError::Exhausted
                | HostError::InvalidArgument
                | HostError::BackendFault
                | HostError::BudgetExceeded
                | HostError::Failed
                | HostError::Cancelled
                | HostError::InvalidState,
            ) => lifecycle_fail_stop(),
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpaceAccessError {
    Denied,
    Structural,
}

#[cfg(feature = "ssh-component-command")]
fn exact_lease<T: Resource>(
    cspace: &CSpace,
    cap: Cap,
    exact_rights: Rights,
) -> Result<InvocationLease<T>, SpaceAccessError> {
    match cspace.rights_of(cap) {
        Ok(rights) if rights == exact_rights => {}
        Ok(_) => return Err(SpaceAccessError::Structural),
        Err(CapError::Invalid) => return Err(SpaceAccessError::Denied),
        Err(_) => return Err(SpaceAccessError::Structural),
    }
    cspace
        .lookup_lease::<T>(cap, exact_rights)
        .map_err(|error| {
            if error == CapError::Invalid {
                SpaceAccessError::Denied
            } else {
                SpaceAccessError::Structural
            }
        })
}

#[cfg(feature = "ssh-component-command")]
fn validate_stream_space(
    cspace: &CSpace,
    streams: RegistryStreamBindings,
) -> Result<(), SpaceAccessError> {
    if cspace.identity() != streams.cspace_identity
        || cspace.incarnation() != streams.cspace_incarnation
    {
        Err(SpaceAccessError::Structural)
    } else {
        Ok(())
    }
}

#[cfg(feature = "ssh-component-command")]
fn map_space_access<R>(
    result: Result<Result<R, SpaceAccessError>, crate::instance::RegistryError>,
) -> Result<R, HostError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(SpaceAccessError::Denied)) => Err(HostError::Denied),
        Ok(Err(SpaceAccessError::Structural)) | Err(_) => {
            lifecycle_fail_stop();
            Err(HostError::BackendFault)
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn current_instance_witness(
    instance: InstanceToken,
) -> Result<crate::exec::ReclaimableTaskWitness, HostError> {
    let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
        lifecycle_fail_stop();
        return Err(HostError::BackendFault);
    };
    if witness.instance_token() != Some(instance) {
        lifecycle_fail_stop();
        return Err(HostError::BackendFault);
    }
    Ok(witness)
}

#[cfg(feature = "ssh-component-command")]
fn with_active_reader<R>(
    instance: InstanceToken,
    streams: RegistryStreamBindings,
    operation: impl FnOnce(&ByteStreamReader, &ByteStreamSupervisor) -> R,
) -> Result<R, HostError> {
    let witness = current_instance_witness(instance)?;
    let result = unsafe {
        registry().with_active_space(witness, |space| {
            let (reader, supervisor) = {
                let cspace = space.cspace().lock();
                validate_stream_space(&cspace, streams)?;
                let reader = exact_lease::<ByteStreamReader>(&cspace, streams.stdin, Rights::RECV)?;
                let supervisor = exact_lease::<ByteStreamSupervisor>(
                    &cspace,
                    streams.stdin_supervisor,
                    Rights::INVOKE,
                )?;
                (reader, supervisor)
            };
            Ok(reader.with(|reader| supervisor.with(|supervisor| operation(reader, supervisor))))
        })
    };
    map_space_access(result)
}

#[cfg(feature = "ssh-component-command")]
fn with_active_writer<R>(
    instance: InstanceToken,
    streams: RegistryStreamBindings,
    operation: impl FnOnce(&ByteStreamWriter) -> R,
) -> Result<R, HostError> {
    let witness = current_instance_witness(instance)?;
    let result = unsafe {
        registry().with_active_space(witness, |space| {
            let writer = {
                let cspace = space.cspace().lock();
                validate_stream_space(&cspace, streams)?;
                exact_lease::<ByteStreamWriter>(&cspace, streams.stdout, Rights::SEND)?
            };
            Ok(writer.with(operation))
        })
    };
    map_space_access(result)
}

#[cfg(feature = "ssh-component-command")]
fn with_cleanup_reader<R>(
    instance: InstanceToken,
    streams: RegistryStreamBindings,
    operation: impl FnOnce(&ByteStreamReader) -> R,
) -> Result<R, HostError> {
    let witness = current_instance_witness(instance)?;
    let result = unsafe {
        registry().with_current_space_for_cleanup(witness, |space| {
            let reader = {
                let cspace = space.cspace().lock();
                validate_stream_space(&cspace, streams)?;
                exact_lease::<ByteStreamReader>(&cspace, streams.stdin, Rights::RECV)?
            };
            Ok(reader.with(operation))
        })
    };
    map_space_access(result)
}

#[cfg(feature = "ssh-component-command")]
fn with_cleanup_writer<R>(
    instance: InstanceToken,
    streams: RegistryStreamBindings,
    operation: impl FnOnce(&ByteStreamWriter) -> R,
) -> Result<R, HostError> {
    let witness = current_instance_witness(instance)?;
    let result = unsafe {
        registry().with_current_space_for_cleanup(witness, |space| {
            let writer = {
                let cspace = space.cspace().lock();
                validate_stream_space(&cspace, streams)?;
                exact_lease::<ByteStreamWriter>(&cspace, streams.stdout, Rights::SEND)?
            };
            Ok(writer.with(operation))
        })
    };
    map_space_access(result)
}

#[cfg(feature = "ssh-component-command")]
fn promote_provisional_eof(supervisor: &ByteStreamSupervisor) -> Result<(), HostError> {
    match supervisor.promote_normal_if_drained_observed() {
        None => {}
        Some(observation)
            if observation.outcome() == StreamCloseOutcome::Conflict
                || observation.effective_reason().is_none()
                || (observation.outcome() == StreamCloseOutcome::Published
                    && observation.effective_reason() != Some(StreamCloseReason::Normal)) =>
        {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        // AlreadyPublished preserves the old behavior: an immutable terminal,
        // including a non-normal first winner, is observed without attempting
        // a conflicting Normal publication.
        Some(_) => {}
    }
    Ok(())
}

#[cfg(feature = "ssh-component-command")]
fn map_stream_error(error: StreamError) -> HostError {
    match error {
        StreamError::InvalidChunk | StreamError::EndpointClosed => HostError::InvalidArgument,
        StreamError::Busy
        | StreamError::TokenMismatch
        | StreamError::WakeAlreadyRegistered
        | StreamError::InvalidCommitLength
        | StreamError::TokenExhausted
        | StreamError::FailStopped => {
            lifecycle_fail_stop();
            HostError::BackendFault
        }
    }
}

#[cfg(feature = "ssh-component-command")]
const fn closed_stream_error(reason: StreamCloseReason) -> HostError {
    match reason {
        StreamCloseReason::Normal => HostError::InvalidArgument,
        StreamCloseReason::Failure => HostError::Failed,
        StreamCloseReason::Cancelled => HostError::Cancelled,
        StreamCloseReason::Denied => HostError::Denied,
        StreamCloseReason::Unavailable => HostError::Unavailable,
        StreamCloseReason::Exhausted => HostError::Exhausted,
        StreamCloseReason::Invalid => HostError::InvalidState,
        StreamCloseReason::BackendFault => HostError::BackendFault,
    }
}

#[cfg(feature = "ssh-component-command")]
fn checked_close(outcome: StreamCloseOutcome) -> Result<(), HostError> {
    match outcome {
        StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished => Ok(()),
        StreamCloseOutcome::Conflict => {
            lifecycle_fail_stop();
            Err(HostError::BackendFault)
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn borrowed_parameter(
    parameter: &vibeos_component_runtime::types::NamedParameterType,
    name: &str,
    resource_type: ResourceTypeId,
) -> bool {
    parameter.name == name
        && parameter.value
            == ValueType::Resource {
                resource_type,
                ownership: ResourceOwnership::Borrow,
            }
}

#[cfg(feature = "ssh-component-command")]
fn stream_read_shape(import: &HostImportInfo, reader: ResourceTypeId) -> bool {
    import.interface == STREAM_INTERFACE
        && import.function == STREAM_READ_FUNCTION
        && matches!(import.function_type.parameters.as_slice(), [input]
            if borrowed_parameter(input, "input", reader))
        && matches!(import.function_type.result.as_ref(), Some(ValueType::List(item))
            if item.as_ref() == &ValueType::U8)
}

#[cfg(feature = "ssh-component-command")]
fn stream_write_shape(import: &HostImportInfo, writer: ResourceTypeId) -> bool {
    import.interface == STREAM_INTERFACE
        && import.function == STREAM_WRITE_FUNCTION
        && matches!(import.function_type.parameters.as_slice(), [output, bytes]
            if borrowed_parameter(output, "output", writer)
                && bytes.name == "bytes"
                && matches!(&bytes.value, ValueType::List(item) if item.as_ref() == &ValueType::U8))
        && import.function_type.result.is_none()
}

#[cfg(feature = "ssh-component-command")]
fn stream_close_shape(
    import: &HostImportInfo,
    resource_type: ResourceTypeId,
    endpoint: StreamEndpoint,
) -> bool {
    let (function, parameter) = match endpoint {
        StreamEndpoint::Reader => (STREAM_CLOSE_READER_FUNCTION, "input"),
        StreamEndpoint::Writer => (STREAM_CLOSE_WRITER_FUNCTION, "output"),
    };
    import.interface == STREAM_INTERFACE
        && import.function == function
        && matches!(import.function_type.parameters.as_slice(), [resource, reason]
            if borrowed_parameter(resource, parameter, resource_type)
                && reason.name == "reason"
                && reason.value == ValueType::Enum(8))
        && import.function_type.result.is_none()
}

#[cfg(feature = "ssh-component-command")]
fn canonical_bytes(values: &[CanonicalValue]) -> Result<Vec<u8>, HostError> {
    if values.is_empty() || values.len() > MAX_STREAM_CHUNK_BYTES {
        return Err(HostError::InvalidArgument);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(values.len())
        .map_err(|_| HostError::Exhausted)?;
    for value in values {
        let CanonicalValue::U8(byte) = value else {
            return Err(HostError::InvalidArgument);
        };
        bytes.push(*byte);
    }
    Ok(bytes)
}

#[cfg(feature = "ssh-component-command")]
fn canonical_close_reason(value: &CanonicalValue) -> Result<StreamCloseReason, HostError> {
    let CanonicalValue::Enum(reason) = value else {
        return Err(HostError::InvalidArgument);
    };
    match reason {
        0 => Ok(StreamCloseReason::Normal),
        1 => Ok(StreamCloseReason::Failure),
        2 => Ok(StreamCloseReason::Cancelled),
        3 => Ok(StreamCloseReason::Denied),
        4 => Ok(StreamCloseReason::Unavailable),
        5 => Ok(StreamCloseReason::Exhausted),
        6 => Ok(StreamCloseReason::Invalid),
        7 => Ok(StreamCloseReason::BackendFault),
        _ => Err(HostError::InvalidArgument),
    }
}

#[cfg(feature = "ssh-component-command")]
fn stream_wake(words: [usize; 4]) {
    let outcome = registry().signal_continuation_words(words);
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::record_stream_wake(outcome);
    match outcome {
        crate::instance::InstanceContinuationSignal::Signalled
        | crate::instance::InstanceContinuationSignal::AlreadySignalled
        | crate::instance::InstanceContinuationSignal::AlreadyConsumed(_)
        | crate::instance::InstanceContinuationSignal::Stale => {}
        crate::instance::InstanceContinuationSignal::Quarantined => lifecycle_fail_stop(),
    }
}

#[cfg(feature = "ssh-component-command")]
impl RegistryStreamDispatcher {
    fn require_idle(&self) -> Result<(), HostError> {
        if self.pending.is_none() {
            Ok(())
        } else {
            lifecycle_fail_stop();
            Err(HostError::BackendFault)
        }
    }

    fn read_allocation() -> Result<Vec<HostPayloadAllocation>, HostError> {
        let mut allocations = Vec::new();
        allocations
            .try_reserve_exact(1)
            .map_err(|_| HostError::Exhausted)?;
        allocations.push(HostPayloadAllocation {
            size: MAX_STREAM_CHUNK_BYTES as u32,
            alignment: 1,
        });
        Ok(allocations)
    }

    fn prepared_read(
        &mut self,
        prepared: StreamPreparedReceive,
        mut allocations: Vec<HostPayloadAllocation>,
        previous: Option<PendingStreamOperation>,
    ) -> Result<HostDispatch, HostError> {
        let length = prepared.length();
        if length == 0 || length > MAX_STREAM_CHUNK_BYTES || allocations.len() != 1 {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        allocations[0].size = u32::try_from(length).map_err(|_| HostError::Exhausted)?;
        let operation = prepared.operation();
        match previous {
            Some(previous) => self.replace_pending(
                previous,
                operation,
                PendingStreamKind::ReadPrepared {
                    length: length as u16,
                },
            )?,
            None => self.install_pending(
                operation,
                PendingStreamKind::ReadPrepared {
                    length: length as u16,
                },
            )?,
        }
        Ok(HostDispatch::Prepared(HostPrepared::new(
            operation,
            allocations,
        )?))
    }

    fn ready_read_closed(&self, reason: StreamCloseReason) -> Result<HostDispatch, HostError> {
        if reason != StreamCloseReason::Normal {
            return Err(closed_stream_error(reason));
        }
        let response = HostResponse::reserve_one(STREAM_READ_WORK)?;
        let response = response.commit(CanonicalValue::List(Vec::new()))?;
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        acceptance::record_stream_eof(self.instance);
        Ok(HostDispatch::Ready(response))
    }

    fn start_read(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        self.require_idle()?;
        if !stream_read_shape(request.import(), self.reader_type)
            || !matches!(request.arguments(), [CanonicalValue::Resource(_)])
        {
            return Err(HostError::Denied);
        }
        let authority = self.borrow_authority(&request, StreamEndpoint::Reader)?;
        let allocations = Self::read_allocation()?;
        let dispatch = with_active_reader(self.instance, self.streams, |reader, supervisor| {
            promote_provisional_eof(supervisor)?;
            reader.start().map_err(map_stream_error)
        })??;
        match dispatch {
            StreamReceiveDispatch::Waiting(operation) => {
                self.install_pending(operation, PendingStreamKind::ReadWaiting)?;
                Ok(HostDispatch::Pending(operation))
            }
            StreamReceiveDispatch::Prepared(prepared) => {
                self.prepared_read(prepared, allocations, None)
            }
            StreamReceiveDispatch::Closed(reason) => self.ready_read_closed(reason),
        }
        .and_then(|dispatch| {
            if self.exact_authority(authority, StreamEndpoint::Reader) {
                Ok(dispatch)
            } else {
                lifecycle_fail_stop();
                Err(HostError::BackendFault)
            }
        })
    }

    fn start_write(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        self.require_idle()?;
        if !stream_write_shape(request.import(), self.writer_type) {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), CanonicalValue::List(values)] = request.arguments()
        else {
            return Err(HostError::Denied);
        };
        let authority = self.borrow_authority(&request, StreamEndpoint::Writer)?;
        let bytes = canonical_bytes(values)?;
        let dispatch = with_active_writer(self.instance, self.streams, |writer| {
            writer.start(&bytes).map_err(map_stream_error)
        })??;
        match dispatch {
            StreamSendDispatch::Sent => Ok(HostDispatch::Ready(HostResponse::unit(
                STREAM_WRITE_BASE_WORK + bytes.len() as u64,
            )?)),
            StreamSendDispatch::Waiting(operation) => {
                self.install_pending(operation, PendingStreamKind::WriteWaiting)?;
                Ok(HostDispatch::Pending(operation))
            }
            StreamSendDispatch::Closed(reason) => Err(closed_stream_error(reason)),
        }
        .and_then(|dispatch| {
            if self.exact_authority(authority, StreamEndpoint::Writer) {
                Ok(dispatch)
            } else {
                lifecycle_fail_stop();
                Err(HostError::BackendFault)
            }
        })
    }

    fn close_reader(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        self.require_idle()?;
        if !stream_close_shape(request.import(), self.reader_type, StreamEndpoint::Reader) {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), reason] = request.arguments() else {
            return Err(HostError::Denied);
        };
        let authority = self.borrow_authority(&request, StreamEndpoint::Reader)?;
        let reason = canonical_close_reason(reason)?;
        let response = HostResponse::unit(STREAM_CLOSE_WORK)?;
        with_active_reader(self.instance, self.streams, |reader, _| {
            checked_close(reader.close(reason))
        })??;
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        if reason == StreamCloseReason::Normal {
            acceptance::record_stream_normal_close(self.instance, true);
        }
        if !self.exact_authority(authority, StreamEndpoint::Reader) {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        Ok(HostDispatch::Ready(response))
    }

    fn close_writer(
        &mut self,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        self.require_idle()?;
        if !stream_close_shape(request.import(), self.writer_type, StreamEndpoint::Writer) {
            return Err(HostError::Denied);
        }
        let [CanonicalValue::Resource(_), reason] = request.arguments() else {
            return Err(HostError::Denied);
        };
        let authority = self.borrow_authority(&request, StreamEndpoint::Writer)?;
        let reason = canonical_close_reason(reason)?;
        let response = HostResponse::unit(STREAM_CLOSE_WORK)?;
        with_active_writer(self.instance, self.streams, |writer| {
            checked_close(writer.close(reason))
        })??;
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        if reason == StreamCloseReason::Normal {
            acceptance::record_stream_normal_close(self.instance, false);
        }
        if !self.exact_authority(authority, StreamEndpoint::Writer) {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        Ok(HostDispatch::Ready(response))
    }

    fn resume_read(
        &mut self,
        previous: PendingStreamOperation,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        if !stream_read_shape(request.import(), self.reader_type)
            || !matches!(request.arguments(), [CanonicalValue::Resource(_)])
        {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        let authority = self.borrow_authority(&request, StreamEndpoint::Reader)?;
        let allocations = Self::read_allocation()?;
        let dispatch = with_active_reader(self.instance, self.streams, |reader, supervisor| {
            promote_provisional_eof(supervisor)?;
            reader.resume(previous.token).map_err(map_stream_error)
        })??;
        match dispatch {
            StreamReceiveDispatch::Waiting(operation) => {
                self.replace_pending(previous, operation, PendingStreamKind::ReadWaiting)?;
                Ok(HostDispatch::Pending(operation))
            }
            StreamReceiveDispatch::Prepared(prepared) => {
                self.prepared_read(prepared, allocations, Some(previous))
            }
            StreamReceiveDispatch::Closed(reason) => {
                self.pending = None;
                self.ready_read_closed(reason)
            }
        }
        .and_then(|dispatch| {
            if self.exact_authority(authority, StreamEndpoint::Reader) {
                Ok(dispatch)
            } else {
                lifecycle_fail_stop();
                Err(HostError::BackendFault)
            }
        })
    }

    fn resume_write(
        &mut self,
        previous: PendingStreamOperation,
        request: HostRequest<'_, ComponentAuthority>,
    ) -> Result<HostDispatch, HostError> {
        if !stream_write_shape(request.import(), self.writer_type) {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        }
        let [CanonicalValue::Resource(_), CanonicalValue::List(values)] = request.arguments()
        else {
            lifecycle_fail_stop();
            return Err(HostError::BackendFault);
        };
        let authority = self.borrow_authority(&request, StreamEndpoint::Writer)?;
        let bytes = canonical_bytes(values)?;
        let dispatch = with_active_writer(self.instance, self.streams, |writer| {
            writer
                .resume(previous.token, &bytes)
                .map_err(map_stream_error)
        })??;
        match dispatch {
            StreamSendDispatch::Sent => {
                self.pending = None;
                #[cfg(feature = "wasm-c48-qemu-acceptance")]
                acceptance::record_stream_resume(self.instance, previous.token);
                Ok(HostDispatch::Ready(HostResponse::unit(
                    STREAM_WRITE_BASE_WORK + bytes.len() as u64,
                )?))
            }
            StreamSendDispatch::Waiting(operation) => {
                self.replace_pending(previous, operation, PendingStreamKind::WriteWaiting)?;
                Ok(HostDispatch::Pending(operation))
            }
            StreamSendDispatch::Closed(reason) => {
                self.pending = None;
                Err(closed_stream_error(reason))
            }
        }
        .and_then(|dispatch| {
            if self.exact_authority(authority, StreamEndpoint::Writer) {
                Ok(dispatch)
            } else {
                lifecycle_fail_stop();
                Err(HostError::BackendFault)
            }
        })
    }
}

#[cfg(feature = "ssh-component-command")]
async fn run_image_component(
    root: Option<&'static ImageRoot>,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    generation: u64,
    streams: RegistryStreamBindings,
    mode: PayloadMode,
) -> u64 {
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let _ = (key, task, domain);
    #[cfg(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    ))]
    if mode.is_native_async() {
        return native_async_acceptance::run(key, token, task, domain, streams).await;
    }
    let Some(root) = root else {
        lifecycle_fail_stop();
        return terminal_word(ComponentTerminal::BackendFault);
    };
    if !revalidate_image_root(root) {
        lifecycle_fail_stop();
        return terminal_word(ComponentTerminal::BackendFault);
    }
    let plan = match root.admitted.validated_plan() {
        Ok(plan) => plan,
        Err(_) => return terminal_word(ComponentTerminal::BackendFault),
    };
    let host_manifest = match VibeHostManifest::from_plan(&plan) {
        Ok(manifest) => manifest,
        Err(_) => return terminal_word(ComponentTerminal::BackendFault),
    };
    let Some((reader_type, writer_type)) = host_manifest.stream_resource_types() else {
        return terminal_word(ComponentTerminal::BackendFault);
    };
    // The engine is deliberately arena-owned. Sharing a static ProfileEngine
    // would let raw fault reclaim skip drops of wasmi Engine Arc clones and
    // monotonically inflate an external strong-reference count.
    let engine = ProfileEngine::new();
    let mut component = match SynchronousComponent::instantiate_with_memory_limit(
        &plan,
        &engine,
        OwnerAllocationReservation::new(root.manifest.memory_bytes()),
        root.manifest.memory_bytes(),
    ) {
        Ok(component) => component,
        Err(error) => return terminal_word(sync_error_terminal(error)),
    };
    if !runtime_signature_matches(
        &component,
        root.manifest.entrypoint(),
        reader_type,
        writer_type,
    ) {
        return terminal_word(ComponentTerminal::BackendFault);
    }
    let mut resources = match ResourceTable::<ComponentAuthority>::new(
        generation,
        root.manifest.resource_limit(),
    ) {
        Ok(resources) => resources,
        Err(_) => return terminal_word(ComponentTerminal::BudgetExceeded),
    };
    let reader =
        match resources.insert_owned(reader_type, ComponentAuthority::reader(token, streams)) {
            Ok(reader) => reader,
            Err(_) => return terminal_word(ComponentTerminal::BudgetExceeded),
        };
    let writer =
        match resources.insert_owned(writer_type, ComponentAuthority::writer(token, streams)) {
            Ok(writer) => writer,
            Err(_) => return terminal_word(ComponentTerminal::BudgetExceeded),
        };
    let mut dispatcher = RegistryStreamDispatcher::new(token, streams, reader_type, writer_type);
    let mut arguments = Vec::new();
    if arguments.try_reserve_exact(2).is_err() {
        return terminal_word(ComponentTerminal::BudgetExceeded);
    }
    arguments.push(CanonicalValue::Resource(reader));
    arguments.push(CanonicalValue::Resource(writer));
    let mut call = match component.start_typed_call_with_host(
        &mut resources,
        &mut dispatcher,
        root.manifest.entrypoint(),
        arguments,
        root.manifest.total_fuel(),
        root.manifest.poll_quantum(),
    ) {
        Ok(call) => call,
        Err(error) => return terminal_word(sync_error_terminal(error)),
    };
    let value = loop {
        match call.poll() {
            TypedPoll::Pending(_) => {
                let continuation = match registry().yield_continuation_current(token) {
                    Ok(continuation) => continuation,
                    Err(_) => {
                        lifecycle_fail_stop();
                        return terminal_word(ComponentTerminal::RunnerFault);
                    }
                };
                if continuation.await.is_err() {
                    lifecycle_fail_stop();
                    return terminal_word(ComponentTerminal::RunnerFault);
                }
            }
            TypedPoll::HostPending(operation) => {
                let continuation_token = match registry()
                    .arm_continuation_current(token, InstanceContinuationKind::External)
                {
                    Ok(continuation) => continuation,
                    Err(_) => {
                        lifecycle_fail_stop();
                        return terminal_word(ComponentTerminal::RunnerFault);
                    }
                };
                let continuation = match registry().wait_continuation(continuation_token) {
                    Ok(continuation) => continuation,
                    Err(_) => {
                        let _ = registry().quarantine(token);
                        lifecycle_fail_stop();
                        return terminal_word(ComponentTerminal::RunnerFault);
                    }
                };
                let wake = HostWakeToken::new(continuation_token.signal_words(), stream_wake);
                if let Err(error) = call.register_host_wake(operation, wake) {
                    drop(continuation);
                    if error != HostError::Denied {
                        lifecycle_fail_stop();
                    }
                    return terminal_word(host_error_terminal(error));
                }
                let consumed = continuation.await;
                if !consumed.is_ok_and(|consumed| consumed.matches_token(continuation_token)) {
                    lifecycle_fail_stop();
                    return terminal_word(ComponentTerminal::RunnerFault);
                }
                if call.resume_host(operation).is_err() {
                    lifecycle_fail_stop();
                    return terminal_word(ComponentTerminal::RunnerFault);
                }
            }
            TypedPoll::Ready(value) => break value,
            TypedPoll::HostFailed(error) => return terminal_word(host_error_terminal(error)),
            TypedPoll::Trapped(trap) => return terminal_word(trap_terminal(trap)),
        }
    };
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let PayloadMode::AcceptanceFault { round, hart } = mode {
        acceptance::fault_with_pending_continuation(token, round, hart).await;
        panic!("C5.2 continuation fault probe returned unexpectedly");
    }
    #[cfg(not(feature = "wasm-c48-qemu-acceptance"))]
    let _ = mode;
    drop(call);
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let PayloadMode::AcceptanceTerminalRace { terminal, .. } = mode {
        return terminal_word(terminal);
    }
    match value {
        CanonicalValue::Tuple(values) if values.is_empty() => {
            terminal_word(ComponentTerminal::Success)
        }
        _ => terminal_word(ComponentTerminal::BackendFault),
    }
}

#[cfg(feature = "ssh-component-command")]
fn runtime_signature_matches(
    component: &SynchronousComponent,
    entrypoint: &str,
    reader_type: ResourceTypeId,
    writer_type: ResourceTypeId,
) -> bool {
    let Some(function) = component.function_type(entrypoint) else {
        return false;
    };
    let [reader, writer] = function.parameters.as_slice() else {
        return false;
    };
    borrowed_parameter(reader, "input", reader_type)
        && borrowed_parameter(writer, "output", writer_type)
        && function.result.is_none()
}

#[cfg(feature = "ssh-component-command")]
const fn build_error_terminal(error: RunnerBuildError) -> ComponentTerminal {
    match error {
        RunnerBuildError::UnsupportedImports | RunnerBuildError::UnsupportedArguments => {
            ComponentTerminal::Denied
        }
        RunnerBuildError::Allocation => ComponentTerminal::BudgetExceeded,
        RunnerBuildError::Admission(
            vibeos_component_admission::AdmissionError::RuntimeUnavailable,
        ) => ComponentTerminal::Unavailable,
        RunnerBuildError::Admission(_)
        | RunnerBuildError::ManifestRejected
        | RunnerBuildError::ManifestMismatch
        | RunnerBuildError::UnsupportedStreams
        | RunnerBuildError::UnsupportedSignature
        | RunnerBuildError::UnsupportedRuntimeInstances => ComponentTerminal::BackendFault,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn sync_error_terminal(error: SyncError) -> ComponentTerminal {
    match error {
        SyncError::Allocation | SyncError::CoreAdmission | SyncError::InvalidBudget => {
            ComponentTerminal::BudgetExceeded
        }
        SyncError::AsyncUnavailable => ComponentTerminal::Unavailable,
        SyncError::CoreInstantiation
        | SyncError::MissingModule
        | SyncError::MissingExport
        | SyncError::InvalidWiring
        | SyncError::Memory
        | SyncError::Codec
        | SyncError::Busy
        | SyncError::Trapped
        | SyncError::Value
        | SyncError::Resource
        | SyncError::Poisoned => ComponentTerminal::BackendFault,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn host_error_terminal(error: HostError) -> ComponentTerminal {
    match error {
        HostError::Denied => ComponentTerminal::Denied,
        HostError::Unavailable => ComponentTerminal::Unavailable,
        HostError::Exhausted | HostError::BudgetExceeded => ComponentTerminal::BudgetExceeded,
        HostError::Failed => ComponentTerminal::Returned(1),
        HostError::Cancelled => ComponentTerminal::Cancelled,
        HostError::InvalidState => ComponentTerminal::Usage,
        HostError::InvalidArgument | HostError::BackendFault => ComponentTerminal::BackendFault,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn trap_terminal(trap: TrapCode) -> ComponentTerminal {
    match trap {
        TrapCode::Cancelled => ComponentTerminal::Cancelled,
        TrapCode::FuelExhausted | TrapCode::LimitExceeded => ComponentTerminal::BudgetExceeded,
        _ => ComponentTerminal::Trapped(ComponentTrapCode::new(trap as u16)),
    }
}

#[cfg(feature = "ssh-component-command")]
const fn terminal_word(terminal: ComponentTerminal) -> u64 {
    match terminal {
        ComponentTerminal::Success => 1 << 56,
        ComponentTerminal::Returned(code) => (2 << 56) | code as u64,
        ComponentTerminal::Usage => 3 << 56,
        ComponentTerminal::Denied => 4 << 56,
        ComponentTerminal::Unavailable => 5 << 56,
        ComponentTerminal::BackendFault => 6 << 56,
        ComponentTerminal::BudgetExceeded => 7 << 56,
        ComponentTerminal::Cancelled => 8 << 56,
        ComponentTerminal::RunnerFault => 9 << 56,
        ComponentTerminal::Trapped(code) => (10 << 56) | code.get() as u64,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn terminal_from_word(word: u64) -> ComponentTerminal {
    match word >> 56 {
        1 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Success,
        2 if word & 0x00ff_ffff_ffff_ff00 == 0 => ComponentTerminal::Returned((word & 0xff) as u8),
        3 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Usage,
        4 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Denied,
        5 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Unavailable,
        6 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::BackendFault,
        7 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::BudgetExceeded,
        8 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Cancelled,
        9 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::RunnerFault,
        10 if word & 0x00ff_ffff_ffff_0000 == 0 => {
            ComponentTerminal::Trapped(ComponentTrapCode::new((word & 0xffff) as u16))
        }
        _ => ComponentTerminal::RunnerFault,
    }
}

#[cfg(feature = "ssh-component-command")]
enum PayloadTerminalPublish {
    Published(ComponentTerminal),
    Busy,
    Failed,
}

#[cfg(feature = "ssh-component-command")]
fn publish_payload_terminal(
    key: ControlKey,
    token: InstanceToken,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> PayloadTerminalPublish {
    if !lifecycle_is_healthy() {
        return PayloadTerminalPublish::Failed;
    }

    // Reacquire the complete current-task registry proof and both exact endpoint
    // types before publishing any terminal candidate. Ordinary cap revocation
    // attenuates the candidate to Denied; seal/type/rights corruption fail-stops.
    let terminal = match with_active_reader(token, streams, |_, _| ()) {
        Ok(()) => match with_active_writer(token, streams, |_| ()) {
            Ok(()) => terminal,
            Err(HostError::Denied) => ComponentTerminal::Denied,
            Err(_) => return PayloadTerminalPublish::Failed,
        },
        Err(HostError::Denied) => ComponentTerminal::Denied,
        Err(_) => return PayloadTerminalPublish::Failed,
    };
    let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
        return PayloadTerminalPublish::Failed;
    };
    if witness.instance_token() != Some(token) {
        return PayloadTerminalPublish::Failed;
    }

    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return PayloadTerminalPublish::Busy,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            return PayloadTerminalPublish::Failed;
        }
    };
    if !lifecycle_is_healthy() {
        return PayloadTerminalPublish::Failed;
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let Some(record) = control.exact_mut(key) else {
        system.restore();
        return PayloadTerminalPublish::Failed;
    };
    let exact = record.phase == ControlPhase::Running
        && record.core_token == Some(token)
        && record.domain == Some(witness.allocation_domain())
        && record.streams == Some(streams)
        && record.supervisor.is_some()
        && record.handle.as_ref().is_some_and(|handle| {
            handle.allocation_domain() == witness.allocation_domain()
                && witness.matches_handle(handle)
        })
        && match (record.start_kind, record.cleanup) {
            (Some(ControlStartKind::ManagedSync), Some(cleanup)) => key
                .managed_token()
                .is_some_and(|managed| cleanup.is_active_for(managed)),
            #[cfg(feature = "ssh-native-async-command")]
            (Some(ControlStartKind::ManagedNativeAsync), Some(cleanup)) => key
                .managed_token()
                .is_some_and(|managed| cleanup.is_active_for(managed)),
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            (Some(ControlStartKind::Acceptance), None) => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            (Some(ControlStartKind::NativeAsyncAcceptance), None) => true,
            _ => false,
        };
    if !exact {
        record.quarantine();
        let _ = registry().quarantine(token);
        system.restore();
        return PayloadTerminalPublish::Failed;
    }
    if !matches!(
        fold_child_detach_reason_locked(record, key),
        Ok(ChildDetachFold::Clear)
    ) {
        record.quarantine();
        let _ = registry().quarantine(token);
        lifecycle_fail_stop();
        system.restore();
        return PayloadTerminalPublish::Failed;
    }
    let effective = match record.terminal_candidate {
        None => {
            record.terminal_candidate = Some(terminal);
            record.candidate_source = Some(TerminalCandidateSource::Payload);
            terminal
        }
        Some(existing) if record.candidate_source == Some(TerminalCandidateSource::Cooperative) => {
            existing
        }
        Some(existing) if existing == terminal => existing,
        Some(_) => {
            record.quarantine();
            let _ = registry().quarantine(token);
            system.restore();
            return PayloadTerminalPublish::Failed;
        }
    };
    system.restore();
    PayloadTerminalPublish::Published(effective)
}

#[cfg(feature = "ssh-component-command")]
fn managed_token_key(token: ManagedComponentToken) -> Option<ControlKey> {
    let raw = unsafe { token.trusted_raw() };
    ControlKey::decode(raw)
}

#[cfg(feature = "ssh-component-command")]
fn release_unpublished_domain(domain: AllocationDomain) -> bool {
    HEAP.close_empty_domain(domain).is_ok() && HEAP.unregister_owner(domain.owner).is_ok()
}

#[cfg(feature = "ssh-component-command")]
fn start_instance(
    cleanup: ManagedComponentStartLease,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    start_image_instance_with_input(
        StartPolicyGate::Sync,
        PayloadMode::CommandSync,
        ComponentStartInput::ManagedSync(cleanup),
    )
}

#[cfg(feature = "ssh-native-async-command")]
fn start_native_async_instance(
    cleanup: ManagedComponentStartLease,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    start_image_instance_with_input(
        StartPolicyGate::NativeAsync,
        PayloadMode::NativeAsyncCommand,
        ComponentStartInput::ManagedNativeAsync(cleanup),
    )
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
fn start_image_instance(mode: PayloadMode) -> Result<ManagedComponentToken, ComponentTerminal> {
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let stdin_writer = stdin.writer();
    if !matches!(
        stdin_writer.close(StreamCloseReason::Normal),
        StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
    ) {
        lifecycle_fail_stop();
        return Err(ComponentTerminal::RunnerFault);
    }
    start_image_instance_with_input(
        StartPolicyGate::None,
        mode,
        ComponentStartInput::Acceptance(Some(InstalledComponentIo {
            stdin: stdin.reader(),
            stdout: stdout.writer(),
            stdin_supervisor: stdin.supervisor(),
            stdout_supervisor: stdout.supervisor(),
        })),
    )
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
fn start_image_instance_with_io(
    mode: PayloadMode,
    io: InstalledComponentIo,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    start_image_instance_with_input(
        StartPolicyGate::None,
        mode,
        ComponentStartInput::Acceptance(Some(io)),
    )
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy)]
struct ResolvedImageStart {
    native_mode: bool,
    root: Option<&'static ImageRoot>,
    command_name: &'static str,
}

#[cfg(feature = "ssh-component-command")]
fn resolve_image_start(
    gate: StartPolicyGate,
    mode: PayloadMode,
    input: &ComponentStartInput,
) -> Result<ResolvedImageStart, ComponentTerminal> {
    if !start_route_exact(gate, mode, &input) {
        lifecycle_fail_stop();
        return Err(ComponentTerminal::RunnerFault);
    }
    if !lifecycle_is_healthy() || !gate.permits() {
        return Err(ComponentTerminal::Unavailable);
    }
    #[cfg(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    ))]
    let native_mode = mode.is_native_async();
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let native_mode = false;
    let root = if native_mode {
        #[cfg(any(
            feature = "wasm-c53-native-async-qemu-acceptance",
            feature = "ssh-native-async-command"
        ))]
        if !native_async_acceptance::root_ready() {
            native_async_acceptance::lifecycle_fail_stop();
            return Err(ComponentTerminal::Unavailable);
        }
        None
    } else {
        let Some(root) = image_root() else {
            lifecycle_fail_stop();
            return Err(ComponentTerminal::Unavailable);
        };
        Some(root)
    };
    let command_name = if native_mode {
        #[cfg(any(
            feature = "wasm-c53-native-async-qemu-acceptance",
            feature = "ssh-native-async-command"
        ))]
        {
            native_async_acceptance::command_name()
        }
        #[cfg(not(any(
            feature = "wasm-c53-native-async-qemu-acceptance",
            feature = "ssh-native-async-command"
        )))]
        unreachable!()
    } else {
        SSH_EXEC_COMPONENT.command_name()
    };
    Ok(ResolvedImageStart {
        native_mode,
        root,
        command_name,
    })
}

#[cfg(feature = "ssh-component-command")]
fn start_image_instance_with_input(
    gate: StartPolicyGate,
    mode: PayloadMode,
    input: ComponentStartInput,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    let resolved = match resolve_image_start(gate, mode, &input) {
        Ok(resolved) => resolved,
        Err(terminal) => return Err(input.abort_unpublished(terminal)),
    };
    let control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => {
            return Err(input.abort_unpublished(ComponentTerminal::Unavailable));
        }
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return Err(input.abort_unpublished(ComponentTerminal::RunnerFault));
        }
    };
    start_image_instance_under_control(gate, mode, input, resolved, control)
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
fn start_image_instance_with_io_under_control(
    control: ControlGuard<'_>,
    mode: PayloadMode,
    io: InstalledComponentIo,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    let input = ComponentStartInput::Acceptance(Some(io));
    let resolved = match resolve_image_start(StartPolicyGate::None, mode, &input) {
        Ok(resolved) => resolved,
        Err(terminal) => {
            drop(control);
            return Err(input.abort_unpublished(terminal));
        }
    };
    start_image_instance_under_control(StartPolicyGate::None, mode, input, resolved, control)
}

#[cfg(feature = "ssh-component-command")]
fn start_image_instance_under_control(
    gate: StartPolicyGate,
    mode: PayloadMode,
    mut input: ComponentStartInput,
    resolved: ResolvedImageStart,
    mut control: ControlGuard<'_>,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    let ResolvedImageStart {
        native_mode,
        root,
        command_name,
    } = resolved;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy() || !gate.permits() || !start_route_exact(gate, mode, &input) {
        system.restore();
        drop(control);
        return Err(input.abort_unpublished(ComponentTerminal::Unavailable));
    }
    if root.is_some_and(|root| !revalidate_image_root(root))
        || (native_mode && {
            #[cfg(any(
                feature = "wasm-c53-native-async-qemu-acceptance",
                feature = "ssh-native-async-command"
            ))]
            {
                !native_async_acceptance::root_ready()
            }
            #[cfg(not(any(
                feature = "wasm-c53-native-async-qemu-acceptance",
                feature = "ssh-native-async-command"
            )))]
            {
                true
            }
        })
    {
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        return Err(input.abort_unpublished(ComponentTerminal::BackendFault));
    }
    let Some(key) = control.reserve(&CONTROL) else {
        system.restore();
        drop(control);
        return Err(input.abort_unpublished(ComponentTerminal::Unavailable));
    };
    let Some(raw) = key.encode() else {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        return Err(input.abort_unpublished(ComponentTerminal::RunnerFault));
    };
    let managed_token = unsafe { ManagedComponentToken::from_trusted_raw(raw) };

    let owner = match HEAP.create_owner(INSTANCE_HEAP_QUOTA) {
        Ok(owner) => owner,
        Err(_) => {
            control
                .exact_mut(key)
                .expect("reserved control slot exists")
                .phase = ControlPhase::Vacant;
            system.restore();
            drop(control);
            return Err(input.abort_unpublished(ComponentTerminal::BudgetExceeded));
        }
    };
    let arena = match HEAP.create_arena(owner) {
        Ok(arena) => arena,
        Err(_) => {
            let record = control
                .exact_mut(key)
                .expect("reserved control slot exists");
            if HEAP.unregister_owner(owner).is_ok() {
                record.phase = ControlPhase::Vacant;
            } else {
                record.quarantine();
                lifecycle_fail_stop();
            }
            system.restore();
            drop(control);
            return Err(input.abort_unpublished(ComponentTerminal::BudgetExceeded));
        }
    };
    let domain = AllocationDomain::new(owner, arena);
    let core_token = match registry().reserve_named(domain, command_name) {
        Ok(token) => token,
        Err(error) => {
            let record = control
                .exact_mut(key)
                .expect("reserved control slot exists");
            if error == ReserveError::Capacity && release_unpublished_domain(domain) {
                record.phase = ControlPhase::Vacant;
            } else {
                // Identity failures may mean this domain aliases a retained
                // stable projection. Do not close or retire ambiguous state.
                record.quarantine();
                lifecycle_fail_stop();
            }
            system.restore();
            drop(control);
            return Err(input.abort_unpublished(ComponentTerminal::Unavailable));
        }
    };

    // Prepare both futures and all of their cleanup-ledger capacity while the
    // VSH reaper still owns the unpublished endpoint envelope. Neither future
    // is scheduler-visible and both capture copy-only keys.
    let child = ManagedChildFuture {
        token: core_token,
        control: key,
    };
    let mut batch = PreparedTaskBatch::new();
    unsafe {
        batch.prepare_managed_instance_owned(core_token, domain, command_name, child);
    }
    batch.prepare("wasm-instance-supervisor", supervise_instance(key));
    if !batch.try_reserve_prepared_task_registrations(0, 2)
        || !batch.try_reserve_prepared_task_registrations(1, 2)
    {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        let _ = registry().quarantine(core_token);
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        return Err(input.abort_unpublished(ComponentTerminal::RunnerFault));
    }
    let prepared_child = batch
        .prepared_handles()
        .first()
        .expect("managed batch contains one child")
        .clone();
    let prepared_supervisor = batch
        .prepared_handles()
        .get(1)
        .expect("managed batch contains one supervisor")
        .clone();
    let binding = *batch
        .prepared_reclaimable_bindings()
        .first()
        .expect("managed batch contains one reclaimable binding");
    {
        let record = control
            .exact_mut(key)
            .expect("reserved control slot exists");
        record.core_token = Some(core_token);
        record.handle = Some(prepared_child.clone());
        record.supervisor = Some(prepared_supervisor.clone());
        record.domain = Some(domain);
        record.cleanup = input.cleanup();
        record.start_kind = Some(input.kind());
    }

    if !input.bind(managed_token)
        || input
            .cleanup()
            .is_some_and(|cleanup| !CONTROL.install_cleanup_shadow(key, cleanup))
    {
        control
            .exact_mut(key)
            .expect("prepared control slot exists")
            .quarantine();
        let _ = registry().quarantine(core_token);
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    }
    let Some(io) = input.take_bound_io(managed_token) else {
        control
            .exact_mut(key)
            .expect("bound control slot exists")
            .quarantine();
        let _ = registry().quarantine(core_token);
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    };
    if io.stdin.same_stream_as(&io.stdout)
        || Arc::ptr_eq(&io.stdin_supervisor, &io.stdout_supervisor)
        || !io.stdin_supervisor.same_stream_as_reader(&io.stdin)
        || io.stdin_supervisor.same_stream_as_writer(&io.stdout)
        || !io.stdout_supervisor.same_stream_as_writer(&io.stdout)
        || io.stdout_supervisor.same_stream_as_reader(&io.stdin)
    {
        control
            .exact_mut(key)
            .expect("bound control slot exists")
            .quarantine();
        let _ = registry().quarantine(core_token);
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    }
    let streams = match unsafe {
        registry().configure_reserved_space(core_token, move |cspace| {
            let cspace_identity = cspace.identity();
            let cspace_incarnation = cspace.incarnation();
            let stdin = cspace.mint(io.stdin, Rights::RECV);
            let stdout = cspace.mint(io.stdout, Rights::SEND);
            let stdin_supervisor = cspace.mint(io.stdin_supervisor, Rights::INVOKE);
            let stdout_supervisor = cspace.mint(io.stdout_supervisor, Rights::INVOKE);
            RegistryStreamBindings {
                cspace_identity,
                cspace_incarnation,
                stdin,
                stdout,
                stdin_supervisor,
                stdout_supervisor,
            }
        })
    } {
        Ok(streams) => streams,
        Err(_) => {
            control
                .exact_mut(key)
                .expect("reserved control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            drop(control);
            input.quarantine_partial();
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    {
        let record = control
            .exact_mut(key)
            .expect("configured control slot exists");
        if record.phase != ControlPhase::Starting
            || record.core_token != Some(core_token)
            || record.domain != Some(domain)
            || record.streams.is_some()
            || record.terminal_candidate.is_some()
            || record.candidate_source.is_some()
            || record.handle.as_ref().is_none_or(|handle| {
                handle.id() != prepared_child.id() || !handle.shares_status_with(&prepared_child)
            })
            || record.supervisor.as_ref().is_none_or(|handle| {
                handle.id() != prepared_supervisor.id()
                    || !handle.shares_status_with(&prepared_supervisor)
            })
        {
            record.quarantine();
            let _ = registry().quarantine(core_token);
            lifecycle_fail_stop();
            system.restore();
            drop(control);
            input.quarantine_partial();
            return Err(ComponentTerminal::RunnerFault);
        }
        record.streams = Some(streams);
    }
    if unsafe {
        registry().install_payload(core_token, || {
            LazyComponentPayload::new(
                root,
                key,
                core_token,
                prepared_child.id(),
                domain,
                key.generation,
                streams,
                mode,
            )
        })
    }
    .is_err()
    {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    }

    if registry()
        .bind(core_token, binding, &prepared_child)
        .is_err()
    {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    }
    let Some(child_target) = child_detach_target(key) else {
        unreachable!("encoded control key already validated")
    };
    let Some(supervisor_target) = supervisor_detach_target(key) else {
        unreachable!("encoded control key already validated")
    };
    let shadows_installed = CONTROL.child_shadow[key.slot as usize].install(key, &prepared_child)
        && CONTROL.supervisor_shadow[key.slot as usize].install(key, &prepared_supervisor);
    if !shadows_installed
        || !batch.install_prepared_task_detach(0, child_target)
        || !batch.install_prepared_task_detach(1, supervisor_target)
    {
        control
            .exact_mut(key)
            .expect("bound control slot exists")
            .quarantine();
        CONTROL.child_shadow[key.slot as usize].quarantine(key);
        CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
        let _ = registry().quarantine(core_token);
        lifecycle_fail_stop();
        system.restore();
        drop(control);
        input.quarantine_partial();
        return Err(ComponentTerminal::RunnerFault);
    }

    let cleanup = input.cleanup();
    let start_kind = input.kind();
    system.restore();
    let suspended = match control.suspend_for_scheduler(key, cleanup) {
        Ok(suspended) => suspended,
        Err(_) => {
            input.quarantine_partial();
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    // Bind the SYSTEM pending shadow while CONTROL is released and before the
    // prepared child can become scheduler-visible. Thus a zero-operation
    // completion, pre-first-poll cancellation, or pre-first-poll fault all
    // resolve the exact generation as snapshot(None), while no CONTROL ->
    // shadow lock edge is introduced.
    #[cfg(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    ))]
    let pending_shadow_bound = !start_kind.is_native_async()
        || native_async_acceptance::bind_pending_shadow(
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let pending_shadow_bound = true;
    if !pending_shadow_bound {
        if let Ok(mut control) = suspended.resume() {
            let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            system.restore();
            drop(control);
        }
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        return Err(ComponentTerminal::RunnerFault);
    }
    // SCHED may invoke only the fixed registry activation transaction.
    let staged = unsafe {
        batch.stage_exclusive_reclaimable_with(|bindings| registry().activate_batch(bindings))
    };
    let mut control = match suspended.resume() {
        Ok(control) => control,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let stage = match staged {
        Ok(stage) => stage,
        Err(_) => {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            system.restore();
            drop(control);
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    if !control.exact(key).is_some_and(|record| {
        control_start_projection_exact(
            record,
            core_token,
            domain,
            streams,
            &prepared_child,
            &prepared_supervisor,
            cleanup,
            start_kind,
        )
    }) || !lifecycle_is_healthy()
    {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        system.restore();
        drop(control);
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        drop(stage);
        return Err(ComponentTerminal::RunnerFault);
    }

    // Query the Bound VSH record without holding CONTROL, then linearize the
    // per-generation publication permit only after an exact resume/recheck.
    system.restore();
    let suspended = match control.suspend_for_scheduler(key, cleanup) {
        Ok(suspended) => suspended,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            drop(stage);
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let cleanup_bound = cleanup.is_none_or(|cleanup| cleanup.is_bound_for(managed_token));
    let mut control = match suspended.resume() {
        Ok(control) => control,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            drop(stage);
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let commit_exact = cleanup_bound
        && control.exact(key).is_some_and(|record| {
            control_start_projection_exact(
                record,
                core_token,
                domain,
                streams,
                &prepared_child,
                &prepared_supervisor,
                cleanup,
                start_kind,
            )
        });
    if !commit_exact || !lifecycle_is_healthy() || !CONTROL.commit_publication(key) {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        system.restore();
        drop(control);
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        drop(stage);
        return Err(ComponentTerminal::RunnerFault);
    }
    #[cfg(feature = "ssh-native-async-qemu-acceptance")]
    if start_kind == ControlStartKind::ManagedNativeAsync
        && !native_async_acceptance::target_record_managed_start(
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
            managed_token,
        )
    {
        control
            .exact_mut(key)
            .expect("target-audited control slot exists")
            .quarantine();
        system.restore();
        drop(control);
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        drop(stage);
        return Err(ComponentTerminal::RunnerFault);
    }

    // First make both token-only futures scheduler-visible. Their fixed task
    // shadows remain Prepared, so ManagedChildFuture parks without polling the
    // registry payload and the supervisor can only install its child-exit
    // listener. This removes any Active-reaper/unpublished-child window.
    let (permit, expected) = CONTROL
        .publication_permit(key)
        .expect("reserved control slot has a publication permit");
    system.restore();
    let suspended = match control.suspend_for_scheduler(key, cleanup) {
        Ok(suspended) => suspended,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            drop(stage);
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let ready = unsafe { stage.publish_ready_if(permit, expected) };
    let mut control = match suspended.resume() {
        Ok(control) => control,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let handles = match ready {
        Ok(handles) => handles,
        Err(stage) => {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            system.restore();
            drop(control);
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            drop(stage);
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    if handles.len() != 2
        || !handles[0].is_published()
        || handles[0].id() != prepared_child.id()
        || !handles[0].shares_status_with(&prepared_child)
        || !handles[1].is_published()
        || handles[1].id() != prepared_supervisor.id()
        || !handles[1].shares_status_with(&prepared_supervisor)
        || !control.exact(key).is_some_and(|record| {
            control_start_projection_exact(
                record,
                core_token,
                domain,
                streams,
                &handles[0],
                &handles[1],
                cleanup,
                start_kind,
            )
        })
        || !lifecycle_is_healthy()
    {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        system.restore();
        drop(control);
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        return Err(ComponentTerminal::RunnerFault);
    }

    // The tasks are scheduler-visible but the child still observes Prepared
    // and therefore cannot touch the registry payload. Seal CONTROL while the
    // fixed VSH and task-shadow projections become Active/Running; their wakes
    // remain undispatched until the exact table projection is committed.
    system.restore();
    let suspended = match control.suspend_for_scheduler(key, cleanup) {
        Ok(suspended) => suspended,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let activate_allowed = lifecycle_is_healthy();
    let cleanup_active =
        activate_allowed && cleanup.is_none_or(|cleanup| CONTROL.mark_cleanup_active(key, cleanup));
    let reaper_wake = match cleanup {
        Some(cleanup) if cleanup_active => cleanup.commit_child_publication(managed_token),
        Some(_) | None => None,
    };
    let child_running = activate_allowed
        && CONTROL.child_shadow[key.slot as usize].transition(
            key,
            TASK_SHADOW_PREPARED,
            TASK_SHADOW_RUNNING,
        );
    let supervisor_running = activate_allowed
        && CONTROL.supervisor_shadow[key.slot as usize].transition(
            key,
            TASK_SHADOW_PREPARED,
            TASK_SHADOW_RUNNING,
        );
    let mut control = match suspended.resume() {
        Ok(control) => control,
        Err(_) => {
            quarantine_committed_start(
                &input,
                key,
                core_token,
                prepared_child.id(),
                domain,
                streams,
            );
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let activation_exact = cleanup_active
        && (cleanup.is_none() || reaper_wake.is_some())
        && child_running
        && supervisor_running
        && lifecycle_is_healthy()
        && control.exact(key).is_some_and(|record| {
            control_start_projection_exact(
                record,
                core_token,
                domain,
                streams,
                &handles[0],
                &handles[1],
                cleanup,
                start_kind,
            )
        });
    if !activation_exact {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        system.restore();
        drop(control);
        quarantine_committed_start(
            &input,
            key,
            core_token,
            prepared_child.id(),
            domain,
            streams,
        );
        return Err(ComponentTerminal::RunnerFault);
    }
    control
        .exact_mut(key)
        .expect("published start projection remains exact")
        .phase = ControlPhase::Running;
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let PayloadMode::AcceptanceFault { round, hart } = mode {
        let record = control
            .exact(key)
            .expect("acceptance running control slot exists");
        let accepted = record.handle.as_ref().is_some_and(|handle| {
            acceptance::arm_positive(key, core_token, handle, domain, round, hart)
        });
        if !accepted {
            let _ = registry().quarantine(core_token);
            control
                .exact_mut(key)
                .expect("acceptance running control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            drop(control);
            input.quarantine_partial();
            return Err(ComponentTerminal::RunnerFault);
        }
    }
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let PayloadMode::AcceptanceStream { round, hart } = mode {
        let record = control
            .exact(key)
            .expect("stream acceptance running control slot exists");
        let accepted = record.handle.as_ref().is_some_and(|handle| {
            acceptance::arm_stream(key, core_token, handle, domain, round, hart)
        });
        if !accepted {
            let _ = registry().quarantine(core_token);
            control
                .exact_mut(key)
                .expect("stream acceptance running control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            drop(control);
            input.quarantine_partial();
            return Err(ComponentTerminal::RunnerFault);
        }
    }
    system.restore();
    drop(control);
    // These exact task identities were validated again after ready
    // publication and before CONTROL became Running. Close the intentional
    // Prepared park without exposing an owning TaskHandle to either future.
    if let Some(wake) = CONTROL.child_shadow[key.slot as usize].exact_wake(key) {
        let _ = wake.wake_if_exact();
    }
    if let Some(wake) = CONTROL.supervisor_shadow[key.slot as usize].exact_wake(key) {
        let _ = wake.wake_if_exact();
    }
    if let Some(wake) = reaper_wake {
        wake.dispatch();
    }
    Ok(managed_token)
}

#[cfg(feature = "ssh-component-command")]
async fn supervise_instance(key: ControlKey) {
    let Some(child_exit) = CONTROL.child_exit(key) else {
        lifecycle_fail_stop();
        return;
    };
    if child_exit.wait(key.generation).await.is_err() {
        lifecycle_fail_stop();
        if let Some(target) = supervisor_detach_target(key) {
            let _ = crate::exec::disarm_current_task_detach(target);
        }
        return;
    }
    loop {
        match finalize_instance(key) {
            FinalizeControl::Complete | FinalizeControl::Lost => return,
            FinalizeControl::Busy => crate::exec::yield_now().await,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalizeControl {
    Complete,
    Busy,
    Lost,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalProof {
    Busy,
    Exact {
        terminal: ComponentTerminal,
        completion: Option<u64>,
        derived_from_fault_reclaim: bool,
    },
    Lost,
}

/// Isolate every copy-only projection which can still be reached without
/// CONTROL. This helper never publishes a terminal, retires an owner, takes or
/// drops the registry payload, or resets Space/CSpace. The exact CONTROL slot
/// is quarantined separately whenever its guard remains available.
#[cfg(feature = "ssh-component-command")]
fn quarantine_terminal_tuple(key: ControlKey, tuple: &ControlTuple) {
    CONTROL.child_shadow[key.slot as usize].quarantine(key);
    CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
    let _ = registry().quarantine(tuple.core_token);
    lifecycle_fail_stop();
}

/// Build terminal authority while CONTROL is sealed in a
/// [`ControlPublicationLease`]. TaskDetach is only a wake/reason projection:
/// the sole candidate-less fault authority is the exact immutable triple
/// TaskState::Faulted + registry FaultReclaimed + completion(None).
#[cfg(feature = "ssh-component-command")]
fn prove_terminal_outside_control(
    key: ControlKey,
    tuple: &ControlTuple,
    state: TaskState,
) -> TerminalProof {
    let cleanup_active = match (tuple.start_kind, tuple.cleanup) {
        (ControlStartKind::ManagedSync, Some(cleanup)) => key
            .managed_token()
            .is_some_and(|token| cleanup.is_active_for(token)),
        #[cfg(feature = "ssh-native-async-command")]
        (ControlStartKind::ManagedNativeAsync, Some(cleanup)) => key
            .managed_token()
            .is_some_and(|token| cleanup.is_active_for(token)),
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        (ControlStartKind::Acceptance, None) => true,
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        (ControlStartKind::NativeAsyncAcceptance, None) => true,
        _ => false,
    };
    if !cleanup_active || !lifecycle_is_healthy() {
        quarantine_terminal_tuple(key, tuple);
        return TerminalProof::Lost;
    }
    let snapshot = match registry().observe_structural(tuple.core_token, &tuple.handle) {
        Ok(snapshot)
            if snapshot.domain == tuple.domain && snapshot.task == Some(tuple.handle.id()) =>
        {
            snapshot
        }
        Ok(_) | Err(_) => {
            quarantine_terminal_tuple(key, tuple);
            return TerminalProof::Lost;
        }
    };
    let completion = || registry().observe_terminal_completion(tuple.core_token, &tuple.handle);
    let proof = match state {
        TaskState::Exited => match (tuple.terminal_candidate, completion()) {
            (Some(terminal), Ok(Some(word))) if word == terminal_word(terminal) => {
                TerminalProof::Exact {
                    terminal,
                    completion: Some(word),
                    derived_from_fault_reclaim: false,
                }
            }
            (_, Err(RegistryError::TaskNotTerminal)) => TerminalProof::Busy,
            _ => TerminalProof::Lost,
        },
        TaskState::Faulted if snapshot.phase == InstancePhase::FaultReclaiming => {
            TerminalProof::Busy
        }
        TaskState::Faulted if snapshot.phase == InstancePhase::FaultReclaimed => {
            match (tuple.terminal_candidate, completion()) {
                (Some(terminal), Ok(None)) => TerminalProof::Exact {
                    terminal,
                    completion: None,
                    derived_from_fault_reclaim: false,
                },
                (Some(terminal), Ok(Some(word))) if word == terminal_word(terminal) => {
                    TerminalProof::Exact {
                        terminal,
                        completion: Some(word),
                        derived_from_fault_reclaim: false,
                    }
                }
                (None, Ok(None)) => TerminalProof::Exact {
                    terminal: ComponentTerminal::RunnerFault,
                    completion: None,
                    derived_from_fault_reclaim: true,
                },
                (_, Err(RegistryError::TaskNotTerminal)) => TerminalProof::Busy,
                _ => TerminalProof::Lost,
            }
        }
        // An executor-cancelled installed payload has no immutable registry
        // terminal authority. In particular, completion(None) is not a reason
        // to close streams or reset Space. Preserve every object in place.
        TaskState::Cancelled | TaskState::Faulted | TaskState::Running => TerminalProof::Lost,
    };
    if proof == TerminalProof::Lost {
        quarantine_terminal_tuple(key, tuple);
    }
    proof
}

#[cfg(feature = "ssh-component-command")]
fn control_tuple_is_structurally_exact(tuple: &ControlTuple) -> bool {
    let observed = registry().observe_structural(tuple.core_token, &tuple.handle);
    let exact = observed.as_ref().is_ok_and(|snapshot| {
        snapshot.domain == tuple.domain
            && snapshot.task == Some(tuple.handle.id())
            && matches!(
                snapshot.phase,
                InstancePhase::Active
                    | InstancePhase::PayloadDropping
                    | InstancePhase::PayloadDropped
                    | InstancePhase::FaultReclaiming
                    | InstancePhase::FaultReclaimed
                    | InstancePhase::FaultRetiring
                    | InstancePhase::FaultTerminal
                    | InstancePhase::NormalClosing
                    | InstancePhase::NormalTerminal
            )
    });
    if !exact && observed.is_ok() {
        let _ = registry().quarantine(tuple.core_token);
    }
    exact
}

#[cfg(feature = "ssh-component-command")]
fn finalize_stream_state(
    space: &InstanceSpace,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let (stdin, stdout, stdin_supervisor, stdout_supervisor) = {
        let cspace = space.cspace().lock();
        if validate_stream_space(&cspace, streams).is_err() {
            return false;
        }
        let Ok(stdin) = exact_lease::<ByteStreamReader>(&cspace, streams.stdin, Rights::RECV)
        else {
            return false;
        };
        let Ok(stdout) = exact_lease::<ByteStreamWriter>(&cspace, streams.stdout, Rights::SEND)
        else {
            return false;
        };
        let Ok(stdin_supervisor) =
            exact_lease::<ByteStreamSupervisor>(&cspace, streams.stdin_supervisor, Rights::INVOKE)
        else {
            return false;
        };
        let Ok(stdout_supervisor) =
            exact_lease::<ByteStreamSupervisor>(&cspace, streams.stdout_supervisor, Rights::INVOKE)
        else {
            return false;
        };
        (stdin, stdout, stdin_supervisor, stdout_supervisor)
    };

    // Keep both endpoint leases alive through terminal publication. They are
    // not used for close authority, but prove exact type/rights in the same
    // CSpace incarnation immediately before the supervisor actions.
    let _ = stdin.with(|_| ());
    let _ = stdout.with(|_| ());
    let reason = terminal.stream_close_reason();
    let published = stdout_supervisor.with(|supervisor| {
        if supervisor.is_fail_stopped() {
            return false;
        }
        // A guest-side close may legitimately precede the async invocation
        // result. Publish only if still open; otherwise atomically preserve
        // and observe the immutable first winner without a TOCTOU conflict.
        let stdout_observed = supervisor.finalize_preserving_first_observed(reason);
        if !matches!(
            stdout_observed.outcome(),
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
        ) || stdout_observed.effective_reason().is_none()
            || supervisor.is_fail_stopped()
        {
            return false;
        }

        let stdin_published = stdin_supervisor.with(|stdin| {
            if stdin.is_fail_stopped() {
                return false;
            }
            // Input is source-owned. The same atomic operation preserves an
            // established EOF/failure or closes the still-open/provisional
            // source with the component terminal reason.
            let stdin_observed = stdin.finalize_preserving_first_observed(reason);
            matches!(
                stdin_observed.outcome(),
                StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
            ) && !stdin.is_fail_stopped()
                && stdin_observed.effective_reason().is_some()
        });
        stdin_published && !supervisor.is_fail_stopped()
    });
    published
}

#[cfg(any(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
fn finalize_stream_state_from_supervisors(
    space: &InstanceSpace,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    let (stdin_supervisor, stdout_supervisor) = {
        let cspace = space.cspace().lock();
        if validate_stream_space(&cspace, streams).is_err() {
            return false;
        }
        let Ok(stdin_supervisor) =
            exact_lease::<ByteStreamSupervisor>(&cspace, streams.stdin_supervisor, Rights::INVOKE)
        else {
            return false;
        };
        let Ok(stdout_supervisor) =
            exact_lease::<ByteStreamSupervisor>(&cspace, streams.stdout_supervisor, Rights::INVOKE)
        else {
            return false;
        };
        (stdin_supervisor, stdout_supervisor)
    };

    // Native finalization reaches this helper only after the exact pending
    // ledger has resolved backend operations and any required endpoint
    // revocation. The two supervisor caps retain terminal authority
    // independently of revoked endpoint caps, while the Space
    // identity/incarnation proof above prevents a stale binding from publishing
    // into a replacement CSpace.
    let reason = terminal.stream_close_reason();
    stdout_supervisor.with(|supervisor| {
        if supervisor.is_fail_stopped() {
            return false;
        }
        let stdout_observed = supervisor.finalize_preserving_first_observed(reason);
        if !matches!(
            stdout_observed.outcome(),
            StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
        ) || stdout_observed.effective_reason().is_none()
            || supervisor.is_fail_stopped()
        {
            return false;
        }

        let stdin_published = stdin_supervisor.with(|stdin| {
            if stdin.is_fail_stopped() {
                return false;
            }
            let stdin_observed = stdin.finalize_preserving_first_observed(reason);
            matches!(
                stdin_observed.outcome(),
                StreamCloseOutcome::Published | StreamCloseOutcome::AlreadyPublished
            ) && !stdin.is_fail_stopped()
                && stdin_observed.effective_reason().is_some()
        });
        stdin_published && !supervisor.is_fail_stopped()
    })
}

#[cfg(any(
    feature = "wasm-c53-native-async-qemu-acceptance",
    feature = "ssh-native-async-command"
))]
fn finalize_native_stream_state(
    space: &InstanceSpace,
    key: ControlKey,
    token: InstanceToken,
    task: TaskId,
    domain: AllocationDomain,
    streams: RegistryStreamBindings,
    terminal: ComponentTerminal,
) -> bool {
    if !native_async_acceptance::prepare_terminal_shadow(
        space, key, token, task, domain, streams, terminal,
    ) {
        return false;
    }
    if !finalize_stream_state_from_supervisors(space, streams, terminal) {
        return false;
    }
    native_async_acceptance::retire_terminal_shadow(key, token, task, domain, streams)
}

#[cfg(feature = "ssh-component-command")]
unsafe fn finalize_registry_terminal(
    key: ControlKey,
    tuple: &ControlTuple,
    terminal: ComponentTerminal,
    completion: Option<u64>,
) -> Result<FinalizeOutcome, RegistryError> {
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let _ = key;
    unsafe {
        registry().finalize_with_space_expect_completion(
            tuple.core_token,
            &tuple.handle,
            completion,
            |space, _| {
                #[cfg(any(
                    feature = "wasm-c53-native-async-qemu-acceptance",
                    feature = "ssh-native-async-command"
                ))]
                let published = if tuple.start_kind.is_native_async() {
                    finalize_native_stream_state(
                        space,
                        key,
                        tuple.core_token,
                        tuple.handle.id(),
                        tuple.domain,
                        tuple.streams,
                        terminal,
                    )
                } else {
                    finalize_stream_state(space, tuple.streams, terminal)
                };
                #[cfg(not(any(
                    feature = "wasm-c53-native-async-qemu-acceptance",
                    feature = "ssh-native-async-command"
                )))]
                let published = finalize_stream_state(space, tuple.streams, terminal);
                #[cfg(feature = "wasm-c48-qemu-acceptance")]
                if published {
                    acceptance::record_stream_terminal_published(
                        tuple.handle.id(),
                        tuple.domain,
                        terminal,
                        terminal.stream_close_reason(),
                    );
                }
                published
            },
            |domain, kind| {
                let retired = match kind {
                    TerminalRetireKind::Normal => {
                        HEAP.close_empty_domain(domain).is_ok()
                            && HEAP.unregister_owner(domain.owner).is_ok()
                    }
                    TerminalRetireKind::FaultReclaimed => {
                        HEAP.unregister_owner(domain.owner).is_ok()
                    }
                };
                #[cfg(feature = "wasm-c48-qemu-acceptance")]
                acceptance::record_owner_retired(tuple.handle.id(), domain, kind, retired);
                retired
            },
        )
    }
}

#[cfg(feature = "ssh-component-command")]
fn finalize_instance(key: ControlKey) -> FinalizeControl {
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return FinalizeControl::Busy,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return FinalizeControl::Lost;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy() {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        system.restore();
        return FinalizeControl::Lost;
    }
    let tuple = match control.running_tuple_structural(key) {
        Ok(Some(tuple)) => tuple,
        Ok(None) => {
            system.restore();
            return FinalizeControl::Lost;
        }
        Err(()) => {
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    let state = match tuple.handle.try_exit().map(|exit| exit.state()) {
        None | Some(TaskState::Running) => {
            // TaskDetach publishes its fixed edge before TaskStatus and raw
            // fault reclamation become terminal. Retry without quarantining.
            system.restore();
            return FinalizeControl::Busy;
        }
        Some(state) => state,
    };
    let folded = control
        .exact(key)
        .map(|record| fold_child_detach_reason_locked(record, key));
    if !matches!(
        (state, folded),
        (TaskState::Exited, Some(Ok(ChildDetachFold::Clear)))
            | (TaskState::Faulted, Some(Ok(ChildDetachFold::Clear)))
            | (TaskState::Faulted, Some(Ok(ChildDetachFold::FaultInFlight)))
    ) {
        control
            .exact_mut(key)
            .expect("validated running control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }
    let cleanup = tuple.cleanup;
    let suspended = match control.suspend_for_scheduler(key, cleanup) {
        Ok(suspended) => suspended,
        Err(_) => {
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    let proof = prove_terminal_outside_control(key, &tuple, state);
    let (terminal, expected_completion, derived_from_fault_reclaim) = match proof {
        TerminalProof::Busy => {
            let resumed = suspended.resume();
            system.restore();
            return if resumed.is_ok() {
                FinalizeControl::Busy
            } else {
                FinalizeControl::Lost
            };
        }
        TerminalProof::Lost => {
            if let Ok(mut control) = suspended.resume() {
                if let Some(record) = control.exact_mut(key) {
                    record.quarantine();
                }
            }
            system.restore();
            return FinalizeControl::Lost;
        }
        TerminalProof::Exact {
            terminal,
            completion,
            derived_from_fault_reclaim,
        } => (terminal, completion, derived_from_fault_reclaim),
    };
    let candidate_less_fault = state == TaskState::Faulted
        && tuple.terminal_candidate.is_none()
        && expected_completion.is_none()
        && terminal == ComponentTerminal::RunnerFault;
    if derived_from_fault_reclaim != candidate_less_fault {
        quarantine_terminal_tuple(key, &tuple);
        if let Ok(mut control) = suspended.resume() {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
        }
        system.restore();
        return FinalizeControl::Lost;
    }
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::record_terminal_visible(&tuple.handle, tuple.domain, state);
    let finalized =
        unsafe { finalize_registry_terminal(key, &tuple, terminal, expected_completion) };
    let mut control = match suspended.resume() {
        Ok(control) => control,
        Err(_) => {
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    let _outcome = match finalized {
        Ok(outcome) if outcome.detached_completion == expected_completion => outcome,
        Ok(_) | Err(_) => {
            CONTROL.child_shadow[key.slot as usize].quarantine(key);
            CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            let _ = registry().quarantine(tuple.core_token);
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    #[cfg(feature = "ssh-native-async-qemu-acceptance")]
    if tuple.start_kind == ControlStartKind::ManagedNativeAsync
        && !native_async_acceptance::target_record_managed_terminal(
            key,
            tuple.core_token,
            tuple.handle.id(),
            tuple.domain,
            tuple.streams,
            terminal,
        )
    {
        CONTROL.child_shadow[key.slot as usize].quarantine(key);
        CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
        control
            .exact_mut(key)
            .expect("target-audited terminal control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::record_cspace_reset(
        tuple.handle.id(),
        tuple.domain,
        _outcome.next_cspace_incarnation,
    );
    if !lifecycle_is_healthy()
        || control
            .exact(key)
            .is_none_or(|record| !control_record_matches_tuple(record, &tuple))
        || !CONTROL.child_shadow[key.slot as usize].exact_handle(key, &tuple.handle)
        || !CONTROL.supervisor_shadow[key.slot as usize].exact_handle(key, &tuple.supervisor)
        || !CONTROL.child_shadow[key.slot as usize].transition(
            key,
            TASK_SHADOW_RUNNING,
            TASK_SHADOW_COMPLETE,
        )
        || !CONTROL.supervisor_shadow[key.slot as usize].transition(
            key,
            TASK_SHADOW_RUNNING,
            TASK_SHADOW_COMPLETE,
        )
    {
        CONTROL.child_shadow[key.slot as usize].quarantine(key);
        CONTROL.supervisor_shadow[key.slot as usize].quarantine(key);
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }

    let managed = match (tuple.start_kind, cleanup, key.managed_token()) {
        (ControlStartKind::ManagedSync, Some(cleanup), Some(token)) => {
            if !CONTROL.mark_cleanup_completing(key, cleanup, token, terminal) {
                control
                    .exact_mut(key)
                    .expect("validated terminal control slot exists")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                return FinalizeControl::Lost;
            }
            Some((cleanup, token))
        }
        #[cfg(feature = "ssh-native-async-command")]
        (ControlStartKind::ManagedNativeAsync, Some(cleanup), Some(token)) => {
            if !CONTROL.mark_cleanup_completing(key, cleanup, token, terminal) {
                control
                    .exact_mut(key)
                    .expect("validated terminal control slot exists")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                return FinalizeControl::Lost;
            }
            Some((cleanup, token))
        }
        #[cfg(feature = "wasm-c48-qemu-acceptance")]
        (ControlStartKind::Acceptance, None, _) => None,
        #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
        (ControlStartKind::NativeAsyncAcceptance, None, _) => None,
        _ => {
            control
                .exact_mut(key)
                .expect("validated terminal control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    {
        let record = control
            .exact_mut(key)
            .expect("validated terminal control slot exists");
        record.phase = ControlPhase::Complete {
            terminal,
            acknowledged: false,
        };
        record.core_token = None;
        record.handle = None;
        record.domain = None;
        record.streams = None;
        record.terminal_candidate = None;
        record.candidate_source = None;
    }

    let reaper_wake = if let Some((cleanup, token)) = managed {
        let suspended = match control.suspend_for_scheduler(key, Some(cleanup)) {
            Ok(suspended) => suspended,
            Err(_) => {
                system.restore();
                return FinalizeControl::Lost;
            }
        };
        let wake = cleanup.notify_complete(token, terminal);
        control = match suspended.resume() {
            Ok(control) => control,
            Err(_) => {
                system.restore();
                return FinalizeControl::Lost;
            }
        };
        let complete_projection = lifecycle_is_healthy()
            && CONTROL.child_shadow[key.slot as usize].exact_handle(key, &tuple.handle)
            && CONTROL.child_shadow[key.slot as usize].phase(key) == Some(TASK_SHADOW_COMPLETE)
            && CONTROL.supervisor_shadow[key.slot as usize].exact_handle(key, &tuple.supervisor)
            && CONTROL.supervisor_shadow[key.slot as usize].phase(key)
                == Some(TASK_SHADOW_COMPLETE)
            && control.exact(key).is_some_and(|record| {
                matches!(
                    record.phase,
                    ControlPhase::Complete {
                        terminal: stored,
                        acknowledged: false,
                    } if stored == terminal
                ) && record.core_token.is_none()
                    && record.handle.is_none()
                    && record.domain.is_none()
                    && record.streams.is_none()
                    && record.terminal_candidate.is_none()
                    && record.candidate_source.is_none()
                    && record.supervisor.as_ref().is_some_and(|supervisor| {
                        supervisor.id() == tuple.supervisor.id()
                            && supervisor.shares_status_with(&tuple.supervisor)
                    })
                    && record
                        .cleanup
                        .is_some_and(|stored| stored.matches_exact(cleanup))
                    && record.start_kind == Some(tuple.start_kind)
            });
        let cleanup_complete = CONTROL.mark_cleanup_complete(key, cleanup, token, terminal);
        if wake.is_none() || !complete_projection || !cleanup_complete || !lifecycle_is_healthy() {
            control
                .exact_mut(key)
                .expect("staged terminal control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
        #[cfg(feature = "ssh-native-async-qemu-acceptance")]
        if tuple.start_kind == ControlStartKind::ManagedNativeAsync
            && !native_async_acceptance::target_record_reaper_notified(
                key,
                tuple.core_token,
                tuple.handle.id(),
                tuple.domain,
                tuple.streams,
                token,
                terminal,
            )
        {
            control
                .exact_mut(key)
                .expect("target-audited reaper notification slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
        wake
    } else {
        None
    };

    let Some(completion) = lifecycle_is_healthy()
        .then(|| CONTROL.completion(key))
        .flatten()
    else {
        control
            .exact_mut(key)
            .expect("completed control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    };
    let wake = match completion.publish(key.generation) {
        Ok(wake) => wake,
        Err(_) => {
            control
                .exact_mut(key)
                .expect("completed control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::record_outer_complete(tuple.handle.id(), tuple.domain, terminal);
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::terminal_race_completion_edge(key);
    system.restore();
    drop(control);
    wake.dispatch();
    if let Some(wake) = reaper_wake {
        wake.dispatch();
    }
    FinalizeControl::Complete
}

#[cfg(feature = "ssh-component-command")]
fn observe_instance(token: ManagedComponentToken) -> ManagedComponentState {
    if !lifecycle_is_healthy() {
        return ManagedComponentState::Lost;
    }
    let Some(key) = managed_token_key(token) else {
        return ManagedComponentState::Lost;
    };
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => {
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            acceptance::terminal_race_observed_control_busy();
            return ManagedComponentState::Busy;
        }
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return ManagedComponentState::Lost;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy() {
        system.restore();
        return ManagedComponentState::Lost;
    }
    let Some(phase) = control.exact(key).map(|record| record.phase) else {
        system.restore();
        return ManagedComponentState::Lost;
    };
    match phase {
        ControlPhase::Complete { terminal, .. } => {
            let complete_is_clean = control.exact(key).is_some_and(|record| {
                record.core_token.is_none()
                    && record.handle.is_none()
                    && record.domain.is_none()
                    && record.streams.is_none()
                    && record.terminal_candidate.is_none()
            });
            if !complete_is_clean {
                control
                    .exact_mut(key)
                    .expect("exact complete control slot exists")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                return ManagedComponentState::Lost;
            }
            system.restore();
            ManagedComponentState::Complete(terminal)
        }
        ControlPhase::Running => {
            let tuple = match control.running_tuple(key) {
                Ok(Some(tuple)) => tuple,
                Ok(None) => {
                    system.restore();
                    return ManagedComponentState::Lost;
                }
                Err(()) => {
                    lifecycle_fail_stop();
                    system.restore();
                    return ManagedComponentState::Lost;
                }
            };
            let observed = registry().observe_structural(tuple.core_token, &tuple.handle);
            let valid = observed.as_ref().is_ok_and(|snapshot| {
                snapshot.domain == tuple.domain
                    && snapshot.task == Some(tuple.handle.id())
                    && matches!(
                        snapshot.phase,
                        InstancePhase::Active
                            | InstancePhase::PayloadDropping
                            | InstancePhase::PayloadDropped
                            | InstancePhase::FaultReclaiming
                            | InstancePhase::FaultReclaimed
                            | InstancePhase::FaultRetiring
                            | InstancePhase::FaultTerminal
                            | InstancePhase::NormalClosing
                            | InstancePhase::NormalTerminal
                    )
            });
            if valid {
                system.restore();
                ManagedComponentState::Running
            } else {
                if observed.is_ok() {
                    let _ = registry().quarantine(tuple.core_token);
                }
                control
                    .exact_mut(key)
                    .expect("validated running control slot exists")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                ManagedComponentState::Lost
            }
        }
        ControlPhase::Vacant | ControlPhase::Starting | ControlPhase::Quarantined => {
            system.restore();
            ManagedComponentState::Lost
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn quarantine_wait_instance(key: ControlKey) {
    let mut control = match CONTROL.try_lock_completion_ack() {
        Ok(control) => control,
        Err(_) => {
            lifecycle_fail_stop();
            return;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if control.exact(key).is_none() {
        // A stale generation is observational only. It must not publish into,
        // quarantine, or otherwise touch a replacement control record.
        system.restore();
        return;
    }
    control
        .exact_mut(key)
        .expect("exact wait control slot exists")
        .quarantine();
    lifecycle_fail_stop();
    let wake = CONTROL
        .completion(key)
        .and_then(|completion| completion.publish(key.generation).ok());
    system.restore();
    drop(control);
    if let Some(wake) = wake {
        wake.dispatch();
    }
}

#[cfg(feature = "ssh-component-command")]
async fn wait_instance(token: ManagedComponentToken) -> ManagedComponentState {
    let Some(key) = managed_token_key(token) else {
        return ManagedComponentState::Lost;
    };
    let Some(completion) = CONTROL.completion(key) else {
        return ManagedComponentState::Lost;
    };

    // Construct the listener before the scalar recheck. If terminal
    // publication wins before the first listener poll, the queue's generation
    // watermark makes that poll ready without installing a stale wake edge.
    let listener = completion.wait(key.generation);
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::terminal_race_listener_armed(key);
    loop {
        match observe_instance(token) {
            ManagedComponentState::Busy => crate::exec::yield_now().await,
            ManagedComponentState::Running => break,
            terminal => return terminal,
        }
    }
    if listener.await.is_err() {
        quarantine_wait_instance(key);
        return ManagedComponentState::Lost;
    }
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::terminal_race_listener_returned(key).await;
    loop {
        match observe_instance(token) {
            ManagedComponentState::Busy => crate::exec::yield_now().await,
            terminal @ ManagedComponentState::Complete(_) => return terminal,
            ManagedComponentState::Lost => return ManagedComponentState::Lost,
            ManagedComponentState::Running => {
                // Only exact terminal publication can release this generation.
                // Running after that edge means the control projection disagrees
                // with its stable queue; fail-stop rather than polling again.
                quarantine_wait_instance(key);
                return ManagedComponentState::Lost;
            }
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn cancel_instance_with_terminal(
    token: ManagedComponentToken,
    terminal: ComponentTerminal,
) -> ManagedComponentCancel {
    if !matches!(
        terminal,
        ComponentTerminal::Cancelled | ComponentTerminal::RunnerFault
    ) {
        lifecycle_fail_stop();
        return ManagedComponentCancel::Lost;
    }
    if !lifecycle_is_healthy() {
        return ManagedComponentCancel::Lost;
    }
    let Some(key) = managed_token_key(token) else {
        return ManagedComponentCancel::Lost;
    };
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return ManagedComponentCancel::Busy,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return ManagedComponentCancel::Lost;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy() {
        system.restore();
        return ManagedComponentCancel::Lost;
    }
    let Some(phase) = control.exact(key).map(|record| record.phase) else {
        system.restore();
        return ManagedComponentCancel::Lost;
    };
    if matches!(phase, ControlPhase::Complete { .. }) {
        let clean = control.exact(key).is_some_and(|record| {
            record.core_token.is_none()
                && record.handle.is_none()
                && record.domain.is_none()
                && record.streams.is_none()
                && record.terminal_candidate.is_none()
        });
        if !clean {
            control
                .exact_mut(key)
                .expect("exact complete control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return ManagedComponentCancel::Lost;
        }
        system.restore();
        return ManagedComponentCancel::AlreadyComplete;
    }
    if phase != ControlPhase::Running {
        system.restore();
        return ManagedComponentCancel::Lost;
    }
    let mut tuple = match control.running_tuple(key) {
        Ok(Some(tuple)) => tuple,
        Ok(None) => {
            system.restore();
            return ManagedComponentCancel::Lost;
        }
        Err(()) => {
            lifecycle_fail_stop();
            system.restore();
            return ManagedComponentCancel::Lost;
        }
    };
    if !control_tuple_is_structurally_exact(&tuple)
        || control
            .exact(key)
            .is_none_or(|record| !control_record_matches_tuple(record, &tuple))
    {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        let _ = registry().quarantine(tuple.core_token);
        lifecycle_fail_stop();
        system.restore();
        return ManagedComponentCancel::Lost;
    }

    // CONTROL is the first terminal arbiter. publish_payload_terminal records
    // a candidate only after the exact child passed both full CSpace
    // identity/incarnation and endpoint gates. We intentionally repeat only
    // the core structural (Space + CSpace-lock object) observation here: a
    // cancellation hart must never wait for the CSpace guard while holding
    // CONTROL/core locks because a fault-abandoned guard needs the reclaimer
    // to enter those same registries. Once the candidate is recorded,
    // cancellation is observational only; calling request_cooperative_cancel
    // could otherwise install payload_cancel in the narrow window before that
    // already-winning completion is stored.
    let folded = control
        .exact(key)
        .map(|record| fold_child_detach_reason_locked(record, key));
    if matches!(folded, Some(Ok(ChildDetachFold::FaultInFlight))) {
        system.restore();
        return ManagedComponentCancel::AlreadyCompleting;
    }
    if !matches!(folded, Some(Ok(ChildDetachFold::Clear))) {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        let _ = registry().quarantine(tuple.core_token);
        lifecycle_fail_stop();
        system.restore();
        return ManagedComponentCancel::Lost;
    }
    if tuple.terminal_candidate.is_some() {
        system.restore();
        return ManagedComponentCancel::AlreadyCompleting;
    }

    {
        let record = control
            .exact_mut(key)
            .expect("validated running control slot exists");
        record.terminal_candidate = Some(terminal);
        record.candidate_source = Some(TerminalCandidateSource::Cooperative);
    }
    tuple.terminal_candidate = Some(terminal);
    tuple.candidate_source = Some(TerminalCandidateSource::Cooperative);

    let outcome = registry().request_cooperative_cancel(
        tuple.core_token,
        &tuple.handle,
        terminal_word(terminal),
    );
    let structurally_exact = control_tuple_is_structurally_exact(&tuple);
    let projection_exact = control
        .exact(key)
        .is_some_and(|record| control_record_matches_tuple(record, &tuple));
    if !structurally_exact || !projection_exact {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        let _ = registry().quarantine(tuple.core_token);
        lifecycle_fail_stop();
        system.restore();
        return ManagedComponentCancel::Lost;
    }

    let (wake, result) = match outcome {
        Ok(CooperativeCancelOutcome::Requested(task)) if tuple.handle.id() == task => {
            (Some(task), ManagedComponentCancel::Requested)
        }
        // A fault, executor cancellation, or already-tombstoned completion is
        // advancing in core. The exact None candidate remains unchanged; the
        // task's terminal state decides whether a candidate was required.
        Ok(CooperativeCancelOutcome::AlreadyCompleting) => {
            let record = control
                .exact_mut(key)
                .expect("post-validated running control slot exists");
            if record.terminal_candidate == Some(terminal)
                && record.candidate_source == Some(TerminalCandidateSource::Cooperative)
            {
                record.terminal_candidate = None;
                record.candidate_source = None;
            } else {
                record.quarantine();
                let _ = registry().quarantine(tuple.core_token);
                lifecycle_fail_stop();
                system.restore();
                return ManagedComponentCancel::Lost;
            }
            (None, ManagedComponentCancel::AlreadyCompleting)
        }
        Ok(CooperativeCancelOutcome::Requested(_)) => {
            // A Requested result proved the core token/status/domain tuple.
            // A different returned TaskId is therefore an outer projection
            // failure, and this exact core generation may be quarantined.
            let _ = registry().quarantine(tuple.core_token);
            control
                .exact_mut(key)
                .expect("validated running control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return ManagedComponentCancel::Lost;
        }
        Err(_) => {
            // Requested/AlreadyCompleting first prove the core tuple. Every
            // error path already quarantines a mismatched core record.
            control
                .exact_mut(key)
                .expect("validated running control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return ManagedComponentCancel::Lost;
        }
    };
    system.restore();
    drop(control);
    if let Some(task) = wake {
        crate::exec::wake(task);
    }
    result
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
fn cancel_instance(token: ManagedComponentToken) -> ManagedComponentCancel {
    cancel_instance_with_terminal(token, ComponentTerminal::Cancelled)
}

#[cfg(feature = "ssh-component-command")]
fn acknowledge_instance(token: ManagedComponentToken) -> ManagedComponentAcknowledge {
    if !lifecycle_is_healthy() {
        return ManagedComponentAcknowledge::Lost;
    }
    let Some(key) = managed_token_key(token) else {
        return ManagedComponentAcknowledge::Lost;
    };
    let mut control = match CONTROL.try_lock_completion_ack() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return ManagedComponentAcknowledge::Busy,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return ManagedComponentAcknowledge::Lost;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy() {
        system.restore();
        return ManagedComponentAcknowledge::Lost;
    }
    let Some(record) = control.exact(key) else {
        system.restore();
        return ManagedComponentAcknowledge::Lost;
    };
    let (terminal, acknowledged) = match record.phase {
        ControlPhase::Complete {
            terminal,
            acknowledged,
        } => (terminal, acknowledged),
        ControlPhase::Running | ControlPhase::Starting => {
            system.restore();
            return ManagedComponentAcknowledge::Busy;
        }
        ControlPhase::Vacant | ControlPhase::Quarantined => {
            system.restore();
            return ManagedComponentAcknowledge::Lost;
        }
    };
    if acknowledged {
        system.restore();
        return ManagedComponentAcknowledge::Acknowledged;
    }
    #[cfg(feature = "ssh-native-async-qemu-acceptance")]
    let target_native = record.start_kind == Some(ControlStartKind::ManagedNativeAsync);
    let projection_exact = record.core_token.is_none()
        && record.handle.is_none()
        && record.domain.is_none()
        && record.streams.is_none()
        && record.terminal_candidate.is_none()
        && record.candidate_source.is_none()
        && record.supervisor.as_ref().is_some_and(|supervisor| {
            CONTROL.supervisor_shadow[key.slot as usize].exact(
                key,
                supervisor.id(),
                supervisor.allocation_domain(),
            ) && CONTROL.supervisor_shadow[key.slot as usize].phase(key)
                == Some(TASK_SHADOW_COMPLETE)
        })
        && match (record.start_kind, record.cleanup) {
            (Some(ControlStartKind::ManagedSync), Some(cleanup)) => {
                CONTROL.cleanup_shadow_is_complete(key, cleanup, token, terminal)
            }
            #[cfg(feature = "ssh-native-async-command")]
            (Some(ControlStartKind::ManagedNativeAsync), Some(cleanup)) => {
                CONTROL.cleanup_shadow_is_complete(key, cleanup, token, terminal)
            }
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            (Some(ControlStartKind::Acceptance), None) => true,
            #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
            (Some(ControlStartKind::NativeAsyncAcceptance), None) => true,
            _ => false,
        };
    if !projection_exact {
        control
            .exact_mut(key)
            .expect("acknowledgement record remains exact")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return ManagedComponentAcknowledge::Lost;
    }
    let supervisor_state = control
        .exact(key)
        .and_then(|record| record.supervisor.as_ref())
        .and_then(TaskHandle::try_exit)
        .map(|exit| exit.state());
    match supervisor_state {
        None | Some(TaskState::Running) => {
            system.restore();
            ManagedComponentAcknowledge::Busy
        }
        Some(TaskState::Exited) => {
            let cleanup = control.exact(key).and_then(|record| record.cleanup);
            if cleanup.is_some_and(|cleanup| !CONTROL.clear_cleanup_shadow(key, cleanup)) {
                control
                    .exact_mut(key)
                    .expect("acknowledgement record remains exact")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                return ManagedComponentAcknowledge::Lost;
            }
            let record = control
                .exact_mut(key)
                .expect("acknowledgement record remains exact");
            record.phase = ControlPhase::Complete {
                terminal,
                acknowledged: true,
            };
            record.supervisor = None;
            record.cleanup = None;
            record.start_kind = None;
            #[cfg(feature = "ssh-native-async-qemu-acceptance")]
            if target_native
                && !native_async_acceptance::target_record_managed_acknowledgement(
                    key, token, terminal,
                )
            {
                control
                    .exact_mut(key)
                    .expect("target-audited acknowledgement slot exists")
                    .quarantine();
                lifecycle_fail_stop();
                system.restore();
                return ManagedComponentAcknowledge::Lost;
            }
            system.restore();
            ManagedComponentAcknowledge::Acknowledged
        }
        Some(TaskState::Faulted | TaskState::Cancelled) => {
            control
                .exact_mut(key)
                .expect("acknowledgement record remains exact")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            ManagedComponentAcknowledge::Lost
        }
    }
}

// SAFETY: the service and image root are boot-static; start publishes the
// complete core registry/control/executor transaction before returning a
// token. Every method uses only scalar tokens and the stable exact TaskHandle,
// and only the independent supervisor calls terminal finalization/reset.
#[cfg(feature = "ssh-component-command")]
unsafe impl ManagedComponentLifecycle for ImageComponentLifecycle {
    fn manifest(&self) -> &ComponentCommandManifest {
        &image_root()
            .expect("managed component lifecycle used before boot admission")
            .manifest
    }

    fn start(
        &self,
        cleanup: ManagedComponentStartLease,
    ) -> Result<ManagedComponentToken, ComponentTerminal> {
        start_instance(cleanup)
    }

    fn state(&self, token: ManagedComponentToken) -> ManagedComponentState {
        observe_instance(token)
    }

    fn wait_state<'a>(&'a self, token: ManagedComponentToken) -> ManagedComponentStateFuture<'a> {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let future = Box::pin(wait_instance(token));
        system.restore();
        future
    }

    fn request_cancel(
        &self,
        token: ManagedComponentToken,
        terminal: ComponentTerminal,
    ) -> ManagedComponentCancel {
        cancel_instance_with_terminal(token, terminal)
    }

    fn acknowledge_complete(&self, token: ManagedComponentToken) -> ManagedComponentAcknowledge {
        acknowledge_instance(token)
    }
}

#[cfg(feature = "ssh-component-command")]
pub(crate) fn ssh_exec_policy(profile: AuthorizedProfile) -> Option<SshExecComponentSessionPolicy> {
    if !lifecycle_is_healthy() || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED {
        return None;
    }
    let Some(root) = image_root() else {
        lifecycle_fail_stop();
        return None;
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let image_matches = revalidate_image_root(root);
    system.restore();
    if !image_matches {
        lifecycle_fail_stop();
        return None;
    }
    if !lifecycle_is_healthy() || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED {
        return None;
    }
    Some(SshExecComponentSessionPolicy::new(
        profile,
        root.policy_incarnation,
        SSH_EXEC_COMPONENT.command_name(),
        SSH_EXEC_COMPONENT.expected_sha256(),
    ))
}

#[cfg(feature = "ssh-component-command")]
pub(crate) fn select_ssh_exec_component_policy(
    profile: AuthorizedProfile,
    source: &str,
) -> Option<SshExecComponentSessionPolicy> {
    let sync_selected = vibeos_vsh::validate_ssh_exec_with_component_name(
        source,
        SSH_EXEC_COMPONENT.command_name(),
    ) == Ok(true);
    #[cfg(feature = "ssh-native-async-command")]
    let native_selected = vibeos_vsh::validate_ssh_exec_with_component_name(
        source,
        native_async_acceptance::command_name(),
    ) == Ok(true);
    #[cfg(not(feature = "ssh-native-async-command"))]
    let native_selected = false;

    match (sync_selected, native_selected) {
        (true, false) => ssh_exec_policy(profile),
        (false, true) => {
            #[cfg(feature = "ssh-native-async-command")]
            {
                return native_async_acceptance::ssh_exec_policy(profile);
            }
            #[cfg(not(feature = "ssh-native-async-command"))]
            {
                lifecycle_fail_stop();
                None
            }
        }
        (false, false) => None,
        (true, true) => {
            lifecycle_fail_stop();
            #[cfg(feature = "ssh-native-async-command")]
            native_async_acceptance::lifecycle_fail_stop();
            None
        }
    }
}

#[cfg(feature = "ssh-component-command")]
pub(crate) fn install_ssh_exec_component(
    session: &mut Session,
    accepted: SshExecComponentSessionPolicy,
    io: SshExecComponentIoInstall,
) -> Result<(), vibeos_vsh::Diagnostic> {
    #[cfg(feature = "ssh-native-async-command")]
    if native_async_acceptance::ssh_exec_policy(accepted.profile()) == Some(accepted) {
        return native_async_acceptance::install_ssh_exec_component(session, accepted, io);
    }
    if ssh_exec_policy(accepted.profile()) != Some(accepted) {
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    }
    let Some(root) = image_root() else {
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let image_matches = revalidate_image_root(root)
        && accepted.command_name() == SSH_EXEC_COMPONENT.command_name()
        && accepted.artifact_sha256() == SSH_EXEC_COMPONENT.expected_sha256();
    system.restore();
    if !image_matches {
        lifecycle_fail_stop();
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    }
    if !lifecycle_is_healthy() || SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED {
        return Err(vibeos_vsh::ssh_exec_component_policy_rejected(
            accepted.command_name(),
        ));
    }
    unsafe { session.install_ssh_exec_managed_component_io(&root.ssh_policy, &LIFECYCLE, io) }
}

#[cfg(feature = "ssh-native-async-qemu-acceptance")]
fn target_control_residue(control: &ControlTable) -> (usize, usize) {
    let mut live = 0usize;
    let mut stream_bindings = 0usize;
    for record in &control.slots {
        stream_bindings += usize::from(record.streams.is_some());
        let projection_empty = record.core_token.is_none()
            && record.handle.is_none()
            && record.supervisor.is_none()
            && record.domain.is_none()
            && record.streams.is_none()
            && record.cleanup.is_none()
            && record.start_kind.is_none()
            && record.terminal_candidate.is_none()
            && record.candidate_source.is_none();
        let phase_clean = record.phase == ControlPhase::Vacant
            || matches!(
                record.phase,
                ControlPhase::Complete {
                    acknowledged: true,
                    ..
                }
            );
        live += usize::from(!projection_empty || !phase_clean);
    }
    (live, stream_bindings)
}

/// Target-only completion observer called after the SSH peer has received the
/// exact status/stdout/EOF/CLOSE sequence and VSH has shut down its reaper.
#[cfg(feature = "ssh-native-async-qemu-acceptance")]
pub(crate) fn ssh_exec_component_completed(accepted: SshExecComponentSessionPolicy, status: u32) {
    if accepted.command_name() != native_async_acceptance::command_name() {
        return;
    }

    let native_policy = native_async_acceptance::ssh_exec_policy(accepted.profile());
    let sync_policy = ssh_exec_policy(accepted.profile());
    let route_exact = native_policy == Some(accepted)
        && accepted.command_name() == native_async_acceptance::command_name();
    let gates_open = native_policy.is_some()
        && sync_policy.is_some_and(|policy| {
            policy.command_name() == SSH_EXEC_COMPONENT.command_name()
                && policy.artifact_sha256() == SSH_EXEC_COMPONENT.expected_sha256()
        });

    let reapers = vibeos_vsh::managed_component_target_snapshot();
    let pending_shadows = native_async_acceptance::target_pending_shadow_residue();
    let (registry_occupied, registry_header_mismatches, control_live, stream_bindings, cleanup) =
        match CONTROL.try_lock() {
            Ok(control) => {
                let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
                let registry = registry().occupancy_stats();
                let (control_live, stream_bindings) = target_control_residue(&control);
                let cleanup = CONTROL.target_cleanup_shadow_residue();
                system.restore();
                drop(control);
                (
                    registry.occupied,
                    registry.header_mismatches,
                    control_live,
                    stream_bindings,
                    cleanup,
                )
            }
            Err(_) => (usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        };
    let report = native_async_acceptance::target_completion_report(
        status,
        route_exact,
        gates_open,
        pending_shadows,
        registry_occupied,
        registry_header_mismatches,
        control_live,
        stream_bindings,
        cleanup,
        reapers.reaper_slots,
        reapers.reaper_waiters,
    );
    let passed = native_async_acceptance::target_report_passed(report);
    native_async_acceptance::publish_target_report(report);
    if !passed {
        native_async_acceptance::lifecycle_fail_stop();
    }
}

#[cfg(feature = "ssh-component-command")]
pub(crate) unsafe fn recover_faulted_task(task: TaskId, domain: AllocationDomain) {
    if unsafe { CONTROL.recover_faulted_task(task, domain) } {
        lifecycle_fail_stop();
    }
}

#[cfg(feature = "ssh-component-command")]
#[allow(dead_code)]
pub(crate) fn fail_ssh_policy_gate() {
    lifecycle_fail_stop();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultRoute {
    Legacy,
    ManagedReclaimed,
    Quarantined,
}

unsafe fn reclaim_authorized_domain(
    task: crate::exec::TaskId,
    domain: crate::heap::AllocationDomain,
    component_control_validated: bool,
) -> bool {
    unsafe {
        if component_control_validated {
            crate::cleanup_faulted_task_after_component_gate(task, domain);
        } else {
            crate::cleanup_faulted_task(task, domain);
        }
        // Recover only shared service state which is keyed by this exact
        // allocation domain. The legacy World hook is intentionally not
        // reused: the instance registry owns Space/CSpace reset authority.
        crate::block_device::recover_faulted_domain(domain);
        crate::net_device::recover_faulted_domain(domain);
        #[cfg(feature = "qemu-virt")]
        crate::virtio_rng::recover_faulted_domain(domain);
        crate::code_pool::recover_faulted_domain(domain);
        #[cfg(feature = "ssh-component-command")]
        if component_control_validated && !lifecycle_is_healthy() {
            return false;
        }
        HEAP.reclaim_faulted_domain(domain).is_ok()
    }
}

#[cfg(feature = "ssh-component-command")]
unsafe fn reclaim_faulted_managed(witness: ReclaimableFaultWitness) -> FaultRoute {
    if !lifecycle_is_healthy() {
        return FaultRoute::Quarantined;
    }
    let mut control = match unsafe {
        CONTROL.try_lock_detached(witness.task_id(), witness.allocation_domain())
    } {
        Ok(control) => control,
        // Legitimate concurrent observation is not an identity mismatch, but
        // reclamation cannot wait or proceed without one simultaneous proof.
        Err(ControlGateError::Busy) => return FaultRoute::Quarantined,
        Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
            lifecycle_fail_stop();
            return FaultRoute::Quarantined;
        }
    };
    let key = match control.fault_tuple(witness) {
        Ok(key) => key,
        Err(()) => {
            lifecycle_fail_stop();
            return FaultRoute::Quarantined;
        }
    };
    let tuple = match control.running_tuple_structural(key) {
        Ok(Some(tuple))
            if tuple.core_token
                == witness
                    .instance_token()
                    .expect("managed witness has a token")
                && tuple.domain == witness.allocation_domain()
                && witness.matches_handle(&tuple.handle)
                && match (tuple.start_kind, tuple.cleanup, key.managed_token()) {
                    (ControlStartKind::ManagedSync, Some(cleanup), Some(_)) => {
                        CONTROL.cleanup_shadow_is_active(key, cleanup)
                    }
                    #[cfg(feature = "ssh-native-async-command")]
                    (ControlStartKind::ManagedNativeAsync, Some(cleanup), Some(_)) => {
                        CONTROL.cleanup_shadow_is_active(key, cleanup)
                    }
                    #[cfg(feature = "wasm-c48-qemu-acceptance")]
                    (ControlStartKind::Acceptance, None, _) => true,
                    #[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
                    (ControlStartKind::NativeAsyncAcceptance, None, _) => true,
                    _ => false,
                } =>
        {
            tuple
        }
        _ => {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            lifecycle_fail_stop();
            return FaultRoute::Quarantined;
        }
    };
    #[cfg(not(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    )))]
    let _ = &tuple;
    if !lifecycle_is_healthy() {
        return FaultRoute::Quarantined;
    }

    let task = witness.task_id();
    #[cfg(any(
        feature = "wasm-c53-native-async-qemu-acceptance",
        feature = "ssh-native-async-command"
    ))]
    if tuple.start_kind.is_native_async() {
        // Release CONTROL only after its complete task/domain projection is
        // proven. The core callback runs after it has restored the exact Space,
        // abandoned the exact continuation, and released its registry lock.
        // Native cleanup consumes that receipt and releases every backend
        // operation before raw arena reclaim or any CSpace reset can occur.
        drop(control);
        let outcome = unsafe {
            registry().fault_reclaim_with_space(witness, |domain, space, continuation| {
                if domain != tuple.domain
                    || !continuation.matches_instance(tuple.core_token)
                    || !lifecycle_is_healthy()
                    || !native_async_acceptance::lifecycle_is_healthy()
                    || !native_async_acceptance::raw_fault_cleanup(
                        space,
                        key,
                        tuple.core_token,
                        tuple.handle.id(),
                        domain,
                        tuple.streams,
                        continuation,
                    )
                {
                    return false;
                }
                reclaim_authorized_domain(task, domain, true)
            })
        };
        return match outcome {
            FaultGateOutcome::ManagedReclaimed => FaultRoute::ManagedReclaimed,
            FaultGateOutcome::NotManaged | FaultGateOutcome::Quarantined => {
                native_async_acceptance::quarantine_fault_shadow(
                    key,
                    tuple.core_token,
                    tuple.handle.id(),
                    tuple.domain,
                    tuple.streams,
                );
                FaultRoute::Quarantined
            }
        };
    }
    // Keep CONTROL from the outer generation/task/status/domain proof through
    // the core Space/CSpace proof and raw arena reclaim. Detached faults use a
    // separate bounded acquisition budget so independent harts serialize here
    // instead of weakening either identity gate.
    let outcome = unsafe {
        registry().fault_reclaim(witness, |domain| {
            if !lifecycle_is_healthy() {
                return false;
            }
            reclaim_authorized_domain(task, domain, true)
        })
    };
    match outcome {
        FaultGateOutcome::ManagedReclaimed => {
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            acceptance::record_raw_reclaimed(witness);
            FaultRoute::ManagedReclaimed
        }
        FaultGateOutcome::NotManaged | FaultGateOutcome::Quarantined => {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            lifecycle_fail_stop();
            FaultRoute::Quarantined
        }
    }
}

/// Classify a detached fault before any legacy recovery hook can mutate
/// stable state.  The registry performs the complete generation/task/status/
/// owner/arena/hart/Space/CSpace gate; only that success authorizes raw arena
/// reclamation.  It never resets the CSpace here.
///
/// # Safety
///
/// `witness` is supplied only by the executor after permanent detach and its
/// all-hart quiescence proof.  The exact registry domain, if any, must still be
/// active in `HEAP`.
pub(crate) unsafe fn reclaim_faulted(witness: ReclaimableFaultWitness) -> FaultRoute {
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let Some(route) = unsafe { acceptance::route_fault(witness) } {
        return route;
    }

    #[cfg(feature = "ssh-component-command")]
    if witness.instance_token().is_some() {
        return unsafe { reclaim_faulted_managed(witness) };
    }

    let task = witness.task_id();
    match unsafe {
        registry().fault_reclaim(witness, |domain| {
            // Managed exact-task cleanup is deliberately delayed until after
            // the registry's complete identity/CSpace gate.  The executor
            // skips its legacy pre-reclaimer cleanup for token-bearing
            // witnesses, so a mismatch cannot mutate stable task state.
            reclaim_authorized_domain(task, domain, false)
        })
    } {
        FaultGateOutcome::NotManaged => FaultRoute::Legacy,
        FaultGateOutcome::ManagedReclaimed => FaultRoute::ManagedReclaimed,
        FaultGateOutcome::Quarantined => FaultRoute::Quarantined,
    }
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
pub(crate) async fn run_qemu_acceptance() -> bool {
    acceptance::run().await
}

#[cfg(feature = "wasm-c53-native-async-qemu-acceptance")]
pub(crate) async fn run_native_async_qemu_acceptance() -> bool {
    native_async_acceptance::run_acceptance().await
}
