//! Allocation-free state machine for one SYSTEM-owned native transport slot.
//!
//! This file deliberately has no kernel dependencies. The production adapter
//! supplies opaque copy-only CONTROL/instance/CSpace/token identities, while
//! the same source can be compiled directly with `rustc --test` on the host.

pub(crate) const DRIVER_CHUNK_BYTES: usize = 1024;

/// Opaque runtime tokens must prove strict generation order without exposing
/// their numeric seal. Equality alone cannot exclude multi-step ABA replay.
pub(crate) trait ExactRuntimeToken: Copy + Eq {
    fn strictly_after(self, previous: Self) -> bool;
}

/// Orders an irreversible backend cancellation before the exact aggregate
/// receipt which credits its copied wake authority. A failed external cancel
/// never calls `release`; a failed release remains fail-stop after the
/// physical operation has already disappeared.
pub(crate) fn exact_backend_cancel_then_release<E>(
    cancel: impl FnOnce() -> Result<(), E>,
    release: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    cancel()?;
    release()
}

/// Bytes already popped from the backend but not yet committed to the guest.
/// Input and output intentionally never alias the same fixed storage.
pub(crate) struct InputSpill {
    bytes: [u8; DRIVER_CHUNK_BYTES],
    cursor: u16,
    length: u16,
}

impl InputSpill {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; DRIVER_CHUNK_BYTES],
            cursor: 0,
            length: 0,
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.cursor == self.length
    }

    pub(crate) fn receive_target(&mut self, length: usize) -> Option<&mut [u8]> {
        if !self.is_empty() || length == 0 || length > DRIVER_CHUNK_BYTES {
            return None;
        }
        self.cursor = 0;
        self.length = length as u16;
        Some(&mut self.bytes[..length])
    }

    pub(crate) fn remaining_prefix(&self, maximum: usize) -> &[u8] {
        let start = usize::from(self.cursor);
        let available = usize::from(self.length) - start;
        &self.bytes[start..start + available.min(maximum)]
    }

    pub(crate) fn consume(&mut self, length: usize) -> bool {
        let remaining = usize::from(self.length) - usize::from(self.cursor);
        if length > remaining {
            return false;
        }
        self.cursor += length as u16;
        if self.cursor == self.length {
            self.cursor = 0;
            self.length = 0;
        }
        true
    }

    pub(crate) fn abort_receive(&mut self) {
        self.cursor = 0;
        self.length = 0;
    }
}

pub(crate) struct OutputStaging {
    bytes: [u8; DRIVER_CHUNK_BYTES],
    length: u16,
}

impl OutputStaging {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; DRIVER_CHUNK_BYTES],
            length: 0,
        }
    }

    pub(crate) fn prepare(&mut self, maximum: usize) -> &mut [u8] {
        let length = maximum.min(DRIVER_CHUNK_BYTES);
        self.length = length as u16;
        &mut self.bytes[..length]
    }

    pub(crate) fn prepared(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub(crate) fn clear(&mut self) {
        self.length = 0;
    }
}

/// Exact stream-side authority involved in one native host operation.
///
/// These values are internal correlation labels. They never contain or expose
/// a capability; the production adapter separately binds the complete CSpace
/// projection in [`ExactInstanceIdentity::bindings`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactStreamResource {
    StdinReader,
    StdoutWriter,
    StdinSupervisor,
    StdoutSupervisor,
}

impl ExactStreamResource {
    const fn index(self) -> usize {
        match self {
            Self::StdinReader => 0,
            Self::StdoutWriter => 1,
            Self::StdinSupervisor => 2,
            Self::StdoutSupervisor => 3,
        }
    }

    const fn revocable_endpoint(self) -> bool {
        matches!(self, Self::StdinReader | Self::StdoutWriter)
    }
}

const fn resource_function_exact(
    resource: ExactStreamResource,
    function: ExactHostFunction,
) -> bool {
    matches!(
        (resource, function),
        (
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream
        ) | (
            ExactStreamResource::StdinSupervisor,
            ExactHostFunction::InputClosed
        ) | (
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream
        ) | (
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputClosed
        )
    )
}

/// Exact native host function whose runtime token is being consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactHostFunction {
    InputStream,
    InputClosed,
    OutputStream,
    OutputClosed,
}

/// Exact backend method currently outside the ledger lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactBackendAction {
    Start,
    RegisterWake,
    Resume,
    CommitPrepared,
}

/// Exact cancellable slot published by the byte-stream backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactBackendPendingKind {
    ReadWaiting,
    ReadPrepared,
    WriteWaiting,
    TerminalWaiting,
}

const fn pending_kind_exact(
    resource: ExactStreamResource,
    function: ExactHostFunction,
    kind: ExactBackendPendingKind,
) -> bool {
    matches!(
        (resource, function, kind),
        (
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            ExactBackendPendingKind::ReadWaiting | ExactBackendPendingKind::ReadPrepared
        ) | (
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            ExactBackendPendingKind::WriteWaiting
        ) | (
            ExactStreamResource::StdinSupervisor,
            ExactHostFunction::InputClosed,
            ExactBackendPendingKind::TerminalWaiting
        )
    )
}

/// An irreversible backend observation which has not yet been committed to
/// the native component runtime.
///
/// Close values are deliberately only correlation receipts. The immutable
/// terminal truth remains owned by `ByteStream` and is never reconstructed
/// from this ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendEffect {
    InputReceived {
        total: u16,
        cursor: u16,
    },
    OutputSent {
        length: u16,
    },
    InputPeerClosed {
        reason: u8,
    },
    InputPreparedClosed {
        reason: u8,
    },
    OutputPeerClosed {
        reason: u8,
    },
    InputTerminalObserved {
        reason: u8,
    },
    OutputCloseObserved {
        requested: u8,
        outcome: u8,
        effective: Option<u8>,
    },
}

impl BackendEffect {
    fn valid_initial(self) -> bool {
        match self {
            Self::InputReceived { total, cursor } => total != 0 && cursor == 0,
            Self::OutputSent { length } => length != 0,
            Self::InputPeerClosed { reason }
            | Self::InputPreparedClosed { reason }
            | Self::OutputPeerClosed { reason }
            | Self::InputTerminalObserved { reason } => reason <= 7,
            Self::OutputCloseObserved {
                requested,
                outcome,
                effective,
            } => requested <= 7 && outcome <= 2 && effective.is_some_and(|reason| reason <= 7),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputCloseResolution {
    Commit,
    Drop,
    Quarantine,
}

const fn output_close_resolution(effect: BackendEffect) -> Option<OutputCloseResolution> {
    let BackendEffect::OutputCloseObserved {
        requested,
        outcome,
        effective: Some(effective),
    } = effect
    else {
        return None;
    };
    Some(match outcome {
        0 if effective == requested => OutputCloseResolution::Commit,
        1 if effective == requested => OutputCloseResolution::Commit,
        1 if requested == 0 && effective != 0 => OutputCloseResolution::Drop,
        0..=2 => OutputCloseResolution::Quarantine,
        _ => return None,
    })
}

/// Complete stable-instance projection required before an operation may
/// mutate the ledger. Every type parameter is copy-only and supplied by the
/// kernel adapter; the model neither interprets nor prints those identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactInstanceIdentity<I, T, D, B> {
    /// Opaque encoding of the complete CONTROL key (slot plus generation).
    pub(crate) control: u64,
    pub(crate) control_generation: u64,
    pub(crate) instance: I,
    pub(crate) task: T,
    pub(crate) domain: D,
    pub(crate) bindings: B,
}

/// Exact lifecycle of one registry continuation registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactContinuation<C> {
    None,
    Armed(C),
    WakeRegistered(C),
    Signalled(C),
    Cancelled(C),
    Abandoned(C),
    Consumed(C),
}

/// Exact scheduler-side disposition of a continuation after the backend wake
/// registration has been cancelled. A live revoke must signal the child; a
/// fault path may instead prove that Core abandoned the continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactContinuationCleanup {
    Signalled,
    AlreadySignalled,
    Cancelled,
    Abandoned,
}

/// Exact disposition of the runtime host token after SYSTEM cancellation.
/// Live revoke requires the driver which owned the token to acknowledge the
/// cancellation. Fault cleanup instead proves that Core abandoned that owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactRuntimeCleanup {
    Cancelled,
    Dropped,
    Abandoned,
}

impl<C: Copy> ExactContinuation<C> {
    pub(crate) const fn token(self) -> Option<C> {
        match self {
            Self::None => None,
            Self::Armed(token)
            | Self::WakeRegistered(token)
            | Self::Signalled(token)
            | Self::Cancelled(token)
            | Self::Abandoned(token)
            | Self::Consumed(token) => Some(token),
        }
    }
}

/// Why SYSTEM claimed an operation for exact cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactCancelCause {
    Revoke,
    RawFault,
    FaultFinalizer,
    BackendResidual,
}

/// Monotonic cancellation claim. Its numeric generation is intentionally
/// private so diagnostics cannot reveal it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactCancelClaim {
    generation: u64,
    cause: ExactCancelCause,
}

impl ExactCancelClaim {
    pub(crate) const fn cause(self) -> ExactCancelCause {
        self.cause
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactInvocation<R> {
    generation: u64,
    input_spill_generation: Option<u64>,
    offered_runtime: R,
    prepared_runtime: Option<R>,
    resource: ExactStreamResource,
    function: ExactHostFunction,
    request_units: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactOperation<R, O, C> {
    RuntimeOffered {
        invocation: ExactInvocation<R>,
    },
    RuntimePrepared {
        invocation: ExactInvocation<R>,
    },
    BackendInvoking {
        invocation: ExactInvocation<R>,
        action: ExactBackendAction,
        previous_backend: Option<O>,
        previous_kind: Option<ExactBackendPendingKind>,
        continuation: ExactContinuation<C>,
        deferred_revoke: Option<ExactCancelClaim>,
    },
    BackendPending {
        invocation: ExactInvocation<R>,
        kind: ExactBackendPendingKind,
        backend: O,
        continuation: ExactContinuation<C>,
    },
    BackendLinearized {
        invocation: ExactInvocation<R>,
        backend: Option<O>,
        continuation: ExactContinuation<C>,
        effect: BackendEffect,
    },
    BackendResidualClaimed {
        invocation: ExactInvocation<R>,
        backend: O,
        continuation: ExactContinuation<C>,
        effect: BackendEffect,
        claim: ExactCancelClaim,
    },
    CancelClaimed {
        invocation: ExactInvocation<R>,
        kind: ExactBackendPendingKind,
        backend: O,
        continuation: ExactContinuation<C>,
        claim: ExactCancelClaim,
    },
    BackendCancelled {
        invocation: ExactInvocation<R>,
        continuation: ExactContinuation<C>,
        claim: ExactCancelClaim,
        runtime_cleanup: Option<ExactRuntimeCleanup>,
    },
}

/// Redacted phase used by target hooks and model assertions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactLedgerPhase {
    Retired,
    Idle,
    InputSpill,
    RuntimeOffered,
    RuntimePrepared,
    BackendInvoking,
    BackendPending,
    BackendLinearized,
    CancelClaimed,
    BackendCancelled,
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactInputSpillState {
    generation: u64,
    total: u16,
    cursor: u16,
}

/// Linear authority for bytes which have crossed the backend receive point but
/// have not yet been committed to the guest. The ledger retains the matching
/// fixed state while its ordinary operation slot remains available for the
/// opposite stream direction.
///
/// This receipt is deliberately neither `Copy` nor `Clone`: each remaining
/// prefix must consume the preceding authority and receive the exact successor.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ExactInputSpillReceipt<I, T, D, B> {
    identity: ExactInstanceIdentity<I, T, D, B>,
    state: ExactInputSpillState,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy> ExactInputSpillReceipt<I, T, D, B> {
    pub(crate) const fn remaining(&self) -> u16 {
        self.state.total - self.state.cursor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceLatch {
    Live,
    Revoking(ExactCancelClaim),
    Revoked(ExactCancelClaim),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeOwner {
    Live,
    Dropped,
    Abandoned,
}

/// Identity-bound projection used by terminal finalization to distinguish an
/// intentionally revoked endpoint cap from CSpace corruption. Supervisor caps
/// are never revocable in this profile because they retain terminal authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactResourceState {
    Live,
    Revoking,
    Revoked,
}

/// Copy-only exact snapshot. Callers must return the complete previous value
/// for every transition; matching one token or phase is never sufficient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactLedgerSnapshot<I, T, D, B, R, O, C> {
    identity: ExactInstanceIdentity<I, T, D, B>,
    operation: ExactOperation<R, O, C>,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy, R: Copy, O: Copy, C: Copy>
    ExactLedgerSnapshot<I, T, D, B, R, O, C>
{
    pub(crate) const fn identity(self) -> ExactInstanceIdentity<I, T, D, B> {
        self.identity
    }

    pub(crate) const fn phase(self) -> ExactLedgerPhase {
        match self.operation {
            ExactOperation::RuntimeOffered { .. } => ExactLedgerPhase::RuntimeOffered,
            ExactOperation::RuntimePrepared { .. } => ExactLedgerPhase::RuntimePrepared,
            ExactOperation::BackendInvoking { .. } => ExactLedgerPhase::BackendInvoking,
            ExactOperation::BackendPending { .. } => ExactLedgerPhase::BackendPending,
            ExactOperation::BackendLinearized { .. } => ExactLedgerPhase::BackendLinearized,
            ExactOperation::CancelClaimed { .. }
            | ExactOperation::BackendResidualClaimed { .. } => ExactLedgerPhase::CancelClaimed,
            ExactOperation::BackendCancelled { .. } => ExactLedgerPhase::BackendCancelled,
        }
    }

    pub(crate) const fn resource(self) -> ExactStreamResource {
        match self.operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation }
            | ExactOperation::BackendInvoking { invocation, .. }
            | ExactOperation::BackendPending { invocation, .. }
            | ExactOperation::BackendLinearized { invocation, .. }
            | ExactOperation::BackendResidualClaimed { invocation, .. }
            | ExactOperation::CancelClaimed { invocation, .. }
            | ExactOperation::BackendCancelled { invocation, .. } => invocation.resource,
        }
    }

    pub(crate) const fn function(self) -> ExactHostFunction {
        match self.operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation }
            | ExactOperation::BackendInvoking { invocation, .. }
            | ExactOperation::BackendPending { invocation, .. }
            | ExactOperation::BackendLinearized { invocation, .. }
            | ExactOperation::BackendResidualClaimed { invocation, .. }
            | ExactOperation::CancelClaimed { invocation, .. }
            | ExactOperation::BackendCancelled { invocation, .. } => invocation.function,
        }
    }

    pub(crate) const fn prepared_runtime(self) -> Option<R> {
        match self.operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation }
            | ExactOperation::BackendInvoking { invocation, .. }
            | ExactOperation::BackendPending { invocation, .. }
            | ExactOperation::BackendLinearized { invocation, .. }
            | ExactOperation::BackendResidualClaimed { invocation, .. }
            | ExactOperation::CancelClaimed { invocation, .. }
            | ExactOperation::BackendCancelled { invocation, .. } => invocation.prepared_runtime,
        }
    }

    pub(crate) const fn request_units(self) -> u16 {
        match self.operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation }
            | ExactOperation::BackendInvoking { invocation, .. }
            | ExactOperation::BackendPending { invocation, .. }
            | ExactOperation::BackendLinearized { invocation, .. }
            | ExactOperation::BackendResidualClaimed { invocation, .. }
            | ExactOperation::CancelClaimed { invocation, .. }
            | ExactOperation::BackendCancelled { invocation, .. } => invocation.request_units,
        }
    }

    pub(crate) const fn backend(self) -> Option<O> {
        match self.operation {
            ExactOperation::BackendPending { backend, .. }
            | ExactOperation::CancelClaimed { backend, .. }
            | ExactOperation::BackendResidualClaimed { backend, .. } => Some(backend),
            ExactOperation::BackendInvoking {
                previous_backend, ..
            }
            | ExactOperation::BackendLinearized {
                backend: previous_backend,
                ..
            } => previous_backend,
            ExactOperation::RuntimeOffered { .. }
            | ExactOperation::RuntimePrepared { .. }
            | ExactOperation::BackendCancelled { .. } => None,
        }
    }

    pub(crate) const fn pending_kind(self) -> Option<ExactBackendPendingKind> {
        match self.operation {
            ExactOperation::BackendPending { kind, .. }
            | ExactOperation::CancelClaimed { kind, .. } => Some(kind),
            ExactOperation::BackendResidualClaimed { .. } => {
                Some(ExactBackendPendingKind::ReadPrepared)
            }
            ExactOperation::BackendInvoking { previous_kind, .. } => previous_kind,
            _ => None,
        }
    }

    pub(crate) const fn continuation(self) -> ExactContinuation<C> {
        match self.operation {
            ExactOperation::BackendInvoking { continuation, .. }
            | ExactOperation::BackendPending { continuation, .. }
            | ExactOperation::BackendLinearized { continuation, .. }
            | ExactOperation::BackendResidualClaimed { continuation, .. }
            | ExactOperation::CancelClaimed { continuation, .. }
            | ExactOperation::BackendCancelled { continuation, .. } => continuation,
            ExactOperation::RuntimeOffered { .. } | ExactOperation::RuntimePrepared { .. } => {
                ExactContinuation::None
            }
        }
    }

    pub(crate) const fn effect(self) -> Option<BackendEffect> {
        match self.operation {
            ExactOperation::BackendLinearized { effect, .. }
            | ExactOperation::BackendResidualClaimed { effect, .. } => Some(effect),
            _ => None,
        }
    }
}

/// Exact backend cancellation work detached from the ledger lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactCancelPlan<I, T, D, B, R, O, C> {
    snapshot: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    kind: ExactBackendPendingKind,
    backend: O,
    continuation: ExactContinuation<C>,
    claim: ExactCancelClaim,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy, R: Copy, O: Copy, C: Copy>
    ExactCancelPlan<I, T, D, B, R, O, C>
{
    pub(crate) const fn snapshot(self) -> ExactLedgerSnapshot<I, T, D, B, R, O, C> {
        self.snapshot
    }

    pub(crate) const fn backend(self) -> O {
        self.backend
    }

    pub(crate) const fn kind(self) -> ExactBackendPendingKind {
        self.kind
    }

    pub(crate) const fn continuation(self) -> ExactContinuation<C> {
        self.continuation
    }

    pub(crate) const fn claim(self) -> ExactCancelClaim {
        self.claim
    }

    pub(crate) const fn resource_revoke_plan(self) -> ExactResourceRevokePlan<I, T, D, B> {
        ExactResourceRevokePlan {
            identity: self.snapshot.identity,
            resource: self.snapshot.resource(),
            claim: self.claim,
        }
    }
}

/// Exact cancellation of a prepared-reader token which survived a
/// `CommitPrepared -> Closed` return. The close effect remains irreversible
/// while only this residual backend reservation is cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactResidualCancelPlan<I, T, D, B, R, O, C> {
    snapshot: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    backend: O,
    claim: ExactCancelClaim,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy, R: Copy, O: Copy, C: Copy>
    ExactResidualCancelPlan<I, T, D, B, R, O, C>
{
    pub(crate) const fn backend(self) -> O {
        self.backend
    }
}

/// Exact CSpace revocation work detached from the ledger lock. Backend
/// cancellation must not be acknowledged until this plan is completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactResourceRevokePlan<I, T, D, B> {
    identity: ExactInstanceIdentity<I, T, D, B>,
    resource: ExactStreamResource,
    claim: ExactCancelClaim,
}

/// Opaque proof that revoke lost to an in-flight backend call. It deliberately
/// exposes no CSpace plan; only the exact backend return may produce one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactDeferredRevoke<I, T, D, B> {
    identity: ExactInstanceIdentity<I, T, D, B>,
    resource: ExactStreamResource,
    claim: ExactCancelClaim,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy> ExactResourceRevokePlan<I, T, D, B> {
    pub(crate) const fn identity(self) -> ExactInstanceIdentity<I, T, D, B> {
        self.identity
    }

    pub(crate) const fn resource(self) -> ExactStreamResource {
        self.resource
    }

    pub(crate) const fn claim(self) -> ExactCancelClaim {
        self.claim
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactRevokeDecision<I, T, D, B, R, O, C> {
    RevokeCap(ExactResourceRevokePlan<I, T, D, B>),
    RuntimeOnly {
        cap: ExactResourceRevokePlan<I, T, D, B>,
        runtime: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    },
    Deferred(ExactDeferredRevoke<I, T, D, B>),
    Cancel(ExactCancelPlan<I, T, D, B, R, O, C>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactBackendReturn<I, T, D, B, R, O, C> {
    Pending(ExactLedgerSnapshot<I, T, D, B, R, O, C>),
    Cancel(ExactCancelPlan<I, T, D, B, R, O, C>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactCleanupDecision<I, T, D, B, R, O, C> {
    ReclaimSafe,
    Cancel(ExactCancelPlan<I, T, D, B, R, O, C>),
    Quarantined,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactLedgerError {
    Busy,
    Vacant,
    StaleGeneration,
    IdentityMismatch,
    SnapshotMismatch,
    TokenDidNotRotate,
    ResourceRevoked,
    AlreadyRevoking,
    AlreadyRevoked,
    ClaimMismatch,
    ContinuationPending,
    ResourceRevoking,
    InvalidTransition,
    InvalidEffect,
    GenerationExhausted,
    Quarantined,
}

/// Allocation-free exact-incarnation ledger for one stable CONTROL slot.
///
/// Its API returns the exact cancellation plan needed outside the ledger lock
/// and classifies raw-fault/finalizer safety from the same live state.
pub(crate) struct ExactOperationLedger<I, T, D, B, R, O, C> {
    watermark: u64,
    next_invocation: u64,
    next_claim: u64,
    identity: Option<ExactInstanceIdentity<I, T, D, B>>,
    operation: Option<ExactOperation<R, O, C>>,
    input_spill: Option<ExactInputSpillState>,
    runtime_watermark: Option<R>,
    resources: [ResourceLatch; 4],
    runtime_owner: RuntimeOwner,
    quarantined: bool,
}

impl<
        I: Copy + Eq,
        T: Copy + Eq,
        D: Copy + Eq,
        B: Copy + Eq,
        R: ExactRuntimeToken,
        O: Copy + Eq,
        C: Copy + Eq,
    > ExactOperationLedger<I, T, D, B, R, O, C>
{
    pub(crate) const fn new() -> Self {
        Self {
            watermark: 0,
            next_invocation: 1,
            next_claim: 1,
            identity: None,
            operation: None,
            input_spill: None,
            runtime_watermark: None,
            resources: [ResourceLatch::Live; 4],
            runtime_owner: RuntimeOwner::Live,
            quarantined: false,
        }
    }

    pub(crate) fn bind(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactLedgerError> {
        self.check_live()?;
        if identity.control_generation == 0 {
            return self.reject(ExactLedgerError::StaleGeneration);
        }
        if identity.control_generation <= self.watermark {
            return Err(ExactLedgerError::StaleGeneration);
        }
        if self.identity.is_some() || self.operation.is_some() || self.input_spill.is_some() {
            return self.reject(ExactLedgerError::Busy);
        }
        self.watermark = identity.control_generation;
        self.identity = Some(identity);
        self.input_spill = None;
        self.runtime_watermark = None;
        self.resources = [ResourceLatch::Live; 4];
        self.runtime_owner = RuntimeOwner::Live;
        Ok(())
    }

    pub(crate) fn begin_runtime(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        offered_runtime: R,
        resource: ExactStreamResource,
        function: ExactHostFunction,
        request_units: usize,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.begin_runtime_inner(
            identity,
            offered_runtime,
            resource,
            function,
            request_units,
            false,
        )
    }

    fn begin_runtime_inner(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        offered_runtime: R,
        resource: ExactStreamResource,
        function: ExactHostFunction,
        request_units: usize,
        consuming_input_spill: bool,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(identity)?;
        self.require_runtime_owner_live()?;
        if self.operation.is_some() {
            return self.reject(ExactLedgerError::Busy);
        }
        if self.input_spill.is_some()
            && ((resource == ExactStreamResource::StdinReader && !consuming_input_spill)
                || function == ExactHostFunction::InputClosed)
        {
            return self.reject(ExactLedgerError::Busy);
        }
        if !resource_function_exact(resource, function) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        let request_units = match function {
            ExactHostFunction::InputStream | ExactHostFunction::OutputStream
                if request_units <= DRIVER_CHUNK_BYTES =>
            {
                request_units as u16
            }
            ExactHostFunction::InputClosed | ExactHostFunction::OutputClosed
                if request_units == 0 =>
            {
                0
            }
            _ => return self.reject(ExactLedgerError::InvalidEffect),
        };
        if !matches!(self.resources[resource.index()], ResourceLatch::Live) {
            return Err(ExactLedgerError::ResourceRevoked);
        }
        if self
            .runtime_watermark
            .is_some_and(|previous| !offered_runtime.strictly_after(previous))
        {
            return self.reject(ExactLedgerError::TokenDidNotRotate);
        }
        let generation = self.take_invocation_generation()?;
        let input_spill_generation = if consuming_input_spill {
            Some(
                self.input_spill
                    .expect("receipt-consuming input has exact spill state")
                    .generation,
            )
        } else {
            None
        };
        let operation = ExactOperation::RuntimeOffered {
            invocation: ExactInvocation {
                generation,
                input_spill_generation,
                offered_runtime,
                prepared_runtime: None,
                resource,
                function,
                request_units,
            },
        };
        self.operation = Some(operation);
        Ok(ExactLedgerSnapshot {
            identity,
            operation,
        })
    }

    pub(crate) fn prepare_runtime(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        prepared_runtime: R,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let mut invocation = match previous.operation {
            ExactOperation::RuntimeOffered { invocation } => invocation,
            ExactOperation::BackendPending {
                invocation,
                kind: ExactBackendPendingKind::ReadPrepared,
                continuation: ExactContinuation::None,
                ..
            } if invocation.function == ExactHostFunction::InputStream => invocation,
            ExactOperation::BackendPending {
                invocation,
                kind: ExactBackendPendingKind::TerminalWaiting,
                continuation: ExactContinuation::None,
                ..
            } if invocation.function == ExactHostFunction::InputClosed => invocation,
            ExactOperation::BackendLinearized {
                invocation,
                effect: BackendEffect::InputTerminalObserved { .. },
                ..
            } if invocation.function == ExactHostFunction::InputClosed => invocation,
            _ => return self.reject(ExactLedgerError::InvalidTransition),
        };
        if invocation.prepared_runtime.is_some()
            || !prepared_runtime.strictly_after(invocation.offered_runtime)
            || self
                .runtime_watermark
                .is_some_and(|previous| !prepared_runtime.strictly_after(previous))
        {
            return self.reject(ExactLedgerError::TokenDidNotRotate);
        }
        invocation.prepared_runtime = Some(prepared_runtime);
        let operation = match previous.operation {
            ExactOperation::RuntimeOffered { .. } => ExactOperation::RuntimePrepared { invocation },
            ExactOperation::BackendPending {
                kind,
                backend,
                continuation,
                ..
            } => ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation,
            },
            ExactOperation::BackendLinearized {
                backend,
                continuation,
                effect,
                ..
            } => ExactOperation::BackendLinearized {
                invocation,
                backend,
                continuation,
                effect,
            },
            _ => unreachable!("prepare-runtime source already checked"),
        };
        self.publish(previous.identity, operation)
    }

    pub(crate) fn begin_backend(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        action: ExactBackendAction,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let (invocation, previous_backend, previous_kind, continuation) = match previous.operation {
            ExactOperation::RuntimePrepared { invocation }
                if action == ExactBackendAction::Start
                    && invocation.input_spill_generation.is_none() =>
            {
                (invocation, None, None, ExactContinuation::None)
            }
            ExactOperation::RuntimeOffered { invocation }
                if action == ExactBackendAction::Start
                    && invocation.input_spill_generation.is_none()
                    && matches!(
                        invocation.function,
                        ExactHostFunction::InputStream | ExactHostFunction::InputClosed
                    ) =>
            {
                (invocation, None, None, ExactContinuation::None)
            }
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation,
            } => {
                let allowed = match (action, kind, continuation) {
                    (
                        ExactBackendAction::RegisterWake,
                        ExactBackendPendingKind::ReadWaiting
                        | ExactBackendPendingKind::WriteWaiting
                        | ExactBackendPendingKind::TerminalWaiting,
                        ExactContinuation::Armed(_),
                    ) => true,
                    (
                        ExactBackendAction::Resume,
                        ExactBackendPendingKind::ReadWaiting
                        | ExactBackendPendingKind::WriteWaiting
                        | ExactBackendPendingKind::TerminalWaiting,
                        ExactContinuation::Consumed(_),
                    ) => true,
                    (
                        ExactBackendAction::CommitPrepared,
                        ExactBackendPendingKind::ReadPrepared,
                        ExactContinuation::None,
                    ) => invocation.prepared_runtime.is_some(),
                    _ => false,
                };
                if !allowed {
                    return self.reject(ExactLedgerError::InvalidTransition);
                }
                (invocation, Some(backend), Some(kind), continuation)
            }
            _ => return self.reject(ExactLedgerError::InvalidTransition),
        };
        self.publish(
            previous.identity,
            ExactOperation::BackendInvoking {
                invocation,
                action,
                previous_backend,
                previous_kind,
                continuation,
                deferred_revoke: None,
            },
        )
    }

    pub(crate) fn backend_pending(
        &mut self,
        invoking_receipt: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        kind: ExactBackendPendingKind,
        backend: O,
    ) -> Result<ExactBackendReturn<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_runtime_owner_live()?;
        let current = self.require_backend_return(invoking_receipt)?;
        let ExactOperation::BackendInvoking {
            invocation,
            action,
            previous_backend,
            previous_kind: _,
            continuation,
            deferred_revoke,
        } = current
        else {
            unreachable!("backend-return receipt validated an invoking state");
        };
        if !matches!(
            action,
            ExactBackendAction::Start | ExactBackendAction::Resume
        ) || !pending_kind_exact(invocation.resource, invocation.function, kind)
        {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if previous_backend == Some(backend) {
            return self.reject(ExactLedgerError::TokenDidNotRotate);
        }
        match deferred_revoke {
            Some(claim) => {
                let operation = ExactOperation::CancelClaimed {
                    invocation,
                    kind,
                    backend,
                    continuation,
                    claim,
                };
                self.operation = Some(operation);
                let snapshot = ExactLedgerSnapshot {
                    identity: invoking_receipt.identity,
                    operation,
                };
                Ok(ExactBackendReturn::Cancel(ExactCancelPlan {
                    snapshot,
                    kind,
                    backend,
                    continuation,
                    claim,
                }))
            }
            None => {
                let snapshot = self.publish(
                    invoking_receipt.identity,
                    ExactOperation::BackendPending {
                        invocation,
                        kind,
                        backend,
                        continuation: ExactContinuation::None,
                    },
                )?;
                Ok(ExactBackendReturn::Pending(snapshot))
            }
        }
    }

    pub(crate) fn snapshot(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<ExactLedgerSnapshot<I, T, D, B, R, O, C>>, ExactLedgerError> {
        self.require_identity(identity)?;
        Ok(self.operation.map(|operation| ExactLedgerSnapshot {
            identity,
            operation,
        }))
    }

    pub(crate) fn arm_continuation(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        token: C,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendPending {
            invocation,
            kind,
            backend,
            continuation: ExactContinuation::None,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if !matches!(
            kind,
            ExactBackendPendingKind::ReadWaiting
                | ExactBackendPendingKind::WriteWaiting
                | ExactBackendPendingKind::TerminalWaiting
        ) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.publish(
            previous.identity,
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation: ExactContinuation::Armed(token),
            },
        )
    }

    pub(crate) fn finish_register_wake(
        &mut self,
        invoking_receipt: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        token: C,
    ) -> Result<ExactBackendReturn<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_runtime_owner_live()?;
        let current_operation = self.require_backend_return(invoking_receipt)?;
        let ExactOperation::BackendInvoking {
            invocation,
            action: ExactBackendAction::RegisterWake,
            previous_backend: Some(backend),
            previous_kind: Some(kind),
            continuation: ExactContinuation::Armed(current),
            deferred_revoke,
        } = current_operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if current != token {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        match deferred_revoke {
            Some(claim) => {
                let operation = ExactOperation::CancelClaimed {
                    invocation,
                    kind,
                    backend,
                    continuation: ExactContinuation::WakeRegistered(token),
                    claim,
                };
                self.operation = Some(operation);
                let snapshot = ExactLedgerSnapshot {
                    identity: invoking_receipt.identity,
                    operation,
                };
                Ok(ExactBackendReturn::Cancel(ExactCancelPlan {
                    snapshot,
                    kind,
                    backend,
                    continuation: ExactContinuation::WakeRegistered(token),
                    claim,
                }))
            }
            None => self
                .publish(
                    invoking_receipt.identity,
                    ExactOperation::BackendPending {
                        invocation,
                        kind,
                        backend,
                        continuation: ExactContinuation::WakeRegistered(token),
                    },
                )
                .map(ExactBackendReturn::Pending),
        }
    }

    pub(crate) fn consume_continuation(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        token: C,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendPending {
            invocation,
            kind,
            backend,
            continuation: ExactContinuation::WakeRegistered(current),
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if current != token {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        self.publish(
            previous.identity,
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation: ExactContinuation::Consumed(token),
            },
        )
    }

    /// Projects Core's typed consumed receipt into the one ledger state that
    /// owns the same opaque continuation. The receipt may race an exact
    /// cancellation claim or its backend completion, so those two phases are
    /// accepted in addition to the ordinary pending phase. No other field may
    /// change concurrently.
    pub(crate) fn project_consumed_continuation(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        token: C,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(identity)?;
        let Some(current) = self.operation else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        let operation = match current {
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation,
            } => ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation: self.consumed_projection(continuation, token)?,
            },
            ExactOperation::CancelClaimed {
                invocation,
                kind,
                backend,
                continuation,
                claim,
            } => ExactOperation::CancelClaimed {
                invocation,
                kind,
                backend,
                continuation: self.consumed_projection(continuation, token)?,
                claim,
            },
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup,
            } => ExactOperation::BackendCancelled {
                invocation,
                continuation: self.consumed_projection(continuation, token)?,
                claim,
                runtime_cleanup,
            },
            _ => return self.reject(ExactLedgerError::InvalidTransition),
        };
        self.publish(identity, operation)
    }

    pub(crate) fn backend_linearized(
        &mut self,
        invoking_receipt: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        effect: BackendEffect,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_runtime_owner_live()?;
        let current_operation = self.require_backend_return(invoking_receipt)?;
        if !effect.valid_initial() {
            return self.reject(ExactLedgerError::InvalidEffect);
        }
        let ExactOperation::BackendInvoking {
            invocation,
            action,
            previous_backend,
            previous_kind,
            continuation,
            deferred_revoke,
        } = current_operation
        else {
            unreachable!("backend-return receipt validated an invoking state");
        };
        if action == ExactBackendAction::RegisterWake {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        let effect_exact = match (invocation.function, action, previous_kind, effect) {
            (
                ExactHostFunction::InputStream,
                ExactBackendAction::CommitPrepared,
                Some(ExactBackendPendingKind::ReadPrepared),
                BackendEffect::InputReceived { total, .. },
            ) => invocation.prepared_runtime.is_some() && usize::from(total) <= DRIVER_CHUNK_BYTES,
            (
                ExactHostFunction::InputStream,
                ExactBackendAction::Start | ExactBackendAction::Resume,
                None | Some(ExactBackendPendingKind::ReadWaiting),
                BackendEffect::InputPeerClosed { .. },
            ) => true,
            (
                ExactHostFunction::InputStream,
                ExactBackendAction::CommitPrepared,
                Some(ExactBackendPendingKind::ReadPrepared),
                BackendEffect::InputPreparedClosed { .. },
            ) => invocation.prepared_runtime.is_some(),
            (
                ExactHostFunction::InputClosed,
                ExactBackendAction::Start | ExactBackendAction::Resume,
                None | Some(ExactBackendPendingKind::TerminalWaiting),
                BackendEffect::InputTerminalObserved { .. },
            ) => true,
            (
                ExactHostFunction::OutputStream,
                ExactBackendAction::Start | ExactBackendAction::Resume,
                None | Some(ExactBackendPendingKind::WriteWaiting),
                BackendEffect::OutputSent { length },
            ) => invocation.prepared_runtime.is_some() && length == invocation.request_units,
            (
                ExactHostFunction::OutputStream,
                ExactBackendAction::Start | ExactBackendAction::Resume,
                None | Some(ExactBackendPendingKind::WriteWaiting),
                BackendEffect::OutputPeerClosed { .. },
            ) => invocation.prepared_runtime.is_some(),
            (
                ExactHostFunction::OutputClosed,
                ExactBackendAction::Start,
                None,
                BackendEffect::OutputCloseObserved { .. },
            ) => invocation.prepared_runtime.is_some(),
            _ => false,
        };
        if !effect_exact {
            return self.reject(ExactLedgerError::InvalidEffect);
        }
        let operation = ExactOperation::BackendLinearized {
            invocation,
            backend: previous_backend,
            continuation,
            effect,
        };
        self.operation = Some(operation);
        let invalid_close_winner =
            output_close_resolution(effect) == Some(OutputCloseResolution::Quarantine);
        if deferred_revoke.is_some() || invalid_close_winner {
            self.quarantined = true;
            return Err(ExactLedgerError::Quarantined);
        }
        Ok(ExactLedgerSnapshot {
            identity: invoking_receipt.identity,
            operation,
        })
    }

    /// Records an unexpected/ambiguous backend return without manufacturing a
    /// token disposition. The exact invoking receipt (including a concurrent
    /// deferred revoke claim) remains stored for fail-stop inspection.
    pub(crate) fn abort_backend_invoke(
        &mut self,
        invoking_receipt: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_runtime_owner_live()?;
        let _ = self.require_backend_return(invoking_receipt)?;
        self.quarantined = true;
        Ok(())
    }

    pub(crate) fn commit_runtime(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendLinearized {
            invocation, effect, ..
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if invocation.prepared_runtime.is_none() {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if matches!(
            effect,
            BackendEffect::InputPeerClosed { .. }
                | BackendEffect::InputPreparedClosed { .. }
                | BackendEffect::OutputPeerClosed { .. }
        ) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if matches!(effect, BackendEffect::OutputCloseObserved { .. })
            && output_close_resolution(effect) != Some(OutputCloseResolution::Commit)
        {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if matches!(effect, BackendEffect::InputReceived { total, cursor } if cursor < total) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.record_runtime_consumed(invocation)?;
        self.operation = None;
        Ok(())
    }

    /// Commits a zero-length stream host call which is satisfied entirely by
    /// the runtime and therefore never crossed a backend linearization point.
    pub(crate) fn commit_runtime_only(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::RuntimePrepared { invocation } = previous.operation else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if invocation.request_units != 0
            || invocation.input_spill_generation.is_some()
            || !matches!(
                invocation.function,
                ExactHostFunction::InputStream | ExactHostFunction::OutputStream
            )
        {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.record_runtime_consumed(invocation)?;
        self.operation = None;
        Ok(())
    }

    /// Consumes the exact runtime peer after the backend observed a close and
    /// the guest-side host call is dropped rather than committed.
    pub(crate) fn drop_runtime_peer(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendLinearized {
            invocation,
            backend,
            effect,
            ..
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        let peer_closed = matches!(
            effect,
            BackendEffect::InputPeerClosed { .. } | BackendEffect::OutputPeerClosed { .. }
        ) || matches!(effect, BackendEffect::InputPreparedClosed { .. })
            && backend.is_none();
        let close_drop = output_close_resolution(effect) == Some(OutputCloseResolution::Drop);
        if !peer_closed && !close_drop {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.record_runtime_consumed(invocation)?;
        self.operation = None;
        Ok(())
    }

    pub(crate) fn claim_backend_residual(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<ExactResidualCancelPlan<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendLinearized {
            invocation,
            backend: Some(backend),
            continuation,
            effect: effect @ BackendEffect::InputPreparedClosed { .. },
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        let claim = self.take_claim(ExactCancelCause::BackendResidual)?;
        let operation = ExactOperation::BackendResidualClaimed {
            invocation,
            backend,
            continuation,
            effect,
            claim,
        };
        self.operation = Some(operation);
        Ok(ExactResidualCancelPlan {
            snapshot: ExactLedgerSnapshot {
                identity: previous.identity,
                operation,
            },
            backend,
            claim,
        })
    }

    pub(crate) fn finish_backend_residual_cancel(
        &mut self,
        plan: ExactResidualCancelPlan<I, T, D, B, R, O, C>,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(plan.snapshot)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendResidualClaimed {
            invocation,
            backend,
            continuation,
            effect,
            claim,
        } = plan.snapshot.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if backend != plan.backend || claim != plan.claim {
            return self.reject(ExactLedgerError::ClaimMismatch);
        }
        self.publish(
            plan.snapshot.identity,
            ExactOperation::BackendLinearized {
                invocation,
                backend: None,
                continuation,
                effect,
            },
        )
    }

    pub(crate) fn commit_input_prefix(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        bytes: u16,
    ) -> Result<Option<ExactInputSpillReceipt<I, T, D, B>>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let (invocation, state) = match previous.operation {
            ExactOperation::BackendLinearized {
                invocation,
                effect: BackendEffect::InputReceived { total, cursor },
                ..
            } => {
                if self.input_spill.is_some() {
                    return self.reject(ExactLedgerError::InvalidTransition);
                }
                (
                    invocation,
                    ExactInputSpillState {
                        generation: invocation.generation,
                        total,
                        cursor,
                    },
                )
            }
            ExactOperation::RuntimePrepared { invocation }
                if invocation.resource == ExactStreamResource::StdinReader
                    && invocation.function == ExactHostFunction::InputStream
                    && self.input_spill.is_some_and(|state| {
                        invocation.input_spill_generation == Some(state.generation)
                    }) =>
            {
                let Some(state) = self.input_spill else {
                    return self.reject(ExactLedgerError::InvalidTransition);
                };
                (invocation, state)
            }
            _ => return self.reject(ExactLedgerError::InvalidTransition),
        };
        let Some(next) = state.cursor.checked_add(bytes) else {
            return self.reject(ExactLedgerError::InvalidEffect);
        };
        if next > state.total || bytes > invocation.request_units {
            return self.reject(ExactLedgerError::InvalidEffect);
        }
        if invocation.prepared_runtime.is_none() {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.record_runtime_consumed(invocation)?;
        self.operation = None;
        if next == state.total {
            self.input_spill = None;
            return Ok(None);
        }
        let state = ExactInputSpillState {
            generation: invocation.generation,
            cursor: next,
            ..state
        };
        self.input_spill = Some(state);
        Ok(Some(ExactInputSpillReceipt {
            identity: previous.identity,
            state,
        }))
    }

    pub(crate) fn attach_input_runtime(
        &mut self,
        receipt: ExactInputSpillReceipt<I, T, D, B>,
        offered_runtime: R,
        request_units: usize,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(receipt.identity)?;
        if self.input_spill != Some(receipt.state)
            || receipt.state.cursor >= receipt.state.total
            || self.operation.is_some()
        {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        self.begin_runtime_inner(
            receipt.identity,
            offered_runtime,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            request_units,
            true,
        )
    }

    pub(crate) fn prepare_input_runtime(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        prepared_runtime: R,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        if self.input_spill.is_none()
            || !matches!(
                previous.operation,
                ExactOperation::RuntimeOffered { invocation }
                    if invocation.resource == ExactStreamResource::StdinReader
                        && invocation.function == ExactHostFunction::InputStream
                        && self.input_spill.is_some_and(|state| {
                            invocation.input_spill_generation == Some(state.generation)
                        })
            )
        {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.prepare_runtime(previous, prepared_runtime)
    }

    pub(crate) fn claim_revoke(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        resource: ExactStreamResource,
    ) -> Result<ExactRevokeDecision<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(identity)?;
        if !resource.revocable_endpoint() {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if resource == ExactStreamResource::StdinReader && self.input_spill.is_some() {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        match self.resources[resource.index()] {
            ResourceLatch::Revoking(_) => return Err(ExactLedgerError::AlreadyRevoking),
            ResourceLatch::Revoked(_) => return Err(ExactLedgerError::AlreadyRevoked),
            ResourceLatch::Live => {}
        }
        let claim = self.take_claim(ExactCancelCause::Revoke)?;
        let cap = ExactResourceRevokePlan {
            identity,
            resource,
            claim,
        };
        let Some(operation) = self.operation else {
            self.resources[resource.index()] = ResourceLatch::Revoking(claim);
            return Ok(ExactRevokeDecision::RevokeCap(cap));
        };
        let snapshot = ExactLedgerSnapshot {
            identity,
            operation,
        };
        if snapshot.resource() != resource {
            self.resources[resource.index()] = ResourceLatch::Revoking(claim);
            return Ok(ExactRevokeDecision::RevokeCap(cap));
        }
        match operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation } => {
                self.resources[resource.index()] = ResourceLatch::Revoking(claim);
                let operation = ExactOperation::BackendCancelled {
                    invocation,
                    continuation: ExactContinuation::None,
                    claim,
                    runtime_cleanup: None,
                };
                self.operation = Some(operation);
                Ok(ExactRevokeDecision::RuntimeOnly {
                    cap,
                    runtime: ExactLedgerSnapshot {
                        identity,
                        operation,
                    },
                })
            }
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation,
            } => {
                self.resources[resource.index()] = ResourceLatch::Revoking(claim);
                let operation = ExactOperation::CancelClaimed {
                    invocation,
                    kind,
                    backend,
                    continuation,
                    claim,
                };
                self.operation = Some(operation);
                let snapshot = ExactLedgerSnapshot {
                    identity,
                    operation,
                };
                Ok(ExactRevokeDecision::Cancel(ExactCancelPlan {
                    snapshot,
                    kind,
                    backend,
                    continuation,
                    claim,
                }))
            }
            ExactOperation::BackendInvoking {
                invocation,
                action,
                previous_backend,
                previous_kind,
                continuation,
                deferred_revoke: None,
            } => {
                self.resources[resource.index()] = ResourceLatch::Revoking(claim);
                self.operation = Some(ExactOperation::BackendInvoking {
                    invocation,
                    action,
                    previous_backend,
                    previous_kind,
                    continuation,
                    deferred_revoke: Some(claim),
                });
                Ok(ExactRevokeDecision::Deferred(ExactDeferredRevoke {
                    identity,
                    resource,
                    claim,
                }))
            }
            ExactOperation::BackendInvoking {
                deferred_revoke: Some(_),
                ..
            }
            | ExactOperation::CancelClaimed { .. } => Err(ExactLedgerError::AlreadyRevoking),
            ExactOperation::BackendCancelled { .. } => Err(ExactLedgerError::AlreadyRevoked),
            ExactOperation::BackendLinearized { .. }
            | ExactOperation::BackendResidualClaimed { .. } => {
                self.reject(ExactLedgerError::InvalidTransition)
            }
        }
    }

    pub(crate) fn finish_cancel(
        &mut self,
        plan: ExactCancelPlan<I, T, D, B, R, O, C>,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(plan.snapshot.identity)?;
        let ExactOperation::CancelClaimed {
            invocation,
            kind,
            backend,
            continuation,
            claim,
        } = plan.snapshot.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if kind != plan.kind
            || backend != plan.backend
            || continuation != plan.continuation
            || claim != plan.claim
        {
            return self.reject(ExactLedgerError::ClaimMismatch);
        }
        let Some(current) = self.operation else {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        };
        let continuation = if current == plan.snapshot.operation {
            continuation
        } else {
            match (plan.snapshot.operation, current) {
                (
                    ExactOperation::CancelClaimed {
                        invocation: planned_invocation,
                        kind: planned_kind,
                        backend: planned_backend,
                        continuation:
                            ExactContinuation::WakeRegistered(planned_token)
                            | ExactContinuation::Signalled(planned_token),
                        claim: planned_claim,
                    },
                    ExactOperation::CancelClaimed {
                        invocation: current_invocation,
                        kind: current_kind,
                        backend: current_backend,
                        continuation: ExactContinuation::Consumed(current_token),
                        claim: current_claim,
                    },
                ) if planned_invocation == current_invocation
                    && planned_kind == current_kind
                    && planned_backend == current_backend
                    && planned_token == current_token
                    && planned_claim == current_claim =>
                {
                    ExactContinuation::Consumed(current_token)
                }
                _ => return self.reject(ExactLedgerError::SnapshotMismatch),
            }
        };
        if claim.cause == ExactCancelCause::Revoke {
            match self.resources[invocation.resource.index()] {
                ResourceLatch::Revoked(current) if current == claim => {}
                _ => return self.reject(ExactLedgerError::ClaimMismatch),
            }
        }
        self.publish(
            plan.snapshot.identity,
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup: None,
            },
        )
    }

    pub(crate) fn finish_cap_revoke(
        &mut self,
        plan: ExactResourceRevokePlan<I, T, D, B>,
    ) -> Result<(), ExactLedgerError> {
        self.require_identity(plan.identity)?;
        if plan.claim.cause != ExactCancelCause::Revoke {
            return self.reject(ExactLedgerError::ClaimMismatch);
        }
        if matches!(
            self.operation,
            Some(ExactOperation::BackendInvoking {
                invocation,
                deferred_revoke: Some(claim),
                ..
            }) if invocation.resource == plan.resource && claim == plan.claim
        ) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        match self.resources[plan.resource.index()] {
            ResourceLatch::Revoking(current) if current == plan.claim => {
                self.resources[plan.resource.index()] = ResourceLatch::Revoked(plan.claim);
                Ok(())
            }
            _ => self.reject(ExactLedgerError::ClaimMismatch),
        }
    }

    pub(crate) fn consume_cancelled(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_snapshot(previous)?;
        let ExactOperation::BackendCancelled {
            invocation,
            continuation,
            claim,
            runtime_cleanup,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if claim.cause == ExactCancelCause::Revoke
            && !matches!(
                self.resources[invocation.resource.index()],
                ResourceLatch::Revoked(current) if current == claim
            )
        {
            return Err(ExactLedgerError::ResourceRevoking);
        }
        if self.has_revoking_resource() {
            return Err(ExactLedgerError::ResourceRevoking);
        }
        let continuation_complete = match claim.cause {
            ExactCancelCause::Revoke => {
                matches!(
                    continuation,
                    ExactContinuation::None | ExactContinuation::Consumed(_)
                ) || (matches!(continuation, ExactContinuation::Cancelled(_))
                    && runtime_cleanup == Some(ExactRuntimeCleanup::Dropped))
            }
            ExactCancelCause::RawFault => matches!(
                continuation,
                ExactContinuation::None
                    | ExactContinuation::Consumed(_)
                    | ExactContinuation::Abandoned(_)
            ),
            ExactCancelCause::FaultFinalizer => matches!(
                continuation,
                ExactContinuation::None
                    | ExactContinuation::Consumed(_)
                    | ExactContinuation::Cancelled(_)
            ),
            ExactCancelCause::BackendResidual => false,
        };
        if !continuation_complete {
            return Err(ExactLedgerError::ContinuationPending);
        }
        if runtime_cleanup.is_none() {
            return Err(ExactLedgerError::InvalidTransition);
        }
        self.record_runtime_consumed(invocation)?;
        self.operation = None;
        Ok(())
    }

    pub(crate) fn finish_continuation_cleanup(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        token: C,
        cleanup: ExactContinuationCleanup,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        let ExactOperation::BackendCancelled {
            invocation,
            continuation,
            claim,
            runtime_cleanup,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        let Some(current) = continuation.token() else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if current != token {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        let disposition_exact = match claim.cause {
            ExactCancelCause::Revoke => {
                matches!(
                    cleanup,
                    ExactContinuationCleanup::Signalled
                        | ExactContinuationCleanup::AlreadySignalled
                ) || (cleanup == ExactContinuationCleanup::Cancelled
                    && self.runtime_owner == RuntimeOwner::Dropped
                    && matches!(
                        self.resources[invocation.resource.index()],
                        ResourceLatch::Revoked(current) if current == claim
                    ))
            }
            ExactCancelCause::RawFault => cleanup == ExactContinuationCleanup::Abandoned,
            ExactCancelCause::FaultFinalizer => cleanup == ExactContinuationCleanup::Cancelled,
            ExactCancelCause::BackendResidual => false,
        };
        if !disposition_exact {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        let source_exact = match (claim.cause, cleanup) {
            (ExactCancelCause::Revoke, ExactContinuationCleanup::Cancelled) => {
                matches!(continuation, ExactContinuation::Signalled(_))
            }
            (
                _,
                ExactContinuationCleanup::Signalled
                | ExactContinuationCleanup::AlreadySignalled
                | ExactContinuationCleanup::Cancelled,
            ) => matches!(
                continuation,
                ExactContinuation::Armed(_)
                    | ExactContinuation::WakeRegistered(_)
                    | ExactContinuation::Signalled(_)
            ),
            (_, ExactContinuationCleanup::Abandoned) => matches!(
                continuation,
                ExactContinuation::Armed(_)
                    | ExactContinuation::WakeRegistered(_)
                    | ExactContinuation::Consumed(_)
            ),
        };
        if !source_exact {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.publish(
            previous.identity,
            ExactOperation::BackendCancelled {
                invocation,
                continuation: match cleanup {
                    ExactContinuationCleanup::Signalled
                    | ExactContinuationCleanup::AlreadySignalled => {
                        ExactContinuation::Signalled(token)
                    }
                    ExactContinuationCleanup::Cancelled => ExactContinuation::Cancelled(token),
                    ExactContinuationCleanup::Abandoned => ExactContinuation::Abandoned(token),
                },
                claim,
                runtime_cleanup,
            },
        )
    }

    pub(crate) fn acknowledge_runtime_cleanup(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        cleanup: ExactRuntimeCleanup,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        let ExactOperation::BackendCancelled {
            invocation,
            continuation,
            claim,
            runtime_cleanup: None,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        let (continuation, cleanup_exact) = match (claim.cause, cleanup, continuation) {
            (
                ExactCancelCause::Revoke,
                ExactRuntimeCleanup::Cancelled,
                ExactContinuation::None | ExactContinuation::Consumed(_),
            ) if self.runtime_owner == RuntimeOwner::Live => (continuation, true),
            (
                ExactCancelCause::Revoke,
                ExactRuntimeCleanup::Dropped,
                ExactContinuation::Cancelled(_),
            ) if self.runtime_owner == RuntimeOwner::Dropped => (continuation, true),
            (
                ExactCancelCause::RawFault,
                ExactRuntimeCleanup::Abandoned,
                ExactContinuation::None
                | ExactContinuation::Consumed(_)
                | ExactContinuation::Abandoned(_),
            ) if self.runtime_owner == RuntimeOwner::Abandoned => (continuation, true),
            (
                ExactCancelCause::FaultFinalizer,
                ExactRuntimeCleanup::Dropped,
                ExactContinuation::None
                | ExactContinuation::Consumed(_)
                | ExactContinuation::Cancelled(_),
            ) if self.runtime_owner == RuntimeOwner::Dropped => (continuation, true),
            _ => (continuation, false),
        };
        if !cleanup_exact {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.publish(
            previous.identity,
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup: Some(cleanup),
            },
        )
    }

    /// Acknowledges that the exact live waiter consumed the cancellation
    /// signal. This is distinct from publishing the signal and must be called
    /// only by the driver after its `InstanceContinuation` returns ready for
    /// the same opaque token.
    pub(crate) fn acknowledge_cancelled_continuation(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
        token: C,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendCancelled {
            invocation,
            continuation: ExactContinuation::Signalled(current),
            claim,
            runtime_cleanup,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if current != token || claim.cause != ExactCancelCause::Revoke {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        self.publish(
            previous.identity,
            ExactOperation::BackendCancelled {
                invocation,
                continuation: ExactContinuation::Consumed(token),
                claim,
                runtime_cleanup,
            },
        )
    }

    /// Takes over a revoke whose physical backend cancellation and Core wake
    /// publication both completed before the runtime owner faulted.
    ///
    /// `Armed` and `WakeRegistered` are deliberately excluded: either can
    /// still overlap the worker which publishes the revoke signal. Only an
    /// exact `Signalled` or already `Consumed` snapshot with the matching
    /// revoked resource latch proves that no backend mutation remains.
    pub(crate) fn abandon_completed_revoke_raw_fault(
        &mut self,
        previous: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_snapshot(previous)?;
        self.require_runtime_owner_live()?;
        let ExactOperation::BackendCancelled {
            invocation,
            continuation,
            claim,
            runtime_cleanup,
        } = previous.operation
        else {
            return self.reject(ExactLedgerError::InvalidTransition);
        };
        if claim.cause != ExactCancelCause::Revoke
            || !matches!(
                self.resources[invocation.resource.index()],
                ResourceLatch::Revoked(current) if current == claim
            )
        {
            return self.reject(ExactLedgerError::ClaimMismatch);
        }
        let (continuation, runtime_cleanup) = match (continuation, runtime_cleanup) {
            (ExactContinuation::Signalled(token), None) => (
                ExactContinuation::Abandoned(token),
                Some(ExactRuntimeCleanup::Abandoned),
            ),
            (ExactContinuation::Consumed(token), None) => (
                ExactContinuation::Consumed(token),
                Some(ExactRuntimeCleanup::Abandoned),
            ),
            // The live driver may already have acknowledged cancellation
            // after consuming Core's signal. Raw fault merely takes over the
            // owner; the exact Cancelled cleanup evidence stays intact.
            (ExactContinuation::Consumed(token), Some(ExactRuntimeCleanup::Cancelled)) => (
                ExactContinuation::Consumed(token),
                Some(ExactRuntimeCleanup::Cancelled),
            ),
            _ => return self.reject(ExactLedgerError::ContinuationPending),
        };
        self.runtime_owner = RuntimeOwner::Abandoned;
        self.publish(
            previous.identity,
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup,
            },
        )
    }

    pub(crate) fn raw_fault(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<ExactCleanupDecision<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(identity)?;
        self.runtime_owner = RuntimeOwner::Abandoned;
        self.cleanup_decision(identity, ExactCancelCause::RawFault, false)
    }

    /// Exact `InstancePayload::drop` acknowledgement. Rust may drop the
    /// driver only between polls, so BackendInvoking is never a valid source;
    /// an irreversible effect likewise remains quarantined for finalization.
    pub(crate) fn acknowledge_runtime_owner_drop(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactLedgerError> {
        self.require_identity(identity)?;
        if self.runtime_owner != RuntimeOwner::Live {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        if matches!(
            self.operation,
            Some(
                ExactOperation::BackendInvoking { .. }
                    | ExactOperation::BackendLinearized { .. }
                    | ExactOperation::BackendResidualClaimed { .. }
            )
        ) {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.input_spill = None;
        self.runtime_owner = RuntimeOwner::Dropped;
        Ok(())
    }

    pub(crate) fn prepare_finalizer(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        success: bool,
    ) -> Result<ExactCleanupDecision<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.cleanup_decision(identity, ExactCancelCause::FaultFinalizer, success)
    }

    pub(crate) fn retire(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactLedgerError> {
        self.require_identity(identity)?;
        if self.operation.is_some() || self.input_spill.is_some() {
            return self.reject(ExactLedgerError::Busy);
        }
        if self.has_revoking_resource() {
            return self.reject(ExactLedgerError::ResourceRevoking);
        }
        if self.runtime_owner == RuntimeOwner::Live {
            return self.reject(ExactLedgerError::InvalidTransition);
        }
        self.identity = None;
        Ok(())
    }

    pub(crate) fn phase(&self) -> ExactLedgerPhase {
        if self.quarantined {
            return ExactLedgerPhase::Quarantined;
        }
        if self.identity.is_none() {
            return ExactLedgerPhase::Retired;
        }
        match self.operation {
            None if self.input_spill.is_some() => ExactLedgerPhase::InputSpill,
            None => ExactLedgerPhase::Idle,
            Some(operation) => ExactLedgerSnapshot {
                identity: self.identity.expect("live ledger identity"),
                operation,
            }
            .phase(),
        }
    }

    pub(crate) fn resource_state(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        resource: ExactStreamResource,
    ) -> Result<ExactResourceState, ExactLedgerError> {
        self.require_identity(identity)?;
        Ok(match self.resources[resource.index()] {
            ResourceLatch::Live => ExactResourceState::Live,
            ResourceLatch::Revoking(_) => ExactResourceState::Revoking,
            ResourceLatch::Revoked(_) => ExactResourceState::Revoked,
        })
    }

    pub(crate) fn terminal_empty(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<bool, ExactLedgerError> {
        self.require_identity(identity)?;
        Ok(self.operation.is_none() && self.input_spill.is_none())
    }

    pub(crate) fn input_spill_remaining(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<u16>, ExactLedgerError> {
        self.require_identity(identity)?;
        Ok(self.input_spill.map(|state| state.total - state.cursor))
    }

    pub(crate) const fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    pub(crate) const fn quarantined_effect(&self) -> Option<BackendEffect> {
        if !self.quarantined {
            return None;
        }
        match self.operation {
            Some(ExactOperation::BackendLinearized { effect, .. }) => Some(effect),
            _ => None,
        }
    }

    /// Read-only fail-stop evidence for an exact identity. Quarantine blocks
    /// every mutating protocol operation, but the trusted acceptance auditor
    /// must still be able to prove which endpoint latch accompanied the
    /// irreversible effect that forced quarantine.
    pub(crate) fn quarantined_resource_state(
        &self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        resource: ExactStreamResource,
    ) -> Option<ExactResourceState> {
        if !self.quarantined || self.identity != Some(identity) {
            return None;
        }
        Some(match self.resources[resource.index()] {
            ResourceLatch::Live => ExactResourceState::Live,
            ResourceLatch::Revoking(_) => ExactResourceState::Revoking,
            ResourceLatch::Revoked(_) => ExactResourceState::Revoked,
        })
    }

    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
    }

    fn cleanup_decision(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        cause: ExactCancelCause,
        success: bool,
    ) -> Result<ExactCleanupDecision<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.require_identity(identity)?;
        if self.has_revoking_resource() {
            self.quarantined = true;
            return Ok(ExactCleanupDecision::Quarantined);
        }
        let Some(operation) = self.operation else {
            if self.input_spill.is_some() {
                if success
                    || (cause != ExactCancelCause::RawFault
                        && self.runtime_owner != RuntimeOwner::Dropped)
                {
                    self.quarantined = true;
                    return Ok(ExactCleanupDecision::Quarantined);
                }
                self.input_spill = None;
            }
            return Ok(ExactCleanupDecision::ReclaimSafe);
        };
        match operation {
            ExactOperation::RuntimeOffered { invocation }
            | ExactOperation::RuntimePrepared { invocation }
                if !success
                    && (cause == ExactCancelCause::RawFault
                        || self.runtime_owner == RuntimeOwner::Dropped) =>
            {
                self.record_runtime_consumed(invocation)?;
                self.operation = None;
                self.input_spill = None;
                Ok(ExactCleanupDecision::ReclaimSafe)
            }
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup: Some(ExactRuntimeCleanup::Abandoned),
            } if !success
                && cause == ExactCancelCause::RawFault
                && self.runtime_owner == RuntimeOwner::Abandoned
                && claim.cause == ExactCancelCause::Revoke
                && matches!(
                    self.resources[invocation.resource.index()],
                    ResourceLatch::Revoked(current) if current == claim
                )
                && matches!(
                    continuation,
                    ExactContinuation::Consumed(_) | ExactContinuation::Abandoned(_)
                ) =>
            {
                self.record_runtime_consumed(invocation)?;
                self.operation = None;
                self.input_spill = None;
                Ok(ExactCleanupDecision::ReclaimSafe)
            }
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup: Some(ExactRuntimeCleanup::Cancelled),
            } if !success
                && cause == ExactCancelCause::RawFault
                && claim.cause == ExactCancelCause::Revoke
                && matches!(
                    self.resources[invocation.resource.index()],
                    ResourceLatch::Revoked(current) if current == claim
                )
                && matches!(
                    continuation,
                    ExactContinuation::None | ExactContinuation::Consumed(_)
                ) =>
            {
                self.record_runtime_consumed(invocation)?;
                self.operation = None;
                self.input_spill = None;
                Ok(ExactCleanupDecision::ReclaimSafe)
            }
            ExactOperation::BackendCancelled {
                invocation,
                continuation,
                claim,
                runtime_cleanup,
                ..
            } if !success
                && claim.cause != ExactCancelCause::Revoke
                && matches!(
                    (claim.cause, runtime_cleanup),
                    (
                        ExactCancelCause::RawFault,
                        Some(ExactRuntimeCleanup::Abandoned)
                    ) | (
                        ExactCancelCause::FaultFinalizer,
                        Some(ExactRuntimeCleanup::Dropped)
                    )
                )
                && matches!(
                    continuation,
                    ExactContinuation::None
                        | ExactContinuation::Consumed(_)
                        | ExactContinuation::Abandoned(_)
                        | ExactContinuation::Cancelled(_)
                ) =>
            {
                self.record_runtime_consumed(invocation)?;
                self.operation = None;
                self.input_spill = None;
                Ok(ExactCleanupDecision::ReclaimSafe)
            }
            ExactOperation::BackendPending {
                invocation,
                kind,
                backend,
                continuation,
            } if !success => {
                let claim = self.take_claim(cause)?;
                let claimed = ExactOperation::CancelClaimed {
                    invocation,
                    kind,
                    backend,
                    continuation,
                    claim,
                };
                self.operation = Some(claimed);
                let snapshot = ExactLedgerSnapshot {
                    identity,
                    operation: claimed,
                };
                Ok(ExactCleanupDecision::Cancel(ExactCancelPlan {
                    snapshot,
                    kind,
                    backend,
                    continuation,
                    claim,
                }))
            }
            _ => {
                self.quarantined = true;
                Ok(ExactCleanupDecision::Quarantined)
            }
        }
    }

    fn take_invocation_generation(&mut self) -> Result<u64, ExactLedgerError> {
        let generation = self.next_invocation;
        let Some(next) = generation.checked_add(1) else {
            return self.reject(ExactLedgerError::GenerationExhausted);
        };
        self.next_invocation = next;
        Ok(generation)
    }

    fn take_claim(
        &mut self,
        cause: ExactCancelCause,
    ) -> Result<ExactCancelClaim, ExactLedgerError> {
        let generation = self.next_claim;
        let Some(next) = generation.checked_add(1) else {
            return self.reject(ExactLedgerError::GenerationExhausted);
        };
        self.next_claim = next;
        Ok(ExactCancelClaim { generation, cause })
    }

    fn require_identity(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactLedgerError> {
        self.check_live()?;
        if identity.control_generation < self.watermark
            || (self.identity.is_none() && identity.control_generation == self.watermark)
        {
            return Err(ExactLedgerError::StaleGeneration);
        }
        if self.identity != Some(identity) || identity.control_generation != self.watermark {
            return self.reject(ExactLedgerError::IdentityMismatch);
        }
        Ok(())
    }

    fn require_snapshot(
        &mut self,
        snapshot: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<(), ExactLedgerError> {
        self.require_identity(snapshot.identity)?;
        if self.operation != Some(snapshot.operation) {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        Ok(())
    }

    /// Backend calls leave the ledger lock with a receipt whose deferred
    /// revoke field is necessarily empty. The only legal concurrent mutation
    /// before return is the unique `None -> Some(claim)` transition made by
    /// `claim_revoke`; callers never obtain a replacement receipt by snapshot.
    fn require_backend_return(
        &mut self,
        receipt: ExactLedgerSnapshot<I, T, D, B, R, O, C>,
    ) -> Result<ExactOperation<R, O, C>, ExactLedgerError> {
        self.require_identity(receipt.identity)?;
        let Some(current) = self.operation else {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        };
        let (
            ExactOperation::BackendInvoking {
                invocation: receipt_invocation,
                action: receipt_action,
                previous_backend: receipt_backend,
                previous_kind: receipt_kind,
                continuation: receipt_continuation,
                deferred_revoke: None,
            },
            ExactOperation::BackendInvoking {
                invocation: current_invocation,
                action: current_action,
                previous_backend: current_backend,
                previous_kind: current_kind,
                continuation: current_continuation,
                deferred_revoke: current_deferred,
            },
        ) = (receipt.operation, current)
        else {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        };
        if receipt_invocation != current_invocation
            || receipt_action != current_action
            || receipt_backend != current_backend
            || receipt_kind != current_kind
            || receipt_continuation != current_continuation
        {
            return self.reject(ExactLedgerError::SnapshotMismatch);
        }
        if let Some(claim) = current_deferred {
            if !matches!(
                self.resources[current_invocation.resource.index()],
                ResourceLatch::Revoking(current) if current == claim
            ) {
                return self.reject(ExactLedgerError::ClaimMismatch);
            }
        }
        Ok(current)
    }

    fn has_revoking_resource(&self) -> bool {
        self.resources
            .iter()
            .any(|resource| matches!(resource, ResourceLatch::Revoking(_)))
    }

    fn consumed_projection(
        &mut self,
        continuation: ExactContinuation<C>,
        token: C,
    ) -> Result<ExactContinuation<C>, ExactLedgerError> {
        match continuation {
            ExactContinuation::WakeRegistered(current) | ExactContinuation::Signalled(current)
                if current == token =>
            {
                Ok(ExactContinuation::Consumed(token))
            }
            ExactContinuation::WakeRegistered(_) | ExactContinuation::Signalled(_) => {
                self.reject(ExactLedgerError::SnapshotMismatch)
            }
            _ => self.reject(ExactLedgerError::InvalidTransition),
        }
    }

    fn record_runtime_consumed(
        &mut self,
        invocation: ExactInvocation<R>,
    ) -> Result<(), ExactLedgerError> {
        let token = invocation
            .prepared_runtime
            .unwrap_or(invocation.offered_runtime);
        if self
            .runtime_watermark
            .is_some_and(|previous| !token.strictly_after(previous))
        {
            return self.reject(ExactLedgerError::TokenDidNotRotate);
        }
        self.runtime_watermark = Some(token);
        Ok(())
    }

    fn publish(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        operation: ExactOperation<R, O, C>,
    ) -> Result<ExactLedgerSnapshot<I, T, D, B, R, O, C>, ExactLedgerError> {
        self.operation = Some(operation);
        Ok(ExactLedgerSnapshot {
            identity,
            operation,
        })
    }

    fn check_live(&self) -> Result<(), ExactLedgerError> {
        if self.quarantined {
            Err(ExactLedgerError::Quarantined)
        } else {
            Ok(())
        }
    }

    fn require_runtime_owner_live(&mut self) -> Result<(), ExactLedgerError> {
        if self.runtime_owner != RuntimeOwner::Live {
            self.reject(ExactLedgerError::InvalidTransition)
        } else {
            Ok(())
        }
    }

    fn reject<U>(&mut self, error: ExactLedgerError) -> Result<U, ExactLedgerError> {
        self.quarantined = true;
        Err(error)
    }
}

/// Aggregate number of cross-turn native authorities allowed for one stable
/// CONTROL incarnation.
///
/// Four entries are permanently reserved for the stdin/stdout endpoint and
/// supervisor capabilities while an incarnation is live. The other four
/// entries cover the largest legal pending branch: an input-spill receipt, a
/// backend or runtime-selector reservation, one scheduler continuation, and
/// its matching wake registration.
pub(crate) const EXACT_NATIVE_LEASE_LIMIT: u8 = 8;

const LEASE_STDIN_READER: u16 = 1 << 0;
const LEASE_STDOUT_WRITER: u16 = 1 << 1;
const LEASE_STDIN_SUPERVISOR: u16 = 1 << 2;
const LEASE_STDOUT_SUPERVISOR: u16 = 1 << 3;
const LEASE_STREAM_CAPS: u16 =
    LEASE_STDIN_READER | LEASE_STDOUT_WRITER | LEASE_STDIN_SUPERVISOR | LEASE_STDOUT_SUPERVISOR;
const LEASE_INPUT_SPILL: u16 = 1 << 4;
const LEASE_BACKEND_OPERATION: u16 = 1 << 5;
const LEASE_STREAM_WAKE: u16 = 1 << 6;
const LEASE_SCHEDULER_CONTINUATION: u16 = 1 << 7;
const LEASE_RUNTIME_SELECTOR_WAIT: u16 = 1 << 8;
const LEASE_RUNTIME_WAKE: u16 = 1 << 9;
const LEASE_TRANSIENTS: u16 = LEASE_INPUT_SPILL
    | LEASE_BACKEND_OPERATION
    | LEASE_STREAM_WAKE
    | LEASE_SCHEDULER_CONTINUATION
    | LEASE_RUNTIME_SELECTOR_WAIT
    | LEASE_RUNTIME_WAKE;

const fn stream_cap_lease(resource: ExactStreamResource) -> u16 {
    match resource {
        ExactStreamResource::StdinReader => LEASE_STDIN_READER,
        ExactStreamResource::StdoutWriter => LEASE_STDOUT_WRITER,
        ExactStreamResource::StdinSupervisor => LEASE_STDIN_SUPERVISOR,
        ExactStreamResource::StdoutSupervisor => LEASE_STDOUT_SUPERVISOR,
    }
}

/// Redacted aggregate lease telemetry. It deliberately contains no CONTROL,
/// task, CSpace, runtime-wait, or continuation identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactNativeLeaseMetrics {
    current: u8,
    peak: u8,
    limit: u8,
}

impl ExactNativeLeaseMetrics {
    pub(crate) const fn current(self) -> u8 {
        self.current
    }

    pub(crate) const fn peak(self) -> u8 {
        self.peak
    }

    pub(crate) const fn limit(self) -> u8 {
        self.limit
    }
}

/// The two pending branches are deliberately exclusive. A backend call is
/// driven by the synchronous host adapter; a runtime selector wait parks the
/// component between runtime turns. Holding both would manufacture a ninth
/// authority and make cancellation ownership ambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactNativeLeaseBranch {
    Quantum,
    Backend,
    RuntimeWait,
}

/// Redacted phase of an exact scheduler-continuation reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactNativeLeaseContinuationPhase {
    Reserved,
    Bound,
    WakeRegistered,
    Signalled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExactNativePendingBranch<W> {
    None,
    Backend,
    RuntimeWait(W),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactNativeContinuationState<C> {
    generation: u64,
    branch: ExactNativeLeaseBranch,
    phase: ExactNativeLeaseContinuationPhase,
    token: Option<C>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExactNativeContinuationTombstone<C> {
    branch: ExactNativeLeaseBranch,
    token: C,
}

/// Copy-only exact receipt for the single continuation reservation. The
/// private generation prevents an old same-valued Core token from replaying
/// after the slot has completed and been reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExactNativeLeaseContinuationReceipt<I, T, D, B, C> {
    identity: ExactInstanceIdentity<I, T, D, B>,
    state: ExactNativeContinuationState<C>,
}

impl<I: Copy, T: Copy, D: Copy, B: Copy, C: Copy>
    ExactNativeLeaseContinuationReceipt<I, T, D, B, C>
{
    pub(crate) const fn branch(self) -> ExactNativeLeaseBranch {
        self.state.branch
    }

    pub(crate) const fn phase(self) -> ExactNativeLeaseContinuationPhase {
        self.state.phase
    }

    pub(crate) const fn token(self) -> Option<C> {
        self.state.token
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactNativeLeaseError {
    Busy,
    StaleGeneration,
    IdentityMismatch,
    LimitExceeded,
    CategoryAlreadyHeld,
    CategoryVacant,
    BranchConflict,
    WaitTokenMismatch,
    StaleReceipt,
    ReceiptMismatch,
    InvalidTransition,
    GenerationExhausted,
    Quarantined,
}

/// Allocation-free aggregate authority ledger for one stable CONTROL slot.
///
/// The operation ledger above proves the semantics of each stream action. This
/// parallel ledger proves that the union of all authorities which survive a
/// kernel turn never exceeds `R`, even when an input spill overlaps work on
/// the opposite stream. Categories are individual bits, so every increment
/// has exactly one matching decrement and failed admission cannot partially
/// mutate the count.
pub(crate) struct ExactNativeLeaseLedger<I, T, D, B, W, C> {
    watermark: u64,
    next_continuation: u64,
    identity: Option<ExactInstanceIdentity<I, T, D, B>>,
    held: u16,
    peak: u8,
    input_spill: Option<ExactInputSpillState>,
    branch: ExactNativePendingBranch<W>,
    continuation: Option<ExactNativeContinuationState<C>>,
    continuation_tombstone: Option<ExactNativeContinuationTombstone<C>>,
    quarantined: bool,
}

impl<I: Copy + Eq, T: Copy + Eq, D: Copy + Eq, B: Copy + Eq, W: Copy + Eq, C: Copy + Eq>
    ExactNativeLeaseLedger<I, T, D, B, W, C>
{
    pub(crate) const fn new() -> Self {
        Self {
            watermark: 0,
            next_continuation: 1,
            identity: None,
            held: 0,
            peak: 0,
            input_spill: None,
            branch: ExactNativePendingBranch::None,
            continuation: None,
            continuation_tombstone: None,
            quarantined: false,
        }
    }

    /// Binds a strictly newer CONTROL incarnation and seeds its four exact
    /// stream-capability authorities.
    pub(crate) fn bind(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.check_live()?;
        if identity.control_generation == 0 || identity.control_generation < self.watermark {
            return Err(ExactNativeLeaseError::StaleGeneration);
        }
        if identity.control_generation == self.watermark {
            return match self.identity {
                None => Err(ExactNativeLeaseError::StaleGeneration),
                Some(current) if current != identity => {
                    self.reject(ExactNativeLeaseError::IdentityMismatch)
                }
                Some(_) => self.reject(ExactNativeLeaseError::Busy),
            };
        }
        if self.identity.is_some() || self.held != 0 {
            return self.reject(ExactNativeLeaseError::Busy);
        }
        self.watermark = identity.control_generation;
        self.identity = Some(identity);
        self.held = LEASE_STREAM_CAPS;
        self.peak = LEASE_STREAM_CAPS.count_ones() as u8;
        self.input_spill = None;
        self.branch = ExactNativePendingBranch::None;
        self.continuation = None;
        self.continuation_tombstone = None;
        Ok(())
    }

    pub(crate) const fn metrics(&self) -> ExactNativeLeaseMetrics {
        ExactNativeLeaseMetrics {
            current: self.held.count_ones() as u8,
            peak: self.peak,
            limit: EXACT_NATIVE_LEASE_LIMIT,
        }
    }

    pub(crate) const fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    /// Sticky fail-stop projection used when the paired operation ledger
    /// detects a same-incarnation invariant violation first.
    pub(crate) fn quarantine(&mut self) {
        self.quarantined = true;
    }

    /// Redacted residue check for target finalization hooks.
    pub(crate) const fn is_retired(&self) -> bool {
        self.identity.is_none() && self.held == 0
    }

    pub(crate) fn release_stream_cap(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        resource: ExactStreamResource,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        self.release(stream_cap_lease(resource))
    }

    /// Drops any still-live base caps after all cross-turn work has been
    /// reconciled. Already-revoked individual caps remain exact no-ops here.
    pub(crate) fn reset_stream_caps(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        revoked_capabilities: u8,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.held & LEASE_TRANSIENTS != 0
            || self.input_spill.is_some()
            || self.branch != ExactNativePendingBranch::None
            || self.continuation.is_some()
        {
            return self.reject(ExactNativeLeaseError::Busy);
        }
        if (self.held & LEASE_STREAM_CAPS).count_ones() as u8 != revoked_capabilities {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        self.held &= !LEASE_STREAM_CAPS;
        Ok(())
    }

    pub(crate) fn retire(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.held != 0
            || self.input_spill.is_some()
            || self.branch != ExactNativePendingBranch::None
            || self.continuation.is_some()
        {
            return self.reject(ExactNativeLeaseError::Busy);
        }
        self.identity = None;
        self.continuation_tombstone = None;
        Ok(())
    }

    /// Accounts the linear spill receipt created by the operation ledger.
    /// Successor receipts rotate monotonically with the consuming runtime
    /// invocation and advance their cursor independently.
    pub(crate) fn begin_input_spill(
        &mut self,
        receipt: &ExactInputSpillReceipt<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(receipt.identity)?;
        if self.input_spill.is_some()
            || receipt.state.total == 0
            || receipt.state.cursor >= receipt.state.total
        {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        self.acquire(LEASE_INPUT_SPILL)?;
        self.input_spill = Some(receipt.state);
        Ok(())
    }

    pub(crate) fn update_input_spill(
        &mut self,
        receipt: &ExactInputSpillReceipt<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(receipt.identity)?;
        let Some(previous) = self.input_spill else {
            return self.reject(ExactNativeLeaseError::CategoryVacant);
        };
        if receipt.state.generation <= previous.generation
            || receipt.state.total != previous.total
            || receipt.state.cursor < previous.cursor
            || receipt.state.cursor >= receipt.state.total
        {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        self.input_spill = Some(receipt.state);
        Ok(())
    }

    pub(crate) fn finish_input_spill(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.input_spill.is_none() {
            return self.reject(ExactNativeLeaseError::CategoryVacant);
        }
        self.release(LEASE_INPUT_SPILL)?;
        self.input_spill = None;
        Ok(())
    }

    pub(crate) fn has_input_spill(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<bool, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(self.input_spill.is_some())
    }

    pub(crate) fn begin_backend(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        self.preflight_acquire(LEASE_BACKEND_OPERATION)?;
        if self.branch != ExactNativePendingBranch::None {
            return self.reject(ExactNativeLeaseError::BranchConflict);
        }
        self.acquire_preflighted(LEASE_BACKEND_OPERATION);
        self.branch = ExactNativePendingBranch::Backend;
        Ok(())
    }

    pub(crate) fn finish_backend(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.branch != ExactNativePendingBranch::Backend || self.continuation.is_some() {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        self.release(LEASE_BACKEND_OPERATION)?;
        self.branch = ExactNativePendingBranch::None;
        Ok(())
    }

    pub(crate) fn has_backend(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<bool, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(self.branch == ExactNativePendingBranch::Backend)
    }

    pub(crate) fn begin_runtime_wait(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        wait: W,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        self.preflight_acquire(LEASE_RUNTIME_SELECTOR_WAIT)?;
        if self.branch != ExactNativePendingBranch::None {
            return self.reject(ExactNativeLeaseError::BranchConflict);
        }
        self.acquire_preflighted(LEASE_RUNTIME_SELECTOR_WAIT);
        self.branch = ExactNativePendingBranch::RuntimeWait(wait);
        Ok(())
    }

    /// Rotates the exact runtime selector token after precisely one resume.
    /// No count changes: the cross-turn selector authority remains live.
    pub(crate) fn rotate_runtime_wait(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        previous: W,
        next: W,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.continuation.is_some() {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        match self.branch {
            ExactNativePendingBranch::RuntimeWait(current) if current == previous => {}
            ExactNativePendingBranch::RuntimeWait(_) => {
                return Err(ExactNativeLeaseError::WaitTokenMismatch)
            }
            _ => return self.reject(ExactNativeLeaseError::BranchConflict),
        }
        if next == previous {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        self.branch = ExactNativePendingBranch::RuntimeWait(next);
        Ok(())
    }

    pub(crate) fn finish_runtime_wait(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        wait: W,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(identity)?;
        if self.continuation.is_some() {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        match self.branch {
            ExactNativePendingBranch::RuntimeWait(current) if current == wait => {}
            ExactNativePendingBranch::RuntimeWait(_) => {
                return Err(ExactNativeLeaseError::WaitTokenMismatch)
            }
            _ => return self.reject(ExactNativeLeaseError::BranchConflict),
        }
        self.release(LEASE_RUNTIME_SELECTOR_WAIT)?;
        self.branch = ExactNativePendingBranch::None;
        Ok(())
    }

    /// Identity-gated exact selector token used only to drive teardown of the
    /// matching runtime registration. It is never included in diagnostics.
    pub(crate) fn runtime_wait(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<W>, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(match self.branch {
            ExactNativePendingBranch::RuntimeWait(wait) => Some(wait),
            ExactNativePendingBranch::None | ExactNativePendingBranch::Backend => None,
        })
    }

    /// Exact terminal residue check. Base stream caps intentionally do not
    /// participate because finalization validates and debits their separate
    /// CSpace reset receipt afterwards.
    pub(crate) fn terminal_empty(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<bool, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(self.held & LEASE_TRANSIENTS == 0
            && self.input_spill.is_none()
            && self.branch == ExactNativePendingBranch::None
            && self.continuation.is_none())
    }

    /// Reserves aggregate capacity before the adapter asks Core to arm its
    /// sole continuation slot. If Core cannot arm, the returned receipt is
    /// cancelled with [`Self::cancel_reserved_continuation`].
    pub(crate) fn reserve_continuation(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        let branch = match self.branch {
            ExactNativePendingBranch::Backend => ExactNativeLeaseBranch::Backend,
            ExactNativePendingBranch::RuntimeWait(_) => ExactNativeLeaseBranch::RuntimeWait,
            ExactNativePendingBranch::None => {
                return self.reject(ExactNativeLeaseError::BranchConflict)
            }
        };
        self.reserve_continuation_inner(identity, branch)
    }

    /// Reserves the ordinary scheduler-yield continuation before Core is
    /// called. Quantum continuations have no host wake registration and their
    /// exact bound receipt is consumed directly when the scheduler runs the
    /// task again. They retain, rather than replace, any backend or runtime-wait
    /// branch whose bounded cleanup turn requested the yield.
    pub(crate) fn reserve_quantum_continuation(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        self.reserve_continuation_inner(identity, ExactNativeLeaseBranch::Quantum)
    }

    fn reserve_continuation_inner(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
        branch: ExactNativeLeaseBranch,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.preflight_acquire(LEASE_SCHEDULER_CONTINUATION)?;
        if self.continuation.is_some() {
            return self.reject(ExactNativeLeaseError::CategoryAlreadyHeld);
        }
        let generation = self.next_continuation;
        let Some(next) = generation.checked_add(1) else {
            return self.reject(ExactNativeLeaseError::GenerationExhausted);
        };
        let state = ExactNativeContinuationState {
            generation,
            branch,
            phase: ExactNativeLeaseContinuationPhase::Reserved,
            token: None,
        };
        self.acquire_preflighted(LEASE_SCHEDULER_CONTINUATION);
        self.next_continuation = next;
        self.continuation = Some(state);
        Ok(ExactNativeLeaseContinuationReceipt { identity, state })
    }

    pub(crate) fn bind_continuation(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        token: C,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.phase != ExactNativeLeaseContinuationPhase::Reserved
            || previous.state.token.is_some()
        {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        let state = ExactNativeContinuationState {
            phase: ExactNativeLeaseContinuationPhase::Bound,
            token: Some(token),
            ..previous.state
        };
        // Core has published a newer live operation, so an older terminal
        // disposition can no longer describe its current continuation record.
        self.continuation_tombstone = None;
        self.continuation = Some(state);
        Ok(ExactNativeLeaseContinuationReceipt {
            identity: previous.identity,
            state,
        })
    }

    pub(crate) fn register_stream_wake(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.branch != ExactNativeLeaseBranch::Backend
            || previous.state.phase != ExactNativeLeaseContinuationPhase::Bound
            || self.branch != ExactNativePendingBranch::Backend
        {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        self.register_wake(previous, LEASE_STREAM_WAKE)
    }

    pub(crate) fn register_runtime_wake(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        wait: W,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.branch != ExactNativeLeaseBranch::RuntimeWait
            || previous.state.phase != ExactNativeLeaseContinuationPhase::Bound
        {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        match self.branch {
            ExactNativePendingBranch::RuntimeWait(current) if current == wait => {}
            ExactNativePendingBranch::RuntimeWait(_) => {
                return Err(ExactNativeLeaseError::WaitTokenMismatch)
            }
            _ => return self.reject(ExactNativeLeaseError::BranchConflict),
        }
        self.register_wake(previous, LEASE_RUNTIME_WAKE)
    }

    /// Records a separately witnessed Core signal. Wake ownership is consumed
    /// here, after the signal callback has returned and outside all ledger and
    /// registry locks.
    pub(crate) fn mark_signalled(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        token: C,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.phase != ExactNativeLeaseContinuationPhase::WakeRegistered
            || previous.state.token != Some(token)
        {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        let Some(wake) = self.wake_bit(previous.state.branch) else {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        };
        self.release(wake)?;
        let state = ExactNativeContinuationState {
            phase: ExactNativeLeaseContinuationPhase::Signalled,
            ..previous.state
        };
        self.continuation = Some(state);
        Ok(ExactNativeLeaseContinuationReceipt {
            identity: previous.identity,
            state,
        })
    }

    /// Consumes Core's exact listener receipt. A wake which raced registration
    /// may still be projected as `WakeRegistered`; in that case this single
    /// transition debits both the wake and continuation authorities.
    pub(crate) fn consume_continuation(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        token: C,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.token != Some(token)
            || !matches!(
                previous.state.phase,
                ExactNativeLeaseContinuationPhase::WakeRegistered
                    | ExactNativeLeaseContinuationPhase::Signalled
            )
        {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        self.release_continuation(previous.state)?;
        self.continuation_tombstone = Some(ExactNativeContinuationTombstone {
            branch: previous.state.branch,
            token,
        });
        Ok(())
    }

    pub(crate) fn consume_quantum_continuation(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        token: C,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.branch != ExactNativeLeaseBranch::Quantum
            || previous.state.phase != ExactNativeLeaseContinuationPhase::Bound
            || previous.state.token != Some(token)
        {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        self.release_continuation(previous.state)?;
        self.continuation_tombstone = Some(ExactNativeContinuationTombstone {
            branch: previous.state.branch,
            token,
        });
        Ok(())
    }

    pub(crate) fn cancel_reserved_continuation(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.phase != ExactNativeLeaseContinuationPhase::Reserved {
            return self.reject(ExactNativeLeaseError::InvalidTransition);
        }
        self.release_continuation(previous.state)
    }

    /// Exact normal-drop cancellation after Core has armed the token.
    pub(crate) fn drop_cancelled_continuation(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        token: C,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        if previous.state.token != Some(token)
            || !matches!(
                previous.state.phase,
                ExactNativeLeaseContinuationPhase::Bound
                    | ExactNativeLeaseContinuationPhase::WakeRegistered
                    | ExactNativeLeaseContinuationPhase::Signalled
            )
        {
            return self.reject(ExactNativeLeaseError::ReceiptMismatch);
        }
        self.release_continuation(previous.state)?;
        self.continuation_tombstone = Some(ExactNativeContinuationTombstone {
            branch: previous.state.branch,
            token,
        });
        Ok(())
    }

    /// Exact raw-fault projection. Core's reclaimer, rather than the abandoned
    /// child stack, supplies this receipt; no untyped global sweep is allowed.
    pub(crate) fn abandon_continuation_raw_fault(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_continuation(previous)?;
        self.release_continuation(previous.state)?;
        if let Some(token) = previous.state.token {
            self.continuation_tombstone = Some(ExactNativeContinuationTombstone {
                branch: previous.state.branch,
                token,
            });
        }
        Ok(())
    }

    pub(crate) fn continuation(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>>, ExactNativeLeaseError>
    {
        self.require_identity(identity)?;
        Ok(self
            .continuation
            .map(|state| ExactNativeLeaseContinuationReceipt { identity, state }))
    }

    /// Exact non-authority projection of Core's current continuation record.
    /// A consumed, cancelled, or fault-abandoned operation no longer contributes
    /// to `current`, but its opaque token remains until Core arms a successor so
    /// raw-fault teardown can validate the complete abandonment receipt.
    pub(crate) fn core_continuation(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<C>, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(self
            .continuation
            .and_then(|continuation| continuation.token)
            .or(self.continuation_tombstone.map(|tombstone| tombstone.token)))
    }

    pub(crate) fn core_continuation_branch(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<Option<ExactNativeLeaseBranch>, ExactNativeLeaseError> {
        self.require_identity(identity)?;
        Ok(self
            .continuation
            .and_then(|continuation| continuation.token.map(|_| continuation.branch))
            .or(self
                .continuation_tombstone
                .map(|tombstone| tombstone.branch)))
    }

    fn register_wake(
        &mut self,
        previous: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
        bit: u16,
    ) -> Result<ExactNativeLeaseContinuationReceipt<I, T, D, B, C>, ExactNativeLeaseError> {
        self.acquire(bit)?;
        let state = ExactNativeContinuationState {
            phase: ExactNativeLeaseContinuationPhase::WakeRegistered,
            ..previous.state
        };
        self.continuation = Some(state);
        Ok(ExactNativeLeaseContinuationReceipt {
            identity: previous.identity,
            state,
        })
    }

    fn release_continuation(
        &mut self,
        state: ExactNativeContinuationState<C>,
    ) -> Result<(), ExactNativeLeaseError> {
        if state.phase == ExactNativeLeaseContinuationPhase::WakeRegistered {
            let Some(wake) = self.wake_bit(state.branch) else {
                return self.reject(ExactNativeLeaseError::InvalidTransition);
            };
            self.release(wake)?;
        }
        self.release(LEASE_SCHEDULER_CONTINUATION)?;
        self.continuation = None;
        Ok(())
    }

    const fn wake_bit(&self, branch: ExactNativeLeaseBranch) -> Option<u16> {
        match branch {
            ExactNativeLeaseBranch::Quantum => None,
            ExactNativeLeaseBranch::Backend => Some(LEASE_STREAM_WAKE),
            ExactNativeLeaseBranch::RuntimeWait => Some(LEASE_RUNTIME_WAKE),
        }
    }

    fn preflight_acquire(&self, bit: u16) -> Result<(), ExactNativeLeaseError> {
        if self.held & bit != 0 {
            return Err(ExactNativeLeaseError::CategoryAlreadyHeld);
        }
        if self.metrics().current >= EXACT_NATIVE_LEASE_LIMIT {
            return Err(ExactNativeLeaseError::LimitExceeded);
        }
        Ok(())
    }

    fn acquire(&mut self, bit: u16) -> Result<(), ExactNativeLeaseError> {
        self.preflight_acquire(bit)?;
        self.acquire_preflighted(bit);
        Ok(())
    }

    fn acquire_preflighted(&mut self, bit: u16) {
        self.held |= bit;
        self.peak = self.peak.max(self.metrics().current);
    }

    fn release(&mut self, bit: u16) -> Result<(), ExactNativeLeaseError> {
        if self.held & bit == 0 {
            return self.reject(ExactNativeLeaseError::CategoryVacant);
        }
        self.held &= !bit;
        Ok(())
    }

    fn require_continuation(
        &mut self,
        receipt: ExactNativeLeaseContinuationReceipt<I, T, D, B, C>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.require_identity(receipt.identity)?;
        match self.continuation {
            Some(current) if receipt.state.generation < current.generation => {
                Err(ExactNativeLeaseError::StaleReceipt)
            }
            None if receipt.state.generation < self.next_continuation => {
                Err(ExactNativeLeaseError::StaleReceipt)
            }
            Some(current) if current == receipt.state => Ok(()),
            _ => self.reject(ExactNativeLeaseError::ReceiptMismatch),
        }
    }

    fn require_identity(
        &mut self,
        identity: ExactInstanceIdentity<I, T, D, B>,
    ) -> Result<(), ExactNativeLeaseError> {
        self.check_live()?;
        if identity.control_generation < self.watermark
            || (self.identity.is_none() && identity.control_generation == self.watermark)
        {
            return Err(ExactNativeLeaseError::StaleGeneration);
        }
        if self.identity != Some(identity) || identity.control_generation != self.watermark {
            return self.reject(ExactNativeLeaseError::IdentityMismatch);
        }
        Ok(())
    }

    fn check_live(&self) -> Result<(), ExactNativeLeaseError> {
        if self.quarantined {
            Err(ExactNativeLeaseError::Quarantined)
        } else {
            Ok(())
        }
    }

    fn reject<U>(&mut self, error: ExactNativeLeaseError) -> Result<U, ExactNativeLeaseError> {
        self.quarantined = true;
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn backend_release_coordinator_never_credits_before_physical_cancel() {
        let stage = Cell::new(0_u8);
        exact_backend_cancel_then_release(
            || {
                assert_eq!(stage.get(), 0);
                stage.set(1);
                Ok::<(), u8>(())
            },
            || {
                assert_eq!(stage.get(), 1);
                stage.set(2);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(stage.get(), 2);

        let cancel_failed_stage = Cell::new(0_u8);
        assert_eq!(
            exact_backend_cancel_then_release(
                || {
                    cancel_failed_stage.set(1);
                    Err::<(), u8>(1)
                },
                || {
                    cancel_failed_stage.set(2);
                    Ok(())
                },
            ),
            Err(1)
        );
        assert_eq!(cancel_failed_stage.get(), 1);

        let release_failed_stage = Cell::new(0_u8);
        assert_eq!(
            exact_backend_cancel_then_release(
                || {
                    release_failed_stage.set(1);
                    Ok::<(), u8>(())
                },
                || {
                    assert_eq!(release_failed_stage.get(), 1);
                    release_failed_stage.set(2);
                    Err(2)
                },
            ),
            Err(2)
        );
        assert_eq!(release_failed_stage.get(), 2);
    }

    #[test]
    fn input_spill_and_output_staging_are_independent_and_bounded() {
        let mut input = InputSpill::new();
        let mut output = OutputStaging::new();
        assert!(input.is_empty());
        assert!(output.is_empty());
        let target = input.receive_target(DRIVER_CHUNK_BYTES).unwrap();
        target[0] = 0x11;
        target[DRIVER_CHUNK_BYTES - 1] = 0x22;
        let staged = output.prepare(DRIVER_CHUNK_BYTES + 1);
        staged[0] = 0xaa;
        staged[DRIVER_CHUNK_BYTES - 1] = 0xbb;

        assert_eq!(input.remaining_prefix(1), &[0x11]);
        assert_eq!(output.prepared()[0], 0xaa);
        assert_eq!(output.prepared()[DRIVER_CHUNK_BYTES - 1], 0xbb);
        assert!(input.consume(1));
        assert_eq!(input.remaining_prefix(DRIVER_CHUNK_BYTES).len(), 1023);
        assert!(input.consume(1023));
        assert!(input.is_empty());
        output.clear();
        assert!(output.is_empty());
        assert!(output.prepared().is_empty());
        assert!(input.receive_target(0).is_none());
        assert!(input.receive_target(DRIVER_CHUNK_BYTES + 1).is_none());
    }

    type TestLedger = ExactOperationLedger<u64, u64, u64, u64, u64, u64, u64>;
    type TestSnapshot = ExactLedgerSnapshot<u64, u64, u64, u64, u64, u64, u64>;
    type TestInputSpillReceipt = ExactInputSpillReceipt<u64, u64, u64, u64>;

    impl ExactRuntimeToken for u64 {
        fn strictly_after(self, previous: Self) -> bool {
            self > previous
        }
    }

    fn exact_identity(generation: u64) -> ExactInstanceIdentity<u64, u64, u64, u64> {
        ExactInstanceIdentity {
            control: (generation << 8) | 1,
            control_generation: generation,
            instance: 0x11,
            task: 0x22,
            domain: 0x33,
            bindings: 0x44,
        }
    }

    fn prepared_operation(
        ledger: &mut TestLedger,
        identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        offered: u64,
        prepared: u64,
        resource: ExactStreamResource,
        function: ExactHostFunction,
        request_units: usize,
    ) -> TestSnapshot {
        let offered = ledger
            .begin_runtime(identity, offered, resource, function, request_units)
            .unwrap();
        ledger.prepare_runtime(offered, prepared).unwrap()
    }

    fn pending_operation(
        ledger: &mut TestLedger,
        identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        runtime: u64,
        backend: u64,
        resource: ExactStreamResource,
        function: ExactHostFunction,
        request_units: usize,
    ) -> TestSnapshot {
        let prepared = prepared_operation(
            ledger,
            identity,
            runtime,
            runtime + 1,
            resource,
            function,
            request_units,
        );
        let kind = match (resource, function) {
            (ExactStreamResource::StdinReader, ExactHostFunction::InputStream) => {
                ExactBackendPendingKind::ReadPrepared
            }
            (ExactStreamResource::StdoutWriter, ExactHostFunction::OutputStream) => {
                ExactBackendPendingKind::WriteWaiting
            }
            (ExactStreamResource::StdinSupervisor, ExactHostFunction::InputClosed) => {
                ExactBackendPendingKind::TerminalWaiting
            }
            _ => panic!("test helper requires a cancellable backend function"),
        };
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        match ledger.backend_pending(invoking, kind, backend).unwrap() {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        }
    }

    fn registered_output_operation(
        ledger: &mut TestLedger,
        identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        runtime: u64,
        backend: u64,
        continuation: u64,
        request_units: usize,
    ) -> TestSnapshot {
        let pending = pending_operation(
            ledger,
            identity,
            runtime,
            backend,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            request_units,
        );
        let armed = ledger.arm_continuation(pending, continuation).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        match ledger
            .finish_register_wake(registering, continuation)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        }
    }

    fn input_spill_receipt(
        ledger: &mut TestLedger,
        identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        runtime: u64,
        backend: u64,
        total: u16,
        prefix: u16,
    ) -> TestInputSpillReceipt {
        let pending = pending_operation(
            ledger,
            identity,
            runtime,
            backend,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            usize::from(prefix),
        );
        let invoking = ledger
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let received = ledger
            .backend_linearized(invoking, BackendEffect::InputReceived { total, cursor: 0 })
            .unwrap();
        ledger
            .commit_input_prefix(received, prefix)
            .unwrap()
            .expect("test spill must retain a nonempty suffix")
    }

    #[test]
    fn exact_ledger_preserves_every_linearization_phase_until_runtime_commit() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(1);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            10,
            20,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            17,
        );
        assert_eq!(pending.phase(), ExactLedgerPhase::BackendPending);
        assert_eq!(pending.backend(), Some(20));
        let armed = ledger.arm_continuation(pending, 30).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let registered = match ledger.finish_register_wake(registering, 30).unwrap() {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        };
        assert_eq!(
            registered.continuation(),
            ExactContinuation::WakeRegistered(30)
        );
        let consumed = ledger.consume_continuation(registered, 30).unwrap();
        let invoking = ledger
            .begin_backend(consumed, ExactBackendAction::Resume)
            .unwrap();
        assert_eq!(invoking.phase(), ExactLedgerPhase::BackendInvoking);
        let linearized = ledger
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 17 })
            .unwrap();
        assert_eq!(linearized.phase(), ExactLedgerPhase::BackendLinearized);
        assert_eq!(
            linearized.effect(),
            Some(BackendEffect::OutputSent { length: 17 })
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::BackendLinearized);
        ledger.commit_runtime(linearized).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Retired);
    }

    #[test]
    fn input_spill_receipt_allows_interleaved_output_and_exact_prefixes() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(2);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            40,
            50,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            99,
        );
        let invoking = ledger
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let linearized = ledger
            .backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: 257,
                    cursor: 0,
                },
            )
            .unwrap();
        let first = ledger
            .commit_input_prefix(linearized, 99)
            .unwrap()
            .expect("158 backend bytes remain irreversible");
        assert_eq!(first.remaining(), 158);
        assert_eq!(ledger.phase(), ExactLedgerPhase::InputSpill);

        let output = prepared_operation(
            &mut ledger,
            identity,
            60,
            61,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            3,
        );
        let invoking = ledger
            .begin_backend(output, ExactBackendAction::Start)
            .unwrap();
        let sent = ledger
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 3 })
            .unwrap();
        ledger.commit_runtime(sent).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::InputSpill);

        let attached = ledger.attach_input_runtime(first, 70, 99).unwrap();
        let prepared = ledger.prepare_input_runtime(attached, 71).unwrap();
        let second = ledger
            .commit_input_prefix(prepared, 99)
            .unwrap()
            .expect("59 backend bytes remain irreversible");
        assert_eq!(second.remaining(), 59);

        let output = prepared_operation(
            &mut ledger,
            identity,
            80,
            81,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            2,
        );
        let invoking = ledger
            .begin_backend(output, ExactBackendAction::Start)
            .unwrap();
        let sent = ledger
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 2 })
            .unwrap();
        ledger.commit_runtime(sent).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::InputSpill);

        let attached = ledger.attach_input_runtime(second, 90, 99).unwrap();
        let prepared = ledger.prepare_input_runtime(attached, 91).unwrap();
        assert_eq!(ledger.commit_input_prefix(prepared, 59).unwrap(), None);
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        assert_eq!(ledger.terminal_empty(identity), Ok(true));
    }

    #[test]
    fn zero_length_prefix_rotates_the_spill_receipt_generation() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(3);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            100,
            110,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            10,
        );
        let invoking = ledger
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let linearized = ledger
            .backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: 10,
                    cursor: 0,
                },
            )
            .unwrap();
        let first = ledger
            .commit_input_prefix(linearized, 0)
            .unwrap()
            .expect("the full spill remains");
        let first_generation = first.state.generation;
        let stale_state = first.state;
        let attached = ledger.attach_input_runtime(first, 120, 0).unwrap();
        let prepared = ledger.prepare_input_runtime(attached, 121).unwrap();
        let second = ledger
            .commit_input_prefix(prepared, 0)
            .unwrap()
            .expect("the full spill still remains");
        assert_eq!(second.remaining(), 10);
        assert!(second.state.generation > first_generation);
        assert_eq!(ledger.phase(), ExactLedgerPhase::InputSpill);
        let stale = ExactInputSpillReceipt {
            identity,
            state: stale_state,
        };
        assert_eq!(
            ledger.attach_input_runtime(stale, 130, 0),
            Err(ExactLedgerError::SnapshotMismatch)
        );
        drop(second);
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn pending_revoke_returns_one_exact_cancel_plan_and_strands_no_slot() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(3);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            70,
            80,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let armed = ledger.arm_continuation(pending, 90).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let registered = match ledger.finish_register_wake(registering, 90).unwrap() {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        };
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("pending backend must require exact cancel, got {other:?}"),
        };
        assert_eq!(plan.backend(), 80);
        assert_eq!(plan.continuation(), ExactContinuation::WakeRegistered(90));
        assert_eq!(plan.claim().cause(), ExactCancelCause::Revoke);
        assert_eq!(
            ledger.claim_revoke(identity, ExactStreamResource::StdoutWriter),
            Err(ExactLedgerError::AlreadyRevoking)
        );
        assert!(!ledger.is_quarantined());
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        assert_eq!(cancelled.phase(), ExactLedgerPhase::BackendCancelled);
        assert_eq!(
            ledger.consume_cancelled(cancelled),
            Err(ExactLedgerError::ContinuationPending)
        );
        let cleaned = ledger
            .finish_continuation_cleanup(cancelled, 90, ExactContinuationCleanup::Signalled)
            .unwrap();
        assert_eq!(
            ledger.consume_cancelled(cleaned),
            Err(ExactLedgerError::ContinuationPending)
        );
        let consumed = ledger
            .acknowledge_cancelled_continuation(cleaned, 90)
            .unwrap();
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(consumed, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        ledger.consume_cancelled(acknowledged).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        assert_eq!(
            ledger.begin_runtime(
                identity,
                100,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                1,
            ),
            Err(ExactLedgerError::ResourceRevoked)
        );
        assert!(!ledger.is_quarantined());
        let _ = registered;
    }

    #[test]
    fn revoke_and_backend_invocation_have_only_two_safe_winners() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(4);
        ledger.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut ledger,
            identity,
            110,
            111,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let _deferred = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Deferred(deferred) => deferred,
            other => panic!("in-flight backend must defer revoke, got {other:?}"),
        };
        let plan = match ledger
            .backend_pending(invoking, ExactBackendPendingKind::WriteWaiting, 120)
            .unwrap()
        {
            ExactBackendReturn::Cancel(plan) => plan,
            ExactBackendReturn::Pending(_) => panic!("deferred revoke must own fresh token"),
        };
        let cap = plan.resource_revoke_plan();
        ledger.finish_cap_revoke(cap).unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        ledger.consume_cancelled(acknowledged).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);

        let mut ledger = TestLedger::new();
        let identity = exact_identity(5);
        ledger.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut ledger,
            identity,
            130,
            131,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let linearized = ledger
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 1 })
            .unwrap();
        assert_eq!(linearized.phase(), ExactLedgerPhase::BackendLinearized);
        assert_eq!(
            ledger.claim_revoke(identity, ExactStreamResource::StdoutWriter),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn raw_fault_and_finalizer_classify_ambiguous_backend_states_fail_closed() {
        let identity = exact_identity(6);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(
            ledger.begin_runtime(
                identity,
                139,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            ),
            Err(ExactLedgerError::InvalidTransition)
        );

        let mut offered_ledger = TestLedger::new();
        offered_ledger.bind(identity).unwrap();
        let offered = offered_ledger
            .begin_runtime(
                identity,
                140,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        assert_eq!(offered.phase(), ExactLedgerPhase::RuntimeOffered);
        assert_eq!(
            offered_ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(offered_ledger.phase(), ExactLedgerPhase::Idle);

        let mut pending_ledger = TestLedger::new();
        pending_ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut pending_ledger,
            identity,
            150,
            160,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            1,
        );
        let plan = match pending_ledger.raw_fault(identity).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("pending raw fault needs exact cancel, got {other:?}"),
        };
        assert_eq!(plan.claim().cause(), ExactCancelCause::RawFault);
        let cancelled = pending_ledger.finish_cancel(plan).unwrap();
        let abandoned = pending_ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Abandoned)
            .unwrap();
        assert_eq!(
            pending_ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(pending_ledger.phase(), ExactLedgerPhase::Idle);
        let _ = (pending, abandoned);

        let mut invoking = TestLedger::new();
        invoking.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut invoking,
            identity,
            170,
            171,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let _ = invoking
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            invoking.raw_fault(identity),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert!(invoking.is_quarantined());

        let mut linearized = TestLedger::new();
        linearized.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut linearized,
            identity,
            180,
            181,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            2,
        );
        let invoking = linearized
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let _ = linearized
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 2 })
            .unwrap();
        assert_eq!(
            linearized.prepare_finalizer(identity, false),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert!(linearized.is_quarantined());
    }

    #[test]
    fn raw_fault_projects_exact_consumed_core_receipt_to_abandoned() {
        let identity = exact_identity(79);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_250, 1_260, 1_270, 2);
        ledger
            .project_consumed_continuation(identity, 1_270)
            .unwrap();
        let plan = match ledger.raw_fault(identity).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("consumed pending operation must cancel, got {other:?}"),
        };
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let abandoned = ledger
            .finish_continuation_cleanup(cancelled, 1_270, ExactContinuationCleanup::Abandoned)
            .unwrap();
        let abandoned = ledger
            .acknowledge_runtime_cleanup(abandoned, ExactRuntimeCleanup::Abandoned)
            .unwrap();
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        let _ = abandoned;
    }

    #[test]
    fn success_finalizer_requires_idle_and_fault_finalizer_can_cancel_pending() {
        let identity = exact_identity(7);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        assert_eq!(
            ledger.prepare_finalizer(identity, true),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );

        let pending = pending_operation(
            &mut ledger,
            identity,
            190,
            200,
            ExactStreamResource::StdinSupervisor,
            ExactHostFunction::InputClosed,
            0,
        );
        let plan = match ledger.prepare_finalizer(identity, false).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("fault finalizer needs terminal cancel, got {other:?}"),
        };
        assert_eq!(plan.claim().cause(), ExactCancelCause::FaultFinalizer);
        assert_eq!(plan.backend(), 200);
        let _ = pending;

        let mut busy = TestLedger::new();
        busy.bind(identity).unwrap();
        let _ = busy
            .begin_runtime(
                identity,
                210,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        assert_eq!(
            busy.prepare_finalizer(identity, true),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert!(busy.is_quarantined());
    }

    #[test]
    fn retired_generation_is_inert_and_cannot_quarantine_replacement() {
        let mut ledger = TestLedger::new();
        let old = exact_identity(8);
        ledger.bind(old).unwrap();
        ledger.acknowledge_runtime_owner_drop(old).unwrap();
        ledger.retire(old).unwrap();
        assert_eq!(ledger.snapshot(old), Err(ExactLedgerError::StaleGeneration));
        assert!(!ledger.is_quarantined());
        let mut replacement = exact_identity(9);
        replacement.instance = 0x55;
        replacement.task = 0x66;
        replacement.domain = 0x77;
        replacement.bindings = 0x88;
        ledger.bind(replacement).unwrap();
        assert_eq!(ledger.snapshot(old), Err(ExactLedgerError::StaleGeneration));
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        assert!(!ledger.is_quarantined());
        let current = ledger
            .begin_runtime(
                replacement,
                220,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        assert_eq!(current.identity(), replacement);
    }

    #[test]
    fn every_current_incarnation_identity_mismatch_sticky_quarantines() {
        for field in 0..4 {
            let mut ledger = TestLedger::new();
            let exact = exact_identity(10);
            ledger.bind(exact).unwrap();
            let mut wrong = exact;
            match field {
                0 => wrong.instance += 1,
                1 => wrong.task += 1,
                2 => wrong.domain += 1,
                _ => wrong.bindings += 1,
            }
            assert_eq!(
                ledger.snapshot(wrong),
                Err(ExactLedgerError::IdentityMismatch)
            );
            assert!(ledger.is_quarantined());
        }
    }

    #[test]
    fn runtime_resource_function_effect_and_continuation_mismatches_quarantine() {
        let identity = exact_identity(11);
        let mut wrong_shape = TestLedger::new();
        wrong_shape.bind(identity).unwrap();
        assert_eq!(
            wrong_shape.begin_runtime(
                identity,
                230,
                ExactStreamResource::StdinReader,
                ExactHostFunction::OutputStream,
                1,
            ),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(wrong_shape.is_quarantined());

        let mut runtime = TestLedger::new();
        runtime.bind(identity).unwrap();
        let offered = runtime
            .begin_runtime(
                identity,
                240,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        assert_eq!(
            runtime.prepare_runtime(offered, 240),
            Err(ExactLedgerError::TokenDidNotRotate)
        );
        assert!(runtime.is_quarantined());

        let mut effect = TestLedger::new();
        effect.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut effect,
            identity,
            250,
            251,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = effect
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            effect
                .backend_linearized(invoking, BackendEffect::InputTerminalObserved { reason: 1 },),
            Err(ExactLedgerError::InvalidEffect)
        );
        assert!(effect.is_quarantined());

        let mut continuation = TestLedger::new();
        continuation.bind(identity).unwrap();
        let pending = pending_operation(
            &mut continuation,
            identity,
            260,
            270,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let armed = continuation.arm_continuation(pending, 280).unwrap();
        let registering = continuation
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        assert_eq!(
            continuation.finish_register_wake(registering, 281),
            Err(ExactLedgerError::SnapshotMismatch)
        );
        assert!(continuation.is_quarantined());
    }

    #[test]
    fn cancellation_claim_aba_is_rejected_before_state_changes() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(12);
        ledger.bind(identity).unwrap();
        let _pending = pending_operation(
            &mut ledger,
            identity,
            290,
            300,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("expected cancel plan, got {other:?}"),
        };
        let forged = ExactCancelPlan {
            claim: ExactCancelClaim {
                generation: plan.claim.generation + 1,
                ..plan.claim
            },
            ..plan
        };
        assert_eq!(
            ledger.finish_cancel(forged),
            Err(ExactLedgerError::ClaimMismatch)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn revoke_during_wake_registration_waits_for_the_exact_backend_return() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(13);
        ledger.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut ledger,
            identity,
            310,
            311,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            1,
        );
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let pending = match ledger
            .backend_pending(invoking, ExactBackendPendingKind::ReadWaiting, 320)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists yet"),
        };
        let armed = ledger.arm_continuation(pending, 330).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let _deferred = match ledger
            .claim_revoke(identity, ExactStreamResource::StdinReader)
            .unwrap()
        {
            ExactRevokeDecision::Deferred(deferred) => deferred,
            other => panic!("register-wake call must defer revoke, got {other:?}"),
        };
        assert_eq!(ledger.phase(), ExactLedgerPhase::BackendInvoking);
        let cancel = match ledger.finish_register_wake(registering, 330) {
            Ok(ExactBackendReturn::Cancel(plan)) => plan,
            other => panic!("registered wake must be cancelled after revoke: {other:?}"),
        };
        assert_eq!(cancel.kind(), ExactBackendPendingKind::ReadWaiting);
        assert_eq!(cancel.continuation().token(), Some(330));
        let cap = cancel.resource_revoke_plan();
        ledger.finish_cap_revoke(cap).unwrap();
        let cancelled = ledger.finish_cancel(cancel).unwrap();
        let cleaned = ledger
            .finish_continuation_cleanup(cancelled, 330, ExactContinuationCleanup::AlreadySignalled)
            .unwrap();
        assert_eq!(
            ledger.consume_cancelled(cleaned),
            Err(ExactLedgerError::ContinuationPending)
        );
        let consumed = ledger
            .acknowledge_cancelled_continuation(cleaned, 330)
            .unwrap();
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(consumed, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        ledger.consume_cancelled(acknowledged).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn real_input_order_waits_then_prepares_and_commits_the_exact_chunk() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(14);
        ledger.bind(identity).unwrap();
        let offered = ledger
            .begin_runtime(
                identity,
                500,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                7,
            )
            .unwrap();
        let starting = ledger
            .begin_backend(offered, ExactBackendAction::Start)
            .unwrap();
        let waiting = match ledger
            .backend_pending(starting, ExactBackendPendingKind::ReadWaiting, 510)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
        };
        let armed = ledger.arm_continuation(waiting, 520).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let registered = match ledger.finish_register_wake(registering, 520).unwrap() {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
        };
        let consumed = ledger.consume_continuation(registered, 520).unwrap();
        let resuming = ledger
            .begin_backend(consumed, ExactBackendAction::Resume)
            .unwrap();
        let prepared_backend = match ledger
            .backend_pending(resuming, ExactBackendPendingKind::ReadPrepared, 511)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
        };
        assert_eq!(prepared_backend.prepared_runtime(), None);
        let prepared_runtime = ledger.prepare_runtime(prepared_backend, 501).unwrap();
        let committing = ledger
            .begin_backend(prepared_runtime, ExactBackendAction::CommitPrepared)
            .unwrap();
        let received = ledger
            .backend_linearized(
                committing,
                BackendEffect::InputReceived {
                    total: 7,
                    cursor: 0,
                },
            )
            .unwrap();
        assert_eq!(ledger.commit_input_prefix(received, 7).unwrap(), None);
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn real_terminal_order_prepares_while_waiting_and_after_immediate_ready() {
        let identity = exact_identity(15);
        let mut waiting = TestLedger::new();
        waiting.bind(identity).unwrap();
        let offered = waiting
            .begin_runtime(
                identity,
                530,
                ExactStreamResource::StdinSupervisor,
                ExactHostFunction::InputClosed,
                0,
            )
            .unwrap();
        let starting = waiting
            .begin_backend(offered, ExactBackendAction::Start)
            .unwrap();
        let pending = match waiting
            .backend_pending(starting, ExactBackendPendingKind::TerminalWaiting, 540)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
        };
        let prepared = waiting.prepare_runtime(pending, 531).unwrap();
        let armed = waiting.arm_continuation(prepared, 550).unwrap();
        let registering = waiting
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let registered = match waiting.finish_register_wake(registering, 550).unwrap() {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
        };
        let consumed = waiting.consume_continuation(registered, 550).unwrap();
        let resuming = waiting
            .begin_backend(consumed, ExactBackendAction::Resume)
            .unwrap();
        let observed = waiting
            .backend_linearized(resuming, BackendEffect::InputTerminalObserved { reason: 0 })
            .unwrap();
        waiting.commit_runtime(observed).unwrap();
        assert_eq!(waiting.phase(), ExactLedgerPhase::Idle);

        let mut immediate = TestLedger::new();
        let identity = exact_identity(16);
        immediate.bind(identity).unwrap();
        let offered = immediate
            .begin_runtime(
                identity,
                560,
                ExactStreamResource::StdinSupervisor,
                ExactHostFunction::InputClosed,
                0,
            )
            .unwrap();
        let starting = immediate
            .begin_backend(offered, ExactBackendAction::Start)
            .unwrap();
        let observed = immediate
            .backend_linearized(starting, BackendEffect::InputTerminalObserved { reason: 1 })
            .unwrap();
        let prepared = immediate.prepare_runtime(observed, 561).unwrap();
        immediate.commit_runtime(prepared).unwrap();
        assert_eq!(immediate.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn deferred_revoke_releases_no_cspace_plan_until_backend_return() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(17);
        ledger.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut ledger,
            identity,
            570,
            571,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let _deferred = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Deferred(deferred) => deferred,
            other => panic!("invoke must defer revoke, got {other:?}"),
        };
        assert_eq!(ledger.phase(), ExactLedgerPhase::BackendInvoking);
        let cancel = match ledger
            .backend_pending(invoking, ExactBackendPendingKind::WriteWaiting, 572)
            .unwrap()
        {
            ExactBackendReturn::Cancel(plan) => plan,
            ExactBackendReturn::Pending(_) => panic!("deferred revoke lost its exact claim"),
        };
        let cap = cancel.resource_revoke_plan();
        assert_eq!(cap.identity(), identity);
        assert_eq!(cap.resource(), ExactStreamResource::StdoutWriter);
    }

    #[test]
    fn deferred_irreversible_effect_is_recorded_before_quarantine() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(18);
        ledger.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut ledger,
            identity,
            580,
            581,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            3,
        );
        let invoking = ledger
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert!(matches!(
            ledger
                .claim_revoke(identity, ExactStreamResource::StdoutWriter)
                .unwrap(),
            ExactRevokeDecision::Deferred(_)
        ));
        let effect = BackendEffect::OutputSent { length: 3 };
        assert_eq!(
            ledger.backend_linearized(invoking, effect),
            Err(ExactLedgerError::Quarantined)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Quarantined);
        assert_eq!(ledger.quarantined_effect(), Some(effect));
        assert_eq!(
            ledger.quarantined_resource_state(identity, ExactStreamResource::StdoutWriter),
            Some(ExactResourceState::Revoking)
        );
    }

    #[test]
    fn incomplete_cap_revoke_blocks_cleanup_retirement_and_cancel_consumption() {
        let identity = exact_identity(19);

        let mut raw_fault = TestLedger::new();
        raw_fault.bind(identity).unwrap();
        assert!(matches!(
            raw_fault
                .claim_revoke(identity, ExactStreamResource::StdinReader)
                .unwrap(),
            ExactRevokeDecision::RevokeCap(_)
        ));
        assert_eq!(
            raw_fault.raw_fault(identity),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert!(raw_fault.is_quarantined());

        let mut success = TestLedger::new();
        success.bind(identity).unwrap();
        assert!(matches!(
            success
                .claim_revoke(identity, ExactStreamResource::StdinReader)
                .unwrap(),
            ExactRevokeDecision::RevokeCap(_)
        ));
        assert_eq!(
            success.prepare_finalizer(identity, true),
            Ok(ExactCleanupDecision::Quarantined)
        );

        let mut retire = TestLedger::new();
        retire.bind(identity).unwrap();
        assert!(matches!(
            retire
                .claim_revoke(identity, ExactStreamResource::StdinReader)
                .unwrap(),
            ExactRevokeDecision::RevokeCap(_)
        ));
        assert_eq!(
            retire.retire(identity),
            Err(ExactLedgerError::ResourceRevoking)
        );

        let mut runtime = TestLedger::new();
        runtime.bind(identity).unwrap();
        let _ = runtime
            .begin_runtime(
                identity,
                590,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                1,
            )
            .unwrap();
        let (cap, cancelled) = match runtime
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::RuntimeOnly { cap, runtime } => (cap, runtime),
            other => panic!("runtime-only revoke expected, got {other:?}"),
        };
        assert_eq!(
            runtime.consume_cancelled(cancelled),
            Err(ExactLedgerError::ResourceRevoking)
        );
        runtime.finish_cap_revoke(cap).unwrap();
        let acknowledged = runtime
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        runtime.consume_cancelled(acknowledged).unwrap();
    }

    #[test]
    fn partial_input_requires_a_fresh_prepared_runtime_for_every_prefix() {
        fn linearized(
            identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        ) -> (TestLedger, TestInputSpillReceipt) {
            let mut ledger = TestLedger::new();
            ledger.bind(identity).unwrap();
            let pending = pending_operation(
                &mut ledger,
                identity,
                600,
                610,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                8,
            );
            let invoking = ledger
                .begin_backend(pending, ExactBackendAction::CommitPrepared)
                .unwrap();
            let received = ledger
                .backend_linearized(
                    invoking,
                    BackendEffect::InputReceived {
                        total: 8,
                        cursor: 0,
                    },
                )
                .unwrap();
            let partial = ledger.commit_input_prefix(received, 3).unwrap().unwrap();
            (ledger, partial)
        }

        let identity = exact_identity(20);
        let (mut missing_prepare, partial) = linearized(identity);
        let attached = missing_prepare
            .attach_input_runtime(partial, 620, 5)
            .unwrap();
        assert_eq!(
            missing_prepare.commit_input_prefix(attached, 1),
            Err(ExactLedgerError::InvalidTransition)
        );

        let identity = exact_identity(21);
        let (mut offered_aba, partial) = linearized(identity);
        assert_eq!(
            offered_aba.attach_input_runtime(partial, 601, 1),
            Err(ExactLedgerError::TokenDidNotRotate)
        );

        let identity = exact_identity(22);
        let (mut prepared_aba, partial) = linearized(identity);
        let attached = prepared_aba.attach_input_runtime(partial, 620, 5).unwrap();
        assert_eq!(
            prepared_aba.prepare_input_runtime(attached, 601),
            Err(ExactLedgerError::TokenDidNotRotate)
        );
    }

    #[test]
    fn current_control_mismatch_and_same_generation_rebind_quarantine() {
        let identity = exact_identity(23);
        let mut mismatch = TestLedger::new();
        mismatch.bind(identity).unwrap();
        let mut wrong = identity;
        wrong.control += 1;
        assert_eq!(
            mismatch.snapshot(wrong),
            Err(ExactLedgerError::IdentityMismatch)
        );
        assert!(mismatch.is_quarantined());

        let mut same = TestLedger::new();
        same.bind(identity).unwrap();
        same.acknowledge_runtime_owner_drop(identity).unwrap();
        same.retire(identity).unwrap();
        assert_eq!(same.bind(identity), Err(ExactLedgerError::StaleGeneration));
        assert!(!same.is_quarantined());

        let mut older = TestLedger::new();
        older.bind(identity).unwrap();
        older.acknowledge_runtime_owner_drop(identity).unwrap();
        older.retire(identity).unwrap();
        assert_eq!(
            older.bind(exact_identity(22)),
            Err(ExactLedgerError::StaleGeneration)
        );
        assert!(!older.is_quarantined());
    }

    #[test]
    fn backend_effect_shape_and_explicit_abort_fail_closed() {
        let identity = exact_identity(24);
        let mut wrong_action = TestLedger::new();
        wrong_action.bind(identity).unwrap();
        let offered = wrong_action
            .begin_runtime(
                identity,
                630,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        let invoking = wrong_action
            .begin_backend(offered, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            wrong_action.backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: 1,
                    cursor: 0,
                },
            ),
            Err(ExactLedgerError::InvalidEffect)
        );

        let mut invalid_receipt = TestLedger::new();
        let identity = exact_identity(25);
        invalid_receipt.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut invalid_receipt,
            identity,
            640,
            641,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputClosed,
            0,
        );
        let invoking = invalid_receipt
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            invalid_receipt.backend_linearized(
                invoking,
                BackendEffect::OutputCloseObserved {
                    requested: 0,
                    outcome: 0,
                    effective: None,
                },
            ),
            Err(ExactLedgerError::InvalidEffect)
        );

        let mut aborted = TestLedger::new();
        let identity = exact_identity(26);
        aborted.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut aborted,
            identity,
            650,
            651,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = aborted
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        aborted.abort_backend_invoke(invoking).unwrap();
        assert!(aborted.is_quarantined());
        assert_eq!(aborted.phase(), ExactLedgerPhase::Quarantined);
    }

    #[test]
    fn prepared_close_requires_exact_residual_cancel_before_runtime_drop() {
        fn prepared_close(
            identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        ) -> (TestLedger, TestSnapshot) {
            let mut ledger = TestLedger::new();
            ledger.bind(identity).unwrap();
            let offered = ledger
                .begin_runtime(
                    identity,
                    700,
                    ExactStreamResource::StdinReader,
                    ExactHostFunction::InputStream,
                    1,
                )
                .unwrap();
            let starting = ledger
                .begin_backend(offered, ExactBackendAction::Start)
                .unwrap();
            let prepared_backend = match ledger
                .backend_pending(starting, ExactBackendPendingKind::ReadPrepared, 710)
                .unwrap()
            {
                ExactBackendReturn::Pending(snapshot) => snapshot,
                ExactBackendReturn::Cancel(_) => panic!("no revoke exists"),
            };
            let prepared_runtime = ledger.prepare_runtime(prepared_backend, 701).unwrap();
            let committing = ledger
                .begin_backend(prepared_runtime, ExactBackendAction::CommitPrepared)
                .unwrap();
            let closed = ledger
                .backend_linearized(committing, BackendEffect::InputPreparedClosed { reason: 1 })
                .unwrap();
            (ledger, closed)
        }

        let identity = exact_identity(28);
        let (mut early_drop, closed) = prepared_close(identity);
        assert_eq!(
            early_drop.drop_runtime_peer(closed),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(early_drop.is_quarantined());

        let identity = exact_identity(29);
        let (mut ledger, closed) = prepared_close(identity);
        let plan = ledger.claim_backend_residual(closed).unwrap();
        assert_eq!(plan.backend(), 710);
        let cancelled = ledger.finish_backend_residual_cancel(plan).unwrap();
        assert_eq!(cancelled.backend(), None);
        ledger.drop_runtime_peer(cancelled).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn output_close_winner_selects_exact_commit_drop_or_quarantine() {
        fn observe(
            generation: u64,
            effect: BackendEffect,
        ) -> (TestLedger, Result<TestSnapshot, ExactLedgerError>) {
            let mut ledger = TestLedger::new();
            let identity = exact_identity(generation);
            ledger.bind(identity).unwrap();
            let prepared = prepared_operation(
                &mut ledger,
                identity,
                720,
                721,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputClosed,
                0,
            );
            let invoking = ledger
                .begin_backend(prepared, ExactBackendAction::Start)
                .unwrap();
            let observed = ledger.backend_linearized(invoking, effect);
            (ledger, observed)
        }

        let matching = BackendEffect::OutputCloseObserved {
            requested: 3,
            outcome: 0,
            effective: Some(3),
        };
        let (mut commit, observed) = observe(31, matching);
        commit.commit_runtime(observed.unwrap()).unwrap();
        assert_eq!(commit.phase(), ExactLedgerPhase::Idle);

        let late_failure = BackendEffect::OutputCloseObserved {
            requested: 0,
            outcome: 1,
            effective: Some(3),
        };
        let (mut drop_peer, observed) = observe(32, late_failure);
        drop_peer.drop_runtime_peer(observed.unwrap()).unwrap();
        assert_eq!(drop_peer.phase(), ExactLedgerPhase::Idle);

        for (generation, effect) in [
            (
                33,
                BackendEffect::OutputCloseObserved {
                    requested: 0,
                    outcome: 2,
                    effective: Some(0),
                },
            ),
            (
                34,
                BackendEffect::OutputCloseObserved {
                    requested: 1,
                    outcome: 1,
                    effective: Some(2),
                },
            ),
        ] {
            let (ledger, observed) = observe(generation, effect);
            assert_eq!(observed, Err(ExactLedgerError::Quarantined));
            assert_eq!(ledger.quarantined_effect(), Some(effect));
        }
    }

    #[test]
    fn partial_runtime_watermark_rejects_non_adjacent_aba() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(35);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            730,
            740,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            9,
        );
        let invoking = ledger
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let received = ledger
            .backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: 9,
                    cursor: 0,
                },
            )
            .unwrap();
        let first = ledger.commit_input_prefix(received, 3).unwrap().unwrap();
        let second_offered = ledger.attach_input_runtime(first, 750, 3).unwrap();
        let second_prepared = ledger.prepare_input_runtime(second_offered, 751).unwrap();
        let second = ledger
            .commit_input_prefix(second_prepared, 3)
            .unwrap()
            .unwrap();
        assert_eq!(
            ledger.attach_input_runtime(second, 731, 3),
            Err(ExactLedgerError::TokenDidNotRotate)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn payload_drop_receipt_allows_fault_finalizer_to_cancel_pending() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(36);
        ledger.bind(identity).unwrap();
        let _pending = pending_operation(
            &mut ledger,
            identity,
            760,
            770,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        let plan = match ledger.prepare_finalizer(identity, false).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("dropped pending runtime needs exact cancel, got {other:?}"),
        };
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let dropped = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Dropped)
            .unwrap();
        assert_eq!(
            ledger.prepare_finalizer(identity, false),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        let _ = dropped;
    }

    #[test]
    fn payload_drop_requires_exact_cancelled_continuation_receipt() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(37);
        ledger.bind(identity).unwrap();
        let pending = pending_operation(
            &mut ledger,
            identity,
            780,
            790,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let armed = ledger.arm_continuation(pending, 800).unwrap();
        let registering = ledger
            .begin_backend(armed, ExactBackendAction::RegisterWake)
            .unwrap();
        let waiting = match ledger.finish_register_wake(registering, 800).unwrap() {
            ExactBackendReturn::Pending(waiting) => waiting,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        };
        assert_eq!(
            waiting.continuation(),
            ExactContinuation::WakeRegistered(800)
        );

        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        let plan = match ledger.prepare_finalizer(identity, false).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("dropped waiter needs exact cancel, got {other:?}"),
        };
        let backend_cancelled = ledger.finish_cancel(plan).unwrap();
        let continuation_cancelled = ledger
            .finish_continuation_cleanup(
                backend_cancelled,
                800,
                ExactContinuationCleanup::Cancelled,
            )
            .unwrap();
        let runtime_dropped = ledger
            .acknowledge_runtime_cleanup(continuation_cancelled, ExactRuntimeCleanup::Dropped)
            .unwrap();
        ledger.consume_cancelled(runtime_dropped).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn payload_drop_takes_over_exact_signalled_revoke() {
        let identity = exact_identity(78);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_220, 1_230, 1_240, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let signalled = ledger
            .finish_continuation_cleanup(cancelled, 1_240, ExactContinuationCleanup::Signalled)
            .unwrap();

        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        let cancelled = ledger
            .finish_continuation_cleanup(signalled, 1_240, ExactContinuationCleanup::Cancelled)
            .unwrap();
        let dropped = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Dropped)
            .unwrap();
        ledger.consume_cancelled(dropped).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        assert_eq!(ledger.terminal_empty(identity), Ok(true));
    }

    #[test]
    fn payload_drop_cannot_take_over_revoke_before_signal_publication() {
        let identity = exact_identity(80);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_280, 1_290, 1_300, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        assert_eq!(
            ledger.finish_continuation_cleanup(
                cancelled,
                1_300,
                ExactContinuationCleanup::Cancelled,
            ),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn raw_fault_takes_over_exact_signalled_completed_revoke() {
        let identity = exact_identity(82);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_310, 1_320, 1_330, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let signalled = ledger
            .finish_continuation_cleanup(cancelled, 1_330, ExactContinuationCleanup::Signalled)
            .unwrap();

        let abandoned = ledger
            .abandon_completed_revoke_raw_fault(signalled)
            .unwrap();
        assert_eq!(
            abandoned.continuation(),
            ExactContinuation::Abandoned(1_330)
        );
        assert_eq!(abandoned.phase(), ExactLedgerPhase::BackendCancelled);
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        assert_eq!(ledger.terminal_empty(identity), Ok(true));
        ledger.retire(identity).unwrap();
    }

    #[test]
    fn raw_fault_takes_over_exact_consumed_completed_revoke() {
        let identity = exact_identity(83);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_340, 1_350, 1_360, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let signalled = ledger
            .finish_continuation_cleanup(cancelled, 1_360, ExactContinuationCleanup::Signalled)
            .unwrap();
        let consumed = ledger
            .acknowledge_cancelled_continuation(signalled, 1_360)
            .unwrap();

        let abandoned = ledger.abandon_completed_revoke_raw_fault(consumed).unwrap();
        assert_eq!(abandoned.continuation(), ExactContinuation::Consumed(1_360));
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        ledger.retire(identity).unwrap();
    }

    #[test]
    fn raw_fault_preserves_acknowledged_cancelled_revoke_cleanup() {
        let identity = exact_identity(85);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_400, 1_410, 1_420, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let signalled = ledger
            .finish_continuation_cleanup(cancelled, 1_420, ExactContinuationCleanup::Signalled)
            .unwrap();
        let consumed = ledger
            .acknowledge_cancelled_continuation(signalled, 1_420)
            .unwrap();
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(consumed, ExactRuntimeCleanup::Cancelled)
            .unwrap();

        let taken_over = ledger
            .abandon_completed_revoke_raw_fault(acknowledged)
            .unwrap();
        assert_eq!(
            taken_over.continuation(),
            ExactContinuation::Consumed(1_420)
        );
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        ledger.retire(identity).unwrap();
    }

    #[test]
    fn raw_fault_completed_revoke_takeover_rejects_pre_signal_state() {
        let identity = exact_identity(84);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_370, 1_380, 1_390, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("registered waiter must cancel, got {other:?}"),
        };
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        assert_eq!(
            cancelled.continuation(),
            ExactContinuation::WakeRegistered(1_390)
        );
        assert_eq!(
            ledger.abandon_completed_revoke_raw_fault(cancelled),
            Err(ExactLedgerError::ContinuationPending)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn runtime_owner_drop_permanently_blocks_driver_progress() {
        let mut idle = TestLedger::new();
        let idle_identity = exact_identity(38);
        idle.bind(idle_identity).unwrap();
        idle.acknowledge_runtime_owner_drop(idle_identity).unwrap();
        assert_eq!(
            idle.begin_runtime(
                idle_identity,
                810,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            ),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(idle.is_quarantined());

        let mut offered = TestLedger::new();
        let offered_identity = exact_identity(39);
        offered.bind(offered_identity).unwrap();
        let snapshot = offered
            .begin_runtime(
                offered_identity,
                820,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        offered
            .acknowledge_runtime_owner_drop(offered_identity)
            .unwrap();
        assert_eq!(
            offered.prepare_runtime(snapshot, 821),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(offered.is_quarantined());
    }

    #[test]
    fn runtime_only_staging_commits_without_a_backend_effect() {
        let mut ledger = TestLedger::new();
        let identity = exact_identity(27);
        ledger.bind(identity).unwrap();
        let offered = ledger
            .begin_runtime(
                identity,
                660,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                0,
            )
            .unwrap();
        let prepared = ledger.prepare_runtime(offered, 661).unwrap();
        ledger.commit_runtime_only(prepared).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn every_close_receipt_remains_correlation_only_until_runtime_commit() {
        let cases = [
            (
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                BackendEffect::InputPeerClosed { reason: 1 },
            ),
            (
                ExactStreamResource::StdinSupervisor,
                ExactHostFunction::InputClosed,
                BackendEffect::InputTerminalObserved { reason: 2 },
            ),
            (
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputClosed,
                BackendEffect::OutputCloseObserved {
                    requested: 0,
                    outcome: 1,
                    effective: Some(3),
                },
            ),
        ];
        for (index, (resource, function, effect)) in cases.into_iter().enumerate() {
            let mut ledger = TestLedger::new();
            let identity = exact_identity(20 + index as u64);
            ledger.bind(identity).unwrap();
            let request_units = usize::from(matches!(
                function,
                ExactHostFunction::InputStream | ExactHostFunction::OutputStream
            ));
            let prepared = prepared_operation(
                &mut ledger,
                identity,
                340 + index as u64 * 10,
                341 + index as u64 * 10,
                resource,
                function,
                request_units,
            );
            let invoking = ledger
                .begin_backend(prepared, ExactBackendAction::Start)
                .unwrap();
            let linearized = ledger.backend_linearized(invoking, effect).unwrap();
            assert_eq!(linearized.effect(), Some(effect));
            assert_eq!(linearized.function(), function);
            if matches!(effect, BackendEffect::InputPeerClosed { .. })
                || output_close_resolution(effect) == Some(OutputCloseResolution::Drop)
            {
                ledger.drop_runtime_peer(linearized).unwrap();
            } else {
                ledger.commit_runtime(linearized).unwrap();
            }
            assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        }
    }

    #[test]
    fn idle_and_runtime_only_revoke_require_cspace_confirmation() {
        let identity = exact_identity(30);
        let mut idle = TestLedger::new();
        idle.bind(identity).unwrap();
        assert_eq!(
            idle.resource_state(identity, ExactStreamResource::StdinReader),
            Ok(ExactResourceState::Live)
        );
        let cap = match idle
            .claim_revoke(identity, ExactStreamResource::StdinReader)
            .unwrap()
        {
            ExactRevokeDecision::RevokeCap(cap) => cap,
            other => panic!("idle resource needs only CSpace revoke, got {other:?}"),
        };
        assert_eq!(
            idle.resource_state(identity, ExactStreamResource::StdinReader),
            Ok(ExactResourceState::Revoking)
        );
        assert_eq!(
            idle.claim_revoke(identity, ExactStreamResource::StdinReader),
            Err(ExactLedgerError::AlreadyRevoking)
        );
        idle.finish_cap_revoke(cap).unwrap();
        assert_eq!(
            idle.resource_state(identity, ExactStreamResource::StdinReader),
            Ok(ExactResourceState::Revoked)
        );
        assert_eq!(
            idle.claim_revoke(identity, ExactStreamResource::StdinReader),
            Err(ExactLedgerError::AlreadyRevoked)
        );
        assert!(!idle.is_quarantined());

        let mut supervisor = TestLedger::new();
        supervisor.bind(identity).unwrap();
        assert_eq!(
            supervisor.claim_revoke(identity, ExactStreamResource::StdinSupervisor),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(supervisor.is_quarantined());

        let mut runtime = TestLedger::new();
        runtime.bind(identity).unwrap();
        let _offered = runtime
            .begin_runtime(
                identity,
                400,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                1,
            )
            .unwrap();
        let (cap, cancelled) = match runtime
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::RuntimeOnly { cap, runtime } => (cap, runtime),
            other => panic!("runtime-only operation needs no backend cancel, got {other:?}"),
        };
        assert_eq!(cancelled.phase(), ExactLedgerPhase::BackendCancelled);
        runtime.finish_cap_revoke(cap).unwrap();
        let acknowledged = runtime
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        runtime.consume_cancelled(acknowledged).unwrap();
        assert_eq!(runtime.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn request_units_reject_oversized_streams_and_nonzero_close_calls() {
        let identity = exact_identity(40);
        let mut bounded = TestLedger::new();
        bounded.bind(identity).unwrap();
        let maximum = bounded
            .begin_runtime(
                identity,
                900,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                DRIVER_CHUNK_BYTES,
            )
            .unwrap();
        assert_eq!(maximum.request_units(), DRIVER_CHUNK_BYTES as u16);

        let mut oversized = TestLedger::new();
        oversized.bind(identity).unwrap();
        assert_eq!(
            oversized.begin_runtime(
                identity,
                910,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                DRIVER_CHUNK_BYTES + 1,
            ),
            Err(ExactLedgerError::InvalidEffect)
        );
        assert!(oversized.is_quarantined());

        let mut nonzero_close = TestLedger::new();
        nonzero_close.bind(identity).unwrap();
        assert_eq!(
            nonzero_close.begin_runtime(
                identity,
                920,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputClosed,
                1,
            ),
            Err(ExactLedgerError::InvalidEffect)
        );
        assert!(nonzero_close.is_quarantined());
    }

    #[test]
    fn backend_batches_are_chunk_bounded_and_output_matches_the_exact_request() {
        let identity = exact_identity(41);
        let mut input_batch = TestLedger::new();
        input_batch.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut input_batch,
            identity,
            930,
            931,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            4,
        );
        let invoking = input_batch
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let pending = match input_batch
            .backend_pending(invoking, ExactBackendPendingKind::ReadPrepared, 932)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        };
        let invoking = input_batch
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let received = input_batch
            .backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: DRIVER_CHUNK_BYTES as u16,
                    cursor: 0,
                },
            )
            .unwrap();
        let residual = input_batch
            .commit_input_prefix(received, 4)
            .unwrap()
            .expect("the backend batch must retain its 1020-byte spill");
        assert_eq!(residual.remaining(), (DRIVER_CHUNK_BYTES - 4) as u16);
        assert_eq!(input_batch.phase(), ExactLedgerPhase::InputSpill);

        let mut input_overflow = TestLedger::new();
        input_overflow.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut input_overflow,
            identity,
            933,
            934,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            4,
        );
        let invoking = input_overflow
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let pending = match input_overflow
            .backend_pending(invoking, ExactBackendPendingKind::ReadPrepared, 935)
            .unwrap()
        {
            ExactBackendReturn::Pending(snapshot) => snapshot,
            ExactBackendReturn::Cancel(_) => panic!("no revoke was claimed"),
        };
        let invoking = input_overflow
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        assert_eq!(
            input_overflow.backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: DRIVER_CHUNK_BYTES as u16 + 1,
                    cursor: 0,
                },
            ),
            Err(ExactLedgerError::InvalidEffect)
        );

        let mut output_mismatch = TestLedger::new();
        output_mismatch.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut output_mismatch,
            identity,
            940,
            941,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            4,
        );
        let invoking = output_mismatch
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            output_mismatch.backend_linearized(invoking, BackendEffect::OutputSent { length: 3 }),
            Err(ExactLedgerError::InvalidEffect)
        );

        let mut exact_output = TestLedger::new();
        exact_output.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut exact_output,
            identity,
            950,
            951,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            4,
        );
        let invoking = exact_output
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let sent = exact_output
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 4 })
            .unwrap();
        exact_output.commit_runtime(sent).unwrap();
        assert_eq!(exact_output.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn every_attached_input_runtime_rebinds_its_request_units() {
        fn residual(
            identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        ) -> (TestLedger, TestInputSpillReceipt) {
            let mut ledger = TestLedger::new();
            ledger.bind(identity).unwrap();
            let pending = pending_operation(
                &mut ledger,
                identity,
                960,
                970,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                8,
            );
            let invoking = ledger
                .begin_backend(pending, ExactBackendAction::CommitPrepared)
                .unwrap();
            let received = ledger
                .backend_linearized(
                    invoking,
                    BackendEffect::InputReceived {
                        total: 8,
                        cursor: 0,
                    },
                )
                .unwrap();
            let residual = ledger.commit_input_prefix(received, 3).unwrap().unwrap();
            (ledger, residual)
        }

        let identity = exact_identity(42);
        let (mut exact, exact_residual) = residual(identity);
        let attached = exact.attach_input_runtime(exact_residual, 980, 5).unwrap();
        assert_eq!(attached.request_units(), 5);

        let (mut remaining_overflow, remaining_residual) = residual(identity);
        let attached = remaining_overflow
            .attach_input_runtime(remaining_residual, 980, 6)
            .unwrap();
        assert_eq!(attached.request_units(), 6);
        let prepared = remaining_overflow
            .prepare_input_runtime(attached, 981)
            .unwrap();
        assert_eq!(
            remaining_overflow.commit_input_prefix(prepared, 5).unwrap(),
            None
        );

        let (mut chunk_overflow, chunk_residual) = residual(identity);
        assert_eq!(
            chunk_overflow.attach_input_runtime(chunk_residual, 980, DRIVER_CHUNK_BYTES + 1,),
            Err(ExactLedgerError::InvalidEffect)
        );
    }

    #[test]
    fn runtime_only_commit_is_exactly_a_zero_unit_stream_event() {
        let identity = exact_identity(43);
        let mut nonzero_stream = TestLedger::new();
        nonzero_stream.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut nonzero_stream,
            identity,
            990,
            991,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            1,
        );
        assert_eq!(
            nonzero_stream.commit_runtime_only(prepared),
            Err(ExactLedgerError::InvalidTransition)
        );

        let mut close = TestLedger::new();
        close.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut close,
            identity,
            1_000,
            1_001,
            ExactStreamResource::StdinSupervisor,
            ExactHostFunction::InputClosed,
            0,
        );
        assert_eq!(
            close.commit_runtime_only(prepared),
            Err(ExactLedgerError::InvalidTransition)
        );

        let mut zero_stream = TestLedger::new();
        zero_stream.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut zero_stream,
            identity,
            1_010,
            1_011,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            0,
        );
        zero_stream.commit_runtime_only(prepared).unwrap();
        assert_eq!(zero_stream.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn prepared_reader_tokens_cannot_arm_scheduler_continuations() {
        let identity = exact_identity(44);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let prepared = pending_operation(
            &mut ledger,
            identity,
            1_020,
            1_030,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            8,
        );
        assert_eq!(
            prepared.pending_kind(),
            Some(ExactBackendPendingKind::ReadPrepared)
        );
        assert_eq!(
            ledger.arm_continuation(prepared, 1_040),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn core_consumed_before_revoke_projects_through_the_exact_cancel_claim() {
        let identity = exact_identity(45);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let registered = registered_output_operation(&mut ledger, identity, 1_050, 1_060, 1_070, 4);
        // Core has already returned this exact typed receipt to the task, but
        // the SYSTEM ledger must remain WakeRegistered until that receipt is
        // projected under its own lock.
        let typed_consumed_receipt = 1_070;
        assert_eq!(
            registered.continuation(),
            ExactContinuation::WakeRegistered(typed_consumed_receipt)
        );
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("pending operation must cancel, got {other:?}"),
        };
        assert_eq!(
            plan.continuation(),
            ExactContinuation::WakeRegistered(typed_consumed_receipt)
        );
        let consumed = ledger
            .project_consumed_continuation(identity, typed_consumed_receipt)
            .unwrap();
        assert_eq!(
            consumed.continuation(),
            ExactContinuation::Consumed(typed_consumed_receipt)
        );
        ledger
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        assert_eq!(
            cancelled.continuation(),
            ExactContinuation::Consumed(typed_consumed_receipt)
        );
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        ledger.consume_cancelled(acknowledged).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn typed_consumed_projection_accepts_pending_and_signalled_cancelled_states() {
        let identity = exact_identity(46);
        let mut pending = TestLedger::new();
        pending.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut pending, identity, 1_080, 1_090, 1_100, 2);
        let consumed = pending
            .project_consumed_continuation(identity, 1_100)
            .unwrap();
        let invoking = pending
            .begin_backend(consumed, ExactBackendAction::Resume)
            .unwrap();
        assert_eq!(invoking.phase(), ExactLedgerPhase::BackendInvoking);

        let mut cancelled = TestLedger::new();
        cancelled.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut cancelled, identity, 1_110, 1_120, 1_130, 2);
        let plan = match cancelled
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("pending operation must cancel, got {other:?}"),
        };
        cancelled
            .finish_cap_revoke(plan.resource_revoke_plan())
            .unwrap();
        let backend_cancelled = cancelled.finish_cancel(plan).unwrap();
        let signalled = cancelled
            .finish_continuation_cleanup(
                backend_cancelled,
                1_130,
                ExactContinuationCleanup::Signalled,
            )
            .unwrap();
        let consumed = cancelled
            .project_consumed_continuation(identity, 1_130)
            .unwrap();
        assert_eq!(consumed.continuation(), ExactContinuation::Consumed(1_130));
        assert_ne!(signalled, consumed);
        let acknowledged = cancelled
            .acknowledge_runtime_cleanup(consumed, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        cancelled.consume_cancelled(acknowledged).unwrap();
    }

    #[test]
    fn finish_cancel_rejects_every_delta_except_exact_typed_consumption() {
        let identity = exact_identity(47);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _registered =
            registered_output_operation(&mut ledger, identity, 1_140, 1_150, 1_160, 2);
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("pending operation must cancel, got {other:?}"),
        };
        let Some(ExactOperation::CancelClaimed {
            invocation,
            kind,
            backend,
            claim,
            ..
        }) = ledger.operation
        else {
            panic!("cancel claim must remain published");
        };
        ledger.operation = Some(ExactOperation::CancelClaimed {
            invocation,
            kind,
            backend,
            continuation: ExactContinuation::Consumed(1_161),
            claim,
        });
        assert_eq!(
            ledger.finish_cancel(plan),
            Err(ExactLedgerError::SnapshotMismatch)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn revoke_runtime_ack_requires_a_live_owner() {
        let identity = exact_identity(48);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _offered = ledger
            .begin_runtime(
                identity,
                1_170,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                2,
            )
            .unwrap();
        let (cap, cancelled) = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::RuntimeOnly { cap, runtime } => (cap, runtime),
            other => panic!("runtime-only operation must cancel, got {other:?}"),
        };
        ledger.finish_cap_revoke(cap).unwrap();
        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        assert_eq!(
            ledger.acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn raw_fault_can_finish_a_fully_acknowledged_live_revoke() {
        let identity = exact_identity(49);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let _offered = ledger
            .begin_runtime(
                identity,
                1_180,
                ExactStreamResource::StdoutWriter,
                ExactHostFunction::OutputStream,
                2,
            )
            .unwrap();
        let (cap, cancelled) = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::RuntimeOnly { cap, runtime } => (cap, runtime),
            other => panic!("runtime-only operation must cancel, got {other:?}"),
        };
        ledger.finish_cap_revoke(cap).unwrap();
        let acknowledged = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        assert_eq!(acknowledged.phase(), ExactLedgerPhase::BackendCancelled);
        assert_eq!(
            ledger.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
        ledger.retire(identity).unwrap();
    }

    #[test]
    fn retirement_requires_owner_disposition_and_bind_restores_live_owner() {
        let identity = exact_identity(50);
        let mut live = TestLedger::new();
        live.bind(identity).unwrap();
        assert_eq!(
            live.retire(identity),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert!(live.is_quarantined());

        let mut recycled = TestLedger::new();
        recycled.bind(identity).unwrap();
        assert_eq!(
            recycled.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        recycled.retire(identity).unwrap();
        let replacement = exact_identity(51);
        recycled.bind(replacement).unwrap();
        let offered = recycled
            .begin_runtime(
                replacement,
                1_190,
                ExactStreamResource::StdinReader,
                ExactHostFunction::InputStream,
                1,
            )
            .unwrap();
        assert_eq!(offered.phase(), ExactLedgerPhase::RuntimeOffered);
    }

    #[test]
    fn invoking_and_linearized_revoke_fault_races_fail_closed() {
        let identity = exact_identity(52);

        let mut invoking_revoke = TestLedger::new();
        invoking_revoke.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut invoking_revoke,
            identity,
            1_200,
            1_201,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = invoking_revoke
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert!(matches!(
            invoking_revoke
                .claim_revoke(identity, ExactStreamResource::StdoutWriter)
                .unwrap(),
            ExactRevokeDecision::Deferred(_)
        ));
        assert_eq!(invoking_revoke.phase(), ExactLedgerPhase::BackendInvoking);
        assert_eq!(
            invoking_revoke.resource_state(identity, ExactStreamResource::StdoutWriter),
            Ok(ExactResourceState::Revoking)
        );
        let effect = BackendEffect::OutputSent { length: 1 };
        assert_eq!(
            invoking_revoke.backend_linearized(invoking, effect),
            Err(ExactLedgerError::Quarantined)
        );
        assert_eq!(invoking_revoke.quarantined_effect(), Some(effect));

        let mut invoking_fault = TestLedger::new();
        invoking_fault.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut invoking_fault,
            identity,
            1_210,
            1_211,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let _invoking = invoking_fault
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        assert_eq!(
            invoking_fault.raw_fault(identity),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert!(invoking_fault.is_quarantined());

        let mut linearized_revoke = TestLedger::new();
        linearized_revoke.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut linearized_revoke,
            identity,
            1_220,
            1_221,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = linearized_revoke
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let effect = BackendEffect::OutputSent { length: 1 };
        let _linearized = linearized_revoke
            .backend_linearized(invoking, effect)
            .unwrap();
        assert_eq!(
            linearized_revoke.claim_revoke(identity, ExactStreamResource::StdoutWriter),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert_eq!(linearized_revoke.quarantined_effect(), Some(effect));

        let mut linearized_fault = TestLedger::new();
        linearized_fault.bind(identity).unwrap();
        let prepared = prepared_operation(
            &mut linearized_fault,
            identity,
            1_230,
            1_231,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = linearized_fault
            .begin_backend(prepared, ExactBackendAction::Start)
            .unwrap();
        let effect = BackendEffect::OutputSent { length: 1 };
        let _linearized = linearized_fault
            .backend_linearized(invoking, effect)
            .unwrap();
        assert_eq!(
            linearized_fault.raw_fault(identity),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert_eq!(linearized_fault.quarantined_effect(), Some(effect));
    }

    #[test]
    fn retired_and_restarted_stale_events_never_consume_or_pollute_replacement() {
        let mut ledger = TestLedger::new();
        let old = exact_identity(53);
        ledger.bind(old).unwrap();
        ledger.acknowledge_runtime_owner_drop(old).unwrap();
        ledger.retire(old).unwrap();
        assert_eq!(ledger.snapshot(old), Err(ExactLedgerError::StaleGeneration));
        assert_eq!(ledger.bind(old), Err(ExactLedgerError::StaleGeneration));
        assert!(!ledger.is_quarantined());

        let mut replacement = exact_identity(54);
        replacement.instance = 0x5511;
        replacement.task = 0x6622;
        replacement.domain = 0x7733;
        replacement.bindings = 0x8844;
        ledger.bind(replacement).unwrap();
        let registered =
            registered_output_operation(&mut ledger, replacement, 1_240, 1_250, 1_260, 2);
        assert_eq!(
            registered.continuation(),
            ExactContinuation::WakeRegistered(1_260)
        );

        assert_eq!(
            ledger.project_consumed_continuation(old, 1_260),
            Err(ExactLedgerError::StaleGeneration)
        );
        assert_eq!(
            ledger.claim_revoke(old, ExactStreamResource::StdoutWriter),
            Err(ExactLedgerError::StaleGeneration)
        );
        assert_eq!(
            ledger.raw_fault(old),
            Err(ExactLedgerError::StaleGeneration)
        );
        assert_eq!(ledger.snapshot(replacement), Ok(Some(registered)));
        assert_eq!(
            ledger.resource_state(replacement, ExactStreamResource::StdoutWriter),
            Ok(ExactResourceState::Live)
        );
        assert!(!ledger.is_quarantined());

        let consumed = ledger
            .project_consumed_continuation(replacement, 1_260)
            .unwrap();
        let invoking = ledger
            .begin_backend(consumed, ExactBackendAction::Resume)
            .unwrap();
        let sent = ledger
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 2 })
            .unwrap();
        ledger.commit_runtime(sent).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::Idle);
    }

    #[test]
    fn spill_blocks_success_and_retirement_but_owner_drop_discards_it_exactly() {
        let identity = exact_identity(55);
        let mut success = TestLedger::new();
        success.bind(identity).unwrap();
        let receipt = input_spill_receipt(&mut success, identity, 1_300, 1_310, 257, 99);
        assert_eq!(receipt.remaining(), 158);
        assert_eq!(success.terminal_empty(identity), Ok(false));
        assert_eq!(
            success.prepare_finalizer(identity, true),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert_eq!(
            success.input_spill.map(|state| state.total - state.cursor),
            Some(158)
        );

        let mut retire = TestLedger::new();
        retire.bind(identity).unwrap();
        let _receipt = input_spill_receipt(&mut retire, identity, 1_320, 1_330, 257, 99);
        assert_eq!(retire.retire(identity), Err(ExactLedgerError::Busy));
        assert_eq!(
            retire.input_spill.map(|state| state.total - state.cursor),
            Some(158)
        );

        let mut dropped = TestLedger::new();
        dropped.bind(identity).unwrap();
        let receipt = input_spill_receipt(&mut dropped, identity, 1_340, 1_350, 257, 99);
        drop(receipt);
        dropped.acknowledge_runtime_owner_drop(identity).unwrap();
        assert_eq!(dropped.terminal_empty(identity), Ok(true));
        assert_eq!(
            dropped.prepare_finalizer(identity, false),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        dropped.retire(identity).unwrap();
        assert_eq!(dropped.phase(), ExactLedgerPhase::Retired);
    }

    #[test]
    fn stdout_revoke_preserves_exact_spill_until_payload_owner_drop() {
        let identity = exact_identity(56);
        let mut ledger = TestLedger::new();
        ledger.bind(identity).unwrap();
        let receipt = input_spill_receipt(&mut ledger, identity, 1_400, 1_410, 767, 594);
        assert_eq!(receipt.remaining(), 173);
        let _pending = pending_operation(
            &mut ledger,
            identity,
            1_420,
            1_430,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let plan = match ledger
            .claim_revoke(identity, ExactStreamResource::StdoutWriter)
            .unwrap()
        {
            ExactRevokeDecision::Cancel(plan) => plan,
            other => panic!("pending stdout revoke expected, got {other:?}"),
        };
        let cap = plan.resource_revoke_plan();
        ledger.finish_cap_revoke(cap).unwrap();
        let cancelled = ledger.finish_cancel(plan).unwrap();
        let cancelled = ledger
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Cancelled)
            .unwrap();
        ledger.consume_cancelled(cancelled).unwrap();
        assert_eq!(ledger.phase(), ExactLedgerPhase::InputSpill);
        assert_eq!(ledger.input_spill_remaining(identity), Ok(Some(173)));

        drop(receipt);
        ledger.acknowledge_runtime_owner_drop(identity).unwrap();
        assert_eq!(ledger.input_spill_remaining(identity), Ok(None));
        assert_eq!(
            ledger.prepare_finalizer(identity, false),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        ledger.retire(identity).unwrap();
    }

    #[test]
    fn spill_overtake_and_fault_paths_preserve_or_discard_only_exactly() {
        let identity = exact_identity(57);

        let mut close = TestLedger::new();
        close.bind(identity).unwrap();
        let _receipt = input_spill_receipt(&mut close, identity, 1_500, 1_510, 257, 99);
        assert_eq!(
            close.begin_runtime(
                identity,
                1_520,
                ExactStreamResource::StdinSupervisor,
                ExactHostFunction::InputClosed,
                0,
            ),
            Err(ExactLedgerError::Busy)
        );
        assert_eq!(
            close.input_spill.map(|state| state.total - state.cursor),
            Some(158)
        );

        let mut backend = TestLedger::new();
        backend.bind(identity).unwrap();
        let receipt = input_spill_receipt(&mut backend, identity, 1_530, 1_540, 257, 99);
        let offered = backend.attach_input_runtime(receipt, 1_550, 99).unwrap();
        let prepared = backend.prepare_input_runtime(offered, 1_551).unwrap();
        assert_eq!(
            backend.begin_backend(prepared, ExactBackendAction::Start),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert_eq!(
            backend.input_spill.map(|state| state.total - state.cursor),
            Some(158)
        );

        let mut revoke = TestLedger::new();
        revoke.bind(identity).unwrap();
        let _receipt = input_spill_receipt(&mut revoke, identity, 1_560, 1_570, 257, 99);
        let _output = prepared_operation(
            &mut revoke,
            identity,
            1_580,
            1_581,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        assert_eq!(
            revoke.claim_revoke(identity, ExactStreamResource::StdinReader),
            Err(ExactLedgerError::InvalidTransition)
        );
        assert_eq!(
            revoke.input_spill.map(|state| state.total - state.cursor),
            Some(158)
        );

        let mut reclaim = TestLedger::new();
        reclaim.bind(identity).unwrap();
        let receipt = input_spill_receipt(&mut reclaim, identity, 1_590, 1_600, 257, 99);
        drop(receipt);
        assert_eq!(
            reclaim.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        assert_eq!(reclaim.input_spill_remaining(identity), Ok(None));

        let mut ambiguous = TestLedger::new();
        ambiguous.bind(identity).unwrap();
        let _receipt = input_spill_receipt(&mut ambiguous, identity, 1_610, 1_620, 257, 99);
        let output = prepared_operation(
            &mut ambiguous,
            identity,
            1_630,
            1_631,
            ExactStreamResource::StdoutWriter,
            ExactHostFunction::OutputStream,
            1,
        );
        let invoking = ambiguous
            .begin_backend(output, ExactBackendAction::Start)
            .unwrap();
        let _linearized = ambiguous
            .backend_linearized(invoking, BackendEffect::OutputSent { length: 1 })
            .unwrap();
        assert_eq!(
            ambiguous.raw_fault(identity),
            Ok(ExactCleanupDecision::Quarantined)
        );
        assert_eq!(
            ambiguous
                .input_spill
                .map(|state| state.total - state.cursor),
            Some(158)
        );
    }

    type TestLeaseLedger = ExactNativeLeaseLedger<u64, u64, u64, u64, u64, u64>;

    fn lease_spill(
        identity: ExactInstanceIdentity<u64, u64, u64, u64>,
        generation: u64,
        total: u16,
        cursor: u16,
    ) -> TestInputSpillReceipt {
        ExactInputSpillReceipt {
            identity,
            state: ExactInputSpillState {
                generation,
                total,
                cursor,
            },
        }
    }

    #[test]
    fn aggregate_lease_backend_branch_reaches_r_and_r_plus_one_is_inert() {
        let identity = exact_identity(60);
        let mut ledger = TestLeaseLedger::new();
        assert_eq!(
            ledger.metrics(),
            ExactNativeLeaseMetrics {
                current: 0,
                peak: 0,
                limit: EXACT_NATIVE_LEASE_LIMIT,
            }
        );
        ledger.bind(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 4);

        let spill = lease_spill(identity, 7, 257, 99);
        ledger.begin_input_spill(&spill).unwrap();
        assert_eq!(ledger.has_input_spill(identity), Ok(true));
        ledger.begin_backend(identity).unwrap();
        assert_eq!(ledger.has_backend(identity), Ok(true));
        assert_eq!(ledger.runtime_wait(identity), Ok(None));
        assert_eq!(ledger.terminal_empty(identity), Ok(false));
        let reserved = ledger.reserve_continuation(identity).unwrap();
        assert_eq!(reserved.branch(), ExactNativeLeaseBranch::Backend);
        assert_eq!(
            reserved.phase(),
            ExactNativeLeaseContinuationPhase::Reserved
        );
        let bound = ledger.bind_continuation(reserved, 0x710).unwrap();
        assert_eq!(bound.token(), Some(0x710));
        let registered = ledger.register_stream_wake(bound).unwrap();
        assert_eq!(ledger.metrics().current(), EXACT_NATIVE_LEASE_LIMIT);
        assert_eq!(ledger.metrics().peak(), EXACT_NATIVE_LEASE_LIMIT);

        let at_limit = ledger.metrics();
        assert_eq!(
            ledger.begin_runtime_wait(identity, 0x900),
            Err(ExactNativeLeaseError::LimitExceeded)
        );
        assert_eq!(ledger.metrics(), at_limit);
        assert!(!ledger.is_quarantined());

        let signalled = ledger.mark_signalled(registered, 0x710).unwrap();
        assert_eq!(
            signalled.phase(),
            ExactNativeLeaseContinuationPhase::Signalled
        );
        assert_eq!(ledger.metrics().current(), 7);
        ledger.consume_continuation(signalled, 0x710).unwrap();
        assert_eq!(ledger.metrics().current(), 6);

        let after_consume = ledger.metrics();
        assert_eq!(
            ledger.consume_continuation(registered, 0x710),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), after_consume);
        assert!(!ledger.is_quarantined());

        ledger.finish_backend(identity).unwrap();
        ledger.finish_input_spill(identity).unwrap();
        assert_eq!(ledger.has_backend(identity), Ok(false));
        assert_eq!(ledger.has_input_spill(identity), Ok(false));
        assert_eq!(ledger.terminal_empty(identity), Ok(true));
        ledger.reset_stream_caps(identity, 4).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
    }

    #[test]
    fn aggregate_lease_runtime_wait_parks_rotates_and_cancels_exactly() {
        let identity = exact_identity(61);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        let spill = lease_spill(identity, 9, 767, 99);
        ledger.begin_input_spill(&spill).unwrap();
        ledger.begin_runtime_wait(identity, 0xa00).unwrap();
        assert_eq!(ledger.runtime_wait(identity), Ok(Some(0xa00)));
        assert_eq!(ledger.has_backend(identity), Ok(false));

        let reserved = ledger.reserve_continuation(identity).unwrap();
        assert_eq!(reserved.branch(), ExactNativeLeaseBranch::RuntimeWait);
        let bound = ledger.bind_continuation(reserved, 0xa10).unwrap();
        let before_wrong_wait = ledger.metrics();
        assert_eq!(
            ledger.register_runtime_wake(bound, 0xa01),
            Err(ExactNativeLeaseError::WaitTokenMismatch)
        );
        assert_eq!(ledger.metrics(), before_wrong_wait);
        assert!(!ledger.is_quarantined());

        let registered = ledger.register_runtime_wake(bound, 0xa00).unwrap();
        assert_eq!(ledger.metrics().current(), EXACT_NATIVE_LEASE_LIMIT);
        // A signal which raced registration is consumed directly from the
        // registered projection; there is no intermediate polling turn.
        ledger.consume_continuation(registered, 0xa10).unwrap();
        assert_eq!(ledger.metrics().current(), 6);
        ledger.rotate_runtime_wait(identity, 0xa00, 0xa01).unwrap();
        assert_eq!(ledger.runtime_wait(identity), Ok(Some(0xa01)));
        let after_rotate = ledger.metrics();
        assert_eq!(
            ledger.finish_runtime_wait(identity, 0xa00),
            Err(ExactNativeLeaseError::WaitTokenMismatch)
        );
        assert_eq!(ledger.metrics(), after_rotate);
        assert!(!ledger.is_quarantined());

        let next_reserved = ledger.reserve_continuation(identity).unwrap();
        let next_bound = ledger.bind_continuation(next_reserved, 0xa11).unwrap();
        let next_registered = ledger.register_runtime_wake(next_bound, 0xa01).unwrap();
        assert_eq!(ledger.metrics().current(), EXACT_NATIVE_LEASE_LIMIT);
        ledger
            .drop_cancelled_continuation(next_registered, 0xa11)
            .unwrap();
        assert_eq!(ledger.metrics().current(), 6);

        ledger.finish_runtime_wait(identity, 0xa01).unwrap();
        assert_eq!(ledger.runtime_wait(identity), Ok(None));
        ledger.finish_input_spill(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert_eq!(ledger.metrics().peak(), EXACT_NATIVE_LEASE_LIMIT);
    }

    #[test]
    fn aggregate_lease_continuation_reserve_cancel_and_raw_abandon_are_exact() {
        let identity = exact_identity(62);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();

        let unarmed = ledger.reserve_continuation(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 6);
        ledger.cancel_reserved_continuation(unarmed).unwrap();
        assert_eq!(ledger.metrics().current(), 5);

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0xb10).unwrap();
        let registered = ledger.register_stream_wake(bound).unwrap();
        assert_eq!(ledger.metrics().current(), 7);
        assert_eq!(ledger.continuation(identity), Ok(Some(registered)));
        ledger.abandon_continuation_raw_fault(registered).unwrap();
        assert_eq!(ledger.metrics().current(), 5);
        assert_eq!(ledger.continuation(identity), Ok(None));

        let stable = ledger.metrics();
        assert_eq!(
            ledger.abandon_continuation_raw_fault(registered),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), stable);
        assert!(!ledger.is_quarantined());

        ledger.finish_backend(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
    }

    #[test]
    fn aggregate_lease_backend_drop_waits_for_physical_cancel_ack() {
        let identity = exact_identity(78);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0x1110).unwrap();
        let registered = ledger.register_stream_wake(bound).unwrap();
        let awaiting_physical_cancel = ledger.metrics();
        assert_eq!(awaiting_physical_cancel.current(), 7);
        assert_eq!(ledger.continuation(identity), Ok(Some(registered)));

        // Core may already have returned its cancellation disposition here,
        // but the backend still owns the copied wake token. Until physical
        // cancellation succeeds, both wake and scheduler charges stay live.
        assert_eq!(ledger.metrics(), awaiting_physical_cancel);
        assert_eq!(
            registered.phase(),
            ExactNativeLeaseContinuationPhase::WakeRegistered
        );

        // This exact disposition is published only after the simulated
        // physical cancellation acknowledgement.
        ledger
            .drop_cancelled_continuation(registered, 0x1110)
            .unwrap();
        assert_eq!(
            awaiting_physical_cancel.current() - ledger.metrics().current(),
            2
        );
        assert_eq!(ledger.continuation(identity), Ok(None));

        let after_drop = ledger.metrics();
        assert_eq!(
            ledger.drop_cancelled_continuation(registered, 0x1110),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), after_drop);
        assert!(!ledger.is_quarantined());

        // A successor may reuse the same opaque Core token. The private
        // receipt generation keeps the old physical-cancel disposition inert.
        let successor = ledger.reserve_continuation(identity).unwrap();
        let successor = ledger.bind_continuation(successor, 0x1110).unwrap();
        let successor = ledger.register_stream_wake(successor).unwrap();
        let successor_live = ledger.metrics();
        assert_eq!(
            ledger.drop_cancelled_continuation(registered, 0x1110),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), successor_live);
        assert_eq!(ledger.continuation(identity), Ok(Some(successor)));
        assert!(!ledger.is_quarantined());
        ledger
            .drop_cancelled_continuation(successor, 0x1110)
            .unwrap();
        assert_eq!(successor_live.current() - ledger.metrics().current(), 2);

        ledger.finish_backend(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
    }

    #[test]
    fn aggregate_lease_backend_abandon_waits_for_physical_cancel_ack() {
        let identity = exact_identity(79);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0x1210).unwrap();
        let registered = ledger.register_stream_wake(bound).unwrap();
        let awaiting_physical_cancel = ledger.metrics();
        assert_eq!(awaiting_physical_cancel.current(), 7);
        assert_eq!(ledger.continuation(identity), Ok(Some(registered)));

        // Core abandonment alone cannot release the wake copied into the
        // physical stream slot, so the aggregate projection remains exact.
        assert_eq!(ledger.metrics(), awaiting_physical_cancel);
        ledger.abandon_continuation_raw_fault(registered).unwrap();
        assert_eq!(
            awaiting_physical_cancel.current() - ledger.metrics().current(),
            2
        );

        let after_abandon = ledger.metrics();
        assert_eq!(
            ledger.abandon_continuation_raw_fault(registered),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), after_abandon);
        assert!(!ledger.is_quarantined());

        ledger.finish_backend(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
    }

    #[test]
    fn aggregate_lease_backend_bound_and_signalled_release_one_each() {
        let identity = exact_identity(80);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0x1310).unwrap();
        let bound_live = ledger.metrics();
        assert_eq!(bound_live.current(), 6);
        ledger.drop_cancelled_continuation(bound, 0x1310).unwrap();
        assert_eq!(bound_live.current() - ledger.metrics().current(), 1);

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0x1320).unwrap();
        let registered = ledger.register_stream_wake(bound).unwrap();
        let signalled = ledger.mark_signalled(registered, 0x1320).unwrap();
        let signalled_live = ledger.metrics();
        assert_eq!(
            signalled.phase(),
            ExactNativeLeaseContinuationPhase::Signalled
        );
        assert_eq!(signalled_live.current(), 6);
        ledger.abandon_continuation_raw_fault(signalled).unwrap();
        assert_eq!(signalled_live.current() - ledger.metrics().current(), 1);

        ledger.finish_backend(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
    }

    #[test]
    fn aggregate_lease_backend_wrong_cancel_disposition_is_fail_stop() {
        let identity = exact_identity(81);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();

        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0x1410).unwrap();
        let registered = ledger.register_stream_wake(bound).unwrap();
        let charged = ledger.metrics();
        assert_eq!(charged.current(), 7);

        assert_eq!(
            ledger.drop_cancelled_continuation(registered, 0x1411),
            Err(ExactNativeLeaseError::ReceiptMismatch)
        );
        assert_eq!(ledger.metrics(), charged);
        assert!(ledger.is_quarantined());
        assert_eq!(
            ledger.drop_cancelled_continuation(registered, 0x1410),
            Err(ExactNativeLeaseError::Quarantined)
        );
        assert_eq!(ledger.metrics(), charged);
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
    }

    #[test]
    fn aggregate_lease_spill_successors_do_not_mint_extra_authority() {
        let identity = exact_identity(63);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        let first = lease_spill(identity, 21, 767, 99);
        let second = lease_spill(identity, 22, 767, 198);
        ledger.begin_input_spill(&first).unwrap();
        assert_eq!(ledger.metrics().current(), 5);
        ledger.update_input_spill(&second).unwrap();
        assert_eq!(ledger.metrics().current(), 5);

        let stale = lease_spill(identity, 21, 767, 99);
        assert_eq!(
            ledger.update_input_spill(&stale),
            Err(ExactNativeLeaseError::ReceiptMismatch)
        );
        assert_eq!(ledger.metrics().current(), 5);
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn aggregate_lease_accepts_operation_ledger_spill_successors() {
        let identity = exact_identity(64);
        let mut operations = TestLedger::new();
        let mut leases = TestLeaseLedger::new();
        operations.bind(identity).unwrap();
        leases.bind(identity).unwrap();

        let pending = pending_operation(
            &mut operations,
            identity,
            1_000,
            1_010,
            ExactStreamResource::StdinReader,
            ExactHostFunction::InputStream,
            3,
        );
        let invoking = operations
            .begin_backend(pending, ExactBackendAction::CommitPrepared)
            .unwrap();
        let received = operations
            .backend_linearized(
                invoking,
                BackendEffect::InputReceived {
                    total: 9,
                    cursor: 0,
                },
            )
            .unwrap();
        let first = operations
            .commit_input_prefix(received, 3)
            .unwrap()
            .unwrap();
        leases.begin_input_spill(&first).unwrap();

        let offered = operations.attach_input_runtime(first, 1_020, 3).unwrap();
        let prepared = operations.prepare_input_runtime(offered, 1_021).unwrap();
        let second = operations
            .commit_input_prefix(prepared, 3)
            .unwrap()
            .unwrap();
        leases.update_input_spill(&second).unwrap();
        assert_eq!(leases.metrics().current(), 5);

        let offered = operations.attach_input_runtime(second, 1_030, 3).unwrap();
        let prepared = operations.prepare_input_runtime(offered, 1_031).unwrap();
        assert_eq!(operations.commit_input_prefix(prepared, 3), Ok(None));
        leases.finish_input_spill(identity).unwrap();
        leases.reset_stream_caps(identity, 4).unwrap();
        leases.retire(identity).unwrap();
        assert_eq!(leases.metrics().current(), 0);
    }

    #[test]
    fn aggregate_lease_old_control_generation_is_inert_and_alias_quarantines() {
        let identity = exact_identity(70);
        let stale = exact_identity(69);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        let seeded = ledger.metrics();
        assert_eq!(
            ledger.begin_backend(stale),
            Err(ExactNativeLeaseError::StaleGeneration)
        );
        assert_eq!(ledger.metrics(), seeded);
        assert!(!ledger.is_quarantined());

        let same_generation_alias = ExactInstanceIdentity {
            bindings: 0x45,
            ..identity
        };
        assert_eq!(
            ledger.bind(same_generation_alias),
            Err(ExactNativeLeaseError::IdentityMismatch)
        );
        assert_eq!(ledger.metrics(), seeded);
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn aggregate_lease_double_wake_registration_is_fail_stop_without_overcount() {
        let identity = exact_identity(71);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        ledger.begin_backend(identity).unwrap();
        let reserved = ledger.reserve_continuation(identity).unwrap();
        let bound = ledger.bind_continuation(reserved, 0xc10).unwrap();
        let _registered = ledger.register_stream_wake(bound).unwrap();
        let once = ledger.metrics();
        assert_eq!(
            ledger.register_stream_wake(bound),
            Err(ExactNativeLeaseError::ReceiptMismatch)
        );
        assert_eq!(ledger.metrics(), once);
        assert!(ledger.is_quarantined());
        assert!(ledger.metrics().peak() <= ledger.metrics().limit());
    }

    #[test]
    fn aggregate_lease_quantum_count_is_stable_and_receipt_generation_blocks_aba() {
        let identity = exact_identity(72);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();

        let first_reserved = ledger.reserve_quantum_continuation(identity).unwrap();
        assert_eq!(first_reserved.branch(), ExactNativeLeaseBranch::Quantum);
        assert_eq!(ledger.metrics().current(), 5);
        let first_bound = ledger.bind_continuation(first_reserved, 0xd10).unwrap();
        assert_eq!(ledger.metrics().current(), 5);
        ledger
            .consume_quantum_continuation(first_bound, 0xd10)
            .unwrap();
        assert_eq!(ledger.metrics().current(), 4);

        let stable = ledger.metrics();
        assert_eq!(
            ledger.consume_quantum_continuation(first_bound, 0xd10),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), stable);
        assert!(!ledger.is_quarantined());

        // Core token values are opaque and may compare equal. The private
        // reservation generation still prevents the first receipt from
        // consuming the second incarnation.
        let second_reserved = ledger.reserve_quantum_continuation(identity).unwrap();
        let second_bound = ledger.bind_continuation(second_reserved, 0xd10).unwrap();
        let second_live = ledger.metrics();
        assert_eq!(
            ledger.consume_quantum_continuation(first_bound, 0xd10),
            Err(ExactNativeLeaseError::StaleReceipt)
        );
        assert_eq!(ledger.metrics(), second_live);
        assert!(!ledger.is_quarantined());
        ledger
            .drop_cancelled_continuation(second_bound, 0xd10)
            .unwrap();
        assert_eq!(ledger.metrics().current(), 4);

        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert!(ledger.is_retired());
        assert_eq!(ledger.metrics().current(), 0);
        assert_eq!(ledger.metrics().peak(), 5);
    }

    #[test]
    fn aggregate_lease_tombstone_tracks_uncharged_core_disposition() {
        let identity = exact_identity(76);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();

        let first = ledger.reserve_quantum_continuation(identity).unwrap();
        let first = ledger.bind_continuation(first, 0xf10).unwrap();
        ledger.consume_quantum_continuation(first, 0xf10).unwrap();
        assert_eq!(ledger.metrics().current(), 4);
        assert_eq!(ledger.core_continuation(identity), Ok(Some(0xf10)));

        // Reserving capacity does not itself change Core. A failed arm must
        // therefore preserve the previous terminal projection.
        let unarmed = ledger.reserve_quantum_continuation(identity).unwrap();
        assert_eq!(ledger.core_continuation(identity), Ok(Some(0xf10)));
        ledger.cancel_reserved_continuation(unarmed).unwrap();
        assert_eq!(ledger.core_continuation(identity), Ok(Some(0xf10)));

        let second = ledger.reserve_quantum_continuation(identity).unwrap();
        let second = ledger.bind_continuation(second, 0xf20).unwrap();
        assert_eq!(ledger.core_continuation(identity), Ok(Some(0xf20)));
        ledger.drop_cancelled_continuation(second, 0xf20).unwrap();
        assert_eq!(ledger.metrics().current(), 4);
        assert_eq!(ledger.core_continuation(identity), Ok(Some(0xf20)));

        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert!(ledger.is_retired());
    }

    #[test]
    fn aggregate_lease_quantum_retains_backend_and_spill_branch() {
        let identity = exact_identity(75);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        let spill = lease_spill(identity, 31, 9, 3);
        ledger.begin_input_spill(&spill).unwrap();
        ledger.begin_backend(identity).unwrap();

        let reserved = ledger.reserve_quantum_continuation(identity).unwrap();
        assert_eq!(reserved.branch(), ExactNativeLeaseBranch::Quantum);
        let bound = ledger.bind_continuation(reserved, 0xe10).unwrap();
        assert_eq!(ledger.metrics().current(), 7);
        ledger.consume_quantum_continuation(bound, 0xe10).unwrap();
        assert_eq!(ledger.has_backend(identity), Ok(true));
        assert_eq!(ledger.has_input_spill(identity), Ok(true));

        ledger.finish_backend(identity).unwrap();
        ledger.finish_input_spill(identity).unwrap();
        ledger.reset_stream_caps(identity, 4).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
        assert_eq!(ledger.metrics().peak(), 7);
    }

    #[test]
    fn raw_fault_keeps_historical_backend_consumed_under_new_quantum_tombstone() {
        let identity = exact_identity(77);
        let mut operations = TestLedger::new();
        let mut leases = TestLeaseLedger::new();
        operations.bind(identity).unwrap();
        leases.bind(identity).unwrap();
        leases.begin_backend(identity).unwrap();

        let registered =
            registered_output_operation(&mut operations, identity, 1_200, 1_210, 0x1010, 2);
        let consumed = operations
            .project_consumed_continuation(identity, 0x1010)
            .unwrap();
        assert_eq!(consumed.continuation(), ExactContinuation::Consumed(0x1010));

        let old = leases.reserve_continuation(identity).unwrap();
        let old = leases.bind_continuation(old, 0x1010).unwrap();
        let old = leases.register_stream_wake(old).unwrap();
        leases.consume_continuation(old, 0x1010).unwrap();
        assert_eq!(leases.core_continuation(identity), Ok(Some(0x1010)));

        let quantum = leases.reserve_quantum_continuation(identity).unwrap();
        let quantum = leases.bind_continuation(quantum, 0x1020).unwrap();
        leases
            .consume_quantum_continuation(quantum, 0x1020)
            .unwrap();
        assert_eq!(leases.core_continuation(identity), Ok(Some(0x1020)));
        assert_eq!(
            leases.core_continuation_branch(identity),
            Ok(Some(ExactNativeLeaseBranch::Quantum))
        );

        let plan = match operations.raw_fault(identity).unwrap() {
            ExactCleanupDecision::Cancel(plan) => plan,
            other => panic!("pending raw fault needs exact cancel, got {other:?}"),
        };
        let cancelled = operations.finish_cancel(plan).unwrap();
        assert_eq!(
            cancelled.continuation(),
            ExactContinuation::Consumed(0x1010)
        );
        let abandoned = operations
            .acknowledge_runtime_cleanup(cancelled, ExactRuntimeCleanup::Abandoned)
            .unwrap();
        assert_eq!(
            operations.raw_fault(identity),
            Ok(ExactCleanupDecision::ReclaimSafe)
        );
        let _ = (registered, abandoned);

        leases.finish_backend(identity).unwrap();
        leases.reset_stream_caps(identity, 4).unwrap();
        leases.retire(identity).unwrap();
        assert_eq!(leases.metrics().current(), 0);
    }

    #[test]
    fn aggregate_lease_cap_reset_requires_exact_revocation_credit() {
        let identity = exact_identity(73);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        let before = ledger.metrics();
        assert_eq!(
            ledger.reset_stream_caps(identity, 3),
            Err(ExactNativeLeaseError::ReceiptMismatch)
        );
        assert_eq!(ledger.metrics(), before);
        assert!(ledger.is_quarantined());
    }

    #[test]
    fn aggregate_lease_individual_cap_reset_reaches_zero_before_retire() {
        let identity = exact_identity(74);
        let mut ledger = TestLeaseLedger::new();
        ledger.bind(identity).unwrap();
        for resource in [
            ExactStreamResource::StdinReader,
            ExactStreamResource::StdoutWriter,
            ExactStreamResource::StdinSupervisor,
            ExactStreamResource::StdoutSupervisor,
        ] {
            ledger.release_stream_cap(identity, resource).unwrap();
        }
        assert_eq!(ledger.metrics().current(), 0);
        assert_eq!(ledger.metrics().peak(), 4);
        assert_eq!(ledger.metrics().limit(), EXACT_NATIVE_LEASE_LIMIT);
        ledger.reset_stream_caps(identity, 0).unwrap();
        ledger.retire(identity).unwrap();
        assert_eq!(ledger.metrics().current(), 0);
    }
}
