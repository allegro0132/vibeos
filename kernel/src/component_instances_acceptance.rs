//! QEMU-only C4.8 target evidence for the managed component lifecycle.
//!
//! Positive cycles use the production CONTROL/INSTANCES path.  Deliberate
//! identity corruptions use a separate SYSTEM-owned registry and control gate,
//! so proving sticky quarantine never requires a forbidden Failed -> Healthy
//! transition before the real SSH image/session gate is opened.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use crate::heap::ArenaId;
use crate::println;
use vibeos_core::exec::AcceptanceWitnessMismatch;
use vibeos_core::instance::{
    AcceptanceInstanceProbe, AcceptanceSealMismatch, InstanceContinuationSignal,
    InstanceContinuationToken, InstancePhase,
};

use super::*;

const HARTS: usize = 4;
const ROUNDS: usize = 5;
const POSITIVE_CYCLES: usize = HARTS * ROUNDS;
const WAIT_SECONDS: u64 = 10;

const POS_FREE: u8 = 0;
const POS_ARMED: u8 = 1;
const POS_RUNTIME_READY: u8 = 2;
const POS_CONTINUATION_PARKED: u8 = 3;
const POS_CONTINUATION_SIGNALLED: u8 = 4;
const POS_CONTINUATION_RESUMED: u8 = 5;
const POS_STALE_REJECTED: u8 = 6;
const POS_FAULT_WAIT_PARKED: u8 = 7;
const POS_RAW_RECLAIMED: u8 = 8;
const POS_TERMINAL_VISIBLE: u8 = 9;
const POS_OWNER_RETIRED: u8 = 10;
const POS_CSPACE_RESET: u8 = 11;
const POS_COMPLETE: u8 = 12;
const POS_DONE: u8 = 13;

const NEG_FREE: u8 = 0;
const NEG_ARMED: u8 = 1;
const NEG_ROUTING: u8 = 2;
const NEG_DONE: u8 = 3;

const NEG_OUTCOME_NONE: u8 = 0;
const NEG_OUTCOME_QUARANTINED: u8 = 1;
const NEG_OUTCOME_RECLAIMED: u8 = 2;

const ERROR_POSITIVE_ARM: u64 = 1 << 0;
const ERROR_POSITIVE_RUNTIME: u64 = 1 << 1;
const ERROR_POSITIVE_RAW: u64 = 1 << 2;
const ERROR_POSITIVE_TERMINAL: u64 = 1 << 3;
const ERROR_POSITIVE_RETIRE: u64 = 1 << 4;
const ERROR_POSITIVE_RESET: u64 = 1 << 5;
const ERROR_POSITIVE_COMPLETE: u64 = 1 << 6;
const ERROR_POSITIVE_WORKER: u64 = 1 << 7;
const ERROR_POSITIVE_BASELINE: u64 = 1 << 8;
const ERROR_NEGATIVE_ROUTE: u64 = 1 << 9;
const ERROR_NEGATIVE_RESULT: u64 = 1 << 10;
const ERROR_ABA: u64 = 1 << 11;
const ERROR_NORMAL_PROBE: u64 = 1 << 12;
const ERROR_POLICY_GATE: u64 = 1 << 13;
const ERROR_CONTINUATION_FAULT: u64 = 1 << 14;

static ERRORS: AtomicU64 = AtomicU64::new(0);
static POSITIVE_RAW_RECLAIMS: AtomicUsize = AtomicUsize::new(0);
static POSITIVE_RESETS: AtomicUsize = AtomicUsize::new(0);
static POSITIVE_REGISTRATION_DRAINS: AtomicUsize = AtomicUsize::new(0);
static C52_PARKS: AtomicUsize = AtomicUsize::new(0);
static C52_RESUMES: AtomicUsize = AtomicUsize::new(0);
static C52_CROSS_HART_SIGNALS: AtomicUsize = AtomicUsize::new(0);
static C52_STALE_REJECTS: AtomicUsize = AtomicUsize::new(0);
static C52_LIVE_FAULTS: AtomicUsize = AtomicUsize::new(0);
static FAULT_PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
static HART_FAULTS: [AtomicUsize; HARTS] = [const { AtomicUsize::new(0) }; HARTS];
static READY_MASKS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static PARKED_MASKS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static ROUND_DONE: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];

struct PositiveSlot {
    stage: AtomicU8,
    task: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    round: AtomicU8,
    hart: AtomicU8,
    signal_hart: AtomicU8,
    park_polls: AtomicU64,
    token: UnsafeCell<MaybeUninit<InstanceToken>>,
    continuation: UnsafeCell<MaybeUninit<InstanceContinuationToken>>,
    handle: UnsafeCell<MaybeUninit<TaskHandle>>,
    before: UnsafeCell<MaybeUninit<AcceptanceInstanceProbe>>,
}

unsafe impl Sync for PositiveSlot {}

impl PositiveSlot {
    const fn new() -> Self {
        Self {
            stage: AtomicU8::new(POS_FREE),
            task: AtomicU64::new(0),
            owner: AtomicU64::new(0),
            arena: AtomicU64::new(0),
            round: AtomicU8::new(0),
            hart: AtomicU8::new(0),
            signal_hart: AtomicU8::new(u8::MAX),
            park_polls: AtomicU64::new(0),
            token: UnsafeCell::new(MaybeUninit::uninit()),
            continuation: UnsafeCell::new(MaybeUninit::uninit()),
            handle: UnsafeCell::new(MaybeUninit::uninit()),
            before: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn matches(&self, task: TaskId, domain: AllocationDomain) -> bool {
        self.stage.load(Ordering::Acquire) >= POS_ARMED
            && self.task.load(Ordering::Relaxed) == task.0
            && self.owner.load(Ordering::Relaxed) == domain.owner.get()
            && self.arena.load(Ordering::Relaxed) == domain.arena.get()
    }

    fn token(&self) -> InstanceToken {
        unsafe { (*self.token.get()).assume_init() }
    }

    fn continuation(&self) -> InstanceContinuationToken {
        unsafe { (*self.continuation.get()).assume_init() }
    }

    fn handle(&self) -> TaskHandle {
        unsafe { (*self.handle.get()).assume_init_ref().clone() }
    }

    unsafe fn release_handle(&self) {
        unsafe { (*self.handle.get()).assume_init_drop() };
    }

    fn before(&self) -> AcceptanceInstanceProbe {
        unsafe { (*self.before.get()).assume_init() }
    }
}

static POSITIVE: [PositiveSlot; POSITIVE_CYCLES] = [const { PositiveSlot::new() }; POSITIVE_CYCLES];

#[derive(Clone, Copy)]
struct RoundSnapshot {
    heap: crate::heap::HeapSnapshot,
    live_tasks: usize,
    reclaimable_domains: usize,
    timers: usize,
    irq_probes: usize,
}

struct RoundEvidence {
    ready: AtomicBool,
    value: UnsafeCell<MaybeUninit<RoundSnapshot>>,
}

unsafe impl Sync for RoundEvidence {}

impl RoundEvidence {
    const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&self, value: RoundSnapshot) {
        unsafe { (*self.value.get()).write(value) };
        self.ready.store(true, Ordering::Release);
    }

    fn get(&self) -> Option<RoundSnapshot> {
        self.ready
            .load(Ordering::Acquire)
            .then(|| unsafe { (*self.value.get()).assume_init() })
    }
}

static ROUND_EVIDENCE: [RoundEvidence; ROUNDS] = [const { RoundEvidence::new() }; ROUNDS];

fn fail(bit: u64) {
    ERRORS.fetch_or(bit, Ordering::Release);
}

fn deadline_expired(started: u64) -> bool {
    crate::sbi::time().wrapping_sub(started)
        >= crate::exec::timebase_hz().saturating_mul(WAIT_SECONDS)
}

fn positive_index(round: u8, hart: u8) -> Option<usize> {
    let round = usize::from(round);
    let hart = usize::from(hart);
    (round < ROUNDS && hart < HARTS).then_some(round * HARTS + hart)
}

fn positive_for(task: TaskId, domain: AllocationDomain) -> Option<&'static PositiveSlot> {
    POSITIVE.iter().find(|slot| slot.matches(task, domain))
}

pub(super) fn arm_positive(
    _key: ControlKey,
    token: InstanceToken,
    handle: &TaskHandle,
    domain: AllocationDomain,
    round: u8,
    hart: u8,
) -> bool {
    let Some(index) = positive_index(round, hart) else {
        fail(ERROR_POSITIVE_ARM);
        return false;
    };
    let slot = &POSITIVE[index];
    if slot.stage.load(Ordering::Acquire) != POS_FREE || handle.allocation_domain() != domain {
        fail(ERROR_POSITIVE_ARM);
        return false;
    }
    let snapshot = registry().snapshot(token);
    let probe = registry().acceptance_probe(token);
    let valid = snapshot.as_ref().is_ok_and(|snapshot| {
        snapshot.phase == InstancePhase::Active
            && snapshot.domain == domain
            && snapshot.task == Some(handle.id())
            && snapshot
                .home_hart
                .is_some_and(|home| home.index() == usize::from(hart))
    }) && probe.is_some_and(|probe| {
        probe.is_exact()
            && probe.exact_phase() == Some(InstancePhase::Active)
            && probe.seal_matches_space()
            && probe.seal_matches_cspace()
            && probe.capability_table_len() == 0
    });
    if !valid {
        fail(ERROR_POSITIVE_ARM);
        return false;
    }
    unsafe {
        (*slot.token.get()).write(token);
        (*slot.handle.get()).write(handle.clone());
        (*slot.before.get()).write(probe.expect("validated acceptance probe exists"));
    }
    slot.task.store(handle.id().0, Ordering::Relaxed);
    slot.owner.store(domain.owner.get(), Ordering::Relaxed);
    slot.arena.store(domain.arena.get(), Ordering::Relaxed);
    slot.round.store(round, Ordering::Relaxed);
    slot.hart.store(hart, Ordering::Relaxed);
    slot.stage.store(POS_ARMED, Ordering::Release);
    true
}

async fn fault_after_runtime_barrier(round: u8, hart: u8) {
    let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
        fail(ERROR_POSITIVE_RUNTIME);
        return;
    };
    let Some(slot) = positive_for(witness.task_id(), witness.allocation_domain()) else {
        fail(ERROR_POSITIVE_RUNTIME);
        return;
    };
    let identity_matches = positive_index(round, hart)
        .is_some_and(|index| core::ptr::eq(slot, &POSITIVE[index]))
        && witness.instance_token() == Some(slot.token())
        && witness.home_hart().index() == usize::from(hart)
        && witness.current_hart().index() == usize::from(hart);
    if !identity_matches
        || slot
            .stage
            .compare_exchange(
                POS_ARMED,
                POS_RUNTIME_READY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_RUNTIME);
        return;
    }
    READY_MASKS[usize::from(round)].fetch_or(1 << hart, Ordering::AcqRel);
    let started = crate::sbi::time();
    while READY_MASKS[usize::from(round)].load(Ordering::Acquire) != 0x0f {
        if deadline_expired(started) {
            fail(ERROR_POSITIVE_RUNTIME);
            return;
        }
        crate::exec::yield_now().await;
    }
}

struct ResumableContinuation {
    continuation: InstanceContinuation<'static>,
    operation: InstanceContinuationToken,
    token: InstanceToken,
    round: u8,
    hart: u8,
    parked: bool,
}

impl Future for ResumableContinuation {
    type Output = Result<(), ()>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let polled = Pin::new(&mut self.continuation).poll(context);
        let Some(index) = positive_index(self.round, self.hart) else {
            fail(ERROR_CONTINUATION_FAULT);
            return Poll::Ready(Err(()));
        };
        let slot = &POSITIVE[index];
        match polled {
            Poll::Pending if !self.parked => {
                let witness = crate::exec::current_reclaimable_task_witness();
                let exact = witness.is_some_and(|witness| {
                    witness.instance_token() == Some(self.token)
                        && witness.task_id().0 == slot.task.load(Ordering::Relaxed)
                        && witness.home_hart().index() == usize::from(self.hart)
                        && witness.current_hart().index() == usize::from(self.hart)
                        && slot.matches(witness.task_id(), witness.allocation_domain())
                });
                let handle = slot.handle();
                if !exact
                    || handle.id().0 != slot.task.load(Ordering::Relaxed)
                    || handle.allocation_domain().owner.get() != slot.owner.load(Ordering::Relaxed)
                    || handle.allocation_domain().arena.get() != slot.arena.load(Ordering::Relaxed)
                {
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(Err(()));
                }
                let polls = handle.polls();
                unsafe { (*slot.continuation.get()).write(self.operation) };
                slot.park_polls.store(polls, Ordering::Relaxed);
                if slot
                    .stage
                    .compare_exchange(
                        POS_RUNTIME_READY,
                        POS_CONTINUATION_PARKED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(Err(()));
                }
                self.parked = true;
                C52_PARKS.fetch_add(1, Ordering::AcqRel);
                PARKED_MASKS[usize::from(self.round)].fetch_or(1 << self.hart, Ordering::AcqRel);
                Poll::Pending
            }
            Poll::Pending => {
                // An External continuation has no self-wake. Any second poll
                // before its one exact signal is observable spin.
                fail(ERROR_CONTINUATION_FAULT);
                Poll::Ready(Err(()))
            }
            Poll::Ready(Ok(())) if self.parked => {
                let witness = crate::exec::current_reclaimable_task_witness();
                let resume_polls = slot.handle().polls();
                let exact = witness.is_some_and(|witness| {
                    witness.instance_token() == Some(self.token)
                        && witness.task_id().0 == slot.task.load(Ordering::Relaxed)
                        && witness.home_hart().index() == usize::from(self.hart)
                        && witness.current_hart().index() == usize::from(self.hart)
                        && slot.matches(witness.task_id(), witness.allocation_domain())
                }) && slot.signal_hart.load(Ordering::Acquire) != self.hart
                    && usize::from(slot.signal_hart.load(Ordering::Relaxed))
                        == (usize::from(self.hart) + HARTS - 1) % HARTS
                    && slot.park_polls.load(Ordering::Relaxed).checked_add(1) == Some(resume_polls);
                if !exact
                    || slot
                        .stage
                        .compare_exchange(
                            POS_CONTINUATION_SIGNALLED,
                            POS_CONTINUATION_RESUMED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                {
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(Err(()));
                }
                C52_RESUMES.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                fail(ERROR_CONTINUATION_FAULT);
                Poll::Ready(Err(()))
            }
        }
    }
}

struct PendingContinuationFault {
    continuation: InstanceContinuation<'static>,
    token: InstanceToken,
    round: u8,
    hart: u8,
}

impl Future for PendingContinuationFault {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.continuation).poll(context) {
            Poll::Pending => {
                let witness = crate::exec::current_reclaimable_task_witness();
                let Some(index) = positive_index(self.round, self.hart) else {
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(());
                };
                let slot = &POSITIVE[index];
                let exact = witness.is_some_and(|witness| {
                    witness.instance_token() == Some(self.token)
                        && witness.task_id().0 == slot.task.load(Ordering::Relaxed)
                        && witness.home_hart().index() == usize::from(self.hart)
                        && witness.current_hart().index() == usize::from(self.hart)
                        && slot.matches(witness.task_id(), witness.allocation_domain())
                });
                let registrations = slot.handle().acceptance_registration_stats();
                if !exact
                    || registrations.total != 1
                    || registrations.waits != 1
                    || registrations.timers != 0
                    || registrations.joins != 0
                    || registrations.irq_poll_probes != 0
                    || slot
                        .stage
                        .compare_exchange(
                            POS_STALE_REJECTED,
                            POS_FAULT_WAIT_PARKED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                {
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(());
                }
                C52_LIVE_FAULTS.fetch_add(1, Ordering::AcqRel);
                // Deliberately fault with the one-shot listener still owned by
                // this task. The executor must drain it before the instance
                // registry may mark the continuation Abandoned and authorize
                // raw arena reclamation.
                panic!("deliberate C5.2 fault with a live continuation wait");
            }
            Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                fail(ERROR_CONTINUATION_FAULT);
                Poll::Ready(())
            }
        }
    }
}

pub(super) async fn fault_with_pending_continuation(token: InstanceToken, round: u8, hart: u8) {
    fault_after_runtime_barrier(round, hart).await;
    let operation =
        match registry().arm_continuation_current(token, InstanceContinuationKind::External) {
            Ok(operation) => operation,
            Err(_) => {
                fail(ERROR_CONTINUATION_FAULT);
                return;
            }
        };
    let continuation = match registry().wait_continuation(operation) {
        Ok(continuation) => continuation,
        Err(_) => {
            fail(ERROR_CONTINUATION_FAULT);
            return;
        }
    };
    if (ResumableContinuation {
        continuation,
        operation,
        token,
        round,
        hart,
        parked: false,
    })
    .await
    .is_err()
    {
        fail(ERROR_CONTINUATION_FAULT);
        return;
    }

    // A completed operation token must be stale, and probing before/after the
    // rejection proves that no instance, Space, or CSpace projection changed.
    let before_stale = registry().acceptance_probe(token);
    let stale = registry().signal_continuation(operation);
    let after_stale = registry().acceptance_probe(token);
    let Some(index) = positive_index(round, hart) else {
        fail(ERROR_CONTINUATION_FAULT);
        return;
    };
    if stale != InstanceContinuationSignal::Stale
        || before_stale.is_none()
        || before_stale != after_stale
        || !after_stale.is_some_and(|probe| {
            probe.is_exact()
                && probe.exact_phase() == Some(InstancePhase::Active)
                && probe.seal_matches_space()
                && probe.seal_matches_cspace()
        })
        || POSITIVE[index]
            .stage
            .compare_exchange(
                POS_CONTINUATION_RESUMED,
                POS_STALE_REJECTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_CONTINUATION_FAULT);
        return;
    }
    C52_STALE_REJECTS.fetch_add(1, Ordering::AcqRel);

    let fault_operation =
        match registry().arm_continuation_current(token, InstanceContinuationKind::External) {
            Ok(fault_operation) if fault_operation != operation => fault_operation,
            Ok(_) | Err(_) => {
                fail(ERROR_CONTINUATION_FAULT);
                return;
            }
        };
    let continuation = match registry().wait_continuation(fault_operation) {
        Ok(continuation) => continuation,
        Err(_) => {
            fail(ERROR_CONTINUATION_FAULT);
            return;
        }
    };
    PendingContinuationFault {
        continuation,
        token,
        round,
        hart,
    }
    .await;
    fail(ERROR_CONTINUATION_FAULT);
}

pub(super) fn record_raw_reclaimed(witness: ReclaimableFaultWitness) {
    let Some(slot) = positive_for(witness.task_id(), witness.allocation_domain()) else {
        return;
    };
    let hart = usize::from(slot.hart.load(Ordering::Relaxed));
    if witness.instance_token() != Some(slot.token())
        || witness.home_hart().index() != hart
        || witness.current_hart().index() != hart
        || slot
            .stage
            .compare_exchange(
                POS_FAULT_WAIT_PARKED,
                POS_RAW_RECLAIMED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_RAW);
        return;
    }
    POSITIVE_RAW_RECLAIMS.fetch_add(1, Ordering::AcqRel);
    if hart < HARTS {
        HART_FAULTS[hart].fetch_add(1, Ordering::AcqRel);
    } else {
        fail(ERROR_POSITIVE_RAW);
    }
}

pub(super) fn record_terminal_visible(
    handle: &TaskHandle,
    domain: AllocationDomain,
    state: TaskState,
) {
    let Some(slot) = positive_for(handle.id(), domain) else {
        return;
    };
    let registrations = handle.acceptance_registration_stats();
    if state != TaskState::Faulted
        || registrations.total != 0
        || registrations.waits != 0
        || registrations.timers != 0
        || registrations.joins != 0
        || registrations.irq_poll_probes != 0
        || slot
            .stage
            .compare_exchange(
                POS_RAW_RECLAIMED,
                POS_TERMINAL_VISIBLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_TERMINAL);
    } else {
        POSITIVE_REGISTRATION_DRAINS.fetch_add(1, Ordering::AcqRel);
        // The static slot only needs this observer through the park/resume and
        // terminal-ledger checks. Release the Arc here so round baselines also
        // prove the gate does not retain completed TaskStatus objects.
        unsafe { slot.release_handle() };
    }
}

pub(super) fn record_owner_retired(
    task: TaskId,
    domain: AllocationDomain,
    kind: TerminalRetireKind,
    retired: bool,
) {
    let Some(slot) = positive_for(task, domain) else {
        return;
    };
    if kind != TerminalRetireKind::FaultReclaimed
        || !retired
        || HEAP.arena_stats(domain.arena).is_some()
        || HEAP.account_stats(domain.owner).is_some()
        || slot
            .stage
            .compare_exchange(
                POS_TERMINAL_VISIBLE,
                POS_OWNER_RETIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_RETIRE);
    }
}

pub(super) fn record_cspace_reset(task: TaskId, domain: AllocationDomain, next_incarnation: u64) {
    let Some(slot) = positive_for(task, domain) else {
        return;
    };
    let expected = slot
        .before()
        .cspace_incarnation()
        .and_then(|value| value.checked_add(1));
    if expected != Some(next_incarnation)
        || slot
            .stage
            .compare_exchange(
                POS_OWNER_RETIRED,
                POS_CSPACE_RESET,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_RESET);
        return;
    }
    POSITIVE_RESETS.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn record_outer_complete(
    task: TaskId,
    domain: AllocationDomain,
    terminal: ComponentTerminal,
) {
    let Some(slot) = positive_for(task, domain) else {
        return;
    };
    if terminal != ComponentTerminal::RunnerFault
        || slot
            .stage
            .compare_exchange(
                POS_CSPACE_RESET,
                POS_COMPLETE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_POSITIVE_COMPLETE);
    }
}

pub(super) fn record_fault_payload_drop() {
    FAULT_PAYLOAD_DROPS.fetch_add(1, Ordering::AcqRel);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum NegativeCase {
    Generation = 1,
    Task = 2,
    Status = 3,
    Owner = 4,
    Arena = 5,
    CurrentHart = 6,
    SpaceObject = 7,
    CSpaceIncarnation = 8,
    Duplicate = 9,
    AbaSeed = 10,
}

impl NegativeCase {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Generation),
            2 => Some(Self::Task),
            3 => Some(Self::Status),
            4 => Some(Self::Owner),
            5 => Some(Self::Arena),
            6 => Some(Self::CurrentHart),
            7 => Some(Self::SpaceObject),
            8 => Some(Self::CSpaceIncarnation),
            9 => Some(Self::Duplicate),
            10 => Some(Self::AbaSeed),
            _ => None,
        }
    }

    fn witness_mismatch(self) -> Option<AcceptanceWitnessMismatch> {
        match self {
            Self::Generation => Some(AcceptanceWitnessMismatch::Generation),
            Self::Task => Some(AcceptanceWitnessMismatch::Task),
            Self::Status => Some(AcceptanceWitnessMismatch::Status),
            Self::Owner => Some(AcceptanceWitnessMismatch::Owner),
            Self::Arena => Some(AcceptanceWitnessMismatch::Arena),
            Self::CurrentHart => Some(AcceptanceWitnessMismatch::CurrentHart),
            Self::SpaceObject | Self::CSpaceIncarnation | Self::Duplicate | Self::AbaSeed => None,
        }
    }

    fn seal_mismatch(self) -> Option<AcceptanceSealMismatch> {
        match self {
            Self::SpaceObject => Some(AcceptanceSealMismatch::SpaceObject),
            Self::CSpaceIncarnation => Some(AcceptanceSealMismatch::CSpaceIncarnation),
            _ => None,
        }
    }
}

const MISMATCH_CASES: [NegativeCase; 8] = [
    NegativeCase::Generation,
    NegativeCase::Task,
    NegativeCase::Status,
    NegativeCase::Owner,
    NegativeCase::Arena,
    NegativeCase::CurrentHart,
    NegativeCase::SpaceObject,
    NegativeCase::CSpaceIncarnation,
];

static NEG_REGISTRY: InstanceRegistry = InstanceRegistry::new();
static NEG_CONTROL: ControlGate = ControlGate::new();
static NEG_RAW_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);
static NEG_RAW_RECLAIMS: AtomicUsize = AtomicUsize::new(0);
static NEG_REPLAY_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);
static ABA_STALE_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);

struct NegativeRouteSlot {
    state: AtomicU8,
    kind: AtomicU8,
    outcome: AtomicU8,
    task: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    token: UnsafeCell<MaybeUninit<InstanceToken>>,
    key: UnsafeCell<MaybeUninit<ControlKey>>,
    before: UnsafeCell<MaybeUninit<AcceptanceInstanceProbe>>,
    exact_witness: UnsafeCell<MaybeUninit<ReclaimableFaultWitness>>,
}

unsafe impl Sync for NegativeRouteSlot {}

impl NegativeRouteSlot {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(NEG_FREE),
            kind: AtomicU8::new(0),
            outcome: AtomicU8::new(NEG_OUTCOME_NONE),
            task: AtomicU64::new(0),
            owner: AtomicU64::new(0),
            arena: AtomicU64::new(0),
            token: UnsafeCell::new(MaybeUninit::uninit()),
            key: UnsafeCell::new(MaybeUninit::uninit()),
            before: UnsafeCell::new(MaybeUninit::uninit()),
            exact_witness: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn arm(
        &self,
        kind: NegativeCase,
        token: InstanceToken,
        key: ControlKey,
        handle: &TaskHandle,
        domain: AllocationDomain,
        before: AcceptanceInstanceProbe,
    ) -> bool {
        if self.state.load(Ordering::Acquire) != NEG_FREE {
            return false;
        }
        unsafe {
            (*self.token.get()).write(token);
            (*self.key.get()).write(key);
            (*self.before.get()).write(before);
        }
        self.kind.store(kind as u8, Ordering::Relaxed);
        self.outcome.store(NEG_OUTCOME_NONE, Ordering::Relaxed);
        self.task.store(handle.id().0, Ordering::Relaxed);
        self.owner.store(domain.owner.get(), Ordering::Relaxed);
        self.arena.store(domain.arena.get(), Ordering::Relaxed);
        self.state.store(NEG_ARMED, Ordering::Release);
        true
    }

    fn matches(&self, witness: ReclaimableFaultWitness) -> bool {
        self.state.load(Ordering::Acquire) == NEG_ARMED
            && self.task.load(Ordering::Relaxed) == witness.task_id().0
            && self.owner.load(Ordering::Relaxed) == witness.allocation_domain().owner.get()
            && self.arena.load(Ordering::Relaxed) == witness.allocation_domain().arena.get()
            && witness.instance_token() == Some(self.token())
    }

    fn kind(&self) -> Option<NegativeCase> {
        NegativeCase::from_raw(self.kind.load(Ordering::Relaxed))
    }

    fn token(&self) -> InstanceToken {
        unsafe { (*self.token.get()).assume_init() }
    }

    fn key(&self) -> ControlKey {
        unsafe { (*self.key.get()).assume_init() }
    }

    fn before(&self) -> AcceptanceInstanceProbe {
        unsafe { (*self.before.get()).assume_init() }
    }

    fn exact_witness(&self) -> ReclaimableFaultWitness {
        unsafe { (*self.exact_witness.get()).assume_init() }
    }

    fn finish(&self, outcome: u8) {
        self.outcome.store(outcome, Ordering::Relaxed);
        self.state.store(NEG_DONE, Ordering::Release);
    }

    fn clear(&self) {
        self.kind.store(0, Ordering::Relaxed);
        self.outcome.store(NEG_OUTCOME_NONE, Ordering::Relaxed);
        self.task.store(0, Ordering::Relaxed);
        self.owner.store(0, Ordering::Relaxed);
        self.arena.store(0, Ordering::Relaxed);
        self.state.store(NEG_FREE, Ordering::Release);
    }
}

static NEG_ROUTE: NegativeRouteSlot = NegativeRouteSlot::new();

struct NegativeFaultFuture {
    token: InstanceToken,
}

impl Future for NegativeFaultFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let witness = crate::exec::current_reclaimable_task_witness()
            .expect("negative managed task has no executor witness");
        assert_eq!(witness.instance_token(), Some(self.token));
        panic!("deliberate C4.8 negative managed fault");
    }
}

struct NegativePendingFuture {
    token: InstanceToken,
}

impl Future for NegativePendingFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let witness = crate::exec::current_reclaimable_task_witness()
            .expect("negative pending task has no executor witness");
        assert_eq!(witness.instance_token(), Some(self.token));
        Poll::Pending
    }
}

const _: () = {
    assert!(core::mem::size_of::<NegativeFaultFuture>() == core::mem::size_of::<InstanceToken>());
    assert!(core::mem::size_of::<NegativePendingFuture>() == core::mem::size_of::<InstanceToken>());
};

struct NegativeInstance {
    token: InstanceToken,
    key: ControlKey,
    handle: TaskHandle,
    domain: AllocationDomain,
    before: AcceptanceInstanceProbe,
}

fn same_control_key(left: ControlKey, right: ControlKey) -> bool {
    left.slot == right.slot && left.generation == right.generation
}

fn start_negative(kind: NegativeCase, pending: bool) -> Result<NegativeInstance, ()> {
    if !pending && NEG_ROUTE.state.load(Ordering::Acquire) != NEG_FREE {
        return Err(());
    }
    let mut control = NEG_CONTROL.try_lock().map_err(|_| ())?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let key = control.reserve(&NEG_CONTROL).ok_or(())?;
    let owner = HEAP.create_owner(INSTANCE_HEAP_QUOTA).map_err(|_| ())?;
    let arena = HEAP.create_arena(owner).map_err(|_| ())?;
    let domain = AllocationDomain::new(owner, arena);
    let token = NEG_REGISTRY
        .reserve_named(domain, "wasm-c48-negative")
        .map_err(|_| ())?;
    {
        let record = control.exact_mut(key).ok_or(())?;
        record.core_token = Some(token);
        record.domain = Some(domain);
    }

    let mut batch = PreparedTaskBatch::new();
    unsafe {
        if pending {
            batch.prepare_managed_instance_owned(
                token,
                domain,
                "wasm-c48-aba-replacement",
                NegativePendingFuture { token },
            );
        } else {
            batch.prepare_managed_instance_owned(
                token,
                domain,
                "wasm-c48-negative",
                NegativeFaultFuture { token },
            );
        }
    }
    let handle = batch.prepared_handles().first().ok_or(())?.clone();
    let binding = *batch.prepared_reclaimable_bindings().first().ok_or(())?;
    NEG_REGISTRY.bind(token, binding, &handle).map_err(|_| ())?;
    let mut handles = unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| NEG_REGISTRY.activate_batch(bindings))
    }
    .map_err(|_| ())?;
    let published = handles.pop().ok_or(())?;
    if !handles.is_empty()
        || published.id() != handle.id()
        || published.allocation_domain() != domain
        || !published.shares_status_with(&handle)
        || !control.starting_tuple_is_unique(key, token, &published, domain)
    {
        let _ = NEG_REGISTRY.quarantine(token);
        control.exact_mut(key).ok_or(())?.quarantine();
        system.restore();
        return Err(());
    }
    {
        let record = control.exact_mut(key).ok_or(())?;
        record.handle = Some(published.clone());
        record.phase = ControlPhase::Running;
    }
    let before = NEG_REGISTRY.acceptance_probe(token).ok_or(())?;
    if !before.is_exact()
        || before.exact_phase() != Some(InstancePhase::Active)
        || !before.seal_matches_space()
        || !before.seal_matches_cspace()
        || before.capability_table_len() != 0
    {
        let _ = NEG_REGISTRY.quarantine(token);
        control.exact_mut(key).ok_or(())?.quarantine();
        system.restore();
        return Err(());
    }
    if let Some(mismatch) = kind.seal_mismatch() {
        if unsafe { NEG_REGISTRY.corrupt_active_seal(token, mismatch) }.is_err() {
            let _ = NEG_REGISTRY.quarantine(token);
            control.exact_mut(key).ok_or(())?.quarantine();
            system.restore();
            return Err(());
        }
    }
    if !pending && !NEG_ROUTE.arm(kind, token, key, &published, domain, before) {
        let _ = NEG_REGISTRY.quarantine(token);
        control.exact_mut(key).ok_or(())?.quarantine();
        system.restore();
        return Err(());
    }
    system.restore();
    drop(control);
    Ok(NegativeInstance {
        token,
        key,
        handle: published,
        domain,
        before,
    })
}

fn quarantine_negative_control(key: ControlKey) {
    if let Ok(mut control) = NEG_CONTROL.try_lock() {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
    }
}

/// Route one deliberately faulted negative instance through an isolated
/// SYSTEM registry. No negative result can change production lifecycle health
/// or reopen its SSH policy gate.
pub(super) unsafe fn route_fault(witness: ReclaimableFaultWitness) -> Option<FaultRoute> {
    if !NEG_ROUTE.matches(witness)
        || NEG_ROUTE
            .state
            .compare_exchange(NEG_ARMED, NEG_ROUTING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return None;
    }
    unsafe { (*NEG_ROUTE.exact_witness.get()).write(witness) };
    let Some(kind) = NEG_ROUTE.kind() else {
        fail(ERROR_NEGATIVE_ROUTE);
        NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
        return Some(FaultRoute::Quarantined);
    };
    let exact_token = NEG_ROUTE.token();
    let key = NEG_ROUTE.key();
    let routed = match kind.witness_mismatch() {
        Some(mismatch) => match witness.with_acceptance_mismatch(mismatch) {
            Some(witness) => witness,
            None => {
                fail(ERROR_NEGATIVE_ROUTE);
                let _ = NEG_REGISTRY.quarantine(exact_token);
                quarantine_negative_control(key);
                NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
                return Some(FaultRoute::Quarantined);
            }
        },
        None => witness,
    };

    let mut control = match unsafe {
        NEG_CONTROL.try_lock_detached(witness.task_id(), witness.allocation_domain())
    } {
        Ok(control) => control,
        Err(_) => {
            fail(ERROR_NEGATIVE_ROUTE);
            let _ = NEG_REGISTRY.quarantine(exact_token);
            NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
            return Some(FaultRoute::Quarantined);
        }
    };
    let routed_key = match control.fault_tuple(routed) {
        Ok(routed_key) => routed_key,
        Err(()) => {
            let _ = NEG_REGISTRY.quarantine(exact_token);
            NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
            return Some(FaultRoute::Quarantined);
        }
    };
    if !same_control_key(key, routed_key) {
        fail(ERROR_NEGATIVE_ROUTE);
        let _ = NEG_REGISTRY.quarantine(exact_token);
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
        return Some(FaultRoute::Quarantined);
    }

    let authorize_raw = matches!(kind, NegativeCase::Duplicate | NegativeCase::AbaSeed);
    let task = witness.task_id();
    let outcome = unsafe {
        NEG_REGISTRY.fault_reclaim(routed, |domain| {
            NEG_RAW_AUTHORIZATIONS.fetch_add(1, Ordering::AcqRel);
            if !authorize_raw {
                return false;
            }
            let reclaimed = super::reclaim_authorized_domain(task, domain, true);
            if reclaimed {
                NEG_RAW_RECLAIMS.fetch_add(1, Ordering::AcqRel);
            }
            reclaimed
        })
    };
    match outcome {
        FaultGateOutcome::ManagedReclaimed => {
            if kind == NegativeCase::Duplicate {
                let replay = unsafe {
                    NEG_REGISTRY.fault_reclaim(witness, |_| {
                        NEG_REPLAY_AUTHORIZATIONS.fetch_add(1, Ordering::AcqRel);
                        false
                    })
                };
                if replay != FaultGateOutcome::Quarantined
                    || NEG_REPLAY_AUTHORIZATIONS.load(Ordering::Acquire) != 0
                {
                    fail(ERROR_NEGATIVE_RESULT);
                }
                control
                    .exact_mut(key)
                    .expect("duplicate control record remains exact")
                    .quarantine();
            }
            NEG_ROUTE.finish(NEG_OUTCOME_RECLAIMED);
            Some(FaultRoute::ManagedReclaimed)
        }
        FaultGateOutcome::NotManaged | FaultGateOutcome::Quarantined => {
            control
                .exact_mut(key)
                .expect("negative control record remains exact")
                .quarantine();
            NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
            Some(FaultRoute::Quarantined)
        }
    }
}

async fn wait_for_terminal(token: ManagedComponentToken, expected: ComponentTerminal) -> bool {
    let started = crate::sbi::time();
    loop {
        match observe_instance(token) {
            ManagedComponentState::Complete(terminal) => return terminal == expected,
            ManagedComponentState::Lost => return false,
            ManagedComponentState::Running => {}
        }
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

fn token_is_acknowledged(token: ManagedComponentToken) -> Result<bool, ControlGateError> {
    let Some(key) = managed_token_key(token) else {
        return Ok(false);
    };
    let control = CONTROL.try_lock()?;
    Ok(control.exact(key).is_some_and(|record| {
        matches!(
            record.phase,
            ControlPhase::Complete {
                acknowledged: true,
                ..
            }
        ) && record.core_token.is_none()
            && record.handle.is_none()
            && record.domain.is_none()
    }))
}

async fn acknowledge_until_stable(token: ManagedComponentToken) -> bool {
    let started = crate::sbi::time();
    loop {
        acknowledge_instance(token);
        match token_is_acknowledged(token) {
            Ok(true) => return true,
            Ok(false) | Err(ControlGateError::Busy) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Ok(false)
            | Err(ControlGateError::Busy)
            | Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => return false,
        }
    }
}

async fn start_positive(round: u8, hart: u8) -> Option<ManagedComponentToken> {
    let started = crate::sbi::time();
    loop {
        match start_image_instance(false, PayloadMode::AcceptanceFault { round, hart }) {
            Ok(token) => return Some(token),
            Err(ComponentTerminal::Unavailable) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Err(_) => return None,
        }
    }
}

fn positive_postconditions(index: usize) -> bool {
    let slot = &POSITIVE[index];
    if slot.stage.load(Ordering::Acquire) != POS_COMPLETE {
        return false;
    }
    let before = slot.before();
    let Some(after) = registry().acceptance_probe(slot.token()) else {
        return false;
    };
    let expected_generation = before.current_generation().checked_add(1);
    let expected_incarnation = before
        .cspace_incarnation()
        .and_then(|value| value.checked_add(1));
    !after.is_exact()
        && after.current_phase() == InstancePhase::Vacant
        && Some(after.current_generation()) == expected_generation
        && before.same_space_object(after)
        && before.same_cspace_lock(after)
        && before.same_cspace_identity(after)
        && before.same_capability_table(after)
        && expected_incarnation == after.cspace_incarnation()
        && after.capability_table_len() == 0
        && HEAP
            .arena_stats(ArenaId::new(slot.arena.load(Ordering::Relaxed)))
            .is_none()
        && HEAP
            .account_stats(OwnerId::new(slot.owner.load(Ordering::Relaxed)))
            .is_none()
}

async fn wait_for_supervisors_to_retire() -> bool {
    let started = crate::sbi::time();
    loop {
        let report = crate::exec::task_report();
        let present = report
            .iter()
            .any(|task| task.name == "wasm-instance-supervisor");
        drop(report);
        if !present {
            return true;
        }
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

fn capture_round_snapshot() -> RoundSnapshot {
    let live_tasks = crate::exec::task_report().len();
    RoundSnapshot {
        heap: HEAP.snapshot(),
        live_tasks,
        reclaimable_domains: crate::exec::reclaimable_domain_count(),
        timers: crate::exec::timer_registration_count(),
        irq_probes: crate::exec::irq_poll_probe_count(),
    }
}

async fn finish_positive_round(round: usize) {
    let previous = ROUND_DONE[round].fetch_add(1, Ordering::AcqRel);
    if previous >= HARTS as u8 {
        fail(ERROR_POSITIVE_BASELINE);
        return;
    }
    if previous == (HARTS - 1) as u8 {
        if !wait_for_supervisors_to_retire().await {
            fail(ERROR_POSITIVE_BASELINE);
        }
        ROUND_EVIDENCE[round].publish(capture_round_snapshot());
    }
    let started = crate::sbi::time();
    while ROUND_EVIDENCE[round].get().is_none() {
        if deadline_expired(started) {
            fail(ERROR_POSITIVE_BASELINE);
            return;
        }
        crate::exec::yield_now().await;
    }
}

async fn signal_cross_hart_continuation(round: usize, source_hart: usize) -> bool {
    let started = crate::sbi::time();
    while PARKED_MASKS[round].load(Ordering::Acquire) != 0x0f {
        if deadline_expired(started) {
            fail(ERROR_CONTINUATION_FAULT);
            return false;
        }
        crate::exec::yield_now().await;
    }

    // Each pinned SYSTEM worker signals the next hart's component. Give the
    // scheduler two opportunities before signalling and require the parked
    // task's poll count to remain unchanged across both: an External wait must
    // not self-wake or spin.
    let target_hart = (source_hart + 1) % HARTS;
    let slot = &POSITIVE[round * HARTS + target_hart];
    let parked_polls = slot.park_polls.load(Ordering::Relaxed);
    let mut no_spin = slot.stage.load(Ordering::Acquire) == POS_CONTINUATION_PARKED
        && slot.handle().polls() == parked_polls;
    for _ in 0..2 {
        crate::exec::yield_now().await;
        no_spin &= slot.stage.load(Ordering::Acquire) == POS_CONTINUATION_PARKED
            && slot.handle().polls() == parked_polls;
    }
    let cross_hart = crate::ipi::current_logical_hart()
        .is_some_and(|current| current.index() == source_hart)
        && source_hart != target_hart;
    let operation = slot.continuation();
    slot.signal_hart.store(source_hart as u8, Ordering::Relaxed);
    if slot
        .stage
        .compare_exchange(
            POS_CONTINUATION_PARKED,
            POS_CONTINUATION_SIGNALLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        fail(ERROR_CONTINUATION_FAULT);
        return false;
    }
    let signalled = registry().signal_continuation(operation);
    if !no_spin || !cross_hart || signalled != InstanceContinuationSignal::Signalled {
        fail(ERROR_CONTINUATION_FAULT);
        return false;
    }
    C52_CROSS_HART_SIGNALS.fetch_add(1, Ordering::AcqRel);
    true
}

async fn positive_worker(hart: usize) {
    for round in 0..ROUNDS {
        let Some(token) = start_positive(round as u8, hart as u8).await else {
            fail(ERROR_POSITIVE_WORKER);
            READY_MASKS[round].fetch_or(1 << hart, Ordering::AcqRel);
            finish_positive_round(round).await;
            continue;
        };
        if !signal_cross_hart_continuation(round, hart).await {
            fail(ERROR_POSITIVE_WORKER);
        }
        let index = round * HARTS + hart;
        if !wait_for_terminal(token, ComponentTerminal::RunnerFault).await
            || !positive_postconditions(index)
        {
            fail(ERROR_POSITIVE_WORKER);
        }
        if !acknowledge_until_stable(token).await {
            fail(ERROR_POSITIVE_WORKER);
        }
        if POSITIVE[index]
            .stage
            .compare_exchange(POS_COMPLETE, POS_DONE, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            fail(ERROR_POSITIVE_WORKER);
        }
        finish_positive_round(round).await;
    }
}

fn positive_reuse_is_exact() -> bool {
    for round in 1..ROUNDS {
        for hart in 0..HARTS {
            let current = &POSITIVE[round * HARTS + hart];
            let mut matching_previous = None;
            let mut matches = 0;
            for previous in &POSITIVE[(round - 1) * HARTS..round * HARTS] {
                if current.token().shares_stable_slot(previous.token()) {
                    matching_previous = Some(previous);
                    matches += 1;
                }
            }
            let Some(previous) = matching_previous else {
                return false;
            };
            let current_probe = current.before();
            let previous_probe = previous.before();
            if matches != 1
                || !current_probe.is_exact()
                || current_probe.exact_phase() != Some(InstancePhase::Active)
                || !current_probe.same_space_object(previous_probe)
                || !current_probe.same_cspace_lock(previous_probe)
                || !current_probe.same_cspace_identity(previous_probe)
                || !current_probe.same_capability_table(previous_probe)
                || current_probe.current_generation()
                    != previous_probe.current_generation().saturating_add(1)
                || current_probe.cspace_incarnation()
                    != previous_probe
                        .cspace_incarnation()
                        .and_then(|value| value.checked_add(1))
            {
                return false;
            }
        }
    }
    true
}

fn positive_baselines_are_stable() -> bool {
    // Allocator bump/peak gauges and global timer/IRQ totals include concurrent
    // VSH and network activity, so they are diagnostic snapshots rather than
    // equality gates.  Live bytes/tasks/domains remain strict, and the exact
    // TaskStatus registration ledger is drained and checked separately for
    // every positive fault instance before its raw reclaim.
    let Some(reference) = ROUND_EVIDENCE[2].get() else {
        return false;
    };
    for round in 3..ROUNDS {
        let Some(current) = ROUND_EVIDENCE[round].get() else {
            return false;
        };
        if current.heap.live_bytes != reference.heap.live_bytes
            || current.live_tasks != reference.live_tasks
            || current.reclaimable_domains != reference.reclaimable_domains
        {
            return false;
        }
    }
    true
}

async fn run_positive_matrix() {
    if crate::online_hart_count() < HARTS || crate::online_hart_mask() & 0x0f != 0x0f {
        fail(ERROR_POSITIVE_WORKER);
        return;
    }
    let mut workers = Vec::new();
    if workers.try_reserve_exact(HARTS).is_err() {
        fail(ERROR_POSITIVE_WORKER);
        return;
    }
    for hart in 0..HARTS {
        let Some(hart_id) = crate::exec::HartId::new(hart) else {
            fail(ERROR_POSITIVE_WORKER);
            return;
        };
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let worker = crate::exec::spawn_pinned_on(
            hart_id,
            "wasm-c48-positive-worker",
            positive_worker(hart),
        );
        system.restore();
        workers.push(worker);
    }
    for worker in workers {
        if worker.join().await.state() != TaskState::Exited {
            fail(ERROR_POSITIVE_WORKER);
        }
    }
    let stats = registry().occupancy_stats();
    if POSITIVE_RAW_RECLAIMS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || POSITIVE_RESETS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || POSITIVE_REGISTRATION_DRAINS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C52_PARKS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C52_RESUMES.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C52_CROSS_HART_SIGNALS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C52_STALE_REJECTS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C52_LIVE_FAULTS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || FAULT_PAYLOAD_DROPS.load(Ordering::Acquire) != 0
        || HART_FAULTS
            .iter()
            .any(|faults| faults.load(Ordering::Acquire) != ROUNDS)
        || READY_MASKS
            .iter()
            .any(|mask| mask.load(Ordering::Acquire) != 0x0f)
        || PARKED_MASKS
            .iter()
            .any(|mask| mask.load(Ordering::Acquire) != 0x0f)
        || ROUND_DONE
            .iter()
            .any(|done| done.load(Ordering::Acquire) != HARTS as u8)
        || POSITIVE
            .iter()
            .any(|slot| slot.stage.load(Ordering::Acquire) != POS_DONE)
        || stats.occupied != 0
        || stats.header_mismatches != 0
        || !positive_reuse_is_exact()
        || !positive_baselines_are_stable()
    {
        fail(ERROR_POSITIVE_BASELINE);
    }
}

fn unchanged_quarantined_probe(
    before: AcceptanceInstanceProbe,
    after: AcceptanceInstanceProbe,
) -> bool {
    after.is_exact()
        && after.exact_phase() == Some(InstancePhase::Quarantined)
        && after.current_generation() == before.current_generation()
        && before.same_space_object(after)
        && before.same_cspace_lock(after)
        && before.same_cspace_identity(after)
        && before.same_cspace_incarnation(after)
        && before.same_capability_table(after)
        && after.capability_table_len() == 0
}

fn negative_control_matches(
    instance: &NegativeInstance,
    expected: ControlPhase,
    retain_tuple: bool,
) -> bool {
    let Ok(control) = NEG_CONTROL.try_lock() else {
        return false;
    };
    control.exact(instance.key).is_some_and(|record| {
        record.phase == expected
            && if retain_tuple {
                record.core_token == Some(instance.token)
                    && record.domain == Some(instance.domain)
                    && record.handle.as_ref().is_some_and(|handle| {
                        handle.id() == instance.handle.id()
                            && handle.allocation_domain() == instance.domain
                            && handle.shares_status_with(&instance.handle)
                    })
            } else {
                record.core_token.is_none() && record.domain.is_none() && record.handle.is_none()
            }
    })
}

async fn run_mismatch_case(kind: NegativeCase) {
    let raw_authorizations = NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire);
    let raw_reclaims = NEG_RAW_RECLAIMS.load(Ordering::Acquire);
    let Ok(instance) = start_negative(kind, false) else {
        fail(ERROR_NEGATIVE_RESULT);
        return;
    };
    let exit = instance.handle.join().await;
    let route_done = NEG_ROUTE.state.load(Ordering::Acquire) == NEG_DONE
        && NEG_ROUTE.outcome.load(Ordering::Relaxed) == NEG_OUTCOME_QUARANTINED
        && NEG_ROUTE.before() == instance.before;
    let after = NEG_REGISTRY.acceptance_probe(instance.token);
    let retained = HEAP.arena_stats(instance.domain.arena).is_some()
        && HEAP.account_stats(instance.domain.owner).is_some();
    let valid = exit.state() == TaskState::Faulted
        && route_done
        && after.is_some_and(|after| unchanged_quarantined_probe(instance.before, after))
        && retained
        && negative_control_matches(&instance, ControlPhase::Quarantined, true)
        && NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire) == raw_authorizations
        && NEG_RAW_RECLAIMS.load(Ordering::Acquire) == raw_reclaims
        && lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED;
    if !valid {
        fail(ERROR_NEGATIVE_RESULT);
    }
    NEG_ROUTE.clear();
}

async fn run_duplicate_case() {
    let raw_authorizations = NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire);
    let raw_reclaims = NEG_RAW_RECLAIMS.load(Ordering::Acquire);
    let replay_authorizations = NEG_REPLAY_AUTHORIZATIONS.load(Ordering::Acquire);
    let Ok(instance) = start_negative(NegativeCase::Duplicate, false) else {
        fail(ERROR_NEGATIVE_RESULT);
        return;
    };
    let exit = instance.handle.join().await;
    let after = NEG_REGISTRY.acceptance_probe(instance.token);
    let valid = exit.state() == TaskState::Faulted
        && NEG_ROUTE.state.load(Ordering::Acquire) == NEG_DONE
        && NEG_ROUTE.outcome.load(Ordering::Relaxed) == NEG_OUTCOME_RECLAIMED
        && after.is_some_and(|after| unchanged_quarantined_probe(instance.before, after))
        && HEAP.arena_stats(instance.domain.arena).is_none()
        && HEAP.account_stats(instance.domain.owner).is_some()
        && negative_control_matches(&instance, ControlPhase::Quarantined, true)
        && NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire) == raw_authorizations + 1
        && NEG_RAW_RECLAIMS.load(Ordering::Acquire) == raw_reclaims + 1
        && NEG_REPLAY_AUTHORIZATIONS.load(Ordering::Acquire) == replay_authorizations
        && lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED;
    if !valid {
        fail(ERROR_NEGATIVE_RESULT);
    }
    NEG_ROUTE.clear();
}

fn finalize_negative_seed(instance: &NegativeInstance) -> Option<u64> {
    let mut control = NEG_CONTROL.try_lock().ok()?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let tuple = control.running_tuple(instance.key).ok()??;
    if tuple.core_token != instance.token
        || tuple.handle.id() != instance.handle.id()
        || !tuple.handle.shares_status_with(&instance.handle)
        || tuple.domain != instance.domain
        || tuple.handle.try_exit()?.state() != TaskState::Faulted
    {
        system.restore();
        return None;
    }
    let outcome = unsafe {
        NEG_REGISTRY.finalize(instance.token, &tuple.handle, |domain, kind| {
            kind == TerminalRetireKind::FaultReclaimed
                && domain == instance.domain
                && HEAP.unregister_owner(domain.owner).is_ok()
        })
    }
    .ok()?;
    let record = control.exact_mut(instance.key)?;
    if record.phase != ControlPhase::Running
        || record.core_token != Some(instance.token)
        || record.domain != Some(instance.domain)
        || record.handle.as_ref().is_none_or(|handle| {
            handle.id() != instance.handle.id() || !handle.shares_status_with(&instance.handle)
        })
    {
        record.quarantine();
        system.restore();
        return None;
    }
    record.phase = ControlPhase::Complete {
        terminal: ComponentTerminal::RunnerFault,
        acknowledged: true,
    };
    record.core_token = None;
    record.handle = None;
    record.domain = None;
    system.restore();
    Some(outcome.next_cspace_incarnation)
}

async fn wait_until_polled(handle: &TaskHandle) -> bool {
    let started = crate::sbi::time();
    while handle.polls() == 0 {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn run_aba_case() {
    let raw_authorizations = NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire);
    let raw_reclaims = NEG_RAW_RECLAIMS.load(Ordering::Acquire);
    let Ok(seed) = start_negative(NegativeCase::AbaSeed, false) else {
        fail(ERROR_ABA);
        return;
    };
    let exit = seed.handle.join().await;
    if exit.state() != TaskState::Faulted
        || NEG_ROUTE.state.load(Ordering::Acquire) != NEG_DONE
        || NEG_ROUTE.outcome.load(Ordering::Relaxed) != NEG_OUTCOME_RECLAIMED
        || NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire) != raw_authorizations + 1
        || NEG_RAW_RECLAIMS.load(Ordering::Acquire) != raw_reclaims + 1
    {
        fail(ERROR_ABA);
        NEG_ROUTE.clear();
        return;
    }
    let stale_witness = NEG_ROUTE.exact_witness();
    let Some(next_incarnation) = finalize_negative_seed(&seed) else {
        fail(ERROR_ABA);
        NEG_ROUTE.clear();
        return;
    };
    let seed_after = NEG_REGISTRY.acceptance_probe(seed.token);
    let seed_finalized = seed_after.is_some_and(|after| {
        !after.is_exact()
            && after.current_phase() == InstancePhase::Vacant
            && seed.before.same_space_object(after)
            && seed.before.same_cspace_lock(after)
            && seed.before.same_cspace_identity(after)
            && seed.before.same_capability_table(after)
            && after.cspace_incarnation() == Some(next_incarnation)
            && seed
                .before
                .cspace_incarnation()
                .and_then(|value| value.checked_add(1))
                == Some(next_incarnation)
            && after.capability_table_len() == 0
    });
    if !seed_finalized
        || HEAP.arena_stats(seed.domain.arena).is_some()
        || HEAP.account_stats(seed.domain.owner).is_some()
        || !negative_control_matches(
            &seed,
            ControlPhase::Complete {
                terminal: ComponentTerminal::RunnerFault,
                acknowledged: true,
            },
            false,
        )
    {
        fail(ERROR_ABA);
    }
    NEG_ROUTE.clear();

    let Ok(replacement) = start_negative(NegativeCase::AbaSeed, true) else {
        fail(ERROR_ABA);
        return;
    };
    if !seed.token.shares_stable_slot(replacement.token)
        || !seed.before.same_space_object(replacement.before)
        || !seed.before.same_cspace_lock(replacement.before)
        || !seed.before.same_cspace_identity(replacement.before)
        || !seed.before.same_capability_table(replacement.before)
        || replacement.before.cspace_incarnation() != Some(next_incarnation)
        || !wait_until_polled(&replacement.handle).await
    {
        fail(ERROR_ABA);
    }

    let stale_authorizations = ABA_STALE_AUTHORIZATIONS.load(Ordering::Acquire);
    let mut outer_rejected = false;
    let mut core_outcome = FaultGateOutcome::NotManaged;
    if let Ok(mut control) = unsafe {
        NEG_CONTROL.try_lock_detached(stale_witness.task_id(), stale_witness.allocation_domain())
    } {
        outer_rejected = control.fault_tuple(stale_witness).is_err();
        core_outcome = unsafe {
            NEG_REGISTRY.fault_reclaim(stale_witness, |_| {
                ABA_STALE_AUTHORIZATIONS.fetch_add(1, Ordering::AcqRel);
                false
            })
        };
        if !outer_rejected {
            if let Some(record) = control.exact_mut(replacement.key) {
                record.quarantine();
            }
        }
    }
    let replacement_after = NEG_REGISTRY.acceptance_probe(replacement.token);
    let stale_after = NEG_REGISTRY.acceptance_probe(seed.token);
    let aba_valid = outer_rejected
        && core_outcome == FaultGateOutcome::Quarantined
        && ABA_STALE_AUTHORIZATIONS.load(Ordering::Acquire) == stale_authorizations
        && replacement_after
            .is_some_and(|after| unchanged_quarantined_probe(replacement.before, after))
        && stale_after.is_some_and(|after| {
            !after.is_exact()
                && after.current_phase() == InstancePhase::Quarantined
                && replacement_after.is_some_and(|current| {
                    after.current_generation() == current.current_generation()
                        && after.same_space_object(current)
                        && after.same_cspace_lock(current)
                        && after.same_cspace_identity(current)
                        && after.same_cspace_incarnation(current)
                        && after.same_capability_table(current)
                })
        })
        && replacement.handle.state() == TaskState::Running
        && HEAP.arena_stats(replacement.domain.arena).is_some()
        && HEAP.account_stats(replacement.domain.owner).is_some()
        && negative_control_matches(&replacement, ControlPhase::Quarantined, true)
        && lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED;
    if !aba_valid {
        fail(ERROR_ABA);
    }
}

async fn run_normal_production_probe() {
    let Some(token) = start_positive_command().await else {
        fail(ERROR_NORMAL_PROBE);
        return;
    };
    if !wait_for_terminal(token, ComponentTerminal::Success).await {
        fail(ERROR_NORMAL_PROBE);
        return;
    }
    if !acknowledge_until_stable(token).await {
        fail(ERROR_NORMAL_PROBE);
    }
    if !wait_for_supervisors_to_retire().await {
        fail(ERROR_NORMAL_PROBE);
    }
    let stats = registry().occupancy_stats();
    if stats.occupied != 0 || stats.header_mismatches != 0 {
        fail(ERROR_NORMAL_PROBE);
    }
}

async fn start_positive_command() -> Option<ManagedComponentToken> {
    let started = crate::sbi::time();
    loop {
        match start_image_instance(false, PayloadMode::Command) {
            Ok(token) => return Some(token),
            Err(ComponentTerminal::Unavailable) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Err(_) => return None,
        }
    }
}

fn production_control_is_terminal_and_acknowledged(control: &ControlTable) -> bool {
    control.slots.iter().all(|record| match record.phase {
        ControlPhase::Vacant => {
            record.core_token.is_none() && record.handle.is_none() && record.domain.is_none()
        }
        ControlPhase::Complete {
            acknowledged: true, ..
        } => record.core_token.is_none() && record.handle.is_none() && record.domain.is_none(),
        ControlPhase::Starting
        | ControlPhase::Running
        | ControlPhase::Complete {
            acknowledged: false,
            ..
        }
        | ControlPhase::Quarantined => false,
    })
}

fn try_open_production_policy_gate() -> Result<bool, ControlGateError> {
    let control = CONTROL.try_lock()?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let root_valid = image_root().is_some_and(revalidate_image_root);
    let registry_stats = registry().occupancy_stats();
    let ready = lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED
        && root_valid
        && registry_stats.occupied == 0
        && registry_stats.header_mismatches == 0
        && production_control_is_terminal_and_acknowledged(&control)
        && ERRORS.load(Ordering::Acquire) == 0;
    let opened = ready
        && SSH_POLICY_GATE
            .compare_exchange(
                POLICY_CLOSED,
                POLICY_PASSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
    system.restore();
    Ok(
        opened
            && lifecycle_is_healthy()
            && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_PASSED,
    )
}

async fn open_production_policy_gate() -> bool {
    let started = crate::sbi::time();
    loop {
        match try_open_production_policy_gate() {
            Ok(opened) => return opened,
            Err(ControlGateError::Busy) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Err(ControlGateError::Busy)
            | Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => return false,
        }
    }
}

fn initial_state_is_closed_and_clean() -> bool {
    let production = registry().occupancy_stats();
    let negative = NEG_REGISTRY.occupancy_stats();
    lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED
        && image_root().is_some_and(revalidate_image_root)
        && production.occupied == 0
        && production.header_mismatches == 0
        && negative.occupied == 0
        && negative.header_mismatches == 0
        && ERRORS.load(Ordering::Acquire) == 0
        && NEG_ROUTE.state.load(Ordering::Acquire) == NEG_FREE
}

static RUN_STATE: AtomicU8 = AtomicU8::new(0);

pub(super) async fn run() -> bool {
    if RUN_STATE
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    if !initial_state_is_closed_and_clean() {
        fail(ERROR_POLICY_GATE);
    } else {
        run_positive_matrix().await;
        for kind in MISMATCH_CASES {
            run_mismatch_case(kind).await;
        }
        run_duplicate_case().await;
        run_aba_case().await;
        run_normal_production_probe().await;

        let negative = NEG_REGISTRY.occupancy_stats();
        if negative.occupied != 10
            || negative.header_mismatches != 0
            || negative.phase_count(InstancePhase::Quarantined) != 10
            || NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire) != 2
            || NEG_RAW_RECLAIMS.load(Ordering::Acquire) != 2
            || NEG_REPLAY_AUTHORIZATIONS.load(Ordering::Acquire) != 0
            || ABA_STALE_AUTHORIZATIONS.load(Ordering::Acquire) != 0
        {
            fail(ERROR_NEGATIVE_RESULT);
        }
    }

    if ERRORS.load(Ordering::Acquire) == 0 && open_production_policy_gate().await {
        RUN_STATE.store(2, Ordering::Release);
        println!(
            "WASM_C52_ACCEPTANCE PASS parks={} resumes={} cross_hart_signals={} stale_rejects={} live_faults={}",
            C52_PARKS.load(Ordering::Acquire),
            C52_RESUMES.load(Ordering::Acquire),
            C52_CROSS_HART_SIGNALS.load(Ordering::Acquire),
            C52_STALE_REJECTS.load(Ordering::Acquire),
            C52_LIVE_FAULTS.load(Ordering::Acquire),
        );
        println!(
            "WASM_C48_ACCEPTANCE PASS faults={} harts={} policy=passed",
            POSITIVE_RAW_RECLAIMS.load(Ordering::Acquire),
            HARTS
        );
        true
    } else {
        fail(ERROR_POLICY_GATE);
        lifecycle_fail_stop();
        RUN_STATE.store(3, Ordering::Release);
        for (round, evidence) in ROUND_EVIDENCE.iter().enumerate() {
            if let Some(snapshot) = evidence.get() {
                println!(
                    "WASM_C48_ACCEPTANCE round={} ready={:#x} done={} live={} reclaimable={} heap_live={} bump_used={} bump_remaining={} timers={} irq={}",
                    round,
                    READY_MASKS[round].load(Ordering::Acquire),
                    ROUND_DONE[round].load(Ordering::Acquire),
                    snapshot.live_tasks,
                    snapshot.reclaimable_domains,
                    snapshot.heap.live_bytes,
                    snapshot.heap.bump_used_bytes,
                    snapshot.heap.bump_remaining_bytes,
                    snapshot.timers,
                    snapshot.irq_probes,
                );
            }
        }
        println!(
            "WASM_C52_ACCEPTANCE FAIL errors={:#x} parks={} resumes={} cross_hart_signals={} stale_rejects={} live_faults={}",
            ERRORS.load(Ordering::Acquire),
            C52_PARKS.load(Ordering::Acquire),
            C52_RESUMES.load(Ordering::Acquire),
            C52_CROSS_HART_SIGNALS.load(Ordering::Acquire),
            C52_STALE_REJECTS.load(Ordering::Acquire),
            C52_LIVE_FAULTS.load(Ordering::Acquire),
        );
        println!(
            "WASM_C48_ACCEPTANCE FAIL errors={:#x}",
            ERRORS.load(Ordering::Acquire)
        );
        false
    }
}
