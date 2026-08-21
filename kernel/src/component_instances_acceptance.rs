//! QEMU-only C4.8/C5.2/C5.3 target evidence for the managed component lifecycle.
//!
//! Positive cycles use the production CONTROL/INSTANCES path.  Deliberate
//! identity corruptions use a separate SYSTEM-owned registry and control gate,
//! so proving sticky quarantine never requires a forbidden Failed -> Healthy
//! transition before the real SSH image/session gate is opened.

use alloc::{sync::Arc, vec::Vec};
use core::any::Any;
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
const NEGATIVE_STREAM_CAPABILITIES: usize = 4;
const NEGATIVE_SENTINEL_CAPABILITIES: usize = 1;
const NEGATIVE_CAPABILITIES: usize = NEGATIVE_STREAM_CAPABILITIES + NEGATIVE_SENTINEL_CAPABILITIES;

const _: () = assert!(NEGATIVE_CAPABILITIES == 5);

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
const ERROR_C53_PREPARE: u64 = 1 << 15;
const ERROR_C53_ARM: u64 = 1 << 16;
const ERROR_C53_BACKPRESSURE: u64 = 1 << 17;
const ERROR_C53_HOST_PENDING: u64 = 1 << 18;
const ERROR_C53_WAKE: u64 = 1 << 19;
const ERROR_C53_RESUME: u64 = 1 << 20;
const ERROR_C53_STREAM: u64 = 1 << 21;
const ERROR_C53_TERMINAL: u64 = 1 << 22;
const ERROR_C53_BASELINE: u64 = 1 << 23;
const ERROR_C53_TERMINAL_RACE: u64 = 1 << 24;

static ERRORS: AtomicU64 = AtomicU64::new(0);
static POSITIVE_RAW_RECLAIMS: AtomicUsize = AtomicUsize::new(0);
static POSITIVE_RESETS: AtomicUsize = AtomicUsize::new(0);
static POSITIVE_REGISTRATION_DRAINS: AtomicUsize = AtomicUsize::new(0);
static C52_PARKS: AtomicUsize = AtomicUsize::new(0);
static C52_RESUMES: AtomicUsize = AtomicUsize::new(0);
static C52_CROSS_HART_SIGNALS: AtomicUsize = AtomicUsize::new(0);
static C52_STALE_REJECTS: AtomicUsize = AtomicUsize::new(0);
static C52_LIVE_FAULTS: AtomicUsize = AtomicUsize::new(0);
static C53_PAIRS: AtomicUsize = AtomicUsize::new(0);
static C53_INPUT_CHUNKS: AtomicUsize = AtomicUsize::new(0);
static C53_OUTPUT_CHUNKS: AtomicUsize = AtomicUsize::new(0);
static C53_XOR_BYTES: AtomicUsize = AtomicUsize::new(0);
static C53_BACKEND_PENDING: AtomicUsize = AtomicUsize::new(0);
static C53_BACKEND_WAKES: AtomicUsize = AtomicUsize::new(0);
static C53_HOST_PENDING: AtomicUsize = AtomicUsize::new(0);
static C53_EXACT_WAKES: AtomicUsize = AtomicUsize::new(0);
static C53_EXACT_RESUMES: AtomicUsize = AtomicUsize::new(0);
static C53_LATE_WAKE_REJECTS: AtomicUsize = AtomicUsize::new(0);
static C53_EOF: AtomicUsize = AtomicUsize::new(0);
static C53_NORMAL_CLOSES: AtomicUsize = AtomicUsize::new(0);
static C53_TERMINAL_MATCHES: AtomicUsize = AtomicUsize::new(0);
static C53_TERMINAL_ORDERS: AtomicUsize = AtomicUsize::new(0);
static C53_CLOSE_RACES: AtomicUsize = AtomicUsize::new(0);
static C53_TERMINAL_MAPPINGS: AtomicUsize = AtomicUsize::new(0);
static C53_START_ERROR_TERMINALS: AtomicUsize = AtomicUsize::new(0);
static C53_TERMINAL_RACES: AtomicUsize = AtomicUsize::new(0);
static C53_CANCEL_BUSY_RETRIES: AtomicUsize = AtomicUsize::new(0);
static C53_COMPLETION_BUSY_RETRIES: AtomicUsize = AtomicUsize::new(0);
static C53_MISMATCH_REJECTS: AtomicUsize = AtomicUsize::new(0);
static C53_DUPLICATE_FAULT_REJECTS: AtomicUsize = AtomicUsize::new(0);
static C53_ABA_REJECTS: AtomicUsize = AtomicUsize::new(0);
static FAULT_PAYLOAD_DROPS: AtomicUsize = AtomicUsize::new(0);
static HART_FAULTS: [AtomicUsize; HARTS] = [const { AtomicUsize::new(0) }; HARTS];
static C53_HART_PAIRS: [AtomicUsize; HARTS] = [const { AtomicUsize::new(0) }; HARTS];
static READY_MASKS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static PARKED_MASKS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static ROUND_DONE: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static C53_ROUND_DONE: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static C53_PENDING_MASKS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static C53_INPUT_TURNS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static C53_DRAIN_TURNS: [AtomicU8; ROUNDS] = [const { AtomicU8::new(0) }; ROUNDS];
static C53_INPUT_WAKE_GATE: AtomicUsize = AtomicUsize::new(0);
static C53_WAKE_GATE: AtomicUsize = AtomicUsize::new(0);
static C53_START_INTENT: AtomicBool = AtomicBool::new(false);

const TERMINAL_RACE_SUCCESS_FIRST: u8 = 1;
const TERMINAL_RACE_RETURNED_FIRST: u8 = 2;
const TERMINAL_RACE_CANCEL_FIRST: u8 = 3;
const TERMINAL_RACE_IDLE: u8 = 0;
const TERMINAL_RACE_ARMED: u8 = 1;
const TERMINAL_RACE_PAYLOAD_BLOCKED: u8 = 2;
const TERMINAL_RACE_PAYLOAD_RELEASED: u8 = 3;
const TERMINAL_RACE_PAYLOAD_FOLDED: u8 = 4;
const TERMINAL_RACE_HOLD_REQUESTED: u8 = 1;
const TERMINAL_RACE_CONTROL_HELD: u8 = 2;
const TERMINAL_RACE_BUSY_OBSERVED: u8 = 3;
const TERMINAL_RACE_CONTROL_RELEASED: u8 = 4;
const TERMINAL_RACE_COMPLETION_ARMED: u8 = 1;
const TERMINAL_RACE_COMPLETION_EDGE: u8 = 2;
const TERMINAL_RACE_COMPLETION_HELD: u8 = 3;
const TERMINAL_RACE_COMPLETION_BUSY: u8 = 4;
const TERMINAL_RACE_COMPLETION_RELEASED: u8 = 5;

static TERMINAL_RACE_CASE: AtomicU8 = AtomicU8::new(TERMINAL_RACE_IDLE);
static TERMINAL_RACE_EXPECTED: AtomicU64 = AtomicU64::new(0);
static TERMINAL_RACE_KEY_SLOT: AtomicU8 = AtomicU8::new(u8::MAX);
static TERMINAL_RACE_KEY_GENERATION: AtomicU64 = AtomicU64::new(0);
static TERMINAL_RACE_TASK: AtomicU64 = AtomicU64::new(0);
static TERMINAL_RACE_OWNER: AtomicU64 = AtomicU64::new(0);
static TERMINAL_RACE_ARENA: AtomicU64 = AtomicU64::new(0);
static TERMINAL_RACE_PAYLOAD: AtomicU8 = AtomicU8::new(TERMINAL_RACE_IDLE);
static TERMINAL_RACE_LISTENER_ARMED: AtomicBool = AtomicBool::new(false);
static TERMINAL_RACE_CANCEL_HOLD: AtomicU8 = AtomicU8::new(TERMINAL_RACE_IDLE);
static TERMINAL_RACE_COMPLETION: AtomicU8 = AtomicU8::new(TERMINAL_RACE_IDLE);
static TERMINAL_RACE_CANCEL_VALID: AtomicBool = AtomicBool::new(false);
static TERMINAL_RACE_OBSERVED_TERMINAL: AtomicU64 = AtomicU64::new(0);

const C53_FREE: u8 = 0;
const C53_PUMP_READY: u8 = 1;
const C53_ARMED: u8 = 2;
const C53_TERMINAL_VISIBLE: u8 = 3;
const C53_STREAM_TERMINAL_PUBLISHED: u8 = 4;
const C53_OWNER_RETIRED: u8 = 5;
const C53_CSPACE_RESET: u8 = 6;
const C53_COMPLETE: u8 = 7;
const C53_DONE: u8 = 8;

struct C53Slot {
    stage: AtomicU8,
    task: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    round: AtomicU8,
    hart: AtomicU8,
    input_woken: AtomicBool,
    host_pending: AtomicBool,
    exact_wake: AtomicBool,
    exact_resume: AtomicBool,
    eof: AtomicBool,
    close_mask: AtomicU8,
    token: UnsafeCell<MaybeUninit<InstanceToken>>,
    handle: UnsafeCell<MaybeUninit<TaskHandle>>,
    before: UnsafeCell<MaybeUninit<AcceptanceInstanceProbe>>,
    pending_operation: UnsafeCell<MaybeUninit<HostOperationToken>>,
}

unsafe impl Sync for C53Slot {}

impl C53Slot {
    const fn new() -> Self {
        Self {
            stage: AtomicU8::new(C53_FREE),
            task: AtomicU64::new(0),
            owner: AtomicU64::new(0),
            arena: AtomicU64::new(0),
            round: AtomicU8::new(0),
            hart: AtomicU8::new(0),
            input_woken: AtomicBool::new(false),
            host_pending: AtomicBool::new(false),
            exact_wake: AtomicBool::new(false),
            exact_resume: AtomicBool::new(false),
            eof: AtomicBool::new(false),
            close_mask: AtomicU8::new(0),
            token: UnsafeCell::new(MaybeUninit::uninit()),
            handle: UnsafeCell::new(MaybeUninit::uninit()),
            before: UnsafeCell::new(MaybeUninit::uninit()),
            pending_operation: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn matches(&self, task: TaskId, domain: AllocationDomain) -> bool {
        self.stage.load(Ordering::Acquire) >= C53_ARMED
            && self.task.load(Ordering::Relaxed) == task.0
            && self.owner.load(Ordering::Relaxed) == domain.owner.get()
            && self.arena.load(Ordering::Relaxed) == domain.arena.get()
    }

    fn token(&self) -> InstanceToken {
        unsafe { (*self.token.get()).assume_init() }
    }

    unsafe fn release_handle(&self) {
        unsafe { (*self.handle.get()).assume_init_drop() };
    }

    fn before(&self) -> AcceptanceInstanceProbe {
        unsafe { (*self.before.get()).assume_init() }
    }

    fn pending_operation(&self) -> HostOperationToken {
        unsafe { (*self.pending_operation.get()).assume_init() }
    }
}

static C53: [C53Slot; POSITIVE_CYCLES] = [const { C53Slot::new() }; POSITIVE_CYCLES];

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

fn terminal_race_key_matches(key: ControlKey) -> bool {
    TERMINAL_RACE_CASE.load(Ordering::Acquire) != TERMINAL_RACE_IDLE
        && TERMINAL_RACE_KEY_SLOT.load(Ordering::Relaxed) == key.slot
        && TERMINAL_RACE_KEY_GENERATION.load(Ordering::Relaxed) == key.generation
}

fn terminal_race_arm(case: u8, terminal: ComponentTerminal) -> bool {
    if !matches!(
        case,
        TERMINAL_RACE_SUCCESS_FIRST | TERMINAL_RACE_RETURNED_FIRST | TERMINAL_RACE_CANCEL_FIRST
    ) || TERMINAL_RACE_CASE
        .compare_exchange(
            TERMINAL_RACE_IDLE,
            case,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return false;
    }
    TERMINAL_RACE_EXPECTED.store(terminal_word(terminal), Ordering::Release);
    TERMINAL_RACE_KEY_SLOT.store(u8::MAX, Ordering::Relaxed);
    TERMINAL_RACE_KEY_GENERATION.store(0, Ordering::Relaxed);
    TERMINAL_RACE_TASK.store(0, Ordering::Relaxed);
    TERMINAL_RACE_OWNER.store(0, Ordering::Relaxed);
    TERMINAL_RACE_ARENA.store(0, Ordering::Relaxed);
    TERMINAL_RACE_PAYLOAD.store(TERMINAL_RACE_ARMED, Ordering::Release);
    TERMINAL_RACE_LISTENER_ARMED.store(false, Ordering::Release);
    TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_HOLD_REQUESTED, Ordering::Release);
    TERMINAL_RACE_COMPLETION.store(TERMINAL_RACE_COMPLETION_ARMED, Ordering::Release);
    TERMINAL_RACE_CANCEL_VALID.store(false, Ordering::Release);
    TERMINAL_RACE_OBSERVED_TERMINAL.store(0, Ordering::Release);
    true
}

fn terminal_race_bind(key: ControlKey, handle: &TaskHandle, domain: AllocationDomain) -> bool {
    if TERMINAL_RACE_CASE.load(Ordering::Acquire) == TERMINAL_RACE_IDLE
        || TERMINAL_RACE_KEY_SLOT.load(Ordering::Acquire) != u8::MAX
        || handle.allocation_domain() != domain
    {
        return false;
    }
    TERMINAL_RACE_KEY_SLOT.store(key.slot, Ordering::Relaxed);
    TERMINAL_RACE_KEY_GENERATION.store(key.generation, Ordering::Relaxed);
    TERMINAL_RACE_TASK.store(handle.id().0, Ordering::Relaxed);
    TERMINAL_RACE_OWNER.store(domain.owner.get(), Ordering::Relaxed);
    TERMINAL_RACE_ARENA.store(domain.arena.get(), Ordering::Release);
    true
}

fn terminal_race_bound_identity_matches(key: ControlKey, handle: &TaskHandle) -> bool {
    terminal_race_key_matches(key)
        && handle.id().0 == TERMINAL_RACE_TASK.load(Ordering::Relaxed)
        && handle.allocation_domain().owner.get() == TERMINAL_RACE_OWNER.load(Ordering::Relaxed)
        && handle.allocation_domain().arena.get() == TERMINAL_RACE_ARENA.load(Ordering::Relaxed)
}

fn terminal_race_spin_until(state: &AtomicU8, expected: u8) -> bool {
    let started = crate::sbi::time();
    while state.load(Ordering::Acquire) != expected {
        if deadline_expired(started) {
            fail(ERROR_C53_TERMINAL_RACE);
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

pub(super) fn terminal_race_before_publish(case: u8, terminal: ComponentTerminal) {
    if case != TERMINAL_RACE_CANCEL_FIRST {
        return;
    }
    if TERMINAL_RACE_CASE.load(Ordering::Acquire) != case
        || TERMINAL_RACE_EXPECTED.load(Ordering::Acquire) != terminal_word(terminal)
        || TERMINAL_RACE_PAYLOAD
            .compare_exchange(
                TERMINAL_RACE_ARMED,
                TERMINAL_RACE_PAYLOAD_BLOCKED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_C53_TERMINAL_RACE);
        return;
    }
    let _ = terminal_race_spin_until(&TERMINAL_RACE_PAYLOAD, TERMINAL_RACE_PAYLOAD_RELEASED);
}

pub(super) fn terminal_race_after_publish(
    case: u8,
    original: ComponentTerminal,
    effective: ComponentTerminal,
) {
    if TERMINAL_RACE_CASE.load(Ordering::Acquire) != case
        || TERMINAL_RACE_EXPECTED.load(Ordering::Acquire) != terminal_word(original)
    {
        fail(ERROR_C53_TERMINAL_RACE);
        return;
    }
    if case == TERMINAL_RACE_CANCEL_FIRST {
        if effective != ComponentTerminal::Cancelled
            || TERMINAL_RACE_PAYLOAD
                .compare_exchange(
                    TERMINAL_RACE_PAYLOAD_RELEASED,
                    TERMINAL_RACE_PAYLOAD_FOLDED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            fail(ERROR_C53_TERMINAL_RACE);
        }
        return;
    }
    if effective != original
        || TERMINAL_RACE_PAYLOAD
            .compare_exchange(
                TERMINAL_RACE_ARMED,
                TERMINAL_RACE_PAYLOAD_BLOCKED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_C53_TERMINAL_RACE);
        return;
    }
    let _ = terminal_race_spin_until(&TERMINAL_RACE_PAYLOAD, TERMINAL_RACE_PAYLOAD_RELEASED);
}

pub(super) fn terminal_race_listener_armed(key: ControlKey) {
    if terminal_race_key_matches(key) {
        TERMINAL_RACE_LISTENER_ARMED.store(true, Ordering::Release);
    }
}

pub(super) fn terminal_race_completion_edge(key: ControlKey) {
    if !terminal_race_key_matches(key) {
        return;
    }
    if TERMINAL_RACE_COMPLETION
        .compare_exchange(
            TERMINAL_RACE_COMPLETION_ARMED,
            TERMINAL_RACE_COMPLETION_EDGE,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        fail(ERROR_C53_TERMINAL_RACE);
        return;
    }
}

pub(super) async fn terminal_race_listener_returned(key: ControlKey) {
    if !terminal_race_key_matches(key) {
        return;
    }
    let started = crate::sbi::time();
    while TERMINAL_RACE_COMPLETION.load(Ordering::Acquire) != TERMINAL_RACE_COMPLETION_HELD {
        if deadline_expired(started) {
            fail(ERROR_C53_TERMINAL_RACE);
            return;
        }
        crate::exec::yield_now().await;
    }
}

pub(super) fn terminal_race_observed_control_busy() {
    if TERMINAL_RACE_COMPLETION
        .compare_exchange(
            TERMINAL_RACE_COMPLETION_HELD,
            TERMINAL_RACE_COMPLETION_BUSY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok()
    {
        C53_COMPLETION_BUSY_RETRIES.fetch_add(1, Ordering::AcqRel);
    }
}

pub(super) fn component_start_intent() -> bool {
    C53_START_INTENT.load(Ordering::Acquire)
}

fn positive_index(round: u8, hart: u8) -> Option<usize> {
    let round = usize::from(round);
    let hart = usize::from(hart);
    (round < ROUNDS && hart < HARTS).then_some(round * HARTS + hart)
}

fn c53_for_token(token: InstanceToken) -> Option<&'static C53Slot> {
    C53.iter()
        .find(|slot| slot.stage.load(Ordering::Acquire) >= C53_ARMED && slot.token() == token)
}

fn c53_for(task: TaskId, domain: AllocationDomain) -> Option<&'static C53Slot> {
    C53.iter().find(|slot| slot.matches(task, domain))
}

fn prepare_c53_slot(round: u8, hart: u8) -> Option<(usize, &'static C53Slot)> {
    let index = positive_index(round, hart)?;
    let slot = &C53[index];
    if slot
        .stage
        .compare_exchange(
            C53_FREE,
            C53_PUMP_READY,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return None;
    }
    slot.round.store(round, Ordering::Relaxed);
    slot.hart.store(hart, Ordering::Relaxed);
    Some((index, slot))
}

fn c53_input_wake(_words: [usize; 4]) {
    let encoded = C53_INPUT_WAKE_GATE.swap(0, Ordering::AcqRel);
    let Some(slot) = encoded.checked_sub(1).and_then(|index| C53.get(index)) else {
        fail(ERROR_C53_WAKE);
        return;
    };
    if slot.stage.load(Ordering::Acquire) < C53_PUMP_READY
        || slot.input_woken.swap(true, Ordering::AcqRel)
    {
        fail(ERROR_C53_BACKPRESSURE);
        return;
    }
    C53_BACKEND_WAKES.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn arm_stream(
    _key: ControlKey,
    token: InstanceToken,
    handle: &TaskHandle,
    domain: AllocationDomain,
    round: u8,
    hart: u8,
) -> bool {
    let Some(index) = positive_index(round, hart) else {
        fail(ERROR_C53_ARM);
        return false;
    };
    let slot = &C53[index];
    let snapshot = registry().snapshot(token);
    let probe = registry().acceptance_probe(token);
    let valid = slot.stage.load(Ordering::Acquire) == C53_PUMP_READY
        && handle.allocation_domain() == domain
        && snapshot.as_ref().is_ok_and(|snapshot| {
            snapshot.phase == InstancePhase::Active
                && snapshot.domain == domain
                && snapshot.task == Some(handle.id())
                && snapshot
                    .home_hart
                    .is_some_and(|home| home.index() == usize::from(hart))
        })
        && probe.is_some_and(|probe| {
            probe.is_exact()
                && probe.exact_phase() == Some(InstancePhase::Active)
                && probe.seal_matches_space()
                && probe.seal_matches_cspace()
                && probe.capability_table_len() == 4
                && probe.installed_capability_count() == 4
        });
    if !valid {
        fail(ERROR_C53_ARM);
        return false;
    }
    unsafe {
        (*slot.token.get()).write(token);
        (*slot.handle.get()).write(handle.clone());
        (*slot.before.get()).write(probe.expect("validated C5.3 acceptance probe exists"));
    }
    slot.task.store(handle.id().0, Ordering::Relaxed);
    slot.owner.store(domain.owner.get(), Ordering::Relaxed);
    slot.arena.store(domain.arena.get(), Ordering::Relaxed);
    if slot
        .stage
        .compare_exchange(
            C53_PUMP_READY,
            C53_ARMED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        fail(ERROR_C53_ARM);
        return false;
    }
    C53_PAIRS.fetch_add(1, Ordering::AcqRel);
    C53_HART_PAIRS[usize::from(hart)].fetch_add(1, Ordering::AcqRel);
    true
}

/// Record the single output-ring backpressure edge only after the component
/// runtime installed the exact wake token for that host operation.
pub(super) fn record_stream_host_pending(token: InstanceToken, operation: HostOperationToken) {
    let Some(slot) = c53_for_token(token) else {
        return;
    };
    let exact = slot.stage.load(Ordering::Acquire) == C53_ARMED
        && registry().acceptance_probe(token).is_some_and(|probe| {
            probe.is_exact()
                && probe.exact_phase() == Some(InstancePhase::Active)
                && probe.seal_matches_space()
                && probe.seal_matches_cspace()
                && probe.capability_table_len() == 4
                && probe.installed_capability_count() == 4
        })
        && !slot.host_pending.load(Ordering::Acquire);
    if !exact {
        fail(ERROR_C53_HOST_PENDING);
        return;
    }
    unsafe { (*slot.pending_operation.get()).write(operation) };
    if slot.host_pending.swap(true, Ordering::Release) {
        fail(ERROR_C53_HOST_PENDING);
        return;
    }
    C53_HOST_PENDING.fetch_add(1, Ordering::AcqRel);
    C53_PENDING_MASKS[usize::from(slot.round.load(Ordering::Relaxed))]
        .fetch_or(1 << slot.hart.load(Ordering::Relaxed), Ordering::AcqRel);
}

/// Observe one signal only while the acceptance pump has opened the bounded
/// output-drain window. No callback word is retained, decoded, or correlated.
pub(super) fn record_stream_wake(outcome: InstanceContinuationSignal) {
    let encoded = C53_WAKE_GATE.swap(0, Ordering::AcqRel);
    if encoded == 0 {
        // Ordinary production and input-side wakeups share this callback.
        return;
    }
    let Some(slot) = encoded.checked_sub(1).and_then(|index| C53.get(index)) else {
        fail(ERROR_C53_WAKE);
        return;
    };
    if outcome != InstanceContinuationSignal::Signalled
        || slot.exact_wake.swap(true, Ordering::AcqRel)
    {
        fail(ERROR_C53_WAKE);
        return;
    }
    C53_EXACT_WAKES.fetch_add(1, Ordering::AcqRel);
}

/// Record the matching writer-host resume. Opaque late-token rejection remains
/// exercised by the core C5.2 continuation matrix; this layer never retains
/// or decodes the host callback representation.
pub(super) fn record_stream_resume(token: InstanceToken, operation: HostOperationToken) {
    let Some(slot) = c53_for_token(token) else {
        return;
    };
    let exact = slot.stage.load(Ordering::Acquire) == C53_ARMED
        && slot.host_pending.load(Ordering::Acquire)
        && slot.exact_wake.load(Ordering::Acquire)
        && slot.pending_operation() == operation
        && !slot.exact_resume.swap(true, Ordering::AcqRel);
    if !exact
        || !registry().acceptance_probe(token).is_some_and(|probe| {
            probe.is_exact()
                && probe.exact_phase() == Some(InstancePhase::Active)
                && probe.seal_matches_space()
                && probe.seal_matches_cspace()
                && probe.capability_table_len() == 4
                && probe.installed_capability_count() == 4
        })
    {
        fail(ERROR_C53_RESUME);
        return;
    }
    C53_EXACT_RESUMES.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn record_stream_eof(token: InstanceToken) {
    let Some(slot) = c53_for_token(token) else {
        return;
    };
    if !slot.exact_resume.load(Ordering::Acquire) || slot.eof.swap(true, Ordering::AcqRel) {
        fail(ERROR_C53_STREAM);
        return;
    }
    C53_EOF.fetch_add(1, Ordering::AcqRel);
}

pub(super) fn record_stream_normal_close(token: InstanceToken, reader: bool) {
    let Some(slot) = c53_for_token(token) else {
        return;
    };
    let bit = if reader { 1 } else { 2 };
    let previous = slot.close_mask.fetch_or(bit, Ordering::AcqRel);
    if !slot.eof.load(Ordering::Acquire) || previous & bit != 0 {
        fail(ERROR_C53_STREAM);
        return;
    }
    C53_NORMAL_CLOSES.fetch_add(1, Ordering::AcqRel);
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
            && probe.capability_table_len() == 4
            && probe.installed_capability_count() == 4
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
                    println!(
                        "WASM_C52_DIAG round={} hart={} first-park-identity",
                        self.round, self.hart
                    );
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
                    println!(
                        "WASM_C52_DIAG round={} hart={} first-park-stage={}",
                        self.round,
                        self.hart,
                        slot.stage.load(Ordering::Acquire),
                    );
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
                println!(
                    "WASM_C52_DIAG round={} hart={} first-resume-spurious-pending",
                    self.round, self.hart
                );
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
                    && slot.park_polls.load(Ordering::Relaxed) < resume_polls;
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
                    println!(
                        "WASM_C52_DIAG round={} hart={} first-resume-identity stage={} polls={}/{} signal_hart={}",
                        self.round,
                        self.hart,
                        slot.stage.load(Ordering::Acquire),
                        slot.park_polls.load(Ordering::Acquire),
                        resume_polls,
                        slot.signal_hart.load(Ordering::Acquire),
                    );
                    fail(ERROR_CONTINUATION_FAULT);
                    return Poll::Ready(Err(()));
                }
                C52_RESUMES.fetch_add(1, Ordering::AcqRel);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(())) | Poll::Ready(Err(_)) => {
                println!(
                    "WASM_C52_DIAG round={} hart={} first-resume-terminal-shape",
                    self.round, self.hart
                );
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
                    || registrations.total != 2
                    || registrations.waits != 1
                    || registrations.timers != 0
                    || registrations.joins != 0
                    || registrations.irq_poll_probes != 0
                    || registrations.task_detaches != 1
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
                    println!(
                        "WASM_C52_DIAG round={} hart={} pending-precondition exact={} stage={} regs={}/{}/{}/{}/{}/{}",
                        self.round,
                        self.hart,
                        exact,
                        slot.stage.load(Ordering::Acquire),
                        registrations.total,
                        registrations.waits,
                        registrations.timers,
                        registrations.joins,
                        registrations.irq_poll_probes,
                        registrations.task_detaches,
                    );
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
            Err(error) => {
                println!(
                    "WASM_C52_DIAG round={} hart={} first-arm={error:?}",
                    round, hart
                );
                fail(ERROR_CONTINUATION_FAULT);
                return;
            }
        };
    let continuation = match registry().wait_continuation(operation) {
        Ok(continuation) => continuation,
        Err(error) => {
            println!(
                "WASM_C52_DIAG round={} hart={} first-wait={error:?}",
                round, hart
            );
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
        println!(
            "WASM_C52_DIAG round={} hart={} first-resume-failed",
            round, hart
        );
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
        println!(
            "WASM_C52_DIAG round={} hart={} stale-check-failed signal={stale:?}",
            round, hart
        );
        fail(ERROR_CONTINUATION_FAULT);
        return;
    }
    C52_STALE_REJECTS.fetch_add(1, Ordering::AcqRel);
    C53_LATE_WAKE_REJECTS.fetch_add(1, Ordering::AcqRel);

    let fault_operation =
        match registry().arm_continuation_current(token, InstanceContinuationKind::External) {
            Ok(fault_operation) if fault_operation != operation => fault_operation,
            Ok(_) => {
                println!(
                    "WASM_C52_DIAG round={} hart={} second-arm-reused-token",
                    round, hart
                );
                fail(ERROR_CONTINUATION_FAULT);
                return;
            }
            Err(error) => {
                println!(
                    "WASM_C52_DIAG round={} hart={} second-arm={error:?}",
                    round, hart
                );
                fail(ERROR_CONTINUATION_FAULT);
                return;
            }
        };
    let continuation = match registry().wait_continuation(fault_operation) {
        Ok(continuation) => continuation,
        Err(error) => {
            println!(
                "WASM_C52_DIAG round={} hart={} second-wait={error:?}",
                round, hart
            );
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
    println!(
        "WASM_C52_DIAG round={} hart={} pending-fault-returned",
        round, hart
    );
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
    if let Some(slot) = c53_for(handle.id(), domain) {
        let registrations = handle.acceptance_registration_stats();
        if state != TaskState::Exited
            || registrations.total != 0
            || registrations.waits != 0
            || registrations.timers != 0
            || registrations.joins != 0
            || registrations.irq_poll_probes != 0
            || !slot.host_pending.load(Ordering::Acquire)
            || !slot.exact_wake.load(Ordering::Acquire)
            || !slot.exact_resume.load(Ordering::Acquire)
            || !slot.eof.load(Ordering::Acquire)
            || slot.close_mask.load(Ordering::Acquire) != 3
            || slot
                .stage
                .compare_exchange(
                    C53_ARMED,
                    C53_TERMINAL_VISIBLE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            fail(ERROR_C53_TERMINAL);
        } else {
            unsafe { slot.release_handle() };
        }
        return;
    }
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

pub(super) fn record_stream_terminal_published(
    task: TaskId,
    domain: AllocationDomain,
    terminal: ComponentTerminal,
    reason: StreamCloseReason,
) {
    let Some(slot) = c53_for(task, domain) else {
        return;
    };
    if terminal != ComponentTerminal::Success
        || reason != StreamCloseReason::Normal
        || slot
            .stage
            .compare_exchange(
                C53_TERMINAL_VISIBLE,
                C53_STREAM_TERMINAL_PUBLISHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        fail(ERROR_C53_TERMINAL);
    }
}

pub(super) fn record_owner_retired(
    task: TaskId,
    domain: AllocationDomain,
    kind: TerminalRetireKind,
    retired: bool,
) {
    if let Some(slot) = c53_for(task, domain) {
        if kind != TerminalRetireKind::Normal
            || !retired
            || HEAP.arena_stats(domain.arena).is_some()
            || HEAP.account_stats(domain.owner).is_some()
            || slot
                .stage
                .compare_exchange(
                    C53_STREAM_TERMINAL_PUBLISHED,
                    C53_OWNER_RETIRED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            fail(ERROR_C53_TERMINAL);
        }
        return;
    }
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
    if let Some(slot) = c53_for(task, domain) {
        let expected = slot
            .before()
            .cspace_incarnation()
            .and_then(|value| value.checked_add(1));
        if expected != Some(next_incarnation)
            || slot
                .stage
                .compare_exchange(
                    C53_OWNER_RETIRED,
                    C53_CSPACE_RESET,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            fail(ERROR_C53_TERMINAL);
        }
        return;
    }
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
    if let Some(slot) = c53_for(task, domain) {
        if terminal != ComponentTerminal::Success
            || slot
                .stage
                .compare_exchange(
                    C53_CSPACE_RESET,
                    C53_COMPLETE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            fail(ERROR_C53_TERMINAL);
        } else {
            C53_TERMINAL_MATCHES.fetch_add(1, Ordering::AcqRel);
            C53_TERMINAL_ORDERS.fetch_add(1, Ordering::AcqRel);
        }
        return;
    }
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
    CSpaceObject = 8,
    CSpaceIncarnation = 9,
    Duplicate = 10,
    AbaSeed = 11,
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
            8 => Some(Self::CSpaceObject),
            9 => Some(Self::CSpaceIncarnation),
            10 => Some(Self::Duplicate),
            11 => Some(Self::AbaSeed),
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
            Self::SpaceObject
            | Self::CSpaceObject
            | Self::CSpaceIncarnation
            | Self::Duplicate
            | Self::AbaSeed => None,
        }
    }

    fn seal_mismatch(self) -> Option<AcceptanceSealMismatch> {
        match self {
            Self::SpaceObject => Some(AcceptanceSealMismatch::SpaceObject),
            Self::CSpaceObject => Some(AcceptanceSealMismatch::CSpaceObject),
            Self::CSpaceIncarnation => Some(AcceptanceSealMismatch::CSpaceIncarnation),
            _ => None,
        }
    }
}

const MISMATCH_CASES: [NegativeCase; 9] = [
    NegativeCase::Generation,
    NegativeCase::Task,
    NegativeCase::Status,
    NegativeCase::Owner,
    NegativeCase::Arena,
    NegativeCase::CurrentHart,
    NegativeCase::SpaceObject,
    NegativeCase::CSpaceObject,
    NegativeCase::CSpaceIncarnation,
];

static NEG_REGISTRY: InstanceRegistry = InstanceRegistry::new();
static NEG_CONTROL: ControlGate = ControlGate::new();
static NEG_RAW_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);
static NEG_RAW_RECLAIMS: AtomicUsize = AtomicUsize::new(0);
static NEG_REPLAY_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);
static ABA_STALE_AUTHORIZATIONS: AtomicUsize = AtomicUsize::new(0);

struct NegativeSentinel;

impl Resource for NegativeSentinel {
    fn kind(&self) -> &'static str {
        "wasm-c53-negative-cspace-sentinel"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

struct NegativeRouteSlot {
    state: AtomicU8,
    kind: AtomicU8,
    outcome: AtomicU8,
    task: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    token: UnsafeCell<MaybeUninit<InstanceToken>>,
    key: UnsafeCell<MaybeUninit<ControlKey>>,
    streams: UnsafeCell<MaybeUninit<RegistryStreamBindings>>,
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
            streams: UnsafeCell::new(MaybeUninit::uninit()),
            before: UnsafeCell::new(MaybeUninit::uninit()),
            exact_witness: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn arm(
        &self,
        kind: NegativeCase,
        token: InstanceToken,
        key: ControlKey,
        streams: RegistryStreamBindings,
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
            (*self.streams.get()).write(streams);
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

    fn streams(&self) -> RegistryStreamBindings {
        unsafe { (*self.streams.get()).assume_init() }
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
    streams: RegistryStreamBindings,
    handle: TaskHandle,
    domain: AllocationDomain,
    before: AcceptanceInstanceProbe,
}

fn same_control_key(left: ControlKey, right: ControlKey) -> bool {
    left.slot == right.slot && left.generation == right.generation
}

fn negative_stream_projection_is_well_formed(streams: RegistryStreamBindings) -> bool {
    let caps: [Cap; NEGATIVE_STREAM_CAPABILITIES] = [
        streams.stdin,
        streams.stdout,
        streams.stdin_supervisor,
        streams.stdout_supervisor,
    ];
    streams.cspace_incarnation != 0
        && caps
            .iter()
            .enumerate()
            .all(|(index, cap)| caps.iter().skip(index + 1).all(|other| cap != other))
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

    let stdin_stream = ByteStream::new();
    let stdout_stream = ByteStream::new();
    let io = InstalledComponentIo {
        stdin: stdin_stream.reader(),
        stdout: stdout_stream.writer(),
        stdin_supervisor: stdin_stream.supervisor(),
        stdout_supervisor: stdout_stream.supervisor(),
    };
    if io.stdin.same_stream_as(&io.stdout)
        || Arc::ptr_eq(&io.stdin_supervisor, &io.stdout_supervisor)
        || !io.stdin_supervisor.same_stream_as_reader(&io.stdin)
        || io.stdin_supervisor.same_stream_as_writer(&io.stdout)
        || !io.stdout_supervisor.same_stream_as_writer(&io.stdout)
        || io.stdout_supervisor.same_stream_as_reader(&io.stdin)
    {
        let _ = NEG_REGISTRY.quarantine(token);
        control.exact_mut(key).ok_or(())?.quarantine();
        system.restore();
        return Err(());
    }
    // The stable CSpace receives the only endpoint/supervisor Arcs. These
    // construction roots are not retained by the future or control table.
    drop(stdin_stream);
    drop(stdout_stream);
    let (streams, configured_exactly) = match unsafe {
        NEG_REGISTRY.configure_reserved_space(token, move |cspace| {
            let cspace_identity = cspace.identity();
            let cspace_incarnation = cspace.incarnation();
            let stdin = cspace.mint(io.stdin, Rights::RECV);
            let stdout = cspace.mint(io.stdout, Rights::SEND);
            let stdin_supervisor = cspace.mint(io.stdin_supervisor, Rights::INVOKE);
            let stdout_supervisor = cspace.mint(io.stdout_supervisor, Rights::INVOKE);
            let sentinel = cspace.mint(Arc::new(NegativeSentinel), Rights::INVOKE);
            let streams = RegistryStreamBindings {
                cspace_identity,
                cspace_incarnation,
                stdin,
                stdout,
                stdin_supervisor,
                stdout_supervisor,
            };
            let configured_exactly = negative_stream_projection_is_well_formed(streams)
                && validate_stream_space(cspace, streams).is_ok()
                && exact_lease::<ByteStreamReader>(cspace, stdin, Rights::RECV).is_ok()
                && exact_lease::<ByteStreamWriter>(cspace, stdout, Rights::SEND).is_ok()
                && exact_lease::<ByteStreamSupervisor>(cspace, stdin_supervisor, Rights::INVOKE)
                    .is_ok()
                && exact_lease::<ByteStreamSupervisor>(cspace, stdout_supervisor, Rights::INVOKE)
                    .is_ok()
                && exact_lease::<NegativeSentinel>(cspace, sentinel, Rights::INVOKE).is_ok();
            (streams, configured_exactly)
        })
    } {
        Ok(configured) => configured,
        Err(_) => {
            let _ = NEG_REGISTRY.quarantine(token);
            control.exact_mut(key).ok_or(())?.quarantine();
            system.restore();
            return Err(());
        }
    };
    if !configured_exactly {
        let _ = NEG_REGISTRY.quarantine(token);
        control.exact_mut(key).ok_or(())?.quarantine();
        system.restore();
        return Err(());
    }
    {
        let record = control.exact_mut(key).ok_or(())?;
        if record.phase != ControlPhase::Starting
            || record.core_token.is_some()
            || record.handle.is_some()
            || record.domain.is_some()
            || record.streams.is_some()
            || record.terminal_candidate.is_some()
        {
            let _ = NEG_REGISTRY.quarantine(token);
            record.quarantine();
            system.restore();
            return Err(());
        }
        record.core_token = Some(token);
        record.domain = Some(domain);
        record.streams = Some(streams);
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
        || before.cspace_incarnation() != Some(streams.cspace_incarnation)
        || before.capability_table_len() != NEGATIVE_CAPABILITIES
        || before.installed_capability_count() != NEGATIVE_CAPABILITIES
        || control.exact(key).is_none_or(|record| {
            record.phase != ControlPhase::Running
                || record.core_token != Some(token)
                || record.domain != Some(domain)
                || record.streams != Some(streams)
                || record.terminal_candidate.is_some()
        })
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
    if !pending && !NEG_ROUTE.arm(kind, token, key, streams, &published, domain, before) {
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
        streams,
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
    let expected_streams = NEG_ROUTE.streams();
    let route_projection_is_exact = control.exact(key).is_some_and(|record| {
        record.phase == ControlPhase::Running
            && record.core_token == Some(exact_token)
            && record.handle.as_ref().is_some_and(|handle| {
                witness.matches_handle(handle)
                    && handle.allocation_domain() == witness.allocation_domain()
            })
            && record.domain == Some(witness.allocation_domain())
            && record.streams == Some(expected_streams)
            && record.terminal_candidate.is_none()
            && negative_stream_projection_is_well_formed(expected_streams)
    });
    if !route_projection_is_exact {
        fail(ERROR_NEGATIVE_ROUTE);
        let _ = NEG_REGISTRY.quarantine(exact_token);
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        NEG_ROUTE.finish(NEG_OUTCOME_QUARANTINED);
        return Some(FaultRoute::Quarantined);
    }
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
            ManagedComponentState::Busy | ManagedComponentState::Running => {}
        }
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
}

fn c53_fill_chunk(round: usize, hart: usize, chunk: usize, output: &mut [u8; 1024]) {
    for (offset, byte) in output.iter_mut().enumerate() {
        *byte = (round as u8)
            .wrapping_mul(41)
            .wrapping_add((hart as u8).wrapping_mul(67))
            .wrapping_add((chunk as u8).wrapping_mul(17))
            .wrapping_add(offset as u8);
    }
}

fn c53_receive_and_check(
    reader: &ByteStreamReader,
    round: usize,
    hart: usize,
    chunk: usize,
) -> bool {
    let prepared = match reader.start() {
        Ok(StreamReceiveDispatch::Prepared(prepared)) if prepared.length() == 1024 => prepared,
        _ => return false,
    };
    let mut actual = [0_u8; 1024];
    if reader.commit(prepared.operation(), &mut actual)
        != Ok(StreamReceiveCommit::Received(actual.len()))
    {
        return false;
    }
    let mut input = [0_u8; 1024];
    c53_fill_chunk(round, hart, chunk, &mut input);
    if !actual
        .iter()
        .zip(input.iter())
        .all(|(actual, input)| *actual == *input ^ 0x20)
    {
        return false;
    }
    C53_OUTPUT_CHUNKS.fetch_add(1, Ordering::AcqRel);
    C53_XOR_BYTES.fetch_add(actual.len(), Ordering::AcqRel);
    true
}

async fn wait_c53_flag(flag: &AtomicBool) -> bool {
    let started = crate::sbi::time();
    while !flag.load(Ordering::Acquire) {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn wait_c53_pending_round(round: usize) -> bool {
    let started = crate::sbi::time();
    while C53_PENDING_MASKS[round].load(Ordering::Acquire) != 0x0f {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn wait_c53_input_turn(round: usize, hart: usize) -> bool {
    let started = crate::sbi::time();
    while usize::from(C53_INPUT_TURNS[round].load(Ordering::Acquire)) != hart {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn wait_c53_drain_turn(round: usize, hart: usize) -> bool {
    let started = crate::sbi::time();
    while usize::from(C53_DRAIN_TURNS[round].load(Ordering::Acquire)) != hart {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn start_c53_instance(
    stdin: &Arc<ByteStream>,
    stdout: &Arc<ByteStream>,
    round: u8,
    hart: u8,
) -> Option<ManagedComponentToken> {
    let started = crate::sbi::time();
    while C53_START_INTENT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        if deadline_expired(started) {
            return None;
        }
        crate::exec::yield_now().await;
    }
    loop {
        let ready = match CONTROL.try_lock() {
            Ok(control) => {
                drop(control);
                true
            }
            Err(ControlGateError::Busy) => false,
            Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
                C53_START_INTENT.store(false, Ordering::Release);
                return None;
            }
        };
        if ready {
            break;
        }
        if deadline_expired(started) {
            C53_START_INTENT.store(false, Ordering::Release);
            return None;
        }
        crate::exec::yield_now().await;
    }
    let io = InstalledComponentIo {
        stdin: stdin.reader(),
        stdout: stdout.writer(),
        stdin_supervisor: stdin.supervisor(),
        stdout_supervisor: stdout.supervisor(),
    };
    let result =
        start_image_instance_with_io(PayloadMode::AcceptanceStream { round, hart }, io).ok();
    C53_START_INTENT.store(false, Ordering::Release);
    result
}

fn c53_postconditions(index: usize) -> bool {
    let slot = &C53[index];
    if slot.stage.load(Ordering::Acquire) != C53_COMPLETE {
        return false;
    }
    let before = slot.before();
    let Some(after) = registry().acceptance_probe(slot.token()) else {
        return false;
    };
    !after.is_exact()
        && after.current_phase() == InstancePhase::Vacant
        && before.current_generation().checked_add(1) == Some(after.current_generation())
        && before.same_space_object(after)
        && before.same_cspace_lock(after)
        && before.same_cspace_identity(after)
        && after.capability_table_len() == before.capability_table_len()
        && before
            .cspace_incarnation()
            .and_then(|value| value.checked_add(1))
            == after.cspace_incarnation()
        && after.installed_capability_count() == 0
        && HEAP
            .arena_stats(ArenaId::new(slot.arena.load(Ordering::Relaxed)))
            .is_none()
        && HEAP
            .account_stats(OwnerId::new(slot.owner.load(Ordering::Relaxed)))
            .is_none()
}

async fn run_c53_cycle(round: usize, hart: usize) -> bool {
    let Some((index, slot)) = prepare_c53_slot(round as u8, hart as u8) else {
        fail(ERROR_C53_PREPARE);
        return false;
    };
    let stdin = ByteStream::new();
    let stdout = ByteStream::new();
    let input = stdin.writer();
    let output = stdout.reader();

    let mut bytes = [0_u8; 1024];
    for chunk in 0..8 {
        c53_fill_chunk(round, hart, chunk, &mut bytes);
        if input.start(&bytes) != Ok(StreamSendDispatch::Sent) {
            fail(ERROR_C53_PREPARE);
            return false;
        }
        C53_INPUT_CHUNKS.fetch_add(1, Ordering::AcqRel);
    }
    c53_fill_chunk(round, hart, 8, &mut bytes);
    let blocked_input = match input.start(&bytes) {
        Ok(StreamSendDispatch::Waiting(operation)) => operation,
        _ => {
            fail(ERROR_C53_BACKPRESSURE);
            return false;
        }
    };
    if stdin.depth() != 8 || stdin.peak_depth() != 8 {
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }
    C53_BACKEND_PENDING.fetch_add(1, Ordering::AcqRel);
    if !wait_c53_input_turn(round, hart).await {
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }
    let backend_wakes_before = C53_BACKEND_WAKES.load(Ordering::Acquire);
    if C53_INPUT_WAKE_GATE
        .compare_exchange(0, index + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }
    let wake = HostWakeToken::new([0; 4], c53_input_wake);
    if input.register_wake(blocked_input, wake).is_err() {
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }

    let Some(token) = start_c53_instance(&stdin, &stdout, round as u8, hart as u8).await else {
        let _ = input.cancel(blocked_input);
        fail(ERROR_C53_ARM);
        return false;
    };
    if !wait_c53_flag(&slot.input_woken).await
        || C53_INPUT_WAKE_GATE.load(Ordering::Acquire) != 0
        || C53_BACKEND_WAKES.load(Ordering::Acquire) != backend_wakes_before + 1
    {
        let _ = input.close(StreamCloseReason::BackendFault);
        let _ = output.close(StreamCloseReason::BackendFault);
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }
    c53_fill_chunk(round, hart, 8, &mut bytes);
    if input.resume(blocked_input, &bytes) != Ok(StreamSendDispatch::Sent) {
        fail(ERROR_C53_BACKPRESSURE);
        return false;
    }
    C53_INPUT_CHUNKS.fetch_add(1, Ordering::AcqRel);
    if input.close(StreamCloseReason::Normal) != StreamCloseOutcome::Published {
        fail(ERROR_C53_STREAM);
        return false;
    }
    C53_INPUT_TURNS[round].store((hart + 1) as u8, Ordering::Release);

    if !wait_c53_flag(&slot.host_pending).await {
        let _ = output.close(StreamCloseReason::BackendFault);
        fail(ERROR_C53_HOST_PENDING);
        return false;
    }
    if !wait_c53_pending_round(round).await || !wait_c53_drain_turn(round, hart).await {
        fail(ERROR_C53_HOST_PENDING);
        return false;
    }
    if stdout.depth() != 8 || stdout.peak_depth() != 8 || slot.exact_wake.load(Ordering::Acquire) {
        fail(ERROR_C53_HOST_PENDING);
        return false;
    }
    let wakes_before = C53_EXACT_WAKES.load(Ordering::Acquire);
    if C53_WAKE_GATE
        .compare_exchange(0, index + 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fail(ERROR_C53_WAKE);
        return false;
    }
    if !c53_receive_and_check(&output, round, hart, 0)
        || C53_WAKE_GATE.load(Ordering::Acquire) != 0
        || C53_EXACT_WAKES.load(Ordering::Acquire) != wakes_before + 1
        || !slot.exact_wake.load(Ordering::Acquire)
        || !wait_c53_flag(&slot.exact_resume).await
    {
        fail(ERROR_C53_WAKE | ERROR_C53_RESUME);
        return false;
    }
    C53_DRAIN_TURNS[round].store((hart + 1) as u8, Ordering::Release);
    if stdout.depth() != 8 {
        fail(ERROR_C53_RESUME);
        return false;
    }
    for chunk in 1..9 {
        if !c53_receive_and_check(&output, round, hart, chunk) {
            fail(ERROR_C53_STREAM);
            return false;
        }
    }
    if stdout.depth() != 0 || !wait_for_terminal(token, ComponentTerminal::Success).await {
        fail(ERROR_C53_TERMINAL);
        return false;
    }
    if stdin.final_reason() != Some(StreamCloseReason::Normal)
        || stdout.final_reason() != Some(StreamCloseReason::Normal)
        || stdin.is_fail_stopped()
        || stdout.is_fail_stopped()
        || output.start() != Ok(StreamReceiveDispatch::Closed(StreamCloseReason::Normal))
        || !c53_postconditions(index)
        || !acknowledge_until_stable(token).await
    {
        fail(ERROR_C53_TERMINAL);
        return false;
    }
    if slot
        .stage
        .compare_exchange(C53_COMPLETE, C53_DONE, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fail(ERROR_C53_TERMINAL);
        return false;
    }
    true
}

async fn finish_c53_round(round: usize) {
    let previous = C53_ROUND_DONE[round].fetch_add(1, Ordering::AcqRel);
    if previous >= HARTS as u8 {
        fail(ERROR_C53_BASELINE);
        return;
    }
    let started = crate::sbi::time();
    while C53_ROUND_DONE[round].load(Ordering::Acquire) != HARTS as u8 {
        if deadline_expired(started) {
            fail(ERROR_C53_BASELINE);
            return;
        }
        crate::exec::yield_now().await;
    }
}

async fn c53_worker(hart: usize) {
    for round in 0..ROUNDS {
        if !run_c53_cycle(round, hart).await {
            fail(ERROR_C53_STREAM);
        }
        finish_c53_round(round).await;
    }
}

fn c53_reuse_is_exact() -> bool {
    for round in 1..ROUNDS {
        for hart in 0..HARTS {
            let current = &C53[round * HARTS + hart];
            let mut matching_previous = None;
            let mut matches = 0;
            for previous in &C53[(round - 1) * HARTS..round * HARTS] {
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
                || current_probe.capability_table_len() != 4
                || current_probe.installed_capability_count() != 4
                || !current_probe.same_space_object(previous_probe)
                || !current_probe.same_cspace_lock(previous_probe)
                || !current_probe.same_cspace_identity(previous_probe)
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

async fn run_c53_matrix() {
    if crate::online_hart_count() < HARTS || crate::online_hart_mask() & 0x0f != 0x0f {
        fail(ERROR_C53_BASELINE);
        return;
    }
    let mut workers = Vec::new();
    if workers.try_reserve_exact(HARTS).is_err() {
        fail(ERROR_C53_BASELINE);
        return;
    }
    for hart in 0..HARTS {
        let Some(hart_id) = crate::exec::HartId::new(hart) else {
            fail(ERROR_C53_BASELINE);
            return;
        };
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let worker =
            crate::exec::spawn_pinned_on(hart_id, "wasm-c53-stream-worker", c53_worker(hart));
        system.restore();
        workers.push(worker);
    }
    for worker in workers {
        if worker.join().await.state() != TaskState::Exited {
            fail(ERROR_C53_BASELINE);
        }
    }
    let stats = registry().occupancy_stats();
    if C53_PAIRS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_INPUT_CHUNKS.load(Ordering::Acquire) != POSITIVE_CYCLES * 9
        || C53_OUTPUT_CHUNKS.load(Ordering::Acquire) != POSITIVE_CYCLES * 9
        || C53_XOR_BYTES.load(Ordering::Acquire) != POSITIVE_CYCLES * 9 * 1024
        || C53_BACKEND_PENDING.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_BACKEND_WAKES.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_HOST_PENDING.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_EXACT_WAKES.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_EXACT_RESUMES.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_EOF.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_NORMAL_CLOSES.load(Ordering::Acquire) != POSITIVE_CYCLES * 2
        || C53_TERMINAL_MATCHES.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_TERMINAL_ORDERS.load(Ordering::Acquire) != POSITIVE_CYCLES
        || C53_HART_PAIRS
            .iter()
            .any(|pairs| pairs.load(Ordering::Acquire) != ROUNDS)
        || C53_ROUND_DONE
            .iter()
            .any(|done| done.load(Ordering::Acquire) != HARTS as u8)
        || C53_PENDING_MASKS
            .iter()
            .any(|mask| mask.load(Ordering::Acquire) != 0x0f)
        || C53_INPUT_TURNS
            .iter()
            .any(|turn| turn.load(Ordering::Acquire) != HARTS as u8)
        || C53_DRAIN_TURNS
            .iter()
            .any(|turn| turn.load(Ordering::Acquire) != HARTS as u8)
        || C53_INPUT_WAKE_GATE.load(Ordering::Acquire) != 0
        || C53_WAKE_GATE.load(Ordering::Acquire) != 0
        || C53
            .iter()
            .any(|slot| slot.stage.load(Ordering::Acquire) != C53_DONE)
        || stats.occupied != 0
        || stats.header_mismatches != 0
        || !c53_reuse_is_exact()
    {
        fail(ERROR_C53_BASELINE);
    }
}

fn run_c53_close_races() -> bool {
    let production_before = registry().occupancy_stats();
    let negative_before = NEG_REGISTRY.occupancy_stats();
    let mappings = [
        (
            HostError::Failed,
            ComponentTerminal::Returned(1),
            StreamCloseReason::Failure,
        ),
        (
            HostError::Cancelled,
            ComponentTerminal::Cancelled,
            StreamCloseReason::Cancelled,
        ),
        (
            HostError::InvalidState,
            ComponentTerminal::Usage,
            StreamCloseReason::Invalid,
        ),
    ];
    for (error, terminal, reason) in mappings {
        if host_error_terminal(error) != terminal || terminal.stream_close_reason() != reason {
            return false;
        }

        // Target-side regression for the prepared receive race: terminal
        // publication may clear the FIFO, but it must leave the exact
        // reservation attached until the runtime performs one cancellation.
        let stream = ByteStream::new();
        let reader = stream.reader();
        let writer = stream.writer();
        let supervisor = stream.supervisor();
        if writer.start(&[1, 2, 3]) != Ok(StreamSendDispatch::Sent) {
            return false;
        }
        let prepared = match reader.start() {
            Ok(StreamReceiveDispatch::Prepared(prepared)) => prepared,
            _ => return false,
        };
        if supervisor.finalize(reason) != StreamCloseOutcome::Published || stream.depth() != 0 {
            return false;
        }
        let mut output = [0_u8; 3];
        if reader.commit(prepared.operation(), &mut output)
            != Ok(StreamReceiveCommit::Closed(reason))
            || output != [0, 0, 0]
            || reader.cancel(prepared.operation()) != Ok(())
            || reader.cancel(prepared.operation()) != Err(StreamError::TokenMismatch)
            || stream.is_fail_stopped()
        {
            return false;
        }
        C53_TERMINAL_MAPPINGS.fetch_add(1, Ordering::AcqRel);
    }

    // Before publication there is no child finalizer. Every recoverable start
    // error must therefore use the original paired supervisors to make the
    // exact terminal visible to the SSH pump before returning Err.
    for (terminal, reason) in [
        (
            ComponentTerminal::Unavailable,
            StreamCloseReason::Unavailable,
        ),
        (
            ComponentTerminal::BudgetExceeded,
            StreamCloseReason::Exhausted,
        ),
    ] {
        let stdin = ByteStream::new();
        let stdout = ByteStream::new();
        let input = stdin.writer();
        let output = stdout.reader();
        let io = InstalledComponentIo {
            stdin: stdin.reader(),
            stdout: stdout.writer(),
            stdin_supervisor: stdin.supervisor(),
            stdout_supervisor: stdout.supervisor(),
        };
        if finalize_unpublished_start_error(&io, terminal) != terminal
            || stdin.final_reason() != Some(reason)
            || stdout.final_reason() != Some(reason)
            || input.start(&[1]) != Ok(StreamSendDispatch::Closed(reason))
            || output.start() != Ok(StreamReceiveDispatch::Closed(reason))
            || stdin.is_fail_stopped()
            || stdout.is_fail_stopped()
        {
            return false;
        }
        C53_START_ERROR_TERMINALS.fetch_add(1, Ordering::AcqRel);
    }

    // Transport Failure wins before the cooperative lifecycle publishes the
    // matching terminal. The lifecycle must confirm, not conflict or reset.
    let failure = ByteStream::new();
    let failure_writer = failure.writer();
    let failure_supervisor = failure.supervisor();
    if failure_writer.close(StreamCloseReason::Failure) != StreamCloseOutcome::Published
        || failure_supervisor.finalize(StreamCloseReason::Failure)
            != StreamCloseOutcome::AlreadyPublished
        || failure.final_reason() != Some(StreamCloseReason::Failure)
        || failure.is_fail_stopped()
    {
        return false;
    }
    C53_CLOSE_RACES.fetch_add(1, Ordering::AcqRel);

    // Cooperative cancellation wins first; a later matching transport close
    // is idempotent and cannot quarantine or generically reset any registry.
    let cancelled = ByteStream::new();
    let cancelled_writer = cancelled.writer();
    let cancelled_supervisor = cancelled.supervisor();
    if cancelled_supervisor.finalize(StreamCloseReason::Cancelled) != StreamCloseOutcome::Published
        || cancelled_writer.close(StreamCloseReason::Cancelled)
            != StreamCloseOutcome::AlreadyPublished
        || cancelled.final_reason() != Some(StreamCloseReason::Cancelled)
        || cancelled.is_fail_stopped()
    {
        return false;
    }
    C53_CLOSE_RACES.fetch_add(1, Ordering::AcqRel);

    // Normal endpoint completion is provisional. Usage/Invalid may still win
    // immutable lifecycle publication and must then be idempotent at transport.
    let invalid = ByteStream::new();
    let invalid_writer = invalid.writer();
    let invalid_supervisor = invalid.supervisor();
    if invalid_writer.close(StreamCloseReason::Normal) != StreamCloseOutcome::Published
        || invalid.final_reason().is_some()
        || invalid_supervisor.finalize(StreamCloseReason::Invalid) != StreamCloseOutcome::Published
        || invalid_writer.close(StreamCloseReason::Invalid) != StreamCloseOutcome::AlreadyPublished
        || invalid.final_reason() != Some(StreamCloseReason::Invalid)
        || invalid.is_fail_stopped()
    {
        return false;
    }
    C53_CLOSE_RACES.fetch_add(1, Ordering::AcqRel);

    let production_after = registry().occupancy_stats();
    let negative_after = NEG_REGISTRY.occupancy_stats();
    production_after.occupied == production_before.occupied
        && production_after.header_mismatches == production_before.header_mismatches
        && negative_after.occupied == negative_before.occupied
        && negative_after.header_mismatches == negative_before.header_mismatches
        && lifecycle_is_healthy()
        && SSH_POLICY_GATE.load(Ordering::Acquire) == POLICY_CLOSED
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
        match start_image_instance(PayloadMode::AcceptanceFault { round, hart }) {
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
        && after.capability_table_len() == before.capability_table_len()
        && expected_incarnation == after.cspace_incarnation()
        && after.installed_capability_count() == 0
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
        && after.capability_table_len() == NEGATIVE_CAPABILITIES
        && after.installed_capability_count() == NEGATIVE_CAPABILITIES
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
                    && record.streams == Some(instance.streams)
                    && record.terminal_candidate.is_none()
                    && record.handle.as_ref().is_some_and(|handle| {
                        handle.id() == instance.handle.id()
                            && handle.allocation_domain() == instance.domain
                            && handle.shares_status_with(&instance.handle)
                    })
            } else {
                record.core_token.is_none()
                    && record.domain.is_none()
                    && record.handle.is_none()
                    && record.streams.is_none()
                    && record.terminal_candidate.is_none()
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
    } else {
        C53_MISMATCH_REJECTS.fetch_add(1, Ordering::AcqRel);
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
    } else {
        C53_DUPLICATE_FAULT_REJECTS.fetch_add(1, Ordering::AcqRel);
    }
    NEG_ROUTE.clear();
}

fn finalize_negative_seed(instance: &NegativeInstance) -> Option<u64> {
    let mut control = NEG_CONTROL.try_lock().ok()?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    // The isolated negative table deliberately stores only the child/core,
    // domain, and stream projection. It must not borrow production's full
    // supervisor/reaper tuple gate merely to retire the already-authorized
    // ABA seed.
    let (core_token, handle, domain, streams) = {
        let record = control.exact(instance.key)?;
        if record.phase != ControlPhase::Running
            || record.core_token != Some(instance.token)
            || record.domain != Some(instance.domain)
            || record.streams != Some(instance.streams)
            || record.terminal_candidate.is_some()
            || record.candidate_source.is_some()
        {
            system.restore();
            return None;
        }
        (
            record.core_token?,
            record.handle.as_ref()?.clone(),
            record.domain?,
            record.streams?,
        )
    };
    if core_token != instance.token
        || handle.id() != instance.handle.id()
        || !handle.shares_status_with(&instance.handle)
        || domain != instance.domain
        || streams != instance.streams
        || handle.try_exit()?.state() != TaskState::Faulted
    {
        system.restore();
        return None;
    }
    let lifecycle_stage = core::cell::Cell::new(0_u8);
    let outcome = unsafe {
        NEG_REGISTRY.finalize_with_space_expect_completion(
            instance.token,
            &handle,
            None,
            |space, kind| {
                if lifecycle_stage.get() != 0 || kind != TerminalRetireKind::FaultReclaimed {
                    return false;
                }
                let published =
                    finalize_stream_state(space, streams, ComponentTerminal::RunnerFault);
                if published {
                    lifecycle_stage.set(1);
                }
                published
            },
            |domain, kind| {
                if lifecycle_stage.get() != 1
                    || kind != TerminalRetireKind::FaultReclaimed
                    || domain != instance.domain
                {
                    return false;
                }
                let retired = HEAP.unregister_owner(domain.owner).is_ok();
                if retired {
                    lifecycle_stage.set(2);
                }
                retired
            },
        )
    }
    .ok()?;
    // Returning from finalize_with_space after stage 2 proves that terminal
    // publication preceded owner retirement and the exact CSpace reset.
    if lifecycle_stage.get() != 2
        || outcome.revoked_capabilities != NEGATIVE_CAPABILITIES
        || outcome.detached_completion.is_some()
    {
        system.restore();
        return None;
    }
    let record = control.exact_mut(instance.key)?;
    if record.phase != ControlPhase::Running
        || record.core_token != Some(instance.token)
        || record.domain != Some(instance.domain)
        || record.streams != Some(instance.streams)
        || record.terminal_candidate.is_some()
        || record.candidate_source.is_some()
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
    record.streams = None;
    record.terminal_candidate = None;
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
            && after.capability_table_len() == seed.before.capability_table_len()
            && after.cspace_incarnation() == Some(next_incarnation)
            && seed
                .before
                .cspace_incarnation()
                .and_then(|value| value.checked_add(1))
                == Some(next_incarnation)
            && after.installed_capability_count() == 0
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
    } else {
        C53_ABA_REJECTS.fetch_add(1, Ordering::AcqRel);
    }
}

struct TerminalRaceEvidence {
    key: ControlKey,
    core_token: InstanceToken,
    handle: TaskHandle,
    domain: AllocationDomain,
    home_hart: crate::exec::HartId,
    before: AcceptanceInstanceProbe,
}

fn capture_terminal_race(token: ManagedComponentToken) -> Option<TerminalRaceEvidence> {
    let key = managed_token_key(token)?;
    let mut control = CONTROL.try_lock().ok()?;
    let tuple = control.running_tuple(key).ok()??;
    if tuple.terminal_candidate.is_some()
        || !control_record_matches_tuple(control.exact(key)?, &tuple)
    {
        return None;
    }
    let snapshot = registry()
        .observe_structural(tuple.core_token, &tuple.handle)
        .ok()?;
    let home_hart = snapshot.home_hart?;
    let before = registry().acceptance_probe(tuple.core_token)?;
    if !before.is_exact()
        || before.exact_phase() != Some(InstancePhase::Active)
        || !before.seal_matches_space()
        || !before.seal_matches_cspace()
        || before.capability_table_len() != 4
        || before.installed_capability_count() != 4
        || !terminal_race_bind(key, &tuple.handle, tuple.domain)
    {
        return None;
    }
    Some(TerminalRaceEvidence {
        key,
        core_token: tuple.core_token,
        handle: tuple.handle,
        domain: tuple.domain,
        home_hart,
        before,
    })
}

async fn wait_terminal_race_ready_for_hold() -> bool {
    let started = crate::sbi::time();
    while TERMINAL_RACE_PAYLOAD.load(Ordering::Acquire) != TERMINAL_RACE_PAYLOAD_BLOCKED
        || !TERMINAL_RACE_LISTENER_ARMED.load(Ordering::Acquire)
    {
        if deadline_expired(started) {
            return false;
        }
        crate::exec::yield_now().await;
    }
    true
}

async fn hold_terminal_race_control() {
    if !wait_terminal_race_ready_for_hold().await {
        fail(ERROR_C53_TERMINAL_RACE);
        TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_CONTROL_RELEASED, Ordering::Release);
        return;
    }
    let started = crate::sbi::time();
    let control = loop {
        let retry = match CONTROL.try_lock() {
            Ok(control) => break control,
            Err(ControlGateError::Busy) if !deadline_expired(started) => true,
            Err(_) => {
                fail(ERROR_C53_TERMINAL_RACE);
                TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_CONTROL_RELEASED, Ordering::Release);
                return;
            }
        };
        if retry {
            crate::exec::yield_now().await;
        }
    };
    if TERMINAL_RACE_CANCEL_HOLD
        .compare_exchange(
            TERMINAL_RACE_HOLD_REQUESTED,
            TERMINAL_RACE_CONTROL_HELD,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
        || TERMINAL_RACE_CASE.load(Ordering::Acquire) == TERMINAL_RACE_IDLE
    {
        fail(ERROR_C53_TERMINAL_RACE);
        drop(control);
        TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_CONTROL_RELEASED, Ordering::Release);
        return;
    }
    let _ = terminal_race_spin_until(&TERMINAL_RACE_CANCEL_HOLD, TERMINAL_RACE_BUSY_OBSERVED);
    drop(control);
    TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_CONTROL_RELEASED, Ordering::Release);

    let started = crate::sbi::time();
    while TERMINAL_RACE_COMPLETION.load(Ordering::Acquire) != TERMINAL_RACE_COMPLETION_EDGE {
        if deadline_expired(started) {
            fail(ERROR_C53_TERMINAL_RACE);
            return;
        }
        crate::exec::yield_now().await;
    }
    let started = crate::sbi::time();
    let completion_control = loop {
        let retry = match CONTROL.try_lock() {
            Ok(control) => break control,
            Err(ControlGateError::Busy) if !deadline_expired(started) => true,
            Err(_) => {
                fail(ERROR_C53_TERMINAL_RACE);
                return;
            }
        };
        if retry {
            crate::exec::yield_now().await;
        }
    };
    if TERMINAL_RACE_COMPLETION
        .compare_exchange(
            TERMINAL_RACE_COMPLETION_EDGE,
            TERMINAL_RACE_COMPLETION_HELD,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        fail(ERROR_C53_TERMINAL_RACE);
        return;
    }
    let observed =
        terminal_race_spin_until(&TERMINAL_RACE_COMPLETION, TERMINAL_RACE_COMPLETION_BUSY);
    drop(completion_control);
    if observed {
        TERMINAL_RACE_COMPLETION.store(TERMINAL_RACE_COMPLETION_RELEASED, Ordering::Release);
    }
}

async fn terminal_race_cancel_worker(
    token: ManagedComponentToken,
    evidence: TerminalRaceEvidence,
    case: u8,
    original: ComponentTerminal,
) {
    let started = crate::sbi::time();
    while TERMINAL_RACE_CANCEL_HOLD.load(Ordering::Acquire) != TERMINAL_RACE_CONTROL_HELD {
        if deadline_expired(started) {
            fail(ERROR_C53_TERMINAL_RACE);
            TERMINAL_RACE_PAYLOAD.store(TERMINAL_RACE_PAYLOAD_RELEASED, Ordering::Release);
            return;
        }
        crate::exec::yield_now().await;
    }
    if cancel_instance(token) != ManagedComponentCancel::Busy {
        fail(ERROR_C53_TERMINAL_RACE);
    } else {
        C53_CANCEL_BUSY_RETRIES.fetch_add(1, Ordering::AcqRel);
    }
    TERMINAL_RACE_CANCEL_HOLD.store(TERMINAL_RACE_BUSY_OBSERVED, Ordering::Release);
    let started = crate::sbi::time();
    while TERMINAL_RACE_CANCEL_HOLD.load(Ordering::Acquire) != TERMINAL_RACE_CONTROL_RELEASED {
        if deadline_expired(started) {
            fail(ERROR_C53_TERMINAL_RACE);
            TERMINAL_RACE_PAYLOAD.store(TERMINAL_RACE_PAYLOAD_RELEASED, Ordering::Release);
            return;
        }
        crate::exec::yield_now().await;
    }

    let expected_cancel = if case == TERMINAL_RACE_CANCEL_FIRST {
        ManagedComponentCancel::Requested
    } else {
        ManagedComponentCancel::AlreadyCompleting
    };
    let started = crate::sbi::time();
    let outcome = loop {
        let outcome = cancel_instance(token);
        if outcome != ManagedComponentCancel::Busy {
            break outcome;
        }
        if deadline_expired(started) {
            break ManagedComponentCancel::Lost;
        }
        crate::exec::yield_now().await;
    };
    let expected_candidate = if case == TERMINAL_RACE_CANCEL_FIRST {
        ComponentTerminal::Cancelled
    } else {
        original
    };
    let projection_exact = if let Ok(control) = CONTROL.try_lock() {
        control.exact(evidence.key).is_some_and(|record| {
            record.phase == ControlPhase::Running
                && record.core_token == Some(evidence.core_token)
                && record.domain == Some(evidence.domain)
                && record.terminal_candidate == Some(expected_candidate)
                && record.handle.as_ref().is_some_and(|handle| {
                    terminal_race_bound_identity_matches(evidence.key, handle)
                        && handle.shares_status_with(&evidence.handle)
                })
        })
    } else {
        false
    };
    let core_exact = registry()
        .acceptance_probe(evidence.core_token)
        .is_some_and(|probe| {
            probe.is_exact()
                && probe.exact_phase() == Some(InstancePhase::Active)
                && probe.seal_matches_space()
                && probe.seal_matches_cspace()
                && probe.capability_table_len() == 4
                && probe.installed_capability_count() == 4
        });
    if outcome == expected_cancel && projection_exact && core_exact {
        TERMINAL_RACE_CANCEL_VALID.store(true, Ordering::Release);
    } else {
        fail(ERROR_C53_TERMINAL_RACE);
    }
    TERMINAL_RACE_PAYLOAD.store(TERMINAL_RACE_PAYLOAD_RELEASED, Ordering::Release);
}

async fn terminal_race_observer(token: ManagedComponentToken) {
    let terminal = match wait_instance(token).await {
        ManagedComponentState::Complete(terminal) => terminal_word(terminal),
        ManagedComponentState::Busy
        | ManagedComponentState::Running
        | ManagedComponentState::Lost => u64::MAX,
    };
    TERMINAL_RACE_OBSERVED_TERMINAL.store(terminal, Ordering::Release);
}

fn terminal_race_postconditions(evidence: &TerminalRaceEvidence) -> bool {
    let Some(after) = registry().acceptance_probe(evidence.core_token) else {
        return false;
    };
    !after.is_exact()
        && after.current_phase() == InstancePhase::Vacant
        && evidence.before.current_generation().checked_add(1) == Some(after.current_generation())
        && evidence.before.same_space_object(after)
        && evidence.before.same_cspace_lock(after)
        && evidence.before.same_cspace_identity(after)
        && after.capability_table_len() == evidence.before.capability_table_len()
        && evidence
            .before
            .cspace_incarnation()
            .and_then(|incarnation| incarnation.checked_add(1))
            == after.cspace_incarnation()
        && after.installed_capability_count() == 0
        && HEAP.arena_stats(evidence.domain.arena).is_none()
        && HEAP.account_stats(evidence.domain.owner).is_none()
}

async fn start_terminal_race(
    case: u8,
    terminal: ComponentTerminal,
) -> Option<ManagedComponentToken> {
    let started = crate::sbi::time();
    loop {
        match start_image_instance(PayloadMode::AcceptanceTerminalRace { case, terminal }) {
            Ok(token) => return Some(token),
            Err(ComponentTerminal::Unavailable) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Err(_) => return None,
        }
    }
}

async fn run_terminal_race_case(case: u8, original: ComponentTerminal) -> bool {
    if !terminal_race_arm(case, original) {
        return false;
    }
    let Some(token) = start_terminal_race(case, original).await else {
        fail(ERROR_C53_TERMINAL_RACE);
        TERMINAL_RACE_CASE.store(TERMINAL_RACE_IDLE, Ordering::Release);
        return false;
    };
    let Some(evidence) = capture_terminal_race(token) else {
        fail(ERROR_C53_TERMINAL_RACE);
        TERMINAL_RACE_PAYLOAD.store(TERMINAL_RACE_PAYLOAD_RELEASED, Ordering::Release);
        return false;
    };
    let home = evidence.home_hart.index();
    let Some(cancel_hart) = crate::exec::HartId::new((home + 1) % HARTS) else {
        return false;
    };
    let Some(observer_hart) = crate::exec::HartId::new((home + 2) % HARTS) else {
        return false;
    };
    let Some(holder_hart) = crate::exec::HartId::new((home + 3) % HARTS) else {
        return false;
    };
    let (observer, holder, canceller) = {
        let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
        let observer = crate::exec::spawn_pinned_on(
            observer_hart,
            "wasm-c53-terminal-observer",
            terminal_race_observer(token),
        );
        let holder = crate::exec::spawn_pinned_on(
            holder_hart,
            "wasm-c53-control-holder",
            hold_terminal_race_control(),
        );
        let cancel_evidence = TerminalRaceEvidence {
            key: evidence.key,
            core_token: evidence.core_token,
            handle: evidence.handle.clone(),
            domain: evidence.domain,
            home_hart: evidence.home_hart,
            before: evidence.before,
        };
        let canceller = crate::exec::spawn_pinned_on(
            cancel_hart,
            "wasm-c53-terminal-canceller",
            terminal_race_cancel_worker(token, cancel_evidence, case, original),
        );
        system.restore();
        (observer, holder, canceller)
    };

    let cancel_exit = canceller.join().await.state();
    let holder_exit = holder.join().await.state();
    let observer_exit = observer.join().await.state();
    let expected_terminal = if case == TERMINAL_RACE_CANCEL_FIRST {
        ComponentTerminal::Cancelled
    } else {
        original
    };
    let expected_payload_phase = if case == TERMINAL_RACE_CANCEL_FIRST {
        TERMINAL_RACE_PAYLOAD_FOLDED
    } else {
        TERMINAL_RACE_PAYLOAD_RELEASED
    };
    let valid = cancel_exit == TaskState::Exited
        && holder_exit == TaskState::Exited
        && observer_exit == TaskState::Exited
        && TERMINAL_RACE_CANCEL_VALID.load(Ordering::Acquire)
        && TERMINAL_RACE_OBSERVED_TERMINAL.load(Ordering::Acquire)
            == terminal_word(expected_terminal)
        && TERMINAL_RACE_PAYLOAD.load(Ordering::Acquire) == expected_payload_phase
        && TERMINAL_RACE_COMPLETION.load(Ordering::Acquire) == TERMINAL_RACE_COMPLETION_RELEASED
        && terminal_race_postconditions(&evidence)
        && acknowledge_until_stable(token).await
        && wait_for_supervisors_to_retire().await;
    if valid {
        C53_TERMINAL_RACES.fetch_add(1, Ordering::AcqRel);
    } else {
        fail(ERROR_C53_TERMINAL_RACE);
    }
    TERMINAL_RACE_CASE.store(TERMINAL_RACE_IDLE, Ordering::Release);
    valid
}

async fn run_terminal_race_matrix() {
    for (case, terminal) in [
        (TERMINAL_RACE_SUCCESS_FIRST, ComponentTerminal::Success),
        (TERMINAL_RACE_RETURNED_FIRST, ComponentTerminal::Returned(7)),
        (TERMINAL_RACE_CANCEL_FIRST, ComponentTerminal::Returned(9)),
    ] {
        if !run_terminal_race_case(case, terminal).await {
            fail(ERROR_C53_TERMINAL_RACE);
            return;
        }
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
        match start_image_instance(PayloadMode::CommandSync) {
            Ok(token) => return Some(token),
            Err(ComponentTerminal::Unavailable) if !deadline_expired(started) => {
                crate::exec::yield_now().await;
            }
            Err(_) => return None,
        }
    }
}

fn production_control_is_terminal_and_acknowledged(control: &ControlTable) -> bool {
    control.slots.iter().enumerate().all(|(index, record)| {
        CONTROL.completion[index].waiter_count() == 0
            && match record.phase {
                ControlPhase::Vacant => {
                    record.core_token.is_none()
                        && record.handle.is_none()
                        && record.domain.is_none()
                        && record.streams.is_none()
                        && record.terminal_candidate.is_none()
                }
                ControlPhase::Complete {
                    acknowledged: true, ..
                } => {
                    record.core_token.is_none()
                        && record.handle.is_none()
                        && record.domain.is_none()
                        && record.streams.is_none()
                        && record.terminal_candidate.is_none()
                }
                ControlPhase::Starting
                | ControlPhase::Running
                | ControlPhase::Complete {
                    acknowledged: false,
                    ..
                }
                | ControlPhase::Quarantined => false,
            }
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
        && C53
            .iter()
            .all(|slot| slot.stage.load(Ordering::Acquire) == C53_FREE)
        && C53_PAIRS.load(Ordering::Acquire) == 0
        && C53_HOST_PENDING.load(Ordering::Acquire) == 0
        && C53_EXACT_WAKES.load(Ordering::Acquire) == 0
        && C53_EXACT_RESUMES.load(Ordering::Acquire) == 0
        && C53_START_ERROR_TERMINALS.load(Ordering::Acquire) == 0
        && C53_TERMINAL_RACES.load(Ordering::Acquire) == 0
        && C53_CANCEL_BUSY_RETRIES.load(Ordering::Acquire) == 0
        && C53_COMPLETION_BUSY_RETRIES.load(Ordering::Acquire) == 0
        && !C53_START_INTENT.load(Ordering::Acquire)
        && TERMINAL_RACE_CASE.load(Ordering::Acquire) == TERMINAL_RACE_IDLE
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
        if !run_c53_close_races() {
            fail(ERROR_C53_STREAM);
        }
        run_c53_matrix().await;
        run_positive_matrix().await;
        for kind in MISMATCH_CASES {
            run_mismatch_case(kind).await;
        }
        run_duplicate_case().await;
        run_aba_case().await;
        run_terminal_race_matrix().await;
        run_normal_production_probe().await;

        let negative = NEG_REGISTRY.occupancy_stats();
        let control_reusable = CONTROL
            .try_lock()
            .is_ok_and(|control| production_control_is_terminal_and_acknowledged(&control));
        if negative.occupied != 11
            || negative.header_mismatches != 0
            || negative.phase_count(InstancePhase::Quarantined) != 11
            || NEG_RAW_AUTHORIZATIONS.load(Ordering::Acquire) != 2
            || NEG_RAW_RECLAIMS.load(Ordering::Acquire) != 2
            || NEG_REPLAY_AUTHORIZATIONS.load(Ordering::Acquire) != 0
            || ABA_STALE_AUTHORIZATIONS.load(Ordering::Acquire) != 0
            || C53_MISMATCH_REJECTS.load(Ordering::Acquire) != MISMATCH_CASES.len()
            || C53_DUPLICATE_FAULT_REJECTS.load(Ordering::Acquire) != 1
            || C53_ABA_REJECTS.load(Ordering::Acquire) != 1
            || C53_LATE_WAKE_REJECTS.load(Ordering::Acquire) != POSITIVE_CYCLES
            || C53_CLOSE_RACES.load(Ordering::Acquire) != 3
            || C53_TERMINAL_MAPPINGS.load(Ordering::Acquire) != 3
            || C53_START_ERROR_TERMINALS.load(Ordering::Acquire) != 2
            || C53_TERMINAL_RACES.load(Ordering::Acquire) != 3
            || C53_CANCEL_BUSY_RETRIES.load(Ordering::Acquire) != 3
            || C53_COMPLETION_BUSY_RETRIES.load(Ordering::Acquire) != 3
            || C53_START_INTENT.load(Ordering::Acquire)
            || !control_reusable
        {
            fail(ERROR_NEGATIVE_RESULT);
        }
    }

    if ERRORS.load(Ordering::Acquire) == 0 && open_production_policy_gate().await {
        RUN_STATE.store(2, Ordering::Release);
        println!(
            "WASM_C53_ACCEPTANCE PASS pairs={} input_chunks={} output_chunks={} xor_bytes={} backend_pending={} backend_wakes={} host_pending={} exact_wakes={} exact_resumes={} late_wake_rejects={} eof={} normal_closes={} terminal_matches={} terminal_orders={} close_races={} terminal_mappings={} start_error_terminals={} terminal_races={} cancel_busy_retries={} completion_busy_retries={} mismatches={} duplicate_fault_rejects={} aba_rejects={} harts={}",
            C53_PAIRS.load(Ordering::Acquire),
            C53_INPUT_CHUNKS.load(Ordering::Acquire),
            C53_OUTPUT_CHUNKS.load(Ordering::Acquire),
            C53_XOR_BYTES.load(Ordering::Acquire),
            C53_BACKEND_PENDING.load(Ordering::Acquire),
            C53_BACKEND_WAKES.load(Ordering::Acquire),
            C53_HOST_PENDING.load(Ordering::Acquire),
            C53_EXACT_WAKES.load(Ordering::Acquire),
            C53_EXACT_RESUMES.load(Ordering::Acquire),
            C53_LATE_WAKE_REJECTS.load(Ordering::Acquire),
            C53_EOF.load(Ordering::Acquire),
            C53_NORMAL_CLOSES.load(Ordering::Acquire),
            C53_TERMINAL_MATCHES.load(Ordering::Acquire),
            C53_TERMINAL_ORDERS.load(Ordering::Acquire),
            C53_CLOSE_RACES.load(Ordering::Acquire),
            C53_TERMINAL_MAPPINGS.load(Ordering::Acquire),
            C53_START_ERROR_TERMINALS.load(Ordering::Acquire),
            C53_TERMINAL_RACES.load(Ordering::Acquire),
            C53_CANCEL_BUSY_RETRIES.load(Ordering::Acquire),
            C53_COMPLETION_BUSY_RETRIES.load(Ordering::Acquire),
            C53_MISMATCH_REJECTS.load(Ordering::Acquire),
            C53_DUPLICATE_FAULT_REJECTS.load(Ordering::Acquire),
            C53_ABA_REJECTS.load(Ordering::Acquire),
            HARTS,
        );
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
        for (index, slot) in C53.iter().enumerate() {
            let stage = slot.stage.load(Ordering::Acquire);
            if stage != C53_FREE {
                println!(
                    "WASM_C53_ACCEPTANCE slot={} stage={} task={} owner={} arena={} round={} hart={} input_woken={} host_pending={} exact_wake={} exact_resume={} eof={} close_mask={:#x}",
                    index,
                    stage,
                    slot.task.load(Ordering::Acquire),
                    slot.owner.load(Ordering::Acquire),
                    slot.arena.load(Ordering::Acquire),
                    slot.round.load(Ordering::Acquire),
                    slot.hart.load(Ordering::Acquire),
                    slot.input_woken.load(Ordering::Acquire),
                    slot.host_pending.load(Ordering::Acquire),
                    slot.exact_wake.load(Ordering::Acquire),
                    slot.exact_resume.load(Ordering::Acquire),
                    slot.eof.load(Ordering::Acquire),
                    slot.close_mask.load(Ordering::Acquire),
                );
            }
        }
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
            "WASM_C53_ACCEPTANCE FAIL errors={:#x} pairs={} input_chunks={} output_chunks={} xor_bytes={} backend_pending={} backend_wakes={} host_pending={} exact_wakes={} exact_resumes={} late_wake_rejects={} eof={} normal_closes={} terminal_matches={} terminal_orders={} close_races={} terminal_mappings={} start_error_terminals={} terminal_races={} cancel_busy_retries={} completion_busy_retries={} mismatches={} duplicate_fault_rejects={} aba_rejects={}",
            ERRORS.load(Ordering::Acquire),
            C53_PAIRS.load(Ordering::Acquire),
            C53_INPUT_CHUNKS.load(Ordering::Acquire),
            C53_OUTPUT_CHUNKS.load(Ordering::Acquire),
            C53_XOR_BYTES.load(Ordering::Acquire),
            C53_BACKEND_PENDING.load(Ordering::Acquire),
            C53_BACKEND_WAKES.load(Ordering::Acquire),
            C53_HOST_PENDING.load(Ordering::Acquire),
            C53_EXACT_WAKES.load(Ordering::Acquire),
            C53_EXACT_RESUMES.load(Ordering::Acquire),
            C53_LATE_WAKE_REJECTS.load(Ordering::Acquire),
            C53_EOF.load(Ordering::Acquire),
            C53_NORMAL_CLOSES.load(Ordering::Acquire),
            C53_TERMINAL_MATCHES.load(Ordering::Acquire),
            C53_TERMINAL_ORDERS.load(Ordering::Acquire),
            C53_CLOSE_RACES.load(Ordering::Acquire),
            C53_TERMINAL_MAPPINGS.load(Ordering::Acquire),
            C53_START_ERROR_TERMINALS.load(Ordering::Acquire),
            C53_TERMINAL_RACES.load(Ordering::Acquire),
            C53_CANCEL_BUSY_RETRIES.load(Ordering::Acquire),
            C53_COMPLETION_BUSY_RETRIES.load(Ordering::Acquire),
            C53_MISMATCH_REJECTS.load(Ordering::Acquire),
            C53_DUPLICATE_FAULT_REJECTS.load(Ordering::Acquire),
            C53_ABA_REJECTS.load(Ordering::Acquire),
        );
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
