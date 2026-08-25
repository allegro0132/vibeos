//! Kernel-owned single-slot boundary for the C8.4 target profiler.
//!
//! The two storage-bearing typestates always live in [`SLOT`] while an async
//! task is allowed to suspend. `RunLease` and `StreamLease` carry only sealed
//! task/sample identity. Finish, verification, cancellation, and recycling
//! move a handle through an exact synchronous tombstone, release the
//! IRQ-masking [`SpinLock`], do the O(n) work, then reinstall only into that
//! same tombstone. No storage-bearing handle is held across `.await`.
//!
//! A task-detach callback is registered before the start tick. It can recover
//! an `Active` or `Verified` handle even when the executor's raw-fault path
//! skips the future's `Drop`. The callback context is the lineage epoch and is
//! additionally checked against the exact task and allocation domain.
//!
//! The optional Core-poll observer is a caller-owned adapter over an exact
//! [`RunLease`]; ordinary runtime `poll()` remains untouched. A separate
//! default-off trap overlay can bracket an interrupt with a linear cookie;
//! SSH and publication hooks remain deliberately disconnected. Isolated QEMU
//! workers prove each boundary without composing their exact transcripts.

extern crate alloc;

use alloc::boxed::Box;
use core::cell::Cell;
use core::marker::PhantomData;
use core::mem;
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
use core::sync::atomic::AtomicBool;
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::exec::{
    CurrentTaskDetachLease, TaskDetachDisarm, TaskDetachReason, TaskDetachRegistrationError,
    TaskDetachTarget, TaskId,
};
use crate::heap::AllocationDomain;
use crate::sync::SpinLock;
#[cfg(feature = "wasm-c84-core-poll-observer")]
use vibeos_component_runtime::sync::ProfileClock;
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
use vibeos_wasm_aot_profile::IrqCookie;
use vibeos_wasm_aot_profile::{
    FacadeFaults, Interval, Phase, SampleToken, Storage, Summary, TargetActive, TargetContext,
    TargetReady, TargetRejected, TargetStartError, TargetVerified, VerificationError,
    INTERVAL_CAPACITY,
};

static SLOT: SpinLock<SlotState> = SpinLock::new(SlotState::Uninitialized);
static POISON: AtomicU8 = AtomicU8::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
static ACTIVE_EPOCH: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_SSIP_PAIRED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_SSIP_INACTIVE: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_CHILD_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
static ACCEPTANCE_CHILD_RELEASE: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct OwnerSeal {
    epoch: u64,
    detach: CurrentTaskDetachLease,
}

impl OwnerSeal {
    fn matches(self, epoch: u64, detach: CurrentTaskDetachLease) -> bool {
        self.epoch == epoch && self.detach.matches_exact(detach)
    }

    fn callback_matches(self, epoch: u64, task: TaskId, domain: AllocationDomain) -> bool {
        self.epoch == epoch
            && self.detach.task_id() == task
            && self.detach.allocation_domain() == domain
    }
}

enum SlotState {
    Uninitialized,
    Ready(TargetReady<'static>),
    Reserved {
        ready: TargetReady<'static>,
        owner: OwnerSeal,
    },
    Active {
        sample: TargetActive<'static>,
        owner: OwnerSeal,
        faults: SlotFaults,
    },
    Transit {
        owner: OwnerSeal,
        kind: TransitKind,
    },
    Verified {
        sample: TargetVerified<'static>,
        owner: OwnerSeal,
        cursor: usize,
    },
    Rejected {
        ready: TargetReady<'static>,
        report: RejectionReport,
    },
    Poisoned(SlotPoison),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitKind {
    Start,
    Finish,
    Cancel,
    Recycle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SlotPoison {
    DuplicateInitialization = 1,
    StateMismatch = 2,
    DetachDisarm = 3,
    DetachedDuringTransit = 4,
    IrqStateMismatch = 5,
}

impl SlotPoison {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::DuplicateInitialization),
            2 => Some(Self::StateMismatch),
            3 => Some(Self::DetachDisarm),
            4 => Some(Self::DetachedDuringTransit),
            5 => Some(Self::IrqStateMismatch),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SlotFaults(u8);

impl SlotFaults {
    const NONE: Self = Self(0);
    const OWNER_NOT_CURRENT: Self = Self(1 << 0);

    const fn is_empty(self) -> bool {
        self.0 == 0
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionCause {
    LeaseCancelled,
    StreamAbandoned,
    TargetRejected,
    TaskDetached(TaskDetachReason),
    SlotFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RejectionReport {
    pub epoch: u64,
    pub cause: RejectionCause,
    pub facade_faults: FacadeFaults,
    pub ledger_error: Option<VerificationError>,
    pub slot_faults: SlotFaults,
    pub intervals_emitted: usize,
}

impl RejectionReport {
    fn from_target(
        target: &TargetRejected<'_>,
        cause: RejectionCause,
        slot_faults: SlotFaults,
        intervals_emitted: usize,
    ) -> Self {
        Self {
            epoch: target.token().epoch(),
            cause,
            facade_faults: target.facade_faults(),
            ledger_error: target.ledger_error(),
            slot_faults,
            intervals_emitted,
        }
    }

    fn detached_verified(epoch: u64, reason: TaskDetachReason, cursor: usize) -> Self {
        Self {
            epoch,
            cause: RejectionCause::TaskDetached(reason),
            facade_faults: FacadeFaults::NONE,
            ledger_error: None,
            slot_faults: SlotFaults::NONE,
            intervals_emitted: cursor,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotStatus {
    Uninitialized,
    Ready {
        next_epoch: Option<u64>,
    },
    Reserved {
        epoch: u64,
    },
    Active {
        epoch: u64,
    },
    Transit {
        epoch: u64,
        kind: TransitKind,
    },
    Verified {
        epoch: u64,
        cursor: usize,
        intervals: usize,
    },
    Rejected(RejectionReport),
    Poisoned(SlotPoison),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileError {
    Uninitialized,
    Busy,
    Exhausted,
    RejectionPending,
    RegistrationReserveFailed,
    Registration(TaskDetachRegistrationError),
    Detach(TaskDetachDisarm),
    OwnerNotCurrent,
    StateMismatch,
    Start(TargetStartError),
    Facade(FacadeFaults),
    SlotFault(SlotFaults),
    IncompleteStream { emitted: usize, required: usize },
    Rejected(RejectionReport),
    Poisoned(SlotPoison),
}

/// One Core-finish boundary even when the slot operation latched a failure.
///
/// `ProfileClock` is infallible. Keeping the original tick beside the sticky
/// error lets the runtime close its aggregate with the exact tick already used
/// by the target ledger instead of taking an unsound replacement sample.
#[cfg(feature = "wasm-c84-core-poll-observer")]
struct PhaseBoundary {
    tick: u64,
    error: Option<ProfileError>,
}

fn poison(reason: SlotPoison) {
    let _ = POISON.compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire);
    #[cfg(feature = "wasm-c84-profile-irq-overlay")]
    ACTIVE_EPOCH.store(0, Ordering::Release);
}

fn poison_reason() -> Option<SlotPoison> {
    SlotPoison::from_code(POISON.load(Ordering::Acquire))
}

fn ensure_not_poisoned() -> Result<(), ProfileError> {
    match poison_reason() {
        Some(reason) => Err(ProfileError::Poisoned(reason)),
        None => Ok(()),
    }
}

fn live_context() -> TargetContext {
    TargetContext::new(
        u64::try_from(crate::online_hart_mask()).unwrap_or(u64::MAX),
        crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
        crate::sbi::current_hart_id(),
    )
}

fn live_tick() -> u64 {
    crate::sbi::time()
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
fn publish_active_epoch(epoch: u64) -> Result<(), ProfileError> {
    if let Some(reason) = poison_reason() {
        ACTIVE_EPOCH.store(0, Ordering::Release);
        return Err(ProfileError::Poisoned(reason));
    }
    if epoch == 0
        || ACTIVE_EPOCH
            .compare_exchange(0, epoch, Ordering::Release, Ordering::Acquire)
            .is_err()
    {
        poison(SlotPoison::IrqStateMismatch);
        return Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch));
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
fn clear_active_epoch(epoch: u64) -> Result<(), ProfileError> {
    if let Some(reason) = poison_reason() {
        ACTIVE_EPOCH.store(0, Ordering::Release);
        return Err(ProfileError::Poisoned(reason));
    }
    if epoch == 0
        || ACTIVE_EPOCH
            .compare_exchange(epoch, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        poison(SlotPoison::IrqStateMismatch);
        return Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch));
    }
    Ok(())
}

/// Linear trap-stack witness for one target interrupt overlay. The inactive
/// value keeps trap exit unconditional without exposing the facade cookie.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
#[must_use]
pub(crate) struct TrapIrqCookie {
    epoch: u64,
    inner: IrqCookie,
}

#[cfg(feature = "wasm-c84-profile-irq-overlay")]
impl TrapIrqCookie {
    const fn inactive() -> Self {
        Self {
            epoch: 0,
            inner: IrqCookie::inactive(),
        }
    }
}

/// Opens a Wait overlay at the assembly-captured trap-entry tick. Only an IRQ
/// preempting the exact current slot owner may mutate the sample.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
pub(crate) fn profile_irq_enter(irq_entry: u64) -> TrapIrqCookie {
    if poison_reason().is_some() {
        return TrapIrqCookie::inactive();
    }
    let epoch = ACTIVE_EPOCH.load(Ordering::Acquire);
    if epoch == 0 {
        return TrapIrqCookie::inactive();
    }

    let mut slot = SLOT.lock();
    if poison_reason().is_some() {
        return TrapIrqCookie::inactive();
    }
    let SlotState::Active {
        sample,
        owner,
        faults,
    } = &mut *slot
    else {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return TrapIrqCookie::inactive();
    };
    let token = sample.token();
    if token.epoch() != epoch {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return TrapIrqCookie::inactive();
    }
    if !owner.detach.is_current_irq_scope_exact() {
        return TrapIrqCookie::inactive();
    }
    if !faults.is_empty() {
        return TrapIrqCookie::inactive();
    }
    let context = live_context();
    let inner = sample.interrupt_enter(token, context, irq_entry);
    TrapIrqCookie { epoch, inner }
}

/// Closes one active overlay at the trap-supplied exit boundary. The caller
/// samples that boundary after handler work and allocation-owner restoration,
/// before this function can wait for the slot lock.
#[cfg(feature = "wasm-c84-profile-irq-overlay")]
pub(crate) fn profile_irq_exit(cookie: TrapIrqCookie, exit_tick: u64) -> bool {
    if cookie.epoch == 0 {
        return false;
    }
    if poison_reason().is_some() || ACTIVE_EPOCH.load(Ordering::Acquire) != cookie.epoch {
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }

    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        faults,
    } = &mut *slot
    else {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    };
    let token = sample.token();
    if token.epoch() != cookie.epoch {
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }
    if !owner.detach.is_current_irq_scope_exact() {
        faults.insert(SlotFaults::OWNER_NOT_CURRENT);
        drop(slot);
        poison(SlotPoison::IrqStateMismatch);
        return false;
    }
    let context = live_context();
    let applied = cookie.inner.is_active();
    sample.interrupt_exit(cookie.inner, context, exit_tick);
    applied
}

/// Acceptance-only attribution for the code=1 trap branch. Production state
/// remains limited to the active-epoch gate and the target's linear cookie.
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
pub(crate) fn profile_irq_acceptance_note_ssip(applied: bool) {
    if applied {
        ACCEPTANCE_SSIP_PAIRED.fetch_add(1, Ordering::Relaxed);
    } else {
        ACCEPTANCE_SSIP_INACTIVE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Allocates and installs the exact packed storage once, before secondary
/// harts are released. Box leaking is deliberate: the unique mutable borrows
/// then live only inside the single target lineage for the life of the kernel.
pub(crate) fn init() {
    let endpoints = Box::leak(alloc::vec![0_u64; INTERVAL_CAPACITY].into_boxed_slice());
    let phases = Box::leak(alloc::vec![0_u8; INTERVAL_CAPACITY].into_boxed_slice());
    let storage = Storage::new(endpoints, phases).expect("C8.4 slot storage has exact capacity");
    let ready = TargetReady::new(storage);

    let mut slot = SLOT.lock();
    if matches!(&*slot, SlotState::Uninitialized) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return;
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::DuplicateInitialization);
    panic!("C8.4 profile slot initialized more than once");
}

pub(crate) fn status() -> SlotStatus {
    if let Some(reason) = poison_reason() {
        return SlotStatus::Poisoned(reason);
    }
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Uninitialized => SlotStatus::Uninitialized,
        SlotState::Ready(ready) => SlotStatus::Ready {
            next_epoch: ready.next_epoch(),
        },
        SlotState::Reserved { owner, .. } => SlotStatus::Reserved { epoch: owner.epoch },
        SlotState::Active { sample, .. } => SlotStatus::Active {
            epoch: sample.token().epoch(),
        },
        SlotState::Transit { owner, kind } => SlotStatus::Transit {
            epoch: owner.epoch,
            kind: *kind,
        },
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } => SlotStatus::Verified {
            epoch: owner.epoch,
            cursor: *cursor,
            intervals: sample.summary().interval_count(),
        },
        SlotState::Rejected { report, .. } => SlotStatus::Rejected(*report),
        SlotState::Poisoned(reason) => SlotStatus::Poisoned(*reason),
    }
}

fn next_epoch_for_prepare() -> Result<u64, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Ready(ready) => ready.next_epoch().ok_or(ProfileError::Exhausted),
        SlotState::Uninitialized => Err(ProfileError::Uninitialized),
        SlotState::Rejected { .. } => Err(ProfileError::RejectionPending),
        SlotState::Poisoned(reason) => Err(ProfileError::Poisoned(*reason)),
        _ => Err(ProfileError::Busy),
    }
}

fn task_detach_target(epoch: u64) -> TaskDetachTarget {
    // SAFETY: `profile_task_detached` is a permanent kernel function. Its
    // context is a scalar epoch; it allocates nothing, never awaits, only
    // holds the IRQ-masking slot lock for O(1) transitions, and performs the
    // bounded full-buffer clear after releasing that lock.
    unsafe { TaskDetachTarget::new(epoch, profile_task_detached) }
}

fn disarm(detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    let result = detach.disarm();
    if result == TaskDetachDisarm::Disarmed {
        Ok(())
    } else {
        poison(SlotPoison::DetachDisarm);
        Err(ProfileError::Detach(result))
    }
}

fn reserve_ready(epoch: u64, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    match &*slot {
        SlotState::Ready(ready) if ready.next_epoch() == Some(epoch) => {}
        SlotState::Ready(ready) if ready.is_exhausted() => return Err(ProfileError::Exhausted),
        SlotState::Ready(_) => return Err(ProfileError::Busy),
        SlotState::Rejected { .. } => return Err(ProfileError::RejectionPending),
        SlotState::Uninitialized => return Err(ProfileError::Uninitialized),
        SlotState::Poisoned(reason) => return Err(ProfileError::Poisoned(*reason)),
        _ => return Err(ProfileError::Busy),
    }

    let owner = OwnerSeal { epoch, detach };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Start,
        },
    );
    let SlotState::Ready(ready) = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    *slot = SlotState::Reserved { ready, owner };
    Ok(())
}

/// Preallocates one detach-ledger entry and reserves the current Ready epoch.
/// This must run before the request acceptance/start tick boundary.
pub(crate) fn prepare_current() -> Result<StartPermit, ProfileError> {
    let epoch = next_epoch_for_prepare()?;
    if !crate::exec::try_reserve_current_task_registrations(1) {
        return Err(ProfileError::RegistrationReserveFailed);
    }
    let target = task_detach_target(epoch);
    // SAFETY: `target` satisfies TaskDetachTarget's permanent SYSTEM callback
    // contract, and the returned exact lease remains both in the reservation
    // state and in the storage-free permit until one side disarms or detaches.
    let detach = unsafe { crate::exec::register_current_task_detach(target) }
        .map_err(ProfileError::Registration)?;
    if !detach.is_current_running_exact() {
        let _ = disarm(detach);
        return Err(ProfileError::OwnerNotCurrent);
    }
    if let Err(error) = reserve_ready(epoch, detach) {
        disarm(detach)?;
        return Err(error);
    }
    Ok(StartPermit {
        epoch,
        detach,
        live: true,
        not_sync: PhantomData,
    })
}

fn owner_matches(owner: OwnerSeal, epoch: u64, detach: CurrentTaskDetachLease) -> bool {
    owner.matches(epoch, detach)
}

fn release_reservation(epoch: u64, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let owner = OwnerSeal { epoch, detach };
    let ready = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Reserved { owner, .. } if owner_matches(*owner, epoch, detach)
        );
        if !exact {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Start,
            },
        );
        let SlotState::Reserved { ready, .. } = previous else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        ready
    };

    if let Err(error) = disarm(detach) {
        drop(ready);
        return Err(error);
    }

    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Start }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && ready.next_epoch() == Some(epoch) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn start_reserved(epoch: u64, detach: CurrentTaskDetachLease) -> Result<SampleToken, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Reserved { owner, .. } if owner_matches(*owner, epoch, detach)
    );
    if !exact {
        return Err(ProfileError::StateMismatch);
    }

    let context = live_context();
    let tick = live_tick();
    let owner = OwnerSeal { epoch, detach };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Start,
        },
    );
    let SlotState::Reserved { ready, .. } = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    match ready.start(context, tick) {
        Ok(sample) => {
            let token = sample.token();
            if token.epoch() != epoch {
                poison(SlotPoison::StateMismatch);
                drop(slot);
                let rejected = sample.cancel(token, context);
                drop(rejected);
                return Err(ProfileError::StateMismatch);
            }
            #[cfg(feature = "wasm-c84-profile-irq-overlay")]
            if let Err(error) = publish_active_epoch(token.epoch()) {
                *slot = SlotState::Poisoned(SlotPoison::IrqStateMismatch);
                drop(sample);
                return Err(error);
            }
            *slot = SlotState::Active {
                sample,
                owner,
                faults: SlotFaults::NONE,
            };
            Ok(token)
        }
        Err(failure) => {
            let error = failure.error();
            *slot = SlotState::Reserved {
                ready: failure.into_ready(),
                owner,
            };
            Err(ProfileError::Start(error))
        }
    }
}

/// Storage-free reservation proof. It is `Send` but deliberately not `Sync`.
pub(crate) struct StartPermit {
    epoch: u64,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl StartPermit {
    pub(crate) const fn expected_epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn start(mut self) -> Result<RunLease, ProfileError> {
        if !self.detach.is_current_running_exact() {
            let error = release_reservation(self.epoch, self.detach)
                .err()
                .unwrap_or(ProfileError::OwnerNotCurrent);
            self.live = false;
            return Err(error);
        }
        match start_reserved(self.epoch, self.detach) {
            Ok(token) => {
                self.live = false;
                Ok(RunLease {
                    token,
                    detach: self.detach,
                    live: true,
                    not_sync: PhantomData,
                })
            }
            Err(error) => {
                let release = release_reservation(self.epoch, self.detach);
                self.live = false;
                match release {
                    Ok(()) => Err(error),
                    Err(release_error) => Err(release_error),
                }
            }
        }
    }
}

impl Drop for StartPermit {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = release_reservation(self.epoch, self.detach);
        }
    }
}

fn mark_owner_fault(token: SampleToken, detach: CurrentTaskDetachLease) {
    let mut slot = SLOT.lock();
    if let SlotState::Active {
        sample,
        owner,
        faults,
    } = &mut *slot
    {
        if sample.token() == token && owner.matches(token.epoch(), detach) {
            faults.insert(SlotFaults::OWNER_NOT_CURRENT);
        }
    }
}

fn apply_phase(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    phase: Option<Phase>,
) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        faults,
    } = &mut *slot
    else {
        return Err(ProfileError::StateMismatch);
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return Err(ProfileError::StateMismatch);
    }
    if !faults.is_empty() {
        return Err(ProfileError::SlotFault(*faults));
    }
    let context = live_context();
    let tick = live_tick();
    match phase {
        Some(phase) => sample.set_phase(token, context, tick, phase),
        None => sample.begin_cleanup(token, context, tick),
    }
    let facade = sample.facade_faults();
    if facade.is_empty() {
        Ok(())
    } else {
        Err(ProfileError::Facade(facade))
    }
}

/// Closes Interpretation with one tick that is both recorded in the ledger
/// and returned to the portable runtime observer.
#[cfg(feature = "wasm-c84-core-poll-observer")]
fn end_core_phase(token: SampleToken, detach: CurrentTaskDetachLease) -> PhaseBoundary {
    if let Err(error) = ensure_not_poisoned() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(error),
        };
    }
    let mut slot = SLOT.lock();
    let SlotState::Active {
        sample,
        owner,
        faults,
    } = &mut *slot
    else {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    };
    if sample.token() != token || !owner.matches(token.epoch(), detach) {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::StateMismatch),
        };
    }
    if !faults.is_empty() {
        return PhaseBoundary {
            tick: live_tick(),
            error: Some(ProfileError::SlotFault(*faults)),
        };
    }
    let context = live_context();
    let tick = live_tick();
    sample.set_phase(token, context, tick, Phase::Abi);
    let facade = sample.facade_faults();
    PhaseBoundary {
        tick,
        error: if facade.is_empty() {
            None
        } else {
            Some(ProfileError::Facade(facade))
        },
    }
}

fn install_verified(owner: OwnerSeal, sample: TargetVerified<'static>) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Finish }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && sample.token().epoch() == owner.epoch && poison_reason().is_none() {
        *slot = SlotState::Verified {
            sample,
            owner,
            cursor: 0,
        };
        return Ok(());
    }
    drop(slot);
    drop(sample);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn install_rejected(
    owner: OwnerSeal,
    expected_kind: TransitKind,
    ready: TargetReady<'static>,
    report: RejectionReport,
) -> Result<(), ProfileError> {
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind }
            if actual.matches(owner.epoch, owner.detach) && *kind == expected_kind
    );
    if exact
        && report.epoch == owner.epoch
        && ready.next_epoch() == owner.epoch.checked_add(1)
        && poison_reason().is_none()
    {
        *slot = SlotState::Rejected { ready, report };
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn reject_target_normal(
    owner: OwnerSeal,
    expected_kind: TransitKind,
    rejected: TargetRejected<'static>,
    cause: RejectionCause,
    slot_faults: SlotFaults,
    intervals_emitted: usize,
) -> Result<RejectionReport, ProfileError> {
    let report = RejectionReport::from_target(&rejected, cause, slot_faults, intervals_emitted);
    let ready = rejected.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    install_rejected(owner, expected_kind, ready, report)?;
    Ok(report)
}

fn finish_active(token: SampleToken, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    ensure_not_poisoned()?;
    let (sample, owner, slot_faults, context, tick) = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Active { sample, owner, .. }
                if sample.token() == token && owner.matches(token.epoch(), detach)
        );
        if !exact {
            return Err(ProfileError::StateMismatch);
        }
        let context = live_context();
        let tick = live_tick();
        let owner = OwnerSeal {
            epoch: token.epoch(),
            detach,
        };
        #[cfg(feature = "wasm-c84-profile-irq-overlay")]
        if let Err(error) = clear_active_epoch(token.epoch()) {
            let previous = mem::replace(
                &mut *slot,
                SlotState::Poisoned(SlotPoison::IrqStateMismatch),
            );
            drop(previous);
            return Err(error);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Finish,
            },
        );
        let SlotState::Active {
            sample,
            owner,
            faults,
        } = previous
        else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        (sample, owner, faults, context, tick)
    };

    if !slot_faults.is_empty() {
        let rejected = sample.cancel(token, context);
        let report = reject_target_normal(
            owner,
            TransitKind::Finish,
            rejected,
            RejectionCause::SlotFault,
            slot_faults,
            0,
        )?;
        return Err(ProfileError::Rejected(report));
    }

    let finished = match sample.finish(token, context, tick) {
        Ok(finished) => finished,
        Err(rejected) => {
            let report = reject_target_normal(
                owner,
                TransitKind::Finish,
                rejected,
                RejectionCause::TargetRejected,
                slot_faults,
                0,
            )?;
            return Err(ProfileError::Rejected(report));
        }
    };
    match finished.verify() {
        Ok(verified) => install_verified(owner, verified),
        Err(rejected) => {
            let report = reject_target_normal(
                owner,
                TransitKind::Finish,
                rejected,
                RejectionCause::TargetRejected,
                slot_faults,
                0,
            )?;
            Err(ProfileError::Rejected(report))
        }
    }
}

fn cancel_active(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    cause: RejectionCause,
) -> Result<RejectionReport, ProfileError> {
    ensure_not_poisoned()?;
    let (sample, owner, faults, context) = {
        let mut slot = SLOT.lock();
        let exact = matches!(
            &*slot,
            SlotState::Active { sample, owner, .. }
                if sample.token() == token && owner.matches(token.epoch(), detach)
        );
        if !exact {
            return Err(ProfileError::StateMismatch);
        }
        let context = live_context();
        let owner = OwnerSeal {
            epoch: token.epoch(),
            detach,
        };
        #[cfg(feature = "wasm-c84-profile-irq-overlay")]
        if let Err(error) = clear_active_epoch(token.epoch()) {
            let previous = mem::replace(
                &mut *slot,
                SlotState::Poisoned(SlotPoison::IrqStateMismatch),
            );
            drop(previous);
            return Err(error);
        }
        let previous = mem::replace(
            &mut *slot,
            SlotState::Transit {
                owner,
                kind: TransitKind::Cancel,
            },
        );
        let SlotState::Active {
            sample,
            owner,
            faults,
        } = previous
        else {
            poison(SlotPoison::StateMismatch);
            return Err(ProfileError::StateMismatch);
        };
        (sample, owner, faults, context)
    };
    let rejected = sample.cancel(token, context);
    reject_target_normal(owner, TransitKind::Cancel, rejected, cause, faults, 0)
}

/// Storage-free exact owner of one globally resident Active sample.
pub(crate) struct RunLease {
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl RunLease {
    pub(crate) const fn token(&self) -> SampleToken {
        self.token
    }

    pub(crate) fn set_phase(&self, phase: Phase) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_phase(self.token, self.detach, Some(phase))
    }

    pub(crate) fn begin_cleanup(&self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return Err(ProfileError::OwnerNotCurrent);
        }
        apply_phase(self.token, self.detach, None)
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn begin_core_interpretation(&self) -> Option<ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            Some(ProfileError::OwnerNotCurrent)
        } else {
            apply_phase(self.token, self.detach, Some(Phase::Interpretation)).err()
        }
    }

    #[cfg(feature = "wasm-c84-core-poll-observer")]
    fn end_core_interpretation(&self) -> PhaseBoundary {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
            return PhaseBoundary {
                tick: live_tick(),
                error: Some(ProfileError::OwnerNotCurrent),
            };
        }
        end_core_phase(self.token, self.detach)
    }

    pub(crate) fn finish(mut self) -> Result<StreamLease, ProfileError> {
        if !self.detach.is_current_running_exact() {
            mark_owner_fault(self.token, self.detach);
        }
        let result = finish_active(self.token, self.detach);
        match result {
            Ok(()) => {
                self.live = false;
                Ok(StreamLease {
                    token: self.token,
                    detach: self.detach,
                    live: true,
                    not_sync: PhantomData,
                })
            }
            Err(error @ ProfileError::Rejected(_)) => {
                self.live = false;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn cancel(mut self) -> Result<RejectionReport, ProfileError> {
        self.live = false;
        cancel_active(self.token, self.detach, RejectionCause::LeaseCancelled)
    }
}

/// Lexically scoped bridge from portable Core observers to one exact slot
/// owner. Construct one around each `poll_profiled` call and inspect its sticky
/// error and closed state before the next poll or any `.await`.
#[cfg(feature = "wasm-c84-core-poll-observer")]
pub(crate) struct SlotCorePollClock<'a> {
    run: &'a RunLease,
    first_error: Option<ProfileError>,
    core_open: bool,
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
impl<'a> SlotCorePollClock<'a> {
    pub(crate) const fn new(run: &'a RunLease) -> Self {
        Self {
            run,
            first_error: None,
            core_open: false,
        }
    }

    fn latch(&mut self, error: Option<ProfileError>) {
        if self.first_error.is_none() {
            self.first_error = error;
        }
    }

    pub(crate) const fn error(&self) -> Option<ProfileError> {
        self.first_error
    }

    pub(crate) const fn core_is_closed(&self) -> bool {
        !self.core_open
    }
}

#[cfg(feature = "wasm-c84-core-poll-observer")]
impl ProfileClock for SlotCorePollClock<'_> {
    fn ticks(&mut self) -> u64 {
        live_tick()
    }

    fn core_poll_started(&mut self) -> u64 {
        if self.core_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        self.core_open = true;
        let error = self.run.begin_core_interpretation();
        self.latch(error);
        // The portable contract requires this to be the final observer work.
        live_tick()
    }

    fn core_poll_finished(&mut self) -> u64 {
        if !self.core_open {
            self.latch(Some(ProfileError::StateMismatch));
            return live_tick();
        }
        self.core_open = false;
        let boundary = self.run.end_core_interpretation();
        self.latch(boundary.error);
        boundary.tick
    }
}

impl Drop for RunLease {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = cancel_active(self.token, self.detach, RejectionCause::LeaseCancelled);
        }
    }
}

fn stream_summary(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<Summary, ProfileError> {
    ensure_not_poisoned()?;
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Verified { sample, owner, .. }
            if sample.token() == token && owner.matches(token.epoch(), detach) =>
        {
            Ok(sample.summary())
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

fn stream_next(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<Option<Interval>, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    match &mut *slot {
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } if sample.token() == token && owner.matches(token.epoch(), detach) => {
            let interval = sample.interval(*cursor);
            if interval.is_some() {
                *cursor += 1;
            }
            Ok(interval)
        }
        _ => Err(ProfileError::StateMismatch),
    }
}

fn take_verified(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    require_complete: bool,
) -> Result<(TargetVerified<'static>, OwnerSeal, usize), ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let (required, emitted) = match &*slot {
        SlotState::Verified {
            sample,
            owner,
            cursor,
        } if sample.token() == token && owner.matches(token.epoch(), detach) => {
            (sample.summary().interval_count(), *cursor)
        }
        _ => return Err(ProfileError::StateMismatch),
    };
    if require_complete && emitted != required {
        return Err(ProfileError::IncompleteStream { emitted, required });
    }
    let owner = OwnerSeal {
        epoch: token.epoch(),
        detach,
    };
    let previous = mem::replace(
        &mut *slot,
        SlotState::Transit {
            owner,
            kind: TransitKind::Recycle,
        },
    );
    let SlotState::Verified {
        sample,
        owner,
        cursor,
    } = previous
    else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    Ok((sample, owner, cursor))
}

fn complete_stream(token: SampleToken, detach: CurrentTaskDetachLease) -> Result<(), ProfileError> {
    let (sample, owner, _) = take_verified(token, detach, true)?;
    let ready = sample.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    let mut slot = SLOT.lock();
    let exact = matches!(
        &*slot,
        SlotState::Transit { owner: actual, kind: TransitKind::Recycle }
            if actual.matches(owner.epoch, owner.detach)
    );
    if exact && ready.next_epoch() == owner.epoch.checked_add(1) && poison_reason().is_none() {
        *slot = SlotState::Ready(ready);
        return Ok(());
    }
    drop(slot);
    drop(ready);
    poison(SlotPoison::StateMismatch);
    Err(ProfileError::StateMismatch)
}

fn discard_stream(
    token: SampleToken,
    detach: CurrentTaskDetachLease,
) -> Result<RejectionReport, ProfileError> {
    let (sample, owner, cursor) = take_verified(token, detach, false)?;
    let report = RejectionReport {
        epoch: token.epoch(),
        cause: RejectionCause::StreamAbandoned,
        facade_faults: FacadeFaults::NONE,
        ledger_error: None,
        slot_faults: SlotFaults::NONE,
        intervals_emitted: cursor,
    };
    let ready = sample.recycle();
    if let Err(error) = disarm(owner.detach) {
        drop(ready);
        return Err(error);
    }
    install_rejected(owner, TransitKind::Recycle, ready, report)?;
    Ok(report)
}

/// Storage-free cursor for one globally resident verified sample.
pub(crate) struct StreamLease {
    token: SampleToken,
    detach: CurrentTaskDetachLease,
    live: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl StreamLease {
    pub(crate) const fn token(&self) -> SampleToken {
        self.token
    }

    pub(crate) fn summary(&self) -> Result<Summary, ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        stream_summary(self.token, self.detach)
    }

    pub(crate) fn next_interval(&mut self) -> Result<Option<Interval>, ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        stream_next(self.token, self.detach)
    }

    pub(crate) fn complete(mut self) -> Result<(), ProfileError> {
        if !self.detach.is_current_running_exact() {
            return Err(ProfileError::OwnerNotCurrent);
        }
        match complete_stream(self.token, self.detach) {
            Ok(()) => {
                self.live = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn discard(mut self) -> Result<RejectionReport, ProfileError> {
        self.live = false;
        discard_stream(self.token, self.detach)
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        if self.live {
            self.live = false;
            let _ = discard_stream(self.token, self.detach);
        }
    }
}

pub(crate) fn rejection() -> Option<RejectionReport> {
    if poison_reason().is_some() {
        return None;
    }
    let slot = SLOT.lock();
    match &*slot {
        SlotState::Rejected { report, .. } => Some(*report),
        _ => None,
    }
}

pub(crate) fn acknowledge_rejection(epoch: u64) -> Result<RejectionReport, ProfileError> {
    ensure_not_poisoned()?;
    let mut slot = SLOT.lock();
    let report = match &*slot {
        SlotState::Rejected { report, .. } if report.epoch == epoch => *report,
        SlotState::Rejected { .. } => return Err(ProfileError::StateMismatch),
        _ => return Err(ProfileError::StateMismatch),
    };
    // Rejected has no armed detach callback. `Uninitialized` is therefore a
    // private move placeholder which cannot be observed while this lock is
    // held; the slot is restored to Ready before unlocking.
    let previous = mem::replace(&mut *slot, SlotState::Uninitialized);
    let SlotState::Rejected { ready, .. } = previous else {
        poison(SlotPoison::StateMismatch);
        return Err(ProfileError::StateMismatch);
    };
    *slot = SlotState::Ready(ready);
    Ok(report)
}

enum DetachAction {
    None,
    Cancel {
        sample: TargetActive<'static>,
        owner: OwnerSeal,
        faults: SlotFaults,
        context: TargetContext,
        reason: TaskDetachReason,
    },
    Recycle {
        sample: TargetVerified<'static>,
        owner: OwnerSeal,
        cursor: usize,
        reason: TaskDetachReason,
    },
}

unsafe fn profile_task_detached(
    epoch: u64,
    task: TaskId,
    domain: AllocationDomain,
    reason: TaskDetachReason,
) {
    if poison_reason().is_some() {
        return;
    }
    let action = {
        let mut slot = SLOT.lock();
        match &*slot {
            SlotState::Reserved { owner, .. } if owner.callback_matches(epoch, task, domain) => {
                let previous = mem::replace(&mut *slot, SlotState::Uninitialized);
                let SlotState::Reserved { ready, .. } = previous else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                *slot = SlotState::Ready(ready);
                DetachAction::None
            }
            SlotState::Active { sample, owner, .. }
                if sample.token().epoch() == epoch
                    && owner.callback_matches(epoch, task, domain) =>
            {
                let owner = *owner;
                let context = live_context();
                #[cfg(feature = "wasm-c84-profile-irq-overlay")]
                if clear_active_epoch(epoch).is_err() {
                    let previous = mem::replace(
                        &mut *slot,
                        SlotState::Poisoned(SlotPoison::IrqStateMismatch),
                    );
                    drop(previous);
                    return;
                }
                let previous = mem::replace(
                    &mut *slot,
                    SlotState::Transit {
                        owner,
                        kind: TransitKind::Cancel,
                    },
                );
                let SlotState::Active { sample, faults, .. } = previous else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                DetachAction::Cancel {
                    sample,
                    owner,
                    faults,
                    context,
                    reason,
                }
            }
            SlotState::Verified {
                sample,
                owner,
                cursor,
            } if sample.token().epoch() == epoch && owner.callback_matches(epoch, task, domain) => {
                let owner = *owner;
                let previous = mem::replace(
                    &mut *slot,
                    SlotState::Transit {
                        owner,
                        kind: TransitKind::Recycle,
                    },
                );
                let SlotState::Verified { sample, cursor, .. } = previous else {
                    poison(SlotPoison::StateMismatch);
                    return;
                };
                DetachAction::Recycle {
                    sample,
                    owner,
                    cursor,
                    reason,
                }
            }
            SlotState::Transit { owner, .. } if owner.callback_matches(epoch, task, domain) => {
                *slot = SlotState::Poisoned(SlotPoison::DetachedDuringTransit);
                poison(SlotPoison::DetachedDuringTransit);
                DetachAction::None
            }
            _ => DetachAction::None,
        }
    };

    match action {
        DetachAction::None => {}
        DetachAction::Cancel {
            sample,
            owner,
            faults,
            context,
            reason,
        } => {
            let token = sample.token();
            let rejected = sample.cancel(token, context);
            let report = RejectionReport::from_target(
                &rejected,
                RejectionCause::TaskDetached(reason),
                faults,
                0,
            );
            let ready = rejected.recycle();
            let _ = install_rejected(owner, TransitKind::Cancel, ready, report);
        }
        DetachAction::Recycle {
            sample,
            owner,
            cursor,
            reason,
        } => {
            let report = RejectionReport::detached_verified(owner.epoch, reason, cursor);
            let ready = sample.recycle();
            let _ = install_rejected(owner, TransitKind::Recycle, ready, report);
        }
    }
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-core-poll-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance"
))]
fn wait_for_tick_progress() {
    let start = live_tick();
    while live_tick().wrapping_sub(start) < 32 {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
fn start_seven_phase_sample(expected_epoch: u64) -> Result<StreamLease, ProfileError> {
    let permit = prepare_current()?;
    if permit.expected_epoch() != expected_epoch {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != expected_epoch {
        return Err(ProfileError::StateMismatch);
    }
    wait_for_tick_progress();
    run.set_phase(Phase::Instantiation)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Abi)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Interpretation)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Host)?;
    wait_for_tick_progress();
    run.set_phase(Phase::Wait)?;
    wait_for_tick_progress();
    run.begin_cleanup()?;
    wait_for_tick_progress();
    run.finish()
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance"
))]
async fn wait_for_rejection(epoch: u64) -> Result<RejectionReport, ProfileError> {
    for _ in 0..128 {
        if let Some(report) = rejection() {
            if report.epoch == epoch {
                return Ok(report);
            }
        }
        crate::exec::yield_now().await;
    }
    Err(ProfileError::StateMismatch)
}

#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
async fn run_positive_acceptance() -> Result<(), ProfileError> {
    let active =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-detach-active", async {
            let permit = prepare_current().expect("C8.4 active detach permit");
            assert_eq!(permit.expected_epoch(), 1);
            let run = permit.start().expect("C8.4 active detach start");
            wait_for_tick_progress();
            run.set_phase(Phase::Host)
                .expect("C8.4 active detach phase");
            core::mem::forget(run);
        });
    if active.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let active_report = wait_for_rejection(1).await?;
    if active_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited) {
        return Err(ProfileError::Rejected(active_report));
    }
    acknowledge_rejection(1)?;

    let streaming =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-detach-stream", async {
            let mut stream = start_seven_phase_sample(2).expect("C8.4 stream detach sample");
            assert_eq!(
                stream
                    .summary()
                    .expect("C8.4 stream summary")
                    .interval_count(),
                7
            );
            assert!(stream
                .next_interval()
                .expect("C8.4 first interval")
                .is_some());
            core::mem::forget(stream);
        });
    if streaming.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let stream_report = wait_for_rejection(2).await?;
    if stream_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited)
        || stream_report.intervals_emitted != 1
    {
        return Err(ProfileError::Rejected(stream_report));
    }
    acknowledge_rejection(2)?;

    let mut stream = start_seven_phase_sample(3)?;
    let summary = stream.summary()?;
    if summary.interval_count() != 7 || stream.token().epoch() != 3 {
        return Err(ProfileError::StateMismatch);
    }
    let mut previous_end = 0;
    let mut count = 0;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count || interval.start_offset_ticks() != previous_end {
            return Err(ProfileError::StateMismatch);
        }
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != 7 || previous_end != summary.total_ticks() {
        return Err(ProfileError::StateMismatch);
    }
    stream.complete()?;
    if status()
        != (SlotStatus::Ready {
            next_epoch: Some(4),
        })
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

#[cfg(any(
    feature = "wasm-c84-profile-slot-qemu-acceptance",
    feature = "wasm-c84-core-poll-qemu-acceptance",
    feature = "wasm-c84-profile-irq-overlay-qemu-acceptance"
))]
fn run_topology_rejection() -> Result<(), ProfileError> {
    let permit = prepare_current()?;
    let epoch = permit.expected_epoch();
    match permit.start() {
        Err(ProfileError::Start(TargetStartError::InvalidContext(faults)))
            if faults.contains(FacadeFaults::WRONG_ONLINE_MASK)
                && !faults.contains(FacadeFaults::WRONG_LOGICAL_HART)
                && !faults.contains(FacadeFaults::WRONG_PHYSICAL_HART)
                && epoch == 1
                && status()
                    == (SlotStatus::Ready {
                        next_epoch: Some(1),
                    }) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
        Ok(run) => {
            drop(run);
            Err(ProfileError::StateMismatch)
        }
    }
}

/// QEMU-only positive single-hart and negative multi-hart ownership proof.
#[cfg(feature = "wasm-c84-profile-slot-qemu-acceptance")]
pub(crate) async fn run_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_positive_acceptance().await {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_SLOT PASS detached_active=1 detached_stream=1 epochs=1,2,3 intervals=7 indexed=1 complete=1 ready_epoch=4"
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_SLOT FAIL {:?}", error),
        }
    } else {
        match run_topology_rejection() {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_SLOT TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_SLOT FAIL {:?}", error),
        }
    }
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn exact_stream_resource_types(
    component: &vibeos_component_runtime::sync::SynchronousComponent,
    entrypoint: &str,
) -> Option<(
    vibeos_component_runtime::resource::ResourceTypeId,
    vibeos_component_runtime::resource::ResourceTypeId,
)> {
    use vibeos_component_runtime::value::{ResourceOwnership, ValueType};

    let function = component.function_type(entrypoint)?;
    let [reader, writer] = function.parameters.as_slice() else {
        return None;
    };
    let borrowed = |value: &ValueType| match value {
        ValueType::Resource {
            resource_type,
            ownership: ResourceOwnership::Borrow,
        } => Some(*resource_type),
        _ => None,
    };
    Some((borrowed(&reader.value)?, borrowed(&writer.value)?))
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn profile_is_publishable(profile: &vibeos_component_runtime::sync::SyncCallProfile) -> bool {
    profile.typed_polls != u64::MAX
        && profile.core_polls != u64::MAX
        && profile.outer_poll_ticks != u64::MAX
        && profile.core_interpreter_ticks != u64::MAX
        && profile.consumed_work != u64::MAX
}

#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
fn run_core_poll_positive_acceptance() -> Result<(), ProfileError> {
    use alloc::vec::Vec;
    use vibeos_component_runtime::{
        decode::inspect_component,
        resource::ResourceTable,
        sync::{SyncCallProfile, SynchronousComponent, TypedPoll},
        value::CanonicalValue,
    };
    use vibeos_wasm_runtime::{OwnerAllocationReservation, ProfileEngine};

    let permit = prepare_current()?;
    if permit.expected_epoch() != 1 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    let pin = vibeos_image_policy::SSH_EXEC_COMPONENT;
    let limits = pin.limits();

    wait_for_tick_progress();
    let plan = inspect_component(pin.artifact_bytes()).map_err(|_| ProfileError::StateMismatch)?;
    if !plan.runtime_ready() {
        return Err(ProfileError::StateMismatch);
    }

    run.set_phase(Phase::Instantiation)?;
    let engine = ProfileEngine::new();
    let mut component = SynchronousComponent::instantiate_with_memory_limit(
        &plan,
        &engine,
        OwnerAllocationReservation::new(limits.memory_bytes),
        limits.memory_bytes,
    )
    .map_err(|_| ProfileError::StateMismatch)?;
    let (reader_type, writer_type) = exact_stream_resource_types(&component, pin.entrypoint())
        .ok_or(ProfileError::StateMismatch)?;

    run.set_phase(Phase::Abi)?;
    let mut resources =
        ResourceTable::<u8>::new(1, limits.resources).map_err(|_| ProfileError::StateMismatch)?;
    let reader = resources
        .insert_owned(reader_type, 1)
        .map_err(|_| ProfileError::StateMismatch)?;
    let writer = resources
        .insert_owned(writer_type, 2)
        .map_err(|_| ProfileError::StateMismatch)?;
    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(2)
        .map_err(|_| ProfileError::StateMismatch)?;
    arguments.push(CanonicalValue::Resource(reader));
    arguments.push(CanonicalValue::Resource(writer));
    let mut call = component
        .start_typed_call(
            &mut resources,
            pin.entrypoint(),
            arguments,
            limits.total_fuel,
            limits.poll_quantum,
        )
        .map_err(|_| ProfileError::StateMismatch)?;
    let mut profile = SyncCallProfile::default();
    let mut observed_core = false;

    for _ in 0..4_096 {
        let before = profile.core_polls;
        let mut clock = SlotCorePollClock::new(&run);
        let result = call.poll_profiled(&mut clock, &mut profile);
        if clock.error().is_some() || !clock.core_is_closed() {
            return Err(clock.error().unwrap_or(ProfileError::StateMismatch));
        }
        if !profile_is_publishable(&profile) {
            return Err(ProfileError::StateMismatch);
        }
        if profile.core_polls > before {
            if profile.core_polls - before != 1 {
                return Err(ProfileError::StateMismatch);
            }
            observed_core = true;
            break;
        }
        if !matches!(result, TypedPoll::Pending(_)) {
            return Err(ProfileError::StateMismatch);
        }
    }
    if !observed_core || profile.core_interpreter_ticks == 0 {
        return Err(ProfileError::StateMismatch);
    }

    wait_for_tick_progress();
    run.begin_cleanup()?;
    drop(call);
    drop(resources);
    drop(component);
    drop(engine);
    wait_for_tick_progress();

    let mut stream = run.finish()?;
    let summary = stream.summary()?;
    if summary.phase_ticks().interpretation < profile.core_interpreter_ticks
        || !summary.intervals_complete()
        || summary.interval_count() != 6
    {
        return Err(ProfileError::StateMismatch);
    }
    let expected_phases = [
        Phase::Validation,
        Phase::Instantiation,
        Phase::Abi,
        Phase::Interpretation,
        Phase::Abi,
        Phase::Cleanup,
    ];
    let mut count = 0;
    let mut previous_end = 0;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count
            || interval.start_offset_ticks() != previous_end
            || expected_phases.get(count) != Some(&interval.phase())
        {
            return Err(ProfileError::StateMismatch);
        }
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != expected_phases.len() || previous_end != summary.total_ticks() {
        return Err(ProfileError::StateMismatch);
    }
    stream.complete()?;
    if status()
        != (SlotStatus::Ready {
            next_epoch: Some(2),
        })
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

/// QEMU-only proof that the explicit portable observer drives a real wasmi
/// Core poll into the exact task-owned slot. It does not modify ordinary
/// `TypedCall::poll` or claim SSH/trap/publication integration.
#[cfg(feature = "wasm-c84-core-poll-qemu-acceptance")]
pub(crate) async fn run_core_poll_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_core_poll_positive_acceptance() {
            Ok(()) => crate::println!(
                "WASM_C84_CORE_POLL PASS exact_artifact=1 real_core=1 observer_paired=1 interpretation_nonzero=1 complete=1 ready_epoch=2"
            ),
            Err(error) => crate::println!("WASM_C84_CORE_POLL FAIL {:?}", error),
        }
    } else {
        match run_topology_rejection() {
            Ok(()) => crate::println!(
                "WASM_C84_CORE_POLL TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_CORE_POLL FAIL {:?}", error),
        }
    }
}

/// Publish one local runnable reason, then deliberately force its pending
/// doorbell through OpenSBI as a real supervisor self-IPI. The worker remains
/// in one synchronous poll stack while the trap runs and returns.
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
fn force_boot_self_ssip(expect_profiled: bool) -> Result<(), ProfileError> {
    use crate::ipi::DoorbellDisposition;

    let hart = crate::exec::HartId::BOOT;
    let before = crate::ipi::stats(hart);
    let paired_before = ACCEPTANCE_SSIP_PAIRED.load(Ordering::Acquire);
    let inactive_before = ACCEPTANCE_SSIP_INACTIVE.load(Ordering::Acquire);
    if crate::ipi::publish_runnable(hart) != DoorbellDisposition::Local
        || crate::ipi::retry_pending(hart) != DoorbellDisposition::Sent
    {
        return Err(ProfileError::StateMismatch);
    }

    let start = live_tick();
    let after = loop {
        let observed = crate::ipi::stats(hart);
        if observed.acknowledged.wrapping_sub(before.acknowledged) == 1
            && observed.pending_reasons == 0
        {
            break observed;
        }
        if live_tick().wrapping_sub(start) >= crate::exec::timebase_hz() {
            return Err(ProfileError::StateMismatch);
        }
        core::hint::spin_loop();
    };

    if after.notifications.wrapping_sub(before.notifications) < 1
        || after.doorbells.wrapping_sub(before.doorbells) != 1
        || after.send_failures != before.send_failures
        || after.idle_consumed != before.idle_consumed
        || after.stale != before.stale
    {
        return Err(ProfileError::StateMismatch);
    }
    let paired_delta = ACCEPTANCE_SSIP_PAIRED
        .load(Ordering::Acquire)
        .wrapping_sub(paired_before);
    let inactive_delta = ACCEPTANCE_SSIP_INACTIVE
        .load(Ordering::Acquire)
        .wrapping_sub(inactive_before);
    if (expect_profiled && (paired_delta != 1 || inactive_delta != 0))
        || (!expect_profiled && (paired_delta != 0 || inactive_delta != 1))
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
async fn run_irq_positive_acceptance() -> Result<(), ProfileError> {
    let ready_epoch_one = SlotStatus::Ready {
        next_epoch: Some(1),
    };
    if status() != ready_epoch_one || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // A real SSIP before Active must remain observationally inert.
    force_boot_self_ssip(false)?;
    if status() != ready_epoch_one || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // Hold epoch 1 across suspension. The parent then receives a real SSIP
    // while it is not the sample owner; that trap must be a total no-op. The
    // child's ordinary RunLease Drop independently proves gate clearing.
    ACCEPTANCE_CHILD_ACTIVE.store(false, Ordering::Release);
    ACCEPTANCE_CHILD_RELEASE.store(false, Ordering::Release);
    let suspended =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-irq-non-owner-drop", async {
            let permit = prepare_current().expect("C8.4 IRQ suspended permit");
            assert_eq!(permit.expected_epoch(), 1);
            let run = permit.start().expect("C8.4 IRQ suspended start");
            assert_eq!(run.token().epoch(), 1);
            assert_eq!(ACTIVE_EPOCH.load(Ordering::Acquire), 1);
            ACCEPTANCE_CHILD_ACTIVE.store(true, Ordering::Release);
            while !ACCEPTANCE_CHILD_RELEASE.load(Ordering::Acquire) {
                crate::exec::yield_now().await;
            }
            drop(run);
        });
    for _ in 0..128 {
        if ACCEPTANCE_CHILD_ACTIVE.load(Ordering::Acquire) {
            break;
        }
        crate::exec::yield_now().await;
    }
    if !ACCEPTANCE_CHILD_ACTIVE.load(Ordering::Acquire)
        || status() != (SlotStatus::Active { epoch: 1 })
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 1
    {
        return Err(ProfileError::StateMismatch);
    }
    force_boot_self_ssip(false)?;
    if status() != (SlotStatus::Active { epoch: 1 }) || ACTIVE_EPOCH.load(Ordering::Acquire) != 1 {
        return Err(ProfileError::StateMismatch);
    }
    ACCEPTANCE_CHILD_RELEASE.store(true, Ordering::Release);
    if suspended.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let drop_report = wait_for_rejection(1).await?;
    if drop_report.cause != RejectionCause::LeaseCancelled
        || !drop_report.slot_faults.is_empty()
        || !drop_report.facade_faults.is_empty()
        || drop_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(drop_report));
    }
    acknowledge_rejection(1)?;

    // Explicit cancel is a distinct public exit through the shared cancel
    // transition and must clear epoch 2 before installing Rejected.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 2 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != 2 || ACTIVE_EPOCH.load(Ordering::Acquire) != 2 {
        return Err(ProfileError::StateMismatch);
    }
    let cancel_report = run.cancel()?;
    if cancel_report.cause != RejectionCause::LeaseCancelled
        || !cancel_report.slot_faults.is_empty()
        || !cancel_report.facade_faults.is_empty()
        || cancel_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(cancel_report));
    }
    acknowledge_rejection(2)?;

    // Forget epoch 3 so only the executor's exact task-detach callback can
    // recover Active and clear the gate.
    let detached =
        crate::exec::spawn_pinned_on(crate::exec::HartId::BOOT, "c84-irq-detach", async {
            let permit = prepare_current().expect("C8.4 IRQ detach permit");
            assert_eq!(permit.expected_epoch(), 3);
            let run = permit.start().expect("C8.4 IRQ detach start");
            assert_eq!(run.token().epoch(), 3);
            assert_eq!(ACTIVE_EPOCH.load(Ordering::Acquire), 3);
            core::mem::forget(run);
        });
    if detached.join().await.state() != crate::exec::TaskState::Exited {
        return Err(ProfileError::StateMismatch);
    }
    let detach_report = wait_for_rejection(3).await?;
    if detach_report.cause != RejectionCause::TaskDetached(TaskDetachReason::Exited)
        || !detach_report.slot_faults.is_empty()
        || !detach_report.facade_faults.is_empty()
        || detach_report.ledger_error.is_some()
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::Rejected(detach_report));
    }
    acknowledge_rejection(3)?;

    // Epoch 4 is the publishable sample. The SSIP-specific acceptance counter
    // proves the forced doorbell, rather than a periodic timer, supplied one
    // successfully closed active cookie.
    let permit = prepare_current()?;
    if permit.expected_epoch() != 4 {
        return Err(ProfileError::StateMismatch);
    }
    let run = permit.start()?;
    if run.token().epoch() != 4 || ACTIVE_EPOCH.load(Ordering::Acquire) != 4 {
        return Err(ProfileError::StateMismatch);
    }

    wait_for_tick_progress();
    run.set_phase(Phase::Host)?;
    wait_for_tick_progress();
    force_boot_self_ssip(true)?;
    // Make the restored Host interval independently non-zero before Cleanup.
    wait_for_tick_progress();
    run.begin_cleanup()?;
    wait_for_tick_progress();

    let mut stream = run.finish()?;
    let summary = stream.summary()?;
    if !summary.intervals_complete() || summary.phase_ticks().wait == 0 {
        return Err(ProfileError::StateMismatch);
    }

    let mut count = 0;
    let mut previous_end = 0;
    let mut previous_phase = None;
    let mut phase_before_previous = None;
    let mut previous_nonzero = false;
    let mut wait_count = 0;
    let mut paired_count = 0;
    let mut restored_host = false;
    while let Some(interval) = stream.next_interval()? {
        if interval.sequence() != count || interval.start_offset_ticks() != previous_end {
            return Err(ProfileError::StateMismatch);
        }
        let phase = interval.phase();
        if phase == Phase::Wait {
            wait_count += 1;
        }
        if previous_phase == Some(Phase::Wait) {
            let Some(base) = phase_before_previous else {
                return Err(ProfileError::StateMismatch);
            };
            if base == Phase::Wait || phase != base || !previous_nonzero {
                return Err(ProfileError::StateMismatch);
            }
            paired_count += 1;
            restored_host |= base == Phase::Host;
        }
        previous_nonzero = interval.end_offset_ticks() > interval.start_offset_ticks();
        phase_before_previous = previous_phase;
        previous_phase = Some(phase);
        previous_end = interval.end_offset_ticks();
        count += 1;
    }
    if count != summary.interval_count()
        || previous_end != summary.total_ticks()
        || previous_phase == Some(Phase::Wait)
        || wait_count == 0
        || paired_count != wait_count
        || !restored_host
    {
        return Err(ProfileError::StateMismatch);
    }

    stream.complete()?;
    let ready_epoch_five = SlotStatus::Ready {
        next_epoch: Some(5),
    };
    if status() != ready_epoch_five || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // A final real SSIP proves the gate was cleared by Active -> Verified
    // before streaming and remains inert after Verified -> Ready recycling.
    force_boot_self_ssip(false)?;
    if status() != ready_epoch_five || ACTIVE_EPOCH.load(Ordering::Acquire) != 0 {
        return Err(ProfileError::StateMismatch);
    }

    // Acceptance-only mismatch injection proves the first poison remains
    // stable, forcibly clears the fast gate, makes inactive-cookie exit a
    // no-op, and prevents either helper or prepare from re-arming the slot.
    ACTIVE_EPOCH.store(77, Ordering::Release);
    if publish_active_epoch(88) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || poison_reason() != Some(SlotPoison::IrqStateMismatch)
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }
    poison(SlotPoison::StateMismatch);
    let inactive = profile_irq_enter(live_tick());
    if profile_irq_exit(inactive, live_tick())
        || publish_active_epoch(99) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || clear_active_epoch(99) != Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        || !matches!(
            prepare_current(),
            Err(ProfileError::Poisoned(SlotPoison::IrqStateMismatch))
        )
        || poison_reason() != Some(SlotPoison::IrqStateMismatch)
        || ACTIVE_EPOCH.load(Ordering::Acquire) != 0
    {
        return Err(ProfileError::StateMismatch);
    }
    Ok(())
}

/// QEMU-only proof of the default-off trap overlay using real OpenSBI
/// self-SSIPs, exactly one of which is an active-owner profiled pair. Timer,
/// PLIC, SSH, and publication integration remain separate.
#[cfg(feature = "wasm-c84-profile-irq-overlay-qemu-acceptance")]
pub(crate) async fn run_irq_qemu_acceptance() {
    if crate::online_hart_mask() == 1 {
        match run_irq_positive_acceptance().await {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_IRQ_OVERLAY PASS inactive_before=1 forced_ssip=4 causal_ssip_pair=1 non_owner_inert=1 cleared_cancel=1 cleared_drop=1 cleared_detach=1 wait_nonzero=1 restored=1 paired=1 complete=1 ready_epoch=5 inactive_after=1 poison_fail_closed=1"
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_IRQ_OVERLAY FAIL {:?}", error),
        }
    } else {
        let result = run_topology_rejection().and_then(|()| {
            if ACTIVE_EPOCH.load(Ordering::Acquire) == 0 {
                Ok(())
            } else {
                Err(ProfileError::StateMismatch)
            }
        });
        match result {
            Ok(()) => crate::println!(
                "WASM_C84_PROFILE_IRQ_OVERLAY TOPOLOGY_REJECT mask={:#x} logical={} physical={} epoch=1",
                crate::online_hart_mask(),
                crate::ipi::current_logical_hart().map_or(usize::MAX, crate::exec::HartId::index),
                crate::sbi::current_hart_id(),
            ),
            Err(error) => crate::println!("WASM_C84_PROFILE_IRQ_OVERLAY FAIL {:?}", error),
        }
    }
}
