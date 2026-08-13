//! Hart-aware, interrupt-safe spinlock.
//!
//! A local interrupt cannot re-enter a protected value because acquisition
//! saves and disables interrupts until the guard is dropped. Contending harts
//! coordinate through an explicit state machine so recovery never observes a
//! half-published owner domain.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::num::NonZeroU64;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{current_hart_id, irq_restore, irq_save};
use crate::heap::{self, AllocationDomain, ArenaId, OwnerId};
use crate::runqueue::{HartId, MAX_HARTS};

const PHASE_BITS: u32 = 2;
const PHASE_MASK: u64 = (1 << PHASE_BITS) - 1;
const MAX_GENERATION: u64 = u64::MAX >> PHASE_BITS;
const FREE: u64 = 0;
const ACQUIRING: u64 = 1;
const HELD: u64 = 2;
const RECOVERING: u64 = 3;

static TASK_RECOVERY_CONTEXTS: [AtomicU64; MAX_HARTS] = [const { AtomicU64::new(0) }; MAX_HARTS];

const fn state_token(generation: u64, phase: u64) -> u64 {
    (generation << PHASE_BITS) | phase
}

const fn token_generation(token: u64) -> u64 {
    token >> PHASE_BITS
}

const fn token_phase(token: u64) -> u64 {
    token & PHASE_MASK
}

const fn with_phase(token: u64, phase: u64) -> u64 {
    state_token(token_generation(token), phase)
}

/// Globally unique identity of one task incarnation eligible for exact-task
/// abandoned-lock recovery. Zero is deliberately unrepresentable and denotes
/// scheduler, interrupt, boot, or otherwise unattributed lock acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TaskRecoveryKey(NonZeroU64);

impl TaskRecoveryKey {
    pub const fn new(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(key) => Some(Self(key)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[inline(always)]
fn recovery_context_hart_index() -> Option<usize> {
    if let Some(logical) = crate::ipi::current_logical_hart() {
        return Some(logical.index());
    }

    // Host integration tests do not construct a complete SBI topology. The
    // target must never equate a dense-looking firmware hartid with a logical
    // slot: M5.2 explicitly supports non-contiguous and permuted mappings.
    #[cfg(not(target_arch = "riscv64"))]
    {
        let physical = current_hart_id();
        return (physical < MAX_HARTS).then_some(physical);
    }

    #[cfg(target_arch = "riscv64")]
    None
}

fn current_task_recovery_key() -> u64 {
    recovery_context_hart_index()
        .map(|hart| TASK_RECOVERY_CONTEXTS[hart].load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Install one exact-task recovery identity on the current logical hart.
///
/// Contexts may nest and must restore in LIFO order. The executor should keep
/// this scope outside its fault landing pad and call [`TaskRecoveryContext::restore`]
/// explicitly after a longjmp, just as it does for the allocation-domain
/// scope. Ordinary unwinding restores through `Drop`.
pub fn enter_task_recovery_context(key: TaskRecoveryKey) -> TaskRecoveryContext {
    let irq = irq_save();
    let Some(hart) = recovery_context_hart_index() else {
        irq_restore(irq);
        panic!("task recovery context requires a mapped logical hart");
    };
    let slot = &TASK_RECOVERY_CONTEXTS[hart];
    let previous = slot.swap(key.get(), Ordering::AcqRel);
    let physical_hart = current_hart_id();
    irq_restore(irq);
    TaskRecoveryContext {
        hart,
        physical_hart,
        slot,
        installed: key,
        previous,
        active: true,
        not_send: PhantomData,
    }
}

/// Install recovery identity after the executor has already validated `hart`.
///
/// # Safety
/// The current CPU must own `hart` until the returned scope is restored.
pub(crate) unsafe fn enter_task_recovery_context_on_hart(
    hart: HartId,
    key: TaskRecoveryKey,
) -> TaskRecoveryContext {
    let irq = irq_save();
    debug_assert_eq!(recovery_context_hart_index(), Some(hart.index()));
    let slot = &TASK_RECOVERY_CONTEXTS[hart.index()];
    let previous = slot.swap(key.get(), Ordering::AcqRel);
    let physical_hart = current_hart_id();
    irq_restore(irq);
    TaskRecoveryContext {
        hart: hart.index(),
        physical_hart,
        slot,
        installed: key,
        previous,
        active: true,
        not_send: PhantomData,
    }
}

/// Hart-affine scope returned by [`enter_task_recovery_context`].
pub struct TaskRecoveryContext {
    hart: usize,
    physical_hart: usize,
    slot: &'static AtomicU64,
    installed: TaskRecoveryKey,
    previous: u64,
    active: bool,
    not_send: PhantomData<*mut ()>,
}

impl TaskRecoveryContext {
    pub(crate) fn is_current_hart(&self) -> bool {
        current_hart_id() == self.physical_hart
    }

    fn restore_inner(&mut self) {
        let restored = self.slot.compare_exchange(
            self.installed.get(),
            self.previous,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.active = false;
        assert_eq!(
            restored,
            Ok(self.installed.get()),
            "task recovery contexts restored out of LIFO order"
        );
    }

    /// Restore after an enclosing hart-affine scope validated this CPU.
    ///
    /// # Safety
    /// The caller must have independently verified the current physical hart.
    pub(crate) unsafe fn restore_on_verified_hart(&mut self) {
        if !self.active {
            return;
        }
        let irq = irq_save();
        self.restore_inner();
        irq_restore(irq);
    }

    /// Restore the previous exact-task identity. This is idempotent.
    pub fn restore(&mut self) {
        if !self.active {
            return;
        }

        let irq = irq_save();
        let current_physical_hart = current_hart_id();
        if current_physical_hart != self.physical_hart {
            irq_restore(irq);
            // Prevent a second panic from `Drop` while unwinding this invariant
            // violation. The original hart's context deliberately remains
            // installed so misuse cannot silently attribute another task.
            self.active = false;
            panic!(
                "task recovery context entered on logical hart {} / physical hart {} restored on physical hart {}",
                self.hart,
                self.physical_hart,
                current_physical_hart
            );
        }
        self.restore_inner();
        irq_restore(irq);
    }
}

impl Drop for TaskRecoveryContext {
    fn drop(&mut self) {
        self.restore();
    }
}

/// A lock-local, allocation-free telemetry snapshot.
///
/// Each wrapping counter is sampled independently, so snapshots taken while
/// other harts are active are intentionally not a globally linearizable event
/// log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpinLockStats {
    /// Guards that completed acquisition and were returned to callers.
    pub acquisitions: u64,
    /// Acquisitions that observed another acquisition or guard in progress.
    pub contended_acquisitions: u64,
    /// Abandoned matching-domain guards released by fault teardown.
    pub fault_recoveries: u64,
}

/// Result of claiming an abandoned exact-task guard and validating the value
/// while the lock is exclusively held in its recovery phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalRecovery {
    /// The lock was already free, so no abandoned-task provenance exists and
    /// the protected value was deliberately not inspected. Callers must
    /// validate a separate SYSTEM-owned immutable/atomic witness before
    /// reclaim; this result is never evidence that the value matched.
    NotHeldUnvalidated,
    /// The lock kind, phase, allocation domain, task, or acquisition
    /// generation did not match. No lock state was changed.
    ProvenanceMismatch,
    /// Provenance matched and the value predicate accepted the abandoned
    /// state. The lock was released for later lifecycle use.
    Recovered,
    /// Provenance matched but the value predicate rejected the abandoned
    /// state. The lock remains permanently in `RECOVERING` as a fail-stop
    /// quarantine and must never be acquired or recovered again.
    ValueMismatch,
}

pub struct SpinLock<T> {
    /// Lean acquire/release word for locks that never use fault recovery.
    fast_locked: AtomicBool,
    /// Phase and acquisition generation form one compare-exchange identity.
    /// Keeping them in one atomic prevents a delayed recovery snapshot from
    /// claiming a later guard held by the same allocation domain.
    state: AtomicU64,
    owner: AtomicU64,
    arena: AtomicU64,
    recovery_key: AtomicU64,
    recoverable: bool,
    stats_enabled: AtomicBool,
    acquisitions: AtomicU64,
    contended_acquisitions: AtomicU64,
    fault_recoveries: AtomicU64,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self::with_recovery(data, false)
    }

    /// Construct a lock whose guards publish fault-recovery provenance.
    ///
    /// Most kernel locks never cross a component fault boundary and use the
    /// lean [`Self::new`] path. Stable service locks explicitly opt in when a
    /// cleanup hook may call one of the unsafe recovery APIs.
    pub const fn new_recoverable(data: T) -> Self {
        Self::with_recovery(data, true)
    }

    const fn with_recovery(data: T, recoverable: bool) -> Self {
        Self {
            fast_locked: AtomicBool::new(false),
            state: AtomicU64::new(state_token(0, FREE)),
            owner: AtomicU64::new(OwnerId::SYSTEM.get()),
            arena: AtomicU64::new(ArenaId::UNTRACKED.get()),
            recovery_key: AtomicU64::new(0),
            recoverable,
            stats_enabled: AtomicBool::new(false),
            acquisitions: AtomicU64::new(0),
            contended_acquisitions: AtomicU64::new(0),
            fault_recoveries: AtomicU64::new(0),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinGuard<'_, T> {
        let irq = irq_save();
        if !self.recoverable {
            return self.lock_fast(irq);
        }

        self.lock_recoverable(irq)
    }

    fn lock_fast(&self, irq: bool) -> SpinGuard<'_, T> {
        let mut contended = false;
        loop {
            match self.fast_locked.compare_exchange_weak(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => {
                    if actual && !contended {
                        contended = true;
                        if self.stats_enabled.load(Ordering::Relaxed) {
                            self.contended_acquisitions.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    core::hint::spin_loop();
                }
            }
        }
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.acquisitions.fetch_add(1, Ordering::Relaxed);
        }
        SpinGuard {
            lock: self,
            irq,
            acquisition_hart: current_hart_id(),
            held_token: 0,
            not_send: PhantomData,
        }
    }

    fn lock_recoverable(&self, irq: bool) -> SpinGuard<'_, T> {
        let mut contended = false;
        let acquiring_token = loop {
            let observed = self.state.load(Ordering::Relaxed);
            if token_phase(observed) == FREE {
                let generation = token_generation(observed);
                if generation == MAX_GENERATION {
                    // Reusing a generation would make a sufficiently delayed
                    // recovery token valid again. Exhaustion is therefore a
                    // fail-closed terminal condition, not a wrapping counter.
                    irq_restore(irq);
                    panic!("SpinLock acquisition generation exhausted");
                }
                let acquiring = state_token(generation + 1, ACQUIRING);
                match self.state.compare_exchange_weak(
                    observed,
                    acquiring,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break acquiring,
                    Err(actual) => {
                        // A weak CAS may fail spuriously while the same FREE
                        // token remains. Count only an observed non-free phase.
                        if token_phase(actual) != FREE && !contended {
                            contended = true;
                            if self.stats_enabled.load(Ordering::Relaxed) {
                                self.contended_acquisitions.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            } else if !contended {
                contended = true;
                if self.stats_enabled.load(Ordering::Relaxed) {
                    self.contended_acquisitions.fetch_add(1, Ordering::Relaxed);
                }
            }
            core::hint::spin_loop();
        };

        let acquisition_hart = current_hart_id();
        let domain = heap::current_domain();
        self.owner.store(domain.owner.get(), Ordering::Relaxed);
        self.arena.store(domain.arena.get(), Ordering::Relaxed);
        self.recovery_key
            .store(current_task_recovery_key(), Ordering::Relaxed);
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.acquisitions.fetch_add(1, Ordering::Relaxed);
        }

        // This release publishes the complete owner/domain/task tuple. Fault
        // recovery accepts HELD only, never the ACQUIRING publication window.
        let held_token = with_phase(acquiring_token, HELD);
        self.state.store(held_token, Ordering::Release);
        SpinGuard {
            lock: self,
            irq,
            acquisition_hart,
            held_token,
            // Raw pointers are !Send. The marker makes moving a guard to a
            // different hart a compile-time error on stable Rust.
            not_send: PhantomData,
        }
    }

    /// Return allocation-free telemetry for this lock.
    ///
    /// The first sample enables counters for later operations on this lock.
    /// Keeping telemetry opt-in avoids an atomic read/modify/write on every
    /// production acquisition merely to support an occasional audit.
    pub fn stats(&self) -> SpinLockStats {
        self.stats_enabled.store(true, Ordering::Release);
        SpinLockStats {
            acquisitions: self.acquisitions.load(Ordering::Acquire),
            contended_acquisitions: self.contended_acquisitions.load(Ordering::Acquire),
            fault_recoveries: self.fault_recoveries.load(Ordering::Acquire),
        }
    }

    /// Capture a fully published, matching-domain guard identity.
    fn matching_held_token(&self, expected_domain: AllocationDomain) -> Option<u64> {
        if !self.recoverable {
            return None;
        }
        let token = self.state.load(Ordering::Acquire);
        (token_phase(token) == HELD
            && self.owner.load(Ordering::Relaxed) == expected_domain.owner.get()
            && self.arena.load(Ordering::Relaxed) == expected_domain.arena.get())
        .then_some(token)
    }

    /// Capture a fully published guard belonging to one exact task.
    fn matching_task_held_token(
        &self,
        expected_domain: AllocationDomain,
        expected_task: TaskRecoveryKey,
    ) -> Option<u64> {
        let token = self.matching_held_token(expected_domain)?;
        (self.recovery_key.load(Ordering::Relaxed) == expected_task.get()).then_some(token)
    }

    /// Claim exactly the observed guard generation for recovery.
    fn claim_recovery_token(&self, held_token: u64) -> bool {
        token_phase(held_token) == HELD
            && self
                .state
                .compare_exchange(
                    held_token,
                    with_phase(held_token, RECOVERING),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    fn finish_recovery(&self, token: u64) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.fault_recoveries.fetch_add(1, Ordering::Relaxed);
        }
        self.state.store(with_phase(token, FREE), Ordering::Release);
    }

    /// Recover a lock only when its fully published guard was acquired by
    /// `expected_domain` and then abandoned by that fault domain's `longjmp`.
    ///
    /// Untracked domains (including SYSTEM) are always left untouched; they do
    /// not provide domain-wide quiescence and must use exact-task recovery
    /// instead. A guard held by another tracked component is also left
    /// untouched. An acquisition still in `ACQUIRING` is left untouched: the `HELD`
    /// release/acquire edge makes the owner, arena, and task key one
    /// published record rather than independent evidence. Phase and generation
    /// share one atomic token, so a delayed recovery CAS cannot claim a newer
    /// guard even when that guard belongs to the same domain.
    ///
    /// # Safety
    ///
    /// The caller must establish an **all-hart quiescence boundary** for
    /// `expected_domain`: every hart that could run one of its tasks has
    /// stopped doing so, all such tasks are terminal, and none can resume. The
    /// coordinator must observe every hart's Release quiescence acknowledgement
    /// with an Acquire load before calling this method. Disabling interrupts on
    /// only the calling hart is not sufficient. The Acquire token load below
    /// synchronizes guard metadata publication; it does not replace those
    /// per-hart barrier acknowledgements.
    ///
    /// M5.3 invokes recovery while physical component execution is still
    /// boot-hart-affine. M5.4's hart-local running state must preserve this API
    /// contract by completing an all-hart quiescence/ack barrier before fault
    /// teardown calls it. This method does not implement that barrier itself.
    pub unsafe fn recover_after_fault(&self, expected_domain: AllocationDomain) -> bool {
        if !expected_domain.arena.is_tracked() {
            return false;
        }
        let irq = irq_save();
        let recovered_token = self
            .matching_held_token(expected_domain)
            .filter(|token| self.claim_recovery_token(*token));
        if let Some(token) = recovered_token {
            self.finish_recovery(token);
        }
        irq_restore(irq);
        recovered_token.is_some()
    }

    /// Recover an abandoned guard attributed to one exact task incarnation.
    ///
    /// Unlike [`Self::recover_after_fault`], this API may recover a guard in an
    /// untracked or SYSTEM domain because the nonzero task key distinguishes
    /// unrelated tasks sharing that domain. The exact phase+generation token
    /// also prevents a delayed cleanup from claiming a later guard acquired by
    /// the same task key.
    ///
    /// # Safety
    ///
    /// `expected_task` must be globally unique and never reused. The caller
    /// must prove that this exact task is terminal and cannot resume or drop
    /// its abandoned guard. If it ran on another hart, the cleanup coordinator
    /// must observe that hart's Release quiescence acknowledgement with an
    /// Acquire load first. Sibling tasks in the same domain may remain live.
    pub unsafe fn recover_after_task_fault(
        &self,
        expected_domain: AllocationDomain,
        expected_task: TaskRecoveryKey,
    ) -> bool {
        let irq = irq_save();
        let recovered_token = self
            .matching_task_held_token(expected_domain, expected_task)
            .filter(|token| self.claim_recovery_token(*token));
        if let Some(token) = recovered_token {
            self.finish_recovery(token);
        }
        irq_restore(irq);
        recovered_token.is_some()
    }

    /// Recover an exact-task guard only if its protected value still matches
    /// immutable lifecycle evidence.
    ///
    /// The predicate runs after the exact HELD acquisition generation has been
    /// atomically claimed as RECOVERING, so another hart cannot mutate the
    /// value between validation and release. A false predicate deliberately
    /// leaves that generation in RECOVERING forever. This supplies the
    /// fail-stop primitive needed when releasing the lock would make a
    /// mismatched CSpace or registry entry reachable again.
    ///
    /// A FREE lock has no current owner/domain/task tuple to authenticate, so
    /// this method returns [`ConditionalRecovery::NotHeldUnvalidated`] without
    /// calling the predicate. Lifecycle code must pair that result with a
    /// separate SYSTEM-owned witness whose publication cannot race reset.
    ///
    /// # Safety
    ///
    /// The exact-task terminal and all-hart quiescence requirements of
    /// [`Self::recover_after_task_fault`] apply. `predicate` must not allocate,
    /// block, acquire a lock, or panic. It may only inspect `value` and stable
    /// immutable evidence. On [`ConditionalRecovery::ValueMismatch`], the
    /// caller must quarantine every lifecycle record that could name this lock
    /// and conservatively leak the protected value.
    pub unsafe fn recover_after_task_fault_if<F>(
        &self,
        expected_domain: AllocationDomain,
        expected_task: TaskRecoveryKey,
        predicate: F,
    ) -> ConditionalRecovery
    where
        F: FnOnce(&T) -> bool,
    {
        let irq = irq_save();
        if !self.recoverable {
            irq_restore(irq);
            return ConditionalRecovery::ProvenanceMismatch;
        }

        let held_token = self.state.load(Ordering::Acquire);
        if token_phase(held_token) == FREE {
            irq_restore(irq);
            return ConditionalRecovery::NotHeldUnvalidated;
        }
        if token_phase(held_token) != HELD
            || self.owner.load(Ordering::Relaxed) != expected_domain.owner.get()
            || self.arena.load(Ordering::Relaxed) != expected_domain.arena.get()
            || self.recovery_key.load(Ordering::Relaxed) != expected_task.get()
            || !self.claim_recovery_token(held_token)
        {
            irq_restore(irq);
            return ConditionalRecovery::ProvenanceMismatch;
        }

        // Safety: the exact HELD generation is now exclusively RECOVERING and
        // the caller established permanent task quiescence. No guard can
        // access the UnsafeCell until this method either releases or fail-stops
        // the lock.
        let matches = predicate(unsafe { &*self.data.get() });
        let result = if matches {
            self.finish_recovery(held_token);
            ConditionalRecovery::Recovered
        } else {
            ConditionalRecovery::ValueMismatch
        };
        irq_restore(irq);
        result
    }
}

/// An interrupt-state guard bound to the hart that acquired it.
///
/// ```compile_fail
/// use vibeos_core::sync::SpinLock;
///
/// fn require_send<T: Send>(_: T) {}
/// let lock = SpinLock::new(0u8);
/// require_send(lock.lock());
/// ```
#[must_use = "dropping the guard releases the lock and restores local interrupts"]
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    irq: bool,
    acquisition_hart: usize,
    held_token: u64,
    not_send: PhantomData<*mut ()>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        let current_hart = current_hart_id();
        assert_eq!(
            current_hart, self.acquisition_hart,
            "SpinGuard acquired on hart {} dropped on hart {}",
            self.acquisition_hart, current_hart
        );
        if self.lock.recoverable {
            assert_eq!(
                self.lock.state.compare_exchange(
                    self.held_token,
                    with_phase(self.held_token, FREE),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ),
                Ok(self.held_token),
                "SpinGuard dropped after its lock stopped being held"
            );
        } else {
            self.lock.fast_locked.store(false, Ordering::Release);
        }
        irq_restore(self.irq);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_recovery_snapshot_cannot_claim_a_reacquired_lock() {
        let lock = SpinLock::new(());

        // Recovery actor R snapshots generation 41, then pauses before CAS.
        let stale_held = state_token(41, HELD);
        lock.state.store(stale_held, Ordering::Release);

        // The old guard releases and acquisition actor A publishes a new guard
        // in the same lock. Domain equality cannot distinguish this ABA; the
        // exact generation token must do so.
        lock.state
            .store(with_phase(stale_held, FREE), Ordering::Release);
        let fresh_held = state_token(42, HELD);
        lock.state.store(fresh_held, Ordering::Release);

        // R resumes with its old snapshot and must not transition generation
        // 42 to RECOVERING. A recovery that snapshots 42 still can.
        assert!(!lock.claim_recovery_token(stale_held));
        assert_eq!(lock.state.load(Ordering::Acquire), fresh_held);
        assert!(lock.claim_recovery_token(fresh_held));
        assert_eq!(
            lock.state.load(Ordering::Acquire),
            with_phase(fresh_held, RECOVERING)
        );
    }
}
