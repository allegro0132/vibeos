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

#[cfg(feature = "ssh-component-command")]
extern crate alloc;

#[cfg(feature = "ssh-component-command")]
use alloc::{boxed::Box, vec::Vec};
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
    OneShotWaitQueue, OneShotWake, PreparedTaskBatch, TaskHandle, TaskId, TaskState,
};
#[cfg(feature = "ssh-component-command")]
use crate::heap::{AllocationDomain, OwnerId};
#[cfg(feature = "ssh-component-command")]
use crate::instance::{
    CooperativeCancelOutcome, InstanceContinuation, InstanceContinuationKind, InstancePayload,
    InstancePhase, InstanceToken, ReserveError, TerminalRetireKind,
};
use crate::instance::{FaultGateOutcome, InstanceRegistry};
use crate::HEAP;

#[cfg(feature = "ssh-component-command")]
use vibeos_component_admission::{
    admit, AdmissionPolicy, AdmittedComponent, ArtifactTrust, CallerAuthority, CommandStreamMode,
    ComponentArtifact, InstanceLimits,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_command::{
    try_manifest_from_admitted, validate_admitted_filter, RunnerBuildError,
};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_format::TrapCode;
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::host::HostError;
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::resource::ResourceTable;
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::sync::{SyncError, SynchronousComponent, TypedPoll};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::value::{CanonicalValue, ValueType};
#[cfg(feature = "ssh-component-command")]
use vibeos_component_runtime::world::WorldContract;
#[cfg(feature = "ssh-component-command")]
use vibeos_image_policy::{ComponentCommandPin, ComponentStreamMode, SSH_EXEC_COMPONENT};
#[cfg(feature = "ssh-component-command")]
use vibeos_sshd::{AuthorizedProfile, SshExecComponentSessionPolicy};
#[cfg(feature = "ssh-component-command")]
use vibeos_vsh::{
    ComponentArtifactIdentity, ComponentCommandManifest, ComponentTerminal, ComponentTrapCode,
    ManagedComponentCancel, ManagedComponentLifecycle, ManagedComponentState,
    ManagedComponentStateFuture, ManagedComponentToken, Session, SshExecComponentPolicy,
    StreamMode,
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

#[cfg(feature = "ssh-component-command")]
const LIFECYCLE_HEALTHY: u8 = 0;
#[cfg(feature = "ssh-component-command")]
const LIFECYCLE_FAILED: u8 = 1;

#[cfg(feature = "ssh-component-command")]
static IMAGE_ROOT: AtomicPtr<ImageRoot> = AtomicPtr::new(ptr::null_mut());
#[cfg(feature = "ssh-component-command")]
static SSH_POLICY_GATE: AtomicU8 = AtomicU8::new(POLICY_CLOSED);
#[cfg(feature = "ssh-component-command")]
static LIFECYCLE_HEALTH: AtomicU8 = AtomicU8::new(LIFECYCLE_HEALTHY);
#[cfg(feature = "ssh-component-command")]
static CONTROL: ControlGate = ControlGate::new();
#[cfg(feature = "ssh-component-command")]
static LIFECYCLE: ImageComponentLifecycle = ImageComponentLifecycle;

#[cfg(feature = "ssh-component-command")]
fn lifecycle_is_healthy() -> bool {
    LIFECYCLE_HEALTH.load(Ordering::Acquire) == LIFECYCLE_HEALTHY
}

#[cfg(feature = "ssh-component-command")]
fn lifecycle_fail_stop() {
    LIFECYCLE_HEALTH.store(LIFECYCLE_FAILED, Ordering::Release);
    SSH_POLICY_GATE.store(POLICY_FAILED, Ordering::Release);
    CONTROL.request_fail_stop_wake();
}

#[cfg(feature = "ssh-component-command")]
struct ImageRoot {
    admitted: AdmittedComponent,
    manifest: ComponentCommandManifest,
    ssh_policy: SshExecComponentPolicy,
    policy_incarnation: NonZeroU64,
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
struct ControlRecord {
    generation: u64,
    phase: ControlPhase,
    core_token: Option<InstanceToken>,
    handle: Option<TaskHandle>,
    domain: Option<AllocationDomain>,
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone)]
struct ControlTuple {
    core_token: InstanceToken,
    handle: TaskHandle,
    domain: AllocationDomain,
}

#[cfg(feature = "ssh-component-command")]
impl ControlRecord {
    const fn new() -> Self {
        Self {
            generation: 0,
            phase: ControlPhase::Vacant,
            core_token: None,
            handle: None,
            domain: None,
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
                if gate.completion[index].waiter_count() != 0 {
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
                record.domain = None;
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
    fn running_tuple(&mut self, key: ControlKey) -> Result<Option<ControlTuple>, ()> {
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
        let Some(domain) = record.domain else {
            self.exact_mut(key)
                .expect("exact control record vanished")
                .quarantine();
            return Err(());
        };
        if handle.allocation_domain() != domain {
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
            domain,
        }))
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
        let tuple = ControlTuple {
            core_token: record
                .core_token
                .expect("exact fault control record has a core token"),
            handle: record
                .handle
                .as_ref()
                .expect("exact fault control record has a handle")
                .clone(),
            domain: record
                .domain
                .expect("exact fault control record has a domain"),
        };
        for (index, other) in self.slots.iter_mut().enumerate() {
            if index != key.slot as usize
                && Self::records_alias(other, tuple.core_token, &tuple.handle, tuple.domain)
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
    table: UnsafeCell<ControlTable>,
    completion: [OneShotWaitQueue; CONTROL_SLOTS],
    completion_generation: [AtomicU64; CONTROL_SLOTS],
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
            table: UnsafeCell::new(ControlTable::new()),
            completion: [const { OneShotWaitQueue::new() }; CONTROL_SLOTS],
            completion_generation: [const { AtomicU64::new(0) }; CONTROL_SLOTS],
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

    /// Install the queue key while CONTROL serializes the matching record
    /// generation. The monotonically increasing mirror lets a poisoned global
    /// fail-stop wake current listeners without reading a possibly partial
    /// table or guessing at a replacement generation.
    fn install_completion_generation(&self, key: ControlKey) -> bool {
        let Some(current) = self.completion_generation.get(key.slot as usize) else {
            return false;
        };
        let previous = current.load(Ordering::Acquire);
        if key.generation <= previous {
            return false;
        }
        current.store(key.generation, Ordering::Release);
        true
    }

    fn detach_fail_stop_wakes(&self) -> [Option<OneShotWake>; CONTROL_SLOTS] {
        let mut wakes = [const { None }; CONTROL_SLOTS];
        for (index, generation) in self.completion_generation.iter().enumerate() {
            let generation = generation.load(Ordering::Acquire);
            if generation != 0 {
                wakes[index] = self.completion[index].publish(generation).ok();
            }
        }
        wakes
    }

    fn dispatch_wakes(wakes: [Option<OneShotWake>; CONTROL_SLOTS]) {
        for wake in wakes.into_iter().flatten() {
            wake.dispatch();
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
        Self::dispatch_wakes(self.detach_fail_stop_wakes());
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
        let wakes = if self.gate.fail_wake_pending.swap(false, Ordering::AcqRel) {
            self.gate.detach_fail_stop_wakes()
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
        ControlGate::dispatch_wakes(wakes);
        // Close the race where another task stores fail_wake_pending after
        // the locked drain above but still observes this guard's HELD word.
        // CONTROL is now FREE or POISONED, so the generation mirror is the
        // conservative lock-independent source of truth.
        if self.gate.fail_wake_pending.swap(false, Ordering::AcqRel) {
            ControlGate::dispatch_wakes(self.gate.detach_fail_stop_wakes());
        }
    }
}

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy)]
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
}

#[cfg(feature = "ssh-component-command")]
struct ImageComponentLifecycle;

#[cfg(feature = "ssh-component-command")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PayloadMode {
    Command,
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    AcceptanceFault {
        round: u8,
        hart: u8,
    },
}

#[cfg(feature = "ssh-component-command")]
struct LazyComponentPayload {
    root: &'static ImageRoot,
    token: InstanceToken,
    resource_generation: u64,
    mode: PayloadMode,
    driver: Option<Pin<Box<dyn Future<Output = u64> + Send>>>,
}

#[cfg(feature = "ssh-component-command")]
struct ManagedChildFuture {
    token: InstanceToken,
}

#[cfg(feature = "ssh-component-command")]
const _: () =
    assert!(core::mem::size_of::<ManagedChildFuture>() == core::mem::size_of::<InstanceToken>());

#[cfg(feature = "ssh-component-command")]
impl Future for ManagedChildFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(witness) = crate::exec::current_reclaimable_task_witness() else {
            return Poll::Ready(());
        };
        if witness.instance_token() != Some(self.token) {
            return Poll::Ready(());
        }
        match unsafe { registry().poll_payload(witness, context) } {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(_)) | Err(_) => Poll::Ready(()),
        }
    }
}

#[cfg(feature = "ssh-component-command")]
impl LazyComponentPayload {
    const fn new(
        root: &'static ImageRoot,
        token: InstanceToken,
        resource_generation: u64,
        mode: PayloadMode,
    ) -> Self {
        Self {
            root,
            token,
            resource_generation,
            mode,
            driver: None,
        }
    }
}

#[cfg(feature = "wasm-c48-qemu-acceptance")]
impl Drop for LazyComponentPayload {
    fn drop(&mut self) {
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
            return Poll::Ready(terminal_word(ComponentTerminal::RunnerFault));
        }
        if self.driver.is_none() {
            self.driver = Some(Box::pin(run_image_component(
                self.root,
                self.token,
                self.resource_generation,
                self.mode,
            )));
        }
        self.driver
            .as_mut()
            .expect("lazy component driver was just installed")
            .as_mut()
            .poll(context)
    }
}

#[cfg(feature = "ssh-component-command")]
pub(crate) fn init() {
    if !IMAGE_ROOT.load(Ordering::Acquire).is_null() {
        panic!("managed component image root initialized twice");
    }
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    let root = Box::new(build_image_root().expect("image-pinned WASM component admission failed"));
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
        system.restore();
        panic!("managed component image root publication raced");
    }
    system.restore();
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
    validate_admitted_filter(&admitted, &manifest).map_err(build_error_terminal)?;
    let ssh_policy = image_vsh_policy(pin).map_err(|_| ComponentTerminal::BackendFault)?;
    if !ssh_policy.admits_manifest(&manifest)
        || manifest.min_args() != 0
        || manifest.max_args() != 0
        || manifest.stdin() != StreamMode::Closed
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
    root.admitted.identity().as_bytes() == &SSH_EXEC_COMPONENT.expected_sha256()
        && try_manifest_from_admitted(&root.admitted).is_ok_and(|manifest| {
            manifest == root.manifest
                && root.ssh_policy.admits_manifest(&manifest)
                && validate_admitted_filter(&root.admitted, &manifest).is_ok()
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
async fn run_image_component(
    root: &'static ImageRoot,
    token: InstanceToken,
    generation: u64,
    mode: PayloadMode,
) -> u64 {
    if !revalidate_image_root(root) {
        lifecycle_fail_stop();
        return terminal_word(ComponentTerminal::BackendFault);
    }
    let plan = match root.admitted.validated_plan() {
        Ok(plan) => plan,
        Err(_) => return terminal_word(ComponentTerminal::BackendFault),
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
    if !runtime_signature_matches(&component, root.manifest.entrypoint()) {
        return terminal_word(ComponentTerminal::BackendFault);
    }
    let mut resources = match ResourceTable::<()>::new(generation, root.manifest.resource_limit()) {
        Ok(resources) => resources,
        Err(_) => return terminal_word(ComponentTerminal::BudgetExceeded),
    };
    let mut arguments = Vec::new();
    if arguments.try_reserve_exact(1).is_err() {
        return terminal_word(ComponentTerminal::BudgetExceeded);
    }
    arguments.push(CanonicalValue::List(Vec::new()));
    let mut call = match component.start_typed_call(
        &mut resources,
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
    match value {
        CanonicalValue::List(values) if values.is_empty() => {
            terminal_word(ComponentTerminal::Success)
        }
        _ => terminal_word(ComponentTerminal::BackendFault),
    }
}

#[cfg(feature = "ssh-component-command")]
fn runtime_signature_matches(component: &SynchronousComponent, entrypoint: &str) -> bool {
    let Some(function) = component.function_type(entrypoint) else {
        return false;
    };
    let [parameter] = function.parameters.as_slice() else {
        return false;
    };
    parameter.name == vibeos_component_command::BYTE_FILTER_PARAMETER
        && matches!(&parameter.value, ValueType::List(value) if matches!(value.as_ref(), ValueType::U8))
        && matches!(function.result.as_ref(), Some(ValueType::List(value)) if matches!(value.as_ref(), ValueType::U8))
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
        ComponentTerminal::Denied => 3 << 56,
        ComponentTerminal::Unavailable => 4 << 56,
        ComponentTerminal::BackendFault => 5 << 56,
        ComponentTerminal::BudgetExceeded => 6 << 56,
        ComponentTerminal::Cancelled => 7 << 56,
        ComponentTerminal::RunnerFault => 8 << 56,
        ComponentTerminal::Trapped(code) => (9 << 56) | code.get() as u64,
    }
}

#[cfg(feature = "ssh-component-command")]
const fn terminal_from_word(word: u64) -> ComponentTerminal {
    match word >> 56 {
        1 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Success,
        2 if word & 0x00ff_ffff_ffff_ff00 == 0 => ComponentTerminal::Returned((word & 0xff) as u8),
        3 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Denied,
        4 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Unavailable,
        5 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::BackendFault,
        6 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::BudgetExceeded,
        7 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::Cancelled,
        8 if word & 0x00ff_ffff_ffff_ffff == 0 => ComponentTerminal::RunnerFault,
        9 if word & 0x00ff_ffff_ffff_0000 == 0 => {
            ComponentTerminal::Trapped(ComponentTrapCode::new((word & 0xffff) as u16))
        }
        _ => ComponentTerminal::RunnerFault,
    }
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
fn start_instance() -> Result<ManagedComponentToken, ComponentTerminal> {
    start_image_instance(true, PayloadMode::Command)
}

#[cfg(feature = "ssh-component-command")]
fn start_image_instance(
    require_session_gate: bool,
    mode: PayloadMode,
) -> Result<ManagedComponentToken, ComponentTerminal> {
    if !lifecycle_is_healthy()
        || (require_session_gate && SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED)
    {
        return Err(ComponentTerminal::Unavailable);
    }
    let Some(root) = image_root() else {
        lifecycle_fail_stop();
        return Err(ComponentTerminal::Unavailable);
    };
    let mut control = CONTROL.try_lock().map_err(|error| match error {
        ControlGateError::Busy => ComponentTerminal::Unavailable,
        ControlGateError::Poisoned | ControlGateError::Unattributed => {
            lifecycle_fail_stop();
            ComponentTerminal::RunnerFault
        }
    })?;
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if !lifecycle_is_healthy()
        || (require_session_gate && SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED)
    {
        system.restore();
        return Err(ComponentTerminal::Unavailable);
    }
    if !revalidate_image_root(root) {
        lifecycle_fail_stop();
        system.restore();
        return Err(ComponentTerminal::BackendFault);
    }
    let Some(key) = control.reserve(&CONTROL) else {
        system.restore();
        return Err(ComponentTerminal::Unavailable);
    };
    let Some(raw) = key.encode() else {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return Err(ComponentTerminal::RunnerFault);
    };

    let owner = match HEAP.create_owner(INSTANCE_HEAP_QUOTA) {
        Ok(owner) => owner,
        Err(_) => {
            control
                .exact_mut(key)
                .expect("reserved control slot exists")
                .phase = ControlPhase::Vacant;
            system.restore();
            return Err(ComponentTerminal::BudgetExceeded);
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
            return Err(ComponentTerminal::BudgetExceeded);
        }
    };
    let domain = AllocationDomain::new(owner, arena);
    let core_token = match registry().reserve_named(domain, SSH_EXEC_COMPONENT.command_name()) {
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
            return Err(ComponentTerminal::Unavailable);
        }
    };
    {
        let record = control
            .exact_mut(key)
            .expect("reserved control slot exists");
        record.core_token = Some(core_token);
        record.domain = Some(domain);
    }
    if unsafe {
        registry().install_payload(core_token, || {
            LazyComponentPayload::new(root, core_token, key.generation, mode)
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
        return Err(ComponentTerminal::RunnerFault);
    }

    let child = ManagedChildFuture { token: core_token };
    let mut batch = PreparedTaskBatch::new();
    unsafe {
        batch.prepare_managed_instance_owned(
            core_token,
            domain,
            SSH_EXEC_COMPONENT.command_name(),
            child,
        );
    }
    let handle = batch
        .prepared_handles()
        .first()
        .expect("managed batch contains one prepared handle")
        .clone();
    let binding = *batch
        .prepared_reclaimable_bindings()
        .first()
        .expect("managed batch contains one reclaimable binding");
    if registry().bind(core_token, binding, &handle).is_err() {
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return Err(ComponentTerminal::RunnerFault);
    }
    let published = unsafe {
        batch.publish_exclusive_reclaimable_with(|bindings| registry().activate_batch(bindings))
    };
    let mut handles = match published {
        Ok(handles) => handles,
        Err(_) => {
            control
                .exact_mut(key)
                .expect("reserved control slot exists")
                .quarantine();
            lifecycle_fail_stop();
            system.restore();
            return Err(ComponentTerminal::RunnerFault);
        }
    };
    let published_handle = handles
        .pop()
        .expect("managed publication returns one exact handle");
    if published_handle.id() != handle.id()
        || published_handle.allocation_domain() != domain
        || handles.len() != 0
    {
        // This token was activated by this still-serialized start transaction
        // and cannot have been retired or reused yet.
        let _ = registry().quarantine(core_token);
        control
            .exact_mut(key)
            .expect("reserved control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return Err(ComponentTerminal::RunnerFault);
    }
    {
        if !lifecycle_is_healthy()
            || (require_session_gate && SSH_POLICY_GATE.load(Ordering::Acquire) != POLICY_PASSED)
            || !control.starting_tuple_is_unique(key, core_token, &published_handle, domain)
        {
            // Activation happened in this transaction, so the token remains
            // exact while CONTROL excludes every terminal reuse path.
            let _ = registry().quarantine(core_token);
            lifecycle_fail_stop();
            system.restore();
            return Err(ComponentTerminal::RunnerFault);
        }
        let record = control
            .exact_mut(key)
            .expect("validated starting control slot exists");
        record.handle = Some(published_handle);
        record.phase = ControlPhase::Running;
    }
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
            return Err(ComponentTerminal::RunnerFault);
        }
    }
    crate::exec::spawn("wasm-instance-supervisor", supervise_instance(key));
    system.restore();
    drop(control);
    Ok(unsafe { ManagedComponentToken::from_trusted_raw(raw) })
}

#[cfg(feature = "ssh-component-command")]
async fn supervise_instance(key: ControlKey) {
    let handle = loop {
        match supervisor_handle(key) {
            Ok(Some(handle)) => break handle,
            Ok(None) => return,
            Err(ControlGateError::Busy) => crate::exec::yield_now().await,
            Err(ControlGateError::Poisoned | ControlGateError::Unattributed) => {
                lifecycle_fail_stop();
                return;
            }
        }
    };
    let _ = handle.join().await;
    loop {
        match finalize_instance(key) {
            FinalizeControl::Complete | FinalizeControl::Lost => return,
            FinalizeControl::Busy => crate::exec::yield_now().await,
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn supervisor_handle(key: ControlKey) -> Result<Option<TaskHandle>, ControlGateError> {
    let mut control = CONTROL.try_lock()?;
    if !lifecycle_is_healthy() {
        if let Some(record) = control.exact_mut(key) {
            record.quarantine();
        }
        return Ok(None);
    }
    match control.running_tuple(key) {
        Ok(Some(tuple)) => Ok(Some(tuple.handle)),
        Ok(None) => Ok(None),
        Err(()) => {
            lifecycle_fail_stop();
            Ok(None)
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
    let tuple = match control.running_tuple(key) {
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
    let structural = registry().observe_structural(tuple.core_token, &tuple.handle);
    let structurally_exact = structural.as_ref().is_ok_and(|snapshot| {
        snapshot.domain == tuple.domain && snapshot.task == Some(tuple.handle.id())
    });
    if !structurally_exact {
        // An Ok snapshot proved this exact token generation before the outer
        // projection comparison failed, so quarantine cannot hit a reused
        // core slot. Err already sticky-quarantined the core candidate.
        if structural.is_ok() {
            let _ = registry().quarantine(tuple.core_token);
        }
        control
            .exact_mut(key)
            .expect("validated running control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }
    let state = tuple.handle.try_exit().map(|exit| exit.state());
    if state.is_none() || !lifecycle_is_healthy() {
        let _ = registry().quarantine(tuple.core_token);
        control
            .exact_mut(key)
            .expect("validated running control slot exists")
            .quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    acceptance::record_terminal_visible(&tuple.handle, tuple.domain, state.unwrap());
    let finalized = unsafe {
        registry().finalize(tuple.core_token, &tuple.handle, |domain, kind| {
            let retired = match kind {
                TerminalRetireKind::Normal => {
                    HEAP.close_empty_domain(domain).is_ok()
                        && HEAP.unregister_owner(domain.owner).is_ok()
                }
                TerminalRetireKind::FaultReclaimed => HEAP.unregister_owner(domain.owner).is_ok(),
            };
            #[cfg(feature = "wasm-c48-qemu-acceptance")]
            acceptance::record_owner_retired(tuple.handle.id(), domain, kind, retired);
            retired
        })
    };
    #[cfg(feature = "wasm-c48-qemu-acceptance")]
    if let Ok(outcome) = finalized {
        acceptance::record_cspace_reset(
            tuple.handle.id(),
            tuple.domain,
            outcome.next_cspace_incarnation,
        );
    }
    let terminal = match (state, finalized) {
        (Some(TaskState::Exited), Ok(outcome)) => outcome
            .detached_completion
            .map(terminal_from_word)
            .unwrap_or(ComponentTerminal::RunnerFault),
        (Some(TaskState::Faulted), Ok(_)) => ComponentTerminal::RunnerFault,
        (Some(TaskState::Cancelled), Ok(_)) => ComponentTerminal::Cancelled,
        _ => {
            if let Some(record) = control.exact_mut(key) {
                record.quarantine();
            }
            lifecycle_fail_stop();
            system.restore();
            return FinalizeControl::Lost;
        }
    };
    let Some(record) = control.exact_mut(key) else {
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    };
    if record.phase != ControlPhase::Running
        || record.core_token != Some(tuple.core_token)
        || record.handle.as_ref().is_none_or(|handle| {
            handle.id() != tuple.handle.id()
                || handle.allocation_domain() != tuple.domain
                || !handle.shares_status_with(&tuple.handle)
        })
        || record.domain != Some(tuple.domain)
    {
        record.quarantine();
        lifecycle_fail_stop();
        system.restore();
        return FinalizeControl::Lost;
    }
    record.phase = ControlPhase::Complete {
        terminal,
        acknowledged: false,
    };
    record.core_token = None;
    record.handle = None;
    record.domain = None;
    let Some(completion) = CONTROL.completion(key) else {
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
    system.restore();
    drop(control);
    wake.dispatch();
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
        Err(ControlGateError::Busy) => return ManagedComponentState::Running,
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
                record.core_token.is_none() && record.handle.is_none() && record.domain.is_none()
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
    match observe_instance(token) {
        ManagedComponentState::Running => {}
        terminal => return terminal,
    }
    if listener.await.is_err() {
        quarantine_wait_instance(key);
        return ManagedComponentState::Lost;
    }
    match observe_instance(token) {
        terminal @ ManagedComponentState::Complete(_) => terminal,
        ManagedComponentState::Lost => ManagedComponentState::Lost,
        ManagedComponentState::Running => {
            // Only exact terminal publication can release this generation.
            // Running after that edge means the control projection disagrees
            // with its stable queue; fail-stop rather than polling again.
            quarantine_wait_instance(key);
            ManagedComponentState::Lost
        }
    }
}

#[cfg(feature = "ssh-component-command")]
fn cancel_instance(token: ManagedComponentToken) -> ManagedComponentCancel {
    if !lifecycle_is_healthy() {
        return ManagedComponentCancel::Lost;
    }
    let Some(key) = managed_token_key(token) else {
        return ManagedComponentCancel::Lost;
    };
    let mut control = match CONTROL.try_lock() {
        Ok(control) => control,
        Err(ControlGateError::Busy) => return ManagedComponentCancel::Lost,
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
        system.restore();
        return ManagedComponentCancel::AlreadyComplete;
    }
    if phase != ControlPhase::Running {
        system.restore();
        return ManagedComponentCancel::Lost;
    }
    let tuple = match control.running_tuple(key) {
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
    let outcome = registry().request_cooperative_cancel(
        tuple.core_token,
        &tuple.handle,
        terminal_word(ComponentTerminal::Cancelled),
    );
    let wake = match outcome {
        Ok(CooperativeCancelOutcome::Requested(task)) if tuple.handle.id() == task => Some(task),
        // Completion is already advancing. VSH must keep observing it, but
        // the registry contract forbids waking or mutating this raced slot.
        Ok(CooperativeCancelOutcome::AlreadyCompleting) => None,
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
    ManagedComponentCancel::Requested
}

#[cfg(feature = "ssh-component-command")]
fn acknowledge_instance(token: ManagedComponentToken) {
    if !lifecycle_is_healthy() {
        return;
    }
    let Some(key) = managed_token_key(token) else {
        return;
    };
    let mut control = match CONTROL.try_lock_completion_ack() {
        Ok(control) => control,
        Err(
            ControlGateError::Busy | ControlGateError::Poisoned | ControlGateError::Unattributed,
        ) => {
            lifecycle_fail_stop();
            return;
        }
    };
    let mut system = crate::heap::enter_owner(OwnerId::SYSTEM);
    if let Some(record) = control.exact_mut(key) {
        if let ControlPhase::Complete { acknowledged, .. } = &mut record.phase {
            if record.core_token.is_none() && record.handle.is_none() && record.domain.is_none() {
                *acknowledged = true;
            } else {
                record.quarantine();
                lifecycle_fail_stop();
            }
        }
    }
    system.restore();
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

    fn start(&self) -> Result<ManagedComponentToken, ComponentTerminal> {
        start_instance()
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

    fn request_cancel(&self, token: ManagedComponentToken) -> ManagedComponentCancel {
        cancel_instance(token)
    }

    fn acknowledge_complete(&self, token: ManagedComponentToken) {
        acknowledge_instance(token);
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
pub(crate) fn install_ssh_exec_component(
    session: &mut Session,
    accepted: SshExecComponentSessionPolicy,
) -> Result<(), vibeos_vsh::Diagnostic> {
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
    unsafe { session.install_ssh_exec_managed_component_command(&root.ssh_policy, &LIFECYCLE) }
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
    if !lifecycle_is_healthy() {
        return FaultRoute::Quarantined;
    }

    let task = witness.task_id();
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
