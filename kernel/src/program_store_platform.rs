//! Kernel compilation, execution, and CSpace adapter for the program store.
//!
//! Durable source/native-image publication and execution for the fixed `hello`
//! program slot.
//!
//! The persistent object capability is the only durable entry. Console and
//! memory authority are reconstructed after recovery from a private supervisor
//! policy CSpace, attenuated to the exact canonical artifact manifest. They are
//! deliberately never copied from the legacy boot-local `prog` CSpace.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use vibeos_core::cap::{
    Cap, InvocationLease, PendingSlotReservation, PersistentCapIdentity, Resource, Rights,
};
use vibeos_durable_format::{
    DerivationId, GrantFlags, GrantRecord, ObjectId, SlotIdentity, TransactionId,
};
use vibeos_core::program::{
    self, ProgramArtifact, PROGRAM_CONSOLE_RIGHTS, PROGRAM_MEMORY_RIGHTS, PROGRAM_ROOT_RIGHTS,
    PROGRAM_ROOT_SLOT, PROGRAM_SPACE_ID_RAW,
};
use vibeos_object_store as object_codec;

use crate::store::{AuthorityJournal, StoredObject};
use crate::sync::SpinLock;
use crate::world::Space;
use crate::{cap, exec, heap};

pub use vibeos_program_store::{authorize_recovered, SavedProgramError, SavedProgramInfo, SavedProgramState, TrustedProgram};

pub struct SavedProgramService {
    inner: Arc<SavedProgramInner>,
}

struct SavedProgramInner {
    journal: AuthorityJournal,
    target: Arc<Space>,
    policy: Arc<Space>,
    policy_console: Cap,
    policy_memory: Cap,
    state: AtomicU8,
    running: AtomicBool,
    running_owner: SpinLock<Option<SavedRunOwner>>,
    active: SpinLock<Option<SavedActiveClaim>>,
    live: SpinLock<SavedProgramLive>,
}

#[derive(Clone, Copy)]
struct SavedActiveClaim {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    reservation: Option<PendingSlotReservation>,
}

#[derive(Clone, Copy)]
struct SavedRunOwner {
    task: exec::TaskId,
    domain: heap::AllocationDomain,
}

#[derive(Default)]
struct SavedProgramLive {
    artifact: Option<PersistentCapIdentity>,
    console: Option<Cap>,
    memory: Option<Cap>,
}

static NEXT_ACTIVE_TOKEN: AtomicU64 = AtomicU64::new(1);
static INSTALLED_SAVED_PROGRAM: SpinLock<Option<Arc<SavedProgramInner>>> = SpinLock::new(None);

impl SavedProgramService {
    pub(crate) fn new(
        journal: AuthorityJournal,
        target: Arc<Space>,
        policy: Arc<Space>,
        policy_console: Cap,
        policy_memory: Cap,
    ) -> Arc<Self> {
        let inner = Arc::new(SavedProgramInner {
            journal,
            target,
            policy,
            policy_console,
            policy_memory,
            state: AtomicU8::new(SavedProgramState::Cold as u8),
            running: AtomicBool::new(false),
            running_owner: SpinLock::new_recoverable(None),
            active: SpinLock::new_recoverable(None),
            live: SpinLock::new_recoverable(SavedProgramLive::default()),
        });
        {
            let mut installed = INSTALLED_SAVED_PROGRAM.lock();
            assert!(
                installed.is_none(),
                "only one saved-program service may be installed"
            );
            *installed = Some(inner.clone());
        }
        Arc::new(Self { inner })
    }

    pub fn state(&self) -> SavedProgramState {
        SavedProgramState::from_raw(self.inner.state.load(Ordering::Acquire))
    }

    pub fn info(&self) -> SavedProgramInfo {
        let live = self.inner.live.lock();
        SavedProgramInfo {
            state: self.state(),
            running: self.inner.running.load(Ordering::Acquire),
            artifact: live.artifact,
            console_rights: Rights::WRITE,
            memory_rights: Rights::READ.union(Rights::WRITE),
        }
    }

    pub async fn wait_ready(&self) -> Result<(), SavedProgramError> {
        loop {
            match self.state() {
                SavedProgramState::ReadyEmpty | SavedProgramState::Ready => return Ok(()),
                SavedProgramState::FailedClosed => return Err(SavedProgramError::NotReady),
                SavedProgramState::Cold => exec::sleep_ms(1).await,
            }
        }
    }

    pub(crate) fn target(&self) -> &Arc<Space> {
        &self.inner.target
    }

    pub(crate) fn mark_failed_closed(&self) {
        self.inner
            .state
            .store(SavedProgramState::FailedClosed as u8, Ordering::Release);
        let _ = self.inner.target.0.lock().quarantine_persistent();
        *self.inner.live.lock() = SavedProgramLive::default();
    }

    fn begin_operation(&self) -> Result<SavedOperation, SavedProgramError> {
        let task = exec::current_task_id().ok_or(SavedProgramError::OutsideTask)?;
        let domain = heap::current_domain();
        let token = NEXT_ACTIVE_TOKEN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |token| {
                token.checked_add(1)
            })
            .expect("saved-program operation token space exhausted");
        let mut active = self.inner.active.lock();
        if active.is_some() {
            return Err(SavedProgramError::Busy);
        }
        // The first optimistic state check in `save_with` happens before
        // compilation. Recheck under the operation lock so two callers that
        // both observed ReadyEmpty cannot let the later caller reserve or
        // quarantine an already-published slot.
        match self.state() {
            SavedProgramState::ReadyEmpty => {}
            SavedProgramState::Ready => return Err(SavedProgramError::AlreadySaved),
            SavedProgramState::Cold | SavedProgramState::FailedClosed => {
                return Err(SavedProgramError::NotReady);
            }
        }
        *active = Some(SavedActiveClaim {
            task,
            domain,
            token,
            reservation: None,
        });
        drop(active);
        Ok(SavedOperation {
            inner: self.inner.clone(),
            task,
            domain,
            token,
            armed: true,
        })
    }

    fn begin_run(&self) -> Result<RunningClaim, SavedProgramError> {
        let task = exec::current_task_id().ok_or(SavedProgramError::OutsideTask)?;
        let domain = heap::current_domain();
        let mut owner = self.inner.running_owner.lock();
        if self.inner.running.load(Ordering::Acquire) || owner.is_some() {
            return Err(SavedProgramError::Busy);
        }
        // Publish the fault-recoverable owner before the observable busy bit.
        // If this task faults at either instruction, raw cleanup can identify
        // the exact owner while all competitors remain excluded by this lock.
        *owner = Some(SavedRunOwner { task, domain });
        self.inner.running.store(true, Ordering::Release);
        drop(owner);
        Ok(RunningClaim {
            inner: self.inner.clone(),
            task,
            domain,
            armed: true,
        })
    }

    /// Called only by the unified durable boot coordinator after both root
    /// partitions have passed external policy and the persistent slot graph has
    /// been installed. No dependent can observe this CSpace before this method
    /// and the M4.3 target both complete.
    pub(crate) fn install_recovered(
        &self,
        identity: Option<PersistentCapIdentity>,
    ) -> Result<(), SavedProgramError> {
        match identity {
            None => {
                *self.inner.live.lock() = SavedProgramLive::default();
                self.inner
                    .state
                    .store(SavedProgramState::ReadyEmpty as u8, Ordering::Release);
                Ok(())
            }
            Some(identity) => {
                let (console, memory) = self.install_manifest_authority()?;
                *self.inner.live.lock() = SavedProgramLive {
                    artifact: Some(identity),
                    console: Some(console),
                    memory: Some(memory),
                };
                self.inner
                    .state
                    .store(SavedProgramState::Ready as u8, Ordering::Release);
                Ok(())
            }
        }
    }

    fn install_manifest_authority(&self) -> Result<(Cap, Cap), SavedProgramError> {
        let policy = self.inner.policy.0.lock();
        let mut target = self.inner.target.0.lock();
        let console = cap::grant(
            &policy,
            self.inner.policy_console,
            Rights::from_durable(PROGRAM_CONSOLE_RIGHTS),
            &mut target,
        )
        .map_err(|_| SavedProgramError::Install)?;
        let memory = cap::grant(
            &policy,
            self.inner.policy_memory,
            Rights::from_durable(PROGRAM_MEMORY_RIGHTS),
            &mut target,
        )
        .map_err(|_| SavedProgramError::Install)?;
        Ok((console, memory))
    }
}

struct SavedOperation {
    inner: Arc<SavedProgramInner>,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: u64,
    armed: bool,
}

impl SavedOperation {
    fn reserve(&self, expected_incarnation: u64) -> Result<SlotIdentity, SavedProgramError> {
        let reservation = self
            .inner
            .target
            .0
            .lock()
            .reserve_persistent_slot(expected_incarnation)
            .map_err(|_| SavedProgramError::Install)?;
        let target = reservation.target();
        let mut active = self.inner.active.lock();
        let Some(claim) = active.as_mut().filter(|claim| {
            claim.task == self.task
                && claim.domain == self.domain
                && claim.token == self.token
                && claim.reservation.is_none()
        }) else {
            drop(active);
            let _ = self
                .inner
                .target
                .0
                .lock()
                .cancel_persistent_slot(&reservation);
            return Err(SavedProgramError::Install);
        };
        claim.reservation = Some(reservation);
        Ok(target)
    }

    fn reservation(&self) -> Result<PendingSlotReservation, SavedProgramError> {
        self.inner
            .active
            .lock()
            .as_ref()
            .filter(|claim| {
                claim.task == self.task && claim.domain == self.domain && claim.token == self.token
            })
            .and_then(|claim| claim.reservation)
            .ok_or(SavedProgramError::Install)
    }

    fn install_root(
        &self,
        grant: &GrantRecord,
        resource: Arc<StoredObject>,
    ) -> Result<PersistentCapIdentity, SavedProgramError> {
        let reservation = self.reservation()?;
        let identity = self
            .inner
            .target
            .0
            .lock()
            .install_reserved_root(&reservation, grant, resource)
            .map(|(_cap, witness)| witness.identity())
            .map_err(|_| SavedProgramError::Install)?;
        let mut active = self.inner.active.lock();
        let claim = active
            .as_mut()
            .filter(|claim| {
                claim.task == self.task
                    && claim.domain == self.domain
                    && claim.token == self.token
                    && claim.reservation == Some(reservation)
            })
            .ok_or(SavedProgramError::Install)?;
        claim.reservation = None;
        Ok(identity)
    }

    fn finish(mut self) {
        let mut active = self.inner.active.lock();
        assert!(
            active.as_ref().is_some_and(|claim| {
                claim.task == self.task
                    && claim.domain == self.domain
                    && claim.token == self.token
                    && claim.reservation.is_none()
            }),
            "only the exact saved-program operation may finish"
        );
        *active = None;
        self.armed = false;
    }

    fn fail(mut self) {
        quarantine_operation(&self.inner, self.task, self.domain, Some(self.token));
        self.armed = false;
    }
}

impl Drop for SavedOperation {
    fn drop(&mut self) {
        if self.armed {
            quarantine_operation(&self.inner, self.task, self.domain, Some(self.token));
        }
    }
}

fn quarantine_operation(
    inner: &SavedProgramInner,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    token: Option<u64>,
) -> bool {
    let claimed = inner.active.lock().as_ref().is_some_and(|claim| {
        claim.task == task
            && claim.domain == domain
            && token.is_none_or(|expected| claim.token == expected)
    });
    if !claimed {
        return false;
    }

    // Keep the exact claim as a recovery breadcrumb until every operation that
    // can itself fault has completed. A raw fault can then repeat this
    // idempotent fail-closed sequence instead of losing ownership between
    // clearing `active` and quarantining the target.
    inner
        .state
        .store(SavedProgramState::FailedClosed as u8, Ordering::Release);
    let _ = inner.target.0.lock().quarantine_persistent();
    *inner.live.lock() = SavedProgramLive::default();

    let mut active = inner.active.lock();
    if !active.as_ref().is_some_and(|claim| {
        claim.task == task
            && claim.domain == domain
            && token.is_none_or(|expected| claim.token == expected)
    }) {
        return false;
    }
    *active = None;
    true
}

impl Resource for SavedProgramService {
    fn kind(&self) -> &'static str {
        "saved-program"
    }

    fn describe(&self) -> String {
        let info = self.info();
        format!(
            "fixed saved program `hello` [{:?}, artifact {}, authority console=w memory=rw]",
            info.state,
            if info.artifact.is_some() {
                "installed"
            } else {
                "absent"
            }
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedProgramReport {
    pub identity: PersistentCapIdentity,
    pub source_bytes: usize,
    pub executable_bytes: usize,
    pub console_rights: Rights,
    pub memory_rights: Rights,
}

pub struct SavedRunReport {
    pub identity: PersistentCapIdentity,
    pub source_bytes: usize,
    pub executable_bytes: usize,
    pub compiled_bytes: usize,
    pub data_bytes: usize,
    pub funcs: usize,
    pub outcome: crate::rustc::RunOutcome,
}

pub async fn save_with(
    lease: InvocationLease<SavedProgramService>,
    source: &str,
) -> Result<SavedProgramReport, SavedProgramError> {
    if !lease.authorizes(Rights::WRITE) {
        return Err(SavedProgramError::PermissionDenied);
    }
    let service = SavedProgramService {
        inner: lease.with(|service| service.inner.clone()),
    };
    service.wait_ready().await?;
    if service.state() != SavedProgramState::ReadyEmpty {
        return Err(SavedProgramError::AlreadySaved);
    }

    // Compile and canonically wrap the complete source/binary pair before
    // taking a durable-operation claim or reserving a CSpace slot.
    let executable =
        crate::rustc::compile_persistable(source).map_err(SavedProgramError::Compiler)?;
    let artifact =
        ProgramArtifact::new(source, &executable).map_err(|_| SavedProgramError::Artifact)?;
    let bytes = artifact.encode();
    let decoded = ProgramArtifact::decode(&bytes).map_err(|_| SavedProgramError::Artifact)?;
    if decoded != artifact {
        return Err(SavedProgramError::Artifact);
    }

    let operation = service.begin_operation()?;
    let expected_incarnation = service.inner.target.0.lock().incarnation();
    let result = service
        .publish(&operation, expected_incarnation, &bytes)
        .await;
    match result {
        Ok(identity) => {
            operation.finish();
            Ok(SavedProgramReport {
                identity,
                source_bytes: source.len(),
                executable_bytes: executable.len(),
                console_rights: Rights::from_durable(PROGRAM_CONSOLE_RIGHTS),
                memory_rights: Rights::from_durable(PROGRAM_MEMORY_RIGHTS),
            })
        }
        Err(error) => {
            operation.fail();
            Err(error)
        }
    }
}

impl SavedProgramService {
    async fn publish(
        &self,
        operation: &SavedOperation,
        expected_incarnation: u64,
        bytes: &[u8],
    ) -> Result<PersistentCapIdentity, SavedProgramError> {
        let target = operation.reserve(expected_incarnation)?;
        if target
            != (SlotIdentity {
                space: program::program_space_id(),
                slot: PROGRAM_ROOT_SLOT,
                generation: 0,
            })
        {
            return Err(SavedProgramError::Install);
        }

        let snapshot = self.inner.journal.recover().await?;
        if snapshot.preflight.as_ref().is_some_and(|preflight| {
            preflight
                .slots()
                .iter()
                .any(|slot| slot.space == program::program_space_id())
        }) {
            return Err(SavedProgramError::AlreadySaved);
        }

        // One high-water reservation covers both transactions, the object, and
        // the root derivation. The ordered append is object-commit first and
        // root-grant commit last, so every crash prefix has either old authority
        // or the complete source/binary capability.
        let first = snapshot
            .id_high_water()
            .max(
                PROGRAM_SPACE_ID_RAW
                    .checked_add(1)
                    .ok_or(SavedProgramError::IdExhausted)?,
            )
            .max(1);
        let exclusive_end = first.checked_add(4).ok_or(SavedProgramError::IdExhausted)?;
        let object_transaction = TransactionId::new(first).ok_or(SavedProgramError::IdExhausted)?;
        let object_id = ObjectId::new(first + 1).ok_or(SavedProgramError::IdExhausted)?;
        let grant_transaction =
            TransactionId::new(first + 2).ok_or(SavedProgramError::IdExhausted)?;
        let derivation_id = DerivationId::new(first + 3).ok_or(SavedProgramError::IdExhausted)?;

        let expected = snapshot.checkpoint;
        let mut chain = snapshot.chain()?;
        let mut records = Vec::new();
        if !snapshot.formatted {
            records.push(
                chain
                    .append(None, vibeos_durable_format::RecordBody::Format)
                    .map_err(|_| SavedProgramError::Encode)?,
            );
        }
        let (high_water, next) = vibeos_durable_format::preview_id_high_water(&chain, exclusive_end)
            .map_err(|_| SavedProgramError::Encode)?;
        records.extend(high_water.records);
        chain = next;
        let (object, next) = object_codec::preview_object_transaction(
            &chain,
            object_transaction,
            object_id,
            program::program_artifact_object_kind(),
            bytes,
        )
        .map_err(|_| SavedProgramError::Encode)?;
        records.extend(object.records);
        chain = next;
        let grant = GrantRecord {
            derivation_id,
            parent_id: None,
            object_id,
            target,
            rights: PROGRAM_ROOT_RIGHTS,
            resource_kind: program::stored_object_resource_kind(),
            flags: GrantFlags::ROOT,
        };
        let (grant_records, _next) = vibeos_durable_format::preview_grant_transaction(
            &chain,
            grant_transaction,
            grant.clone(),
        )
        .map_err(|_| SavedProgramError::Encode)?;
        records.extend(grant_records.records);

        let committed = self.inner.journal.append(expected, &records).await?;
        let recovered = committed
            .preflight
            .as_ref()
            .ok_or(SavedProgramError::UnexpectedGraph)?;
        let object = recovered
            .committed_objects()
            .iter()
            .find(|candidate| {
                candidate.object_id == object_id
                    && candidate.object_kind == program::program_artifact_object_kind()
                    && candidate.bytes.as_slice() == bytes
            })
            .ok_or(SavedProgramError::UnexpectedGraph)?;
        let resource = StoredObject::from_recovered(object);
        let identity = operation.install_root(&grant, resource)?;
        let (console, memory) = self.install_manifest_authority()?;
        *self.inner.live.lock() = SavedProgramLive {
            artifact: Some(identity),
            console: Some(console),
            memory: Some(memory),
        };
        self.inner
            .state
            .store(SavedProgramState::Ready as u8, Ordering::Release);
        Ok(identity)
    }
}

pub async fn run_with(
    lease: InvocationLease<SavedProgramService>,
) -> Result<SavedRunReport, SavedProgramError> {
    if !lease.authorizes(Rights::READ) {
        return Err(SavedProgramError::PermissionDenied);
    }
    let service = SavedProgramService {
        inner: lease.with(|service| service.inner.clone()),
    };
    service.wait_ready().await?;
    let _running = service.begin_run()?;
    let (identity, console, memory) = {
        let live = service.inner.live.lock();
        (
            live.artifact.ok_or(SavedProgramError::Missing)?,
            live.console.ok_or(SavedProgramError::Missing)?,
            live.memory.ok_or(SavedProgramError::Missing)?,
        )
    };
    let artifact_lease = service
        .inner
        .target
        .0
        .lock()
        .lookup_persistent_identity::<StoredObject>(identity, Rights::READ)
        .map_err(|_| SavedProgramError::Missing)?;
    let bytes = service.inner.journal.read(artifact_lease).await?;
    let artifact = ProgramArtifact::decode(&bytes).map_err(|_| SavedProgramError::Artifact)?;

    // This exact comparison is the admission proof for persisted native code.
    // A recomputed disk CRC cannot turn arbitrary machine code into compiler
    // output because the current compiler must reproduce the canonical bytes.
    let compiled = crate::rustc::compile_verified(artifact.source(), artifact.executable())
        .map_err(SavedProgramError::Compiler)?;
    let funcs = compiled.funcs;
    let compiled_bytes = compiled.bytes;
    let data_bytes = compiled.data_bytes;
    let outcome =
        crate::rustc::run_with_authority(&compiled, &service.inner.target, console, memory);
    Ok(SavedRunReport {
        identity,
        source_bytes: artifact.source().len(),
        executable_bytes: artifact.executable().len(),
        compiled_bytes,
        data_bytes,
        funcs,
        outcome,
    })
}

struct RunningClaim {
    inner: Arc<SavedProgramInner>,
    task: exec::TaskId,
    domain: heap::AllocationDomain,
    armed: bool,
}

impl Drop for RunningClaim {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut owner = self.inner.running_owner.lock();
        assert!(
            owner
                .as_ref()
                .is_some_and(|owner| { owner.task == self.task && owner.domain == self.domain }),
            "only the exact saved-program run may release its claim"
        );
        // Keep the recoverable owner published until the observable busy bit is
        // gone. `begin_run` is excluded by this guard, and a raw fault between
        // these stores can therefore still identify the exact task to clean up.
        self.inner.running.store(false, Ordering::Release);
        *owner = None;
        self.armed = false;
    }
}

/// Repair locks and claims abandoned by one exact task fault. These locks are
/// supervisor-stable; persistent state is quarantined without running resource
/// destructors.
pub(crate) unsafe fn recover_faulted_task(task: exec::TaskId, domain: heap::AllocationDomain) {
    let installed = INSTALLED_SAVED_PROGRAM.lock();
    let Some(inner) = installed.as_ref() else {
        return;
    };

    let task_key = crate::sync::TaskRecoveryKey::new(task.0)
        .expect("executor TaskId zero is reserved");

    // Repair every saved-program lock before inspecting ownership. The durable
    // boot coordinator owns a durable claim, not a SavedActiveClaim, while it
    // installs this target and its ephemeral manifest. Consequently these
    // repairs must not be conditional on a saved operation/run claim.
    let _ = unsafe {
        inner
            .running_owner
            .recover_after_task_fault(domain, task_key)
    };
    let _ = unsafe { inner.active.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { inner.live.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { inner.target.0.recover_after_task_fault(domain, task_key) };
    let _ = unsafe { inner.policy.0.recover_after_task_fault(domain, task_key) };

    let mut owner = inner.running_owner.lock();
    if owner
        .as_ref()
        .is_some_and(|owner| owner.task == task && owner.domain == domain)
    {
        // Busy disappears before its recovery breadcrumb, mirroring normal
        // RunningClaim release while this lock excludes a competing begin_run.
        inner.running.store(false, Ordering::Release);
        *owner = None;
    }
    drop(owner);

    // `quarantine_operation` keeps the claim live until target and live-state
    // isolation are complete, so this remains safe if cleanup is retried.
    let _ = quarantine_operation(inner, task, domain, None);
}
